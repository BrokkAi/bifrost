use crate::analyzer::usages::get_definition::python;
use brokk_bifrost_analysis::analyzer::common::language_for_file;
#[cfg(test)]
use brokk_bifrost_analysis::analyzer::read_ledger::ReadKey;
use brokk_bifrost_analysis::analyzer::usages::get_definition::*;
use brokk_bifrost_analysis::analyzer::{
    AnalyzerDefinitionLookup, AnalyzerQueryScope, CodeUnit, IAnalyzer, Language, ProjectFile,
    Range, resolve_analyzer,
};
use brokk_bifrost_core::analyzer::definition_lookup::sort_units;
use brokk_bifrost_core::analyzer::query_token::QueryScope;
use brokk_bifrost_core::analyzer::usages::local_inference::LocalBindingsSnapshot;
use brokk_bifrost_core::analyzer::usages::model::{ImportBinder, ImportKind};
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use brokk_bifrost_core::analyzer::usages::reference_site::{
    ResolvedReferenceSite, smallest_named_node_covering,
};
use brokk_bifrost_core::analyzer::usages::resolution_session::{
    BoundedResolution, ResolutionSession,
};
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::hash::{HashMap, HashSet};
use brokk_bifrost_core::text_utils::{compute_line_starts, find_line_index_for_offset};
use brokk_bifrost_python::usage_index::{ModuleBindingEventKind, ModuleBindingTimeline};
use std::sync::{Arc, OnceLock};
#[cfg(test)]
use tree_sitter::Parser;
use tree_sitter::{Node, Tree};

use crate::analyzer::PythonAnalyzer;

trait PythonRuntimeCallProof: Sized {
    fn with_python_runtime_binding(
        self,
        binding: &crate::analyzer::python::runtime_binding::PythonDefiningBinding,
        provider: &crate::analyzer::python::runtime_binding::PythonRuntimeProviderProof,
    ) -> Option<Self>;
}

impl PythonRuntimeCallProof for ExactExternalCallProof {
    /// Promote the lexical Python call-shape proof only when the active
    /// defining binding and installed-provider proof identify the same exact
    /// artifact in the same source and published workspace snapshot.
    fn with_python_runtime_binding(
        mut self,
        binding: &crate::analyzer::python::runtime_binding::PythonDefiningBinding,
        provider: &crate::analyzer::python::runtime_binding::PythonRuntimeProviderProof,
    ) -> Option<Self> {
        if binding.artifact() != provider.artifact()
            || binding.source_path() != provider.source_path()
            || binding.snapshot() != provider.snapshot()
        {
            return None;
        }

        let artifact = provider.artifact();
        let evidence = provider.evidence();
        assert_eq!(evidence.language, "python");
        assert_eq!(evidence.ecosystem, "python");
        let package = evidence
            .package
            .as_ref()
            .expect("checked Python provider evidence names its PyPI artifact");
        assert_eq!(package.name, artifact.purl());
        assert!(package.version.is_none());
        assert_eq!(
            evidence.artifact_sha256.as_deref(),
            Some(artifact.archive_sha256()),
            "provider evidence retains the raw installed archive SHA-256"
        );
        assert!(
            !binding.canonical().is_empty()
                && binding
                    .canonical()
                    .iter()
                    .all(|component| !component.is_empty()),
            "checked defining bindings have nonempty canonical components"
        );

        self.canonical_callee = binding.canonical().join(".").into_boxed_str();
        self.python_runtime_artifact = Some(evidence.clone());
        self.python_model_manifest_sha256 = Some(binding.model_manifest_sha256().into());
        self.python_formal_slots = Some(binding.formal_slots().to_vec().into_boxed_slice());
        Some(self)
    }
}

struct PythonRuntimeBindingAndProvider {
    binding: crate::analyzer::python::runtime_binding::PythonDefiningBinding,
    provider: crate::analyzer::python::runtime_binding::PythonRuntimeProviderProof,
}

struct PythonImportedMember<'a> {
    module: &'a [String],
    member: &'a str,
}

type PythonDefiningBindingResolver = fn(
    &brokk_bifrost_analysis::analyzer::semantic_model::runtime::ResolvedActiveSemanticModels,
    &brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelActivationEvidence,
    &[String],
    &str,
    &std::path::Path,
    &brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshotId,
    Option<&brokk_bifrost_analysis::analyzer::semantic_model::PythonConditionSnapshot>,
) -> Result<
    crate::analyzer::python::runtime_binding::PythonDefiningBinding,
    crate::analyzer::python::runtime_binding::PythonRuntimeBindingError,
>;

enum PythonRuntimeBindingFailure {
    Binding(crate::analyzer::python::runtime_binding::PythonRuntimeBindingError),
    ProviderIncomplete(String),
    ProviderStale(String),
    ProviderVerification(String),
}

fn python_runtime_binding_failure_parts(
    failure: PythonRuntimeBindingFailure,
) -> (DefinitionLookupStatus, &'static str, String) {
    match failure {
        PythonRuntimeBindingFailure::Binding(error) => {
            let status = if matches!(
                &error,
                crate::analyzer::python::runtime_binding::PythonRuntimeBindingError::Ambiguous(_)
            ) {
                DefinitionLookupStatus::Ambiguous
            } else {
                DefinitionLookupStatus::Incomplete
            };
            (
                status,
                "python_runtime_binding_incomplete",
                format!("{error:?}"),
            )
        }
        PythonRuntimeBindingFailure::ProviderIncomplete(message) => (
            DefinitionLookupStatus::Incomplete,
            "python_runtime_provider_incomplete",
            message,
        ),
        PythonRuntimeBindingFailure::ProviderStale(message) => (
            DefinitionLookupStatus::Incomplete,
            "python_runtime_provider_stale",
            message,
        ),
        PythonRuntimeBindingFailure::ProviderVerification(message) => (
            DefinitionLookupStatus::Incomplete,
            "python_runtime_applicability_incomplete",
            message,
        ),
    }
}

fn python_runtime_binding_failure_diagnostic(
    failure: PythonRuntimeBindingFailure,
) -> DefinitionLookupDiagnostic {
    let (_, kind, message) = python_runtime_binding_failure_parts(failure);
    DefinitionLookupDiagnostic {
        kind: kind.to_owned(),
        message,
        claim: None,
    }
}

fn python_class_resolution_incomplete_diagnostic(
    message: impl Into<String>,
) -> DefinitionLookupDiagnostic {
    DefinitionLookupDiagnostic {
        kind: "python_imported_class_resolution_incomplete".to_owned(),
        message: message.into(),
        claim: None,
    }
}

fn python_incomplete_class_value(
    mut outcome: DefinitionLookupOutcome,
    status: DefinitionLookupStatus,
    diagnostic: DefinitionLookupDiagnostic,
) -> DefinitionLookupOutcome {
    if status == DefinitionLookupStatus::Ambiguous {
        // no candidates: the binding resolver proves competing native class
        // declarations but withholds their identities, so there is no exact
        // modeled symbol this outcome can safely publish.
        let mut ambiguous = ambiguous_without_candidates(
            "the imported Python class binding has multiple native declarations",
        );
        ambiguous.reference = outcome.reference.take();
        ambiguous.diagnostics.append(&mut outcome.diagnostics);
        ambiguous.diagnostics.push(diagnostic);
        return ambiguous;
    }
    outcome.status = status;
    outcome.definitions.clear();
    outcome.modeled_definitions.clear();
    outcome.lexical_definition = None;
    outcome.diagnostics.push(diagnostic);
    outcome
}

enum PythonRuntimeBindingAttempt {
    Unavailable,
    Cancelled,
    Resolved(Box<PythonRuntimeBindingAndProvider>),
    Failed(PythonRuntimeBindingFailure),
}

// Keep staged import evidence behind the runtime attempt's terminal outcome.
// The same boundary is exercised by the imported-call cancellation regression.
fn finish_python_imported_call_binding(
    outcome: &mut DefinitionLookupOutcome,
    evidence: &mut CallEvidence,
    site: &ResolvedReferenceSite,
    mut proof: ExactExternalCallProof,
    runtime_binding: PythonRuntimeBindingAttempt,
    cancellation: Option<&CancellationToken>,
) {
    match runtime_binding {
        PythonRuntimeBindingAttempt::Resolved(proof_and_provider) => {
            if let Some(promoted) = proof.clone().with_python_runtime_binding(
                &proof_and_provider.binding,
                &proof_and_provider.provider,
            ) {
                proof = promoted;
                // A complete callable family can be selected exactly
                // through a partial package import surface. Preserve
                // the external-body boundary while closing this
                // callable's identity and formal contract.
                outcome.status = DefinitionLookupStatus::UnresolvableImportBoundary;
            }
        }
        PythonRuntimeBindingAttempt::Unavailable => {}
        PythonRuntimeBindingAttempt::Cancelled => {
            *outcome = cancelled("Python imported call binding resolution was cancelled");
        }
        PythonRuntimeBindingAttempt::Failed(failure) => {
            outcome
                .diagnostics
                .push(python_runtime_binding_failure_diagnostic(failure));
        }
    }
    // Runtime binding may stop after import selection succeeded.
    // Do not publish the staged identity/application on that stop.
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        *outcome = cancelled("Python imported call binding resolution was cancelled");
    }
    if !matches!(
        outcome.status,
        DefinitionLookupStatus::Cancelled | DefinitionLookupStatus::ExceededBudget(_)
    ) {
        let mut reference = outcome.reference.take().unwrap_or_else(|| site.clone());
        reference.text = proof.canonical_callee().to_owned();
        outcome.reference = Some(reference);
        evidence.call_application = proof.call_application();
        evidence.dispatch_extensibility = proof.dispatch_extensibility();
        evidence.exact_external_call = Some(proof);
    }
}

fn resolve_python_runtime_binding(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    imported: PythonImportedMember<'_>,
    cancellation: Option<&CancellationToken>,
    resolve_binding: PythonDefiningBindingResolver,
) -> PythonRuntimeBindingAttempt {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return PythonRuntimeBindingAttempt::Cancelled;
    }
    let Some(active_snapshot) = analyzer.active_semantic_model_snapshot() else {
        return PythonRuntimeBindingAttempt::Unavailable;
    };
    let Some(publication) = active_snapshot.python_runtime() else {
        return PythonRuntimeBindingAttempt::Unavailable;
    };
    let Some(python_analyzer) = resolve_analyzer::<crate::analyzer::PythonAnalyzer>(analyzer)
    else {
        return PythonRuntimeBindingAttempt::Unavailable;
    };
    let Some((store, current_snapshot)) = python_analyzer.python_runtime_store_snapshot() else {
        return PythonRuntimeBindingAttempt::Unavailable;
    };

    let selected = store.with_python_runtime_acquisition(
        publication.acquisition_id,
        &publication.snapshot,
        |tx| {
            crate::analyzer::python::runtime_provider::python_runtime_provider_lookup(
                tx,
                publication.acquisition_id,
                &publication.snapshot,
                file.rel_path(),
                &imported.module.join("."),
            )
        },
    );
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return PythonRuntimeBindingAttempt::Cancelled;
    }
    let candidate = match selected {
        Ok(rows)
            if current_snapshot == publication.snapshot
                && !rows.has_scope_ambiguity
                && rows.unresolved_scopes.is_empty()
                && rows.candidates.len() == 1 =>
        {
            rows.candidates.into_iter().next().expect("one provider")
        }
        Ok(rows) => {
            return PythonRuntimeBindingAttempt::Failed(
                PythonRuntimeBindingFailure::ProviderIncomplete(format!("{rows:?}")),
            );
        }
        Err(error) => {
            return PythonRuntimeBindingAttempt::Failed(
                PythonRuntimeBindingFailure::ProviderStale(error.to_string()),
            );
        }
    };
    let selected_evidence =
        brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelActivationEvidence {
            language: "python".into(),
            ecosystem: "python".into(),
            package: candidate.purl.as_ref().map(|purl| {
                brokk_bifrost_analysis::analyzer::semantic_model::CatalogCoordinate {
                    name: purl.clone(),
                    version: None,
                }
            }),
            module: None,
            toolchain: None,
            target: None,
            configuration: None,
            artifact_sha256: candidate.archive_sha256.clone(),
        };
    let fallback_cancellation = CancellationToken::default();
    let provider_limits =
        brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackLimits::default();
    let provider_context =
        crate::analyzer::python::runtime_provider::PythonRuntimeProviderContext {
            store: &store,
            publication,
            workspace_root: analyzer.project().root(),
            limits: &provider_limits,
            cancellation: cancellation.unwrap_or(&fallback_cancellation),
        };
    let binding = match provider_context.checked_environment(candidate.environment_id) {
        Ok(checked) => resolve_binding(
            active_snapshot.active_models(),
            &selected_evidence,
            imported.module,
            imported.member,
            file.rel_path(),
            &publication.snapshot,
            Some(&checked.condition_snapshot()),
        ),
        Err(error) => Err(
            crate::analyzer::python::runtime_binding::PythonRuntimeBindingError::Incomplete(vec![
                crate::analyzer::python::runtime_binding::PythonRuntimeBindingDiagnostic {
                    code: "python.runtime_binding.environment_incomplete",
                    message: format!("{error:?}"),
                },
            ]),
        ),
    };
    let binding = match binding {
        Ok(_) if cancellation.is_some_and(CancellationToken::is_cancelled) => {
            return PythonRuntimeBindingAttempt::Cancelled;
        }
        Ok(binding) => binding,
        Err(_) if cancellation.is_some_and(CancellationToken::is_cancelled) => {
            return PythonRuntimeBindingAttempt::Cancelled;
        }
        Err(
            crate::analyzer::python::runtime_binding::PythonRuntimeBindingError::NotClassOrModuleValue,
        ) => return PythonRuntimeBindingAttempt::Unavailable,
        Err(error) => {
            return PythonRuntimeBindingAttempt::Failed(PythonRuntimeBindingFailure::Binding(
                error,
            ));
        }
    };

    let mut provider = Err(
        brokk_bifrost_analysis::analyzer::store::StoreError::stale_resolution(
            "Python defining binding touched no import module",
        ),
    );
    let mut provider_environment = None;
    for module in binding.touched_modules() {
        let checked = provider_context.verify_selected_provider(
            file.rel_path(),
            module,
            &binding,
            &selected_evidence,
        );
        match checked {
            Ok(checked)
                if provider_environment
                    .is_none_or(|environment| environment == checked.environment_id()) =>
            {
                provider_environment = Some(checked.environment_id());
                provider = Ok(checked);
            }
            Ok(checked) => {
                provider = Err(
                    brokk_bifrost_analysis::analyzer::store::StoreError::stale_resolution(format!(
                        "Python touched modules resolved through different environments: {} and {}",
                        provider_environment.expect("an earlier touched module was checked"),
                        checked.environment_id()
                    )),
                );
                break;
            }
            Err(error) => {
                if cancellation.is_some_and(CancellationToken::is_cancelled) {
                    return PythonRuntimeBindingAttempt::Cancelled;
                }
                provider = Err(error);
                break;
            }
        }
    }
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return PythonRuntimeBindingAttempt::Cancelled;
    }
    match provider {
        Ok(provider) => {
            PythonRuntimeBindingAttempt::Resolved(Box::new(PythonRuntimeBindingAndProvider {
                binding,
                provider,
            }))
        }
        Err(error) => PythonRuntimeBindingAttempt::Failed(
            PythonRuntimeBindingFailure::ProviderVerification(error.to_string()),
        ),
    }
}

fn python_class_symbol_from_binding(
    analyzer: &dyn IAnalyzer,
    binding: &crate::analyzer::python::runtime_binding::PythonDefiningBinding,
    provider: &crate::analyzer::python::runtime_binding::PythonRuntimeProviderProof,
) -> Result<brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbol, String> {
    if binding.value_identity().is_some() {
        return python_module_value_symbol_from_binding(analyzer, binding, provider);
    }
    use brokk_bifrost_analysis::analyzer::semantic_model::{
        Locator, SemanticModelOriginKind, SemanticModelProof, SemanticModelSymbolKind, TypeKind,
    };

    let Some(identity) = binding.class_identity() else {
        return Err("Python defining binding is callable, not a class object".to_owned());
    };
    if identity.native_declaration_id().is_empty()
        || identity.portable_symbol().is_empty()
        || binding.artifact() != provider.artifact()
        || binding.source_path() != provider.source_path()
        || binding.snapshot() != provider.snapshot()
    {
        return Err("Python class identity and installed-provider evidence disagree".to_owned());
    }
    let Some(active_snapshot) = analyzer.active_semantic_model_snapshot() else {
        return Err("active Python semantic-model snapshot is unavailable".to_owned());
    };
    if active_snapshot
        .python_runtime()
        .is_none_or(|publication| publication.snapshot != *binding.snapshot())
    {
        return Err("active Python provider publication changed during lookup".to_owned());
    }
    let Some(overlay) = active_snapshot.semantic_model_overlay() else {
        return Err("active Python declaration overlay is unavailable".to_owned());
    };
    let modeled = overlay.symbols_with_id(identity.native_declaration_id());
    if modeled.disposition
        != brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
        || modeled.records.len() != 1
    {
        return Err(format!(
            "native Python class identity did not select one overlay symbol: {:?}",
            modeled.disposition
        ));
    }
    let symbol = modeled.records[0];
    let active_models = active_snapshot.active_models();
    let mut matching_declarations = Vec::new();
    for shard in active_models.shards().iter().filter(|shard| {
        shard.manifest.content_sha256 == binding.model_manifest_sha256()
            && shard
                .matching_evidence
                .iter()
                .any(|evidence| evidence == provider.evidence())
    }) {
        let Some((types, _, _)) = shard.shard.payload().declaration_facts() else {
            continue;
        };
        for declaration in types
            .iter()
            .filter(|declaration| declaration.id == identity.native_declaration_id())
        {
            let Locator::Interchange {
                symbol: portable_symbol,
                identity: portable_identity,
                ..
            } = &declaration.locator
            else {
                continue;
            };
            if declaration.type_kind == TypeKind::Class
                && portable_symbol == identity.portable_symbol()
                && brokk_bifrost_semantic::analyzer::semantic_model::csmi::python::validate_identity(
                    portable_identity,
                )
                .is_ok()
                && brokk_bifrost_semantic::analyzer::semantic_model::csmi::python::native_id(portable_identity)
                    == declaration.id
            {
                matching_declarations.push((shard, declaration));
            }
        }
    }
    if matching_declarations.len() != 1 {
        let candidates = matching_declarations
            .iter()
            .map(|(shard, declaration)| {
                (
                    shard.manifest.content_sha256.as_str(),
                    shard.shard.shard_id(),
                    shard.source_id.as_str(),
                    declaration.id.as_str(),
                )
            })
            .collect::<Vec<_>>();
        return Err(format!(
            "native Python class identity did not select one checked active manifest declaration record: {candidates:?}"
        ));
    }
    let (native_shard, native_declaration) = matching_declarations[0];
    if symbol.language != "python"
        || symbol.kind != SemanticModelSymbolKind::Class
        || symbol.provenance.ambiguous
        || symbol.provenance.origin != SemanticModelOriginKind::DeclarativeModel
        || symbol.provenance.proof != SemanticModelProof::ExactArtifact
        || symbol.locator_symbol.as_deref() != Some(identity.portable_symbol())
        || symbol.qualified_name != binding.canonical().join(".")
        || symbol.provenance.active_model_set_hash != active_models.active_model_set_hash()
        || symbol.provenance.pack_id != native_shard.manifest.pack_id
        || symbol.provenance.pack_digest != native_shard.manifest.semantic_sha256
        || symbol.provenance.pack_version != native_shard.manifest.version
        || symbol.provenance.producer != native_shard.manifest.producer.name
        || symbol.provenance.producer_version != native_shard.manifest.producer.version
        || symbol.provenance.record_id != native_declaration.id
        || symbol.provenance.activation.status != "active"
        || symbol.provenance.activation.source_id != native_shard.source_id
        || !python_model_symbol_matches_provider(symbol, provider.evidence())
    {
        return Err(format!(
            "native Python class identity does not match the checked model publication: {}",
            symbol.id
        ));
    }
    Ok(symbol.clone())
}

fn python_module_value_symbol_from_binding(
    analyzer: &dyn IAnalyzer,
    binding: &crate::analyzer::python::runtime_binding::PythonDefiningBinding,
    provider: &crate::analyzer::python::runtime_binding::PythonRuntimeProviderProof,
) -> Result<brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbol, String> {
    use brokk_bifrost_analysis::analyzer::semantic_model::{
        Locator, MemberKind, SemanticModelOriginKind, SemanticModelProof, SemanticModelSymbolKind,
        TypeKind,
    };

    let Some(identity) = binding.value_identity() else {
        return Err("Python defining binding is not a module-level value".to_owned());
    };
    if identity.native_declaration_id().is_empty()
        || identity.portable_symbol().is_empty()
        || binding.artifact() != provider.artifact()
        || binding.source_path() != provider.source_path()
        || binding.snapshot() != provider.snapshot()
    {
        return Err("Python module-value identity and installed-provider evidence disagree".into());
    }
    let Some(active_snapshot) = analyzer.active_semantic_model_snapshot() else {
        return Err("active Python semantic-model snapshot is unavailable".to_owned());
    };
    if active_snapshot
        .python_runtime()
        .is_none_or(|publication| publication.snapshot != *binding.snapshot())
    {
        return Err("active Python provider publication changed during lookup".to_owned());
    }
    let Some(overlay) = active_snapshot.semantic_model_overlay() else {
        return Err("active Python declaration overlay is unavailable".to_owned());
    };
    let modeled = overlay.symbols_with_id(identity.native_declaration_id());
    if modeled.disposition
        != brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
        || modeled.records.len() != 1
    {
        return Err(format!(
            "native Python module-value identity did not select one overlay symbol: {:?}",
            modeled.disposition
        ));
    }
    let symbol = modeled.records[0];
    let active_models = active_snapshot.active_models();
    let mut matching_declarations = Vec::new();
    for shard in active_models.shards().iter().filter(|shard| {
        shard.manifest.content_sha256 == binding.model_manifest_sha256()
            && shard
                .matching_evidence
                .iter()
                .any(|evidence| evidence == provider.evidence())
    }) {
        let Some((types, members, _)) = shard.shard.payload().declaration_facts() else {
            continue;
        };
        for member in members
            .iter()
            .filter(|member| member.id == identity.native_declaration_id())
        {
            let Some((_, module_segments)) = binding.canonical().split_last() else {
                return Err("Python module-value identity has no owner path".to_owned());
            };
            if module_segments.is_empty() {
                return Err("Python module-value identity has no owner path".to_owned());
            }
            let module_name = module_segments.join(".");
            let Locator::Interchange {
                symbol: portable_symbol,
                identity: portable_identity,
                ..
            } = &member.locator
            else {
                continue;
            };
            let module_owner = types.iter().any(|owner| {
                owner.id == member.owner
                    && owner.type_kind == TypeKind::Module
                    && owner.name == module_name
            });
            if member.member_kind == MemberKind::Field
                && member.value_type.is_some()
                && module_owner
                && portable_symbol == identity.portable_symbol()
                && brokk_bifrost_semantic::analyzer::semantic_model::csmi::python::validate_identity(
                    portable_identity,
                )
                .is_ok()
                && brokk_bifrost_semantic::analyzer::semantic_model::csmi::python::native_id(portable_identity)
                    == member.id
            {
                matching_declarations.push((shard, member));
            }
        }
    }
    if matching_declarations.len() != 1 {
        let candidates = matching_declarations
            .iter()
            .map(|(shard, member)| {
                (
                    shard.manifest.content_sha256.as_str(),
                    shard.shard.shard_id(),
                    shard.source_id.as_str(),
                    member.id.as_str(),
                )
            })
            .collect::<Vec<_>>();
        return Err(format!(
            "native Python module-value identity did not select one checked active manifest declaration record: {candidates:?}"
        ));
    }
    let (native_shard, native_declaration) = matching_declarations[0];
    if symbol.language != "python"
        || symbol.kind != SemanticModelSymbolKind::Field
        || symbol.provenance.ambiguous
        || symbol.provenance.origin != SemanticModelOriginKind::DeclarativeModel
        || symbol.provenance.proof != SemanticModelProof::ExactArtifact
        || symbol.locator_symbol.as_deref() != Some(identity.portable_symbol())
        || symbol.qualified_name != binding.canonical().join(".")
        || symbol.owner_id.as_deref() != Some(native_declaration.owner.as_str())
        || symbol.provenance.active_model_set_hash != active_models.active_model_set_hash()
        || symbol.provenance.pack_id != native_shard.manifest.pack_id
        || symbol.provenance.pack_digest != native_shard.manifest.semantic_sha256
        || symbol.provenance.pack_version != native_shard.manifest.version
        || symbol.provenance.producer != native_shard.manifest.producer.name
        || symbol.provenance.producer_version != native_shard.manifest.producer.version
        || symbol.provenance.record_id != native_declaration.id
        || symbol.provenance.activation.status != "active"
        || symbol.provenance.activation.source_id != native_shard.source_id
        || !python_model_symbol_matches_provider(symbol, provider.evidence())
    {
        return Err(format!(
            "native Python module-value identity does not match the checked model publication: {}",
            symbol.id
        ));
    }
    Ok(symbol.clone())
}

fn python_model_symbol_matches_provider(
    symbol: &brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbol,
    evidence: &brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelActivationEvidence,
) -> bool {
    use brokk_bifrost_analysis::analyzer::semantic_model::{
        CatalogCoordinate, SemanticModelMatchedCoordinate,
    };

    fn coordinate_matches(
        matched: Option<&SemanticModelMatchedCoordinate>,
        expected: Option<&CatalogCoordinate>,
    ) -> bool {
        match (matched, expected) {
            (None, None) => true,
            (Some(matched), Some(expected)) => {
                matched.name == expected.name
                    && match &expected.version {
                        None => matched.version.is_none(),
                        Some(version) => {
                            matched.version.as_deref() == Some(version.to_string().as_str())
                        }
                    }
            }
            _ => false,
        }
    }

    let matched = &symbol.provenance.activation.matched_evidence;
    matched.language == evidence.language
        && matched.ecosystem == evidence.ecosystem
        && coordinate_matches(matched.package.as_ref(), evidence.package.as_ref())
        && coordinate_matches(matched.module.as_ref(), evidence.module.as_ref())
        && coordinate_matches(matched.toolchain.as_ref(), evidence.toolchain.as_ref())
        && matched.target == evidence.target
        && matched.configuration == evidence.configuration
        && matched.artifact_sha256 == evidence.artifact_sha256
}

pub(crate) fn definition_value_identity(
    analyzer: &dyn IAnalyzer,
    request: &DefinitionLookupRequest,
    file: &ProjectFile,
    source: &str,
    cancellation: Option<&CancellationToken>,
) -> Option<ResolvedValueIdentity> {
    python_external_value_identity_at_range(analyzer, request, file, source, cancellation).or_else(
        || python_attribute_value_identity_at_range(analyzer, request, file, source, cancellation),
    )
}

fn python_attribute_value_identity_at_range(
    analyzer: &dyn IAnalyzer,
    request: &DefinitionLookupRequest,
    file: &ProjectFile,
    source: &str,
    cancellation: Option<&CancellationToken>,
) -> Option<ResolvedValueIdentity> {
    let (start_byte, end_byte) = (request.start_byte?, request.end_byte?);
    let python = resolve_analyzer::<PythonAnalyzer>(analyzer)?;
    let (terminal_start_byte, terminal_end_byte) =
        crate::analyzer::python::python_attribute_value_terminal_range(
            python, file, source, start_byte, end_byte,
        )?;
    let terminal_request = DefinitionLookupRequest {
        file: file.clone(),
        line: None,
        column: None,
        start_byte: Some(terminal_start_byte),
        end_byte: Some(terminal_end_byte),
    };
    let outcome = if let Some(cancellation) = cancellation {
        resolve_definition_batch_with_source_and_cancellation(
            analyzer,
            vec![terminal_request],
            file.clone(),
            Arc::<str>::from(source),
            cancellation,
        )
    } else {
        resolve_definition_batch_with_source(
            analyzer,
            vec![terminal_request],
            file.clone(),
            Arc::<str>::from(source),
        )
    }
    .into_iter()
    .next()?;
    if outcome.status != DefinitionLookupStatus::Resolved {
        return None;
    }
    let mut definitions = outcome.definitions;
    definitions.sort_by_key(|definition| definition.declaration_id());
    definitions.dedup_by(|left, right| left.declaration_id() == right.declaration_id());
    let mut modeled = outcome.modeled_definitions;
    modeled.sort_by(|left, right| left.id.cmp(&right.id));
    modeled.dedup_by(|left, right| left.id == right.id);
    match (definitions.as_slice(), modeled.as_slice()) {
        ([definition], []) => Some(ResolvedValueIdentity {
            kind: ResolvedValueIdentityKind::WorkspaceDeclaration,
            identity: definition.declaration_id().to_string(),
            aliases: Vec::new(),
        }),
        ([], [symbol]) if exact_semantic_model_value_identity(symbol) => {
            Some(ResolvedValueIdentity {
                kind: ResolvedValueIdentityKind::ActiveSemanticModel,
                identity: symbol.id.clone(),
                aliases: symbol.aliases.clone(),
            })
        }
        _ => None,
    }
}

fn python_external_value_identity_at_range(
    analyzer: &dyn IAnalyzer,
    request: &DefinitionLookupRequest,
    file: &ProjectFile,
    source: &str,
    cancellation: Option<&CancellationToken>,
) -> Option<ResolvedValueIdentity> {
    let (start_byte, end_byte) = (request.start_byte?, request.end_byte?);
    let scope = AnalyzerQueryScope::new(analyzer);
    let python = resolve_analyzer::<PythonAnalyzer>(analyzer)?;
    let resolution = python_external_imported_symbol_at_range_bounded(
        python,
        scope.token(),
        file,
        source,
        start_byte,
        end_byte,
        cancellation,
    );
    let (module, member) = match resolution {
        BoundedResolution::Complete {
            value: Some((module, member)),
            ..
        } => (module, member),
        BoundedResolution::Complete { value: None, .. }
        | BoundedResolution::Exceeded { .. }
        | BoundedResolution::Cancelled { .. } => return None,
    };
    let external = format!("{module}.{member}");
    let overlay = analyzer.semantic_model_overlay()?;
    let matched = overlay.symbols_named(&external);
    if matched.disposition
        != brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
    {
        return None;
    }
    let [symbol] = matched.records.as_slice() else {
        return None;
    };
    if symbol.qualified_name != external
        || symbol.language != Language::Python.config_label()
        || !exact_semantic_model_value_identity(symbol)
    {
        return None;
    }
    Some(ResolvedValueIdentity {
        kind: ResolvedValueIdentityKind::ActiveSemanticModel,
        identity: symbol.id.clone(),
        aliases: symbol.aliases.clone(),
    })
}

pub(crate) fn definition_tree(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    language: Language,
    source: &str,
) -> Option<Tree> {
    // Reuse only the exact analyzer snapshot matching the caller's source.
    if let Some(py) = resolve_analyzer::<PythonAnalyzer>(analyzer)
        && let Some(prepared) = py.prepared_syntax(token, file)
        && prepared.source() == source
    {
        return Some(prepared.tree().clone());
    }
    parse_tree_for_language(file, language, source)
}

pub(crate) fn release_definition_file(
    context: &mut DefinitionBatchContext<'_, '_>,
    file: &ProjectFile,
) {
    context
        .language_state::<PythonDefinitionState>()
        .python_contexts
        .remove(file);
}

#[derive(Default)]
pub(crate) struct PythonDefinitionState {
    python_contexts: HashMap<ProjectFile, Arc<PythonDefinitionContext>>,
}

impl PythonDefinitionState {
    pub(crate) fn python_context(
        &mut self,
        token: QueryToken<'_>,
        py: &PythonAnalyzer,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        source: &str,
    ) -> Arc<python::PythonDefinitionContext> {
        self.python_contexts
            .entry(file.clone())
            .or_insert_with(|| request_definition_context(py, analyzer, token, file, source))
            .clone()
    }

    #[cfg(test)]
    pub(crate) fn python_build_counts(
        &self,
        analyzer: &dyn IAnalyzer,
    ) -> (usize, usize, usize, usize) {
        let py = resolve_analyzer::<PythonAnalyzer>(analyzer).expect("Python analyzer");
        request_definition_build_counts(py)
    }
}

use brokk_bifrost_python::graph::extractor::collect_module_binding_timeline;

use brokk_bifrost_python::graph::extractor::collect_scope_facts_from_parsed_source;

use brokk_bifrost_python::graph::extractor::enclosing_scope_facts;

use brokk_bifrost_python::graph::extractor::is_declaration_identifier as python_is_declaration_identifier;

use brokk_bifrost_python::graph::extractor::slice as python_slice;

use brokk_bifrost_python::graph::resolver::resolve_receiver_type as resolve_python_receiver_type;

use crate::analyzer::usages::python_graph::with_python_graph_source;

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use brokk_bifrost_core::analyzer::pool_memo::KeyedPoolSafeMemo;

use brokk_bifrost_analysis::analyzer::lexical_definitions::PythonMethodBinding;

use brokk_bifrost_analysis::analyzer::lexical_definitions::formal_parameter_slots_for_owner_bounded;

use crate::analyzer::python::lexical_scope::python_lexical_scope_inventory_bounded;

use brokk_bifrost_python::syntax::python_deferred_annotation_identifier_ranges;

use brokk_bifrost_python::syntax::python_node_is_in_annotation;

use brokk_bifrost_core::analyzer::usages::model::ExportEntry;

use brokk_bifrost_core::analyzer::usages::common::same_node;

use brokk_bifrost_analysis::analyzer::usages::target_kind::TypeLookupTargetKind;

use brokk_bifrost_core::analyzer::definition_lookup::BoundedDefinitionLookup;

use brokk_bifrost_core::analyzer::capabilities::ImportAnalysisProvider;

use brokk_bifrost_python::imports::resolve_fqn_candidates;

use brokk_bifrost_python::graph_support::resolve_module_code_unit;

use brokk_bifrost_python::graph_support::retain_modules_for_importer;

use brokk_bifrost_python::usage_index::usage_resolve_module_files;

use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxSource;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path;
use brokk_bifrost_core::path_utils::rel_path_string;
use brokk_bifrost_python::bindings::{
    PythonClassReferenceScope, PythonDirectScopeBindingKind, PythonLexicalNameResolution,
    PythonLexicalScopeBindings, python_comprehension_binds_name_at,
    python_comprehension_binds_name_at_bounded, python_direct_scope_bindings_bounded,
    python_executable_scope_children, python_global_binding_is_untouched_bounded,
    python_type_parameter_binds_name_at, python_type_parameter_binds_name_at_bounded,
    python_unambiguous_module_binding_node_bounded,
    python_unambiguous_module_class_binding_bounded,
};
use brokk_bifrost_python::declarations::python_module_name;
use brokk_bifrost_python::diagnostics::is_python_builtin_or_constant;
use brokk_bifrost_python::graph::extractor::python_first_function_definition;
use brokk_bifrost_python::graph::resolver::annotation_reference_candidates_at_focus;
use brokk_bifrost_python::graph_support::PythonSource;
use brokk_bifrost_python::imports::{
    PythonImportBinding, PythonImportDetails, python_function_scoped_import_binding,
    python_import_bindings_from_imports, python_import_bindings_from_imports_bounded,
    python_import_details, python_import_infos_from_node, python_local_module_alias_path_before,
    resolve_python_relative_module,
};
use brokk_bifrost_python::source_facts::{PythonModuleMutationFacts, PythonSourceFactProvider};
use brokk_bifrost_python::syntax::{
    leftmost_identifier, python_keyword_argument_label, python_reference_is_deferred_function_body,
    python_static_attribute_path, python_static_attribute_path_bounded,
};
use brokk_bifrost_python::usage_index::visible_module_binding_suffix;
use std::cell::Cell;
use std::sync::Mutex;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

const PYTHON_RECEIVER_TYPE_CACHE_LIMIT: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PythonDefinitionContextKey {
    // The request memo lives on one Python analyzer generation. The remaining
    // identity axes distinguish exact-source calls and concurrent query
    // contexts that selected different semantic-model publications.
    file: ProjectFile,
    source: brokk_bifrost_analysis::analyzer::semantic::StableDigest,
    semantic_overlay: Option<Box<str>>,
}

struct Replayable<T> {
    value: T,
    reads: Arc<brokk_bifrost_analysis::analyzer::read_ledger::ReadLedger>,
}

#[derive(Default)]
pub(crate) struct PythonDefinitionContextRequestMemo {
    contexts:
        KeyedPoolSafeMemo<PythonDefinitionContextKey, Replayable<Arc<PythonDefinitionContext>>>,
    #[cfg(test)]
    build_counters: Arc<PythonDefinitionBuildCounters>,
}

fn definition_context_key(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    prepared: Option<&brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree>,
) -> PythonDefinitionContextKey {
    let semantic_overlay = analyzer
        .semantic_model_overlay()
        .map(|overlay| Box::<str>::from(overlay.active_model_set_hash()));
    let source = match prepared {
        Some(prepared) if prepared.source().as_bytes() == source.as_bytes() => {
            brokk_bifrost_analysis::analyzer::semantic::StableDigest::from_array(
                prepared.source_sha256(),
            )
        }
        _ => brokk_bifrost_analysis::analyzer::semantic::StableDigest::sha256(source),
    };
    PythonDefinitionContextKey {
        file: file.clone(),
        source,
        semantic_overlay,
    }
}

pub(crate) fn request_definition_context(
    py: &PythonAnalyzer,
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
) -> Arc<PythonDefinitionContext> {
    let prepared = py.prepared_syntax(token, file);
    let key = definition_context_key(analyzer, file, source, prepared.as_deref());
    let memo = py
        .active_query_request_memo::<PythonDefinitionContextRequestMemo>()
        .expect("Python definition context requires an active query scope");
    let cell = memo.contexts.cell(&key);
    let built_here = Cell::new(false);
    let entry = cell.get_or_build_pool_independent(|| {
        built_here.set(true);
        let _scope = brokk_bifrost_core::profiling::scope("get_definition::python::batch_context");
        #[cfg(test)]
        memo.build_counters
            .context_builds
            .fetch_add(1, Ordering::Relaxed);
        let (context, reads) =
            brokk_bifrost_analysis::analyzer::i_analyzer::capture_query_reads(analyzer, || {
                PythonDefinitionContext::build(
                    py,
                    analyzer,
                    token,
                    file,
                    #[cfg(test)]
                    Arc::clone(&memo.build_counters),
                )
            });
        Replayable {
            value: Arc::new(context),
            reads,
        }
    });
    if !built_here.get() {
        brokk_bifrost_analysis::analyzer::i_analyzer::replay_query_reads(analyzer, &entry.reads);
    }
    Arc::clone(&entry.value)
}

#[cfg(test)]
pub(crate) fn request_definition_build_counts(py: &PythonAnalyzer) -> (usize, usize, usize, usize) {
    let counters = &py
        .active_query_request_memo::<PythonDefinitionContextRequestMemo>()
        .expect("Python definition build counts require an active query scope")
        .build_counters;
    (
        counters.context_builds.load(Ordering::Relaxed),
        counters.scope_fact_builds.load(Ordering::Relaxed),
        counters.receiver_type_cache_misses.load(Ordering::Relaxed),
        counters
            .generic_receiver_type_fallbacks
            .load(Ordering::Relaxed),
    )
}

#[cfg(test)]
pub(crate) fn request_definition_cached_read_keys(
    py: &PythonAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
) -> Vec<ReadKey> {
    let memo = py
        .active_query_request_memo::<PythonDefinitionContextRequestMemo>()
        .expect("Python definition cached reads require an active query scope");
    let key = definition_context_key(analyzer, file, source, None);
    let cell = memo.contexts.cell(&key);
    let entry = cell
        .get_or_build_pool_independent(|| panic!("Python definition context was not initialized"));
    let mut reads = entry.reads.keys();
    if let Some(scope_facts) = entry.value.scope_facts.get() {
        reads.extend(scope_facts.reads.keys());
    }
    for receiver in entry
        .value
        .receiver_types
        .lock()
        .expect("Python receiver type cache mutex poisoned")
        .values
        .values()
    {
        reads.extend(receiver.reads.keys());
    }
    reads.sort();
    reads.dedup();
    reads
}

/// Complete syntax facts live for one active query, or one provider when no
/// outer query exists. Owners and selected reads are deliberately not cached.
#[derive(Default)]
struct PythonModuleMutationRequestMemo {
    facts: Mutex<HashMap<[u8; 32], Arc<PythonModuleMutationFacts>>>,
    #[cfg(test)]
    collections: AtomicUsize,
}

impl PythonModuleMutationRequestMemo {
    fn facts(
        &self,
        prepared: &brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree,
        session: &ResolutionSession,
    ) -> Option<Arc<PythonModuleMutationFacts>> {
        if !session.scope_step() {
            return None;
        }
        let key = prepared.source_sha256();
        let cached = self
            .facts
            .lock()
            .expect("module mutation memo lock poisoned")
            .get(&key)
            .cloned();
        if let Some(cached) = cached {
            return session.scope_step().then_some(cached);
        }
        #[cfg(test)]
        self.collections.fetch_add(1, Ordering::Relaxed);
        // Collection never holds the map lock and uses this caller's session.
        let collected = Arc::new(PythonModuleMutationFacts::collect_bounded(
            prepared.tree().root_node(),
            prepared.source(),
            || session.scope_step(),
        )?);
        if !session.scope_step() {
            return None;
        }
        let facts = {
            let mut facts = self
                .facts
                .lock()
                .expect("module mutation memo lock poisoned");
            // A concurrent fill cannot repair this caller's stop while waiting.
            if !session.scope_step() {
                return None;
            }
            Arc::clone(facts.entry(key).or_insert(collected))
        };
        session.scope_step().then_some(facts)
    }
}

pub(crate) struct PythonDefinitionProvider<'a> {
    python: &'a PythonAnalyzer,
    session: &'a ResolutionSession,
    source_facts_unavailable: Cell<bool>,
    module_mutations: Arc<PythonModuleMutationRequestMemo>,
}

impl<'a> PythonDefinitionProvider<'a> {
    pub(crate) fn new(python: &'a PythonAnalyzer, session: &'a ResolutionSession) -> Self {
        Self {
            python,
            session,
            source_facts_unavailable: Cell::new(false),
            // Choose once, before nested per-base scopes can change the registry.
            module_mutations: python
                .active_query_request_memo::<PythonModuleMutationRequestMemo>()
                .unwrap_or_else(|| Arc::new(PythonModuleMutationRequestMemo::default())),
        }
    }

    pub(crate) fn analyzer(&self) -> &PythonAnalyzer {
        self.python
    }

    pub(crate) fn session(&self) -> &ResolutionSession {
        self.session
    }

    pub(crate) fn source_facts_unavailable(&self) -> bool {
        self.source_facts_unavailable.get()
    }

    fn module_mutation_owner_syntax(
        &self,
        file: &ProjectFile,
        source: &str,
    ) -> Option<Arc<brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree>> {
        if !self.scope_step() {
            return None;
        }
        let scope = AnalyzerQueryScope::new(self.python);
        // This read occurs for every owner, including byte-identical memo hits.
        let prepared = self
            .session
            .query(|| self.python.prepared_syntax(scope.token(), file))??;
        if prepared.source() != source || !self.python.indexed_source_matches(file, source) {
            return None;
        }
        self.scope_step().then_some(prepared)
    }

    pub(crate) fn module_binding_unmutated_at_bounded(
        &self,
        file: &ProjectFile,
        prepared: &brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree,
        name: &str,
        reference: Node<'_>,
    ) -> Option<bool> {
        self.module_binding_unmutated_from_source_bounded(
            file,
            prepared.tree().root_node(),
            prepared.source(),
            name,
            reference,
        )
    }

    fn module_binding_unmutated_from_source_bounded(
        &self,
        file: &ProjectFile,
        root: Node<'_>,
        source: &str,
        name: &str,
        reference: Node<'_>,
    ) -> Option<bool> {
        let prepared = self.module_mutation_owner_syntax(file, source)?;
        let facts = self.module_mutations.facts(&prepared, self.session)?;
        let answer =
            facts.binding_unmutated_at_bounded(root, name, reference, || self.scope_step())?;
        if !self.python.indexed_source_matches(file, source) {
            return None;
        }
        self.scope_step().then_some(answer)
    }

    /// Syntax-only builtin callers already own their current prepared read.
    /// This does not establish a workspace class or an exported owner identity.
    pub(crate) fn module_binding_unmutated_in_prepared_bounded(
        &self,
        prepared: &brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree,
        name: &str,
        reference: Node<'_>,
    ) -> Option<bool> {
        let facts = self.module_mutations.facts(prepared, self.session)?;
        let answer = facts.binding_unmutated_at_bounded(
            prepared.tree().root_node(),
            name,
            reference,
            || self.scope_step(),
        )?;
        self.scope_step().then_some(answer)
    }

    fn module_export_unmutated_bounded(
        &self,
        file: &ProjectFile,
        prepared: &brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree,
        name: &str,
    ) -> Option<bool> {
        let source = prepared.source();
        let current = self.module_mutation_owner_syntax(file, source)?;
        let facts = self.module_mutations.facts(&current, self.session)?;
        let answer = facts.export_unmutated_bounded(name, || self.scope_step())?;
        if !self.python.indexed_source_matches(file, source) {
            return None;
        }
        self.scope_step().then_some(answer)
    }

    fn callable_source_facts(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Option<Arc<brokk_bifrost_python::source_facts::PythonFileSourceFacts>> {
        let facts = self.session.query(|| {
            self.python
                .python_source_facts(token, file, &|| self.scope_step())
        })?;
        if facts.is_none() {
            self.source_facts_unavailable.set(true);
        }
        facts
    }

    pub(crate) fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        let units = self.session.query_limited_rows(|limit| {
            self.python
                .declaration_candidates_by_fqn_limited(fqn, limit, || {
                    self.session.observe_cancellation()
                })
        });
        brokk_bifrost_core::analyzer::definition_lookup::sort_dedup_units(units)
    }

    pub(crate) fn identifier(&self, identifier: &str) -> Vec<CodeUnit> {
        let units = self.session.query_limited_rows(|limit| {
            self.python
                .declaration_candidates_by_identifier_limited(identifier, limit, || {
                    self.session.observe_cancellation()
                })
        });
        brokk_bifrost_core::analyzer::definition_lookup::sort_dedup_units(units)
    }

    pub(crate) fn file_identifier(&self, file: &ProjectFile, identifier: &str) -> Vec<CodeUnit> {
        self.identifier(identifier)
            .into_iter()
            .filter(|unit| unit.source() == file)
            .collect()
    }

    /// Resolve one module identity through the request session. The source
    /// module surface is path-backed. An incomplete bounded path query must
    /// remain a session stop, not launch an allocating definition fallback.
    ///
    /// `importer` is the file whose import named `module`. Two sibling source
    /// roots can spell one module name, so the root that owns the importer is
    /// what says which of them its import means (#3475); a module no
    /// containing root owns keeps every candidate and therefore no unique
    /// identity, which is the honest answer for an interactive lookup.
    fn module_code_unit(&self, importer: &ProjectFile, module: &str) -> Option<CodeUnit> {
        let mut candidates = self.module_candidates(module);
        retain_modules_for_importer(
            self.python.project(),
            importer,
            &mut candidates,
            CodeUnit::source,
        );
        let candidate = unique_python_candidate(candidates)?;
        candidate.is_module().then_some(candidate)
    }

    fn module_candidates(&self, module: &str) -> Vec<CodeUnit> {
        self.session.query_limited_rows(|limit| {
            self.python
                .module_candidates_by_fqn_limited(module, limit, || {
                    self.session.observe_cancellation()
                })
        })
    }

    pub(crate) fn members_for_owner(&self, owner: &CodeUnit, name: &str) -> Vec<CodeUnit> {
        brokk_bifrost_analysis::analyzer::usages::get_definition::query_limited_definition_units(
            self.session,
            |limit| {
                self.python
                    .member_candidates_for_owner_limited(owner, name, limit, || {
                        self.session.observe_cancellation()
                    })
            },
        )
    }

    pub(crate) fn ranges(&self, unit: &CodeUnit) -> Vec<Range> {
        self.session
            .query_limited_rows(|limit| self.python.ranges_limited(unit, limit))
    }

    /// The import bindings `file` declares, charged as one indexed query.
    fn import_binder(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Option<Arc<ImportBinder>> {
        self.session
            .query(|| self.python.import_binder_of(token, file))
    }

    fn scope_step(&self) -> bool {
        self.session.scope_step()
    }
}

#[derive(Debug, Clone)]
pub(crate) enum PythonTypeLookupTarget {
    Workspace(CodeUnit),
    External { qualified_name: String },
}

#[derive(Debug, Clone)]
pub(crate) struct PythonTypeLookupResolution {
    pub(crate) target: PythonTypeLookupTarget,
    pub(crate) target_kind: TypeLookupTargetKind,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_python_bounded(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<DefinitionLookupOutcome> {
    let session = ResolutionSession::bounded(budget, cancellation);
    let Some(python) = resolve_analyzer::<PythonAnalyzer>(analyzer) else {
        return session.finish(no_definition(
            "python_analyzer_unavailable",
            "Python analyzer is unavailable",
        ));
    };
    let Some(tree) = tree else {
        return session.finish(no_definition(
            "python_parse_failed",
            "Python source could not be parsed",
        ));
    };
    let support = PythonDefinitionProvider::new(python, &session);
    let Some(node) = python_smallest_named_node_covering_bounded(
        &support,
        tree.root_node(),
        site.focus_start_byte,
        site.focus_end_byte,
    ) else {
        return session.finish(no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed Python definition",
                site.text
            ),
        ));
    };
    if let Some(module_fqn) = python_import_module_fqn(python.project(), file, source, node)
        && let Some(Some(module)) =
            session.query(|| resolve_module_code_unit(python, Some(file), &module_fqn))
    {
        return session.finish(candidates_outcome(vec![module]));
    }
    if python_is_non_reference_context(node) || python_is_declaration_identifier(node) {
        return session.finish(no_definition(
            "declaration_or_import_site",
            format!("`{}` is not a Python reference site", site.text),
        ));
    }
    let outcome = match python_reference_node_bounded(&support, node) {
        Some(PythonReferenceNode::Attribute { object, attribute }) => {
            let member = python_slice(attribute, source);
            let receiver = python_type_for_expression_bounded(
                &support,
                token,
                file,
                source,
                tree.root_node(),
                object,
                0,
            );
            match receiver {
                Some(receiver) if !member.is_empty() => {
                    let candidates = support.members_for_owner(&receiver, member);
                    if candidates.is_empty() {
                        no_definition(
                            "no_indexed_definition",
                            format!(
                                "`{}.{member}` is not indexed as a Python definition",
                                receiver.fq_name()
                            ),
                        )
                    } else {
                        // Found by asking the index for `<receiver fq>.<member>`,
                        // so the receiver is the owner and the walk took no
                        // hierarchy hop (#1477). This seam has no ancestor walk
                        // at all, so an inherited member never reaches it.
                        let mut attribution = PythonMemberAttribution::default();
                        attribution.record_direct(&receiver, &candidates);
                        attribution.stage();
                        candidates_outcome(candidates)
                    }
                }
                _ => no_definition(
                    "python_dynamic_receiver",
                    format!(
                        "`{}` has no structurally proven Python receiver type",
                        site.text
                    ),
                ),
            }
        }
        Some(PythonReferenceNode::Identifier(identifier)) => {
            let Some(name) = python_focused_reference_text(
                identifier,
                source,
                site.focus_start_byte,
                site.focus_end_byte,
                cancellation,
            ) else {
                return session.finish(no_definition(
                    "python_reference_shape_unsupported",
                    format!("`{}` is not a parsed Python reference", site.text),
                ));
            };
            let candidates = support.file_identifier(file, name);
            if candidates.is_empty() {
                no_definition(
                    "no_indexed_definition",
                    format!("`{name}` did not resolve to an indexed Python definition"),
                )
            } else {
                candidates_outcome(candidates)
            }
        }
        Some(PythonReferenceNode::KeywordArgument { .. }) | None => no_definition(
            "python_reference_shape_unsupported",
            format!(
                "`{}` is not a supported bounded Python reference shape",
                site.text
            ),
        ),
    };
    if support.source_facts_unavailable() {
        return session.finish(no_definition(
            "python_source_facts_unavailable",
            "Canonical Python declaration annotations are unavailable",
        ));
    }
    session.finish(outcome)
}

pub(crate) fn python_type_lookup_resolution_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
) -> Option<PythonTypeLookupResolution> {
    let node = python_smallest_named_node_covering_bounded(
        support,
        root,
        site.focus_start_byte,
        site.focus_end_byte,
    )?;
    let expression = python_type_expression_node_bounded(support, node)?;
    let target_kind = if expression.kind() == "identifier"
        && !python_has_lexical_binding_bounded(support, expression, source)
        && python_class_candidate_for_name(
            support,
            token,
            file,
            source,
            expression,
            python_slice(expression, source),
        )
        .is_some()
    {
        TypeLookupTargetKind::TypeReference
    } else {
        TypeLookupTargetKind::ValueExpression
    };
    if let Some(qualified_name) =
        python_external_class_reference_fqn_bounded(support, token, file, source, root, expression)
    {
        return Some(PythonTypeLookupResolution {
            target: PythonTypeLookupTarget::External { qualified_name },
            target_kind,
        });
    }
    let unit =
        python_type_for_expression_bounded(support, token, file, source, root, expression, 0)?;
    Some(PythonTypeLookupResolution {
        target: PythonTypeLookupTarget::Workspace(unit),
        target_kind,
    })
}

fn python_external_class_reference_fqn_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
) -> Option<String> {
    let reference = if expression.kind() == "call" {
        expression.child_by_field_name("function")?
    } else {
        expression
    };
    let (module, member) =
        python_external_imported_symbol_bounded(support, token, file, source, root, reference)?;
    let qualified_name = format!("{module}.{member}");
    let overlay = support.python.semantic_model_overlay()?;
    let matched = overlay.symbols_named(&qualified_name);
    matched
        .records
        .iter()
        .any(|symbol| {
            symbol.language == brokk_bifrost_core::analyzer::model::Language::Python.config_label()
                && symbol.owner_id.is_none()
                && symbol.kind == brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbolKind::Class
                && (symbol.qualified_name == qualified_name
                    || symbol.aliases.iter().any(|alias| alias == &qualified_name))
        })
        .then_some(qualified_name)
}

/// The expression whose type the caret asks for.
///
/// A caret on the member of `value.paint` covers the `paint` identifier alone,
/// but the type owed is the attribute expression's, so climb to the outermost
/// `attribute` the caret's node is the member of. A caret on the receiver stays
/// where it is: `value` in `value.paint` still asks for `value`'s own type.
fn python_type_expression_node_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    node: Node<'tree>,
) -> Option<Node<'tree>> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if !support.scope_step() {
            return None;
        }
        if parent.kind() != "attribute" || parent.child_by_field_name("attribute") != Some(current)
        {
            break;
        }
        current = parent;
    }
    Some(current)
}

fn python_smallest_named_node_covering_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    node: Node<'tree>,
    start: usize,
    end: usize,
) -> Option<Node<'tree>> {
    brokk_bifrost_core::analyzer::usages::reference_site::smallest_named_node_covering_with_scope(
        node,
        start,
        end,
        || support.scope_step(),
    )
}

fn python_named_children_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    node: Node<'tree>,
) -> Option<Vec<Node<'tree>>> {
    let mut children = Vec::new();
    let mut cursor = node.walk();
    brokk_bifrost_core::analyzer::tree_walk::push_bounded_nodes(
        node.named_children(&mut cursor),
        &mut children,
        || support.scope_step(),
    )
    .then_some(children)
}

fn python_keyword_argument_with_step<'tree>(
    node: Node<'tree>,
    mut scope_step: impl FnMut() -> bool,
) -> Option<PythonReferenceNode<'tree>> {
    if !scope_step() || node.kind() != "identifier" {
        return None;
    }
    let kwarg = node.parent()?;
    if !scope_step() || !python_keyword_argument_label(node) {
        return None;
    }
    let arguments = kwarg.parent()?;
    if !scope_step() || arguments.kind() != "argument_list" {
        return None;
    }
    let call = arguments.parent()?;
    if !scope_step() || call.kind() != "call" {
        return None;
    }
    Some(PythonReferenceNode::KeywordArgument { call, name: node })
}

fn python_reference_node_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    node: Node<'tree>,
) -> Option<PythonReferenceNode<'tree>> {
    python_reference_node_with_step(node, || support.scope_step())
}

fn python_reference_node_with_step<'tree>(
    node: Node<'tree>,
    mut scope_step: impl FnMut() -> bool,
) -> Option<PythonReferenceNode<'tree>> {
    if let Some(keyword) = python_keyword_argument_with_step(node, &mut scope_step) {
        return Some(keyword);
    }
    if !scope_step() {
        return None;
    }
    let original = node;
    let mut node = node;
    while let Some(parent) = node.parent() {
        if !scope_step() {
            return None;
        }
        if parent.kind() != "attribute" {
            break;
        }
        if parent.child_by_field_name("attribute") == Some(node)
            || parent.child_by_field_name("attribute") == Some(original)
        {
            node = parent;
        } else {
            break;
        }
    }
    match node.kind() {
        "attribute" => {
            let object = node.child_by_field_name("object")?;
            let attribute = node.child_by_field_name("attribute")?;
            Some(PythonReferenceNode::Attribute { object, attribute })
        }
        "identifier" => Some(PythonReferenceNode::Identifier(node)),
        "string_content" if python_node_is_in_annotation(node) => {
            Some(PythonReferenceNode::Identifier(node))
        }
        _ => None,
    }
}

fn python_namespace_imported_class_candidate_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
) -> Option<CodeUnit> {
    let fqn = python_namespace_imported_class_name_bounded(
        support, token, file, source, root, expression,
    )?;
    if let Some(candidate) = unique_python_candidate(
        support
            .fqn(&fqn)
            .into_iter()
            .filter(CodeUnit::is_class)
            .collect(),
    ) {
        return Some(candidate);
    }

    let (module, member) = fqn.rsplit_once('.')?;
    python_imported_class_from_module(support, token, file, module.to_owned(), member.to_owned())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PythonAttributeCalleeKind {
    Class,
    Function,
    Value,
}

/// Classify the declaration named by an attribute call.
///
/// A type lookup answers the same way for three different shapes.
/// `Parameter` in `Holder.Parameter()` names a class, so the lookup's class is
/// what the call constructs. `make` in `Holder().make()` names a method, so
/// the lookup's class is that method's return type. `_regex` in
/// `self._regex()` names a field, so the lookup's class is the class of the
/// stored value; calling it runs that value's `__call__` and produces
/// something else. `None` means the receiver or the member did not resolve.
pub(crate) fn python_attribute_callee_kind_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    callee: Node<'_>,
) -> Option<PythonAttributeCalleeKind> {
    if python_namespace_imported_class_candidate_bounded(support, token, file, source, root, callee)
        .is_some()
    {
        return Some(PythonAttributeCalleeKind::Class);
    }
    let object = callee.child_by_field_name("object")?;
    let member = python_slice(callee.child_by_field_name("attribute")?, source);
    if member.is_empty() {
        return None;
    }
    let receiver =
        python_type_for_expression_bounded(support, token, file, source, root, object, 1)?;
    let declaration = unique_python_candidate(support.members_for_owner(&receiver, member))?;
    Some(if declaration.is_class() {
        PythonAttributeCalleeKind::Class
    } else if declaration.is_function() {
        PythonAttributeCalleeKind::Function
    } else {
        PythonAttributeCalleeKind::Value
    })
}

/// Whether an attribute call uses the conventional Python receiver name.
pub(crate) fn python_attribute_callee_uses_self_or_cls_bounded(
    source: &str,
    callee: Node<'_>,
) -> bool {
    let Some(object) = callee.child_by_field_name("object") else {
        return false;
    };
    object.kind() == "identifier" && matches!(python_slice(object, source), "self" | "cls")
}

/// Whether an attribute callee names a nested class in its enclosing class.
pub(crate) fn python_attribute_callee_names_enclosing_nested_class_bounded(
    source: &str,
    callee: Node<'_>,
) -> bool {
    let Some(attribute) = callee.child_by_field_name("attribute") else {
        return false;
    };
    let name = python_slice(attribute, source);
    let mut ancestor = callee.parent();
    while let Some(node) = ancestor {
        if node.kind() == "class_definition" {
            let Some(body) = node.child_by_field_name("body") else {
                return false;
            };
            let mut cursor = body.walk();
            return body.named_children(&mut cursor).any(|member| {
                member.kind() == "class_definition"
                    && member
                        .child_by_field_name("name")
                        .is_some_and(|class_name| python_slice(class_name, source) == name)
            });
        }
        ancestor = node.parent();
    }
    false
}

/// Whether an attribute callee reads a stored value rather than naming a
/// class or a callable declaration.
pub(crate) fn python_attribute_callee_reads_a_field_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    callee: Node<'_>,
) -> Option<bool> {
    python_attribute_callee_kind_bounded(support, token, file, source, root, callee)
        .map(|kind| kind == PythonAttributeCalleeKind::Value)
}

pub(crate) fn python_namespace_imported_class_name_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
) -> Option<String> {
    let path = python_static_attribute_path_bounded(expression, || support.scope_step())?;
    if path.len() < 2 {
        return None;
    }
    let local_name = python_slice(path[0], source);
    if local_name.is_empty() {
        return None;
    }
    if let Some(module_path) = python_namespace_imported_module_path_bounded(
        support, token, file, source, root, expression,
    ) {
        return Some(module_path.join("."));
    }
    let mut support_context = support;
    let module_path = python_local_module_alias_path_before(
        expression,
        local_name,
        source,
        &mut support_context,
        |module_expression, support| {
            Ok(python_namespace_imported_module_path_bounded(
                support,
                token,
                file,
                source,
                root,
                module_expression,
            ))
        },
        |support| {
            if support.scope_step() {
                Ok(())
            } else {
                Err(())
            }
        },
    )
    .ok()?;
    let mut canonical = module_path?.to_vec();
    canonical.extend(
        path.into_iter()
            .skip(1)
            .map(|attribute| python_slice(attribute, source).to_owned().into_boxed_str()),
    );
    Some(
        canonical
            .iter()
            .map(Box::as_ref)
            .collect::<Vec<_>>()
            .join("."),
    )
}

fn python_namespace_imported_module_path_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
) -> Option<Box<[Box<str>]>> {
    let path = python_static_attribute_path_bounded(expression, || support.scope_step())?;
    let local_name = python_slice(*path.first()?, source);
    if local_name.is_empty()
        || python_namespace_root_shadowed_bounded(support, local_name, expression, source)?
    {
        return None;
    }
    let binder = support.import_binder(token, file)?;
    let binding = binder.bindings.get(local_name)?;
    if binding.kind != ImportKind::Namespace
        || !python_namespace_import_binding_is_unique_bounded(
            support,
            root,
            local_name,
            expression.start_byte(),
            source,
        )?
    {
        return None;
    }
    let mut canonical = binding
        .module_specifier
        .split('.')
        .map(str::to_owned)
        .map(String::into_boxed_str)
        .collect::<Vec<_>>();
    canonical.extend(
        path.into_iter()
            .skip(1)
            .map(|attribute| python_slice(attribute, source).to_owned().into_boxed_str()),
    );
    Some(canonical.into_boxed_slice())
}

/// Prove one imported external symbol's owner and member without requiring a
/// call node. Decorator applications have an implicit argument, so their bare
/// callee must use the same import and shadowing proofs as explicit calls.
pub(crate) fn python_external_imported_symbol_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
) -> Option<(String, String)> {
    if !support.python.indexed_source_matches(file, source) {
        return None;
    }
    if let Some(selected) =
        python_local_imported_symbol_bounded(support, token, file, source, root, expression)?
    {
        return selected
            .external_symbol_bounded(support)
            .filter(|_| support.python.indexed_source_matches(file, source));
    }
    let path = python_static_attribute_path_bounded(expression, || support.scope_step())?;
    let local_name = python_slice(*path.first()?, source);
    if !support
        .module_binding_unmutated_from_source_bounded(file, root, source, local_name, expression)?
    {
        return None;
    }
    let binder = support.import_binder(token, file)?;
    let binding = binder.bindings.get(local_name)?;
    let (module, member) = match binding.kind {
        ImportKind::Named if path.len() == 1 => (
            binding.module_specifier.clone(),
            binding.imported_name.as_ref()?.clone(),
        ),
        ImportKind::Namespace if path.len() >= 2 => {
            let mut module = binding.module_specifier.clone();
            if path.len() > 2 {
                python_complete_external_module(support, &module)?;
                for segment in &path[1..path.len() - 1] {
                    module.push('.');
                    module.push_str(python_slice(*segment, source));
                    python_complete_external_module(support, &module)?;
                }
            }
            (module, python_slice(*path.last()?, source).to_owned())
        }
        ImportKind::Named if path.len() >= 2 => {
            // A from-import can bind a submodule alias. Every additional
            // attribute before the callable must also be an activated,
            // complete module; otherwise a dotted value chain could borrow a
            // package identity from its spelling.
            let imported_name = binding.imported_name.as_ref()?;
            let mut module = format!("{}.{imported_name}", binding.module_specifier);
            python_complete_external_module(support, &module)?;
            for segment in &path[1..path.len() - 1] {
                module.push('.');
                module.push_str(python_slice(*segment, source));
                python_complete_external_module(support, &module)?;
            }
            (module, python_slice(*path.last()?, source).to_owned())
        }
        _ => return None,
    };
    if local_name.is_empty()
        || python_namespace_root_shadowed_bounded(support, local_name, expression, source)?
    {
        return None;
    }
    // An activated external model cannot stand in for a workspace module with
    // the same name, even when that module does not declare the requested member.
    let unique = python_import_binding_is_unique_bounded(
        support,
        root,
        local_name,
        expression.start_byte(),
        source,
    )?;
    if !unique
        && (!python_import_binding_is_unique_without_wildcards_bounded(
            support,
            root,
            local_name,
            expression.start_byte(),
            source,
        )? || !python_wildcard_imports_reexport_same_external_bounded(
            support, token, file, local_name, &module, &member,
        )?)
    {
        return None;
    }
    if !python_external_model_namespace_available(support, &module, &member)
        || !support.python.indexed_source_matches(file, source)
    {
        return None;
    }
    Some((module, member))
}

/// A model cannot replace a workspace module/member whose source does not
/// establish the requested external class object.
pub(crate) fn python_external_model_namespace_available(
    support: &PythonDefinitionProvider<'_>,
    module: &str,
    member: &str,
) -> bool {
    support.module_candidates(module).is_empty()
        && support.fqn(module).is_empty()
        && support.fqn(&format!("{module}.{member}")).is_empty()
        && support.scope_step()
}

fn python_complete_external_module(
    support: &PythonDefinitionProvider<'_>,
    module: &str,
) -> Option<()> {
    let overlay = support.python.semantic_model_overlay()?;
    let matched = overlay.symbols_named(module);
    let [symbol] = matched.records.as_slice() else {
        return None;
    };
    if matched.disposition
        != brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
        || symbol.kind
            != brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbolKind::Module
        || symbol.language != brokk_bifrost_core::analyzer::model::Language::Python.config_label()
        || symbol.qualified_name != module
        || symbol.provenance.ambiguous
        || symbol.provenance.completeness
            != brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelCompleteness::Complete
    {
        return None;
    }
    let workspace_modules = support
        .session
        .query(|| support.python.path_module_fqn(module))??;
    if !workspace_modules.is_empty() || !support.fqn(module).is_empty() || !support.scope_step() {
        return None;
    }
    Some(())
}

pub(crate) fn python_external_imported_symbol_at_range_bounded(
    py: &PythonAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    start_byte: usize,
    end_byte: usize,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<Option<(String, String)>> {
    let session = ResolutionSession::bounded(
        brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET,
        cancellation,
    );
    let support = PythonDefinitionProvider::new(py, &session);
    let resolved = brokk_bifrost_python::declarations::parse_python_tree(source).and_then(|tree| {
        if tree.root_node().has_error() {
            return None;
        }
        let mut pending = vec![tree.root_node()];
        let mut exact = None;
        while let Some(node) = pending.pop() {
            if node.start_byte() == start_byte && node.end_byte() == end_byte {
                if exact.is_some() {
                    return None;
                }
                exact = Some(node);
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
        let selected = exact?;
        let expression = if selected.kind() == "call" {
            selected.child_by_field_name("function")?
        } else {
            selected
        };
        python_external_imported_symbol_bounded(
            &support,
            token,
            file,
            source,
            tree.root_node(),
            expression,
        )
    });
    session.finish(resolved)
}

pub(crate) enum PythonImportedClassValueSelection {
    Proven {
        import_module: Vec<String>,
        class_name: String,
    },
    Unproven(String),
}

/// Recognize a direct imported symbol used as a value, preserving the import's
/// parser-derived module segments for the runtime binding resolver. This does
/// not follow assignments or turn a constructor call into a class-object use.
pub(crate) fn python_imported_class_value_selection_bounded(
    py: &PythonAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<Option<PythonImportedClassValueSelection>> {
    let session = ResolutionSession::bounded(
        brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET,
        cancellation,
    );
    let support = PythonDefinitionProvider::new(py, &session);
    let selection = python_smallest_named_node_covering_bounded(
        &support,
        root,
        site.focus_start_byte,
        site.focus_end_byte,
    )
    .and_then(|focus| python_imported_value_expression_bounded(&support, focus))
    .and_then(|expression| {
        python_imported_class_value_candidate_bounded(
            &support, token, file, source, root, expression,
        )
    });
    session.finish(selection)
}

fn python_imported_class_value_candidate_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
) -> Option<PythonImportedClassValueSelection> {
    let path = python_static_attribute_path(expression)?;
    let local_name = python_slice(*path.first()?, source);
    if local_name.is_empty() {
        return None;
    }
    if python_namespace_root_shadowed_bounded(support, local_name, expression, source)? {
        return None;
    }
    let imports = support
        .session
        .query(|| support.python.import_info_of(token, file))?;
    let matching_imports = imports
        .iter()
        .filter(|import| import.local_name() == Some(local_name))
        .count();
    if matching_imports > 1 {
        return Some(PythonImportedClassValueSelection::Unproven(format!(
            "`{local_name}` has multiple parser-recorded imports at this value reference"
        )));
    }
    if matching_imports == 0 && imports.iter().any(|import| import.is_wildcard) {
        return Some(PythonImportedClassValueSelection::Unproven(format!(
            "`{local_name}` may be supplied by a wildcard import whose member identity is unresolved"
        )));
    }
    if matching_imports == 0 {
        return None;
    }
    let binder = support.import_binder(token, file)?;
    let Some(binding) = binder.bindings.get(local_name) else {
        return Some(PythonImportedClassValueSelection::Unproven(format!(
            "parser-recorded import `{local_name}` has no resolved import-binder record"
        )));
    };
    let class_name = match binding.kind {
        ImportKind::Named if path.len() == 1 => binding.imported_name.as_ref()?.clone(),
        ImportKind::Namespace if path.len() == 2 => python_slice(path[1], source).to_owned(),
        // A longer attribute chain is outside this direct imported-class
        // route. Keep the original resolver's boundary result for it instead
        // of treating an attribute as a class-binding failure.
        ImportKind::Named | ImportKind::Namespace => return None,
        _ => {
            return Some(PythonImportedClassValueSelection::Unproven(format!(
                "import binder `{local_name}` does not provide a direct class-value route"
            )));
        }
    };
    let Some((module, proved_class_name)) =
        python_external_imported_symbol_bounded(support, token, file, source, root, expression)
    else {
        return Some(PythonImportedClassValueSelection::Unproven(format!(
            "imported class candidate `{local_name}.{class_name}` was shadowed or its import identity was not unique"
        )));
    };
    let Some(import_module) = python_external_import_module_segments_bounded(
        support,
        token,
        file,
        source,
        expression,
        &module,
        &proved_class_name,
    ) else {
        return Some(PythonImportedClassValueSelection::Unproven(format!(
            "imported class candidate `{local_name}.{class_name}` has no unique structured module path"
        )));
    };
    Some(PythonImportedClassValueSelection::Proven {
        import_module,
        class_name: proved_class_name,
    })
}

fn python_imported_value_expression_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    focus: Node<'tree>,
) -> Option<Node<'tree>> {
    if python_is_non_reference_context(focus)
        || python_is_declaration_identifier(focus)
        || focus.kind() == "string_content"
    {
        return None;
    }
    let mut expression = focus;
    while let Some(parent) = expression.parent() {
        if !support.scope_step() {
            return None;
        }
        if parent.kind() != "attribute"
            || parent.child_by_field_name("attribute") != Some(expression)
        {
            break;
        }
        expression = parent;
    }
    let path = python_static_attribute_path(expression)?;
    for _ in 0..path.len() {
        if !support.scope_step() {
            return None;
        }
    }
    let mut current = expression;
    while let Some(parent) = current.parent() {
        if !support.scope_step() {
            return None;
        }
        if (parent.kind() == "call" && parent.child_by_field_name("function") == Some(current))
            || (matches!(parent.kind(), "assignment" | "augmented_assignment")
                && parent
                    .child_by_field_name("left")
                    .is_some_and(|left| node_contains_focus(left, current)))
            || (parent.kind() == "keyword_argument"
                && parent
                    .child_by_field_name("name")
                    .is_some_and(|name| node_contains_focus(name, current)))
        {
            return None;
        }
        current = parent;
    }
    Some(expression)
}

fn python_external_import_module_segments_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    expression: Node<'_>,
    expected_module: &str,
    expected_member: &str,
) -> Option<Vec<String>> {
    let path = python_static_attribute_path(expression)?;
    let local_name = python_slice(*path.first()?, source);
    let imports = support
        .session
        .query(|| support.python.import_info_of(token, file))?;
    let mut matches = imports.iter().filter_map(|import| {
        if import.local_name() != Some(local_name) {
            return None;
        }
        let path = import.path.as_ref()?;
        match path.kind? {
            brokk_bifrost_core::analyzer::model::StructuredImportPathKind::Namespace
                if path.render_segments(".") == expected_module =>
            {
                Some(path.segments.clone())
            }
            brokk_bifrost_core::analyzer::model::StructuredImportPathKind::ImportFrom
                if path
                    .segments
                    .last()
                    .is_some_and(|member| member == expected_member)
                    && path.segments[..path.segments.len().saturating_sub(1)].join(".")
                        == expected_module =>
            {
                Some(path.segments[..path.segments.len() - 1].to_vec())
            }
            _ => None,
        }
    });
    let import_module = matches.next()?;
    if matches.next().is_some()
        || import_module.is_empty()
        || import_module.iter().any(String::is_empty)
    {
        return None;
    }
    Some(import_module)
}

fn python_namespace_root_shadowed_bounded(
    support: &PythonDefinitionProvider<'_>,
    name: &str,
    reference: Node<'_>,
    source: &str,
) -> Option<bool> {
    if python_comprehension_binds_name_at_bounded(name, reference, source, || support.scope_step())?
        || python_type_parameter_binds_name_at_bounded(name, reference, source, || {
            support.scope_step()
        })?
    {
        return Some(true);
    }
    let mut current = reference;
    let mut crossed_callable_body = false;
    while let Some(parent) = current.parent() {
        if !support.scope_step() {
            return None;
        }
        let body = parent.child_by_field_name("body");
        let inside_body = body.is_some_and(|body| {
            body.start_byte() <= reference.start_byte() && reference.end_byte() <= body.end_byte()
        });
        if inside_body && matches!(parent.kind(), "function_definition" | "lambda") {
            let inventory =
                python_lexical_scope_inventory_bounded(parent, source, || support.scope_step())?;
            let resolution =
                inventory.name_resolution_at_bounded(name, reference, || support.scope_step())?;
            if resolution == PythonLexicalNameResolution::Global {
                return Some(!python_global_binding_is_untouched_bounded(
                    name,
                    reference,
                    parent,
                    source,
                    || support.scope_step(),
                )?);
            }
            if inventory
                .has_runtime_callable_binding_at_bounded(name, reference, || support.scope_step())?
                || matches!(
                    resolution,
                    PythonLexicalNameResolution::Local | PythonLexicalNameResolution::Nonlocal
                )
            {
                return Some(true);
            }
            crossed_callable_body = true;
        } else if parent.kind() == "class_definition" && !crossed_callable_body && inside_body {
            let class_scope =
                PythonClassReferenceScope::new_bounded(parent, reference, || support.scope_step())?;
            let inventory = class_scope.collect_bounded(source, || support.scope_step())?;
            let resolution =
                inventory.name_resolution_at_bounded(name, reference, || support.scope_step())?;
            if resolution == PythonLexicalNameResolution::Global {
                return Some(!python_global_binding_is_untouched_bounded(
                    name,
                    reference,
                    parent,
                    source,
                    || support.scope_step(),
                )?);
            }
            if resolution == PythonLexicalNameResolution::Nonlocal
                || class_scope.binds_name_bounded(name, source, || support.scope_step())?
            {
                return Some(true);
            }
            // Nested classes do not capture their enclosing class namespace.
            crossed_callable_body = true;
        }
        current = parent;
    }
    Some(false)
}

fn python_import_binding_is_unique_bounded(
    support: &PythonDefinitionProvider<'_>,
    root: Node<'_>,
    name: &str,
    reference_start: usize,
    source: &str,
) -> Option<bool> {
    let mut matched_import = false;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !support.scope_step() {
            return None;
        }
        if node.kind() == "wildcard_import" {
            return Some(false);
        }
        for direct in python_direct_scope_bindings_bounded(node, source, || support.scope_step())? {
            if python_slice(direct.declaration, source) != name {
                continue;
            }
            let mut declaration = direct.declaration;
            while !matches!(
                declaration.kind(),
                "import_statement" | "import_from_statement"
            ) {
                let Some(parent) = declaration.parent() else {
                    return Some(false);
                };
                if parent.kind() == "module" {
                    return Some(false);
                }
                declaration = parent;
            }
            if declaration
                .parent()
                .is_none_or(|parent| parent.kind() != "module")
                || declaration.start_byte() > reference_start
                || matched_import
            {
                return Some(false);
            }
            matched_import = true;
        }
        for child in python_executable_scope_children(node)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
        {
            stack.push(child);
        }
    }
    Some(matched_import)
}

/// Prove a namespace local is imported only by top-level imports that Python
/// binds to the same unaliased root. Repeating `import pkg` before or after
/// `import pkg.sub` still binds the same namespace root; the dotted import
/// facts below retain the longer path needed to qualify a class reference.
fn python_namespace_import_binding_is_unique_bounded(
    support: &PythonDefinitionProvider<'_>,
    root: Node<'_>,
    name: &str,
    reference_start: usize,
    source: &str,
) -> Option<bool> {
    let mut declarations = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !support.scope_step() {
            return None;
        }
        if node.kind() == "wildcard_import" {
            return Some(false);
        }
        for direct in python_direct_scope_bindings_bounded(node, source, || support.scope_step())? {
            if python_slice(direct.declaration, source) != name {
                continue;
            }
            let mut declaration = direct.declaration;
            while !matches!(
                declaration.kind(),
                "import_statement" | "import_from_statement"
            ) {
                let Some(parent) = declaration.parent() else {
                    return Some(false);
                };
                if parent.kind() == "module" {
                    return Some(false);
                }
                declaration = parent;
            }
            if declaration
                .parent()
                .is_none_or(|parent| parent.kind() != "module")
                || declaration.start_byte() > reference_start
            {
                return Some(false);
            }
            if !declarations
                .iter()
                .any(|existing: &Node<'_>| existing.id() == declaration.id())
            {
                declarations.push(declaration);
            }
        }
        let excluded_body = matches!(
            node.kind(),
            "function_definition" | "class_definition" | "lambda"
        )
        .then(|| node.child_by_field_name("body").map(|body| body.id()))
        .flatten();
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        for child in children.into_iter().rev() {
            if Some(child.id()) != excluded_body {
                stack.push(child);
            }
        }
    }
    if declarations.is_empty() {
        return Some(false);
    }
    let repeated_declarations = declarations.len() > 1;
    for declaration in declarations {
        let matching = python_import_infos_from_node(declaration, source)
            .into_iter()
            .filter(|import| import.local_name() == Some(name))
            .collect::<Vec<_>>();
        if matching.is_empty() {
            return Some(false);
        }
        if matching.len() == 1 && !repeated_declarations {
            continue;
        }
        if declaration.kind() != "import_statement"
            || matching.iter().any(|import| {
                import.alias.is_some()
                    || import.path.as_ref().is_none_or(|path| {
                        path.kind
                    != Some(
                        brokk_bifrost_core::analyzer::model::StructuredImportPathKind::Namespace,
                    )
                    || path.segments.first().is_none_or(|root| root != name)
                    })
            })
        {
            return Some(false);
        }
    }
    Some(true)
}

/// Whether the explicit import remains the same external binding through every
/// workspace wildcard import in the module. A wildcard is open evidence unless
/// its structured export surface proves that it reexports this exact symbol.
fn python_wildcard_imports_reexport_same_external_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    local_name: &str,
    expected_module: &str,
    expected_member: &str,
) -> Option<bool> {
    let imports = support
        .session
        .query(|| support.python.import_info_of(token, file))?;
    let mut saw_wildcard = false;
    for import in imports.iter().filter(|import| import.is_wildcard) {
        let Some(PythonImportDetails::FromImport {
            module,
            wildcard: true,
            ..
        }) = python_import_details(import)
        else {
            return Some(false);
        };
        let Some(module) = resolve_python_relative_module(support.python.project(), file, &module)
        else {
            return Some(false);
        };
        let Some(module_unit) = support
            .session
            .query(|| resolve_module_code_unit(support.python, Some(file), &module))?
        else {
            return Some(false);
        };
        let exports = support
            .session
            .query(|| support.python.export_index_of(token, module_unit.source()))?;
        if !exports.reexport_stars.is_empty()
            || !matches!(
                exports.exports_by_name.get(local_name),
                Some(ExportEntry::ReexportedNamed {
                    module_specifier,
                    imported_name,
                }) if module_specifier == expected_module && imported_name == expected_member
            )
        {
            return Some(false);
        }
        saw_wildcard = true;
    }
    Some(saw_wildcard)
}

/// The ordinary import uniqueness check rejects every wildcard. This variant
/// proves the explicit binding independently so the caller can validate each
/// wildcard's actual export through `ExportIndex` instead of treating unrelated
/// stars as an automatic shadow.
fn python_import_binding_is_unique_without_wildcards_bounded(
    support: &PythonDefinitionProvider<'_>,
    root: Node<'_>,
    name: &str,
    reference_start: usize,
    source: &str,
) -> Option<bool> {
    let mut matched_import = false;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !support.scope_step() {
            return None;
        }
        if node.kind() == "wildcard_import" {
            continue;
        }
        for direct in python_direct_scope_bindings_bounded(node, source, || support.scope_step())? {
            if python_slice(direct.declaration, source) != name {
                continue;
            }
            let mut declaration = direct.declaration;
            while !matches!(
                declaration.kind(),
                "import_statement" | "import_from_statement"
            ) {
                let Some(parent) = declaration.parent() else {
                    return Some(false);
                };
                if parent.kind() == "module" {
                    return Some(false);
                }
                declaration = parent;
            }
            if declaration
                .parent()
                .is_none_or(|parent| parent.kind() != "module")
                || declaration.start_byte() > reference_start
                || matched_import
            {
                return Some(false);
            }
            matched_import = true;
        }
        let excluded_body = matches!(
            node.kind(),
            "function_definition" | "class_definition" | "lambda"
        )
        .then(|| node.child_by_field_name("body").map(|body| body.id()))
        .flatten();
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        for child in children.into_iter().rev() {
            if Some(child.id()) != excluded_body {
                stack.push(child);
            }
        }
    }
    Some(matched_import)
}

fn python_focused_reference_text<'source>(
    node: Node<'_>,
    source: &'source str,
    focus_start: usize,
    focus_end: usize,
    cancellation: Option<&CancellationToken>,
) -> Option<&'source str> {
    if node.kind() != "string_content" {
        return Some(python_slice(node, source));
    }
    let string = node.parent()?;
    python_deferred_annotation_identifier_ranges(string, source, cancellation)?
        .into_iter()
        .any(|range| range.start_byte == focus_start && range.end_byte == focus_end)
        .then(|| source.get(focus_start..focus_end))?
}

fn python_type_for_expression_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
    depth: usize,
) -> Option<CodeUnit> {
    if depth >= 12 || !support.scope_step() {
        return None;
    }
    match node.kind() {
        "identifier" => {
            let name = python_slice(node, source);
            if let Some(receiver) =
                python_current_receiver_class(support, token, file, source, node, name)
            {
                Some(receiver)
            } else if python_has_lexical_binding_bounded(support, node, source) {
                python_bound_type_for_identifier(
                    support,
                    token,
                    file,
                    source,
                    root,
                    node,
                    name,
                    depth + 1,
                )
            } else {
                python_class_candidate_for_name(support, token, file, source, node, name)
            }
        }
        "call" => {
            let function = node.child_by_field_name("function")?;
            let callable = match function.kind() {
                "identifier" => {
                    let name = python_slice(function, source);
                    let lexical_binding = python_lexical_binding_bounded(support, function, source);
                    match lexical_binding {
                        PythonLexicalBinding::Other | PythonLexicalBinding::LocalClass(_) => {
                            return None;
                        }
                        PythonLexicalBinding::LocalFunction(declaration) => {
                            return python_function_return_type_from_node_bounded(
                                support,
                                token,
                                file,
                                source,
                                root,
                                declaration,
                                depth + 1,
                            );
                        }
                        PythonLexicalBinding::UnboundOrGlobal => {
                            if let Some(class) = python_class_candidate_for_name(
                                support, token, file, source, function, name,
                            ) {
                                return Some(class);
                            }
                        }
                    }
                    unique_python_candidate(
                        support
                            .file_identifier(file, name)
                            .into_iter()
                            .filter(CodeUnit::is_function)
                            .filter(|candidate| {
                                python_same_file_function_visible_at(
                                    support, source, function, candidate,
                                )
                                .unwrap_or(false)
                            })
                            .collect(),
                    )
                }
                "attribute" => {
                    if let Some(class) = python_namespace_imported_class_candidate_bounded(
                        support, token, file, source, root, function,
                    ) {
                        return Some(class);
                    }
                    let object = function.child_by_field_name("object")?;
                    let member = python_slice(function.child_by_field_name("attribute")?, source);
                    let receiver = python_type_for_expression_bounded(
                        support,
                        token,
                        file,
                        source,
                        root,
                        object,
                        depth + 1,
                    )?;
                    unique_python_candidate(
                        support
                            .members_for_owner(&receiver, member)
                            .into_iter()
                            .filter(CodeUnit::is_function)
                            .collect(),
                    )
                }
                _ => None,
            }?;
            python_callable_return_type_in_tree(
                support,
                token,
                file,
                source,
                root,
                &callable,
                depth + 1,
            )
        }
        // `value.paint` outside a call: the receiver's type owns the member, so
        // the member declaration's own type is the expression's type.
        "attribute" => {
            if let Some(class) = python_namespace_imported_class_candidate_bounded(
                support, token, file, source, root, node,
            ) {
                return Some(class);
            }
            let object = node.child_by_field_name("object")?;
            let member = python_slice(node.child_by_field_name("attribute")?, source);
            if member.is_empty() {
                return None;
            }
            let receiver = python_type_for_expression_bounded(
                support,
                token,
                file,
                source,
                root,
                object,
                depth + 1,
            )?;
            let declaration =
                unique_python_candidate(support.members_for_owner(&receiver, member))?;
            python_member_declared_type_bounded(
                support,
                token,
                file,
                source,
                root,
                &declaration,
                depth + 1,
            )
        }
        "parenthesized_expression" => {
            let child = node.named_child(0)?;
            python_type_for_expression_bounded(support, token, file, source, root, child, depth + 1)
        }
        _ => None,
    }
}

/// The type a resolved member declaration carries: a nested class is its own
/// type, a method's is its return type, and an attribute's is its annotation or
/// the type of the value bound to it.
///
/// The syntax routes read the site's own tree, so a member declared in another
/// file has no bounded answer here. That is the same in-file rule
/// [`python_callable_return_type_in_tree`] applies to a resolved callable: the
/// bounded core answers from the tree the caller already parsed and never
/// cold-parses a second file to finish a step.
fn python_member_declared_type_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    member: &CodeUnit,
    depth: usize,
) -> Option<CodeUnit> {
    if depth >= 12 || !support.scope_step() {
        return None;
    }
    if member.is_class() {
        return Some(member.clone());
    }
    if member.source() != file {
        return None;
    }
    let mut types = Vec::new();
    for range in support.ranges(member) {
        if range.start_byte >= range.end_byte || range.end_byte > source.len() {
            continue;
        }
        let Some(mut node) = python_smallest_named_node_covering_bounded(
            support,
            root,
            range.start_byte,
            range.end_byte,
        ) else {
            continue;
        };
        loop {
            if !support.scope_step() {
                return None;
            }
            if node.kind() == "function_definition"
                && node
                    .child_by_field_name("name")
                    .is_some_and(|name| python_slice(name, source) == member.identifier())
            {
                types.extend(python_function_return_type_from_node_bounded(
                    support,
                    token,
                    file,
                    source,
                    root,
                    node,
                    depth + 1,
                ));
                break;
            }
            // `name: T = ..` at class level and `self.name = ..` in a method are
            // both assignments whose bound name is the member's identifier.
            let bound = (node.kind() == "assignment")
                .then(|| node.child_by_field_name("left"))
                .flatten()
                .and_then(|left| match left.kind() {
                    "identifier" => Some(left),
                    "attribute" => left.child_by_field_name("attribute"),
                    _ => None,
                });
            if bound.is_some_and(|bound| python_slice(bound, source) == member.identifier()) {
                let declared = python_assignment_bound_type_bounded(
                    support,
                    token,
                    file,
                    source,
                    root,
                    node,
                    depth + 1,
                );
                types.extend(declared);
                break;
            }
            let Some(parent) = node.parent() else {
                break;
            };
            node = parent;
        }
    }
    unique_python_candidate(types)
}

fn python_assignment_bound_type_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    assignment: Node<'_>,
    depth: usize,
) -> Option<CodeUnit> {
    match assignment.child_by_field_name("type") {
        Some(annotation) => {
            python_type_from_annotation_bounded(support, token, file, source, annotation, depth)
        }
        None => assignment.child_by_field_name("right").and_then(|value| {
            python_type_for_expression_bounded(support, token, file, source, root, value, depth)
        }),
    }
}

/// Runtime-only transport within the caller's prepared tree and session.
/// Ordinary declaration navigation never follows these assignment nodes.
pub(crate) enum PythonRuntimeClassCandidate<'tree> {
    WorkspaceClass(CodeUnit),
    AliasRhs {
        assignment: Node<'tree>,
        rhs: Node<'tree>,
    },
}

/// A selected runtime base must name the class object itself. Type inference
/// for an instance/call/annotation is deliberately not used here.
pub(crate) fn python_class_object_base_candidate<'tree>(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    prepared: &brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree,
    base: Node<'tree>,
) -> Option<PythonRuntimeClassCandidate<'tree>> {
    let source = prepared.source();
    if let Some(selected) = python_local_imported_symbol_bounded(
        support,
        token,
        file,
        source,
        prepared.tree().root_node(),
        base,
    )? {
        // A path-backed module with this spelling does not prove that a
        // from-imported value is that module. Keep such attribute chains
        // unknown until source export ownership can establish that fact.
        if selected.import_kind
            == brokk_bifrost_core::analyzer::model::StructuredImportPathKind::ImportFrom
            && selected.requires_imported_module
        {
            return None;
        }
        return python_runtime_imported_class_from_module(
            support,
            token,
            file,
            selected.module.join("."),
            selected.member,
        )
        .map(PythonRuntimeClassCandidate::WorkspaceClass);
    }
    if base.kind() == "attribute" {
        let path = python_static_attribute_path_bounded(base, || support.scope_step())?;
        let root = *path.first()?;
        if !support.module_binding_unmutated_at_bounded(
            file,
            prepared,
            python_slice(root, source),
            base,
        )? {
            return None;
        }
        if python_type_parameter_binds_name_at_bounded(
            python_slice(root, source),
            root,
            source,
            || support.scope_step(),
        )? {
            return None;
        }
        let canonical = python_namespace_imported_class_name_bounded(
            support,
            token,
            file,
            source,
            prepared.tree().root_node(),
            base,
        )?;
        let (module, member) = canonical.rsplit_once('.')?;
        return python_runtime_imported_class_from_module(
            support,
            token,
            file,
            module.into(),
            member.into(),
        )
        .map(PythonRuntimeClassCandidate::WorkspaceClass);
    }
    if base.kind() != "identifier" {
        return None;
    }
    let name = python_slice(base, source);
    // Only the nearest executing class body participates. C's own header
    // executes outside C's body, and methods/lambdas do not capture a class
    // namespace. Inspect this scope before an enclosing callable's bindings.
    let mut current = base;
    while let Some(parent) = current.parent() {
        if !support.scope_step() {
            return None;
        }
        let inside_body = parent.child_by_field_name("body").is_some_and(|body| {
            body.start_byte() <= base.start_byte() && base.end_byte() <= body.end_byte()
        });
        if inside_body && matches!(parent.kind(), "function_definition" | "lambda") {
            break;
        }
        if inside_body && parent.kind() == "class_definition" {
            let class_scope =
                PythonClassReferenceScope::new_bounded(parent, base, || support.scope_step())?;
            let inventory = class_scope.collect_bounded(source, || support.scope_step())?;
            let binds = class_scope.binds_name_bounded(name, source, || support.scope_step())?;
            match inventory.name_resolution_at_bounded(name, base, || support.scope_step())? {
                PythonLexicalNameResolution::Global => {
                    // Skip outer locals, but never skip known writes to this
                    // same global namespace in enclosing executing scopes.
                    return if python_global_binding_is_untouched_bounded(
                        name,
                        base,
                        parent,
                        source,
                        || support.scope_step(),
                    )? {
                        python_runtime_module_class_candidate_bounded(
                            support, token, file, source, base, name,
                        )
                    } else {
                        None
                    };
                }
                PythonLexicalNameResolution::Nonlocal => return None,
                PythonLexicalNameResolution::Local => {
                    let declaration =
                        inventory
                            .local_class_declaration_bounded(name, base, || support.scope_step())?;
                    if declaration.parent() != parent.child_by_field_name("body")
                        || declaration.end_byte() > base.start_byte()
                    {
                        return None;
                    }
                    return python_unit_for_class_declaration(
                        support,
                        file,
                        source,
                        base,
                        declaration,
                    )
                    .map(PythonRuntimeClassCandidate::WorkspaceClass);
                }
                PythonLexicalNameResolution::Unbound if binds => return None,
                PythonLexicalNameResolution::Unbound => break,
            }
        }
        current = parent;
    }
    if python_type_parameter_binds_name_at_bounded(name, base, source, || support.scope_step())? {
        return None;
    }
    match python_lexical_declaration_binding_bounded(support, base, source) {
        PythonLexicalBinding::LocalClass(declaration) => {
            python_unit_for_class_declaration(support, file, source, base, declaration)
                .map(PythonRuntimeClassCandidate::WorkspaceClass)
        }
        PythonLexicalBinding::UnboundOrGlobal => {
            python_runtime_module_class_candidate_bounded(support, token, file, source, base, name)
        }
        PythonLexicalBinding::LocalFunction(_) | PythonLexicalBinding::Other => None,
    }
}

/// Runtime class admission has mutation obligations beyond ordinary navigation.
fn python_runtime_module_class_candidate_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    reference: Node<'tree>,
    name: &str,
) -> Option<PythonRuntimeClassCandidate<'tree>> {
    let mut root = reference;
    while let Some(parent) = root.parent() {
        if !support.scope_step() {
            return None;
        }
        root = parent;
    }
    if !support.module_binding_unmutated_from_source_bounded(file, root, source, name, reference)? {
        return None;
    }
    // A positive assignment witness requires the COMPLETE module inventory;
    // an early Other kind is not evidence that later writes are absent.
    let binding = python_unambiguous_module_binding_node_bounded(root, source, name, || {
        support.scope_step()
    })??;
    if binding.kind == PythonDirectScopeBindingKind::Other {
        let target = binding.declaration;
        let assignment = target.parent()?;
        let statement = assignment.parent()?;
        if target.kind() != "identifier"
            || assignment.kind() != "assignment"
            || assignment.child_by_field_name("left") != Some(target)
            || assignment.child_by_field_name("type").is_some()
            || assignment.child_by_field_name("annotation").is_some()
            || statement.kind() != "expression_statement"
            || statement.parent() != Some(root)
            || assignment.end_byte() > reference.start_byte()
            || assignment.has_error()
        {
            return None;
        }
        let rhs = assignment.child_by_field_name("right")?;
        if rhs.kind() == "assignment" || rhs.has_error() || rhs.is_missing() {
            return None;
        }
        // Transport syntax, never an inferred instance/type or a cached answer.
        // The hierarchy rechecks the RHS binding at THIS source occurrence.
        return (support.python.indexed_source_matches(file, source) && support.scope_step())
            .then_some(PythonRuntimeClassCandidate::AliasRhs { assignment, rhs });
    }
    python_class_candidate_for_name_with_import_admission(
        support,
        token,
        file,
        source,
        reference,
        name,
        |owner, prepared, imported_name| {
            support.module_export_unmutated_bounded(owner, prepared, imported_name)
        },
    )
    .filter(|_| support.python.indexed_source_matches(file, source))
    .map(PythonRuntimeClassCandidate::WorkspaceClass)
}

fn python_unit_for_class_declaration(
    support: &PythonDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    base: Node<'_>,
    declaration: Node<'_>,
) -> Option<CodeUnit> {
    let name = python_slice(declaration.child_by_field_name("name")?, source);
    let mut selected = None;
    for candidate in support.file_identifier(file, name) {
        if !support.scope_step() {
            return None;
        }
        if candidate.is_class()
            && python_class_node_for_candidate_bounded(support, source, base, &candidate)
                == Some(declaration)
        {
            if selected.is_some() {
                return None;
            }
            selected = Some(candidate);
        }
    }
    selected
}

pub(crate) fn python_class_candidate_for_name(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    site: Node<'_>,
    name: &str,
) -> Option<CodeUnit> {
    python_class_candidate_for_name_with_import_admission(
        support,
        token,
        file,
        source,
        site,
        name,
        |_, _, _| Some(true),
    )
}

fn python_class_candidate_for_name_with_import_admission(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    site: Node<'_>,
    name: &str,
    mut admit_export: impl FnMut(
        &ProjectFile,
        &brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree,
        &str,
    ) -> Option<bool>,
) -> Option<CodeUnit> {
    if name.is_empty() {
        return None;
    }
    let mut file_candidates = support
        .file_identifier(file, name)
        .into_iter()
        .filter(CodeUnit::is_class)
        .collect::<Vec<_>>();
    file_candidates.retain(|candidate| {
        python_same_file_class_visible_at(support, source, site, candidate).unwrap_or(false)
    });
    if let Some(candidate) = unique_python_candidate(file_candidates) {
        return Some(candidate);
    }
    // A same-file declaration shadows an import, so the binder is consulted only
    // after the file's own classes cannot answer the name.
    if let Some(candidate) = python_imported_class_candidate_with_admission(
        support,
        token,
        file,
        source,
        site,
        name,
        &mut admit_export,
    ) {
        return Some(candidate);
    }
    if !name.contains('.') {
        return None;
    }
    let exact_candidates = support
        .fqn(name)
        .into_iter()
        .filter(CodeUnit::is_class)
        .collect::<Vec<_>>();
    unique_python_candidate(exact_candidates)
}

/// Resolve a class imported exclusively under `if TYPE_CHECKING:` for use in
/// static type bounds. Runtime expression resolution must continue to ignore
/// this import because the name is not bound when the module executes.
pub(crate) fn python_type_checking_imported_class_candidate(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    site: Node<'_>,
    name: &str,
) -> Option<CodeUnit> {
    if name.is_empty() || !support.python.indexed_source_matches(file, source) {
        return None;
    }
    let binder = support.import_binder(token, file)?;
    let binding = binder.bindings.get(name)?;
    if binding.kind != ImportKind::Named {
        return None;
    }
    let mut root = site;
    while let Some(parent) = root.parent() {
        if !support.scope_step() {
            return None;
        }
        root = parent;
    }
    if !python_type_checking_import_is_unique_bounded(
        support,
        token,
        file,
        root,
        name,
        site.start_byte(),
        source,
    )? {
        return None;
    }
    python_imported_class_from_module(
        support,
        token,
        file,
        binding.module_specifier.clone(),
        binding.imported_name.as_ref()?.clone(),
    )
}

fn python_type_checking_import_is_unique_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    root: Node<'_>,
    name: &str,
    reference_start: usize,
    source: &str,
) -> Option<bool> {
    let mut matched_import = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !support.scope_step() {
            return None;
        }
        if node.kind() == "wildcard_import" {
            return Some(false);
        }
        for direct in python_direct_scope_bindings_bounded(node, source, || support.scope_step())? {
            if python_slice(direct.declaration, source) != name {
                continue;
            }
            let mut declaration = direct.declaration;
            while !matches!(
                declaration.kind(),
                "import_statement" | "import_from_statement"
            ) {
                let Some(parent) = declaration.parent() else {
                    return Some(false);
                };
                declaration = parent;
            }
            if declaration.kind() != "import_from_statement"
                || declaration.start_byte() > reference_start
                || matched_import.is_some()
            {
                return Some(false);
            }
            let Some(block) = declaration.parent() else {
                return Some(false);
            };
            let Some(guard) = block.parent() else {
                return Some(false);
            };
            if block.kind() != "block"
                || guard.kind() != "if_statement"
                || guard
                    .child_by_field_name("consequence")
                    .map(|body| body.id())
                    != Some(block.id())
                || guard.parent().map(|parent| parent.kind()) != Some("module")
            {
                return Some(false);
            }
            let Some(condition) = guard.child_by_field_name("condition") else {
                return Some(false);
            };
            if !python_type_checking_condition_is_imported(
                support, token, file, root, condition, source,
            )? {
                return Some(false);
            }
            matched_import = Some(declaration);
        }
        let excluded_body = matches!(
            node.kind(),
            "function_definition" | "class_definition" | "lambda"
        )
        .then(|| node.child_by_field_name("body").map(|body| body.id()))
        .flatten();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if Some(child.id()) != excluded_body {
                stack.push(child);
            }
        }
    }
    Some(matched_import.is_some())
}

fn python_type_checking_condition_is_imported(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    root: Node<'_>,
    condition: Node<'_>,
    source: &str,
) -> Option<bool> {
    if condition.kind() != "identifier" {
        return Some(false);
    }
    let name = python_slice(condition, source);
    let binding = support
        .import_binder(token, file)?
        .bindings
        .get(name)?
        .clone();
    if binding.kind != ImportKind::Named
        || binding.module_specifier != "typing"
        || binding.imported_name.as_deref() != Some("TYPE_CHECKING")
    {
        return Some(false);
    }
    python_import_binding_is_unique_bounded(support, root, name, condition.start_byte(), source)
}

/// The class an imported local name binds to.
///
/// A named import may point directly at a class declaration or at a package
/// facade that re-exports it. Resolve that structured export identity before
/// applying the uniqueness/class gate. Namespace imports name modules, not
/// class declarations.
fn python_imported_class_candidate_with_admission(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    site: Node<'_>,
    name: &str,
    admit_export: impl FnMut(
        &ProjectFile,
        &brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree,
        &str,
    ) -> Option<bool>,
) -> Option<CodeUnit> {
    let binder = support.import_binder(token, file)?;
    let binding = binder.bindings.get(name)?;
    if binding.kind != ImportKind::Named || !support.python.indexed_source_matches(file, source) {
        return None;
    }
    let imported = binding.imported_name.as_ref()?;
    let mut root = site;
    while let Some(parent) = root.parent() {
        if !support.scope_step() {
            return None;
        }
        root = parent;
    }
    if !python_import_binding_is_unique_bounded(support, root, name, site.start_byte(), source)? {
        return None;
    }
    python_imported_class_from_module_with_admission(
        support,
        token,
        file,
        binding.module_specifier.clone(),
        imported.clone(),
        admit_export,
    )
}

fn python_imported_class_from_module(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    importer: &ProjectFile,
    module: String,
    imported_name: String,
) -> Option<CodeUnit> {
    python_imported_class_from_module_with_admission(
        support,
        token,
        importer,
        module,
        imported_name,
        |_, _, _| Some(true),
    )
}

fn python_runtime_imported_class_from_module(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    importer: &ProjectFile,
    module: String,
    imported_name: String,
) -> Option<CodeUnit> {
    python_imported_class_from_module_with_admission(
        support,
        token,
        importer,
        module,
        imported_name,
        |owner, prepared, name| support.module_export_unmutated_bounded(owner, prepared, name),
    )
}

fn python_imported_class_from_module_with_admission(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    importer: &ProjectFile,
    mut module: String,
    mut imported_name: String,
    mut admit_export: impl FnMut(
        &ProjectFile,
        &brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree,
        &str,
    ) -> Option<bool>,
) -> Option<CodeUnit> {
    let mut importer = importer.clone();
    let mut visited = HashSet::default();

    loop {
        if !support.scope_step() || !visited.insert((module.clone(), imported_name.clone())) {
            return None;
        }
        let module_unit = support.module_code_unit(&importer, &module)?;
        let prepared = support
            .session
            .query(|| support.python.prepared_syntax(token, module_unit.source()))??;
        if !matches!(prepared.backing(), PreparedSyntaxSource::Indexed(_))
            || !support
                .python
                .indexed_source_matches(module_unit.source(), prepared.source())
        {
            return None;
        }
        let target_root = prepared.tree().root_node();
        let target_source = prepared.source();
        // Runtime imports require mutation admission at every actual owner;
        // ordinary navigation retains its declaration-based export contract.
        if !admit_export(module_unit.source(), &prepared, &imported_name)? {
            return None;
        }
        let target_binder = support.import_binder(token, module_unit.source())?;

        if let Some(target_binding) = target_binder.bindings.get(&imported_name) {
            // A facade hop is safe only when the target module's complete
            // module-scope inventory proves one unconditional named import.
            // The ordinary binder is collapsed and therefore cannot establish
            // source order or reject a conditional/rebound import by itself.
            if target_binding.kind != ImportKind::Named
                || !python_import_binding_is_unique_bounded(
                    support,
                    target_root,
                    &imported_name,
                    usize::MAX,
                    target_source,
                )?
                || !support
                    .python
                    .indexed_source_matches(module_unit.source(), target_source)
            {
                return None;
            }
            importer = module_unit.source().clone();
            module = target_binding.module_specifier.clone();
            imported_name = target_binding.imported_name.as_ref()?.clone();
            continue;
        }

        // No import means this module must provide exactly one unconditional
        // class declaration. Keep all indexed declarations through the
        // uniqueness check so a class/function collision cannot be treated as
        // a type proof.
        if !python_unambiguous_module_class_binding_bounded(
            target_root,
            target_source,
            &imported_name,
            || support.scope_step(),
        )? {
            return None;
        }
        // The module's own module-scope inventory has already proven one
        // unconditional binding for this name, so the indexed lookup only has
        // to hand back that declaration's unit. Two sibling roots can share
        // one module FQN, so the uniqueness question is which declaration
        // *this* module file owns, not how many the workspace spells that way.
        let fqn = format!("{}.{}", module_unit.fq_name(), imported_name);
        let candidate = unique_python_candidate(
            support
                .fqn(&fqn)
                .into_iter()
                .filter(|candidate| candidate.source() == module_unit.source())
                .collect(),
        )?;
        if !support
            .python
            .indexed_source_matches(module_unit.source(), prepared.source())
        {
            return None;
        }
        return candidate.is_class().then_some(candidate);
    }
}

#[derive(Clone, Copy)]
struct PythonReferenceVisibility<'tree> {
    class_scope: Option<Node<'tree>>,
    deferred_body: bool,
}

#[derive(Clone, Copy)]
enum PythonClassDeclarationScope<'tree> {
    Module,
    Class(Node<'tree>),
    Other,
}

#[derive(Clone, Copy)]
enum PythonFunctionDeclarationScope<'tree> {
    Module,
    Function(Node<'tree>),
    Other,
}

#[derive(Clone, Copy)]
enum PythonDeclarationScope<'tree> {
    Module,
    Class(Node<'tree>),
    Function(Node<'tree>),
    Other,
}

fn python_same_file_class_visible_at(
    support: &PythonDefinitionProvider<'_>,
    source: &str,
    site: Node<'_>,
    candidate: &CodeUnit,
) -> Option<bool> {
    let visibility = python_reference_visibility_bounded(support, site)?;
    let declaration = python_class_node_for_candidate_bounded(support, source, site, candidate)?;
    if !visibility.deferred_body && declaration.start_byte() > site.start_byte() {
        return Some(false);
    }
    let declaration_scope = python_class_declaration_scope_bounded(support, declaration)?;
    let visible = match declaration_scope {
        PythonClassDeclarationScope::Module => {
            let mut root = site;
            while let Some(parent) = root.parent() {
                if !support.scope_step() {
                    return None;
                }
                root = parent;
            }
            python_unambiguous_module_class_binding_bounded(
                root,
                source,
                candidate.identifier(),
                || support.scope_step(),
            )?
        }
        PythonClassDeclarationScope::Class(scope) => visibility
            .class_scope
            .is_some_and(|visible| visible == scope),
        PythonClassDeclarationScope::Other => false,
    };
    Some(visible)
}

fn python_reference_visibility_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    site: Node<'tree>,
) -> Option<PythonReferenceVisibility<'tree>> {
    let site_start = site.start_byte();
    let site_end = site.end_byte();
    let mut class_scope = None;
    let mut current = site;
    while let Some(parent) = current.parent() {
        if !support.scope_step() {
            return None;
        }
        if matches!(parent.kind(), "function_definition" | "lambda")
            && parent
                .child_by_field_name("body")
                .is_some_and(|body| body.start_byte() <= site_start && site_end <= body.end_byte())
        {
            return Some(PythonReferenceVisibility {
                class_scope: None,
                deferred_body: true,
            });
        }
        if class_scope.is_none() && parent.kind() == "class_definition" {
            class_scope = Some(parent);
        }
        current = parent;
    }
    Some(PythonReferenceVisibility {
        class_scope,
        deferred_body: false,
    })
}

fn python_class_node_for_candidate_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    source: &str,
    site: Node<'tree>,
    candidate: &CodeUnit,
) -> Option<Node<'tree>> {
    python_declaration_node_for_candidate_bounded(
        support,
        source,
        site,
        candidate,
        "class_definition",
    )
}

fn python_declaration_node_for_candidate_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    source: &str,
    site: Node<'tree>,
    candidate: &CodeUnit,
    declaration_kind: &str,
) -> Option<Node<'tree>> {
    let mut root = site;
    while let Some(parent) = root.parent() {
        if !support.scope_step() {
            return None;
        }
        root = parent;
    }
    for range in support.ranges(candidate) {
        if range.start_byte >= range.end_byte || range.end_byte > source.len() {
            continue;
        }
        let Some(mut node) = python_smallest_named_node_covering_bounded(
            support,
            root,
            range.start_byte,
            range.end_byte,
        ) else {
            continue;
        };
        loop {
            if node.kind() == declaration_kind
                && node
                    .child_by_field_name("name")
                    .is_some_and(|name| python_slice(name, source) == candidate.identifier())
            {
                return Some(node);
            }
            if node.kind() == "decorated_definition" {
                for child in python_named_children_bounded(support, node)? {
                    if child.kind() == declaration_kind
                        && child.child_by_field_name("name").is_some_and(|name| {
                            python_slice(name, source) == candidate.identifier()
                        })
                    {
                        return Some(child);
                    }
                }
            }
            let Some(parent) = node.parent() else {
                break;
            };
            if !support.scope_step() {
                return None;
            }
            node = parent;
        }
    }
    None
}

fn python_class_declaration_scope_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    declaration: Node<'tree>,
) -> Option<PythonClassDeclarationScope<'tree>> {
    match python_declaration_scope_bounded(support, declaration)? {
        PythonDeclarationScope::Module => Some(PythonClassDeclarationScope::Module),
        PythonDeclarationScope::Class(owner) => Some(PythonClassDeclarationScope::Class(owner)),
        PythonDeclarationScope::Function(_) | PythonDeclarationScope::Other => {
            Some(PythonClassDeclarationScope::Other)
        }
    }
}

fn python_same_file_function_visible_at(
    support: &PythonDefinitionProvider<'_>,
    source: &str,
    site: Node<'_>,
    candidate: &CodeUnit,
) -> Option<bool> {
    let declaration = python_function_node_for_candidate_bounded(support, source, site, candidate)?;
    let visibility = python_reference_visibility_bounded(support, site)?;
    match python_function_declaration_scope_bounded(support, declaration)? {
        PythonFunctionDeclarationScope::Module => {
            Some(visibility.deferred_body || declaration.start_byte() <= site.start_byte())
        }
        PythonFunctionDeclarationScope::Function(owner) => {
            let nearest = python_enclosing_callable_bounded(support, site)?;
            let mut inside_owner = false;
            let mut current = Some(site);
            while let Some(node) = current {
                if !support.scope_step() {
                    return None;
                }
                if node == owner {
                    inside_owner = true;
                    break;
                }
                current = node.parent();
            }
            Some(
                inside_owner && (nearest != owner || declaration.start_byte() <= site.start_byte()),
            )
        }
        PythonFunctionDeclarationScope::Other => Some(false),
    }
}

fn python_function_node_for_candidate_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    source: &str,
    site: Node<'tree>,
    candidate: &CodeUnit,
) -> Option<Node<'tree>> {
    python_declaration_node_for_candidate_bounded(
        support,
        source,
        site,
        candidate,
        "function_definition",
    )
}

fn python_function_declaration_scope_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    declaration: Node<'tree>,
) -> Option<PythonFunctionDeclarationScope<'tree>> {
    match python_declaration_scope_bounded(support, declaration)? {
        PythonDeclarationScope::Module => Some(PythonFunctionDeclarationScope::Module),
        PythonDeclarationScope::Function(owner) => {
            Some(PythonFunctionDeclarationScope::Function(owner))
        }
        PythonDeclarationScope::Class(_) | PythonDeclarationScope::Other => {
            Some(PythonFunctionDeclarationScope::Other)
        }
    }
}

fn python_declaration_scope_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    declaration: Node<'tree>,
) -> Option<PythonDeclarationScope<'tree>> {
    let mut current = declaration;
    while let Some(parent) = current.parent() {
        if !support.scope_step() {
            return None;
        }
        match parent.kind() {
            "module" => return Some(PythonDeclarationScope::Module),
            "class_definition" => return Some(PythonDeclarationScope::Class(parent)),
            "function_definition" | "lambda" => {
                return Some(PythonDeclarationScope::Function(parent));
            }
            "decorated_definition" => current = parent,
            "if_statement" | "for_statement" | "while_statement" | "try_statement"
            | "with_statement" | "match_statement" | "case_clause" => {
                return Some(PythonDeclarationScope::Other);
            }
            _ => current = parent,
        }
    }
    Some(PythonDeclarationScope::Other)
}

fn unique_python_candidate(mut candidates: Vec<CodeUnit>) -> Option<CodeUnit> {
    sort_units(&mut candidates);
    candidates.dedup();
    (candidates.len() == 1).then(|| candidates.remove(0))
}

fn python_current_receiver_class(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    name: &str,
) -> Option<CodeUnit> {
    if !matches!(name, "self" | "cls") {
        return None;
    }
    let function = python_enclosing_callable_bounded(support, node)?;
    let layout =
        formal_parameter_slots_for_owner_bounded(Language::Python, function, source, || {
            support.scope_step()
        })?;
    if matches!(layout.python_binding, Some(PythonMethodBinding::Static))
        || layout
            .slots
            .first()
            .is_none_or(|slot| !slot.names.iter().any(|candidate| candidate == name))
    {
        return None;
    }
    let mut parent = function.parent();
    while let Some(candidate) = parent {
        if !support.scope_step() {
            return None;
        }
        if candidate.kind() == "class_definition" {
            let class_name = candidate.child_by_field_name("name")?;
            return python_class_candidate_for_name(
                support,
                token,
                file,
                source,
                node,
                python_slice(class_name, source),
            );
        }
        if matches!(candidate.kind(), "function_definition" | "lambda") {
            return None;
        }
        parent = candidate.parent();
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn python_bound_type_for_identifier(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    identifier: Node<'_>,
    name: &str,
    depth: usize,
) -> Option<CodeUnit> {
    let function = python_enclosing_callable_bounded(support, identifier)?;
    if let Some(parameters) = function.child_by_field_name("parameters")
        && let Some(annotation) =
            python_parameter_annotation_bounded(support, parameters, source, name)
    {
        return python_type_from_annotation_bounded(
            support,
            token,
            file,
            source,
            annotation,
            depth + 1,
        );
    }
    let body = function.child_by_field_name("body")?;
    let mut best: Option<Node<'_>> = None;
    let mut stack = vec![body];
    while let Some(candidate) = stack.pop() {
        if !support.scope_step() {
            return None;
        }
        if candidate.start_byte() >= identifier.start_byte() {
            continue;
        }
        if candidate != body
            && matches!(
                candidate.kind(),
                "function_definition" | "lambda" | "class_definition"
            )
        {
            continue;
        }
        if candidate.kind() == "assignment"
            && let Some(left) = candidate.child_by_field_name("left")
            && left.kind() == "identifier"
            && python_slice(left, source) == name
            && best.is_none_or(|previous| previous.start_byte() < candidate.start_byte())
        {
            best = Some(candidate);
        }
        let children = python_named_children_bounded(support, candidate)?;
        stack.extend(children.into_iter().rev());
    }
    let assignment = best?;
    python_assignment_bound_type_bounded(support, token, file, source, root, assignment, depth + 1)
}

fn python_parameter_annotation_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    parameters: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<Node<'tree>> {
    let mut stack = vec![parameters];
    while let Some(node) = stack.pop() {
        if !support.scope_step() {
            return None;
        }
        if matches!(node.kind(), "typed_parameter" | "typed_default_parameter") {
            let binding = node.child_by_field_name("name").or_else(|| {
                node.named_child(0)
                    .filter(|candidate| candidate.kind() == "identifier")
            });
            if binding.is_some_and(|binding| python_slice(binding, source) == name) {
                if let Some(annotation) = node.child_by_field_name("type") {
                    return Some(annotation);
                }
                for candidate in python_named_children_bounded(support, node)? {
                    if candidate.kind() != "identifier" {
                        return Some(candidate);
                    }
                }
                return None;
            }
        }
        let children = python_named_children_bounded(support, node)?;
        stack.extend(children.into_iter().rev());
    }
    None
}

fn python_type_from_annotation_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    annotation: Node<'_>,
    depth: usize,
) -> Option<CodeUnit> {
    if depth >= 12 || !support.scope_step() {
        return None;
    }
    match annotation.kind() {
        "identifier" | "string_content" => python_class_candidate_for_name(
            support,
            token,
            file,
            source,
            annotation,
            python_slice(annotation, source),
        ),
        "attribute" => {
            let exact = python_slice(annotation, source);
            unique_python_candidate(
                support
                    .fqn(exact)
                    .into_iter()
                    .filter(CodeUnit::is_class)
                    .collect(),
            )
        }
        "string" => {
            let content = python_named_children_bounded(support, annotation)?
                .into_iter()
                .find(|child| child.kind() == "string_content")?;
            python_type_from_annotation_bounded(support, token, file, source, content, depth + 1)
        }
        // The grammar wraps an annotation, a PEP 695 bound and a `*Ts` unpack
        // around the type they carry, and the type is the first named child.
        "type" | "constrained_type" | "splat_type" | "type_parameter" => {
            let inner = python_named_children_bounded(support, annotation)?
                .into_iter()
                .next()?;
            python_type_from_annotation_bounded(support, token, file, source, inner, depth + 1)
        }
        // A subscripted annotation names its outer class, never a type
        // argument: `list[int]` is a `list` and `Generator[Result, None,
        // None]` is a generator, not a `Result`. `Optional[X]` and
        // `Union[...]` are the two forms that name their arguments instead.
        "generic_type" | "subscript" => {
            let parts = python_subscripted_annotation_parts(support, annotation)?;
            if python_annotation_names_its_arguments(parts.base, source) {
                let mut candidates = Vec::new();
                for argument in parts.arguments {
                    if let Some(candidate) = python_type_from_annotation_bounded(
                        support,
                        token,
                        file,
                        source,
                        argument,
                        depth + 1,
                    ) {
                        candidates.push(candidate);
                    }
                }
                unique_python_candidate(candidates)
            } else {
                python_type_from_annotation_bounded(
                    support,
                    token,
                    file,
                    source,
                    parts.base,
                    depth + 1,
                )
            }
        }
        // A PEP 604 `X | Y` names each member of the union. The grammar
        // spells it `union_type` in a type position and `binary_operator`
        // where the annotation is read as an expression.
        "union_type" | "binary_operator"
            if annotation.kind() == "union_type"
                || annotation
                    .child_by_field_name("operator")
                    .is_some_and(|operator| operator.kind() == "|") =>
        {
            let mut candidates = Vec::new();
            for member in python_named_children_bounded(support, annotation)? {
                if let Some(candidate) = python_type_from_annotation_bounded(
                    support,
                    token,
                    file,
                    source,
                    member,
                    depth + 1,
                ) {
                    candidates.push(candidate);
                }
            }
            unique_python_candidate(candidates)
        }
        _ => None,
    }
}

/// The outer type and the type arguments of a subscripted annotation.
struct PythonSubscriptedAnnotation<'tree> {
    base: Node<'tree>,
    arguments: Vec<Node<'tree>>,
}

fn python_subscripted_annotation_parts<'tree>(
    support: &PythonDefinitionProvider<'_>,
    annotation: Node<'tree>,
) -> Option<PythonSubscriptedAnnotation<'tree>> {
    match annotation.kind() {
        // `list[int]` in an annotation: the outer name comes first and the
        // bracketed arguments follow as one `type_parameter` list.
        "generic_type" => {
            let mut children = python_named_children_bounded(support, annotation)?.into_iter();
            let base = children.next()?;
            let mut arguments = Vec::new();
            for list in children {
                arguments.extend(python_named_children_bounded(support, list)?);
            }
            Some(PythonSubscriptedAnnotation { base, arguments })
        }
        // The same shape reached through expression syntax carries its
        // arguments in one or more `subscript` fields.
        "subscript" => {
            let base = annotation.child_by_field_name("value")?;
            let mut arguments = Vec::new();
            let mut cursor = annotation.walk();
            for child in annotation.children_by_field_name("subscript", &mut cursor) {
                if !support.scope_step() {
                    return None;
                }
                if child.kind() == "tuple" {
                    arguments.extend(python_named_children_bounded(support, child)?);
                } else {
                    arguments.push(child);
                }
            }
            Some(PythonSubscriptedAnnotation { base, arguments })
        }
        _ => None,
    }
}

/// Whether a subscripted annotation's outer name is one of the two forms whose
/// type arguments are the annotated classes rather than parameters of an outer
/// class: `Optional[X]` and `Union[...]`.
fn python_annotation_names_its_arguments(base: Node<'_>, source: &str) -> bool {
    let name = match base.kind() {
        "identifier" => python_slice(base, source),
        "attribute" => {
            let (Some(object), Some(attribute)) = (
                base.child_by_field_name("object"),
                base.child_by_field_name("attribute"),
            ) else {
                return false;
            };
            if object.kind() != "identifier"
                || attribute.kind() != "identifier"
                || !matches!(python_slice(object, source), "typing" | "typing_extensions")
            {
                return false;
            }
            python_slice(attribute, source)
        }
        _ => return false,
    };
    matches!(name, "Optional" | "Union")
}

fn python_callable_return_type_in_tree(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    callable: &CodeUnit,
    depth: usize,
) -> Option<CodeUnit> {
    if callable.source() != file || depth >= 12 {
        return None;
    }
    let ranges = support.ranges(callable);
    let mut functions = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !support.scope_step() {
            return None;
        }
        if node.kind() == "function_definition"
            && node
                .child_by_field_name("name")
                .is_some_and(|name| python_slice(name, source) == callable.identifier())
            && ranges.iter().any(|range| {
                range.start_byte <= node.start_byte() && node.end_byte() <= range.end_byte
            })
        {
            functions.push(node);
            continue;
        }
        let children = python_named_children_bounded(support, node)?;
        stack.extend(children.into_iter().rev());
    }
    let function = (functions.len() == 1).then(|| functions.remove(0))?;
    python_function_return_type_from_node_bounded(
        support, token, file, source, root, function, depth,
    )
}

/// Whether a function definition is a coroutine function.
///
/// The grammar marks it with an `async` token before `def` rather than with a
/// distinct node kind or a field.
fn python_function_is_async(function: Node<'_>) -> bool {
    let mut cursor = function.walk();
    function
        .children(&mut cursor)
        .any(|child| !child.is_named() && child.kind() == "async")
}

fn python_function_return_type_from_node_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    function: Node<'_>,
    depth: usize,
) -> Option<CodeUnit> {
    // Calling an `async def` produces a coroutine. Its annotation describes
    // what awaiting that coroutine yields, so it is not the call's own type,
    // and the body's `return` values are not either.
    if python_function_is_async(function) {
        return None;
    }
    let facts = support.callable_source_facts(token, file)?;
    let declaration = function
        .parent()
        .filter(|parent| parent.kind() == "decorated_definition")
        .unwrap_or(function);
    let Some(fact) =
        facts.callable_return_for_range(declaration.start_byte(), declaration.end_byte(), &|| {
            support.scope_step()
        })
    else {
        support.source_facts_unavailable.set(true);
        return None;
    };
    if fact.return_annotation.is_some() {
        return python_captured_return_type_bounded(
            support,
            token,
            file,
            source,
            root,
            &facts,
            fact,
            depth + 1,
        );
    }

    let body = function.child_by_field_name("body")?;
    let mut returns = Vec::new();
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        if !support.scope_step() {
            return None;
        }
        if node != body
            && matches!(
                node.kind(),
                "function_definition" | "lambda" | "class_definition"
            )
        {
            continue;
        }
        if node.kind() == "return_statement"
            && let Some(value) = node.named_child(0)
            && let Some(candidate) = python_type_for_expression_bounded(
                support,
                token,
                file,
                source,
                root,
                value,
                depth + 1,
            )
        {
            returns.push(candidate);
            continue;
        }
        let children = python_named_children_bounded(support, node)?;
        stack.extend(children.into_iter().rev());
    }
    unique_python_candidate(returns)
}

/// Resolve source-owned annotation candidates in the active lexical scope.
/// Their ordering and attribute fallback structure were selected by the primary
/// producer; this walk does not interpret declaration annotation syntax.
#[allow(clippy::too_many_arguments)]
fn python_captured_return_type_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    facts: &brokk_bifrost_python::source_facts::PythonFileSourceFacts,
    fact: &brokk_bifrost_core::analyzer::python_facts::PythonCallableReturnFact,
    depth: usize,
) -> Option<CodeUnit> {
    use brokk_bifrost_core::analyzer::python_facts::PythonAnnotationReferenceName;
    let mut candidates = Vec::new();
    let mut index = 0;
    while let Some(reference) = fact.annotation_references.get(index) {
        if !support.scope_step() {
            return None;
        }
        if depth.saturating_add(usize::from(reference.lookup_depth)) >= 12 {
            index += 1;
            continue;
        }
        let candidate = match &reference.name {
            PythonAnnotationReferenceName::Lexical(name) => {
                let range = facts.occurrences.occurrence(reference.occurrence).range;
                let focus = root.descendant_for_byte_range(range.start_byte, range.end_byte);
                let Some(focus) = focus.filter(|focus| {
                    focus.start_byte() == range.start_byte && focus.end_byte() == range.end_byte
                }) else {
                    support.source_facts_unavailable.set(true);
                    return None;
                };
                python_class_candidate_for_name(support, token, file, source, focus, name)
            }
            PythonAnnotationReferenceName::Qualified(path) => unique_python_candidate(
                support
                    .fqn(&path.join("."))
                    .into_iter()
                    .filter(CodeUnit::is_class)
                    .collect(),
            ),
            PythonAnnotationReferenceName::Unavailable => None,
        };
        if let Some(candidate) = candidate {
            candidates.push(candidate);
            index = reference.subtree_end;
        } else {
            index += 1;
        }
    }
    unique_python_candidate(candidates)
}

fn python_enclosing_callable_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    node: Node<'tree>,
) -> Option<Node<'tree>> {
    python_nearest_enclosing_callable(node, || support.scope_step(), |_| true)
}

fn python_nearest_enclosing_callable<'tree>(
    node: Node<'tree>,
    mut scope_step: impl FnMut() -> bool,
    mut accepts: impl FnMut(Node<'tree>) -> bool,
) -> Option<Node<'tree>> {
    let mut parent = node.parent();
    while let Some(candidate) = parent {
        if !scope_step() {
            return None;
        }
        if matches!(candidate.kind(), "function_definition" | "lambda") && accepts(candidate) {
            return Some(candidate);
        }
        parent = candidate.parent();
    }
    None
}

fn python_has_lexical_binding_bounded(
    support: &PythonDefinitionProvider<'_>,
    identifier: Node<'_>,
    source: &str,
) -> bool {
    !matches!(
        python_lexical_binding_bounded(support, identifier, source),
        PythonLexicalBinding::UnboundOrGlobal
    )
}

#[derive(Clone, Copy, Debug)]
enum PythonLexicalBinding<'tree> {
    UnboundOrGlobal,
    LocalFunction(Node<'tree>),
    LocalClass(Node<'tree>),
    Other,
}

fn python_lexical_binding_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    identifier: Node<'tree>,
    source: &str,
) -> PythonLexicalBinding<'tree> {
    match python_lexical_declaration_binding_bounded(support, identifier, source) {
        PythonLexicalBinding::LocalClass(_) => PythonLexicalBinding::Other,
        binding => binding,
    }
}

fn python_lexical_declaration_binding_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    identifier: Node<'tree>,
    source: &str,
) -> PythonLexicalBinding<'tree> {
    let name = python_slice(identifier, source);
    let reference_start = identifier.start_byte();
    let reference_end = identifier.end_byte();
    let mut current = identifier;
    let mut unresolved_nonlocal = false;
    while let Some(candidate) = current.parent() {
        if !support.scope_step() {
            // Exhausted or cancelled binding discovery must never reopen the
            // module-level class fallback.
            return PythonLexicalBinding::Other;
        }
        if matches!(candidate.kind(), "function_definition" | "lambda")
            && candidate.child_by_field_name("body").is_some_and(|body| {
                body.start_byte() <= reference_start && reference_end <= body.end_byte()
            })
        {
            let Some(inventory) =
                python_lexical_scope_inventory_bounded(candidate, source, || support.scope_step())
            else {
                return PythonLexicalBinding::Other;
            };
            let Some(resolution) =
                inventory.name_resolution_at_bounded(name, identifier, || support.scope_step())
            else {
                return PythonLexicalBinding::Other;
            };
            match resolution {
                PythonLexicalNameResolution::Local => {
                    let declaration = if let Some(declaration) = inventory
                        .local_function_declaration_bounded(name, identifier, || {
                            support.scope_step()
                        }) {
                        declaration
                    } else if let Some(declaration) =
                        inventory.local_class_declaration_bounded(name, identifier, || {
                            support.scope_step()
                        })
                    {
                        // Class bases execute now. Prove a preceding class in
                        // the identical immediate statement container; never
                        // turn a parameter/assignment/conditional into a class.
                        let mut statement = identifier;
                        while statement.parent().is_some_and(|parent| {
                            parent.kind() != "block" && parent.kind() != "module"
                        }) {
                            if !support.scope_step() {
                                return PythonLexicalBinding::Other;
                            }
                            statement = statement.parent().expect("parent checked");
                        }
                        return if declaration.parent() == statement.parent()
                            && declaration.end_byte() <= statement.start_byte()
                            && declaration.parent() == candidate.child_by_field_name("body")
                        {
                            PythonLexicalBinding::LocalClass(declaration)
                        } else {
                            PythonLexicalBinding::Other
                        };
                    } else {
                        return PythonLexicalBinding::Other;
                    };
                    let Some(PythonFunctionDeclarationScope::Function(owner)) =
                        python_function_declaration_scope_bounded(support, declaration)
                    else {
                        return PythonLexicalBinding::Other;
                    };
                    let Some(nearest) = python_enclosing_body_callable_bounded(support, identifier)
                    else {
                        return PythonLexicalBinding::Other;
                    };
                    return if owner == candidate
                        && (nearest != owner || declaration.start_byte() <= identifier.start_byte())
                    {
                        PythonLexicalBinding::LocalFunction(declaration)
                    } else {
                        PythonLexicalBinding::Other
                    };
                }
                PythonLexicalNameResolution::Nonlocal => unresolved_nonlocal = true,
                PythonLexicalNameResolution::Global => {
                    return if python_global_binding_is_untouched_bounded(
                        name,
                        identifier,
                        candidate,
                        source,
                        || support.scope_step(),
                    ) == Some(true)
                    {
                        PythonLexicalBinding::UnboundOrGlobal
                    } else {
                        PythonLexicalBinding::Other
                    };
                }
                PythonLexicalNameResolution::Unbound => {}
            }
        }
        current = candidate;
    }
    if unresolved_nonlocal {
        PythonLexicalBinding::Other
    } else {
        PythonLexicalBinding::UnboundOrGlobal
    }
}

fn python_enclosing_body_callable_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    node: Node<'tree>,
) -> Option<Node<'tree>> {
    let reference_start = node.start_byte();
    let reference_end = node.end_byte();
    python_nearest_enclosing_callable(
        node,
        || support.scope_step(),
        |candidate| {
            candidate.child_by_field_name("body").is_some_and(|body| {
                body.start_byte() <= reference_start && reference_end <= body.end_byte()
            })
        },
    )
}

pub(crate) fn resolve_python(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    context: &mut DefinitionBatchContext<'_, '_>,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    let Some(py) = resolve_analyzer::<PythonAnalyzer>(analyzer) else {
        return no_definition(
            "python_analyzer_unavailable",
            "Python analyzer is unavailable",
        );
    };
    let Some(tree) = tree else {
        return no_definition("python_parse_failed", "Python source could not be parsed");
    };
    if py.python_source_facts(token, file, &|| true).is_none() {
        return no_definition(
            "python_source_facts_unavailable",
            "Canonical Python declaration annotations are unavailable",
        );
    }
    let Some(node) =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)
    else {
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed Python definition",
                site.text
            ),
        );
    };
    if let Some(module_fqn) = python_import_module_fqn(py.project(), file, source, node)
        && let Some(module) = resolve_module_code_unit(py, Some(file), &module_fqn)
    {
        return candidates_outcome(vec![module]);
    }
    if python_is_non_reference_context(node) || python_is_declaration_identifier(node) {
        return no_definition(
            "declaration_or_import_site",
            format!("`{}` is not a Python reference site", site.text),
        );
    }
    if python_type_parameter_binds_name_at(&site.text, node, source) {
        return no_definition(
            "local_variable_reference",
            format!("`{}` is a local Python type parameter", site.text),
        );
    }
    if let Some(candidates) = python_annotation_focus_candidates(
        analyzer,
        py,
        file,
        source,
        node,
        site.focus_start_byte,
        site.focus_end_byte,
    ) {
        return if candidates.is_empty() {
            no_definition(
                "no_indexed_definition",
                format!(
                    "annotation `{}` did not resolve to an indexed Python definition",
                    site.text
                ),
            )
        } else {
            candidates_outcome(candidates)
        };
    }

    let ctx = context
        .language_state::<PythonDefinitionState>()
        .python_context(token, py, analyzer, file, source);
    let support = context.bounded_support();
    let reference = python_reference_node(node);
    match reference {
        Some(PythonReferenceNode::Attribute { object, attribute }) => {
            let object_text = python_slice(object, source);
            let attribute_text = python_slice(attribute, source);
            if object_text.is_empty() || attribute_text.is_empty() {
                return no_definition("no_reference_text", "Python attribute reference is blank");
            }
            // Shadowing belongs to the root binding, not the rendered object
            // chain. For `K.feature.DISK` the import binder is `K`; asking the
            // lexical inventory about the non-binding spelling `K.feature`
            // allowed a parameter named `K` to fall through to the namespace
            // import route.
            let (shadow_name, shadow_site) = leftmost_identifier(object)
                .map(|root| (python_slice(root, source), root))
                .unwrap_or((object_text, object));
            let object_shadowed = ctx.name_shadowed_at(shadow_name, shadow_site, source);
            if !object_shadowed && let Some(module) = ctx.namespace_module_for_node(object, source)
            {
                return python_fqn_outcome(
                    py,
                    support,
                    file,
                    &format!("{module}.{attribute_text}"),
                    site.text.as_str(),
                );
            }
            if !object_shadowed
                && let Some(receiver_type) = ctx.receiver_type_for_object(py, support, object_text)
            {
                return python_member_outcome(
                    analyzer,
                    support,
                    receiver_type,
                    attribute_text,
                    site,
                );
            }
            if let Some(receiver_type) = python_receiver_type_unit(
                analyzer,
                token,
                py,
                support,
                &ctx,
                file,
                source,
                tree.root_node(),
                object,
            ) {
                return python_member_outcome(
                    analyzer,
                    support,
                    receiver_type,
                    attribute_text,
                    site,
                );
            }
            if object_shadowed {
                return no_definition(
                    "local_variable_reference",
                    format!("`{object_text}` is a local Python value"),
                );
            }
            if let Some(import_target) = python_unresolved_import_boundary(
                py,
                file,
                analyzer,
                token,
                object_text,
                Some(attribute_text),
            ) {
                return python_import_binding_outcome(
                    analyzer,
                    py,
                    token,
                    support,
                    file,
                    object_text,
                    Some(attribute_text),
                    &import_target,
                    site.text.as_str(),
                );
            }
            no_definition(
                "no_indexed_definition",
                format!(
                    "`{}` did not resolve to an indexed Python definition",
                    site.text
                ),
            )
        }
        Some(PythonReferenceNode::Identifier(identifier)) => {
            let Some(text) = python_focused_reference_text(
                identifier,
                source,
                site.focus_start_byte,
                site.focus_end_byte,
                None,
            ) else {
                return no_definition(
                    "python_reference_shape_unsupported",
                    format!("`{}` is not a parsed Python reference", site.text),
                );
            };
            if text.is_empty() {
                return no_definition("no_reference_text", "Python identifier is blank");
            }
            if let Some(candidates) = python_function_import_binding_candidates(
                py,
                support,
                &ctx,
                source,
                tree.root_node(),
                identifier,
                text,
            ) {
                return if candidates.is_empty() {
                    no_definition(
                        "local_variable_reference",
                        format!(
                            "`{text}` has a function-local Python binding without one indexed import target"
                        ),
                    )
                } else {
                    candidates_outcome(candidates)
                };
            }
            if ctx.name_shadowed_at(text, identifier, source) {
                return no_definition(
                    "local_variable_reference",
                    format!("`{text}` is a local Python value"),
                );
            }
            if let Some(local) = ctx.same_file.get(text) {
                let class_candidates =
                    python_visible_class_binding_candidates(analyzer, file, identifier, local);
                if !class_candidates.is_empty() {
                    return candidates_outcome(class_candidates);
                }
            }
            if let Some(candidates) = python_visible_module_binding_candidates(
                analyzer,
                py,
                support,
                &ctx,
                source,
                tree.root_node(),
                identifier,
                text,
            ) {
                if !candidates.is_empty() {
                    return candidates_outcome(candidates);
                }
                if let Some(import_target) =
                    python_unresolved_import_boundary(py, file, analyzer, token, text, None)
                {
                    return python_import_binding_outcome(
                        analyzer,
                        py,
                        token,
                        support,
                        file,
                        text,
                        None,
                        &import_target,
                        text,
                    );
                }
                if is_python_builtin_or_constant(text) {
                    return no_definition(
                        PREDECLARED_SYMBOL_REFERENCE_DIAGNOSTIC_KIND,
                        format!("`{text}` is supplied by the Python runtime"),
                    );
                }
                if let Some(module) = ctx.namespace.get(text) {
                    return python_module_outcome(py, support, file, module, text);
                }
                return no_definition(
                    "no_indexed_definition",
                    format!("`{text}` is bound locally but has no indexed Python definition"),
                );
            }
            if let Some(module) = ctx.namespace.get(text) {
                return python_module_outcome(py, support, file, module, text);
            }
            if let Some(fqn) = ctx.named.get(text) {
                return python_fqn_outcome(py, support, file, fqn, text);
            }
            if let Some(candidates) = ctx.same_file.get(text)
                && !candidates.is_empty()
            {
                let candidates =
                    python_visible_same_file_candidates(analyzer, file, identifier, candidates);
                if !candidates.is_empty() {
                    return candidates_outcome(candidates);
                }
            }
            if is_python_builtin_or_constant(text) {
                return no_definition(
                    PREDECLARED_SYMBOL_REFERENCE_DIAGNOSTIC_KIND,
                    format!("`{text}` is supplied by the Python runtime"),
                );
            }
            if let Some(import_target) =
                python_unresolved_import_boundary(py, file, analyzer, token, text, None)
            {
                return python_import_binding_outcome(
                    analyzer,
                    py,
                    token,
                    support,
                    file,
                    text,
                    None,
                    &import_target,
                    text,
                );
            }
            no_definition(
                "no_indexed_definition",
                format!("`{text}` did not resolve to an indexed Python definition"),
            )
        }
        Some(PythonReferenceNode::KeywordArgument { call, name }) => {
            let name_text = python_slice(name, source);
            if name_text.is_empty() {
                return no_definition("no_reference_text", "Python keyword argument is blank");
            }
            let Some(function) = call.child_by_field_name("function") else {
                return no_definition("no_function_name", "Python call has no callee");
            };
            // `Foo(a=..)` -> `a` is a member/parameter of the callee's type (e.g. a
            // dataclass field `Foo.a`). Type the callee and look the name up as a
            // member.
            if let Some(receiver_type) = python_receiver_type_unit(
                analyzer,
                token,
                py,
                support,
                &ctx,
                file,
                source,
                tree.root_node(),
                function,
            ) {
                return python_member_outcome(analyzer, support, receiver_type, name_text, site);
            }
            no_definition(
                "no_indexed_definition",
                format!(
                    "keyword argument `{name_text}` did not resolve to an indexed Python member"
                ),
            )
        }
        None => no_definition(
            "unsupported_python_reference_shape",
            format!(
                "`{}` is a Python `{}` reference shape that get_definition does not resolve yet",
                site.text,
                node.kind()
            ),
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn python_annotation_focus_candidates(
    analyzer: &dyn IAnalyzer,
    python: &PythonAnalyzer,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    focus_start: usize,
    focus_end: usize,
) -> Option<Vec<CodeUnit>> {
    with_python_graph_source(analyzer, |graph| {
        annotation_reference_candidates_at_focus(
            &graph,
            python,
            file,
            source,
            node,
            focus_start,
            focus_end,
            true,
        )
    })
}

/// Restore the exact synthetic identifier selected inside a deferred annotation.
///
/// Tree-sitter represents the contents of `"Widget | Gadget"` as one
/// `string_content` leaf. The generic reference-site resolver therefore widens
/// either structured occurrence range to that whole leaf, even though the
/// Python adapter has parsed and validated two distinct identifier ranges
/// inside it. Narrow only ranges reproduced by that structured parser; ordinary
/// strings and arbitrary subranges retain the generic fail-closed behavior.
pub(crate) fn python_site_for_focus(
    mut site: ResolvedReferenceSite,
    tree: &Tree,
    source: &str,
    requested_start: Option<usize>,
    requested_end: Option<usize>,
) -> ResolvedReferenceSite {
    let (Some(start), Some(end)) = (requested_start, requested_end) else {
        return site;
    };
    let Some(node) = smallest_named_node_covering(tree.root_node(), start, end) else {
        return site;
    };
    if node.kind() != "string_content" {
        return site;
    }
    let Some(string) = node.parent() else {
        return site;
    };
    let exact_deferred_identifier =
        python_deferred_annotation_identifier_ranges(string, source, None).is_some_and(|ranges| {
            ranges
                .iter()
                .any(|range| range.start_byte == start && range.end_byte == end)
        });
    if !exact_deferred_identifier {
        return site;
    }
    let Some(text) = source.get(start..end) else {
        return site;
    };
    let line_starts = compute_line_starts(source);
    site.text = text.to_owned();
    site.range = Range {
        start_byte: start,
        end_byte: end,
        start_line: find_line_index_for_offset(&line_starts, start) + 1,
        end_line: find_line_index_for_offset(&line_starts, end.saturating_sub(1)) + 1,
    };
    site.focus_start_byte = start;
    site.focus_end_byte = end;
    site
}

/// Exact external callable selected by one explicit Python import.
///
/// Identity comes from the tree-sitter import binder and call expression, not
/// from the local spelling. A proof exists only when that import is the one
/// unconditional, module- or function-scoped binding visible at a static call.
/// Rebinding, competing bindings, wildcard/class-local uncertainty, and the
/// wrong attribute depth intentionally return no proof.
pub(crate) struct PythonImportedCallSelection {
    pub(crate) proof: ExactExternalCallProof,
    pub(crate) module: Vec<String>,
    pub(crate) member: String,
}

/// An import path is not yet a class or callable declaration proof.
pub(crate) struct PythonImportedSymbolSelection {
    pub(crate) module: Vec<String>,
    pub(crate) member: String,
    canonical_name: String,
    import_kind: brokk_bifrost_core::analyzer::model::StructuredImportPathKind,
    // Selected structured namespace segments consumed before the final member.
    consumed_attributes: usize,
    requires_imported_module: bool,
}

impl PythonImportedSymbolSelection {
    /// Import selection alone cannot turn an imported value into a module.
    /// Share the original external intermediate-module admission across local
    /// class bases, decorators and other exact imported-symbol consumers.
    pub(crate) fn external_symbol_bounded(
        self,
        support: &PythonDefinitionProvider<'_>,
    ) -> Option<(String, String)> {
        let first_module = match self.import_kind {
            brokk_bifrost_core::analyzer::model::StructuredImportPathKind::ImportFrom
                if self.requires_imported_module =>
            {
                Some(self.module.len())
            }
            brokk_bifrost_core::analyzer::model::StructuredImportPathKind::Namespace
                if self.consumed_attributes > 0 =>
            {
                Some(self.module.len().checked_sub(self.consumed_attributes)?)
            }
            _ => None,
        };
        if let Some(first) = first_module {
            for end in first..=self.module.len() {
                if !support.scope_step() {
                    return None;
                }
                python_complete_external_module(support, &self.module[..end].join("."))?;
            }
        }
        let module = self.module.join(".");
        python_external_model_namespace_available(support, &module, &self.member)
            .then_some((module, self.member))
    }
}

enum PythonFunctionImportSelection<'a> {
    Selected(&'a PythonImportBinding),
    NotLocal,
    Blocked,
}

/// Shared import-binding proof for a selected expression, before source or
/// external declaration admission. None is a stopped walk, not an empty proof.
pub(crate) fn python_local_imported_symbol_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
) -> Option<Option<PythonImportedSymbolSelection>> {
    if !support.python.indexed_source_matches(file, source) {
        return None;
    }
    let Some(path) = python_static_attribute_path_bounded(expression, || support.scope_step())
    else {
        return if support.session.observe_cancellation() {
            Some(None)
        } else {
            None
        };
    };
    let reference = *path.first()?;
    // Module/class-body-only references keep their existing module gates;
    // no function-local import projection is needed for that route.
    let owner = python_nearest_enclosing_callable(
        reference,
        || support.scope_step(),
        |candidate| {
            candidate.child_by_field_name("body").is_some_and(|body| {
                body.start_byte() <= reference.start_byte()
                    && reference.end_byte() <= body.end_byte()
            })
        },
    );
    if owner.is_none() {
        return if support.session.observe_cancellation() {
            Some(None)
        } else {
            None
        };
    }
    let imports = support
        .session
        .query(|| support.python.import_info_of(token, file))?;
    let bindings =
        python_import_bindings_from_imports_bounded(&imports, root, source.len(), || {
            support.scope_step()
        })?;
    let binding = match python_visible_function_import_binding_bounded(
        &bindings,
        python_slice(reference, source),
        reference,
        source,
        || support.scope_step(),
    )? {
        PythonFunctionImportSelection::Selected(binding) => binding,
        PythonFunctionImportSelection::NotLocal | PythonFunctionImportSelection::Blocked => {
            return Some(None);
        }
    };
    let selected =
        python_imported_symbol_for_binding_bounded(binding, &path, &imports, source, || {
            support.scope_step()
        });
    if !support.python.indexed_source_matches(file, source) {
        return None;
    }
    if !support.session.observe_cancellation() {
        return None;
    }
    Some(selected)
}

fn python_imported_symbol_for_binding_bounded(
    binding: &PythonImportBinding,
    path: &[Node<'_>],
    imports: &[brokk_bifrost_core::analyzer::model::ImportInfo],
    source: &str,
    mut scope_step: impl FnMut() -> bool,
) -> Option<PythonImportedSymbolSelection> {
    let local_name = python_slice(*path.first()?, source);
    let final_segment = python_slice(*path.last()?, source);
    let canonical_name = if path.len() == 1 {
        (binding.consumed_attributes == 0).then(|| binding.qualified_name.clone())?
    } else {
        (path.len() - 1 == binding.consumed_attributes + 1)
            .then(|| format!("{}.{}", binding.qualified_name, final_segment))?
    };
    let mut matched = None;
    for import in imports {
        if !scope_step() {
            return None;
        }
        let Some(import_path) = &import.path else {
            continue;
        };
        for _ in &import_path.segments {
            if !scope_step() {
                return None;
            }
        }
        if import_path.declaration_start_byte == binding.start_byte
            && import_path.render_segments(".") == binding.qualified_name
            && import.local_name() == Some(local_name)
        {
            if matched.is_some() {
                return None;
            }
            matched = Some(import_path);
        }
    }
    let import = matched?;
    // An unaliased dotted namespace import consumes those exact receiver
    // segments, not any receiver prefix of the same length. Aliases consume
    // no attributes; their local token was checked against ImportInfo above.
    if binding.consumed_attributes > 0 {
        if import.kind
            != Some(brokk_bifrost_core::analyzer::model::StructuredImportPathKind::Namespace)
            || import.segments.len() != binding.consumed_attributes + 1
        {
            return None;
        }
        for (node, segment) in path.iter().zip(&import.segments) {
            if !scope_step() || python_slice(*node, source) != segment {
                return None;
            }
        }
    }
    if path.len() == 1
        && import.kind
            != Some(brokk_bifrost_core::analyzer::model::StructuredImportPathKind::ImportFrom)
    {
        return None;
    }
    let (module, member) = if path.len() == 1 {
        let (member, module) = import.segments.split_last()?;
        (module.to_vec(), member.clone())
    } else {
        (import.segments.clone(), final_segment.to_owned())
    };
    if !scope_step() {
        return None;
    }
    Some(PythonImportedSymbolSelection {
        module,
        member,
        canonical_name,
        import_kind: import.kind?,
        consumed_attributes: binding.consumed_attributes,
        requires_imported_module: path.len() > 1,
    })
}

pub(crate) fn exact_python_imported_call_selection(
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    imports: &[brokk_bifrost_core::analyzer::model::ImportInfo],
    mut scope_step: impl FnMut() -> bool,
) -> Option<PythonImportedCallSelection> {
    let root = tree.root_node();
    let callee = brokk_bifrost_core::analyzer::usages::reference_site::smallest_named_node_covering_with_scope(
        root, site.focus_start_byte, site.focus_end_byte, &mut scope_step,
    )?;
    if !scope_step() || callee.kind() != "identifier" {
        return None;
    }
    let parent = callee.parent()?;
    let focused_chain = if parent.kind() == "attribute" {
        (parent.child_by_field_name("attribute") == Some(callee)).then_some(parent)?
    } else {
        callee
    };
    let call = focused_chain.parent()?;
    if call.kind() != "call" || call.child_by_field_name("function") != Some(focused_chain) {
        return None;
    }
    let path = python_static_attribute_path_bounded(focused_chain, &mut scope_step)?;
    if path.last()?.id() != callee.id() {
        return None;
    }
    let bindings =
        python_import_bindings_from_imports_bounded(imports, root, source.len(), &mut scope_step)?;
    let reference = *path.first()?;
    let name = python_slice(reference, source);
    let binding = match python_visible_function_import_binding_bounded(
        &bindings,
        name,
        reference,
        source,
        &mut scope_step,
    )? {
        PythonFunctionImportSelection::Selected(binding) => binding,
        PythonFunctionImportSelection::Blocked => return None,
        PythonFunctionImportSelection::NotLocal => python_visible_module_import_binding_bounded(
            root,
            &bindings,
            name,
            reference,
            source,
            &mut scope_step,
        )??,
    };
    let selected = python_imported_symbol_for_binding_bounded(
        binding,
        &path,
        imports,
        source,
        &mut scope_step,
    )?;
    let arguments = call.child_by_field_name("arguments")?;
    let mut parameter_count = 0u32;
    let mut cursor = arguments.walk();
    for _ in arguments.named_children(&mut cursor) {
        if !scope_step() {
            return None;
        }
        parameter_count = parameter_count.checked_add(1)?;
    }
    Some(PythonImportedCallSelection {
        proof: ExactExternalCallProof::python_imported_call(
            selected.canonical_name,
            parameter_count,
        ),
        module: selected.module,
        member: selected.member,
    })
}

fn python_visible_function_import_binding_bounded<'a>(
    bindings: &'a [PythonImportBinding],
    local_name: &str,
    reference: Node<'_>,
    source: &str,
    mut scope_step: impl FnMut() -> bool,
) -> Option<PythonFunctionImportSelection<'a>> {
    use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, try_walk_named_tree_preorder};
    if python_comprehension_binds_name_at_bounded(local_name, reference, source, &mut scope_step)?
        || python_type_parameter_binds_name_at_bounded(
            local_name,
            reference,
            source,
            &mut scope_step,
        )?
    {
        return Some(PythonFunctionImportSelection::Blocked);
    }
    let mut current = reference;
    let mut crossed_callable = false;
    let mut crossed_class_namespace = false;
    while let Some(parent) = current.parent() {
        if !scope_step() {
            return None;
        }
        let inside_body = parent.child_by_field_name("body").is_some_and(|body| {
            body.start_byte() <= reference.start_byte() && reference.end_byte() <= body.end_byte()
        });
        if parent.kind() == "class_definition"
            && inside_body
            && !crossed_callable
            && !crossed_class_namespace
        {
            let class_scope =
                PythonClassReferenceScope::new_bounded(parent, reference, &mut scope_step)?;
            let inventory = class_scope.collect_bounded(source, &mut scope_step)?;
            match inventory.name_resolution_at_bounded(local_name, reference, &mut scope_step)? {
                PythonLexicalNameResolution::Global => {
                    return Some(
                        if python_global_binding_is_untouched_bounded(
                            local_name,
                            reference,
                            parent,
                            source,
                            &mut scope_step,
                        )? {
                            PythonFunctionImportSelection::NotLocal
                        } else {
                            PythonFunctionImportSelection::Blocked
                        },
                    );
                }
                PythonLexicalNameResolution::Nonlocal | PythonLexicalNameResolution::Local => {
                    return Some(PythonFunctionImportSelection::Blocked);
                }
                PythonLexicalNameResolution::Unbound => {
                    if class_scope.binds_name_bounded(local_name, source, &mut scope_step)? {
                        return Some(PythonFunctionImportSelection::Blocked);
                    }
                    // A nested class does not capture an outer class namespace.
                    crossed_class_namespace = true;
                }
            }
        } else if inside_body && matches!(parent.kind(), "function_definition" | "lambda") {
            let inventory =
                python_lexical_scope_inventory_bounded(parent, source, &mut scope_step)?;
            match inventory.name_resolution_at_bounded(local_name, reference, &mut scope_step)? {
                PythonLexicalNameResolution::Global => {
                    return Some(
                        if python_global_binding_is_untouched_bounded(
                            local_name,
                            reference,
                            parent,
                            source,
                            &mut scope_step,
                        )? {
                            PythonFunctionImportSelection::NotLocal
                        } else {
                            PythonFunctionImportSelection::Blocked
                        },
                    );
                }
                PythonLexicalNameResolution::Nonlocal => {
                    return Some(PythonFunctionImportSelection::Blocked);
                }
                PythonLexicalNameResolution::Unbound => crossed_callable = true,
                PythonLexicalNameResolution::Local => {
                    if crossed_callable {
                        return Some(PythonFunctionImportSelection::Blocked);
                    }
                    let Some(declaration) = inventory.unique_import_declaration_bounded(
                        local_name,
                        reference,
                        &mut scope_step,
                    )?
                    else {
                        return Some(PythonFunctionImportSelection::Blocked);
                    };
                    let mut selected = None;
                    for binding in bindings {
                        if !scope_step() {
                            return None;
                        }
                        if binding.is_function_scoped()
                            && binding.local_name == local_name
                            && binding.scope_start_byte == parent.start_byte()
                            && binding.scope_end_byte == parent.end_byte()
                        {
                            if selected.is_some() {
                                return Some(PythonFunctionImportSelection::Blocked);
                            }
                            selected = Some(binding);
                        }
                    }
                    let Some(binding) = selected else {
                        return Some(PythonFunctionImportSelection::Blocked);
                    };
                    if !python_function_import_is_unconditional_bounded(
                        parent,
                        binding,
                        declaration,
                        reference,
                        &mut scope_step,
                    )? {
                        return Some(PythonFunctionImportSelection::Blocked);
                    }
                    // Nonlocal declarations expose this cell. A preceding
                    // nested callable can also capture it without a nonlocal
                    // statement; refuse that uncertainty without interpreting
                    // calls, closure objects or cell_contents writes. Bodies
                    // created by the selected class after its header are not
                    // preceding captures.
                    let mut exposed_cell = false;
                    try_walk_named_tree_preorder(
                        parent.child_by_field_name("body")?,
                        true,
                        |node| {
                            if !scope_step() {
                                return Err(());
                            }
                            if node.kind() != "identifier"
                                || python_slice(node, source) != local_name
                            {
                                return Ok(WalkControl::Continue);
                            }
                            let nonlocal = node
                                .parent()
                                .is_some_and(|p| p.kind() == "nonlocal_statement");
                            let preceding_capture = if !nonlocal
                                && node.start_byte() < reference.start_byte()
                            {
                                let owner = python_nearest_enclosing_callable(
                                    node,
                                    &mut scope_step,
                                    |candidate| {
                                        candidate.child_by_field_name("body").is_some_and(|body| {
                                            body.start_byte() <= node.start_byte()
                                                && node.end_byte() <= body.end_byte()
                                        })
                                    },
                                )
                                .ok_or(())?;
                                owner != parent
                            } else {
                                false
                            };
                            if nonlocal || preceding_capture {
                                exposed_cell = true;
                                return Ok(WalkControl::Break);
                            }
                            Ok(WalkControl::Continue)
                        },
                    )
                    .ok()?;
                    return Some(if exposed_cell {
                        PythonFunctionImportSelection::Blocked
                    } else {
                        PythonFunctionImportSelection::Selected(binding)
                    });
                }
            }
        }
        current = parent;
    }
    Some(PythonFunctionImportSelection::NotLocal)
}

fn python_function_import_is_unconditional_bounded(
    function: Node<'_>,
    binding: &PythonImportBinding,
    declaration: Node<'_>,
    reference: Node<'_>,
    mut scope_step: impl FnMut() -> bool,
) -> Option<bool> {
    let mut current = declaration;
    while !matches!(current.kind(), "import_statement" | "import_from_statement") {
        if !scope_step() {
            return None;
        }
        let Some(parent) = current.parent() else {
            return Some(false);
        };
        if parent == function {
            return Some(false);
        }
        current = parent;
    }
    if current.start_byte() != binding.start_byte || current.end_byte() > reference.start_byte() {
        return Some(false);
    }
    let Some(body) = function.child_by_field_name("body") else {
        return Some(false);
    };
    Some(current.parent() == Some(body) && body.parent() == Some(function))
}

fn python_visible_module_import_binding_bounded<'a>(
    root: Node<'_>,
    bindings: &'a [PythonImportBinding],
    local_name: &str,
    reference: Node<'_>,
    source: &str,
    mut scope_step: impl FnMut() -> bool,
) -> Option<Option<&'a PythonImportBinding>> {
    let mut selected = None;
    for binding in bindings {
        if !scope_step() {
            return None;
        }
        if !binding.is_function_scoped()
            && binding.local_name == local_name
            && binding.start_byte <= reference.start_byte()
        {
            if selected.is_some() {
                return Some(None);
            }
            selected = Some(binding);
        }
    }
    let Some(binding) = selected else {
        return Some(None);
    };
    // Preserve the module selector's preceding-event contract; this is not
    // the function-local uniqueness proof and cannot admit a class-body import.
    use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, try_walk_named_tree_preorder};
    let mut matched = false;
    let mut valid = true;
    try_walk_named_tree_preorder(root, true, |node| {
        if !scope_step() {
            return Err(());
        }
        if node.start_byte() >= reference.start_byte()
            || node.parent().is_some_and(|owner| {
                matches!(
                    owner.kind(),
                    "function_definition" | "lambda" | "class_definition"
                ) && owner.child_by_field_name("body") == Some(node)
            })
        {
            return Ok(WalkControl::SkipChildren);
        }
        if node.kind() == "wildcard_import" {
            valid = false;
            return Ok(WalkControl::Break);
        }
        for event in python_direct_scope_bindings_bounded(node, source, &mut scope_step).ok_or(())?
        {
            if python_slice(event.declaration, source) != local_name {
                continue;
            }
            let mut declaration = event.declaration;
            while !matches!(
                declaration.kind(),
                "import_statement" | "import_from_statement"
            ) {
                if !scope_step() {
                    return Err(());
                }
                let Some(parent) = declaration.parent() else {
                    valid = false;
                    return Ok(WalkControl::Break);
                };
                if parent.kind() == "module" {
                    valid = false;
                    return Ok(WalkControl::Break);
                }
                declaration = parent;
            }
            if declaration.parent() != Some(root)
                || declaration.start_byte() != binding.start_byte
                || matched
            {
                valid = false;
                return Ok(WalkControl::Break);
            }
            matched = true;
        }
        Ok(WalkControl::Continue)
    })
    .ok()?;
    Some((matched && valid).then_some(binding))
}

#[allow(clippy::too_many_arguments)]
fn python_visible_module_binding_candidates(
    analyzer: &dyn IAnalyzer,
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    context: &PythonDefinitionContext,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
    name: &str,
) -> Option<Vec<CodeUnit>> {
    let timeline = context.module_bindings(source, root);
    let events = timeline.get(name)?;
    let cutoff = if python_reference_is_deferred_function_body(node) {
        usize::MAX
    } else {
        node.start_byte()
    };
    let mut candidates = Vec::new();
    for event in visible_module_binding_suffix(events, cutoff) {
        match &event.kind {
            ModuleBindingEventKind::FromImport {
                module,
                imported_name,
            } => {
                let mut resolved = false;
                for module_file in usage_resolve_module_files(py, &context.file, module) {
                    let Some(module_fqn) = analyzer
                        .declarations(&module_file)
                        .into_iter()
                        .find(CodeUnit::is_module)
                        .map(|unit| unit.fq_name())
                    else {
                        continue;
                    };
                    resolved = true;
                    let fqn = format!("{module_fqn}.{imported_name}");
                    if let Some(module) = resolve_module_code_unit(py, Some(&context.file), &fqn)
                        && module.fq_name() == fqn
                    {
                        candidates.push(module);
                        continue;
                    }
                    let mut imported =
                        resolve_fqn_candidates(py, Some(&context.file), &fqn, |candidate| {
                            support.fqn(candidate)
                        });
                    imported
                        .retain(|candidate| !candidate.is_module() || candidate.fq_name() == fqn);
                    candidates.extend(imported);
                }
                if !resolved {
                    if let Some(fqn) = context.named.get(name) {
                        let imported =
                            resolve_fqn_candidates(py, Some(&context.file), fqn, |candidate| {
                                support.fqn(candidate)
                            });
                        if !imported.is_empty() {
                            candidates.extend(imported);
                            continue;
                        }
                    }
                    let fqn = if module.ends_with('.') {
                        format!("{module}{imported_name}")
                    } else {
                        format!("{module}.{imported_name}")
                    };
                    let mut resolved_candidates =
                        resolve_fqn_candidates(py, Some(&context.file), &fqn, |candidate| {
                            support.fqn(candidate)
                        });
                    if resolved_candidates.is_empty() {
                        // No Python module backs the specifier because it names a
                        // CLR/JVM namespace this workspace indexes in another
                        // language (#1174) -- pythonnet's
                        // `from Python.Test import ClassCtorTest2`.
                        resolved_candidates = python_cross_language_declarations(support, &fqn);
                    }
                    candidates.extend(resolved_candidates);
                }
            }
            ModuleBindingEventKind::ImportModule { module, .. } => {
                let bound_module = context
                    .namespace
                    .get(name)
                    .map(String::as_str)
                    .unwrap_or(module);
                candidates.extend(resolve_module_code_unit(
                    py,
                    Some(&context.file),
                    bound_module,
                ));
            }
            ModuleBindingEventKind::Other => {
                if let Some(local) = context.same_file.get(name) {
                    candidates.extend(python_same_file_candidates_for_binding_event(
                        analyzer,
                        &context.file,
                        root,
                        node,
                        local,
                        event.visible_from,
                    ));
                }
            }
        }
    }
    sort_units(&mut candidates);
    candidates.dedup();
    Some(candidates)
}

fn python_function_import_binding_candidates(
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    context: &PythonDefinitionContext,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
    name: &str,
) -> Option<Vec<CodeUnit>> {
    let bindings = context.scoped_import_bindings(source, root);
    let binding = python_function_scoped_import_binding(&bindings, name, node)?;

    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(parent.kind(), "function_definition" | "lambda") {
            let inventory = python_lexical_scope_inventory_bounded(parent, source, || true)?;
            if inventory.has_runtime_callable_binding_at(name, node) {
                return Some(Vec::new());
            }
            break;
        }
        current = parent.parent();
    }

    let qualified_name =
        resolve_python_relative_module(py.project(), &context.file, &binding.qualified_name)
            .unwrap_or_else(|| binding.qualified_name.clone());
    Some(resolve_fqn_candidates(
        py,
        Some(&context.file),
        &qualified_name,
        |candidate| support.fqn(candidate),
    ))
}

fn python_same_file_candidates_for_binding_event(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    root: Node<'_>,
    node: Node<'_>,
    candidates: &[CodeUnit],
    event_visible_from: usize,
) -> Vec<CodeUnit> {
    let visible = python_visible_same_file_candidates(analyzer, file, node, candidates);
    // A function and a later assignment intentionally share one Python FQN, so
    // this event has to name the physical declaration that was active when the
    // event became visible instead of merging both units (#2053).
    //
    // Repeated assignments to one module-level name are one declaration, and
    // the analyzer records it once, at its last spelling. An event that precedes
    // every recorded range is therefore still a binding of that same
    // declaration, written again further down; rejecting it discarded the
    // timeline's own answer and reported a bound module-level name as having no
    // indexed definition (#2157). The anchor is the latest declaration at or
    // before the event, and the earliest recorded declaration when they all
    // follow it.
    let declaration_ends: Vec<usize> = visible
        .iter()
        .flat_map(|candidate| analyzer.ranges(candidate))
        .map(|range| range.end_byte)
        .collect();
    let anchor_end = declaration_ends
        .iter()
        .copied()
        .filter(|end| *end <= event_visible_from)
        .max()
        .or_else(|| declaration_ends.iter().copied().min());
    let Some(anchor_end) = anchor_end else {
        return Vec::new();
    };
    let reference_path = python_conditional_branch_path(node);
    let event_path = event_visible_from
        .checked_sub(1)
        .and_then(|start| root.named_descendant_for_byte_range(start, event_visible_from))
        .map(python_conditional_branch_path)
        .unwrap_or_default();
    visible
        .into_iter()
        .filter(|candidate| {
            analyzer.ranges(candidate).iter().any(|range| {
                range.end_byte == anchor_end
                    && ((candidate.is_function()
                        && range.start_byte <= node.start_byte()
                        && node.end_byte() <= range.end_byte)
                        || python_conditional_paths_are_compatible(&reference_path, &event_path))
            })
        })
        .collect()
}

fn python_conditional_branch_path(mut node: Node<'_>) -> Vec<(usize, usize)> {
    let mut path = Vec::new();
    while let Some(parent) = node.parent() {
        if matches!(parent.kind(), "if_statement" | "elif_clause") {
            let in_condition = parent
                .child_by_field_name("condition")
                .is_some_and(|condition| {
                    condition.start_byte() <= node.start_byte()
                        && node.end_byte() <= condition.end_byte()
                });
            if !in_condition {
                path.push((parent.start_byte(), node.start_byte()));
            }
        }
        if matches!(
            parent.kind(),
            "module" | "function_definition" | "class_definition"
        ) {
            break;
        }
        node = parent;
    }
    path
}

fn python_conditional_paths_are_compatible(
    left: &[(usize, usize)],
    right: &[(usize, usize)],
) -> bool {
    left.iter().all(|(conditional, arm)| {
        right
            .iter()
            .find(|(other, _)| other == conditional)
            .is_none_or(|(_, other_arm)| other_arm == arm)
    })
}

/// Which same-file declarations a bare Python name written at `node` can bind
/// to: a binding of the class body the name is written in, otherwise a
/// module-level declaration. A method or an attribute of some other class is
/// absent, because Python has no implicit receiver -- `list(values)` inside a
/// class that declares `def list(self, ...)` is the builtin, never `self.list`.
///
/// The forward resolver answers same-file lookups with this, and the reference
/// census grades against the same notion of scope (#2054): a same-file
/// declaration this rejects is not evidence that forward lookup missed a target.
pub fn python_visible_same_file_candidates(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    node: Node<'_>,
    candidates: &[CodeUnit],
) -> Vec<CodeUnit> {
    let class_candidates =
        python_visible_class_binding_candidates(analyzer, file, node, candidates);
    if !class_candidates.is_empty() {
        return class_candidates;
    }
    candidates
        .iter()
        .filter(|candidate| {
            !candidate.is_module()
                && analyzer
                    .parent_of(candidate)
                    .is_some_and(|parent| parent.is_module())
        })
        .cloned()
        .collect()
}

fn python_visible_class_binding_candidates(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    node: Node<'_>,
    candidates: &[CodeUnit],
) -> Vec<CodeUnit> {
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: 0,
        end_line: 0,
    };
    let enclosing_class = analyzer
        .enclosing_code_unit(file, &range)
        .and_then(|mut scope| {
            if scope.is_function() && !python_function_declaration_expression_is_class_scoped(node)
            {
                return None;
            }
            loop {
                if scope.is_class() {
                    break Some(scope);
                }
                if scope.is_module() {
                    break None;
                }
                scope = analyzer.parent_of(&scope)?;
            }
        });
    let Some(enclosing_class) = enclosing_class else {
        return Vec::new();
    };
    let latest_end = candidates
        .iter()
        .filter(|candidate| {
            analyzer
                .parent_of(candidate)
                .is_some_and(|parent| parent == enclosing_class)
        })
        .flat_map(|candidate| analyzer.ranges(candidate))
        .filter(|range| range.end_byte <= node.start_byte())
        .map(|range| range.end_byte)
        .max();
    let Some(latest_end) = latest_end else {
        return Vec::new();
    };
    candidates
        .iter()
        .filter(|candidate| {
            analyzer
                .parent_of(candidate)
                .is_some_and(|parent| parent == enclosing_class)
                && analyzer
                    .ranges(candidate)
                    .iter()
                    .any(|range| range.end_byte == latest_end)
        })
        .cloned()
        .collect()
}

fn python_function_declaration_expression_is_class_scoped(node: Node<'_>) -> bool {
    let site_start = node.start_byte();
    let site_end = node.end_byte();
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "function_definition" {
            return parent.child_by_field_name("body").is_none_or(|body| {
                !(body.start_byte() <= site_start && site_end <= body.end_byte())
            });
        }
        if parent.kind() == "decorated_definition" {
            return current.kind() == "decorator";
        }
        if parent.kind() == "class_definition" {
            break;
        }
        current = parent;
    }
    false
}

#[cfg(test)]
pub(crate) fn parse_python_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

type PythonScopeFacts = HashMap<CodeUnit, LocalBindingsSnapshot<String>>;

pub(crate) struct PythonDefinitionContext {
    file: ProjectFile,
    named: HashMap<String, String>,
    namespace: HashMap<String, String>,
    same_file: HashMap<String, Vec<CodeUnit>>,
    scope_facts: OnceLock<Replayable<Arc<PythonScopeFacts>>>,
    lexical_scopes: Mutex<HashMap<(usize, usize), PythonLexicalScopeBindings>>,
    module_bindings: OnceLock<Arc<ModuleBindingTimeline>>,
    scoped_import_bindings: OnceLock<Arc<Vec<PythonImportBinding>>>,
    imports: Vec<brokk_bifrost_core::analyzer::model::ImportInfo>,
    receiver_types: Mutex<PythonReceiverTypeCache>,
    #[cfg(test)]
    build_counters: Arc<PythonDefinitionBuildCounters>,
}

struct PythonReceiverTypeCache {
    limit: usize,
    values: HashMap<(String, bool), Replayable<Option<CodeUnit>>>,
}

impl PythonReceiverTypeCache {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            values: HashMap::default(),
        }
    }
}

impl PythonDefinitionContext {
    fn name_shadowed_at(&self, name: &str, reference: Node<'_>, source: &str) -> bool {
        // The context key already names the exact source. Cached inventories
        // contain owned binding facts, never nodes borrowed from another tree.
        let mut scopes = self
            .lexical_scopes
            .lock()
            .expect("Python lexical scope cache poisoned");
        python_name_shadowed_at(name, reference, source, &mut scopes)
    }

    pub(crate) fn build(
        py: &PythonAnalyzer,
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        file: &ProjectFile,
        #[cfg(test)] build_counters: Arc<PythonDefinitionBuildCounters>,
    ) -> Self {
        let binder = py.import_binder_of(token, file);
        let mut named = HashMap::default();
        let mut namespace = HashMap::default();
        for (local, binding) in &binder.bindings {
            match binding.kind {
                ImportKind::Named => {
                    if let Some(imported) = &binding.imported_name {
                        named.insert(
                            local.clone(),
                            format!("{}.{}", binding.module_specifier, imported),
                        );
                    }
                }
                ImportKind::Namespace => {
                    namespace.insert(local.clone(), binding.module_specifier.clone());
                }
                ImportKind::Default | ImportKind::CommonJsRequire | ImportKind::Glob => {}
            }
        }
        let mut same_file: HashMap<String, Vec<CodeUnit>> = HashMap::default();
        for unit in analyzer.declarations(file) {
            same_file
                .entry(unit.identifier().to_string())
                .or_default()
                .push(unit.clone());
        }
        for units in same_file.values_mut() {
            sort_units(units);
        }
        Self {
            file: file.clone(),
            named,
            namespace,
            same_file,
            scope_facts: OnceLock::new(),
            lexical_scopes: Mutex::default(),
            module_bindings: OnceLock::new(),
            scoped_import_bindings: OnceLock::new(),
            imports: analyzer
                .import_analysis_provider()
                .expect("Python import provider")
                .import_info_of(token, file),
            receiver_types: Mutex::new(PythonReceiverTypeCache::new(
                PYTHON_RECEIVER_TYPE_CACHE_LIMIT,
            )),
            #[cfg(test)]
            build_counters,
        }
    }

    fn namespace_module_for_node(&self, object: Node<'_>, source: &str) -> Option<String> {
        let mut attributes = Vec::new();
        let mut current = object;
        while current.kind() == "attribute" {
            let attribute = current.child_by_field_name("attribute")?;
            let text = python_slice(attribute, source);
            if text.is_empty() {
                return None;
            }
            attributes.push(text);
            current = current.child_by_field_name("object")?;
        }
        if current.kind() != "identifier" {
            return None;
        }
        let root = python_slice(current, source);
        let mut module = self.namespace.get(root)?.clone();
        for attribute in attributes.into_iter().rev() {
            module.push('.');
            module.push_str(attribute);
        }
        Some(module)
    }

    fn receiver_type_for_object(
        &self,
        py: &PythonAnalyzer,
        support: &dyn BoundedDefinitionLookup,
        object: &str,
    ) -> Option<CodeUnit> {
        if let Some(fqn) = self.named.get(object) {
            return python_class_for_fqn(py, support, &self.file, fqn);
        }
        self.same_file
            .get(object)?
            .iter()
            .find(|unit| unit.is_class())
            .cloned()
    }

    fn receiver_type(
        &self,
        analyzer: &dyn IAnalyzer,
        py: &PythonAnalyzer,
        support: &dyn BoundedDefinitionLookup,
        file: &ProjectFile,
        raw_type: &str,
        target_self_file: bool,
    ) -> Option<CodeUnit> {
        let raw_type = raw_type.trim();
        if &self.file != file {
            return self.generic_receiver_type(analyzer, py, file, raw_type, target_self_file);
        }

        let key = (raw_type.to_string(), target_self_file);
        if let Some(cached) = self
            .receiver_types
            .lock()
            .expect("Python receiver type cache mutex poisoned")
            .values
            .get(&key)
        {
            brokk_bifrost_analysis::analyzer::i_analyzer::replay_query_reads(
                analyzer,
                &cached.reads,
            );
            return cached.value.clone();
        }

        #[cfg(test)]
        self.build_counters
            .receiver_type_cache_misses
            .fetch_add(1, Ordering::Relaxed);

        let (resolved, reads) =
            brokk_bifrost_analysis::analyzer::i_analyzer::capture_query_reads(analyzer, || {
                self.receiver_type_for_object(py, support, raw_type)
                    .or_else(|| {
                        self.generic_receiver_type(analyzer, py, file, raw_type, target_self_file)
                    })
            });

        let mut cache = self
            .receiver_types
            .lock()
            .expect("Python receiver type cache mutex poisoned");
        if cache.values.len() < cache.limit {
            cache.values.insert(
                key,
                Replayable {
                    value: resolved.clone(),
                    reads,
                },
            );
        }
        resolved
    }

    fn generic_receiver_type(
        &self,
        analyzer: &dyn IAnalyzer,
        py: &PythonAnalyzer,
        file: &ProjectFile,
        raw_type: &str,
        target_self_file: bool,
    ) -> Option<CodeUnit> {
        #[cfg(test)]
        self.build_counters
            .generic_receiver_type_fallbacks
            .fetch_add(1, Ordering::Relaxed);
        with_python_graph_source(analyzer, |graph| {
            resolve_python_receiver_type(&graph, py, file, raw_type, target_self_file)
        })
    }

    #[cfg(test)]
    pub(crate) fn set_receiver_type_cache_limit(&self, limit: usize) {
        let mut cache = self
            .receiver_types
            .lock()
            .expect("Python receiver type cache mutex poisoned");
        cache.limit = limit;
        cache.values.clear();
    }

    #[cfg(test)]
    pub(crate) fn receiver_type_cache_len(&self) -> usize {
        self.receiver_types
            .lock()
            .expect("Python receiver type cache mutex poisoned")
            .values
            .len()
    }

    fn scope_facts(
        &self,
        analyzer: &dyn IAnalyzer,
        py: &PythonAnalyzer,
        file: &ProjectFile,
        source: &str,
        root: Node<'_>,
    ) -> Option<Arc<PythonScopeFacts>> {
        if let Some(entry) = self.scope_facts.get() {
            brokk_bifrost_analysis::analyzer::i_analyzer::replay_query_reads(
                analyzer,
                &entry.reads,
            );
            return Some(Arc::clone(&entry.value));
        }
        let _scope = brokk_bifrost_core::profiling::scope("get_definition::python::scope_facts");
        #[cfg(test)]
        self.build_counters
            .scope_fact_builds
            .fetch_add(1, Ordering::Relaxed);
        let (facts, reads) =
            brokk_bifrost_analysis::analyzer::i_analyzer::capture_query_reads(analyzer, || {
                with_python_graph_source(analyzer, |graph| {
                    collect_scope_facts_from_parsed_source(&graph, py, file, source, root)
                })
            });
        let Some(facts) = facts else {
            analyzer.record_query_failure(
                brokk_bifrost_analysis::analyzer::store::StoreError::new(format!(
                    "Canonical Python callable annotations are unavailable for {file:?}"
                )),
            );
            return None;
        };
        let entry = self.scope_facts.get_or_init(|| Replayable {
            value: Arc::new(facts),
            reads,
        });
        brokk_bifrost_analysis::analyzer::i_analyzer::replay_query_reads(analyzer, &entry.reads);
        Some(Arc::clone(&entry.value))
    }

    fn module_bindings(&self, source: &str, root: Node<'_>) -> Arc<ModuleBindingTimeline> {
        self.module_bindings
            .get_or_init(|| Arc::new(collect_module_binding_timeline(root, source, &self.imports)))
            .clone()
    }

    fn scoped_import_bindings(
        &self,
        source: &str,
        root: Node<'_>,
    ) -> Arc<Vec<PythonImportBinding>> {
        self.scoped_import_bindings
            .get_or_init(|| {
                Arc::new(python_import_bindings_from_imports(
                    &self.imports,
                    root,
                    source.len(),
                ))
            })
            .clone()
    }
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct PythonDefinitionBuildCounters {
    pub(crate) context_builds: AtomicUsize,
    pub(crate) scope_fact_builds: AtomicUsize,
    pub(crate) receiver_type_cache_misses: AtomicUsize,
    pub(crate) generic_receiver_type_fallbacks: AtomicUsize,
}

enum PythonReferenceNode<'tree> {
    Identifier(Node<'tree>),
    Attribute {
        object: Node<'tree>,
        attribute: Node<'tree>,
    },
    /// A keyword argument `name=value` in a call `Callee(name=..)`: `name` resolves
    /// to the callee type's member/parameter (e.g. a dataclass field `Foo.a`), not
    /// a name in scope.
    KeywordArgument {
        call: Node<'tree>,
        name: Node<'tree>,
    },
}

/// A keyword-argument identifier (`a` in `Foo(a=3)`): the `name` of a
/// `keyword_argument` inside a call's `argument_list`.
fn python_reference_node(node: Node<'_>) -> Option<PythonReferenceNode<'_>> {
    python_reference_node_with_step(node, || true)
}

fn python_fqn_outcome(
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    importer: &ProjectFile,
    fqn: &str,
    raw: &str,
) -> DefinitionLookupOutcome {
    let candidates = resolve_fqn_candidates(py, Some(importer), fqn, |name| support.fqn(name));
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    // pythonnet-style interop (#1174): `from Python.Test import ClassCtorTest2`
    // names a CLR type whose C# declaration is indexed at exactly this fq. The
    // Python index has nothing here, so the exact cross-language declaration is
    // the honest answer rather than a boundary claim about a workspace type.
    let cross_language = python_cross_language_declarations(support, fqn);
    if !cross_language.is_empty() {
        return candidates_outcome(cross_language);
    }
    // `python_crosses_unindexed_boundary` is `!python_workspace_module_exists`,
    // so its negation is the workspace-internal gate.
    gated_boundary(
        || !python_crosses_unindexed_boundary(py, support, fqn),
        format!(
            "`{raw}` resolves to `{fqn}`, which is outside this partial Python workspace analysis"
        ),
        UnindexedClaim::resolved_external(fqn, ClaimSubjectRole::Any),
        "no_indexed_definition",
        format!("`{raw}` resolved to `{fqn}`, but no indexed Python definition was found"),
    )
}

/// Declarations indexed at exactly `fqn` in a language other than Python.
fn python_cross_language_declarations(
    support: &dyn BoundedDefinitionLookup,
    fqn: &str,
) -> Vec<CodeUnit> {
    cross_language_declarations(support, fqn, Language::Python)
}

fn python_module_outcome(
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    importer: &ProjectFile,
    module_fq: &str,
    raw: &str,
) -> DefinitionLookupOutcome {
    if let Some(module) = resolve_module_code_unit(py, Some(importer), module_fq) {
        return candidates_outcome(vec![module]);
    }
    // Same workspace-namespace gate as the fqn path above, plus the module path
    // itself: `import Python.Test as Test` names a C# namespace that this
    // workspace indexes, so it is internal even though Python declares no such
    // module (#1174).
    gated_boundary(
        || {
            !python_crosses_unindexed_boundary(py, support, module_fq)
                || python_workspace_module_exists(py, support, module_fq)
        },
        format!(
            "`{raw}` resolves to module `{module_fq}`, which is outside this partial Python workspace analysis"
        ),
        UnindexedClaim::resolved_external(module_fq, ClaimSubjectRole::Module),
        "no_indexed_definition",
        format!("`{raw}` resolved to module `{module_fq}`, but no indexed Python module was found"),
    )
}

fn python_class_for_fqn(
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    importer: &ProjectFile,
    fqn: &str,
) -> Option<CodeUnit> {
    resolve_fqn_candidates(py, Some(importer), fqn, |name| support.fqn(name))
        .into_iter()
        .find(|unit| unit.is_class())
        .or_else(|| {
            // An imported CLR/JVM type used as a receiver: the class is indexed
            // at this exact fq in another language (#1174).
            python_cross_language_declarations(support, fqn)
                .into_iter()
                .find(|unit| unit.is_class())
        })
}

fn python_member_outcome(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    receiver_type: CodeUnit,
    member: &str,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    // A receiver typed cross-language (#1174) owns members in *its* language's
    // index, not Python's, so the exact-fq member lookup has to follow it there.
    let receiver_language = language_for_file(receiver_type.source());
    let cross_language_owner = receiver_language != Language::Python;
    let mut candidates = support.members_for_owner(&receiver_type, member);
    // The member attribution this seam can name: every candidate was found by
    // asking the index for `<owner fq>.<member>`, so the owner is exactly the
    // type the lookup asked about, and the hop distance is that type's distance
    // from the receiver. Built only while a trace records (#1477).
    let mut attribution = PythonMemberAttribution::default();
    attribution.record_direct(&receiver_type, &candidates);
    if candidates.is_empty()
        && let Some(provider) = analyzer.type_hierarchy_provider()
    {
        // The routes are the walk `get_ancestors` performs, retaining the hop
        // distance and the first-discovery parent it discards.
        let routes = if trace::recording() {
            PythonAncestorRoutes::build(provider, &receiver_type)
        } else {
            PythonAncestorRoutes::default()
        };
        for ancestor in provider.get_ancestors(&receiver_type) {
            let found = support.members_for_owner(&ancestor, member);
            attribution.record_inherited(&receiver_type, &ancestor, &found, &routes);
            candidates.extend(found);
        }
        sort_units(&mut candidates);
        candidates.dedup();
    }
    if candidates.is_empty()
        && !cross_language_owner
        && let Some(python) = resolve_analyzer::<PythonAnalyzer>(analyzer)
        && let Some(overlay) = analyzer.semantic_model_overlay()
        && let Some(symbol) =
            crate::analyzer::python::python_external_value_member_on_workspace_class(
                python,
                &receiver_type,
                member,
                &overlay,
            )
    {
        let mut reference = site.clone();
        reference.text = symbol.qualified_name.clone();
        let outcome = DefinitionLookupOutcome {
            modeled_definitions: vec![symbol],
            status: DefinitionLookupStatus::Resolved,
            reference: Some(reference),
            definitions: Vec::new(),
            lexical_definition: None,
            diagnostics: Vec::new(),
        };
        trace::record_selected_modeled(&outcome);
        return outcome;
    }
    if candidates.is_empty() {
        let owner = receiver_type.fq_name();
        let message = if cross_language_owner {
            format!(
                "`{owner}.{member}` is not indexed; `{owner}` is a {} declaration, not a Python one",
                receiver_language.config_label()
            )
        } else {
            format!("`{owner}.{member}` is not indexed as a Python definition")
        };
        no_definition("no_indexed_definition", message)
    } else {
        attribution.stage();
        candidates_outcome(candidates)
    }
}

/// How many ancestor types the recording-only route walk may visit. Mirrors the
/// bound the Java member-family walk applies to the same kind of closure: a
/// diamond or a deep framework hierarchy stays bounded, and a hierarchy that
/// exceeds the bound loses attribution rather than gaining a wrong one.
const MAX_ANCESTOR_FRONTIER: usize = 512;

/// The hop distance and first-discovery parent of every ancestor the Python
/// member walk can reach (#1477).
///
/// `TypeHierarchyProvider::get_ancestors` flattens its breadth-first walk to a
/// list, discarding both facts. This repeats that walk over the same
/// direct-ancestor edges, in the same order and with the same
/// fully-qualified-name deduplication, and retains them. It decides nothing:
/// the production loop still consumes `get_ancestors` unchanged.
///
/// The walk is bounded by [`MAX_ANCESTOR_FRONTIER`]. Truncation removes
/// attribution, never distorts it: breadth-first order fixes every depth at
/// the level it was recorded, so an ancestor the bound cut off simply has no
/// depth and [`PythonAncestorRoutes::route`] returns `None` for it, leaving
/// that candidate unattributed.
#[derive(Default)]
struct PythonAncestorRoutes {
    /// First-discovery parent of each ancestor the walk expanded.
    parents: HashMap<CodeUnit, CodeUnit>,
    /// Breadth-first hop distance from the receiver.
    depths: HashMap<CodeUnit, usize>,
}

impl PythonAncestorRoutes {
    fn build(
        provider: &dyn brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider,
        receiver: &CodeUnit,
    ) -> Self {
        let mut routes = Self::default();
        let mut seen: HashSet<String> = HashSet::default();
        seen.insert(receiver.fq_name());
        let mut level = provider.get_direct_ancestors(receiver);
        for ancestor in &level {
            routes
                .parents
                .entry(ancestor.clone())
                .or_insert_with(|| receiver.clone());
        }
        let mut depth = 0usize;
        let mut visited = 0usize;
        'walk: while !level.is_empty() {
            depth += 1;
            let mut next_level = Vec::new();
            for ancestor in level {
                if !seen.insert(ancestor.fq_name()) {
                    continue;
                }
                visited += 1;
                if visited > MAX_ANCESTOR_FRONTIER {
                    // Stop before recording anything about this ancestor. Every
                    // depth already recorded is the breadth-first minimum and
                    // stays correct; the rest of the closure is simply absent,
                    // so its candidates stay unattributed.
                    break 'walk;
                }
                routes.depths.insert(ancestor.clone(), depth);
                let expanded = provider.get_direct_ancestors(&ancestor);
                for next in &expanded {
                    routes
                        .parents
                        .entry(next.clone())
                        .or_insert_with(|| ancestor.clone());
                }
                next_level.extend(expanded);
            }
            level = next_level;
        }
        routes
    }

    /// The exact route from `receiver` to `owner`, as first-discovery hops.
    /// Every Python direct-ancestor edge is a base-class edge, so each hop is
    /// [`HierarchyRelation::Extends`]. Returns `None` when the walk never
    /// reached `owner`, which leaves the candidate unattributed rather than
    /// attributed to a route this seam cannot name.
    fn route(
        &self,
        receiver: &CodeUnit,
        owner: &CodeUnit,
    ) -> Option<(usize, Vec<trace::HierarchyHopRecord>)> {
        use brokk_bifrost_core::analyzer::structural::resolution::HierarchyRelation;

        let depth = *self.depths.get(owner)?;
        let (route, reached_receiver) = trace::hierarchy_route_from_predecessors(
            owner,
            depth,
            |current, _| current == receiver,
            |current| {
                self.parents
                    .get(current)
                    .cloned()
                    .map(|parent| (parent, HierarchyRelation::Extends))
            },
            |unit| Some(unit.clone()),
        )?;
        if !reached_receiver {
            return None;
        }
        debug_assert_eq!(
            route.len(),
            depth,
            "the first-discovery chain must be exactly the walk's hop distance"
        );
        Some((depth, route))
    }
}

/// The member attribution the Python member seams accumulate before they hand
/// their candidates to the shared outcome constructor (#1477).
///
/// Applicability stays `Unknown`: these seams select by owner and name and
/// never inspect the call shape, so claiming anything else would be inventing
/// a check the resolver did not perform.
#[derive(Default)]
struct PythonMemberAttribution {
    by_fq_name: Vec<(String, trace::MemberEnrichment)>,
}

impl PythonMemberAttribution {
    /// Candidates found on the receiver's own type: depth zero, no route.
    fn record_direct(&mut self, receiver: &CodeUnit, found: &[CodeUnit]) {
        if !trace::recording() {
            return;
        }
        for candidate in found {
            self.by_fq_name.push((
                candidate.fq_name(),
                trace::member_enrichment_with_tier(
                    receiver.clone(),
                    0,
                    brokk_bifrost_core::analyzer::structural::resolution::MemberDispatchTier::InherentOrDirect,
                    brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict::Unknown,
                    Vec::new(),
                ),
            ));
        }
    }

    /// Candidates found on an ancestor of the receiver. A candidate whose owner
    /// the route walk cannot place stays unattributed.
    fn record_inherited(
        &mut self,
        receiver: &CodeUnit,
        owner: &CodeUnit,
        found: &[CodeUnit],
        routes: &PythonAncestorRoutes,
    ) {
        if !trace::recording() || found.is_empty() {
            return;
        }
        let Some((depth, route)) = routes.route(receiver, owner) else {
            return;
        };
        for candidate in found {
            self.by_fq_name.push((
                candidate.fq_name(),
                trace::member_enrichment_with_tier(
                    owner.clone(),
                    depth,
                    brokk_bifrost_core::analyzer::structural::resolution::MemberDispatchTier::InheritedOrPromoted,
                    brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict::Unknown,
                    route.clone(),
                ),
            ));
        }
    }

    /// Stage the attribution for the outcome constructor the caller is about to
    /// reach. Staging nothing leaves the rows unattributed, which is what an
    /// unrecorded trace and an unplaceable owner must both look like.
    fn stage(self) {
        if self.by_fq_name.is_empty() {
            return;
        }
        trace::stage_member_context(self.by_fq_name);
    }
}

fn python_crosses_unindexed_boundary(
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    fqn: &str,
) -> bool {
    // Python module paths are `.`-joined and identifiers never contain a
    // literal `.`, so re-tokenizing `fqn` with the shared structured splitter
    // and rejoining every part but the last with `.` reproduces
    // `rsplit_once('.')`'s (module, _) split exactly, including the no-dot
    // case (an empty module, which `python_workspace_module_exists` always
    // rejects).
    let segments = parse_symbol_path(Language::Python, fqn);
    let module = segments[..segments.len().saturating_sub(1)].join(".");
    !python_workspace_module_exists(py, support, &module)
}

/// Whether the workspace declares `module` as a package/namespace or as a
/// declaration.
///
/// Deliberately language-blind: this is the honesty gate behind every confident
/// Python boundary claim, and a namespace that only C#/Java/Scala declares (a
/// pythonnet CLR namespace, say) is still *inside* the workspace. Answering it
/// Python-only made the claim wrong about workspace-internal targets (#1174).
fn python_workspace_module_exists(
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    module: &str,
) -> bool {
    if module.is_empty() {
        return false;
    }
    python_workspace_declares_module(support, module)
        || !python_source_root_spellings(py, module).is_empty()
}

fn python_workspace_declares_module(support: &dyn BoundedDefinitionLookup, module: &str) -> bool {
    !module.is_empty()
        && (support.package_exists_in_any_language(module)
            || !support.fqn_in_any_language(module).is_empty())
}

/// The names and paths this workspace indexes `module` under when `module` is
/// written against a source root below the project root.
///
/// This is diagnostic evidence, not a binding decision. A tail match says the
/// file would be the module *if* its implied root were on the importing
/// program's path, and only the workspace's own structure -- a packaging
/// manifest declaring that root, or a complete package chain from it -- makes
/// that true; a candidate that fails that test is still the spelling the
/// workspace indexes the file under, which the gap has to name (#3506).
///
/// Empty for every module the index spells exactly and for every genuinely
/// external one, so it is only ever consulted after the exact lookups fail.
fn python_source_root_spellings(py: &PythonAnalyzer, module: &str) -> Vec<String> {
    python_source_root_spellings_excluding_installed_roots(py, module, &[])
}

/// Read installed roots from the exact active runtime publication selected by
/// this query. A missing publication has no declared runtime evidence to
/// exclude. A stale or unreadable publication is an error so uncertainty never
/// turns a workspace candidate into an external identity.
fn python_verified_installed_roots(
    analyzer: &dyn IAnalyzer,
    py: &PythonAnalyzer,
) -> Result<Vec<std::path::PathBuf>, String> {
    let Some(active_snapshot) = analyzer.active_semantic_model_snapshot() else {
        return Ok(Vec::new());
    };
    let Some(publication) = active_snapshot.python_runtime() else {
        return Ok(Vec::new());
    };
    let Some((store, current_snapshot)) = py.python_runtime_store_snapshot() else {
        return Err("the Python analyzer has no selected runtime store snapshot".to_owned());
    };
    if current_snapshot != publication.snapshot {
        return Err(format!(
            "runtime publication snapshot {:?} differs from selected snapshot {:?}",
            publication.snapshot, current_snapshot
        ));
    }
    store
        .with_python_runtime_acquisition(publication.acquisition_id, &publication.snapshot, |tx| {
            brokk_bifrost_analysis::analyzer::store::python_runtime::python_runtime_declared_archive_verified_installed_roots(
                        tx,
                        publication.acquisition_id,
                    )
        })
        .map_err(|error| format!("{error:?}"))
}

fn python_source_root_spellings_excluding_installed_roots(
    py: &PythonAnalyzer,
    module: &str,
    installed_roots: &[std::path::PathBuf],
) -> Vec<String> {
    let mut names = py
        .module_spellings()
        .suffix_candidates(module)
        .into_iter()
        .filter(|candidate| {
            !installed_roots
                .iter()
                .any(|root| candidate.file.abs_path().starts_with(root))
        })
        .map(|candidate| {
            format!(
                "{} ({})",
                python_module_name(py.project(), &candidate.file),
                rel_path_string(&candidate.file)
            )
        })
        .collect::<Vec<_>>();
    names.sort();
    names.dedup();
    names
}

/// The outcome for a reference whose import binding named a module, when that
/// binding resolved to nothing.
///
/// A module the workspace indexes only under a longer path-derived name is
/// inside the workspace, so the honest failure names the spelling gap instead
/// of claiming the import left the workspace: the two want different actions
/// from a caller, and only one of them is true (#3506). The resolvers try the
/// source roots first, so reaching this with a spelling gap means the specifier
/// named more than one workspace module, or the imported member is absent from
/// the module it did name.
#[allow(clippy::too_many_arguments)]
fn python_import_binding_outcome(
    analyzer: &dyn IAnalyzer,
    py: &PythonAnalyzer,
    token: QueryToken<'_>,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    local: &str,
    attribute: Option<&str>,
    import_target: &str,
    reference: &str,
) -> DefinitionLookupOutcome {
    let installed_roots = match python_verified_installed_roots(analyzer, py) {
        Ok(roots) => roots,
        Err(error) => {
            return no_definition(
                "python_runtime_installed_root_evidence_incomplete",
                format!(
                    "`{reference}` could not establish whether `{import_target}` is an installed external package because the selected Python runtime evidence could not be read: {error}"
                ),
            );
        }
    };
    let spellings =
        python_source_root_spellings_excluding_installed_roots(py, import_target, &installed_roots);
    if !spellings.is_empty() {
        return no_definition(
            "python_source_root_resolution_gap",
            format!(
                "`{reference}` is imported from `{import_target}`, which this workspace indexes under a source root below the project root as {spellings:?}; the module is inside the workspace, so this is a resolution gap rather than an import that left it"
            ),
        );
    }
    let subject = match attribute {
        Some(attribute) => format!("{local}.{attribute}"),
        None => local.to_string(),
    };
    let workspace_internal = python_import_binding_is_workspace_internal(
        py,
        token,
        support,
        file,
        local,
        attribute,
        &installed_roots,
    );
    gated_boundary(
        || workspace_internal,
        format!(
            "`{subject}` crosses a Python import boundary through `{import_target}` that is not indexed in this workspace"
        ),
        UnindexedClaim::external_boundary(import_target, ClaimSubjectRole::Module),
        "no_indexed_definition",
        format!("`{reference}` did not resolve to an indexed Python definition"),
    )
}

#[allow(clippy::too_many_arguments)]
fn python_receiver_type_unit(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    context: &PythonDefinitionContext,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    object: Node<'_>,
) -> Option<CodeUnit> {
    match object.kind() {
        "identifier" => {
            let receiver = python_slice(object, source);
            if let Some(unit) =
                python_self_receiver_type(analyzer, py, file, root, object, receiver)
            {
                return Some(unit);
            }
            // A typed-variable receiver: use the local/parameter's inferred type.
            let facts_by_scope = context.scope_facts(analyzer, py, file, source, root)?;
            if let Some(facts) = enclosing_scope_facts(analyzer, file, &facts_by_scope, object)
                && let Some(raw_type) = facts
                    .resolution_for(receiver)
                    .as_precise()
                    .and_then(|targets| targets.iter().next().cloned())
                && let Some(unit) =
                    context.receiver_type(analyzer, py, support, file, &raw_type, false)
            {
                return Some(unit);
            }
            // A class-name receiver: `ClassName.Nested` / `ClassName.member`
            // accesses a member on the class itself.
            let class = context.receiver_type(analyzer, py, support, file, receiver, false);
            if class.is_some() {
                return class;
            }
            let binder = py.import_binder_of(token, file);
            let binding = binder.bindings.get(receiver)?;
            let imported = binding.imported_name.as_ref()?;
            let fqn = format!("{}.{}", binding.module_specifier, imported);
            python_class_for_fqn(py, support, file, &fqn)
        }
        // A call receiver: `Foo().bar` (construction) or `make().bar` (the
        // called function/method's return type).
        "call" => python_call_result_type(
            analyzer, token, py, support, context, file, source, root, object,
        ),
        _ => None,
    }
}

/// Resolve the instance class for one exact Python bound-method call. A
/// class-qualified call is excluded because an instance's `__getattribute__`
/// does not intercept lookup on the class object.
pub(crate) fn python_bound_receiver_class_for_method_call(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    callee_start_byte: usize,
) -> Option<CodeUnit> {
    let py = resolve_analyzer::<PythonAnalyzer>(analyzer)?;
    let context = request_definition_context(py, analyzer, token, file, source);
    let support = AnalyzerDefinitionLookup::new(analyzer, Language::None);
    let focus = tree
        .root_node()
        .named_descendant_for_byte_range(callee_start_byte, callee_start_byte.saturating_add(1))?;
    let PythonReferenceNode::Attribute { object, .. } = python_reference_node(focus)? else {
        return None;
    };
    let callee = match focus.kind() {
        "attribute" => focus,
        _ => {
            let mut current = focus;
            loop {
                let parent = current.parent()?;
                if parent.kind() != "attribute"
                    || parent.child_by_field_name("attribute") != Some(current)
                {
                    return None;
                }
                current = parent;
                if let Some(call) = current.parent()
                    && call.kind() == "call"
                    && call.child_by_field_name("function") == Some(current)
                {
                    break current;
                }
            }
        }
    };
    let call = callee.parent()?;
    if call.kind() != "call" || call.child_by_field_name("function") != Some(callee) {
        return None;
    }
    if python_receiver_is_class_qualified(py, &support, &context, object, source) {
        return None;
    }
    python_receiver_type_unit(
        analyzer,
        token,
        py,
        &support,
        &context,
        file,
        source,
        tree.root_node(),
        object,
    )
}

fn python_receiver_is_class_qualified(
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    context: &PythonDefinitionContext,
    receiver: Node<'_>,
    source: &str,
) -> bool {
    match receiver.kind() {
        "identifier" => {
            let name = python_slice(receiver, source);
            !context.name_shadowed_at(name, receiver, source)
                && context
                    .receiver_type_for_object(py, support, name)
                    .is_some()
        }
        "attribute" => context
            .namespace_module_for_node(receiver, source)
            .is_some(),
        _ => false,
    }
}

/// The type produced by a call expression: the class for a construction
/// (`Foo()`), or the resolved return type of the called function/method
/// (`make()`, `obj.make()`).
#[allow(clippy::too_many_arguments)]
fn python_call_result_type(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    context: &PythonDefinitionContext,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    call: Node<'_>,
) -> Option<CodeUnit> {
    let function = call.child_by_field_name("function")?;
    let callee = python_resolve_callable(
        analyzer, token, py, support, context, file, source, root, function,
    )?;
    if callee.is_class() {
        return Some(callee);
    }
    python_callable_return_type(analyzer, py, support, context, &callee)
}

/// Resolve a call's callee expression to the class or function/method being
/// called.
#[allow(clippy::too_many_arguments)]
fn python_resolve_callable(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    context: &PythonDefinitionContext,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    function: Node<'_>,
) -> Option<CodeUnit> {
    match function.kind() {
        "identifier" => {
            let name = python_slice(function, source);
            if let Some(class) = context.receiver_type(analyzer, py, support, file, name, false) {
                return Some(class);
            }
            analyzer
                .declarations(file)
                .into_iter()
                .find(|unit| unit.identifier() == name && unit.is_function())
        }
        "attribute" => {
            let receiver = function.child_by_field_name("object")?;
            let method = python_slice(function.child_by_field_name("attribute")?, source);
            let receiver_type = python_receiver_type_unit(
                analyzer, token, py, support, context, file, source, root, receiver,
            )?;
            analyzer
                .definitions(&format!("{}.{}", receiver_type.fq_name(), method))
                .next()
        }
        _ => None,
    }
}

/// The declared or inferred return type of a Python function/method: read a
/// `-> T` annotation, else infer from a `return T(...)` / `return T` in the
/// body. Resolved in the callable's own file.
fn python_callable_return_type(
    analyzer: &dyn IAnalyzer,
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    context: &PythonDefinitionContext,
    callable: &CodeUnit,
) -> Option<CodeUnit> {
    let file = callable.source();
    let metadata = analyzer.signature_metadata(callable);
    let first = metadata.first()?;
    if let Some(nominal) = first
        .return_type_identity()
        .and_then(|identity| identity.nominal_name())
        && let Some(class) =
            context.receiver_type(analyzer, py, support, file, &nominal.path().join("."), true)
    {
        return Some(class);
    }
    let query_scope = AnalyzerQueryScope::new(analyzer);
    let prepared = brokk_bifrost_python::graph_support::PythonSource::prepared_syntax(
        py,
        query_scope.token(),
        file,
    )?;
    let source = prepared.source();
    let root = prepared.tree().root_node();
    let mut ranges = analyzer.ranges(callable);
    ranges.sort_by_key(|range| range.start_byte);
    let function = ranges.into_iter().find_map(|range| {
        let declaration = root.descendant_for_byte_range(range.start_byte, range.end_byte)?;
        python_first_function_definition(declaration)
    })?;

    let body = function.child_by_field_name("body")?;
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        // Don't descend into nested functions/classes — their returns are theirs.
        if matches!(node.kind(), "function_definition" | "class_definition") {
            continue;
        }
        if node.kind() == "return_statement"
            && let Some(value) = node.named_child(0)
        {
            let name = match value.kind() {
                "call" => value
                    .child_by_field_name("function")
                    .filter(|f| f.kind() == "identifier")
                    .map(|f| python_slice(f, source)),
                "identifier" => Some(python_slice(value, source)),
                _ => None,
            };
            let class = name
                .and_then(|name| context.receiver_type(analyzer, py, support, file, name, true));
            if let Some(class) = class {
                return Some(class);
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    None
}

fn python_self_receiver_type(
    analyzer: &dyn IAnalyzer,
    _py: &PythonAnalyzer,
    file: &ProjectFile,
    _root: Node<'_>,
    object: Node<'_>,
    receiver: &str,
) -> Option<CodeUnit> {
    if receiver != "self" && receiver != "cls" {
        return None;
    }
    let range = Range {
        start_byte: object.start_byte(),
        end_byte: object.end_byte(),
        start_line: 0,
        end_line: 0,
    };
    analyzer
        .enclosing_code_unit(file, &range)
        .and_then(|enclosing| analyzer.parent_of(&enclosing).or(Some(enclosing)))
        .filter(|unit| unit.is_class())
}

fn python_unresolved_import_boundary(
    py: &PythonAnalyzer,
    file: &ProjectFile,
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    local: &str,
    attribute: Option<&str>,
) -> Option<String> {
    let provider = analyzer.import_analysis_provider()?;
    for import in provider.import_info_of(token, file) {
        let alias_or_identifier = import.alias.as_deref().or(import.identifier.as_deref());
        if alias_or_identifier == Some(local)
            && provider
                .imported_code_units_of(file)
                .iter()
                .all(|unit| unit.identifier() != local)
        {
            return Some(python_import_boundary_target(
                py, token, file, local, attribute,
            ));
        }
        if let Some(attribute) = attribute
            && import.identifier.as_deref() == Some(attribute)
            && import.alias.as_deref().unwrap_or(attribute) == attribute
            && provider
                .imported_code_units_of(file)
                .iter()
                .all(|unit| unit.identifier() != attribute)
        {
            return Some(python_import_boundary_target(
                py,
                token,
                file,
                local,
                Some(attribute),
            ));
        }
    }
    None
}

fn python_import_boundary_target(
    py: &PythonAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    local: &str,
    attribute: Option<&str>,
) -> String {
    let binder = py.import_binder_of(token, file);
    binder
        .bindings
        .get(local)
        .or_else(|| attribute.and_then(|attribute| binder.bindings.get(attribute)))
        .map(|binding| {
            binding
                .namespace_imported_module
                .as_deref()
                .unwrap_or(binding.module_specifier.as_str())
                .to_string()
        })
        .unwrap_or_else(|| local.to_string())
}

/// True when the name is bound by an import whose *target module* the workspace
/// actually indexes — e.g. `from .sibling import Thing` where `sibling` is a
/// workspace module. A missing `Thing` is then a not-yet-indexed member of a
/// known-internal module, never a confident cross-workspace boundary (#1158).
/// This is the workspace-module guard the fqn/module paths already apply through
/// `python_crosses_unindexed_boundary`, which the import-binding paths lacked.
fn python_import_binding_is_workspace_internal(
    py: &PythonAnalyzer,
    token: QueryToken<'_>,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    local: &str,
    attribute: Option<&str>,
    installed_roots: &[std::path::PathBuf],
) -> bool {
    let binder = py.import_binder_of(token, file);
    let Some(binding) = binder
        .bindings
        .get(local)
        .or_else(|| attribute.and_then(|attribute| binder.bindings.get(attribute)))
    else {
        return false;
    };
    let module = binding
        .namespace_imported_module
        .as_deref()
        .unwrap_or(binding.module_specifier.as_str());
    python_workspace_declares_module(support, module)
        || !python_source_root_spellings_excluding_installed_roots(py, module, installed_roots)
            .is_empty()
}

fn python_name_shadowed_at(
    name: &str,
    reference: Node<'_>,
    source: &str,
    scopes: &mut HashMap<(usize, usize), PythonLexicalScopeBindings>,
) -> bool {
    if python_comprehension_binds_name_at(name, reference, source) {
        return true;
    }
    let mut current = reference;
    while let Some(parent) = current.parent() {
        current = parent;
        if !matches!(current.kind(), "function_definition" | "lambda") {
            continue;
        }
        let bindings = match scopes.entry((current.start_byte(), current.end_byte())) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                let Some(inventory) =
                    python_lexical_scope_inventory_bounded(current, source, || true)
                else {
                    return true;
                };
                entry.insert(inventory.into_bindings())
            }
        };
        match bindings.name_resolution_at(name, reference) {
            PythonLexicalNameResolution::Local => return true,
            PythonLexicalNameResolution::Global => return false,
            PythonLexicalNameResolution::Nonlocal | PythonLexicalNameResolution::Unbound => {}
        }
    }
    false
}

fn python_is_non_reference_context(node: Node<'_>) -> bool {
    let deferred_annotation = node.kind() == "string_content" && python_node_is_in_annotation(node);
    let mut parent = Some(node);
    while let Some(current) = parent {
        // An f-string interpolation hole holds ordinary expression nodes, so the
        // enclosing `string` does not make them opaque. The walk is bottom-up, so
        // reaching the hole before any `string` proves no nested string literal
        // separates the node from the code context. `format_expression` is the
        // same hole inside a format specifier (`f"{value:{width}}"`).
        if matches!(current.kind(), "interpolation" | "format_expression") {
            return false;
        }
        if deferred_annotation && matches!(current.kind(), "string" | "string_content") {
            parent = current.parent();
            continue;
        }
        if matches!(
            current.kind(),
            "import_statement"
                | "import_from_statement"
                | "comment"
                | "string"
                | "string_content"
                | "module"
        ) && current.kind() != "module"
        {
            return true;
        }
        parent = current.parent();
    }
    false
}

fn python_import_module_fqn(
    project: &dyn brokk_bifrost_core::analyzer::project::Project,
    file: &ProjectFile,
    source: &str,
    focus: Node<'_>,
) -> Option<String> {
    let mut current = Some(focus);
    while let Some(node) = current {
        let module = match node.kind() {
            "import_from_statement" => node.child_by_field_name("module_name"),
            "import_statement" => {
                let mut cursor = node.walk();
                node.children_by_field_name("name", &mut cursor)
                    .find_map(|imported| {
                        let module = if imported.kind() == "aliased_import" {
                            imported.child_by_field_name("name")?
                        } else {
                            imported
                        };
                        (module.start_byte() <= focus.start_byte()
                            && focus.end_byte() <= module.end_byte())
                        .then_some(module)
                    })
            }
            _ => None,
        };
        if let Some(module) = module
            && module.start_byte() <= focus.start_byte()
            && focus.end_byte() <= module.end_byte()
        {
            let raw = python_focused_import_module(module, focus, source)?;
            return if module.kind() == "relative_import" {
                resolve_python_relative_module(project, file, &raw)
            } else {
                Some(raw)
            };
        }
        current = node.parent();
    }
    None
}

fn python_focused_import_module(module: Node<'_>, focus: Node<'_>, source: &str) -> Option<String> {
    match module.kind() {
        "identifier" => same_node(module, focus).then(|| python_slice(module, source).to_string()),
        "dotted_name" => {
            let mut segments = Vec::new();
            let mut cursor = module.walk();
            for segment in module
                .named_children(&mut cursor)
                .filter(|child| child.kind() == "identifier")
            {
                segments.push(python_slice(segment, source));
                if same_node(segment, focus) {
                    return Some(segments.join("."));
                }
            }
            None
        }
        "relative_import" => {
            let mut cursor = module.walk();
            let children: Vec<_> = module.named_children(&mut cursor).collect();
            let prefix = children
                .iter()
                .find(|child| child.kind() == "import_prefix")
                .copied()?;
            let raw_prefix = python_slice(prefix, source);
            if same_node(prefix, focus) {
                return Some(raw_prefix.to_string());
            }
            let path = children
                .into_iter()
                .find(|child| matches!(child.kind(), "identifier" | "dotted_name"))?;
            let suffix = python_focused_import_module(path, focus, source)?;
            Some(format!("{raw_prefix}{suffix}"))
        }
        _ => None,
    }
}

pub(crate) fn python_call_reference_candidate(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "call" if parent.child_by_field_name("function") == Some(current) => return true,
            "attribute" if parent.child_by_field_name("attribute") == Some(current) => {
                current = parent;
            }
            _ => return false,
        }
    }
    false
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_definition_dispatch<'a>(
    analyzer: &'a dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
    token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    context: &mut brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionBatchContext<
        'a,
        '_,
    >,
    request: &brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupRequest,
    source: &std::sync::Arc<str>,
    tree: &Option<tree_sitter::Tree>,
    site: &brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite,
    _operation: Option<brokk_bifrost_analysis::navigation::NavigationOperation>,
    cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    _go_session: Option<
        &brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession,
    >,
) -> std::ops::ControlFlow<
    brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionResolution,
    brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionResolution,
> {
    let mut evidence = CallEvidence::default();
    let outcome = {
        let mut outcome = python::resolve_python(
            analyzer,
            token,
            context,
            &request.file,
            source,
            tree.as_ref(),
            site,
        );
        if outcome.status == DefinitionLookupStatus::UnresolvableImportBoundary
            && cancellation.is_some_and(CancellationToken::is_cancelled)
        {
            outcome = cancelled("Python imported class value resolution was cancelled");
        } else if outcome.status == DefinitionLookupStatus::UnresolvableImportBoundary
            && analyzer
                .active_semantic_model_snapshot()
                .is_some_and(|snapshot| snapshot.python_runtime().is_some())
        {
            match tree.as_ref().map(|tree| {
                python::python_imported_class_value_selection_bounded(
                    resolve_analyzer::<PythonAnalyzer>(analyzer).expect("Python analyzer"),
                    token,
                    &request.file,
                    source.as_ref(),
                    tree.root_node(),
                    site,
                    cancellation,
                )
            }) {
                Some(BoundedResolution::Complete {
                    value: Some(selection),
                    ..
                }) => {
                    outcome = match selection {
                        python::PythonImportedClassValueSelection::Unproven(message) => {
                            python_incomplete_class_value(
                                outcome,
                                DefinitionLookupStatus::Incomplete,
                                python_class_resolution_incomplete_diagnostic(message),
                            )
                        }
                        python::PythonImportedClassValueSelection::Proven {
                            import_module,
                            class_name,
                        } => {
                            let attempt = resolve_python_runtime_binding(
                                    analyzer,
                                    &request.file,
                                    PythonImportedMember {
                                        module: &import_module,
                                        member: &class_name,
                                    },
                                    cancellation,
                                    crate::analyzer::python::runtime_binding::resolve_python_defining_class_binding,
                                );
                            match attempt {
                                PythonRuntimeBindingAttempt::Resolved(proof) => {
                                    let canonical = proof.binding.canonical().join(".");
                                    match python_class_symbol_from_binding(
                                        analyzer,
                                        &proof.binding,
                                        &proof.provider,
                                    ) {
                                        Ok(symbol) => {
                                            let mut reference = outcome
                                                .reference
                                                .take()
                                                .unwrap_or_else(|| site.clone());
                                            reference.text = canonical;
                                            let resolved = DefinitionLookupOutcome {
                                                modeled_definitions: vec![symbol],
                                                status: DefinitionLookupStatus::Resolved,
                                                reference: Some(reference),
                                                definitions: Vec::new(),
                                                lexical_definition: None,
                                                diagnostics: Vec::new(),
                                            };
                                            trace::record_selected_modeled(&resolved);
                                            resolved
                                        }
                                        Err(message) => python_incomplete_class_value(
                                            outcome,
                                            DefinitionLookupStatus::Incomplete,
                                            python_class_resolution_incomplete_diagnostic(message),
                                        ),
                                    }
                                }
                                // No selected provider proof is available
                                // to refine the boundary, so retain the
                                // source resolver's existing claim.
                                PythonRuntimeBindingAttempt::Unavailable => outcome,
                                PythonRuntimeBindingAttempt::Cancelled => cancelled(
                                    "Python imported class value resolution was cancelled",
                                ),
                                PythonRuntimeBindingAttempt::Failed(failure) => {
                                    let (status, kind, message) =
                                        python_runtime_binding_failure_parts(failure);
                                    // A provider can withhold its competing declarations while
                                    // still proving ambiguity; retain that typed verdict.
                                    python_incomplete_class_value(
                                        outcome,
                                        status,
                                        DefinitionLookupDiagnostic {
                                            kind: kind.to_owned(),
                                            message,
                                            claim: None,
                                        },
                                    )
                                }
                            }
                        }
                    };
                }
                Some(BoundedResolution::Exceeded { limit, .. }) => {
                    outcome = exceeded_budget(
                        limit,
                        "Python imported class value resolution exceeded its bounded scope",
                    );
                }
                Some(BoundedResolution::Cancelled { .. }) => {
                    outcome = cancelled("Python imported class value resolution was cancelled");
                }
                Some(BoundedResolution::Complete { value: None, .. }) | None => {}
            }
        }
        let imported_call = if matches!(
            outcome.status,
            DefinitionLookupStatus::UnresolvableImportBoundary
                | DefinitionLookupStatus::Incomplete
                | DefinitionLookupStatus::NoDefinition
        ) {
            let session = ResolutionSession::bounded(
                brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET,
                cancellation,
            );
            let selection = tree.as_ref().and_then(|tree| {
                let python = resolve_analyzer::<PythonAnalyzer>(analyzer)?;
                if !session
                    .query(|| python.indexed_source_matches(&request.file, source.as_ref()))?
                {
                    return None;
                }
                let imports = session.query(|| {
                    analyzer
                        .import_analysis_provider()
                        .expect("Python import provider")
                        .import_info_of(token, &request.file)
                })?;
                let selected = python::exact_python_imported_call_selection(
                    source.as_ref(),
                    tree,
                    site,
                    &imports,
                    || session.scope_step(),
                );
                session
                    .query(|| python.indexed_source_matches(&request.file, source.as_ref()))?
                    .then_some(selected)
                    .flatten()
            });
            match session.finish(selection) {
                BoundedResolution::Complete { value, .. } => value,
                BoundedResolution::Exceeded { limit, .. } => {
                    outcome = exceeded_budget(
                        limit,
                        "Python imported call selection exhausted its budget",
                    );
                    None
                }
                BoundedResolution::Cancelled { .. } => {
                    outcome = cancelled("Python imported call selection was cancelled");
                    None
                }
            }
        } else {
            None
        };
        if let Some(selection) = imported_call {
            let runtime_binding = resolve_python_runtime_binding(
                analyzer,
                &request.file,
                PythonImportedMember {
                    module: &selection.module,
                    member: &selection.member,
                },
                cancellation,
                crate::analyzer::python::runtime_binding::resolve_python_defining_binding,
            );
            finish_python_imported_call_binding(
                &mut outcome,
                &mut evidence,
                site,
                selection.proof,
                runtime_binding,
                cancellation,
            );
        }
        outcome
    };
    std::ops::ControlFlow::Continue(DefinitionResolution { outcome, evidence })
}

#[cfg(test)]
mod bounded_tests {

    use crate::analyzer::usages::get_definition::python::*;

    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverBudgetLimit;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::Range;

    use brokk_bifrost_core::path_utils::rel_path_string;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon(
        "#5745: repeated module guards exhausted hierarchy work and memo hits must retain current owner reads"
    )]
    fn module_mutation_operation_memo_preserves_stops_sources_and_owner_reads() {
        use brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET;
        let source = "class A: pass\nclass B: pass\nclass C(A, B): pass\n";
        let changed = format!("{source}\ndef writer():\n    global A\n    A = B\n");
        let project = crate::inline_project::InlineTestProject::with_language(Language::Python)
            .file("a.py", source)
            .file("b.py", source)
            .file("changed.py", &changed)
            .build();
        let workspace = project
            .workspace_analyzer(brokk_bifrost_core::analyzer::config::AnalyzerConfig::default());
        let analyzer = workspace.analyzer();
        let py = resolve_analyzer::<PythonAnalyzer>(analyzer).unwrap();
        let prepared = {
            let scope = AnalyzerQueryScope::new(analyzer);
            py.prepared_syntax(scope.token(), &project.file("a.py"))
                .unwrap()
        };
        let base = prepared
            .tree()
            .root_node()
            .named_child(2)
            .unwrap()
            .child_by_field_name("superclasses")
            .unwrap()
            .named_child(0)
            .unwrap();
        let funded = || ResolutionSession::bounded(INTERACTIVE_TYPE_LOOKUP_BUDGET, None);

        // No outer query: nested owner reads must not replace the provider's memo.
        assert!(
            py.active_query_request_memo::<PythonModuleMutationRequestMemo>()
                .is_none()
        );
        let session = funded();
        let provider = PythonDefinitionProvider::new(py, &session);
        for _ in 0..2 {
            assert_eq!(
                provider.module_binding_unmutated_at_bounded(
                    &project.file("a.py"),
                    &prepared,
                    "A",
                    base
                ),
                Some(true)
            );
            assert_eq!(
                provider.module_export_unmutated_bounded(&project.file("a.py"), &prepared, "B"),
                Some(true)
            );
        }
        assert_eq!(
            provider
                .module_mutations
                .collections
                .load(Ordering::Relaxed),
            1
        );
        let fresh_session = funded();
        let fresh = PythonDefinitionProvider::new(py, &fresh_session);
        assert!(!Arc::ptr_eq(
            &provider.module_mutations,
            &fresh.module_mutations
        ));

        // An active query shares only syntax facts. A warm identical-byte owner
        // must record its own file dependency, never replay the first owner's.
        let scope = AnalyzerQueryScope::new(analyzer);
        let session = funded();
        let active = PythonDefinitionProvider::new(py, &session);
        let sibling = PythonDefinitionProvider::new(py, &session);
        assert!(Arc::ptr_eq(
            &active.module_mutations,
            &sibling.module_mutations
        ));
        assert_eq!(
            active.module_export_unmutated_bounded(&project.file("a.py"), &prepared, "A"),
            Some(true)
        );
        let other = py
            .prepared_syntax(scope.token(), &project.file("b.py"))
            .unwrap();
        let (answer, reads) =
            brokk_bifrost_analysis::analyzer::i_analyzer::capture_query_reads(analyzer, || {
                sibling.module_export_unmutated_bounded(&project.file("b.py"), &other, "A")
            });
        assert_eq!(answer, Some(true));
        let keys = reads.keys();
        assert!(
            keys.iter().any(|key| matches!(key,
            ReadKey::File { rel_path, .. } if rel_path.as_ref() == "b.py")),
            "{keys:?}"
        );
        assert!(
            !keys.iter().any(|key| matches!(key,
            ReadKey::File { rel_path, .. } if rel_path.as_ref() == "a.py")),
            "{keys:?}"
        );
        assert_eq!(
            active.module_mutations.collections.load(Ordering::Relaxed),
            1
        );
        let changed = py
            .prepared_syntax(scope.token(), &project.file("changed.py"))
            .unwrap();
        assert_ne!(prepared.source_sha256(), changed.source_sha256());
        assert_eq!(
            active.module_export_unmutated_bounded(&project.file("changed.py"), &changed, "A"),
            Some(false)
        );
        assert_eq!(
            active.module_export_unmutated_bounded(&project.file("changed.py"), &changed, "B"),
            Some(true)
        );
        assert_eq!(
            active.module_mutations.collections.load(Ordering::Relaxed),
            2
        );
        assert_eq!(
            active.module_export_unmutated_bounded(&project.file("changed.py"), &prepared, "A"),
            None,
            "a warm digest cannot substitute for a changed owner's current bytes"
        );

        // Partial collection is not published; a funded caller can fill later.
        let memo = PythonModuleMutationRequestMemo::default();
        let mut tiny = INTERACTIVE_TYPE_LOOKUP_BUDGET;
        tiny.max_scope_nodes = 1;
        let stopped = ResolutionSession::bounded(tiny, None);
        assert!(memo.facts(&prepared, &stopped).is_none());
        assert!(memo.facts.lock().unwrap().is_empty());
        assert!(memo.facts(&prepared, &funded()).is_some());
        assert_eq!(memo.collections.load(Ordering::Relaxed), 2);
        assert!(
            memo.facts(&prepared, &stopped).is_none(),
            "a warm hit cannot repair exhaustion"
        );
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let cancelled =
            ResolutionSession::bounded(INTERACTIVE_TYPE_LOOKUP_BUDGET, Some(&cancellation));
        assert!(memo.facts(&prepared, &cancelled).is_none());
        let late = CancellationToken::cancel_after_checks_for_test(2);
        let cancelled = ResolutionSession::bounded(INTERACTIVE_TYPE_LOOKUP_BUDGET, Some(&late));
        assert!(
            memo.facts(&prepared, &cancelled).is_none(),
            "cancellation after hit entry is still terminal"
        );
        assert!(matches!(
            cancelled.finish(()),
            BoundedResolution::Cancelled { .. }
        ));
        assert_eq!(memo.collections.load(Ordering::Relaxed), 2);
    }

    struct ExpandedCallableRangeAnalyzer {
        base: PythonAnalyzer,
        callable: CodeUnit,
        range: Range,
    }

    impl CodeUnitIndex for ExpandedCallableRangeAnalyzer {
        fn project(&self) -> &dyn brokk_bifrost_core::analyzer::project::Project {
            self.base.project()
        }

        fn languages(&self) -> std::collections::BTreeSet<Language> {
            self.base.languages()
        }

        fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
            self.base.all_declarations()
        }

        fn search_definitions(
            &self,
            pattern: &str,
            auto_quote: bool,
        ) -> std::collections::BTreeSet<CodeUnit> {
            self.base.search_definitions(pattern, auto_quote)
        }

        fn enclosing_code_unit(&self, file: &ProjectFile, range: &Range) -> Option<CodeUnit> {
            self.base.enclosing_code_unit(file, range)
        }

        fn enclosing_code_unit_for_lines(
            &self,
            file: &ProjectFile,
            start_line: usize,
            end_line: usize,
        ) -> Option<CodeUnit> {
            self.base
                .enclosing_code_unit_for_lines(file, start_line, end_line)
        }

        fn ranges(&self, code_unit: &CodeUnit) -> Vec<Range> {
            if code_unit == &self.callable {
                vec![self.range]
            } else {
                self.base.ranges(code_unit)
            }
        }

        fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
            self.base.get_skeleton(code_unit)
        }

        fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
            self.base.get_skeleton_header(code_unit)
        }

        fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String> {
            self.base.get_source(code_unit, include_comments)
        }

        fn get_sources(
            &self,
            code_unit: &CodeUnit,
            include_comments: bool,
        ) -> std::collections::BTreeSet<String> {
            self.base.get_sources(code_unit, include_comments)
        }

        fn signature_metadata(
            &self,
            code_unit: &CodeUnit,
        ) -> Vec<brokk_bifrost_core::analyzer::model::SignatureMetadata> {
            self.base.signature_metadata(code_unit)
        }
    }

    impl IAnalyzer for ExpandedCallableRangeAnalyzer {
        fn update(&self, changed_files: &std::collections::BTreeSet<ProjectFile>) -> Self {
            Self {
                base: self.base.update(changed_files),
                callable: self.callable.clone(),
                range: self.range,
            }
        }

        fn update_all(&self) -> Self {
            Self {
                base: self.base.update_all(),
                callable: self.callable.clone(),
                range: self.range,
            }
        }

        fn extract_call_receiver(&self, reference: &str) -> Option<String> {
            self.base.extract_call_receiver(reference)
        }

        fn is_access_expression(
            &self,
            file: &ProjectFile,
            start_byte: usize,
            end_byte: usize,
        ) -> bool {
            self.base.is_access_expression(file, start_byte, end_byte)
        }

        fn find_nearest_declaration(
            &self,
            file: &ProjectFile,
            start_byte: usize,
            end_byte: usize,
            ident: &str,
        ) -> Option<brokk_bifrost_core::analyzer::model::DeclarationInfo> {
            self.base
                .find_nearest_declaration(file, start_byte, end_byte, ident)
        }
    }

    #[test]
    #[hardwon("#4271: Python callable return inference selected the last sibling definition")]
    fn callable_return_type_uses_the_first_sibling_function_definition() {
        let source = "class First:\n    pass\n\nclass Second:\n    pass\n\ndef make_first():\n    return First()\n\ndef make_second():\n    return Second()\n";
        let fixture = AnalyzerFixture::new_for_language(Language::Python, &[("app.py", source)]);
        let analyzer = fixture.analyzer.analyzer();
        let py = resolve_analyzer::<PythonAnalyzer>(analyzer).expect("Python analyzer");
        let file = analyzer
            .analyzed_files()
            .into_iter()
            .next()
            .expect("fixture Python file");
        let callable = analyzer
            .declarations(&file)
            .into_iter()
            .find(|unit| unit.identifier() == "make_first" && unit.is_function())
            .expect("make_first declaration");
        let scope = AnalyzerQueryScope::new(analyzer);
        let context = request_definition_context(py, analyzer, scope.token(), &file, source);
        let first_start = source.find("def make_first").expect("first sibling");
        let range = Range {
            start_byte: first_start,
            end_byte: source.len(),
            start_line: source[..first_start]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count(),
            end_line: source.bytes().filter(|byte| *byte == b'\n').count(),
        };
        let indexed = ExpandedCallableRangeAnalyzer {
            base: py.clone(),
            callable: callable.clone(),
            range,
        };
        let support = AnalyzerDefinitionLookup::new(analyzer, Language::None);

        let inferred = python_callable_return_type(&indexed, py, &support, &context, &callable)
            .expect("the first sibling returns a known class");

        assert_eq!(inferred.identifier(), "First");
    }

    #[test]
    fn python_shadowing_context_keeps_supplied_source_identities_separate() {
        let original = "def read(local):\n    local.use()\n";
        let changed = "def read(other):\n    local.use()\n";
        let project = crate::inline_project::InlineTestProject::with_language(Language::Python)
            .file("app.py", original)
            .build();
        let workspace = project
            .workspace_analyzer(brokk_bifrost_core::analyzer::config::AnalyzerConfig::default());
        let analyzer = workspace.analyzer();
        let py = resolve_analyzer::<PythonAnalyzer>(analyzer).unwrap();
        let scope = AnalyzerQueryScope::new(analyzer);
        let file = project.file("app.py");
        let equivalent = String::from(original);
        let prepared = py
            .prepared_syntax(scope.token(), &file)
            .expect("prepared source is indexed");
        let original_key = definition_context_key(analyzer, &file, original, Some(&prepared));
        let equivalent_key = definition_context_key(analyzer, &file, &equivalent, Some(&prepared));
        let changed_key = definition_context_key(analyzer, &file, changed, Some(&prepared));
        assert_eq!(original_key, equivalent_key);
        assert_eq!(
            original_key.source,
            brokk_bifrost_analysis::analyzer::semantic::StableDigest::from_array(
                prepared.source_sha256()
            )
        );
        assert_ne!(original_key, changed_key);
        assert_eq!(
            changed_key.source,
            brokk_bifrost_analysis::analyzer::semantic::StableDigest::sha256(changed)
        );

        for (source, expected) in [
            (original, true),
            (changed, false),
            (equivalent.as_str(), true),
            (original, true),
        ] {
            let context = request_definition_context(py, analyzer, scope.token(), &file, source);
            let tree = parse_python_tree(source).unwrap();
            let reference = tree
                .root_node()
                .named_child(0)
                .unwrap()
                .child_by_field_name("body")
                .unwrap()
                .named_child(0)
                .unwrap()
                .named_child(0)
                .unwrap()
                .child_by_field_name("function")
                .unwrap()
                .child_by_field_name("object")
                .unwrap();
            assert_eq!(
                context.name_shadowed_at("local", reference, source),
                expected
            );
        }
        assert_eq!(
            request_definition_build_counts(py).0,
            2,
            "byte-equivalent supplied source reuses the original context"
        );
    }

    #[test]
    fn python_shadowing_reuses_completed_bindings_across_reparsed_references() {
        let source = "def first(local):\n    local.use()\n    imported.use()\ndef second():\n    local.use()\n";
        let mut scopes = HashMap::default();
        for _ in 0..2 {
            // Each parse owns different nodes; retained facts must use source
            // positions and preserve both local and module binding behavior.
            let tree = parse_python_tree(source).unwrap();
            let mut pending = vec![tree.root_node()];
            let mut answers = Vec::new();
            while let Some(node) = pending.pop() {
                if node.kind() == "attribute" {
                    let reference = node.child_by_field_name("object").unwrap();
                    answers.push((
                        reference.start_byte(),
                        python_name_shadowed_at(
                            python_slice(reference, source),
                            reference,
                            source,
                            &mut scopes,
                        ),
                    ));
                }
                let mut cursor = node.walk();
                pending.extend(node.named_children(&mut cursor));
            }
            answers.sort_unstable();
            assert_eq!(
                answers
                    .into_iter()
                    .map(|(_, shadowed)| shadowed)
                    .collect::<Vec<_>>(),
                [true, false, false]
            );
            assert_eq!(scopes.len(), 2, "one completed inventory per callable");
        }
    }

    #[test]
    fn external_decorator_binding_distinguishes_absence_and_lexical_shadowing() {
        for (body, expected) in [
            ("@decorator\nclass Expected: pass\n", true),
            (
                "def outer():\n    from external import decorator\n    @decorator\n    class Expected: pass\n",
                true,
            ),
            (
                "def outer():\n    from external import value\n    @value.decorator\n    class Expected: pass\n",
                false,
            ),
            (
                "def outer():\n    import external.value\n    @external.value.decorator\n    class Expected: pass\n",
                false,
            ),
            (
                "def outer():\n    @decorator\n    class Expected: pass\n",
                true,
            ),
            (
                "def outer():\n    def decorator(cls): return cls\n    @decorator\n    class Expected: pass\n",
                false,
            ),
            (
                "def outer():\n    class decorator: pass\n    @decorator\n    class Expected: pass\n",
                false,
            ),
            (
                "def outer():\n    decorator = replacement\n    def inner():\n        nonlocal decorator\n        @decorator\n        class Expected: pass\n",
                false,
            ),
        ] {
            let source = format!("from external import decorator\n{body}");
            let project = crate::inline_project::InlineTestProject::with_language(Language::Python)
                .file("app.py", &source)
                .build();
            let workspace = project.workspace_analyzer(
                brokk_bifrost_core::analyzer::config::AnalyzerConfig::default(),
            );
            let python = resolve_analyzer::<PythonAnalyzer>(workspace.analyzer()).unwrap();
            let tree = parse_python_tree(&source).unwrap();
            let mut stack = vec![tree.root_node()];
            let expression = loop {
                let node = stack.pop().expect("fixture contains a decorator");
                if node.kind() == "decorator" {
                    break node.named_child(0).unwrap();
                }
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor));
            };
            let scope = AnalyzerQueryScope::new(python);
            let session = ResolutionSession::bounded(
                brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET,
                None,
            );
            let support = PythonDefinitionProvider::new(python, &session);
            let actual = python_external_imported_symbol_bounded(
                &support,
                scope.token(),
                &project.file("app.py"),
                &source,
                tree.root_node(),
                expression,
            );
            assert_eq!(
                actual,
                expected.then(|| ("external".to_owned(), "decorator".to_owned())),
                "{source}"
            );
        }
    }

    #[brokk_bifrost_test_macros::hardwon(
        "6c7b92f9623b: modeled Python wildcard imports were incorrectly left uncertain across same-target reexports"
    )]
    #[test]
    fn external_import_survives_only_same_target_workspace_wildcard_reexports() {
        let interface = concat!(
            "from abc import ABC\n",
            "from registry.models import *\n",
            "\n",
            "class Registry(ABC):\n",
            "    pass\n",
        );
        for (models, expected) in [
            (
                "from abc import ABC\nclass ToDict(ABC):\n    pass\n",
                Some(("abc".to_owned(), "ABC".to_owned())),
            ),
            ("class ABC:\n    pass\n", None),
        ] {
            let project = crate::inline_project::InlineTestProject::with_language(Language::Python)
                .file("registry/__init__.py", "")
                .file("registry/interface.py", interface)
                .file("registry/models.py", models)
                .build();
            let workspace = project.workspace_analyzer(
                brokk_bifrost_core::analyzer::config::AnalyzerConfig::default(),
            );
            let python = resolve_analyzer::<PythonAnalyzer>(workspace.analyzer()).unwrap();
            let scope = AnalyzerQueryScope::new(python);
            let file = project.file("registry/interface.py");
            let tree = parse_python_tree(interface).unwrap();
            let mut stack = vec![tree.root_node()];
            let base = loop {
                let node = stack.pop().expect("fixture contains Registry(ABC)");
                if node.kind() == "class_definition"
                    && node
                        .child_by_field_name("name")
                        .is_some_and(|name| python_slice(name, interface) == "Registry")
                {
                    break node
                        .child_by_field_name("superclasses")
                        .and_then(|bases| bases.named_child(0))
                        .expect("Registry has one base");
                }
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor));
            };
            let session = ResolutionSession::bounded(
                brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET,
                None,
            );
            let support = PythonDefinitionProvider::new(python, &session);
            let actual = python_external_imported_symbol_bounded(
                &support,
                scope.token(),
                &file,
                interface,
                tree.root_node(),
                base,
            );
            assert_eq!(actual, expected, "models source:\n{models}");
        }
    }

    fn wide_deep_member_fixture() -> (
        AnalyzerFixture,
        ProjectFile,
        String,
        Tree,
        ResolvedReferenceSite,
    ) {
        let statements = (0..96)
            .map(|index| format!("    value{index} = {index}\n"))
            .collect::<String>();
        let expression = format!("{}service{}.run()", "(".repeat(24), ")".repeat(24));
        let source = format!(
            "class Service:\n    def run(self) -> None:\n        pass\n\n\
             def use(service: Service) -> None:\n{statements}    {expression}\n"
        );
        brokk_bifrost_analysis::analyzer::usages::test_support::wide_deep_member_fixture(
            Language::Python,
            "receiver.py",
            source,
            &expression,
            "run",
            parse_python_tree,
        )
    }

    #[test]
    fn bounded_python_wide_deep_walk_stops_without_partial_result() {
        let (fixture, file, source, tree, site) = wide_deep_member_fixture();
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let token = scope.token();
        let outcome = resolve_python_bounded(
            fixture.analyzer.analyzer(),
            token,
            &file,
            &source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::tiny(),
            None,
        );

        assert!(matches!(
            outcome,
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                ..
            }
        ));
    }

    #[brokk_bifrost_test_macros::hardwon(
        "bb38340252e1: Python from-import fixture resolves the module segment as the import anchor rather than the imported member"
    )]
    #[test]
    fn bounded_python_from_import_module_segment_resolves_module_anchor() {
        let source = "from example.service import Repository\n";
        let fixture = AnalyzerFixture::new_for_language(
            Language::Python,
            &[
                ("src/example/__init__.py", ""),
                ("src/example/service.py", "class Repository:\n    pass\n"),
                ("tests/test_service.py", source),
            ],
        );
        let file = ProjectFile::new(fixture.project_root(), "tests/test_service.py");
        let tree = parse_python_tree(source).expect("Python tree");
        let start_byte = source.find("service").expect("module segment");
        let site = ResolvedReferenceSite {
            path: rel_path_string(&file),
            text: "service".to_string(),
            range: Range {
                start_byte,
                end_byte: start_byte + "service".len(),
                start_line: 1,
                end_line: 1,
            },
            focus_start_byte: start_byte,
            focus_end_byte: start_byte + "service".len(),
        };
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let outcome = resolve_python_bounded(
            fixture.analyzer.analyzer(),
            scope.token(),
            &file,
            source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        );

        let BoundedResolution::Complete { value, .. } = outcome else {
            panic!("Python module lookup should complete: {outcome:#?}");
        };
        assert_eq!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");
        assert!(
            matches!(value.definitions.as_slice(), [definition]
                if definition.is_module()
                    && definition.fq_name() == "example.service"
                    && rel_path_string(definition.source()) == "src/example/service.py"),
            "{value:#?}"
        );
    }

    #[test]
    fn bounded_python_wide_deep_walk_honors_mid_walk_cancellation() {
        let (fixture, file, source, tree, site) = wide_deep_member_fixture();
        let cancellation = CancellationToken::cancel_after_checks_for_test(12);
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let token = scope.token();
        let outcome = resolve_python_bounded(
            fixture.analyzer.analyzer(),
            token,
            &file,
            &source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            Some(&cancellation),
        );

        assert!(matches!(outcome, BoundedResolution::Cancelled { .. }));
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#1612: Ensures ordinary Python string content is not treated as a reference without a structured import/call node"
    )]
    #[test]
    fn bounded_python_ordinary_string_is_not_a_reference() {
        let source = "class Widget:\n    pass\n\nname = \"Widget\"\n";
        let fixture =
            AnalyzerFixture::new_for_language(Language::Python, &[("ordinary.py", source)]);
        let file = ProjectFile::new(fixture.project_root(), "ordinary.py");
        let tree = parse_python_tree(source).expect("Python tree");
        let start_byte = source.rfind("Widget").expect("ordinary string content");
        let site = ResolvedReferenceSite {
            path: rel_path_string(&file),
            text: "Widget".to_string(),
            range: Range {
                start_byte,
                end_byte: start_byte + "Widget".len(),
                start_line: 4,
                end_line: 4,
            },
            focus_start_byte: start_byte,
            focus_end_byte: start_byte + "Widget".len(),
        };
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let token = scope.token();
        let outcome = resolve_python_bounded(
            fixture.analyzer.analyzer(),
            token,
            &file,
            source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        );
        let BoundedResolution::Complete { value, .. } = outcome else {
            panic!("ordinary string lookup did not complete: {outcome:#?}");
        };
        assert!(value.definitions.is_empty(), "{value:#?}");
    }

    #[test]
    fn bounded_python_local_function_requires_definite_visibility() {
        for (path, source) in [
            (
                "forward_local_factory.py",
                r#"class Product:
    def run(self) -> None:
        pass

def caller() -> None:
    value = make()
    value.run()

    def make() -> Product:
        return Product()
"#,
            ),
            (
                "conditional_local_factory.py",
                r#"class Product:
    def run(self) -> None:
        pass

def caller(flag) -> None:
    if flag:
        def make() -> Product:
            return Product()

    value = make()
    value.run()
"#,
            ),
            (
                "header_forward_local_factory.py",
                r#"class Product:
    def run(self) -> None:
        pass

def outer() -> None:
    def nested(argument=make().run()) -> None:
        pass

    def make() -> Product:
        return Product()
"#,
            ),
        ] {
            let fixture = AnalyzerFixture::new_for_language(Language::Python, &[(path, source)]);
            let file = ProjectFile::new(fixture.project_root(), path);
            let tree = parse_python_tree(source).expect("Python tree");
            let start_byte = source.rfind("run").expect("member name");
            let start_line = source[..start_byte]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count()
                + 1;
            let site = ResolvedReferenceSite {
                path: rel_path_string(&file),
                text: "run".to_string(),
                range: Range {
                    start_byte,
                    end_byte: start_byte + "run".len(),
                    start_line,
                    end_line: start_line,
                },
                focus_start_byte: start_byte,
                focus_end_byte: start_byte + "run".len(),
            };
            let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
            let token = scope.token();
            let outcome = resolve_python_bounded(
                fixture.analyzer.analyzer(),
                token,
                &file,
                source,
                Some(&tree),
                &site,
                ReceiverAnalysisBudget::default(),
                None,
            );
            let BoundedResolution::Complete { value, .. } = outcome else {
                panic!("{path} lookup did not complete: {outcome:#?}");
            };
            assert!(
                value
                    .definitions
                    .iter()
                    .all(|definition| !definition.fq_name().ends_with("Product.run")),
                "{path}: {value:#?}"
            );
        }
    }

    fn imported_call_selection(source: &str, callee: &str) -> Option<PythonImportedCallSelection> {
        imported_call_selection_with_steps(source, callee, || true)
    }

    fn imported_call_selection_with_steps(
        source: &str,
        callee: &str,
        scope_step: impl FnMut() -> bool,
    ) -> Option<PythonImportedCallSelection> {
        let tree = parse_python_tree(source).expect("Python tree");
        let start_byte = source
            .rfind(callee)
            .unwrap_or_else(|| panic!("missing `{callee}` call in source"));
        let end_byte = start_byte + callee.len();
        let start_line = source[..start_byte]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1;
        let site = ResolvedReferenceSite {
            path: "caller.py".to_string(),
            text: callee.to_string(),
            range: Range {
                start_byte,
                end_byte,
                start_line,
                end_line: start_line,
            },
            focus_start_byte: start_byte,
            focus_end_byte: end_byte,
        };
        let file = ProjectFile::new(std::env::temp_dir(), "caller.py");
        let parsed = brokk_bifrost_python::declarations::parse_python_file(
            &brokk_bifrost_core::analyzer::project::TestProject::new(file.root(), Language::Python),
            &file,
            source,
            &tree,
        );
        exact_python_imported_call_selection(source, &tree, &site, &parsed.imports, scope_step)
    }

    fn imported_call_proof(source: &str, callee: &str) -> Option<ExactExternalCallProof> {
        imported_call_selection(source, callee).map(|selection| selection.proof)
    }

    #[test]
    fn same_statement_from_import_aliases_keep_their_own_callable_identity() {
        let source = "from yaml import unsafe_load as unsafe_load_alias, safe_load as safe_load_alias, load as load_alias\nunsafe_load_alias(data)\nsafe_load_alias(data)\nload_alias(data, Loader=loader)\n";
        for (alias, canonical, member, parameter_count) in [
            ("unsafe_load_alias", "yaml.unsafe_load", "unsafe_load", 1),
            ("safe_load_alias", "yaml.safe_load", "safe_load", 1),
            ("load_alias", "yaml.load", "load", 2),
        ] {
            let selection = imported_call_selection(source, alias)
                .unwrap_or_else(|| panic!("missing exact proof for `{canonical}`"));
            assert_eq!(selection.proof.canonical_callee(), canonical);
            assert_eq!(selection.module, vec!["yaml".to_owned()]);
            assert_eq!(selection.member, member);
            assert_eq!(selection.proof.parameter_count(), parameter_count);
        }
    }

    #[test]
    #[hardwon(
        "#5721: imported-call fallback bypassed competing declarations and captured-cell writes"
    )]
    fn exact_python_import_call_refuses_shadowed_and_rebound_locals() {
        let sources = [
            "import subprocess as sp\nsp = FakeProcess()\nsp.run(command)\n",
            "import requests\nrequests = FakeSession()\nrequests.get(url, verify=False)\n",
            "import subprocess as sp\ndef call(sp):\n    sp.run(command)\n",
            "def call(factory):\n    import subprocess as sp\n    sp = factory()\n    sp.run(command)\n",
            "def call():\n    from subprocess import run\n    def run(): pass\n    run(command)\n",
            "def call():\n    from subprocess import run\n    class run: pass\n    run(command)\n",
            "def call():\n    from subprocess import run\n    def mutate():\n        nonlocal run\n        run = fake\n    mutate()\n    run(command)\n",
            "def call():\n    from subprocess import run\n    class Mutate:\n        nonlocal run\n        run = fake\n    run(command)\n",
            "def call():\n    from subprocess import run\n    def capture(): return run\n    capture.__closure__[0].cell_contents = fake\n    run(command)\n",
        ];
        for source in sources {
            let callee = if source.contains("requests.get") {
                "get"
            } else {
                "run"
            };
            assert!(
                imported_call_proof(source, callee).is_none(),
                "shadowed call unexpectedly proved: {source}"
            );
        }
        let source = "def call():\n    from subprocess import run\n    run(command)\n";
        assert!(imported_call_proof(source, "run").is_some());
        for source in [
            "def call():\n    import pkg.sub\n    pkg.sub.run(command)\n",
            "def call():\n    import pkg.sub as alias\n    alias.run(command)\n",
        ] {
            assert_eq!(
                imported_call_proof(source, "run")
                    .unwrap()
                    .canonical_callee(),
                "pkg.sub.run",
                "{source}",
            );
        }
        for allowance in [0, 1, 8] {
            let session = ResolutionSession::bounded(
                ReceiverAnalysisBudget {
                    max_scope_nodes: allowance,
                    ..brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET
                },
                None,
            );
            let selected =
                imported_call_selection_with_steps(source, "run", || session.scope_step());
            assert!(
                selected.is_none(),
                "a stopped selector must not attach import proof"
            );
            assert!(matches!(
                session.finish(selected),
                BoundedResolution::Exceeded { .. }
            ));
        }
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::new();
        cancellation.cancel();
        let session = ResolutionSession::bounded(
            brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET,
            Some(&cancellation),
        );
        let selected = imported_call_selection_with_steps(source, "run", || session.scope_step());
        assert!(matches!(
            session.finish(selected),
            BoundedResolution::Cancelled { .. }
        ));

        // Selection has already succeeded here. Drive the actual production
        // post-runtime boundary, rather than pre-cancelling the selector again.
        let site = ResolvedReferenceSite {
            path: "caller.py".to_owned(),
            text: "run".to_owned(),
            range: Range {
                start_byte: 0,
                end_byte: 3,
                start_line: 1,
                end_line: 1,
            },
            focus_start_byte: 0,
            focus_end_byte: 3,
        };
        for (runtime_binding, late_cancellation, stopped) in [
            (PythonRuntimeBindingAttempt::Unavailable, None, false),
            (PythonRuntimeBindingAttempt::Cancelled, None, true),
            (
                PythonRuntimeBindingAttempt::Unavailable,
                Some(&cancellation),
                true,
            ),
        ] {
            let proof = imported_call_proof(source, "run")
                .expect("selection completed before runtime binding");
            let mut outcome =
                no_definition("pending_import", "import selected before runtime binding");
            let mut evidence = CallEvidence::default();
            finish_python_imported_call_binding(
                &mut outcome,
                &mut evidence,
                &site,
                proof,
                runtime_binding,
                late_cancellation,
            );
            if stopped {
                assert_eq!(outcome.status, DefinitionLookupStatus::Cancelled);
                assert!(
                    outcome.reference.is_none(),
                    "late stop must not publish a canonical reference"
                );
                assert!(evidence.exact_external_call.is_none());
                assert_eq!(
                    evidence.call_application,
                    CallEvidence::default().call_application
                );
                assert!(evidence.dispatch_extensibility.is_none());
            } else {
                assert_eq!(outcome.reference.as_ref().unwrap().text, "subprocess.run");
                assert!(evidence.exact_external_call.is_some());
            }
        }
    }

    #[test]
    fn exact_python_import_call_refuses_ambiguous_and_unstructured_shapes() {
        let sources = [
            (
                "import subprocess as sp\nimport fake as sp\nsp.run(command)\n",
                "run",
            ),
            (
                "import subprocess\nsubprocess.run.extra(command)\n",
                "extra",
            ),
            ("from subprocess import *\nrun(command)\n", "run"),
            ("run(command)\n", "run"),
            (
                "def call():\n    import pkg.sub\n    pkg.other.run(command)\n",
                "run",
            ),
            ("import pkg.sub\npkg.other.run(command)\n", "run"),
            (
                "import subprocess\nvalue = subprocess\nvalue.run(command)\n",
                "run",
            ),
        ];
        for (source, callee) in sources {
            assert!(
                imported_call_proof(source, callee).is_none(),
                "unstructured call unexpectedly proved: {source}"
            );
        }
    }

    #[test]
    fn exact_python_import_call_refuses_class_and_conditional_scopes() {
        let class_source = "class Commands:\n    import subprocess as sp\n\n    def call(self):\n        sp.run(command)\n";
        assert!(imported_call_proof(class_source, "run").is_none());
        let conditional_source =
            "import subprocess\nif enabled:\n    import fake as sp\nsp.run(command)\n";
        assert!(imported_call_proof(conditional_source, "run").is_none());
        let conditional_function_source = "def invoke(command, enabled):\n    if enabled:\n        from subprocess import run\n    return run(command)\n";
        assert!(imported_call_proof(conditional_function_source, "run").is_none());
    }
}

#[cfg(test)]
mod batch_context_tests {

    use crate::analyzer::usages::get_definition::python::*;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    use brokk_bifrost_test_macros::hardwon;
    #[test]
    #[hardwon(
        "#3164: one-call Python batches repeatedly rebuilt scope facts and parsed prepared source"
    )]
    fn python_call_target_batches_reuse_request_context_and_prepared_syntax() {
        let source = Arc::<str>::from(
            "from service import Service\n\ndef handle(service: Service):\n    service.run()\n",
        );
        let fixture = AnalyzerFixture::new_for_language(
            Language::Python,
            &[
                (
                    "service.py",
                    "class Service:\n    def run(self):\n        pass\n",
                ),
                ("app.py", source.as_ref()),
            ],
        );
        let file = ProjectFile::new(fixture.project_root(), "app.py");
        let analyzer = fixture.analyzer.analyzer();
        let py = resolve_analyzer::<PythonAnalyzer>(analyzer).expect("Python analyzer");
        let member_start = source.rfind("run").expect("receiver member in source");
        let request = DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(member_start),
            end_byte: Some(member_start + "run".len()),
        };
        let scope = AnalyzerQueryScope::new(analyzer);
        let prepared = py
            .prepared_syntax(scope.token(), &file)
            .expect("prepared Python syntax");
        assert_eq!(prepared.source(), source.as_ref());
        let mut ledgers = Vec::new();

        for _ in 0..2 {
            let ledger = Arc::new(brokk_bifrost_analysis::analyzer::read_ledger::ReadLedger::new());
            let ledger_scope = AnalyzerQueryScope::with_read_ledger(analyzer, Arc::clone(&ledger));
            let outcomes = resolve_call_target_batch_with_source(
                analyzer,
                scope.token(),
                vec![request.clone()],
                file.clone(),
                Arc::clone(&source),
                None,
            );
            assert_eq!(outcomes.len(), 1);
            assert_eq!(outcomes[0].outcome.status, DefinitionLookupStatus::Resolved);
            assert_eq!(
                outcomes[0].outcome.definitions[0].fq_name(),
                "service.Service.run"
            );
            drop(ledger_scope);
            ledgers.push(ledger);
        }

        assert_eq!(py.prepared_syntax_parse_count_for_test(&file), 1);
        assert_eq!(request_definition_build_counts(py), (1, 1, 1, 0));
        assert!(!ledgers[0].is_empty());
        let cached_reads =
            request_definition_cached_read_keys(py, analyzer, &file, source.as_ref());
        let replayed_reads = ledgers[1].keys();
        assert!(
            cached_reads
                .iter()
                .all(|read| replayed_reads.contains(read)),
            "cached Python definition reads were not replayed: cached={cached_reads:?}, replayed={replayed_reads:?}"
        );
    }

    /// #3496: one call-target batch keeps whatever its resolver proved about
    /// the call, whichever language wrote it.
    ///
    /// The route used to send a hand-kept list of languages through the branch
    /// that retains `exact_external_call` and `external_callee_identity`, and
    /// flattened every other language's evidence to `None` one layer above the
    /// resolver that produced it. Ruby's boundary proof was discarded that way
    /// for as long as Ruby was absent from the list (#3459). These rows read
    /// the languages that publish a proof today back through the production
    /// entry point, beside one that publishes none, so an absent proof stays
    /// the resolver's own answer rather than the route's.

    #[test]
    fn python_batch_context_resolves_explicit_reexports_without_generic_imports() {
        let source =
            "from facade import Service\n\ndef handle(service: Service):\n    service.run()\n";
        let fixture = AnalyzerFixture::new_for_language(
            Language::Python,
            &[
                (
                    "service.py",
                    "class Service:\n    def run(self):\n        pass\n",
                ),
                ("facade.py", "from service import Service\n"),
                ("app.py", source),
            ],
        );
        let file = ProjectFile::new(fixture.project_root(), "app.py");
        let analyzer = fixture.analyzer.analyzer();
        let scope = AnalyzerQueryScope::new(analyzer);
        let mut context = DefinitionBatchContext::new(analyzer, scope.token());
        let start_byte = source.rfind("run").expect("receiver member in source");

        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        let outcomes = resolve_definition_requests(
            analyzer,
            token,
            &mut context,
            vec![DefinitionLookupRequest {
                file,
                line: None,
                column: None,
                start_byte: Some(start_byte),
                end_byte: Some(start_byte + "run".len()),
            }],
            None,
            None,
        );

        assert_eq!(outcomes[0].status, DefinitionLookupStatus::Resolved);
        assert_eq!(outcomes[0].definitions[0].fq_name(), "service.Service.run");
        assert_eq!(
            context
                .language_state::<PythonDefinitionState>()
                .python_build_counts(analyzer),
            (1, 1, 1, 0)
        );
        assert!(
            context
                .language_state::<PythonDefinitionState>()
                .python_contexts
                .is_empty()
        );
    }

    #[test]
    fn python_batch_context_preserves_reexport_source_order_across_facades() {
        let source = "from facade_import_wins import Service as ImportedWins\nfrom facade_local_wins import Service as LocalWins\n\ndef handle(imported: ImportedWins, local: LocalWins):\n    imported.leaf_only()\n    local.local_only()\n";
        let fixture = AnalyzerFixture::new_for_language(
            Language::Python,
            &[
                (
                    "leaf.py",
                    "class Service:\n    def leaf_only(self):\n        pass\n",
                ),
                (
                    "middle_import_wins.py",
                    "class Service:\n    pass\n\nfrom leaf import Service\n",
                ),
                (
                    "middle_local_wins.py",
                    "from leaf import Service\n\nclass Service:\n    def local_only(self):\n        pass\n",
                ),
                (
                    "facade_import_wins.py",
                    "from middle_import_wins import Service\n",
                ),
                (
                    "facade_local_wins.py",
                    "from middle_local_wins import Service\n",
                ),
                ("app.py", source),
            ],
        );
        let file = ProjectFile::new(fixture.project_root(), "app.py");
        let analyzer = fixture.analyzer.analyzer();
        let scope = AnalyzerQueryScope::new(analyzer);
        let mut context = DefinitionBatchContext::new(analyzer, scope.token());
        let requests = ["leaf_only", "local_only"]
            .into_iter()
            .map(|needle| {
                let start_byte = source.rfind(needle).expect("receiver member in source");
                DefinitionLookupRequest {
                    file: file.clone(),
                    line: None,
                    column: None,
                    start_byte: Some(start_byte),
                    end_byte: Some(start_byte + needle.len()),
                }
            })
            .collect();

        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        let outcomes =
            resolve_definition_requests(analyzer, token, &mut context, requests, None, None);

        assert_eq!(
            outcomes[0].definitions[0].fq_name(),
            "leaf.Service.leaf_only"
        );
        assert_eq!(
            outcomes[1].definitions[0].fq_name(),
            "middle_local_wins.Service.local_only"
        );
        assert_eq!(
            context
                .language_state::<PythonDefinitionState>()
                .python_build_counts(analyzer),
            (1, 1, 2, 0)
        );
        assert!(
            context
                .language_state::<PythonDefinitionState>()
                .python_contexts
                .is_empty()
        );
    }

    #[test]
    fn python_batch_context_keeps_receiver_types_isolated_by_file() {
        let source_a =
            "from service_a import Service\n\ndef handle(service: Service):\n    service.run()\n";
        let source_b =
            "from service_b import Service\n\ndef handle(service: Service):\n    service.stop()\n";
        let fixture = AnalyzerFixture::new_for_language(
            Language::Python,
            &[
                (
                    "service_a.py",
                    "class Service:\n    def run(self):\n        pass\n",
                ),
                (
                    "service_b.py",
                    "class Service:\n    def stop(self):\n        pass\n",
                ),
                ("app_a.py", source_a),
                ("app_b.py", source_b),
            ],
        );
        let file_a = ProjectFile::new(fixture.project_root(), "app_a.py");
        let file_b = ProjectFile::new(fixture.project_root(), "app_b.py");
        let analyzer = fixture.analyzer.analyzer();
        let scope = AnalyzerQueryScope::new(analyzer);
        let mut context = DefinitionBatchContext::new(analyzer, scope.token());
        let requests = [(file_a, source_a, "run"), (file_b, source_b, "stop")]
            .into_iter()
            .map(|(file, source, needle)| {
                let start_byte = source.rfind(needle).expect("receiver member in source");
                DefinitionLookupRequest {
                    file,
                    line: None,
                    column: None,
                    start_byte: Some(start_byte),
                    end_byte: Some(start_byte + needle.len()),
                }
            })
            .collect();

        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        let outcomes =
            resolve_definition_requests(analyzer, token, &mut context, requests, None, None);

        assert_eq!(
            outcomes[0].definitions[0].fq_name(),
            "service_a.Service.run"
        );
        assert_eq!(
            outcomes[1].definitions[0].fq_name(),
            "service_b.Service.stop"
        );
        assert_eq!(
            context
                .language_state::<PythonDefinitionState>()
                .python_build_counts(analyzer),
            (2, 2, 2, 0)
        );
        assert!(
            context
                .language_state::<PythonDefinitionState>()
                .python_contexts
                .is_empty()
        );
    }

    #[test]
    fn python_batch_receiver_type_cache_bypasses_inserts_at_its_limit() {
        let source = "from service import Service\nfrom other import Other\n\ndef handle(service: Service, other: Other):\n    service.run()\n    other.stop()\n    service.run()\n";
        let fixture = AnalyzerFixture::new_for_language(
            Language::Python,
            &[
                (
                    "service.py",
                    "class Service:\n    def run(self):\n        pass\n",
                ),
                (
                    "other.py",
                    "class Other:\n    def stop(self):\n        pass\n",
                ),
                ("app.py", source),
            ],
        );
        let file = ProjectFile::new(fixture.project_root(), "app.py");
        let analyzer = fixture.analyzer.analyzer();
        let py = resolve_analyzer::<PythonAnalyzer>(analyzer).expect("Python analyzer");
        let scope = AnalyzerQueryScope::new(analyzer);
        let mut context = DefinitionBatchContext::new(analyzer, scope.token());
        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        let python_context = context
            .language_state::<PythonDefinitionState>()
            .python_context(token, py, analyzer, &file, source);
        python_context.set_receiver_type_cache_limit(1);
        let member_offsets = [
            source
                .find("service.run")
                .expect("first service call in source")
                + "service.".len(),
            source.find("other.stop").expect("other call in source") + "other.".len(),
            source
                .rfind("service.run")
                .expect("second service call in source")
                + "service.".len(),
        ];
        let requests = member_offsets
            .into_iter()
            .zip(["run", "stop", "run"])
            .map(|(start_byte, needle)| DefinitionLookupRequest {
                file: file.clone(),
                line: None,
                column: None,
                start_byte: Some(start_byte),
                end_byte: Some(start_byte + needle.len()),
            })
            .collect();

        let outcomes =
            resolve_definition_requests(analyzer, token, &mut context, requests, None, None);

        assert_eq!(outcomes[0].definitions[0].fq_name(), "service.Service.run");
        assert_eq!(outcomes[1].definitions[0].fq_name(), "other.Other.stop");
        assert_eq!(outcomes[2].definitions[0].fq_name(), "service.Service.run");
        assert_eq!(python_context.receiver_type_cache_len(), 1);
        assert_eq!(
            context
                .language_state::<PythonDefinitionState>()
                .python_build_counts(analyzer),
            (1, 1, 2, 0)
        );
        assert!(
            context
                .language_state::<PythonDefinitionState>()
                .python_contexts
                .is_empty()
        );
    }
}
