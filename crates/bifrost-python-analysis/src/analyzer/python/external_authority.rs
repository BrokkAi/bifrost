//! Checked external Python identity shared by native and legacy requests.
//!
//! All memoized authority belongs to one active query, never to an analyzer.

use brokk_bifrost_analysis::analyzer::usages::get_definition::*;
use brokk_bifrost_analysis::analyzer::{IAnalyzer, ProjectFile, resolve_analyzer};
use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;
use brokk_bifrost_core::cancellation::CancellationToken;
use std::sync::Arc;

pub(crate) trait PythonRuntimeCallProof: Sized {
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

pub(crate) struct PythonRuntimeBindingAndProvider {
    pub(crate) binding: crate::analyzer::python::runtime_binding::PythonDefiningBinding,
    pub(crate) provider: crate::analyzer::python::runtime_binding::PythonRuntimeProviderProof,
}

pub(crate) struct PythonImportedMember<'a> {
    pub(crate) module: &'a [String],
    pub(crate) member: &'a str,
}

pub(crate) type PythonDefiningBindingResolver = fn(
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

pub(crate) enum PythonRuntimeBindingFailure {
    Binding(crate::analyzer::python::runtime_binding::PythonRuntimeBindingError),
    ProviderIncomplete(String),
    ProviderStale(String),
    ProviderVerification(String),
}

pub(crate) fn python_runtime_binding_failure_parts(
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

pub(crate) fn python_runtime_binding_failure_diagnostic(
    failure: PythonRuntimeBindingFailure,
) -> DefinitionLookupDiagnostic {
    let (_, kind, message) = python_runtime_binding_failure_parts(failure);
    DefinitionLookupDiagnostic {
        kind: kind.to_owned(),
        message,
        claim: None,
    }
}

pub(crate) fn python_class_resolution_incomplete_diagnostic(
    message: impl Into<String>,
) -> DefinitionLookupDiagnostic {
    DefinitionLookupDiagnostic {
        kind: "python_imported_class_resolution_incomplete".to_owned(),
        message: message.into(),
        claim: None,
    }
}

pub(crate) fn python_incomplete_class_value(
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

pub(crate) enum PythonRuntimeBindingAttempt {
    Unavailable,
    Cancelled,
    Resolved(Box<PythonRuntimeBindingAndProvider>),
    Failed(PythonRuntimeBindingFailure),
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PythonRuntimeBindingTestResult {
    Unavailable,
    Cancelled,
    Resolved,
    Failed,
}

/// Test-support entry point for one production Python runtime binding call site.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn resolve_python_runtime_binding_for_test(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    module: &[String],
    member: &str,
) -> PythonRuntimeBindingTestResult {
    match resolve_python_runtime_binding(
        analyzer,
        file,
        PythonImportedMember { module, member },
        None,
        crate::analyzer::python::runtime_binding::resolve_python_defining_binding,
    ) {
        PythonRuntimeBindingAttempt::Unavailable => PythonRuntimeBindingTestResult::Unavailable,
        PythonRuntimeBindingAttempt::Cancelled => PythonRuntimeBindingTestResult::Cancelled,
        PythonRuntimeBindingAttempt::Resolved(_) => PythonRuntimeBindingTestResult::Resolved,
        PythonRuntimeBindingAttempt::Failed(_) => PythonRuntimeBindingTestResult::Failed,
    }
}

// Keep staged import evidence behind the runtime attempt's terminal outcome.
// The same boundary is exercised by the imported-call cancellation regression.
pub(crate) fn finish_python_imported_call_binding(
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

pub(crate) fn resolve_python_runtime_binding(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    imported: PythonImportedMember<'_>,
    cancellation: Option<&CancellationToken>,
    resolve_binding: PythonDefiningBindingResolver,
) -> PythonRuntimeBindingAttempt {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return PythonRuntimeBindingAttempt::Cancelled;
    }
    let resolve = || match analyzer.active_semantic_model_snapshot() {
        Some(active_snapshot) => resolve_python_runtime_binding_in_snapshot(
            analyzer,
            file,
            PythonImportedMember {
                module: imported.module,
                member: imported.member,
            },
            cancellation,
            resolve_binding,
            &active_snapshot,
        ),
        None => PythonRuntimeBindingAttempt::Unavailable,
    };
    let (answer, fact) = if brokk_bifrost_analysis::analyzer::read_attribution_records_reads(|| {
        analyzer.read_ledger_attached()
    }) {
        let ((answer, fact), _) =
            brokk_bifrost_analysis::analyzer::capture_subsumed_query_reads(analyzer, || {
                let answer = resolve();
                let fact = (!matches!(answer, PythonRuntimeBindingAttempt::Cancelled)).then(|| {
                    environment_binding_fact(analyzer, file, imported.module, imported.member)
                });
                (answer, fact)
            });
        (answer, fact)
    } else {
        (resolve(), None)
    };
    if let Some(fact) = fact {
        brokk_bifrost_analysis::analyzer::workspace_authority::record_workspace_authority_read(
            analyzer,
            brokk_bifrost_analysis::analyzer::WorkspaceFactFamily::PythonEnvironmentBinding,
            fact.inputs(),
        );
    }
    answer
}

#[derive(Clone)]
struct EnvironmentBindingFact {
    subject: brokk_bifrost_analysis::analyzer::FactSubject,
    answer: brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest,
    complete: bool,
}

impl EnvironmentBindingFact {
    fn inputs(&self) -> brokk_bifrost_analysis::analyzer::AuthorityInputs<'static> {
        if !self.complete {
            // Installed provider or launch evidence could not be verified. A
            // Models key alone does not cover these non-source inputs.
            return brokk_bifrost_analysis::analyzer::AuthorityInputs::Unnamed;
        }
        brokk_bifrost_analysis::analyzer::AuthorityInputs::Fact {
            language: brokk_bifrost_analysis::analyzer::Language::Python,
            subject: self.subject.clone(),
            answer: self.answer,
        }
    }
}

/// A complete question covers both callable and class/value interpretations.
/// Callers can ask either without assigning two answers to the same Fact key.
fn environment_binding_fact(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    module: &[String],
    member: &str,
) -> EnvironmentBindingFact {
    use brokk_bifrost_analysis::analyzer::FactSubject;
    use brokk_bifrost_analysis::analyzer::canonical_hash::CanonicalHasher;
    use brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest;
    let mut digest = CanonicalHasher::new(b"bifrost-python-environment-binding/v1");
    let mut environment = StableDigest::sha256(b"no-selected-python-environment");
    let mut complete = true;
    let snapshot = analyzer.active_semantic_model_snapshot();
    if let Some(snapshot) = snapshot.as_ref() {
        digest.value(snapshot.active_models().active_model_set_hash().as_bytes());
        if let Some(publication) = snapshot.python_runtime() {
            let python = resolve_analyzer::<crate::analyzer::PythonAnalyzer>(analyzer);
            for resolver in [
                crate::analyzer::python::runtime_binding::resolve_python_defining_binding
                    as PythonDefiningBindingResolver,
                crate::analyzer::python::runtime_binding::resolve_python_defining_class_binding,
            ] {
                match resolve_python_runtime_binding_in_snapshot(
                    analyzer,
                    file,
                    PythonImportedMember { module, member },
                    None,
                    resolver,
                    snapshot,
                ) {
                    PythonRuntimeBindingAttempt::Resolved(checked) => {
                        digest.value(b"checked");
                        let binding = &checked.binding;
                        digest.sequence("canonical", binding.canonical(), |hash, part| {
                            hash.value(part.as_bytes())
                        });
                        digest.value(binding.artifact().purl().as_bytes());
                        digest.value(binding.artifact().archive_sha256().as_bytes());
                        digest.value(binding.model_manifest_sha256().as_bytes());
                        if let Some(class) = binding.class_identity() {
                            digest.value(b"class");
                            digest.value(class.portable_symbol().as_bytes());
                        } else if let Some(value) = binding.value_identity() {
                            digest.value(b"value");
                            digest.value(value.portable_symbol().as_bytes());
                        } else {
                            digest.value(b"callable");
                            digest.sequence(
                                "formal_slots",
                                binding.formal_slots(),
                                |hash, slot| {
                                    hash.sequence("names", &slot.names, |hash, name| {
                                        hash.value(name.as_bytes())
                                    });
                                    hash.value(&[
                                        u8::from(slot.receiver),
                                        u8::from(slot.default_range.is_some()),
                                    ]);
                                    hash.value(format!("{:?}", slot.variadic).as_bytes());
                                    hash.value(format!("{:?}", slot.passing_mode).as_bytes());
                                },
                            );
                        }
                        // This portable digest covers checked launch inputs,
                        // ordered roots and inventory. It contains no mount path
                        // or transient acquisition/environment row IDs.
                        let selected = python.and_then(|python| python.python_runtime_store_snapshot()).and_then(|(store, _)| {
                            let cancellation = CancellationToken::default();
                            let limits = brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackLimits::default();
                            crate::analyzer::python::runtime_provider::PythonRuntimeProviderContext {
                                store: &store, publication, workspace_root: analyzer.project().root(), limits: &limits, cancellation: &cancellation,
                            }.checked_environment(checked.provider.environment_id()).ok()
                        });
                        if let Some(selected) = selected {
                            environment =
                                StableDigest::sha256(selected.project_config().value.as_bytes());
                            digest.value(environment.as_bytes());
                        } else {
                            complete = false;
                        }
                    }
                    PythonRuntimeBindingAttempt::Unavailable => digest.value(b"unavailable"),
                    PythonRuntimeBindingAttempt::Cancelled => {
                        digest.value(b"cancelled");
                        complete = false;
                    }
                    PythonRuntimeBindingAttempt::Failed(_) => {
                        // No portable checked provider/environment proof was
                        // produced. Refuse reuse instead of hashing diagnostics
                        // that can contain positions or local filesystem paths.
                        digest.value(b"unproven");
                        complete = false;
                    }
                }
            }
        } else {
            digest.value(b"no-runtime-publication");
        }
    } else {
        digest.value(b"no-model-snapshot");
    }
    let path = brokk_bifrost_core::path_utils::rel_path_string(file);
    EnvironmentBindingFact {
        subject: FactSubject::FileNamedMember {
            rel_path: path.into(),
            owner: module.join(".").into(),
            member: member.into(),
            environment: Some(environment),
        },
        answer: StableDigest::from_array(digest.finish()),
        complete,
    }
}

pub(super) fn environment_binding_answer(
    analyzer: &dyn IAnalyzer,
    rel_path: &str,
    owner: &str,
    member: &str,
    environment: Option<brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest>,
) -> Option<brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest> {
    let file = ProjectFile::new(analyzer.project().root(), rel_path);
    // The question already contains a semantic module identity, not source
    // syntax. Components here are values supplied by the structured binder.
    let module = owner.split('.').map(str::to_owned).collect::<Vec<_>>();
    let fact = environment_binding_fact(analyzer, &file, &module, member);
    let brokk_bifrost_analysis::analyzer::FactSubject::FileNamedMember {
        environment: selected,
        ..
    } = fact.subject
    else {
        unreachable!("binding fact subject");
    };
    (fact.complete && selected == environment).then_some(fact.answer)
}

fn resolve_python_runtime_binding_in_snapshot(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    imported: PythonImportedMember<'_>,
    cancellation: Option<&CancellationToken>,
    resolve_binding: PythonDefiningBindingResolver,
    active_snapshot: &brokk_bifrost_analysis::analyzer::semantic_model::ActiveSemanticModelSnapshot,
) -> PythonRuntimeBindingAttempt {
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

pub(crate) fn python_class_symbol_from_binding(
    analyzer: &dyn IAnalyzer,
    binding: &crate::analyzer::python::runtime_binding::PythonDefiningBinding,
    provider: &crate::analyzer::python::runtime_binding::PythonRuntimeProviderProof,
) -> Result<Arc<brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbol>, String> {
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
    let symbol = modeled.records[0].clone();
    let active_models = active_snapshot.active_models();
    let mut matching_declarations = Vec::new();
    let shards = active_models.shards();
    for shard in shards.iter().filter(|shard| {
        shard.manifest.content_sha256 == binding.model_manifest_sha256()
            && shard
                .matching_evidence
                .iter()
                .any(|evidence| evidence == provider.evidence())
    }) {
        let Some((types, _, _)) = shard.decoded().payload().declaration_facts() else {
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
                    shard.descriptor.shard_id.as_str(),
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
        || !python_model_symbol_matches_provider(&symbol, provider.evidence())
    {
        return Err(format!(
            "native Python class identity does not match the checked model publication: {}",
            symbol.id
        ));
    }
    Ok(symbol.clone())
}

pub(crate) fn python_module_value_symbol_from_binding(
    analyzer: &dyn IAnalyzer,
    binding: &crate::analyzer::python::runtime_binding::PythonDefiningBinding,
    provider: &crate::analyzer::python::runtime_binding::PythonRuntimeProviderProof,
) -> Result<Arc<brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbol>, String> {
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
    let symbol = modeled.records[0].clone();
    let active_models = active_snapshot.active_models();
    let mut matching_declarations = Vec::new();
    let shards = active_models.shards();
    for shard in shards.iter().filter(|shard| {
        shard.manifest.content_sha256 == binding.model_manifest_sha256()
            && shard
                .matching_evidence
                .iter()
                .any(|evidence| evidence == provider.evidence())
    }) {
        let Some((types, members, _)) = shard.decoded().payload().declaration_facts() else {
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
                    shard.descriptor.shard_id.as_str(),
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
        || !python_model_symbol_matches_provider(&symbol, provider.evidence())
    {
        return Err(format!(
            "native Python module-value identity does not match the checked model publication: {}",
            symbol.id
        ));
    }
    Ok(symbol.clone())
}

pub(crate) fn python_model_symbol_matches_provider(
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

/// The complete static callee chain stops at the first non-attribute node.
/// Calls and subscripts in a receiver belong to receiver identity, not imports.
#[doc(hidden)]
pub fn python_imported_callee_shape<'tree>(
    tree: &'tree tree_sitter::Tree,
    focus_start: usize,
    focus_end: usize,
    mut scope_step: impl FnMut() -> bool,
) -> Option<(Vec<tree_sitter::Node<'tree>>, tree_sitter::Node<'tree>)> {
    let callee = brokk_bifrost_core::analyzer::usages::reference_site::smallest_named_node_covering_with_scope(
        tree.root_node(), focus_start, focus_end, &mut scope_step,
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
    let path = brokk_bifrost_python::syntax::python_static_attribute_path_bounded(
        focused_chain,
        &mut scope_step,
    )?;
    if path.last()?.id() != callee.id() {
        return None;
    }
    Some((path, call))
}

/// Native import identity is exercised directly until the point-dispatch
/// adapter owns product refinement. No incumbent resolver calls this service.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod native {
    use super::*;
    use brokk_bifrost_analysis::analyzer::semantic_model::{
        ActiveSemanticModelSnapshot, SemanticModelActivationEvidence, SemanticModelSymbol,
    };
    use brokk_bifrost_analysis::analyzer::store::python_runtime::PythonRuntimeProviderPublication;
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::PythonSelectedImportBoundary;
    use brokk_bifrost_core::analyzer::resolution_facts::PythonNativeImportForm;
    use brokk_bifrost_core::hash::HashMap;

    /// Structured member spelling for a selected import expression. This does
    /// not select a reaching binding; callers supply that authority separately.
    pub fn member_chain(expression: tree_sitter::Node<'_>, source: &str) -> Option<Vec<String>> {
        brokk_bifrost_python::syntax::python_static_attribute_path(expression)?
            .iter()
            .map(|node| node.utf8_text(source.as_bytes()).ok().map(str::to_owned))
            .collect()
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum PythonExternalIdentityKind {
        Callable,
        Class,
        ModuleValue,
    }

    pub struct PythonCheckedExternalIdentity {
        checked: Box<PythonRuntimeBindingAndProvider>,
    }

    impl PythonCheckedExternalIdentity {
        pub fn canonical(&self) -> &[String] {
            self.checked.binding.canonical()
        }
        pub fn artifact(&self) -> &SemanticModelActivationEvidence {
            self.checked.provider.evidence()
        }
        pub fn manifest(&self) -> &str {
            self.checked.binding.model_manifest_sha256()
        }
        pub fn kind(&self) -> PythonExternalIdentityKind {
            if self.checked.binding.class_identity().is_some() {
                PythonExternalIdentityKind::Class
            } else if self.checked.binding.value_identity().is_some() {
                PythonExternalIdentityKind::ModuleValue
            } else {
                PythonExternalIdentityKind::Callable
            }
        }
        pub fn call_proof(&self, parameter_count: u32) -> Option<ExactExternalCallProof> {
            (self.kind() == PythonExternalIdentityKind::Callable).then(|| {
                ExactExternalCallProof::python_imported_call(
                    self.canonical().join("."),
                    parameter_count,
                )
                .with_python_runtime_binding(&self.checked.binding, &self.checked.provider)
                .expect("checked binding and provider agree")
            })
        }
        pub fn model_symbol(
            &self,
            analyzer: &dyn IAnalyzer,
        ) -> Result<Arc<SemanticModelSymbol>, String> {
            python_class_symbol_from_binding(
                analyzer,
                &self.checked.binding,
                &self.checked.provider,
            )
        }
    }

    pub enum PythonExternalAuthorityResult {
        Checked(PythonCheckedExternalIdentity),
        Open(String),
        Ambiguous(String),
        Stale(String),
        Cancelled,
    }

    type PythonExternalAnswers =
        HashMap<Vec<String>, (Arc<PythonExternalAuthorityResult>, EnvironmentBindingFact)>;

    /// One caller file, active model snapshot and publication per request.
    /// Only demanded identities survive verification, not provider inventories.
    pub struct PythonExternalAuthority<'a> {
        analyzer: &'a dyn IAnalyzer,
        file: &'a ProjectFile,
        snapshot: &'a ActiveSemanticModelSnapshot,
        publication: Option<&'a PythonRuntimeProviderPublication>,
        cancellation: &'a CancellationToken,
        answers: brokk_bifrost_analysis::analyzer::WorkspaceAuthorityMemo<
            std::sync::Mutex<PythonExternalAnswers>,
        >,
    }

    impl<'a> PythonExternalAuthority<'a> {
        pub fn new(
            analyzer: &'a dyn IAnalyzer,
            file: &'a ProjectFile,
            snapshot: &'a ActiveSemanticModelSnapshot,
            publication: Option<&'a PythonRuntimeProviderPublication>,
            cancellation: &'a CancellationToken,
        ) -> Self {
            Self {
                analyzer,
                file,
                snapshot,
                publication,
                cancellation,
                answers: brokk_bifrost_analysis::analyzer::WorkspaceAuthorityMemo::new(
                    brokk_bifrost_analysis::analyzer::WorkspaceFactFamily::PythonEnvironmentBinding,
                    std::sync::Mutex::new(HashMap::default()),
                ),
            }
        }

        /// `path` is the full structured attribute chain, including its bound
        /// root. The caller proves which import event reaches that root. This
        /// service does not infer a reaching binding from a matching spelling.
        pub fn check(
            &mut self,
            boundary: &PythonSelectedImportBoundary,
            path: &[String],
        ) -> Arc<PythonExternalAuthorityResult> {
            use PythonExternalAuthorityResult::*;
            if self.cancellation.is_cancelled() {
                return Arc::new(Cancelled);
            }
            if boundary.relative_level != 0 || path.is_empty() {
                return Arc::new(Open("relative or empty import route".into()));
            }
            if boundary.form != PythonNativeImportForm::Star
                && boundary.bound_name.as_ref() != path.first()
            {
                return Arc::new(Open(
                    "the supplied member chain does not start at this binding".into(),
                ));
            }
            let bound_segments = boundary.binding_segment_count as usize;
            assert!(
                bound_segments <= boundary.route.len(),
                "retained binding prefix is inside its route"
            );
            let mut canonical = boundary.route[..bound_segments].to_vec();
            if boundary.form == PythonNativeImportForm::Star {
                canonical.extend_from_slice(path);
            } else {
                canonical.extend_from_slice(&path[1..]);
            }
            self.answers
                .read(
                    &brokk_bifrost_analysis::analyzer::workspace_authority::memo_attribution(
                        self.analyzer,
                    ),
                    |memo| {
                        if let Some(answer) = memo
                            .lock()
                            .expect("external authority lock poisoned")
                            .get(&canonical)
                            .cloned()
                        {
                            return answer;
                        }
                        let answer = Arc::new(self.resolve(&canonical));
                        let (member, module) =
                            canonical.split_last().expect("nonempty canonical import");
                        let mut fact =
                            environment_binding_fact(self.analyzer, self.file, module, member);
                        let active = self.analyzer.active_semantic_model_snapshot();
                        if active
                            .as_ref()
                            .map(|snapshot| snapshot.active_models().active_model_set_hash())
                            != Some(self.snapshot.active_models().active_model_set_hash())
                            || self.snapshot.python_runtime() != self.publication
                            || active
                                .as_ref()
                                .and_then(|snapshot| snapshot.python_runtime())
                                != self.publication
                        {
                            fact.complete = false;
                        }
                        let entry = (answer, fact);
                        memo.lock()
                            .expect("external authority lock poisoned")
                            .insert(canonical, entry.clone());
                        entry
                    },
                    |entry| entry.1.inputs(),
                )
                .0
        }

        fn resolve(&self, canonical: &[String]) -> PythonExternalAuthorityResult {
            use PythonExternalAuthorityResult::*;
            let Some(publication) = self.publication else {
                return Open("active runtime publication is unavailable".into());
            };
            if self.snapshot.python_runtime() != Some(publication) {
                return Stale("active model snapshot and runtime publication disagree".into());
            }
            let Some(python) = resolve_analyzer::<crate::analyzer::PythonAnalyzer>(self.analyzer)
            else {
                return Open("Python analyzer is unavailable".into());
            };
            let Some((store, current)) = python.python_runtime_store_snapshot() else {
                return Open("selected Python snapshot is unavailable".into());
            };
            if current != publication.snapshot {
                return Stale("selected Python snapshot changed".into());
            }
            let mut reason = "no artifact module prefix selects this member".to_owned();
            // Module continuation belongs to the artifact authority. A shorter
            // prefix with multiple remaining attributes is receiver identity,
            // which this import bridge deliberately leaves open.
            for split in (1..canonical.len()).rev() {
                if self.cancellation.is_cancelled() {
                    return Cancelled;
                }
                let module = &canonical[..split];
                let selection = store.with_python_runtime_acquisition(
                    publication.acquisition_id,
                    &publication.snapshot,
                    |tx| {
                        crate::analyzer::python::runtime_provider::python_runtime_provider_lookup(
                            tx,
                            publication.acquisition_id,
                            &publication.snapshot,
                            self.file.rel_path(),
                            &module.join("."),
                        )
                    },
                );
                if self.cancellation.is_cancelled() {
                    return Cancelled;
                }
                let rows = match selection {
                    Ok(rows) => rows,
                    Err(error) => return Stale(error.to_string()),
                };
                if rows.has_scope_ambiguity || rows.candidates.len() > 1 {
                    return Ambiguous(format!("{rows:?}"));
                }
                if !rows.unresolved_scopes.is_empty() || rows.candidates.len() != 1 {
                    reason = format!("{rows:?}");
                    continue;
                }
                if canonical.len() - split != 1 {
                    return Open("attributes after the longest artifact module prefix require receiver identity".into());
                }
                let member = &canonical[split];
                for resolver in [
                    crate::analyzer::python::runtime_binding::resolve_python_defining_binding
                        as PythonDefiningBindingResolver,
                    crate::analyzer::python::runtime_binding::resolve_python_defining_class_binding,
                ] {
                    match resolve_python_runtime_binding_in_snapshot(self.analyzer, self.file,
                        PythonImportedMember { module, member }, Some(self.cancellation), resolver, self.snapshot) {
                        PythonRuntimeBindingAttempt::Resolved(checked) => return Checked(PythonCheckedExternalIdentity { checked }),
                        PythonRuntimeBindingAttempt::Cancelled => return Cancelled,
                        PythonRuntimeBindingAttempt::Unavailable => {},
                        PythonRuntimeBindingAttempt::Failed(PythonRuntimeBindingFailure::ProviderStale(reason)
                            | PythonRuntimeBindingFailure::ProviderVerification(reason)) => return Stale(reason),
                        PythonRuntimeBindingAttempt::Failed(PythonRuntimeBindingFailure::Binding(
                            crate::analyzer::python::runtime_binding::PythonRuntimeBindingError::Ambiguous(reasons))) => return Ambiguous(format!("{reasons:?}")),
                        PythonRuntimeBindingAttempt::Failed(failure) => reason = python_runtime_binding_failure_parts(failure).2,
                    }
                }
                return Open(reason);
            }
            Open(reason)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_analysis::analyzer::Range;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon(
        "#5721: imported-call cancellation published staged identity after runtime resolution stopped"
    )]
    fn cancelled_runtime_binding_withholds_staged_identity() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
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
            let proof = ExactExternalCallProof::python_imported_call("subprocess.run", 1);
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
}
