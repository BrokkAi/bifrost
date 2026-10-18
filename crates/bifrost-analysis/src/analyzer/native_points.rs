//! Shared selected-source definition adapter for native language readers.

use crate::CancellationToken;
use crate::analyzer::Language;
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::languages::BoundedReceiverQuery;
use crate::analyzer::resolution::{
    FactProjectedTypeNodeForm, FactProjectedTypeShape, FactResolutionAnswer, ResolutionCompletion,
    ResolutionIncompleteReason, ResolutionSlotValue,
};
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::resolution::{SelectedResolutionContextSet, SelectedSemanticLocator};
use crate::analyzer::store::WorkspaceSnapshots;
use crate::analyzer::store::resolution_operation::{
    ProjectedNativeMemberContext, SelectedNativeDefinition, SelectedNativeDefinitions,
    SelectedNativeNamedArgument, SelectedNativeReferenceTypes, SelectedNativeReferenceUnits,
    SelectedNativeTypes, SelectedResolutionOperationInput, SelectedResolutionOperationOpenOutcome,
};
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::store::resolution_operation::{
    SelectedResolutionContextMetrics, SelectedResolutionLocated, SelectedResolutionOperation,
    SelectedResolutionOperationOutcome,
};
use crate::analyzer::store::resolution_publication::SelectedResolutionOverlayInputsOutcome;
use crate::analyzer::store::resolution_selection::SelectedResolutionLanguage;
use crate::analyzer::structural::resolution::RejectionReason;
use crate::analyzer::tree_sitter_analyzer::{LanguageAdapter, TreeSitterAnalyzer};
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::usages::get_definition::BoundedResolution;
use crate::analyzer::usages::get_definition::trace::{
    self, CallableApplicabilityRecord, TraceCandidate, TraceCandidateRef,
};
use crate::analyzer::usages::get_definition::{
    DefinitionLookupDiagnostic, DefinitionLookupOutcome, DefinitionLookupStatus,
    PREDECLARED_SYMBOL_REFERENCE_DIAGNOSTIC_KIND, ResolvedReferenceSite,
};
use crate::analyzer::usages::get_type::{
    TypeLookupDiagnostic, TypeLookupOutcome, TypeLookupStatus, TypeLookupType,
};
use crate::analyzer::usages::target_kind::TypeLookupTargetKind;
#[cfg(any(test, feature = "test-support"))]
use crate::path_utils::rel_path_string;
use brokk_bifrost_core::analyzer::resolution_facts::BindingProjectionKind;
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
use brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisWork;
#[cfg(test)]
use std::cell::Cell;

#[cfg(any(test, feature = "test-support"))]
pub(crate) enum NativePointContext {
    Ready {
        context: Box<SelectedResolutionContextSet>,
        selected_import_model: Option<Box<SelectedNativeImportModel>>,
    },
    Unavailable,
    Cancelled,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug)]
pub(crate) struct SelectedNativeImportModel {
    pub(crate) symbol: crate::analyzer::semantic_model::SemanticModelSymbol,
    pub(crate) source_token: crate::analyzer::resolution::SemanticId,
    pub(crate) gap_reason: crate::analyzer::resolution::SemanticId,
}

#[cfg(any(test, feature = "test-support"))]
struct NativePointReference<'a> {
    query: BoundedReceiverQuery<'a>,
    namespace: Option<ResolutionNamespace>,
    call_argument_ordinal: Option<u32>,
}

pub(crate) fn native_point_operation_inputs<A: LanguageAdapter>(
    inner: &TreeSitterAnalyzer<A>,
) -> Result<
    (
        std::sync::Arc<WorkspaceSnapshots>,
        Vec<SelectedResolutionLanguage>,
    ),
    crate::analyzer::store::StoreError,
> {
    let language = inner.adapter().language();
    if matches!(
        language,
        Language::Java | Language::Kotlin | Language::Scala
    ) {
        let storage_languages = ["java", "kotlin", "scala"].map(str::to_owned);
        let snapshots = std::sync::Arc::new(
            inner
                .analyzer_store()
                .workspace_snapshots_for_current_languages(
                    inner.workspace_id(),
                    &storage_languages,
                )?,
        );
        let languages = [
            ("java", Language::Java),
            ("kotlin", Language::Kotlin),
            ("scala", Language::Scala),
        ]
        .into_iter()
        .filter(|(storage_language, _)| snapshots.contains_key(*storage_language))
        .map(|(storage_language, semantic_language)| {
            SelectedResolutionLanguage::new(storage_language, semantic_language)
        })
        .collect();
        Ok((snapshots, languages))
    } else {
        let snapshots = inner.selected_workspace_snapshots();
        let languages = vec![SelectedResolutionLanguage::new(
            language.config_label(),
            language,
        )];
        Ok((snapshots, languages))
    }
}

#[cfg(test)]
thread_local! {
    static NATIVE_POINT_OPERATION_OPEN_COUNT: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_native_point_operation_open_count_for_test() {
    NATIVE_POINT_OPERATION_OPEN_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn native_point_operation_open_count_for_test() -> usize {
    NATIVE_POINT_OPERATION_OPEN_COUNT.with(Cell::get)
}

pub(crate) fn open_native_point_operation<'a, A: LanguageAdapter>(
    inner: &'a TreeSitterAnalyzer<A>,
    cancellation: &CancellationToken,
) -> crate::analyzer::store::Result<SelectedResolutionOperationOpenOutcome<'a, 'a>> {
    #[cfg(test)]
    NATIVE_POINT_OPERATION_OPEN_COUNT.with(|count| count.set(count.get().saturating_add(1)));
    let language = inner.adapter().language();
    let (snapshots, languages) = native_point_operation_inputs(inner)?;
    if !languages
        .iter()
        .any(|selected| selected.semantic_language() == language)
    {
        return Ok(SelectedResolutionOperationOpenOutcome::Unavailable(
            crate::analyzer::store::resolution_selection::SelectedResolutionUnavailable::MissingWorkspaceSnapshot {
                storage_language: language.config_label().to_owned(),
            },
        ));
    }
    let (masks, content_mounts) =
        match inner.selected_resolution_overlay_inputs(snapshots.as_ref(), cancellation)? {
            SelectedResolutionOverlayInputsOutcome::Ready {
                masks,
                content_mounts,
            } => (masks, content_mounts),
            SelectedResolutionOverlayInputsOutcome::Unavailable(reason) => {
                return Ok(SelectedResolutionOperationOpenOutcome::Unavailable(reason));
            }
            SelectedResolutionOverlayInputsOutcome::Stale(reason) => {
                return Ok(SelectedResolutionOperationOpenOutcome::Stale(reason));
            }
            SelectedResolutionOverlayInputsOutcome::Cancelled => {
                return Ok(SelectedResolutionOperationOpenOutcome::Cancelled);
            }
        };
    let input = SelectedResolutionOperationInput::new(
        inner.project(),
        inner.workspace_id(),
        snapshots.as_ref(),
        &languages,
        &masks,
    )
    .with_content_mounts(content_mounts);
    inner
        .analyzer_store()
        .open_selected_resolution_operation(input, cancellation)
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn resolve_native_definition_bounded<A: LanguageAdapter>(
    inner: &TreeSitterAnalyzer<A>,
    query: BoundedReceiverQuery<'_>,
    reference_namespace: Option<ResolutionNamespace>,
    prepare_context: impl FnOnce(
        &SelectedResolutionOperation<'_, '_>,
        &str,
        &CancellationToken,
    ) -> crate::analyzer::store::Result<NativePointContext>,
    after_open: impl FnOnce(),
) -> BoundedResolution<DefinitionLookupOutcome> {
    resolve_native_point_bounded(
        inner,
        NativePointReference {
            query,
            namespace: reference_namespace,
            call_argument_ordinal: None,
        },
        prepare_context,
        after_open,
        |operation, context, locator, cancellation, selected_import_gap| {
            operation.resolve_native_reference_units_bounded_with_import_gap(
                context,
                locator,
                query.budget,
                cancellation,
                &mut SelectedResolutionContextMetrics,
                selected_import_gap,
            )
        },
        |mut answer, work, selected_import_model| match answer.definitions {
            SelectedNativeDefinitions::Cancelled => BoundedResolution::Cancelled { work },
            _ => {
                let absent_member_owners = std::mem::take(&mut answer.absent_member_owners);
                let mut value = adapt_definition_answer_with_import_model(
                    query.site,
                    inner.adapter().language(),
                    answer,
                    selected_import_model,
                );
                let member = query
                    .source
                    .get(query.site.focus_start_byte..query.site.focus_end_byte)
                    .expect("a resolved reference site's focus lies inside its source");
                state_absent_member(&mut value, member, &absent_member_owners);
                BoundedResolution::Complete { value, work }
            }
        },
        unavailable_definition,
    )
}

/// Say that a member is absent where the answer proved it: the lookup searched
/// complete owner inventories and none declares the member.
///
/// JVM member points and Go composite-literal labels report this shared
/// absent-member proof as `no_indexed_definition`. An answer that already
/// carries a diagnostic keeps it. The caller supplies the structurally
/// selected member token; this helper does not interpret source syntax.
fn state_absent_member(
    value: &mut DefinitionLookupOutcome,
    member: &str,
    owners: &[crate::analyzer::CodeUnit],
) {
    if owners.is_empty()
        || value.status != DefinitionLookupStatus::NoDefinition
        || !value.definitions.is_empty()
        || value.lexical_definition.is_some()
        || !value.diagnostics.is_empty()
    {
        return;
    }
    let owners = owners
        .iter()
        .map(|owner| format!("`{}`", owner.fq_name_str()))
        .collect::<Vec<_>>();
    let (owners, inherits) = match owners.as_slice() {
        [owner] => (owner.clone(), "it inherits"),
        _ => (owners.join(", "), "they inherit"),
    };
    value.diagnostics.push(DefinitionLookupDiagnostic {
        claim: None,
        kind: "no_indexed_definition".into(),
        message: format!("`{member}` is not a member of {owners} or anything {inherits}"),
    });
}

#[cfg(any(test, feature = "test-support"))]
fn resolve_native_point_bounded<A: LanguageAdapter, T, O>(
    inner: &TreeSitterAnalyzer<A>,
    reference: NativePointReference<'_>,
    prepare_context: impl FnOnce(
        &SelectedResolutionOperation<'_, '_>,
        &str,
        &CancellationToken,
    ) -> crate::analyzer::store::Result<NativePointContext>,
    after_open: impl FnOnce(),
    resolve: impl FnOnce(
        SelectedResolutionOperation<'_, '_>,
        SelectedResolutionContextSet,
        &SelectedSemanticLocator,
        &CancellationToken,
        Option<(
            crate::analyzer::resolution::SemanticId,
            crate::analyzer::resolution::SemanticId,
        )>,
    ) -> crate::analyzer::store::Result<
        BoundedResolution<SelectedResolutionOperationOutcome<SelectedResolutionLocated<T>>>,
    >,
    adapt: impl FnOnce(
        T,
        ReceiverAnalysisWork,
        Option<crate::analyzer::semantic_model::SemanticModelSymbol>,
    ) -> BoundedResolution<O>,
    unavailable_value: impl Fn(&ResolvedReferenceSite, &str, String) -> O,
) -> BoundedResolution<O> {
    let NativePointReference {
        query,
        namespace,
        call_argument_ordinal,
    } = reference;
    let unavailable = |kind: &str, message: String| BoundedResolution::Complete {
        value: unavailable_value(query.site, kind, message),
        work: ReceiverAnalysisWork::default(),
    };
    let cancellation = query.cancellation.cloned().unwrap_or_default();
    let cancelled = || BoundedResolution::Cancelled {
        work: ReceiverAnalysisWork::default(),
    };
    if cancellation.is_cancelled() {
        return cancelled();
    }
    if !inner.workspace_declaration_identities_authoritative() {
        return unavailable(
            "native_identity_authority_unavailable",
            "selected native declaration identities are not authoritative".into(),
        );
    }
    let attempt = || -> Result<_, crate::analyzer::store::StoreError> {
        let language = inner.adapter().language();
        let (snapshots, languages) = native_point_operation_inputs(inner)?;
        if !languages
            .iter()
            .any(|selected| selected.semantic_language() == language)
        {
            return Ok(unavailable(
                "native_unavailable",
                format!(
                    "selected {} workspace snapshot is unavailable",
                    language.config_label()
                ),
            ));
        }
        let (masks, content_mounts) =
            match inner.selected_resolution_overlay_inputs(&snapshots, &cancellation)? {
                SelectedResolutionOverlayInputsOutcome::Ready {
                    masks,
                    content_mounts,
                } => (masks, content_mounts),
                SelectedResolutionOverlayInputsOutcome::Unavailable(reason) => {
                    return Ok(unavailable("native_unavailable", format!("{reason:?}")));
                }
                SelectedResolutionOverlayInputsOutcome::Stale(reason) => {
                    return Ok(unavailable("native_stale", format!("{reason:?}")));
                }
                SelectedResolutionOverlayInputsOutcome::Cancelled => return Ok(cancelled()),
            };
        let input = SelectedResolutionOperationInput::new(
            inner.project(),
            inner.workspace_id(),
            &snapshots,
            &languages,
            &masks,
        )
        .with_content_mounts(content_mounts)
        .with_analyzer(query.analyzer);
        let operation = match inner
            .analyzer_store()
            .open_selected_resolution_operation(input, &cancellation)?
        {
            SelectedResolutionOperationOpenOutcome::Ready(operation) => operation,
            SelectedResolutionOperationOpenOutcome::Unavailable(reason) => {
                return Ok(unavailable("native_unavailable", format!("{reason:?}")));
            }
            SelectedResolutionOperationOpenOutcome::Stale(reason) => {
                return Ok(unavailable("native_stale", format!("{reason:?}")));
            }
            SelectedResolutionOperationOpenOutcome::Cancelled => return Ok(cancelled()),
        };
        after_open();
        if cancellation.is_cancelled() {
            return Ok(cancelled());
        }
        if !inner.source_matches_selected_native_content(query.file, query.source) {
            return Ok(unavailable(
                "native_source_mismatch",
                "supplied native reference text differs from the admitted selected source".into(),
            ));
        }
        let path = rel_path_string(query.file);
        let (context, selected_import_model) =
            match prepare_context(&operation, &path, &cancellation)? {
                NativePointContext::Ready {
                    context,
                    selected_import_model,
                } => (*context, selected_import_model),
                NativePointContext::Unavailable => {
                    return Ok(unavailable(
                        "native_context_unavailable",
                        "selected native import context is unavailable".into(),
                    ));
                }
                NativePointContext::Cancelled => return Ok(cancelled()),
            };
        let selected_import_gap = selected_import_model
            .as_ref()
            .map(|model| (model.source_token, model.gap_reason));
        let selected_import_symbol = selected_import_model.map(|model| model.symbol);
        let locator = match namespace {
            Some(namespace) => SelectedSemanticLocator::for_reference_range_in_namespace(
                language.config_label(),
                path,
                query.site.focus_start_byte,
                query.site.focus_end_byte,
                namespace,
            ),
            None => SelectedSemanticLocator::for_reference_range(
                language.config_label(),
                path,
                query.site.focus_start_byte,
                query.site.focus_end_byte,
            ),
        };
        let locator = match call_argument_ordinal {
            Some(ordinal) => locator.with_call_argument_ordinal(ordinal),
            None => locator,
        };
        let result = resolve(
            *operation,
            context,
            &locator,
            &cancellation,
            selected_import_gap,
        )?;
        Ok(match result {
            BoundedResolution::Exceeded { limit, work } => {
                BoundedResolution::Exceeded { limit, work }
            }
            BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
            BoundedResolution::Complete { value, work } => {
                let outcome = match value {
                    SelectedResolutionOperationOutcome::Native(
                        SelectedResolutionLocated::Found(answer),
                    ) => return Ok(adapt(answer, work, selected_import_symbol)),
                    SelectedResolutionOperationOutcome::Native(
                        SelectedResolutionLocated::Missing,
                    ) => unavailable_value(
                        query.site,
                        "native_reference_unavailable",
                        "the selected producer has no reference at this source range".into(),
                    ),
                    SelectedResolutionOperationOutcome::Unavailable(reason) => {
                        unavailable_value(query.site, "native_unavailable", format!("{reason:?}"))
                    }
                    SelectedResolutionOperationOutcome::Stale(reason) => {
                        unavailable_value(query.site, "native_stale", format!("{reason:?}"))
                    }
                    SelectedResolutionOperationOutcome::Cancelled(_) => {
                        return Ok(BoundedResolution::Cancelled { work });
                    }
                };
                BoundedResolution::Complete {
                    value: outcome,
                    work,
                }
            }
        })
    };
    match attempt() {
        Ok(result) => result,
        Err(error) => unavailable("native_store_error", error.to_string()),
    }
}

pub(crate) fn unavailable_definition(
    site: &ResolvedReferenceSite,
    kind: &str,
    message: String,
) -> DefinitionLookupOutcome {
    DefinitionLookupOutcome {
        modeled_definitions: Vec::new(),
        status: DefinitionLookupStatus::Unavailable,
        reference: Some(site.clone()),
        definitions: Vec::new(),
        lexical_definition: None,
        diagnostics: vec![DefinitionLookupDiagnostic {
            claim: None,
            kind: kind.into(),
            message,
        }],
    }
}

pub(crate) fn adapt_definition_answer(
    site: &ResolvedReferenceSite,
    language: Language,
    answer: SelectedNativeReferenceUnits,
) -> DefinitionLookupOutcome {
    adapt_definition_answer_with_import_model(site, language, answer, None)
}

fn adapt_definition_answer_with_import_model(
    site: &ResolvedReferenceSite,
    language: Language,
    answer: SelectedNativeReferenceUnits,
    selected_import_model: Option<crate::analyzer::semantic_model::SemanticModelSymbol>,
) -> DefinitionLookupOutcome {
    let trace_start = trace::native_projection_start();
    let member_contexts = answer.member_contexts;
    let declared_visibilities = answer.declared_visibilities;
    let trace_provenance = answer.trace_provenance;
    let absent_literal_member = language == Language::Go
        && answer.answer.site_metadata().is_some_and(|metadata| {
            metadata.site_kind()
                == brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind::CompositeLiteralKeyReference
        });
    if answer.predeclared_go_symbol {
        return DefinitionLookupOutcome {
            modeled_definitions: Vec::new(),
            status: DefinitionLookupStatus::NoDefinition,
            reference: Some(site.clone()),
            definitions: Vec::new(),
            lexical_definition: None,
            diagnostics: vec![DefinitionLookupDiagnostic {
                claim: None,
                kind: PREDECLARED_SYMBOL_REFERENCE_DIAGNOSTIC_KIND.into(),
                message: format!("`{}` is a predeclared Go symbol", site.text),
            }],
        };
    }
    if let Some(named_argument) = answer.named_argument {
        let (status, definitions, lexical_definition, diagnostics) = match named_argument {
            SelectedNativeNamedArgument::Resolved(SelectedNativeDefinition::Unit(unit)) => (
                DefinitionLookupStatus::Resolved,
                vec![unit],
                None,
                Vec::new(),
            ),
            SelectedNativeNamedArgument::Resolved(SelectedNativeDefinition::Lexical(lexical)) => (
                DefinitionLookupStatus::Resolved,
                Vec::new(),
                Some(lexical),
                Vec::new(),
            ),
            SelectedNativeNamedArgument::Resolved(SelectedNativeDefinition::Intrinsic {
                ..
            }) => {
                unreachable!("a named argument selects a parameter, not an intrinsic type")
            }
            SelectedNativeNamedArgument::Incomplete(message) => (
                DefinitionLookupStatus::Incomplete,
                Vec::new(),
                None,
                vec![DefinitionLookupDiagnostic {
                    claim: None,
                    kind: "named_argument_resolution_incomplete".into(),
                    message,
                }],
            ),
        };
        let outcome = DefinitionLookupOutcome {
            modeled_definitions: Vec::new(),
            status,
            reference: Some(site.clone()),
            definitions,
            lexical_definition,
            diagnostics,
        };
        record_native_member_contexts(language, member_contexts);
        trace::record_selected_units(&outcome);
        trace::record_native_declared_visibilities(&declared_visibilities);
        return outcome;
    }
    let SelectedNativeDefinitions::Ready(units) = answer.definitions else {
        return unavailable_definition(
            site,
            "native_definition_projection_unavailable",
            "selected native definitions have no supported source-unit projection".into(),
        );
    };
    let mut definitions_by_identity = std::collections::HashMap::new();
    let mut lexical_definitions = Vec::new();
    let mut intrinsic_definitions = Vec::new();
    for (identity, definition) in units {
        match definition {
            SelectedNativeDefinition::Unit(unit) => {
                definitions_by_identity.insert(identity, unit);
            }
            SelectedNativeDefinition::Lexical(lexical) => lexical_definitions.push(lexical),
            SelectedNativeDefinition::Intrinsic { canonical_name, .. } => {
                intrinsic_definitions.push(canonical_name);
            }
        }
    }
    if !intrinsic_definitions.is_empty()
        && !crate::analyzer::resolution::projects_intrinsic_definitions(language)
    {
        return unavailable_definition(
            site,
            "native_definition_projection_unavailable",
            "selected native definitions have no supported source-unit projection".into(),
        );
    }
    for (identity, unit) in answer.callable_applicability_candidates {
        definitions_by_identity.insert(identity, unit);
    }
    record_native_callable_applicability(
        language,
        &answer.answer,
        &definitions_by_identity,
        &member_contexts,
    );
    let mut definitions = answer
        .answer
        .binding()
        .targets()
        .iter()
        .filter_map(|identity| definitions_by_identity.get(identity).cloned())
        .collect::<Vec<_>>();
    definitions.sort_unstable();
    definitions.dedup();
    let completion = answer.answer.binding().completion();
    let mut incomplete_hierarchy_names = answer
        .named_reasons
        .iter()
        .filter(|(kind, _)| *kind == "UnsupportedHierarchyTraversal")
        .map(|(_, evidence)| evidence.clone())
        .collect::<Vec<_>>();
    incomplete_hierarchy_names.sort_unstable();
    incomplete_hierarchy_names.dedup();
    let mut diagnostics = answer
        .named_reasons
        .into_iter()
        .map(|(kind, message)| DefinitionLookupDiagnostic {
            claim: None,
            kind: kind.into(),
            message,
        })
        .collect::<Vec<_>>();
    if !intrinsic_definitions.is_empty() {
        diagnostics.push(DefinitionLookupDiagnostic {
            claim: None,
            kind: "intrinsic_type_reference".into(),
            message: format!(
                "intrinsic type bindings have no source location: {intrinsic_definitions:?}"
            ),
        });
    }
    if lexical_definitions.len() > 1 {
        diagnostics.push(DefinitionLookupDiagnostic {
            claim: None,
            kind: "ambiguous_lexical_definition".into(),
            message: format!(
                "selected native binding has multiple lexical declarations: {lexical_definitions:?}"
            ),
        });
    }
    let lexical_definition =
        (lexical_definitions.len() == 1).then(|| lexical_definitions.remove(0));
    let target_count = answer.answer.binding().targets().len();
    let go_inconsistent_precedence = language == Language::Go
        && matches!(completion, ResolutionCompletion::Incomplete(reasons)
            if reasons.iter().any(|reason| matches!(reason,
                ResolutionIncompleteReason::InconsistentPrecedence(_))));
    let scala_type_ambiguity =
        language == Language::Scala && native_scala_type_ambiguity(&answer.answer);
    let only_go_inconsistent_precedence = go_inconsistent_precedence
        && matches!(completion, ResolutionCompletion::Incomplete(reasons)
            if reasons.iter().all(|reason| matches!(reason,
                ResolutionIncompleteReason::InconsistentPrecedence(_))));
    let is_incomplete =
        !matches!(completion, ResolutionCompletion::Complete) && !only_go_inconsistent_precedence;
    let unproven_term_family = is_incomplete
        && crate::analyzer::languages::language_support(language)
            .is_some_and(|support| support.call_target_lookup_routes().is_some())
        && answer
            .answer
            .callable_candidate_applicability()
            .iter()
            .any(|candidate| candidate.verdict() == ApplicabilityVerdict::Unknown);
    let ambiguous = (target_count > 1 || go_inconsistent_precedence) && !unproven_term_family;
    if ambiguous {
        diagnostics.push(DefinitionLookupDiagnostic {
            claim: None,
            kind: if scala_type_ambiguity {
                "ambiguous_scala_type"
            } else {
                "ambiguous_definition"
            }
            .into(),
            message: format!(
                "selected native binding has ambiguous alternatives: {:?}",
                answer.answer.binding().targets()
            ),
        });
    }
    if is_incomplete {
        let message = if language == Language::Scala && !incomplete_hierarchy_names.is_empty() {
            format!(
                "selected native binding is incomplete because hierarchy traversal is unavailable for unindexed supertype(s): {incomplete_hierarchy_names:?}"
            )
        } else {
            format!("selected native binding is incomplete: {completion:?}")
        };
        diagnostics.push(DefinitionLookupDiagnostic {
            claim: None,
            kind: "incomplete_binding".into(),
            message,
        });
    }
    let external_family = answer.external_members.first().filter(|first| {
        answer.external_members.len() == target_count
            && lexical_definition.is_none()
            && definitions.is_empty()
            && answer.external_members.iter().all(|member| {
                member.identity.owner == first.identity.owner
                    && member.member_name == first.member_name
            })
    });
    if let Some(first) = external_family {
        diagnostics.push(DefinitionLookupDiagnostic {
            claim: Some(
                crate::analyzer::usages::get_definition::UnindexedClaim::external_boundary(
                    format!("{}.{}", first.identity.owner.owner_fqn, first.member_name),
                    crate::analyzer::usages::get_definition::ClaimSubjectRole::Member,
                ),
            ),
            kind: "native_external_member_inventory".into(),
            message: format!(
                "indexed external member rows {:?}; static={}",
                answer
                    .external_members
                    .iter()
                    .map(|member| &member.identity)
                    .collect::<Vec<_>>(),
                first.is_static
            ),
        });
    }
    let unindexed_family = match &answer.direct_target {
        Some(
            crate::analyzer::store::resolution_operation::NativeExternalMemberTarget::Unindexed {
                provider_path,
                provider_package_id,
                member_name,
            },
        ) if target_count == 0 && definitions.is_empty() && lexical_definition.is_none() => {
            Some((provider_path, provider_package_id, member_name))
        }
        _ => None,
    };
    if let Some((path, package_id, member)) = unindexed_family {
        diagnostics.push(DefinitionLookupDiagnostic {
            claim: Some(
                crate::analyzer::usages::get_definition::UnindexedClaim::external_boundary(
                    format!("{path}.{member}"),
                    crate::analyzer::usages::get_definition::ClaimSubjectRole::Member,
                ),
            ),
            kind: "native_unindexed_external_member".into(),
            message: format!(
                "external member {member:?} of unindexed provider {path:?}, package_id={package_id:?}; value type unknown"
            ),
        });
    }
    let status = if unindexed_family.is_some()
        || (external_family.is_some() && !ambiguous && !is_incomplete)
    {
        DefinitionLookupStatus::UnresolvableImportBoundary
    } else if ambiguous {
        // Exact Go selector ties and multiple semantic targets establish
        // ambiguity even when another open inventory limits completeness.
        DefinitionLookupStatus::Ambiguous
    } else if is_incomplete {
        DefinitionLookupStatus::Incomplete
    } else {
        match target_count {
            0 => DefinitionLookupStatus::NoDefinition,
            1 if !intrinsic_definitions.is_empty() => DefinitionLookupStatus::NoDefinition,
            1 => DefinitionLookupStatus::Resolved,
            _ => unreachable!("multiple native targets are ambiguous"),
        }
    };
    if status == DefinitionLookupStatus::Resolved
        && definitions.is_empty()
        && let Some(local) = &lexical_definition
        && crate::analyzer::languages::language_support(language)
            .is_some_and(|support| support.native_local_binding_diagnostic())
    {
        diagnostics.push(DefinitionLookupDiagnostic {
            claim: None,
            kind: crate::analyzer::usages::get_definition::LOCAL_VARIABLE_REFERENCE_DIAGNOSTIC_KIND
                .into(),
            message: format!("selected native binding identifies a local declaration: {local:?}"),
        });
    }
    if status == DefinitionLookupStatus::NoDefinition
        && let Some(kind) = crate::analyzer::languages::language_support(language)
            .and_then(|support| support.call_applicability_adapter())
            .and_then(|adapter| adapter.no_applicable_call_diagnostic())
    {
        let rejected = answer
            .answer
            .callable_candidate_applicability()
            .iter()
            .filter(|candidate| candidate.verdict() == ApplicabilityVerdict::Inapplicable)
            .collect::<Vec<_>>();
        if !rejected.is_empty() {
            diagnostics.push(DefinitionLookupDiagnostic {
                kind: kind.into(),
                message: format!("indexed callable alternatives rejected this call: {rejected:?}"),
                claim: None,
            });
        }
    }
    if language == Language::Java
        && status == DefinitionLookupStatus::NoDefinition
        && answer
            .answer
            .site_metadata()
            .is_some_and(|metadata| metadata.namespace() == ResolutionNamespace::Constructor)
    {
        let rejected_constructors = answer
            .answer
            .callable_candidate_applicability()
            .iter()
            .filter(|candidate| candidate.verdict() == ApplicabilityVerdict::Inapplicable)
            .map(|candidate| {
                (
                    definitions_by_identity
                        .get(&candidate.target())
                        .map(|unit| unit.fq_name()),
                    candidate,
                )
            })
            .collect::<Vec<_>>();
        if !rejected_constructors.is_empty() {
            diagnostics.push(DefinitionLookupDiagnostic {
                kind: "no_applicable_java_constructor".into(),
                message: format!(
                    "indexed Java constructors rejected this call: {rejected_constructors:?}"
                ),
                claim: None,
            });
        }
    }
    let use_import_model = (target_count == 0 && lexical_definition.is_none())
        .then_some(selected_import_model)
        .flatten();
    let modeled_definitions = use_import_model.into_iter().collect::<Vec<_>>();
    let status =
        if status == DefinitionLookupStatus::NoDefinition && !modeled_definitions.is_empty() {
            DefinitionLookupStatus::Resolved
        } else {
            status
        };
    let mut outcome = DefinitionLookupOutcome {
        modeled_definitions,
        status,
        reference: Some({
            let mut reference = site.clone();
            if let [canonical_name] = intrinsic_definitions.as_slice() {
                reference.text.clone_from(canonical_name);
            } else if let Some((path, _, member)) = unindexed_family {
                reference.text = format!("{path}.{member}");
            } else if let Some(member) = external_family {
                reference.text =
                    format!("{}.{}", member.identity.owner.owner_fqn, member.member_name);
            }
            reference
        }),
        definitions,
        lexical_definition,
        diagnostics,
    };
    if absent_literal_member {
        state_absent_member(&mut outcome, &site.text, &answer.absent_member_owners);
    }
    record_native_member_contexts(language, member_contexts);
    trace::record_selected_units(&outcome);
    trace::record_native_provenance(
        &outcome,
        trace_start,
        trace_provenance.rows,
        trace_provenance.rejection_coverage,
    );
    trace::record_native_declared_visibilities(&declared_visibilities);
    outcome
}

fn native_scala_type_ambiguity(answer: &FactResolutionAnswer) -> bool {
    answer.projections().iter().any(|projection| {
        if !matches!(
            projection.kind(),
            BindingProjectionKind::TargetTypeIdentity
                | BindingProjectionKind::TargetTypeOrDeclaredValueType
        ) {
            return false;
        }
        answer
            .projected_frontiers()
            .iter()
            .find(|frontier| frontier.slot() == projection.output_slot())
            .is_some_and(|frontier| {
                let values = frontier.possible_values();
                !values.is_empty()
                    && values.iter().all(|value| {
                        matches!(value, ResolutionSlotValue::TypeObject(ty) if ty.indirection() == 0)
                    })
            })
    })
}

fn record_native_member_contexts(language: Language, contexts: Vec<ProjectedNativeMemberContext>) {
    if !trace::recording() {
        return;
    }
    let mut selected = Vec::new();
    let mut minimum_tier = None;
    for context in contexts {
        if !context.selected && context.rejection.is_none() {
            continue;
        }
        let outcome = context.rejection.map_or(
            crate::analyzer::structural::CandidateOutcome::Selected,
            crate::analyzer::structural::CandidateOutcome::Rejected,
        );
        let Some((tier, enrichment)) = native_member_attribution(language, &context, outcome)
        else {
            continue;
        };
        if let Some(reason) = context.rejection {
            trace::record(
                TraceCandidate::rejected(
                    TraceCandidateRef::Unit(context.target),
                    Some(tier),
                    reason,
                )
                .with_member(enrichment),
            );
            continue;
        }
        minimum_tier = Some(minimum_tier.map_or(
            tier,
            |found: crate::analyzer::structural::PrecedenceTier| found.min(tier),
        ));
        selected.push((context.target.fq_name(), enrichment));
    }
    if let Some(tier) = minimum_tier {
        trace::stage_tier(
            tier,
            selected.iter().map(|(name, _)| name.clone()).collect(),
        );
    }
    trace::stage_member_context(selected);
}

fn native_member_attribution(
    language: Language,
    context: &ProjectedNativeMemberContext,
    outcome: crate::analyzer::structural::CandidateOutcome,
) -> Option<(
    crate::analyzer::structural::PrecedenceTier,
    trace::MemberEnrichment,
)> {
    assert!(
        !context.owner_path.is_empty(),
        "member route has a receiver owner"
    );
    let owner = context
        .owner_path
        .last()
        .expect("non-empty member route has an owner");
    let depth = context.owner_path.len() - 1;
    let crate::analyzer::languages::NativeMemberAttribution {
        dispatch_tier,
        relation,
        precedence_tier,
    } = crate::analyzer::languages::language_support(language)?
        .native_member_attribution(context, outcome)?;
    let enrichment = trace::MemberEnrichment {
        owner: owner.clone(),
        hierarchy_depth: depth,
        dispatch_tier,
        applicability: context.applicability,
        route: context
            .owner_path
            .windows(2)
            .enumerate()
            .map(|(hop, pair)| trace::HierarchyHopRecord {
                hop,
                from: pair[0].clone(),
                to: pair[1].clone(),
                relation,
            })
            .collect(),
    };
    Some((precedence_tier, enrichment))
}

fn record_native_callable_applicability(
    language: Language,
    answer: &crate::analyzer::resolution::FactResolutionAnswer,
    definitions: &std::collections::HashMap<
        crate::analyzer::resolution::SemanticId,
        crate::analyzer::CodeUnit,
    >,
    member_contexts: &[ProjectedNativeMemberContext],
) {
    if !trace::recording() {
        return;
    }
    let mut selected_context = Vec::new();
    for candidate in answer.callable_candidate_applicability() {
        let Some(unit) = definitions.get(&candidate.target()) else {
            continue;
        };
        let record = CallableApplicabilityRecord {
            verdict: candidate.verdict(),
            reason: candidate.reason(),
        };
        if answer.binding().targets().binary_search(&candidate.target()).is_ok() {
            selected_context.push((unit.fq_name(), record));
        } else if candidate.verdict()
            == brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict::Inapplicable
        {
            let member = member_contexts.iter()
                .find(|context| context.target_identity == candidate.target())
                .and_then(|context| native_member_attribution(language, context,
                    crate::analyzer::structural::CandidateOutcome::Rejected(
                        RejectionReason::CallableApplicabilityDeferred)));
            let mut rejected = TraceCandidate::rejected(
                TraceCandidateRef::Unit(unit.clone()),
                member.as_ref().map(|(tier, _)| *tier),
                RejectionReason::CallableApplicabilityDeferred,
            )
            .with_callable(record);
            if let Some((_, enrichment)) = member {
                rejected = rejected.with_member(enrichment);
            }
            trace::record(rejected);
        }
    }
    trace::stage_callable_context(selected_context);
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn resolve_native_type_bounded<A: LanguageAdapter>(
    inner: &TreeSitterAnalyzer<A>,
    query: BoundedReceiverQuery<'_>,
    prepare_context: impl FnOnce(
        &SelectedResolutionOperation<'_, '_>,
        &str,
        &CancellationToken,
    ) -> crate::analyzer::store::Result<NativePointContext>,
    after_open: impl FnOnce(),
) -> BoundedResolution<TypeLookupOutcome> {
    // A plain type lookup consumes the rendered result only. Keep static-term
    // materialization in expression/conversion queries so other language point
    // queries do not pay for an unused recursive transport value.
    resolve_native_point_bounded(
        inner,
        NativePointReference {
            query,
            namespace: None,
            call_argument_ordinal: None,
        },
        prepare_context,
        after_open,
        |operation, context, locator, cancellation, _| {
            operation.resolve_native_reference_types_bounded(
                context,
                locator,
                query.budget,
                cancellation,
                &mut SelectedResolutionContextMetrics,
            )
        },
        |answer, work, _| match answer.value_types {
            SelectedNativeTypes::Cancelled => BoundedResolution::Cancelled { work },
            _ => BoundedResolution::Complete {
                value: adapt_type_answer(query.site, inner.adapter().language(), answer),
                work,
            },
        },
        unavailable_type,
    )
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) struct NativeExpressionValueTypeLookup {
    pub(crate) static_type: Option<crate::analyzer::semantic_model::TypeRef>,
    pub(crate) value_types: TypeLookupOutcome,
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn resolve_native_expression_value_type_bounded<A: LanguageAdapter>(
    inner: &TreeSitterAnalyzer<A>,
    query: BoundedReceiverQuery<'_>,
    prepare_context: impl FnOnce(
        &SelectedResolutionOperation<'_, '_>,
        &str,
        &CancellationToken,
    ) -> crate::analyzer::store::Result<NativePointContext>,
    after_open: impl FnOnce(),
) -> BoundedResolution<NativeExpressionValueTypeLookup> {
    resolve_native_expression_type_projection_bounded(
        inner,
        NativePointReference {
            query,
            namespace: None,
            call_argument_ordinal: None,
        },
        prepare_context,
        after_open,
    )
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn resolve_native_call_argument_type_bounded<A: LanguageAdapter>(
    inner: &TreeSitterAnalyzer<A>,
    query: BoundedReceiverQuery<'_>,
    argument_ordinal: u32,
    prepare_context: impl FnOnce(
        &SelectedResolutionOperation<'_, '_>,
        &str,
        &CancellationToken,
    ) -> crate::analyzer::store::Result<NativePointContext>,
    after_open: impl FnOnce(),
) -> BoundedResolution<NativeExpressionValueTypeLookup> {
    resolve_native_expression_type_projection_bounded(
        inner,
        NativePointReference {
            query,
            namespace: None,
            call_argument_ordinal: Some(argument_ordinal),
        },
        prepare_context,
        after_open,
    )
}

#[cfg(any(test, feature = "test-support"))]
fn resolve_native_expression_type_projection_bounded<A: LanguageAdapter>(
    inner: &TreeSitterAnalyzer<A>,
    reference: NativePointReference<'_>,
    prepare_context: impl FnOnce(
        &SelectedResolutionOperation<'_, '_>,
        &str,
        &CancellationToken,
    ) -> crate::analyzer::store::Result<NativePointContext>,
    after_open: impl FnOnce(),
) -> BoundedResolution<NativeExpressionValueTypeLookup> {
    let query = reference.query;
    resolve_native_point_bounded(
        inner,
        reference,
        prepare_context,
        after_open,
        |operation, context, locator, cancellation, _selected_import_gap| {
            operation.resolve_native_reference_types_bounded(
                context,
                locator,
                query.budget,
                cancellation,
                &mut SelectedResolutionContextMetrics,
            )
        },
        |answer, work, _selected_import_model| match answer.value_types {
            SelectedNativeTypes::Cancelled => BoundedResolution::Cancelled { work },
            _ => {
                let static_type = project_native_static_type(&answer);
                BoundedResolution::Complete {
                    value: NativeExpressionValueTypeLookup {
                        value_types: adapt_type_answer(
                            query.site,
                            inner.adapter().language(),
                            answer,
                        ),
                        static_type,
                    },
                    work,
                }
            }
        },
        |site, kind, message| NativeExpressionValueTypeLookup {
            value_types: unavailable_type(site, kind, message),
            static_type: None,
        },
    )
}

/// Keep the selected structured type term; display strings cannot distinguish
/// array/application structure or a source declaration from an external name.
#[cfg(any(test, feature = "test-support"))]
fn project_native_static_type(
    answer: &SelectedNativeReferenceTypes,
) -> Option<crate::analyzer::semantic_model::TypeRef> {
    use crate::analyzer::resolution::SemanticId;
    use crate::analyzer::semantic_model::TypeRef;
    let SelectedNativeTypes::Ready {
        nominal,
        intrinsic,
        external_owners,
    } = &answer.value_types
    else {
        return None;
    };
    let resolve_identity = |identity: SemanticId| {
        if let Some(descriptor) = intrinsic.iter().find(|item| item.identity() == identity) {
            if descriptor.kind()
                == brokk_bifrost_core::analyzer::resolution_facts::IntrinsicTypeKind::Structural
            {
                return None;
            }
            let name = if descriptor.spelling() == "null" {
                "<null>"
            } else {
                descriptor.spelling()
            };
            return Some(TypeRef::named(name));
        }
        if let Some((_, SelectedNativeDefinition::Unit(unit))) =
            nominal.iter().find(|(id, _)| *id == identity)
        {
            return Some(TypeRef::Declared {
                id: unit.declaration_id().as_str().to_owned(),
                arguments: Vec::new(),
                nullable: false,
            });
        }
        external_owners
            .iter()
            .find(|(id, _)| *id == identity)
            .map(|(_, owner)| TypeRef::named(owner.owner_fqn.as_ref()))
    };
    let selected_kind =
        crate::analyzer::usages::get_type::projection_target_kind(answer.answer.projections()).1;
    let slots = answer
        .query_result_slot
        .or_else(|| answer.answer.observed_type_identity())
        .into_iter()
        .chain(
            answer
                .answer
                .projections()
                .iter()
                .filter(|projection| {
                    answer.query_result_slot.is_none() && Some(projection.kind()) == selected_kind
                })
                .map(|projection| projection.output_slot()),
        )
        .collect::<std::collections::BTreeSet<_>>();
    let mut selected = None;
    for slot in slots {
        let frontier = answer
            .answer
            .projected_frontiers()
            .iter()
            .find(|frontier| frontier.slot() == slot)?;
        if frontier.completion() != &ResolutionCompletion::Complete {
            return None;
        }
        let ty = if let Some(shape) = answer
            .answer
            .projected_type_shapes()
            .iter()
            .find(|shape| shape.output_slot() == slot)
        {
            if !shape.supported() || shape.completion() != &ResolutionCompletion::Complete {
                return None;
            }
            let nodes = shape
                .nodes()
                .iter()
                .map(|node| (node.slot(), node))
                .collect::<std::collections::HashMap<_, _>>();
            let mut terms = std::collections::HashMap::<SemanticId, TypeRef>::new();
            let mut active = std::collections::HashSet::new();
            // TypeRef transport uses recursively owned terms. Match the model
            // domain's validated depth before constructing or cloning one;
            // malformed deep source graphs still use an iterative traversal.
            let max_depth = crate::analyzer::semantic_model::DecodeLimits::default().max_depth;
            let mut pending = vec![(shape.root_slot(), false, 1_usize)];
            while let Some((slot, finish, depth)) = pending.pop() {
                if depth > max_depth {
                    return None;
                }
                let node = nodes.get(&slot)?;
                if node.indirection() != 0 {
                    return None;
                }
                if !finish {
                    if terms.contains_key(&slot) {
                        continue;
                    }
                    if !active.insert(slot) {
                        return None;
                    }
                    pending.push((slot, true, depth));
                    match node.form() {
                        FactProjectedTypeNodeForm::Alias(child) => {
                            pending.push((*child, false, depth))
                        }
                        FactProjectedTypeNodeForm::Array(child) => {
                            pending.push((*child, false, depth + 1))
                        }
                        FactProjectedTypeNodeForm::Applied(arguments) => pending.extend(
                            arguments
                                .iter()
                                .rev()
                                .map(|child| (*child, false, depth + 1)),
                        ),
                        FactProjectedTypeNodeForm::Leaf => {}
                        _ => return None,
                    }
                    continue;
                }
                let ty = match node.form() {
                    FactProjectedTypeNodeForm::Alias(child) => terms.get(child)?.clone(),
                    FactProjectedTypeNodeForm::Array(child) => TypeRef::Array {
                        element: Box::new(terms.get(child)?.clone()),
                    },
                    FactProjectedTypeNodeForm::Leaf => resolve_identity(node.identity())?,
                    FactProjectedTypeNodeForm::Applied(arguments) => {
                        let mut head = resolve_identity(node.identity())?;
                        let actuals = arguments
                            .iter()
                            .map(|child| terms.get(child).cloned())
                            .collect::<Option<Vec<_>>>()?;
                        match &mut head {
                            TypeRef::Named { arguments, .. }
                            | TypeRef::Declared { arguments, .. } => *arguments = actuals,
                            _ => return None,
                        }
                        head
                    }
                    _ => return None,
                };
                terms.insert(slot, ty);
                active.remove(&slot);
            }
            terms.remove(&shape.root_slot())?
        } else {
            let [value] = frontier.possible_values() else {
                return None;
            };
            if value.ty().indirection() != 0 {
                return None;
            }
            resolve_identity(value.ty().identity())?
        };
        if selected.as_ref().is_some_and(|previous| previous != &ty) {
            return None;
        }
        selected = Some(ty);
    }
    selected
}

pub(crate) fn unavailable_type(
    site: &ResolvedReferenceSite,
    kind: &str,
    message: String,
) -> TypeLookupOutcome {
    TypeLookupOutcome {
        status: TypeLookupStatus::Unavailable,
        reference: Some(site.clone()),
        types: Vec::new(),
        target_kind: TypeLookupTargetKind::ValueExpression,
        diagnostics: vec![TypeLookupDiagnostic {
            kind: kind.into(),
            message,
        }],
    }
}

pub(crate) fn adapt_type_answer(
    site: &ResolvedReferenceSite,
    language: Language,
    answer: SelectedNativeReferenceTypes,
) -> TypeLookupOutcome {
    adapt_type_answer_with_spelling(site, language, answer, |spelling, value, diagnostics| {
        let depth = value.ty().indirection();
        if depth == 0 {
            Some(spelling.to_owned())
        } else if language == Language::Go {
            Some(format!("{}{spelling}", "*".repeat(depth as usize)))
        } else {
            diagnostics.push(TypeLookupDiagnostic {
                kind: "unsupported_type_indirection".into(),
                message: format!(
                    "selected {language:?} type {:?} has unsupported indirection {depth}",
                    value.ty().identity()
                ),
            });
            None
        }
    })
}

fn adapt_type_answer_with_spelling(
    site: &ResolvedReferenceSite,
    language: Language,
    answer: SelectedNativeReferenceTypes,
    mut render_spelling: impl FnMut(
        &str,
        ResolutionSlotValue,
        &mut Vec<TypeLookupDiagnostic>,
    ) -> Option<String>,
) -> TypeLookupOutcome {
    let SelectedNativeTypes::Ready {
        nominal,
        intrinsic,
        external_owners,
    } = answer.value_types
    else {
        return unavailable_type(
            site,
            "native_type_projection_unavailable",
            "selected native type identities have no supported source projection".into(),
        );
    };
    let mut diagnostics = answer
        .named_reasons
        .into_iter()
        .map(|(kind, message)| TypeLookupDiagnostic {
            kind: kind.into(),
            message,
        })
        .collect::<Vec<_>>();
    if let Some(
        crate::analyzer::store::resolution_operation::NativeExternalMemberTarget::Unindexed {
            provider_path,
            provider_package_id,
            member_name,
        },
    ) = answer.direct_target
    {
        diagnostics.push(TypeLookupDiagnostic { kind: "native_unindexed_external_member".into(), message: format!("external member {member_name:?} of unindexed provider {provider_path:?}, package_id={provider_package_id:?}; value type unknown") });
    }
    let resolution = answer.answer;
    let observed = resolution
        .observed_type_identity()
        .filter(|_| answer.query_result_slot.is_none());
    let (mut target_kind, selected, kinds) = if answer.query_result_slot.is_some() {
        (TypeLookupTargetKind::ValueExpression, None, Vec::new())
    } else if observed.is_some() {
        (
            TypeLookupTargetKind::TypeReference,
            Some(BindingProjectionKind::TargetTypeIdentity),
            vec![BindingProjectionKind::TargetTypeIdentity],
        )
    } else {
        crate::analyzer::usages::get_type::projection_target_kind(resolution.projections())
    };
    if language == Language::Java
        && observed.is_none()
        && selected == Some(BindingProjectionKind::TargetTypeOrDeclaredValueType)
    {
        let slots = resolution
            .projections()
            .iter()
            .filter(|projection| {
                projection.kind() == BindingProjectionKind::TargetTypeOrDeclaredValueType
            })
            .map(|projection| projection.output_slot())
            .collect::<Vec<_>>();
        let frontiers = slots
            .iter()
            .filter_map(|slot| {
                resolution
                    .projected_frontiers()
                    .iter()
                    .find(|frontier| frontier.slot() == *slot)
            })
            .collect::<Vec<_>>();
        if !frontiers.is_empty()
            && frontiers.iter().all(|frontier| {
                !frontier.possible_values().is_empty()
                    && frontier
                        .possible_values()
                        .iter()
                        .all(|value| matches!(value, ResolutionSlotValue::TypeObject(_)))
            })
        {
            target_kind = TypeLookupTargetKind::TypeReference;
        }
    }
    let shapes = resolution
        .projected_type_shapes()
        .iter()
        .map(|shape| (shape.output_slot(), shape))
        .collect::<std::collections::HashMap<_, _>>();
    let mut complete = resolution.binding().completion() == &ResolutionCompletion::Complete;
    for frontier in resolution.projected_frontiers() {
        if let Some(shape) = shapes.get(&frontier.slot()) {
            complete &= shape.supported() && shape.completion() == &ResolutionCompletion::Complete;
        } else {
            complete &= frontier.completion() == &ResolutionCompletion::Complete;
        }
    }
    if !complete {
        diagnostics.push(TypeLookupDiagnostic {
            kind: "incomplete_native_type".into(),
            message: format!(
                "selected native type evidence is incomplete after supported substitutions: {:?}",
                resolution.completion()
            ),
        });
    }
    let slots = resolution
        .projections()
        .iter()
        .filter(|projection| Some(projection.kind()) == selected)
        .map(|projection| projection.output_slot())
        .chain(observed)
        .chain(answer.query_result_slot);
    let mut examined = false;
    let mut canonical = std::collections::BTreeMap::new();
    for slot in slots {
        let Some(frontier) = resolution
            .projected_frontiers()
            .iter()
            .find(|frontier| frontier.slot() == slot)
        else {
            complete = false;
            diagnostics.push(TypeLookupDiagnostic {
                kind: "missing_typed_frontier".into(),
                message: format!("selected native type slot {slot:?} has no frontier"),
            });
            continue;
        };
        examined = true;
        if let Some(shape) = shapes.get(&slot) {
            if shape.supported()
                && let Some((fqn, definitions)) =
                    render_projected_type_shape(shape, &nominal, &intrinsic, &external_owners)
            {
                canonical.entry((slot, 0)).or_insert(TypeLookupType {
                    fqn,
                    definitions,
                    semantic_model_id: None,
                });
            } else {
                complete = false;
                diagnostics.push(TypeLookupDiagnostic {
                    kind: "unsupported_substituted_type_shape".into(),
                    message: format!("selected type shape is not supported: {shape:?}"),
                });
            }
            continue;
        }
        complete &= frontier.completion() == &ResolutionCompletion::Complete;
        for value in frontier.possible_values() {
            let identity = value.ty().identity();
            let depth = value.ty().indirection();
            let projected = if let Some(descriptor) = intrinsic
                .iter()
                .find(|descriptor| descriptor.identity() == identity)
            {
                Some((descriptor.spelling().to_owned(), Vec::new()))
            } else {
                nominal
                    .iter()
                    .find(|(candidate, _)| *candidate == identity)
                    .and_then(|(_, definition)| match definition {
                        SelectedNativeDefinition::Unit(unit) => {
                            Some((unit.fq_name().to_string(), vec![unit.clone()]))
                        }
                        SelectedNativeDefinition::Intrinsic { canonical_name, .. } => {
                            Some((canonical_name.clone(), Vec::new()))
                        }
                        SelectedNativeDefinition::Lexical(_) => None,
                    })
                    .or_else(|| {
                        external_owners
                            .iter()
                            .find(|(candidate, _)| *candidate == identity)
                            .map(|(_, owner)| (owner.owner_fqn.to_string(), Vec::new()))
                    })
            };
            let Some((spelling, definitions)) = projected else {
                complete = false;
                diagnostics.push(TypeLookupDiagnostic {
                    kind: "missing_nominal_type_definition".into(),
                    message: format!(
                        "selected native type {identity:?} has no nominal source unit"
                    ),
                });
                continue;
            };
            let Some(fqn) = render_spelling(&spelling, *value, &mut diagnostics) else {
                complete = false;
                continue;
            };
            canonical
                .entry((identity, depth))
                .or_insert(TypeLookupType {
                    fqn,
                    definitions,
                    semantic_model_id: None,
                });
        }
    }
    if !examined {
        complete = false;
        diagnostics.push(TypeLookupDiagnostic {
            kind: "unprojected_type_frontier".into(),
            message: "selected native reference has no examined type frontier".into(),
        });
    }
    if kinds.len() > 1 {
        diagnostics.push(TypeLookupDiagnostic {
            kind: "ambiguous_type_projection_kind".into(),
            message: format!(
                "selected native reference has projection kinds {kinds:?}; selected {selected:?}"
            ),
        });
    }
    let status = if !complete {
        TypeLookupStatus::Incomplete
    } else {
        match canonical.len() {
            0 => {
                diagnostics.push(TypeLookupDiagnostic {
                    kind: "native_no_typed_projection".into(),
                    message: "the selected native type frontier was complete and named no type"
                        .into(),
                });
                TypeLookupStatus::NoType
            }
            1 => TypeLookupStatus::Resolved,
            _ => {
                diagnostics.push(TypeLookupDiagnostic {
                    kind: "ambiguous_type".into(),
                    message: format!(
                        "selected native type identities: {:?}",
                        canonical.keys().collect::<Vec<_>>()
                    ),
                });
                TypeLookupStatus::Ambiguous
            }
        }
    };
    TypeLookupOutcome {
        status,
        reference: Some(site.clone()),
        target_kind,
        types: canonical.into_values().collect(),
        diagnostics,
    }
}

fn render_projected_type_shape(
    shape: &FactProjectedTypeShape,
    nominal: &[(
        crate::analyzer::resolution::SemanticId,
        SelectedNativeDefinition,
    )],
    intrinsic: &[crate::analyzer::resolution::FactIntrinsicTypeDescriptor],
    external_owners: &[(
        crate::analyzer::resolution::SemanticId,
        crate::analyzer::resolution::ExternalOwnerIdentity,
    )],
) -> Option<(String, Vec<crate::analyzer::CodeUnit>)> {
    use crate::analyzer::resolution::SemanticId;

    let nodes = shape
        .nodes()
        .iter()
        .map(|node| (node.slot(), node))
        .collect::<std::collections::HashMap<SemanticId, _>>();
    let mut rendered = std::collections::HashMap::<SemanticId, String>::new();
    let mut definitions = std::collections::BTreeMap::<String, crate::analyzer::CodeUnit>::new();
    let mut active = std::collections::HashSet::new();
    let mut pending = vec![(shape.root_slot(), false)];
    while let Some((slot, finish)) = pending.pop() {
        let node = nodes.get(&slot)?;
        if !finish {
            if rendered.contains_key(&slot) {
                continue;
            }
            if !active.insert(slot) {
                return None;
            }
            pending.push((slot, true));
            match node.form() {
                FactProjectedTypeNodeForm::Alias(child)
                | FactProjectedTypeNodeForm::Slice(child)
                | FactProjectedTypeNodeForm::Array(child) => pending.push((*child, false)),
                FactProjectedTypeNodeForm::Map { key, value } => {
                    pending.push((*value, false));
                    pending.push((*key, false));
                }
                FactProjectedTypeNodeForm::Applied(arguments) => {
                    pending.extend(arguments.iter().rev().map(|argument| (*argument, false)));
                }
                FactProjectedTypeNodeForm::Leaf | FactProjectedTypeNodeForm::Unsupported => {}
            }
            continue;
        }

        let mut resolve_identity = |identity: SemanticId| -> Option<String> {
            if let Some(descriptor) = intrinsic.iter().find(|item| item.identity() == identity) {
                return Some(descriptor.spelling().to_owned());
            }
            if let Some((_, owner)) = external_owners
                .iter()
                .find(|(candidate, _)| *candidate == identity)
            {
                return Some(owner.owner_fqn.to_string());
            }
            match nominal
                .iter()
                .find(|(candidate, _)| *candidate == identity)
                .map(|(_, definition)| definition)?
            {
                SelectedNativeDefinition::Unit(unit) => {
                    let fqn = unit.fq_name().to_string();
                    definitions
                        .entry(fqn.clone())
                        .or_insert_with(|| unit.clone());
                    Some(fqn)
                }
                SelectedNativeDefinition::Intrinsic { canonical_name, .. } => {
                    Some(canonical_name.clone())
                }
                SelectedNativeDefinition::Lexical(_) => None,
            }
        };
        let indirection = usize::try_from(node.indirection()).ok()?;
        let spelling = match node.form() {
            FactProjectedTypeNodeForm::Alias(child) => rendered.get(child)?.clone(),
            FactProjectedTypeNodeForm::Leaf => resolve_identity(node.identity())?,
            FactProjectedTypeNodeForm::Slice(element) => {
                format!("[]{}", rendered.get(element)?)
            }
            FactProjectedTypeNodeForm::Array(element) => format!("{}[]", rendered.get(element)?),
            FactProjectedTypeNodeForm::Unsupported => return None,
            FactProjectedTypeNodeForm::Map { key, value } => {
                format!("map[{}]{}", rendered.get(key)?, rendered.get(value)?)
            }
            FactProjectedTypeNodeForm::Applied(arguments) => {
                let base = resolve_identity(node.identity())?;
                let arguments = arguments
                    .iter()
                    .map(|argument| rendered.get(argument).cloned())
                    .collect::<Option<Vec<_>>>()?;
                format!("{base}[{}]", arguments.join(", "))
            }
        };
        let spelling = if indirection == 0 {
            spelling
        } else {
            format!("{}{spelling}", "*".repeat(indirection))
        };
        rendered.insert(slot, spelling);
        active.remove(&slot);
    }
    Some((
        rendered.remove(&shape.root_slot())?,
        definitions.into_values().collect(),
    ))
}

/// Caller-visible native type evidence for the private differential harness.
/// The module is absent unless tests or the existing test-support feature are enabled.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug)]
pub struct NativeTypeProbe {
    pub status: &'static str,
    pub types: Vec<TypeLookupType>,
    pub diagnostics: Vec<(String, String)>,
    pub reference: Option<ResolvedReferenceSite>,
    pub target_kind: TypeLookupTargetKind,
}

/// Owned evidence for the unordered value union of an exact local binder.
/// `observed_frontier_complete` describes the selected assignment-value slot,
/// independently of the binding answer's combined completion.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug)]
pub struct NativeAssignmentValueProbe {
    pub status: &'static str,
    pub types: Vec<TypeLookupType>,
    pub diagnostics: Vec<(String, String)>,
    pub reference: Option<ResolvedReferenceSite>,
    pub observed_frontier_complete: bool,
}

#[cfg(any(test, feature = "test-support"))]
fn adapt_assignment_value_probe(
    site: &ResolvedReferenceSite,
    language: Language,
    answer: crate::analyzer::store::resolution_operation::SelectedNativeAssignmentValue,
) -> NativeAssignmentValueProbe {
    let observed_frontier_complete = answer.observed_frontier_complete;
    let mut outcome = if language == Language::Rust {
        adapt_type_answer_with_spelling(
            site,
            language,
            answer.types,
            |spelling, value, diagnostics| {
                let ty = value.ty();
                // The Rust renderer spells total depth as references. Do not turn
                // raw-pointer or mixed indirection into reference evidence.
                if ty.indirection() != ty.reference_indirection() {
                    diagnostics.push(TypeLookupDiagnostic {
                        kind: "unsupported_type_indirection".into(),
                        message: format!(
                            "unsupported Rust assignment-value indirection for {spelling:?}: {value:?}"
                        ),
                    });
                    return None;
                }
                Some(crate::analyzer::rust::native_points::render_type_spelling(
                    spelling,
                    value,
                    diagnostics,
                ))
            },
        )
    } else {
        adapt_type_answer(site, language, answer.types)
    };
    // The owned type spelling cannot express the Rust renderer's mutable
    // reference qualifier. This limits display, not the observed frontier.
    if outcome
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == "unsupported_mut_reference_qualifier")
    {
        outcome.status = TypeLookupStatus::Incomplete;
    }
    NativeAssignmentValueProbe {
        status: outcome.status.as_str(),
        types: outcome.types,
        diagnostics: outcome
            .diagnostics
            .into_iter()
            .map(|diagnostic| (diagnostic.kind, diagnostic.message))
            .collect(),
        reference: outcome.reference,
        observed_frontier_complete,
    }
}

#[cfg(any(test, feature = "test-support"))]
fn unavailable_assignment_value_probe(
    site: &ResolvedReferenceSite,
    kind: &str,
    message: String,
) -> NativeAssignmentValueProbe {
    NativeAssignmentValueProbe {
        status: TypeLookupStatus::Incomplete.as_str(),
        types: Vec::new(),
        diagnostics: vec![(kind.to_owned(), message)],
        reference: Some(site.clone()),
        observed_frontier_complete: false,
    }
}

#[cfg(any(test, feature = "test-support"))]
fn map_bounded<T, U>(
    value: BoundedResolution<T>,
    map: impl FnOnce(T) -> U,
) -> BoundedResolution<U> {
    match value {
        BoundedResolution::Complete { value, work } => BoundedResolution::Complete {
            value: map(value),
            work,
        },
        BoundedResolution::Exceeded { limit, work } => BoundedResolution::Exceeded { limit, work },
        BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
    }
}

#[cfg(any(test, feature = "test-support"))]
fn probe_jvm_assignment_value<A: LanguageAdapter>(
    inner: &TreeSitterAnalyzer<A>,
    query: BoundedReceiverQuery<'_>,
) -> BoundedResolution<NativeAssignmentValueProbe> {
    let language = inner.adapter().language();
    resolve_native_point_bounded(
        inner,
        NativePointReference {
            query,
            namespace: None,
            call_argument_ordinal: None,
        },
        |operation, path, cancellation| {
            use crate::analyzer::store::resolution_operation::JvmImportContext;
            Ok(
                match operation.jvm_import_context(language, path, cancellation)? {
                    JvmImportContext::Ready { context, .. } => NativePointContext::Ready {
                        context,
                        selected_import_model: None,
                    },
                    JvmImportContext::Unavailable => NativePointContext::Unavailable,
                    JvmImportContext::Cancelled => NativePointContext::Cancelled,
                },
            )
        },
        || {},
        |mut operation, context, locator, cancellation, _| {
            operation.resolve_native_assignment_value_bounded(
                context,
                locator,
                query.budget,
                cancellation,
            )
        },
        |answer, work, _| BoundedResolution::Complete {
            value: adapt_assignment_value_probe(query.site, language, answer),
            work,
        },
        unavailable_assignment_value_probe,
    )
}

/// Probe a local reference's persisted ObservedValue through selected readers
/// and the production typed evaluator. The location must select the reference
/// token itself, for example `current` in `current.summary()`.
#[cfg(any(test, feature = "test-support"))]
pub fn probe_native_assignment_value(
    analyzer: &dyn crate::analyzer::IAnalyzer,
    request: &brokk_bifrost_core::analyzer::usages::reference_site::SourceLocationRequest,
    source: &str,
    budget: brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget,
    cancellation: &CancellationToken,
) -> Result<BoundedResolution<NativeAssignmentValueProbe>, String> {
    use crate::analyzer::resolve_analyzer;
    let language = crate::analyzer::common::language_for_file(&request.file);
    if cancellation.is_cancelled() {
        return Ok(BoundedResolution::Cancelled {
            work: ReceiverAnalysisWork::default(),
        });
    }
    if !analyzer.indexed_source_matches(&request.file, source) {
        return Err(
            "assignment-value probe source differs from the selected analyzer source".into(),
        );
    }
    let tree = crate::analyzer::usages::get_definition::parse_tree_for_language(
        &request.file,
        language,
        source,
    )
    .ok_or_else(|| format!("assignment-value probe could not parse {:?}", request.file))?;
    let site = brokk_bifrost_core::analyzer::usages::reference_site::resolve_reference_site(
        request,
        source,
        Some(tree.root_node()),
    )?;
    let query = BoundedReceiverQuery {
        analyzer,
        file: &request.file,
        source,
        tree: Some(&tree),
        site: &site,
        budget,
        cancellation: Some(cancellation),
    };
    Ok(match language {
        Language::Java => probe_jvm_assignment_value(
            resolve_analyzer::<crate::analyzer::JavaAnalyzer>(analyzer)
                .ok_or("assignment-value probe has no Java analyzer")?
                .inner(),
            query,
        ),
        Language::Kotlin => probe_jvm_assignment_value(
            resolve_analyzer::<crate::analyzer::kotlin::KotlinAnalyzer>(analyzer)
                .ok_or("assignment-value probe has no Kotlin analyzer")?
                .tree_sitter_analyzer(),
            query,
        ),
        Language::Scala => probe_jvm_assignment_value(
            resolve_analyzer::<crate::analyzer::scala::ScalaAnalyzer>(analyzer)
                .ok_or("assignment-value probe has no Scala analyzer")?
                .tree_sitter_analyzer(),
            query,
        ),
        Language::Rust => {
            let factory =
                crate::analyzer::rust::native_points::RustDefinitionOperationFactory::new(
                    analyzer,
                    cancellation,
                )
                .ok_or("assignment-value probe has no authoritative Rust operation factory")?;
            let mut operation = match factory
                .open(cancellation)
                .map_err(|error| error.to_string())?
            {
                SelectedResolutionOperationOpenOutcome::Ready(operation) => operation,
                SelectedResolutionOperationOpenOutcome::Cancelled => {
                    return Ok(BoundedResolution::Cancelled {
                        work: ReceiverAnalysisWork::default(),
                    });
                }
                SelectedResolutionOperationOpenOutcome::Unavailable(reason) => {
                    return Err(format!(
                        "assignment-value operation unavailable: {reason:?}"
                    ));
                }
                SelectedResolutionOperationOpenOutcome::Stale(reason) => {
                    return Err(format!("assignment-value operation stale: {reason:?}"));
                }
            };
            let locator = SelectedSemanticLocator::for_reference_range_in_namespace(
                "rust",
                rel_path_string(&request.file),
                site.focus_start_byte,
                site.focus_end_byte,
                ResolutionNamespace::Value,
            );
            let answer = operation
                .resolve_rust_assignment_value_bounded(
                    request.file.rel_path(),
                    &locator,
                    budget,
                    cancellation,
                )
                .map_err(|error| error.to_string())?;
            map_bounded(answer, |outcome| match outcome {
                SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                    answer,
                )) => adapt_assignment_value_probe(&site, language, answer),
                SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Missing) => {
                    unavailable_assignment_value_probe(
                        &site,
                        "native_reference_unavailable",
                        "assignment-value probe has no exact selected reference".into(),
                    )
                }
                SelectedResolutionOperationOutcome::Unavailable(reason) => {
                    unavailable_assignment_value_probe(
                        &site,
                        "native_unavailable",
                        format!("{reason:?}"),
                    )
                }
                SelectedResolutionOperationOutcome::Stale(reason) => {
                    unavailable_assignment_value_probe(&site, "native_stale", format!("{reason:?}"))
                }
                SelectedResolutionOperationOutcome::Cancelled(completion) => {
                    unavailable_assignment_value_probe(
                        &site,
                        "native_cancelled",
                        format!("{completion:?}"),
                    )
                }
            })
        }
        Language::Go => {
            use crate::analyzer::go::native_points::{
                GoNativePointRequest, GoNativePointRequestOpen,
            };
            let go = resolve_analyzer::<crate::analyzer::go::GoAnalyzer>(analyzer)
                .ok_or("assignment-value probe has no Go analyzer")?;
            let mut go_request = match GoNativePointRequest::open(go, None, cancellation)
                .map_err(|error| error.to_string())?
            {
                GoNativePointRequestOpen::Ready(request) => request,
                GoNativePointRequestOpen::Unavailable { kind, message } => {
                    return Ok(BoundedResolution::Complete {
                        value: unavailable_assignment_value_probe(&site, kind, message),
                        work: ReceiverAnalysisWork::default(),
                    });
                }
                GoNativePointRequestOpen::Cancelled => {
                    return Ok(BoundedResolution::Cancelled {
                        work: ReceiverAnalysisWork::default(),
                    });
                }
            };
            let locator = SelectedSemanticLocator::for_reference_range(
                "go",
                rel_path_string(&request.file),
                site.focus_start_byte,
                site.focus_end_byte,
            );
            let Some(answer) = go_request
                .resolve_assignment_value_bounded(
                    &rel_path_string(&request.file),
                    &locator,
                    budget,
                    cancellation,
                )
                .map_err(|error| error.to_string())?
            else {
                return Ok(BoundedResolution::Complete {
                    value: unavailable_assignment_value_probe(
                        &site,
                        "native_context_unavailable",
                        "selected Go file import/demand context is unavailable".into(),
                    ),
                    work: ReceiverAnalysisWork::default(),
                });
            };
            map_bounded(answer, |outcome| match outcome {
                SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                    answer,
                )) => adapt_assignment_value_probe(&site, language, answer),
                SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Missing) => {
                    unavailable_assignment_value_probe(
                        &site,
                        "native_reference_unavailable",
                        "assignment-value probe has no exact selected reference".into(),
                    )
                }
                SelectedResolutionOperationOutcome::Unavailable(reason) => {
                    unavailable_assignment_value_probe(
                        &site,
                        "native_unavailable",
                        format!("{reason:?}"),
                    )
                }
                SelectedResolutionOperationOutcome::Stale(reason) => {
                    unavailable_assignment_value_probe(&site, "native_stale", format!("{reason:?}"))
                }
                SelectedResolutionOperationOutcome::Cancelled(completion) => {
                    unavailable_assignment_value_probe(
                        &site,
                        "native_cancelled",
                        format!("{completion:?}"),
                    )
                }
            })
        }
        _ => {
            return Err(format!(
                "assignment-value probe does not admit {language:?}"
            ));
        }
    })
}

#[cfg(any(test, feature = "test-support"))]
fn with_native_probe<T>(
    analyzer: &dyn crate::analyzer::IAnalyzer,
    request: &brokk_bifrost_core::analyzer::usages::reference_site::SourceLocationRequest,
    source: &str,
    budget: brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget,
    cancellation: &CancellationToken,
    resolve: impl FnOnce(
        &'static dyn crate::analyzer::languages::StructuralReceiverResolver,
        BoundedReceiverQuery<'_>,
    ) -> T,
) -> Result<T, String> {
    let language = crate::analyzer::common::language_for_file(&request.file);
    let support = crate::analyzer::languages::language_support(language);
    let Some(points) = support
        .and_then(|support| support.native_rollout_points())
        .or_else(|| {
            (language == crate::analyzer::Language::Go)
                .then(|| support.and_then(|support| support.structural_receiver()))
                .flatten()
        })
    else {
        return Err(format!("native rollout probe does not admit {language:?}"));
    };
    let tree = crate::analyzer::usages::get_definition::parse_tree_for_language(
        &request.file,
        language,
        source,
    )
    .ok_or_else(|| format!("native rollout probe could not parse {:?}", request.file))?;
    let site = brokk_bifrost_core::analyzer::usages::reference_site::resolve_reference_site(
        request,
        source,
        Some(tree.root_node()),
    )?;
    Ok(resolve(
        points,
        BoundedReceiverQuery {
            analyzer,
            file: &request.file,
            source,
            tree: Some(&tree),
            site: &site,
            budget,
            cancellation: Some(cancellation),
        },
    ))
}

/// Probe the selected native definition reader.
#[cfg(any(test, feature = "test-support"))]
pub fn probe_native_definition(
    analyzer: &dyn crate::analyzer::IAnalyzer,
    request: &brokk_bifrost_core::analyzer::usages::reference_site::SourceLocationRequest,
    source: &str,
    budget: brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget,
    cancellation: &CancellationToken,
) -> Result<BoundedResolution<DefinitionLookupOutcome>, String> {
    with_native_probe(
        analyzer,
        request,
        source,
        budget,
        cancellation,
        |points, query| points.resolve_definition_bounded(query),
    )
}

/// Probe the selected native definition reader with a definition trace
/// installed, and return the candidate rows it recorded.
#[cfg(any(test, feature = "test-support"))]
pub fn probe_native_definition_trace(
    analyzer: &dyn crate::analyzer::IAnalyzer,
    request: &brokk_bifrost_core::analyzer::usages::reference_site::SourceLocationRequest,
    source: &str,
    budget: brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget,
    cancellation: &CancellationToken,
) -> Result<
    (
        BoundedResolution<DefinitionLookupOutcome>,
        Vec<TraceCandidate>,
    ),
    String,
> {
    let session = trace::TraceSession::install();
    let resolution = probe_native_definition(analyzer, request, source, budget, cancellation)?;
    Ok((resolution, session.take_request()))
}

/// Probe native type identity and completion through the same selected operation.
#[cfg(any(test, feature = "test-support"))]
pub fn probe_native_type(
    analyzer: &dyn crate::analyzer::IAnalyzer,
    request: &brokk_bifrost_core::analyzer::usages::reference_site::SourceLocationRequest,
    source: &str,
    budget: brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget,
    cancellation: &CancellationToken,
) -> Result<BoundedResolution<NativeTypeProbe>, String> {
    let result = with_native_probe(
        analyzer,
        request,
        source,
        budget,
        cancellation,
        |points, query| points.resolve_type_bounded(query),
    )?;
    Ok(match result {
        BoundedResolution::Complete { value, work } => BoundedResolution::Complete {
            value: NativeTypeProbe {
                status: value.status.as_str(),
                types: value.types,
                diagnostics: value
                    .diagnostics
                    .into_iter()
                    .map(|reason| (reason.kind, reason.message))
                    .collect(),
                reference: value.reference,
                target_kind: value.target_kind,
            },
            work,
        },
        BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
        BoundedResolution::Exceeded { limit, work } => BoundedResolution::Exceeded { limit, work },
    })
}

#[cfg(test)]
mod assignment_value_tests {
    use super::*;
    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#5015: Scala term-family binding made constructor write values incomplete")]
    fn scala_constructor_write_keeps_its_observed_frontier_complete() {
        let source = r#"package app
class Base
class Child extends Base
object Use {
  def value(): Base = {
    var current: Base = new Base
    current = new Child
    current
  }
}
"#;
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Scala)
            .file("Use.scala", source)
            .build();
        let workspace = crate::WorkspaceAnalyzer::build_persisted(
            fixture.project_dyn(),
            crate::AnalyzerConfig::default(),
        )
        .expect("build constructor-write workspace");
        let request = brokk_bifrost_core::analyzer::usages::reference_site::SourceLocationRequest {
            file: fixture.file("Use.scala"),
            line: Some(8),
            column: Some(5),
            start_byte: None,
            end_byte: None,
        };
        let answer = probe_native_assignment_value(
            workspace.analyzer(),
            &request,
            source,
            ReceiverAnalysisBudget::default(),
            &CancellationToken::new(),
        )
        .expect("query constructed write value");
        let BoundedResolution::Complete { value, .. } = answer else {
            panic!("constructor-write query must finish: {answer:?}");
        };
        let mut types = value
            .types
            .iter()
            .map(|ty| ty.fqn.as_str())
            .collect::<Vec<_>>();
        types.sort_unstable();
        assert_eq!(types, ["app.Base", "app.Child"], "{value:?}");
        assert!(value.observed_frontier_complete, "{value:?}");
    }
}
