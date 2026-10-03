//! Shared selected-source definition adapter for the pre-cutover Java/Go readers.

use crate::CancellationToken;
use crate::analyzer::Language;
use crate::analyzer::languages::BoundedReceiverQuery;
use crate::analyzer::resolution::{
    ResolutionCompletion, SelectedResolutionContextSet, SelectedSemanticLocator,
};
use crate::analyzer::store::resolution_operation::{
    SelectedNativeDefinition, SelectedNativeDefinitions, SelectedNativeReferenceTypes,
    SelectedNativeReferenceUnits, SelectedNativeTypes, SelectedResolutionContextMetrics,
    SelectedResolutionLocated, SelectedResolutionOperation, SelectedResolutionOperationInput,
    SelectedResolutionOperationOpenOutcome, SelectedResolutionOperationOutcome,
};
use crate::analyzer::store::resolution_publication::SelectedResolutionOverlayInputsOutcome;
use crate::analyzer::store::resolution_selection::SelectedResolutionLanguage;
use crate::analyzer::tree_sitter_analyzer::{LanguageAdapter, TreeSitterAnalyzer};
use crate::analyzer::usages::get_definition::{
    BoundedResolution, DefinitionLookupDiagnostic, DefinitionLookupOutcome, DefinitionLookupStatus,
    ResolvedReferenceSite,
};
use crate::analyzer::usages::get_type::{
    TypeLookupDiagnostic, TypeLookupOutcome, TypeLookupStatus, TypeLookupType,
};
use crate::analyzer::usages::target_kind::TypeLookupTargetKind;
use crate::path_utils::rel_path_string;
use brokk_bifrost_core::analyzer::resolution_facts::BindingProjectionKind;
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisWork;

pub(crate) enum NativePointContext {
    Ready(SelectedResolutionContextSet),
    Unavailable,
    Cancelled,
}

pub(crate) fn resolve_native_definition_bounded<A: LanguageAdapter>(
    inner: &TreeSitterAnalyzer<A>,
    query: BoundedReceiverQuery<'_>,
    prepare_context: impl FnOnce(
        &SelectedResolutionOperation<'_, '_>,
        &str,
        &CancellationToken,
    ) -> crate::analyzer::store::Result<NativePointContext>,
    after_open: impl FnOnce(),
) -> BoundedResolution<DefinitionLookupOutcome> {
    resolve_native_point_bounded(
        inner,
        query,
        prepare_context,
        after_open,
        |operation, context, locator, cancellation| {
            operation.resolve_native_reference_units_bounded(
                context,
                locator,
                query.budget,
                cancellation,
                &mut SelectedResolutionContextMetrics,
            )
        },
        |answer, work| match answer.definitions {
            SelectedNativeDefinitions::Cancelled => BoundedResolution::Cancelled { work },
            _ => BoundedResolution::Complete {
                value: adapt_definition_answer(query.site, answer),
                work,
            },
        },
        unavailable_definition,
    )
}

fn resolve_native_point_bounded<A: LanguageAdapter, T, O>(
    inner: &TreeSitterAnalyzer<A>,
    query: BoundedReceiverQuery<'_>,
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
    ) -> crate::analyzer::store::Result<
        BoundedResolution<SelectedResolutionOperationOutcome<SelectedResolutionLocated<T>>>,
    >,
    adapt: impl FnOnce(T, ReceiverAnalysisWork) -> BoundedResolution<O>,
    unavailable_value: impl Fn(&ResolvedReferenceSite, &str, String) -> O,
) -> BoundedResolution<O> {
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
        let snapshots = inner.selected_workspace_snapshots();
        let language = inner.adapter().language();
        let languages = [SelectedResolutionLanguage::new(
            language.config_label(),
            language,
        )];
        let (masks, content_mounts) =
            match inner.selected_resolution_overlay_inputs(snapshots.as_ref(), &cancellation)? {
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
            snapshots.as_ref(),
            &languages,
            &masks,
        )
        .with_content_mounts(content_mounts);
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
        let context = match prepare_context(&operation, &path, &cancellation)? {
            NativePointContext::Ready(context) => context,
            NativePointContext::Unavailable => {
                return Ok(unavailable(
                    "native_context_unavailable",
                    "selected native import context is unavailable".into(),
                ));
            }
            NativePointContext::Cancelled => return Ok(cancelled()),
        };
        let locator = SelectedSemanticLocator::for_reference_range(
            language.config_label(),
            path,
            query.site.focus_start_byte,
            query.site.focus_end_byte,
        );
        let result = resolve(*operation, context, &locator, &cancellation)?;
        Ok(match result {
            BoundedResolution::Exceeded { limit, work } => {
                BoundedResolution::Exceeded { limit, work }
            }
            BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
            BoundedResolution::Complete { value, work } => {
                let outcome = match value {
                    SelectedResolutionOperationOutcome::Native(
                        SelectedResolutionLocated::Found(answer),
                    ) => return Ok(adapt(answer, work)),
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

fn adapt_definition_answer(
    site: &ResolvedReferenceSite,
    answer: SelectedNativeReferenceUnits,
) -> DefinitionLookupOutcome {
    let SelectedNativeDefinitions::Ready(units) = answer.definitions else {
        return unavailable_definition(
            site,
            "native_definition_projection_unavailable",
            "selected native definitions have no supported source-unit projection".into(),
        );
    };
    let mut definitions = Vec::new();
    let mut lexical_definitions = Vec::new();
    for (_, definition) in units {
        match definition {
            SelectedNativeDefinition::Unit(unit) => definitions.push(unit),
            SelectedNativeDefinition::Lexical(lexical) => lexical_definitions.push(lexical),
        }
    }
    definitions.sort_unstable();
    definitions.dedup();
    let completion = answer.answer.binding().completion();
    let mut diagnostics = answer
        .named_reasons
        .into_iter()
        .map(|(kind, message)| DefinitionLookupDiagnostic {
            claim: None,
            kind: kind.into(),
            message,
        })
        .collect::<Vec<_>>();
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
    let is_incomplete = !matches!(completion, ResolutionCompletion::Complete);
    if is_incomplete {
        diagnostics.push(DefinitionLookupDiagnostic {
            claim: None,
            kind: "incomplete_binding".into(),
            message: format!("selected native binding is incomplete: {completion:?}"),
        });
    }
    let status = if target_count > 1 {
        // Multiple exact semantic targets establish ambiguity even when an
        // unrelated open inventory also limits completeness. Preserve the
        // incomplete diagnostic so callers retain that uncertainty.
        DefinitionLookupStatus::Ambiguous
    } else if is_incomplete {
        DefinitionLookupStatus::Incomplete
    } else {
        match target_count {
            0 => DefinitionLookupStatus::NoDefinition,
            1 => DefinitionLookupStatus::Resolved,
            _ => unreachable!("multiple native targets are ambiguous"),
        }
    };
    DefinitionLookupOutcome {
        modeled_definitions: Vec::new(),
        status,
        reference: Some(site.clone()),
        definitions,
        lexical_definition,
        diagnostics,
    }
}

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
    resolve_native_point_bounded(
        inner,
        query,
        prepare_context,
        after_open,
        |operation, context, locator, cancellation| {
            operation.resolve_native_reference_types_bounded(
                context,
                locator,
                query.budget,
                cancellation,
                &mut SelectedResolutionContextMetrics,
            )
        },
        |answer, work| match answer.types {
            SelectedNativeTypes::Cancelled => BoundedResolution::Cancelled { work },
            _ => BoundedResolution::Complete {
                value: adapt_type_answer(query.site, inner.adapter().language(), answer),
                work,
            },
        },
        unavailable_type,
    )
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

fn adapt_type_answer(
    site: &ResolvedReferenceSite,
    language: Language,
    answer: SelectedNativeReferenceTypes,
) -> TypeLookupOutcome {
    let SelectedNativeTypes::Ready { nominal, intrinsic } = answer.types else {
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
    let resolution = answer.answer;
    let observed = resolution.observed_type_identity();
    let (target_kind, selected, kinds) = if observed.is_some() {
        (
            TypeLookupTargetKind::TypeReference,
            Some(BindingProjectionKind::TargetTypeIdentity),
            vec![BindingProjectionKind::TargetTypeIdentity],
        )
    } else {
        crate::analyzer::usages::get_type::projection_target_kind(resolution.projections())
    };
    let mut complete = resolution.completion() == &ResolutionCompletion::Complete;
    if !complete {
        diagnostics.push(TypeLookupDiagnostic {
            kind: "incomplete_native_type".into(),
            message: format!(
                "selected native type evidence is incomplete: {:?}",
                resolution.completion()
            ),
        });
    }
    let slots = resolution
        .projections()
        .iter()
        .filter(|projection| Some(projection.kind()) == selected)
        .map(|projection| projection.output_slot())
        .chain(observed);
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
                        SelectedNativeDefinition::Lexical(_) => None,
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
            let fqn = if depth == 0 {
                spelling
            } else if language == Language::Go {
                format!("{}{spelling}", "*".repeat(depth as usize))
            } else {
                complete = false;
                diagnostics.push(TypeLookupDiagnostic { kind: "unsupported_type_indirection".into(),
                    message: format!("selected {language:?} type {identity:?} has unsupported indirection {depth}") });
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

/// Caller-visible native type evidence for the private differential harness.
/// The module is absent unless tests or the existing test-support feature are enabled.
#[derive(Debug)]
pub struct NativeTypeProbe {
    pub status: &'static str,
    pub types: Vec<TypeLookupType>,
    pub diagnostics: Vec<(String, String)>,
    pub reference: Option<ResolvedReferenceSite>,
    pub target_kind: TypeLookupTargetKind,
}

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
    let Some(points) = crate::analyzer::languages::language_support(language)
        .and_then(|support| support.native_rollout_points())
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

/// Probe the selected native definition reader without changing production dispatch.
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

/// Probe native type identity and completion through the same selected operation.
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
