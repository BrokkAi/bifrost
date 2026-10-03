//! Rust selected-resolution diagnostics and native reference-index construction.
//!
//! Diagnostic helpers retain selected native evidence without invoking an
//! incumbent producer after the production adapter cutover.

use super::RustAnalyzer;
#[cfg(test)]
use super::native_rename::{
    RustBindingTargetProof, RustBindingWorldOutcome, RustRenameSafetyOutcome, native_rust_rename,
    selected_rust_binding_world, validate_selected_rust_rename,
};
#[cfg(test)]
use super::selected_projection::rust_selected_workspace_identity_gap;
#[cfg(test)]
use crate::analyzer::Project;
#[cfg(test)]
use crate::analyzer::Range;
#[cfg(test)]
use crate::analyzer::languages::BoundedReceiverQuery;
#[cfg(test)]
use crate::analyzer::resolution::ResolutionCompletion;
#[cfg(test)]
use crate::analyzer::resolution::{ResolutionBatchMetrics, SelectedSemanticLocator};
#[cfg(test)]
use crate::analyzer::store::resolution_operation::{
    SelectedResolutionContextMetrics, SelectedResolutionOperationInput,
    SelectedResolutionOperationOpenOutcome, SelectedResolutionOperationOutcome,
    SelectedRustBindingDefinition, SelectedRustBindingDefinitionUnitsOutcome,
    SelectedRustBindingOwner, SelectedRustBindingWorld,
};
#[cfg(test)]
use crate::analyzer::store::resolution_operation::{
    SelectedResolutionLocated, SelectedRustCallerReferenceOutcome,
};
#[cfg(test)]
use crate::analyzer::store::resolution_publication::SelectedResolutionOverlayInputsOutcome;
#[cfg(test)]
use crate::analyzer::store::resolution_selection::SelectedResolutionLanguage;
use crate::analyzer::structural::EdgeProvenance;
use crate::analyzer::structural::reference_edges::{
    EdgeCompleteness, EdgeDerivationResult, EdgeIncompleteReason, SelectedInverseIndexOutcome,
    SelectedInverseReferenceIndex, SelectedInverseReferenceProvider,
};
#[cfg(test)]
use crate::analyzer::usages::FuzzyResult;
#[cfg(test)]
use crate::analyzer::usages::get_definition::{
    BoundedResolution, CallSyntaxKind, DefinitionLookupStatus, candidates_outcome,
};
#[cfg(test)]
use crate::analyzer::usages::inverted_edges::MAX_CALLSITES;
#[cfg(test)]
use crate::analyzer::usages::workspace_graph::is_graph_declaration;
#[cfg(test)]
use crate::analyzer::usages::workspace_graph::{UsageEcosystem, WorkspaceUsageGraph};
#[cfg(test)]
use crate::analyzer::usages::{UsageHitKind, UsageProof};
use crate::analyzer::{CodeUnit, IAnalyzer};
#[cfg(test)]
use crate::analyzer::{CodeUnitIndex, Language, ProjectFile};
#[cfg(test)]
use crate::hash::HashSet;
#[cfg(test)]
use crate::path_utils::rel_path_string;
#[cfg(test)]
use crate::symbol_rename::RenameResult;
#[cfg(test)]
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind;
#[cfg(test)]
use brokk_bifrost_core::analyzer::usages::inverted_edges::{
    UsageReferenceCounts, UsageReferenceKind,
};
#[cfg(test)]
use brokk_bifrost_core::analyzer::usages::receiver_analysis::{
    ReceiverAnalysisWork, ReceiverBudgetLimit,
};
#[cfg(test)]
use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;
#[cfg(test)]
use brokk_bifrost_core::text_utils::{compute_line_starts, find_line_index_for_offset};
#[cfg(test)]
use std::collections::btree_map::Entry;
#[cfg(test)]
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
enum RustDefinitionShadowResult {
    Complete {
        status: DefinitionLookupStatus,
        definitions: Vec<CodeUnit>,
        work: ReceiverAnalysisWork,
    },
    Exceeded {
        limit: ReceiverBudgetLimit,
        work: ReceiverAnalysisWork,
    },
    Cancelled {
        work: ReceiverAnalysisWork,
    },
    UnsupportedCallerProfile {
        work: ReceiverAnalysisWork,
    },
    Incomplete {
        definitions: Vec<CodeUnit>,
        completion: ResolutionCompletion,
        work: ReceiverAnalysisWork,
    },
    Unavailable(String),
    Stale(String),
    StoreError(String),
}

#[cfg(test)]
fn selected_rust_definition_shadow_result(
    rust: &RustAnalyzer,
    query: BoundedReceiverQuery<'_>,
) -> RustDefinitionShadowResult {
    selected_rust_definition_shadow_result_with_after_open(rust, query, || {})
}

#[cfg(test)]
fn selected_rust_definition_shadow_result_with_after_open(
    rust: &RustAnalyzer,
    query: BoundedReceiverQuery<'_>,
    after_open: impl FnOnce(),
) -> RustDefinitionShadowResult {
    let cancellation = query.cancellation.cloned().unwrap_or_default();
    if !cancellation.is_cancelled()
        && let Some(detail) = rust_selected_workspace_identity_gap(rust)
    {
        return RustDefinitionShadowResult::Unavailable(detail);
    }
    let snapshots = rust.inner.selected_workspace_snapshots();
    let languages = [SelectedResolutionLanguage::new("rust", Language::Rust)];
    let (masks, content_mounts) = match rust
        .inner
        .selected_rust_resolution_overlay_inputs(snapshots.as_ref(), &cancellation)
    {
        Ok(SelectedResolutionOverlayInputsOutcome::Ready {
            masks,
            content_mounts,
        }) => (masks, content_mounts),
        Ok(SelectedResolutionOverlayInputsOutcome::Unavailable(reason)) => {
            return RustDefinitionShadowResult::Unavailable(format!("{reason:?}"));
        }
        Ok(SelectedResolutionOverlayInputsOutcome::Stale(reason)) => {
            return RustDefinitionShadowResult::Stale(format!("{reason:?}"));
        }
        Ok(SelectedResolutionOverlayInputsOutcome::Cancelled) => {
            return RustDefinitionShadowResult::Cancelled {
                work: ReceiverAnalysisWork::default(),
            };
        }
        Err(error) => return RustDefinitionShadowResult::StoreError(error.to_string()),
    };
    let input = SelectedResolutionOperationInput::new(
        rust.inner.project(),
        rust.inner.workspace_id(),
        snapshots.as_ref(),
        &languages,
        &masks,
    )
    .with_content_mounts(content_mounts);
    let operation = match rust
        .inner
        .analyzer_store()
        .open_selected_resolution_operation(input, &cancellation)
    {
        Ok(SelectedResolutionOperationOpenOutcome::Ready(operation)) => *operation,
        Ok(SelectedResolutionOperationOpenOutcome::Unavailable(reason)) => {
            return RustDefinitionShadowResult::Unavailable(format!("{reason:?}"));
        }
        Ok(SelectedResolutionOperationOpenOutcome::Stale(reason)) => {
            return RustDefinitionShadowResult::Stale(format!("{reason:?}"));
        }
        Ok(SelectedResolutionOperationOpenOutcome::Cancelled) => {
            return RustDefinitionShadowResult::Cancelled {
                work: ReceiverAnalysisWork::default(),
            };
        }
        Err(error) => return RustDefinitionShadowResult::StoreError(error.to_string()),
    };
    after_open();
    let locator = SelectedSemanticLocator::for_reference_range(
        "rust",
        rel_path_string(query.file),
        query.site.focus_start_byte,
        query.site.focus_end_byte,
    );
    let mut context_metrics = SelectedResolutionContextMetrics;
    let mut point_metrics = ResolutionBatchMetrics::default();
    let result = operation.resolve_rust_reference_for_caller_bounded(
        query.file.rel_path(),
        &locator,
        query.budget,
        &cancellation,
        &mut context_metrics,
        &mut point_metrics,
    );
    let result = match result {
        Ok(result) => result,
        Err(error) => return RustDefinitionShadowResult::StoreError(error.to_string()),
    };
    match result {
        BoundedResolution::Exceeded { limit, work } => {
            RustDefinitionShadowResult::Exceeded { limit, work }
        }
        BoundedResolution::Cancelled { work } => RustDefinitionShadowResult::Cancelled { work },
        BoundedResolution::Complete {
            value: SelectedRustCallerReferenceOutcome::UnsupportedCallerProfile,
            work,
        } => RustDefinitionShadowResult::UnsupportedCallerProfile { work },
        BoundedResolution::Complete {
            value: SelectedRustCallerReferenceOutcome::Operation(operation),
            work,
        } => match operation {
            SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Missing) => {
                // The caller supplied a structured reference occurrence. A
                // missing native site is missing producer support, not proof
                // that this occurrence has no definition. Closed negatives
                // come from a found reference with a complete empty binding.
                RustDefinitionShadowResult::Unavailable(format!(
                    "selected Rust reference inventory has no site for {:?}:{}..{}",
                    query.file, query.site.focus_start_byte, query.site.focus_end_byte,
                ))
            }
            SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                answers,
            )) => {
                let completion =
                    answers
                        .iter()
                        .fold(ResolutionCompletion::Complete, |completion, answer| {
                            completion.combine(answer.resolution.binding().completion())
                        });
                let definitions = answers
                    .into_iter()
                    .flat_map(|answer| answer.definitions)
                    .collect();
                if !matches!(completion, ResolutionCompletion::Complete) {
                    RustDefinitionShadowResult::Incomplete {
                        definitions,
                        completion,
                        work,
                    }
                } else {
                    let translated = candidates_outcome(definitions);
                    RustDefinitionShadowResult::Complete {
                        status: translated.status,
                        definitions: translated.definitions,
                        work,
                    }
                }
            }
            SelectedResolutionOperationOutcome::Unavailable(reason) => {
                RustDefinitionShadowResult::Unavailable(format!("{reason:?}"))
            }
            SelectedResolutionOperationOutcome::Stale(reason) => {
                RustDefinitionShadowResult::Stale(format!("{reason:?}"))
            }
            SelectedResolutionOperationOutcome::Cancelled(_) => {
                RustDefinitionShadowResult::Cancelled { work }
            }
        },
    }
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct RustUsageShadowSite {
    file: ProjectFile,
    start_byte: usize,
    end_byte: usize,
    enclosing: CodeUnit,
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
enum RustUsageShadowResult {
    Complete {
        sites: BTreeSet<RustUsageShadowSite>,
        capped: bool,
    },
    Incomplete {
        sites: BTreeSet<RustUsageShadowSite>,
        capped: bool,
        completion: EdgeCompleteness,
    },
    Unavailable(String),
    Stale(String),
    Cancelled,
    StoreError(String),
}

#[cfg(test)]
fn selected_rust_usage_shadow_result(
    rust: &RustAnalyzer,
    targets: &[CodeUnit],
    scan_scope: &UsageScanScope<'_>,
    max_usages: usize,
) -> RustUsageShadowResult {
    use super::selected_reverse::{RustSelectedReverseOutcome, with_rust_selected_reverse_queries};
    let fallback = crate::CancellationToken::default();
    let cancellation = scan_scope.cancellation().unwrap_or(&fallback);
    let answers = match with_rust_selected_reverse_queries(rust, cancellation, |queries| {
        queries.inverse_for(targets)
    }) {
        RustSelectedReverseOutcome::Ready(Some(answers)) => answers,
        RustSelectedReverseOutcome::Ready(None) => {
            return RustUsageShadowResult::Unavailable(
                "selected inverse target is unavailable".into(),
            );
        }
        RustSelectedReverseOutcome::Unavailable(reason) => {
            return RustUsageShadowResult::Unavailable(reason);
        }
        RustSelectedReverseOutcome::Stale(reason) => return RustUsageShadowResult::Stale(reason),
        RustSelectedReverseOutcome::Cancelled => return RustUsageShadowResult::Cancelled,
        RustSelectedReverseOutcome::StoreError(reason) => {
            return RustUsageShadowResult::StoreError(reason);
        }
    };
    let mut sites = BTreeSet::new();
    let mut reasons = Vec::new();
    for answer in answers {
        if let EdgeCompleteness::Incomplete { reasons: gaps } = answer.completeness {
            reasons.extend(gaps);
        }
        for edge in answer.edges {
            if edge.usage_kind == UsageHitKind::Import
                || !scan_scope.candidate_files().contains(&edge.site.file)
            {
                continue;
            }
            let enclosing = edge
                .site
                .enclosing
                .unwrap_or_else(|| CodeUnit::file_scope(edge.site.file.clone()));
            if targets.contains(&enclosing) {
                continue;
            }
            sites.insert(RustUsageShadowSite {
                file: edge.site.file,
                start_byte: edge.site.range.start_byte,
                end_byte: edge.site.range.end_byte,
                enclosing,
            });
        }
    }
    let capped = sites.len() > max_usages;
    let sites = sites.into_iter().take(max_usages).collect();
    if reasons.is_empty() {
        RustUsageShadowResult::Complete { sites, capped }
    } else {
        RustUsageShadowResult::Incomplete {
            sites,
            capped,
            completion: EdgeCompleteness::Incomplete { reasons },
        }
    }
}

#[cfg(test)]
struct RustWorkspaceBindingWorld {
    definition_units: BTreeMap<SelectedRustBindingDefinition, CodeUnit>,
    world: SelectedRustBindingWorld,
}

#[cfg(test)]
enum RustWorkspaceBindingWorldResult {
    Ready(RustWorkspaceBindingWorld),
    Unavailable(String),
    Stale(String),
    Cancelled,
    StoreError(String),
}

/// Test-only graph oracle assembled from per-definition row demands. Production
/// inverse consumers retain only the generation-bound query handle below.
#[cfg(test)]
fn selected_rust_workspace_binding_world(
    rust: &RustAnalyzer,
    cancellation: &crate::CancellationToken,
) -> RustWorkspaceBindingWorldResult {
    let _timing = crate::profiling::scope("rust_selected::workspace_binding_world");
    if cancellation.is_cancelled() {
        return RustWorkspaceBindingWorldResult::Cancelled;
    }
    let generation = rust.inner.project().analysis_generation();
    let snapshots = rust.inner.selected_workspace_snapshots();
    let languages = [SelectedResolutionLanguage::new("rust", Language::Rust)];
    let (masks, content_mounts) = match rust
        .inner
        .selected_rust_resolution_overlay_inputs(snapshots.as_ref(), cancellation)
    {
        Ok(SelectedResolutionOverlayInputsOutcome::Ready {
            masks,
            content_mounts,
        }) => (masks, content_mounts),
        Ok(SelectedResolutionOverlayInputsOutcome::Unavailable(reason)) => {
            return RustWorkspaceBindingWorldResult::Unavailable(format!("{reason:?}"));
        }
        Ok(SelectedResolutionOverlayInputsOutcome::Stale(reason)) => {
            return RustWorkspaceBindingWorldResult::Stale(format!("{reason:?}"));
        }
        Ok(SelectedResolutionOverlayInputsOutcome::Cancelled) => {
            return RustWorkspaceBindingWorldResult::Cancelled;
        }
        Err(error) => {
            return RustWorkspaceBindingWorldResult::StoreError(error.to_string());
        }
    };
    let input = SelectedResolutionOperationInput::new(
        rust.inner.project(),
        rust.inner.workspace_id(),
        snapshots.as_ref(),
        &languages,
        &masks,
    )
    .with_content_mounts(content_mounts);
    let operation = match rust
        .inner
        .analyzer_store()
        .open_selected_resolution_operation(input, cancellation)
    {
        Ok(SelectedResolutionOperationOpenOutcome::Ready(operation)) => *operation,
        Ok(SelectedResolutionOperationOpenOutcome::Unavailable(reason)) => {
            return RustWorkspaceBindingWorldResult::Unavailable(format!("{reason:?}"));
        }
        Ok(SelectedResolutionOperationOpenOutcome::Stale(reason)) => {
            return RustWorkspaceBindingWorldResult::Stale(format!("{reason:?}"));
        }
        Ok(SelectedResolutionOperationOpenOutcome::Cancelled) => {
            return RustWorkspaceBindingWorldResult::Cancelled;
        }
        Err(error) => {
            return RustWorkspaceBindingWorldResult::StoreError(error.to_string());
        }
    };
    let definition_timing = crate::profiling::scope("rust_selected::definition_units");
    let definition_units = match operation.rust_binding_definition_units(cancellation) {
        Ok(SelectedRustBindingDefinitionUnitsOutcome::Ready(units)) => units,
        Ok(SelectedRustBindingDefinitionUnitsOutcome::Cancelled) => {
            return RustWorkspaceBindingWorldResult::Cancelled;
        }
        Err(error) => {
            return RustWorkspaceBindingWorldResult::StoreError(error.to_string());
        }
    };
    drop(definition_timing);
    let Some(anchor) = definition_units
        .iter()
        .find_map(|(definition, unit)| is_graph_declaration(unit).then(|| definition.clone()))
    else {
        return RustWorkspaceBindingWorldResult::Unavailable(
            "selected Rust workspace has no graph declaration anchor".to_string(),
        );
    };
    let mut sites = Vec::new();
    let mut completion = ResolutionCompletion::Complete;
    for unit in definition_units.values() {
        let (masks, content_mounts) = match rust
            .inner
            .selected_rust_resolution_overlay_inputs(snapshots.as_ref(), cancellation)
        {
            Ok(SelectedResolutionOverlayInputsOutcome::Ready {
                masks,
                content_mounts,
            }) => (masks, content_mounts),
            Ok(SelectedResolutionOverlayInputsOutcome::Cancelled) => {
                return RustWorkspaceBindingWorldResult::Cancelled;
            }
            Ok(SelectedResolutionOverlayInputsOutcome::Stale(reason)) => {
                return RustWorkspaceBindingWorldResult::Stale(format!("{reason:?}"));
            }
            Ok(SelectedResolutionOverlayInputsOutcome::Unavailable(reason)) => {
                return RustWorkspaceBindingWorldResult::Unavailable(format!("{reason:?}"));
            }
            Err(error) => return RustWorkspaceBindingWorldResult::StoreError(error.to_string()),
        };
        match selected_rust_binding_world(
            rust,
            snapshots.as_ref(),
            RustBindingTargetProof::Current(unit),
            &masks,
            content_mounts,
            cancellation,
        ) {
            RustBindingWorldOutcome::Ready(world) => {
                sites.extend_from_slice(world.sites());
                completion = completion.combine(world.completion());
            }
            RustBindingWorldOutcome::Unavailable(detail) => {
                return RustWorkspaceBindingWorldResult::Unavailable(detail);
            }
            RustBindingWorldOutcome::Stale(detail) => {
                return RustWorkspaceBindingWorldResult::Stale(detail);
            }
            RustBindingWorldOutcome::Cancelled => {
                return RustWorkspaceBindingWorldResult::Cancelled;
            }
            RustBindingWorldOutcome::StoreError(detail) => {
                return RustWorkspaceBindingWorldResult::StoreError(detail);
            }
        }
    }
    let world =
        match operation.finish_rust_row_binding_world(anchor, sites, completion, cancellation) {
            Ok(SelectedResolutionOperationOutcome::Native(world)) => world,
            Ok(SelectedResolutionOperationOutcome::Unavailable(reason)) => {
                return RustWorkspaceBindingWorldResult::Unavailable(format!("{reason:?}"));
            }
            Ok(SelectedResolutionOperationOutcome::Stale(reason)) => {
                return RustWorkspaceBindingWorldResult::Stale(format!("{reason:?}"));
            }
            Ok(SelectedResolutionOperationOutcome::Cancelled(_)) => {
                return RustWorkspaceBindingWorldResult::Cancelled;
            }
            Err(error) => return RustWorkspaceBindingWorldResult::StoreError(error.to_string()),
        };
    if cancellation.is_cancelled() {
        return RustWorkspaceBindingWorldResult::Cancelled;
    }
    if rust.inner.project().analysis_generation() != generation {
        return RustWorkspaceBindingWorldResult::Stale(
            "selected Rust binding world crossed an analyzer generation".to_string(),
        );
    }
    RustWorkspaceBindingWorldResult::Ready(RustWorkspaceBindingWorld {
        definition_units,
        world,
    })
}

#[cfg(test)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct RustWorkspaceGraphShadow {
    edges: BTreeMap<(CodeUnit, CodeUnit), UsageReferenceCounts>,
    truncated: BTreeMap<CodeUnit, usize>,
    unproven_inbound: BTreeMap<CodeUnit, usize>,
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
enum RustWorkspaceGraphShadowResult {
    Complete(RustWorkspaceGraphShadow),
    Incomplete {
        graph: RustWorkspaceGraphShadow,
        detail: String,
    },
    Unavailable(String),
    Stale(String),
    Cancelled,
    StoreError(String),
}

#[cfg(test)]
fn rust_workspace_graph_reference_kind(
    site_kind: ResolutionSiteKind,
) -> Option<UsageReferenceKind> {
    match site_kind {
        ResolutionSiteKind::CallableReference | ResolutionSiteKind::ConstructorReference => {
            Some(UsageReferenceKind::Call)
        }
        ResolutionSiteKind::MemberReference => Some(UsageReferenceKind::Member),
        ResolutionSiteKind::TypeReference => Some(UsageReferenceKind::Type),
        ResolutionSiteKind::ImportDeclaration
        | ResolutionSiteKind::ModuleReference
        | ResolutionSiteKind::MacroReference
        | ResolutionSiteKind::ValueReference => Some(UsageReferenceKind::Other),
        _ => None,
    }
}

#[cfg(test)]
fn native_rust_workspace_graph_shadow(
    rust: &RustAnalyzer,
    production: &WorkspaceUsageGraph,
    definition_units: &BTreeMap<SelectedRustBindingDefinition, CodeUnit>,
    world: &SelectedRustBindingWorld,
    cancellation: &crate::CancellationToken,
) -> RustWorkspaceGraphShadowResult {
    let graph_units = production
        .nodes
        .iter()
        .filter(|node| node.key.ecosystem == UsageEcosystem::Rust)
        .map(|node| (node.primary.clone(), node.primary.clone()))
        .collect::<BTreeMap<_, _>>();
    let required_units = definition_units
        .values()
        .filter(|unit| is_graph_declaration(unit))
        .cloned()
        .collect::<BTreeSet<_>>();
    let graph_definition_spans = production
        .nodes
        .iter()
        .filter(|node| node.key.ecosystem == UsageEcosystem::Rust)
        .filter_map(|node| {
            node.primary_range.map(|range| {
                (
                    node.primary.clone(),
                    vec![(node.primary.source().clone(), range)],
                )
            })
        })
        .collect::<BTreeMap<_, _>>();
    native_rust_graph_shadow_for_units(
        rust,
        definition_units,
        &graph_units,
        &required_units,
        &graph_definition_spans,
        world,
        cancellation,
    )
}

#[cfg(test)]
fn native_rust_graph_shadow_for_units(
    rust: &RustAnalyzer,
    definition_units: &BTreeMap<SelectedRustBindingDefinition, CodeUnit>,
    graph_units: &BTreeMap<CodeUnit, CodeUnit>,
    required_units: &BTreeSet<CodeUnit>,
    graph_definition_spans: &BTreeMap<CodeUnit, Vec<(ProjectFile, Range)>>,
    world: &SelectedRustBindingWorld,
    cancellation: &crate::CancellationToken,
) -> RustWorkspaceGraphShadowResult {
    let mut edge_lines = BTreeMap::new();
    let mut callsites: BTreeMap<CodeUnit, BTreeSet<(ProjectFile, usize)>> = BTreeMap::new();
    let mut unproven: BTreeMap<CodeUnit, BTreeSet<(ProjectFile, usize)>> = BTreeMap::new();
    let mut line_starts = BTreeMap::new();
    let mut projection_complete = true;
    let mut completion = world.completion().clone();

    for site in world.sites() {
        if cancellation.is_cancelled() {
            return RustWorkspaceGraphShadowResult::Cancelled;
        }
        completion = completion.combine(site.completion());
        let Some(metadata) = site.metadata() else {
            projection_complete = false;
            continue;
        };
        let Some(kind) = rust_workspace_graph_reference_kind(metadata.site_kind()) else {
            projection_complete = false;
            continue;
        };
        let caller = match site.owner() {
            SelectedRustBindingOwner::Definition(owner) => Some(owner),
            SelectedRustBindingOwner::FileRoot => None,
            SelectedRustBindingOwner::Unknown | SelectedRustBindingOwner::Unavailable => {
                projection_complete = false;
                None
            }
        };
        let Some(caller) = caller else {
            continue;
        };
        let targets = site
            .definitions()
            .iter()
            .filter_map(|definition| definition_units.get(definition))
            .filter_map(|unit| match graph_units.get(unit) {
                Some(unit) => Some(unit),
                None if required_units.contains(unit) => {
                    projection_complete = false;
                    None
                }
                None => None,
            })
            .collect::<Vec<_>>();
        let overlaps_target_definition = |target: &CodeUnit| {
            graph_definition_spans.get(target).is_some_and(|ranges| {
                ranges.iter().any(|(file, range)| {
                    file == site.file()
                        && range.start_byte < metadata.end_byte()
                        && metadata.start_byte() < range.end_byte
                })
            })
        };
        let proven = site.definitions().len() == 1
            && targets.len() == 1
            && site.completion() == &ResolutionCompletion::Complete;
        if !proven {
            for target in targets {
                if caller != target && !overlaps_target_definition(target) {
                    unproven
                        .entry(target.clone())
                        .or_default()
                        .insert((site.file().clone(), metadata.start_byte()));
                }
            }
            continue;
        }
        let target = targets[0];
        if caller == target {
            continue;
        }
        callsites
            .entry(target.clone())
            .or_default()
            .insert((site.file().clone(), metadata.start_byte()));
        if overlaps_target_definition(target) {
            continue;
        }
        let caller = match graph_units.get(caller) {
            Some(caller) => caller,
            None => {
                if required_units.contains(caller) {
                    projection_complete = false;
                }
                continue;
            }
        };
        let starts = match line_starts.entry(site.file().clone()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let Some(source) = rust.indexed_source(site.file()) else {
                    projection_complete = false;
                    continue;
                };
                entry.insert(compute_line_starts(&source))
            }
        };
        let line = find_line_index_for_offset(starts, metadata.start_byte()) + 1;
        let retained_kind = edge_lines
            .entry((caller.clone(), target.clone(), site.file().clone(), line))
            .or_insert(kind);
        *retained_kind = (*retained_kind).max(kind);
    }

    let mut truncated = BTreeMap::new();
    for (target, sites) in callsites {
        if cancellation.is_cancelled() {
            return RustWorkspaceGraphShadowResult::Cancelled;
        }
        if sites.len() > MAX_CALLSITES {
            truncated.insert(target, sites.len());
        }
    }
    let mut edges: BTreeMap<(CodeUnit, CodeUnit), UsageReferenceCounts> = BTreeMap::new();
    for ((caller, target, _, _), kind) in edge_lines {
        if cancellation.is_cancelled() {
            return RustWorkspaceGraphShadowResult::Cancelled;
        }
        if !truncated.contains_key(&target) {
            edges.entry((caller, target)).or_default().record(kind);
        }
    }
    let mut unproven_inbound = BTreeMap::new();
    for (target, sites) in unproven {
        if cancellation.is_cancelled() {
            return RustWorkspaceGraphShadowResult::Cancelled;
        }
        unproven_inbound.insert(target, sites.len());
    }
    if cancellation.is_cancelled() {
        return RustWorkspaceGraphShadowResult::Cancelled;
    }
    let graph = RustWorkspaceGraphShadow {
        edges,
        truncated,
        unproven_inbound,
    };
    if projection_complete && completion == ResolutionCompletion::Complete {
        RustWorkspaceGraphShadowResult::Complete(graph)
    } else {
        RustWorkspaceGraphShadowResult::Incomplete {
            graph,
            detail: format!(
                "selected Rust workspace graph is open: completion={completion:?}, projection_complete={projection_complete}"
            ),
        }
    }
}

#[cfg(test)]
fn selected_rust_workspace_graph_shadow_result(
    rust: &RustAnalyzer,
    production: &WorkspaceUsageGraph,
    cancellation: &crate::CancellationToken,
) -> RustWorkspaceGraphShadowResult {
    match selected_rust_workspace_binding_world(rust, cancellation) {
        RustWorkspaceBindingWorldResult::Ready(selected) => native_rust_workspace_graph_shadow(
            rust,
            production,
            &selected.definition_units,
            &selected.world,
            cancellation,
        ),
        RustWorkspaceBindingWorldResult::Unavailable(detail) => {
            RustWorkspaceGraphShadowResult::Unavailable(detail)
        }
        RustWorkspaceBindingWorldResult::Stale(detail) => {
            RustWorkspaceGraphShadowResult::Stale(detail)
        }
        RustWorkspaceBindingWorldResult::Cancelled => RustWorkspaceGraphShadowResult::Cancelled,
        RustWorkspaceBindingWorldResult::StoreError(detail) => {
            RustWorkspaceGraphShadowResult::StoreError(detail)
        }
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct RustDeadCodeGraphShadow {
    edges: BTreeMap<(String, String), usize>,
    truncated: BTreeMap<String, usize>,
    unproven_inbound: BTreeMap<String, usize>,
}

#[cfg(test)]
fn accumulate_rust_dead_code_count(
    counts: &mut BTreeMap<String, usize>,
    name: String,
    added: usize,
) {
    let count = counts.entry(name).or_default();
    *count = count
        .checked_add(added)
        .expect("Rust dead-code graph count must fit usize");
}

#[cfg(test)]
fn native_rust_dead_code_graph_shadow(graph: &RustWorkspaceGraphShadow) -> RustDeadCodeGraphShadow {
    let mut shadow = RustDeadCodeGraphShadow::default();
    for ((caller, target), counts) in &graph.edges {
        let key = (caller.fq_name(), target.fq_name());
        let count = shadow.edges.entry(key).or_default();
        *count = count
            .checked_add(counts.total())
            .expect("Rust dead-code edge count must fit usize");
    }
    for (target, &count) in &graph.truncated {
        accumulate_rust_dead_code_count(&mut shadow.truncated, target.fq_name(), count);
    }
    for (target, &count) in &graph.unproven_inbound {
        accumulate_rust_dead_code_count(&mut shadow.unproven_inbound, target.fq_name(), count);
    }
    shadow
}

#[cfg(test)]
fn selected_rust_dead_code_graph_shadow_result(
    rust: &RustAnalyzer,
    nodes: &HashSet<String>,
    cancellation: &crate::CancellationToken,
) -> RustWorkspaceGraphShadowResult {
    let selected = match selected_rust_workspace_binding_world(rust, cancellation) {
        RustWorkspaceBindingWorldResult::Ready(selected) => selected,
        RustWorkspaceBindingWorldResult::Unavailable(detail) => {
            return RustWorkspaceGraphShadowResult::Unavailable(detail);
        }
        RustWorkspaceBindingWorldResult::Stale(detail) => {
            return RustWorkspaceGraphShadowResult::Stale(detail);
        }
        RustWorkspaceBindingWorldResult::Cancelled => {
            return RustWorkspaceGraphShadowResult::Cancelled;
        }
        RustWorkspaceBindingWorldResult::StoreError(detail) => {
            return RustWorkspaceGraphShadowResult::StoreError(detail);
        }
    };
    let mut graph_units = BTreeMap::new();
    let mut projected_fq_names = HashSet::default();
    for unit in selected.definition_units.values() {
        let fq_name = unit.fq_name();
        if !rust_selected_reference_target(unit) || !nodes.contains(&fq_name) {
            continue;
        }
        projected_fq_names.insert(fq_name);
        if let Some(previous) = graph_units.insert(unit.clone(), unit.clone()) {
            assert_eq!(
                previous, *unit,
                "one Rust dead-code graph declaration has one canonical parser unit"
            );
        }
    }
    let required_units = graph_units.keys().cloned().collect::<BTreeSet<_>>();
    let graph_definition_spans = graph_units
        .values()
        .map(|unit| {
            (
                unit.clone(),
                rust.ranges(unit)
                    .into_iter()
                    .map(|range| (unit.source().clone(), range))
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let result = native_rust_graph_shadow_for_units(
        rust,
        &selected.definition_units,
        &graph_units,
        &required_units,
        &graph_definition_spans,
        &selected.world,
        cancellation,
    );
    let mut missing_nodes = nodes
        .difference(&projected_fq_names)
        .cloned()
        .collect::<Vec<_>>();
    missing_nodes.sort_unstable();
    if missing_nodes.is_empty() {
        return result;
    }
    match result {
        RustWorkspaceGraphShadowResult::Complete(graph) => {
            RustWorkspaceGraphShadowResult::Incomplete {
                graph,
                detail: format!(
                    "selected Rust dead-code graph omitted requested nodes: {missing_nodes:?}"
                ),
            }
        }
        RustWorkspaceGraphShadowResult::Incomplete { graph, detail } => {
            RustWorkspaceGraphShadowResult::Incomplete {
                graph,
                detail: format!("{detail}; omitted requested nodes: {missing_nodes:?}"),
            }
        }
        terminal => terminal,
    }
}

/// Real native Rust graph preparation feeding the shared relevance reducer.
/// This diagnostic seam never changes production graph or cache selection.
#[cfg(test)]
pub(crate) fn selected_rust_relevance_graph_shadow(
    rust: &RustAnalyzer,
    cancellation: &crate::CancellationToken,
) -> Result<
    crate::analyzer::usages::workspace_graph::SelectedWorkspaceUsageRankingBuildOutcome,
    String,
> {
    use super::native_graph::{
        RustNativeWorkspaceGraphOutcome, build_rust_native_workspace_graph_for_files,
    };
    use crate::analyzer::usages::workspace_graph::SelectedWorkspaceUsageGraphProjectionOutcome;
    let root_files: Vec<ProjectFile> = rust
        .source_file_inventory()
        .rows
        .into_iter()
        .filter(|file| crate::analyzer::common::language_for_file(file) == Language::Rust)
        .collect();
    let projection =
        match build_rust_native_workspace_graph_for_files(rust, &root_files, 8, cancellation)
            .map_err(|error| error.to_string())?
        {
            RustNativeWorkspaceGraphOutcome::Complete(graph) => {
                SelectedWorkspaceUsageGraphProjectionOutcome::Complete(graph)
            }
            RustNativeWorkspaceGraphOutcome::Incomplete(graph) => {
                SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(graph)
            }
            RustNativeWorkspaceGraphOutcome::Cancelled => {
                SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled
            }
            RustNativeWorkspaceGraphOutcome::Stale(_) => {
                SelectedWorkspaceUsageGraphProjectionOutcome::Stale
            }
            RustNativeWorkspaceGraphOutcome::Unavailable(reason) => return Err(reason),
        };
    Ok(projection.into_ranking_graph(rust, cancellation))
}

#[cfg(test)]
pub(crate) fn selected_rust_native_usage_consumer_shadow(
    rust: &RustAnalyzer,
    target: &CodeUnit,
    files: &HashSet<ProjectFile>,
) -> crate::analyzer::usages::outcome::GraphUsageOutcome {
    super::native_usages::find_native_usages(
        rust,
        std::slice::from_ref(target),
        &brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope::new(files),
        1,
    )
}

/// A generation-bound handle; each target owns and drops its row query.
pub(crate) struct RustSelectedReferenceIndex {
    generation: u64,
    rust: Box<RustAnalyzer>,
    cancellation: crate::CancellationToken,
}

impl RustSelectedReferenceIndex {
    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    #[cfg(test)]
    pub(crate) fn covers_target(&self, target: &CodeUnit) -> bool {
        use super::selected_reverse::{
            RustSelectedReverseOutcome, with_rust_selected_reverse_queries,
        };
        matches!(
            with_rust_selected_reverse_queries(&self.rust, &self.cancellation, |queries| queries
                .candidate_files(std::slice::from_ref(target))),
            RustSelectedReverseOutcome::Ready(Some(_))
        )
    }

    pub(crate) fn inverse_for(&self, target: &CodeUnit) -> EdgeDerivationResult {
        use super::selected_reverse::{
            RustSelectedReverseOutcome, with_rust_selected_reverse_queries,
        };
        if self.rust.inner.project().analysis_generation() == self.generation {
            match with_rust_selected_reverse_queries(&self.rust, &self.cancellation, |queries| {
                queries.inverse_for(std::slice::from_ref(target))
            }) {
                RustSelectedReverseOutcome::Ready(Some(mut answers)) => {
                    assert_eq!(answers.len(), 1);
                    let mut answer = answers.pop().expect("one target answer");
                    let mut edges = std::collections::BTreeMap::new();
                    for row in answer.edges {
                        let key = (
                            row.site.file.clone(),
                            row.site.range.start_byte,
                            row.site.range.end_byte,
                            row.target.clone(),
                            row.usage_kind,
                        );
                        if let Some(previous) = edges.insert(key, row.clone()) {
                            assert_eq!(
                                previous, row,
                                "one physical inverse edge has one canonical projection"
                            );
                        }
                    }
                    answer.edges = edges.into_values().collect();
                    return answer;
                }
                RustSelectedReverseOutcome::Ready(None) => {
                    return self.incomplete(EdgeIncompleteReason::InverseIndexTargetUncovered);
                }
                failure => eprintln!("selected inverse row query did not complete: {failure:?}"),
            }
        }
        self.incomplete(EdgeIncompleteReason::InverseIndexResolutionIncomplete)
    }

    fn incomplete(&self, reason: EdgeIncompleteReason) -> EdgeDerivationResult {
        EdgeDerivationResult {
            edges: Vec::new(),
            completeness: EdgeCompleteness::Incomplete {
                reasons: vec![reason],
            },
            provenance: EdgeProvenance::Inverse,
            generation: self.generation,
        }
    }
}

pub(crate) enum RustSelectedReferenceIndexOutcome {
    Ready(RustSelectedReferenceIndex),
    Unavailable(String),
    Stale(String),
    Cancelled,
    StoreError(String),
}

impl SelectedInverseReferenceIndex for RustSelectedReferenceIndex {
    fn generation(&self) -> u64 {
        Self::generation(self)
    }

    fn inverse_for(&self, target: &CodeUnit) -> EdgeDerivationResult {
        Self::inverse_for(self, target)
    }
}

/// The registered Rust selected inverse index builder.
///
/// RQL `edges_of` and the policy edge asserts reach Rust's native inverse
/// answer through this provider, so a workspace whose selected facts cannot
/// produce an index reports that refusal instead of an empty edge set.
pub(crate) struct RustNativeSelectedInverseProvider;

impl SelectedInverseReferenceProvider for RustNativeSelectedInverseProvider {
    fn build_selected_inverse_index(
        &self,
        analyzer: &dyn IAnalyzer,
        cancellation: Option<&crate::CancellationToken>,
    ) -> SelectedInverseIndexOutcome {
        let Some(rust) = crate::analyzer::resolve_analyzer::<RustAnalyzer>(analyzer) else {
            return SelectedInverseIndexOutcome::Unavailable(
                "the workspace has no Rust analyzer".to_string(),
            );
        };
        let token = cancellation.cloned().unwrap_or_default();
        match build_rust_selected_reference_index(rust, &token) {
            RustSelectedReferenceIndexOutcome::Ready(index) => {
                SelectedInverseIndexOutcome::Ready(Arc::new(index))
            }
            RustSelectedReferenceIndexOutcome::Unavailable(detail) => {
                SelectedInverseIndexOutcome::Unavailable(detail)
            }
            RustSelectedReferenceIndexOutcome::Stale(detail) => {
                SelectedInverseIndexOutcome::Stale(detail)
            }
            RustSelectedReferenceIndexOutcome::Cancelled => SelectedInverseIndexOutcome::Cancelled,
            RustSelectedReferenceIndexOutcome::StoreError(detail) => {
                SelectedInverseIndexOutcome::StoreError(detail)
            }
        }
    }
}

#[cfg(test)]
fn rust_selected_reference_target(unit: &CodeUnit) -> bool {
    !unit.is_synthetic() && (unit.is_class() || unit.is_callable() || unit.is_field())
}

pub(crate) fn build_rust_selected_reference_index(
    rust: &RustAnalyzer,
    cancellation: &crate::CancellationToken,
) -> RustSelectedReferenceIndexOutcome {
    use super::selected_reverse::{RustSelectedReverseOutcome, with_rust_selected_reverse_queries};
    let generation = rust.inner.project().analysis_generation();
    match with_rust_selected_reverse_queries(rust, cancellation, |_| Ok(())) {
        RustSelectedReverseOutcome::Ready(()) => {
            RustSelectedReferenceIndexOutcome::Ready(RustSelectedReferenceIndex {
                generation,
                rust: Box::new(rust.clone()),
                cancellation: cancellation.clone(),
            })
        }
        RustSelectedReverseOutcome::Unavailable(detail) => {
            RustSelectedReferenceIndexOutcome::Unavailable(detail)
        }
        RustSelectedReverseOutcome::Stale(detail) => {
            RustSelectedReferenceIndexOutcome::Stale(detail)
        }
        RustSelectedReverseOutcome::Cancelled => RustSelectedReferenceIndexOutcome::Cancelled,
        RustSelectedReverseOutcome::StoreError(detail) => {
            RustSelectedReferenceIndexOutcome::StoreError(detail)
        }
    }
}

#[cfg(test)]
fn selected_rust_rename_shadow_result(
    rust: &RustAnalyzer,
    project: &dyn Project,
    result: &RenameResult,
    new_name: &str,
) -> RustRenameSafetyOutcome {
    let cancellation = crate::CancellationToken::default();
    validate_selected_rust_rename(rust, project, result, new_name, &cancellation)
}

#[cfg(test)]
#[path = "selected_shadow/module_system_tests.rs"]
mod module_system_tests;

#[cfg(test)]
mod tests {
    use super::super::RustSupport;
    use super::*;
    use crate::CancellationToken;
    use crate::analyzer::languages::{LanguageSupport, StructuralReceiverResolver, fqn_bulk_nodes};
    use crate::analyzer::usages::call_relations::CallRelationService;
    use crate::analyzer::usages::get_definition::ResolvedReferenceSite;
    use crate::analyzer::usages::workspace_graph::{
        WorkspaceUsageCatalog, WorkspaceUsageGraphBuildOutcome,
        build_workspace_usage_graph_with_cancellation,
    };
    use crate::analyzer::{AnalyzerQueryScope, Project, QueryScope, Range};
    use crate::hash::HashSet;
    use crate::inline_project::InlineTestProject;
    use crate::symbol_rename::RenameSelection;
    use std::sync::Arc;

    fn rust_shadow_site(source: &str, spelling: &str) -> ResolvedReferenceSite {
        let start_byte = source.rfind(spelling).expect("Rust shadow call");
        ResolvedReferenceSite {
            path: "src/lib.rs".to_string(),
            text: spelling.to_string(),
            range: Range {
                start_byte,
                end_byte: start_byte + spelling.len(),
                start_line: 3,
                end_line: 3,
            },
            focus_start_byte: start_byte,
            focus_end_byte: start_byte + spelling.len(),
        }
    }

    fn rust_shadow_tree(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("configure Rust parser");
        parser
            .parse(source, None)
            .expect("parse Rust shadow fixture")
    }

    fn assert_rust_shadow_case(
        source: &str,
        spelling: &str,
        extra_files: &[(&str, &str)],
        expected_status: DefinitionLookupStatus,
        expected_names: &[&str],
    ) {
        let mut project = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", source);
        for &(path, contents) in extra_files {
            project = project.file(path, contents);
        }
        let fixture = project.build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let site = rust_shadow_site(source, spelling);
        let tree = rust_shadow_tree(source);
        let query = BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: Some(&tree),
            site: &site,
            budget: Default::default(),
            cancellation: None,
        };
        let native = selected_rust_definition_shadow_result(&analyzer, query);
        let RustDefinitionShadowResult::Complete {
            status,
            definitions,
            ..
        } = native
        else {
            panic!("Rust shadow case must complete")
        };
        assert_eq!(status, expected_status);
        let mut names = definitions
            .iter()
            .map(CodeUnit::short_name)
            .collect::<Vec<_>>();
        names.sort_unstable();
        assert_eq!(names, expected_names);
    }

    #[test]
    fn production_structural_resolver_shadows_selected_rust_library_resolution() {
        let source = concat!(
            "pub mod model;\n",
            "pub use model::target as alias;\n",
            "pub fn caller() -> usize { alias() }\n",
        );
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", source)
            .file("src/model.rs", "pub fn target() -> usize { 1 }\n")
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let site = rust_shadow_site(source, "alias");
        let tree = rust_shadow_tree(source);
        let query = BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: Some(&tree),
            site: &site,
            budget: brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget::default(),
            cancellation: None,
        };

        let RustDefinitionShadowResult::Complete {
            status,
            definitions,
            ..
        } = selected_rust_definition_shadow_result(&analyzer, query)
        else {
            panic!("selected Rust library resolution must complete")
        };
        assert_eq!(status, DefinitionLookupStatus::Resolved);
        assert_eq!(definitions.len(), 1);
        assert_eq!(definitions[0].short_name(), "target");
    }

    #[test]
    fn selected_rust_forward_mixed_module_and_type_prefixes_retain_both_targets() {
        let source = concat!(
            "pub mod modules;\n",
            "pub mod types;\n",
            "use crate::modules::Api;\n",
            "use crate::types::Api;\n",
            "pub fn caller() { Api::target(); }\n",
        );
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"mixed-prefix\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", source)
            .file("src/modules.rs", "pub mod Api { pub fn target() {} }\n")
            .file(
                "src/types.rs",
                "pub struct Api;\nimpl Api { pub fn target() {} }\n",
            )
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let site = rust_shadow_site(source, "target");
        let tree = rust_shadow_tree(source);
        let query = BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: Some(&tree),
            site: &site,
            budget: Default::default(),
            cancellation: None,
        };

        let native = selected_rust_definition_shadow_result(&analyzer, query);
        let definitions = match native {
            RustDefinitionShadowResult::Complete {
                status,
                definitions,
                ..
            } => {
                assert_eq!(
                    status,
                    DefinitionLookupStatus::Ambiguous,
                    "a complete mixed prefix must remain ambiguous"
                );
                definitions
            }
            RustDefinitionShadowResult::Incomplete { definitions, .. } => definitions,
            other => panic!("mixed module/type prefix must retain native targets: {other:#?}"),
        };
        assert_eq!(
            definitions.len(),
            2,
            "native forward targets: {definitions:#?}"
        );
        assert!(definitions.iter().any(|unit| {
            unit.source().rel_path() == std::path::Path::new("src/modules.rs")
                && unit.identifier() == "target"
                && unit.owner_identifier() == Some("Api")
        }));
        assert!(definitions.iter().any(|unit| {
            unit.source().rel_path() == std::path::Path::new("src/types.rs")
                && unit.identifier() == "target"
                && unit.owner_identifier() == Some("Api")
        }));
    }

    #[test]
    fn production_structural_definition_ignores_unused_call_result_projection() {
        assert_rust_shadow_case(
            "pub fn target() {}\npub fn caller() { target(); }\n",
            "target",
            &[],
            DefinitionLookupStatus::Resolved,
            &["target"],
        );
    }

    #[test]
    fn production_usage_resolver_shadows_selected_rust_reverse_source_sites() {
        let consumer_source = concat!(
            "use crate::model::target as imported_target;\n",
            "pub fn caller() { imported_target(); }\n",
        );
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "pub mod model;\nmod consumer;\nmod excluded;\n",
            )
            .file("src/model.rs", "pub fn target() {}\n")
            .file("src/consumer.rs", consumer_source)
            .file(
                "src/excluded.rs",
                "use crate::model::target;\npub fn outside_scope() { target(); }\n",
            )
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let model = fixture.file("src/model.rs");
        let consumer = fixture.file("src/consumer.rs");
        let target = analyzer
            .declarations(&model)
            .into_iter()
            .find(|unit| unit.identifier() == "target")
            .expect("target declaration");
        let candidates: HashSet<_> = [consumer.clone()].into_iter().collect();
        let scope = UsageScanScope::new(&candidates);

        let native = selected_rust_usage_shadow_result(
            &analyzer,
            std::slice::from_ref(&target),
            &scope,
            100,
        );

        let RustUsageShadowResult::Complete {
            sites,
            capped: false,
        } = native
        else {
            panic!("the selected library-only Rust workspace reverse must be complete")
        };
        let expected_start = consumer_source
            .rfind("imported_target")
            .expect("consumer call");
        assert_eq!(
            sites,
            BTreeSet::from([RustUsageShadowSite {
                file: consumer,
                start_byte: expected_start,
                end_byte: expected_start + "imported_target".len(),
                enclosing: analyzer
                    .declarations(&fixture.file("src/consumer.rs"))
                    .into_iter()
                    .find(|unit| unit.identifier() == "caller")
                    .expect("caller declaration"),
            }])
        );
    }

    #[test]
    fn production_usage_resolver_shadows_selected_rust_reverse_chained_let_sites() {
        let consumer_source = concat!(
            "use crate::model::target as imported_target;\n",
            "pub fn caller() {\n",
            "    if let Some(value) = Some(1) && imported_target() {\n",
            "        imported_target();\n",
            "    }\n",
            "    while let Some(value) = Some(1) && imported_target() {\n",
            "        imported_target();\n",
            "        break;\n",
            "    }\n",
            "}\n",
        );
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "pub mod model;\nmod consumer;\n")
            .file("src/model.rs", "pub fn target() -> bool { true }\n")
            .file("src/consumer.rs", consumer_source)
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let model = fixture.file("src/model.rs");
        let consumer = fixture.file("src/consumer.rs");
        let target = analyzer
            .declarations(&model)
            .into_iter()
            .find(|unit| unit.identifier() == "target")
            .expect("target declaration");
        let candidates: HashSet<_> = [consumer.clone()].into_iter().collect();
        let scope = UsageScanScope::new(&candidates);

        let native = selected_rust_usage_shadow_result(
            &analyzer,
            std::slice::from_ref(&target),
            &scope,
            100,
        );

        let RustUsageShadowResult::Complete {
            sites,
            capped: false,
        } = native
        else {
            panic!("the selected chained-let reverse must be complete")
        };
        let caller = analyzer
            .declarations(&consumer)
            .into_iter()
            .find(|unit| unit.identifier() == "caller")
            .expect("caller declaration");
        let expected_sites = consumer_source
            .match_indices("imported_target")
            .skip(1)
            .map(|(start_byte, _)| RustUsageShadowSite {
                file: consumer.clone(),
                start_byte,
                end_byte: start_byte + "imported_target".len(),
                enclosing: caller.clone(),
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(sites, expected_sites);
    }

    #[test]
    fn production_rename_shadow_detects_counterfactual_lexical_capture() {
        let source = concat!(
            "pub fn target() {}\n",
            "pub fn caller() {\n",
            "    let renamed = || {};\n",
            "    target();\n",
            "}\n",
        );
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", source)
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let declaration_start = source.find("target").expect("target declaration");

        let error = crate::symbol_rename::rename_symbol(
            &analyzer,
            fixture.project(),
            file,
            RenameSelection::ByteOffset(declaration_start),
            "renamed",
        )
        .expect_err("production rename must reject lexical capture");
        assert_eq!(error.kind, "incomplete_analysis");
        assert!(error.message.contains("CapturedOrRebound"), "{error:#?}");
    }

    #[test]
    fn production_rename_shadow_proves_lexical_near_miss_safe_in_closed_library() {
        let source = concat!(
            "pub fn target() {}\n",
            "pub fn caller() {\n",
            "    {\n",
            "        let renamed = || {};\n",
            "        renamed();\n",
            "    }\n",
            "    target();\n",
            "}\n",
        );
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", source)
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let declaration_start = source.find("target").expect("target declaration");

        let result = crate::symbol_rename::rename_symbol(
            &analyzer,
            fixture.project(),
            file,
            RenameSelection::ByteOffset(declaration_start),
            "renamed",
        )
        .expect("production rename returns its non-mutating edits");
        let native =
            selected_rust_rename_shadow_result(&analyzer, fixture.project(), &result, "renamed");

        assert_eq!(native, RustRenameSafetyOutcome::Safe);
        let file = fixture.file("src/lib.rs");
        let target = analyzer
            .declarations(&file)
            .into_iter()
            .find(|unit| unit.identifier() == "target")
            .unwrap();
        let result = crate::symbol_rename::RenameProvider::rename(
            &super::super::native_rename::RustNativeRenameProvider,
            &analyzer,
            fixture.project(),
            &target,
            "renamed",
        )
        .expect("native-only preparation proves the near miss safe");
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].edits.len(), 2);
        for edit in &result.files[0].edits {
            assert_eq!(&source[edit.start_byte..edit.end_byte], "target");
            assert_eq!(edit.new_text, "renamed");
        }
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(
            native_rust_rename(&analyzer, fixture.project(), &target, "renamed", &cancelled)
                .is_err()
        );
    }

    #[test]
    fn native_rename_updates_import_targets_without_changing_aliases() {
        for (import, call, expected_edits) in [
            ("use crate::api::target;", "target", 2),
            ("use crate::api::target as local;", "local", 1),
        ] {
            let source = format!("pub mod api;\n{import}\npub fn caller() {{ {call}(); }}\n");
            let fixture = InlineTestProject::with_language(Language::Rust)
                .file("Cargo.toml", "[package]\nname = \"rename_import\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
                .file("src/lib.rs", source.clone())
                .file("src/api.rs", "pub fn target() {}\n")
                .build();
            let analyzer = RustAnalyzer::new(fixture.project_dyn());
            let target = analyzer
                .declarations(&fixture.file("src/api.rs"))
                .into_iter()
                .find(|unit| unit.identifier() == "target")
                .unwrap();
            let result = native_rust_rename(
                &analyzer,
                fixture.project(),
                &target,
                "renamed",
                &CancellationToken::new(),
            )
            .expect("native import references must produce a capture-safe rename");
            assert_eq!(result.files.len(), 2, "{result:?}");
            let imported = result
                .files
                .iter()
                .find(|file| file.file == fixture.file("src/lib.rs"))
                .unwrap();
            assert_eq!(imported.edits.len(), expected_edits, "{result:?}");
            for edit in &imported.edits {
                assert_eq!(&source[edit.start_byte..edit.end_byte], "target");
                assert_eq!(edit.new_text, "renamed");
            }
            let declaration = result
                .files
                .iter()
                .find(|file| file.file == fixture.file("src/api.rs"))
                .unwrap();
            assert_eq!(declaration.edits.len(), 1, "{result:?}");
        }
    }

    #[test]
    fn native_rename_preserves_qualified_prefixes_in_counterfactual_content() {
        let mut failures = Vec::new();
        for (label, source) in [
            (
                "module prefix",
                "pub mod inner { pub fn target() {} }\npub fn caller() { inner::target(); }\n",
            ),
            (
                "enum prefix",
                "pub enum Choice { target }\npub fn caller() { let _ = Choice::target; }\n",
            ),
            (
                "module declaration",
                "pub mod target { pub fn member() {} }\npub fn caller() { target::member(); }\n",
            ),
            (
                "enum declaration",
                "pub enum target { Member }\npub fn caller() { let _ = target::Member; }\n",
            ),
        ] {
            let fixture = InlineTestProject::with_language(Language::Rust)
                .file("Cargo.toml", "[package]\nname = \"rename_prefix\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
                .file("src/lib.rs", source)
                .build();
            let analyzer = RustAnalyzer::new(fixture.project_dyn());
            let target = analyzer
                .declarations(&fixture.file("src/lib.rs"))
                .into_iter()
                .find(|unit| unit.identifier() == "target")
                .expect("fixture target declaration");
            match native_rust_rename(
                &analyzer,
                fixture.project(),
                &target,
                "renamed",
                &CancellationToken::new(),
            ) {
                Ok(result) => {
                    assert_eq!(result.files.len(), 1, "{label}: {result:?}");
                    assert_eq!(result.files[0].edits.len(), 2, "{label}: {result:?}");
                    for edit in &result.files[0].edits {
                        assert_eq!(&source[edit.start_byte..edit.end_byte], "target");
                        assert_eq!(edit.new_text, "renamed");
                    }
                }
                Err(error) => failures.push((label, error)),
            }
        }
        assert!(
            failures.is_empty(),
            "qualified counterfactual rename failures: {failures:?}"
        );
    }

    // R4.6 (#3250): the native rename consumer must refuse rather than answer
    // from a reference inventory it cannot prove complete. A refusal is a
    // reviewable outcome; a rename built on partial references silently edits
    // some call sites and leaves others behind.
    #[test]
    fn native_rename_refuses_an_unprovable_reference_inventory() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"rename_refusal\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "pub fn target() {}\npub fn caller() { target(); }\nunknown_macro!(target);\n",
            )
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let target = analyzer
            .declarations(&fixture.file("src/lib.rs"))
            .into_iter()
            .find(|unit| unit.is_function() && unit.identifier() == "target")
            .expect("target declaration");
        let outcome = native_rust_rename(
            &analyzer,
            fixture.project(),
            &target,
            "renamed",
            &CancellationToken::new(),
        );
        let error = outcome.expect_err(
            "an unprovable reference inventory must refuse the rename, not edit a subset",
        );
        assert!(
            error.contains("incomplete or ambiguous"),
            "the refusal must name the evidence it lacked: {error}"
        );
    }

    #[test]
    fn production_rename_shadow_accepts_counterfactuals_based_on_prepared_overlay() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"rename_overlay\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "pub fn target() {}\n")
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        assert!(
            disk.all_declarations()
                .any(|unit| unit.identifier() == "target")
        );
        let source = "pub fn target() {}\npub fn caller() { target(); }\n";
        let overlay = Arc::new(crate::OverlayProject::new(fixture.project_dyn()));
        assert!(overlay.set(file.abs_path(), source.to_owned()));
        let request: Arc<dyn Project> = Arc::new(overlay.snapshot());
        let analyzer = disk.clone_with_project(Arc::clone(&request));
        assert!(
            analyzer
                .declarations(&file)
                .iter()
                .any(|unit| unit.identifier() == "caller")
        );
        let result = crate::symbol_rename::rename_symbol(
            &analyzer,
            request.as_ref(),
            file,
            RenameSelection::ByteOffset(source.find("target").expect("target declaration")),
            "renamed",
        )
        .expect("prepared overlay rename returns non-mutating edits");
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].edits.len(), 2);
        let native =
            selected_rust_rename_shadow_result(&analyzer, request.as_ref(), &result, "renamed");
        assert_eq!(
            native,
            RustRenameSafetyOutcome::Safe,
            "hypothetical renamed bytes must validate against their live base, not themselves"
        );
    }

    #[test]
    fn production_rename_shadow_proves_shared_explicit_target_safe() {
        let source = "pub fn target() {}\npub fn caller() { target(); }\n";
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                concat!(
                    "[package]\nname = \"shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
                    "[[bin]]\nname = \"same-source\"\npath = \"src/lib.rs\"\n",
                ),
            )
            .file("src/lib.rs", source)
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let declaration_start = source.find("target").expect("target declaration");

        let result = crate::symbol_rename::rename_symbol(
            &analyzer,
            fixture.project(),
            file,
            RenameSelection::ByteOffset(declaration_start),
            "renamed",
        )
        .expect("production rename returns its non-mutating edits");
        let native =
            selected_rust_rename_shadow_result(&analyzer, fixture.project(), &result, "renamed");

        assert_eq!(
            native,
            RustRenameSafetyOutcome::Safe,
            "enumerating every Cargo profile closes the shared-source counterfactual"
        );
    }

    /// A Rust source no Cargo target reaches does not leave the rename's
    /// source inventory open.
    ///
    /// `scratch.rs` is outside every Cargo target of `shadow`, so the
    /// workspace inventory gives it a `Detached` profile: it is its own
    /// single-file crate root with no dependency crates, and it declares no
    /// module of its own. It therefore cannot name `shadow::target` at all,
    /// the counterfactual it used to keep open is closed, and the rename
    /// certifies its two edits in `src/lib.rs`.
    #[test]
    fn production_rename_over_a_detached_rust_source_certifies_its_edits() {
        let source = "pub fn target() {}\npub fn caller() { target(); }\n";
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", source)
            .file("scratch.rs", "pub fn unrelated() {}\n")
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let declaration_start = source.find("target").expect("target declaration");

        let result = crate::symbol_rename::rename_symbol(
            &analyzer,
            fixture.project(),
            file.clone(),
            RenameSelection::ByteOffset(declaration_start),
            "renamed",
        )
        .expect("a detached source closes the rename's open inventory");
        assert_eq!(result.files.len(), 1, "{result:#?}");
        assert_eq!(result.files[0].file, file, "{result:#?}");
        assert_eq!(
            result.files[0]
                .edits
                .iter()
                .map(|edit| (edit.start_byte, edit.end_byte))
                .collect::<Vec<_>>(),
            vec![(7, 13), (37, 43)],
            "{result:#?}"
        );
    }

    #[test]
    fn production_rename_shadow_detects_named_import_over_wildcard_capture() {
        let source = concat!(
            "pub mod provider;\n",
            "pub mod named;\n",
            "use crate::provider::*;\n",
            "use crate::named::renamed;\n",
            "pub fn caller() { target(); }\n",
        );
        let provider_source = "pub fn target() {}\n";
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", source)
            .file("src/provider.rs", provider_source)
            .file("src/named.rs", "pub fn renamed() {}\n")
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let provider = fixture.file("src/provider.rs");
        let declaration_start = provider_source.find("target").expect("target declaration");

        let error = crate::symbol_rename::rename_symbol(
            &analyzer,
            fixture.project(),
            provider,
            RenameSelection::ByteOffset(declaration_start),
            "renamed",
        )
        .expect_err("production rename must reject named-import capture");
        assert_eq!(error.kind, "incomplete_analysis");
        assert!(error.message.contains("CapturedOrRebound"), "{error:#?}");
    }

    #[test]
    fn production_structural_resolver_shadows_local_absent_and_ambiguous_rust_points() {
        assert_rust_shadow_case(
            "pub fn target() -> usize { 1 }\npub fn caller() -> usize { target() }\n",
            "target",
            &[],
            DefinitionLookupStatus::Resolved,
            &["target"],
        );
        assert_rust_shadow_case(
            "pub fn caller() -> usize { missing() }\n",
            "missing",
            &[],
            DefinitionLookupStatus::NoDefinition,
            &[],
        );
        assert_rust_shadow_case(
            "#[link(name = \"native\")]\nunsafe extern \"C\" { fn foreign() -> usize; }\npub fn caller() -> usize { unsafe { foreign() } }\n",
            "foreign",
            &[],
            DefinitionLookupStatus::Resolved,
            &["foreign"],
        );
        assert_rust_shadow_case(
            "pub union Bits { word: u32, bytes: [u8; 4] }\npub fn read(value: Bits) -> u32 { unsafe { value.word } }\n",
            "Bits",
            &[],
            DefinitionLookupStatus::Resolved,
            &["Bits"],
        );
        assert_rust_shadow_case(
            "pub struct Unit;\npub fn make() -> Unit { Unit }\n",
            "Unit",
            &[],
            DefinitionLookupStatus::Resolved,
            &["Unit"],
        );
        assert_rust_shadow_case(
            "pub struct Tuple(pub u32);\npub fn make() -> Tuple { Tuple(1) }\n",
            "Tuple",
            &[],
            DefinitionLookupStatus::Resolved,
            &["Tuple"],
        );
        assert_rust_shadow_case(
            "pub fn target() -> usize { 1 }\npub fn generic<T, const N: usize>(value: T) -> usize { let _ = [0; N]; let _ = value; target() }\n",
            "target",
            &[],
            DefinitionLookupStatus::Resolved,
            &["target"],
        );
        assert_rust_shadow_case(
            "pub mod model;\npub use model::Tuple;\npub fn make() -> Tuple { Tuple(1) }\n",
            "Tuple",
            &[("src/model.rs", "pub struct Tuple(pub u32);\n")],
            DefinitionLookupStatus::Resolved,
            &["Tuple"],
        );
        assert_rust_shadow_case(
            "pub static READY: bool = true;\npub fn caller() { if READY {} }\n",
            "READY",
            &[],
            DefinitionLookupStatus::Resolved,
            &["_module_.READY"],
        );
        assert_rust_shadow_case(
            "pub static mut COUNTER: usize = 0;\npub fn reset() { unsafe { COUNTER = 1; } }\n",
            "COUNTER",
            &[],
            DefinitionLookupStatus::Resolved,
            &["_module_.COUNTER"],
        );
        assert_rust_shadow_case(
            "pub static LIMIT: usize = 4;\npub fn values() { let _ = 0..LIMIT; }\n",
            "LIMIT",
            &[],
            DefinitionLookupStatus::Resolved,
            &["_module_.LIMIT"],
        );
        assert_rust_shadow_case(
            concat!(
                "pub mod left;\n",
                "pub mod right;\n",
                "pub use left::*;\n",
                "pub use right::*;\n",
                "pub fn caller() -> usize { target() }\n",
            ),
            "target",
            &[
                ("src/left.rs", "pub fn target() -> usize { 1 }\n"),
                ("src/right.rs", "pub fn target() -> usize { 2 }\n"),
            ],
            DefinitionLookupStatus::Ambiguous,
            &["target", "target"],
        );
    }

    #[test]
    fn production_native_shadow_fails_closed_for_unprojectable_local_items() {
        let source = "pub fn caller() -> usize { fn local() -> usize { 1 } local() }\n";
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", source)
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let site = rust_shadow_site(source, "local");
        let tree = rust_shadow_tree(source);
        let query = BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: Some(&tree),
            site: &site,
            budget: Default::default(),
            cancellation: None,
        };

        let native = selected_rust_definition_shadow_result(&analyzer, query);
        let RustDefinitionShadowResult::Incomplete {
            definitions,
            completion,
            ..
        } = native
        else {
            panic!("local item must remain an explicit native boundary: {native:#?}")
        };
        assert!(definitions.is_empty());
        assert_ne!(completion, ResolutionCompletion::Complete);
        // Items declared in a block expression are in scope throughout the
        // block (Rust reference, block expressions and items), so `local()`
        // does have a definition and an answer of "none" would be an absence
        // rather than a correct negative. The shadow comparator above still
        // holds the whole selection to the producer's gap, because the
        // whole-workspace graph has no node for a block-local declaration and
        // that incompleteness is the graph's to hear.
        //
        // The production point route answers the definition. It found the
        // binding, and since 2026-09-11 (`b3836b21f`) the item carries an
        // out-of-graph canonical source declaration, so the projection the gap
        // said was missing exists and the route discharges the gap against it
        // (`rust::native_points`, `adapt_definition_answer`). This expectation
        // was `Incomplete` with an `incomplete_binding` diagnostic, which
        // described the state before that declaration was published: the route
        // could then say only that it had found the binding and could not
        // project it, and before that it failed the whole operation with
        // `Unavailable(MissingDefinitionUnit)`.
        let BoundedResolution::Complete { value, .. } =
            RustSupport.resolve_definition_bounded(query)
        else {
            panic!("uncancelled local-item query must retain its native boundary")
        };
        assert_eq!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");
        assert!(value.definitions.is_empty(), "{value:#?}");
        assert_eq!(
            value
                .lexical_definition
                .as_ref()
                .map(|definition| (definition.identifier.as_str(), definition.kind)),
            Some((
                "local",
                brokk_bifrost_core::analyzer::model::DeclarationKind::BlockLocalItem
            )),
            "{value:#?}"
        );
    }
    #[test]
    fn production_call_relations_preserve_exact_and_ambiguous_rust_calls() {
        let source = concat!(
            "pub mod left;\n",
            "pub mod right;\n",
            "pub use left::*;\n",
            "pub use right::*;\n",
            "pub fn exact(value: usize) -> usize { value }\n",
            "pub fn caller() -> usize { exact(1) + target(2) }\n",
        );
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", source)
            .file(
                "src/left.rs",
                "pub fn target(value: usize) -> usize { value }\n",
            )
            .file(
                "src/right.rs",
                "pub fn target(value: usize) -> usize { value }\n",
            )
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let caller = analyzer
            .declarations(&file)
            .into_iter()
            .find(|unit| unit.identifier() == "caller")
            .expect("caller declaration");
        let scope = AnalyzerQueryScope::new(&analyzer);
        let outgoing = CallRelationService::outgoing(&analyzer, scope.token(), &caller, 16);
        assert_eq!(outgoing.sites.len(), 3, "{outgoing:#?}");
        assert!(!outgoing.truncated && !outgoing.cancelled, "{outgoing:#?}");
        assert_eq!(
            outgoing
                .sites
                .iter()
                .filter(|site| site.proof == UsageProof::Proven)
                .count(),
            1
        );
        assert_eq!(
            outgoing
                .sites
                .iter()
                .filter(|site| site.proof == UsageProof::Unproven)
                .count(),
            2
        );
        assert!(outgoing.sites.iter().all(|site| {
            site.kind == CallSyntaxKind::Function
                && site.receiver.is_none()
                && site.arguments.len() == 1
                && site.arguments[0].position == Some(0)
                && site.arguments[0].name.is_none()
                && site.arguments[0].formal_index.is_none()
                && site.arguments[0].formal_name.is_none()
                && !site.arguments[0].variadic
                && !site.arguments[0].spread
        }));
        assert!(outgoing.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == crate::analyzer::usages::CallRelationDiagnosticCode::TargetsAmbiguous
                && diagnostic.reason_kind.as_deref() == Some("native_call_targets_ambiguous")
        }));

        let exact = analyzer
            .declarations(&file)
            .into_iter()
            .find(|unit| unit.identifier() == "exact")
            .expect("exact target declaration");
        let left_target = analyzer
            .declarations(&fixture.file("src/left.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "target")
            .expect("ambiguous left target declaration");
        let incoming_exact =
            CallRelationService::incoming(&analyzer, scope.token(), &exact, 16, 16);
        assert_eq!(incoming_exact.sites.len(), 1, "{incoming_exact:#?}");
        assert_eq!(incoming_exact.sites[0].caller, caller);
        assert_eq!(incoming_exact.sites[0].proof, UsageProof::Proven);
        assert_eq!(incoming_exact.sites[0].kind, CallSyntaxKind::Function);
        assert!(incoming_exact.sites[0].receiver.is_none());
        assert_eq!(incoming_exact.sites[0].arguments.len(), 1);

        let incoming_ambiguous =
            CallRelationService::incoming(&analyzer, scope.token(), &left_target, 16, 16);
        assert_eq!(incoming_ambiguous.sites.len(), 1, "{incoming_ambiguous:#?}");
        assert_eq!(incoming_ambiguous.sites[0].caller, caller);
        assert_eq!(incoming_ambiguous.sites[0].proof, UsageProof::Unproven);
    }

    #[test]
    fn production_binding_world_keeps_local_calls_proven_with_unrelated_gaps() {
        let mut incomplete_local_calls = Vec::new();
        for extra_source in [
            "",
            "fn unrelated() { external::missing(); }\n",
            "use external::Unknown;\nfn unrelated(_: Unknown) {}\n",
            "#[cfg(test)] mod tests { #[test] fn check() { super::target(); } }\n",
            "fn methods(value: Unknown) { value.method(); value.method::<usize>(); }\n",
            "fn indirect(function: fn(), pair: (fn(),), values: [fn(); 1]) { (function)(); pair.0(); values[0](); }\n",
            "struct Subject;\nimpl Subject { fn method(&self) {} }\n",
            "fn generic<T>(_: T) {}\n",
            "fn pattern(pair: (usize, usize)) { let (left, right) = pair; }\n",
        ] {
            let source = format!("{extra_source}fn target() {{}}\nfn caller() {{ target(); }}\n");
            let fixture = InlineTestProject::with_language(Language::Rust)
                .file(
                    "Cargo.toml",
                    "[package]\nname = \"shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
                )
                .file("src/lib.rs", &source)
                .build();
            let analyzer = RustAnalyzer::new(fixture.project_dyn());
            let target = analyzer
                .all_declarations()
                .find(|unit| unit.identifier() == "target")
                .expect("local target declaration");
            let cancellation = CancellationToken::default();
            let result = selected_rust_binding_world(
                &analyzer,
                analyzer.inner.selected_workspace_snapshots().as_ref(),
                RustBindingTargetProof::Current(&target),
                &[],
                Vec::new(),
                &cancellation,
            );
            let RustBindingWorldOutcome::Ready(world) = result else {
                panic!("local binding world must be available: {result:?}")
            };
            if extra_source.is_empty() {
                assert_eq!(
                    world.completion(),
                    &ResolutionCompletion::Complete,
                    "unused call-result projections must not weaken the binding world"
                );
            }
            let call_start = source.rfind("target()").expect("local call");
            let site = world
                .sites()
                .iter()
                .find(|site| {
                    site.metadata()
                        .is_some_and(|metadata| metadata.start_byte() == call_start)
                })
                .expect("local call has a structured binding site");
            assert_eq!(site.definitions(), std::slice::from_ref(world.target()));
            if site.completion() != &ResolutionCompletion::Complete {
                incomplete_local_calls.push((extra_source, site.clone()));
            }
        }
        assert!(
            incomplete_local_calls.is_empty(),
            "unrelated input must not weaken a local declaration binding: {incomplete_local_calls:#?}"
        );
    }

    fn partition_binding_world(source: &str) -> SelectedRustBindingWorld {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"partition\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", source)
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let target = analyzer
            .all_declarations()
            .find(|unit| unit.identifier() == "target")
            .expect("local target declaration");
        let result = selected_rust_binding_world(
            &analyzer,
            analyzer.inner.selected_workspace_snapshots().as_ref(),
            RustBindingTargetProof::Current(&target),
            &[],
            Vec::new(),
            &CancellationToken::default(),
        );
        let RustBindingWorldOutcome::Ready(world) = result else {
            panic!("local binding world must be available: {result:?}")
        };
        world
    }

    fn assert_unrelated_item_keeps_local_call_proven(extra_source: &str) {
        let source = format!("{extra_source}\nfn target() {{}}\nfn caller() {{ target(); }}\n");
        let world = partition_binding_world(&source);
        let call_start = source.rfind("target()").expect("local call");
        let site = world
            .sites()
            .iter()
            .find(|site| {
                site.metadata()
                    .is_some_and(|metadata| metadata.start_byte() == call_start)
            })
            .expect("local call has a structured binding site");
        assert_eq!(site.definitions(), std::slice::from_ref(world.target()));
        assert_eq!(
            site.completion(),
            &ResolutionCompletion::Complete,
            "unrelated item must not weaken the local call: {extra_source}"
        );
    }

    #[test]
    fn partition_2767_serde_helper_enum_keeps_local_call_proven() {
        assert_unrelated_item_keeps_local_call_proven(
            "#[derive(serde::Serialize)]\n#[serde(rename_all = \"snake_case\")]\nenum Mode { Exact }",
        );
    }

    #[test]
    fn partition_2767_serde_helper_struct_keeps_local_call_proven() {
        assert_unrelated_item_keeps_local_call_proven(
            "#[derive(serde::Deserialize)]\n#[serde(deny_unknown_fields)]\nstruct Params { value: bool }",
        );
    }

    #[test]
    fn partition_2767_local_import_alias_keeps_sibling_call_proven() {
        assert_unrelated_item_keeps_local_call_proven(
            "enum Mode { Exact }\nfn unrelated() { use Mode as Alias; }",
        );
    }

    #[test]
    fn partition_2767_local_macro_keeps_local_call_proven() {
        assert_unrelated_item_keeps_local_call_proven(
            "fn unrelated() { macro_rules! value { () => { 1 }; } let _ = value!(); }",
        );
    }

    #[test]
    fn partition_2767_malformed_block_keeps_local_call_proven() {
        assert_unrelated_item_keeps_local_call_proven("fn unrelated() { let = ; }");
    }

    #[test]
    fn partition_2767_malformed_scope_keeps_affected_call_incomplete() {
        let source = "fn target() {}\nfn caller() { let broken = ; target(); }\n";
        let world = partition_binding_world(source);
        assert_ne!(world.completion(), &ResolutionCompletion::Complete);
        assert_eq!(world.sites().len(), 1);
        let site = &world.sites()[0];
        assert_eq!(site.definitions(), std::slice::from_ref(world.target()));
        assert_ne!(site.completion(), &ResolutionCompletion::Complete);
    }

    #[test]
    fn partition_2767_unknown_attribute_boundaries_remain_incomplete() {
        for extra in [
            "#[serde(rename_all = \"snake_case\")] enum Mode { Exact }",
            "#[derive(other::Serialize)] #[serde(rename_all = \"snake_case\")] enum Mode { Exact }",
            "#[derive(serde::Serialize)] #[other::transform] struct Params;",
            "mod serde {} #[derive(serde::Serialize)] #[serde(rename_all = \"snake_case\")] enum Mode { Exact }",
            "extern crate other as serde; #[derive(serde::Serialize)] #[serde(rename_all = \"snake_case\")] enum Mode { Exact }",
        ] {
            let world = partition_binding_world(&format!(
                "{extra}\nfn target() {{}}\nfn caller() {{ target(); }}\n"
            ));
            let sites = world
                .sites()
                .iter()
                .filter(|site| site.definitions().contains(world.target()))
                .collect::<Vec<_>>();
            assert_eq!(sites.len(), 1, "{extra}");
            assert_ne!(
                sites[0].completion(),
                &ResolutionCompletion::Complete,
                "{extra}"
            );
        }
    }

    /// A `serde` helper whose bare derive the file cannot show to be serde's
    /// (here the only `use serde::Serialize` is cfg-inactive, so the name is
    /// unbound in the file) no longer skips the item. The item is kept, and
    /// the open question is its own binder: `Mode` and the paths that reach
    /// it stay incomplete until the crate route proves the derive, and a call
    /// to a locally declared function beside it is exact, since an item-
    /// position expansion cannot rebind a name the module declares without a
    /// duplicate-definition error.
    #[test]
    fn partition_2767_undecided_serde_helper_opens_only_its_own_item() {
        let world = partition_binding_world(
            "#[cfg(any())] use serde::Serialize; #[derive(Serialize)] #[serde(rename_all = \"snake_case\")] enum Mode { Exact }\nfn target() {}\nfn caller() { target(); }\n",
        );
        let sites = world
            .sites()
            .iter()
            .filter(|site| site.definitions().contains(world.target()))
            .collect::<Vec<_>>();
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].completion(), &ResolutionCompletion::Complete);
    }

    /// A local import the producer cannot state keeps the scope's binder set
    /// unknown, so a call in that scope stays incomplete. `use Mode as Alias;`
    /// was the fixture until single-segment imports were lowered exactly
    /// (2026-09-21): the producer now states that `Alias` binds the path root
    /// `Mode`, which cannot shadow `target`, so that call is honestly Complete.
    /// The one import shape still unstatable is the bare glob `use *;`, which
    /// names no module to glob; it keeps the partition's contract testable.
    #[test]
    fn partition_2767_local_import_keeps_affected_call_incomplete() {
        let world = partition_binding_world(
            "enum Mode { Exact }\nfn target() {}\nfn caller() { use *; target(); }\n",
        );
        assert_eq!(world.sites().len(), 1);
        assert_ne!(
            world.sites()[0].completion(),
            &ResolutionCompletion::Complete
        );
    }

    #[test]
    #[ignore = "finds real bug: function-local macro enumeration retains two UnsupportedSemantic reasons instead of Complete (#2767). Owner: selected_rust_workspace_binding_world"]
    fn partition_2767_local_macro_enumeration_is_complete() {
        let world = partition_binding_world(
            "fn unrelated() { macro_rules! value { () => { 1 }; } let _ = value!(); }\nfn target() {}\nfn caller() { target(); }\n",
        );
        assert_eq!(world.completion(), &ResolutionCompletion::Complete);
    }

    #[test]
    fn partition_2767_eight_reference_bindings() {
        let files = [
            (
                "src/lib.rs",
                "mod missing_tests; mod mcp_diff; mod mcp_registry; mod scoped_project; mod searchtools_service;\n",
            ),
            (
                "src/missing_tests.rs",
                r#"
use serde::Serialize;
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum Mode { Exact }
fn scan_target() {}
fn caller() { scan_target(); }
fn unrelated() { macro_rules! value { () => { 1 }; } let _ = value!(); }
fn alias_scope() { use Mode as Alias; }
"#,
            ),
            ("src/mcp_diff.rs", "pub fn diff_tool_descriptors() {}\n"),
            (
                "src/mcp_registry.rs",
                r#"
fn discovery_instructions() {}
fn discover() { discovery_instructions(); }
fn registry() { crate::mcp_diff::diff_tool_descriptors(); }
"#,
            ),
            (
                "src/scoped_project.rs",
                r#"
use crate::searchtools_service::SearchToolsService;
fn caller() { SearchToolsService::tool_is_workspace_independent(); }
"#,
            ),
            (
                "src/searchtools_service.rs",
                r#"
use serde::Deserialize;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Params { value: bool }
pub struct SearchToolsService;
impl SearchToolsService {
    pub fn tool_is_workspace_independent() {}
    fn call_tool_output_with_transport_queue_wait_inner(&self) {}
    fn call_2583(&self) { self.call_tool_output_with_transport_queue_wait_inner(); }
    fn call_2597(&self) { self.call_tool_output_with_transport_queue_wait_inner(); }
    fn call_2623(&self) { self.call_tool_output_with_transport_queue_wait_inner(); }
    fn call_2645(&self) { self.call_tool_output_with_transport_queue_wait_inner(); }
}
"#,
            ),
        ];
        let mut project = InlineTestProject::with_language(Language::Rust).file(
            "Cargo.toml",
            "[package]\nname = \"partition\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        );
        for (path, source) in files {
            project = project.file(path, source);
        }
        let fixture = project.build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let mut proven = 0;
        for (name, count) in [
            ("scan_target", 1),
            ("diff_tool_descriptors", 1),
            ("discovery_instructions", 1),
            ("tool_is_workspace_independent", 1),
            ("call_tool_output_with_transport_queue_wait_inner", 4),
        ] {
            let target = analyzer
                .all_declarations()
                .find(|unit| unit.identifier() == name)
                .unwrap();
            let RustBindingWorldOutcome::Ready(world) = selected_rust_binding_world(
                &analyzer,
                analyzer.inner.selected_workspace_snapshots().as_ref(),
                RustBindingTargetProof::Current(&target),
                &[],
                Vec::new(),
                &CancellationToken::default(),
            ) else {
                panic!("fixture reverse world must be ready for {name}");
            };
            let sites = world
                .sites()
                .iter()
                .filter(|site| site.definitions().contains(world.target()))
                .collect::<Vec<_>>();
            assert_eq!(sites.len(), count, "{name}");
            for site in sites {
                assert_eq!(
                    site.definitions(),
                    std::slice::from_ref(world.target()),
                    "{name}"
                );
                assert_eq!(site.completion(), &ResolutionCompletion::Complete, "{name}");
                proven += 1;
            }
        }
        assert_eq!(proven, 8);
    }

    #[test]
    fn selected_shadow_barrel_import_has_one_canonical_row() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"barrel\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "\nmod service;\npub use service::Foo as Bar;\nmod consumer;\n",
            )
            .file("src/service.rs", "pub struct Foo;\n")
            .file(
                "src/consumer.rs",
                "use crate::Bar;\npub fn consume(_: Bar) {}\n",
            )
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let target = analyzer
            .all_declarations()
            .find(|unit| unit.identifier() == "Foo")
            .expect("barrel target");
        let index =
            match build_rust_selected_reference_index(&analyzer, &CancellationToken::default()) {
                RustSelectedReferenceIndexOutcome::Ready(index) => index,
                RustSelectedReferenceIndexOutcome::Unavailable(detail)
                | RustSelectedReferenceIndexOutcome::Stale(detail)
                | RustSelectedReferenceIndexOutcome::StoreError(detail) => panic!("{detail}"),
                RustSelectedReferenceIndexOutcome::Cancelled => panic!("unexpected cancellation"),
            };
        let inverse = index.inverse_for(&target);
        let consumer = inverse
            .edges
            .iter()
            .find(|edge| {
                edge.usage_kind == UsageHitKind::Import
                    && edge.site.file == fixture.file("src/consumer.rs")
            })
            .expect("consumer import");
        assert_eq!(
            consumer.reference_kind,
            Some(crate::analyzer::usages::ReferenceKind::TypeReference)
        );
        assert_eq!(consumer.proof, UsageProof::Proven);
        let imports = inverse
            .edges
            .iter()
            .filter(|edge| edge.usage_kind == UsageHitKind::Import)
            .map(|edge| {
                (
                    edge.site.file.clone(),
                    edge.site.range.start_byte,
                    edge.site.range.end_byte,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            imports,
            vec![
                (fixture.file("src/consumer.rs"), 11, 14),
                (fixture.file("src/lib.rs"), 31, 34),
            ],
            "{inverse:#?}"
        );
    }

    #[test]
    fn production_import_reference_locations_follow_grouped_overlay_identity() {
        let original = "pub mod model;\nuse crate::model::{target as chosen, target as other};\npub fn caller() { chosen(); other(); }\n";
        let replacement = "// shifted import locations\npub mod model;\nuse crate::model::{replacement as chosen, replacement as other};\npub fn caller() { chosen(); other(); }\n";
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"import_sites\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", original)
            .file(
                "src/model.rs",
                "pub fn target() {}\npub fn replacement() {}\n",
            )
            .build();
        let db_path = fixture.root().join("selected-import-overlays.db");
        let open = || {
            let project = fixture.project_dyn();
            let store =
                Arc::new(crate::analyzer::store::AnalyzerStore::open_persistent(&db_path).unwrap());
            let context = crate::analyzer::tree_sitter_analyzer::revision_image_store_context(
                project.as_ref(),
                store,
            );
            RustAnalyzer::new_with_config_store_context(
                project,
                crate::AnalyzerConfig::default(),
                context,
                None,
            )
            .unwrap()
        };
        let disk = open();
        let file = fixture.file("src/lib.rs");
        let mut prepared = Vec::new();
        for source in [original, replacement] {
            let overlay = Arc::new(crate::OverlayProject::new(fixture.project_dyn()));
            assert!(overlay.set(file.abs_path(), source.to_owned()));
            let analyzer = disk.clone_with_project(Arc::new(overlay.snapshot()));
            assert!(!analyzer.declarations(&file).is_empty());
            prepared.push(analyzer);
        }
        let check = |analyzer: &RustAnalyzer, source: &str, name: &str| {
            let target = analyzer
                .all_declarations()
                .find(|unit| unit.identifier() == name)
                .unwrap();
            let outcome =
                build_rust_selected_reference_index(analyzer, &CancellationToken::default());
            let index = match outcome {
                RustSelectedReferenceIndexOutcome::Ready(index) => index,
                RustSelectedReferenceIndexOutcome::Unavailable(detail)
                | RustSelectedReferenceIndexOutcome::Stale(detail)
                | RustSelectedReferenceIndexOutcome::StoreError(detail) => {
                    panic!("import index: {detail}")
                }
                RustSelectedReferenceIndexOutcome::Cancelled => panic!("unexpected cancellation"),
            };
            let inverse = index.inverse_for(&target);
            let actual = inverse
                .edges
                .iter()
                .filter(|edge| edge.usage_kind == UsageHitKind::Import && edge.site.file == file)
                .map(|edge| (edge.site.range.start_byte, edge.site.range.end_byte))
                .collect::<BTreeSet<_>>();
            // The path's target token only. An `as` alias is the new name the
            // use declaration binds, not a second naming of the imported item
            // (the Rust Reference, use declarations), so `chosen` and `other`
            // are declaration sites rather than import edges.
            let expected = source
                .match_indices(name)
                .filter(|(start, _)| *start < source.find("pub fn caller").unwrap())
                .map(|(start, _)| (start, start + name.len()))
                .collect::<BTreeSet<_>>();
            assert_eq!(actual, expected, "{inverse:?}");
        };
        for (analyzer, source, name) in [
            (&prepared[0], original, "target"),
            (&prepared[1], replacement, "replacement"),
            (&prepared[0], original, "target"),
        ] {
            check(analyzer, source, name);
        }
        drop(prepared);
        drop(disk);
        let reopened = open();
        for (source, name) in [
            (original, "target"),
            (replacement, "replacement"),
            (original, "target"),
        ] {
            let overlay = Arc::new(crate::OverlayProject::new(fixture.project_dyn()));
            assert!(overlay.set(file.abs_path(), source.to_owned()));
            let analyzer = reopened.clone_with_project(Arc::new(overlay.snapshot()));
            assert!(!analyzer.declarations(&file).is_empty());
            assert!(
                analyzer
                    .inner
                    .cached_canonical_source_state(&file, source)
                    .is_none(),
                "reopened overlays must exercise persisted content, not a retained producer arena"
            );
            let snapshots = analyzer.inner.selected_workspace_snapshots();
            let SelectedResolutionOverlayInputsOutcome::Ready {
                content_mounts: mounts,
                ..
            } = analyzer
                .inner
                .selected_rust_resolution_overlay_inputs(
                    snapshots.as_ref(),
                    &CancellationToken::default(),
                )
                .unwrap()
            else {
                panic!("reopened overlay publication must be ready");
            };
            assert_eq!(mounts.len(), 1);
            check(&analyzer, source, name);
        }
    }

    #[test]
    fn production_reference_index_covers_trait_impl_bodies_with_local_proof() {
        use crate::analyzer::structural::EdgeAxis;

        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"local_proof\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                concat!(
                    "fn target() {}\n",
                    "struct Service;\n",
                    "trait Contract { fn skipped(&self); }\n",
                    "impl Contract for Service { fn skipped(&self) { target(); } }\n",
                    "fn caller() { target(); }\n",
                ),
            )
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let target = analyzer
            .all_declarations()
            .find(|unit| unit.identifier() == "target")
            .expect("local target declaration");
        let declarations = analyzer.all_declarations().collect::<Vec<_>>();
        let contract = declarations
            .iter()
            .find(|unit| unit.identifier() == "Contract")
            .cloned()
            .expect("trait declaration");
        let service = declarations
            .iter()
            .find(|unit| unit.identifier() == "Service")
            .cloned()
            .expect("impl subject declaration");
        let trait_skipped = declarations
            .iter()
            .find(|unit| {
                unit.identifier() == "skipped" && unit.owner_identifier() == Some("Contract")
            })
            .cloned()
            .expect("retained trait signature declaration");
        assert_eq!(analyzer.parent_of(&trait_skipped), Some(contract.clone()));
        let skipped = declarations
            .iter()
            .find(|unit| {
                unit.identifier() == "skipped" && unit.owner_identifier() == Some("Service")
            })
            .cloned()
            .expect("actual impl method declaration");
        assert_eq!(analyzer.parent_of(&skipped), Some(service));
        assert_ne!(trait_skipped.declaration_id(), skipped.declaration_id());
        let RustSelectedReferenceIndexOutcome::Ready(index) =
            build_rust_selected_reference_index(&analyzer, &CancellationToken::default())
        else {
            panic!("selected reference index must be available")
        };
        assert!(index.covers_target(&target));
        assert!(index.covers_target(&trait_skipped));
        assert!(index.covers_target(&skipped));
        let inverse = index.inverse_for(&target);
        assert!(inverse.covers(EdgeAxis::ProofAttribution));
        // The body inventory is closed. Abstract trait Self uncertainty belongs
        // to its typed frontier rather than this unrelated inverse projection.
        assert!(inverse.covers(EdgeAxis::InverseProjection), "{inverse:?}");
        assert_eq!(inverse.edges.len(), 2, "{inverse:?}");
        assert!(
            inverse
                .edges
                .iter()
                .all(|edge| edge.proof == UsageProof::Proven)
        );
        assert_eq!(
            inverse
                .edges
                .iter()
                .map(|edge| edge.site.enclosing.as_ref().map(CodeUnit::identifier))
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([Some("caller"), Some("skipped")])
        );
        assert!(!matches!(
            index.inverse_for(&skipped).completeness,
            EdgeCompleteness::Incomplete { reasons }
                if reasons.contains(&EdgeIncompleteReason::InverseIndexTargetUncovered)
        ));
        let files = [fixture.file("src/lib.rs")].into_iter().collect();
        let reverse = selected_rust_usage_shadow_result(
            &analyzer,
            std::slice::from_ref(&target),
            &UsageScanScope::new(&files),
            100,
        );
        let RustUsageShadowResult::Complete {
            sites,
            capped: false,
        } = reverse
        else {
            panic!("direct reverse must include the enumerated impl caller: {reverse:?}")
        };
        assert_eq!(sites.len(), 2, "{sites:?}");
        assert_eq!(
            sites
                .iter()
                .map(|site| site.enclosing.identifier())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["caller", "skipped"])
        );
    }

    #[test]
    fn production_reference_index_retains_inherent_callables_without_free_binders() {
        use crate::analyzer::structural::EdgeAxis;

        let source = concat!(
            "fn target() {}\n",
            "fn method() {}\n",
            "pub struct Service;\n",
            "impl Service { pub fn method(&self) { target(); method(); } }\n",
            "impl Service { pub fn associated() { target(); } }\n",
            "fn caller() { target(); }\n",
        );
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"inherent_bodies\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", source)
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let declarations = analyzer.all_declarations().collect::<Vec<_>>();
        let declaration = |name, start_text| {
            let start = source.find(start_text).expect("unique declaration prefix");
            declarations
                .iter()
                .find(|unit| {
                    unit.identifier() == name
                        && analyzer
                            .ranges(unit)
                            .iter()
                            .any(|range| range.start_byte == start)
                })
                .cloned()
                .expect("exact parser declaration")
        };
        let target = declaration("target", "fn target()");
        let free_method = declaration("method", "fn method()");
        let method = declaration("method", "pub fn method(");
        let associated = declaration("associated", "pub fn associated()");
        let caller = declaration("caller", "fn caller()");

        let RustSelectedReferenceIndexOutcome::Ready(index) =
            build_rust_selected_reference_index(&analyzer, &CancellationToken::default())
        else {
            panic!("inherent body reference index must be available")
        };
        for unit in [&target, &free_method, &method, &associated, &caller] {
            assert!(
                index.covers_target(unit),
                "missing exact native crosswalk for {unit:?}"
            );
        }
        let inverse = index.inverse_for(&target);
        assert!(inverse.covers(EdgeAxis::ProofAttribution));
        assert!(
            inverse.covers(EdgeAxis::InverseProjection),
            "supported inherent bodies retain complete reference inventory"
        );
        let owners = inverse
            .edges
            .iter()
            .map(|edge| {
                assert_eq!(edge.target, target);
                assert_eq!(edge.proof, UsageProof::Proven);
                assert_eq!(edge.usage_kind, UsageHitKind::Reference);
                assert_eq!(edge.site.file, file);
                assert_eq!(
                    &source[edge.site.range.start_byte..edge.site.range.end_byte],
                    "target"
                );
                edge.site
                    .enclosing
                    .clone()
                    .expect("body call has an exact callable owner")
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(inverse.edges.len(), 3, "{inverse:?}");
        assert_eq!(owners, BTreeSet::from([method.clone(), associated, caller]));

        let free_inverse = index.inverse_for(&free_method);
        assert_eq!(free_inverse.edges.len(), 1, "{free_inverse:?}");
        let edge = &free_inverse.edges[0];
        assert_eq!(edge.proof, UsageProof::Proven);
        assert_eq!(edge.site.enclosing.as_ref(), Some(&method));
        assert_eq!(
            edge.site.range.start_byte,
            source.find("method();").expect("free call in method body")
        );
        assert!(
            index.inverse_for(&method).edges.is_empty(),
            "method() inside a method body must not become an implicit self call"
        );
    }

    #[test]
    fn production_reference_index_keeps_root_qualified_terminal_edges_exact() {
        use crate::analyzer::structural::EdgeAxis;

        let source = concat!(
            "pub fn target() {}\n",
            "pub mod api { pub fn target() {} }\n",
            "pub fn caller() { crate::api::target(); target(); }\n",
        );
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"root_reference\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", source)
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let declarations = analyzer.all_declarations().collect::<Vec<_>>();
        let target_declaration_starts = source
            .match_indices("pub fn target() {}")
            .map(|(start, _)| start)
            .collect::<Vec<_>>();
        assert_eq!(target_declaration_starts.len(), 2);
        let root_target = declarations
            .iter()
            .find(|unit| {
                unit.identifier() == "target"
                    && analyzer
                        .ranges(unit)
                        .iter()
                        .any(|range| range.start_byte == target_declaration_starts[0])
            })
            .cloned()
            .expect("root target declaration");
        let api_target = declarations
            .iter()
            .find(|unit| {
                unit.identifier() == "target"
                    && analyzer
                        .ranges(unit)
                        .iter()
                        .any(|range| range.start_byte == target_declaration_starts[1])
            })
            .cloned()
            .expect("api target declaration");
        let caller = declarations
            .iter()
            .find(|unit| unit.identifier() == "caller")
            .cloned()
            .expect("caller declaration");
        let RustSelectedReferenceIndexOutcome::Ready(index) =
            build_rust_selected_reference_index(&analyzer, &CancellationToken::default())
        else {
            panic!("selected reference index must be available")
        };

        let qualified_start = source
            .find("crate::api::target()")
            .expect("qualified terminal call")
            + "crate::api::".len();
        let plain_start = source.rfind("target();").expect("plain terminal call");
        let assert_terminal_edge =
            |inverse: &EdgeDerivationResult, target: &CodeUnit, expected_start: usize| {
                assert!(inverse.covers(EdgeAxis::ProofAttribution));
                assert_eq!(inverse.edges.len(), 1, "{inverse:?}");
                let edge = &inverse.edges[0];
                assert_eq!(edge.target, *target);
                assert_eq!(edge.site.file, file);
                assert_eq!(edge.site.range.start_byte, expected_start);
                assert_eq!(edge.site.range.end_byte, expected_start + "target".len());
                assert_eq!(edge.site.enclosing.as_ref(), Some(&caller));
                assert_eq!(edge.proof, UsageProof::Proven);
                assert_eq!(edge.usage_kind, UsageHitKind::Reference);
                assert_ne!(edge.usage_kind, UsageHitKind::Import);
            };

        let qualified = index.inverse_for(&api_target);
        assert_terminal_edge(&qualified, &api_target, qualified_start);
        let plain = index.inverse_for(&root_target);
        assert_terminal_edge(&plain, &root_target, plain_start);
        assert!(
            qualified
                .edges
                .iter()
                .all(|edge| edge.site.enclosing.as_ref() == Some(&caller))
        );
        assert!(
            plain
                .edges
                .iter()
                .all(|edge| edge.site.enclosing.as_ref() == Some(&caller))
        );
    }

    #[test]
    fn production_reference_index_answers_an_unprepared_overlay_from_its_buffer() {
        let source = "pub fn target() {}\npub fn caller() { target(); }\n";
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname = \"overlay_preflight\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
            .file("src/lib.rs", source)
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        assert!(
            disk.all_declarations()
                .any(|unit| unit.identifier() == "caller")
        );
        let overlay = Arc::new(crate::OverlayProject::new(fixture.project_dyn()));
        assert!(overlay.set(
            file.abs_path(),
            "pub fn target() {}\npub fn caller() {}\n".to_owned()
        ));
        let request_project: Arc<dyn Project> = Arc::new(overlay.snapshot());
        let analyzer = disk.clone_with_project(request_project);
        // R6.4: the first call over an open buffer must answer. The selected
        // overlay inputs now fetch the buffer's file state, so the index is
        // built from the buffer's own facts rather than refused for want of a
        // prior hydrating call. What must never happen is answering from the
        // disk row: the buffer deletes the call, so `target` has no callers.
        let RustSelectedReferenceIndexOutcome::Ready(index) =
            build_rust_selected_reference_index(&analyzer, &CancellationToken::default())
        else {
            panic!("an open Rust buffer answers on its first selected operation")
        };
        let target = analyzer
            .all_declarations()
            .find(|unit| unit.identifier() == "target")
            .expect("overlay target declaration");
        assert!(
            index.inverse_for(&target).edges.is_empty(),
            "the buffer deleted the only call, so the disk edge must not survive"
        );
    }

    #[test]
    fn production_reference_index_follows_changed_and_cleared_overlays() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname = \"overlay_authority\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
            .file("src/lib.rs", "pub fn target() {}\npub fn caller() { target(); }\n")
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        assert!(
            disk.all_declarations()
                .any(|unit| unit.identifier() == "caller")
        );
        let overlay = Arc::new(crate::OverlayProject::new(fixture.project_dyn()));
        assert!(overlay.set(
            file.abs_path(),
            "pub fn target() {}\npub fn caller() {}\n".to_owned()
        ));
        let prepared = disk.clone_with_project(Arc::new(overlay.snapshot()));
        assert!(
            prepared
                .declarations(&file)
                .iter()
                .any(|unit| unit.identifier() == "caller")
        );
        let RustSelectedReferenceIndexOutcome::Ready(prepared_index) =
            build_rust_selected_reference_index(&prepared, &CancellationToken::default())
        else {
            panic!("prepared overlay reference index must be available")
        };
        let prepared_target = prepared
            .all_declarations()
            .find(|unit| unit.identifier() == "target")
            .expect("prepared target declaration");
        assert!(
            prepared_index
                .inverse_for(&prepared_target)
                .edges
                .is_empty(),
            "prepared overlay removes the caller-to-target edge"
        );

        assert!(overlay.set(file.abs_path(), "pub fn different() {}\n".to_owned()));
        let changed = prepared.clone_with_project(Arc::new(overlay.snapshot()));
        // The new bytes are hydrated on demand, so the request answers from
        // them. The property that matters is that it cannot reuse the earlier
        // prepared facts: `target` and `caller` are gone from the buffer.
        assert!(
            matches!(
                build_rust_selected_reference_index(&changed, &CancellationToken::default()),
                RustSelectedReferenceIndexOutcome::Ready(_)
            ),
            "new buffer bytes answer from themselves"
        );
        assert!(
            changed
                .declarations(&file)
                .iter()
                .all(|unit| unit.identifier() == "different"),
            "{:?}",
            changed.declarations(&file)
        );
        assert!(
            matches!(
                build_rust_selected_reference_index(&prepared, &CancellationToken::default()),
                RustSelectedReferenceIndexOutcome::Ready(_)
            ),
            "the frozen prepared request retains its original authority"
        );

        assert!(overlay.clear(&file.abs_path()));
        let cleared = prepared.clone_with_project(Arc::new(overlay.snapshot()));
        let RustSelectedReferenceIndexOutcome::Ready(cleared_index) =
            build_rust_selected_reference_index(&cleared, &CancellationToken::default())
        else {
            panic!("cleared overlay must select the persisted disk reference index")
        };
        let cleared_target = cleared
            .all_declarations()
            .find(|unit| unit.identifier() == "target")
            .expect("cleared target declaration");
        let inverse = cleared_index.inverse_for(&cleared_target);
        assert_eq!(inverse.edges.len(), 1, "disk caller-to-target edge");
        let edge = &inverse.edges[0];
        assert_eq!(edge.site.file, file);
        assert_eq!(
            edge.site.enclosing.as_ref().map(CodeUnit::identifier),
            Some("caller")
        );
        assert_eq!(edge.target, cleared_target);
    }

    #[test]
    fn production_reference_index_answers_an_unprepared_new_source_overlay() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"new_overlay\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "pub fn target() {}\n")
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        assert!(
            disk.all_declarations()
                .any(|unit| unit.identifier() == "target")
        );
        let overlay = Arc::new(crate::OverlayProject::new(fixture.project_dyn()));
        assert!(overlay.set(
            fixture.file("src/new.rs").abs_path(),
            "pub fn caller() { crate::target(); }\n".to_owned()
        ));
        let analyzer = disk.clone_with_project(Arc::new(overlay.snapshot()));
        // A buffer for a file no persisted mount carries is hydrated the same
        // way, so the first call answers instead of refusing.
        assert!(
            matches!(
                build_rust_selected_reference_index(&analyzer, &CancellationToken::default()),
                RustSelectedReferenceIndexOutcome::Ready(_)
            ),
            "a new source buffer answers from its own facts"
        );
    }

    #[test]
    fn production_reference_index_retargets_root_qualified_overlay_without_stale_edges() {
        let disk_source = concat!(
            "pub mod left;\n",
            "pub mod right;\n",
            "pub fn caller() { crate::left::target(); }\n",
        );
        let overlay_source = disk_source.replace("crate::left::target", "crate::right::target");
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"root_overlay\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", disk_source)
            .file("src/left.rs", "pub fn target() {}\n")
            .file("src/right.rs", "pub fn target() {}\n")
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let left_file = fixture.file("src/left.rs");
        let right_file = fixture.file("src/right.rs");
        let all_declarations = disk.all_declarations().collect::<Vec<_>>();
        let left_target = all_declarations
            .iter()
            .find(|unit| unit.source() == &left_file && unit.identifier() == "target")
            .cloned()
            .expect("left target declaration");
        let right_target = all_declarations
            .iter()
            .find(|unit| unit.source() == &right_file && unit.identifier() == "target")
            .cloned()
            .expect("right target declaration");
        let overlay = Arc::new(crate::OverlayProject::new(fixture.project_dyn()));
        assert!(overlay.set(file.abs_path(), overlay_source.clone()));
        let request_project: Arc<dyn Project> = Arc::new(overlay.snapshot());
        let analyzer = disk.clone_with_project(request_project);
        assert!(
            analyzer
                .declarations(&file)
                .iter()
                .any(|unit| unit.identifier() == "caller")
        );
        let updated_start = overlay_source
            .find("crate::right::target()")
            .expect("updated qualified terminal call")
            + "crate::right::".len();
        let selected =
            match selected_rust_workspace_binding_world(&analyzer, &CancellationToken::default()) {
                RustWorkspaceBindingWorldResult::Ready(selected) => selected,
                RustWorkspaceBindingWorldResult::Unavailable(detail) => {
                    panic!("selected overlay binding world unavailable: {detail}")
                }
                RustWorkspaceBindingWorldResult::Stale(detail) => {
                    panic!("selected overlay binding world stale: {detail}")
                }
                RustWorkspaceBindingWorldResult::Cancelled => {
                    panic!("selected overlay binding world cancelled")
                }
                RustWorkspaceBindingWorldResult::StoreError(detail) => {
                    panic!("selected overlay binding world store error: {detail}")
                }
            };
        let expected_right_definition = selected
            .definition_units
            .iter()
            .find(|(_, unit)| *unit == &right_target)
            .map(|(definition, _)| definition)
            .expect("selected overlay definition units contain right target");
        let updated_site = selected
            .world
            .sites()
            .iter()
            .find(|site| {
                site.file() == &file
                    && site
                        .metadata()
                        .is_some_and(|metadata| metadata.start_byte() == updated_start)
            })
            .expect("selected overlay world retains updated qualified terminal site");
        assert_eq!(
            updated_site.completion(),
            &ResolutionCompletion::Complete,
            "updated selected site completion: {updated_site:?}"
        );
        assert_eq!(
            updated_site.definitions(),
            std::slice::from_ref(expected_right_definition),
            "updated selected site definitions: site={updated_site:?}, right={right_target:?}, units={:?}",
            selected.definition_units.values().collect::<Vec<_>>()
        );
        let RustSelectedReferenceIndexOutcome::Ready(index) =
            build_rust_selected_reference_index(&analyzer, &CancellationToken::default())
        else {
            panic!("selected overlay reference index must be available")
        };
        let updated = index.inverse_for(&right_target);
        assert_eq!(updated.edges.len(), 1, "{updated:?}");
        let edge = &updated.edges[0];
        assert_eq!(edge.target, right_target);
        assert_eq!(edge.site.file, file);
        assert_eq!(edge.site.range.start_byte, updated_start);
        assert_eq!(edge.site.range.end_byte, updated_start + "target".len());
        assert_eq!(edge.proof, UsageProof::Proven);
        assert_eq!(edge.usage_kind, UsageHitKind::Reference);
        assert!(index.inverse_for(&left_target).edges.is_empty());
    }

    #[test]
    fn production_workspace_graph_shadow_preserves_bare_local_import_edges_and_line_weights() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                concat!(
                    "pub mod dep;\n",
                    "use dep::target;\n",
                    "pub fn caller() -> usize { target() + target() }\n",
                    "pub fn second() -> usize { target() }\n",
                ),
            )
            .file("src/dep.rs", "pub fn target() -> usize { 1 }\n")
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let catalog = WorkspaceUsageCatalog::build(&analyzer);
        let selected = BTreeSet::from([UsageEcosystem::Rust]);
        let cancellation = CancellationToken::default();
        let WorkspaceUsageGraphBuildOutcome::Complete(graph) =
            build_workspace_usage_graph_with_cancellation(
                &analyzer,
                catalog,
                &selected,
                &cancellation,
            )
        else {
            panic!("uncancelled Rust workspace graph build")
        };

        let native = selected_rust_workspace_graph_shadow_result(&analyzer, &graph, &cancellation);
        let RustWorkspaceGraphShadowResult::Complete(native) = native else {
            panic!("simple library Rust graph must complete: {native:#?}")
        };
        assert!(native.truncated.is_empty());
        assert!(native.unproven_inbound.is_empty());
        assert_eq!(native.edges.len(), 2);
        assert!(native.edges.iter().all(|((caller, callee), counts)| {
            matches!(caller.identifier(), "caller" | "second")
                && callee.identifier() == "target"
                && counts.calls == 1
                && counts.total() == 1
        }));
    }

    #[test]
    fn production_dead_code_graph_shadow_preserves_candidate_inbound_evidence() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                concat!(
                    "pub mod dep;\n",
                    "use dep::target;\n",
                    "pub fn caller() -> usize { target() + target() }\n",
                    "pub fn second() -> usize { target() }\n",
                ),
            )
            .file("src/dep.rs", "pub fn target() -> usize { 1 }\n")
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let target = analyzer
            .all_declarations()
            .find(|unit| unit.identifier() == "target")
            .expect("dead-code target declaration");
        let expected_callers = analyzer
            .all_declarations()
            .filter(|unit| matches!(unit.identifier(), "caller" | "second"))
            .map(|unit| unit.fq_name())
            .collect::<BTreeSet<_>>();
        let nodes = fqn_bulk_nodes(
            &analyzer,
            Language::Rust,
            |unit| unit.is_function() || unit.is_class(),
            std::slice::from_ref(&target),
        );
        let candidates = analyzer.get_analyzed_files().into_iter().collect();
        let result @ FuzzyResult::Success { .. } = RustSupport
            .dead_code()
            .strategy
            .expect("Rust dead-code analysis registers its native strategy")
            .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 100)
        else {
            panic!("registered native Rust dead-code query must complete")
        };
        let hits = result.all_hits();
        assert_eq!(
            hits.len(),
            3,
            "native usages preserve every call occurrence: {hits:?}"
        );
        assert_eq!(
            hits.iter()
                .map(|hit| hit.enclosing.fq_name())
                .collect::<BTreeSet<_>>(),
            expected_callers,
        );
        let cancellation = CancellationToken::default();
        let RustWorkspaceGraphShadowResult::Complete(native) =
            selected_rust_dead_code_graph_shadow_result(&analyzer, &nodes, &cancellation)
        else {
            panic!("simple Rust dead-code graph must complete")
        };

        let native = native_rust_dead_code_graph_shadow(&native);
        assert!(native.truncated.is_empty());
        assert!(native.unproven_inbound.is_empty());
        assert_eq!(native.edges.len(), 2);
        let target_fqn = target.fq_name();
        assert!(native.edges.iter().all(|((caller, callee), &count)| {
            expected_callers.contains(caller) && callee == &target_fqn && count == 1
        }));
    }

    /// R6.4: the first `StructuralReceiverResolver` call over a dirty Rust
    /// buffer answers from the buffer, both for a definition and for a type.
    ///
    /// This is the production trait a receiver query reaches, not the adapter
    /// function underneath it, so it states the property at the boundary the
    /// editor path actually crosses.
    #[test]
    fn production_rust_support_answers_a_dirty_buffer_on_its_first_call() {
        let disk = "pub struct DiskWidget;\npub fn make() -> DiskWidget { DiskWidget }\n";
        let buffer = "pub struct BufferWidget;\npub fn make() -> BufferWidget { BufferWidget }\n";
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"dirty_support\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", disk)
            .build();
        let file = fixture.file("src/lib.rs");
        let overlay = Arc::new(crate::OverlayProject::new(fixture.project_dyn()));
        assert!(overlay.set(file.abs_path(), buffer.to_owned()));
        let analyzer = RustAnalyzer::new(fixture.project_dyn())
            .clone_with_project(Arc::new(overlay.snapshot()) as Arc<dyn Project>);

        let mut site = rust_shadow_site(buffer, "BufferWidget");
        site.path = rel_path_string(&file);
        let tree = rust_shadow_tree(buffer);
        let query = BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source: buffer,
            tree: Some(&tree),
            site: &site,
            budget: Default::default(),
            cancellation: None,
        };

        let BoundedResolution::Complete {
            value: definition, ..
        } = RustSupport.resolve_definition_bounded(query)
        else {
            panic!("a dirty Rust buffer completes on its first definition call")
        };
        assert_eq!(
            definition.status,
            DefinitionLookupStatus::Resolved,
            "{definition:#?}"
        );
        assert_eq!(
            definition
                .definitions
                .iter()
                .map(|unit| unit.short_name().to_owned())
                .collect::<Vec<_>>(),
            vec!["BufferWidget".to_owned()],
        );

        let BoundedResolution::Complete {
            value: projected, ..
        } = RustSupport.resolve_type_bounded(query)
        else {
            panic!("a dirty Rust buffer completes on its first type call")
        };
        assert_ne!(
            projected.status,
            crate::analyzer::usages::get_type::TypeLookupStatus::Unavailable,
            "{projected:#?}"
        );
    }

    #[test]
    fn production_resolver_answers_a_detached_rust_binary_root_natively() {
        let source = "fn target() {}\nfn main() { target(); }\n";
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/main.rs", source)
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/main.rs");
        let mut site = rust_shadow_site(source, "target");
        site.path = rel_path_string(&file);
        let tree = rust_shadow_tree(source);
        let query = BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: Some(&tree),
            site: &site,
            budget: Default::default(),
            cancellation: None,
        };
        // The package declares no library, so `src/lib.rs` does not exist and no
        // library target places `src/main.rs`. Cargo's automatic target
        // discovery makes `src/main.rs` a binary crate root, and the detached
        // profile reads it as its own crate root, so the same-file call
        // resolves instead of being refused.
        assert!(!matches!(
            selected_rust_definition_shadow_result(&analyzer, query),
            RustDefinitionShadowResult::UnsupportedCallerProfile { .. }
        ));
        let BoundedResolution::Complete { value, .. } =
            RustSupport.resolve_definition_bounded(query)
        else {
            panic!("an uncancelled detached caller completes")
        };
        assert_eq!(value.status, DefinitionLookupStatus::Resolved);
        assert_eq!(
            value
                .definitions
                .iter()
                .map(|unit| unit.fq_name())
                .collect::<Vec<_>>(),
            vec!["shadow.main.target".to_string()],
        );
    }

    #[test]
    fn production_structural_resolver_shadows_rust_budget_and_cancellation_terminals() {
        let source = concat!(
            "pub mod model;\n",
            "pub use model::target as alias;\n",
            "pub fn caller() -> usize { alias() }\n",
        );
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", source)
            .file("src/model.rs", "pub fn target() -> usize { 1 }\n")
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let site = rust_shadow_site(source, "alias");
        let tree = rust_shadow_tree(source);
        let caller_cancellation = CancellationToken::new();
        let baseline_query = BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: Some(&tree),
            site: &site,
            budget: Default::default(),
            cancellation: Some(&caller_cancellation),
        };
        // An analyzer's first selected operation charges more receiver-analysis
        // work than its later ones, because the first one populates the
        // retained selection and typed-frontier reads that the rest reuse.
        // Measured on this tree at HEAD: cold (setup_nodes 0,
        // summary_expansions 13, scope_nodes 657) and warm (0, 10, 621),
        // identical on every operation after the first. The exact-budget and
        // one-unit-under properties below are about one steady-state
        // operation, so discard the cold operation before measuring.
        let cold = selected_rust_definition_shadow_result(&analyzer, baseline_query);
        assert!(matches!(cold, RustDefinitionShadowResult::Complete { .. }));
        let baseline = selected_rust_definition_shadow_result(&analyzer, baseline_query);
        let RustDefinitionShadowResult::Complete {
            work: baseline_work,
            ..
        } = baseline
        else {
            panic!("default Rust shadow budget must complete")
        };
        let exact_query = BoundedReceiverQuery {
            budget:
                brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget {
                    max_summary_expansions: baseline_work.summary_expansions,
                    max_scope_nodes: baseline_work.scope_nodes,
                    ..Default::default()
                },
            ..baseline_query
        };
        assert!(matches!(
            selected_rust_definition_shadow_result(&analyzer, exact_query),
            RustDefinitionShadowResult::Complete { work, .. } if work == baseline_work
        ));
        assert!(matches!(
            RustSupport.resolve_definition_bounded(exact_query),
            BoundedResolution::Complete { .. }
        ));
        let under_query = BoundedReceiverQuery {
            budget:
                brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget {
                    max_summary_expansions: baseline_work.summary_expansions,
                    max_scope_nodes: baseline_work.scope_nodes - 1,
                    ..Default::default()
                },
            ..baseline_query
        };
        assert!(matches!(
            selected_rust_definition_shadow_result(&analyzer, under_query),
            RustDefinitionShadowResult::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                ..
            }
        ));
        assert!(!caller_cancellation.is_cancelled());

        let exhausted = BoundedReceiverQuery {
            budget:
                brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget {
                    max_scope_nodes: 0,
                    ..Default::default()
                },
            ..baseline_query
        };
        let native = selected_rust_definition_shadow_result(&analyzer, exhausted);
        assert!(matches!(
            native,
            RustDefinitionShadowResult::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                ..
            }
        ));
        assert!(!caller_cancellation.is_cancelled());

        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let cancelled_query = BoundedReceiverQuery {
            budget: Default::default(),
            cancellation: Some(&cancelled),
            ..exhausted
        };
        let native = selected_rust_definition_shadow_result(&analyzer, cancelled_query);
        assert!(matches!(
            native,
            RustDefinitionShadowResult::Cancelled { .. }
        ));
    }

    #[test]
    fn production_structural_resolver_follows_unsaved_import_name() {
        let disk_source = concat!(
            "pub mod model;\n",
            "pub use model::target as alias;\n",
            "pub fn caller() -> usize { alias() }\n",
        );
        let overlay_source = concat!(
            "pub mod model;\n",
            "pub use model::replacement as alias;\n",
            "pub fn caller() -> usize { alias() }\n",
        );
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", disk_source)
            .file(
                "src/model.rs",
                "pub fn target() -> usize { 1 }\npub fn replacement() -> usize { 2 }\n",
            )
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let overlay = Arc::new(crate::OverlayProject::new(fixture.project_dyn()));
        assert!(overlay.set(file.abs_path(), overlay_source.to_string()));
        let request_project: Arc<dyn Project> = Arc::new(overlay.snapshot());
        let analyzer = disk.clone_with_project(request_project);
        assert!(
            analyzer
                .declarations(&file)
                .iter()
                .any(|unit| unit.short_name() == "caller")
        );
        let site = rust_shadow_site(overlay_source, "alias");
        let tree = rust_shadow_tree(overlay_source);
        let query = BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source: overlay_source,
            tree: Some(&tree),
            site: &site,
            budget: Default::default(),
            cancellation: None,
        };
        let native = selected_rust_definition_shadow_result(&analyzer, query);
        let RustDefinitionShadowResult::Complete {
            status: DefinitionLookupStatus::Resolved,
            definitions,
            ..
        } = native
        else {
            panic!("selected import name must resolve to its actual target: {native:#?}")
        };
        let expected = analyzer
            .declarations(&fixture.file("src/model.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "replacement")
            .expect("parsed replacement declaration");
        assert_eq!(definitions, [expected]);
    }

    #[test]
    fn production_rust_shadow_rejects_a_generation_change_after_open() {
        let source = "pub fn target() {}\npub fn caller() { target(); }\n";
        let changed_source = "pub fn target() {}\npub fn caller() { target(); target(); }\n";
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", source)
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let overlay = Arc::new(crate::OverlayProject::new(fixture.project_dyn()));
        assert!(overlay.set(file.abs_path(), source.to_string()));
        let request_project: Arc<dyn Project> = overlay.clone();
        let analyzer = disk.clone_with_project(request_project);
        let _ = analyzer.declarations(&file);
        let site = rust_shadow_site(source, "target");
        let tree = rust_shadow_tree(source);
        let query = BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: Some(&tree),
            site: &site,
            budget: Default::default(),
            cancellation: None,
        };
        let result =
            selected_rust_definition_shadow_result_with_after_open(&analyzer, query, || {
                assert!(overlay.set(file.abs_path(), changed_source.to_string()));
            });
        assert!(
            matches!(result, RustDefinitionShadowResult::Stale(_)),
            "{result:?}"
        );
    }
}
