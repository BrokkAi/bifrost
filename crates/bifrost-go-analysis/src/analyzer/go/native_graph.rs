//! Native Go workspace graph projection.

use crate::analyzer::go::GoAnalyzer;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_analysis::analyzer::languages::EdgePassId;

use brokk_bifrost_analysis::analyzer::languages::LanguageEdgeFailure;

use brokk_bifrost_analysis::analyzer::languages::NativeWorkspaceGraphProvider;

use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::FactReferenceEdgeDeclarationDomain;

use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionContextMetrics;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationInput;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_publication::SelectedResolutionOverlayInputsOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;

use brokk_bifrost_analysis::analyzer::store::Result;

use brokk_bifrost_analysis::analyzer::store::StoreError;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeCompleteness;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeIncompleteReason;

use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::NativeWorkspaceUsageGraphAccumulator;

use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::SelectedWorkspaceUsageGraphProjectionOutcome;

use brokk_bifrost_analysis::analyzer::usages::workspace_graph::UsageEcosystem;

use brokk_bifrost_analysis::analyzer::usages::workspace_graph::WorkspaceUsageCatalog;

use brokk_bifrost_analysis::analyzer::usages::workspace_graph::is_graph_declaration;

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_analysis::analyzer::store_bridge::go_graph::GoGraphStageExt;
use brokk_bifrost_core::hash::HashSet;
use std::collections::BTreeSet;

#[doc(hidden)]
pub struct GoNativeWorkspaceGraphProvider;

impl NativeWorkspaceGraphProvider for GoNativeWorkspaceGraphProvider {
    fn id(&self) -> EdgePassId {
        EdgePassId::Go
    }

    fn project(
        &self,
        analyzer: &dyn IAnalyzer,
        admitted_callers: &[ProjectFile],
        cancellation: &CancellationToken,
    ) -> Result<SelectedWorkspaceUsageGraphProjectionOutcome> {
        let Some(go) = resolve_analyzer::<GoAnalyzer>(analyzer) else {
            return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(
                "selected Go analyzer is unavailable".into(),
            ));
        };
        build_go_native_workspace_graph_for_files(go, admitted_callers, cancellation)
    }

    fn input_failure(
        &self,
        analyzer: &dyn IAnalyzer,
        request_files: &[ProjectFile],
    ) -> Option<LanguageEdgeFailure> {
        let go = resolve_analyzer::<GoAnalyzer>(analyzer)?;
        let request_files = request_files
            .iter()
            .filter(|file| go.inner.is_analyzed(file))
            .cloned()
            .collect::<Vec<_>>();
        if request_files.is_empty() {
            return None;
        }
        if !go.graph_inventory_complete() {
            return Some(LanguageEdgeFailure {
                reason: "Go canonical package identities are unavailable",
                files: request_files,
            });
        }
        let Some(_snapshot) = go.inner.selected_workspace_snapshots().get("go").cloned() else {
            return Some(LanguageEdgeFailure {
                reason: "selected Go source publication is unavailable",
                files: request_files.to_vec(),
            });
        };
        if go.native_context_base_profile().is_none() {
            Some(LanguageEdgeFailure {
                reason: "selected Go package/import base profile is unavailable",
                files: request_files,
            })
        } else {
            None
        }
    }
}

/// Classify requested Go callers, then project admitted files' outgoing edges
/// through one selected operation. Rust and other languages are outside this pass.
#[doc(hidden)]
pub fn build_go_native_workspace_graph_for_files(
    go: &GoAnalyzer,
    caller_files: &[ProjectFile],
    cancellation: &CancellationToken,
) -> Result<SelectedWorkspaceUsageGraphProjectionOutcome> {
    if cancellation.is_cancelled() {
        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
    }
    let generation = go.inner.project().analysis_generation();
    let snapshots = go.inner.selected_workspace_snapshots();
    let Some(_snapshot) = snapshots.get("go") else {
        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(
            "selected Go workspace snapshot is unavailable".into(),
        ));
    };
    let Some(base_profile) = go.native_context_base_profile() else {
        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(
            "selected Go package/import base profile is unavailable".into(),
        ));
    };
    let (masks, content_mounts) = match go
        .inner
        .selected_resolution_overlay_inputs(snapshots.as_ref(), cancellation)?
    {
        SelectedResolutionOverlayInputsOutcome::Ready {
            masks,
            content_mounts,
        } => (masks, content_mounts),
        SelectedResolutionOverlayInputsOutcome::Cancelled => {
            return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
        }
        SelectedResolutionOverlayInputsOutcome::Stale(reason) => {
            let _ = reason;
            return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Stale);
        }
        SelectedResolutionOverlayInputsOutcome::Unavailable(reason) => {
            return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(
                format!("{reason:?}"),
            ));
        }
    };
    let languages = [SelectedResolutionLanguage::new("go", Language::Go)];
    let input = SelectedResolutionOperationInput::new(
        go.inner.project(),
        go.inner.workspace_id(),
        snapshots.as_ref(),
        &languages,
        &masks,
    )
    .with_content_mounts(content_mounts);
    let mut operation = match go
        .inner
        .analyzer_store()
        .open_selected_resolution_operation(input, cancellation)?
    {
        SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
        SelectedResolutionOperationOpenOutcome::Cancelled => {
            return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
        }
        SelectedResolutionOperationOpenOutcome::Stale(_) => {
            return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Stale);
        }
        SelectedResolutionOperationOpenOutcome::Unavailable(reason) => {
            return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(
                format!("{reason:?}"),
            ));
        }
    };

    let mut admitted_callers = HashSet::default();
    for file in caller_files {
        if cancellation.is_cancelled() {
            return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
        }
        // Admission, including a missing selected mount, is classified by the
        // stage. Filtering here would lose the requested caller's evidence.
        admitted_callers.insert(file.clone());
    }
    let mut declarations = Vec::new();
    for file in &admitted_callers {
        if cancellation.is_cancelled() {
            return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
        }
        let Some(catalog) = WorkspaceUsageCatalog::build_for_files_with_cancellation(
            go,
            std::slice::from_ref(file),
            cancellation,
        ) else {
            return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
        };
        declarations.extend(catalog.nodes.into_iter().map(|node| node.primary));
    }
    let mut declarations_with_ranges = Vec::new();
    for unit in declarations {
        if cancellation.is_cancelled() {
            return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
        }
        declarations_with_ranges.push((unit.clone(), go.ranges(&unit)));
    }
    let mut declarations = declarations_with_ranges;
    let mut rooted_declarations = declarations
        .iter()
        .map(|(unit, _)| unit.clone())
        .collect::<HashSet<_>>();
    let mut rows = Vec::new();
    let mut unresolved_names = BTreeSet::new();
    let mut unresolved_names_complete = true;
    let mut withheld_references = Vec::new();
    let mut reasons = Vec::new();
    let mut reference_count = 0_usize;
    let mut batch_count = 0_usize;
    let mut receiver_type_file = None::<(ProjectFile, Box<[(usize, usize)]>)>;

    let staged = operation.stage_go_graph_reference_edge_batches_in_files(
        go,
        base_profile,
        &admitted_callers,
        brokk_bifrost_analysis::analyzer::resolution::batch::MAX_REFERENCE_SEEDS_PER_BATCH,
        cancellation,
        &mut SelectedResolutionContextMetrics,
        &mut |file, source_batch, edge_batch, _reference_owners| {
            assert_eq!(edge_batch.generation(), generation);
            let status =
                edge_batch.domain_status(FactReferenceEdgeDeclarationDomain::TypeOrCallable);
            if let EdgeCompleteness::Incomplete {
                reasons: batch_reasons,
            } = status.completeness()
            {
                for reason in batch_reasons {
                    if !reasons.contains(reason) {
                        reasons.push(reason.clone());
                    }
                }
            }
            withheld_references.extend_from_slice(edge_batch.withheld_references());
            match edge_batch.unresolved_names() {
                Some(names) => unresolved_names.extend(names.iter().cloned()),
                None => unresolved_names_complete = false,
            }
            if receiver_type_file
                .as_ref()
                .is_none_or(|(cached_file, _)| cached_file != file)
            {
                let source = go.indexed_source(file).ok_or_else(|| {
                    StoreError::new(format!(
                        "selected Go graph file has no indexed source: {file}"
                    ))
                })?;
                if !go
                    .inner
                    .source_matches_selected_native_content(file, &source)
                {
                    return Err(StoreError::new(format!(
                        "selected Go graph source changed before projection: {file}"
                    )));
                }
                receiver_type_file = Some((
                    file.clone(),
                    crate::analyzer::go::selected_reverse::go_receiver_type_reference_ranges(
                        &source,
                    ),
                ));
            }
            let receiver_ranges = &receiver_type_file
                .as_ref()
                .expect("selected Go graph source was indexed")
                .1;
            for row in edge_batch.edges() {
                let mut row = row.clone();
                if receiver_ranges
                    .binary_search(&(row.site.range.start_byte, row.site.range.end_byte))
                    .is_ok()
                {
                    row.usage_kind =
                        brokk_bifrost_core::analyzer::usages::model::UsageHitKind::SelfReceiver;
                }
                for unit in row
                    .site
                    .enclosing
                    .iter()
                    .chain(std::iter::once(&row.target))
                {
                    if is_graph_declaration(unit) && rooted_declarations.insert(unit.clone()) {
                        declarations.push((unit.clone(), go.ranges(unit)));
                    }
                }
                rows.push(row);
            }
            reference_count += source_batch.answers().len();
            batch_count += 1;
            Ok(())
        },
    )?;
    let (mut summary, skipped) = match staged {
        SelectedResolutionOperationOutcome::Native(result) => (result.summary, result.skipped),
        SelectedResolutionOperationOutcome::Cancelled(_) => {
            return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
        }
        SelectedResolutionOperationOutcome::Stale(_) => {
            return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Stale);
        }
        SelectedResolutionOperationOutcome::Unavailable(reason) => {
            return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(
                format!("{reason:?}"),
            ));
        }
    };
    admitted_callers.retain(|file| !skipped.contains_key(file));
    declarations.retain(|(unit, _)| !skipped.contains_key(unit.source()));
    assert_eq!(reference_count, summary.reference_count());
    assert_eq!(batch_count, summary.batch_count());
    let completion = summary
        .completion()
        .combine(summary.reference_enumeration_completion());
    summary = match operation.finish_native(summary, &completion, cancellation)? {
        SelectedResolutionOperationOutcome::Native(summary) => summary,
        SelectedResolutionOperationOutcome::Cancelled(_) => {
            return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
        }
        SelectedResolutionOperationOutcome::Stale(_) => {
            return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Stale);
        }
        SelectedResolutionOperationOutcome::Unavailable(reason) => {
            return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(
                format!("{reason:?}"),
            ));
        }
    };
    if cancellation.is_cancelled() {
        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
    }
    if summary.reference_enumeration_completion() != &ResolutionCompletion::Complete
        && !reasons.contains(&EdgeIncompleteReason::ReferenceEnumerationIncomplete)
    {
        reasons.push(EdgeIncompleteReason::ReferenceEnumerationIncomplete);
    }
    let completeness = if reasons.is_empty() {
        EdgeCompleteness::Complete
    } else {
        EdgeCompleteness::Incomplete { reasons }
    };
    let Some(mut accumulator) = NativeWorkspaceUsageGraphAccumulator::new(
        declarations,
        generation,
        UsageEcosystem::Go,
        &admitted_callers,
        cancellation,
    ) else {
        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
    };
    accumulator.record_skipped_callers(skipped);
    if !accumulator.stage(&rows, cancellation) {
        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
    }
    if !accumulator.note_withheld_references(&withheld_references, cancellation) {
        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
    }
    if !accumulator.note_unresolved_names(
        unresolved_names_complete.then_some(&unresolved_names),
        cancellation,
    ) {
        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
    }
    let projection = accumulator.finish(&completeness, &summary, rows.len(), cancellation);
    let mut domain_failures = BTreeSet::new();
    for publication in operation.bound_go_context_publications() {
        if let Some(failure) = operation.go_domain_discovery_failure(publication.context_id)? {
            domain_failures.insert(failure);
        }
    }
    let projection = if !domain_failures.is_empty() {
        match projection {
            SelectedWorkspaceUsageGraphProjectionOutcome::Complete(mut graph)
            | SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(mut graph) => {
                graph.domain_discovery_failures = domain_failures.into_iter().collect();
                graph.unresolved_names = None;
                SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(graph)
            }
            other => other,
        }
    } else {
        projection
    };
    let projection = if let Some(discovery_error) = go.build_selection_error() {
        match projection {
            SelectedWorkspaceUsageGraphProjectionOutcome::Complete(mut graph)
            | SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(mut graph) => {
                if graph.domain_discovery_failures.is_empty() {
                    graph.build_selection_unavailable = Some(brokk_bifrost_analysis::analyzer::store::resolution_operation::graph_stage::GraphBuildSelectionUnavailable { discovery_error });
                }
                // Unknown directive selection cannot certify absent inbound references.
                graph.unresolved_names = None;
                SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(graph)
            }
            other => other,
        }
    } else {
        projection
    };
    if cancellation.is_cancelled() {
        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
    }
    if go.inner.project().analysis_generation() != generation {
        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Stale);
    }
    Ok(
        match operation.finish_native(projection, &completion, cancellation)? {
            SelectedResolutionOperationOutcome::Native(projection) => projection,
            SelectedResolutionOperationOutcome::Cancelled(_) => {
                SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled
            }
            SelectedResolutionOperationOutcome::Stale(reason) => {
                SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(format!("{reason:?}"))
            }
            SelectedResolutionOperationOutcome::Unavailable(reason) => {
                SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(format!("{reason:?}"))
            }
        },
    )
}
