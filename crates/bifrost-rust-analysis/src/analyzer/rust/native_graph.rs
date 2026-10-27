//! Native Rust broad consumer preparation for the production workspace graph provider.
use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation;
use brokk_bifrost_analysis::analyzer::store_bridge::rust_graph::RustGraphStageExt;

use crate::analyzer::rust::RustAnalyzer;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_analysis::analyzer::languages::EdgePassId;

use brokk_bifrost_analysis::analyzer::languages::LanguageEdgeFailure;

use brokk_bifrost_analysis::analyzer::languages::NativeWorkspaceGraphProvider;

use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::FactReferenceEdgeDeclarationDomain;

use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

use brokk_bifrost_analysis::analyzer::store::Result;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionContextMetrics;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationInput;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_publication::SelectedResolutionOverlayInputsOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeCompleteness;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeIncompleteReason;

use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::NativeWorkspaceUsageGraphAccumulator;

use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::SelectedWorkspaceUsageGraphProjection;

use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::SelectedWorkspaceUsageGraphProjectionOutcome;

use brokk_bifrost_analysis::analyzer::usages::workspace_graph::UsageEcosystem;

use brokk_bifrost_analysis::analyzer::usages::workspace_graph::WorkspaceUsageCatalog;

use brokk_bifrost_analysis::analyzer::usages::workspace_graph::is_graph_declaration;

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::hash::HashSet;

#[doc(hidden)]
pub enum RustNativeWorkspaceGraphOutcome {
    Complete(SelectedWorkspaceUsageGraphProjection),
    Incomplete(SelectedWorkspaceUsageGraphProjection),
    Cancelled,
    Stale(String),
    Unavailable(String),
}

#[doc(hidden)]
pub struct RustNativeWorkspaceGraphProvider;

impl NativeWorkspaceGraphProvider for RustNativeWorkspaceGraphProvider {
    fn id(&self) -> EdgePassId {
        EdgePassId::Rust
    }

    /// Live Rust blobs whose canonical facts were never published cannot
    /// contribute a reference, and the native projection cannot tell that
    /// absence from a file with no references. Reporting it here is what keeps
    /// "canonical Rust facts unavailable" from rendering as a complete empty
    /// graph.
    ///
    /// The question is asked of `request_files` alone. Rust publication is per
    /// blob, so a request's availability is decided by the blobs it resolves:
    /// a rooted request is unavailable only when one of its own files is
    /// unpublished, and an unrooted one still asks about every analyzable
    /// file, which is where the workspace-wide answer was the honest one.
    fn input_failure(
        &self,
        analyzer: &dyn IAnalyzer,
        request_files: &[ProjectFile],
    ) -> Option<LanguageEdgeFailure> {
        let rust = resolve_analyzer::<RustAnalyzer>(analyzer)?;
        match rust.rust_files_without_facts_among(request_files) {
            Ok(files) if files.is_empty() => None,
            Ok(files) => Some(LanguageEdgeFailure {
                reason: "canonical Rust facts are unavailable for live files",
                files,
            }),
            Err(error) => {
                rust.inner.record_store_error(error.context(
                    "checking canonical Rust publication before native workspace graph projection",
                ));
                Some(LanguageEdgeFailure {
                    reason: "canonical Rust fact publication could not be checked",
                    files: Vec::new(),
                })
            }
        }
    }

    /// A Rust caller reaches a target only when one of its crates has the
    /// target's crate in its dependency closure; see
    /// `SelectedResolutionOperation::rust_callers_reaching`. A selection that
    /// cannot open narrows nothing: the projection that follows opens its
    /// own and reports why it could not.
    fn callers_reaching(
        &self,
        analyzer: &dyn IAnalyzer,
        callers: &[ProjectFile],
        targets: &[ProjectFile],
        cancellation: &CancellationToken,
    ) -> Result<Vec<ProjectFile>> {
        let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) else {
            return Ok(callers.to_vec());
        };
        Ok(with_rust_graph_operation(rust, cancellation, |operation| {
            operation.rust_callers_reaching(callers, targets, cancellation)
        })?
        .unwrap_or_else(|_| callers.to_vec()))
    }

    fn project(
        &self,
        analyzer: &dyn IAnalyzer,
        admitted_callers: &[ProjectFile],
        cancellation: &CancellationToken,
    ) -> Result<SelectedWorkspaceUsageGraphProjectionOutcome> {
        let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) else {
            return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(
                "selected Rust analyzer is unavailable".into(),
            ));
        };
        Ok(
            match build_rust_native_workspace_graph_for_files(
                rust,
                admitted_callers,
                brokk_bifrost_analysis::analyzer::resolution::batch::MAX_REFERENCE_SEEDS_PER_BATCH,
                cancellation,
            )? {
                RustNativeWorkspaceGraphOutcome::Complete(graph) => {
                    SelectedWorkspaceUsageGraphProjectionOutcome::Complete(graph)
                }
                RustNativeWorkspaceGraphOutcome::Incomplete(graph) => {
                    SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(graph)
                }
                RustNativeWorkspaceGraphOutcome::Cancelled => {
                    SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled
                }
                RustNativeWorkspaceGraphOutcome::Stale(reason) => {
                    debug_assert!(!reason.is_empty());
                    SelectedWorkspaceUsageGraphProjectionOutcome::Stale
                }
                RustNativeWorkspaceGraphOutcome::Unavailable(reason) => {
                    SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(reason)
                }
            },
        )
    }
}

/// Project outgoing edges from exactly the supplied caller files. Definitions
/// in dependencies remain available, and only returned endpoints join the
/// rooted node catalog. A depth traversal can call this for each caller frontier.
#[doc(hidden)]
pub fn build_rust_native_workspace_graph_for_files(
    rust: &RustAnalyzer,
    root_files: &[ProjectFile],
    maximum_batch_size: usize,
    cancellation: &CancellationToken,
) -> Result<RustNativeWorkspaceGraphOutcome> {
    build_rust_native_workspace_graph_with_progress(
        rust,
        root_files,
        maximum_batch_size,
        cancellation,
        &mut || {},
    )
}

/// Fold admitted files once through the canonical edge projector and shared
/// graph reducer. Every staged row remains private until operation authority
/// and the final analyzer generation check both pass.
#[doc(hidden)]
pub fn build_rust_native_workspace_graph_with_progress(
    rust: &RustAnalyzer,
    root_files: &[ProjectFile],
    maximum_batch_size: usize,
    cancellation: &CancellationToken,
    progress: &mut dyn FnMut(),
) -> Result<RustNativeWorkspaceGraphOutcome> {
    if cancellation.is_cancelled() {
        return Ok(RustNativeWorkspaceGraphOutcome::Cancelled);
    }
    let generation = rust.project().analysis_generation();
    match with_rust_graph_operation(rust, cancellation, |operation| {
        project_rust_graph_in_operation(
            rust,
            operation,
            generation,
            root_files,
            maximum_batch_size,
            cancellation,
            progress,
        )
    })? {
        Ok(outcome) | Err(outcome) => Ok(outcome),
    }
}

/// Open the selected operation a Rust graph request runs in and hand it to
/// `run`, or answer the outcome that kept it from opening.
fn with_rust_graph_operation<T>(
    rust: &RustAnalyzer,
    cancellation: &CancellationToken,
    run: impl FnOnce(SelectedResolutionOperation<'_, '_>) -> Result<T>,
) -> Result<std::result::Result<T, RustNativeWorkspaceGraphOutcome>> {
    let snapshots = rust.inner.selected_workspace_snapshots();
    let languages = [SelectedResolutionLanguage::new("rust", Language::Rust)];
    let (masks, content_mounts) = match rust
        .inner
        .selected_rust_resolution_overlay_inputs(snapshots.as_ref(), cancellation)?
    {
        SelectedResolutionOverlayInputsOutcome::Ready {
            masks,
            content_mounts,
        } => (masks, content_mounts),
        SelectedResolutionOverlayInputsOutcome::Cancelled => {
            return Ok(Err(RustNativeWorkspaceGraphOutcome::Cancelled));
        }
        SelectedResolutionOverlayInputsOutcome::Stale(reason) => {
            return Ok(Err(RustNativeWorkspaceGraphOutcome::Stale(format!(
                "{reason:?}"
            ))));
        }
        SelectedResolutionOverlayInputsOutcome::Unavailable(reason) => {
            return Ok(Err(RustNativeWorkspaceGraphOutcome::Unavailable(format!(
                "{reason:?}"
            ))));
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
        .open_selected_resolution_operation(input, cancellation)?
    {
        SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
        SelectedResolutionOperationOpenOutcome::Cancelled => {
            return Ok(Err(RustNativeWorkspaceGraphOutcome::Cancelled));
        }
        SelectedResolutionOperationOpenOutcome::Stale(reason) => {
            return Ok(Err(RustNativeWorkspaceGraphOutcome::Stale(format!(
                "{reason:?}"
            ))));
        }
        SelectedResolutionOperationOpenOutcome::Unavailable(reason) => {
            return Ok(Err(RustNativeWorkspaceGraphOutcome::Unavailable(format!(
                "{reason:?}"
            ))));
        }
    };
    Ok(Ok(run(operation)?))
}

/// Fold admitted files once through the canonical edge projector and shared
/// graph reducer inside `operation`.
fn project_rust_graph_in_operation(
    rust: &RustAnalyzer,
    mut operation: SelectedResolutionOperation<'_, '_>,
    generation: u64,
    root_files: &[ProjectFile],
    maximum_batch_size: usize,
    cancellation: &CancellationToken,
    progress: &mut dyn FnMut(),
) -> Result<RustNativeWorkspaceGraphOutcome> {
    let mut admitted_callers = HashSet::default();
    for file in root_files {
        if cancellation.is_cancelled() {
            return Ok(RustNativeWorkspaceGraphOutcome::Cancelled);
        }
        admitted_callers.insert(file.clone());
    }
    let mut units = Vec::new();
    let mut seen_files = HashSet::default();
    for file in root_files {
        if cancellation.is_cancelled() {
            return Ok(RustNativeWorkspaceGraphOutcome::Cancelled);
        }
        if seen_files.insert(file) {
            let Some(catalog) = WorkspaceUsageCatalog::build_for_files_with_cancellation(
                rust,
                std::slice::from_ref(file),
                cancellation,
            ) else {
                return Ok(RustNativeWorkspaceGraphOutcome::Cancelled);
            };
            units.extend(catalog.nodes.into_iter().map(|node| node.primary));
        }
    }
    let mut declarations = Vec::new();
    for unit in units {
        if cancellation.is_cancelled() {
            return Ok(RustNativeWorkspaceGraphOutcome::Cancelled);
        }
        let ranges = rust.ranges(&unit);
        declarations.push((unit, ranges));
    }
    let mut rooted_declarations = declarations
        .iter()
        .map(|(unit, _)| unit.clone())
        .collect::<HashSet<_>>();
    let mut rooted_rows = Vec::new();
    // The names the edges this build withheld may reach. A forward gap is
    // evidence about the declarations one of these names reaches and about no
    // others, so the projection carries them and a dead-code consumer abstains
    // per candidate instead of discarding the whole pass.
    let mut unresolved_names = std::collections::BTreeSet::new();
    let mut unresolved_names_complete = true;
    let mut withheld_references = Vec::new();
    let mut reasons = Vec::new();
    let mut reference_count = 0;
    let mut edge_count = 0;
    let mut batch_count = 0;
    let mut stage = |batch: &brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::FactReferenceEdgeBatch| {
        assert_eq!(batch.generation(), generation);
        let status = batch.domain_status(FactReferenceEdgeDeclarationDomain::TypeOrCallable);
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
        for row in batch.edges() {
            for unit in row
                .site
                .enclosing
                .iter()
                .chain(std::iter::once(&row.target))
            {
                if is_graph_declaration(unit) && rooted_declarations.insert(unit.clone()) {
                    declarations.push((unit.clone(), rust.ranges(unit)));
                }
            }
        }
        for reference in batch.withheld_references() {
            for unit in reference.site.enclosing.iter().chain(match &reference.callee {
                brokk_bifrost_analysis::analyzer::resolution::reference_vocabulary::WithheldCallee::Named(_) => None,
                brokk_bifrost_analysis::analyzer::resolution::reference_vocabulary::WithheldCallee::Declaration(unit) => Some(unit),
            }) {
                if is_graph_declaration(unit) && rooted_declarations.insert(unit.clone()) {
                    declarations.push((unit.clone(), rust.ranges(unit)));
                }
            }
        }
        withheld_references.extend_from_slice(batch.withheld_references());
        match batch.unresolved_names() {
            Some(names) => {
                for name in names {
                    unresolved_names.insert(name.clone());
                }
            }
            None => unresolved_names_complete = false,
        }
        rooted_rows.extend_from_slice(batch.edges());
        reference_count += batch.reference_count();
        edge_count += batch.edges().len();
        batch_count += 1;
        progress();
        Ok(())
    };
    // The generic driver keeps each crate's language-owned rows inside one
    // stage, and places unowned request files in a final empty-crate unit.
    let stage_files = admitted_callers.iter().cloned().collect::<Vec<_>>();
    let summary = match operation.stage_rust_graph_units(
        rust.project().root(),
        rust,
        &stage_files,
        maximum_batch_size,
        rust.inner.analyzer_config().parallelism(),
        cancellation,
        &mut SelectedResolutionContextMetrics,
        &mut stage,
    )? {
        SelectedResolutionOperationOutcome::Native(staged) => staged.summary,
        SelectedResolutionOperationOutcome::Cancelled(_) => {
            return Ok(RustNativeWorkspaceGraphOutcome::Cancelled);
        }
        SelectedResolutionOperationOutcome::Stale(reason) => {
            return Ok(RustNativeWorkspaceGraphOutcome::Stale(format!(
                "{reason:?}"
            )));
        }
        SelectedResolutionOperationOutcome::Unavailable(reason) => {
            return Ok(RustNativeWorkspaceGraphOutcome::Unavailable(format!(
                "{reason:?}"
            )));
        }
    };
    let completion = summary
        .completion()
        .combine(summary.reference_enumeration_completion());
    let summary = match operation.finish_native(summary, &completion, cancellation)? {
        SelectedResolutionOperationOutcome::Native(summary) => summary,
        SelectedResolutionOperationOutcome::Cancelled(_) => {
            return Ok(RustNativeWorkspaceGraphOutcome::Cancelled);
        }
        SelectedResolutionOperationOutcome::Stale(reason) => {
            return Ok(RustNativeWorkspaceGraphOutcome::Stale(format!(
                "{reason:?}"
            )));
        }
        SelectedResolutionOperationOutcome::Unavailable(reason) => {
            return Ok(RustNativeWorkspaceGraphOutcome::Unavailable(format!(
                "{reason:?}"
            )));
        }
    };
    if cancellation.is_cancelled() {
        return Ok(RustNativeWorkspaceGraphOutcome::Cancelled);
    }
    assert_eq!(reference_count, summary.reference_count());
    assert_eq!(batch_count, summary.batch_count());
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
        UsageEcosystem::Rust,
        &admitted_callers,
        cancellation,
    ) else {
        return Ok(RustNativeWorkspaceGraphOutcome::Cancelled);
    };
    if !accumulator.stage(&rooted_rows, cancellation) {
        return Ok(RustNativeWorkspaceGraphOutcome::Cancelled);
    }
    if !accumulator.note_withheld_references(&withheld_references, cancellation) {
        return Ok(RustNativeWorkspaceGraphOutcome::Cancelled);
    }
    if !accumulator.note_unresolved_names(
        unresolved_names_complete.then_some(&unresolved_names),
        cancellation,
    ) {
        return Ok(RustNativeWorkspaceGraphOutcome::Cancelled);
    }
    let mut projection = accumulator.finish(&completeness, &summary, edge_count, cancellation);
    attach_implicit_callers(rust, &mut projection, cancellation)?;
    if cancellation.is_cancelled() {
        return Ok(RustNativeWorkspaceGraphOutcome::Cancelled);
    }
    if rust.project().analysis_generation() != generation {
        return Ok(RustNativeWorkspaceGraphOutcome::Stale(
            "analyzer generation changed during native graph projection".into(),
        ));
    }
    Ok(match projection {
        SelectedWorkspaceUsageGraphProjectionOutcome::Complete(graph) => {
            RustNativeWorkspaceGraphOutcome::Complete(graph)
        }
        SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(graph) => {
            RustNativeWorkspaceGraphOutcome::Incomplete(graph)
        }
        SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled => {
            RustNativeWorkspaceGraphOutcome::Cancelled
        }
        SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(reason) => {
            RustNativeWorkspaceGraphOutcome::Unavailable(reason)
        }
        SelectedWorkspaceUsageGraphProjectionOutcome::Stale => {
            unreachable!("a reducer has no source authority to mark stale")
        }
    })
}

/// Attach query-local trait-impl metadata without changing forward resolution.
fn attach_implicit_callers(
    rust: &RustAnalyzer,
    outcome: &mut SelectedWorkspaceUsageGraphProjectionOutcome,
    cancellation: &CancellationToken,
) -> Result<()> {
    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;
    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::ImplicitUsageGraphCallers;
    use brokk_bifrost_core::analyzer::query_token::QueryScope;
    let (SelectedWorkspaceUsageGraphProjectionOutcome::Complete(graph)
    | SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(graph)) = outcome
    else {
        return Ok(());
    };
    let scope = AnalyzerQueryScope::new(rust);
    let files = graph
        .nodes
        .iter()
        .map(|node| node.primary.source().clone())
        .collect::<HashSet<_>>();
    let mut implicit = brokk_bifrost_core::hash::HashMap::default();
    let mut implemented_members = brokk_bifrost_core::hash::HashMap::default();
    let mut node_ids = graph
        .nodes
        .iter()
        .map(|node| node.key.id.clone())
        .collect::<HashSet<_>>();
    for file in files {
        if cancellation.is_cancelled() {
            return Ok(());
        }
        for callers in brokk_bifrost_rust::hierarchy::rust_implicit_impl_callers_for_file(
            rust,
            scope.token(),
            &file,
        )
        .map_err(|error| {
            brokk_bifrost_analysis::analyzer::store::StoreError::new(format!(
                "reading implicit Rust callers for {file:?}: {error:?}"
            ))
        })? {
            for endpoint in callers.self_type.iter().chain(callers.implements.iter()) {
                if !node_ids.insert(endpoint.declaration_id()) {
                    continue;
                }
                // Scoped requests retain dispatch and fallback endpoints even
                // when their declarations are in another file.
                let range = rust
                    .ranges(endpoint)
                    .into_iter()
                    .min_by_key(|range| (range.start_line, range.start_byte));
                let Some(catalog) = WorkspaceUsageCatalog::from_declarations(
                    vec![(endpoint.clone(), range)],
                    cancellation,
                ) else {
                    return Ok(());
                };
                assert_eq!(
                    catalog.nodes.len(),
                    1,
                    "one trait dispatch endpoint is one graph node"
                );
                graph.nodes.extend(catalog.nodes);
                graph.raw_proven_inbound.push(0);
            }
            if let Some(member) = callers.implements {
                implemented_members
                    .insert(callers.method.declaration_id(), member.declaration_id());
            } else {
                implicit.insert(
                    callers.method.declaration_id(),
                    ImplicitUsageGraphCallers {
                        trait_name: callers.trait_name,
                        self_type_id: callers.self_type.map(|unit| unit.declaration_id()),
                    },
                );
            }
        }
    }
    for node in &mut graph.nodes {
        node.implements = implemented_members.remove(&node.key.id);
        node.implicit_callers = implicit.remove(&node.key.id);
    }
    Ok(())
}
