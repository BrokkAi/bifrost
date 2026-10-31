//! Query-scoped Python import-cycle checks over persisted file adjacency.

use super::*;
use crate::analyzer::content_identity::WorkspaceContentIdentity;
use crate::analyzer::{PersistedImportAdjacency, PersistedImportDirection};
use brokk_bifrost_analysis::analyzer::workspace_authority::{CaptureScopedMemo, memo_attribution};
use std::path::Path;

pub(super) struct PythonImportCycleContext<'a> {
    pub(super) analyzer: &'a dyn IAnalyzer,
    pub(super) access_mode: StructuralAccessMode,
    pub(super) budget: &'a mut CodeQueryExecutionBudget,
    pub(super) access_failure: &'a mut Option<String>,
    pub(super) limits: CodeQueryExecutionLimits,
    pub(super) cancellation: Option<&'a CancellationToken>,
}

#[derive(Default)]
pub(super) struct PythonImportCycleCache {
    content_identity: CaptureScopedMemo<Option<WorkspaceContentIdentity>>,
    identity_checked: CaptureScopedMemo<bool>,
    graph_ready: CaptureScopedMemo<bool>,
    refresh_attempted: CaptureScopedMemo<bool>,
    read_scope_recorded: CaptureScopedMemo<bool>,
}

pub(super) struct PythonReverseImportReachability {
    /// Python files with a persisted path to `imported_file`.
    pub(super) files: HashSet<ProjectFile>,
    /// Persisted forward edges, keyed by importer, within the reverse closure.
    pub(super) outgoing: HashMap<ProjectFile, HashSet<ProjectFile>>,
    pub(super) complete: bool,
}

pub(super) fn reverse_import_reachability(
    context: &mut PythonImportCycleContext<'_>,
    imported_file: &ProjectFile,
    cache: &mut PythonImportCycleCache,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> PythonReverseImportReachability {
    let mut result = PythonReverseImportReachability {
        files: HashSet::default(),
        outgoing: HashMap::default(),
        complete: true,
    };
    if module_identity_is_limited(imported_file.rel_path()) {
        report_incomplete(
            diagnostics,
            Incompleteness::Content,
            "Python package module identity is path-derived and remains incomplete until #3673 supplies snapshot-consistent source roots.",
        );
        result.complete = false;
        return result;
    }
    let Some(identity) = cycle_content_identity(context, cache, diagnostics) else {
        result.complete = false;
        return result;
    };
    result.files.insert(imported_file.clone());
    let mut frontier = vec![imported_file.clone()];
    if charge_import_file(context).is_none() {
        report_budget_exhausted(diagnostics, "file");
        result.complete = false;
        return result;
    }

    while !frontier.is_empty() {
        if context
            .cancellation
            .is_some_and(CancellationToken::is_cancelled)
        {
            report_incomplete(
                diagnostics,
                Incompleteness::Operational(DerivationExecutionCause::Cancelled),
                "Python import-cycle traversal was cancelled.",
            );
            result.complete = false;
            break;
        }
        let Some(adjacency) =
            read_reverse_adjacency(context, identity, &frontier, cache, diagnostics)
        else {
            result.complete = false;
            break;
        };
        context.budget.import_edges_resolved = context
            .budget
            .import_edges_resolved
            .saturating_add(adjacency.rows_read);
        let mut next_frontier = Vec::new();
        for target in &frontier {
            let Some(importers) = adjacency.by_file.get(target) else {
                continue;
            };
            for importer in importers {
                if importer.language() != Language::Python {
                    continue;
                }
                if module_identity_is_limited(importer.rel_path()) {
                    report_incomplete(
                        diagnostics,
                        Incompleteness::Content,
                        "Python package module identity is path-derived and remains incomplete until #3673 supplies snapshot-consistent source roots.",
                    );
                    result.complete = false;
                    continue;
                }
                result
                    .outgoing
                    .entry(importer.clone())
                    .or_default()
                    .insert(target.clone());
                if result.files.insert(importer.clone()) {
                    if charge_import_file(context).is_none() {
                        report_budget_exhausted(diagnostics, "file");
                        result.complete = false;
                        break;
                    }
                    next_frontier.push(importer.clone());
                }
            }
            if !result.complete {
                break;
            }
        }
        if !context.analyzer.workspace_content_matches(identity) {
            context.analyzer.mark_execution_dependent();
            report_incomplete(
                diagnostics,
                Incompleteness::Operational(DerivationExecutionCause::Snapshot),
                "workspace content changed during Python import-cycle traversal.",
            );
            result.complete = false;
            break;
        }
        if adjacency.exhausted {
            report_budget_exhausted(diagnostics, "edge");
            result.complete = false;
            break;
        }
        next_frontier.sort();
        frontier = next_frontier;
    }
    result
}

pub(super) fn annotate_import_site(
    context: &mut PythonImportCycleContext<'_>,
    importer: &ProjectFile,
    site: &mut CodeQueryPythonImportSite,
    cache: &mut PythonImportCycleCache,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) {
    for leaf in &mut site.sites {
        leaf.cycle_state = Some("incomplete");
    }

    if module_identity_is_limited(importer.rel_path()) {
        report_incomplete(
            diagnostics,
            Incompleteness::Content,
            "Python package module identity is path-derived and remains incomplete until #3673 supplies snapshot-consistent source roots.",
        );
        summarize_cycle_state(site);
        return;
    }

    let mut targets = HashMap::<ProjectFile, Vec<usize>>::default();
    for (index, leaf) in site.sites.iter().enumerate() {
        if leaf.target_status != "resolved_local" || leaf.target_paths.len() != 1 {
            report_incomplete(
                diagnostics,
                Incompleteness::Content,
                "Python import cycle has an unresolved, external, ambiguous, or unavailable target.",
            );
            continue;
        }
        let target = importer.with_rel_path(leaf.target_paths[0].as_str());
        if target.language() != Language::Python || module_identity_is_limited(target.rel_path()) {
            report_incomplete(
                diagnostics,
                Incompleteness::Content,
                "Python package module identity is path-derived and remains incomplete until #3673 supplies snapshot-consistent source roots.",
            );
            continue;
        }
        targets.entry(target).or_default().push(index);
    }

    if targets.is_empty() {
        summarize_cycle_state(site);
        return;
    }

    let Some(content_identity) = cycle_content_identity(context, cache, diagnostics) else {
        summarize_cycle_state(site);
        return;
    };

    let mut remaining_targets = targets.keys().cloned().collect::<HashSet<_>>();
    let mut visited = HashSet::default();
    visited.insert(importer.clone());
    let mut frontier = vec![importer.clone()];
    let mut found_targets = HashSet::default();
    let mut incomplete = false;

    if charge_import_file(context).is_none() {
        report_budget_exhausted(diagnostics, "file");
        summarize_cycle_state(site);
        return;
    }

    let mut traversal_incompleteness = Incompleteness::Content;
    while !frontier.is_empty() && !remaining_targets.is_empty() {
        if context
            .cancellation
            .is_some_and(CancellationToken::is_cancelled)
        {
            report_incomplete(
                diagnostics,
                Incompleteness::Operational(DerivationExecutionCause::Cancelled),
                "Python import cycle traversal was cancelled.",
            );
            traversal_incompleteness =
                Incompleteness::Operational(DerivationExecutionCause::Cancelled);
            incomplete = true;
            break;
        }

        let Some(adjacency) =
            read_reverse_adjacency(context, content_identity, &frontier, cache, diagnostics)
        else {
            traversal_incompleteness =
                Incompleteness::Operational(DerivationExecutionCause::Provider);
            incomplete = true;
            break;
        };

        context.budget.import_edges_resolved = context
            .budget
            .import_edges_resolved
            .saturating_add(adjacency.rows_read);
        let mut next_frontier = Vec::new();
        for current in &frontier {
            let Some(importers) = adjacency.by_file.get(current) else {
                continue;
            };
            for predecessor in importers {
                if remaining_targets.remove(predecessor) {
                    found_targets.insert(predecessor.clone());
                }
                if predecessor.language() != Language::Python
                    || !visited.insert(predecessor.clone())
                {
                    continue;
                }
                if charge_import_file(context).is_none() {
                    traversal_incompleteness =
                        Incompleteness::Operational(DerivationExecutionCause::Budget);
                    incomplete = true;
                    break;
                }
                next_frontier.push(predecessor.clone());
            }
            if incomplete {
                break;
            }
        }

        if !context.analyzer.workspace_content_matches(content_identity) {
            context.analyzer.mark_execution_dependent();
            report_incomplete(
                diagnostics,
                Incompleteness::Operational(DerivationExecutionCause::Snapshot),
                "workspace content changed during Python import cycle traversal.",
            );
            traversal_incompleteness =
                Incompleteness::Operational(DerivationExecutionCause::Snapshot);
            incomplete = true;
            break;
        }
        if adjacency.exhausted {
            report_budget_exhausted(diagnostics, "edge");
            traversal_incompleteness =
                Incompleteness::Operational(DerivationExecutionCause::Budget);
            incomplete = true;
            break;
        }
        if incomplete {
            report_budget_exhausted(diagnostics, "file");
            break;
        }
        next_frontier.sort();
        frontier = next_frontier;
    }

    for target in found_targets {
        if let Some(leaf_indexes) = targets.get(&target) {
            for &index in leaf_indexes {
                site.sites[index].cycle_state = Some("cyclic");
            }
        }
    }

    if !remaining_targets.is_empty() || incomplete {
        report_incomplete(
            diagnostics,
            traversal_incompleteness,
            "No persisted Python import path was found; unresolved, external, dynamic, and path-derived package edges keep absence incomplete.",
        );
    }
    summarize_cycle_state(site);
}

pub(super) fn cycle_content_identity(
    context: &PythonImportCycleContext<'_>,
    cache: &mut PythonImportCycleCache,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Option<WorkspaceContentIdentity> {
    let PythonImportCycleCache {
        identity_checked,
        content_identity,
        ..
    } = cache;
    let attribution = memo_attribution(context.analyzer);
    identity_checked.read_mut(&attribution, |identity_checked| {
        content_identity.read_mut(&attribution, |content_identity| {
            if !context.access_mode.permits_persisted_import_graph() {
                report_incomplete(
                    diagnostics,
                    Incompleteness::Operational(DerivationExecutionCause::Provider),
                    "Python import graph access is unavailable in this query mode.",
                );
                return None;
            }
            if !*identity_checked {
                *content_identity = context.analyzer.workspace_content_identity();
                *identity_checked = true;
            }
            let Some(identity) = *content_identity else {
                report_incomplete(
                    diagnostics,
                    Incompleteness::Operational(DerivationExecutionCause::Provider),
                    "Python import graph has no workspace content identity.",
                );
                return None;
            };
            context
                .analyzer
                .workspace_content_matches(identity)
                .then_some(identity)
                .or_else(|| {
                    report_incomplete(
                        diagnostics,
                        Incompleteness::Operational(DerivationExecutionCause::Snapshot),
                        "workspace content changed before Python import cycle traversal.",
                    );
                    None
                })
        })
    })
}

pub(super) fn read_reverse_adjacency(
    context: &mut PythonImportCycleContext<'_>,
    identity: WorkspaceContentIdentity,
    frontier: &[ProjectFile],
    cache: &mut PythonImportCycleCache,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Option<PersistedImportAdjacency> {
    let PythonImportCycleCache {
        read_scope_recorded,
        graph_ready,
        refresh_attempted,
        ..
    } = cache;
    let attribution = memo_attribution(context.analyzer);
    read_scope_recorded.read_mut(&attribution, |read_scope_recorded| {
        graph_ready.read_mut(&attribution, |graph_ready| {
            refresh_attempted.read_mut(&attribution, |refresh_attempted| {
    if !*read_scope_recorded
        && (brokk_bifrost_analysis::analyzer::read_attribution_records_reads(|| {
            context.analyzer.read_ledger_attached()
        }))
    {
        let languages = context.analyzer.languages().into_iter().collect::<Vec<_>>();
        context
            .analyzer
            .record_read(context.analyzer.workspace_scope_read_key(&languages));
        *read_scope_recorded = true;
    }

    let edge_limit = context
        .limits
        .max_pipeline_rows
        .saturating_sub(context.budget.import_edges_resolved);
    let read = context.analyzer.read_persisted_import_adjacency(
        identity,
        PersistedImportDirection::Reverse,
        frontier,
        edge_limit,
    );
    match read {
        Ok(Some(adjacency)) if context.analyzer.workspace_content_matches(identity) => {
            *graph_ready = true;
            Some(adjacency)
        }
        Ok(Some(_)) => {
            context.analyzer.mark_execution_dependent();
            report_incomplete(
                diagnostics,
                Incompleteness::Operational(DerivationExecutionCause::Snapshot), "workspace content changed during Python import cycle read.",
            );
            None
        }
        Ok(None) if !*graph_ready && !*refresh_attempted => {
            *refresh_attempted = true;
            let max_files = context
                .limits
                .max_scanned_files
                .saturating_sub(context.budget.import_files_resolved);
            let max_edges = context
                .limits
                .max_pipeline_rows
                .saturating_sub(context.budget.import_edges_resolved);
            if max_files == 0 {
                report_budget_exhausted(diagnostics, "file");
                return None;
            }
            match context.analyzer.refresh_persisted_import_graph(
                identity,
                context.cancellation,
                max_files,
                max_edges,
            ) {
                Ok(Some(refresh)) => {
                    context.budget.import_files_resolved = context
                        .budget
                        .import_files_resolved
                        .saturating_add(refresh.recomputed_files);
                    context.budget.import_edges_resolved = context
                        .budget
                        .import_edges_resolved
                        .saturating_add(refresh.recomputed_edges);
                    if !context.analyzer.workspace_content_matches(identity) {
                        context.analyzer.mark_execution_dependent();
                        report_incomplete(
                            diagnostics,
                            Incompleteness::Operational(DerivationExecutionCause::Snapshot), "workspace content changed while refreshing the Python import graph.",
                        );
                        return None;
                    }
                    let refreshed_limit = context
                        .limits
                        .max_pipeline_rows
                        .saturating_sub(context.budget.import_edges_resolved);
                    match context.analyzer.read_persisted_import_adjacency(
                        identity,
                        PersistedImportDirection::Reverse,
                        frontier,
                        refreshed_limit,
                    ) {
                        Ok(Some(adjacency))
                            if context.analyzer.workspace_content_matches(identity) =>
                        {
                            *graph_ready = true;
                            Some(adjacency)
                        }
                        Ok(Some(_)) => {
                            context.analyzer.mark_execution_dependent();
                            report_incomplete(
                                diagnostics,
                                Incompleteness::Operational(DerivationExecutionCause::Snapshot), "workspace content changed during Python import cycle read.",
                            );
                            None
                        }
                        Ok(None) => {
                            report_incomplete(
                                diagnostics,
                                Incompleteness::Operational(DerivationExecutionCause::Provider), "persisted Python import graph does not cover the current file.",
                            );
                            None
                        }
                        Err(error) => {
                            report_graph_read_error(context, error, diagnostics);
                            None
                        }
                    }
                }
                Ok(None) => {
                    report_incomplete(
                        diagnostics,
                        Incompleteness::Operational(DerivationExecutionCause::Provider), "persisted Python import graph is unavailable for this workspace.",
                    );
                    None
                }
                Err(error) => {
                    report_graph_read_error(context, error, diagnostics);
                    None
                }
            }
        }
        Ok(None) => {
            report_incomplete(
                diagnostics,
                Incompleteness::Operational(DerivationExecutionCause::Provider), "persisted Python import graph does not cover the current file.",
            );
            None
        }
        Err(error) => {
            report_graph_read_error(context, error, diagnostics);
            None
        }
    }
    })
        })
    })
}

pub(super) fn charge_import_file(context: &mut PythonImportCycleContext<'_>) -> Option<()> {
    if !brokk_bifrost_core::analyzer::work_budget::LimitedCounter::from_usage(
        context.budget.import_files_resolved,
        context.limits.max_scanned_files,
    )
    .allows(1)
    {
        return None;
    }
    context.budget.import_files_resolved = context.budget.import_files_resolved.saturating_add(1);
    Some(())
}

pub(super) fn module_identity_is_limited(path: &Path) -> bool {
    path.components().count() > 1 || path.file_name().is_some_and(|name| name == "__init__.py")
}

fn summarize_cycle_state(site: &mut CodeQueryPythonImportSite) {
    site.cycle_state = Some(
        if site
            .sites
            .iter()
            .any(|leaf| leaf.cycle_state == Some("cyclic"))
        {
            "cyclic"
        } else {
            "incomplete"
        },
    );
}

pub(super) fn report_budget_exhausted(diagnostics: &mut Vec<CodeQueryDiagnostic>, dimension: &str) {
    // Persisted adjacency reports its row cap after the bounded store read.
    brokk_bifrost_core::analyzer::carried_context::mark_execution_dependent();
    push_cycle_diagnostic(
        diagnostics,
        CodeQueryDiagnosticCode::ImportGraphBudgetExhausted,
        Incompleteness::Operational(DerivationExecutionCause::Budget),
        format!("Python import-cycle {dimension} budget was exhausted."),
    );
}

pub(super) fn report_incomplete(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    incompleteness: Incompleteness,
    message: &str,
) {
    push_cycle_diagnostic(
        diagnostics,
        CodeQueryDiagnosticCode::SemanticAnalysisPartial,
        incompleteness,
        message.to_owned(),
    );
}

fn report_graph_read_error(
    context: &mut PythonImportCycleContext<'_>,
    error: crate::analyzer::store::StoreError,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) {
    context.analyzer.record_query_failure(error.clone());
    let message = format!("reading persisted Python import graph failed: {error}");
    crate::profiling::note(format!("query_code {message}"));
    if context.access_mode == StructuralAccessMode::IndexedRequired {
        context
            .access_failure
            .get_or_insert_with(|| message.clone());
    }
    report_incomplete(
        diagnostics,
        Incompleteness::Operational(DerivationExecutionCause::Provider),
        &message,
    );
}

fn push_cycle_diagnostic(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    code: CodeQueryDiagnosticCode,
    incompleteness: Incompleteness,
    message: String,
) {
    if diagnostics.iter().any(|diagnostic| {
        diagnostic.code == code
            && diagnostic.language == Language::Python.config_label()
            && diagnostic.message == message
    }) {
        return;
    }
    diagnostics.push(CodeQueryDiagnostic::new(CodeQueryDiagnostic {
        incompleteness,
        related: Vec::new(),
        source: None,
        code,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: Language::Python.config_label(),
        message,
        exhausted_roots: Vec::new(),
        withheld_rows_path: None,
    }));
}
