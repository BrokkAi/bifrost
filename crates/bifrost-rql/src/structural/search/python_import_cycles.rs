//! Query-scoped Python import-cycle checks over persisted file adjacency.

use super::*;
use crate::analyzer::content_identity::WorkspaceContentIdentity;
use crate::analyzer::{PersistedImportAdjacency, PersistedImportDirection};
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
    content_identity: Option<WorkspaceContentIdentity>,
    identity_checked: bool,
    graph_ready: bool,
    refresh_attempted: bool,
    read_scope_recorded: bool,
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
            report_incomplete(diagnostics, "Python import-cycle traversal was cancelled.");
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
            report_incomplete(
                diagnostics,
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
                "Python import cycle has an unresolved, external, ambiguous, or unavailable target.",
            );
            continue;
        }
        let target = importer.with_rel_path(leaf.target_paths[0].as_str());
        if target.language() != Language::Python || module_identity_is_limited(target.rel_path()) {
            report_incomplete(
                diagnostics,
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

    while !frontier.is_empty() && !remaining_targets.is_empty() {
        if context
            .cancellation
            .is_some_and(CancellationToken::is_cancelled)
        {
            report_incomplete(diagnostics, "Python import cycle traversal was cancelled.");
            incomplete = true;
            break;
        }

        let Some(adjacency) =
            read_reverse_adjacency(context, content_identity, &frontier, cache, diagnostics)
        else {
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
            report_incomplete(
                diagnostics,
                "workspace content changed during Python import cycle traversal.",
            );
            incomplete = true;
            break;
        }
        if adjacency.exhausted {
            report_budget_exhausted(diagnostics, "edge");
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
    if !context.access_mode.permits_persisted_import_graph() {
        report_incomplete(
            diagnostics,
            "Python import graph access is unavailable in this query mode.",
        );
        return None;
    }
    if !cache.identity_checked {
        cache.content_identity = context.analyzer.workspace_content_identity();
        cache.identity_checked = true;
    }
    let Some(identity) = cache.content_identity else {
        report_incomplete(
            diagnostics,
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
                "workspace content changed before Python import cycle traversal.",
            );
            None
        })
}

pub(super) fn read_reverse_adjacency(
    context: &mut PythonImportCycleContext<'_>,
    identity: WorkspaceContentIdentity,
    frontier: &[ProjectFile],
    cache: &mut PythonImportCycleCache,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Option<PersistedImportAdjacency> {
    if !cache.read_scope_recorded && context.analyzer.read_ledger_attached() {
        let languages = context.analyzer.languages().into_iter().collect::<Vec<_>>();
        context
            .analyzer
            .record_read(context.analyzer.workspace_scope_read_key(&languages));
        cache.read_scope_recorded = true;
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
            cache.graph_ready = true;
            Some(adjacency)
        }
        Ok(Some(_)) => {
            report_incomplete(
                diagnostics,
                "workspace content changed during Python import cycle read.",
            );
            None
        }
        Ok(None) if !cache.graph_ready && !cache.refresh_attempted => {
            cache.refresh_attempted = true;
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
                        report_incomplete(
                            diagnostics,
                            "workspace content changed while refreshing the Python import graph.",
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
                            cache.graph_ready = true;
                            Some(adjacency)
                        }
                        Ok(Some(_)) => {
                            report_incomplete(
                                diagnostics,
                                "workspace content changed during Python import cycle read.",
                            );
                            None
                        }
                        Ok(None) => {
                            report_incomplete(
                                diagnostics,
                                "persisted Python import graph does not cover the current file.",
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
                        "persisted Python import graph is unavailable for this workspace.",
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
                "persisted Python import graph does not cover the current file.",
            );
            None
        }
        Err(error) => {
            report_graph_read_error(context, error, diagnostics);
            None
        }
    }
}

pub(super) fn charge_import_file(context: &mut PythonImportCycleContext<'_>) -> Option<()> {
    if context.budget.import_files_resolved >= context.limits.max_scanned_files {
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
    push_cycle_diagnostic(
        diagnostics,
        CodeQueryDiagnosticCode::ImportGraphBudgetExhausted,
        format!("Python import-cycle {dimension} budget was exhausted."),
    );
}

pub(super) fn report_incomplete(diagnostics: &mut Vec<CodeQueryDiagnostic>, message: &str) {
    push_cycle_diagnostic(
        diagnostics,
        CodeQueryDiagnosticCode::SemanticAnalysisPartial,
        message.to_owned(),
    );
}

fn report_graph_read_error(
    context: &mut PythonImportCycleContext<'_>,
    error: crate::analyzer::store::StoreError,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) {
    let message = format!("reading persisted Python import graph failed: {error}");
    crate::profiling::note(format!("query_code {message}"));
    if context.access_mode == StructuralAccessMode::IndexedRequired {
        context
            .access_failure
            .get_or_insert_with(|| message.clone());
    }
    report_incomplete(diagnostics, &message);
}

fn push_cycle_diagnostic(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    code: CodeQueryDiagnosticCode,
    message: String,
) {
    if diagnostics.iter().any(|diagnostic| {
        diagnostic.code == code
            && diagnostic.language == Language::Python.config_label()
            && diagnostic.message == message
    }) {
        return;
    }
    diagnostics.push(CodeQueryDiagnostic {
        code,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: Language::Python.config_label(),
        message,
        exhausted_roots: Vec::new(),
    });
}
