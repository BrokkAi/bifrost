//! Native Go workspace graph projection.

use super::GoAnalyzer;
use crate::CancellationToken;
use crate::analyzer::languages::{EdgePassId, LanguageEdgeFailure, NativeWorkspaceGraphProvider};
use crate::analyzer::resolution::{FactReferenceEdgeDeclarationDomain, ResolutionCompletion};
use crate::analyzer::store::resolution_operation::{
    SelectedResolutionContextMetrics, SelectedResolutionOperationInput,
    SelectedResolutionOperationOpenOutcome, SelectedResolutionOperationOutcome,
};
use crate::analyzer::store::resolution_publication::SelectedResolutionOverlayInputsOutcome;
use crate::analyzer::store::resolution_selection::SelectedResolutionLanguage;
use crate::analyzer::store::{Result, StoreError};
use crate::analyzer::structural::reference_edges::{EdgeCompleteness, EdgeIncompleteReason};
use crate::analyzer::usages::workspace_graph::{
    NativeWorkspaceUsageGraphAccumulator, SelectedWorkspaceUsageGraphProjectionOutcome,
    UsageEcosystem, WorkspaceUsageCatalog, is_graph_declaration,
};
use crate::analyzer::{CodeUnitIndex, IAnalyzer, Language, ProjectFile, resolve_analyzer};
use crate::hash::HashSet;
use std::collections::BTreeSet;

pub(crate) struct GoNativeWorkspaceGraphProvider;

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
        let Some(snapshot) = go.inner.selected_workspace_snapshots().get("go").cloned() else {
            return Some(LanguageEdgeFailure {
                reason: "selected Go source publication is unavailable",
                files: request_files.to_vec(),
            });
        };
        let Some(profile) = go.native_context_profile() else {
            return Some(LanguageEdgeFailure {
                reason: "selected Go package/import profile is unavailable",
                files: request_files.to_vec(),
            });
        };
        match go
            .inner
            .analyzer_store()
            .selected_go_context(&snapshot, &profile)
        {
            Ok(Some(_)) => None,
            Ok(None) => Some(LanguageEdgeFailure {
                reason: "selected Go package/import publication is unavailable",
                files: request_files.to_vec(),
            }),
            Err(error) => {
                go.inner.record_store_error(error.context(
                    "checking selected Go package/import publication before native graph projection",
                ));
                Some(LanguageEdgeFailure {
                    reason: "selected Go package/import publication could not be checked",
                    files: Vec::new(),
                })
            }
        }
    }
}

/// Classify requested Go callers, then project admitted files' outgoing edges
/// through one selected operation. Rust and other languages are outside this pass.
pub(crate) fn build_go_native_workspace_graph_for_files(
    go: &GoAnalyzer,
    caller_files: &[ProjectFile],
    cancellation: &CancellationToken,
) -> Result<SelectedWorkspaceUsageGraphProjectionOutcome> {
    if cancellation.is_cancelled() {
        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
    }
    let generation = go.inner.project().analysis_generation();
    let snapshots = go.inner.selected_workspace_snapshots();
    let Some(snapshot) = snapshots.get("go") else {
        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(
            "selected Go workspace snapshot is unavailable".into(),
        ));
    };
    let Some(profile) = go.native_context_profile() else {
        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(
            "selected Go package/import profile is unavailable".into(),
        ));
    };
    let Some(context) = go
        .inner
        .analyzer_store()
        .selected_go_context(snapshot, &profile)?
    else {
        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(
            "selected Go package/import publication is unavailable".into(),
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
    let mut reasons = Vec::new();
    let mut reference_count = 0_usize;
    let mut batch_count = 0_usize;
    let mut receiver_type_file = None::<(ProjectFile, Box<[(usize, usize)]>)>;

    let staged = operation.stage_go_graph_reference_edge_batches_in_files(
        go,
        context.context_id,
        &admitted_callers,
        crate::analyzer::resolution::MAX_REFERENCE_SEEDS_PER_BATCH,
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
                    super::selected_reverse::go_receiver_type_reference_ranges(&source),
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
                    row.usage_kind = crate::analyzer::usages::UsageHitKind::SelfReceiver;
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
    if !accumulator.note_unresolved_names(
        unresolved_names_complete.then_some(&unresolved_names),
        cancellation,
    ) {
        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
    }
    let projection = accumulator.finish(&completeness, &summary, rows.len(), cancellation);
    if cancellation.is_cancelled() {
        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
    }
    if go.inner.project().analysis_generation() != generation {
        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Stale);
    }
    Ok(match projection {
        SelectedWorkspaceUsageGraphProjectionOutcome::Complete(graph) => {
            SelectedWorkspaceUsageGraphProjectionOutcome::Complete(graph)
        }
        SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(graph) => {
            SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(graph)
        }
        SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled => {
            SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled
        }
        SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(reason) => {
            SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(reason)
        }
        SelectedWorkspaceUsageGraphProjectionOutcome::Stale => {
            unreachable!("a reducer has no source authority to mark stale")
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::usages::workspace_graph::UsageEcosystem;
    use crate::inline_project::InlineTestProject;
    use crate::searchtools::{UsageGraphParams, UsageGraphResult, usage_graph};

    fn native_edge_names(
        graph: &crate::analyzer::usages::workspace_graph::SelectedWorkspaceUsageGraphProjection,
    ) -> BTreeSet<(String, String)> {
        graph
            .edges
            .iter()
            .map(|edge| {
                (
                    graph.nodes[edge.from].primary.fq_name().to_string(),
                    graph.nodes[edge.to].primary.fq_name().to_string(),
                )
            })
            .collect()
    }

    fn incumbent_edge_names(graph: &UsageGraphResult) -> BTreeSet<(String, String)> {
        graph
            .edges
            .iter()
            .map(|edge| (edge.from.clone(), edge.to.clone()))
            .collect()
    }

    #[test]
    fn native_go_graph_projects_whole_and_rooted_references() {
        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/graph\n\ngo 1.22\n")
            .file(
                "pkg/model.go",
                "package pkg\ntype Item struct{}\nfunc Target() {}\n",
            )
            .file(
                "pkg/caller.go",
                "package pkg\nfunc Caller() { Target(); _ = Item{}; _ = len([]int{}) }\n",
            )
            .file("other/other.go", "package other\nfunc Other() {}\n")
            .build();
        let go = GoAnalyzer::new(fixture.project_dyn());
        super::super::persist_live_go_sources_for_test(&go);
        let files = [
            fixture.file("pkg/model.go"),
            fixture.file("pkg/caller.go"),
            fixture.file("other/other.go"),
        ];
        let whole = GoNativeWorkspaceGraphProvider
            .project(&go, &files, &CancellationToken::new())
            .unwrap();
        let (graph, incomplete) = match whole {
            SelectedWorkspaceUsageGraphProjectionOutcome::Complete(graph) => (graph, false),
            SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(graph) => (graph, true),
            SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled => {
                panic!("Go graph projection was cancelled")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Stale => {
                panic!("Go graph projection became stale")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(reason) => {
                panic!("Go graph projection unavailable: {reason}")
            }
        };
        let incumbent_whole = usage_graph(
            &go,
            UsageGraphParams {
                include_tests: true,
                paths: None,
                depth: 1,
            },
        );
        assert_eq!(
            native_edge_names(&graph),
            incumbent_edge_names(&incumbent_whole),
            "whole-workspace native Go edges must match the incumbent",
        );
        assert!(
            !incomplete,
            "the builtin contributes no unresolved TypeOrCallable edge; the only unresolved name is from another graph domain: forward {:?}, unresolved {:?}, kind projection {}, references {}",
            graph.forward_completeness,
            graph.unresolved_names,
            graph.kind_projection_complete,
            graph.reference_count,
        );
        assert!(graph.resolved_ecosystems.contains(&UsageEcosystem::Go));
        assert!(graph.edges.iter().any(|edge| {
            graph.nodes[edge.from].primary.fq_name().ends_with("Caller")
                && graph.nodes[edge.to].primary.fq_name().ends_with("Target")
        }));
        assert!(graph.edges.iter().any(|edge| {
            graph.nodes[edge.from].primary.fq_name().ends_with("Caller")
                && graph.nodes[edge.to].primary.fq_name().ends_with("Item")
        }));
        assert!(
            graph
                .nodes
                .iter()
                .any(|node| node.primary.fq_name().ends_with("Other"))
        );

        let rooted = build_go_native_workspace_graph_for_files(
            &go,
            &[fixture.file("pkg/caller.go")],
            &CancellationToken::new(),
        )
        .unwrap();
        let rooted = match rooted {
            SelectedWorkspaceUsageGraphProjectionOutcome::Complete(graph)
            | SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(graph) => graph,
            SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled => {
                panic!("rooted Go graph projection was cancelled")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Stale => {
                panic!("rooted Go graph projection became stale")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(reason) => {
                panic!("rooted Go graph projection unavailable: {reason}")
            }
        };
        let incumbent_rooted = usage_graph(
            &go,
            UsageGraphParams {
                include_tests: true,
                paths: Some(vec!["pkg/caller.go".to_owned()]),
                depth: 1,
            },
        );
        assert_eq!(
            native_edge_names(&rooted),
            incumbent_edge_names(&incumbent_rooted),
            "rooted native Go edges must match the incumbent",
        );
        assert!(
            rooted
                .nodes
                .iter()
                .all(|node| !node.primary.fq_name().ends_with("Other"))
        );
    }

    #[test]
    fn native_go_graph_keeps_import_binders_with_their_source_file() {
        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/graph\n\ngo 1.22\n")
            .file(
                "dep/dep.go",
                r#"package foreign
func Explicit() {}
func Aliased() {}
func DotImported() {}
"#,
            )
            .file(
                "pkg/default_import.go",
                r#"package pkg
import "example.test/graph/dep"
func DefaultImportCaller() { foreign.Explicit() }
"#,
            )
            .file(
                "pkg/alias_import.go",
                r#"package pkg
import chosen "example.test/graph/dep"
func AliasImportCaller() { chosen.Aliased() }
"#,
            )
            .file(
                "pkg/dot_import.go",
                r#"package pkg
import . "example.test/graph/dep"
func DotImportCaller() { DotImported() }
"#,
            )
            .file(
                "pkg/no_import.go",
                r#"package pkg
func NoImportCaller() { foreign.Explicit(); chosen.Aliased(); DotImported() }
"#,
            )
            .build();
        let go = GoAnalyzer::new(fixture.project_dyn());
        super::super::persist_live_go_sources_for_test(&go);
        let files = [
            fixture.file("dep/dep.go"),
            fixture.file("pkg/default_import.go"),
            fixture.file("pkg/alias_import.go"),
            fixture.file("pkg/dot_import.go"),
            fixture.file("pkg/no_import.go"),
        ];
        let projected = GoNativeWorkspaceGraphProvider
            .project(&go, &files, &CancellationToken::new())
            .unwrap();
        let graph = match projected {
            SelectedWorkspaceUsageGraphProjectionOutcome::Complete(graph)
            | SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(graph) => graph,
            SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled => {
                panic!("Go graph projection was cancelled")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Stale => {
                panic!("Go graph projection became stale")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(reason) => {
                panic!("Go graph projection unavailable: {reason}")
            }
        };
        let edges = native_edge_names(&graph);
        for (caller, target) in [
            ("DefaultImportCaller", "Explicit"),
            ("AliasImportCaller", "Aliased"),
            ("DotImportCaller", "DotImported"),
        ] {
            assert!(
                edges
                    .iter()
                    .any(|(from, to)| from.ends_with(caller) && to.ends_with(target)),
                "the file-local {caller} import must resolve to {target}; edges were {edges:?}"
            );
        }
        assert!(
            edges.iter().all(|(from, to)| {
                !from.ends_with("NoImportCaller")
                    || !["Explicit", "Aliased", "DotImported"]
                        .iter()
                        .any(|target| to.ends_with(target))
            }),
            "another same-package file's import binder must not resolve from NoImportCaller: {edges:?}"
        );
    }

    #[test]
    #[ignore = "manual whole-corpus graph-stage profile"]
    fn native_go_graph_ttlcache_profile() {
        use std::path::PathBuf;
        use std::time::Instant;

        let root = PathBuf::from(
            std::env::var_os("BIFROST_GO_GRAPH_CORPUS")
                .expect("set BIFROST_GO_GRAPH_CORPUS to the ttlcache repository root"),
        );
        let project = crate::analyzer::FilesystemProject::new(root)
            .expect("open ttlcache as a persistent filesystem project");
        let go = GoAnalyzer::new(std::sync::Arc::new(project));
        super::super::persist_live_go_sources_for_test(&go);
        if std::env::var_os("BIFROST_GO_GRAPH_SETUP_ONLY").is_some() {
            return;
        }
        let output_path = PathBuf::from(
            std::env::var_os("BIFROST_GO_GRAPH_OUTPUT")
                .expect("set BIFROST_GO_GRAPH_OUTPUT to a temporary JSONL output path"),
        );
        let files = go.get_analyzed_files().into_iter().collect::<Vec<_>>();
        let started = Instant::now();
        let projected = GoNativeWorkspaceGraphProvider
            .project(&go, &files, &CancellationToken::new())
            .unwrap();
        let wall_ms = started.elapsed().as_secs_f64() * 1000.0;
        let (graph, complete) = match projected {
            SelectedWorkspaceUsageGraphProjectionOutcome::Complete(graph) => (graph, true),
            SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(graph) => (graph, false),
            SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled => {
                panic!("ttlcache Go graph projection was cancelled")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Stale => {
                panic!("ttlcache Go graph projection became stale")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(reason) => {
                panic!("ttlcache Go graph projection unavailable: {reason}")
            }
        };
        let mut edge_rows = graph
            .edges
            .iter()
            .map(|edge| {
                let from = &graph.nodes[edge.from];
                let to = &graph.nodes[edge.to];
                let mut sites = edge
                    .sites
                    .iter()
                    .map(|(file, line)| {
                        let path = file.rel_path().to_string_lossy().replace('\\', "/");
                        (path, *line)
                    })
                    .collect::<Vec<_>>();
                sites.sort();
                let row = serde_json::json!({
                    "from": from.key.fqn,
                    "from_id": from.key.id.to_string(),
                    "language": "go",
                    "sites": sites.iter().map(|(path, line)| serde_json::json!({
                        "line": line,
                        "path": path,
                    })).collect::<Vec<_>>(),
                    "to": to.key.fqn,
                    "to_id": to.key.id.to_string(),
                    "weight": sites.len(),
                });
                (
                    from.key.fqn.clone(),
                    to.key.fqn.clone(),
                    from.key.id.to_string(),
                    to.key.id.to_string(),
                    row,
                )
            })
            .collect::<Vec<_>>();
        edge_rows.sort_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then_with(|| left.1.cmp(&right.1))
                .then_with(|| left.2.cmp(&right.2))
                .then_with(|| left.3.cmp(&right.3))
        });
        let rows = edge_rows
            .into_iter()
            .map(|(_, _, _, _, row)| row)
            .collect::<Vec<_>>();
        let encoded = rows
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&output_path, format!("{encoded}\n"))
            .expect("write ttlcache Go graph edge set");
        if let Some(expected_path) = std::env::var_os("BIFROST_GO_GRAPH_EXPECTED_EDGE_SET") {
            let expected = std::fs::read_to_string(expected_path)
                .expect("read accepted ttlcache Go graph edge set")
                .lines()
                .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                .collect::<Vec<_>>();
            assert_eq!(rows, expected, "ttlcache graph edges match accepted set");
        }
        println!(
            "ttlcache native graph files={} nodes={} edges={} sites={} complete={} references={} batches={} wall_ms={wall_ms:.3}",
            files.len(),
            graph.nodes.len(),
            graph.edges.len(),
            graph
                .edges
                .iter()
                .map(|edge| edge.sites.len())
                .sum::<usize>(),
            complete,
            graph.reference_count,
            graph.batch_count,
        );
    }

    #[test]
    fn native_go_graph_keeps_nested_field_type_uses_and_excludes_receiver_types() {
        let source = r#"package cache

type Item[K comparable, V any] struct{}
type EvictionReason int

type Cache[K comparable, V any] struct {
    events struct {
        insertion struct {
            fns map[uint64]func(*Item[K, V])
        }
        eviction struct {
            fns map[uint64]func(EvictionReason, *Item[K, V])
        }
    }
}

func (item *Item[K, V]) Touch() {}

func Make() Cache[int, string] { return Cache[int, string]{} }
"#;
        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/cache\n\ngo 1.22\n")
            .file("cache.go", source)
            .build();
        let go = GoAnalyzer::new(fixture.project_dyn());
        super::super::persist_live_go_sources_for_test(&go);
        let graph = GoNativeWorkspaceGraphProvider
            .project(&go, &[fixture.file("cache.go")], &CancellationToken::new())
            .unwrap();
        let graph = match graph {
            SelectedWorkspaceUsageGraphProjectionOutcome::Complete(graph)
            | SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(graph) => graph,
            SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled => {
                panic!("nested-field Go graph projection was cancelled")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Stale => {
                panic!("nested-field Go graph projection became stale")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(reason) => {
                panic!("nested-field Go graph projection unavailable: {reason}")
            }
        };
        let names = native_edge_names(&graph);
        assert!(
            names
                .iter()
                .any(|(from, to)| { from.ends_with("Cache") && to.ends_with("Item") }),
            "generic type uses inside nested anonymous fields belong to Cache: {names:#?}"
        );
        assert!(
            names
                .iter()
                .any(|(from, to)| { from.ends_with("Cache") && to.ends_with("EvictionReason") }),
            "callback parameter type uses inside nested anonymous fields belong to Cache: {names:#?}"
        );
        assert!(
            !names
                .iter()
                .any(|(from, to)| { from.ends_with("Item.Touch") && to.ends_with("Item") }),
            "a method receiver type is a self-receiver hit, not an external graph edge: {names:#?}"
        );
    }

    #[test]
    fn native_go_graph_keeps_generic_callable_result_type_use() {
        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/cache\n\ngo 1.22\n")
            .file(
                "item.go",
                "package cache\ntype Item[K comparable, V any] struct{}\n",
            )
            .file(
                "queue.go",
                "package cache\ntype Queue[K comparable, V any] []*Item[K, V]\n\
                 func newQueue[K comparable, V any]() Queue[K, V] {\n\
                 \t_ = make(Queue[K, V], 0)\n\
                 \tfor {}\n}\n",
            )
            .build();
        let go = GoAnalyzer::new(fixture.project_dyn());
        super::super::persist_live_go_sources_for_test(&go);
        let graph = GoNativeWorkspaceGraphProvider
            .project(
                &go,
                &[fixture.file("item.go"), fixture.file("queue.go")],
                &CancellationToken::new(),
            )
            .unwrap();
        let graph = match graph {
            SelectedWorkspaceUsageGraphProjectionOutcome::Complete(graph)
            | SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(graph) => graph,
            SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled => {
                panic!("generic result Go graph projection was cancelled")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Stale => {
                panic!("generic result Go graph projection became stale")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(reason) => {
                panic!("generic result Go graph projection unavailable: {reason}")
            }
        };
        let names = native_edge_names(&graph);
        assert!(
            names
                .iter()
                .any(|(from, to)| { from.ends_with("newQueue") && to.ends_with("Queue") }),
            "the generic result type remains a reference of its callable: {names:#?}"
        );
        let queue_edge = graph
            .edges
            .iter()
            .find(|edge| {
                graph.nodes[edge.from]
                    .primary
                    .fq_name()
                    .ends_with("newQueue")
                    && graph.nodes[edge.to].primary.fq_name().ends_with("Queue")
            })
            .expect("generic result and make type use share their owner edge");
        assert_eq!(
            queue_edge.counts.types, 2,
            "the signature result and make type operand are both type-use sites"
        );
    }

    #[test]
    fn native_generic_receiver_and_promoted_method_edges_match_the_incumbent() {
        let source = r#"package auth

type Authenticator[T any] interface {
    Authenticate(value *T) error
}

type Handler[T any] struct {
    Authenticator[T]
}

func Use[T any](handler *Handler[T], value *T) error {
    return handler.Authenticate(value)
}

type Override[T any] struct {
    Authenticator[T]
}

func (*Override[T]) Authenticate(value *T) error { return nil }

func UseOverride[T any](handler *Override[T], value *T) error {
    return handler.Authenticate(value)
}

type Stack[T any] struct{}
func (stack Stack[T]) Push(value T) {}
func (stack *Stack[T]) Pop() {}
func Build() Stack[int] { return Stack[int]{} }
"#;
        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/generic\n\ngo 1.22\n")
            .file("auth/auth.go", source)
            .build();
        let go = GoAnalyzer::new(fixture.project_dyn());
        super::super::persist_live_go_sources_for_test(&go);
        let files = [fixture.file("auth/auth.go")];
        let native = GoNativeWorkspaceGraphProvider
            .project(&go, &files, &CancellationToken::new())
            .unwrap();
        let native = match native {
            SelectedWorkspaceUsageGraphProjectionOutcome::Complete(graph)
            | SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(graph) => graph,
            SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled => {
                panic!("generic Go graph projection was cancelled")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Stale => {
                panic!("generic Go graph projection became stale")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(reason) => {
                panic!("generic Go graph projection unavailable: {reason}")
            }
        };
        let incumbent = usage_graph(
            &go,
            UsageGraphParams {
                include_tests: true,
                paths: None,
                depth: 1,
            },
        );
        let is_external_source = |(from, _): &(String, String)| {
            matches!(
                from.rsplit('.').next(),
                Some("Use" | "UseOverride" | "Build")
            )
        };
        let native_edges = native_edge_names(&native);
        let native_external_edges = native_edges
            .iter()
            .filter(|edge| is_external_source(edge))
            .cloned()
            .collect::<BTreeSet<_>>();
        let incumbent_external_edges = incumbent_edge_names(&incumbent)
            .into_iter()
            .filter(|(from, _)| {
                matches!(
                    from.rsplit('.').next(),
                    Some("Use" | "UseOverride" | "Build")
                )
            })
            .collect::<BTreeSet<_>>();
        eprintln!(
            "native generic graph completeness={:?} unresolved={:?} references={} edges={:?}",
            native.forward_completeness,
            native.unresolved_names,
            native.reference_count,
            native_edge_names(&native)
        );
        assert_eq!(
            native_external_edges, incumbent_external_edges,
            "native generic calls and type mentions match the incumbent; declaration and self-receiver edges remain available in the native projection"
        );
        for source in ["Handler", "Override"] {
            assert!(
                native_edges.contains(&(
                    format!("example.test/generic/auth.{source}"),
                    "example.test/generic/auth.Authenticator".into()
                )),
                "the native package context retains {source}'s promoted embedded interface edge"
            );
        }
        assert!(
            native.edges.iter().any(|edge| {
                native.nodes[edge.from].primary.fq_name().ends_with("Use")
                    && native.nodes[edge.to]
                        .primary
                        .fq_name()
                        .ends_with("Authenticator.Authenticate")
            }),
            "the generic embedded interface call retains its exact target"
        );
        assert!(
            native.edges.iter().any(|edge| {
                native.nodes[edge.from].primary.fq_name().ends_with("Build")
                    && native.nodes[edge.to].primary.fq_name().ends_with("Stack")
            }),
            "generic receiver and composite type references resolve to Stack"
        );
        for method in ["Push", "Pop"] {
            assert!(
                !native.edges.iter().any(|edge| {
                    native.nodes[edge.from]
                        .primary
                        .fq_name()
                        .ends_with(&format!("Stack.{method}"))
                        && native.nodes[edge.to].primary.fq_name().ends_with("Stack")
                }),
                "generic {method} receiver reference stays off the external usage graph"
            );
        }
    }

    #[test]
    fn go_native_graph_does_not_change_rust_answers_in_a_mixed_workspace() {
        use crate::analyzer::RustAnalyzer;
        use crate::analyzer::{
            RustNativeWorkspaceGraphOutcome, build_rust_native_workspace_graph_for_files,
        };

        let fixture = InlineTestProject::new()
            .file("go.mod", "module example.test/mixed\n\ngo 1.22\n")
            .file(
                "go/calls.go",
                "package calls\nfunc GoTarget() {}\nfunc GoCaller() { GoTarget() }\n",
            )
            .file(
                "Cargo.toml",
                "[package]\nname = \"mixed_graph\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "pub fn rust_target() {}\npub fn rust_caller() { rust_target() }\n",
            )
            .build();
        let go = GoAnalyzer::new(fixture.project_dyn());
        let rust = RustAnalyzer::new(fixture.project_dyn());
        super::super::persist_live_go_sources_for_test(&go);

        let rust_file = fixture.file("src/lib.rs");
        let cancellation = CancellationToken::new();
        let before = build_rust_native_workspace_graph_for_files(
            &rust,
            std::slice::from_ref(&rust_file),
            crate::analyzer::resolution::MAX_REFERENCE_SEEDS_PER_BATCH,
            &cancellation,
        )
        .unwrap();
        let before = match before {
            RustNativeWorkspaceGraphOutcome::Complete(graph)
            | RustNativeWorkspaceGraphOutcome::Incomplete(graph) => graph,
            RustNativeWorkspaceGraphOutcome::Cancelled => {
                panic!("Rust baseline graph was cancelled")
            }
            RustNativeWorkspaceGraphOutcome::Stale(reason)
            | RustNativeWorkspaceGraphOutcome::Unavailable(reason) => {
                panic!("Rust baseline graph unavailable: {reason}")
            }
        };
        let baseline_edges = native_edge_names(&before);
        let go_outcome = build_go_native_workspace_graph_for_files(
            &go,
            &[fixture.file("go/calls.go")],
            &cancellation,
        )
        .unwrap();
        assert!(matches!(
            go_outcome,
            SelectedWorkspaceUsageGraphProjectionOutcome::Complete(_)
                | SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(_)
        ));
        let after = build_rust_native_workspace_graph_for_files(
            &rust,
            std::slice::from_ref(&rust_file),
            crate::analyzer::resolution::MAX_REFERENCE_SEEDS_PER_BATCH,
            &cancellation,
        )
        .unwrap();
        let after = match after {
            RustNativeWorkspaceGraphOutcome::Complete(graph)
            | RustNativeWorkspaceGraphOutcome::Incomplete(graph) => graph,
            RustNativeWorkspaceGraphOutcome::Cancelled => {
                panic!("Rust comparison graph was cancelled")
            }
            RustNativeWorkspaceGraphOutcome::Stale(reason)
            | RustNativeWorkspaceGraphOutcome::Unavailable(reason) => {
                panic!("Rust comparison graph unavailable: {reason}")
            }
        };
        assert_eq!(native_edge_names(&after), baseline_edges);
    }
}
