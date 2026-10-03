//! Go's usage-graph strategy: the analysis-side half.
//!
//! The language knowledge -- the AST vocabulary, the reference resolver, the
//! project and edge indexes, and both scan bodies -- lives in
//! [`brokk_bifrost_go::graph`]. What stays here is the SPI: the trait impls, the
//! downcasts that unpack a `GoAnalyzer` into the core capability traits and Go
//! side data the go crate takes, and [`build_go_edges`], whose workspace fan-out
//! needs an analyzer handle for each file's declaration index.

use crate::analyzer::usages::traits::GraphUsageAnalyzer;
use brokk_bifrost_core::analyzer::query_token::QueryToken;

use crate::analyzer::usages::common::{
    analyzed_files_for_language, classify_recursive_hits, language_for_target,
};
use crate::analyzer::usages::inverted_edges::{
    EdgeNodeDomain, UsageEdgeBuildOutput, UsageEdgeBuildResult, UsageEdgeWeights, UsageEdges,
    build_edge_output_with_completeness, build_file_declarations,
    parse_source_and_collect_with_declarations_and_domain,
};
use crate::analyzer::usages::model::{FuzzyResult, UsageAnalysisDiagnostic};
use crate::analyzer::usages::outcome::{
    CandidateUsageHits, GraphFailureReason, GraphUsageOutcome, union_candidate_usages,
};
use crate::analyzer::usages::traits::{UsageQueryResolver, UsageScanScope};
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
use crate::analyzer::{CodeUnit, GoAnalyzer, IAnalyzer, Language, ProjectFile, resolve_analyzer};
use crate::hash::HashSet;
use brokk_bifrost_go::graph::extractor::scan_files_for_target;
use brokk_bifrost_go::graph::inverted::scan_go_file;
pub(in crate::analyzer::usages) use brokk_bifrost_go::graph::reference::{
    GoReferenceResolution, GoSelectorDescriptor, go_selector_descriptor,
    go_selector_descriptor_with_scope, resolve_go_reference_with_namespaces,
};
use brokk_bifrost_go::graph::resolver::{
    GoEdgeIndex, GoGraphBuildError, GoGraphSource, GoProjectGraph, TargetSpec,
    build_go_graph_with_edge_index,
};
use std::sync::Arc;

/// Classify Go's runtime/test entry points from the persisted package clause.
/// Only a function named `main` needs that fact; the Go crate owns the pure shape and
/// test-file rules, while this shim supplies the analyzer's structured property.
pub(crate) fn go_implicit_entry_point(
    analyzer: &dyn IAnalyzer,
    candidate: &CodeUnit,
) -> Option<bool> {
    let package_clause = (candidate.is_function() && candidate.identifier() == "main")
        .then(|| {
            resolve_analyzer::<GoAnalyzer>(analyzer)
                .and_then(|go| go.package_clause_of(candidate.source()))
        })
        .flatten();
    brokk_bifrost_go::graph::go_implicit_entry_point(candidate, package_clause.as_deref())
}

/// Build every Go `caller -> callee` edge in one pass over the workspace.
///
/// The per-symbol path ([`scan_candidate_with_graph`]) answers "who calls X" by
/// scanning every candidate file for X. Building the *whole* graph that way
/// walks each file once per symbol whose name it contains -- quadratic on real
/// repos. This inverts it: walk each file's tree once, resolve every reference
/// to the fully qualified callee it names, and emit a `caller -> callee` edge
/// when both endpoints are nodes. Cost is linear in total source size,
/// independent of the symbol count.
///
/// All the language-agnostic accounting (parallel fan-out, enclosing
/// attribution, per-callee cap, dedup, merge) lives in [`build_edge_output`];
/// this function supplies only the two Go-specific pieces: the per-file package
/// facts and [`scan_go_file`], the AST walk that resolves each reference.
///
/// Trees are parsed on demand inside the per-file walk and dropped when the
/// closure returns, so live trees are bounded by the worker count rather than
/// the workspace size (#200). Cross-file resolution comes from the tree-free
/// [`GoEdgeIndex`] and the index's per-file import facts -- no other file's tree
/// is read during a scan. Missing indexed source or an incomplete parse is
/// returned as an explicit error instead of being published as an empty graph.
fn build_go_edges<Output, F>(
    analyzer: &dyn IAnalyzer,
    index: &GoEdgeIndex,
    domain: EdgeNodeDomain<'_>,
    keep_file: F,
) -> Result<Output, GoGraphBuildError>
where
    Output: UsageEdgeBuildOutput<String>,
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let files: Vec<ProjectFile> = index.files().cloned().collect();
    let language = tree_sitter_go::LANGUAGE.into();
    let result = build_edge_output_with_completeness(&files, keep_file, |file| {
        let source = analyzer.indexed_source(file)?;
        let file_pkg = index.package_name_of(file)?;
        let declarations = build_file_declarations(analyzer, file);
        parse_source_and_collect_with_declarations_and_domain(
            source,
            file,
            domain,
            brokk_bifrost_go::parse::go_parse_spec(&language),
            declarations,
            |input| {
                let (alias_packages, dot_packages) = index.namespace_packages(file);
                let import_binding_names = index.import_binding_names(file);
                scan_go_file(
                    index,
                    file_pkg,
                    alias_packages,
                    dot_packages,
                    import_binding_names,
                    input,
                )
            },
        )
    });
    match result {
        UsageEdgeBuildResult::Complete(output) => Ok(output),
        UsageEdgeBuildResult::Uncacheable { omitted_files, .. } => {
            Err(GoGraphBuildError::from_files(omitted_files))
        }
    }
}

/// Build the whole Go `caller -> callee` edge set in a single inverted pass over
/// the workspace (see [`build_go_edges`]). `Ok(None)` means the analyzer does
/// not expose Go files. An error means selected input was unavailable, not an
/// empty graph. `nodes` is the set of node fqns and `keep_file` drops
/// out-of-scope caller files; the per-file definition ranges used to exclude
/// self-declarations are derived inside the shared driver.
pub(crate) fn build_go_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Result<Option<UsageEdges>, GoGraphBuildError>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let Some(resolver) = GoEdgeResolver::try_new(analyzer, token)? else {
        return Ok(None);
    };
    resolver.build_edges(analyzer, nodes, keep_file).map(Some)
}

pub(crate) fn build_rooted_go_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    callers: &HashSet<String>,
    keep_file: F,
) -> Result<Option<UsageEdges>, GoGraphBuildError>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let Some(resolver) = GoEdgeResolver::try_new(analyzer, token)? else {
        return Ok(None);
    };
    resolver
        .build_rooted_edges(analyzer, callers, keep_file)
        .map(Some)
}

pub(crate) fn build_go_usage_edge_weights<F>(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Result<Option<UsageEdgeWeights>, GoGraphBuildError>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let Some(resolver) = GoEdgeResolver::try_new(analyzer, token)? else {
        return Ok(None);
    };
    resolver
        .build_edge_weights(analyzer, nodes, keep_file)
        .map(Some)
}

/// The strategy name every Go usage diagnostic reports.
const GO_STRATEGY: &str = "GoUsageGraphStrategy";

fn unavailable_go_graph_diagnostic(
    target: &CodeUnit,
    error: &GoGraphBuildError,
) -> UsageAnalysisDiagnostic {
    let mut diagnostic =
        GraphFailureReason::UnavailableCanonicalFacts("Go graph indexed source was unavailable")
            .diagnostic(target.fq_name(), GO_STRATEGY);
    diagnostic.reason = format!(
        "{}; unavailable files: {:?}",
        diagnostic.reason, error.unavailable_files
    );
    diagnostic
}

fn cancelled_go_graph_diagnostic(target: &CodeUnit) -> UsageAnalysisDiagnostic {
    GraphFailureReason::Cancelled("Go graph construction was cancelled")
        .diagnostic(target.fq_name(), GO_STRATEGY)
}

fn cancelled_go_graph_outcome(target: &CodeUnit) -> GraphUsageOutcome {
    GraphUsageOutcome::TerminalFailure(cancelled_go_graph_diagnostic(target))
}

pub(crate) struct GoQueryResolver<'a> {
    go: &'a GoAnalyzer,
}

/// The Go crate takes its analyzer facts as core capability traits plus the Go
/// workspace path index; this is the one place the concrete analyzer is
/// unpacked into them.
pub(crate) fn go_graph_source<'a>(go: &'a GoAnalyzer, token: QueryToken<'a>) -> GoGraphSource<'a> {
    GoGraphSource {
        token,
        index: go,
        imports: go,
        type_aliases: go,
        workspace_paths: go.workspace_path_index(),
        package_clauses: go,
        source_facts: go,
    }
}

impl<'a> UsageQueryResolver<'a> for GoQueryResolver<'a> {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        Some(Self {
            go: resolve_analyzer::<GoAnalyzer>(analyzer)?,
        })
    }

    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        let candidate_files = scan_scope.candidate_files();
        // Candidate files bound where references may be reported, not which
        // declarations may participate in receiver typing. A narrow exact-site
        // query can still reach an interface through embedded structs declared
        // in other files/packages (#2072), so build resolution facts from the
        // candidate/target packages and their transitive workspace imports,
        // while retaining/scanning only the requested candidate trees. The
        // complete file inventory lets the Go crate discover that dependency
        // closure without parsing unrelated packages.
        if scan_scope.is_cancelled() {
            return cancelled_go_graph_outcome(
                overloads.first().expect("non-empty Go usage target group"),
            );
        }
        let edge_index = match self.go.usage_edge_index() {
            Ok(edge_index) => edge_index,
            Err(error) => {
                if scan_scope.is_cancelled() {
                    return cancelled_go_graph_outcome(
                        overloads.first().expect("non-empty Go usage target group"),
                    );
                }
                let diagnostic = unavailable_go_graph_diagnostic(
                    overloads.first().expect("non-empty Go usage target group"),
                    &error,
                );
                return GraphUsageOutcome::TerminalFailure(diagnostic);
            }
        };
        let graph_scope = AnalyzerQueryScope::new(self.go);
        let graph_source = go_graph_source(self.go, graph_scope.token());
        let mut graph_failure = None;
        let outcome = union_candidate_usages(overloads, max_usages, |target| {
            // The graph is seeded from the candidate's own file, so a target
            // group holding declarations in different packages (#1779) builds
            // one graph per candidate.
            let graph_result = build_go_graph_with_edge_index(
                graph_source,
                Arc::clone(&edge_index),
                candidate_files,
                target,
                scan_scope.cancellation(),
            );
            if scan_scope.is_cancelled() {
                let diagnostic = cancelled_go_graph_diagnostic(target);
                graph_failure = Some(diagnostic.clone());
                return Err(diagnostic);
            }
            let graph = match graph_result {
                Ok(graph) => graph,
                Err(error) => {
                    let diagnostic = unavailable_go_graph_diagnostic(target, &error);
                    graph_failure = Some(diagnostic.clone());
                    return Err(diagnostic);
                }
            };
            scan_candidate_with_graph(
                analyzer,
                self.go,
                &graph,
                target,
                candidate_files,
                scan_scope,
            )
        });
        if scan_scope.is_cancelled() {
            return cancelled_go_graph_outcome(
                overloads.first().expect("non-empty Go usage target group"),
            );
        }
        if let Some(diagnostic) = graph_failure {
            GraphUsageOutcome::TerminalFailure(diagnostic)
        } else {
            outcome
        }
    }
}

pub(crate) struct GoEdgeResolver {
    index: Arc<GoEdgeIndex>,
}

/// The whole-workspace `caller -> callee` scan behind this language's
/// [`LanguageEdgePass`](crate::analyzer::languages::LanguageEdgePass): borrow the concrete
/// analyzer once, then walk every file once and finalize into either site-bearing edges or
/// reference-kind weights.
impl GoEdgeResolver {
    pub(crate) fn try_new(
        analyzer: &dyn IAnalyzer,
        _token: QueryToken<'_>,
    ) -> Result<Option<Self>, GoGraphBuildError> {
        let files = analyzed_files_for_language(analyzer, Language::Go);
        let Some(go) = resolve_analyzer::<GoAnalyzer>(analyzer) else {
            return if files.is_empty() {
                Ok(None)
            } else {
                Err(GoGraphBuildError::from_files(files))
            };
        };
        if !go.graph_inventory_complete() {
            return Err(GoGraphBuildError::from_files(files));
        }
        if files.is_empty() {
            return Ok(None);
        }
        // Reuse the analyzer's memoized source-authoritative edge index. The
        // per-file walk re-parses only its selected source tree on demand and
        // drops it, so the whole-workspace build retains no syntax trees.
        let index = go.usage_edge_index()?;
        Ok(Some(Self { index }))
    }

    pub(crate) fn build_edges<F>(
        &self,
        analyzer: &dyn IAnalyzer,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> Result<UsageEdges, GoGraphBuildError>
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        build_go_edges(
            analyzer,
            &self.index,
            EdgeNodeDomain::Closed(nodes),
            keep_file,
        )
    }

    pub(crate) fn build_rooted_edges<F>(
        &self,
        analyzer: &dyn IAnalyzer,
        callers: &HashSet<String>,
        keep_file: F,
    ) -> Result<UsageEdges, GoGraphBuildError>
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        build_go_edges(
            analyzer,
            &self.index,
            EdgeNodeDomain::Rooted(callers),
            keep_file,
        )
    }

    pub(crate) fn build_edge_weights<F>(
        &self,
        analyzer: &dyn IAnalyzer,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> Result<UsageEdgeWeights, GoGraphBuildError>
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        build_go_edges(
            analyzer,
            &self.index,
            EdgeNodeDomain::Closed(nodes),
            keep_file,
        )
    }
}

#[derive(Default)]
pub struct GoUsageGraphStrategy {
    _private: (),
}

impl GoUsageGraphStrategy {
    pub const fn new() -> Self {
        Self { _private: () }
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        language_for_target(target) == Language::Go
    }
}

impl GraphUsageAnalyzer for GoUsageGraphStrategy {
    fn find_graph_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        if overloads.is_empty() {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        }

        let target = &overloads[0];
        if language_for_target(target) != Language::Go {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetLanguage("target is not Go"),
                GO_STRATEGY,
            );
        }

        let Some(resolver) = GoQueryResolver::try_new(analyzer) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::MissingAnalyzerCapability(
                    "analyzer does not expose GoAnalyzer",
                ),
                GO_STRATEGY,
            );
        };

        resolver.find_usages(analyzer, overloads, scan_scope, max_usages)
    }
}

/// Resolve one candidate declaration's callers against an already-built
/// [`GoProjectGraph`]. `Err` is this candidate declining; the query's answer
/// unions every candidate that did resolve (see [`union_candidate_usages`]).
fn scan_candidate_with_graph(
    analyzer: &dyn IAnalyzer,
    go: &GoAnalyzer,
    graph: &GoProjectGraph,
    target: &CodeUnit,
    candidate_files: &HashSet<ProjectFile>,
    scan_scope: &UsageScanScope<'_>,
) -> Result<CandidateUsageHits, UsageAnalysisDiagnostic> {
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    let target_spec = TargetSpec::new(go_graph_source(go, token), graph, target);
    if !target_spec.has_scan_seed() {
        return Err(GraphFailureReason::NoGraphSeed("no graph seed resolved")
            .diagnostic(target.fq_name(), GO_STRATEGY));
    }

    let mut scan_files = graph.scan_files(candidate_files, target, &target_spec);
    scan_files.retain(|file| scan_scope.allows(file));
    let scan_result = scan_files_for_target(
        analyzer,
        graph,
        scan_files,
        &target_spec,
        scan_scope.cancellation(),
    );
    // The scan classifies a proven recursive call into a callable target as
    // `SelfReceiver` (#1638); this pass drops every other
    // enclosing-equals-target hit, as does the unproven channel below.
    Ok(CandidateUsageHits {
        hits: classify_recursive_hits(analyzer, scan_result.hits, target),
        unproven_hits: scan_result
            .unproven_hits
            .into_iter()
            .filter(|hit| &hit.enclosing != target)
            .collect(),
    })
}

#[cfg(test)]
mod file_scope_tests {
    use super::*;
    use crate::analyzer::{CodeUnitIndex, EmptyAnalyzer};
    use crate::inline_project::InlineTestProject;
    use std::collections::BTreeSet;

    // Canonical graph resolution is separate from enclosing attribution.
    // EmptyAnalyzer supplies only the latter and makes no completeness claim.
    #[test]
    fn canonical_go_reference_without_enclosing_declaration_keeps_file_scope_hit() {
        let project = InlineTestProject::with_language(Language::Go)
            .file("target.go", "package sample\nfunc target() {}\n")
            .file("caller.go", "package sample\nfunc caller() { target() }\n")
            .build();
        let go = GoAnalyzer::new(project.project_dyn());
        let target = go
            .get_all_declarations()
            .into_iter()
            .find(|unit| unit.is_function() && unit.identifier() == "target")
            .expect("canonical target declaration");
        let caller = project.file("caller.go");
        let candidates = [caller.clone()].into_iter().collect();
        let index = go.usage_edge_index().expect("complete canonical graph");
        let scope = AnalyzerQueryScope::new(&go);
        let source = go_graph_source(&go, scope.token());
        let graph = build_go_graph_with_edge_index(source, index, &candidates, &target, None)
            .expect("canonical candidate facts");
        let spec = TargetSpec::new(source, &graph, &target);
        assert!(spec.has_scan_seed());
        let attribution = EmptyAnalyzer::new(project.project_dyn());
        let result = scan_files_for_target(&attribution, &graph, candidates, &spec, None);
        assert_eq!(result.hits.len(), 1, "{:?}", result.hits);
        let hit = result.hits.first().unwrap();
        assert_eq!(hit.enclosing, CodeUnit::file_scope(caller));
        assert_eq!(
            &graph.parsed[&hit.file].source[hit.start_offset..hit.end_offset],
            "target"
        );
    }

    #[test]
    fn ruby_reference_without_enclosing_declaration_keeps_file_scope_hit() {
        let source = "target()\n";
        let project = InlineTestProject::with_language(Language::Ruby)
            .file("caller.rb", source)
            .build();
        let file = project.file("caller.rb");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_ruby::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let call = tree.root_node().named_child(0).unwrap();
        let node = call.child_by_field_name("method").unwrap();
        let attribution = EmptyAnalyzer::new(project.project_dyn());
        let mut hits = BTreeSet::new();
        brokk_bifrost_ruby::graph::hits::record_usage_hit(
            &attribution,
            &file,
            source,
            &[0],
            &mut hits,
            node,
        );
        assert_eq!(hits.len(), 1, "{hits:?}");
        let hit = hits.first().unwrap();
        assert_eq!(hit.enclosing, CodeUnit::file_scope(file));
        assert_eq!(&source[hit.start_offset..hit.end_offset], "target");
        let mut unproven = BTreeSet::new();
        brokk_bifrost_ruby::graph::hits::record_unproven_usage_hit(
            &attribution,
            &hit.file,
            source,
            &[0],
            &mut unproven,
            node,
        );
        assert_eq!(unproven.len(), 1, "{unproven:?}");
        assert_eq!(unproven.first().unwrap().enclosing, hit.enclosing);
    }
}
