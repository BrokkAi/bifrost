//! The analysis-side wrappers over [`brokk_bifrost_cpp::graph`].
//!
//! The scans themselves moved with the language knowledge -- the forward
//! extractor, the visibility/macro/include resolver, the hit builder and the
//! per-file inverted walk are one body of code and crossed together. What stays
//! here is the downcast that produces their arguments, the dispatching
//! analyzer's side of a scan ([`CppDispatch`]), the `GraphUsageAnalyzer` /
//! `UsageQueryResolver` / `UsageAnalyzer` strategy shells (all analysis-owned
//! traits), the inverted pass's fan-out -- `build_edge_output` and
//! `parse_and_collect` are the shared, language-agnostic driver -- the
//! dead-code bulk eligibility split at the downcast, and
//! [`CppAuthoritativeUsageBatch`], whose public path the root crate's
//! reference differential depends on.

use crate::analyzer::CppAnalyzer;
pub use crate::analyzer::usages::cpp_graph::shared::CppAuthoritativeUsageBatch;
use crate::analyzer::usages::cpp_graph::shared::CppEdgeResolver;
use crate::analyzer::usages::cpp_graph::shared::CppQueryResolver;
use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;
use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;
use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
use brokk_bifrost_analysis::analyzer::usages::common::language_for_target;
use brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageAnalyzer;
use brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageDispatchSpec;
use brokk_bifrost_core::analyzer::model::CodeUnit;
use brokk_bifrost_core::analyzer::model::Language;
use brokk_bifrost_core::analyzer::model::ProjectFile;
use brokk_bifrost_core::analyzer::query_token::QueryScope;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::usages::inverted_edges::UsageEdgeWeights;
use brokk_bifrost_core::analyzer::usages::inverted_edges::UsageEdges;
use brokk_bifrost_core::analyzer::usages::outcome::GraphUsageOutcome;
use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;
use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_cpp::graph::resolver::{TargetKind, TargetSpec};
use brokk_bifrost_cpp::graph::{CppGraphSource, CppWorkspaceSource};
use brokk_bifrost_cpp::graph_support::CppSource;
#[cfg(test)]
mod extractor_tests;
pub mod macro_lexical;
#[cfg(test)]
mod resolver_tests;
mod shared;

/// The *dispatching* analyzer, in the shape [`brokk_bifrost_cpp::graph`] asks
/// for.
///
/// Not the C++ analyzer: in a mixed workspace the query is issued against a
/// `MultiAnalyzer`, whose `definitions` merges every language's shards and
/// whose `import_statements` and provider accessors cross language boundaries,
/// and the C++ walks depend on that reach. The C++ analyzer that answers the
/// C++-only questions is resolved once here rather than at each of the nine
/// `resolve_analyzer::<CppAnalyzer>` sites the scans used to carry.
///
/// A borrowed newtype rather than a bare `&dyn IAnalyzer` because the dispatch
/// carries capabilities that cannot be combined into one trait object.
pub(crate) struct CppDispatch<'a> {
    analyzer: &'a dyn IAnalyzer,
    cpp: Option<&'a CppAnalyzer>,
    /// Proof that the request scope this dispatch serves is open (issue #2414
    /// step 3). Every C++ graph walk below reaches syntax through it.
    token: QueryToken<'a>,
    frontier: Option<&'a dyn brokk_bifrost_core::analyzer::RelationalDefinitionFrontier>,
}

impl<'a> CppDispatch<'a> {
    pub(crate) fn new(analyzer: &'a dyn IAnalyzer, token: QueryToken<'a>) -> Self {
        Self {
            analyzer,
            cpp: resolve_analyzer::<CppAnalyzer>(analyzer),
            token,
            frontier: None,
        }
    }

    pub(crate) fn with_frontier(
        analyzer: &'a dyn IAnalyzer,
        token: QueryToken<'a>,
        frontier: &'a dyn brokk_bifrost_core::analyzer::RelationalDefinitionFrontier,
    ) -> Self {
        Self {
            analyzer,
            cpp: resolve_analyzer::<CppAnalyzer>(analyzer),
            token,
            frontier: Some(frontier),
        }
    }

    pub(crate) fn source(&self) -> CppGraphSource<'_> {
        CppGraphSource {
            index: self.analyzer,
            cpp: self.cpp.map(|cpp| cpp as &dyn CppSource),
            aliases: self.analyzer.type_alias_provider(),
            hierarchy: self.analyzer.type_hierarchy_provider(),
            workspace: self,
            token: self.token,
        }
    }
}

impl CppWorkspaceSource for CppDispatch<'_> {
    fn import_statements(&self, file: &ProjectFile) -> Vec<String> {
        self.analyzer.import_statements(file)
    }

    fn definitions_by_name(
        &self,
        _token: QueryToken<'_>,
        name: &brokk_bifrost_core::analyzer::fq_name::FqName,
    ) -> Vec<CodeUnit> {
        self.definitions(
            name,
            brokk_bifrost_core::analyzer::RelationalDefinitionQuery::ExactName,
        )
    }

    fn definitions_by_identifier(
        &self,
        _token: QueryToken<'_>,
        name: &brokk_bifrost_core::analyzer::fq_name::FqName,
    ) -> Vec<CodeUnit> {
        self.definitions(name, workspace_identifier_query())
    }
}

impl CppDispatch<'_> {
    fn definitions(
        &self,
        name: &brokk_bifrost_core::analyzer::fq_name::FqName,
        query: brokk_bifrost_core::analyzer::RelationalDefinitionQuery,
    ) -> Vec<CodeUnit> {
        if let Some(frontier) = self.frontier {
            return definitions_from_frontier(frontier, name, query);
        }
        relational_definitions(self.analyzer, name, query)
    }
}

pub(crate) fn relational_exact_definitions(
    analyzer: &dyn IAnalyzer,
    name: &brokk_bifrost_core::analyzer::fq_name::FqName,
) -> Vec<CodeUnit> {
    relational_definitions(
        analyzer,
        name,
        brokk_bifrost_core::analyzer::RelationalDefinitionQuery::ExactName,
    )
}

pub(crate) fn relational_identifier_definitions(
    analyzer: &dyn IAnalyzer,
    name: &brokk_bifrost_core::analyzer::fq_name::FqName,
) -> Vec<CodeUnit> {
    relational_definitions(analyzer, name, workspace_identifier_query())
}

fn workspace_identifier_query() -> brokk_bifrost_core::analyzer::RelationalDefinitionQuery {
    brokk_bifrost_core::analyzer::RelationalDefinitionQuery::Identifier { file: None }
}

pub(crate) fn relational_structural_members(
    analyzer: &dyn IAnalyzer,
    owner: &brokk_bifrost_core::analyzer::fq_name::FqName,
    identifier: &str,
) -> Vec<CodeUnit> {
    relational_definitions(
        analyzer,
        owner,
        brokk_bifrost_core::analyzer::RelationalDefinitionQuery::StructuralMembers {
            identifier: identifier.to_string(),
        },
    )
}

fn definitions_from_frontier(
    frontier: &dyn brokk_bifrost_core::analyzer::RelationalDefinitionFrontier,
    name: &brokk_bifrost_core::analyzer::fq_name::FqName,
    query: brokk_bifrost_core::analyzer::RelationalDefinitionQuery,
) -> Vec<CodeUnit> {
    let question = brokk_bifrost_core::analyzer::RelationalDefinitionQuestion {
        language_scope: brokk_bifrost_core::analyzer::DefinitionLanguageScope::Workspace,
        name: brokk_bifrost_core::analyzer::RelationalName::stable(name.clone()),
        query,
    };
    match frontier.ask(&question) {
        brokk_bifrost_core::analyzer::RelationalDefinitionValue::Definitions(units) => units,
        _ => panic!("definition question returned the wrong result shape"),
    }
}

fn relational_definitions(
    analyzer: &dyn IAnalyzer,
    name: &brokk_bifrost_core::analyzer::fq_name::FqName,
    query: brokk_bifrost_core::analyzer::RelationalDefinitionQuery,
) -> Vec<CodeUnit> {
    let cancellation = brokk_bifrost_core::cancellation::CancellationToken::new();
    match brokk_bifrost_analysis::analyzer::relational_frontier::resolve_relational_frontier(
        analyzer,
        &cancellation,
        |frontier| definitions_from_frontier(frontier, name, query.clone()),
    ) {
        brokk_bifrost_core::analyzer::RelationalFrontierOutcome::Complete(units) => units,
        brokk_bifrost_core::analyzer::RelationalFrontierOutcome::Cancelled => {
            analyzer.record_query_incomplete(
                brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadIncomplete::Cancelled,
            );
            Vec::new()
        }
        brokk_bifrost_core::analyzer::RelationalFrontierOutcome::Failed(error) => {
            analyzer.record_query_failure(
                brokk_bifrost_analysis::analyzer::store::StoreError::new(error.message()),
            );
            Vec::new()
        }
    }
}

/// The dispatching source for a call that has no [`CppDispatch`] to hand.
///
/// Every entry point below builds one per call, exactly where the moved code
/// used to run its own `resolve_analyzer` downcast.
pub(crate) fn with_cpp_graph_source<T>(
    analyzer: &dyn IAnalyzer,
    body: impl FnOnce(CppGraphSource<'_>) -> T,
) -> T {
    // The C++ graph's request boundary for callers that reach it without one
    // of their own; nested inside a caller-owned scope it shares that scope's
    // memoization (issue #2414 step 3).
    let scope = AnalyzerQueryScope::new(analyzer);
    let dispatch = CppDispatch::new(analyzer, scope.token());
    body(dispatch.source())
}

#[cfg(any(test, feature = "test-support"))]
pub fn cpp_type_owner_for_test(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> Option<CodeUnit> {
    with_cpp_graph_source(analyzer, |source| {
        brokk_bifrost_cpp::graph::resolver::type_owner_of(&source, unit)
    })
}

pub(crate) fn build_cpp_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdges>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = CppEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edges(analyzer, nodes, keep_file))
}

pub(crate) fn build_rooted_cpp_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    callers: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdges>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = CppEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_rooted_edges(analyzer, callers, keep_file))
}

pub(crate) fn build_cpp_usage_edge_weights<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdgeWeights>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = CppEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edge_weights(analyzer, nodes, keep_file))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CppDeadCodeBulkEligibility {
    BulkSafe,
    NeedsPrecise,
}

pub(crate) fn dead_code_bulk_eligibility(
    analyzer: &dyn IAnalyzer,
    target: &CodeUnit,
    overloaded_fqns: &HashSet<String>,
) -> CppDeadCodeBulkEligibility {
    let Some(spec) =
        with_cpp_graph_source(analyzer, |source| TargetSpec::from_target(&source, target))
    else {
        return CppDeadCodeBulkEligibility::NeedsPrecise;
    };
    match spec.kind {
        TargetKind::Type => CppDeadCodeBulkEligibility::BulkSafe,
        TargetKind::FreeFunction | TargetKind::Method if cpp_effectively_free_function(&spec) => {
            if overloaded_fqns.contains(target.fq_name().as_str()) || cpp_global_main(&spec) {
                CppDeadCodeBulkEligibility::NeedsPrecise
            } else {
                CppDeadCodeBulkEligibility::BulkSafe
            }
        }
        TargetKind::Constructor
        | TargetKind::FreeFunction
        | TargetKind::Method
        | TargetKind::GlobalField
        | TargetKind::MemberField
        | TargetKind::Macro => CppDeadCodeBulkEligibility::NeedsPrecise,
    }
}

#[doc(hidden)]
pub fn is_cpp_global_main(analyzer: &dyn IAnalyzer, target: &CodeUnit) -> bool {
    with_cpp_graph_source(analyzer, |source| TargetSpec::from_target(&source, target))
        .is_some_and(|spec| cpp_global_main(&spec))
}

fn cpp_effectively_free_function(spec: &TargetSpec) -> bool {
    spec.target.is_function() && spec.owner.as_ref().is_none_or(|owner| owner.is_module())
}

fn cpp_global_main(spec: &TargetSpec) -> bool {
    spec.target.is_function()
        && spec.target.identifier() == "main"
        && spec.target.package_name().is_empty()
        && spec.owner.is_none()
}

#[derive(Default)]
pub struct CppUsageGraphStrategy {
    _private: (),
}

impl CppUsageGraphStrategy {
    pub const fn new() -> Self {
        Self { _private: () }
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        language_for_target(target) == Language::Cpp
    }
}

impl GraphUsageAnalyzer for CppUsageGraphStrategy {
    fn find_graph_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        brokk_bifrost_analysis::analyzer::usages::traits::dispatch_graph_usage_query::<
            CppQueryResolver<'_>,
        >(
            analyzer,
            overloads,
            scan_scope,
            max_usages,
            GraphUsageDispatchSpec {
                target_language: Language::Cpp,
                unsupported_target: "target is not C/C++",
                missing_analyzer: "analyzer does not expose CppAnalyzer",
                strategy: "CppUsageGraphStrategy",
            },
        )
    }
}

#[cfg(test)]
mod bare_implicit_this_inverted_edge_tests {

    use crate::analyzer::usages::cpp_graph::*;

    use crate::analyzer::usages::cpp_graph::build_cpp_usage_edges;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_core::analyzer::project::TestProject;

    use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;

    use brokk_bifrost_core::hash::HashSet;
    use std::sync::Arc;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#1161: bare C++ implicit-this calls were dropped instead of retained as unproven inbound edges"
    )]
    fn bare_implicit_this_call_is_recorded_as_unproven_inbound_not_dropped() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), "foo.cpp");
        file.write("class Foo {\npublic:\n  void target() {}\n  void caller() { target(); }\n};\n")
            .expect("write foo.cpp");

        let project = Arc::new(TestProject::new(&root, Language::Cpp));
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("ephemeral workspace should build");
        let analyzer = workspace.analyzer();
        let _scope = AnalyzerQueryScope::new(analyzer);

        let target = analyzer
            .get_all_declarations()
            .into_iter()
            .find(|unit| unit.is_function() && unit.identifier() == "target")
            .expect("Foo::target declaration");
        let target_fqn = target.fq_name();

        let nodes: HashSet<String> = HashSet::from_iter([target_fqn.clone()]);
        let edges = build_cpp_usage_edges(analyzer, &nodes, |_| true)
            .expect("C++ edge resolver must be available for a C++ analyzer");

        assert_eq!(
            edges.unproven_inbound.get(target_fqn.as_str()).copied(),
            Some(1),
            "bare implicit-this call to Foo::target must be recorded as \
             unproven inbound, not dropped: {:?}",
            edges.unproven_inbound
        );
        assert!(
            edges
                .edges
                .keys()
                .all(|(_caller, callee)| callee != &target_fqn),
            "a same-owner call must never become a proven inbound edge: {:?}",
            edges.edges
        );
    }
}
