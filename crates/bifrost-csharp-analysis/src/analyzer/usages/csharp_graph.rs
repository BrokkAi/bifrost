//! The analysis-side wrappers over [`brokk_bifrost_csharp::graph`].
//!
//! The scans themselves moved with the language knowledge. What stays here is
//! the downcast that produces their arguments, the `GraphUsageAnalyzer` /
//! `UsageQueryResolver` / `UsageAnalyzer` strategy shells (all analysis-owned
//! traits), the inverted pass's fan-out -- `build_edge_output` and
//! `parse_and_collect` are the shared, language-agnostic driver -- and the
//! implicit-entry-point predicate, which reads an `IAnalyzer`.

#[cfg(test)]
mod receiver_binding_scope_tests;
#[cfg(test)]
mod resolver_tests;
mod shared;

use brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageAnalyzer;
use brokk_bifrost_core::analyzer::query_token::QueryToken;

#[doc(hidden)]
pub use brokk_bifrost_csharp::syntax::csharp_has_modifier;

use brokk_bifrost_core::analyzer::tree_walk::node_for_exact_range;

use brokk_bifrost_analysis::analyzer::usages::common::language_for_target;

pub use crate::analyzer::usages::csharp_graph::shared::CSharpAuthoritativeUsageBatch;

pub use crate::analyzer::usages::csharp_graph::shared::CSharpAuthoritativeUsageRequest;

use crate::analyzer::usages::csharp_graph::shared::CSharpEdgeResolver;

use crate::analyzer::usages::csharp_graph::shared::CSharpQueryResolver;

use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

use brokk_bifrost_analysis::analyzer::usages::get_definition::parse_tree_for_language;

use brokk_bifrost_analysis::analyzer::usages::inverted_edges::EdgeNodeDomain;

use brokk_bifrost_analysis::analyzer::usages::inverted_edges::UsageEdgeBuildOutput;

use brokk_bifrost_analysis::analyzer::usages::inverted_edges::UsageEdgeBuildResult;

use brokk_bifrost_core::analyzer::usages::inverted_edges::UsageEdgeWeights;

use brokk_bifrost_core::analyzer::usages::inverted_edges::UsageEdges;

use brokk_bifrost_core::analyzer::usages::inverted_edges::PerFileEdges;

use brokk_bifrost_analysis::analyzer::usages::inverted_edges::build_edge_output;

use brokk_bifrost_analysis::analyzer::usages::inverted_edges::build_edge_output_with_completeness;

use brokk_bifrost_analysis::analyzer::usages::inverted_edges::parse_and_collect_with_domain;

use brokk_bifrost_core::analyzer::usages::outcome::GraphUsageOutcome;

use brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageDispatchSpec;

use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;

use crate::analyzer::CSharpAnalyzer;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_csharp::graph::CSharpGraphSource;
use tree_sitter::Node;

/// The [`CSharpGraphSource`] built from the *dispatching* analyzer.
///
/// Not the C# analyzer: in a mixed workspace the query is issued against a
/// `MultiAnalyzer`, whose `definitions` merges every language's shards and whose
/// `get_ancestors` crosses language boundaries, and the C# walks depend on that
/// reach. Both fields are borrowed handles rather than the callback
/// `PythonGraphSource` needs, because neither builds anything on first access:
/// the workspace definition index C# resolves through is reached through
/// `CSharpSource::usage_definitions`, exactly as before the move.
pub(crate) fn csharp_graph_source(analyzer: &dyn IAnalyzer) -> CSharpGraphSource<'_> {
    CSharpGraphSource {
        index: analyzer,
        hierarchy: analyzer.type_hierarchy_provider(),
    }
}

// The five entry points below are the only ones the definition route imports
// whose analyzer-typed parameter was the dispatching `&dyn IAnalyzer`.
// `&CSharpAnalyzer` unsize-coerces to `&dyn CSharpSource` at a call
// site on its own, so every other re-export above is a plain rename.

pub(crate) fn csharp_usage_direct_base(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    csharp: &dyn brokk_bifrost_csharp::graph_support::CSharpSource,
    owner: &CodeUnit,
) -> Option<CodeUnit> {
    brokk_bifrost_csharp::graph::resolver::usage_direct_base(
        &csharp_graph_source(analyzer),
        csharp,
        token,
        owner,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn csharp_extension_invocation_return_type_fq_name(
    csharp: &dyn brokk_bifrost_csharp::graph_support::CSharpSource,
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    source: &str,
    site: Node<'_>,
    receiver_type_names: &[String],
    method: &str,
    call_arity: Option<usize>,
    explicit_generic_arity: Option<usize>,
    explicit_type_arguments: Option<&[String]>,
    usage: bool,
) -> Option<String> {
    brokk_bifrost_csharp::graph::resolver::extension_invocation_return_type_fq_name(
        csharp,
        token,
        &csharp_graph_source(analyzer),
        source,
        site,
        receiver_type_names,
        method,
        call_arity,
        explicit_generic_arity,
        explicit_type_arguments,
        usage,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn csharp_extension_invocation_return_type_fq_name_in_session(
    csharp: &dyn brokk_bifrost_csharp::graph_support::CSharpSource,
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    source: &str,
    site: Node<'_>,
    receiver_type_names: &[String],
    method: &str,
    call_arity: Option<usize>,
    explicit_generic_arity: Option<usize>,
    explicit_type_arguments: Option<&[String]>,
    usage: bool,
    session: &ResolutionSession,
) -> Option<String> {
    brokk_bifrost_csharp::graph::resolver::extension_invocation_return_type_fq_name_in_session(
        csharp,
        token,
        &csharp_graph_source(analyzer),
        source,
        site,
        receiver_type_names,
        method,
        call_arity,
        explicit_generic_arity,
        explicit_type_arguments,
        usage,
        session,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn csharp_visible_extension_method_candidates(
    csharp: &dyn brokk_bifrost_csharp::graph_support::CSharpSource,
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    site: Node<'_>,
    receiver_type_names: &[String],
    member: &str,
    call_arity: Option<usize>,
    explicit_generic_arity: Option<usize>,
) -> Vec<CodeUnit> {
    brokk_bifrost_csharp::graph::resolver::visible_extension_method_candidates(
        csharp,
        token,
        &csharp_graph_source(analyzer),
        file,
        source,
        site,
        receiver_type_names,
        member,
        call_arity,
        explicit_generic_arity,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn csharp_visible_extension_method_candidates_in_session(
    csharp: &dyn brokk_bifrost_csharp::graph_support::CSharpSource,
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    site: Node<'_>,
    receiver_type_names: &[String],
    member: &str,
    call_arity: Option<usize>,
    explicit_generic_arity: Option<usize>,
    session: &ResolutionSession,
) -> Vec<CodeUnit> {
    brokk_bifrost_csharp::graph::resolver::visible_extension_method_candidates_in_session(
        csharp,
        token,
        &csharp_graph_source(analyzer),
        file,
        source,
        site,
        receiver_type_names,
        member,
        call_arity,
        explicit_generic_arity,
        session,
    )
}

/// The whole-workspace inverted pass: the shared driver's parallel fan-out plus
/// on-demand parsing, with [`brokk_bifrost_csharp::graph::inverted::scan_file`]
/// resolving each file.
///
/// Trees are parsed on demand inside the per-file walk and dropped when the
/// closure returns, so live trees are bounded by the worker count rather than
/// the workspace size (#200).
fn build_csharp_edges<Output, F>(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    csharp: &CSharpAnalyzer,
    files: &[ProjectFile],
    domain: EdgeNodeDomain<'_>,
    keep_file: F,
) -> Output
where
    Output: UsageEdgeBuildOutput<String>,
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let language = tree_sitter_c_sharp::LANGUAGE.into();
    let graph = csharp_graph_source(analyzer);
    build_edge_output(files, keep_file, |file| {
        scan_csharp_file(analyzer, &graph, csharp, token, file, domain, &language)
    })
}

fn scan_csharp_file(
    analyzer: &dyn IAnalyzer,
    graph: &CSharpGraphSource<'_>,
    csharp: &CSharpAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    domain: EdgeNodeDomain<'_>,
    language: &tree_sitter::Language,
) -> Option<PerFileEdges> {
    parse_and_collect_with_domain(
        analyzer,
        file,
        domain,
        brokk_bifrost_csharp::preprocessor::csharp_parse_spec(language),
        |input| brokk_bifrost_csharp::graph::inverted::scan_file(graph, csharp, token, file, input),
    )
}

fn build_csharp_edges_with_completeness<Output, F>(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    csharp: &CSharpAnalyzer,
    files: &[ProjectFile],
    domain: EdgeNodeDomain<'_>,
    keep_file: F,
) -> UsageEdgeBuildResult<Output>
where
    Output: UsageEdgeBuildOutput<String>,
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let language = tree_sitter_c_sharp::LANGUAGE.into();
    let graph = csharp_graph_source(analyzer);
    build_edge_output_with_completeness(files, keep_file, |file| {
        scan_csharp_file(analyzer, &graph, csharp, token, file, domain, &language)
    })
}

pub(crate) fn build_rooted_csharp_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    callers: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdges>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = CSharpEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_rooted_edges(analyzer, token, callers, keep_file))
}

pub(crate) fn build_inbound_csharp_usage_edges_with_completeness(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    callees: &HashSet<String>,
) -> Option<UsageEdgeBuildResult<UsageEdges>> {
    let resolver = CSharpEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_inbound_edges_with_completeness(analyzer, token, callees, |_| true))
}

pub(crate) fn build_csharp_usage_edge_weights<F>(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdgeWeights>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = CSharpEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edge_weights(analyzer, token, nodes, keep_file))
}

#[derive(Default)]
pub struct CSharpUsageGraphStrategy {
    _private: (),
}

impl CSharpUsageGraphStrategy {
    pub const fn new() -> Self {
        Self { _private: () }
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        language_for_target(target) == Language::CSharp
    }
}

impl GraphUsageAnalyzer for CSharpUsageGraphStrategy {
    fn find_graph_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        brokk_bifrost_analysis::analyzer::usages::traits::dispatch_graph_usage_query::<
            CSharpQueryResolver<'_>,
        >(
            analyzer,
            overloads,
            scan_scope,
            max_usages,
            GraphUsageDispatchSpec {
                target_language: Language::CSharp,
                unsupported_target: "target is not C#",
                missing_analyzer: "analyzer does not expose CSharpAnalyzer",
                strategy: "CSharpUsageGraphStrategy",
            },
        )
    }
}

/// C#'s implicit entry points: a `static Main`, and any method carrying an
/// attribute recognized by the C# test classifier. Both are reachable without
/// an in-workspace caller, so dead-code scoring must not report them.
///
/// The C# crate owns attribute recognition. This adapter pairs it with the
/// candidate's active source and exact declaration range from `IAnalyzer`.
#[doc(hidden)]
pub fn csharp_implicit_entry_point(analyzer: &dyn IAnalyzer, candidate: &CodeUnit) -> bool {
    if !candidate.is_function() {
        return false;
    }
    csharp_main_entry_point(analyzer, candidate) || csharp_test_entry_point(analyzer, candidate)
}

/// The entry-point classifier for a declaration in a caller-owned indexed
/// syntax context. A dead-code request can reuse one tree for all candidates.
#[doc(hidden)]
pub fn csharp_implicit_entry_point_at_declaration(
    analyzer: &dyn IAnalyzer,
    candidate: &CodeUnit,
    declaration: tree_sitter::Node<'_>,
    source: &str,
) -> bool {
    candidate.is_function()
        && (csharp_main_entry_point(analyzer, candidate)
            || brokk_bifrost_csharp::test_detection::csharp_method_has_runnable_test_attribute(
                declaration,
                source,
            ))
}

fn csharp_test_entry_point(analyzer: &dyn IAnalyzer, candidate: &CodeUnit) -> bool {
    let Some(source) = analyzer.indexed_source(candidate.source()) else {
        return false;
    };
    let Some(tree) = parse_tree_for_language(candidate.source(), Language::CSharp, &source) else {
        return false;
    };
    analyzer.ranges_of(candidate).into_iter().any(|range| {
        node_for_exact_range(tree.root_node(), &range).is_some_and(|method| {
            csharp_implicit_entry_point_at_declaration(analyzer, candidate, method, &source)
        })
    })
}

/// Metadata-only entry-point recognition for callers that own a syntax
/// context. Static Main needs no source hydration or parse.
#[doc(hidden)]
pub fn csharp_main_entry_point(analyzer: &dyn IAnalyzer, candidate: &CodeUnit) -> bool {
    if candidate.identifier() != "Main" {
        return false;
    }
    analyzer
        .signature_metadata(candidate)
        .iter()
        .any(|metadata| metadata.callable_modifiers_recorded() && metadata.callable_is_static())
}
