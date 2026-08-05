//! The analysis-side wrappers over [`brokk_bifrost_csharp::graph`].
//!
//! The scans themselves moved with the language knowledge. What stays here is
//! the downcast that produces their arguments, the `GraphUsageAnalyzer` /
//! `UsageQueryResolver` / `UsageAnalyzer` strategy shells (all analysis-owned
//! traits), the inverted pass's fan-out -- `build_edge_output` and
//! `parse_and_collect` are the shared, language-agnostic driver -- and the
//! implicit-entry-point predicate, which reads an `IAnalyzer`.

#[cfg(test)]
mod resolver_tests;
mod shared;
use crate::analyzer::usages::traits::GraphUsageAnalyzer;

pub(in crate::analyzer::usages) use brokk_bifrost_csharp::graph::extractor::{
    is_declaration_name as csharp_is_declaration_name, member_access_name, member_access_receiver,
};
pub(in crate::analyzer::usages) use brokk_bifrost_csharp::graph::resolver::{
    argument_count as csharp_argument_count, canonical_builtin_type_identity,
    first_type_child as csharp_first_type_child,
    is_type_reference_node as csharp_is_type_reference_node,
    member_declared_type_fq_name as csharp_member_declared_type_fq_name,
    member_declared_type_fq_name_in_session as csharp_member_declared_type_fq_name_in_session,
    method_return_type_fq_name_for_arity as csharp_method_return_type_fq_name_for_arity,
    method_return_type_fq_name_for_arity_in_session as csharp_method_return_type_fq_name_for_arity_in_session,
    node_text as csharp_node_text, object_created_type as csharp_object_created_type,
    object_initializer_for_label as csharp_object_initializer_for_label,
    object_initializer_owner_type_node as csharp_object_initializer_owner_type_node,
    reference_type_text as csharp_reference_type_text,
    resolve_type_fq_name as csharp_resolve_type_fq_name,
    seed_bindings_before as seed_csharp_bindings_before,
    seed_bindings_before_in_session as seed_csharp_bindings_before_in_session,
};

use crate::analyzer::usages::common::language_for_target;
use crate::analyzer::usages::csharp_graph::shared::{CSharpEdgeResolver, CSharpQueryResolver};
use crate::analyzer::usages::get_definition::ResolutionSession;
use crate::analyzer::usages::inverted_edges::{
    UsageEdgeBuildOutput, UsageEdgeWeights, UsageEdges, build_edge_output, parse_and_collect,
};
use crate::analyzer::usages::model::FuzzyResult;
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{UsageAnalyzer, UsageQueryResolver, UsageScanScope};
use crate::analyzer::{CSharpAnalyzer, CodeUnit, IAnalyzer, Language, ProjectFile};
use crate::code_quality::dead_code_smells::{
    contains_java_visibility_modifier, declaration_header,
};
use crate::hash::HashSet;
use brokk_bifrost_csharp::graph::CSharpGraphSource;
use std::sync::LazyLock;
use tree_sitter::Node;

/// The [`CSharpGraphSource`] built from the *dispatching* analyzer.
///
/// Not the C# analyzer: in a mixed workspace the query is issued against a
/// `MultiAnalyzer`, whose `definitions` merges every language's shards and whose
/// `get_ancestors` crosses language boundaries, and the C# walks depend on that
/// reach. Both fields are borrowed handles rather than the callback
/// `PythonGraphSource` needs, because neither builds anything on first access:
/// the workspace definition index C# resolves through is reached through
/// `CSharpAnalysisSource::usage_definitions`, exactly as before the move.
pub(in crate::analyzer::usages) fn csharp_graph_source(
    analyzer: &dyn IAnalyzer,
) -> CSharpGraphSource<'_> {
    CSharpGraphSource {
        index: analyzer,
        hierarchy: analyzer.type_hierarchy_provider(),
    }
}

// The five entry points below are the only ones the definition route imports
// whose analyzer-typed parameter was the dispatching `&dyn IAnalyzer`.
// `&CSharpAnalyzer` unsize-coerces to `&dyn CSharpAnalysisSource` at a call
// site on its own, so every other re-export above is a plain rename.

pub(in crate::analyzer::usages) fn csharp_usage_direct_base(
    analyzer: &dyn IAnalyzer,
    csharp: &CSharpAnalyzer,
    owner: &CodeUnit,
) -> Option<CodeUnit> {
    brokk_bifrost_csharp::graph::resolver::usage_direct_base(
        &csharp_graph_source(analyzer),
        csharp,
        owner,
    )
}

#[allow(clippy::too_many_arguments)]
pub(in crate::analyzer::usages) fn csharp_extension_invocation_return_type_fq_name(
    csharp: &CSharpAnalyzer,
    analyzer: &dyn IAnalyzer,
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
pub(in crate::analyzer::usages) fn csharp_extension_invocation_return_type_fq_name_in_session(
    csharp: &CSharpAnalyzer,
    analyzer: &dyn IAnalyzer,
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
pub(in crate::analyzer::usages) fn csharp_visible_extension_method_candidates(
    csharp: &CSharpAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    site: Node<'_>,
    receiver_type_names: &[String],
    member: &str,
    call_arity: Option<usize>,
    explicit_generic_arity: Option<usize>,
    fallback_when_inapplicable: bool,
) -> Vec<CodeUnit> {
    brokk_bifrost_csharp::graph::resolver::visible_extension_method_candidates(
        csharp,
        &csharp_graph_source(analyzer),
        file,
        source,
        site,
        receiver_type_names,
        member,
        call_arity,
        explicit_generic_arity,
        fallback_when_inapplicable,
    )
}

#[allow(clippy::too_many_arguments)]
pub(in crate::analyzer::usages) fn csharp_visible_extension_method_candidates_in_session(
    csharp: &CSharpAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    site: Node<'_>,
    receiver_type_names: &[String],
    member: &str,
    call_arity: Option<usize>,
    explicit_generic_arity: Option<usize>,
    fallback_when_inapplicable: bool,
    session: &ResolutionSession,
) -> Vec<CodeUnit> {
    brokk_bifrost_csharp::graph::resolver::visible_extension_method_candidates_in_session(
        csharp,
        &csharp_graph_source(analyzer),
        file,
        source,
        site,
        receiver_type_names,
        member,
        call_arity,
        explicit_generic_arity,
        fallback_when_inapplicable,
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
    csharp: &CSharpAnalyzer,
    files: &[ProjectFile],
    nodes: &HashSet<String>,
    keep_file: F,
) -> Output
where
    Output: UsageEdgeBuildOutput<String>,
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let language = tree_sitter_c_sharp::LANGUAGE.into();
    let graph = csharp_graph_source(analyzer);
    build_edge_output(files, keep_file, |file| {
        parse_and_collect(analyzer, file, nodes, &language, |input| {
            brokk_bifrost_csharp::graph::inverted::scan_file(&graph, csharp, file, input)
        })
    })
}

pub(crate) fn build_csharp_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdges>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = CSharpEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edges(analyzer, nodes, keep_file))
}

pub(crate) fn build_csharp_usage_edge_weights<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdgeWeights>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = CSharpEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edge_weights(analyzer, nodes, keep_file))
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
        if overloads.is_empty() {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        }

        let target = &overloads[0];
        if language_for_target(target) != Language::CSharp {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetLanguage("target is not C#"),
                "CSharpUsageGraphStrategy",
            );
        }

        let Some(resolver) = CSharpQueryResolver::try_new(analyzer) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::MissingAnalyzerCapability(
                    "analyzer does not expose CSharpAnalyzer",
                ),
                "CSharpUsageGraphStrategy",
            );
        };

        resolver.find_usages(analyzer, overloads, scan_scope, max_usages)
    }
}

impl UsageAnalyzer for CSharpUsageGraphStrategy {
    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> FuzzyResult {
        let scan_scope = UsageScanScope::new(candidate_files, false);
        self.find_graph_usages(analyzer, overloads, &scan_scope, max_usages)
            .into_fuzzy_result()
    }
}

/// C#'s implicit entry points: a `static Main`, and any method carrying an
/// xUnit/NUnit/MSTest attribute. Both are reachable without an in-workspace
/// caller, so dead-code scoring must not report them.
///
/// This lives here rather than inline in `dead_code_smells.rs` for the reason
/// Go's `go_implicit_entry_point` and C++'s `is_cpp_global_main` do: the
/// knowledge is which attribute spellings a C# test runner honors, which is
/// language knowledge, and a framework file carrying it is one the next
/// language extraction has to find by hand.
pub(crate) fn csharp_implicit_entry_point(analyzer: &dyn IAnalyzer, candidate: &CodeUnit) -> bool {
    if !candidate.is_function() {
        return false;
    }
    csharp_main_entry_point(analyzer, candidate) || csharp_test_entry_point(analyzer, candidate)
}

fn csharp_test_entry_point(analyzer: &dyn IAnalyzer, candidate: &CodeUnit) -> bool {
    let source = analyzer.get_source(candidate, true).unwrap_or_default();
    csharp_source_has_test_attribute(&source)
}

fn csharp_main_entry_point(analyzer: &dyn IAnalyzer, candidate: &CodeUnit) -> bool {
    if candidate.identifier() != "Main" {
        return false;
    }
    let source = analyzer.get_source(candidate, true).unwrap_or_default();
    let header = declaration_header(&source);
    contains_java_visibility_modifier(header, "static")
}

fn csharp_source_has_test_attribute(source: &str) -> bool {
    static TEST_ATTR_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r"\[(?:[A-Za-z_][A-Za-z0-9_.]*\.)?(?:Test|Fact|Theory|TestMethod)(?:Attribute)?(?:\s*\(|\s*\])",
        )
        .expect("valid csharp test regex")
    });
    TEST_ATTR_RE.is_match(source)
}
