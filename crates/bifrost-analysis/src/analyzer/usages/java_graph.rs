//! The analysis-side wrappers over [`brokk_bifrost_jvm::java::graph`].
//!
//! The scans themselves moved with the language knowledge. What stays here is
//! the downcast that produces their arguments, the `GraphUsageAnalyzer` /
//! `UsageQueryResolver` / `UsageAnalyzer` strategy shells (all analysis-owned
//! traits), the inverted pass's fan-out and its two `FileState` decoders, the
//! Java-to-Scala cross-language scan, and the dead-code bulk routing predicate.

use crate::analyzer::usages::parsed_tree::ParseSpec;
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
use brokk_bifrost_core::analyzer::query_token::QueryToken;
mod shared;
use crate::analyzer::usages::traits::GraphUsageAnalyzer;

use crate::analyzer::usages::common::language_for_target;
use crate::analyzer::usages::inverted_edges::{UsageEdgeWeights, UsageEdges};
use crate::analyzer::usages::java_graph::shared::{JavaEdgeResolver, JavaQueryResolver};
use crate::analyzer::usages::model::FuzzyResult;
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{UsageAnalyzer, UsageQueryResolver, UsageScanScope};
use crate::analyzer::{
    BoundedDefinitionLookup, CodeUnit, IAnalyzer, JavaAnalyzer, Language, ProjectFile,
    resolve_analyzer,
};
use crate::hash::HashSet;
use brokk_bifrost_jvm::java::graph::JavaGraphSource;
use brokk_bifrost_jvm::java::graph::extractor::{self, ReturnTypeCaches, ScanState};
use brokk_bifrost_jvm::java::graph::inverted::{
    JavaEdgeScanCaches, scan_file as scan_inverted_file,
};
use brokk_bifrost_jvm::java::graph::resolver::{TargetKind, TargetSpec};
use brokk_bifrost_jvm::java::graph::return_type::{
    FileReturnCache, MethodAnonymousReturnCache, MethodReturnCache,
};
use std::ffi::OsStr;
use std::sync::Mutex;

pub(in crate::analyzer::usages) use brokk_bifrost_jvm::java::graph::resolver::signature_arity as java_signature_arity;

/// Run `visit` with the [`JavaGraphSource`] built from the *dispatching*
/// analyzer.
///
/// A callback rather than a constructor because the definition-index accessor is
/// itself a borrowed closure: `analyzer.global_usage_definition_index()` returns
/// a handle that borrows the analyzer and merges one shard per delegate, and the
/// Java side takes it lazily so a scan that never reaches a realm-wide lookup
/// never pays for the merge.
pub(in crate::analyzer::usages) fn with_java_graph_source<R>(
    analyzer: &dyn IAnalyzer,
    visit: impl FnOnce(JavaGraphSource<'_>) -> R,
) -> R {
    let definitions = |consume: &mut dyn FnMut(&dyn BoundedDefinitionLookup)| {
        consume(&analyzer.global_usage_definition_index());
    };
    let import_statements = |file: &ProjectFile| analyzer.import_statements(file);
    let scope = AnalyzerQueryScope::new(analyzer);
    visit(JavaGraphSource {
        token: scope.token(),
        index: analyzer,
        hierarchy: analyzer.type_hierarchy_provider(),
        definitions: &definitions,
        import_statements: &import_statements,
    })
}

pub(crate) fn build_java_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdges>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = JavaEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edges(analyzer, nodes, keep_file))
}

pub(crate) fn build_java_usage_edge_weights<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdgeWeights>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = JavaEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edge_weights(analyzer, nodes, keep_file))
}

/// Collect hits on a JVM *type* target declared in another JVM language from
/// Java and Scala source.
///
/// The mirror of `kotlin_graph::scan_kotlin_files_for_jvm_type`. Java's scan and
/// its Scala scanner both resolve a written type name through the file's own
/// import and package rules against the realm-wide declaration index, so what a
/// Kotlin class needs from them is the file set, not new resolution.
///
/// Type targets only, for the same reason as the Kotlin direction: a member
/// reference binds by the *target* language's member-lookup rules, and answering
/// one language's member question with another's would be guessing.
#[allow(clippy::too_many_arguments)]
pub(crate) fn scan_jvm_files_for_foreign_type(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    candidate_files: &HashSet<ProjectFile>,
    target: &CodeUnit,
    max_usages: usize,
    hits: &mut std::collections::BTreeSet<crate::analyzer::usages::model::UsageHit>,
    unproven_hits: &mut std::collections::BTreeSet<crate::analyzer::usages::model::UsageHit>,
    raw_match_count: &mut usize,
    limit_exceeded: &mut bool,
) {
    if *limit_exceeded || !target.is_class() {
        return;
    }
    let Some(java) = resolve_analyzer::<JavaAnalyzer>(analyzer) else {
        return;
    };
    let Some(spec) = TargetSpec::from_target(java, token, target) else {
        return;
    };
    let mut state = ScanState {
        max_usages,
        hits,
        unproven_hits,
        raw_match_count,
        limit_exceeded,
    };
    let method_return_cache = Mutex::new(crate::hash::HashMap::default());
    let method_anonymous_return_cache = Mutex::new(crate::hash::HashMap::default());
    let file_return_cache = Mutex::new(crate::hash::HashMap::default());
    let return_caches = ReturnTypeCaches {
        method_return: &method_return_cache,
        method_anonymous_return: &method_anonymous_return_cache,
        file_return: &file_return_cache,
    };
    let mut java_files: Vec<ProjectFile> = candidate_files
        .iter()
        .filter(|file| crate::analyzer::usages::common::language_for_file(file) == Language::Java)
        .cloned()
        .collect();
    java_files.sort();
    with_java_graph_source(analyzer, |graph| {
        for file in java_files {
            extractor::scan_file(
                java,
                token,
                &graph,
                &file,
                &spec,
                &return_caches,
                &mut state,
            );
            if *state.limit_exceeded {
                return;
            }
        }
        scan_scala_files_for_java_target(analyzer, candidate_files, &spec, &mut state, None);
    });
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum JavaDeadCodeBulkEligibility {
    BulkSafe,
    NeedsPrecise,
}

pub(crate) fn dead_code_bulk_eligibility(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    target: &CodeUnit,
    overloaded_fqns: &HashSet<String>,
    static_imports_present: bool,
    scala_files_present: bool,
) -> JavaDeadCodeBulkEligibility {
    let Some(java) = resolve_analyzer::<JavaAnalyzer>(analyzer) else {
        return JavaDeadCodeBulkEligibility::NeedsPrecise;
    };
    let Some(spec) = TargetSpec::from_target(java, token, target) else {
        return JavaDeadCodeBulkEligibility::NeedsPrecise;
    };
    match spec.kind {
        TargetKind::Type if scala_files_present => JavaDeadCodeBulkEligibility::NeedsPrecise,
        TargetKind::Type => JavaDeadCodeBulkEligibility::BulkSafe,
        TargetKind::Method if scala_files_present => JavaDeadCodeBulkEligibility::NeedsPrecise,
        TargetKind::Method if static_imports_present => JavaDeadCodeBulkEligibility::NeedsPrecise,
        TargetKind::Method if overloaded_fqns.contains(target.fq_name().as_str()) => {
            JavaDeadCodeBulkEligibility::NeedsPrecise
        }
        TargetKind::Method => JavaDeadCodeBulkEligibility::BulkSafe,
        TargetKind::Constructor | TargetKind::Field => JavaDeadCodeBulkEligibility::NeedsPrecise,
    }
}

#[derive(Default)]
pub struct JavaUsageGraphStrategy {
    _private: (),
}

impl JavaUsageGraphStrategy {
    pub const fn new() -> Self {
        Self { _private: () }
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        language_for_target(target) == Language::Java
    }
}

impl GraphUsageAnalyzer for JavaUsageGraphStrategy {
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
        if language_for_target(target) != Language::Java {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetLanguage("target is not Java"),
                "JavaUsageGraphStrategy",
            );
        }

        let Some(resolver) = JavaQueryResolver::try_new(analyzer) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::MissingAnalyzerCapability(
                    "analyzer does not expose JavaAnalyzer",
                ),
                "JavaUsageGraphStrategy",
            );
        };

        resolver.find_usages(analyzer, overloads, scan_scope, max_usages)
    }
}

impl UsageAnalyzer for JavaUsageGraphStrategy {
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

/// Collect hits on a Java target from Scala source, when the workspace has a
/// Scala analyzer to read Scala's own imports and declarations with.
///
/// The scan is the Scala query walk itself (#1859): the walk types receivers,
/// the foreign catalog matches the owner's normalized fqn plus the member name
/// under Java's own arity rules, and a receiver that cannot be typed lands in
/// the unproven channel. What stays here is the downcast that produces the
/// scan's `ScalaSource`.
pub(in crate::analyzer::usages) fn scan_scala_files_for_java_target(
    analyzer: &dyn IAnalyzer,
    candidate_files: &HashSet<ProjectFile>,
    spec: &TargetSpec,
    state: &mut brokk_bifrost_jvm::java::graph::extractor::ScanState<'_>,
    cancellation: Option<&crate::cancellation::CancellationToken>,
) {
    let Some(scala) = resolve_analyzer::<crate::analyzer::ScalaAnalyzer>(analyzer) else {
        return;
    };
    let Some(java) = resolve_analyzer::<JavaAnalyzer>(analyzer) else {
        return;
    };
    scan_scala_files_for_foreign_target(
        analyzer,
        scala,
        java,
        candidate_files,
        spec,
        state,
        cancellation,
    );
}

/// One foreign catalog for the Java (or other JVM-language) target family,
/// then the ordinary per-file Scala query scan with a hit sink that also keeps
/// unproven receiver references.
fn scan_scala_files_for_foreign_target(
    analyzer: &dyn IAnalyzer,
    scala: &crate::analyzer::ScalaAnalyzer,
    java: &JavaAnalyzer,
    candidate_files: &HashSet<ProjectFile>,
    spec: &TargetSpec,
    state: &mut brokk_bifrost_jvm::java::graph::extractor::ScanState<'_>,
    cancellation: Option<&crate::cancellation::CancellationToken>,
) {
    use brokk_bifrost_jvm::scala::graph::query::{
        ScalaFileEligibility, ScalaQueryHitSink, ScalaQueryTargetCatalog,
    };

    // Subtype receivers (#1859): a receiver typed as a descendant of the Java
    // owner dispatches to the inherited member, so the catalog's owner set is
    // the receiver set plus every descendant the dispatching analyzer can see.
    // The realm hierarchy is one-directional: a Scala class extending a Java
    // base records no ancestor edge, so a Scala-subclass receiver stays a
    // documented miss until that hierarchy work lands.
    let mut receiver_owners = spec.receiver_owner_fq_names.clone();
    if matches!(spec.kind, TargetKind::Method | TargetKind::Field)
        && let Some(hierarchy) = analyzer.type_hierarchy_provider()
    {
        for descendant in hierarchy.get_descendants(&spec.owner) {
            if descendant.is_class() {
                receiver_owners.insert(descendant.fq_name());
            }
        }
    }
    let catalog = ScalaQueryTargetCatalog::build_foreign_jvm(spec, java, &receiver_owners);
    let relevant_names = catalog.relevant_names();
    let dispatch = crate::analyzer::usages::scala_graph::shared::ScalaDispatch(analyzer);
    let eligibility = ScalaFileEligibility::All;
    let member_name = spec.member_name.as_str();
    let owner_name = spec.owner.identifier();
    let mut files: Vec<ProjectFile> = candidate_files
        .iter()
        .filter(|file| crate::analyzer::usages::common::language_for_file(file) == Language::Scala)
        .cloned()
        .collect();
    files.sort();
    let mut observed_hits = std::collections::BTreeSet::new();
    for file in &files {
        if *state.limit_exceeded || cancellation.is_some_and(|token| token.is_cancelled()) {
            break;
        }
        let Some(source) = analyzer.indexed_source(file) else {
            continue;
        };
        // The retired scanner's cheap gate: a file that spells neither the
        // member nor its owner cannot reference the target.
        if !source.contains(member_name) && !source.contains(owner_name) {
            continue;
        }
        let mut sink = ScalaQueryHitSink {
            analyzer: &dispatch,
            scala,
            file,
            source: &source,
            class_ranges: crate::analyzer::usages::inverted_edges::ClassRangeIndex::build(
                analyzer, file,
            ),
            line_starts: crate::text_utils::compute_line_starts(&source),
            catalog: &catalog,
            eligibility: &eligibility,
            hits: std::slice::from_mut(&mut *state.hits),
            observed_hits: &mut observed_hits,
            unproven_hits: Some(&mut *state.unproven_hits),
            enclosing_cache: crate::hash::HashMap::default(),
            relevant_names: relevant_names.clone(),
            allow_all_names: false,
            max_usages: state.max_usages,
            limit_exceeded: false,
        };
        let scope = AnalyzerQueryScope::new(analyzer);
        brokk_bifrost_jvm::scala::graph::inverted::scan_scala_query_file(
            scala,
            scope.token(),
            analyzer,
            &dispatch,
            file,
            &source,
            &mut sink,
            cancellation,
        );
        if sink.limit_exceeded {
            *state.limit_exceeded = true;
        }
    }
}

/// The whole-workspace inverted pass: the shared driver's parallel fan-out plus
/// on-demand parsing, with
/// [`brokk_bifrost_jvm::java::graph::inverted::scan_file`] resolving each file.
///
/// The two per-file indexes are built here rather than crate-side because both
/// have a `FileState` fast path, and `FileState` is analysis-crate-private
/// (Ruby's `forward_owner_relation_facts` precedent: decode on this side, hand
/// the decoded facts across).
fn build_java_edges<Output, F>(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    files: &[ProjectFile],
    file_states: &crate::hash::HashMap<
        ProjectFile,
        crate::analyzer::tree_sitter_analyzer::FileState,
    >,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Output
where
    Output: crate::analyzer::usages::inverted_edges::UsageEdgeBuildOutput<String>,
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    use crate::analyzer::usages::inverted_edges::{
        ClassRangeIndex, build_edge_output, build_file_declarations_from_state_with_file_scope,
        build_file_declarations_with_file_scope, class_range_index_from_state,
        parse_and_collect_with_declarations,
    };

    let language = tree_sitter_java::LANGUAGE.into();
    let method_return_cache: MethodReturnCache = Mutex::new(crate::hash::HashMap::default());
    let method_anonymous_return_cache: MethodAnonymousReturnCache =
        Mutex::new(crate::hash::HashMap::default());
    let file_return_cache: FileReturnCache = Mutex::new(crate::hash::HashMap::default());
    let caches = JavaEdgeScanCaches {
        method_return: &method_return_cache,
        method_anonymous_return: &method_anonymous_return_cache,
        file_return: &file_return_cache,
    };
    with_java_graph_source(analyzer, |graph| {
        build_edge_output(files, keep_file, |file| {
            let state = file_states.get(file);
            let include_file_scope = is_java_module_descriptor(file);
            let mut declarations = state
                .map(|state| {
                    build_file_declarations_from_state_with_file_scope(state, include_file_scope)
                })
                .unwrap_or_else(|| {
                    build_file_declarations_with_file_scope(analyzer, file, include_file_scope)
                });
            if include_file_scope {
                let file_scope = CodeUnit::file_scope(file.clone());
                let file_scope_key = file_scope.fq_name();
                if !declarations
                    .enclosers
                    .iter()
                    .any(|(_, _, key)| key == &file_scope_key)
                    && let Some(source) = analyzer.indexed_source(file)
                {
                    declarations.add_file_scope(file_scope_key, source.len());
                }
            }
            let class_ranges = state
                .map(class_range_index_from_state)
                .unwrap_or_else(|| ClassRangeIndex::build(analyzer, file));
            parse_and_collect_with_declarations(
                file,
                nodes,
                ParseSpec::whole(&language),
                declarations,
                |input| scan_inverted_file(java, token, &graph, file, input, class_ranges, &caches),
            )
        })
    })
}

fn is_java_module_descriptor(file: &ProjectFile) -> bool {
    file.rel_path().file_name() == Some(OsStr::new("module-info.java"))
}
