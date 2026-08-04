//! Kotlin structured reference, usage, and call graphs (issue #1239).
//!
//! Answers "who uses this Kotlin declaration?" from the Kotlin tree-sitter syntax
//! tree and the analyzer's indexed declarations. Nothing here recovers structure
//! by scanning source text, and nothing reports a reference it could not prove:
//! a reference whose identity cannot be established is recorded as *unproven*,
//! which keeps "we don't know" from collapsing into either "yes" or "no".
//!
//! # Where this sits
//!
//! Java, Scala, and Kotlin share one usage *candidate space* — the `Jvm`
//! ecosystem in `crate::analyzer::usages::workspace_graph` — because they compile
//! to one classpath and can name one another's types directly. Kotlin has been a
//! passive member of that space since issue #1237: Java and Scala references can
//! resolve *onto* Kotlin declarations. This module is what makes the realm
//! symmetric by giving Kotlin source references of its own.
//!
//! # Modelled on Java, not Scala
//!
//! Kotlin's identity model is Java's: dotted package-qualified fully-qualified
//! names, arity-distinguished overloads, an ancestor chain for inherited members.
//! Scala's usage graph is several times larger because Scala has `given`/`using`,
//! implicit conversions, `apply`/`unapply` extractors, export clauses, and union
//! types, none of which Kotlin has. So the module structure here mirrors
//! `super::java_graph` — a target model, a forward scan, a hit recorder — while
//! the syntax it reads comes from `crate::analyzer::kotlin::syntax`, shared with
//! the #1238 definition resolver so navigation and usages cannot drift apart.
//!
//! # What this answers
//!
//! Both usage paths. The *query* path ([`shared::KotlinQueryResolver`]) answers
//! "who uses this declaration?" for `scan_usages`, LSP references, and
//! reference-rewriting rename: a reference to a Kotlin type, constructor,
//! function, or property resolves through inheritance, companions, objects,
//! extensions, and receiver chains, with same-owner and unproven references in
//! their own channels. The *edge* path ([`shared::KotlinEdgeResolver`]) builds
//! the whole `caller -> callee` set in one inverted pass, for `usage_graph`,
//! `callers`/`callees`, relevance ranking, and dead-code detection.
//!
//! Both directions share their entire resolution backbone through
//! [`resolver::KotlinResolutionCtx`], so find-references and `usage_graph`
//! cannot disagree about which declaration a call means.
//!
//! Cross-language: a *type* query crosses the realm both ways — a Kotlin class's
//! Java and Scala call sites are reported, and Kotlin files are scanned for Java
//! and Scala class targets. A *member* reference does not cross: which
//! declaration `receiver.member` binds to is decided by the target language's
//! own member-lookup rules, and answering one language's question with another's
//! would be a guess. See `.agents/plans/kotlin-usage-graph-1239.md`.

mod extractor;
mod hits;
mod inverted;
mod resolver;
mod shared;
use crate::analyzer::usages::traits::GraphUsageAnalyzer;

pub(crate) use resolver::is_companion_object;
pub(crate) use shared::scan_kotlin_files_for_jvm_type;

use crate::analyzer::usages::common::language_for_target;
use crate::analyzer::usages::inverted_edges::{UsageEdgeWeights, UsageEdges};
use crate::analyzer::usages::kotlin_graph::shared::{KotlinEdgeResolver, KotlinQueryResolver};
use crate::analyzer::usages::model::FuzzyResult;
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{UsageAnalyzer, UsageQueryResolver, UsageScanScope};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile};
use crate::hash::HashSet;

/// Every Kotlin `caller -> callee` edge whose callee is one of `nodes`.
pub(crate) fn build_kotlin_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdges>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = KotlinEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edges(analyzer, nodes, keep_file))
}

/// The same edge set as [`build_kotlin_usage_edges`], weighted by call site.
pub(crate) fn build_kotlin_usage_edge_weights<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdgeWeights>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = KotlinEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edge_weights(analyzer, nodes, keep_file))
}

#[derive(Default)]
pub struct KotlinUsageGraphStrategy {
    _private: (),
}

impl KotlinUsageGraphStrategy {
    pub const fn new() -> Self {
        Self { _private: () }
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        language_for_target(target) == Language::Kotlin
    }
}

impl GraphUsageAnalyzer for KotlinUsageGraphStrategy {
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
        if language_for_target(target) != Language::Kotlin {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetLanguage("target is not Kotlin"),
                "KotlinUsageGraphStrategy",
            );
        }

        let Some(resolver) = KotlinQueryResolver::try_new(analyzer) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::MissingAnalyzerCapability(
                    "analyzer does not expose KotlinAnalyzer",
                ),
                "KotlinUsageGraphStrategy",
            );
        };

        resolver.find_usages(analyzer, overloads, scan_scope, max_usages)
    }
}

impl UsageAnalyzer for KotlinUsageGraphStrategy {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{KotlinAnalyzer, Project, TestProject};
    use std::sync::Arc;

    /// A whole-workspace edge build reads every file's declarations in *bulk*,
    /// and never pulls a file through the per-file LRU more than once.
    ///
    /// Scala's builder learned the first half: hydrating each file through the
    /// LRU during a whole-workspace build evicts the entries a user's
    /// interactive queries depend on, so one `usage_graph` call would leave
    /// every subsequent `scan_usages` cold.
    ///
    /// Kotlin reaches *one* LRU hydration per file that Scala and Java do not,
    /// and the bound is asserted rather than hidden. Both of those builders
    /// resolve entirely through workspace-wide indexes; Kotlin additionally
    /// reads per-*declaration* published facts — an overload's arities, a
    /// companion marker, a callee's return type — which are keyed by declaration
    /// rather than by file and so go through the declaring file's state. That
    /// pulls each file in once and then hits the transient cache, which is why
    /// the bound below is one per file and not one per declaration. Closing it
    /// needs the per-declaration facts to be readable out of the bulk states,
    /// which is recorded as a follow-up in
    /// `.agents/plans/kotlin-usage-graph-1239.md`.
    #[test]
    fn kotlin_usage_graph_bulk_fetch_hydrates_each_file_at_most_once() {
        const FILE_COUNT: usize = 132;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        for index in 0..FILE_COUNT {
            let file = ProjectFile::new(root.clone(), format!("C{index}.kt"));
            file.write(format!(
                "package bulk\n\nopen class Base{index} {{\n\n    fun run(): Int {{\n        return {index}\n    }}\n}}\n\nclass C{index} : Base{index}() {{\n\n    fun call(other: Base{index}): Int {{\n        return other.run()\n    }}\n}}\n"
            ))
            .unwrap();
        }

        let project = TestProject::new(root, Language::Kotlin);
        let analyzer = KotlinAnalyzer::new(Arc::new(project.clone()));
        let warm_file = ProjectFile::new(project.root().to_path_buf(), "C0.kt");

        analyzer.reset_full_hydration_count_for_test();
        assert!(!analyzer.declarations(&warm_file).is_empty());
        let lru_after_warm = analyzer.full_hydration_count_for_test();
        assert_eq!(lru_after_warm, 1);

        let nodes: HashSet<String> = analyzer
            .all_declarations()
            .map(|unit| unit.fq_name())
            .collect();
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            lru_after_warm,
            "declaration cataloging must not hydrate through the LRU path"
        );
        let edges = build_kotlin_usage_edges(&analyzer, &nodes, |_| true)
            .expect("kotlin usage graph should build");
        assert!(
            edges
                .edges
                .contains_key(&("bulk.C0.call".to_string(), "bulk.Base0.run".to_string())),
            "the build must still produce the edges it is being measured on"
        );
        let full_after_build = analyzer.full_hydration_count_for_test();
        assert!(
            full_after_build <= FILE_COUNT,
            "whole-workspace graph build must hydrate at most once per file, got {full_after_build} for {FILE_COUNT} files"
        );
        assert_eq!(
            analyzer.bulk_hydration_count_for_test(),
            FILE_COUNT,
            "bulk hydrations should be exactly one per file"
        );

        assert!(!analyzer.declarations(&warm_file).is_empty());
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            full_after_build,
            "a point query after the build must be served from cache, not re-hydrated"
        );
    }
}
