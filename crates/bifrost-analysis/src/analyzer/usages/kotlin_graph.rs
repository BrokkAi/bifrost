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
//! # Milestone status
//!
//! Type references are resolved. Callable and property references, the inverted
//! whole-workspace edge builder, and cross-language JVM scanning are the
//! remaining milestones of #1239; each abstains with a specific diagnostic rather
//! than returning an empty success, so a caller can always tell "no references"
//! from "not supported yet". See `.agents/plans/kotlin-usage-graph-1239.md`.

mod extractor;
mod hits;
mod resolver;
mod shared;

use crate::analyzer::usages::common::language_for_target;
use crate::analyzer::usages::kotlin_graph::shared::KotlinQueryResolver;
use crate::analyzer::usages::model::FuzzyResult;
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{UsageAnalyzer, UsageQueryResolver, UsageScanScope};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile};
use crate::hash::HashSet;

#[derive(Default)]
pub struct KotlinUsageGraphStrategy {
    _private: (),
}

impl KotlinUsageGraphStrategy {
    pub fn new() -> Self {
        Self { _private: () }
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        language_for_target(target) == Language::Kotlin
    }

    pub(crate) fn find_graph_usages(
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
