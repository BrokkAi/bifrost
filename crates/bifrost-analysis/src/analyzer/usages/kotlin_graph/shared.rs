//! The Kotlin resolver for the usage *query* path — "who uses this declaration?".
//!
//! `usages/traits.rs` defines one resolver trait per usage path and requires one
//! impl of each per graph language, so that "both usage paths share one target
//! model" is a contract rather than a convention. This module implements
//! [`UsageQueryResolver`]; the companion [`crate::analyzer::usages::traits::UsageEdgeResolver`]
//! arrives with milestone 3 of issue #1239, and until then Kotlin contributes no
//! edges — the status quo the workspace graph already records.

use super::extractor::{ScanState, scan_file};
use super::resolver::{TargetKind, TargetSpec};
use crate::analyzer::usages::common::language_for_file;
use crate::analyzer::usages::model::{FuzzyResult, UsageHit};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{UsageQueryResolver, UsageScanScope};
use crate::analyzer::{
    CodeUnit, IAnalyzer, KotlinAnalyzer, Language, ProjectFile, resolve_analyzer,
};
use crate::hash::HashSet;
use std::collections::BTreeSet;

/// Resolves usages of one Kotlin target within a candidate file set.
///
/// Carries no state: everything a scan needs is derived per file, and the only
/// job of [`UsageQueryResolver::try_new`] here is the capability check — an
/// analyzer that cannot produce a `KotlinAnalyzer` cannot answer a Kotlin query,
/// and the strategy reports that as a missing capability rather than as an
/// absence of references.
pub(crate) struct KotlinQueryResolver;

impl<'a> UsageQueryResolver<'a> for KotlinQueryResolver {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        resolve_analyzer::<KotlinAnalyzer>(analyzer).map(|_| Self)
    }

    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        let Some(target) = overloads.first() else {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        };
        let _spec_scope = crate::profiling::scope("kotlin_graph::target_spec");
        let Some(spec) = TargetSpec::from_targets(analyzer, overloads) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetShape(
                    "Kotlin target has no indexed owner to resolve references against",
                ),
                "KotlinUsageGraphStrategy",
            );
        };
        drop(_spec_scope);

        // Milestone 1 of issue #1239 resolves references to Kotlin types. A
        // callable or property target abstains with a specific diagnostic rather
        // than returning an empty success, so a caller can tell "this has no
        // references" from "this is not implemented yet".
        if spec.kind != TargetKind::Type {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetShape(
                    "Kotlin usage analysis resolves type references only; callable and property \
                     references are issue #1239 milestone 2",
                ),
                "KotlinUsageGraphStrategy",
            );
        }

        let _select_scope = crate::profiling::scope("kotlin_graph::select_files");
        let mut files: HashSet<ProjectFile> = scan_scope
            .candidate_files()
            .iter()
            .filter(|file| language_for_file(file) == Language::Kotlin)
            .cloned()
            .collect();
        // The declaration's own file is always in scope: a type is regularly
        // referenced beside its own declaration, and omitting it would report
        // those references as absent rather than as out of scope.
        if language_for_file(target.source()) == Language::Kotlin
            && scan_scope.allows(target.source())
        {
            files.insert(target.source().clone());
        }
        let mut ordered: Vec<ProjectFile> = files.into_iter().collect();
        // Deterministic file order, so a truncated result truncates the same way
        // on every run.
        ordered.sort();
        drop(_select_scope);

        let mut hits: BTreeSet<UsageHit> = BTreeSet::new();
        let mut raw_match_count = 0usize;
        let mut limit_exceeded = false;
        let mut state = ScanState {
            max_usages,
            hits: &mut hits,
            raw_match_count: &mut raw_match_count,
            limit_exceeded: &mut limit_exceeded,
        };
        for file in ordered {
            if scan_scope.is_cancelled() {
                break;
            }
            let _file_scope = crate::profiling::scope("kotlin_graph::scan_file");
            scan_file(analyzer, &file, &spec, &mut state);
            if *state.limit_exceeded {
                break;
            }
        }

        if limit_exceeded || hits.len() > max_usages {
            return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
                short_name: target.short_name().to_string(),
                total_callsites: hits.len(),
                limit: max_usages,
                sample_hits: hits,
            });
        }

        // No unproven channel yet: a written type either resolves to the target
        // or does not, with no receiver to be uncertain about. Milestone 2's
        // callable and property arms are what introduce unproven hits.
        GraphUsageOutcome::Resolved(FuzzyResult::success_with_unproven(
            target.clone(),
            hits,
            BTreeSet::new(),
        ))
    }
}
