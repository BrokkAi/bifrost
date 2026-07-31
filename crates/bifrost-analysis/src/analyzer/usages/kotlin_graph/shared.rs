//! The two Kotlin usage resolvers — one per usage path.
//!
//! `usages/traits.rs` defines one resolver trait per usage path and requires one
//! impl of each per graph language, so that "both usage paths share one target
//! model" is a contract rather than a convention. [`KotlinQueryResolver`]
//! answers "who uses *this* declaration?" for `scan_usages`, LSP references, and
//! rename; [`KotlinEdgeResolver`] builds the whole `caller -> callee` edge set in
//! one inverted pass for `usage_graph`, `callers`/`callees`, relevance ranking,
//! and dead code. Both drive the same receiver typing, member lookup, and name
//! ladder through `super::resolver::KotlinResolutionCtx`.

use super::extractor::{ScanState, scan_file};
use super::inverted;
use super::resolver::TargetSpec;
use crate::analyzer::tree_sitter_analyzer::FileState;
use crate::analyzer::usages::common::language_for_file;
use crate::analyzer::usages::inverted_edges::{UsageEdgeWeights, UsageEdges};
use crate::analyzer::usages::model::{FuzzyResult, UsageHit};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{UsageEdgeResolver, UsageQueryResolver, UsageScanScope};
use crate::analyzer::{
    BulkFileStateSource, CodeUnit, IAnalyzer, KotlinAnalyzer, Language, ProjectFile,
    resolve_analyzer,
};
use crate::hash::{HashMap, HashSet};
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
        let mut unproven_hits: BTreeSet<UsageHit> = BTreeSet::new();
        let mut raw_match_count = 0usize;
        let mut limit_exceeded = false;
        let mut state = ScanState {
            max_usages,
            hits: &mut hits,
            unproven_hits: &mut unproven_hits,
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

        // A Kotlin class is equally nameable from Java and Scala source, and the
        // three languages share one candidate space, so find-references on a
        // Kotlin type must see those call sites too (#1239 milestone 4).
        if !scan_scope.is_cancelled() {
            let _cross_scope = crate::profiling::scope("kotlin_graph::scan_jvm_files");
            crate::analyzer::usages::java_graph::scan_jvm_files_for_foreign_type(
                analyzer,
                scan_scope.candidate_files(),
                target,
                max_usages,
                state.hits,
                state.unproven_hits,
                state.raw_match_count,
                state.limit_exceeded,
            );
        }

        let external_callsites = crate::analyzer::usages::common::external_usage_hit_count(&hits);
        if limit_exceeded || external_callsites > max_usages {
            return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
                short_name: target.short_name().to_string(),
                total_callsites: external_callsites,
                limit: max_usages,
                sample_hits: hits,
            });
        }

        // A reference the scan could not prove is reported in its own channel
        // rather than as a proven hit or as silence. A type reference never
        // lands there — a written type either resolves to the target or does not,
        // with no receiver to be uncertain about — but a call through a receiver
        // whose type could not be established does.
        GraphUsageOutcome::Resolved(FuzzyResult::success_with_unproven(
            target.clone(),
            hits,
            unproven_hits,
        ))
    }
}

/// Collect hits on a Java or Scala *type* target from Kotlin source.
///
/// Java, Scala, and Kotlin share one candidate space, so a Kotlin file naming a
/// Java class is a real usage of it — and before this, a Java find-references
/// simply did not see it. The scan is the ordinary Kotlin one: the target model
/// is language-agnostic (a class is a class), and the Kotlin name ladder already
/// resolves against the realm-wide declaration index, so the only thing that
/// changes is which files it runs over.
///
/// Restricted to type targets on purpose. A member reference needs the target
/// language's own member-lookup rules, and answering `Java.method` with Kotlin's
/// would be guessing; Java's existing Scala scanner draws the same line.
#[allow(clippy::too_many_arguments)]
pub(crate) fn scan_kotlin_files_for_jvm_type(
    analyzer: &dyn IAnalyzer,
    candidate_files: &HashSet<ProjectFile>,
    target: &CodeUnit,
    max_usages: usize,
    hits: &mut BTreeSet<UsageHit>,
    unproven_hits: &mut BTreeSet<UsageHit>,
    raw_match_count: &mut usize,
    limit_exceeded: &mut bool,
) {
    if *limit_exceeded || !target.is_class() {
        return;
    }
    if resolve_analyzer::<KotlinAnalyzer>(analyzer).is_none() {
        return;
    }
    let Some(spec) = TargetSpec::from_targets(analyzer, std::slice::from_ref(target)) else {
        return;
    };
    let mut ordered: Vec<ProjectFile> = candidate_files
        .iter()
        .filter(|file| language_for_file(file) == Language::Kotlin)
        .cloned()
        .collect();
    ordered.sort();
    let mut state = ScanState {
        max_usages,
        hits,
        unproven_hits,
        raw_match_count,
        limit_exceeded,
    };
    for file in ordered {
        scan_file(analyzer, &file, &spec, &mut state);
        if *state.limit_exceeded {
            break;
        }
    }
}

/// Builds the whole Kotlin `caller -> callee` edge set in one inverted pass.
///
/// The file states are prefetched in bulk rather than hydrated one at a time.
/// That matters for a reason the Scala builder learned first: pulling each file
/// through the per-file LRU during a whole-workspace build evicts the cache a
/// user's interactive queries depend on, so a `usage_graph` call would leave
/// every subsequent `scan_usages` cold.
pub(crate) struct KotlinEdgeResolver<'a> {
    files: Vec<ProjectFile>,
    file_states: HashMap<ProjectFile, FileState>,
    _kotlin: &'a KotlinAnalyzer,
}

impl<'a> UsageEdgeResolver<'a> for KotlinEdgeResolver<'a> {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        let kotlin = resolve_analyzer::<KotlinAnalyzer>(analyzer)?;
        let files: Vec<ProjectFile> = analyzer
            .project()
            .analyzable_files(Language::Kotlin)
            .ok()?
            .into_iter()
            .collect();
        let file_states = kotlin.bulk_file_states(files.clone(), BulkFileStateSource::Omit);
        Some(Self {
            files,
            file_states,
            _kotlin: kotlin,
        })
    }

    fn build_edges<F>(
        &self,
        analyzer: &dyn IAnalyzer,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdges
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        inverted::build_kotlin_edges(analyzer, &self.files, &self.file_states, nodes, keep_file)
    }

    fn build_edge_weights<F>(
        &self,
        analyzer: &dyn IAnalyzer,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdgeWeights
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        inverted::build_kotlin_edges(analyzer, &self.files, &self.file_states, nodes, keep_file)
    }
}
