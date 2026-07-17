use super::extractor::{ScanState, prepare_file, scan_prepared_file};
use super::inverted;
use super::resolver::{TargetSpec, VisibilityIndex};
use crate::analyzer::usages::common::{analyzed_files_for_language, language_for_file};
use crate::analyzer::usages::inverted_edges::{UsageEdgeWeights, UsageEdges};
use crate::analyzer::usages::model::{FuzzyResult, UsageHit, UsageHitSurface};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{UsageEdgeResolver, UsageQueryResolver, UsageScanScope};
use crate::analyzer::{CodeUnit, CppAnalyzer, IAnalyzer, Language, ProjectFile, resolve_analyzer};
use crate::hash::HashSet;
use std::collections::BTreeSet;

fn scan_file_major<F, S, P, I, C, Prepare, Scan>(
    files: I,
    specs: &[S],
    mut is_cancelled: C,
    mut prepare: Prepare,
    mut scan: Scan,
) where
    I: IntoIterator<Item = F>,
    C: FnMut() -> bool,
    Prepare: FnMut(&F) -> Option<P>,
    Scan: FnMut(&F, &P, &S) -> bool,
{
    let mut capped = false;
    for file in files {
        if capped || is_cancelled() {
            break;
        }
        let Some(prepared) = prepare(&file) else {
            continue;
        };
        for spec in specs {
            if is_cancelled() {
                break;
            }
            capped = scan(&file, &prepared, spec);
            if capped {
                break;
            }
        }
    }
}

pub(crate) struct CppQueryResolver<'a> {
    cpp: &'a CppAnalyzer,
}

/// One authoritative inverse batch over a fixed union of caller roots.
///
/// Each query still scans only its own candidate set; the union index merely
/// prepares the per-root include closure and visible declarations once.
/// This seam is intentionally limited to the reference-differential batch,
/// which has no cancellation input. Cancellable `UsageFinder` requests keep
/// using `build_with_cancellation` and never enter this batch.
pub(crate) struct CppAuthoritativeUsageBatch<'a> {
    analyzer: &'a dyn IAnalyzer,
    resolver: CppQueryResolver<'a>,
    visibility: VisibilityIndex,
}

impl<'a> CppAuthoritativeUsageBatch<'a> {
    pub(crate) fn new(analyzer: &'a dyn IAnalyzer, roots: &HashSet<ProjectFile>) -> Option<Self> {
        let resolver = CppQueryResolver::try_new(analyzer)?;
        #[cfg(test)]
        resolver
            .cpp
            .record_authoritative_visibility_build_for_test();
        let visibility = VisibilityIndex::build(resolver.cpp, analyzer, roots);
        Some(Self {
            analyzer,
            resolver,
            visibility,
        })
    }

    pub(crate) fn find_usages(
        &self,
        overloads: &[CodeUnit],
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        let scan_scope = UsageScanScope::new(candidate_files, true);
        self.resolver.find_usages_with_visibility(
            self.analyzer,
            overloads,
            &scan_scope,
            max_usages,
            &self.visibility,
        )
    }
}

impl<'a> UsageQueryResolver<'a> for CppQueryResolver<'a> {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        Some(Self {
            cpp: resolve_analyzer::<CppAnalyzer>(analyzer)?,
        })
    }

    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        let files = self.scan_files(overloads, scan_scope);
        #[cfg(test)]
        self.cpp.record_authoritative_visibility_build_for_test();
        let visibility = VisibilityIndex::build_with_cancellation(
            self.cpp,
            analyzer,
            &files,
            scan_scope.cancellation(),
        );
        self.find_usages_with_visibility(analyzer, overloads, scan_scope, max_usages, &visibility)
    }
}

impl CppQueryResolver<'_> {
    fn find_usages_with_visibility(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
        visibility: &VisibilityIndex,
    ) -> GraphUsageOutcome {
        let Some(target) = overloads.first() else {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        };
        let mut specs = Vec::with_capacity(overloads.len());
        for overload in overloads {
            let Some(spec) = TargetSpec::from_target(analyzer, overload) else {
                return GraphUsageOutcome::fallback_safe(
                    overload.fq_name(),
                    GraphFailureReason::UnsupportedTargetShape("target shape is unsupported"),
                    "CppUsageGraphStrategy",
                );
            };
            specs.push(spec);
        }
        let target_group: HashSet<CodeUnit> = overloads.iter().cloned().collect();
        let files = self.scan_files(overloads, scan_scope);

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

        scan_file_major(
            files,
            &specs,
            || scan_scope.is_cancelled(),
            |file| prepare_file(self.cpp, file),
            |file, prepared, spec| {
                scan_prepared_file(
                    analyzer,
                    visibility,
                    file,
                    prepared,
                    spec,
                    &target_group,
                    &mut state,
                );
                *state.limit_exceeded
            },
        );

        let external_hit_count = hits
            .iter()
            .filter(|hit| hit.kind.included_in(UsageHitSurface::ExternalUsages))
            .count();
        if limit_exceeded || external_hit_count > max_usages {
            return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
                short_name: target.short_name().to_string(),
                total_callsites: external_hit_count,
                limit: max_usages,
                sample_hits: hits,
            });
        }

        GraphUsageOutcome::Resolved(FuzzyResult::success_with_unproven(
            target.clone(),
            hits,
            unproven_hits,
        ))
    }

    fn scan_files(
        &self,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
    ) -> HashSet<ProjectFile> {
        let mut files: HashSet<ProjectFile> = scan_scope
            .candidate_files()
            .iter()
            .filter(|file| language_for_file(file) == Language::Cpp)
            .cloned()
            .collect();
        for overload in overloads {
            if scan_scope.allows(overload.source()) {
                files.insert(overload.source().clone());
            }
        }
        files
    }
}

pub(crate) struct CppEdgeResolver<'a> {
    cpp: &'a CppAnalyzer,
    files: Vec<ProjectFile>,
}

impl<'a> UsageEdgeResolver<'a> for CppEdgeResolver<'a> {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        let cpp = resolve_analyzer::<CppAnalyzer>(analyzer)?;
        let files = analyzed_files_for_language(analyzer, Language::Cpp);
        Some(Self { cpp, files })
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
        // Resolution honors each caller file's include closure, so the visibility
        // index is seeded with every in-scope caller file as a root (mirroring the
        // forward scan, which builds it from the query's candidate files). Built here
        // rather than at construction so the trait's `try_new` needs no `keep_file`.
        let roots: HashSet<ProjectFile> = self
            .files
            .iter()
            .filter(|file| keep_file(file))
            .cloned()
            .collect();
        let visibility = VisibilityIndex::build(self.cpp, analyzer, &roots);
        inverted::build_cpp_edges(analyzer, &self.files, &visibility, nodes, keep_file)
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
        let roots: HashSet<ProjectFile> = self
            .files
            .iter()
            .filter(|file| keep_file(file))
            .cloned()
            .collect();
        let visibility = VisibilityIndex::build(self.cpp, analyzer, &roots);
        inverted::build_cpp_edges(analyzer, &self.files, &visibility, nodes, keep_file)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::scan_file_major;

    #[test]
    fn file_major_scan_prepares_once_and_visits_every_spec_in_order() {
        let files = ["first.cpp", "unreadable.cpp", "second.cpp"];
        let specs = ["arity-0", "arity-1", "arity-2"];
        let mut prepared = Vec::new();
        let mut scanned = Vec::new();

        scan_file_major(
            files,
            &specs,
            || false,
            |file| {
                prepared.push(*file);
                (*file != "unreadable.cpp").then_some(file.len())
            },
            |file, preparation, spec| {
                scanned.push((*file, *preparation, *spec));
                false
            },
        );

        assert_eq!(prepared, files);
        assert_eq!(
            scanned,
            vec![
                ("first.cpp", "first.cpp".len(), "arity-0"),
                ("first.cpp", "first.cpp".len(), "arity-1"),
                ("first.cpp", "first.cpp".len(), "arity-2"),
                ("second.cpp", "second.cpp".len(), "arity-0"),
                ("second.cpp", "second.cpp".len(), "arity-1"),
                ("second.cpp", "second.cpp".len(), "arity-2"),
            ]
        );
    }

    #[test]
    fn file_major_scan_stops_before_preparing_a_later_file_after_cap() {
        let mut prepared = Vec::new();
        let mut scanned = Vec::new();

        scan_file_major(
            ["first.cpp", "must-not-prepare.cpp"],
            &["first-spec", "capping-spec", "must-not-scan"],
            || false,
            |file| {
                prepared.push(*file);
                Some(())
            },
            |file, (), spec| {
                scanned.push((*file, *spec));
                *spec == "capping-spec"
            },
        );

        assert_eq!(prepared, vec!["first.cpp"]);
        assert_eq!(
            scanned,
            vec![("first.cpp", "first-spec"), ("first.cpp", "capping-spec")]
        );
    }

    #[test]
    fn file_major_scan_checks_cancellation_before_each_spec_and_later_file() {
        let cancelled = Cell::new(false);
        let mut prepared = Vec::new();
        let mut scanned = Vec::new();

        scan_file_major(
            ["first.cpp", "must-not-prepare.cpp"],
            &["first-spec", "must-not-scan"],
            || cancelled.get(),
            |file| {
                prepared.push(*file);
                Some(())
            },
            |file, (), spec| {
                scanned.push((*file, *spec));
                cancelled.set(true);
                false
            },
        );

        assert_eq!(prepared, vec!["first.cpp"]);
        assert_eq!(scanned, vec![("first.cpp", "first-spec")]);
    }

    #[test]
    fn file_major_scan_does_not_prepare_when_already_cancelled() {
        let mut prepared = 0;
        let mut scanned = 0;

        scan_file_major(
            ["must-not-prepare.cpp"],
            &["must-not-scan"],
            || true,
            |_| {
                prepared += 1;
                Some(())
            },
            |_, (), _| {
                scanned += 1;
                false
            },
        );

        assert_eq!(prepared, 0);
        assert_eq!(scanned, 0);
    }

    #[test]
    fn file_major_scan_rechecks_cancellation_after_preparing() {
        let cancelled = Cell::new(false);
        let mut prepared = 0;
        let mut scanned = 0;

        scan_file_major(
            ["prepared.cpp"],
            &["must-not-scan"],
            || cancelled.get(),
            |_| {
                prepared += 1;
                cancelled.set(true);
                Some(())
            },
            |_, (), _| {
                scanned += 1;
                false
            },
        );

        assert_eq!(prepared, 1);
        assert_eq!(scanned, 0);
    }
}
