use crate::analyzer::CodeUnitIndex;
use crate::analyzer::cpp::cpp_sentinel_recovered_classes;
use crate::analyzer::usages::common::{analyzed_files_for_language, language_for_file};
use crate::analyzer::usages::cpp_graph::CppDispatch;
use crate::analyzer::usages::inverted_edges::{
    UsageEdgeBuildOutput, UsageEdgeWeights, UsageEdges, build_edge_output, parse_and_collect,
};
use crate::analyzer::usages::model::{FuzzyResult, UsageHit, UsageHitSurface};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{UsageQueryResolver, UsageScanScope};
use crate::analyzer::{CodeUnit, CppAnalyzer, IAnalyzer, Language, ProjectFile, resolve_analyzer};
use crate::hash::HashSet;
use brokk_bifrost_cpp::graph::extractor::{ScanState, prepare_file, scan_prepared_file};
use brokk_bifrost_cpp::graph::resolver::{TargetSpec, TypeScanKey, VisibilityIndex};
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

fn retain_scan_spec(seen_type_specs: &mut HashSet<TypeScanKey>, spec: &TargetSpec) -> bool {
    spec.type_scan_key()
        .is_none_or(|key| seen_type_specs.insert(key))
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
pub struct CppAuthoritativeUsageBatch<'a> {
    analyzer: &'a dyn IAnalyzer,
    resolver: CppQueryResolver<'a>,
    visibility: VisibilityIndex<'a>,
}

impl<'a> CppAuthoritativeUsageBatch<'a> {
    pub fn new(analyzer: &'a dyn IAnalyzer, roots: &HashSet<ProjectFile>) -> Option<Self> {
        let resolver = CppQueryResolver::try_new(analyzer)?;
        // This listing already validates every live path for the active outer
        // request scope.  Have it seed the request's live-source memo before
        // visibility construction or parallel target scans can begin, so those
        // scans only take read locks and never serialize on first-use inserts.
        let _ = resolver.cpp.analyzed_files();
        // Hydrate the fixed union of authoritative roots once. The concrete
        // analyzer publishes the keyed states into an immutable request
        // snapshot so the visibility build and parallel target scans avoid
        // repeating file-state hydration and range reads.
        resolver
            .cpp
            .bulk_file_states_for_query(roots.iter().cloned());
        #[cfg(any(test, feature = "test-support"))]
        resolver
            .cpp
            .record_authoritative_visibility_build_for_test();
        let dispatch = CppDispatch::new(analyzer);
        let visibility = VisibilityIndex::build(resolver.cpp, dispatch.source(), roots);
        Some(Self {
            analyzer,
            resolver,
            visibility,
        })
    }

    pub fn find_usages(
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

    #[cfg(any(test, feature = "test-support"))]
    pub fn alias_visible_source_files_for_test(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        self.visibility.visible_source_files_for_test(file)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn alias_source_parse_count_for_test(&self, file: &ProjectFile) -> usize {
        self.visibility.alias_source_parse_count_for_test(file)
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
        #[cfg(any(test, feature = "test-support"))]
        self.cpp.record_authoritative_visibility_build_for_test();
        let dispatch = CppDispatch::new(analyzer);
        let visibility = VisibilityIndex::build_with_cancellation(
            self.cpp,
            dispatch.source(),
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
        let dispatch = CppDispatch::new(analyzer);
        let source = dispatch.source();
        let mut specs = Vec::with_capacity(overloads.len());
        let mut seen_type_specs = HashSet::default();
        for overload in overloads {
            let Some(spec) = TargetSpec::from_target(source, overload) else {
                return GraphUsageOutcome::fallback_safe(
                    overload.fq_name(),
                    GraphFailureReason::UnsupportedTargetShape("target shape is unsupported"),
                    "CppUsageGraphStrategy",
                );
            };
            if retain_scan_spec(&mut seen_type_specs, &spec) {
                specs.push(spec);
            }
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
            |file| {
                prepare_file(self.cpp, file).map(|prepared| {
                    let recovered_sentinel_classes = cpp_sentinel_recovered_classes(
                        prepared.tree().root_node(),
                        prepared.source(),
                    );
                    (prepared, recovered_sentinel_classes)
                })
            },
            |file, (prepared, recovered_sentinel_classes), spec| {
                #[cfg(any(test, feature = "test-support"))]
                self.cpp.record_target_spec_scan_for_test();
                let spec = spec
                    .with_visible_callable_arities(source, self.cpp, visibility, file, prepared);
                scan_prepared_file(
                    source,
                    visibility,
                    file,
                    prepared,
                    recovered_sentinel_classes,
                    spec.as_ref(),
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

/// Build the whole C++ `caller -> callee` edge set in a single inverted pass
/// over the resolver-owned file set. `nodes`/`keep_file` mirror the Go builder.
///
/// The fan-out stays on this side of the seam: `build_edge_output` and
/// `parse_and_collect` are the shared, language-agnostic driver, and only the
/// per-file C++ walk crossed.
pub(super) fn build_cpp_edges<Output, F>(
    analyzer: &dyn IAnalyzer,
    files: &[ProjectFile],
    visibility: &VisibilityIndex<'_>,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Output
where
    Output: UsageEdgeBuildOutput<String>,
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let language = tree_sitter_cpp::LANGUAGE.into();
    let dispatch = CppDispatch::new(analyzer);
    build_edge_output(files, keep_file, |file| {
        parse_and_collect(analyzer, file, nodes, &language, |input| {
            brokk_bifrost_cpp::graph::inverted::scan_file(
                dispatch.source(),
                visibility,
                file,
                input,
            )
        })
    })
}

pub(crate) struct CppEdgeResolver<'a> {
    cpp: &'a CppAnalyzer,
    files: Vec<ProjectFile>,
}

/// The whole-workspace `caller -> callee` scan behind this language's
/// [`LanguageEdgePass`](crate::analyzer::languages::LanguageEdgePass): borrow the concrete
/// analyzer once, then walk every file once and finalize into either site-bearing edges or
/// reference-kind weights.
impl<'a> CppEdgeResolver<'a> {
    pub(crate) fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        let cpp = resolve_analyzer::<CppAnalyzer>(analyzer)?;
        let files = analyzed_files_for_language(analyzer, Language::Cpp);
        Some(Self { cpp, files })
    }

    pub(crate) fn build_edges<F>(
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
        let dispatch = CppDispatch::new(analyzer);
        let visibility = VisibilityIndex::build(self.cpp, dispatch.source(), &roots);
        build_cpp_edges(analyzer, &self.files, &visibility, nodes, keep_file)
    }

    pub(crate) fn build_edge_weights<F>(
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
        let dispatch = CppDispatch::new(analyzer);
        let visibility = VisibilityIndex::build(self.cpp, dispatch.source(), &roots);
        build_cpp_edges(analyzer, &self.files, &visibility, nodes, keep_file)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::{retain_scan_spec, scan_file_major};
    use crate::analyzer::{CallableArity, CodeUnit, CodeUnitType, ProjectFile};
    use crate::hash::HashSet;
    use brokk_bifrost_cpp::graph::resolver::{TargetKind, TargetSpec};

    #[test]
    fn identical_method_redeclarations_remain_physically_distinct_scan_specs() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let method_spec = |path: &str| {
            let source = ProjectFile::new(root.clone(), path);
            let owner = CodeUnit::new(source.clone(), CodeUnitType::Class, "demo", "Owner");
            let method = CodeUnit::with_signature(
                source,
                CodeUnitType::Function,
                "demo",
                "Owner.call",
                Some("void call(int)".to_string()),
                false,
            );
            TargetSpec::new(
                method,
                TargetKind::Method,
                Some(owner),
                "call".to_string(),
                Some(CallableArity::exact(1)),
                Some(vec!["int".to_string()]),
            )
        };
        let specs = [method_spec("first.h"), method_spec("second.h")];
        let mut seen = HashSet::default();

        assert_eq!(
            specs
                .iter()
                .filter(|spec| retain_scan_spec(&mut seen, spec))
                .count(),
            2,
            "non-Type specs retain source-sensitive declaration and owner behavior"
        );
    }

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
