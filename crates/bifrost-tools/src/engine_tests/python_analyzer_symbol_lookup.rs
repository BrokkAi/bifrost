#[cfg(test)]
mod python_extraction_tests {

    use brokk_bifrost_core::analyzer::model::CodeUnit;

    use brokk_bifrost_analysis::analyzer::symbol_lookup::CodeUnitResolution;

    use brokk_bifrost_analysis::analyzer::symbol_lookup::FuzzyResolveBudget;

    use brokk_bifrost_analysis::analyzer::symbol_lookup::FuzzyResolveStop;

    use brokk_bifrost_analysis::analyzer::symbol_lookup::resolve_codeunit_fuzzy;

    use brokk_bifrost_analysis::analyzer::symbol_lookup::resolve_codeunit_fuzzy_bounded;

    use brokk_bifrost_python_analysis::analyzer::python::PythonAdapter;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;
    use std::cell::Cell;
    /// A workspace where one identifier names `count` distinct declarations —
    /// the shape #1839 measured at 20,935 on the rustc tree for `main`.
    fn same_named_declarations(
        count: usize,
    ) -> (tempfile::TempDir, TreeSitterAnalyzer<PythonAdapter>) {
        let (temp, project) =
            brokk_bifrost_analysis::analyzer::test_support::python_package_project(
                (0..count).map(|_| "class Shared:\n    pass\n".to_string()),
            );
        let analyzer = TreeSitterAnalyzer::new(project, PythonAdapter::default());
        (temp, analyzer)
    }
    /// A predicate that survives `polls` questions and then reports the
    /// caller's budget as spent, so the stop point is deterministic rather
    /// than a race against a wall clock.
    fn budget_spent_after(polls: usize) -> impl Fn() -> bool {
        let asked = Cell::new(0usize);
        move || {
            let seen = asked.get();
            asked.set(seen + 1);
            seen < polls
        }
    }
    /// #1839 component 1: the caller's budget reaches the resolver's loops.
    /// Without the polls the resolution runs to completion and charges one
    /// `definitions` read per matched declaration — the 20,935-read storm.
    /// `definitions` reads charged by one resolution in its own fresh request
    /// scope. The fixture is warmed outside any scope first, so the figure is
    /// steady-state store traffic rather than first-touch analysis.
    fn definition_reads_for(
        analyzer: &TreeSitterAnalyzer<PythonAdapter>,
        resolve: impl FnOnce() -> Result<CodeUnitResolution, FuzzyResolveStop>,
    ) -> (Result<CodeUnitResolution, FuzzyResolveStop>, usize) {
        let _scope =
            brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(analyzer);
        analyzer.reset_definition_candidates_query_count_for_test();
        let resolution = resolve();
        let reads = analyzer.definition_candidates_query_count_for_test();
        (resolution, reads)
    }
    #[test]
    fn issue_1839_a_spent_budget_stops_resolution_before_the_per_candidate_reads() {
        let (_temp, analyzer) = same_named_declarations(6);
        let warm = resolve_codeunit_fuzzy(&analyzer, "Shared");
        assert!(
            matches!(&warm, CodeUnitResolution::Ambiguous(units) if units.len() == 6),
            "fixture must offer six same-named declarations: {warm:?}"
        );
        let (_, complete_reads) = definition_reads_for(&analyzer, || {
            Ok(resolve_codeunit_fuzzy(&analyzer, "Shared"))
        });

        let keep_going = budget_spent_after(1);
        let (stopped, stopped_reads) = definition_reads_for(&analyzer, || {
            resolve_codeunit_fuzzy_bounded(
                &analyzer,
                "Shared",
                FuzzyResolveBudget::new(&keep_going, usize::MAX),
            )
        });

        assert!(
            matches!(stopped, Err(FuzzyResolveStop::Cancelled)),
            "a spent budget must stop the resolution: {stopped:?}"
        );
        assert!(
            stopped_reads < complete_reads,
            "a stopped resolution must charge fewer reads than the completed one: \
             {stopped_reads} against {complete_reads}"
        );
    }
    /// #1839 component 3: a selector that too many declarations answer reports
    /// the true count instead of expanding a candidate list nobody can act on.
    /// The count is exact and is taken before any per-candidate store read.
    #[test]
    fn issue_1839_an_over_cap_selector_reports_its_true_count_and_skips_the_expansion() {
        let (_temp, analyzer) = same_named_declarations(6);
        let _ = resolve_codeunit_fuzzy(&analyzer, "Shared");
        let (_, complete_reads) = definition_reads_for(&analyzer, || {
            Ok(resolve_codeunit_fuzzy(&analyzer, "Shared"))
        });

        let keep_going = || true;
        let (over, over_reads) = definition_reads_for(&analyzer, || {
            resolve_codeunit_fuzzy_bounded(
                &analyzer,
                "Shared",
                FuzzyResolveBudget::new(&keep_going, 5),
            )
        });

        match over {
            Err(FuzzyResolveStop::TooManyCandidates { total, limit }) => {
                assert_eq!(6, total, "the reported count must be the true match count");
                assert_eq!(5, limit);
            }
            other => panic!("an over-cap selector must report its count: {other:?}"),
        }
        assert!(
            over_reads < complete_reads,
            "an over-cap selector must skip the per-candidate expansion: \
             {over_reads} reads against {complete_reads}"
        );
    }
    /// #1839 seam 2: the fan-out verdict beats the caller's clock.
    ///
    /// The count that the gate exists to report is fully determined once the
    /// two indexed reads in `bare_name_resolution` return. A caller whose
    /// budget expires during those reads used to get a bare `Cancelled` --
    /// `keep_going` was polled per candidate, before `admits` was ever reached
    /// -- so the tool reported the caller's own clock instead of the answer it
    /// already had.
    ///
    /// `budget_spent_after(1)` leaves exactly the entry poll in
    /// `resolve_codeunit_fuzzy_bounded_with` alive, so the budget is spent by
    /// the time the accumulation loops run -- deterministically, without a
    /// wall clock.
    #[test]
    fn issue_1839_an_over_cap_selector_reports_its_count_even_on_a_spent_budget() {
        let (_temp, analyzer) = same_named_declarations(6);
        let warm = resolve_codeunit_fuzzy(&analyzer, "Shared");
        assert!(
            matches!(&warm, CodeUnitResolution::Ambiguous(units) if units.len() == 6),
            "fixture must offer six same-named declarations: {warm:?}"
        );

        let keep_going = budget_spent_after(1);
        let outcome = resolve_codeunit_fuzzy_bounded(
            &analyzer,
            "Shared",
            FuzzyResolveBudget::new(&keep_going, 5),
        );

        match outcome {
            Err(FuzzyResolveStop::TooManyCandidates { total, limit }) => {
                assert_eq!(
                    6, total,
                    "the deduplicated match count, not the pre-dedup row count"
                );
                assert_eq!(5, limit);
            }
            other => panic!("a spent budget must not hide the fan-out verdict: {other:?}"),
        }
    }
    /// The same selector one candidate under the cap is untouched: the whole
    /// candidate set resolves exactly as an unbudgeted call resolves it.
    #[test]
    fn issue_1839_an_under_cap_selector_resolves_exactly_as_an_unbudgeted_call() {
        let (_temp, analyzer) = same_named_declarations(6);
        let _scope =
            brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(&analyzer);
        let keep_going = || true;

        let unbudgeted = resolve_codeunit_fuzzy(&analyzer, "Shared");
        let budgeted = resolve_codeunit_fuzzy_bounded(
            &analyzer,
            "Shared",
            FuzzyResolveBudget::new(&keep_going, 6),
        )
        .expect("six candidates are within a six-candidate budget");

        let units = |resolution: &CodeUnitResolution| match resolution {
            CodeUnitResolution::Resolved(units) | CodeUnitResolution::Ambiguous(units) => {
                units.iter().map(CodeUnit::fq_name).collect::<Vec<_>>()
            }
            CodeUnitResolution::NotFound => Vec::new(),
        };
        assert_eq!(units(&unbudgeted), units(&budgeted));
        assert_eq!(6, units(&budgeted).len());
    }
}
