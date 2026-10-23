#[cfg(test)]
mod jvm_registry_tests {

    use brokk_bifrost_analysis::analyzer::structural::branch_relations::BranchOpenReason;

    use brokk_bifrost_analysis::analyzer::structural::branch_relations::BranchRelationKind;

    use brokk_bifrost_analysis::analyzer::structural::branch_relations::BranchRelationVerdict;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::structural::branch_relations::js_ts_tests_support::identical_bodies;

    use brokk_bifrost_analysis::analyzer::structural::branch_relations::js_ts_tests_support::rows;

    use brokk_bifrost_analysis::analyzer::structural::branch_relations::js_ts_tests_support::verdicts;

    #[test]
    fn java_boolean_returns_pair_only_with_the_next_statement_in_the_same_block() {
        for (source, orientation) in [
            (
                "class Sample { boolean f(boolean x) { if (x) return true; return false; } }",
                "condition",
            ),
            (
                "class Sample { boolean f(boolean x) { if (x) { return false; } /* note */ return true; } }",
                "negated_condition",
            ),
        ] {
            let rows = rows(Language::Java, "Sample.java", source);
            let boolean_rows = rows
                .iter()
                .filter(|row| row.kind == BranchRelationKind::RedundantBooleanReturn)
                .collect::<Vec<_>>();
            assert_eq!(boolean_rows.len(), 1, "{source}: {rows:?}");
            assert_eq!(boolean_rows[0].verdict, BranchRelationVerdict::Proven);
            assert_eq!(boolean_rows[0].orientation, Some(orientation));
            assert!(boolean_rows[0].later.start_byte > boolean_rows[0].owner.end_byte);
        }

        for source in [
            "class Sample { boolean f(boolean x) { if (x) return true; return true; } }",
            "class Sample { boolean f(boolean x) { if (x) return true; int marker = 0; return false; } }",
            "class Sample { boolean f(boolean x, boolean y) { if (x) { if (y) return true; } return false; } }",
        ] {
            let rows = rows(Language::Java, "Sample.java", source);
            assert!(
                verdicts(&rows, BranchRelationKind::RedundantBooleanReturn).is_empty(),
                "{source}: {rows:?}"
            );
        }
    }
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "fb68a2103438: Java boxed predicates and field targets produced incorrect branch proofs"
    )]
    fn java_primitive_and_boxed_relational_and_boolean_composition_are_stable() {
        for source in [
            "class Sample { int f(int x) { if (x > 5) return 1; else if (x > 5) return 2; return 0; } }",
            "class Sample { int f(int x, int y) { if (x > y) return 1; else if (x > y) return 2; return 0; } }",
            "class Sample { int f(int x, boolean ready) { if (ready && x > 5) return 1; else if (ready && x > 5) return 2; return 0; } }",
            "class Sample { int f(int x, int y) { if (x > 5 || y < -1) return 1; else if (x > 5 || y < -1) return 2; return 0; } }",
            "class Sample { int f() { int x = 6; if (x > 5) return 1; else if (x > 5) return 2; return 0; } }",
            "class Sample { int f(Integer x) { if (x > 5) return 1; else if (x > 5) return 2; return 0; } }",
            "class Sample { int f(Boolean ready, int x) { if (ready && x > 5) return 1; else if (ready && x > 5) return 2; return 0; } }",
        ] {
            let branch_rows = rows(Language::Java, "Sample.java", source);
            assert_eq!(
                verdicts(&branch_rows, BranchRelationKind::RepeatedCondition),
                vec![BranchRelationVerdict::Proven],
                "{source}: {branch_rows:#?}"
            );
        }
    }
    #[test]
    fn java_relational_repetition_keeps_unqualified_values_and_effects_open() {
        for source in [
            "class Sample { Double d; int f(Double x) { if (x > 5) return 1; else if (x > 5) return 2; return 0; } }",
            "class Sample { volatile int value; int f() { if (this.value > 5) return 1; else if (this.value > 5) return 2; return 0; } }",
            "class Sample { int f(int x) { if (x > 5) return 1; else if (x + 1 > 5) return 2; else if (x > 5) return 3; return 0; } }",
            "class Sample { boolean next() { return true; } int f(int x) { if (x > 5) return 1; else if (next()) return 2; else if (x > 5) return 3; return 0; } }",
            "class Sample { int f(int x) { if (x > 5) return 1; else if (++x > 0) return 2; else if (x > 5) return 3; return 0; } }",
        ] {
            let branch_rows = rows(Language::Java, "Sample.java", source);
            assert!(
                verdicts(&branch_rows, BranchRelationKind::RepeatedCondition).contains(
                    &BranchRelationVerdict::Open(BranchOpenReason::UnsupportedCondition)
                ) || verdicts(&branch_rows, BranchRelationKind::RepeatedCondition).contains(
                    &BranchRelationVerdict::Open(BranchOpenReason::MemberResolutionUnavailable)
                ) || verdicts(&branch_rows, BranchRelationKind::RepeatedCondition).contains(
                    &BranchRelationVerdict::Open(BranchOpenReason::NonLocalReference)
                ),
                "{source}: {branch_rows:#?}"
            );
            assert!(
                !verdicts(&branch_rows, BranchRelationKind::RepeatedCondition)
                    .contains(&BranchRelationVerdict::Proven),
                "{source}: {branch_rows:#?}"
            );
        }

        let volatile_boolean = rows(
            Language::Java,
            "Sample.java",
            "class Sample { volatile boolean ready; int f() { if (ready == true) return 1; else if (ready == true) return 2; return 0; } }",
        );
        assert!(
            verdicts(&volatile_boolean, BranchRelationKind::RepeatedCondition)
                .iter()
                .all(|verdict| matches!(verdict, BranchRelationVerdict::Open(_))),
            "{volatile_boolean:#?}"
        );
    }
    #[test]
    fn java_method_name_compares_as_a_name_not_through_a_same_named_local() {
        let calls = rows(
            Language::Java,
            "Sample.java",
            "class Sample { int log() { return 1; } int f(boolean condition) { int log = 0; if (condition) return log(); else return log(); } }",
        );
        assert_eq!(
            verdicts(&calls, BranchRelationKind::IdenticalBodies),
            vec![BranchRelationVerdict::Proven],
            "{calls:#?}"
        );
        let call_and_read = rows(
            Language::Java,
            "Sample.java",
            "class Sample { int log() { return 1; } int f(boolean condition) { int log = 0; if (condition) return log(); else return log; } }",
        );
        assert_eq!(
            verdicts(&call_and_read, BranchRelationKind::IdenticalBodies),
            vec![BranchRelationVerdict::Distinct],
            "{call_and_read:#?}"
        );
    }
    /// Catch, resource, loop and comprehension binders declared inside each
    /// arm pair binder by binder, as block locals do.

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#3684: Java pattern binders with identical names were unsafely merged across arms"
    )]
    fn java_pattern_binders_keep_identical_reads_open() {
        for source in [
            "class Sample { Object f(Object o, Object p) { if (o instanceof String s) return s; else if (p instanceof String s) return s; return null; } }",
            "class Sample { record Point(int x, int y) {} int f(Object o, Object p) { if (o instanceof Point(int x, int y)) return x; else if (p instanceof Point(int x, int y)) return x; return 0; } }",
            "class Sample { int s; int f(Object o, boolean flag) { if (flag) return s; else if (o instanceof Integer s) return s; return 0; } }",
        ] {
            let bodies = identical_bodies(Language::Java, "Sample.java", source);
            assert!(
                bodies.contains(&BranchRelationVerdict::Open(
                    BranchOpenReason::LexicalBindingUnavailable
                )) && !bodies.contains(&BranchRelationVerdict::Proven),
                "{source}: {bodies:?}"
            );
        }

        // Pattern and loop variables declared at matching positions inside
        // each arm stand for each other.
        for source in [
            "class Sample { Object f(Object o, boolean flag) { if (flag) { if (o instanceof String s) return s; return null; } else { if (o instanceof String s) return s; return null; } } }",
            "class Sample { int f(int[] values, boolean flag) { int sum = 0; if (flag) { for (int v : values) sum += v; } else { for (int v : values) sum += v; } return sum; } }",
        ] {
            assert_eq!(
                identical_bodies(Language::Java, "Sample.java", source),
                vec![BranchRelationVerdict::Proven],
                "{source}"
            );
        }
    }
}
