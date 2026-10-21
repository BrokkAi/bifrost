#[cfg(test)]
mod js_ts_extraction_tests {

    use brokk_bifrost_analysis::analyzer::structural::branch_relations::BranchOpenReason;

    use brokk_bifrost_analysis::analyzer::structural::branch_relations::BranchRelationKind;

    use brokk_bifrost_analysis::analyzer::structural::branch_relations::BranchRelationVerdict;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_test_macros::hardwon;

    use brokk_bifrost_analysis::analyzer::structural::branch_relations::js_ts_tests_support::identical_bodies;

    use brokk_bifrost_analysis::analyzer::structural::branch_relations::js_ts_tests_support::rows;

    use brokk_bifrost_analysis::analyzer::structural::branch_relations::js_ts_tests_support::verdicts;
    #[test]
    fn typescript_branch_relations_ignore_comments_but_abstain_on_calls() {
        let branch_rows = rows(
            Language::TypeScript,
            "sample.ts",
            "function f(x: number) { if (x === 1) { /* one */ return x; } else if (x === 1) { /* two */ return x; } else { return 0; } }",
        );
        assert_eq!(
            verdicts(&branch_rows, BranchRelationKind::RepeatedCondition),
            vec![BranchRelationVerdict::Proven],
            "{branch_rows:#?}"
        );
        assert!(
            verdicts(&branch_rows, BranchRelationKind::IdenticalBodies)
                .contains(&BranchRelationVerdict::Proven),
            "{branch_rows:#?}"
        );

        let calls = rows(
            Language::TypeScript,
            "sample.ts",
            "function f(next: () => boolean) { if (next()) { return 1; } else if (next()) { return 2; } }",
        );
        assert!(
            matches!(
                verdicts(&calls, BranchRelationKind::RepeatedCondition).as_slice(),
                [BranchRelationVerdict::Open(_)]
            ),
            "{calls:#?}"
        );
    }
    #[test]
    fn javascript_and_jsx_share_exact_branch_evidence() {
        for (path, prefix) in [
            ("sample.js", ""),
            ("sample.jsx", "const element = <section />; "),
        ] {
            let source = format!(
                "{prefix}function f(x) {{ if (x === 'ready') return x; else if (x === 'ready') return x; else return 0; }}"
            );
            let branch_rows = rows(Language::JavaScript, path, &source);
            assert_eq!(
                verdicts(&branch_rows, BranchRelationKind::RepeatedCondition),
                vec![BranchRelationVerdict::Proven],
                "{path}: {branch_rows:#?}"
            );
            assert!(
                verdicts(&branch_rows, BranchRelationKind::IdenticalBodies)
                    .contains(&BranchRelationVerdict::Proven),
                "{path}: {branch_rows:#?}"
            );
        }
    }
    #[test]
    fn javascript_dynamic_with_lookup_and_file_binding_are_open() {
        let with_lookup = rows(
            Language::JavaScript,
            "sample.js",
            "function f(x, object) { with (object) { if (x === null) return x; else if (x === null) return x; } }",
        );
        assert!(
            verdicts(&with_lookup, BranchRelationKind::RepeatedCondition)
                .iter()
                .all(|verdict| matches!(verdict, BranchRelationVerdict::Open(_))),
            "{with_lookup:#?}"
        );
        assert!(
            verdicts(&with_lookup, BranchRelationKind::IdenticalBodies)
                .iter()
                .all(|verdict| matches!(verdict, BranchRelationVerdict::Open(_))),
            "{with_lookup:#?}"
        );

        let file_binding = rows(
            Language::JavaScript,
            "sample.js",
            "let current = null; function f() { if (current === null) return 1; else if (current === null) return 2; }",
        );
        assert!(
            verdicts(&file_binding, BranchRelationKind::RepeatedCondition)
                .iter()
                .all(|verdict| matches!(verdict, BranchRelationVerdict::Open(_))),
            "{file_binding:#?}"
        );
    }
    #[test]
    fn nonadjacent_repetition_requires_every_intervening_test_to_be_stable() {
        let stable = rows(
            Language::JavaScript,
            "sample.js",
            "function f(x) { if (x === 1) return 1; else if (x === 2) return 2; else if (x === 1) return 3; return 0; }",
        );
        assert_eq!(
            verdicts(&stable, BranchRelationKind::RepeatedCondition),
            vec![
                BranchRelationVerdict::Distinct,
                BranchRelationVerdict::Proven,
                BranchRelationVerdict::Distinct
            ],
            "{stable:#?}"
        );

        let effectful = rows(
            Language::JavaScript,
            "sample.js",
            "function f(x, next) { if (x === 1) return 1; else if (next()) return 2; else if (x === 1) return 3; return 0; }",
        );
        assert!(
            verdicts(&effectful, BranchRelationKind::RepeatedCondition)
                .iter()
                .all(|verdict| *verdict != BranchRelationVerdict::Proven),
            "{effectful:#?}"
        );
    }
    /// Each arm creates its own closure, object method or class, whatever the
    /// grammar calls it and whatever parameters it binds.
    #[test]
    #[hardwon("64dfd105e7fd: identical-branch proof compared fresh nested callable identities")]
    fn nested_callables_and_local_classes_in_matching_arms_stay_deferred() {
        let deferred = vec![BranchRelationVerdict::Open(BranchOpenReason::DeferredBody)];
        for &(language, path, source) in
            brokk_bifrost_analysis::test_support::NESTED_CALLABLE_BRANCH_CASES
        {
            assert_eq!(
                identical_bodies(language, path, source),
                deferred,
                "{source}"
            );
        }
        for (language, path, source) in [
            (
                Language::TypeScript,
                "sample.ts",
                "function f(x: number) { if (x === 1) { return class { m() { return x; } }; } else { return class { m() { return x; } }; } }",
            ),
            (
                Language::Java,
                "Sample.java",
                "class Sample { java.util.function.IntBinaryOperator f(int x) { if (x == 1) return (int a, int b) -> a + b + x; else return (int a, int b) -> a + b + x; } }",
            ),
            (
                Language::Java,
                "Sample.java",
                "class Sample { Object f(int x) { if (x == 1) { enum E { A } return E.A; } else { enum E { A } return E.A; } } }",
            ),
        ] {
            assert_eq!(
                identical_bodies(language, path, source),
                deferred,
                "{source}"
            );
        }
    }
    /// Deferring a nested callable does not hide a difference elsewhere in the
    /// arms, and a callable never equals a non-callable.
    #[test]
    #[hardwon("64dfd105e7fd: deferral of nested bodies hid differences in the enclosing arms")]
    fn deferred_callables_keep_distinct_arms_complete() {
        for (language, path, source) in [
            (
                Language::JavaScript,
                "sample.js",
                "function f(x, run) { if (x === 1) { run((a) => a); return 1; } else { run((a) => a); return 2; } }",
            ),
            (
                Language::JavaScript,
                "sample.js",
                "function f(x) { if (x === 1) { return () => x; } else { return x; } }",
            ),
            (
                Language::Python,
                "sample.py",
                "def f(x, run):\n    if x is None:\n        run(lambda a: a)\n        return 1\n    else:\n        run(lambda a: a)\n        return 2\n",
            ),
            (
                Language::Java,
                "Sample.java",
                "class Sample { int f(int x, java.util.function.Consumer<java.util.function.IntUnaryOperator> run) { if (x == 1) { run.accept(a -> a); return 1; } else { run.accept(a -> a); return 2; } } }",
            ),
        ] {
            assert_eq!(
                identical_bodies(language, path, source),
                vec![BranchRelationVerdict::Distinct],
                "{source}"
            );
        }
    }
    #[test]
    #[hardwon("64dfd105e7fd: identical branch text paired different arm-local binders")]
    fn arm_local_catch_resource_loop_and_comprehension_binders_pair() {
        for (language, path, source) in [
            (
                Language::Java,
                "Sample.java",
                "class Sample { int g() { return 1; } int f(boolean flag) { if (flag) { try { return g(); } catch (RuntimeException e) { return e.hashCode(); } } else { try { return g(); } catch (RuntimeException other) { return other.hashCode(); } } } }",
            ),
            (
                Language::Java,
                "Sample.java",
                "class Sample { int f(boolean flag) throws Exception { if (flag) { try (java.io.StringReader r = new java.io.StringReader(\"\")) { return r.read(); } } else { try (java.io.StringReader q = new java.io.StringReader(\"\")) { return q.read(); } } } }",
            ),
            (
                Language::JavaScript,
                "sample.js",
                "function f(flag, g) { if (flag) { try { return g(); } catch (e) { return e; } } else { try { return g(); } catch (other) { return other; } } }",
            ),
            (
                Language::TypeScript,
                "sample.ts",
                "function f(flag: boolean, xs: number[], use: (v: number) => void) { if (flag) { for (const v of xs) use(v); } else { for (const w of xs) use(w); } }",
            ),
            (
                Language::Python,
                "sample.py",
                "def f(flag, xs):\n    if flag:\n        return [y + 1 for y in xs]\n    else:\n        return [z + 1 for z in xs]\n",
            ),
        ] {
            assert_eq!(
                identical_bodies(language, path, source),
                vec![BranchRelationVerdict::Proven],
                "{source}"
            );
        }

        for (language, path, source) in [
            (
                Language::Java,
                "Sample.java",
                "class Sample { int g() { return 1; } int f(boolean flag) { if (flag) { try { return g(); } catch (RuntimeException e) { return e.hashCode(); } } else { try { return g(); } catch (IllegalStateException e) { return e.hashCode(); } } } }",
            ),
            (
                Language::JavaScript,
                "sample.js",
                "function f(flag, g, other) { if (flag) { try { return g(); } catch (e) { return e; } } else { try { return g(); } catch (e) { return other; } } }",
            ),
            (
                Language::Python,
                "sample.py",
                "def f(flag, xs, z):\n    if flag:\n        return [y + 1 for y in xs]\n    else:\n        return [z + 1 for y in xs]\n",
            ),
        ] {
            assert_eq!(
                identical_bodies(language, path, source),
                vec![BranchRelationVerdict::Distinct],
                "{source}"
            );
        }
    }
}
