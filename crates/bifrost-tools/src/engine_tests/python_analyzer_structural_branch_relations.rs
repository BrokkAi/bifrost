#[cfg(test)]
mod python_extraction_tests {

    use brokk_bifrost_analysis::analyzer::structural::branch_relations::BranchOpenReason;

    use brokk_bifrost_analysis::analyzer::structural::branch_relations::BranchRelationKind;

    use brokk_bifrost_analysis::analyzer::structural::branch_relations::BranchRelationVerdict;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::structural::branch_relations::js_ts_tests_support::rows;

    use brokk_bifrost_analysis::analyzer::structural::branch_relations::js_ts_tests_support::verdicts;
    #[test]
    fn python_identity_is_stable_but_truthiness_is_open() {
        let identity = rows(
            Language::Python,
            "sample.py",
            "def f(x):\n    if x is None:\n        return 1\n    elif x is None:\n        return 2\n",
        );
        assert_eq!(
            verdicts(&identity, BranchRelationKind::RepeatedCondition),
            vec![BranchRelationVerdict::Proven],
            "{identity:#?}"
        );

        let truthiness = rows(
            Language::Python,
            "sample.py",
            "class Stateful:\n    def __bool__(self):\n        return True\n\ndef f(x):\n    if x:\n        return 1\n    elif x:\n        return 2\n",
        );
        assert_eq!(
            verdicts(&truthiness, BranchRelationKind::RepeatedCondition),
            vec![BranchRelationVerdict::Open(
                BranchOpenReason::EffectfulCondition
            )],
            "{truthiness:#?}"
        );
    }
}
