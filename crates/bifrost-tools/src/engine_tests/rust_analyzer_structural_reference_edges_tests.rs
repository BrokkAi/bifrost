#[cfg(test)]
mod rust_departing_tests_tests {

    use brokk_bifrost_analysis::analyzer::structural::reference_edges::test_support::Fixture;

    use brokk_bifrost_core::analyzer::structural::edges::OwnerRelation;

    use brokk_bifrost_analysis::analyzer::structural::reference_edges::classify_owner_relation;

    use brokk_bifrost_core::analyzer::model::Language;
    use brokk_bifrost_test_macros::hardwon;
    #[test]
    #[hardwon("#1645: unrelated root-scope functions must remain unknown owners")]
    fn two_root_scope_owners_stay_unknown() {
        let fixture = Fixture::new(
            Language::Rust,
            &[(
                "src/lib.rs",
                "pub fn drive() -> usize {\n    helper()\n}\n\npub fn helper() -> usize {\n    1\n}\n",
            )],
        );
        let analyzer = fixture.analyzer();
        let drive = fixture.declaration("drive");
        let helper = fixture.declaration("helper");
        assert_eq!(
            classify_owner_relation(analyzer, Some(&drive), &helper),
            OwnerRelation::Unknown
        );
    }
}
