#[cfg(test)]
mod jvm_registry_tests {

    use brokk_bifrost_analysis::analyzer::structural::identity_routes::test_support::Fixture;

    use brokk_bifrost_core::analyzer::structural::occurrences::Namespace;

    use brokk_bifrost_analysis::analyzer::structural::identity_routes::canonical_identity_of;

    use brokk_bifrost_core::analyzer::model::Language;
    #[test]
    fn same_terminal_different_owner_decoys_compare_unequal() {
        let fixture = Fixture::new(
            Language::Java,
            &[
                ("src/a/Map.java", "package a;\npublic class Map {}\n"),
                ("src/b/Map.java", "package b;\npublic class Map {}\n"),
            ],
        );
        let a_map = fixture.declaration("a.Map");
        let b_map = fixture.declaration("b.Map");
        let a_identity = canonical_identity_of(fixture.analyzer(), &a_map);
        let b_identity = canonical_identity_of(fixture.analyzer(), &b_map);
        assert_ne!(a_identity, b_identity);
        assert_eq!(
            a_identity.segments.last().unwrap().text,
            b_identity.segments.last().unwrap().text
        );
        assert_eq!(a_identity.namespace, Namespace::Type);
    }
}
