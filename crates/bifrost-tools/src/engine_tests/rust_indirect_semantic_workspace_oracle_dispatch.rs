#[cfg(test)]
mod rust_indirect_table_tests {

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::rust_tests_test_support::RUST_EXTERNAL_CALL_SOURCE as RUST_EXTERNAL_CALL_SOURCE;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::test_support::external_call_identities;

    use brokk_bifrost_core::analyzer::model::Language;

    /// #4317: a resolver-owned identity is a target identity, not a behavior
    /// model row. The receiverless `std` paths remain addressable without an
    /// activated callable declaration; the prelude receiver method still
    /// needs its separate receiver/type route.
    #[test]
    fn an_unmodeled_rust_external_callee_publishes_a_resolver_identity() {
        assert_eq!(
            external_call_identities(Language::Rust, "lib.rs", RUST_EXTERNAL_CALL_SOURCE),
            vec![
                (
                    String::from("Path::new(text)"),
                    Some(("std.path.Path".to_owned(), "new".to_owned(), 1, false))
                ),
                (String::from("String::from(text)"), None),
                (
                    String::from("std::str::from_utf8(bytes)"),
                    Some(("std.str".to_owned(), "from_utf8".to_owned(), 1, false))
                ),
            ]
        );
    }
}
