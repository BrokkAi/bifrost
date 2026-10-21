#[cfg(test)]
mod js_ts_direct_callable_tests {

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::test_support::assert_declared_binding_shortcut_is_skipped;

    use brokk_bifrost_core::analyzer::model::Language;
    #[test]
    fn direct_js_ts_callable_syntax_stays_on_source_resolver_route() {
        assert_declared_binding_shortcut_is_skipped(
            Language::TypeScript,
            "call.ts",
            "export function caller() { (() => 1)(); }\n",
        );
    }
}
