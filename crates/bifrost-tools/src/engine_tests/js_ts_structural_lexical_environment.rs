#[cfg(test)]
mod js_ts_extraction_tests {

    use brokk_bifrost_core::analyzer::structural::resolution::HoistingClass;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::structural::lexical_environment::test_support::Fixture;

    use brokk_bifrost_analysis::analyzer::structural::lexical_environment::test_support::binding;

    use brokk_bifrost_analysis::analyzer::structural::lexical_environment::test_support::reached;
    #[test]
    fn js_var_read_before_its_declaration_reaches_the_hoisted_binding() {
        let source = concat!(
            "function render() {\n",
            "    const before = value;\n",
            "    var value = 2;\n",
            "    return before + value;\n",
            "}\n",
        );
        let fixture = Fixture::new(Language::JavaScript, "src/app.js", source);
        let env = fixture.environment();

        let value = binding(&env, "value");
        assert_eq!(value.hoisting, HoistingClass::ScopeWide);
        assert_eq!(
            reached(&env, "value", fixture.at("value;\n    var")).node,
            value.node
        );
    }
}
