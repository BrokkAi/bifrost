#[cfg(test)]
mod js_ts_extraction_tests {

    use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;

    use brokk_bifrost_core::analyzer::structural::occurrences::Namespace;

    use brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceClass;

    use brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceRole;

    use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::OccurrenceTarget;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::TraceCompleteness;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::js_ts_tests_support::Fixture;

    use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::js_ts_tests_support::discovery_declaring_with_stub_artifacts;

    use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::js_ts_tests_support::expect_row;

    use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::js_ts_tests_support::external_boundaries;

    use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::js_ts_tests_support::trace_of;
    #[test]
    fn role_scoped_derivation_retains_only_observable_rows_and_full_completeness() {
        let source = concat!(
            "function render(value: string) {\n",
            "    return value.trim().length;\n",
            "}\n",
        );
        let fixture = Fixture::new(Language::TypeScript, "src/app.ts", source);
        let exhaustive = fixture.identity_only_result();
        let scoped = fixture.identity_only_roles(&[OccurrenceRole::ReceiverPosition]);

        assert!(!scoped.rows.is_empty());
        assert!(
            scoped
                .rows
                .iter()
                .all(|row| row.role == OccurrenceRole::ReceiverPosition),
            "a role-scoped producer must not materialize unobservable rows: {:?}",
            scoped.rows.iter().map(|row| row.role).collect::<Vec<_>>()
        );
        assert!(exhaustive.rows.len() > scoped.rows.len());
        assert_eq!(scoped.completeness, exhaustive.completeness);
    }
    #[test]
    fn js_shorthand_is_a_binder_in_a_pattern_and_a_reference_in_an_expression() {
        let source = concat!(
            "const source = { alpha: 1, beta: 2 };\n",
            "const { alpha, beta: renamed } = source;\n",
            "const payload = { alpha };\n",
        );
        let fixture = Fixture::new(Language::JavaScript, "src/app.js", source);
        let result = fixture.result();

        let pattern_binder = expect_row(&result.rows, fixture.at("alpha, beta"), "pattern binder");
        assert_eq!(pattern_binder.role, OccurrenceRole::Binder);
        assert_eq!(pattern_binder.class, OccurrenceClass::Binding);
        assert_eq!(pattern_binder.namespace, Namespace::Value);
        assert!(matches!(pattern_binder.target, OccurrenceTarget::None));

        let renamed_key = expect_row(&result.rows, fixture.at("beta: renamed"), "renamed key");
        assert_eq!(renamed_key.role, OccurrenceRole::LabelOrKey);
        assert_eq!(renamed_key.namespace, Namespace::Label);
        let renamed_binder = expect_row(&result.rows, fixture.at("renamed }"), "renamed binder");
        assert_eq!(renamed_binder.role, OccurrenceRole::Binder);

        let shorthand_read = expect_row(&result.rows, fixture.at("alpha };"), "shorthand read");
        assert_eq!(shorthand_read.role, OccurrenceRole::ValueReference);
        assert_eq!(shorthand_read.class, OccurrenceClass::Reference);
        assert!(
            !matches!(shorthand_read.target, OccurrenceTarget::None),
            "reference-class rows always carry a resolution outcome"
        );
    }
    /// A declaration name inherits the namespace of the fact it *names*, not of
    /// the fact it sits inside. `field_declaration` is not itself a fact, so a
    /// Rust struct field's name has a `Class` fact for its arena parent while
    /// naming a value; inheriting the parent's kind would report a field in the
    /// type namespace. The same shape occurs for a TypeScript interface member.
    #[test]
    fn a_member_name_under_a_type_declaration_stays_in_the_value_namespace() {
        let rust = Fixture::new(
            Language::Rust,
            "src/app.rs",
            "struct Widget {\n    label: String,\n}\n",
        );
        let rust_result = rust.result();
        assert_eq!(
            expect_row(&rust_result.rows, rust.at("Widget {"), "struct name").namespace,
            Namespace::Type,
            "the struct's own name is the one token that names the type"
        );
        assert_eq!(
            expect_row(&rust_result.rows, rust.at("label: String"), "field name").namespace,
            Namespace::Value
        );

        let typescript = Fixture::new(
            Language::TypeScript,
            "src/app.ts",
            "interface Widget {\n    label: string;\n}\n",
        );
        let typescript_result = typescript.result();
        assert_eq!(
            expect_row(
                &typescript_result.rows,
                typescript.at("Widget {"),
                "interface name"
            )
            .namespace,
            Namespace::Type
        );
        assert_eq!(
            expect_row(
                &typescript_result.rows,
                typescript.at("label: string"),
                "property name"
            )
            .namespace,
            Namespace::Value
        );
    }
    /// #1601 acceptance for JS/TS: the imported binding's boundary routes
    /// through the npm module the build declares, read from the usage index's
    /// import binders rather than from the binding's own spelling.
    #[test]
    fn a_typescript_import_of_a_declared_unindexed_package_reports_declared_unindexed() {
        let source = concat!(
            "import { debounce } from \"lodash\";\n",
            "export const wrapped = debounce;\n",
        );
        let fixture = Fixture::new(Language::TypeScript, "src/app.ts", source);
        fixture.workspace.retain_dependency_discovery_evidence(
            &[Language::JavaScript, Language::TypeScript],
            &discovery_declaring_with_stub_artifacts("typescript", &["lodash"]),
        );
        let result = fixture.traced_result();
        let trace = trace_of(
            &result.rows,
            fixture.at("debounce;"),
            "declared binding use",
        );
        assert!(
            external_boundaries(trace)
                .iter()
                .all(|boundary| *boundary == BoundaryStatus::ExternalDeclaredUnindexed),
            "`debounce` is imported from declared `lodash`: {:?}",
            trace.candidates
        );
    }
    /// Python and JS/TS reach the shared outcome constructors but no tier of
    /// their resolvers reports what it discarded, so their traces say so
    /// instead of letting an absent rejection row read as "nothing lost".
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn a_language_without_tier_tracing_reports_selection_only() {
        let python = Fixture::new(
            Language::Python,
            "src/app.py",
            "def render(label):\n    return label\n",
        );
        let python_result = python.traced_result();
        assert_eq!(
            trace_of(&python_result.rows, python.at("label\n"), "python read").completeness,
            TraceCompleteness::SelectionOnly
        );

        let js = Fixture::new(
            Language::JavaScript,
            "src/app.js",
            "function render(label) {\n    return label;\n}\n",
        );
        let js_result = js.traced_result();
        assert_eq!(
            trace_of(&js_result.rows, js.at("label;"), "javascript read").completeness,
            TraceCompleteness::SelectionOnly
        );
    }
}
