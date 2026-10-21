#[cfg(test)]
mod python_residency_tests {

    use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;

    use brokk_bifrost_core::analyzer::structural::occurrences::Namespace;

    use brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceClass;

    use brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceRole;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::js_ts_tests_support::Fixture;

    use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::js_ts_tests_support::discovery_declaring_with_stub_artifacts;

    use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::js_ts_tests_support::expect_row;

    use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::js_ts_tests_support::external_boundaries;

    use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::js_ts_tests_support::trace_of;
    #[test]
    fn python_annotations_are_type_operands_and_parameters_are_binders() {
        let source = concat!(
            "import os.path\n",
            "\n",
            "class Widget:\n",
            "    def render(self, label: str) -> str:\n",
            "        return os.path.join(label, key=label)\n",
        );
        let fixture = Fixture::new(Language::Python, "src/app.py", source);
        let result = fixture.result();

        let class_name = expect_row(&result.rows, fixture.at("Widget:"), "class name");
        assert_eq!(class_name.namespace, Namespace::Type);

        let binder = expect_row(&result.rows, fixture.at("label: str"), "parameter binder");
        assert_eq!(binder.role, OccurrenceRole::Binder);
        assert_eq!(binder.namespace, Namespace::Value);

        let annotation = expect_row(&result.rows, fixture.at("str)"), "annotation operand");
        assert_eq!(annotation.role, OccurrenceRole::TypeOperand);
        assert_eq!(annotation.namespace, Namespace::Type);

        let segment = expect_row(&result.rows, fixture.at("os.path\n"), "import path segment");
        assert_eq!(segment.role, OccurrenceRole::PathSegment);
        assert_eq!(
            segment.namespace,
            Namespace::Module,
            "Python dotted-name segments are modules"
        );

        let keyword = expect_row(&result.rows, fixture.at("key="), "keyword argument name");
        assert_eq!(keyword.role, OccurrenceRole::LabelOrKey);
        assert_eq!(keyword.namespace, Namespace::Label);
    }
    #[test]
    fn python_formal_parameters_and_scope_directives_have_distinct_structural_roles() {
        let source = concat!(
            "def outer(enclosing):\n",
            "    shared = 0\n",
            "    def inner(\n",
            "        bare,\n",
            "        typed: int,\n",
            "        default=1,\n",
            "        typed_default: int = 2,\n",
            "        *args,\n",
            "        **kwargs,\n",
            "    ):\n",
            "        global shared\n",
            "        nonlocal enclosing\n",
            "        return bare\n",
        );
        let fixture = Fixture::new(Language::Python, "src/app.py", source);
        let rows = fixture.result().rows;
        for needle in [
            "bare,",
            "typed: int",
            "default=1",
            "typed_default: int",
            "args,",
            "kwargs,",
        ] {
            let row = expect_row(&rows, fixture.at(needle), "formal parameter");
            assert_eq!(row.role, OccurrenceRole::Binder, "{needle}");
            assert_eq!(row.class, OccurrenceClass::Binding, "{needle}");
        }

        let global_name = fixture.at("global shared") + "global ".len();
        let global = expect_row(&rows, global_name, "global directive name");
        assert_eq!(global.role, OccurrenceRole::GlobalDirective);
        assert_eq!(global.class, OccurrenceClass::NonReference);

        let nonlocal_name = fixture.at("nonlocal enclosing") + "nonlocal ".len();
        let nonlocal = expect_row(&rows, nonlocal_name, "nonlocal directive name");
        assert_eq!(nonlocal.role, OccurrenceRole::NonlocalDirective);
        assert_eq!(nonlocal.class, OccurrenceClass::NonReference);
    }
    /// #1601 acceptance: a Python file importing a distribution the workspace
    /// declares but does not contain reports `external_declared_unindexed`,
    /// and the dotted attribute read routes through the same declared module.
    #[test]
    fn a_python_import_of_a_declared_unindexed_distribution_reports_declared_unindexed() {
        let source = concat!(
            "import requests\n",
            "\n",
            "def fetch():\n",
            "    return requests.get\n",
        );
        let fixture = Fixture::new(Language::Python, "app/client.py", source);
        fixture.workspace.retain_dependency_discovery_evidence(
            &[Language::Python],
            &discovery_declaring_with_stub_artifacts("python", &["requests"]),
        );
        let result = fixture.traced_result();
        let trace = trace_of(&result.rows, fixture.at("requests.get"), "declared read");
        assert!(
            external_boundaries(trace)
                .iter()
                .all(|boundary| *boundary == BoundaryStatus::ExternalDeclaredUnindexed),
            "the build declares `requests`, so the miss is declared-unindexed: {:?}",
            trace.candidates
        );
    }
    /// #1601 acceptance: a name nothing declares stays `external_unknown`
    /// even when discovery ran to completion, and a workspace where discovery
    /// never ran reports `external_unknown` for everything.
    #[test]
    fn an_undeclared_python_import_stays_external_unknown() {
        let source = concat!(
            "import nonsuch\n",
            "\n",
            "def fetch():\n",
            "    return nonsuch.get\n",
        );
        let undiscovered = Fixture::new(Language::Python, "app/client.py", source);
        let trace_rows = undiscovered.traced_result();
        let trace = trace_of(
            &trace_rows.rows,
            undiscovered.at("nonsuch.get"),
            "no discovery",
        );
        assert!(
            external_boundaries(trace)
                .iter()
                .all(|boundary| *boundary == BoundaryStatus::ExternalUnknown),
            "no discovery has run, so nothing is known: {:?}",
            trace.candidates
        );

        let declared_elsewhere = Fixture::new(Language::Python, "app/client.py", source);
        declared_elsewhere
            .workspace
            .retain_dependency_discovery_evidence(
                &[Language::Python],
                &discovery_declaring_with_stub_artifacts("python", &["requests"]),
            );
        let result = declared_elsewhere.traced_result();
        let trace = trace_of(
            &result.rows,
            declared_elsewhere.at("nonsuch.get"),
            "undeclared read",
        );
        assert!(
            external_boundaries(trace)
                .iter()
                .all(|boundary| *boundary == BoundaryStatus::ExternalUnknown),
            "a complete discovery declares nothing named `nonsuch`: {:?}",
            trace.candidates
        );
    }
}
