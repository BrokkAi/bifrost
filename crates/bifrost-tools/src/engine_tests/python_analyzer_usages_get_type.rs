#[cfg(test)]
mod python_extraction_tests {

    use brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;

    use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupOutcome;

    use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupStatus;

    use brokk_bifrost_analysis::analyzer::usages::get_type::parse_tree_for_type_lookup;

    use brokk_bifrost_analysis::analyzer::usages::get_type::resolve_type_at_reference_site_with_budget;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    fn direct_site(
        fixture: &AnalyzerFixture,
        language: Language,
        path: &str,
        source: &str,
        expression: &str,
        focus: &str,
    ) -> TypeLookupOutcome {
        let file = ProjectFile::new(fixture.project_root(), path);
        let tree = parse_tree_for_type_lookup(&file, language, source).expect("fixture parses");
        let start = source.rfind(expression).expect("expression source");
        let focus_start = start + expression.find(focus).expect("focus in expression");
        resolve_type_at_reference_site_with_budget(
            fixture.analyzer.analyzer(),
            &file,
            source,
            Some(&tree),
            ResolvedReferenceSite {
                path: path.to_string(),
                text: expression.to_string(),
                range: brokk_bifrost_core::analyzer::model::Range {
                    start_byte: start,
                    end_byte: start + expression.len(),
                    start_line: 0,
                    end_line: 0,
                },
                focus_start_byte: focus_start,
                focus_end_byte: focus_start + focus.len(),
            },
            INTERACTIVE_TYPE_LOOKUP_BUDGET,
        )
    }
    #[test]
    fn namespace_constructor_rebinding_and_invalid_direct_sites_fail_closed() {
        let models = "class Widget:\n    pass\n";
        let consumer = concat!(
            "import models\n",
            "models = object()\n",
            "def make():\n",
            "    return models.Widget()\n",
        );
        let fixture = AnalyzerFixture::new_for_language(
            Language::Python,
            &[("models.py", models), ("consumer.py", consumer)],
        );
        let outcome = direct_site(
            &fixture,
            Language::Python,
            "consumer.py",
            consumer,
            "models.Widget",
            "Widget",
        );
        assert_ne!(outcome.status, TypeLookupStatus::Resolved, "{outcome:#?}");

        let file = ProjectFile::new(fixture.project_root(), "consumer.py");
        let start = consumer.rfind("models.Widget").unwrap();
        let invalid = resolve_type_at_reference_site_with_budget(
            fixture.analyzer.analyzer(),
            &file,
            consumer,
            None,
            ResolvedReferenceSite {
                path: "wrong.py".to_string(),
                text: "models.Widget".to_string(),
                range: brokk_bifrost_core::analyzer::model::Range {
                    start_byte: start,
                    end_byte: start + "models.Widget".len(),
                    start_line: 0,
                    end_line: 0,
                },
                focus_start_byte: start,
                focus_end_byte: start + "models".len(),
            },
            INTERACTIVE_TYPE_LOOKUP_BUDGET,
        );
        assert_eq!(
            invalid.status,
            TypeLookupStatus::InvalidLocation,
            "{invalid:#?}"
        );
    }
}
