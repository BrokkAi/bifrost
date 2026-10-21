#[cfg(test)]
mod php_extraction_tests {

    use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::TraceCandidateRef;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::TraceCompleteness;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::test_support::BoundaryFixture;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::test_support::activate_fixture_pack;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::test_support::external_routes;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::test_support::route_rows;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::test_support::single_type_pack;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::test_support::activation_evidence;
    const PHP_USE_ALIAS_SOURCE: &str = concat!(
        "<?php\n",
        "\n",
        "namespace App\\Model {\n",
        "    class Widget {}\n",
        "}\n",
        "\n",
        "namespace App\\Util {\n",
        "    use App\\Model\\Widget as Gadget;\n",
        "\n",
        "    function make(): Gadget {\n",
        "        return new Gadget();\n",
        "    }\n",
        "}\n",
    );
    const PHP_BOUNDARY_SOURCE: &str = concat!(
        "<?php\n",
        "namespace App;\n",
        "\n",
        "use Vendor\\Widget\\Helper;\n",
        "\n",
        "class Service {\n",
        "    private Helper $helper;\n",
        "}\n",
    );
    #[test]
    fn a_php_use_of_an_indexed_composer_type_reports_external_indexed() {
        use brokk_bifrost_analysis::analyzer::semantic_model::identity::TypeIdentity;

        use brokk_bifrost_analysis::analyzer::semantic_model::identity::type_declaration_id;

        let fixture = BoundaryFixture::new(Language::Php, "src/Service.php", PHP_BOUNDARY_SOURCE);
        let type_id = type_declaration_id(TypeIdentity {
            ecosystem: "composer",
            name: "Vendor.Widget.Helper",
        });
        activate_fixture_pack(
            &fixture,
            "fixture.php.widget",
            &single_type_pack(
                "fixture.php.widget",
                "php",
                "composer",
                "vendor/widget",
                &type_id,
                "Vendor.Widget.Helper",
                serde_json::json!([]),
            ),
            activation_evidence("php", "composer", "vendor/widget"),
        );
        let (_, trace) = fixture.trace("Helper $helper");
        let routes = external_routes(&trace);
        assert!(
            routes.iter().all(|(boundary, target)| {
                *boundary == BoundaryStatus::ExternalIndexed
                    && target.as_deref() == Some(type_id.as_str())
            }),
            "the activated pack publishes `Helper`: {routes:?}"
        );
    }

    #[test]
    fn a_php_use_alias_reports_the_workspace_candidate_it_selected() {
        let fixture = BoundaryFixture::new(Language::Php, "src/Service.php", PHP_USE_ALIAS_SOURCE);
        let (outcome, trace) = fixture.trace("Gadget();");
        assert!(
            !outcome.definitions.is_empty(),
            "the alias names a workspace declaration: {outcome:?}"
        );
        let selected: Vec<String> = trace
            .selected()
            .map(|candidate| match &candidate.candidate {
                TraceCandidateRef::Unit(unit) => unit.fq_name(),
                other => panic!("expected a unit-backed candidate, got {other:?}"),
            })
            .collect();
        assert_eq!(
            selected,
            ["App.Model.Widget"],
            "the trace names the declaration the alias resolved to: {:?}",
            trace.candidates
        );
        assert_eq!(
            trace.completeness,
            TraceCompleteness::SelectionOnly,
            "PHP declares candidate_selection and not candidate_rejection"
        );
        assert!(
            route_rows(&trace).is_empty(),
            "a name the workspace declares draws no boundary: {:?}",
            trace.candidates
        );
    }

    #[test]
    fn a_php_use_of_a_declared_unread_composer_dependency_reports_declared_unindexed() {
        let fixture = BoundaryFixture::new(Language::Php, "src/Service.php", PHP_BOUNDARY_SOURCE);
        fixture.workspace.retain_dependency_discovery_evidence(
            &[Language::Php],
            &brokk_bifrost_analysis::test_support::incomplete_discovery_declaring(
                "php",
                &["Vendor.Widget"],
                |_| Vec::new(),
            ),
        );
        let (_, trace) = fixture.trace("Helper $helper");
        let routes = external_routes(&trace);
        assert!(
            routes
                .iter()
                .all(|(boundary, _)| *boundary == BoundaryStatus::ExternalDeclaredUnindexed),
            "a truncated Composer discovery keeps the name accountable: {routes:?}"
        );
    }
}
