#[cfg(test)]
mod ruby_extraction_tests {

    use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

    use brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceRole;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::test_support::activation_evidence;
    use brokk_bifrost_test_macros::hardwon;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::test_support::BoundaryFixture;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::test_support::activate_fixture_pack;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::test_support::assert_boundary_route_joins_occurrence;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::test_support::assert_declared_unindexed_routes;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::test_support::assert_no_boundary_was_drawn;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::test_support::external_routes;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::test_support::route_names;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::test_support::single_type_pack;
    /// #3466: `ENV.fetch` is a method call on a constant no workspace file
    /// declares, and no activated pack or retained discovery claims it. The
    /// call's written `<receiver>.<member>` identity is one boundary row, the
    /// same identity `call_bindings` reports for the call site.
    #[test]
    #[hardwon(
        "#3466: A Ruby external constant receiver call publishes one candidate route for the matching occurrence"
    )]
    fn a_ruby_external_constant_receiver_call_publishes_its_route_row() {
        let fixture = BoundaryFixture::new(Language::Ruby, "app.rb", "ENV.fetch(\"PATH\")\n");
        let (outcome, trace) = fixture.trace("fetch");
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::UnresolvableImportBoundary,
            "a method on a module declared outside the workspace is a boundary: {:?}",
            outcome.diagnostics
        );
        assert_eq!(
            outcome.resolved_reference_target(),
            Some("ENV.fetch"),
            "the boundary names the written member identity: {:?}",
            outcome.diagnostics
        );
        assert_eq!(
            route_names(&trace),
            vec!["ENV.fetch".to_string()],
            "the trace publishes one route row under the same identity: {:#?}",
            trace.candidates
        );
        assert_eq!(
            external_routes(&trace),
            vec![(BoundaryStatus::ExternalUnknown, None)],
            "nothing has discovered a gem for `ENV`, so the row names the boundary without sharpening it"
        );
        assert_boundary_route_joins_occurrence(&fixture, "fetch", OccurrenceRole::MemberPosition);
    }

    /// The workspace guard beside it: a constant receiver the workspace does
    /// declare is an ordinary in-workspace miss, not a boundary.
    #[test]
    #[hardwon(
        "#3466: A Ruby constant receiver declared in the workspace does not turn its missing member into an external boundary"
    )]
    fn a_ruby_constant_receiver_declared_in_the_workspace_stays_a_plain_miss() {
        let fixture = BoundaryFixture::new(
            Language::Ruby,
            "app.rb",
            concat!("module Widget\n", "end\n", "\n", "Widget.fetch(\"PATH\")\n"),
        );
        assert_no_boundary_was_drawn("fetch", &fixture);
    }

    #[hardwon("#1889: qualified Ruby gem constants failed to report indexed external boundaries")]
    #[test]
    fn a_ruby_reference_to_an_indexed_gem_constant_reports_external_indexed() {
        use brokk_bifrost_analysis::analyzer::semantic_model::identity::TypeIdentity;

        use brokk_bifrost_analysis::analyzer::semantic_model::identity::type_declaration_id;

        let fixture = BoundaryFixture::new(Language::Ruby, "app.rb", "Widget::Config\n");
        let type_id = type_declaration_id(TypeIdentity {
            ecosystem: "rubygems",
            name: "Widget::Config",
        });
        activate_fixture_pack(
            &fixture,
            "fixture.ruby.widget",
            &single_type_pack(
                "fixture.ruby.widget",
                "ruby",
                "rubygems",
                "widget",
                &type_id,
                "Widget::Config",
                serde_json::json!([]),
            ),
            activation_evidence("ruby", "rubygems", "widget"),
        );
        let (_, trace) = fixture.trace("Config");
        let routes = external_routes(&trace);
        assert!(
            routes.iter().all(|(boundary, target)| {
                *boundary == BoundaryStatus::ExternalIndexed
                    && target.as_deref() == Some(type_id.as_str())
            }),
            "the activated pack publishes `Widget::Config`: {routes:?}"
        );
    }

    #[hardwon("#1889: qualified Ruby gem constants failed to report declared unread boundaries")]
    #[test]
    fn a_ruby_reference_into_a_declared_unread_gem_reports_declared_unindexed() {
        let fixture = BoundaryFixture::new(Language::Ruby, "app.rb", "Widget::Config\n");
        let (_, trace) = fixture.trace("Config");
        assert!(
            external_routes(&trace)
                .iter()
                .all(|(boundary, _)| *boundary == BoundaryStatus::ExternalUnknown),
            "with no overlay and no retained discovery, nothing is known: {:?}",
            trace.candidates
        );
        fixture.workspace.retain_dependency_discovery_evidence(
            &[Language::Ruby],
            &brokk_bifrost_analysis::test_support::incomplete_discovery_declaring(
                "ruby",
                &["widget"],
                |_| Vec::new(),
            ),
        );
        let (_, trace) = fixture.trace("Config");
        let routes = external_routes(&trace);
        assert_declared_unindexed_routes(&routes);
    }

    #[hardwon("#1889: Ruby workspace namespaces were at risk of false external classification")]
    #[test]
    fn a_ruby_path_under_a_workspace_namespace_stays_a_plain_miss() {
        // `Widget` is a workspace module, so the miss is inside the workspace
        // however the path continues.
        let fixture = BoundaryFixture::new(
            Language::Ruby,
            "app.rb",
            concat!("module Widget\n", "end\n", "\n", "Widget::Missing\n"),
        );
        assert_no_boundary_was_drawn("Missing", &fixture);
    }

    #[hardwon("#1889: bare Ruby constants were at risk of false external classification")]
    #[test]
    fn a_bare_ruby_constant_never_draws_a_boundary() {
        // Ruby's top-level surface includes the core library and everything a
        // loaded gem defines as a side effect, none of which Bifrost publishes,
        // so a bare miss says nothing about where the name lives (#1624).
        let fixture = BoundaryFixture::new(Language::Ruby, "app.rb", "Missing\n");
        assert_no_boundary_was_drawn("Missing", &fixture);
    }
}
