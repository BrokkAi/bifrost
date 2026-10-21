#[cfg(test)]
mod csharp_extraction_tests {

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::test_support::BoundaryFixture;

    use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::test_support::assert_boundary_route_joins_occurrence;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::test_support::external_routes;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::test_support::route_names;

    use brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceRole;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_test_macros::hardwon;
    /// #3466: a static member call whose receiver is a bare external type
    /// qualifier. No value channel of the workspace declares `Environment` and
    /// no indexed assembly owns it, so the receiver identifier is the type the
    /// member is qualified with, and the call crossed a boundary. Before the fix
    /// the same call answered `unsupported_csharp_receiver` with no route row
    /// while `call_bindings` resolved the identical written reference.
    #[test]
    #[hardwon(
        "#3466: A C# static call over a declared but unindexed type publishes the route joined by its occurrence row"
    )]
    fn a_csharp_static_member_call_on_an_unindexed_type_publishes_its_route_row() {
        let source = concat!(
            "namespace App;\n",
            "class Caller {\n",
            "    string Go() { return Environment.GetEnvironmentVariable(\"PATH\"); }\n",
            "}\n",
        );
        let fixture = BoundaryFixture::new(Language::CSharp, "src/App.cs", source);
        let (outcome, trace) = fixture.trace("GetEnvironmentVariable");
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::UnresolvableImportBoundary,
            "a member on a type the workspace does not index is a boundary: {:?}",
            outcome.diagnostics
        );
        assert_eq!(
            outcome.resolved_reference_target(),
            Some("Environment.GetEnvironmentVariable"),
            "the boundary names the written member identity: {:?}",
            outcome.diagnostics
        );
        assert_eq!(
            route_names(&trace),
            vec!["Environment.GetEnvironmentVariable".to_string()],
            "the trace publishes one route row under the same identity: {:#?}",
            trace.candidates
        );
        assert_eq!(
            external_routes(&trace),
            vec![(BoundaryStatus::ExternalUnknown, None)],
            "no assembly index is configured, so the row names the boundary without sharpening it"
        );
        assert_boundary_route_joins_occurrence(
            &fixture,
            "GetEnvironmentVariable",
            OccurrenceRole::MemberPosition,
        );
    }
    #[test]
    fn a_csharp_reference_into_a_declared_unindexed_package_reports_declared_unindexed() {
        let source = concat!(
            "using Newtonsoft.Json;\n",
            "namespace App;\n",
            "class Caller {\n",
            "    Newtonsoft.Json.JsonConvert Ping() { return default; }\n",
            "}\n",
        );
        let fixture = BoundaryFixture::new(Language::CSharp, "src/App.cs", source);
        fixture.workspace.retain_dependency_discovery_evidence(
            &[Language::CSharp],
            &brokk_bifrost_analysis::test_support::discovery_declaring(
                "csharp",
                &["Newtonsoft.Json"],
                |_| Vec::new(),
            ),
        );
        let (_, trace) = fixture.trace("JsonConvert Ping");
        let routes = external_routes(&trace);
        assert!(
            routes
                .iter()
                .all(|(boundary, _)| *boundary == BoundaryStatus::ExternalDeclaredUnindexed),
            "the build declares `Newtonsoft.Json`, so the miss is declared-unindexed: {routes:?}"
        );
    }
}
