#[cfg(test)]
mod jvm_registry_tests {

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_core::analyzer::model::CodeUnit;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

    use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::js_ts_tests_support::Fixture;

    use brokk_bifrost_core::analyzer::structural::occurrences::Namespace;

    use brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceClass;

    use brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceRole;

    use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::OccurrenceTarget;

    use brokk_bifrost_core::analyzer::structural::resolution::PrecedenceTier;

    use brokk_bifrost_core::analyzer::structural::resolution::RejectionReason;

    use brokk_bifrost_analysis::analyzer::resolution::trace_vocabulary::TraceCandidateRef;

    use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::js_ts_tests_support::expect_row;

    use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::occurrences_for_file_at_lines;

    use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::js_ts_tests_support::trace_of;

    use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;

    use brokk_bifrost_core::analyzer::structural::resolution::EnvironmentAxis;

    use brokk_bifrost_core::analyzer::model::Language;
    use std::collections::BTreeSet;
    #[test]
    fn selected_reference_rows_keep_status_separate_from_undemanded_rows() {
        let source = concat!(
            "class Caller {\n",
            "    void first(Caller other) {\n",
            "        other.run();\n",
            "    }\n",
            "    void second(Caller other) {\n",
            "        other.run();\n",
            "    }\n",
            "    void run() {}\n",
            "}\n",
        );
        let fixture = Fixture::new(Language::Java, "src/Caller.java", source);
        let all = fixture.result();
        let demanded_line = all
            .rows
            .iter()
            .find(|row| {
                row.class == OccurrenceClass::Reference
                    && row.resolution_status == Some(DefinitionLookupStatus::Resolved)
            })
            .map(|row| row.range.start_line)
            .expect("fixture must contain a resolved reference row");
        let lines = BTreeSet::from([demanded_line]);
        let selected = occurrences_for_file_at_lines(
            fixture.workspace.analyzer(),
            &fixture.file,
            &lines,
            &CancellationToken::new(),
        )
        .expect("uncancelled selected occurrence derivation");

        let selected_references: Vec<_> = selected
            .rows
            .iter()
            .filter(|row| {
                row.class == OccurrenceClass::Reference && row.range.start_line == demanded_line
            })
            .collect();
        assert!(!selected_references.is_empty());
        assert!(
            selected_references
                .iter()
                .all(|row| row.resolution_status == Some(DefinitionLookupStatus::Resolved))
        );

        let undemanded_references: Vec<_> = selected
            .rows
            .iter()
            .filter(|row| {
                row.class == OccurrenceClass::Reference && row.range.start_line != demanded_line
            })
            .collect();
        assert!(
            !undemanded_references.is_empty(),
            "fixture must retain reference rows outside the demanded line"
        );
        assert!(undemanded_references.iter().all(|row| {
            row.resolution_status.is_none() && matches!(&row.target, OccurrenceTarget::NotDerived)
        }));
    }
    #[test]
    fn java_declaration_heads_carry_type_namespaces_and_reads_resolve() {
        let source = concat!(
            "package app;\n",
            "class Widget {\n",
            "    static int SIZE = 2;\n",
            "    int render(String label) {\n",
            "        return label.length() + SIZE;\n",
            "    }\n",
            "}\n",
        );
        let fixture = Fixture::new(Language::Java, "app/Widget.java", source);
        let result = fixture.result();

        let class_name = expect_row(&result.rows, fixture.at("Widget {"), "class name");
        assert_eq!(class_name.role, OccurrenceRole::DeclarationName);
        assert_eq!(class_name.class, OccurrenceClass::Declaration);
        assert_eq!(class_name.namespace, Namespace::Type);
        assert_eq!(class_name.raw_spelling, "Widget");
        assert!(matches!(class_name.target, OccurrenceTarget::None));

        let method_name = expect_row(&result.rows, fixture.at("render(String"), "method name");
        assert_eq!(method_name.role, OccurrenceRole::DeclarationName);
        assert_eq!(method_name.namespace, Namespace::Value);

        let parameter = expect_row(&result.rows, fixture.at("label)"), "parameter binder");
        assert_eq!(parameter.role, OccurrenceRole::Binder);
        assert_eq!(parameter.class, OccurrenceClass::Binding);
        assert!(matches!(parameter.target, OccurrenceTarget::None));

        let read = expect_row(&result.rows, fixture.at("label.length"), "receiver read");
        assert_eq!(read.role, OccurrenceRole::ReceiverPosition);
        assert_eq!(read.class, OccurrenceClass::Reference);
        assert!(
            matches!(
                read.target,
                OccurrenceTarget::Resolved(_) | OccurrenceTarget::Lexical(_)
            ),
            "receiver read should resolve to the parameter, got {:?}",
            read.target
        );
        assert_eq!(
            read.enclosing.as_ref().map(CodeUnit::fq_name),
            fixture
                .workspace
                .analyzer()
                .enclosing_code_unit(&fixture.file, &read.range)
                .as_ref()
                .map(CodeUnit::fq_name)
        );
    }
    /// Issue #1569, shape 1: a bare read of a local variable resolves to its
    /// binder as a lexical definition, not `Unresolved(NoDefinition)`. The
    /// shadowing spelling proves the same claim when the name collides with an
    /// indexed type.
    #[test]
    fn java_bare_local_reads_resolve_to_the_local_binder_lexically() {
        let source = concat!(
            "class Widget {\n",
            "    int plain() {\n",
            "        int local = 1;\n",
            "        return local;\n",
            "    }\n",
            "    int shadowing() {\n",
            "        int Config = 1;\n",
            "        return Config;\n",
            "    }\n",
            "}\n",
        );
        let fixture = Fixture::with_supporting_files(
            Language::Java,
            "app/Widget.java",
            source,
            &[(
                "app/Config.java",
                "class Config {\n    static int LIMIT = 7;\n}\n",
            )],
        );
        let result = fixture.result();

        let plain_read = expect_row(&result.rows, fixture.at("local;"), "plain local read");
        assert_eq!(plain_read.class, OccurrenceClass::Reference);
        match &plain_read.target {
            OccurrenceTarget::Lexical(definition) => {
                assert_eq!(definition.identifier, "local");
                assert_eq!(definition.name_range.start_byte, fixture.at("local = 1"));
            }
            other => panic!("bare local read should resolve lexically, got {other:?}"),
        }

        let shadowing_read = expect_row(&result.rows, fixture.at("Config;"), "shadowing read");
        match &shadowing_read.target {
            OccurrenceTarget::Lexical(definition) => {
                assert_eq!(definition.identifier, "Config");
                assert_eq!(definition.name_range.start_byte, fixture.at("Config = 1"));
            }
            other => panic!("shadowed local read should resolve lexically, got {other:?}"),
        }
    }
    /// Issue #1569, shape 2: the member position of a static field access
    /// resolves to the indexed field even when a sibling scope binds a local
    /// with the qualifier's spelling.
    #[test]
    fn java_static_field_member_position_resolves_to_the_indexed_field() {
        let source = concat!(
            "class Caller {\n",
            "    int shadow() {\n",
            "        int Config = 1;\n",
            "        return Config;\n",
            "    }\n",
            "    int use() {\n",
            "        return Config.LIMIT;\n",
            "    }\n",
            "}\n",
        );
        let fixture = Fixture::with_supporting_files(
            Language::Java,
            "app/Caller.java",
            source,
            &[(
                "app/Config.java",
                "class Config {\n    static int LIMIT = 7;\n}\n",
            )],
        );
        let result = fixture.result();

        let member = expect_row(&result.rows, fixture.at("LIMIT;"), "static field member");
        assert_eq!(member.class, OccurrenceClass::Reference);
        match &member.target {
            OccurrenceTarget::Resolved(units) => assert!(
                units
                    .iter()
                    .all(|unit| unit.fq_name().contains("Config.LIMIT") && unit.is_field()),
                "the member must resolve to the static field: {units:?}"
            ),
            other => panic!("static field member should resolve to the field, got {other:?}"),
        }
    }
    /// The regression shape from the issue: a qualified static read must
    /// resolve to the static field, not to the local that shadows its name.
    #[test]
    fn java_static_qualifier_resolves_to_the_static_target_not_the_local() {
        let source = concat!(
            "class Caller {\n",
            // A local that shares the type's spelling, in a sibling scope: the
            // qualifier below must not be captured by it.
            "    int shadow() {\n",
            "        int Config = 1;\n",
            "        return Config;\n",
            "    }\n",
            "    int use() {\n",
            "        return Config.LIMIT;\n",
            "    }\n",
            "}\n",
        );
        let fixture = Fixture::with_supporting_files(
            Language::Java,
            "app/Caller.java",
            source,
            &[(
                "app/Config.java",
                "class Config {\n    static int LIMIT = 7;\n}\n",
            )],
        );
        let result = fixture.result();

        let qualifier = expect_row(&result.rows, fixture.at("Config.LIMIT"), "static qualifier");
        assert_eq!(qualifier.role, OccurrenceRole::ReceiverPosition);
        match &qualifier.target {
            OccurrenceTarget::Resolved(units) => assert!(
                units
                    .iter()
                    .all(|unit| unit.fq_name().contains("Config") && unit.is_class()),
                "the qualifier must resolve to the type, not the sibling local: {units:?}"
            ),
            other => panic!("static qualifier should resolve to the type, got {other:?}"),
        }

        let shadowing_local =
            expect_row(&result.rows, fixture.at("Config;"), "shadowing local read");
        assert!(
            !matches!(shadowing_local.target, OccurrenceTarget::Resolved(_)),
            "a local read must not borrow the type's resolution: {:?}",
            shadowing_local.target
        );
    }
    /// Java resolves a simple type name against single-type imports before
    /// on-demand ones, so an explicit import selects at its tier and the
    /// wildcard routes it beat are recorded as rejected peers.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "0242909d77ed: Java census G04 native traces omitted winning import tiers and defeated wildcard routes"
    )]
    fn an_explicit_java_import_selects_over_the_wildcard_routes_it_beat() {
        let source = concat!(
            "package app;\n",
            "import app.model.Widget;\n",
            "import app.other.*;\n",
            "class Caller {\n",
            "    Widget build() { return null; }\n",
            "}\n",
        );
        let fixture = Fixture::with_supporting_files(
            Language::Java,
            "app/Caller.java",
            source,
            &[
                (
                    "app/model/Widget.java",
                    "package app.model;\npublic class Widget {}\n",
                ),
                (
                    "app/other/Widget.java",
                    "package app.other;\npublic class Widget {}\n",
                ),
            ],
        );
        let result = fixture.traced_result();
        let trace = trace_of(&result.rows, fixture.at("Widget build"), "return type");

        assert!(
            trace.selects_at(PrecedenceTier::ExplicitImport),
            "the single-type import is the winning tier: {:?}",
            trace.candidates
        );
        let wildcard: Vec<_> = trace
            .rejected()
            .filter(|row| row.tier == Some(PrecedenceTier::WildcardImport))
            .collect();
        assert_eq!(
            wildcard.len(),
            1,
            "the one on-demand import is the rejected peer: {:?}",
            trace.candidates
        );
        assert_eq!(
            wildcard[0].outcome.rejection(),
            Some(RejectionReason::ShadowedByNearer)
        );
        match &wildcard[0].candidate {
            // An on-demand import binds no single name, so the route keeps the
            // wildcard marker as its name -- and states the package it pointed
            // at through the parser-derived target segments (#1600).
            TraceCandidateRef::ImportBinder {
                name,
                target_segments,
                ..
            } => {
                assert_eq!(
                    name,
                    brokk_bifrost_analysis::analyzer::resolution::trace_vocabulary::WILDCARD_ROUTE_NAME
                );
                assert_eq!(
                    target_segments,
                    &["app".to_string(), "other".to_string()],
                    "the rejected route names the package its wildcard covered"
                );
            }
            other => panic!("a rejected import route is an import binder, got {other:?}"),
        }
    }
    /// A reference that leaves the workspace reports how far the lookup could
    /// see, and never reports a selection at the fallback tier the anti-fallback
    /// contract forbids.
    #[test]
    fn a_boundary_reference_reports_its_boundary_and_never_a_name_only_fallback() {
        let source = concat!(
            "package app;\n",
            "import com.absent.Gadget;\n",
            "class Caller {\n",
            "    Gadget build() { return null; }\n",
            "}\n",
        );
        let fixture = Fixture::new(Language::Java, "app/Caller.java", source);
        let result = fixture.traced_result();
        let trace = trace_of(&result.rows, fixture.at("Gadget build"), "external type");

        let external: Vec<_> = trace
            .candidates
            .iter()
            .filter(|row| matches!(row.candidate, TraceCandidateRef::ExternalRoute { .. }))
            .collect();
        assert!(
            !external.is_empty(),
            "a boundary outcome always reports the route it took: {:?}",
            trace.candidates
        );
        assert!(
            external
                .iter()
                .all(|row| row.boundary != BoundaryStatus::WorkspaceLocal),
            "a boundary row is by definition not workspace-local: {external:?}"
        );
        assert!(
            !trace.selects_at(PrecedenceTier::NameOnlyFallback),
            "nothing may be selected at the forbidden fallback tier: {:?}",
            trace.candidates
        );
    }
    /// An adapter that has not learned the candidate axes must surface that
    /// through the capability spine. An empty trace from an uninstrumented
    /// language would read exactly like "the resolver considered nothing".
    ///
    /// Scala classifies occurrence roles since #1597, so the rows themselves
    /// are real; what it still does not do is record a considered set, and
    /// that is what the axes and the trace completeness must keep saying.
    #[test]
    fn an_uninstrumented_language_reports_the_candidate_axes_unsupported() {
        let fixture = Fixture::new(
            Language::Scala,
            "src/app.scala",
            "class Widget { def render(label: String): String = label }\n",
        );
        let support = brokk_bifrost_analysis::analyzer::structural_spec_for(Language::Scala)
            .expect("Scala has a structural adapter")
            .lexical_environment_support();
        assert!(
            !support.is_supported(EnvironmentAxis::CandidateSelection),
            "Scala must not claim a selection axis it does not answer"
        );
        assert!(!support.is_supported(EnvironmentAxis::CandidateRejection));

        let result = fixture.traced_result();
        assert!(
            !result.rows.is_empty(),
            "Scala classifies occurrence roles, so the rows are real"
        );
        assert!(
            result
                .rows
                .iter()
                .filter_map(|row| row.candidates.as_ref())
                .all(|trace| !trace.completeness.covers_rejections()),
            "a language that claims neither candidate axis must never publish a considered set: {:?}",
            result.rows
        );
    }
}
