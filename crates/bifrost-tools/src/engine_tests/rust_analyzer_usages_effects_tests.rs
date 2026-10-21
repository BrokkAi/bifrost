#[cfg(test)]
mod rust_departing_tests_tests {

    use brokk_bifrost_analysis::analyzer::usages::get_definition::CallApplicationKind;

    use brokk_bifrost_analysis::analyzer::usages::call_shape::CallShapeReport;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

    use brokk_bifrost_analysis::analyzer::usages::effects::ModeledCallTargetCoverage;

    use brokk_bifrost_analysis::analyzer::usages::effects::ModeledProcedureKey;

    use brokk_bifrost_analysis::analyzer::usages::effects::project_modeled_call_target_lookup;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchBoundaryKind;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchLookup;

    use brokk_bifrost_analysis::analyzer::usages::call_shape::call_shape_for_call;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::ExactExternalCallProof;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;

    fn rust_shape(fixture: &AnalyzerFixture, source: &str, call: &str) -> CallShapeReport {
        let file = ProjectFile::new(fixture.project_root(), "main.rs");
        let facts = fixture
            .analyzer
            .analyzer()
            .structural_fact_providers()
            .into_iter()
            .find_map(|provider| provider.structural_facts(&file))
            .expect("Rust structural facts");
        let call_id = brokk_bifrost_analysis::analyzer::usages::test_support::call_node_id(
            source, &facts, call,
        );
        call_shape_for_call(&facts, &file, call_id).expect("exact Rust call shape")
    }

    #[test]
    fn exact_rust_static_and_bound_calls_keep_distinct_modeled_keys() {
        let source = r#"use std::process::Command;
fn caller(command: Command) {
    Command::new("true");
    command.new("true");
}
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("main.rs", source)]);
        let static_shape = rust_shape(&fixture, source, "Command::new(\"true\")");
        let receiver_shape = rust_shape(&fixture, source, "command.new(\"true\")");
        let identity = || {
            crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity::new(
                Language::Rust,
                "std.process.Command",
                "new",
            )
        };
        let static_dispatch = CallDispatchLookup {
            status: Some(DefinitionLookupStatus::UnresolvableImportBoundary),
            call_application: CallApplicationKind::PackageFunction,
            exact_external_call: Some(ExactExternalCallProof::rust_external_call(
                "std::process::Command::new",
                1,
            )),
            boundaries: vec![CallDispatchBoundaryKind::External {
                callee_text: Some("std::process::Command::new".into()),
                normalized_static_owner: None,
                external_callee_identity: Some(identity()),
            }],
            ..CallDispatchLookup::default()
        };
        let static_target = project_modeled_call_target_lookup(
            fixture.analyzer.analyzer(),
            &static_shape,
            true,
            static_dispatch,
        );
        assert_eq!(
            static_target.coverage,
            ModeledCallTargetCoverage::Exhaustive
        );
        assert_eq!(static_target.arms.len(), 1, "{static_target:#?}");
        assert_eq!(
            &static_target.arms[0].key,
            &ModeledProcedureKey {
                language: "rust".to_owned(),
                owner: "std.process.Command".to_owned(),
                member: "new".to_owned(),
                has_receiver: false,
                parameter_count: 1,
            }
        );

        let receiver_dispatch = CallDispatchLookup {
            status: Some(DefinitionLookupStatus::UnresolvableImportBoundary),
            call_application: CallApplicationKind::BoundReceiver,
            dispatch_extensibility: Some(
                brokk_bifrost_core::analyzer::model::DispatchExtensibility::Closed,
            ),
            exact_external_call: Some(ExactExternalCallProof::rust_bound_external_member(
                "std.process.Command",
                "new",
                1,
            )),
            boundaries: vec![CallDispatchBoundaryKind::External {
                callee_text: Some("std::process::Command::new".into()),
                normalized_static_owner: None,
                external_callee_identity: Some(identity()),
            }],
            ..CallDispatchLookup::default()
        };
        let receiver_target = project_modeled_call_target_lookup(
            fixture.analyzer.analyzer(),
            &receiver_shape,
            true,
            receiver_dispatch.clone(),
        );
        assert_eq!(
            receiver_target.coverage,
            ModeledCallTargetCoverage::Exhaustive
        );
        assert_eq!(receiver_target.arms.len(), 1, "{receiver_target:#?}");
        assert_eq!(
            &receiver_target.arms[0].key,
            &ModeledProcedureKey {
                language: "rust".to_owned(),
                owner: "std.process.Command".to_owned(),
                member: "new".to_owned(),
                has_receiver: true,
                parameter_count: 1,
            }
        );
        assert_ne!(
            static_target.arms[0].key, receiver_target.arms[0].key,
            "an associated function and a value receiver stay distinct"
        );

        let unresolved = project_modeled_call_target_lookup(
            fixture.analyzer.analyzer(),
            &receiver_shape,
            true,
            CallDispatchLookup {
                call_application: CallApplicationKind::ReceiverBindingUnknown,
                exact_external_call: None,
                ..receiver_dispatch
            },
        );
        assert!(unresolved.arms.is_empty(), "{unresolved:#?}");
        assert_eq!(unresolved.coverage, ModeledCallTargetCoverage::Open);
    }
}
