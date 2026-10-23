#[cfg(test)]
mod jvm_registry_tests {

    use brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict;

    use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::ArgumentFormalBinding;

    use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::ConversionKind;

    use brokk_bifrost_core::hash::HashMap;

    use brokk_bifrost_core::analyzer::Language;

    use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredCallApplicabilityObligation;

    use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredCallableSignatureProperty;

    use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::MappingAssessment;

    use brokk_bifrost_analysis::analyzer::resolution::model::SemanticId;

    use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::adapter;

    use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::registry_fixture_support::assessment;

    use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::select_candidate_indices;

    #[test]
    fn kotlin_prefers_the_candidate_that_uses_fewer_defaults_after_equal_conversions() {
        let mut fewer_defaults =
            assessment(1, ApplicabilityVerdict::Applicable, ConversionKind::Exact);
        let mut more_defaults =
            assessment(2, ApplicabilityVerdict::Applicable, ConversionKind::Exact);
        fewer_defaults.used_defaults = 0;
        more_defaults.used_defaults = 1;
        // Equal conversions need known source and target identities; an
        // unknown pair is incomparable, not equal.
        let int = Some(SemanticId::for_test(100_u64.to_le_bytes()));
        for assessment in [&mut fewer_defaults, &mut more_defaults] {
            for evidence in &mut assessment.conversions {
                evidence.source_type = int;
                evidence.target_type = int;
            }
        }
        assert_eq!(
            select_candidate_indices(
                adapter(Language::Kotlin),
                &[fewer_defaults, more_defaults],
                &HashMap::default()
            ),
            vec![0]
        );
    }
    #[test]
    fn kotlin_maps_named_arguments_defaults_and_a_trailing_vararg() {
        use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

        use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredCallArgumentProperty;

        use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredCallableParameterApplicability;

        use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredCallableParameterProperty;

        let id = |label: &'static [u8]| SemanticId::for_test(label);
        let call = LoweredCallApplicabilityObligation::new(
            id(b"call"),
            id(b"reference"),
            None,
            id(b"result"),
            vec![id(b"actual")],
            Vec::new(),
            0,
            id(b"reason"),
            ResolutionCompletion::Complete,
        )
        .with_argument_shape(
            Language::Kotlin,
            vec![LoweredCallArgumentProperty::new(
                0,
                0,
                id(b"actual"),
                Some(Box::from("rest")),
            )],
            vec![0],
        );
        let signature = LoweredCallableSignatureProperty::new(
            id(b"callable"),
            0,
            vec![
                LoweredCallableParameterProperty::new(
                    0,
                    id(b"default"),
                    id(b"default-type"),
                    false,
                ),
                LoweredCallableParameterProperty::new(1, id(b"rest"), id(b"rest-type"), true),
            ],
            ResolutionCompletion::Complete,
        )
        .with_applicability_shape(
            vec![0],
            vec![
                LoweredCallableParameterApplicability::new(
                    0,
                    0,
                    Some(Box::from("prefix")),
                    true,
                    true,
                ),
                LoweredCallableParameterApplicability::new(
                    1,
                    0,
                    Some(Box::from("rest")),
                    false,
                    true,
                ),
            ],
            None,
        );

        assert_eq!(
            adapter(Language::Kotlin).map_arguments(&call, &signature),
            MappingAssessment::Mapped {
                bindings: vec![ArgumentFormalBinding {
                    argument_index: 0,
                    parameter_index: 1,
                }],
                used_defaults: 1,
                used_vararg: true,
                result_application_lists: vec![],
            }
        );
    }
    #[test]
    fn scala_named_labels_select_the_matching_formal() {
        use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

        use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredCallArgumentProperty;

        use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredCallableParameterApplicability;

        use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredCallableParameterProperty;

        let id = |label: &'static [u8]| SemanticId::for_test(label);
        let call = LoweredCallApplicabilityObligation::new(
            id(b"call"),
            id(b"reference"),
            None,
            id(b"result"),
            vec![id(b"actual-right"), id(b"actual-left")],
            Vec::new(),
            0,
            id(b"reason"),
            ResolutionCompletion::Complete,
        )
        .with_argument_shape(
            Language::Scala,
            vec![
                LoweredCallArgumentProperty::new(
                    0,
                    0,
                    id(b"actual-right"),
                    Some(Box::from("right")),
                ),
                LoweredCallArgumentProperty::new(0, 1, id(b"actual-left"), Some(Box::from("left"))),
            ],
            vec![0],
        );
        let signature = LoweredCallableSignatureProperty::new(
            id(b"callable"),
            0,
            vec![
                LoweredCallableParameterProperty::new(0, id(b"left"), id(b"left-type"), false),
                LoweredCallableParameterProperty::new(1, id(b"right"), id(b"right-type"), false),
            ],
            ResolutionCompletion::Complete,
        )
        .with_applicability_shape(
            vec![0],
            vec![
                LoweredCallableParameterApplicability::new(
                    0,
                    0,
                    Some(Box::from("left")),
                    false,
                    true,
                ),
                LoweredCallableParameterApplicability::new(
                    1,
                    0,
                    Some(Box::from("right")),
                    false,
                    true,
                ),
            ],
            None,
        );

        assert_eq!(
            adapter(Language::Scala).map_arguments(&call, &signature),
            MappingAssessment::Mapped {
                bindings: vec![
                    ArgumentFormalBinding {
                        argument_index: 0,
                        parameter_index: 1,
                    },
                    ArgumentFormalBinding {
                        argument_index: 1,
                        parameter_index: 0,
                    },
                ],
                used_defaults: 0,
                used_vararg: false,
                result_application_lists: vec![],
            }
        );
    }
}
