#[cfg(test)]
mod rust_departing_root_tests {
    use brokk_bifrost_analysis::native_resolution_test_support::ResolutionTypeSlotRole;

    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeConstructorKind;

    use brokk_bifrost_analysis::analyzer::resolution::model::BindingFragmentId;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredTypeProduction;

    use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredTypedFragment;

    use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredTypedFrontier;

    use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedResolutionMountOrdinal;

    use brokk_bifrost_analysis::analyzer::resolution::model::SemanticId;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::typed::decode_type_production;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::typed::insert_typed_fragment;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::typed::tests::rust_root_test_support::begin_projection as begin_projection;

    #[test]
    fn constructor_production_stage_rows_round_trip_without_components() {
        let output = SemanticId::local(9, 21);
        let element = SemanticId::context_local(27);
        let expected = LoweredTypeProduction {
            output,
            element,
            constructor: ResolutionTypeConstructorKind::Array,
            length: Some("0x04".to_owned()),
        };
        let fragment = LoweredTypedFragment::new(
            BindingFragmentId::at_ordinal(7),
            Language::Rust,
            vec![
                LoweredTypedFrontier::new(output, ResolutionTypeSlotRole::TargetTypeIdentity),
                LoweredTypedFrontier::new(element, ResolutionTypeSlotRole::TargetTypeIdentity),
            ],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
        )
        .with_type_productions(vec![expected.clone()]);
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::shared_blob(16);
        let selection = fixture.open_ready(&[]);
        let connection = begin_projection(&selection);
        assert!(
            insert_typed_fragment(
                connection,
                1,
                SelectedResolutionMountOrdinal::new(7),
                &fragment,
                &CancellationToken::new()
            )
            .unwrap()
        );
        let actual = connection
            .query_row(
                "SELECT * FROM temp.selected_resolution_stage_type_productions",
                [],
                |row| Ok(decode_type_production(row).unwrap()),
            )
            .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM temp.selected_resolution_stage_type_components",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        connection.execute_batch("ROLLBACK").unwrap();
    }
}
