use super::*;

#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::Language;

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn seed_fragment(slot: SemanticId, identity: SemanticId) -> LoweredTypedFragment {
    let frontier = LoweredTypedFrontier::new(slot, ResolutionTypeSlotRole::ExpressionValue);
    let seed = LoweredIntrinsicSeed::new(
        IntrinsicTypeKind::Primitive,
        "int",
        TypedFrontierState::new(
            slot,
            vec![ResolutionSlotValue::runtime(
                ResolutionTypeRef::new(identity, 0),
                false,
            )],
            ResolutionCompletion::Complete,
        ),
    );
    LoweredTypedFragment::new(
        BindingFragmentId::at_ordinal(7),
        Language::Java,
        vec![frontier],
        vec![],
        vec![seed],
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
}

#[cfg(test)]
#[test]
fn typed_descriptor_digest_tracks_nested_identity_and_cancelled_work() {
    let first = seed_fragment(SemanticId::operation_local(1), SemanticId::context_local(2));
    let second = seed_fragment(SemanticId::operation_local(1), SemanticId::context_local(3));
    let cancellation = CancellationToken::new();
    assert_ne!(
        typed_fragment_digest(&first, [7; 32], &cancellation).unwrap(),
        typed_fragment_digest(&second, [7; 32], &cancellation).unwrap()
    );
    cancellation.cancel();
    assert_eq!(
        typed_fragment_digest(&first, [7; 32], &cancellation).unwrap(),
        None
    );
}

#[cfg(test)]
#[test]
fn stage_body_decoder_retains_raw_completion_and_independent_observation() {
    let connection = Connection::open_in_memory().unwrap();
    let slot = SemanticId::context_local(11);
    let reference = SemanticId::local(13, 17);
    let node = BindingNodeId::operation_local(19);
    let role = code(
        ALL_RESOLUTION_TYPE_SLOT_ROLES,
        ResolutionTypeSlotRole::TargetTypeIdentity,
    );
    let observed = connection.query_row("SELECT ?1 AS slot_key,NULL AS slot_shared,?2 AS role,?3 AS identity_reference_key,NULL AS identity_reference_shared,?4 AS identity_reference_node",rusqlite::params![codec::encode_semantic(slot),role,codec::encode_semantic(reference),codec::encode_node(node)],|row|Ok(decode_frontier(row).unwrap())).unwrap();
    assert_eq!(
        observed,
        LoweredTypedFrontier::new(slot, ResolutionTypeSlotRole::TargetTypeIdentity)
            .with_type_identity_reference(reference, node)
    );
    for completion in [
        ResolutionCompletion::Complete,
        ResolutionCompletion::Incomplete(vec![].into()),
        ResolutionCompletion::Incomplete(
            vec![
                ResolutionIncompleteReason::CyclicPrefixDependency(reference),
                ResolutionIncompleteReason::ReceiverBudgetExhausted(SemanticId::shared_name(
                    SharedNameId::interned(31),
                )),
                ResolutionIncompleteReason::UnmountedFile {
                    fragment: BindingFragmentId::at_ordinal(13),
                },
            ]
            .into(),
        ),
        ResolutionCompletion::Incomplete(
            vec![
                ResolutionIncompleteReason::UnsupportedSemantic(reference),
                ResolutionIncompleteReason::UnsupportedSemantic(reference),
            ]
            .into(),
        ),
    ] {
        let expected = LoweredCallableSignatureProperty::new(
            SemanticId::operation_local(29),
            0,
            vec![],
            completion.clone(),
        );
        let body = serde_json::to_string(&json!([
            0,
            [],
            completion_value(&completion),
            [],
            null,
            null,
            null
        ]))
        .unwrap();
        let actual = typed_rows::decode_callable_signature_body(
            StageBodyDecoder,
            expected.definition(),
            &body,
        );
        assert_eq!(actual, expected);
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn frontier_fragment(host: u32, slots: &[SemanticId]) -> LoweredTypedFragment {
    LoweredTypedFragment::new(
        BindingFragmentId::at_ordinal(host),
        Language::Java,
        slots
            .iter()
            .copied()
            .map(|slot| LoweredTypedFrontier::new(slot, ResolutionTypeSlotRole::ExpressionValue))
            .collect(),
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
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn qualified_fragment(
    host: u32,
    routes: Vec<LoweredQualifiedSeededRoute>,
) -> LoweredTypedFragment {
    let frontiers = routes
        .iter()
        .flat_map(|route| {
            [
                LoweredTypedFrontier::new(
                    route.qualifier_slot(),
                    ResolutionTypeSlotRole::ExpressionValue,
                ),
                LoweredTypedFrontier::new(
                    route.projection_output_slot(),
                    ResolutionTypeSlotRole::CallResult,
                ),
            ]
        })
        .collect();
    let projections = routes
        .iter()
        .map(|route| {
            LoweredBindingProjection::new(
                route.reference(),
                route.projection_output_slot(),
                route.projection_kind(),
            )
        })
        .collect();
    LoweredTypedFragment::new(
        BindingFragmentId::at_ordinal(host),
        Language::Java,
        frontiers,
        vec![],
        vec![],
        projections,
        routes,
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
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn observation_fragment(
    host: u32,
    mut frontiers: Vec<LoweredTypedFrontier>,
) -> LoweredTypedFragment {
    let transfers = frontiers
        .iter()
        .enumerate()
        .map(|(index, frontier)| {
            let index = u64::try_from(index).unwrap();
            LoweredTypeTransfer::new(
                SemanticId::operation_local(40000 + index),
                ResolutionTypeTransferKind::TypeIdentity,
                TypeTransferRule::new(
                    SemanticId::operation_local(50000 + index),
                    frontier.slot(),
                    0,
                    TypeTransferValueTransform::Preserve,
                    ResolutionCompletion::Complete,
                ),
            )
        })
        .collect::<Vec<_>>();
    frontiers.extend(transfers.iter().map(|transfer| {
        LoweredTypedFrontier::new(
            transfer.source_slot(),
            ResolutionTypeSlotRole::TargetTypeIdentity,
        )
    }));
    LoweredTypedFragment::new(
        BindingFragmentId::at_ordinal(host),
        Language::Java,
        frontiers,
        transfers,
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
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod rust_root_test_support {
    use super::*;

    #[doc(hidden)]
    pub fn begin_projection<'a>(
        selection: &'a SelectedResolutionMountInventory<'_>,
    ) -> &'a Connection {
        let connection = selection.connection();
        connection.execute_batch("BEGIN; INSERT INTO temp.selected_resolution_stage_producers(producer_id,host_ordinal,bridge_identity,content_digest) VALUES(1,7,zeroblob(32),zeroblob(32))").unwrap();
        connection
    }
}
