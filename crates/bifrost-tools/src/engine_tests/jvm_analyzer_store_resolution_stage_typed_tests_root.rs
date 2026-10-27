#[cfg(test)]
mod jvm_extraction_tests {

    use brokk_bifrost_analysis::analyzer::resolution::model::BindingFragmentId;

    use brokk_bifrost_analysis::analyzer::resolution::model::BindingNodeId;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredBindingProjection;

    use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredCallApplicabilityObligation;

    use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredCallableParameterProperty;

    use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredCallableSignatureProperty;

    use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredDeclarationTypeProperty;

    use brokk_bifrost_analysis::analyzer::resolution::common_fact_lowering::LoweredDeferredMemberOwner;

    use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredDefinitionPropertyGap;

    use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredQualifiedSeededRoute;

    use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredTypeTransfer;

    use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredTypedFragment;

    use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredTypedFrontier;

    use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweringGapOrigin;

    use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

    use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionIncompleteReason;

    use brokk_bifrost_analysis::analyzer::resolution::fact_source::SelectedGapReasonProvenance;

    use brokk_bifrost_analysis::analyzer::resolution::fact_source::SelectedQualifiedRoute;

    use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedResolutionMountOrdinal;

    use brokk_bifrost_analysis::analyzer::resolution::fact_source::SelectedTypedRow;

    use brokk_bifrost_analysis::analyzer::resolution::model::SemanticId;

    use brokk_bifrost_analysis::analyzer::resolution::model::SharedNameId;

    use brokk_bifrost_analysis::analyzer::resolution::model::TypeTransferRule;

    use brokk_bifrost_analysis::analyzer::resolution::model::TypeTransferValueTransform;

    use brokk_bifrost_analysis::analyzer::resolution::fact_source::TypedFactPageVisitor;

    use brokk_bifrost_analysis::analyzer::resolution::fact_source::TypedFactRequest;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::typed::tests::rust_root_test_support::begin_projection as begin_projection;

    use brokk_bifrost_analysis::analyzer::store::resolution_prepare::resolution_rows::code;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::codec;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::typed::decode_call_obligation;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::typed::decode_deferred_owner;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::typed::decode_frontier;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::typed::decode_intrinsic;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::typed::decode_projection;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::typed::decode_signature;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::typed::decode_transfer;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::typed::tests::frontier_fragment;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::typed::insert_typed_fragment;

    use brokk_bifrost_analysis::analyzer::store::resolution_prepare::resolution_rows::namespace_code;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::typed::tests::observation_fragment;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::typed::tests::qualified_fragment;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::typed::tests::seed_fragment;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::lexical::semantic_cells as semantic_pair;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::typed::semantic_request_json;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::typed::validate_callable_parameter_owners;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::typed::visit_definition_property_gap_pages_for_reasons;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::typed::visit_gap_reason_provenance_pages_for_reasons;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::typed::visit_qualified_route_pages_for_lookups;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::typed::visit_typed_frontier_pages;

    #[cfg(test)]
    use brokk_bifrost_core::analyzer::model::Language;
    #[test]
    fn typed_insert_readback_preserves_runtime_and_shared_coordinates() {
        let cancellation = CancellationToken::new();
        for (slot, identity) in [
            (
                SemanticId::local(9, 11),
                SemanticId::shared_name(SharedNameId::interned(31)),
            ),
            (
                SemanticId::operation_local(23),
                SemanticId::context_local(27),
            ),
            (
                SemanticId::shared_name(SharedNameId::interned(35)),
                SemanticId::local(15, 41),
            ),
        ] {
            let fragment = seed_fragment(slot, identity);
            let fixture = crate::selection_fixture_support::JvmSelectionFixture::shared_blob(16);
            let selection = fixture.open_ready(&[]);
            let connection = begin_projection(&selection);
            assert!(
                insert_typed_fragment(
                    connection,
                    1,
                    SelectedResolutionMountOrdinal::new(7),
                    &fragment,
                    &cancellation
                )
                .unwrap()
            );
            let decoded = connection.query_row("SELECT *,json(possible_values) AS possible_values_json,json(completion) AS completion_json FROM temp.selected_resolution_stage_intrinsic_seeds", [], |row| Ok(decode_intrinsic(row).unwrap())).unwrap();
            assert_eq!(&decoded, &fragment.intrinsic_seeds()[0]);
            let stored: (Option<i64>, Option<i64>) = connection
            .query_row(
                "SELECT slot_key,slot_shared FROM temp.selected_resolution_stage_intrinsic_seeds",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
            assert_eq!(stored, semantic_pair(slot));
            connection.execute_batch("ROLLBACK").unwrap();
        }
    }
    #[test]
    fn unary_indirection_stage_roundtrip_preserves_both_category_transfers() {
        let source = SemanticId::local(7, 11);
        let output = SemanticId::shared_name(SharedNameId::interned(31));
        let type_object_rule = SemanticId::local(7, 12);
        let addressable_runtime_rule = SemanticId::shared_name(SharedNameId::interned(32));
        let unsupported = SemanticId::shared_name(SharedNameId::interned(33));
        let incomplete =
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                unsupported,
            )]);
        let fragment = LoweredTypedFragment::new(
            BindingFragmentId::at_ordinal(7),
            Language::Java,
            vec![
                LoweredTypedFrontier::new(source, ResolutionTypeSlotRole::ExpressionValue),
                LoweredTypedFrontier::new(output, ResolutionTypeSlotRole::ExpressionValue),
            ],
            vec![
                LoweredTypeTransfer::new(
                    source,
                    ResolutionTypeTransferKind::UnaryIndirection,
                    TypeTransferRule::new(
                        type_object_rule,
                        output,
                        1,
                        TypeTransferValueTransform::TypeObjectOnly,
                        incomplete,
                    ),
                ),
                LoweredTypeTransfer::new(
                    source,
                    ResolutionTypeTransferKind::UnaryIndirection,
                    TypeTransferRule::new(
                        addressable_runtime_rule,
                        output,
                        -1,
                        TypeTransferValueTransform::AddressableRuntimeOnly,
                        ResolutionCompletion::Complete,
                    ),
                ),
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
        );
        let expected = fragment.transfers().to_vec();
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::shared_blob(16);
        let selection = fixture.open_ready(&[]);
        let connection = begin_projection(&selection);
        assert!(
            insert_typed_fragment(
                connection,
                1,
                SelectedResolutionMountOrdinal::new(7),
                &fragment,
                &CancellationToken::new(),
            )
            .unwrap()
        );

        let mut statement = connection
        .prepare(
            "SELECT *,json(completion) AS completion_json FROM temp.selected_resolution_stage_type_transfers ORDER BY sequence",
        )
        .unwrap();
        let actual = statement
            .query_map([], |row| Ok(decode_transfer(row).unwrap()))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(actual, expected);
        let type_object_transfer = actual
            .iter()
            .find(|transfer| transfer.rule().semantic() == type_object_rule)
            .unwrap();
        assert_eq!(type_object_transfer.source_slot(), source);
        assert_eq!(type_object_transfer.rule().target_slot(), output);
        assert_eq!(
            type_object_transfer.rule().completion(),
            &ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                unsupported,
            )])
        );
        let addressable_runtime_transfer = actual
            .iter()
            .find(|transfer| transfer.rule().semantic() == addressable_runtime_rule)
            .unwrap();
        assert_eq!(
            addressable_runtime_transfer.rule().completion(),
            &ResolutionCompletion::Complete
        );
        connection.execute_batch("ROLLBACK").unwrap();
    }
    #[test]
    fn typed_projection_cancellation_is_rolled_back_by_owner() {
        let fragment = seed_fragment(
            SemanticId::context_local(7001),
            SemanticId::shared_name(SharedNameId::interned(2)),
        );
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::shared_blob(16);
        let selection = fixture.open_ready(&[]);
        let connection = begin_projection(&selection);
        let cancellation = CancellationToken::cancel_after_checks_for_test(2);
        assert!(
            !insert_typed_fragment(
                connection,
                1,
                SelectedResolutionMountOrdinal::new(7),
                &fragment,
                &cancellation
            )
            .unwrap()
        );
        connection.execute_batch("ROLLBACK").unwrap();
        let count: i64 = connection
            .query_row(
                "SELECT count(*) FROM temp.selected_resolution_stage_type_frontiers",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }
    #[test]
    fn typed_natural_key_conflicts_are_errors() {
        let fragment = seed_fragment(
            SemanticId::context_local(7001),
            SemanticId::shared_name(SharedNameId::interned(2)),
        );
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::shared_blob(16);
        let selection = fixture.open_ready(&[]);
        let connection = begin_projection(&selection);
        let cancellation = CancellationToken::new();
        assert!(
            insert_typed_fragment(
                connection,
                1,
                SelectedResolutionMountOrdinal::new(7),
                &fragment,
                &cancellation
            )
            .unwrap()
        );
        connection.execute("INSERT INTO temp.selected_resolution_stage_producers(producer_id,host_ordinal,bridge_identity,content_digest) VALUES(2,7,?1,zeroblob(32))",[&[1_u8;32][..]]).unwrap();
        assert!(
            insert_typed_fragment(
                connection,
                2,
                SelectedResolutionMountOrdinal::new(7),
                &fragment,
                &cancellation
            )
            .is_err()
        );
        connection.execute_batch("ROLLBACK").unwrap();
    }
    #[test]
    fn stage_frontier_reader_preserves_selected_scope_and_host_multiplicity() {
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionTempTransaction;

        let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(2);
        let selection = fixture.open_ready(&[]);
        let slot = SemanticId::context_local(51);
        selection.with_owned_temp_transaction(|connection| {
        for host in [0,1] {
            let producer = i64::from(host)+1;
            connection.execute("INSERT INTO temp.selected_resolution_stage_producers(producer_id,host_ordinal,bridge_identity,content_digest) VALUES(?1,?2,zeroblob(32),zeroblob(32))",rusqlite::params![producer,host])?;
            assert!(insert_typed_fragment(connection,producer,SelectedResolutionMountOrdinal::new(host),&frontier_fragment(host,&[slot]),&CancellationToken::new())?);
        }
        Ok(SelectedResolutionTempTransaction::Commit(()))
    }).unwrap();
        for scope in [vec![0, 1], vec![0], vec![]] {
            selection
                .with_owned_temp_write(|connection| {
                    connection.execute("DELETE FROM temp.selected_resolution_scope_mounts", [])?;
                    for ordinal in &scope {
                        connection.execute(
                            "INSERT INTO temp.selected_resolution_scope_mounts VALUES(?1)",
                            [ordinal],
                        )?;
                    }
                    Ok(())
                })
                .unwrap();
            let mut rows = Vec::new();
            let mut receive = |page: &[SelectedTypedRow<LoweredTypedFrontier>]| {
                rows.extend_from_slice(page);
                Ok(true)
            };
            let mut visitor = TypedFactPageVisitor::with_maximum_rows(&mut receive, 1);
            let outcome = visit_typed_frontier_pages(
                &selection,
                TypedFactRequest::new(&[slot]),
                &CancellationToken::new(),
                &mut visitor,
            )
            .unwrap();
            assert!(outcome.is_exhausted());
            let mut hosts = rows
                .iter()
                .map(|row| row.fragment().ordinal())
                .collect::<Vec<_>>();
            hosts.sort_unstable();
            assert_eq!(hosts, scope);
            assert!(rows.iter().all(|row| row.row().slot() == slot));
        }
        selection.reset_scope_mounts().unwrap();
        let cancellation = CancellationToken::cancel_after_checks_for_test(2);
        let mut called = false;
        let mut receive = |_: &[SelectedTypedRow<LoweredTypedFrontier>]| {
            called = true;
            Ok(true)
        };
        let outcome = visit_typed_frontier_pages(
            &selection,
            TypedFactRequest::new(&[slot]),
            &cancellation,
            &mut TypedFactPageVisitor::new(&mut receive),
        )
        .unwrap();
        assert!(outcome.is_cancelled());
        assert!(
            !called,
            "cancelled eager read publishes no partial row page"
        );
    }
    #[test]
    fn bundled_stage_frontier_plans_bound_key_work_under_both_statistics_states() {
        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned;

        use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionTempTransaction;

        use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
        use rusqlite::StatementStatus;
        // One parsed blob mounted many times keeps the full selected-scope matrix
        // small enough for the push budget while using real selection rows.
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::shared_blob(4096);
        for statistics in PlannerStatisticsState::BOTH {
            fixture.store.conn.execute(move |connection| {
                statistics.install(connection);
                connection.flush_prepared_statement_cache();
            });
            fixture.store.recycle_readers_for_new_statistics();
            let selection = fixture.open_ready(&[]);
            let foreign = SemanticId::local(11, 23);
            let shared = SemanticId::shared_name(SharedNameId::interned(31));
            selection.with_owned_temp_transaction(|connection| {
            for (producer,host,slots) in [
                (1,7,vec![foreign,shared]),
                (2,13,vec![foreign]),
                (3,14,(0..4096).map(|n|SemanticId::context_local(1000+n)).collect()),
            ] {
                connection.execute("INSERT INTO temp.selected_resolution_stage_producers(producer_id,host_ordinal,bridge_identity,content_digest) VALUES(?1,?2,zeroblob(32),zeroblob(32))",rusqlite::params![producer,host])?;
                assert!(insert_typed_fragment(connection,producer,SelectedResolutionMountOrdinal::new(host),&frontier_fragment(host,&slots),&CancellationToken::new())?);
            }
            Ok(SelectedResolutionTempTransaction::Commit(()))
        }).unwrap();
            let subject = pinned("stage_typed_frontiers");
            for scope_size in [16, 256, 4096] {
                selection.with_owned_temp_write(|connection| {
                connection.execute("DELETE FROM temp.selected_resolution_scope_mounts",[])?;
                connection.execute("INSERT INTO temp.selected_resolution_scope_mounts SELECT mount_ordinal FROM temp.selected_resolution_mounts WHERE mount_ordinal<?1",[scope_size])?;
                Ok(())
            }).unwrap();
                for arity in [1, 6, 16, 64, 256] {
                    for (first, expected_hosts) in [
                        (foreign, vec![7, 13]),
                        (shared, vec![7]),
                        (SemanticId::operation_local(9999), vec![]),
                    ] {
                        let keys = std::iter::once(first)
                            .chain((1..arity).map(|n| SemanticId::operation_local(10000 + n)))
                            .collect::<Vec<_>>();
                        let payload = semantic_request_json(TypedFactRequest::new(&keys));
                        let plan = selection
                            .connection()
                            .prepare(&format!("EXPLAIN QUERY PLAN {}", subject.sql))
                            .unwrap()
                            .query_map([&payload], |row| row.get::<_, String>(3))
                            .unwrap()
                            .collect::<rusqlite::Result<Vec<_>>>()
                            .unwrap();
                        assert!(
                            plan.iter().any(|step| step.contains("SEARCH fact")
                                && step.contains("slot_key=? AND slot_shared=?")),
                            "{statistics:?}, scope={scope_size}, arity={arity}, key={first:?}: {plan:?}"
                        );
                        assert!(
                            !plan.iter().any(
                                |step| step.contains("SCAN fact") || step.contains("AUTOMATIC")
                            ),
                            "{statistics:?}: {plan:?}"
                        );
                        let mut statement = selection.connection().prepare(&subject.sql).unwrap();
                        let mut hosts = statement
                            .query_map([&payload], |row| row.get::<_, u32>("host_ordinal"))
                            .unwrap()
                            .collect::<rusqlite::Result<Vec<_>>>()
                            .unwrap();
                        hosts.sort_unstable();
                        assert_eq!(
                            hosts, expected_hosts,
                            "{statistics:?}, scope={scope_size}, arity={arity}, key={first:?}"
                        );
                        let steps = statement.get_status(StatementStatus::VmStep);
                        assert!(
                            steps <= i32::try_from(arity * 24 + 256).unwrap(),
                            "{statistics:?}, scope={scope_size}, arity={arity}, key={first:?}: {steps} VM steps; {plan:?}"
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn route_lookup_aliases_match_or_semantics_and_preserve_host_multiplicity() {
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionTempTransaction;
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(2);
        let selection = fixture.open_ready(&[]);
        let first = SemanticId::shared_name(SharedNameId::interned(77));
        let second = SemanticId::shared_name(SharedNameId::interned(88));
        let routes = [(first, second), (second, first), (first, first)]
            .into_iter()
            .enumerate()
            .map(|(n, (lookup, source_lookup))| {
                let n = u64::try_from(n).unwrap();
                LoweredQualifiedSeededRoute::new_with_source_lookup(
                    SemanticId::context_local(n + 100),
                    SemanticId::context_local(n + 200),
                    lookup,
                    ResolutionNamespace::Callable,
                    source_lookup,
                    0,
                    SemanticId::context_local(n + 300),
                    BindingProjectionKind::TargetCallableResultType,
                    SemanticId::context_local(n + 400),
                    false,
                )
            })
            .collect::<Vec<_>>();
        selection.with_owned_temp_transaction(|connection| {
        for (sequence, route) in routes.iter().enumerate() {
            let node = BindingNodeId::operation_local(u64::try_from(sequence).unwrap() + 900);
            connection.execute("INSERT INTO temp.selected_resolution_stage_nodes(node,kind,kind_semantic_key) VALUES(?1,8,?2)", rusqlite::params![codec::encode_node(node),codec::encode_semantic(route.reference())])?;
        }
        for host in [0,1] {
            let producer=i64::from(host)+1;
            connection.execute("INSERT INTO temp.selected_resolution_stage_producers(producer_id,host_ordinal,bridge_identity,content_digest) VALUES(?1,?2,zeroblob(32),zeroblob(32))",rusqlite::params![producer,host])?;
            assert!(insert_typed_fragment(connection,producer,SelectedResolutionMountOrdinal::new(host),&qualified_fragment(host,routes.clone()),&CancellationToken::new())?);
            for (sequence,route) in routes.iter().enumerate() {
                // Each host owns the reference node independently of its optional
                // semantic-site metadata; the node and semantic IDs differ.
                let node=BindingNodeId::operation_local(u64::try_from(sequence).unwrap()+900);
                connection.execute("INSERT INTO temp.selected_resolution_stage_node_owners(producer_id,node) VALUES(?1,?2)", rusqlite::params![producer,codec::encode_node(node)])?;
                connection.execute("INSERT INTO temp.selected_resolution_stage_semantics(host_ordinal,producer_id,sequence,semantic_key,semantic_shared,node,source_site,role,namespace,owner_kind) VALUES(?1,?2,?3,?4,NULL,?5,?3,0,?6,0)",rusqlite::params![host,producer,i64::try_from(sequence).unwrap(),codec::encode_semantic(route.reference()),codec::encode_node(node),namespace_code(ResolutionNamespace::Callable)])?;
            }
        }
        Ok(SelectedResolutionTempTransaction::Commit(()))
    }).unwrap();
        // Publish committed fixture rows through the same content epoch as admit.
        selection.note_stage_content_commit();
        for requested in [vec![first], vec![second], vec![first, second]] {
            let payload = semantic_request_json(TypedFactRequest::new(&requested));
            let mut expected=selection.connection().prepare("SELECT fact.host_ordinal,fact.reference_key,fact.precedence_ordinal FROM temp.selected_resolution_stage_qualified_routes fact WHERE EXISTS(SELECT 1 FROM json_each(?1) request WHERE (fact.lookup_key IS request.value->>0 AND fact.lookup_shared IS request.value->>1) OR (fact.source_lookup_key IS request.value->>0 AND fact.source_lookup_shared IS request.value->>1))").unwrap().query_map([&payload],|row|Ok((row.get::<_,u32>(0)?,row.get::<_,i64>(1)?,row.get::<_,u32>(2)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            let mut rows = Vec::new();
            let mut receive = |page: &[SelectedQualifiedRoute]| {
                rows.extend_from_slice(page);
                Ok(true)
            };
            let result = visit_qualified_route_pages_for_lookups(
                &selection,
                TypedFactRequest::new(&requested),
                &CancellationToken::new(),
                &mut TypedFactPageVisitor::with_maximum_rows(&mut receive, 2),
            )
            .unwrap();
            assert!(result.is_exhausted());
            let mut actual = rows
                .iter()
                .map(|row| {
                    (
                        row.fragment().ordinal(),
                        codec::encode_semantic(row.row().reference()),
                        row.row().precedence_ordinal(),
                    )
                })
                .collect::<Vec<_>>();
            expected.sort_unstable();
            actual.sort_unstable();
            assert_eq!(actual, expected);
            for row in rows {
                let index = routes
                    .iter()
                    .position(|route| route.reference() == row.row().reference())
                    .unwrap();
                assert_eq!(
                    row.reference_node(),
                    BindingNodeId::operation_local(u64::try_from(index).unwrap() + 900)
                );
            }
        }
    }
    #[test]
    fn nonempty_stage_body_families_round_trip_through_indexed_rows() {
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::shared_blob(16);
        let selection = fixture.open_ready(&[]);
        let connection = begin_projection(&selection);
        let definition = SemanticId::context_local(101);
        let parameter_definition = SemanticId::shared_name(SharedNameId::interned(51));
        let parameter_slot = SemanticId::context_local(102);
        let receiver = SemanticId::context_local(103);
        let argument = SemanticId::context_local(104);
        let result = SemanticId::context_local(105);
        let hierarchy = SemanticId::context_local(106);
        let callee = SemanticId::context_local(107);
        let reason = SemanticId::context_local(108);
        let type_argument = SemanticId::context_local(110);
        let owner_type_argument = SemanticId::context_local(111);
        let expected = SemanticId::context_local(112);
        let owner_segment = SemanticId::context_local(113);
        let member_reference = SemanticId::context_local(114);
        let member_binding = SemanticId::context_local(115);
        let non_invoking = LoweredBindingProjection::new(
            member_reference,
            member_binding,
            BindingProjectionKind::NonInvokingMemberReference,
        );
        // Appended codec value: existing persisted projection codes stay unchanged.
        assert_eq!(code(ALL_BINDING_PROJECTION_KINDS, non_invoking.kind()), 8);
        let frontiers = [
            (parameter_slot, ResolutionTypeSlotRole::DeclaredValue),
            (type_argument, ResolutionTypeSlotRole::DeclaredValue),
            (owner_type_argument, ResolutionTypeSlotRole::DeclaredValue),
            (expected, ResolutionTypeSlotRole::DeclaredValue),
            (owner_segment, ResolutionTypeSlotRole::TargetTypeIdentity),
            (member_binding, ResolutionTypeSlotRole::ExpressionValue),
            (receiver, ResolutionTypeSlotRole::Receiver),
            (argument, ResolutionTypeSlotRole::Argument),
            (result, ResolutionTypeSlotRole::CallResult),
            (hierarchy, ResolutionTypeSlotRole::TargetTypeIdentity),
        ]
        .into_iter()
        .map(|(slot, role)| LoweredTypedFrontier::new(slot, role))
        .collect();
        let signature = LoweredCallableSignatureProperty::new(
        definition,
        2,
        vec![LoweredCallableParameterProperty::new(
            0,
            parameter_definition,
            parameter_slot,
            true,
        )],
        ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnmountedFile {
            fragment: BindingFragmentId::at_ordinal(1),
        }]),
    )
    .with_result_type_parameter(Some(
        brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredCallableResultBinding::new(1, 1, 1),
    ));
        let call = LoweredCallApplicabilityObligation::new(
            SemanticId::operation_local(109),
            callee,
            Some(receiver),
            result,
            vec![argument],
            vec![ALL_RESOLUTION_ENGINE_RULE_KINDS[0]],
            2,
            reason,
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                reason,
            )]),
        )
        .with_type_argument_slots(vec![type_argument])
        .with_owner_type_arguments(Some(owner_segment), vec![owner_type_argument])
        .with_expected_result_slot(Some(expected))
        .with_language(Language::Java);
        let deferred = LoweredDeferredMemberOwner::new(
            definition,
            parameter_slot,
            SemanticId::shared_name(SharedNameId::interned(55)),
            ResolutionMemberKind::Method,
            ResolutionMemberAccess::Instance,
            ResolutionMemberQualifierCompatibility::RuntimeOnly,
        )
        .with_hierarchy_frontier(Some(hierarchy));
        let fragment = LoweredTypedFragment::new(
            BindingFragmentId::at_ordinal(7),
            Language::Java,
            frontiers,
            vec![],
            vec![],
            vec![
                LoweredBindingProjection::new(
                    callee,
                    result,
                    BindingProjectionKind::TargetCallableResultType,
                ),
                non_invoking,
            ],
            vec![],
            vec![LoweredDeclarationTypeProperty::new(
                parameter_definition,
                parameter_slot,
                DeclarationTypeRole::Parameter,
            )],
            vec![],
            vec![],
            vec![],
            vec![deferred],
            vec![],
            vec![],
            vec![],
            vec![call.clone()],
            vec![signature.clone()],
        );
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
        let actual=connection.query_row("SELECT *,json(body) AS body_json FROM temp.selected_resolution_stage_callable_signatures WHERE producer_id=1",[],|row|Ok(decode_signature(row).unwrap())).unwrap();
        assert_eq!(actual, signature);
        let actual=connection.query_row("SELECT *,json(body) AS body_json FROM temp.selected_resolution_stage_deferred_member_owners WHERE producer_id=1",[],|row|Ok(decode_deferred_owner(row).unwrap())).unwrap();
        assert_eq!(actual, deferred);
        let actual=connection.query_row("SELECT call.*,mount.semantic_language,json(call.argument_slots) AS argument_slots_json,json(call.type_argument_slots) AS type_argument_slots_json,json(call.eligible_rules) AS eligible_rules_json,json(call.completion) AS completion_json FROM temp.selected_resolution_stage_call_obligations call JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=call.host_ordinal WHERE call.producer_id=1",[],|row|Ok(decode_call_obligation(row).unwrap())).unwrap();
        assert_eq!(actual, call);
        let decoded = connection
            .query_row(
                "SELECT * FROM temp.selected_resolution_stage_binding_projections WHERE kind=?1",
                [code(ALL_BINDING_PROJECTION_KINDS, non_invoking.kind())],
                |row| Ok(decode_projection(row).unwrap()),
            )
            .unwrap();
        assert_eq!(decoded, non_invoking);
        connection.execute_batch("ROLLBACK").unwrap();
    }
    #[test]
    fn stage_reason_owner_conflict_agrees_with_fragment_constructor() {
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionTempTransaction;
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(1);
        let selection = fixture.open_ready(&[]);
        let lookup = SemanticId::shared_name(SharedNameId::interned(91));
        let reason = SemanticId::context_local(300);
        let make = |base| {
            qualified_fragment(
                0,
                vec![LoweredQualifiedSeededRoute::new_with_source_lookup(
                    SemanticId::context_local(base),
                    SemanticId::context_local(base + 1),
                    lookup,
                    ResolutionNamespace::Callable,
                    lookup,
                    0,
                    SemanticId::context_local(base + 2),
                    BindingProjectionKind::TargetCallableResultType,
                    reason,
                    false,
                )],
            )
        };
        let first = make(100);
        let second = make(200);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut joined = first.clone();
                joined.append_selected_macro_fragment(second.clone());
            }))
            .is_err()
        );
        selection.with_owned_temp_transaction(|connection|{
        connection.execute("INSERT INTO temp.selected_resolution_stage_producers(producer_id,host_ordinal,bridge_identity,content_digest) VALUES(1,0,zeroblob(32),zeroblob(32))",[])?;
        assert!(insert_typed_fragment(connection,1,SelectedResolutionMountOrdinal::new(0),&first,&CancellationToken::new())?);
        Ok(SelectedResolutionTempTransaction::Commit(()))
    }).unwrap();
        let inserted=selection.with_owned_temp_transaction(|connection|{
        connection.execute("INSERT INTO temp.selected_resolution_stage_producers(producer_id,host_ordinal,bridge_identity,content_digest) VALUES(2,0,?1,zeroblob(32))",[&[1_u8;32][..]])?;
        assert!(insert_typed_fragment(connection,2,SelectedResolutionMountOrdinal::new(0),&second,&CancellationToken::new())?);
        Ok(SelectedResolutionTempTransaction::Commit(()))
    });
        assert!(inserted.is_err());
        let producers: i64 = selection
            .connection()
            .query_row(
                "SELECT count(*) FROM temp.selected_resolution_stage_producers",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            producers, 1,
            "failed admission rolls back the producer and all new facts"
        );
    }
    #[test]
    fn foreign_parameter_owner_admission_uses_full_selection_under_narrowed_scope() {
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::custom_source(
            2,
            "package demo; class Model { int identity(int value) { return value; } }\n",
        );
        let selection = fixture.open_ready(&[]);
        let (parameter_key, owner_key): (u32, u32) = selection.connection().query_row(
        "SELECT owner.parameter_definition,owner.signature_definition FROM temp.selected_resolution_mounts mount JOIN main.resolution_callable_parameter_owners owner ON owner.blob_id=mount.blob_id WHERE mount.mount_ordinal=1 LIMIT 1",
        [], |row| Ok((row.get(0)?,row.get(1)?)),
    ).expect("parsed callable fixture publishes parameter ownership");
        let parameter = SemanticId::local(1, parameter_key);
        let slot = SemanticId::context_local(900);
        let make = |owner| {
            LoweredTypedFragment::new(
                BindingFragmentId::at_ordinal(0),
                Language::Java,
                vec![LoweredTypedFrontier::new(
                    slot,
                    ResolutionTypeSlotRole::DeclaredValue,
                )],
                vec![],
                vec![],
                vec![],
                vec![],
                vec![LoweredDeclarationTypeProperty::new(
                    parameter,
                    slot,
                    DeclarationTypeRole::Parameter,
                )],
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                vec![LoweredCallableSignatureProperty::new(
                    owner,
                    0,
                    vec![LoweredCallableParameterProperty::new(
                        0, parameter, slot, false,
                    )],
                    ResolutionCompletion::Complete,
                )],
            )
        };
        let matching = make(SemanticId::local(1, owner_key));
        let conflicting = [
            make(SemanticId::local(0, owner_key)),
            make(SemanticId::local(1, owner_key.checked_add(1).unwrap())),
            make(SemanticId::shared_name(SharedNameId::interned(71))),
            make(SemanticId::operation_local(901)),
        ];
        for scope in [vec![0, 1], vec![0], vec![]] {
            selection
                .with_owned_temp_write(|connection| {
                    connection.execute("DELETE FROM temp.selected_resolution_scope_mounts", [])?;
                    for ordinal in &scope {
                        connection.execute(
                            "INSERT INTO temp.selected_resolution_scope_mounts VALUES(?1)",
                            [ordinal],
                        )?;
                    }
                    Ok(())
                })
                .unwrap();
            assert!(
                validate_callable_parameter_owners(
                    selection.connection(),
                    &matching,
                    &CancellationToken::new()
                )
                .unwrap(),
                "scope={scope:?}"
            );
            for fragment in &conflicting {
                let error = validate_callable_parameter_owners(
                    selection.connection(),
                    fragment,
                    &CancellationToken::new(),
                )
                .unwrap_err();
                assert!(
                    error.to_string().contains("ordinary signature ownership"),
                    "scope={scope:?}: {error}"
                );
            }
        }
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(
            !validate_callable_parameter_owners(selection.connection(), &matching, &cancelled)
                .unwrap()
        );
    }
    #[test]
    fn bundled_stage_observation_reverse_preserves_nodes_and_bounded_key_seeks() {
        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned;

        use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionTempTransaction;
        use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
        use rusqlite::StatementStatus;
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::shared_blob(4096);
        for statistics in PlannerStatisticsState::BOTH {
            fixture.store.conn.execute(move |connection| {
                statistics.install(connection);
                connection.flush_prepared_statement_cache();
            });
            fixture.store.recycle_readers_for_new_statistics();
            let selection = fixture.open_ready(&[]);
            let foreign = SemanticId::local(11, 23);
            let shared = SemanticId::shared_name(SharedNameId::interned(31));
            selection.with_owned_temp_transaction(|connection| {
            for (producer, host, references) in [
                (1, 7, vec![foreign, shared]),
                (2, 13, vec![foreign]),
                (3, 14, (0..4096).map(|n| SemanticId::context_local(1000+n)).collect()),
            ] {
                connection.execute("INSERT INTO temp.selected_resolution_stage_producers(producer_id,host_ordinal,bridge_identity,content_digest) VALUES(?1,?2,zeroblob(32),zeroblob(32))", rusqlite::params![producer,host])?;
                let fragment = observation_fragment(host,
                    references.into_iter().enumerate().map(|(index,reference)| {
                        LoweredTypedFrontier::new(SemanticId::operation_local(20000+u64::try_from(index).unwrap()),ResolutionTypeSlotRole::TargetTypeIdentity)
                            .with_type_identity_reference(reference,BindingNodeId::context_local(30000+u64::try_from(index).unwrap()))
                    }).collect(),
                );
                assert!(insert_typed_fragment(connection,producer,SelectedResolutionMountOrdinal::new(host),&fragment,&CancellationToken::new())?);
            }
            Ok(SelectedResolutionTempTransaction::Commit(()))
        }).unwrap();
            let subject = pinned("stage_typed_observations");
            for scope in [16, 256, 4096, 8, 0] {
                selection.with_owned_temp_write(|connection| {
                connection.execute("DELETE FROM temp.selected_resolution_scope_mounts",[])?;
                connection.execute("INSERT INTO temp.selected_resolution_scope_mounts SELECT mount_ordinal FROM temp.selected_resolution_mounts WHERE mount_ordinal<?1",[scope])?;
                Ok(())
            }).unwrap();
                for arity in [1, 6, 16, 64, 256] {
                    for (first, hosts) in [
                        (foreign, vec![7, 13]),
                        (shared, vec![7]),
                        (SemanticId::operation_local(9999), vec![]),
                    ] {
                        let keys = std::iter::once(first)
                            .chain((1..arity).map(|n| SemanticId::operation_local(10000 + n)))
                            .collect::<Vec<_>>();
                        let payload = semantic_request_json(TypedFactRequest::new(&keys));
                        let plan = selection
                            .connection()
                            .prepare(&format!("EXPLAIN QUERY PLAN {}", subject.sql))
                            .unwrap()
                            .query_map([&payload], |row| row.get::<_, String>(3))
                            .unwrap()
                            .collect::<rusqlite::Result<Vec<_>>>()
                            .unwrap();
                        assert!(plan.iter().any(|step|step.contains("SEARCH fact USING INDEX selected_resolution_stage_observation_reference")),"{statistics:?}, scope={scope}, arity={arity}: {plan:?}");
                        assert!(
                            !plan.iter().any(
                                |step| step.contains("SCAN fact") || step.contains("AUTOMATIC")
                            ),
                            "{plan:?}"
                        );
                        let mut statement = selection.connection().prepare(&subject.sql).unwrap();
                        let mut actual = statement
                            .query_map([&payload], |row| {
                                Ok((
                                    row.get::<_, u32>("host_ordinal")?,
                                    decode_frontier(row).unwrap(),
                                ))
                            })
                            .unwrap()
                            .collect::<rusqlite::Result<Vec<_>>>()
                            .unwrap();
                        actual.sort_unstable_by_key(|row| row.0);
                        let expected = hosts
                            .into_iter()
                            .filter(|host| *host < scope)
                            .collect::<Vec<_>>();
                        assert_eq!(
                            actual.iter().map(|row| row.0).collect::<Vec<_>>(),
                            expected,
                            "{statistics:?}, scope={scope}, arity={arity}"
                        );
                        for (_, frontier) in actual {
                            let index = if first == shared { 1 } else { 0 };
                            assert_eq!(
                                frontier,
                                LoweredTypedFrontier::new(
                                    SemanticId::operation_local(20000 + index),
                                    ResolutionTypeSlotRole::TargetTypeIdentity
                                )
                                .with_type_identity_reference(
                                    first,
                                    BindingNodeId::context_local(30000 + index)
                                )
                            );
                        }
                        let vm = statement.get_status(StatementStatus::VmStep);
                        assert!(
                            vm <= i32::try_from(arity * 24 + 256).unwrap(),
                            "{statistics:?}, scope={scope}, arity={arity}, VM={vm}: {plan:?}"
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn observation_and_call_result_share_a_reference_in_both_append_orders() {
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionTempTransaction;
        for reference in [
            SemanticId::shared_name(SharedNameId::interned(99)),
            SemanticId::local(1, 23),
        ] {
            let observation = observation_fragment(
                0,
                vec![
                    LoweredTypedFrontier::new(
                        SemanticId::context_local(100),
                        ResolutionTypeSlotRole::TargetTypeIdentity,
                    )
                    .with_type_identity_reference(reference, BindingNodeId::operation_local(900)),
                ],
            );
            let projection = LoweredTypedFragment::new(
                BindingFragmentId::at_ordinal(0),
                Language::Java,
                vec![LoweredTypedFrontier::new(
                    SemanticId::context_local(101),
                    ResolutionTypeSlotRole::CallResult,
                )],
                vec![],
                vec![],
                vec![LoweredBindingProjection::new(
                    reference,
                    SemanticId::context_local(101),
                    BindingProjectionKind::TargetCallableResultType,
                )],
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
            );
            for (first, second) in [(&observation, &projection), (&projection, &observation)] {
                let mut joined = first.clone();
                joined.append_selected_macro_fragment(second.clone());
                let fixture = crate::selection_fixture_support::JvmSelectionFixture::shared_blob(2);
                let selection = fixture.open_ready(&[]);
                selection.with_owned_temp_transaction(|connection|{
                connection.execute("INSERT INTO temp.selected_resolution_stage_producers(producer_id,host_ordinal,bridge_identity,content_digest) VALUES(1,0,zeroblob(32),zeroblob(32))",[])?;
                assert!(insert_typed_fragment(connection,1,SelectedResolutionMountOrdinal::new(0),first,&CancellationToken::new())?);
                Ok(SelectedResolutionTempTransaction::Commit(()))
            }).unwrap();
                let outcome=selection.with_owned_temp_transaction(|connection|{
                connection.execute("INSERT INTO temp.selected_resolution_stage_producers(producer_id,host_ordinal,bridge_identity,content_digest) VALUES(2,0,?1,zeroblob(32))",[&[1_u8;32][..]])?;
                assert!(insert_typed_fragment(connection,2,SelectedResolutionMountOrdinal::new(0),second,&CancellationToken::new())?);
                Ok(SelectedResolutionTempTransaction::Commit(()))
            });
                assert!(outcome.is_ok(), "reference={reference:?}: {outcome:?}");
                let producers: i64 = selection
                    .connection()
                    .query_row(
                        "SELECT count(*) FROM temp.selected_resolution_stage_producers",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(producers, 2);
            }
        }
    }
    #[test]
    fn ordinary_transfer_rule_conflicts_even_with_new_source_and_target() {
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionTempTransaction;
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::custom_source(
            1,
            "package demo; class Model { int identity(int value) { int copy = value; return copy; } }\n",
        );
        let selection = fixture.open_ready(&[]);
        let rule:u32=selection.connection().query_row("SELECT old.rule FROM temp.selected_resolution_mounts mount JOIN main.resolution_type_transfers old ON old.blob_id=mount.blob_id WHERE mount.mount_ordinal=0 LIMIT 1",[],|row|row.get(0)).expect("parsed assignment publishes a transfer");
        let source = SemanticId::context_local(901);
        let target = SemanticId::context_local(902);
        let fragment = LoweredTypedFragment::new(
            BindingFragmentId::at_ordinal(0),
            Language::Java,
            vec![
                LoweredTypedFrontier::new(source, ResolutionTypeSlotRole::ExpressionValue),
                LoweredTypedFrontier::new(target, ResolutionTypeSlotRole::AssignmentValue),
            ],
            vec![LoweredTypeTransfer::new(
                source,
                ResolutionTypeTransferKind::Assignment,
                TypeTransferRule::new(
                    SemanticId::local(0, rule),
                    target,
                    0,
                    TypeTransferValueTransform::Preserve,
                    ResolutionCompletion::Complete,
                ),
            )],
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
        );
        let result=selection.with_owned_temp_transaction(|connection|{
        connection.execute("INSERT INTO temp.selected_resolution_stage_producers(producer_id,host_ordinal,bridge_identity,content_digest) VALUES(1,0,zeroblob(32),zeroblob(32))",[])?;
        assert!(insert_typed_fragment(connection,1,SelectedResolutionMountOrdinal::new(0),&fragment,&CancellationToken::new())?);
        Ok(SelectedResolutionTempTransaction::Commit(()))
    });
        let error = result.unwrap_err();
        assert!(error.to_string().contains("transfer rule"), "{error}");
        let count: i64 = selection
            .connection()
            .query_row(
                "SELECT count(*) FROM temp.selected_resolution_stage_type_transfers",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }
    #[test]
    fn ordinary_call_identity_conflicts_even_with_new_callee_reference() {
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionTempTransaction;
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::custom_source(
            1,
            "package demo; class Model { int identity(int value) { return value; } int invoke() { return identity(1); } }\n",
        );
        let selection = fixture.open_ready(&[]);
        let call:u32=selection.connection().query_row("SELECT old.call FROM temp.selected_resolution_mounts mount JOIN main.resolution_call_obligations old ON old.blob_id=mount.blob_id WHERE mount.mount_ordinal=0 LIMIT 1",[],|row|row.get(0)).expect("parsed invocation publishes a call obligation");
        let callee = SemanticId::context_local(901);
        let result = SemanticId::context_local(902);
        let reason = SemanticId::context_local(903);
        let fragment = LoweredTypedFragment::new(
            BindingFragmentId::at_ordinal(0),
            Language::Java,
            vec![LoweredTypedFrontier::new(
                result,
                ResolutionTypeSlotRole::CallResult,
            )],
            vec![],
            vec![],
            vec![LoweredBindingProjection::new(
                callee,
                result,
                BindingProjectionKind::TargetCallableResultType,
            )],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![LoweredCallApplicabilityObligation::new(
                SemanticId::local(0, call),
                callee,
                None,
                result,
                vec![],
                vec![ALL_RESOLUTION_ENGINE_RULE_KINDS[0]],
                0,
                reason,
                ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(reason),
                ]),
            )],
            vec![],
        );
        let result=selection.with_owned_temp_transaction(|connection|{
        connection.execute("INSERT INTO temp.selected_resolution_stage_producers(producer_id,host_ordinal,bridge_identity,content_digest) VALUES(1,0,zeroblob(32),zeroblob(32))",[])?;
        assert!(insert_typed_fragment(connection,1,SelectedResolutionMountOrdinal::new(0),&fragment,&CancellationToken::new())?);
        Ok(SelectedResolutionTempTransaction::Commit(()))
    });
        let error = result.unwrap_err();
        assert!(error.to_string().contains("call identity"), "{error}");
        let count: i64 = selection
            .connection()
            .query_row(
                "SELECT count(*) FROM temp.selected_resolution_stage_call_obligations",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }
    #[test]
    fn ordinary_property_provenance_requires_same_owner_without_rejecting_new_frontier() {
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionTempTransaction;
        // JLS 9.2 gives a parentless interface a lookup-only Object member root.
        // Its unresolved provider retains property provenance at that reference.
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::custom_source(
            1,
            "package demo; public interface Model {}\n",
        );
        let selection = fixture.open_ready(&[]);
        let (definition,reason,site):(u32,u32,u32)=selection.connection().query_row(
        "SELECT old.definition,old.reason,old.site FROM temp.selected_resolution_mounts mount JOIN main.resolution_definition_property_gaps old ON old.blob_id=mount.blob_id WHERE mount.mount_ordinal=0 AND old.kind=?1 LIMIT 1",
        [code(ALL_RESOLUTION_GAP_KINDS,ResolutionGapKind::UnsupportedHierarchyTraversal)],
        |row|Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
    ).expect("parsed interface publishes property provenance");
        for owner in [
            SemanticId::local(0, definition),
            SemanticId::context_local(990),
        ] {
            let frontier = SemanticId::context_local(991);
            let fragment = LoweredTypedFragment::new(
                BindingFragmentId::at_ordinal(0),
                Language::Java,
                vec![LoweredTypedFrontier::new(
                    frontier,
                    ResolutionTypeSlotRole::TargetTypeIdentity,
                )],
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
                vec![LoweredDefinitionPropertyGap::new(
                    owner,
                    ResolutionSiteId::new(site),
                    ResolutionGapKind::UnsupportedHierarchyTraversal,
                    frontier,
                    SemanticId::local(0, reason),
                )],
                vec![],
                vec![],
            );
            let admitted=selection.with_owned_temp_transaction(|connection|{
            connection.execute("INSERT INTO temp.selected_resolution_stage_producers(producer_id,host_ordinal,bridge_identity,content_digest) VALUES(1,0,zeroblob(32),zeroblob(32))",[])?;
            assert!(insert_typed_fragment(connection,1,SelectedResolutionMountOrdinal::new(0),&fragment,&CancellationToken::new())?);
            Ok(SelectedResolutionTempTransaction::Commit(()))
        });
            if owner == SemanticId::local(0, definition) {
                admitted.expect("same provenance owner can cover a new frontier");
                // Publish committed fixture rows before reads, then clear via the stage boundary.
                selection.note_stage_content_commit();
                let mut found = Vec::new();
                let outcome = visit_definition_property_gap_pages_for_reasons(
                    &selection,
                    TypedFactRequest::new(&[SemanticId::local(0, reason)]),
                    &CancellationToken::new(),
                    &mut TypedFactPageVisitor::new(&mut |page| {
                        found.extend_from_slice(page);
                        Ok(true)
                    }),
                )
                .unwrap();
                assert!(outcome.is_exhausted());
                assert_eq!(
                    found,
                    vec![SelectedTypedRow::new(
                        BindingFragmentId::at_ordinal(0),
                        fragment.property_gaps()[0]
                    )]
                );
                let cancelled = CancellationToken::cancel_after_checks_for_test(0);
                let outcome = visit_definition_property_gap_pages_for_reasons(
                    &selection,
                    TypedFactRequest::new(&[SemanticId::local(0, reason)]),
                    &cancelled,
                    &mut TypedFactPageVisitor::new(&mut |_| {
                        panic!("cancelled owner lookup published rows")
                    }),
                )
                .unwrap();
                assert!(outcome.is_cancelled());
                brokk_bifrost_analysis::analyzer::store::resolution_stage::SelectedResolutionStage::new(&selection).clear_facts().unwrap();
            } else {
                // Invalid-owner admission rolls back before any content can be published.
                let error = admitted.unwrap_err();
                assert!(
                    error.to_string().contains("property provenance owner"),
                    "{error}"
                );
            }
            let count: i64 = selection
                .connection()
                .query_row(
                    "SELECT count(*) FROM temp.selected_resolution_stage_definition_property_gaps",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 0);
        }
    }
    #[test]
    fn raw_gap_provenance_deduplicates_covers_and_rejects_disagreeing_sources() {
        use brokk_bifrost_analysis::analyzer::store::resolution_prepare::resolution_rows::COVERS_REFERENCE;

        use brokk_bifrost_analysis::analyzer::store::resolution_prepare::resolution_rows::COVERS_TYPE_FRONTIER;

        use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionTempTransaction;
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(1);
        let selection = fixture.open_ready(&[]);
        let reason = SemanticId::context_local(77);
        let origin = LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedExpression);
        let origin_code =
        brokk_bifrost_analysis::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code(origin);
        selection.with_owned_temp_transaction(|connection|{
        connection.execute("INSERT INTO temp.selected_resolution_stage_producers(producer_id,host_ordinal,bridge_identity,content_digest) VALUES(1,0,zeroblob(32),zeroblob(32))",[])?;
        for (key, covers, subject, endpoint) in [
            (100, COVERS_REFERENCE, SemanticId::context_local(200), Some(BindingNodeId::operation_local(300))),
            (101, COVERS_TYPE_FRONTIER, SemanticId::context_local(201), None),
        ] {
            connection.execute("INSERT INTO temp.selected_resolution_stage_gaps(host_ordinal,producer_id,covers,gap_key,reason_key,subject_key,endpoint_node,source_site,origin) VALUES(0,1,?1,?2,?6,?3,?4,3,?5)",rusqlite::params![covers,codec::encode_semantic(SemanticId::context_local(key)),codec::encode_semantic(subject),endpoint.map(codec::encode_node),origin_code,codec::encode_semantic(reason)])?;
        }
        Ok(SelectedResolutionTempTransaction::Commit(()))
    }).unwrap();
        // Publish committed fixture rows through the same content epoch as admit.
        selection.note_stage_content_commit();
        let mut rows = Vec::new();
        let mut receive = |page: &[SelectedGapReasonProvenance]| {
            rows.extend_from_slice(page);
            Ok(true)
        };
        let outcome = visit_gap_reason_provenance_pages_for_reasons(
            &selection,
            TypedFactRequest::new(&[reason]),
            &CancellationToken::new(),
            &mut TypedFactPageVisitor::new(&mut receive),
        )
        .unwrap();
        assert!(outcome.is_exhausted());
        assert_eq!(
            rows,
            vec![SelectedGapReasonProvenance::new(
                BindingFragmentId::at_ordinal(0),
                reason,
                ResolutionSiteId::new(3),
                origin
            )]
        );
        selection.with_owned_temp_write(|connection|{
        connection.execute("INSERT INTO temp.selected_resolution_stage_gaps(host_ordinal,producer_id,covers,gap_key,reason_key,source_site,origin) VALUES(0,1,0,?1,?3,4,?2)",rusqlite::params![codec::encode_semantic(SemanticId::context_local(102)),origin_code,codec::encode_semantic(reason)])?;
        Ok(())
    }).unwrap();
        let mut called = false;
        let mut receive = |_: &[SelectedGapReasonProvenance]| {
            called = true;
            Ok(true)
        };
        let error = visit_gap_reason_provenance_pages_for_reasons(
            &selection,
            TypedFactRequest::new(&[reason]),
            &CancellationToken::new(),
            &mut TypedFactPageVisitor::new(&mut receive),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("conflicting source provenance"),
            "{error}"
        );
        assert!(
            !called,
            "conflicting evidence is rejected before any page publication"
        );
    }
    #[test]
    fn staged_property_gap_reason_seek_preserves_frontiers_and_host_scope() {
        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned;

        use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionTempTransaction;
        use brokk_bifrost_core::cache_gc::PlannerStatisticsState;

        let fixture = crate::selection_fixture_support::JvmSelectionFixture::shared_blob(512);
        for statistics in PlannerStatisticsState::BOTH {
            fixture.store.conn.execute(move |connection| {
                statistics.install(connection);
                connection.flush_prepared_statement_cache();
            });
            fixture.store.recycle_readers_for_new_statistics();
            let selection = fixture.open_ready(&[]);
            let reason = SemanticId::operation_local(23);
            let shared = SemanticId::shared_name(SharedNameId::interned(31));
            selection.with_owned_temp_transaction(|connection| {
            for (producer, host, reasons) in [
                (1, 7, vec![reason, reason, shared]),
                (2, 13, vec![reason]),
                (3, 14, (0..512).map(|n| SemanticId::context_local(1000+n)).collect()),
            ] {
                let owner = SemanticId::context_local(9000);
                let gaps = reasons.into_iter().enumerate().map(|(index, reason)| {
                    LoweredDefinitionPropertyGap::new(
                        owner, ResolutionSiteId::new(17), ResolutionGapKind::UnsupportedHierarchyTraversal,
                        SemanticId::context_local(10000 + index as u64), reason,
                    )
                }).collect::<Vec<_>>();
                let frontiers = gaps.iter().map(|gap| LoweredTypedFrontier::new(
                    gap.frontier(), ResolutionTypeSlotRole::TargetTypeIdentity,
                )).collect();
                let fragment = LoweredTypedFragment::new(
                    BindingFragmentId::at_ordinal(host), Language::Java,
                    frontiers, vec![], vec![], vec![], vec![], vec![], vec![], vec![],
                    vec![], vec![], vec![], vec![], gaps, vec![], vec![],
                );
                connection.execute("INSERT INTO temp.selected_resolution_stage_producers(producer_id,host_ordinal,bridge_identity,content_digest) VALUES(?1,?2,zeroblob(32),zeroblob(32))", rusqlite::params![producer,host])?;
                assert!(insert_typed_fragment(connection, producer, SelectedResolutionMountOrdinal::new(host), &fragment, &CancellationToken::new())?);
            }
            Ok(SelectedResolutionTempTransaction::Commit(()))
        }).unwrap();
            let query = pinned("stage_typed_property_gap_reasons");
            for scope in [8, 16, 512] {
                selection.with_owned_temp_write(|connection| {
                connection.execute("DELETE FROM temp.selected_resolution_scope_mounts", [])?;
                connection.execute("INSERT INTO temp.selected_resolution_scope_mounts SELECT mount_ordinal FROM temp.selected_resolution_mounts WHERE mount_ordinal<?1", [scope])?;
                Ok(())
            }).unwrap();
                for arity in [1, 6, 64, 256] {
                    for first in [reason, shared, SemanticId::operation_local(9999)] {
                        let keys = std::iter::once(first)
                            .chain((1..arity).map(|n| SemanticId::operation_local(20000 + n)))
                            .collect::<Vec<_>>();
                        let payload = semantic_request_json(TypedFactRequest::new(&keys));
                        let plan = selection
                            .connection()
                            .prepare(&format!("EXPLAIN QUERY PLAN {}", query.sql))
                            .unwrap()
                            .query_map([&payload], |row| row.get::<_, String>(3))
                            .unwrap()
                            .collect::<rusqlite::Result<Vec<_>>>()
                            .unwrap();
                        assert!(
                            plan.iter().any(|step| step.contains("SEARCH fact")
                                && step.contains("reason_key=? AND reason_shared=?")),
                            "{statistics:?}: {plan:?}"
                        );
                        assert!(
                            !plan.iter().any(|step| step.contains("SCAN fact")
                                || step.contains("AUTOMATIC")
                                || step.contains("TEMP B-TREE")),
                            "{statistics:?}: {plan:?}"
                        );
                        let mut rows = selection
                            .connection()
                            .prepare(&query.sql)
                            .unwrap()
                            .query_map([&payload], |row| {
                                Ok((
                                    row.get::<_, u32>("host_ordinal")?,
                                    row.get::<_, i64>("frontier_key")?,
                                ))
                            })
                            .unwrap()
                            .collect::<rusqlite::Result<Vec<_>>>()
                            .unwrap();
                        rows.sort_unstable();
                        let expected = if first == reason {
                            let mut rows = vec![(7, 10000), (7, 10001)];
                            if scope > 13 {
                                rows.push((13, 10000));
                            }
                            rows
                        } else if first == shared {
                            vec![(7, 10002)]
                        } else {
                            vec![]
                        };
                        let actual = rows
                            .into_iter()
                            .map(|(host, key)| (host, codec::decode_semantic(key)))
                            .collect::<Vec<_>>();
                        let expected = expected
                            .into_iter()
                            .map(|(host, key)| (host, SemanticId::context_local(key)))
                            .collect::<Vec<_>>();
                        assert_eq!(
                            actual, expected,
                            "{statistics:?}, scope={scope}, arity={arity}, reason={first:?}"
                        );
                    }
                }
            }
        }
    }

    use brokk_bifrost_core::analyzer::resolution_facts::ALL_BINDING_PROJECTION_KINDS;
    use brokk_bifrost_core::analyzer::resolution_facts::ALL_RESOLUTION_ENGINE_RULE_KINDS;
    use brokk_bifrost_core::analyzer::resolution_facts::ALL_RESOLUTION_GAP_KINDS;
    use brokk_bifrost_core::analyzer::resolution_facts::BindingProjectionKind;
    use brokk_bifrost_core::analyzer::resolution_facts::DeclarationTypeRole;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberAccess;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberKind;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberQualifierCompatibility;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeSlotRole;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeTransferKind;
}
