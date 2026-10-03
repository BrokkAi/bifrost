use super::*;
use crate::analyzer::resolution::{
    BatchResolutionFragmentSource, BindingNodeKind, EndpointSignature, LoweredResolutionFragment,
    PartialPathId, PartialScopedSymbol, ResolutionCompletion, ResolutionIncompleteReason,
    StackPattern, WitnessStep,
};
use crate::analyzer::store::resolution_lexical::SelectedResolutionLexicalSource;
use crate::analyzer::store::resolution_selection::tests::SelectionFixture;
use rusqlite::params;

#[test]
fn continuation_projection_hydrates_full_runtime_path_through_production_reader() {
    let fixture = SelectionFixture::new(2);
    let selection = fixture.open_ready(&[]);
    let host = SelectedResolutionMountOrdinal::new(0);
    let fragment = BindingFragmentId::at_ordinal(host.get());
    let foreign = BindingNodeId::local(1, 17);
    let boundary = BindingNodeId::context_local((1 << 53) + 23);
    let path_id = PartialPathId::operation_local((1 << 53) + 29);
    let symbol = SemanticId::local(1, 31);
    let endpoint = EndpointSignature::new_scoped(
        foreign,
        StackPattern::closed(vec![PartialScopedSymbol::unscoped(symbol)]),
        StackPattern::closed(vec![foreign]),
    );
    let original = PartialPath::new(
        endpoint.clone(),
        endpoint,
        Vec::new(),
        vec![WitnessStep::Node(foreign)],
        ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnmountedFile { fragment }]),
    );
    let continuation = LoweredResolutionFragment::selected_include_continuation(
        fragment,
        boundary,
        path_id,
        BindingNodeKind::Scope,
        &original,
    );
    let expected = continuation.paths()[0].1.clone();
    let cancellation = CancellationToken::default();
    selection.with_owned_temp_write(|connection| {
        connection.execute(
            "INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(?1,?2,?3)",
            params![host.get(), [1u8; 32].as_slice(), [2u8; 32].as_slice()],
        )?;
        assert!(super::super::lexical::prepare_lexical_fragment(&continuation, &cancellation)
            .unwrap().insert(connection, connection.last_insert_rowid(), host, &cancellation)?);
        Ok(())
    }).unwrap();
    let candidate = CandidatePathIdentity::new(fragment, path_id);
    let source = SelectedResolutionLexicalSource::new_on_demand(&selection);
    assert_eq!(
        source
            .hydrate_candidate_paths(&[candidate], &cancellation)
            .unwrap(),
        vec![(candidate, expected)]
    );
    selection
        .with_owned_temp_write(|connection| {
            connection.execute(
                "DELETE FROM temp.selected_resolution_scope_mounts WHERE mount_ordinal=?1",
                [host.get()],
            )?;
            Ok(())
        })
        .unwrap();
    assert_eq!(
        hydrate_candidate_paths(&selection, &[candidate], &cancellation).unwrap(),
        Some(vec![None])
    );
    cancellation.cancel();
    assert!(
        hydrate_candidate_paths(&selection, &[candidate], &cancellation)
            .unwrap()
            .is_none()
    );
}

#[test]
fn candidate_pages_match_constructor_aggregate_on_empty_buckets_and_budget_breaks() {
    use crate::analyzer::resolution::{BatchCandidateRequest, PreloadedFragmentSource};
    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
    use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
    let fixture = SelectionFixture::new(1);
    let selection = fixture.open_ready(&[]);
    let fragment = BindingFragmentId::at_ordinal(0);
    let boundary = BindingNodeId::context_local((1 << 53) + 101);
    let target = BindingNodeId::operation_local((1 << 53) + 103);
    let endpoint =
        EndpointSignature::new_scoped(target, StackPattern::closed([]), StackPattern::closed([]));
    let path = PartialPath::new(
        endpoint.clone(),
        endpoint,
        Vec::new(),
        Vec::new(),
        ResolutionCompletion::Complete,
    );
    let lowered = LoweredResolutionFragment::selected_include_continuation(
        fragment,
        boundary,
        PartialPathId::operation_local((1 << 53) + 107),
        BindingNodeKind::Scope,
        &path,
    );
    let cancellation = CancellationToken::default();
    selection.with_owned_temp_write(|connection| {
        connection.execute("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(0,?1,?2)",params![[5u8;32].as_slice(),[6u8;32].as_slice()])?;
        assert!(super::super::lexical::prepare_lexical_fragment(&lowered,&cancellation).unwrap()
            .insert(connection,connection.last_insert_rowid(),SelectedResolutionMountOrdinal::new(0),&cancellation)?);
        Ok(())
    }).unwrap();
    let oracle =
        PreloadedFragmentSource::from_lowered_fragments_with_boundaries([boundary], [lowered]);
    let requests = [
        BatchCandidateRequest::new(
            0,
            EndpointSignature::new_scoped(
                BindingNodeId::universal_root(),
                StackPattern::closed([]),
                StackPattern::closed([]),
            ),
        ),
        BatchCandidateRequest::new(
            1,
            EndpointSignature::new_scoped(
                boundary,
                StackPattern::closed([]),
                StackPattern::closed([]),
            ),
        ),
        BatchCandidateRequest::new(
            2,
            EndpointSignature::new_scoped(
                boundary,
                StackPattern::closed([]),
                StackPattern::closed([]),
            ),
        ),
    ];
    let source = SelectedResolutionLexicalSource::new_on_demand(&selection);
    let combined_request = [BatchCandidateRequest::new(
        0,
        requests[1].endpoint().clone(),
    )];
    let mut combined = Vec::new();
    source
        .visit_forward_candidate_match_pages(&combined_request, &cancellation, &mut |page| {
            combined.extend_from_slice(page);
            Ok(true)
        })
        .unwrap();
    assert_eq!(
        combined,
        vec![crate::analyzer::resolution::BatchCandidateMatch::new(
            CandidatePathIdentity::new(fragment, PartialPathId::operation_local((1 << 53) + 107)),
            0,
        )]
    );
    for limit in 0..=8 {
        let budget = ReceiverAnalysisBudget {
            max_scope_nodes: limit,
            ..ReceiverAnalysisBudget::default()
        };
        let expected_session = ResolutionSession::bounded(budget, None);
        let actual_session = ResolutionSession::bounded(budget, None);
        let mut expected = Vec::new();
        oracle
            .visit_forward_candidate_match_pages_limited(
                &requests,
                16,
                Some(&expected_session),
                &cancellation,
                &mut |page| {
                    expected.extend_from_slice(page);
                    Ok(true)
                },
            )
            .unwrap();
        let mut actual = Vec::new();
        let terminal = visit_forward_candidates(
            &selection,
            &requests,
            None,
            16,
            Some(&actual_session),
            &cancellation,
            &mut |page| {
                actual.extend_from_slice(page);
                Ok(true)
            },
        )
        .unwrap();
        assert_eq!(actual, expected, "scope limit {limit}");
        assert_eq!(
            terminal,
            crate::analyzer::store::resolution_lexical::CandidatePageVisit::Exhausted,
            "budget exhaustion is not token cancellation at limit {limit}"
        );
    }
    let mut expected = Vec::new();
    oracle
        .visit_forward_candidate_match_pages_limited(
            &requests,
            1,
            None,
            &cancellation,
            &mut |page| {
                expected.extend_from_slice(page);
                Ok(false)
            },
        )
        .unwrap();
    let mut actual = Vec::new();
    let terminal = visit_forward_candidates(
        &selection,
        &requests,
        None,
        1,
        None,
        &cancellation,
        &mut |page| {
            actual.extend_from_slice(page);
            Ok(false)
        },
    )
    .unwrap();
    assert_eq!(actual, expected);
    assert_eq!(
        terminal,
        crate::analyzer::store::resolution_lexical::CandidatePageVisit::Stopped
    );
    let terminal = visit_forward_candidates(
        &selection,
        &requests,
        None,
        1,
        None,
        &cancellation,
        &mut |_| {
            cancellation.cancel();
            Ok(false)
        },
    )
    .unwrap();
    assert_eq!(
        terminal,
        crate::analyzer::store::resolution_lexical::CandidatePageVisit::Cancelled
    );
}

#[test]
fn scope_batch_preserves_catalog_host_and_absent_internal_scope() {
    use crate::analyzer::resolution::{
        ResolutionIdentityCatalogBuilder, ResolutionRegisteredIdentities, scope_head_node_identity,
        test_shared_names,
    };
    let fixture = SelectionFixture::new(2);
    let selection = fixture.open_ready(&[]);
    let cancellation = CancellationToken::default();
    let scope = ResolutionScopeId::new(7);
    let mut expected = Vec::new();
    for host in 0..2 {
        let fragment = BindingFragmentId::at_ordinal(host);
        let mut builder = ResolutionIdentityCatalogBuilder::new(fragment, test_shared_names());
        builder.source_scope_node(scope);
        let internal_identity = ResolutionNodeIdentity::new([host as u8 + 31; 32]);
        builder.node(internal_identity);
        let catalog = builder.finish();
        let module = BindingNodeId::operation_local((1 << 53) + u64::from(host) * 10 + 1);
        let internal = BindingNodeId::operation_local((1 << 53) + u64::from(host) * 10 + 2);
        let mut assigned = ResolutionRegisteredIdentities::new(fragment);
        assigned.assign_node(
            catalog
                .node_for_identity(scope_head_node_identity(scope))
                .unwrap(),
            module,
        );
        assigned.assign_node(
            catalog.node_for_identity(internal_identity).unwrap(),
            internal,
        );
        let catalog = catalog.retargeted(&assigned);
        selection.with_owned_temp_write(|connection| {
            connection.execute("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(?1,?2,?3)",params![host,[host as u8+41;32].as_slice(),[43u8;32].as_slice()])?;
            super::super::coordinates::PreparedStageCoordinates::new(&catalog, &[], &cancellation).unwrap()
                .insert(connection,connection.last_insert_rowid(),SelectedResolutionMountOrdinal::new(host))?;
            Ok(())
        }).unwrap();
        expected.push((fragment, module, internal));
    }
    let source = SelectedResolutionLexicalSource::new_on_demand(&selection);
    let scopes = source
        .node_scope_ordinals(
            expected
                .iter()
                .flat_map(|(_, module, internal)| [*module, *internal]),
            &cancellation,
        )
        .unwrap()
        .unwrap();
    for &(fragment, module, internal) in &expected {
        assert!(source.node_is_scope_head_in(&scopes, module, fragment, scope));
        assert!(!source.node_is_scope_head_in(&scopes, internal, fragment, scope));
        assert!(!source.node_is_scope_head_in(
            &scopes,
            module,
            BindingFragmentId::at_ordinal(1 - fragment.ordinal()),
            scope
        ));
        assert_eq!(
            source
                .scope_head_node_of(fragment, scope, &cancellation)
                .unwrap(),
            Some(module)
        );
    }
    selection.with_owned_temp_write(|connection| {
        connection.execute("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(1,?1,?2)",params![[51u8;32].as_slice(),[52u8;32].as_slice()])?;
        connection.execute("INSERT INTO temp.selected_resolution_stage_node_coordinates(host_ordinal,producer_id,dense_key,runtime_key,identity_digest,source_scope) VALUES(1,?1,0,?2,?3,7)",params![connection.last_insert_rowid(),codec::encode_node(expected[0].1),scope_head_node_identity(scope).digest().as_slice()])?;
        Ok(())
    }).unwrap();
    assert!(
        source
            .node_scope_ordinals([expected[0].1].into_iter(), &cancellation)
            .is_err()
    );
}

#[test]
fn mixed_scope_authority_requires_identity_and_scope_agreement() {
    let fixture = SelectionFixture::new(1);
    let selection = fixture.open_ready(&[]);
    let host = SelectedResolutionMountOrdinal::new(0);
    let mount = selection.mount_record_by_ordinal(host).unwrap();
    let (key,digest,scope):(u32,[u8;32],u32)=selection.connection().query_row(
        "SELECT local_key,identity_digest,source_scope FROM main.resolution_node_catalog WHERE blob_id=?1 AND source_scope IS NOT NULL ORDER BY local_key LIMIT 1",
        [mount.blob_id()],|row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
    ).unwrap();
    let node = BindingNodeId::local(0, key);
    let unknown = BindingNodeId::operation_local((1 << 53) + 999);
    selection.with_owned_temp_write(|connection| {
        connection.execute("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(0,?1,?2)",params![[61u8;32].as_slice(),[62u8;32].as_slice()])?;
        connection.execute("INSERT INTO temp.selected_resolution_stage_node_coordinates(host_ordinal,producer_id,dense_key,runtime_key,identity_digest,source_scope) VALUES(0,?1,0,?2,?3,?4)",params![connection.last_insert_rowid(),codec::encode_node(node),digest.as_slice(),scope])?;
        Ok(())
    }).unwrap();
    let source = SelectedResolutionLexicalSource::new_on_demand(&selection);
    let cancellation = CancellationToken::default();
    let nodes = [node, unknown, BindingNodeId::universal_root()];
    let scopes = source
        .node_scope_ordinals(nodes.into_iter(), &cancellation)
        .unwrap()
        .unwrap();
    assert_eq!(
        scopes[&node],
        Some((
            BindingFragmentId::at_ordinal(0),
            ResolutionScopeId::new(scope)
        ))
    );
    assert_eq!(scopes[&unknown], None);
    assert_eq!(scopes[&BindingNodeId::universal_root()], None);
    selection
        .with_owned_temp_write(|connection| {
            connection.execute(
                "UPDATE temp.selected_resolution_stage_node_coordinates SET source_scope=NULL",
                [],
            )?;
            Ok(())
        })
        .unwrap();
    assert!(
        source
            .node_scope_ordinals(nodes.into_iter(), &cancellation)
            .is_err()
    );
    let mut other_digest = digest;
    other_digest[0] ^= 1;
    selection.with_owned_temp_write(|connection| {
        connection.execute("UPDATE temp.selected_resolution_stage_node_coordinates SET source_scope=?1,identity_digest=?2",params![scope,other_digest.as_slice()])?;
        Ok(())
    }).unwrap();
    assert!(
        source
            .node_scope_ordinals(nodes.into_iter(), &cancellation)
            .is_err()
    );
}

#[test]
fn continuation_definition_uses_node_payload_without_semantic_site_metadata() {
    let fixture = SelectionFixture::new(1);
    let selection = fixture.open_ready(&[]);
    let fragment = BindingFragmentId::at_ordinal(0);
    let boundary = BindingNodeId::context_local((1 << 53) + 201);
    let definition = SemanticId::operation_local((1 << 53) + 203);
    let definition_node = BindingNodeId::operation_local((1 << 53) + 207);
    let endpoint = EndpointSignature::new_scoped(
        BindingNodeId::universal_root(),
        StackPattern::closed([]),
        StackPattern::closed([]),
    );
    let path = PartialPath::new(
        endpoint,
        EndpointSignature::new_scoped(
            definition_node,
            StackPattern::closed([]),
            StackPattern::closed([]),
        ),
        Vec::new(),
        Vec::new(),
        ResolutionCompletion::Complete,
    );
    let lowered = LoweredResolutionFragment::selected_include_continuation(
        fragment,
        boundary,
        PartialPathId::operation_local((1 << 53) + 205),
        BindingNodeKind::Definition(definition),
        &path,
    );
    let cancellation = CancellationToken::default();
    selection.with_owned_temp_write(|connection| {
        connection.execute("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(0,?1,?2)",params![[25u8;32].as_slice(),[26u8;32].as_slice()])?;
        assert!(super::super::lexical::prepare_lexical_fragment(&lowered,&cancellation).unwrap()
            .insert(connection,connection.last_insert_rowid(),SelectedResolutionMountOrdinal::new(0),&cancellation)?);
        let metadata: i64 = connection.query_row("SELECT count(*) FROM temp.selected_resolution_stage_semantics", [], |row| row.get(0))?;
        assert_eq!(metadata, 0);
        Ok(())
    }).unwrap();
    let source = SelectedResolutionLexicalSource::new_on_demand(&selection);
    assert_eq!(
        source
            .lookup_definition_node(definition, &cancellation)
            .unwrap(),
        Some(definition_node)
    );
    assert_eq!(
        source
            .classify_endpoint_nodes(&[definition_node], &cancellation)
            .unwrap(),
        vec![
            crate::analyzer::resolution::BatchEndpointClassification::new(
                definition_node,
                None,
                Some(definition)
            )
        ],
    );
    assert!(
        source
            .classify_endpoint_nodes(
                &[BindingNodeId::operation_local((1 << 53) + 299)],
                &cancellation
            )
            .is_err()
    );
}

#[test]
fn active_closure_removes_only_the_exact_unsupported_semantic() {
    let fixture = SelectionFixture::new(1);
    let selection = fixture.open_ready(&[]);
    let closed = SemanticId::operation_local((1 << 53) + 301);
    let other = SemanticId::operation_local((1 << 53) + 302);
    selection.with_owned_temp_write(|connection| {
        connection.execute("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(0,?1,?2)",params![[35u8;32].as_slice(),[36u8;32].as_slice()])?;
        connection.execute("INSERT INTO temp.selected_resolution_stage_closed_reasons(producer_id,semantic_key,semantic_shared) VALUES(?1,?2,NULL)",params![connection.last_insert_rowid(),codec::encode_semantic(closed)])?;
        Ok(())
    }).unwrap();
    let cancellation = CancellationToken::default();
    let source = SelectedResolutionLexicalSource::new_on_demand(&selection);
    let retained = [
        ResolutionIncompleteReason::UnsupportedSemantic(other),
        ResolutionIncompleteReason::UnmountedFile {
            fragment: BindingFragmentId::at_ordinal(0),
        },
    ];
    let completion = ResolutionCompletion::incomplete(
        retained
            .into_iter()
            .chain([ResolutionIncompleteReason::UnsupportedSemantic(closed)]),
    );
    assert_eq!(
        source.close_completion(&completion, &cancellation).unwrap(),
        Some(ResolutionCompletion::incomplete(retained))
    );
    assert_eq!(
        source
            .close_completion(
                &ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(closed)
                ]),
                &cancellation
            )
            .unwrap(),
        Some(ResolutionCompletion::Complete)
    );
    cancellation.cancel();
    assert!(
        source
            .close_completion(&completion, &cancellation)
            .unwrap()
            .is_none()
    );
}

#[test]
fn same_range_stage_locators_preserve_distinct_capsule_identities() {
    let fixture = SelectionFixture::custom_source(1, "class A { int x; int f() { return x; } }");
    let selection = fixture.open_ready(&[]);
    let cancellation = CancellationToken::default();
    let mount = &selection.mounts().unwrap()[0];
    let (ordinary_site,start,end): (u32,usize,usize) = selection.connection().query_row(
        "SELECT site,start_byte,end_byte FROM resolution_sites WHERE blob_id=?1 AND role=0 AND start_byte IS NOT NULL ORDER BY site LIMIT 1",
        [mount.blob_id()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
    ).unwrap();
    let source = SelectedResolutionLexicalSource::new_on_demand(&selection);
    let session =
        brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession::unbounded();
    let ordinary_locator = crate::analyzer::resolution::SelectedSemanticLocator::new(
        mount.storage_language(),
        mount.persisted_relative_path(),
        brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId::new(ordinary_site),
        crate::analyzer::resolution::LoweredSemanticRole::Reference,
    );
    let ordinary_before = source
        .lookup_semantic_sites(&ordinary_locator, &cancellation, &session)
        .unwrap();
    let first = SemanticId::operation_local((1 << 53) + 401);
    let second = SemanticId::operation_local((1 << 53) + 402);
    let first_node = BindingNodeId::operation_local((1 << 53) + 403);
    let second_node = BindingNodeId::operation_local((1 << 53) + 404);
    selection.with_owned_temp_write(|connection| {
        for (sequence,(semantic,node)) in [(first,first_node),(second,second_node)].into_iter().enumerate() {
            connection.execute("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(0,?1,?2)",params![[45+sequence as u8;32].as_slice(),[46u8;32].as_slice()])?;
            connection.execute("INSERT INTO temp.selected_resolution_stage_semantics(host_ordinal,producer_id,sequence,semantic_key,node,source_site,role,namespace,start_byte,end_byte,owner_kind) VALUES(0,?1,0,?2,?3,?4,0,0,?5,?6,0)",params![connection.last_insert_rowid(),codec::encode_semantic(semantic),codec::encode_node(node),ordinary_site,start as i64,end as i64])?;
        }
        Ok(())
    }).unwrap();
    let rows = semantic_sites_at_range(
        &selection,
        SelectedResolutionMountOrdinal::new(0),
        start,
        end,
        crate::analyzer::resolution::LoweredSemanticRole::Reference,
        &cancellation,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        rows.iter()
            .map(|(semantic, node, _)| (*semantic, *node))
            .collect::<Vec<_>>(),
        vec![(first, first_node), (second, second_node)]
    );
    assert_eq!(
        source
            .lookup_semantic_sites(&ordinary_locator, &cancellation, &session)
            .unwrap(),
        ordinary_before
    );
    let range_locator = crate::analyzer::resolution::SelectedSemanticLocator::for_reference_range(
        mount.storage_language(),
        mount.persisted_relative_path(),
        start,
        end,
    );
    let crate::analyzer::store::resolution_lexical::SelectedSemanticLookupOutcome::Found(rows) =
        source
            .lookup_semantic_sites(&range_locator, &cancellation, &session)
            .unwrap()
    else {
        panic!("stage range alternatives must be visible");
    };
    assert_eq!(
        rows.iter().map(|row| row.semantic()).collect::<Vec<_>>(),
        vec![first, second]
    );
}

#[test]
fn stage_lexical_declaration_preserves_source_ranges_and_host_scope() {
    let fixture = SelectionFixture::new(2);
    let selection = fixture.open_ready(&[]);
    let semantic = SemanticId::operation_local((1 << 53) + 501);
    let cancellation = CancellationToken::default();
    selection.with_owned_temp_write(|connection| {
        connection.execute("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(1,?1,?2)",params![[55u8;32].as_slice(),[56u8;32].as_slice()])?;
        connection.execute("INSERT INTO temp.selected_resolution_stage_declarations(host_ordinal,producer_id,semantic_key,identifier,kind,name_start_byte,name_end_byte,name_start_line,name_end_line,declaration_start_byte,declaration_end_byte,declaration_start_line,declaration_end_line) VALUES(1,?1,?2,'captured','local_variable',101,109,7,7,97,120,6,8)",params![connection.last_insert_rowid(),codec::encode_semantic(semantic)])?;
        Ok(())
    }).unwrap();
    let source = SelectedResolutionLexicalSource::new_on_demand(&selection);
    let rows = source
        .stage_lexical_definitions(
            &[
                (SelectedResolutionMountOrdinal::new(0), semantic),
                (SelectedResolutionMountOrdinal::new(1), semantic),
            ],
            &cancellation,
        )
        .unwrap()
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, semantic);
    let declaration = &rows[0].1;
    assert_eq!(declaration.identifier, "captured");
    assert!(declaration.source_file.is_none());
    assert_eq!(
        declaration.name_range,
        crate::analyzer::Range {
            start_byte: 101,
            end_byte: 109,
            start_line: 7,
            end_line: 7
        }
    );
    assert_eq!(
        declaration.declaration_range,
        crate::analyzer::Range {
            start_byte: 97,
            end_byte: 120,
            start_line: 6,
            end_line: 8
        }
    );
}

#[test]
fn candidate_completion_keeps_inventory_and_full_runtime_lookup_buckets() {
    use crate::analyzer::resolution::{BatchCandidateRequest, LoweredCandidateDirection};
    let fixture = SelectionFixture::new(2);
    let selection = fixture.open_ready(&[]);
    let endpoint = BindingNodeId::operation_local((1 << 53) + 601);
    let lookup = SemanticId::operation_local((1 << 53) + 602);
    let fragment_reason = SemanticId::operation_local((1 << 53) + 603);
    let inventory_reason = SemanticId::operation_local((1 << 53) + 604);
    let unkeyed_reason = SemanticId::operation_local((1 << 53) + 605);
    let lookup_reason = SemanticId::operation_local((1 << 53) + 606);
    selection.with_owned_temp_write(|connection| {
        connection.execute("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(1,?1,?2)",params![[65u8;32].as_slice(),[66u8;32].as_slice()])?;
        let producer = connection.last_insert_rowid();
        for (covers,reason,node,key) in [
            (0,fragment_reason,None,None),
            (2,inventory_reason,None,None),
            (5,unkeyed_reason,Some(codec::encode_node(endpoint)),None),
            (5,lookup_reason,Some(codec::encode_node(endpoint)),Some(codec::encode_semantic(lookup))),
        ] {
            connection.execute("INSERT INTO temp.selected_resolution_stage_gaps(host_ordinal,producer_id,covers,gap_key,reason_key,endpoint_node,lookup_key,source_site,origin) VALUES(1,?1,?2,?3,?3,?4,?5,0,0)",params![producer,covers,codec::encode_semantic(reason),node,key])?;
        }
        Ok(())
    }).unwrap();
    let requests = [
        BatchCandidateRequest::new(
            0,
            EndpointSignature::new_scoped(
                endpoint,
                StackPattern::closed([]),
                StackPattern::closed([]),
            ),
        ),
        BatchCandidateRequest::new(
            1,
            EndpointSignature::new_scoped(
                endpoint,
                StackPattern::closed([PartialScopedSymbol::unscoped(lookup)]),
                StackPattern::closed([]),
            ),
        ),
    ];
    let cancellation = CancellationToken::default();
    let result = candidate_completion(
        &selection,
        LoweredCandidateDirection::Forward,
        &requests,
        None,
        &[],
        &cancellation,
    )
    .unwrap();
    let reason = ResolutionIncompleteReason::UnsupportedSemantic;
    assert_eq!(
        result.unconditional_completion(),
        &ResolutionCompletion::incomplete([reason(fragment_reason), reason(inventory_reason)])
    );
    assert_eq!(
        result.branch_completions(),
        &[
            ResolutionCompletion::incomplete([reason(unkeyed_reason)]),
            ResolutionCompletion::incomplete([reason(unkeyed_reason), reason(lookup_reason)]),
        ]
    );
    let source = SelectedResolutionLexicalSource::new_on_demand(&selection);
    let combined = source
        .visit_forward_candidate_match_pages(&requests, &cancellation, &mut |_| Ok(false))
        .unwrap();
    assert!(
        combined
            .unconditional_completion()
            .contains_reason(reason(fragment_reason))
    );
    assert!(
        combined
            .unconditional_completion()
            .contains_reason(reason(inventory_reason))
    );
    assert!(combined.branch_completions()[0].contains_reason(reason(unkeyed_reason)));
    assert!(!combined.branch_completions()[0].contains_reason(reason(lookup_reason)));
    assert!(combined.branch_completions()[1].contains_reason(reason(lookup_reason)));
    let excluded = candidate_completion(
        &selection,
        LoweredCandidateDirection::Forward,
        &requests,
        Some(&[SelectedResolutionMountOrdinal::new(0)]),
        &[],
        &cancellation,
    )
    .unwrap();
    assert_eq!(
        excluded.unconditional_completion(),
        &ResolutionCompletion::Complete
    );
    assert!(
        excluded
            .branch_completions()
            .iter()
            .all(|completion| completion == &ResolutionCompletion::Complete)
    );
    selection.with_owned_temp_write(|connection| {
        connection.execute("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(0,?1,?2)",params![[79u8;32].as_slice(),[80u8;32].as_slice()])?;
        let producer = connection.last_insert_rowid();
        connection.execute("INSERT INTO temp.selected_resolution_stage_gaps(host_ordinal,producer_id,covers,gap_key,reason_key,endpoint_node,source_site,origin) VALUES(0,?1,6,?2,?3,?4,0,0)",params![producer,codec::encode_semantic(SemanticId::operation_local(907)),codec::encode_semantic(unkeyed_reason),codec::encode_node(endpoint)])?;
        connection.execute("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(1,?1,?2)",params![[81u8;32].as_slice(),[82u8;32].as_slice()])?;
        let producer = connection.last_insert_rowid();
        connection.execute("INSERT INTO temp.selected_resolution_stage_gaps(host_ordinal,producer_id,covers,gap_key,reason_key,endpoint_node,source_site,origin) VALUES(1,?1,6,?2,?3,?4,0,0)",params![producer,codec::encode_semantic(SemanticId::operation_local(908)),codec::encode_semantic(unkeyed_reason),codec::encode_node(endpoint)])?;
        Ok(())
    }).unwrap();
    let excluded = [
        crate::analyzer::resolution::ReverseCandidateGapIdentity::new(
            BindingFragmentId::at_ordinal(1),
            SemanticId::operation_local(908),
        ),
    ];
    for (scope, expected) in [
        (
            vec![SelectedResolutionMountOrdinal::new(0)],
            ResolutionCompletion::incomplete([reason(unkeyed_reason)]),
        ),
        (
            vec![SelectedResolutionMountOrdinal::new(1)],
            ResolutionCompletion::Complete,
        ),
    ] {
        let actual = candidate_completion(
            &selection,
            LoweredCandidateDirection::Reverse,
            &requests,
            Some(&scope),
            &excluded,
            &cancellation,
        )
        .unwrap();
        assert_eq!(actual.branch_completions(), &[expected.clone(), expected]);
    }
    let retained_fragment_reason = SemanticId::operation_local(909);
    selection.with_owned_temp_write(|connection| {
        connection.execute("INSERT INTO temp.selected_resolution_stage_closed_reasons(producer_id,semantic_key) SELECT producer_id,?1 FROM temp.selected_resolution_stage_producers WHERE host_ordinal=1 LIMIT 1",[codec::encode_semantic(fragment_reason)])?;
        connection.execute("INSERT INTO temp.selected_resolution_stage_gaps(host_ordinal,producer_id,covers,gap_key,reason_key,source_site,origin) SELECT 1,producer_id,0,?1,?1,0,0 FROM temp.selected_resolution_stage_producers WHERE host_ordinal=1 LIMIT 1",[codec::encode_semantic(retained_fragment_reason)])?;
        Ok(())
    }).unwrap();
    let source = SelectedResolutionLexicalSource::new_on_demand(&selection);
    let mut source_plan =
        crate::analyzer::resolution::ReverseCandidateGapExclusionPlan::new(excluded);
    for (host, expected) in [
        (
            0,
            ResolutionCompletion::incomplete([reason(unkeyed_reason)]),
        ),
        (1, ResolutionCompletion::Complete),
    ] {
        let (actual, cancelled) = source
            .reverse_completion_with_exclusions(
                &requests,
                Some(&[SelectedResolutionMountOrdinal::new(host)]),
                &mut source_plan,
                &cancellation,
            )
            .unwrap();
        assert!(!cancelled);
        assert_eq!(actual.branch_completions(), &[expected.clone(), expected]);
    }
    let (decoded, observed) = raw_reverse_candidate_rows(
        &selection,
        &requests,
        &excluded,
        Some(&[SelectedResolutionMountOrdinal::new(1)]),
        &cancellation,
    )
    .unwrap();
    assert!(!observed);
    let interrupted = CancellationToken::default();
    interrupted.cancel();
    for certified in [&[][..], &excluded[..]] {
        let (answer, cancelled) =
            crate::analyzer::store::resolution_lexical::finish_reverse_evidence(
                decoded.clone(),
                certified,
                &requests,
                &interrupted,
            )
            .unwrap();
        assert!(cancelled);
        assert!(
            !answer
                .unconditional_completion()
                .contains_reason(reason(fragment_reason)),
            "known closed raw reason never returns on cancellation"
        );
        assert!(
            answer
                .unconditional_completion()
                .contains_reason(reason(retained_fragment_reason))
        );
        assert!(
            answer
                .unconditional_completion()
                .contains_reason(ResolutionIncompleteReason::Cancelled)
        );
        let branch = if certified.is_empty() {
            ResolutionCompletion::incomplete([reason(unkeyed_reason)])
        } else {
            ResolutionCompletion::Complete
        };
        assert_eq!(
            answer.branch_completions(),
            &[branch.clone(), branch],
            "only certified exact exclusions apply after interruption"
        );
    }
    let mut saw_cancelled = false;
    let mut saw_complete = false;
    for checks in 0..=128 {
        let interrupted = CancellationToken::cancel_after_checks_for_test(checks);
        let (answer, cancelled) = source
            .reverse_completion_with_exclusions(
                &requests,
                Some(&[SelectedResolutionMountOrdinal::new(1)]),
                &mut source_plan,
                &interrupted,
            )
            .unwrap();
        saw_cancelled |= cancelled;
        saw_complete |= !cancelled;
        assert!(
            !answer
                .unconditional_completion()
                .contains_reason(reason(fragment_reason))
        );
        assert!(
            answer
                .branch_completions()
                .iter()
                .all(|branch| branch == &ResolutionCompletion::Complete),
            "reused certified exclusions remain valid when checks={checks}"
        );
        let mut fresh =
            crate::analyzer::resolution::ReverseCandidateGapExclusionPlan::new(excluded);
        let interrupted = CancellationToken::cancel_after_checks_for_test(checks);
        let (answer, _) = source
            .reverse_completion_with_exclusions(
                &requests,
                Some(&[SelectedResolutionMountOrdinal::new(1)]),
                &mut fresh,
                &interrupted,
            )
            .unwrap();
        assert!(
            !answer
                .unconditional_completion()
                .contains_reason(reason(fragment_reason))
        );
        if !fresh
            .needs_preparation_for_authority(selection.candidate_coverage_fingerprint())
            .unwrap()
        {
            assert!(
                answer
                    .branch_completions()
                    .iter()
                    .all(|branch| branch == &ResolutionCompletion::Complete)
            );
        }
    }
    assert!(saw_cancelled && saw_complete);
    let (raw, cancelled) =
        raw_reverse_candidate_rows(&selection, &requests, &excluded, None, &cancellation).unwrap();
    assert!(!cancelled);
    assert!(
        raw.iter().any(|row| row.gap.is_none()),
        "raw evidence includes stage fragment coverage"
    );
    let raw = raw
        .into_iter()
        .filter_map(|row| row.gap)
        .collect::<Vec<_>>();
    assert_eq!(raw.len(), 2);
    let mut builder = crate::analyzer::resolution::ReverseCandidateGapCoverageBuilder::default();
    for row in &raw {
        builder.push(*row).unwrap();
    }
    let (coverage, cancelled) = builder.finish(&cancellation).unwrap();
    assert!(!cancelled);
    let mut plan = crate::analyzer::resolution::ReverseCandidateGapExclusionPlan::new(excluded);
    assert!(
        coverage
            .prepare_exclusions(&mut plan, &cancellation)
            .unwrap()
    );
    selection
        .with_owned_temp_write(|connection| {
            connection.execute("DELETE FROM temp.selected_resolution_scope_mounts", [])?;
            Ok(())
        })
        .unwrap();
    let (mut narrowed, cancelled) =
        raw_reverse_candidate_rows(&selection, &requests, &excluded, None, &cancellation).unwrap();
    assert!(!cancelled);
    assert!(narrowed.iter().all(|row| !row.eligible));
    let mut narrowed = narrowed
        .drain(..)
        .filter_map(|row| row.gap)
        .collect::<Vec<_>>();
    let mut expected = raw;
    expected.sort_unstable_by_key(|row| row.identity());
    narrowed.sort_unstable_by_key(|row| row.identity());
    assert_eq!(
        narrowed, expected,
        "raw exclusion proof does not depend on current selected scope"
    );
    let mut builder = crate::analyzer::resolution::ReverseCandidateGapCoverageBuilder::default();
    for row in narrowed {
        builder.push(row).unwrap();
    }
    let (coverage, cancelled) = builder.finish(&cancellation).unwrap();
    assert!(!cancelled);
    assert!(
        coverage
            .prepare_exclusions(&mut plan, &cancellation)
            .unwrap()
    );
    let (empty, cancelled) = source
        .reverse_completion_with_exclusions(&requests, None, &mut source_plan, &cancellation)
        .unwrap();
    assert!(!cancelled);
    assert_eq!(
        empty.unconditional_completion(),
        &ResolutionCompletion::Complete
    );
    assert!(
        empty
            .branch_completions()
            .iter()
            .all(|completion| completion == &ResolutionCompletion::Complete)
    );
    super::super::SelectedResolutionStage::new(&selection)
        .clear_facts()
        .unwrap();
    assert!(
        source
            .reverse_completion_with_exclusions(&requests, None, &mut source_plan, &cancellation)
            .is_err(),
        "changed committed stage authority rejects an old plan"
    );
}

#[test]
fn macro_head_reference_seed_exists_without_semantic_metadata() {
    let fixture = SelectionFixture::new(2);
    let selection = fixture.open_ready(&[]);
    let reference = SemanticId::operation_local((1 << 53) + 701);
    let node = BindingNodeId::operation_local((1 << 53) + 702);
    let fragment = BindingFragmentId::at_ordinal(0);
    let lowered = LoweredResolutionFragment::selected_macro_head_bridge(
        fragment,
        reference,
        node,
        BindingNodeId::local(0, 3),
        PartialPathId::operation_local((1 << 53) + 703),
    );
    let cancellation = CancellationToken::default();
    selection.with_owned_temp_write(|connection| {
        connection.execute("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(0,?1,?2)",params![[75u8;32].as_slice(),[76u8;32].as_slice()])?;
        assert!(super::super::lexical::prepare_lexical_fragment(&lowered,&cancellation).unwrap().insert(connection,connection.last_insert_rowid(),SelectedResolutionMountOrdinal::new(0),&cancellation)?);
        Ok(())
    }).unwrap();
    let rows = reference_seed_rows(
        &selection,
        &[crate::analyzer::resolution::ResolutionQuery::new(reference)],
        &cancellation,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        rows,
        vec![Some(ReferenceSeedRow {
            host: fragment,
            node,
            metadata: None
        })]
    );
    let source = SelectedResolutionLexicalSource::new_on_demand(&selection);
    let result = source
        .lookup_reference_seeds(
            &[crate::analyzer::resolution::ResolutionQuery::new(reference)],
            &cancellation,
        )
        .unwrap();
    let seed = result.rows()[0]
        .seed()
        .expect("actual macro reference payload has a seed");
    assert_eq!(seed.node(), node);
    assert_eq!(seed.fragment(), fragment);
    assert_eq!(seed.site_metadata(), None);
    let empty_host_reason = SemanticId::operation_local((1 << 53) + 704);
    selection.with_owned_temp_write(|connection| {
        connection.execute("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(1,?1,?2)", params![[77u8;32].as_slice(),[78u8;32].as_slice()])?;
        connection.execute("INSERT INTO temp.selected_resolution_stage_gaps(host_ordinal,producer_id,covers,gap_key,reason_key,source_site,origin) VALUES(1,?1,1,?2,?2,0,0)", params![connection.last_insert_rowid(),codec::encode_semantic(empty_host_reason)])?;
        Ok(())
    }).unwrap();
    let stopped = source
        .visit_reference_seed_batches(1, &cancellation, &mut |_| Ok(false))
        .unwrap();
    assert!(
        stopped.contains_reason(ResolutionIncompleteReason::UnsupportedSemantic(
            empty_host_reason
        )),
        "early visitor stop retains inventory gaps from a host with no stage references"
    );
    let mut found = false;
    source
        .visit_reference_seed_batches(
            crate::analyzer::resolution::MAX_REFERENCE_SEEDS_PER_BATCH,
            &cancellation,
            &mut |batch| {
                found |= batch.seeds().iter().any(|seed| seed.node() == node);
                Ok(true)
            },
        )
        .unwrap();
    assert!(
        found,
        "inventory includes an unsited stage Reference across multiple hosts"
    );
}

#[test]
fn terminal_demands_find_complete_stage_paths_in_request_shared_domain() {
    use crate::analyzer::resolution::SharedNameInterner;
    let fixture = SelectionFixture::new(2);
    let selection = fixture.open_ready(&[]);
    let cancellation = CancellationToken::default();
    let name = selection
        .shared_name_table()
        .interner(selection.connection())
        .intern([193; 32]);
    assert!(
        !name.is_interned(),
        "a new digest belongs to the request shared domain"
    );
    let demand = SemanticId::shared_name(name);
    let path_id = PartialPathId::operation_local((1 << 53) + 914);
    let anchor = SemanticId::operation_local((1 << 53) + 915);
    let token = SemanticId::operation_local((1 << 53) + 916);
    let terminal_symbols = [anchor, token, demand].map(PartialScopedSymbol::unscoped);
    let mut expected = Vec::new();
    for host in [0, 1] {
        let fragment = BindingFragmentId::at_ordinal(host);
        let node = BindingNodeId::operation_local((1 << 53) + 920 + u64::from(host));
        let original = PartialPath::new(
            EndpointSignature::new_scoped(node, StackPattern::closed([]), StackPattern::closed([])),
            EndpointSignature::new_scoped(
                BindingNodeId::universal_root(),
                StackPattern::closed(terminal_symbols.clone()),
                StackPattern::closed([]),
            ),
            vec![crate::analyzer::resolution::PrecedenceStep {
                tier: crate::analyzer::structural::PrecedenceTier::PackageOrModule,
                ordinal: 0,
                semantic: token,
            }],
            vec![WitnessStep::Node(BindingNodeId::universal_root())],
            ResolutionCompletion::Complete,
        );
        let lowered = LoweredResolutionFragment::selected_include_continuation(
            fragment,
            node,
            path_id,
            BindingNodeKind::Scope,
            &original,
        );
        selection.with_owned_temp_write(|connection| {
            connection.execute("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(?1,?2,?3)",params![host,[91u8;32].as_slice(),[92u8;32].as_slice()])?;
            assert!(super::super::lexical::prepare_lexical_fragment(&lowered,&cancellation).unwrap().insert(connection,connection.last_insert_rowid(),SelectedResolutionMountOrdinal::new(host),&cancellation)?);
            if host == 0 {
                let identity = crate::analyzer::resolution::root_import_anchor_semantic_identity(
                    brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootImportAnchor::Lexical,
                );
                connection.execute("INSERT INTO temp.selected_resolution_stage_semantic_coordinates(host_ordinal,producer_id,dense_key,runtime_key,identity_digest) VALUES(0,?1,0,?2,?3)", params![connection.last_insert_rowid(),codec::encode_semantic(anchor),identity.fragment_local_digest().as_slice()])?;
            }
            Ok(())
        }).unwrap();
        expected.push(CandidatePathIdentity::new(fragment, path_id));
    }
    assert_eq!(
        root_terminal_candidates(&selection, &[demand, demand], &cancellation)
            .unwrap()
            .unwrap(),
        expected
    );
    let source = SelectedResolutionLexicalSource::new_on_demand(&selection);
    let paths = source
        .hydrate_candidate_paths(&expected, &cancellation)
        .unwrap();
    assert_eq!(paths.len(), 2);
    for (_, path) in paths {
        assert_eq!(path.end().node(), BindingNodeId::universal_root());
        assert_eq!(path.end().symbols().fixed(), &terminal_symbols);
        assert_eq!(path.end().symbols().tail(), None);
        assert_eq!(
            path.end().symbols().fixed().last().unwrap().symbol(),
            demand
        );
    }
    let mut actual = Vec::new();
    let mut receive = |halves: &[crate::analyzer::resolution::SelectedRootPathHalf]| {
        for half in halves {
            match half {
                crate::analyzer::resolution::SelectedRootPathHalf::Reference {
                    identity,
                    demand: found,
                    ..
                } => {
                    assert_eq!(*found, demand);
                    actual.push(*identity);
                }
                other => panic!("unexpected terminal half {other:?}"),
            }
        }
        Ok(true)
    };
    source
        .visit_root_import_half_pages_for_demands(
            &[demand],
            &cancellation,
            &mut crate::analyzer::resolution::FactPageVisitor::new(&mut receive),
        )
        .unwrap();
    assert_eq!(actual, expected);
    selection
        .with_owned_temp_write(|connection| {
            connection.execute(
                "DELETE FROM temp.selected_resolution_scope_mounts WHERE mount_ordinal=1",
                [],
            )?;
            Ok(())
        })
        .unwrap();
    expected.truncate(1);
    assert_eq!(
        root_terminal_candidates(&selection, &[demand], &cancellation)
            .unwrap()
            .unwrap(),
        expected
    );
}

#[test]
fn stage_type_slot_without_rules_keeps_other_host_fragment_coverage() {
    use crate::analyzer::resolution::{
        ResolutionIdentityCatalogBuilder, ResolutionRegisteredIdentities, test_shared_names,
    };
    let fixture = SelectionFixture::new(2);
    let selection = fixture.open_ready(&[]);
    let cancellation = CancellationToken::default();
    let fragment = BindingFragmentId::at_ordinal(0);
    let slot = SemanticId::operation_local((1 << 53) + 931);
    let reason = SemanticId::operation_local((1 << 53) + 932);
    let identity = ResolutionSemanticIdentity::fragment_local([93u8; 32]);
    let mut builder = ResolutionIdentityCatalogBuilder::new(fragment, test_shared_names());
    let original = builder.semantic(identity);
    let catalog = builder.finish();
    let mut assigned = ResolutionRegisteredIdentities::new(fragment);
    assigned.assign_semantic(original, slot);
    let catalog = catalog.retargeted(&assigned);
    selection.with_owned_temp_write(|connection| {
        connection.execute("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(0,?1,?2)",params![[94u8;32].as_slice(),[95u8;32].as_slice()])?;
        super::super::coordinates::PreparedStageCoordinates::new(&catalog, &[], &cancellation).unwrap().insert(connection,connection.last_insert_rowid(),SelectedResolutionMountOrdinal::new(0))?;
        connection.execute("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(1,?1,?2)",params![[96u8;32].as_slice(),[97u8;32].as_slice()])?;
        connection.execute("INSERT INTO temp.selected_resolution_stage_gaps(host_ordinal,producer_id,covers,gap_key,reason_key,source_site,origin) VALUES(1,?1,0,?2,?2,0,0)",params![connection.last_insert_rowid(),codec::encode_semantic(reason)])?;
        Ok(())
    }).unwrap();
    let ordinary=SemanticId::local(0,selection.connection().query_row("SELECT catalog.local_key FROM temp.selected_resolution_mounts mount JOIN main.resolution_semantic_catalog catalog ON catalog.blob_id=mount.blob_id WHERE mount.mount_ordinal=0 AND catalog.shared_identity IS NULL LIMIT 1",[],|row| row.get(0)).unwrap());
    let source = SelectedResolutionLexicalSource::new_on_demand(&selection);
    for requested in [
        slot,
        SemanticId::shared_name(crate::analyzer::resolution::SharedNameId::per_request(933)),
    ] {
        let completion = source
            .visit_type_transfer_rules(requested, &cancellation, &mut |_| {
                panic!("fixture declares no type transfer rules")
            })
            .unwrap();
        assert_eq!(
            completion,
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                reason
            )])
        );
    }
    assert_eq!(
        source
            .visit_type_transfer_rules(ordinary, &cancellation, &mut |_| Ok(true))
            .unwrap(),
        ResolutionCompletion::Complete
    );
    selection
        .with_owned_temp_write(|connection| {
            connection.execute(
                "DELETE FROM temp.selected_resolution_scope_mounts WHERE mount_ordinal=1",
                [],
            )?;
            Ok(())
        })
        .unwrap();
    assert_eq!(
        source
            .visit_type_transfer_rules(slot, &cancellation, &mut |_| Ok(true))
            .unwrap(),
        ResolutionCompletion::Complete
    );
    cancellation.cancel();
    assert!(
        source
            .visit_type_transfer_rules(slot, &cancellation, &mut |_| Ok(true))
            .unwrap()
            .contains_reason(ResolutionIncompleteReason::Cancelled)
    );
}

#[test]
fn context_readers_preserve_token_scope_coarse_stream_and_pending_page_budget() {
    use crate::analyzer::resolution::{
        BatchCandidateCompletionOutcome, BatchCandidateRequest, SelectedContextPathSource,
        SharedNameId,
    };
    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
    use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
    let fixture = SelectionFixture::new(2);
    let selection = fixture.open_ready(&[]);
    let live = CancellationToken::default();
    let node = BindingNodeId::context_local((1 << 53) + 950);
    let name = SemanticId::shared_name(SharedNameId::per_request(951));
    let other = SemanticId::shared_name(SharedNameId::per_request(952));
    let make_path = |symbols, reason| {
        PartialPath::new(
            EndpointSignature::new_scoped(
                node,
                StackPattern::closed([PartialScopedSymbol::unscoped(other)]),
                StackPattern::closed([]),
            ),
            EndpointSignature::new_scoped(
                BindingNodeId::universal_root(),
                symbols,
                StackPattern::closed([]),
            ),
            Vec::new(),
            Vec::new(),
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                SemanticId::context_local(reason),
            )]),
        )
    };
    let paths = [
        make_path(
            StackPattern::closed([PartialScopedSymbol::scoped(
                name,
                StackPattern::closed([BindingNodeId::local(1, 3)]),
            )]),
            953,
        ),
        make_path(StackPattern::closed([]), 954),
        make_path(
            StackPattern::closed([PartialScopedSymbol::unscoped(other)]),
            955,
        ),
    ];
    let identities = (0..3)
        .map(|index| {
            CandidatePathIdentity::new(
                BindingFragmentId::at_ordinal(index % 2),
                PartialPathId::context_local((1 << 53) + 960 + u64::from(index)),
            )
        })
        .collect::<Vec<_>>();
    let stage = super::super::SelectedResolutionStage::new(&selection);
    let first = stage
        .publish_context_paths(&live, |writer| {
            for (identity, path) in identities.iter().zip(&paths) {
                assert!(writer.insert(*identity, path)?);
            }
            Ok(true)
        })
        .unwrap()
        .unwrap();
    let different = make_path(StackPattern::closed([]), 970);
    let second = stage
        .publish_context_paths(&live, |writer| writer.insert(identities[0], &different))
        .unwrap()
        .unwrap();
    let source = SelectedResolutionLexicalSource::new_on_demand(&selection);
    selection
        .with_owned_temp_write(|connection| {
            connection.execute("DELETE FROM temp.selected_resolution_scope_mounts", [])?;
            Ok(())
        })
        .unwrap();
    let all = source.context_paths(first, &live).unwrap().unwrap();
    assert_eq!(all.len(), 3);
    assert_eq!(
        source
            .hydrate_context_paths(second, &[identities[0]], &live)
            .unwrap()
            .unwrap(),
        vec![(identities[0], different)]
    );
    assert_eq!(
        source
            .hydrate_context_paths(first, &[identities[1], identities[0], identities[1]], &live)
            .unwrap()
            .unwrap(),
        vec![
            (identities[1], paths[1].clone()),
            (identities[0], paths[0].clone())
        ]
    );
    let base_reason =
        ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::context_local(980));
    let base = || {
        BatchCandidateCompletionOutcome::new(
            1,
            ResolutionCompletion::incomplete([base_reason]),
            [ResolutionCompletion::Complete],
        )
    };
    let forward = [BatchCandidateRequest::new(
        0,
        EndpointSignature::new_scoped(
            node,
            StackPattern::closed([PartialScopedSymbol::unscoped(name)]),
            StackPattern::closed([]),
        ),
    )];
    let reverse = [BatchCandidateRequest::new(
        0,
        EndpointSignature::new_scoped(
            BindingNodeId::universal_root(),
            StackPattern::closed([PartialScopedSymbol::unscoped(name)]),
            StackPattern::closed([]),
        ),
    )];
    let mut found = Vec::new();
    let result = source
        .visit_context_forward_additions(first, &forward, base(), 2, &live, None, &mut |page| {
            found.extend(page.iter().map(|matched| matched.candidate()));
            Ok(true)
        })
        .unwrap();
    let mut expected = identities.clone();
    expected.sort_unstable();
    assert_eq!(
        found, expected,
        "nonroot coarse stream ignores fixed symbol mismatch and selected scope"
    );
    assert_eq!(
        result.unconditional_completion(),
        base().unconditional_completion()
    );
    found.clear();
    source
        .visit_context_reverse_additions(first, &reverse, base(), 2, &live, None, &mut |page| {
            found.extend(page.iter().map(|matched| matched.candidate()));
            Ok(true)
        })
        .unwrap();
    let mut expected = identities[..2].to_vec();
    expected.sort_unstable();
    assert_eq!(
        found, expected,
        "root coarse stream ignores scoped mismatch and includes no-fixed wildcard"
    );
    let session = ResolutionSession::bounded(
        ReceiverAnalysisBudget {
            max_scope_nodes: 1,
            ..ReceiverAnalysisBudget::default()
        },
        None,
    );
    found.clear();
    let stopped = source
        .visit_context_forward_additions(
            first,
            &forward,
            base(),
            2,
            &live,
            Some(&session),
            &mut |page| {
                found.extend(page.iter().map(|matched| matched.candidate()));
                Ok(true)
            },
        )
        .unwrap();
    assert!(found.is_empty(), "budget break drops pending context page");
    assert!(
        stopped
            .unconditional_completion()
            .contains_reason(base_reason)
    );
    assert!(
        stopped
            .unconditional_completion()
            .contains_reason(ResolutionIncompleteReason::Cancelled)
    );
    let mut callbacks = 0;
    let stopped = source
        .visit_context_forward_additions(first, &forward, base(), 1, &live, None, &mut |_| {
            callbacks += 1;
            Ok(false)
        })
        .unwrap();
    assert_eq!(callbacks, 1);
    assert_eq!(
        stopped.unconditional_completion(),
        base().unconditional_completion()
    );
    let cancelled = CancellationToken::default();
    let result = source
        .visit_context_forward_additions(first, &forward, base(), 1, &cancelled, None, &mut |_| {
            cancelled.cancel();
            Ok(true)
        })
        .unwrap();
    assert!(
        result
            .unconditional_completion()
            .contains_reason(base_reason)
    );
    assert!(
        result
            .unconditional_completion()
            .contains_reason(ResolutionIncompleteReason::Cancelled)
    );
    selection
        .with_owned_temp_write(|connection| {
            connection.execute(
                "DELETE FROM temp.selected_resolution_contexts WHERE context_id=?1",
                [first.get()],
            )?;
            Ok(())
        })
        .unwrap();
    assert!(source.context_paths(first, &live).is_err());
    assert!(source.hydrate_context_paths(first, &[], &live).is_err());
    assert!(
        source
            .visit_context_forward_additions(first, &forward, base(), 1, &live, None, &mut |_| Ok(
                true
            ))
            .is_err()
    );
    assert_eq!(
        source.context_paths(second, &live).unwrap().unwrap().len(),
        1
    );
    let foreign_fixture = SelectionFixture::new(1);
    let foreign_selection = foreign_fixture.open_ready(&[]);
    let foreign = super::super::SelectedResolutionStage::new(&foreign_selection)
        .publish_context_paths(&live, |_| Ok(true))
        .unwrap()
        .unwrap();
    assert!(source.context_paths(foreign, &live).is_err());
    assert!(source.hydrate_context_paths(foreign, &[], &live).is_err());
    assert!(
        source
            .visit_context_reverse_additions(
                foreign,
                &reverse,
                base(),
                1,
                &live,
                None,
                &mut |_| Ok(true)
            )
            .is_err()
    );
}

#[test]
fn prefix_spellings_use_the_path_producer_recipe_and_both_selected_hosts() {
    use crate::analyzer::resolution::{ResolutionLookupSemanticRecipe, SharedNameInterner};
    use brokk_bifrost_core::analyzer::{model::Language, resolution_facts::ResolutionNamespace};
    let fixture =
        SelectionFixture::custom_source(2, "class Dependency {} class Model extends Dependency {}");
    let selection = fixture.open_ready(&[]);
    let cancellation = CancellationToken::default();
    let names = selection
        .shared_name_table()
        .interner(selection.connection());
    let reference = SemanticId::operation_local((1 << 53) + 2001);
    let node = BindingNodeId::operation_local((1 << 53) + 2002);
    let recipe = ResolutionLookupSemanticRecipe::new(
        Language::Rust,
        ResolutionNamespace::Type,
        "dependency",
    );
    let lookup = SemanticId::shared_name(names.intern(recipe.name_digest()));
    let stage = super::super::SelectedResolutionStage::new(&selection);
    let publish = |host: u32,
                   identity: u8,
                   lowered: &LoweredResolutionFragment,
                   recipes: &[(SemanticId, ResolutionLookupSemanticRecipe)]| {
        let mount = selection
            .persisted_mount_record(SelectedResolutionMountOrdinal::new(host))
            .unwrap()
            .unwrap();
        assert!(matches!(
            stage
                .insert_generated_bridge(
                    &mount,
                    [identity; 32],
                    lowered,
                    None,
                    recipes,
                    &[],
                    &cancellation
                )
                .unwrap(),
            super::super::SelectedResolutionStageOutcome::Ready
        ));
    };
    let owner = LoweredResolutionFragment::selected_macro_head_bridge(
        BindingFragmentId::at_ordinal(0),
        reference,
        node,
        BindingNodeId::operation_local((1 << 53) + 2003),
        PartialPathId::operation_local((1 << 53) + 2004),
    );
    let target = BindingNodeId::operation_local((1 << 53) + 2005);
    let original = PartialPath::new(
        EndpointSignature::new_scoped(target, StackPattern::closed([]), StackPattern::closed([])),
        EndpointSignature::new_scoped(
            target,
            StackPattern::closed([PartialScopedSymbol::unscoped(lookup)]),
            StackPattern::closed([]),
        ),
        Vec::new(),
        Vec::new(),
        ResolutionCompletion::Complete,
    );
    let path = LoweredResolutionFragment::selected_include_continuation(
        BindingFragmentId::at_ordinal(1),
        node,
        PartialPathId::operation_local((1 << 53) + 2006),
        BindingNodeKind::Scope,
        &original,
    );
    publish(0, 201, &owner, &[(lookup, recipe.clone())]);
    publish(1, 202, &path, &[]);
    let source = SelectedResolutionLexicalSource::new_on_demand(&selection);
    assert!(
        source
            .reference_lookup_spellings(&[reference], ResolutionNamespace::Type, &cancellation)
            .unwrap()
            .is_empty(),
        "a recipe on another producer cannot explain this path's endpoint"
    );
    stage.clear_facts().unwrap();
    publish(0, 201, &owner, &[]);
    publish(1, 202, &path, &[(lookup, recipe)]);
    assert_eq!(
        source
            .reference_lookup_spellings(&[reference], ResolutionNamespace::Type, &cancellation)
            .unwrap()
            .get(&reference)
            .map(String::as_str),
        Some("dependency")
    );
    let shared_reference = SemanticId::shared_name(names.intern([198; 32]));
    let shared_node = BindingNodeId::operation_local((1 << 53) + 2010);
    let shared_owner = LoweredResolutionFragment::selected_macro_head_bridge(
        BindingFragmentId::at_ordinal(0),
        shared_reference,
        shared_node,
        BindingNodeId::operation_local((1 << 53) + 2011),
        PartialPathId::operation_local((1 << 53) + 2012),
    );
    let shared_path = LoweredResolutionFragment::selected_include_continuation(
        BindingFragmentId::at_ordinal(1),
        shared_node,
        PartialPathId::operation_local((1 << 53) + 2013),
        BindingNodeKind::Scope,
        &original,
    );
    publish(0, 206, &shared_owner, &[]);
    publish(
        1,
        207,
        &shared_path,
        &[(
            lookup,
            ResolutionLookupSemanticRecipe::new(
                Language::Rust,
                ResolutionNamespace::Type,
                "dependency",
            ),
        )],
    );
    assert_eq!(
        source
            .reference_lookup_spellings(
                &[reference, shared_reference],
                ResolutionNamespace::Type,
                &cancellation
            )
            .unwrap()
            .get(&shared_reference)
            .map(String::as_str),
        Some("dependency")
    );
    for hidden in [0, 1] {
        selection
            .with_owned_temp_write(|connection| {
                connection.execute(
                    "DELETE FROM temp.selected_resolution_scope_mounts WHERE mount_ordinal=?1",
                    [hidden],
                )?;
                Ok(())
            })
            .unwrap();
        assert!(
            source
                .reference_lookup_spellings(&[reference], ResolutionNamespace::Type, &cancellation)
                .unwrap()
                .is_empty(),
            "both the reference owner and the foreign path host must be selected: {hidden}"
        );
        selection
            .with_owned_temp_write(|connection| {
                connection.execute(
                    "INSERT INTO temp.selected_resolution_scope_mounts(mount_ordinal) VALUES(?1)",
                    [hidden],
                )?;
                Ok(())
            })
            .unwrap();
    }
    let host = selection
        .persisted_mount_record(SelectedResolutionMountOrdinal::new(0))
        .unwrap()
        .unwrap();
    let (ordinary_key, ordinary_spelling): (u32, String) = selection.connection().query_row(
        "SELECT p.start_node,i.spelling FROM main.resolution_paths p JOIN main.resolution_sites s ON s.blob_id=p.blob_id AND s.site=p.start_node AND s.role=0 JOIN main.resolution_identities i ON i.id=p.end_lead_identity WHERE p.blob_id=?1 AND i.namespace=?2 ORDER BY p.path LIMIT 1",
        params![host.blob_id(),super::super::super::resolution_prepare::resolution_rows::namespace_code(ResolutionNamespace::Type)],
        |row| Ok((row.get(0)?,row.get(1)?)),
    ).unwrap();
    let ordinary_reference = SemanticId::local(0, ordinary_key);
    let ordinary_node = BindingNodeId::local(0, ordinary_key);
    assert_eq!(
        source
            .reference_lookup_spellings(
                &[ordinary_reference],
                ResolutionNamespace::Type,
                &cancellation
            )
            .unwrap()
            .get(&ordinary_reference),
        Some(&ordinary_spelling)
    );
    let ordinary_owner = LoweredResolutionFragment::selected_macro_head_bridge(
        BindingFragmentId::at_ordinal(0),
        ordinary_reference,
        ordinary_node,
        BindingNodeId::operation_local((1 << 53) + 2020),
        PartialPathId::operation_local((1 << 53) + 2021),
    );
    publish(0, 203, &ordinary_owner, &[]);
    for (index, spelling) in [ordinary_spelling.as_str(), "different_dependency"]
        .into_iter()
        .enumerate()
    {
        let recipe = ResolutionLookupSemanticRecipe::new(
            Language::Rust,
            ResolutionNamespace::Type,
            spelling,
        );
        let lookup = SemanticId::shared_name(names.intern(recipe.name_digest()));
        let endpoint = EndpointSignature::new_scoped(
            target,
            StackPattern::closed([PartialScopedSymbol::unscoped(lookup)]),
            StackPattern::closed([]),
        );
        let original = PartialPath::new(
            endpoint.clone(),
            endpoint,
            Vec::new(),
            Vec::new(),
            ResolutionCompletion::Complete,
        );
        let path = LoweredResolutionFragment::selected_include_continuation(
            BindingFragmentId::at_ordinal(0),
            ordinary_node,
            PartialPathId::operation_local((1 << 53) + 2030 + index as u64),
            BindingNodeKind::Scope,
            &original,
        );
        publish(0, 204 + index as u8, &path, &[(lookup, recipe)]);
        let actual = source.reference_lookup_spellings(
            &[ordinary_reference],
            ResolutionNamespace::Type,
            &cancellation,
        );
        if index == 0 {
            assert_eq!(
                actual.unwrap().get(&ordinary_reference),
                Some(&ordinary_spelling),
                "equal ordinary/stage spelling authority agrees"
            );
        } else {
            assert!(
                actual.is_err(),
                "conflicting actual Type routes cannot silently pick a spelling"
            );
        }
    }
    cancellation.cancel();
    assert!(
        source
            .reference_lookup_spellings(&[reference], ResolutionNamespace::Type, &cancellation)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn borrowed_seed_fragment_filter_keeps_foreign_candidate_dependencies_visible() {
    use crate::analyzer::resolution::BatchCandidateRequest;
    let fixture = SelectionFixture::new(2);
    let selection = fixture.open_ready(&[]);
    let cancellation = CancellationToken::default();
    let mut identities = Vec::new();
    for host in [0, 1] {
        let fragment = BindingFragmentId::at_ordinal(host);
        let reference = SemanticId::operation_local((1 << 53) + 4000 + u64::from(host));
        let node = BindingNodeId::operation_local((1 << 53) + 4010 + u64::from(host));
        let path = PartialPathId::operation_local((1 << 53) + 4020 + u64::from(host));
        let lowered = LoweredResolutionFragment::selected_macro_head_bridge(
            fragment,
            reference,
            node,
            BindingNodeId::universal_root(),
            path,
        );
        selection.with_owned_temp_write(|connection| {
            connection.execute("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(?1,?2,?3)",params![host,[211u8;32].as_slice(),[212u8;32].as_slice()])?;
            assert!(super::super::lexical::prepare_lexical_fragment(&lowered,&cancellation).unwrap().insert(connection,connection.last_insert_rowid(),SelectedResolutionMountOrdinal::new(host),&cancellation)?);
            Ok(())
        }).unwrap();
        identities.push((fragment, node, CandidatePathIdentity::new(fragment, path)));
    }
    let fragments = [identities[0].0]
        .into_iter()
        .collect::<crate::hash::HashSet<_>>();
    let source = SelectedResolutionLexicalSource::new_on_demand(&selection)
        .with_forward_reference_fragments(&fragments);
    let mut nodes = Vec::new();
    source
        .visit_reference_seed_batches(64, &cancellation, &mut |batch| {
            assert!(
                batch
                    .seeds()
                    .iter()
                    .all(|seed| seed.fragment() == identities[0].0)
            );
            nodes.extend(batch.seeds().iter().map(|seed| seed.node()));
            Ok(true)
        })
        .unwrap();
    assert!(nodes.contains(&identities[0].1));
    assert!(!nodes.contains(&identities[1].1));
    let explicit = [identities[1].0]
        .into_iter()
        .collect::<crate::hash::HashSet<_>>();
    let mut explicit_nodes = Vec::new();
    source
        .visit_reference_seed_batches_in_fragments(&explicit, 64, &cancellation, &mut |batch| {
            explicit_nodes.extend(batch.seeds().iter().map(|seed| seed.node()));
            Ok(true)
        })
        .unwrap();
    assert!(
        explicit_nodes.contains(&identities[1].1),
        "explicit seed scope remains independent"
    );
    let request = [BatchCandidateRequest::new(
        0,
        EndpointSignature::new_scoped(
            identities[1].1,
            StackPattern::closed([]),
            StackPattern::closed([]),
        ),
    )];
    let mut candidates = Vec::new();
    source
        .visit_forward_candidate_match_pages(&request, &cancellation, &mut |page| {
            candidates.extend(page.iter().map(|row| row.candidate()));
            Ok(true)
        })
        .unwrap();
    assert_eq!(
        candidates,
        vec![identities[1].2],
        "seed filtering cannot hide a foreign dependency path"
    );
}

#[test]
fn bundled_prefix_spelling_pins_bound_actual_batches_and_preserve_rows() {
    use crate::analyzer::resolution::SharedNameId;
    use crate::analyzer::store::planner_statistics::pinned_plans::pinned;
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
    use rusqlite::{StatementStatus, types::Value};
    for statistics in PlannerStatisticsState::BOTH {
        let fixture = SelectionFixture::shared_blob(512);
        {
            let writer = fixture.store.conn.lock().unwrap();
            statistics.install(&writer);
        }
        let selection = fixture.open_ready(&[]);
        let lookup = SemanticId::shared_name(SharedNameId::per_request(2500));
        let target = BindingNodeId::operation_local((1 << 53) + 9000);
        let body = codec::encode_path(&PartialPath::new(
            EndpointSignature::new_scoped(
                target,
                StackPattern::closed([]),
                StackPattern::closed([]),
            ),
            EndpointSignature::new_scoped(
                target,
                StackPattern::closed([PartialScopedSymbol::unscoped(lookup)]),
                StackPattern::closed([]),
            ),
            Vec::new(),
            Vec::new(),
            ResolutionCompletion::Complete,
        ));
        let references = (0..256_u32)
            .map(|index| {
                if index % 2 == 0 {
                    SemanticId::operation_local((1 << 53) + 3000 + u64::from(index))
                } else {
                    SemanticId::shared_name(SharedNameId::per_request(3000 + index))
                }
            })
            .collect::<Vec<_>>();
        selection.with_owned_temp_write(|connection| {
        for (producer,host) in [(1,0),(2,1)] {
            connection.execute("INSERT INTO temp.selected_resolution_stage_producers(producer_id,host_ordinal,bridge_identity,content_digest) VALUES(?1,?2,zeroblob(32),zeroblob(32))",params![producer,host])?;
        }
        connection.execute("INSERT INTO temp.selected_resolution_stage_recipes(host_ordinal,producer_id,semantic_shared,semantic_language,namespace,spelling) VALUES(1,2,?1,0,0,'dependency')",[lookup.shared_name_id().unwrap().get()])?;
        for (index,reference) in references.iter().enumerate() {
            let node=codec::encode_node(BindingNodeId::operation_local((1 << 53)+6000+index as u64));
            let (key,shared)=super::super::lexical::semantic_cells(*reference);
            connection.execute("INSERT INTO temp.selected_resolution_stage_nodes(node,kind,kind_semantic_key,kind_shared_id) VALUES(?1,8,?2,?3)",params![node,key,shared])?;
            connection.execute("INSERT INTO temp.selected_resolution_stage_node_owners(producer_id,node) VALUES(1,?1)",[node])?;
            connection.execute("INSERT INTO temp.selected_resolution_stage_paths(host_ordinal,producer_id,path,start_node,end_node,start_lead_scoped,end_lead_shared,end_lead_scoped,body) VALUES(1,2,?1,?2,?3,0,?4,0,jsonb(?5))",params![codec::encode_path_id(PartialPathId::operation_local((1 << 53)+7000+index as u64)),node,codec::encode_node(target),lookup.shared_name_id().unwrap().get(),&body])?;
        }
        Ok(())
    }).unwrap();
        let mut baseline = std::collections::BTreeMap::new();
        let mut inserted = 0;
        for (noise, scope_size) in [(0, 16), (64, 256), (512, 512)] {
            selection.with_owned_temp_write(|connection| {
                for index in inserted..noise {
                    let producer=index+3;
                    connection.execute("INSERT INTO temp.selected_resolution_stage_producers(producer_id,host_ordinal,bridge_identity,content_digest) VALUES(?1,1,?2,zeroblob(32))",params![producer,(producer as u64).to_le_bytes().repeat(4)])?;
                    connection.execute("INSERT INTO temp.selected_resolution_stage_recipes(host_ordinal,producer_id,semantic_shared,semantic_language,namespace,spelling) VALUES(1,?1,?2,0,0,'dependency')",params![producer,lookup.shared_name_id().unwrap().get()])?;
                    for suffix in 0..8 {
                        let path=codec::encode_path_id(PartialPathId::operation_local((1 << 53)+10000+(index*8+suffix) as u64));
                        let node=codec::encode_node(BindingNodeId::operation_local((1 << 53)+20000+(index*8+suffix) as u64));
                        connection.execute("INSERT INTO temp.selected_resolution_stage_paths(host_ordinal,producer_id,path,start_node,end_node,start_lead_scoped,end_lead_shared,end_lead_scoped,body) VALUES(1,?1,?2,?3,?4,0,?5,0,jsonb(?6))",params![producer,path,node,codec::encode_node(target),lookup.shared_name_id().unwrap().get(),&body])?;
                    }
                }
                connection.execute("DELETE FROM temp.selected_resolution_scope_mounts",[])?;
                connection.execute("INSERT INTO temp.selected_resolution_scope_mounts SELECT mount_ordinal FROM temp.selected_resolution_mounts WHERE mount_ordinal<?1",[scope_size])?;
                Ok(())
            }).unwrap();
            inserted = noise;
            for arity in [1_usize, 64, 256] {
                for shape in ["hit", "miss", "excluded"] {
                    let mut pin = pinned(&format!("stage_lexical_prefix_spellings_{arity}"));
                    let requested = if shape == "miss" {
                        (0..arity)
                            .map(|index| {
                                SemanticId::operation_local((1 << 53) + 50000 + index as u64)
                            })
                            .collect::<Vec<_>>()
                    } else {
                        references[..arity].to_vec()
                    };
                    if shape == "miss" {
                        pin.params[0] = Value::Text(
                            serde_json::to_string(
                                &requested
                                    .iter()
                                    .copied()
                                    .map(super::super::lexical::semantic_cells)
                                    .collect::<Vec<_>>(),
                            )
                            .unwrap(),
                        );
                    }
                    if shape == "excluded" {
                        selection.with_owned_temp_write(|connection| {
                            connection.execute("DELETE FROM temp.selected_resolution_scope_mounts WHERE mount_ordinal=1",[])?;
                            Ok(())
                        }).unwrap();
                    }
                    let plan = selection
                        .connection()
                        .prepare(&format!("EXPLAIN QUERY PLAN {}", pin.sql))
                        .unwrap()
                        .query_map(rusqlite::params_from_iter(pin.params.iter()), |row| {
                            row.get::<_, String>(3)
                        })
                        .unwrap()
                        .collect::<rusqlite::Result<Vec<_>>>()
                        .unwrap();
                    for index in [
                        "selected_resolution_stage_nodes_semantic",
                        "selected_resolution_stage_node_owners_node",
                        "selected_resolution_stage_paths_forward",
                        "selected_resolution_stage_recipe_identity",
                    ] {
                        assert!(
                            plan.iter()
                                .any(|step| step.contains("SEARCH") && step.contains(index)),
                            "{statistics:?}, arity={arity}, shape={shape}, noise={noise}: {plan:?}"
                        );
                    }
                    assert!(
                        !plan.iter().any(|step| [
                            "SCAN node",
                            "SCAN path",
                            "SCAN recipe",
                            "AUTOMATIC",
                            "TEMP B-TREE",
                            "CO-ROUTINE"
                        ]
                        .iter()
                        .any(|bad| step.contains(bad))),
                        "{statistics:?}: {plan:?}"
                    );
                    let mut statement = selection.connection().prepare(&pin.sql).unwrap();
                    let mut actual = statement
                        .query_map(rusqlite::params_from_iter(pin.params.iter()), |row| {
                            Ok((
                                row.get::<_, usize>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, u32>(2)?,
                                row.get::<_, i64>(3)?,
                            ))
                        })
                        .unwrap()
                        .collect::<rusqlite::Result<Vec<_>>>()
                        .unwrap();
                    actual.sort_unstable();
                    let expected = if shape == "hit" {
                        (0..arity)
                            .map(|index| {
                                (
                                    index,
                                    "dependency".to_owned(),
                                    1,
                                    codec::encode_path_id(PartialPathId::operation_local(
                                        (1 << 53) + 7000 + index as u64,
                                    )),
                                )
                            })
                            .collect::<Vec<_>>()
                    } else {
                        Vec::new()
                    };
                    assert_eq!(
                        actual, expected,
                        "{statistics:?},arity={arity},shape={shape},noise={noise}"
                    );
                    let steps = statement.get_status(StatementStatus::VmStep);
                    let first = *baseline.entry((arity, shape)).or_insert(steps);
                    assert!(
                        steps <= first + first / 4 + 256,
                        "unrelated growth changed work: {statistics:?}, arity={arity}, shape={shape}, noise={noise}, first={first}, steps={steps}, plan={plan:?}"
                    );
                    let actual = reference_lookup_spellings(
                        &selection,
                        &requested,
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace::Type,
                        &CancellationToken::default(),
                    )
                    .unwrap()
                    .unwrap();
                    assert_eq!(actual.len(), if shape == "hit" { arity } else { 0 });
                    assert!(actual.values().all(|spelling| spelling == "dependency"));
                    if shape == "excluded" {
                        selection
                            .with_owned_temp_write(|connection| {
                                connection.execute(
                                    "INSERT INTO temp.selected_resolution_scope_mounts VALUES(1)",
                                    [],
                                )?;
                                Ok(())
                            })
                            .unwrap();
                    }
                }
            }
        }
    }
}

#[test]
fn bundled_suppression_pin_tracks_only_its_authority_rows() {
    use crate::analyzer::resolution::{LoweringGapOrigin, SharedNameId};
    use crate::analyzer::store::planner_statistics::pinned_plans::pinned;
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
    use rusqlite::StatementStatus;
    for statistics in PlannerStatisticsState::BOTH {
        let fixture = SelectionFixture::new(2);
        let qualified = super::super::super::resolution_prepare::resolution_rows::gap_origin_code(
            LoweringGapOrigin::QualifiedReference,
        );
        // This is a planner fixture: create the ordinary reason-key relation before
        // selection opens. Constructor and cache lifecycle laws are separate tests.
        fixture.store.conn.execute(move |connection| {
        let blobs = connection.prepare("SELECT blob_id FROM resolution_fragment_interiors").unwrap().query_map([],|row|row.get::<_,i64>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        for blob in blobs {
            for index in 0..128 {
                connection.execute("INSERT INTO resolution_gap_reasons(blob_id,reason,site,origin) VALUES(?1,?2,0,?3)",params![blob,8000+index,if index%2==0 {qualified}else{0}]).unwrap();
            }
        }
    });
        {
            let writer = fixture.store.conn.lock().unwrap();
            statistics.install(&writer);
        }
        let selection = fixture.open_ready(&[]);
        selection.with_owned_temp_write(|connection| {
        for host in [0,1] {
            connection.execute("INSERT INTO temp.selected_resolution_stage_producers(producer_id,host_ordinal,bridge_identity,content_digest) VALUES(?1,?2,zeroblob(32),zeroblob(32))",params![host+1,host])?;
        }
        Ok(())
    }).unwrap();
        let pin = pinned("stage_lexical_ordinary_completion_suppression");
        let mut baseline = std::collections::BTreeMap::new();
        for noise in [0, 64, 512] {
            selection.with_owned_temp_write(|connection| {
                connection.execute("DELETE FROM temp.selected_resolution_stage_semantic_coordinates",[])?;
                for index in 0..noise {
                    connection.execute("INSERT INTO temp.selected_resolution_stage_semantic_coordinates(host_ordinal,producer_id,dense_key,runtime_key,identity_digest) VALUES(0,1,?1,?2,zeroblob(32))",params![index,codec::encode_semantic(SemanticId::operation_local((1 << 53)+60000+index as u64))])?;
                }
                Ok(())
            }).unwrap();
            for count in [0, 8, 128] {
                let mut expected = std::collections::BTreeSet::new();
                selection.with_owned_temp_write(|connection| {
                    connection.execute("DELETE FROM temp.selected_resolution_stage_closed_reasons",[])?;
                    connection.execute("DELETE FROM temp.selected_resolution_stage_qualified_routes",[])?;
                    for index in 0..count {
                        let local=SemanticId::operation_local((1 << 53)+61000+index as u64);
                        let shared=SharedNameId::per_request(61000+index as u32);
                        connection.execute("INSERT INTO temp.selected_resolution_stage_closed_reasons(producer_id,semantic_key) VALUES(1,?1)",[codec::encode_semantic(local)])?;
                        connection.execute("INSERT INTO temp.selected_resolution_stage_closed_reasons(producer_id,semantic_shared) VALUES(2,?1)",[shared.get()])?;
                        expected.insert(ResolutionIncompleteReason::UnsupportedSemantic(local));
                        expected.insert(ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::shared_name(shared)));
                        for host in [0_u32,1] {
                            let coarse=SemanticId::local(host,8000+index as u32);
                            connection.execute("INSERT INTO temp.selected_resolution_stage_qualified_routes(host_ordinal,producer_id,sequence,reference_key,qualifier_slot_key,lookup_key,source_lookup_key,projection_output_slot_key,coarse_gap_reason_key,precedence_ordinal,namespace,projection_kind) VALUES(?1,?2,?3,?4,?4,?4,?4,?4,?5,0,0,0)",params![host,host+1,index,codec::encode_semantic(SemanticId::operation_local((1 << 53)+62000+index as u64)),codec::encode_semantic(coarse)])?;
                            if index%2==0 {expected.insert(ResolutionIncompleteReason::UnsupportedSemantic(coarse));}
                        }
                    }
                    Ok(())
                }).unwrap();
                let plan = selection
                    .connection()
                    .prepare(&format!("EXPLAIN QUERY PLAN {}", pin.sql))
                    .unwrap()
                    .query_map(rusqlite::params_from_iter(pin.params.iter()), |row| {
                        row.get::<_, String>(3)
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                assert!(
                    plan.iter()
                        .any(|step| step.contains("SEARCH r") && step.contains("PRIMARY KEY")),
                    "{statistics:?}: {plan:?}"
                );
                assert!(
                    !plan.iter().any(|step| step.contains("AUTOMATIC")
                        || step.contains("SCAN r")
                        || step.contains("semantic_coordinates")),
                    "{statistics:?}: {plan:?}"
                );
                let mut statement = selection.connection().prepare(&pin.sql).unwrap();
                let actual = statement
                    .query_map(rusqlite::params_from_iter(pin.params.iter()), |row| {
                        Ok(ResolutionIncompleteReason::UnsupportedSemantic(
                            semantic_from_cells(row.get(0)?, row.get(1)?),
                        ))
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<std::collections::BTreeSet<_>>>()
                    .unwrap();
                assert_eq!(
                    actual, expected,
                    "{statistics:?},noise={noise},count={count}"
                );
                let steps = statement.get_status(StatementStatus::VmStep);
                let first = *baseline.entry(count).or_insert(steps);
                assert!(
                    steps <= first + first / 4 + 128,
                    "unrelated coordinates changed suppression work: {statistics:?}, noise={noise},count={count},first={first},steps={steps},plan={plan:?}"
                );
                let actual =
                    ordinary_completion_suppression(&selection, &CancellationToken::default())
                        .unwrap()
                        .unwrap()
                        .into_iter()
                        .collect::<std::collections::BTreeSet<_>>();
                assert_eq!(actual, expected);
            }
        }
    }
}

#[test]
fn generated_include_boundary_classifies_only_with_scoped_catalog_authority() {
    use crate::analyzer::resolution::BatchEndpointClassification;
    use crate::analyzer::store::resolution_stage::SelectedResolutionStage;
    let fixture = SelectionFixture::shared_blob(2);
    let selection = fixture.open_ready(&[]);
    let cancellation = CancellationToken::default();
    let destination_host = selection
        .persisted_mount_record(SelectedResolutionMountOrdinal::new(0))
        .unwrap()
        .unwrap();
    let origin_host = selection
        .persisted_mount_record(SelectedResolutionMountOrdinal::new(1))
        .unwrap()
        .unwrap();
    let destination = BindingNodeId::context_local((1 << 53) + 81001);
    let end = BindingNodeId::operation_local((1 << 53) + 81002);
    let definition = SemanticId::operation_local((1 << 53) + 81003);
    let original = PartialPath::new(
        EndpointSignature::new(
            destination,
            StackPattern::closed([]),
            StackPattern::closed([]),
        ),
        EndpointSignature::new(end, StackPattern::closed([]), StackPattern::closed([])),
        Vec::new(),
        Vec::new(),
        ResolutionCompletion::Complete,
    );
    let stage = SelectedResolutionStage::new(&selection);
    assert_eq!(
        stage
            .admit_include_binding_pair(
                &destination_host,
                destination,
                &origin_host,
                CandidatePathIdentity::new(
                    origin_host.fragment_id(),
                    PartialPathId::operation_local((1 << 53) + 81004)
                ),
                &original,
                BindingNodeKind::Definition(definition),
                &cancellation,
            )
            .unwrap(),
        Some(())
    );
    let (key, source_scope): (i64, Option<u32>) = selection.connection().query_row(
        "SELECT runtime_key,source_scope FROM temp.selected_resolution_stage_node_coordinates WHERE host_ordinal=0", [],
        |row| Ok((row.get(0)?,row.get(1)?)),
    ).unwrap();
    let boundary = codec::decode_node(key);
    assert_eq!(source_scope, None);
    assert_eq!(
        selection
            .connection()
            .query_row(
                "SELECT count(*) FROM temp.selected_resolution_stage_nodes WHERE node=?1",
                [key],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0,
        "the actual include constructor registers a catalog-only boundary"
    );
    let source = SelectedResolutionLexicalSource::new_on_demand(&selection);
    assert_eq!(
        source
            .classify_endpoint_nodes(&[boundary, end], &cancellation)
            .unwrap(),
        vec![
            BatchEndpointClassification::new(boundary, None, None),
            BatchEndpointClassification::new(end, None, Some(definition)),
        ]
    );
    assert!(
        source
            .classify_endpoint_nodes(
                &[BindingNodeId::operation_local((1 << 53) + 81005)],
                &cancellation
            )
            .is_err()
    );
    selection
        .with_owned_temp_write(|connection| {
            connection.execute(
                "DELETE FROM temp.selected_resolution_scope_mounts WHERE mount_ordinal=0",
                [],
            )?;
            Ok(())
        })
        .unwrap();
    assert!(
        source
            .classify_endpoint_nodes(&[boundary], &cancellation)
            .is_err()
    );
    assert_eq!(
        source
            .classify_endpoint_nodes(&[end], &cancellation)
            .unwrap(),
        vec![BatchEndpointClassification::new(
            end,
            None,
            Some(definition)
        )]
    );
}

#[test]
fn ordinary_reference_seed_batch_checks_authority_once_per_mount() {
    use crate::analyzer::resolution::ResolutionQuery;
    use crate::analyzer::store::resolution_prepare::authority_rows::READ_AUTHORITY_SQL;
    use rusqlite::StatementStatus;

    let fixture = SelectionFixture::custom_source(
        1,
        "class Example { void helper() {} void caller() { helper(); helper(); } }",
    );
    let selection = fixture.open_ready(&[]);
    let cancellation = CancellationToken::new();
    let source = SelectedResolutionLexicalSource::new_on_demand(&selection);
    let keys = selection
        .connection()
        .prepare(
            "SELECT site.site FROM temp.selected_resolution_mounts mount
         JOIN resolution_sites site ON site.blob_id=mount.blob_id
         JOIN resolution_semantic_catalog catalog
           ON catalog.blob_id=site.blob_id AND catalog.local_key=site.site
         WHERE mount.mount_ordinal=0 AND site.role=0 AND catalog.identity_digest IS NOT NULL
         ORDER BY site.site",
        )
        .unwrap()
        .query_map([], |row| row.get::<_, u32>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(
        !keys.is_empty(),
        "the parsed fixture must contain real reference sites"
    );
    let queries = (0..32)
        .map(|index| ResolutionQuery::new(SemanticId::local(0, keys[index % keys.len()])))
        .collect::<Vec<_>>();
    let expected = queries
        .iter()
        .map(|&query| {
            source
                .reference_seed(query, &cancellation)
                .unwrap()
                .unwrap()
        })
        .collect::<Vec<_>>();
    selection
        .connection()
        .prepare_cached(READ_AUTHORITY_SQL)
        .unwrap()
        .reset_status(StatementStatus::Run);
    let batch = source
        .lookup_reference_seeds(&queries, &cancellation)
        .unwrap();
    let checks = selection
        .connection()
        .prepare_cached(READ_AUTHORITY_SQL)
        .unwrap()
        .get_status(StatementStatus::Run);
    assert_eq!(batch.rows().len(), queries.len());
    for (row, expected) in batch.rows().iter().zip(expected) {
        assert_eq!(row.seed(), Some(&expected));
    }
    assert_eq!(
        checks, 1,
        "one mount publication check admits the whole batch"
    );

    let absent = source
        .lookup_reference_seeds(
            &[ResolutionQuery::new(SemanticId::local(0, u32::MAX))],
            &cancellation,
        )
        .unwrap();
    assert!(absent.rows()[0].seed().is_none());
    cancellation.cancel();
    assert!(
        source
            .lookup_reference_seeds(&queries, &cancellation)
            .unwrap()
            .is_cancelled()
    );
}

#[test]
fn ordinary_reference_seed_site_plan_seeks_populated_catalog_and_sites() {
    use crate::analyzer::store::planner_statistics::pinned_plans::pinned;
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;

    let source = format!(
        "class Example {{ void helper() {{}} void caller() {{ {} }} }}",
        "helper();".repeat(256)
    );
    for state in PlannerStatisticsState::BOTH {
        let fixture = SelectionFixture::custom_source(1, &source);
        let conn = fixture.store.conn.lock().unwrap();
        let (blob, site): (i64, i64) = conn
            .query_row(
                "SELECT blob_id, site FROM resolution_sites WHERE role=0 LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM resolution_sites WHERE blob_id=?1 AND role=0",
                [blob],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            count >= 256,
            "the fixture must populate real references: {count}"
        );
        state.install(&conn);
        for arity in [1, 32, 256] {
            let pin = pinned(&format!("ordinary_reference_sites_by_key_{arity}"));
            for keys in [vec![site; arity], vec![i64::from(u32::MAX); arity]] {
                let keys = serde_json::to_string(&keys).unwrap();
                let plan = conn
                    .prepare(&format!("EXPLAIN QUERY PLAN {}", pin.sql))
                    .unwrap()
                    .query_map(params![blob, keys], |row| row.get::<_, String>(3))
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                for required in [
                    "SEARCH catalog USING PRIMARY KEY (blob_id=? AND local_key=?)",
                    "SEARCH site USING PRIMARY KEY (blob_id=? AND site=?)",
                ] {
                    assert!(
                        plan.iter().any(|row| row.contains(required)),
                        "{state} {}: {required}: {plan:?}",
                        pin.name
                    );
                }
                for forbidden in ["SCAN catalog", "SCAN site", "AUTOMATIC", "TEMP B-TREE"] {
                    assert!(
                        !plan.iter().any(|row| row.contains(forbidden)),
                        "{state} {}: {forbidden}: {plan:?}",
                        pin.name
                    );
                }
            }
        }
    }
}

/// The seed-key profile counts a repeated seed read as a repeat.
///
/// Both halves of the instrument's lifecycle are asserted here because its
/// profile is process-global and is written once: the off state has to be
/// observed before the on state exists. This is the same shape as the SQL
/// profile's own test, and it is why `seed_key_profile`'s unit tests do not
/// assert the off state themselves.
#[test]
fn seed_key_profile_counts_repeated_reference_seed_reads() {
    use crate::analyzer::resolution::{ResolutionQuery, seed_key_profile};

    assert!(
        std::env::var_os(seed_key_profile::PROFILE_PATH_ENV).is_none(),
        "{} must be unset for this test's first half",
        seed_key_profile::PROFILE_PATH_ENV
    );
    assert!(
        !seed_key_profile::enabled(),
        "the seed key profile must be off before this test turns it on"
    );

    let directory = tempfile::tempdir().expect("seed key profile test directory");
    let dump_path = directory.path().join("seed-keys.jsonl");
    seed_key_profile::install_for_test(&dump_path);

    let fixture = SelectionFixture::custom_source(
        1,
        "class Example { void helper() {} void caller() { helper(); helper(); } }",
    );
    let selection = fixture.open_ready(&[]);
    let cancellation = CancellationToken::new();
    let source = SelectedResolutionLexicalSource::new_on_demand(&selection);
    let keys = selection
        .connection()
        .prepare(
            "SELECT site.site FROM temp.selected_resolution_mounts mount
         JOIN resolution_sites site ON site.blob_id=mount.blob_id
         JOIN resolution_semantic_catalog catalog
           ON catalog.blob_id=site.blob_id AND catalog.local_key=site.site
         WHERE mount.mount_ordinal=0 AND site.role=0 AND catalog.identity_digest IS NOT NULL
         ORDER BY site.site",
        )
        .unwrap()
        .query_map([], |row| row.get::<_, u32>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(
        !keys.is_empty(),
        "the parsed fixture must contain real reference sites"
    );
    let queries = (0..32)
        .map(|index| ResolutionQuery::new(SemanticId::local(0, keys[index % keys.len()])))
        .collect::<Vec<_>>();

    {
        let _call = seed_key_profile::call_scope("seed_key_profile_test");
        for &query in &queries {
            assert!(
                source
                    .reference_seed(query, &cancellation)
                    .unwrap()
                    .is_some()
            );
        }
        let batch = source
            .lookup_reference_seeds(&queries, &cancellation)
            .unwrap();
        assert_eq!(batch.rows().len(), queries.len());
    }

    let dump = std::fs::read_to_string(&dump_path).expect("seed key profile dump");
    let lines = dump
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("dump line"))
        .collect::<Vec<_>>();
    assert_eq!(lines[0]["kind"], "header", "{lines:?}");
    let requests = lines
        .iter()
        .filter(|line| line["kind"] == "request")
        .collect::<Vec<_>>();
    assert_eq!(requests.len(), 1, "{lines:?}");
    let request = requests[0];
    assert_eq!(request["tool"], "seed_key_profile_test", "{request}");
    assert_eq!(request["overlapped"], false, "{request}");

    // One read per query: thirty-two scalar calls and one batch of thirty-two.
    let reads = request["seed_reads"].as_u64().expect("seed_reads");
    assert_eq!(reads, 64, "{request}");
    assert_eq!(request["seed_batches"], 33, "{request}");
    assert_eq!(request["seeds_returned"], 64, "{request}");
    assert!(
        request["result_bytes"].as_u64().expect("result_bytes") > 0,
        "{request}"
    );

    let distinct = request["distinct_keys"].as_u64().expect("distinct_keys");
    assert!((1..=reads).contains(&distinct), "{request}");
    assert!(distinct <= 32, "{request}");
    assert_eq!(request["uncounted_reads"], 0, "{request}");
    assert_eq!(request["distinct_key_cap_reached"], false, "{request}");

    // One selection, one request, one stage epoch and one whole-selection
    // scope, so every key of one reference is the same key.
    assert_eq!(request["distinct_references"], distinct, "{request}");
    assert_eq!(
        request["references_under_more_than_one_authority"], 0,
        "{request}"
    );
    assert_eq!(
        request["scopes"].as_array().expect("scopes").len(),
        1,
        "{request}"
    );

    let histogram = request["reads_per_key"].as_object().expect("reads_per_key");
    assert_eq!(
        histogram
            .values()
            .map(|count| count.as_u64().unwrap())
            .sum::<u64>(),
        distinct,
        "{request}"
    );
    assert_eq!(
        histogram["1"], 0,
        "every key is read once as a scalar and once in the batch: {request}"
    );

    let top = request["top_keys"].as_array().expect("top_keys");
    assert_eq!(
        u64::try_from(top.len()).unwrap(),
        distinct.min(20),
        "{request}"
    );
    let counts = top
        .iter()
        .map(|key| key["reads"].as_u64().expect("reads"))
        .collect::<Vec<_>>();
    assert!(
        counts.windows(2).all(|pair| pair[0] >= pair[1]),
        "{request}"
    );
    assert!(counts.iter().all(|reads| *reads >= 2), "{request}");
    assert_eq!(
        top[0]["scope"].as_str().expect("scope"),
        request["scopes"][0].as_str().expect("scope"),
        "{request}"
    );

    let totals = lines
        .iter()
        .filter(|line| line["kind"] == "totals")
        .collect::<Vec<_>>();
    assert_eq!(totals.len(), 1, "{lines:?}");
    assert_eq!(totals[0]["calls"], 1, "{totals:?}");
    assert!(
        totals[0]["seed_reads"].as_u64().expect("seed_reads") >= 64,
        "{totals:?}"
    );
}

/// The enumeration's seeds are the seeds the scalar and batched seams answer.
///
/// `visit_reference_inventory` builds each batch by calling
/// `persisted_reference_seeds`, which is the one function behind
/// `reference_seed` and `lookup_reference_seeds`, so a caller that already
/// holds an enumerated seed has no reason to read it again. This pins that:
/// it is the property the demand staging pass relies on when it hands the
/// enumerated seeds straight to the scheduler. Both kinds of content are
/// enumerated here, the parsed blob's ordinary references and a fragment
/// staged into the selection's own temp tables, because they reach the seed
/// reader by different rows.
#[test]
fn enumerated_reference_seeds_equal_the_seeds_both_seams_read() {
    use crate::analyzer::resolution::ResolutionQuery;

    let fixture = SelectionFixture::custom_source(
        1,
        "class Example { void helper() {} void caller() { helper(); helper(); } }",
    );
    let selection = fixture.open_ready(&[]);
    let cancellation = CancellationToken::new();

    // One staged reference beside the parsed blob's ordinary ones.
    let host = 0_u32;
    let fragment = BindingFragmentId::at_ordinal(host);
    let staged_reference = SemanticId::operation_local((1 << 53) + 7701);
    let staged_node = BindingNodeId::operation_local((1 << 53) + 7702);
    let staged_path = PartialPathId::operation_local((1 << 53) + 7703);
    let lowered = LoweredResolutionFragment::selected_macro_head_bridge(
        fragment,
        staged_reference,
        staged_node,
        BindingNodeId::universal_root(),
        staged_path,
    );
    selection
        .with_owned_temp_write(|connection| {
            connection.execute(
                "INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(?1,?2,?3)",
                params![host, [221u8; 32].as_slice(), [222u8; 32].as_slice()],
            )?;
            assert!(
                super::super::lexical::prepare_lexical_fragment(&lowered, &cancellation)
                    .unwrap()
                    .insert(
                        connection,
                        connection.last_insert_rowid(),
                        SelectedResolutionMountOrdinal::new(host),
                        &cancellation,
                    )?
            );
            Ok(())
        })
        .unwrap();

    let source = SelectedResolutionLexicalSource::new_on_demand(&selection);
    let mut enumerated = Vec::new();
    source
        .visit_reference_seed_batches(8, &cancellation, &mut |batch| {
            enumerated.extend(batch.seeds().iter().cloned());
            Ok(true)
        })
        .unwrap();
    assert!(
        enumerated.len() > 1,
        "the fixture enumerates several references"
    );
    assert!(
        enumerated
            .iter()
            .any(|seed| seed.reference() == staged_reference),
        "the enumeration covers the staged reference too: {enumerated:?}"
    );

    for seed in &enumerated {
        let query = ResolutionQuery::new(seed.reference());
        assert_eq!(
            source
                .reference_seed(query, &cancellation)
                .unwrap()
                .as_ref(),
            Some(seed),
            "the scalar seam disagrees with the enumeration for {query:?}"
        );
    }
    let queries = enumerated
        .iter()
        .map(|seed| ResolutionQuery::new(seed.reference()))
        .collect::<Vec<_>>();
    let batched = source
        .lookup_reference_seeds(&queries, &cancellation)
        .unwrap();
    assert!(batched.is_exhausted());
    assert_eq!(
        batched
            .rows()
            .iter()
            .map(|row| row.seed().cloned())
            .collect::<Vec<_>>(),
        enumerated.iter().cloned().map(Some).collect::<Vec<_>>(),
        "the batched seam disagrees with the enumeration"
    );
}

#[test]
fn go_namespace_admission_seeks_requested_nodes_and_selected_hosts() {
    use crate::analyzer::store::planner_statistics::pinned_plans::pinned;
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
    use rusqlite::types::Value;

    for statistics in PlannerStatisticsState::BOTH {
        let fixture = SelectionFixture::shared_blob(2);
        statistics.install(&fixture.store.conn.lock().unwrap());
        let selection = fixture.open_ready(&[]);
        let nodes = (0..512)
            .map(|index| BindingNodeId::operation_local((1 << 53) + 6000 + index))
            .collect::<Vec<_>>();
        selection.with_owned_temp_write(|connection| {
            for host in 0..2 {
                connection.execute("INSERT INTO temp.selected_resolution_stage_producers(producer_id,host_ordinal,bridge_identity,content_digest) VALUES(?1,?2,zeroblob(32),zeroblob(32))", params![host + 1,host])?;
            }
            for (index,node) in nodes.iter().enumerate() {
                connection.execute("INSERT INTO temp.selected_resolution_stage_semantics(host_ordinal,producer_id,sequence,semantic_key,node,source_site,role,namespace,owner_kind,go_definition_namespaces) VALUES(?1,?2,?3,?3,?4,?3,1,0,0,1)",params![index % 2,index % 2 + 1,index,codec::encode_node(*node)])?;
            }
            connection.execute("DELETE FROM temp.selected_resolution_scope_mounts WHERE mount_ordinal=1", [])?;
            for arity in [1,64,256] {
                let mut pin = pinned("stage_go_definition_namespaces");
                pin.params[0] = Value::Text(serde_json::to_string(&nodes[..arity].iter().copied().map(codec::encode_node).collect::<Vec<_>>()).unwrap());
                let plan = connection.prepare(&format!("EXPLAIN QUERY PLAN {}",pin.sql))?.query_map(rusqlite::params_from_iter(pin.params.iter()), |row| row.get::<_,String>(3))?.collect::<rusqlite::Result<Vec<_>>>()?;
                assert!(plan.iter().any(|step| step.contains("SEARCH") && step.contains("selected_resolution_stage_semantics_node")), "{statistics:?}, arity={arity}: {plan:?}");
                assert!(!plan.iter().any(|step| ["SCAN fact","SCAN scope","AUTOMATIC","TEMP B-TREE"].iter().any(|bad| step.contains(bad))), "{statistics:?}, arity={arity}: {plan:?}");
            }
            Ok(())
        }).unwrap();
        let result =
            go_definition_namespaces(&selection, &nodes[..256], &CancellationToken::default())
                .unwrap()
                .unwrap();
        assert_eq!(result.len(), 128);
        for (index, node) in nodes[..256].iter().enumerate() {
            assert_eq!(result.contains_key(node), index % 2 == 0);
        }
        let cancelled = CancellationToken::default();
        cancelled.cancel();
        assert!(
            go_definition_namespaces(&selection, &nodes[..256], &cancelled)
                .unwrap()
                .is_none()
        );
    }
}
