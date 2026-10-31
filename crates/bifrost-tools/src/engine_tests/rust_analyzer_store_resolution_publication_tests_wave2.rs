#[cfg(test)]
mod rust_departing_wave2_root_tests {
    use rusqlite::OptionalExtension;

    use brokk_bifrost_analysis::analyzer::store::resolution_producer_tests::selected_publication::rust_root_test_support::{ready,roots};

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::store::persisted_blob_mutation_cost_fallback_sql;

    use brokk_bifrost_analysis::analyzer::store::persisted_blob_mutation_cost_fallback_statement;

    use brokk_bifrost_analysis::analyzer::store::stale_generation_blob_costs_sql;

    use brokk_bifrost_analysis::analyzer::store::resolution_producer_tests::measured_resolution_payload;

    use brokk_bifrost_analysis::analyzer::store::resolution_publication::ResolutionContentPublicationOutcome;
    fn prepared_capsule(
        fixture: &crate::engine_tests::rust_analyzer_store_resolution_operation_tests::rust_departing_root_tests::DenseSelectedMacroFixture,
    ) -> brokk_bifrost_analysis::analyzer::store::resolution_publication::PreparedResolutionCapsule
    {
        brokk_bifrost_analysis::analyzer::store::resolution_publication::prepare_resolution_capsule(
            fixture.key.clone(),
            fixture.checkpoint,
            fixture.module_scope,
            &fixture.dense,
            &fixture.lowering,
            fixture.host_input_start_line,
            fixture.references.clone(),
            &CancellationToken::default(),
        )
        .unwrap()
        .unwrap()
    }

    #[test]
    fn actual_dense_capsules_publish_distinct_derivations_without_parsed_readiness() {
        crate::engine_tests::rust_analyzer_store_resolution_operation_tests::rust_departing_root_tests::with_dense_selected_macro_fixture(
            |store, owner, fixtures| {
                let mut witnesses = Vec::new();
                for fixture in &fixtures {
                    let capsule = prepared_capsule(fixture);
                    let published = ready(
                        store
                            .publish_selected_resolution_capsule(
                                owner,
                                &fixture.host_path,
                                capsule,
                                &CancellationToken::default(),
                            )
                            .unwrap(),
                    );
                    let (witness, membership) = published.into_parts();
                    assert!(!membership.is_empty());
                    assert_eq!(
                        membership
                            .iter()
                            .map(|(digest, _)| *digest)
                            .collect::<std::collections::BTreeSet<_>>(),
                        fixture
                            .dense
                            .identities()
                            .shared_names()
                            .into_iter()
                            .collect(),
                        "publication receipt includes every producer-catalog shared identity"
                    );
                    assert_eq!(witness.blob_oid(), fixture.key.content_oid().unwrap());
                    assert_eq!(
                        witness.payload_bytes() as usize,
                        measured_resolution_payload(store, witness.blob_oid(), &owner.lang)
                    );
                    let blob_id = witness.blob_id();
                    let (meta, references): (usize, usize) = store.conn.execute(move |conn| {
                        conn.query_row(
                            "SELECT (SELECT count(*) FROM blob_meta WHERE blob_id=?1),
                    (SELECT count(*) FROM resolution_capsule_reference_contexts WHERE blob_id=?1)",
                            [blob_id],
                            |row| Ok((row.get(0)?, row.get(1)?)),
                        )
                        .unwrap()
                    });
                    assert_eq!(
                        meta, 0,
                        "derived content never manufactures Parsed readiness"
                    );
                    assert_eq!(references, fixture.references.len());

                    use brokk_bifrost_analysis::analyzer::store::resolution_publication::ResolutionCapsuleReferenceOwner;
                    use brokk_bifrost_core::analyzer::Range;
                    let stored_contexts = store.conn.execute(move |conn| {
                    conn.prepare(
                        "SELECT semantic_key,source_site,host_occurrence,module_context,module_declaration,reference_owner_kind,host_owner_key FROM resolution_capsule_reference_contexts WHERE blob_id=?1 ORDER BY semantic_key",
                    ).unwrap().query_map([blob_id], |row| Ok((
                        row.get::<_, i64>(0)?, row.get::<_, u32>(1)?,
                        row.get::<_, u32>(2)?, row.get::<_, u32>(3)?,
                        row.get::<_, Option<u32>>(4)?, row.get::<_, i64>(5)?,
                        row.get::<_, Option<i64>>(6)?,
                    ))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
                });
                    let mut expected_contexts = fixture
                        .references
                        .iter()
                        .map(|context| {
                            let (kind, owner) = match context.reference_owner {
                                ResolutionCapsuleReferenceOwner::Unknown => (0, None),
                                ResolutionCapsuleReferenceOwner::Root => (1, None),
                                ResolutionCapsuleReferenceOwner::HostLocal(owner) => {
                                    (2, Some(owner.get()))
                                }
                            };
                            (
                                context.semantic_key.get(),
                                context.source_site.get(),
                                context.host_occurrence.get(),
                                context.module_context.get(),
                                context
                                    .module_declaration
                                    .map(|declaration| declaration.get()),
                                kind,
                                owner,
                            )
                        })
                        .collect::<Vec<_>>();
                    expected_contexts.sort_unstable();
                    assert_eq!(
                        stored_contexts, expected_contexts,
                        "every original host context column survives publication"
                    );
                    let namespaces = store.conn.execute(move |conn| {
                    conn.prepare("SELECT namespace FROM resolution_sites WHERE blob_id=?1 AND role=0 ORDER BY site")
                        .unwrap().query_map([blob_id], |row| row.get::<_, i64>(0)).unwrap()
                        .collect::<rusqlite::Result<Vec<_>>>().unwrap()
                });
                    let expected_namespace = if fixture.host_path == "app/src/scale_0000.rs" {
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace::Type
                    } else {
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace::Value
                    };
                    assert!(!namespaces.is_empty());
                    for namespace in namespaces {
                        assert_eq!(
                        brokk_bifrost_analysis::analyzer::store::resolution_prepare::resolution_rows::namespace_from_code(
                            namespace
                        ),
                        expected_namespace
                    );
                    }
                    let declarations = store.conn.execute(move |conn| {
                    conn.prepare(
                        "SELECT identifier,kind,name_start_byte,name_end_byte,name_start_line,name_end_line,declaration_start_byte,declaration_end_byte,declaration_start_line,declaration_end_line FROM resolution_capsule_declarations WHERE blob_id=?1 ORDER BY semantic_key",
                    ).unwrap().query_map([blob_id], |row| Ok((
                        row.get::<_, String>(0)?, row.get::<_, String>(1)?,
                        Range { start_byte: row.get(2)?, end_byte: row.get(3)?, start_line: row.get(4)?, end_line: row.get(5)? },
                        Range { start_byte: row.get(6)?, end_byte: row.get(7)?, start_line: row.get(8)?, end_line: row.get(9)? },
                    ))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
                });
                    if let Some((name_range, declaration_range)) =
                        fixture.expected_declaration_ranges
                    {
                        assert!(fixture.host_input_start_line > 1);
                        assert!(name_range.start_byte > 0 && name_range.start_line > 1);
                        assert_eq!(
                            declarations,
                            vec![(
                                "local".to_owned(),
                                "local_variable".to_owned(),
                                name_range,
                                declaration_range
                            )],
                            "stored name and full declaration ranges agree with the independent host-coordinate AST"
                        );
                        assert!(!fixture.dense.typed().frontiers().is_empty());
                    } else {
                        assert!(
                            declarations.is_empty(),
                            "a pure type/value name has no lexical declaration"
                        );
                    }

                    let before_reuse = store.conn.execute(|conn| conn.total_changes());
                    let cached = ready(
                        store
                            .admit_cached_selected_content(
                                owner,
                                &fixture.host_path,&brokk_bifrost_core::gitblob::BlobKey::unvaried(witness.blob_oid(), (owner).lang.as_str()),
                                witness.input(),
                                &CancellationToken::default(),
                            )
                            .unwrap(),
                    );
                    assert_eq!(cached.witness(), &witness);
                    let reordered = brokk_bifrost_analysis::analyzer::store::resolution_publication::prepare_resolution_capsule(
                    fixture.key.clone(),
                    fixture.checkpoint,
                    fixture.module_scope,
                    &fixture.reordered,
                    &fixture.lowering,
                    fixture.host_input_start_line,
                    fixture.references.clone(),
                    &CancellationToken::default(),
                )
                .unwrap()
                .unwrap();
                    let reordered = ready(
                        store
                            .publish_selected_resolution_capsule(
                                owner,
                                &fixture.host_path,
                                reordered,
                                &CancellationToken::default(),
                            )
                            .unwrap(),
                    );
                    assert_eq!(reordered.witness(), &witness);
                    assert_eq!(
                        store.conn.execute(|conn| conn.total_changes()),
                        before_reuse,
                        "cached admission and reordered publication perform zero writes"
                    );
                    witnesses.push(witness);
                }
                assert_ne!(witnesses[0].blob_oid(), witnesses[1].blob_oid());
                assert_ne!(
                    witnesses[0].manifest_digest(),
                    witnesses[1].manifest_digest()
                );
                assert_eq!(roots(store).len(), fixtures.len());
            },
        );
    }

    #[test]
    fn changed_complete_capsule_input_preserves_original_content_and_roots() {
        crate::engine_tests::rust_analyzer_store_resolution_operation_tests::rust_departing_root_tests::with_dense_selected_macro_fixture(
            |store, owner, fixtures| {
                let fixture = fixtures.last().unwrap();
                let witness = ready(
                    store
                        .publish_selected_resolution_capsule(
                            owner,
                            &fixture.host_path,
                            prepared_capsule(fixture),
                            &CancellationToken::default(),
                        )
                        .unwrap(),
                )
                .into_parts()
                .0;
                let before = store.conn.execute(|conn| conn.total_changes());
                let changed_scope =
                    brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId::new(
                        fixture.module_scope.get().checked_add(1).unwrap(),
                    );
                for (scope, line) in [
                    (changed_scope, fixture.host_input_start_line),
                    (fixture.module_scope, fixture.host_input_start_line + 1),
                ] {
                    let changed = brokk_bifrost_analysis::analyzer::store::resolution_publication::prepare_resolution_capsule(
                    fixture.key.clone(),
                    fixture.checkpoint,
                    scope,
                    &fixture.dense,
                    &fixture.lowering,
                    line,
                    fixture.references.clone(),
                    &CancellationToken::default(),
                )
                .unwrap()
                .unwrap();
                    assert!(matches!(store.publish_selected_resolution_capsule(owner,&fixture.host_path,
            changed,&CancellationToken::default()).unwrap(),
            ResolutionContentPublicationOutcome::Unavailable(
                brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionUnavailable::InteriorOwnershipMismatch { .. })));
                }
                assert_eq!(store.conn.execute(|conn| conn.total_changes()), before);
                let original = ready(
                    store
                        .admit_cached_selected_content(
                            owner,
                            &fixture.host_path,&brokk_bifrost_core::gitblob::BlobKey::unvaried(witness.blob_oid(), (owner).lang.as_str()),
                            witness.input(),
                            &CancellationToken::default(),
                        )
                        .unwrap(),
                );
                assert_eq!(original.witness(), &witness);
                assert_eq!(roots(store).len(), 1);
            },
        );
    }

    #[test]
    fn headerless_capsule_costs_drive_oversize_progress_in_mixed_stale_cleanup() {
        crate::engine_tests::rust_analyzer_store_resolution_operation_tests::rust_departing_root_tests::with_dense_selected_macro_fixture(
            |store, owner, fixtures| {
                let fixture = fixtures.last().unwrap();
                let witness = ready(
                    store
                        .publish_selected_resolution_capsule(
                            owner,
                            &fixture.host_path,
                            prepared_capsule(fixture),
                            &CancellationToken::default(),
                        )
                        .unwrap(),
                )
                .into_parts()
                .0;
                assert!(witness.logical_rows() > 1);
                let capsule_oid = witness.blob_oid().to_string();
                let capsule_lang = owner.lang.clone();
                let capsule_cost = store.conn.execute(move |conn| {
                    let mut statement = conn
                        .prepare_cached(persisted_blob_mutation_cost_fallback_sql())
                        .unwrap();
                    persisted_blob_mutation_cost_fallback_statement(
                        &mut statement,&brokk_bifrost_core::gitblob::BlobKey::unvaried(git2::Oid::from_str(&capsule_oid).unwrap(), &capsule_lang),
                    )
                    .unwrap()
                });
                assert_eq!(
                    capsule_cost.logical_rows,
                    witness.logical_rows() as usize + 2,
                    "headerless content owns its blob row and revision root in addition to complete manifest rows"
                );
                assert_eq!(
                    capsule_cost.payload_bytes,
                    witness.payload_bytes() as usize + 64 + owner.lang.len()
                );
                store
                    .ensure_language_epoch_value(&owner.lang, "capsule-cleanup-next-generation")
                    .unwrap();
                let mut capsule_deleted = false;
                loop {
                    let candidate: Option<(String, String, usize)> = store.conn.execute(|conn| {
                        conn.query_row(stale_generation_blob_costs_sql(), [], |row| {
                            Ok((row.get(0)?, row.get(1)?, row.get(3)?))
                        })
                        .optional()
                        .unwrap()
                    });
                    let Some((oid, lang, cost)) = candidate else {
                        break;
                    };
                    let existed_before = store.conn.execute(|conn| {
                        conn.query_row("SELECT count(*) FROM blobs", [], |row| {
                            row.get::<_, usize>(0)
                        })
                        .unwrap()
                    });
                    assert_eq!(
                        store.reclaim_stale_generations(1).unwrap(),
                        cost,
                        "one complete oversize content unit advances a one-row cleanup batch"
                    );
                    assert_eq!(
                        store.conn.execute(|conn| conn
                            .query_row("SELECT count(*) FROM blobs", [], |row| row
                                .get::<_, usize>(0))
                            .unwrap())
                            + 1,
                        existed_before
                    );
                    if oid == witness.blob_oid().to_string() && lang == owner.lang {
                        assert_eq!(cost, capsule_cost.logical_rows);
                        capsule_deleted = true;
                    }
                }
                assert!(
                    capsule_deleted,
                    "the real mixed-store sweep reached the rooted headerless capsule"
                );
                assert!(
                    roots(store).is_empty(),
                    "stale cleanup does not preserve old physical roots"
                );
            },
        );
    }

    #[test]
    fn generic_dense_nodes_publish_through_preparation_interning_and_sealing() {
        use brokk_bifrost_analysis::analyzer::resolution::model::BindingNodeId;

        use brokk_bifrost_analysis::analyzer::resolution::model::BindingNodeKind;
        crate::engine_tests::rust_analyzer_store_resolution_operation_tests::rust_departing_root_tests::with_dense_selected_macro_fixture(
            |store, owner, fixtures| {
                let fixture = fixtures.into_iter().last().unwrap();
                let generic = fixture
                    .dense
                    .with_generic_node_payloads_for_publication_test();
                let reordered = fixture
                    .reordered
                    .with_generic_node_payloads_for_publication_test();
                let prepare = |dense| {
                    brokk_bifrost_analysis::analyzer::store::resolution_publication::prepare_resolution_capsule(
                    fixture.key.clone(),
                    fixture.checkpoint,
                    fixture.module_scope,
                    dense,
                    &fixture.lowering,
                    fixture.host_input_start_line,
                    fixture.references.clone(),
                    &CancellationToken::default(),
                )
                .unwrap()
                .unwrap()
                };
                let published = ready(
                    store
                        .publish_selected_resolution_capsule(
                            owner,
                            &fixture.host_path,
                            prepare(&generic),
                            &CancellationToken::default(),
                        )
                        .unwrap(),
                );
                let (witness, membership) = published.into_parts();
                let blob_id = witness.blob_id();
                let rows = store.conn.execute(move |conn| {
            assert_eq!(conn.query_row("SELECT count(*) FROM blob_meta WHERE blob_id=?1",[blob_id],|row|row.get::<_,usize>(0)).unwrap(),0,
                "generic nodes do not manufacture parsed source readiness");
            conn.prepare("SELECT local_key,kind,semantic_local_key,semantic_shared_identity,target_local_key,target_boundary_key FROM resolution_node_catalog WHERE blob_id=?1 ORDER BY local_key")
                .unwrap().query_map([blob_id],|row|Ok((row.get::<_,usize>(0)?,row.get::<_,Option<i64>>(1)?,
                    row.get::<_,Option<usize>>(2)?,row.get::<_,Option<i64>>(3)?,row.get::<_,Option<usize>>(4)?,row.get::<_,Option<i64>>(5)?)))
                .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
        });
                let catalog = generic.identities();
                let mut declared = Vec::new();
                let mut absent = 0;
                let mut shared_payloads = 0;
                let mut root_targets = 0;
                for (key, kind, local, shared, target, boundary) in rows {
                    let node = catalog.nodes()[key].0;
                    let semantic = match (local, shared) {
                        (Some(key), None) => Some(catalog.semantics()[key].0),
                        (None, Some(stored)) => {
                            shared_payloads += 1;
                            let digest = membership
                                .iter()
                                .find(|(_, id)| i64::from(id.get()) == stored)
                                .unwrap()
                                .0;
                            Some(
                                catalog
                                    .semantics()
                                    .iter()
                                    .find(|(_, identity)| {
                                        identity.shared_name().is_some_and(|name| {
                                            catalog.shared_name_digest(name) == digest
                                        })
                                    })
                                    .unwrap()
                                    .0,
                            )
                        }
                        (None, None) => None,
                        _ => panic!("exclusive semantic payload"),
                    };
                    let target = match (target, boundary) {
                        (Some(key), None) => Some(catalog.nodes()[key].0),
                        (None, Some(0)) => {
                            root_targets += 1;
                            Some(BindingNodeId::universal_root())
                        }
                        (None, None) => None,
                        _ => panic!("exclusive node payload"),
                    };
                    let Some(kind) = kind else {
                        absent += 1;
                        assert!(
                            generic
                                .lexical()
                                .nodes()
                                .iter()
                                .all(|(declared, _)| *declared != node)
                        );
                        continue;
                    };
                    let decoded = match kind {
                        0 => BindingNodeKind::Root,
                        1 => BindingNodeKind::Scope,
                        2 => BindingNodeKind::PushSymbol(semantic.unwrap()),
                        3 => BindingNodeKind::PopSymbol(semantic.unwrap()),
                        4 => BindingNodeKind::PushScopedSymbol(semantic.unwrap()),
                        5 => BindingNodeKind::PopScopedSymbol(semantic.unwrap()),
                        6 => BindingNodeKind::DropScopes,
                        7 => BindingNodeKind::JumpToScope(target.unwrap()),
                        8 => BindingNodeKind::Reference(semantic.unwrap()),
                        9 => BindingNodeKind::Definition(semantic.unwrap()),
                        _ => panic!("known node kind"),
                    };
                    declared.push((node, decoded));
                }
                declared.sort_unstable();
                assert_eq!(declared, generic.lexical().nodes());
                assert!(absent > 0 && shared_payloads >= 4 && root_targets > 0);
                assert!(
                    declared
                        .iter()
                        .any(|(_, kind)| matches!(kind, BindingNodeKind::Reference(_)))
                );
                assert!(
                    declared
                        .iter()
                        .any(|(_, kind)| matches!(kind, BindingNodeKind::Definition(_)))
                );
                assert_eq!(
                    witness.payload_bytes() as usize,
                    measured_resolution_payload(store, witness.blob_oid(), &owner.lang)
                );
                let logical_rows=store.conn.execute(move |conn| {
            let tables=conn.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name LIKE 'resolution_%'")
                .unwrap().query_map([],|row|row.get::<_,String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            tables.iter().filter(|table|conn.query_row("SELECT EXISTS(SELECT 1 FROM pragma_table_info(?1) WHERE name='blob_id')",[table.as_str()],|row|row.get::<_,bool>(0)).unwrap())
                .map(|table|conn.query_row(&format!("SELECT count(*) FROM \"{table}\" WHERE blob_id=?1"),[blob_id],|row|row.get::<_,u64>(0)).unwrap()).sum::<u64>()
        });
                assert_eq!(
                    witness.logical_rows(),
                    logical_rows,
                    "complete witness counts all actually stored per-blob resolution families"
                );
                let before = store.conn.execute(|conn| conn.total_changes());
                let cached = ready(
                    store
                        .publish_selected_resolution_capsule(
                            owner,
                            &fixture.host_path,
                            prepare(&reordered),
                            &CancellationToken::default(),
                        )
                        .unwrap(),
                );
                assert_eq!(cached.witness(), &witness);
                assert_eq!(
                    store.conn.execute(|conn| conn.total_changes()),
                    before,
                    "reordered shared interning reuses complete generic publication without writes"
                );
            },
        );
    }
}
