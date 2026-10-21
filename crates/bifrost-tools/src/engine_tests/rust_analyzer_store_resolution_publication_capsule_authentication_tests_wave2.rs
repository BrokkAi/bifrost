#[cfg(test)]
mod rust_departing_wave2_capsule_authentication_tests_tests {

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::store::resolution_publication::ResolutionContentPublicationOutcome;

    use brokk_bifrost_analysis::analyzer::store::resolution_publication::prepare_resolution_capsule;

    use brokk_bifrost_analysis::analyzer::store::resolution_publication::verify_capsule_artifact;
    use brokk_bifrost_test_macros::hardwon;
    #[test]
    #[hardwon(
        "3da13ca2218b: reordered or altered capsule presentation bypassed immutable publication identity"
    )]
    fn capsule_verification_authenticates_fresh_cached_and_reordered_artifacts() {
        use brokk_bifrost_analysis::analyzer::store::resolution_publication::CapsuleArtifactVerification::Cancelled as Cancelled;

        use brokk_bifrost_analysis::analyzer::store::resolution_publication::CapsuleArtifactVerification::Mismatch as Mismatch;

        use brokk_bifrost_analysis::analyzer::store::resolution_publication::CapsuleArtifactVerification::Verified as Verified;
        crate::engine_tests::rust_analyzer_store_resolution_operation_tests::rust_departing_root_tests::with_dense_selected_macro_fixture(
            |store, owner, fixtures| {
                let fixture = fixtures.into_iter().last().unwrap();
                let prepare = |dense, references| {
                    prepare_resolution_capsule(
                        fixture.key.clone(),
                        fixture.checkpoint,
                        fixture.module_scope,
                        dense,
                        &fixture.lowering,
                        fixture.host_input_start_line,
                        references,
                        &CancellationToken::default(),
                    )
                    .unwrap()
                    .unwrap()
                };
                let prepared = prepare(&fixture.dense, fixture.references.clone());
                let ResolutionContentPublicationOutcome::Ready(fresh) = store
                    .publish_selected_resolution_capsule(
                        owner,
                        &fixture.host_path,
                        prepared,
                        &CancellationToken::default(),
                    )
                    .unwrap()
                else {
                    panic!("fresh capsule publication must be ready");
                };
                let witness = fresh.witness().clone();
                {
                    let conn = store.read_conn().unwrap();
                    assert_eq!(
                        verify_capsule_artifact(
                            &conn,
                            &witness,
                            &fixture.dense,
                            &CancellationToken::default()
                        )
                        .unwrap(),
                        Verified
                    );
                    assert_eq!(
                        verify_capsule_artifact(
                            &conn,
                            &witness,
                            &fixture.reordered,
                            &CancellationToken::default()
                        )
                        .unwrap(),
                        Verified
                    );
                    let cancelled = CancellationToken::default();
                    cancelled.cancel();
                    assert_eq!(
                        verify_capsule_artifact(&conn, &witness, &fixture.dense, &cancelled)
                            .unwrap(),
                        Cancelled
                    );
                }
                let mut references = fixture.references.clone();
                references.reverse();
                let before = store.conn.execute(|conn| conn.total_changes());
                let ResolutionContentPublicationOutcome::Ready(cached) = store
                    .publish_selected_resolution_capsule(
                        owner,
                        &fixture.host_path,
                        prepare(&fixture.reordered, references),
                        &CancellationToken::default(),
                    )
                    .unwrap()
                else {
                    panic!("reordered capsule publication must be ready");
                };
                assert_eq!(cached.witness(), &witness);
                assert_eq!(store.conn.execute(|conn| conn.total_changes()), before);
                let changed = fixture
                    .dense
                    .with_changed_reference_end_for_publication_test();
                assert_eq!(
                    changed.identities(),
                    fixture.dense.identities(),
                    "changing reference extent retains the complete identity catalog"
                );
                assert_ne!(changed.lexical(), fixture.dense.lexical());
                let altered = changed
                    .lexical()
                    .semantics()
                    .iter()
                    .zip(fixture.dense.lexical().semantics())
                    .find(|(left, right)| left != right)
                    .unwrap()
                    .0;
                let source_site = fixture
                    .lowering
                    .facts
                    .sites
                    .iter()
                    .find(|site| site.id == altered.site())
                    .unwrap();
                let source_scope = fixture
                    .lowering
                    .facts
                    .scopes
                    .iter()
                    .find(|scope| scope.id == source_site.scope)
                    .unwrap();
                let extent = altered.site_metadata().unwrap();
                assert!(
                    source_scope.start_byte <= extent.start_byte()
                        && extent.end_byte() <= source_scope.end_byte,
                    "changed body remains inside its actual source scope"
                );
                {
                    let conn = store.read_conn().unwrap();
                    assert_eq!(
                        verify_capsule_artifact(
                            &conn,
                            &witness,
                            &changed,
                            &CancellationToken::default()
                        )
                        .unwrap(),
                        Mismatch,
                        "same catalog cannot authenticate changed reference body bytes"
                    );
                }
                let dense = fixture.dense;
                store.conn.execute(move |conn| {
                assert_eq!(verify_capsule_artifact(conn,cached.witness(),&dense,&CancellationToken::default()).unwrap(),Verified);
                let tx = conn.unchecked_transaction().unwrap();
                tx.execute("UPDATE resolution_fragment_interiors SET publication_state='building' WHERE blob_id=?1",[witness.blob_id()]).unwrap();
                assert_eq!(tx.execute("UPDATE resolution_capsule_declarations SET declaration_end_byte=declaration_end_byte+1 WHERE blob_id=?1",[witness.blob_id()]).unwrap(),1);
                assert_eq!(verify_capsule_artifact(&tx,&witness,&dense,&CancellationToken::default()).unwrap(),Mismatch,
                    "same identity catalog cannot authenticate altered durable presentation");
                tx.rollback().unwrap();
            });
            },
        );
    }
}
