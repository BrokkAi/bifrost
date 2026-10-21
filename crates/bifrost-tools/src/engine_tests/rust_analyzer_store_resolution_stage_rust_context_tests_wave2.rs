#[cfg(test)]
mod rust_departing_wave2_root_tests {
    use brokk_bifrost_analysis::native_resolution_test_support::SelectedTypedFactSource;

    use brokk_bifrost_analysis::analyzer::resolution::model::BindingFragmentId;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::resolution::fact_source::LoweredRustReferenceContext;

    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId;

    use brokk_bifrost_analysis::analyzer::store::Result;

    use brokk_bifrost_analysis::analyzer::resolution::fact_source::SelectedTypedRow;

    use brokk_bifrost_analysis::analyzer::resolution::model::SemanticId;

    use brokk_bifrost_core::analyzer::source_facts::SourceDeclarationId;

    use brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceId;

    use brokk_bifrost_analysis::analyzer::resolution::fact_source::TypedFactPageVisitor;

    use brokk_bifrost_analysis::analyzer::resolution::fact_source::TypedFactRequest;

    use brokk_bifrost_analysis::analyzer::store::resolution_prepare::rust_authority;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::SelectedResolutionStage;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::SelectedResolutionStageOutcome;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::codec;

    use brokk_bifrost_analysis::analyzer::store::resolution_typed::SelectedResolutionTypedSource;
    use brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition;
    use rusqlite::params;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::rust_context::tests::rust_wave2_root_test_support::Context as Context;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::rust_context::tests::rust_wave2_root_test_support::collect as collect;

    #[test]
    fn authenticated_capsule_contexts_join_ordinary_rows_and_preserve_stop_and_cancel() {
        use crate::engine_tests::rust_analyzer_store_resolution_operation_tests::rust_departing_root_tests::with_dense_selected_macro_fixture;
        use brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshots;

        use brokk_bifrost_analysis::analyzer::store::resolution_publication::ResolutionContentPublicationOutcome;

        use brokk_bifrost_analysis::analyzer::store::resolution_publication::prepare_resolution_capsule;

        use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;

        use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionMountInventoryOutcome;
        with_dense_selected_macro_fixture(|store, owner, fixtures| {
            let live = CancellationToken::new();
            let mut cases = Vec::new();
            for fixture in fixtures.into_iter().take(2) {
                assert!(!fixture.references.is_empty());
                let prepared = prepare_resolution_capsule(
                    fixture.key.clone(),
                    fixture.checkpoint,
                    fixture.module_scope,
                    &fixture.dense,
                    &fixture.lowering,
                    fixture.host_input_start_line,
                    fixture.references.clone(),
                    &live,
                )
                .unwrap()
                .unwrap();
                let ResolutionContentPublicationOutcome::Ready(receipt) = store
                    .publish_selected_resolution_capsule(owner, &fixture.host_path, prepared, &live)
                    .unwrap()
                else {
                    panic!("actual capsule publication");
                };
                cases.push((fixture, receipt));
            }
            let snapshots = WorkspaceSnapshots::from_iter([(owner.lang.clone(), owner.clone())]);
            let SelectedResolutionMountInventoryOutcome::Ready(selection) = store
                .open_selected_resolution_mount_inventory(
                    &owner.workspace_id,
                    &snapshots,
                    &[SelectedResolutionLanguage::new(
                        owner.lang.clone(),
                        Language::Rust,
                    )],
                    &[],
                    &live,
                )
                .unwrap()
            else {
                panic!("actual selected macro hosts");
            };
            let stage = SelectedResolutionStage::new(&selection);
            let mut expected = Vec::new();
            for (fixture, receipt) in cases {
                let host = selection
                    .mount_record_for_path(&owner.lang, &fixture.host_path)
                    .unwrap()
                    .unwrap();
                assert!(matches!(
                    stage
                        .admit_capsule(*receipt, &host, fixture.dense, &[], &live)
                        .unwrap(),
                    SelectedResolutionStageOutcome::Ready
                ));
                for source in fixture.references {
                    let semantic = selection.connection().query_row(
                    "SELECT coordinate.runtime_key FROM temp.selected_resolution_stage_semantic_coordinates coordinate JOIN temp.selected_resolution_stage_producers producer USING(producer_id) WHERE coordinate.host_ordinal=?1 AND coordinate.dense_key=?2 AND producer.admission_id IS NOT NULL",
                    params![host.ordinal().get(),source.semantic_key.get()], |row| row.get::<_,i64>(0)).unwrap();
                    expected.push(SelectedTypedRow::new(
                        BindingFragmentId::at_ordinal(host.ordinal().get()),
                        LoweredRustReferenceContext::new(
                            codec::decode_semantic(semantic),
                            source.source_site,
                            source.host_occurrence,
                            source.module_context,
                            source.module_declaration,
                        ),
                    ));
                }
            }
            assert!(
                expected
                    .iter()
                    .all(|r| r.row().cfg_condition() == &RustCfgCondition::Always)
            );
            // Ordinary source authority is independently read from the persisted blob.
            let ordinary = selection.connection().query_row(
            "SELECT mount.mount_ordinal,source.semantic_key,source.source_site,source.source_occurrence,source.module_context,source.module_declaration,json(source.cfg_condition) FROM temp.selected_resolution_mounts mount JOIN main.resolution_rust_reference_contexts source USING(blob_id) LIMIT 1", [], |row| {
                let host = row.get::<_,u32>(0)?;
                Ok(SelectedTypedRow::new(BindingFragmentId::at_ordinal(host),LoweredRustReferenceContext::new(
                    SemanticId::local(host,row.get(1)?),ResolutionSiteId::new(row.get(2)?),SourceOccurrenceId::new(row.get(3)?),
                    SourceOccurrenceId::new(row.get(4)?),row.get::<_,Option<u32>>(5)?.map(SourceDeclarationId::new))
                    .with_cfg_condition(rust_authority::decode_cfg(&row.get::<_,String>(6)?))))
            }).unwrap();
            expected.push(ordinary);
            let keys = expected
                .iter()
                .map(|r| r.row().reference())
                .collect::<Vec<_>>();
            let actual = collect(&selection, &keys);
            assert_eq!(actual.len(), expected.len());
            for row in &expected {
                assert!(actual.contains(row), "missing {row:?}; actual={actual:?}");
            }
            let source = SelectedResolutionTypedSource::new_on_demand(&selection);
            let mut seen = Vec::new();
            let mut stop = |page: &[Context]| {
                seen.extend_from_slice(page);
                Ok(false)
            };
            let stopped = source
                .visit_rust_reference_context_pages(
                    TypedFactRequest::new(&keys),
                    &live,
                    &mut TypedFactPageVisitor::with_maximum_rows(&mut stop, 1),
                )
                .unwrap();
            assert!(!stopped.is_exhausted());
            assert!(!stopped.is_cancelled());
            assert_eq!(seen.len(), 1);
            let during = CancellationToken::new();
            let callback_token = during.clone();
            let mut visited = 0;
            let mut cancel_after_page = |page: &[Context]| {
                visited += page.len();
                callback_token.cancel();
                Ok(true)
            };
            assert!(
                source
                    .visit_rust_reference_context_pages(
                        TypedFactRequest::new(&keys),
                        &during,
                        &mut TypedFactPageVisitor::with_maximum_rows(&mut cancel_after_page, 1)
                    )
                    .unwrap()
                    .is_cancelled()
            );
            assert_eq!(visited, 1);
            let cancelled = CancellationToken::new();
            cancelled.cancel();
            let mut reject = |_: &[Context]| -> Result<bool> {
                panic!("cancelled reader cannot visit");
            };
            assert!(
                source
                    .visit_rust_reference_context_pages(
                        TypedFactRequest::new(&keys),
                        &cancelled,
                        &mut TypedFactPageVisitor::new(&mut reject)
                    )
                    .unwrap()
                    .is_cancelled()
            );
        });
    }
}
