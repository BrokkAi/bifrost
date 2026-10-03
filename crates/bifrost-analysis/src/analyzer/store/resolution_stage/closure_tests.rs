use super::*;
use crate::analyzer::Language;
use crate::analyzer::resolution::SelectedResolutionMountOrdinal;
use crate::analyzer::store::WorkspaceSnapshots;
use crate::analyzer::store::resolution_lexical::SelectedResolutionLexicalSource;
use crate::analyzer::store::resolution_operation::with_dense_selected_macro_fixture;
use crate::analyzer::store::resolution_selection::{
    SelectedResolutionLanguage, SelectedResolutionMountInventoryOutcome, tests::SelectionFixture,
};
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId;

#[test]
fn structured_closure_kinds_preserve_exact_authority_repeat_and_atomicity() {
    // The three APIs accept a structured decision established by the caller.
    // This stage law tests descriptor/authority/transaction behavior; it does
    // not claim the matched macro fixture made unmatched/empty/include decisions.
    // Those decisions are exercised by the actual operation matcher tests.
    with_dense_selected_macro_fixture(|store, owner, fixtures| {
        let live = CancellationToken::new();
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
            panic!("actual macro owners are ready")
        };
        let fixture = &fixtures[0];
        let host = selection
            .mount_record_for_path(&owner.lang, &fixture.host_path)
            .unwrap()
            .unwrap();
        let definition_ordinal:u32=selection.connection().query_row(
            "SELECT mount_ordinal FROM temp.selected_resolution_mounts WHERE blob_oid=?1 ORDER BY mount_ordinal LIMIT 1",
            [fixture.key.definition_content_oid.to_string()],|row|row.get(0)).unwrap();
        let definition = selection
            .persisted_mount_record(SelectedResolutionMountOrdinal::new(definition_ordinal))
            .unwrap()
            .unwrap();
        let (site,start):(u32,usize)=selection.connection().query_row(
            "SELECT native_gap_site,invocation_start_byte FROM source_rust_macro_inputs WHERE blob_id=?1 AND invocation_occurrence_id=?2",
            params![host.blob_id(),fixture.key.invocation.get()],|row|Ok((row.get(0)?,row.get(1)?))).unwrap();
        let source = SelectedResolutionLexicalSource::new_on_demand(&selection);
        let mut expected = source
            .unsupported_gap_reasons(host.ordinal(), ResolutionSiteId::new(site), &live)
            .unwrap()
            .unwrap()
            .into_iter()
            .map(super::super::codec::encode_semantic)
            .collect::<Vec<_>>();
        expected.sort_unstable();
        expected.dedup();
        assert!(!expected.is_empty());
        let stage = SelectedResolutionStage::new(&selection);
        let call = |kind, cancellation: &CancellationToken| match kind {
            0 => stage.close_unmatched_macro_input(
                &host,
                fixture.key.invocation,
                &definition,
                fixture.key.selected_declaration,
                cancellation,
            ),
            1 => stage.close_empty_macro_input(
                &host,
                fixture.key.invocation,
                &definition,
                fixture.key.selected_declaration,
                fixture.key.matched_arm_index,
                cancellation,
            ),
            2 => stage.close_included_macro_input(
                &host,
                fixture.key.invocation,
                &definition,
                start,
                cancellation,
            ),
            _ => unreachable!(),
        };
        let epoch = selection.stage_content_epoch_for_test();
        for kind in 0..3 {
            assert!(matches!(
                call(kind, &live).unwrap(),
                SelectedResolutionStageOutcome::Ready
            ));
            assert_eq!(
                selection.stage_content_epoch_for_test(),
                epoch + kind as u64 + 1
            );
            let changes = selection.connection().total_changes();
            assert!(matches!(
                call(kind, &live).unwrap(),
                SelectedResolutionStageOutcome::Ready
            ));
            assert_eq!(selection.connection().total_changes(), changes);
            assert_eq!(
                selection.stage_content_epoch_for_test(),
                epoch + kind as u64 + 1
            );
        }
        let producers:Vec<i64>=selection.connection().prepare("SELECT producer_id FROM temp.selected_resolution_stage_producers ORDER BY producer_id").unwrap()
            .query_map([],|row|row.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap();
        assert_eq!(
            producers.len(),
            3,
            "proof kinds occupy distinct identity domains"
        );
        for producer in &producers {
            let actual=selection.connection().prepare("SELECT semantic_key FROM temp.selected_resolution_stage_closed_reasons WHERE producer_id=?1 ORDER BY semantic_key").unwrap()
                .query_map([producer],|row|row.get::<_,i64>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            assert_eq!(actual, expected);
        }
        selection.with_owned_temp_write(|connection| {
            connection.execute("DELETE FROM temp.selected_resolution_stage_closed_reasons WHERE producer_id=?1 AND semantic_key=?2",params![producers[0],expected[0]])?;
            Ok(())
        }).unwrap();
        assert!(
            call(0, &live).is_err(),
            "exact repeat rejects altered producer closure rows"
        );
        let foreign_fixture = SelectionFixture::new(1);
        let foreign_selection = foreign_fixture.open_ready(&[]);
        let foreign = foreign_selection
            .persisted_mount_record(SelectedResolutionMountOrdinal::new(0))
            .unwrap()
            .unwrap();
        let before = selection.stage_content_epoch_for_test();
        assert!(
            stage
                .close_unmatched_macro_input(
                    &host,
                    fixture.key.invocation,
                    &foreign,
                    fixture.key.selected_declaration,
                    &live
                )
                .is_err()
        );
        assert_eq!(selection.stage_content_epoch_for_test(), before);
        stage.clear_facts().unwrap();
        let before = selection.stage_content_epoch_for_test();
        let cancelled = CancellationToken::new();
        let trigger_cancel = cancelled.clone();
        selection
            .connection()
            .create_scalar_function(
                "cancel_exact_closure",
                0,
                rusqlite::functions::FunctionFlags::SQLITE_UTF8,
                move |_| {
                    trigger_cancel.cancel();
                    Ok(0)
                },
            )
            .unwrap();
        selection.with_owned_temp_write(|connection| {
            connection.execute_batch("CREATE TEMP TRIGGER cancel_exact_closure AFTER INSERT ON selected_resolution_stage_producers BEGIN SELECT cancel_exact_closure(); END;")?;
            Ok(())
        }).unwrap();
        assert!(matches!(
            call(0, &cancelled).unwrap(),
            SelectedResolutionStageOutcome::Cancelled
        ));
        assert!(cancelled.is_cancelled());
        assert!(selection.connection().is_autocommit());
        assert_eq!(selection.stage_content_epoch_for_test(), before);
        for table in [
            "selected_resolution_stage_producers",
            "selected_resolution_stage_closed_reasons",
        ] {
            assert_eq!(
                selection
                    .connection()
                    .query_row(&format!("SELECT count(*) FROM temp.{table}"), [], |row| row
                        .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
        selection
            .with_owned_temp_write(|connection| {
                connection.execute_batch("DROP TRIGGER temp.cancel_exact_closure")?;
                Ok(())
            })
            .unwrap();
        selection
            .connection()
            .remove_function("cancel_exact_closure", 0)
            .unwrap();
        assert!(matches!(
            call(0, &live).unwrap(),
            SelectedResolutionStageOutcome::Ready
        ));
        assert_eq!(selection.stage_content_epoch_for_test(), before + 1);
    });
}
