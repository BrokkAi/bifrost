#[cfg(test)]
mod jvm_extraction_tests {

    use std::collections::BTreeSet;

    use brokk_bifrost_analysis::analyzer::resolution::model::BindingFragmentId;

    use brokk_bifrost_analysis::analyzer::resolution::model::BindingNodeId;

    use brokk_bifrost_analysis::analyzer::store::resolution_lexical::BoundaryHeaderProbe;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::store::resolution_lexical::CandidateDirection;

    use brokk_bifrost_analysis::analyzer::resolution::completion_reasons::CompletionReasons;

    use brokk_bifrost_analysis::analyzer::resolution::model::PartialPathId;

    use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

    use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionIncompleteReason;

    use brokk_bifrost_analysis::analyzer::store::resolution_lexical::SelectedResolutionLexicalSource;

    use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedResolutionMountOrdinal;

    use brokk_bifrost_analysis::analyzer::resolution::model::SemanticId;

    use brokk_bifrost_analysis::analyzer::resolution::model::SharedNameId;

    use brokk_bifrost_analysis::analyzer::store::resolution_lexical::UnconditionalCandidateBox;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#6291: visited mount completion decoded every selected mount's gaps"
    )]
    fn jvm_scoped_unconditional_gaps_keep_only_the_visited_mounts() {
        use brokk_bifrost_analysis::analyzer::store::resolution_lexical::UnconditionalCandidateCache;
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::selected_sql_trace::{
            begin_production_selected_sql_trace_on_connection,
            finish_production_selected_sql_trace_on_connection,
        };
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(2);
        let selection = fixture.open_ready(&[]);
        fixture.store.conn.execute(|conn| {
            conn.execute("INSERT INTO resolution_gap_reasons(blob_id,reason,site,origin) SELECT blob_id,930001,0,2 FROM resolution_fragment_interiors", []).unwrap();
            conn.execute("INSERT INTO resolution_gaps(blob_id,covers,subject,lookup,gap,reason) SELECT blob_id,0,0,0,930001,930001 FROM resolution_fragment_interiors", []).unwrap();
        });
        let cache = std::rc::Rc::new(UnconditionalCandidateCache::for_operation());
        let cancellation = CancellationToken::new();
        let read = |scope: Option<&[SelectedResolutionMountOrdinal]>| {
            let source = SelectedResolutionLexicalSource::new_on_demand_with_unconditional_cache(
                &selection,
                std::rc::Rc::clone(&cache),
            );
            let (answer, cancelled) = source
                .lazy_candidate_completion(
                    CandidateDirection::Forward,
                    &[],
                    scope,
                    None,
                    &cancellation,
                )
                .unwrap();
            assert!(!cancelled);
            answer.unconditional_completion().clone()
        };
        let reason = |ordinal| {
            ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::local(ordinal, 930001))
        };
        begin_production_selected_sql_trace_on_connection(selection.connection());
        let one = [SelectedResolutionMountOrdinal::new(1)];
        let expected = ResolutionCompletion::incomplete([reason(1)]);
        assert_eq!(read(Some(&one)), expected);
        assert_eq!(read(Some(&one)), expected);
        assert_eq!(read(Some(&[])), ResolutionCompletion::Complete);
        assert_eq!(
            read(Some(&[SelectedResolutionMountOrdinal::new(0)])),
            ResolutionCompletion::incomplete([reason(0)])
        );
        assert_eq!(
            read(None),
            ResolutionCompletion::incomplete([reason(0), reason(1)])
        );
        let trace = finish_production_selected_sql_trace_on_connection(selection.connection());
        let gap_reads = trace
            .statements
            .iter()
            .filter(|sql| sql.contains("resolution_gaps_fragment_wide"))
            .collect::<Vec<_>>();
        assert_eq!(
            gap_reads.len(),
            4,
            "exact scoped gap reads share one operation: {trace:?}"
        );
        assert_eq!(
            gap_reads
                .iter()
                .filter(|sql| sql.contains("json_each"))
                .count(),
            3,
            "restricted visits use indexed mount seeks: {trace:?}"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#6291: by_path mount reads repeated SQL within one selection"
    )]
    fn jvm_mount_path_memo_retains_hits_and_absence_in_its_selection() {
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::selected_sql_trace::{
            begin_production_selected_sql_trace_on_connection,
            finish_production_selected_sql_trace_on_connection,
        };
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(1);
        let selection = fixture.open_ready(&[]);
        let mount = selection
            .persisted_mount_record(SelectedResolutionMountOrdinal::new(0))
            .unwrap()
            .unwrap();
        begin_production_selected_sql_trace_on_connection(selection.connection());
        for _ in 0..2 {
            assert_eq!(
                selection
                    .mount_record_for_path("java", mount.persisted_relative_path())
                    .unwrap()
                    .as_deref(),
                Some(mount.as_ref())
            );
            assert!(
                selection
                    .mount_record_for_path("java", "missing.java")
                    .unwrap()
                    .is_none()
            );
        }
        let trace = finish_production_selected_sql_trace_on_connection(selection.connection());
        assert_eq!(
            trace.statements.len(),
            2,
            "both present and absent paths are memoized: {trace:?}"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#6291: fresh JVM lexical readers repeated identical operation-wide gap reads"
    )]
    fn jvm_operation_gap_memo_survives_publication_but_follows_scope_writes() {
        use brokk_bifrost_analysis::analyzer::store::resolution_lexical::UnconditionalCandidateCache;
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::selected_sql_trace::{
            begin_production_selected_sql_trace_on_connection,
            finish_production_selected_sql_trace_on_connection,
        };

        let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(2);
        let selection = fixture.open_ready(&[]);
        let cancellation = CancellationToken::new();
        let cache = std::rc::Rc::new(UnconditionalCandidateCache::for_operation());
        let read = |direction| {
            let source = SelectedResolutionLexicalSource::new_on_demand_with_unconditional_cache(
                &selection,
                std::rc::Rc::clone(&cache),
            );
            let (answer, cancelled) = source
                .lazy_candidate_completion(direction, &[], None, None, &cancellation)
                .unwrap();
            assert!(!cancelled);
            answer.unconditional_completion().clone()
        };
        begin_production_selected_sql_trace_on_connection(selection.connection());
        let whole = read(CandidateDirection::Forward);
        assert_eq!(read(CandidateDirection::Forward), whole);
        selection.note_stage_content_commit();
        assert_eq!(read(CandidateDirection::Forward), whole);
        read(CandidateDirection::Reverse);
        selection
            .with_owned_temp_write(|connection| {
                connection.execute(
                    "DELETE FROM temp.selected_resolution_scope_mounts WHERE mount_ordinal=1",
                    [],
                )?;
                Ok(())
            })
            .unwrap();
        let narrowed = read(CandidateDirection::Forward);
        let uncached = SelectedResolutionLexicalSource::new_on_demand(&selection);
        let (expected, cancelled) = uncached
            .lazy_candidate_completion(CandidateDirection::Forward, &[], None, None, &cancellation)
            .unwrap();
        assert!(!cancelled);
        assert_eq!(&narrowed, expected.unconditional_completion());
        selection.reset_scope_mounts().unwrap();
        assert_eq!(read(CandidateDirection::Forward), whole);
        let trace = finish_production_selected_sql_trace_on_connection(selection.connection());
        assert_eq!(
            trace
                .statements
                .iter()
                .filter(|sql| sql.contains("resolution_gaps_fragment_wide"))
                .count(),
            5,
            "one initial read, reverse, narrowed, uncached comparison and restored scope: {trace:?}"
        );
    }

    #[test]
    fn header_read_memo_follows_scope_writes_and_explicit_mount_restrictions() {
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(2);
        let selection = fixture.open_ready(&[]);
        let source = SelectedResolutionLexicalSource::new_on_demand(&selection);
        let cancellation = CancellationToken::default();
        let probe = BoundaryHeaderProbe {
            first_symbol: None,
            symbol_fixed_count: 0,
            symbol_has_tail: true,
        };
        let read = |restriction: Option<&str>| {
            let mut positions = BTreeSet::new();
            source
                .extend_boundary_header_mounts(
                    CandidateDirection::Reverse,
                    probe,
                    restriction,
                    &mut positions,
                    &cancellation,
                )
                .unwrap();
            positions
        };
        let whole = read(None);
        assert_eq!(whole.len(), 2);
        assert_eq!(read(None), whole);
        selection
            .with_owned_temp_write(|connection| {
                connection.execute(
                    "DELETE FROM temp.selected_resolution_scope_mounts WHERE mount_ordinal=1",
                    [],
                )?;
                Ok(())
            })
            .unwrap();
        assert_eq!(read(None).len(), 1);
        selection.reset_scope_mounts().unwrap();
        assert_eq!(read(None), whole);
        assert_eq!(read(Some("[0]")).len(), 1);
        assert_eq!(read(None), whole);
        cancellation.cancel();
        assert!(read(None).is_empty());
    }
    #[test]
    fn stage_suppression_preserves_factored_boxes_and_refreshes_after_clear() {
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(1);
        let selection = fixture.open_ready(&[]);
        let shared = SemanticId::shared_name(SharedNameId::per_request(701));
        let other_shared = SemanticId::shared_name(SharedNameId::per_request(702));
        let closed = ResolutionIncompleteReason::UnsupportedSemantic(shared);
        let survivor = ResolutionIncompleteReason::UnsupportedSemantic(other_shared);
        let mut reasons = (0..256)
            .map(|key| ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::local(0, key)))
            .chain([closed, survivor])
            .collect::<Vec<_>>();
        reasons.sort_unstable();
        let whole = ResolutionCompletion::Incomplete(CompletionReasons::shared_from_canonical(
            reasons.clone().into_boxed_slice(),
        ));
        selection.with_owned_temp_write(|connection| {
            connection.execute("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(0,?1,?2)", params![[171u8;32].as_slice(),[172u8;32].as_slice()])?;
            connection.execute("INSERT INTO temp.selected_resolution_stage_closed_reasons(producer_id,semantic_shared) VALUES(?1,?2)",params![connection.last_insert_rowid(),shared.shared_name_id().unwrap().get()])?;
            Ok(())
        }).unwrap();
        let source = SelectedResolutionLexicalSource::new_on_demand(&selection);
        // Supply the same factored ordinary box that the tier-1 reader publishes.
        source.unconditional_candidate_reasons[0]
            .set(UnconditionalCandidateBox {
                whole: whole.clone(),
                positions: vec![0; reasons.len()].into_boxed_slice(),
            })
            .unwrap();
        let cancellation = CancellationToken::default();
        for _ in 0..64 {
            let (answer, cancelled) = source
                .lazy_candidate_completion(
                    CandidateDirection::Forward,
                    &[],
                    None,
                    None,
                    &cancellation,
                )
                .unwrap();
            assert!(!cancelled);
            assert!(!answer.unconditional_completion().contains_reason(closed));
            assert!(answer.unconditional_completion().contains_reason(survivor));
            let ResolutionCompletion::Incomplete(kept) = answer.unconditional_completion() else {
                panic!("unclosed ordinary evidence remains");
            };
            assert!(kept.is_shared(), "suppression preserves the factored base");
            assert_eq!(kept.len(), reasons.len() - 1);
        }
        let authority = source
            .ordinary_completion_suppression
            .borrow()
            .as_ref()
            .unwrap()
            .authority;
        brokk_bifrost_analysis::analyzer::store::resolution_stage::SelectedResolutionStage::new(
            &selection,
        )
        .clear_facts()
        .unwrap();
        assert_ne!(authority, selection.candidate_coverage_fingerprint());
        let (answer, cancelled) = source
            .lazy_candidate_completion(CandidateDirection::Forward, &[], None, None, &cancellation)
            .unwrap();
        assert!(!cancelled);
        assert_eq!(answer.unconditional_completion(), &whole);
        assert_eq!(
            source
                .ordinary_completion_suppression
                .borrow()
                .as_ref()
                .unwrap()
                .authority,
            selection.candidate_coverage_fingerprint()
        );

        let before_commit = selection.candidate_coverage_fingerprint();
        let fragment = BindingFragmentId::at_ordinal(0);
        let lowered =
            brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweredResolutionFragment::selected_macro_head_bridge(
                fragment,
                SemanticId::operation_local(9101),
                BindingNodeId::operation_local(9102),
                BindingNodeId::operation_local(9103),
                PartialPathId::operation_local(9104),
            );
        let host = selection
            .persisted_mount_record(SelectedResolutionMountOrdinal::new(0))
            .unwrap()
            .unwrap();
        assert!(matches!(
            brokk_bifrost_analysis::analyzer::store::resolution_stage::SelectedResolutionStage::new(&selection)
                .insert_generated_bridge(
                    &host,
                    [173; 32],
                    &lowered,
                    None,
                    &[],
                    &[shared],
                    &cancellation
                )
                .unwrap(),
            brokk_bifrost_analysis::analyzer::store::resolution_stage::SelectedResolutionStageOutcome::Ready
        ));
        assert_ne!(before_commit, selection.candidate_coverage_fingerprint());
        let (answer, cancelled) = source
            .lazy_candidate_completion(CandidateDirection::Forward, &[], None, None, &cancellation)
            .unwrap();
        assert!(!cancelled);
        assert!(!answer.unconditional_completion().contains_reason(closed));
        assert!(answer.unconditional_completion().contains_reason(survivor));
        let cold = SelectedResolutionLexicalSource::new_on_demand(&selection);
        cold.unconditional_candidate_reasons[0]
            .set(UnconditionalCandidateBox {
                whole,
                positions: vec![0; reasons.len()].into_boxed_slice(),
            })
            .unwrap();
        cancellation.cancel();
        let (answer, cancelled) = cold
            .lazy_candidate_completion(CandidateDirection::Forward, &[], None, None, &cancellation)
            .unwrap();
        assert!(cancelled);
        assert!(answer.unconditional_completion().contains_reason(survivor));
        assert!(
            answer
                .unconditional_completion()
                .contains_reason(ResolutionIncompleteReason::Cancelled)
        );
        assert!(
            cold.ordinary_completion_suppression.borrow().is_none(),
            "an interrupted suppression read cannot publish a cache entry"
        );
    }

    use rusqlite::params;
}
