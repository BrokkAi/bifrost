use super::*;
use crate::analyzer::resolution::{
    BatchCandidateRequest, EndpointSignature, PartialPath, PartialPathId,
    ReverseCandidateGapExclusionPlan, ReverseCandidateGapIdentity,
    SelectedContextPathFragmentSource, SelectedContextPathSource, StackPattern, StackVariableId,
};
use crate::analyzer::store::resolution_selection::tests::SelectionFixture;
use crate::analyzer::store::resolution_stage::SelectedResolutionStage;

/// SQL stores a path's variable-sharing relation, not its caller's numeric
/// variable names or derived allocation ceiling. The model alpha key is an
/// independent endpoint oracle; all other observations compare exactly.
fn assert_context_paths_equal(
    actual: &[(CandidatePathIdentity, PartialPath)],
    expected: &[(CandidatePathIdentity, PartialPath)],
) {
    assert_eq!(actual.len(), expected.len());
    for ((actual_id, actual), (expected_id, expected)) in actual.iter().zip(expected) {
        assert_eq!(actual_id, expected_id);
        assert_eq!(
            actual
                .stack_effect_alpha_key_with_poll(&mut || false)
                .expect("uncancelled actual alpha key"),
            expected
                .stack_effect_alpha_key_with_poll(&mut || false)
                .expect("uncancelled expected alpha key"),
        );
        assert_eq!(actual.precedence(), expected.precedence());
        assert_eq!(actual.witness(), expected.witness());
        assert_eq!(actual.completion(), expected.completion());
    }
}

fn root_request() -> [BatchCandidateRequest; 1] {
    [BatchCandidateRequest::new(
        0,
        EndpointSignature::new(
            BindingNodeId::universal_root(),
            StackPattern::open([], StackVariableId::context_local(991)),
            StackPattern::closed([]),
        ),
    )]
}

#[test]
fn sql_context_adapter_preserves_mixed_pending_budget_stop_and_token_isolation() {
    let fixture = SelectionFixture::new(1);
    let selection = fixture.open_ready(&[]);
    let live = CancellationToken::new();
    let base = SelectedResolutionLexicalSource::new_on_demand(&selection);
    let requests = root_request();
    let ordinary = base.match_forward_candidates(&requests, &live).unwrap();
    assert!(!ordinary.matches().is_empty());
    let original_id = ordinary.matches()[0].candidate();
    let original = base
        .hydrate_candidate_paths(&[original_id], &live)
        .unwrap()
        .pop()
        .unwrap()
        .1;
    let additions = (0..3)
        .map(|ordinal| {
            (
                CandidatePathIdentity::new(
                    original_id.fragment(),
                    PartialPathId::context_local((1 << 53) + ordinal + 17),
                ),
                original
                    .clone()
                    .with_additional_completion(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::context_local(
                            900 + ordinal,
                        )),
                    ])),
            )
        })
        .collect::<Vec<_>>();
    let stage = SelectedResolutionStage::new(&selection);
    let first = stage
        .publish_context_paths(&live, |writer| {
            for (id, path) in &additions {
                assert!(writer.insert(*id, path)?);
            }
            Ok(true)
        })
        .unwrap()
        .unwrap();
    let second_path = original.clone();
    let second = stage
        .publish_context_paths(&live, |writer| writer.insert(additions[0].0, &second_path))
        .unwrap()
        .unwrap();
    let empty = stage
        .publish_context_paths(&live, |_| Ok(true))
        .unwrap()
        .unwrap();
    let source = SelectedContextPathFragmentSource::new(&base, &base, first, None);
    let second_source = SelectedContextPathFragmentSource::new(&base, &base, second, None);
    assert_context_paths_equal(
        &source
            .hydrate_candidate_paths(&[additions[0].0], &live)
            .unwrap(),
        &[additions[0].clone()],
    );
    assert_context_paths_equal(
        &second_source
            .hydrate_candidate_paths(&[additions[0].0], &live)
            .unwrap(),
        &[(additions[0].0, second_path)],
    );
    let page_size = ordinary.matches().len() + 2;
    assert!(page_size < crate::analyzer::resolution::MAX_SOURCE_ROWS_PER_BATCH);
    let mut complete_rows = Vec::new();
    let complete = source
        .visit_forward_candidate_match_pages_limited(
            &requests,
            page_size,
            None,
            &live,
            &mut |page| {
                complete_rows.extend_from_slice(page);
                Ok(true)
            },
        )
        .unwrap();
    assert_eq!(
        complete_rows.len(),
        ordinary.matches().len() + additions.len()
    );
    assert_eq!(
        complete.unconditional_completion(),
        ordinary.unconditional_completion()
    );
    assert_eq!(complete.branch_completions(), ordinary.branch_completions());
    let mut ordinary_stream = Vec::new();
    base.visit_forward_candidate_match_pages_limited(
        &requests,
        page_size,
        None,
        &live,
        &mut |page| {
            ordinary_stream.extend_from_slice(page);
            Ok(true)
        },
    )
    .unwrap();
    assert_eq!(
        &complete_rows[..ordinary_stream.len()],
        ordinary_stream.as_slice()
    );

    // Calibrate only the existing base layers, then allow one addition into
    // the still-partial shared output page. The second addition exhausts it.
    let base_session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
    let empty_source =
        SelectedContextPathFragmentSource::new(&base, &base, empty, Some(&base_session));
    empty_source
        .visit_forward_candidate_match_pages_limited(
            &requests,
            page_size,
            Some(&base_session),
            &live,
            &mut |_| Ok(true),
        )
        .unwrap();
    let budget = ReceiverAnalysisBudget {
        max_scope_nodes: base_session.finish(()).work().scope_nodes + 1,
        ..ReceiverAnalysisBudget::default()
    };
    let limited = ResolutionSession::bounded(budget, None);
    let limited_source =
        SelectedContextPathFragmentSource::new(&base, &base, first, Some(&limited));
    let mut callbacks = 0;
    let exhausted = limited_source
        .visit_forward_candidate_match_pages_limited(
            &requests,
            page_size,
            Some(&limited),
            &live,
            &mut |_| {
                callbacks += 1;
                Ok(true)
            },
        )
        .unwrap();
    assert_eq!(
        callbacks, 0,
        "base plus one addition remains unpublished on exhaustion"
    );
    assert!(
        exhausted
            .unconditional_completion()
            .contains_reason(ResolutionIncompleteReason::Cancelled)
    );
    assert_eq!(
        exhausted.branch_completions(),
        ordinary.branch_completions()
    );

    // Stop in the base, additions, and final flush. Whole-batch coverage is
    // independent of the emitted prefix, including context path evidence.
    for limit in [1, ordinary.matches().len() + 1, complete_rows.len() + 1] {
        let mut callbacks = 0;
        let stopped = source
            .visit_forward_candidate_match_pages_limited(&requests, limit, None, &live, &mut |_| {
                callbacks += 1;
                Ok(false)
            })
            .unwrap();
        assert_eq!(callbacks, 1);
        assert_eq!(
            stopped.unconditional_completion(),
            complete.unconditional_completion()
        );
        assert_eq!(stopped.branch_completions(), complete.branch_completions());
    }

    let cancelled = CancellationToken::new();
    let mut published = Vec::new();
    let outcome = source
        .visit_forward_candidate_match_pages_limited(
            &requests,
            page_size,
            None,
            &cancelled,
            &mut |page| {
                published.extend_from_slice(page);
                cancelled.cancel();
                Ok(true)
            },
        )
        .unwrap();
    assert_eq!(published.len(), page_size);
    assert!(
        outcome
            .unconditional_completion()
            .contains_reason(ResolutionIncompleteReason::Cancelled)
    );
    assert_eq!(outcome.branch_completions(), ordinary.branch_completions());
}

#[test]
fn sql_context_adapter_rejects_base_collisions_and_forwards_generic_exclusions() {
    let fixture = SelectionFixture::new(1);
    let selection = fixture.open_ready(&[]);
    let live = CancellationToken::new();
    let base = SelectedResolutionLexicalSource::new_on_demand(&selection);
    let requests = root_request();
    let ordinary = base.match_forward_candidates(&requests, &live).unwrap();
    let identity = ordinary.matches()[0].candidate();
    let path = base
        .hydrate_candidate_paths(&[identity], &live)
        .unwrap()
        .pop()
        .unwrap()
        .1;
    let stage = SelectedResolutionStage::new(&selection);
    let collision = stage
        .publish_context_paths(&live, |writer| writer.insert(identity, &path))
        .unwrap()
        .unwrap();
    let source = SelectedContextPathFragmentSource::new(&base, &base, collision, None);
    let mut callbacks = 0;
    let error = source
        .visit_forward_candidate_match_pages(&requests, &live, &mut |_| {
            callbacks += 1;
            Ok(true)
        })
        .unwrap_err();
    assert!(error.to_string().contains("collides"));
    assert_eq!(callbacks, 0);

    let empty = stage
        .publish_context_paths(&live, |_| Ok(true))
        .unwrap()
        .unwrap();
    let source = SelectedContextPathFragmentSource::new(&base, &base, empty, None);
    let invalid = ReverseCandidateGapIdentity::new(
        identity.fragment(),
        SemanticId::local(identity.fragment().ordinal(), u32::MAX),
    );
    let mut base_plan = ReverseCandidateGapExclusionPlan::new([invalid]);
    let mut adapted_plan = ReverseCandidateGapExclusionPlan::new([invalid]);
    let expected = base
        .visit_reverse_candidate_match_pages_with_gap_exclusions_shared(
            &requests,
            &mut base_plan,
            &live,
            &mut |_| Ok(true),
        )
        .unwrap_err();
    let actual = source
        .visit_reverse_candidate_match_pages_with_gap_exclusions_shared(
            &requests,
            &mut adapted_plan,
            &live,
            &mut |_| Ok(true),
        )
        .unwrap_err();
    assert_eq!(actual.to_string(), expected.to_string());
}

#[test]
fn sql_context_adapter_late_body_completion_conflict_rolls_back_new_token() {
    let fixture = SelectionFixture::new(1);
    let selection = fixture.open_ready(&[]);
    let live = CancellationToken::new();
    let base = SelectedResolutionLexicalSource::new_on_demand(&selection);
    let requests = root_request();
    let ordinary = base.match_forward_candidates(&requests, &live).unwrap();
    let ordinary_id = ordinary.matches()[0].candidate();
    let path = base
        .hydrate_candidate_paths(&[ordinary_id], &live)
        .unwrap()
        .pop()
        .unwrap()
        .1;
    let identity = CandidatePathIdentity::new(
        ordinary_id.fragment(),
        PartialPathId::context_local((1 << 53) + 41),
    );
    let stage = SelectedResolutionStage::new(&selection);
    let existing = stage
        .publish_context_paths(&live, |writer| writer.insert(identity, &path))
        .unwrap()
        .unwrap();
    let before: i64 = selection
        .connection()
        .query_row(
            "SELECT count(*) FROM temp.selected_resolution_contexts",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let changed = path
        .clone()
        .with_additional_completion(&ResolutionCompletion::incomplete([
            ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::context_local(701)),
        ]));
    assert!(
        stage
            .publish_context_paths(&live, |writer| {
                assert!(writer.insert(identity, &path)?);
                writer.insert(identity, &changed)
            })
            .is_err()
    );
    let after: i64 = selection
        .connection()
        .query_row(
            "SELECT count(*) FROM temp.selected_resolution_contexts",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(before, after);
    let source = SelectedContextPathFragmentSource::new(&base, &base, existing, None);
    assert_context_paths_equal(
        &source.hydrate_candidate_paths(&[identity], &live).unwrap(),
        &[(identity, path)],
    );
}

/// Inject cancellation at the actual base-to-context handoff, after the base
/// has filled only part of the adapter's pending output page.
struct CancelBeforeContextAdditions<'a>(&'a dyn SelectedContextPathSource);

impl SelectedContextPathSource for CancelBeforeContextAdditions<'_> {
    fn visit_context_forward_additions(
        &self,
        token: crate::analyzer::resolution::SelectedContextPathToken,
        requests: &[BatchCandidateRequest],
        completion: crate::analyzer::resolution::BatchCandidateCompletionOutcome,
        maximum_page_rows: usize,
        cancellation: &CancellationToken,
        session: Option<&ResolutionSession>,
        visitor: &mut dyn FnMut(
            &[crate::analyzer::resolution::BatchCandidateMatch],
        ) -> Result<bool>,
    ) -> Result<crate::analyzer::resolution::BatchCandidateCompletionOutcome> {
        cancellation.cancel();
        self.0.visit_context_forward_additions(
            token,
            requests,
            completion,
            maximum_page_rows,
            cancellation,
            session,
            visitor,
        )
    }
    fn visit_context_reverse_additions(
        &self,
        token: crate::analyzer::resolution::SelectedContextPathToken,
        requests: &[BatchCandidateRequest],
        completion: crate::analyzer::resolution::BatchCandidateCompletionOutcome,
        maximum_page_rows: usize,
        cancellation: &CancellationToken,
        session: Option<&ResolutionSession>,
        visitor: &mut dyn FnMut(
            &[crate::analyzer::resolution::BatchCandidateMatch],
        ) -> Result<bool>,
    ) -> Result<crate::analyzer::resolution::BatchCandidateCompletionOutcome> {
        self.0.visit_context_reverse_additions(
            token,
            requests,
            completion,
            maximum_page_rows,
            cancellation,
            session,
            visitor,
        )
    }
    fn context_paths(
        &self,
        token: crate::analyzer::resolution::SelectedContextPathToken,
        cancellation: &CancellationToken,
    ) -> Result<
        Option<
            Vec<(
                CandidatePathIdentity,
                crate::analyzer::resolution::PartialPath,
            )>,
        >,
    > {
        self.0.context_paths(token, cancellation)
    }
    fn hydrate_context_paths(
        &self,
        token: crate::analyzer::resolution::SelectedContextPathToken,
        candidates: &[CandidatePathIdentity],
        cancellation: &CancellationToken,
    ) -> Result<
        Option<
            Vec<(
                CandidatePathIdentity,
                crate::analyzer::resolution::PartialPath,
            )>,
        >,
    > {
        self.0
            .hydrate_context_paths(token, candidates, cancellation)
    }
}

#[test]
fn sql_context_adapter_cancelled_handoff_drops_partial_base_page() {
    let fixture = SelectionFixture::new(1);
    let selection = fixture.open_ready(&[]);
    let live = CancellationToken::new();
    let base = SelectedResolutionLexicalSource::new_on_demand(&selection);
    let requests = root_request();
    let ordinary = base.match_forward_candidates(&requests, &live).unwrap();
    assert!(!ordinary.matches().is_empty());
    let stage = SelectedResolutionStage::new(&selection);
    let token = stage
        .publish_context_paths(&live, |_| Ok(true))
        .unwrap()
        .unwrap();
    let cancel_context = CancelBeforeContextAdditions(&base);
    let source = SelectedContextPathFragmentSource::new(&base, &cancel_context, token, None);
    let cancellation = CancellationToken::new();
    let mut callbacks = 0;
    let result = source
        .visit_forward_candidate_match_pages_limited(
            &requests,
            ordinary.matches().len() + 1,
            None,
            &cancellation,
            &mut |_| {
                callbacks += 1;
                Ok(true)
            },
        )
        .unwrap();
    assert_eq!(callbacks, 0);
    assert!(
        result
            .unconditional_completion()
            .contains_reason(ResolutionIncompleteReason::Cancelled)
    );
    assert_eq!(result.branch_completions(), ordinary.branch_completions());
}

#[test]
fn borrowed_row_seam_preserves_candidate_results_and_session_work() {
    let fixture = SelectionFixture::new(1);
    let selection = fixture.open_ready(&[]);
    let live = CancellationToken::new();
    let raw = SelectedResolutionLexicalSource::new_on_demand(&selection);
    let observed = SeamProfiled::observing(&raw);
    let requests = root_request();
    let baseline = raw.match_forward_candidates(&requests, &live).unwrap();
    assert!(!baseline.matches().is_empty());
    for maximum in [0, 1, 64] {
        let budget = ReceiverAnalysisBudget {
            max_scope_nodes: maximum,
            ..ReceiverAnalysisBudget::default()
        };
        let read = |source: &dyn BatchResolutionFragmentSource| {
            let session = ResolutionSession::bounded(budget, None);
            let mut rows = Vec::new();
            let outcome = source
                .visit_forward_candidate_match_pages_limited(
                    &requests,
                    2,
                    Some(&session),
                    &live,
                    &mut |page| {
                        rows.extend_from_slice(page);
                        Ok(true)
                    },
                )
                .unwrap();
            (rows, outcome, session.finish(()).work().scope_nodes)
        };
        let (rows, outcome, work) = read(&raw);
        let (observed_rows, observed_outcome, observed_work) = read(&observed);
        assert_eq!(observed_rows, rows);
        assert_eq!(
            observed_outcome.unconditional_completion(),
            outcome.unconditional_completion()
        );
        assert_eq!(
            observed_outcome.branch_completions(),
            outcome.branch_completions()
        );
        assert_eq!(
            observed_work, work,
            "observation must not charge a second visitor budget"
        );
    }
}

#[test]
fn selected_row_fragment_inventory_preserves_page_boundaries_stop_and_cancel() {
    use crate::analyzer::resolution::{MAX_TYPED_FACT_ROWS_PER_PAGE, TypedFactReadTerminal};
    for count in [
        0,
        1,
        MAX_TYPED_FACT_ROWS_PER_PAGE,
        MAX_TYPED_FACT_ROWS_PER_PAGE + 1,
    ] {
        let fixture = SelectionFixture::shared_blob(count);
        let selection = fixture.open_ready(&[]);
        let expected = selection
            .mounts()
            .unwrap()
            .iter()
            .map(|mount| mount.fragment_id())
            .collect::<Vec<_>>();
        let raw = SelectedResolutionTypedSource::new_on_demand(&selection);
        let observed = SeamProfiled::observing(&raw);
        let live = CancellationToken::new();
        let mut rows = Vec::new();
        let mut sizes = Vec::new();
        let outcome = observed
            .visit_selected_fragment_pages(
                &live,
                &mut FactPageVisitor::new(&mut |page| {
                    rows.extend_from_slice(page);
                    sizes.push(page.len());
                    Ok(true)
                }),
            )
            .unwrap();
        assert_eq!(rows, expected);
        assert!(outcome.is_exhausted());
        assert_eq!(outcome.evidence(), &ResolutionCompletion::Complete);
        assert_eq!(
            sizes,
            expected
                .chunks(MAX_TYPED_FACT_ROWS_PER_PAGE)
                .map(<[_]>::len)
                .collect::<Vec<_>>()
        );
        if count > MAX_TYPED_FACT_ROWS_PER_PAGE {
            let mut stopped_rows = Vec::new();
            let stopped = observed
                .visit_selected_fragment_pages(
                    &live,
                    &mut FactPageVisitor::new(&mut |page| {
                        stopped_rows.extend_from_slice(page);
                        Ok(false)
                    }),
                )
                .unwrap();
            assert_eq!(stopped.terminal(), TypedFactReadTerminal::Stopped);
            assert_eq!(stopped_rows, expected[..MAX_TYPED_FACT_ROWS_PER_PAGE]);
            let token = CancellationToken::new();
            let mut cancelled_rows = Vec::new();
            let cancelled = observed
                .visit_selected_fragment_pages(
                    &token,
                    &mut FactPageVisitor::new(&mut |page| {
                        cancelled_rows.extend_from_slice(page);
                        token.cancel();
                        Ok(true)
                    }),
                )
                .unwrap();
            assert!(cancelled.is_cancelled());
            assert_eq!(cancelled_rows, expected[..MAX_TYPED_FACT_ROWS_PER_PAGE]);
            assert!(
                observed
                    .visit_selected_fragment_pages(
                        &token,
                        &mut FactPageVisitor::new(&mut |_| {
                            panic!("pre-cancelled inventory cannot publish a page")
                        })
                    )
                    .unwrap()
                    .is_cancelled()
            );
        }
    }
}
