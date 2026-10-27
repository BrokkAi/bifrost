#[cfg(not(test))]
use super::*;

#[cfg(not(test))]
use crate::analyzer::resolution::{
    BatchResolutionFragmentSource, BindingNodeKind, EndpointSignature, LoweredResolutionFragment,
    PartialPathId, PartialScopedSymbol, ResolutionCompletion, ResolutionIncompleteReason,
    StackPattern, WitnessStep,
};

#[cfg(not(test))]
use crate::analyzer::store::resolution_lexical::SelectedResolutionLexicalSource;

#[cfg(not(test))]
use crate::analyzer::store::resolution_selection::selection_test_support::SelectionFixture;

#[cfg(not(test))]
use rusqlite::params;

use brokk_bifrost_test_macros::hardwon;

#[test]
#[hardwon(
    "#5671: context candidates skipped prefix admission, composing whole package-domain buckets"
)]
fn context_package_candidates_admit_only_matching_and_open_prefixes() {
    use super::*;
    use crate::analyzer::resolution::{
        BatchCandidateRequest, EndpointSignature, PartialPathId, ResolutionCompletion,
        SharedNameId, StackPattern, StackVariableId,
    };
    use crate::analyzer::store::resolution_lexical::CandidatePageVisit;
    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
    use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
    use rusqlite::types::Value;

    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(super::super::context::schema_sql())
        .unwrap();
    connection
        .execute(
            "INSERT INTO temp.selected_resolution_contexts VALUES(1)",
            [],
        )
        .unwrap();
    let cancellation = CancellationToken::new();
    let domain = SemanticId::shared_name(SharedNameId::interned(1));
    let token = SemanticId::local(0, 1);
    let name = SemanticId::shared_name(SharedNameId::interned(2));
    let endpoint = |fixed: Vec<SemanticId>, tail| {
        EndpointSignature::new(
            BindingNodeId::universal_root(),
            StackPattern::new(fixed, tail),
            StackPattern::closed(vec![]),
        )
    };
    let mut candidates = Vec::new();
    for t in 1..=16 {
        for n in 2..=17 {
            candidates.push(endpoint(
                vec![
                    domain,
                    SemanticId::local(0, t),
                    SemanticId::shared_name(SharedNameId::interned(n)),
                ],
                None,
            ));
        }
    }
    let tail = Some(StackVariableId::context_local(0));
    for prefix in [vec![], vec![domain], vec![domain, token]] {
        candidates.push(endpoint(prefix.clone(), tail));
        // A shorter closed prefix cannot unify with the requested three cells.
        candidates.push(endpoint(prefix, None));
    }
    let expected = [0, 256, 258, 260].map(|i| {
        CandidatePathIdentity::new(
            BindingFragmentId::at_ordinal(0),
            PartialPathId::context_local(i),
        )
    });
    for (i, candidate) in candidates.iter().enumerate() {
        let path = PartialPath::new(
            candidate.clone(),
            candidate.clone(),
            vec![],
            vec![],
            ResolutionCompletion::Complete,
        );
        let (key, shared) = candidate
            .symbols()
            .fixed()
            .first()
            .map(|s| super::super::lexical::semantic_cells(s.symbol()))
            .unwrap_or((None, None));
        let (fixed, open_tail) = super::super::lexical::root_endpoint_key(candidate, &cancellation)
            .unwrap()
            .unzip();
        connection.execute(
            "INSERT INTO temp.selected_resolution_context_paths(context_id,host_ordinal,path,start_node,end_node,start_lead_key,start_lead_shared,end_lead_key,end_lead_shared,body,start_fixed_key,start_open_tail,end_fixed_key,end_open_tail) VALUES(1,0,?1,?2,?2,?3,?4,?3,?4,jsonb(?5),?6,?7,?6,?7)",
            rusqlite::params![codec::encode_path_id(PartialPathId::context_local(i as u64)), codec::encode_node(candidate.node()), key, shared, codec::encode_path(&path),fixed,open_tail],
        ).unwrap();
    }
    for (request_endpoint, expected) in [
        (
            endpoint(
                vec![domain, token, name],
                Some(StackVariableId::operation_local(0)),
            ),
            expected.to_vec(),
        ),
        (endpoint(vec![domain, token, name], None), expected.to_vec()),
        (
            endpoint(vec![], None),
            [256, 257]
                .into_iter()
                .map(|id| {
                    CandidatePathIdentity::new(
                        BindingFragmentId::at_ordinal(0),
                        PartialPathId::context_local(id),
                    )
                })
                .collect(),
        ),
        (
            endpoint(vec![], Some(StackVariableId::operation_local(0))),
            (0..candidates.len())
                .map(|id| {
                    CandidatePathIdentity::new(
                        BindingFragmentId::at_ordinal(0),
                        PartialPathId::context_local(id as u64),
                    )
                })
                .collect(),
        ),
    ] {
        for sql in [
            CONTEXT_FORWARD_CANDIDATES_SQL,
            CONTEXT_REVERSE_CANDIDATES_SQL,
        ] {
            for request in [
                BatchCandidateRequest::new(0, request_endpoint.clone()),
                BatchCandidateRequest::with_root_terminal_targets(
                    0,
                    request_endpoint.clone(),
                    vec![SharedNameId::interned(2)],
                ),
            ] {
                let encoded = codec::root_candidate_request(0, &request, &cancellation).unwrap();
                let parameters = [
                    Value::Integer(1),
                    Value::Text("[]".into()),
                    Value::Text(format!("[{encoded}]")),
                ];
                // Exercise the production exact-seek row reader and shared charging loop.
                let offered =
                    read_context_candidate_rows(&connection, sql, &parameters, &cancellation)
                        .unwrap();
                assert_eq!(offered.as_ref().unwrap().len(), expected.len());
                // #5671: charge site moved to engine admission; delta = rows the seek over-includes.
                let expected_steps = 0;
                let session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
                let mut actual = Vec::new();
                let mut pages = Vec::new();
                let visit = visit_candidates(
                    &[request],
                    offered,
                    2,
                    Some(&session),
                    &cancellation,
                    &mut |page| {
                        pages.push(page.len());
                        actual.extend(page.iter().map(|matched| matched.candidate()));
                        Ok(true)
                    },
                )
                .unwrap();
                assert_eq!(visit, CandidatePageVisit::Exhausted);
                assert_eq!(actual, expected);
                assert!(pages.iter().all(|count| *count == 2));
                assert_eq!(session.finish(()).work().scope_nodes, expected_steps);
            }
        }
    }
}
