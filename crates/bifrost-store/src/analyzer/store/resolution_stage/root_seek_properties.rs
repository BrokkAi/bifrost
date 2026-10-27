//! The root seek must include exactly the admitted prefix set: compare real writer/SQL paths with
//! the independent Rust admission predicate, including rows a bad key hides.
use super::*;
use crate::analyzer::resolution::{
    BatchCandidateRequest, EndpointSignature, LoweredResolutionFragment, PartialPath,
    PartialPathId, PartialScopedSymbol, ResolutionCompletion, SharedNameId, StackPattern,
    StackVariableId,
};
use proptest::prelude::*;
use rusqlite::types::Value;
use std::collections::BTreeSet;

type Cell = (u8, bool, bool);

fn endpoint(cells: &[Cell], open: bool) -> EndpointSignature {
    EndpointSignature::new_scoped(
        BindingNodeId::universal_root(),
        StackPattern::new(
            cells
                .iter()
                .map(|&(name, shared, scoped)| {
                    let symbol = if shared {
                        SemanticId::shared_name(SharedNameId::interned(i64::from(name) + 1))
                    } else {
                        SemanticId::local(0, u32::from(name) + 1)
                    };
                    if scoped {
                        PartialScopedSymbol::scoped(symbol, StackPattern::closed(vec![]))
                    } else {
                        PartialScopedSymbol::unscoped(symbol)
                    }
                })
                .collect::<Vec<_>>(),
            open.then(|| StackVariableId::context_local(0)),
        ),
        StackPattern::closed(vec![]),
    )
}

fn populate(connection: &Connection, endpoints: &[EndpointSignature]) {
    connection.execute_batch("CREATE TEMP TABLE IF NOT EXISTS selected_resolution_mounts(mount_ordinal INTEGER PRIMARY KEY); INSERT INTO temp.selected_resolution_mounts(mount_ordinal) VALUES(0); CREATE TEMP TABLE IF NOT EXISTS selected_resolution_scope_mounts(mount_ordinal INTEGER PRIMARY KEY); INSERT INTO temp.selected_resolution_scope_mounts VALUES(0)").unwrap();
    connection
        .execute_batch(super::super::schema_sql())
        .unwrap();
    connection
        .execute(
            "INSERT INTO temp.selected_resolution_contexts VALUES(1)",
            [],
        )
        .unwrap();
    let paths = endpoints
        .iter()
        .map(|e| {
            PartialPath::new(
                e.clone(),
                e.clone(),
                vec![],
                vec![],
                ResolutionCompletion::Complete,
            )
        })
        .collect::<Vec<_>>();
    super::super::context::insert_test_paths(connection, &paths);
    connection.execute("INSERT INTO temp.selected_resolution_stage_producers(producer_id,host_ordinal,bridge_identity,content_digest) VALUES(1,0,zeroblob(32),zeroblob(32))", []).unwrap();
    let fragment = LoweredResolutionFragment::new_for_test(
        BindingFragmentId::at_ordinal(0),
        crate::analyzer::Language::Go,
        vec![],
        paths
            .into_iter()
            .enumerate()
            .map(|(i, p)| (PartialPathId::context_local(i as u64), p))
            .collect(),
    );
    assert!(
        super::super::lexical::prepare_lexical_fragment(&fragment, &CancellationToken::new())
            .unwrap()
            .insert(
                connection,
                1,
                SelectedResolutionMountOrdinal::new(0),
                &CancellationToken::new()
            )
            .unwrap()
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]
    #[test]
    fn root_seek_sets_equal_rust_admission(
        request_cells in prop::collection::vec((0u8..3, any::<bool>(), any::<bool>()), 0..4),
        candidate_cells in prop::collection::vec((prop::collection::vec((0u8..3, any::<bool>(), any::<bool>()), 0..4), any::<bool>()), 0..32),
    ) {
        let mut candidates = candidate_cells.iter().map(|(cells,tail)| endpoint(cells,*tail)).collect::<Vec<_>>();
        // Ensure empty/exact/shorter boundary arms and scoped/local/shared cells
        // are covered in every case, rather than relying on random collisions.
        for length in 0..=request_cells.len() {
            for open in [false,true] { candidates.push(endpoint(&request_cells[..length],open)); }
        }
        for shared in [false,true] { for scoped in [false,true] { candidates.push(endpoint(&[(0,shared,scoped)],true)); } }
        let connection = Connection::open_in_memory().unwrap();
        populate(&connection,&candidates);
        for length in 0..=request_cells.len() { for open in [false,true] {
            let request = BatchCandidateRequest::new(0,endpoint(&request_cells[..length],open));
            let encoded = codec::root_candidate_request(0,&request,&CancellationToken::new()).unwrap();
            let roots = Value::Text(format!("[{encoded}]"));
            let expected = candidates.iter().enumerate().filter(|(_,e)| request.admits_candidate(e)).map(|(i,_)| CandidatePathIdentity::new(BindingFragmentId::at_ordinal(0),PartialPathId::context_local(i as u64))).collect::<BTreeSet<_>>();
            for (sql,parameters) in [
                (CONTEXT_FORWARD_CANDIDATES_SQL.as_str(),vec![Value::Integer(1),Value::Text("[]".into()),roots.clone()]),
                (CONTEXT_REVERSE_CANDIDATES_SQL.as_str(),vec![Value::Integer(1),Value::Text("[]".into()),roots.clone()]),
                (reverse_candidate_sql(),vec![Value::Null,Value::Text("[]".into()),Value::Text("[]".into()),Value::Text("[]".into()),roots.clone(),Value::Text("[]".into())]),
            ] {
                let mut statement = connection.prepare_cached(sql).unwrap();
                let actual = statement.query_map(rusqlite::params_from_iter(&parameters), |row| {
                    Ok(CandidatePathIdentity::new(BindingFragmentId::at_ordinal(row.get(1)?), codec::decode_path_id(row.get(2)?)))
                }).unwrap().collect::<rusqlite::Result<BTreeSet<_>>>().unwrap();
                prop_assert_eq!(&actual,&expected,"request={:?}, candidates={:?}, SQL={}",request,candidates,sql);
            }
        } }
    }
}

#[test]
fn root_seek_arms_seek_partial_indexes_with_materialized_request_driver() {
    use crate::analyzer::store::planner_statistics::pinned_plans::{explain_pin, pinned};
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
    for state in PlannerStatisticsState::BOTH {
        let store = crate::analyzer::store::AnalyzerStore::open_ephemeral().unwrap();
        let connection = store.conn.lock().unwrap();
        crate::analyzer::store::planner_statistics::pinned_plans::prepare_pin_context(&connection);
        let mut candidates = (0..2048)
            .map(|i| {
                endpoint(
                    &[
                        ((i % 3) as u8, i % 2 == 0, i % 4 == 0),
                        ((i / 3 % 3) as u8, i % 5 == 0, i % 7 == 0),
                    ],
                    i % 2 == 0,
                )
            })
            .collect::<Vec<_>>();
        candidates.push(EndpointSignature::new(
            BindingNodeId::local(0, 7),
            StackPattern::closed(vec![SemanticId::local(0, 1)]),
            StackPattern::closed(vec![]),
        ));
        candidates.push(EndpointSignature::new(
            BindingNodeId::local(0, 7),
            StackPattern::new(vec![], Some(StackVariableId::context_local(0))),
            StackPattern::closed(vec![]),
        ));
        candidates.push(endpoint(
            &[(0, false, false), (1, false, false), (0, true, false)],
            false,
        ));
        populate(&connection, &candidates);
        state.install(&connection);
        for (name, index) in [
            (
                "context_forward_root_seek",
                "selected_resolution_context_paths_forward_root_prefix",
            ),
            (
                "context_reverse_root_seek",
                "selected_resolution_context_paths_reverse_root_prefix",
            ),
            (
                "stage_reverse_root_seek",
                "selected_resolution_stage_paths_reverse_root_prefix",
            ),
        ] {
            let plan = explain_pin(&connection, &pinned(name));
            let hits = plan
                .iter()
                .filter(|line| line.contains("SEARCH p USING") && line.contains(index))
                .collect::<Vec<_>>();
            assert_eq!(hits.len(), 3, "{state:?} {name}: {plan:?}");
            assert!(
                hits.iter()
                    .all(|line| line.contains("fixed_key=") || line.contains("fixed_key>")),
                "{state:?} {name}: {plan:?}"
            );
            assert!(
                plan.iter()
                    .any(|line| line.contains("MATERIALIZE root_requests")),
                "{state:?} {name}: {plan:?}"
            );
            assert!(
                !plan
                    .iter()
                    .any(|line| line.contains("SCAN p") || line.contains("AUTOMATIC")),
                "{state:?} {name}: {plan:?}"
            );
            // Every root arm must iterate its materialized request before
            // opening the partial index, including the boundary expansion.
            let mut previous_arm = 0;
            for (position, line) in plan
                .iter()
                .enumerate()
                .filter(|(_, line)| line.contains("SEARCH p USING") && line.contains(index))
            {
                assert!(
                    plan[previous_arm..position]
                        .iter()
                        .any(|line| line.contains("SCAN r")),
                    "{state:?} {name}: request is not driving {line}: {plan:?}"
                );
                previous_arm = position + 1;
            }
            eprintln!("{state:?} {name}: {plan:#?}");
        }
    }
}
