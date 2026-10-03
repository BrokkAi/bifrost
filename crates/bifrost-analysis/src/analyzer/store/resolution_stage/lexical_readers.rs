//! Query-owned lexical reads over the active stage's selected host aggregate.

use super::codec;
use crate::CancellationToken;
use crate::analyzer::resolution::{
    BindingFragmentId, BindingNodeId, CandidatePathIdentity, PartialPath, ResolutionNodeIdentity,
    ResolutionSemanticIdentity, SelectedResolutionMountOrdinal, SemanticId,
};
use crate::analyzer::store::resolution::with_resolution_read_progress_handler;
use crate::analyzer::store::resolution_selection::SelectedResolutionMountInventory;
use crate::analyzer::store::{Result, StoreError};
use crate::hash::HashMap;
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId;
use rusqlite::Connection;

// Every seek binds the selected host as well as the full runtime identity.
// Producer-local dense keys are never interpreted as ordinary host keys.
pub(in crate::analyzer::store) const HYDRATE_PATHS_SQL: &str = r#"
SELECT input.key,path.start_node,path.end_node,json(path.body)
FROM json_each(?1) input
JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=input.value->>0
JOIN temp.selected_resolution_stage_paths path
 ON path.host_ordinal=scope.mount_ordinal AND path.path=input.value->>1
"#;

pub(in crate::analyzer::store) fn hydrate_candidate_paths(
    selection: &SelectedResolutionMountInventory<'_>,
    candidates: &[CandidatePathIdentity],
    cancellation: &CancellationToken,
) -> Result<Option<Vec<Option<PartialPath>>>> {
    let parameters = serde_json::to_string(
        &candidates
            .iter()
            .map(|candidate| {
                (
                    candidate.fragment().ordinal(),
                    codec::encode_path_id(candidate.path()),
                )
            })
            .collect::<Vec<_>>(),
    )
    .expect("stage path requests serialize");
    read(selection, cancellation, |connection| {
        let mut result = vec![None; candidates.len()];
        let mut statement = connection.prepare_cached(HYDRATE_PATHS_SQL)?;
        let mut rows = statement.query([parameters])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let position: usize = row.get(0)?;
            assert!(
                result[position].is_none(),
                "one host owns a path identity once"
            );
            result[position] = Some(codec::decode_path(
                row.get(1)?,
                row.get(2)?,
                &row.get::<_, String>(3)?,
            ));
        }
        Ok(Some(result))
    })
}

pub(in crate::analyzer::store) const SEMANTIC_IDENTITIES_SQL: &str = r#"
SELECT input.key,coordinate.runtime_key,coordinate.shared_id
FROM json_each(?1) input
JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=input.value->>0
JOIN temp.selected_resolution_stage_semantic_coordinates coordinate
 ON coordinate.host_ordinal=scope.mount_ordinal AND coordinate.identity_digest=unhex(input.value->>1)
UNION ALL
SELECT input.key,coordinate.runtime_key,coordinate.shared_id
FROM json_each(?1) input
JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=input.value->>0
JOIN temp.selected_resolution_stage_semantic_coordinates coordinate
 ON coordinate.host_ordinal=scope.mount_ordinal AND coordinate.runtime_key IS NULL AND coordinate.shared_id=input.value->>2
"#;

pub(in crate::analyzer::store) fn semantic_identities(
    selection: &SelectedResolutionMountInventory<'_>,
    requests: &[(BindingFragmentId, ResolutionSemanticIdentity)],
    cancellation: &CancellationToken,
) -> Result<Option<Vec<Option<SemanticId>>>> {
    let parameters = serde_json::to_string(
        &requests
            .iter()
            .map(|(fragment, identity)| match identity {
                ResolutionSemanticIdentity::FragmentLocal(digest) => (
                    fragment.ordinal(),
                    Some(crate::analyzer::store::resolution_lexical::hex_digest(
                        *digest,
                    )),
                    None,
                ),
                ResolutionSemanticIdentity::Shared(name) => {
                    (fragment.ordinal(), None, Some(name.get()))
                }
                ResolutionSemanticIdentity::GapReason(_) => {
                    panic!("a gap reason is not requested by identity: {identity:?}")
                }
            })
            .collect::<Vec<_>>(),
    )
    .expect("stage semantic identity requests serialize");
    read(selection, cancellation, |connection| {
        let mut result = vec![None; requests.len()];
        let mut statement = connection.prepare_cached(SEMANTIC_IDENTITIES_SQL)?;
        let mut rows = statement.query([parameters])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let position: usize = row.get(0)?;
            let semantic = semantic_from_cells(row.get(1)?, row.get(2)?);
            if let Some(previous) = result[position] {
                if previous != semantic {
                    return Err(StoreError::new(format!(
                        "selected stage semantic identity has conflicting assignments: {:?}, {previous:?}, {semantic:?}",
                        requests[position]
                    )));
                }
            } else {
                result[position] = Some(semantic);
            }
        }
        Ok(Some(result))
    })
}

pub(in crate::analyzer::store) const NODE_IDENTITIES_SQL: &str = r#"
SELECT input.key,coordinate.runtime_key
FROM json_each(?1) input
JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=input.value->>0
JOIN temp.selected_resolution_stage_node_coordinates coordinate
 ON coordinate.host_ordinal=scope.mount_ordinal AND coordinate.identity_digest=unhex(input.value->>1)
"#;

pub(in crate::analyzer::store) fn node_identities(
    selection: &SelectedResolutionMountInventory<'_>,
    requests: &[(BindingFragmentId, ResolutionNodeIdentity)],
    cancellation: &CancellationToken,
) -> Result<Option<Vec<Option<BindingNodeId>>>> {
    let parameters = serde_json::to_string(
        &requests
            .iter()
            .map(|(fragment, identity)| {
                (
                    fragment.ordinal(),
                    crate::analyzer::store::resolution_lexical::hex_digest(identity.digest()),
                )
            })
            .collect::<Vec<_>>(),
    )
    .expect("stage node identity requests serialize");
    read(selection, cancellation, |connection| {
        let mut result = vec![None; requests.len()];
        let mut statement = connection.prepare_cached(NODE_IDENTITIES_SQL)?;
        let mut rows = statement.query([parameters])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let position: usize = row.get(0)?;
            let node = codec::decode_node(row.get(1)?);
            if let Some(previous) = result[position] {
                if previous != node {
                    return Err(StoreError::new(format!(
                        "selected stage node identity has conflicting assignments: {:?}, {previous:?}, {node:?}",
                        requests[position]
                    )));
                }
            } else {
                result[position] = Some(node);
            }
        }
        Ok(Some(result))
    })
}

pub(in crate::analyzer::store) const NODE_SCOPES_SQL: &str = r#"
SELECT input.key,coordinate.host_ordinal,coordinate.source_scope,coordinate.identity_digest
FROM json_each(?1) input
CROSS JOIN temp.selected_resolution_stage_node_coordinates coordinate INDEXED BY selected_resolution_stage_node_runtime
 ON coordinate.runtime_key=input.value
CROSS JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=coordinate.host_ordinal
"#;

/// Query-owned stage node identities and their optional lexical scope.
pub(in crate::analyzer::store) type StageNodeScopes = HashMap<
    BindingNodeId,
    (
        ResolutionNodeIdentity,
        Option<(BindingFragmentId, ResolutionScopeId)>,
    ),
>;

pub(in crate::analyzer::store) fn scope_nodes(
    selection: &SelectedResolutionMountInventory<'_>,
    requests: &[BindingNodeId],
    cancellation: &CancellationToken,
) -> Result<Option<StageNodeScopes>> {
    let parameters = serde_json::to_string(
        &requests
            .iter()
            .map(|node| codec::encode_node(*node))
            .collect::<Vec<_>>(),
    )
    .expect("stage scope requests serialize");
    read(selection, cancellation, |connection| {
        let mut result = HashMap::default();
        let mut statement = connection.prepare_cached(NODE_SCOPES_SQL)?;
        let mut rows = statement.query([parameters])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let position: usize = row.get(0)?;
            let node = requests[position];
            let host = BindingFragmentId::at_ordinal(row.get(1)?);
            let scope = row
                .get::<_, Option<u32>>(2)?
                .map(|scope| (host, ResolutionScopeId::new(scope)));
            let identity = ResolutionNodeIdentity::new(row.get(3)?);
            let current = (identity, scope);
            if let Some(previous) = result.insert(node, current)
                && previous != current
            {
                return Err(StoreError::new(format!(
                    "selected stage node has conflicting source scopes: {node:?}, {previous:?}, {current:?}"
                )));
            }
        }
        Ok(Some(result))
    })
}

fn semantic_from_cells(runtime: Option<i64>, shared: Option<i64>) -> SemanticId {
    match (runtime, shared) {
        (Some(runtime), None) => codec::decode_semantic(runtime),
        (None, Some(shared)) => codec::decode_semantic(-shared),
        _ => panic!("stage semantic requires exactly one coordinate: {runtime:?}, {shared:?}"),
    }
}

fn read<T>(
    selection: &SelectedResolutionMountInventory<'_>,
    cancellation: &CancellationToken,
    job: impl FnOnce(&Connection) -> Result<Option<T>>,
) -> Result<Option<T>> {
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    match with_resolution_read_progress_handler(selection.connection(), cancellation, job) {
        Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => Ok(None),
        Err(error) => Err(error),
        Ok(_) if cancellation.is_cancelled() => Ok(None),
        Ok(result) => Ok(result),
    }
}

#[cfg(test)]
#[path = "lexical_reader_tests.rs"]
mod tests;

pub(in crate::analyzer::store) const FORWARD_CANDIDATES_SQL: &str = r#"
SELECT r.value ->> 0, p.host_ordinal, p.path, p.start_node, json_extract(p.body, '$[0]', '$[1]', '$[2]', '$[3]')
FROM json_each(?2) AS r
CROSS JOIN temp.selected_resolution_stage_paths AS p INDEXED BY selected_resolution_stage_paths_forward
 ON p.start_node = r.value ->> 1
 AND p.start_lead_shared IS r.value ->> 2
 AND p.start_lead_key IS r.value ->> 3
 AND p.start_lead_scoped = r.value ->> 4

CROSS JOIN temp.selected_resolution_scope_mounts AS scope ON scope.mount_ordinal=p.host_ordinal
WHERE (?1 IS NULL OR scope.mount_ordinal IN (SELECT value FROM json_each(?1)))
UNION ALL
SELECT r.value ->> 0, p.host_ordinal, p.path, p.start_node, json_extract(p.body, '$[0]', '$[1]', '$[2]', '$[3]')
FROM json_each(?3) AS r
CROSS JOIN temp.selected_resolution_stage_paths AS p INDEXED BY selected_resolution_stage_paths_forward
 ON p.start_node = r.value ->> 1
 AND p.start_lead_shared IS NULL
 AND p.start_lead_key IS NULL

CROSS JOIN temp.selected_resolution_scope_mounts AS scope ON scope.mount_ordinal=p.host_ordinal
WHERE (?1 IS NULL OR scope.mount_ordinal IN (SELECT value FROM json_each(?1)))
UNION ALL
SELECT r.value ->> 0, p.host_ordinal, p.path, p.start_node, json_extract(p.body, '$[0]', '$[1]', '$[2]', '$[3]')
FROM json_each(?4) AS r
CROSS JOIN temp.selected_resolution_stage_paths AS p INDEXED BY selected_resolution_stage_paths_forward
 ON p.start_node = r.value ->> 1
CROSS JOIN temp.selected_resolution_scope_mounts AS scope ON scope.mount_ordinal=p.host_ordinal
WHERE (?1 IS NULL OR scope.mount_ordinal IN (SELECT value FROM json_each(?1)))
"#;

pub(in crate::analyzer::store) fn reverse_candidate_sql() -> &'static str {
    static SQL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    SQL.get_or_init(|| {
        let sql = format!(r#"
SELECT r.value ->> 0, p.host_ordinal, p.path, p.end_node, json_extract(p.body, '$[4]', '$[5]', '$[6]', '$[7]')
FROM json_each(?2) AS r
CROSS JOIN temp.selected_resolution_stage_paths AS p INDEXED BY selected_resolution_stage_paths_reverse
 ON p.end_node = r.value ->> 1
 AND p.end_lead_shared IS r.value ->> 2
 AND p.end_lead_key IS r.value ->> 3
 AND p.end_lead_scoped = r.value ->> 4

CROSS JOIN temp.selected_resolution_scope_mounts AS scope ON scope.mount_ordinal=p.host_ordinal
WHERE (?1 IS NULL OR scope.mount_ordinal IN (SELECT value FROM json_each(?1)))
UNION ALL
SELECT r.value ->> 0, p.host_ordinal, p.path, p.end_node, json_extract(p.body, '$[4]', '$[5]', '$[6]', '$[7]')
FROM json_each(?3) AS r
CROSS JOIN temp.selected_resolution_stage_paths AS p INDEXED BY selected_resolution_stage_paths_reverse
 ON p.end_node = r.value ->> 1
 AND p.end_lead_shared IS NULL
 AND p.end_lead_key IS NULL

CROSS JOIN temp.selected_resolution_scope_mounts AS scope ON scope.mount_ordinal=p.host_ordinal
WHERE (?1 IS NULL OR scope.mount_ordinal IN (SELECT value FROM json_each(?1)))
UNION ALL
SELECT r.value ->> 0, p.host_ordinal, p.path, p.end_node, json_extract(p.body, '$[4]', '$[5]', '$[6]', '$[7]')
FROM json_each(?4) AS r
CROSS JOIN temp.selected_resolution_stage_paths AS p INDEXED BY selected_resolution_stage_paths_reverse
 ON p.end_node = r.value ->> 1

CROSS JOIN temp.selected_resolution_scope_mounts AS scope ON scope.mount_ordinal=p.host_ordinal
WHERE (?1 IS NULL OR scope.mount_ordinal IN (SELECT value FROM json_each(?1)))
UNION ALL
SELECT r.value ->> 0, p.host_ordinal, p.path, p.end_node, json_extract(p.body, '$[4]', '$[5]', '$[6]', '$[7]')
FROM json_each(?5) AS r
CROSS JOIN temp.selected_resolution_stage_paths AS p INDEXED BY selected_resolution_stage_paths_reverse_root_prefix
 ON p.end_node = {root}
 AND p.end_fixed_key = r.value ->> 1 COLLATE BINARY

CROSS JOIN temp.selected_resolution_scope_mounts AS scope ON scope.mount_ordinal=p.host_ordinal
WHERE (?1 IS NULL OR scope.mount_ordinal IN (SELECT value FROM json_each(?1))) AND r.value ->> 2 = 0 AND r.value ->> 3 = 1
UNION ALL
SELECT r.value ->> 0, p.host_ordinal, p.path, p.end_node, json_extract(p.body, '$[4]', '$[5]', '$[6]', '$[7]')
FROM json_each(?5) AS r
CROSS JOIN json_each(r.value -> 4) AS boundary
CROSS JOIN temp.selected_resolution_stage_paths AS p INDEXED BY selected_resolution_stage_paths_reverse_root_prefix
 ON p.end_node = {root}
 AND p.end_fixed_key = substr(r.value ->> 1, 1, boundary.value) || ']' COLLATE BINARY
 AND p.end_open_tail = 1

CROSS JOIN temp.selected_resolution_scope_mounts AS scope ON scope.mount_ordinal=p.host_ordinal
WHERE (?1 IS NULL OR scope.mount_ordinal IN (SELECT value FROM json_each(?1)))
UNION ALL
SELECT r.value ->> 0, p.host_ordinal, p.path, p.end_node, json_extract(p.body, '$[4]', '$[5]', '$[6]', '$[7]')
FROM json_each(?5) AS r
CROSS JOIN temp.selected_resolution_stage_paths AS p INDEXED BY selected_resolution_stage_paths_reverse_root_prefix
 ON p.end_node = {root}
 AND p.end_fixed_key >= substr(r.value ->> 1, 1, length(r.value ->> 1) - 1) COLLATE BINARY
 AND p.end_fixed_key < CASE WHEN length(r.value ->> 1) = 2 THEN char(92)
     ELSE substr(r.value ->> 1, 1, length(r.value ->> 1) - 2) || '^' END COLLATE BINARY

CROSS JOIN temp.selected_resolution_scope_mounts AS scope ON scope.mount_ordinal=p.host_ordinal
WHERE (?1 IS NULL OR scope.mount_ordinal IN (SELECT value FROM json_each(?1))) AND r.value ->> 2 = 1 AND r.value ->> 3 = 1"#, root=codec::encode_node(BindingNodeId::universal_root()));
        #[cfg(test)]
        crate::analyzer::store::resolution_selection::note_selected_static_sql_capacity(10, sql.capacity());
        sql
    })
}

#[allow(clippy::too_many_arguments)]
pub(in crate::analyzer::store) fn visit_forward_candidates(
    selection: &SelectedResolutionMountInventory<'_>,
    requests: &[crate::analyzer::resolution::BatchCandidateRequest],
    scope: Option<&[SelectedResolutionMountOrdinal]>,
    maximum_page_rows: usize,
    session: Option<&brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession>,
    cancellation: &CancellationToken,
    visitor: &mut dyn FnMut(&[crate::analyzer::resolution::BatchCandidateMatch]) -> Result<bool>,
) -> Result<crate::analyzer::store::resolution_lexical::CandidatePageVisit> {
    let mut keyed = Vec::new();
    let mut open = Vec::new();
    let mut whole = Vec::new();
    for (ordinal, request) in requests.iter().enumerate() {
        if cancellation.is_cancelled() {
            return Ok(crate::analyzer::store::resolution_lexical::CandidatePageVisit::Cancelled);
        }
        let endpoint = request.endpoint();
        let node = codec::encode_node(endpoint.node());
        if let Some(symbol) = endpoint.symbols().fixed().first() {
            let (runtime, shared) = super::lexical::semantic_cells(symbol.symbol());
            keyed.push(serde_json::json!([
                ordinal,
                node,
                shared,
                runtime,
                symbol.scopes().is_some()
            ]));
            open.push(serde_json::json!([ordinal, node]));
        } else {
            whole.push(serde_json::json!([ordinal, node]));
        }
    }
    visit_candidates(
        selection,
        requests,
        scope,
        maximum_page_rows,
        session,
        cancellation,
        visitor,
        FORWARD_CANDIDATES_SQL,
        vec![keyed, open, whole],
    )
}

#[allow(clippy::too_many_arguments)]
pub(in crate::analyzer::store) fn visit_reverse_candidates(
    selection: &SelectedResolutionMountInventory<'_>,
    requests: &[crate::analyzer::resolution::BatchCandidateRequest],
    scope: Option<&[SelectedResolutionMountOrdinal]>,
    maximum_page_rows: usize,
    session: Option<&brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession>,
    cancellation: &CancellationToken,
    visitor: &mut dyn FnMut(&[crate::analyzer::resolution::BatchCandidateMatch]) -> Result<bool>,
) -> Result<crate::analyzer::store::resolution_lexical::CandidatePageVisit> {
    let mut keyed = Vec::new();
    let mut open = Vec::new();
    let mut whole = Vec::new();
    let mut root = Vec::new();
    for (ordinal, request) in requests.iter().enumerate() {
        if cancellation.is_cancelled() {
            return Ok(crate::analyzer::store::resolution_lexical::CandidatePageVisit::Cancelled);
        }
        let endpoint = request.endpoint();
        let node = codec::encode_node(endpoint.node());
        if endpoint.node() == BindingNodeId::universal_root() {
            let Some(encoded) = codec::root_candidate_request(ordinal, request, cancellation)
            else {
                return Ok(
                    crate::analyzer::store::resolution_lexical::CandidatePageVisit::Cancelled,
                );
            };
            root.push(serde_json::from_str(&encoded).expect("SC root request is structured JSON"));
        } else if let Some(symbol) = endpoint.symbols().fixed().first() {
            let (runtime, shared) = super::lexical::semantic_cells(symbol.symbol());
            keyed.push(serde_json::json!([
                ordinal,
                node,
                shared,
                runtime,
                symbol.scopes().is_some()
            ]));
            open.push(serde_json::json!([ordinal, node]));
        } else {
            whole.push(serde_json::json!([ordinal, node]));
        }
    }
    visit_candidates(
        selection,
        requests,
        scope,
        maximum_page_rows,
        session,
        cancellation,
        visitor,
        reverse_candidate_sql(),
        vec![keyed, open, whole, root],
    )
}

#[allow(clippy::too_many_arguments)]
fn visit_candidates(
    selection: &SelectedResolutionMountInventory<'_>,
    requests: &[crate::analyzer::resolution::BatchCandidateRequest],
    scope: Option<&[SelectedResolutionMountOrdinal]>,
    maximum_page_rows: usize,
    session: Option<&brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession>,
    cancellation: &CancellationToken,
    visitor: &mut dyn FnMut(&[crate::analyzer::resolution::BatchCandidateMatch]) -> Result<bool>,
    sql: &str,
    arrays: Vec<Vec<serde_json::Value>>,
) -> Result<crate::analyzer::store::resolution_lexical::CandidatePageVisit> {
    use crate::analyzer::resolution::BatchCandidateMatch;
    use crate::analyzer::store::resolution_lexical::CandidatePageVisit;
    use rusqlite::types::Value;
    assert!(
        (1..=crate::analyzer::resolution::MAX_SOURCE_ROWS_PER_BATCH).contains(&maximum_page_rows)
    );
    let mut parameters = vec![scope.map_or(Value::Null, |scope| {
        Value::Text(
            serde_json::to_string(&scope.iter().map(|host| host.get()).collect::<Vec<_>>())
                .expect("stage candidate scope serializes"),
        )
    })];
    parameters.extend(arrays.into_iter().map(|rows| {
        Value::Text(serde_json::to_string(&rows).expect("stage candidate request serializes"))
    }));
    let Some(mut offered) = read(selection, cancellation, |connection| {
        let mut offered = Vec::new();
        let mut statement = connection.prepare_cached(sql)?;
        let mut rows = statement.query(rusqlite::params_from_iter(parameters))?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let ordinal: usize = row.get(0)?;
            let fragment = BindingFragmentId::at_ordinal(row.get(1)?);
            let identity = CandidatePathIdentity::new(fragment, codec::decode_path_id(row.get(2)?));
            let endpoint = codec::decode_endpoint(row.get(3)?, &row.get::<_, String>(4)?);
            offered.push((ordinal, identity, endpoint));
        }
        Ok(Some(offered))
    })?
    else {
        return Ok(CandidatePageVisit::Cancelled);
    };
    offered.sort_unstable_by_key(|(ordinal, identity, _)| (*ordinal, *identity));
    let mut page = Vec::with_capacity(maximum_page_rows);
    let mut offered = offered.into_iter().peekable();
    // The former preloaded stage source aggregated every admitted fragment.
    // It charged one step per request, including an empty candidate bucket,
    // then each offered row. A budget break flushes the admitted partial page;
    // only the cancellation token makes this visitor Cancelled.
    'requests: for (ordinal, request) in requests.iter().enumerate() {
        assert_eq!(request.request_ordinal(), ordinal);
        if session.is_some_and(|session| !session.scope_step()) {
            break;
        }
        if cancellation.is_cancelled() {
            return Ok(CandidatePageVisit::Cancelled);
        }
        while offered
            .peek()
            .is_some_and(|(position, _, _)| *position == ordinal)
        {
            if session.is_some_and(|session| !session.scope_step()) {
                break 'requests;
            }
            if cancellation.is_cancelled() {
                return Ok(CandidatePageVisit::Cancelled);
            }
            let (_, identity, endpoint) = offered.next().expect("peeked candidate exists");
            if request.admits_candidate(&endpoint) {
                page.push(BatchCandidateMatch::new(identity, ordinal));
                if page.len() == maximum_page_rows {
                    let keep_going = visitor(&page)?;
                    if cancellation.is_cancelled() {
                        return Ok(CandidatePageVisit::Cancelled);
                    }
                    if !keep_going {
                        return Ok(CandidatePageVisit::Stopped);
                    }
                    page.clear();
                }
            }
        }
    }
    if !page.is_empty() {
        let keep_going = visitor(&page)?;
        if cancellation.is_cancelled() {
            return Ok(CandidatePageVisit::Cancelled);
        }
        if !keep_going {
            return Ok(CandidatePageVisit::Stopped);
        }
    }
    Ok(if cancellation.is_cancelled() {
        CandidatePageVisit::Cancelled
    } else {
        CandidatePageVisit::Exhausted
    })
}

pub(in crate::analyzer::store) fn semantic_provenance(
    selection: &SelectedResolutionMountInventory<'_>,
    semantic: SemanticId,
    cancellation: &CancellationToken,
) -> Result<Option<Option<(SelectedResolutionMountOrdinal, ResolutionSemanticIdentity)>>> {
    if semantic.shared_name_id().is_some() {
        // Shared identity has no producer-local provenance.
        return Ok(Some(None));
    }
    read(selection, cancellation, |connection| {
        let mut statement = connection.prepare_cached(
            r#"
SELECT coordinate.host_ordinal,coordinate.identity_digest
FROM temp.selected_resolution_stage_semantic_coordinates coordinate INDEXED BY selected_resolution_stage_semantic_runtime
CROSS JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=coordinate.host_ordinal
WHERE coordinate.runtime_key=?1 AND coordinate.shared_id IS NULL
"#,
        )?;
        let mut rows = statement.query([codec::encode_semantic(semantic)])?;
        let mut result = None;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let current = (
                SelectedResolutionMountOrdinal::new(row.get(0)?),
                ResolutionSemanticIdentity::fragment_local(row.get(1)?),
            );
            if let Some(previous) = result {
                if previous != current {
                    return Err(StoreError::new(format!(
                        "stage semantic has conflicting provenance: {semantic:?}, {previous:?}, {current:?}"
                    )));
                }
            } else {
                result = Some(current);
            }
        }
        Ok(Some(result))
    })
}

pub(in crate::analyzer::store) fn node_provenance(
    selection: &SelectedResolutionMountInventory<'_>,
    node: BindingNodeId,
    cancellation: &CancellationToken,
) -> Result<Option<Option<(SelectedResolutionMountOrdinal, ResolutionNodeIdentity)>>> {
    read(selection, cancellation, |connection| {
        let mut statement = connection.prepare_cached(
            r#"
SELECT coordinate.host_ordinal,coordinate.identity_digest
FROM temp.selected_resolution_stage_node_coordinates coordinate INDEXED BY selected_resolution_stage_node_runtime
CROSS JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=coordinate.host_ordinal
WHERE coordinate.runtime_key=?1
"#,
        )?;
        let mut rows = statement.query([codec::encode_node(node)])?;
        let mut result = None;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let current = (
                SelectedResolutionMountOrdinal::new(row.get(0)?),
                ResolutionNodeIdentity::new(row.get(1)?),
            );
            if let Some(previous) = result {
                if previous != current {
                    return Err(StoreError::new(format!(
                        "stage node has conflicting provenance: {node:?}, {previous:?}, {current:?}"
                    )));
                }
            } else {
                result = Some(current);
            }
        }
        Ok(Some(result))
    })
}

pub(in crate::analyzer::store) const DEFINITION_NODES_SQL: &str = r#"
SELECT input.key,node.node
FROM json_each(?1) input
CROSS JOIN temp.selected_resolution_stage_nodes node
 ON node.kind_semantic_key IS input.value->>0 AND node.kind_shared_id IS input.value->>1
WHERE node.kind IN(8,9) AND node.kind=9
 AND EXISTS (
  SELECT 1 FROM temp.selected_resolution_stage_node_owners owner
  CROSS JOIN temp.selected_resolution_stage_producers producer
   ON producer.producer_id=owner.producer_id
  CROSS JOIN temp.selected_resolution_scope_mounts scope
   ON scope.mount_ordinal=producer.host_ordinal
  WHERE owner.node=node.node
 )
"#;

pub(in crate::analyzer::store) fn reference_lookup_spellings(
    selection: &SelectedResolutionMountInventory<'_>,
    references: &[SemanticId],
    namespace: brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace,
    cancellation: &CancellationToken,
) -> Result<Option<HashMap<SemanticId, String>>> {
    let parameters = serde_json::to_string(
        &references
            .iter()
            .copied()
            .map(super::lexical::semantic_cells)
            .collect::<Vec<_>>(),
    )
    .expect("reference spelling requests serialize");
    read(selection, cancellation, |connection| {
        let mut statement = connection.prepare_cached(REFERENCE_LOOKUP_SPELLINGS_SQL)?;
        let mut rows = statement.query(rusqlite::named_params! {
            ":requests": parameters,
            ":namespace": super::super::resolution_prepare::resolution_rows::namespace_code(
                namespace),
        })?;
        let mut result = HashMap::default();
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let reference = references[row.get::<_, usize>(0)?];
            let spelling: String = row.get(1)?;
            if let Some(previous) = result.insert(reference, spelling.clone())
                && previous != spelling
            {
                return Err(StoreError::new(format!(
                    "stage reference has conflicting lookup spellings: {reference:?}, {previous:?}, {spelling:?}"
                )));
            }
        }
        Ok(Some(result))
    })
}

pub(in crate::analyzer::store) const REFERENCE_LOOKUP_SPELLINGS_SQL: &str = r#"
SELECT input.key,recipe.spelling,path.host_ordinal,path.path
FROM json_each(:requests) input
CROSS JOIN temp.selected_resolution_stage_nodes node
 ON node.kind=8 AND node.kind_semantic_key IS input.value->>0 AND node.kind_shared_id IS input.value->>1
CROSS JOIN temp.selected_resolution_stage_paths path ON path.start_node=node.node
CROSS JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=path.host_ordinal
CROSS JOIN temp.selected_resolution_stage_recipes recipe
 ON recipe.producer_id=path.producer_id
 AND COALESCE(recipe.semantic_key,-1)=COALESCE(path.end_lead_key,-1)
 AND COALESCE(recipe.semantic_shared,-1)=COALESCE(path.end_lead_shared,-1)
WHERE node.kind IN(8,9) AND recipe.namespace=:namespace
AND EXISTS(SELECT 1 FROM temp.selected_resolution_stage_node_owners owner
 CROSS JOIN temp.selected_resolution_stage_producers producer ON producer.producer_id=owner.producer_id
 CROSS JOIN temp.selected_resolution_scope_mounts owner_scope ON owner_scope.mount_ordinal=producer.host_ordinal
 WHERE owner.node=node.node)
"#;

pub(in crate::analyzer::store) fn definition_nodes(
    selection: &SelectedResolutionMountInventory<'_>,
    definitions: &[SemanticId],
    cancellation: &CancellationToken,
) -> Result<Option<Vec<Option<BindingNodeId>>>> {
    let parameters = serde_json::to_string(
        &definitions
            .iter()
            .copied()
            .map(super::lexical::semantic_cells)
            .collect::<Vec<_>>(),
    )
    .expect("stage definitions serialize");
    read(selection, cancellation, |connection| {
        let mut result = vec![None; definitions.len()];
        let mut statement = connection.prepare_cached(DEFINITION_NODES_SQL)?;
        let mut rows = statement.query([parameters])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let ordinal: usize = row.get(0)?;
            let node = codec::decode_node(row.get(1)?);
            if let Some(previous) = result[ordinal] {
                if previous != node {
                    return Err(StoreError::new(format!(
                        "stage definition has conflicting nodes: {:?}, {previous:?}, {node:?}",
                        definitions[ordinal]
                    )));
                }
            } else {
                result[ordinal] = Some(node);
            }
        }
        Ok(Some(result))
    })
}

pub(in crate::analyzer::store) const NODE_PAYLOADS_SQL: &str = r#"
SELECT node.node,node.kind,node.kind_semantic_key,node.kind_shared_id,node.kind_target_node
FROM json_each(?1) input
CROSS JOIN temp.selected_resolution_stage_nodes node ON node.node=input.value
WHERE EXISTS (
 SELECT 1 FROM temp.selected_resolution_stage_node_owners owner
 CROSS JOIN temp.selected_resolution_stage_producers producer ON producer.producer_id=owner.producer_id
 CROSS JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=producer.host_ordinal
 WHERE owner.node=node.node
)
"#;

pub(in crate::analyzer::store) fn node_payloads(
    selection: &SelectedResolutionMountInventory<'_>,
    nodes: &[BindingNodeId],
    cancellation: &CancellationToken,
) -> Result<Option<HashMap<BindingNodeId, crate::analyzer::resolution::BindingNodeKind>>> {
    let parameters = serde_json::to_string(
        &nodes
            .iter()
            .copied()
            .map(codec::encode_node)
            .collect::<Vec<_>>(),
    )
    .expect("stage node payload requests serialize");
    read(selection, cancellation, |connection| {
        let mut result = HashMap::default();
        let mut statement = connection.prepare_cached(NODE_PAYLOADS_SQL)?;
        let mut rows = statement.query([parameters])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let kind: i64 = row.get(1)?;
            let semantic_key: Option<i64> = row.get(2)?;
            let shared: Option<i64> = row.get(3)?;
            let semantic = match (semantic_key, shared) {
                (Some(key), None) => Some(codec::decode_semantic(key)),
                (None, Some(shared)) => Some(codec::decode_semantic(-shared)),
                (None, None) => None,
                _ => unreachable!("a stage node semantic coordinate is exclusive"),
            };
            let target = row.get::<_, Option<i64>>(4)?.map(codec::decode_node);
            let payload = codec::decode_node_kind(kind, semantic, target);
            result.insert(codec::decode_node(row.get(0)?), payload);
        }
        Ok(Some(result))
    })
}

pub(in crate::analyzer::store) const GO_DEFINITION_NAMESPACES_SQL: &str = r#"
SELECT fact.node,fact.go_definition_namespaces FROM json_each(?1) input
CROSS JOIN temp.selected_resolution_stage_semantics fact ON fact.node=input.value
CROSS JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal
WHERE fact.role=1 AND fact.go_definition_namespaces IS NOT NULL
"#;

/// Source-owned lexical eligibility, restricted to the operation's selected
/// stage hosts. Missing metadata never supplies a namespace admission proof.
pub(in crate::analyzer::store) fn go_definition_namespaces(
    selection: &SelectedResolutionMountInventory<'_>,
    nodes: &[BindingNodeId],
    cancellation: &CancellationToken,
) -> Result<Option<HashMap<BindingNodeId, crate::analyzer::resolution::GoDefinitionNamespaces>>> {
    use crate::analyzer::resolution::GoDefinitionNamespaces;
    let parameters = serde_json::to_string(
        &nodes
            .iter()
            .copied()
            .map(codec::encode_node)
            .collect::<Vec<_>>(),
    )
    .expect("stage endpoint requests serialize");
    read(selection, cancellation, |connection| {
        let mut result = HashMap::default();
        let mut statement = connection.prepare_cached(GO_DEFINITION_NAMESPACES_SQL)?;
        let mut rows = statement.query([parameters])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let node = codec::decode_node(row.get(0)?);
            let namespaces = GoDefinitionNamespaces::from_bits(row.get(1)?);
            if let Some(previous) = result.insert(node, namespaces)
                && previous != namespaces
            {
                return Err(StoreError::corrupt(format!(
                    "stage Go endpoint namespaces disagree: {node:?}, {previous:?}, {namespaces:?}"
                )));
            }
        }
        Ok(Some(result))
    })
}

pub(in crate::analyzer::store) const MEMBER_SCOPE_OWNERS_SQL: &str = r#"
SELECT fact.scope_head_node,fact.definition_key,fact.definition_shared
FROM json_each(?1) input
CROSS JOIN temp.selected_resolution_stage_member_scopes fact ON fact.scope_head_node=input.value
CROSS JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal
"#;

pub(in crate::analyzer::store) fn member_scope_owners(
    selection: &SelectedResolutionMountInventory<'_>,
    nodes: &[BindingNodeId],
    cancellation: &CancellationToken,
) -> Result<Option<HashMap<BindingNodeId, SemanticId>>> {
    let parameters = serde_json::to_string(
        &nodes
            .iter()
            .copied()
            .map(codec::encode_node)
            .collect::<Vec<_>>(),
    )
    .expect("stage member scope requests serialize");
    read(selection, cancellation, |connection| {
        let mut result = HashMap::default();
        let mut statement = connection.prepare_cached(MEMBER_SCOPE_OWNERS_SQL)?;
        let mut rows = statement.query([parameters])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let node = codec::decode_node(row.get(0)?);
            let key: Option<i64> = row.get(1)?;
            let shared: Option<i64> = row.get(2)?;
            let owner = codec::decode_semantic(match (key, shared) {
                (Some(key), None) => key,
                (None, Some(shared)) => -shared,
                _ => panic!("a stage member scope owner has exactly one semantic coordinate"),
            });
            if let Some(previous) = result.insert(node, owner)
                && previous != owner
            {
                return Err(StoreError::new(format!(
                    "stage member scope owners disagree: {node:?}, {previous:?}, {owner:?}"
                )));
            }
        }
        Ok(Some(result))
    })
}

pub(in crate::analyzer::store) fn close_completion(
    selection: &SelectedResolutionMountInventory<'_>,
    completion: &crate::analyzer::resolution::ResolutionCompletion,
    cancellation: &CancellationToken,
) -> Result<Option<crate::analyzer::resolution::ResolutionCompletion>> {
    Ok(
        close_completions(selection, std::slice::from_ref(completion), cancellation)?
            .map(|mut rows| rows.pop().expect("one completion request")),
    )
}

/// Additional stage authority which suppresses ordinary cached completion boxes.
/// Stage answers themselves apply their host-aware effective predicate in SQL.
pub(in crate::analyzer::store) fn ordinary_completion_suppression(
    selection: &SelectedResolutionMountInventory<'_>,
    cancellation: &CancellationToken,
) -> Result<Option<Vec<crate::analyzer::resolution::ResolutionIncompleteReason>>> {
    use crate::analyzer::resolution::{LoweringGapOrigin, ResolutionIncompleteReason};
    use crate::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code;
    read(selection, cancellation, |connection| {
        let mut statement = connection.prepare_cached(ORDINARY_COMPLETION_SUPPRESSION_SQL)?;
        let mut rows = statement.query(rusqlite::named_params! {
            ":local_base": codec::encode_semantic(SemanticId::local(0, 0)),
            ":qualified_origin": gap_origin_code(LoweringGapOrigin::QualifiedReference),
        })?;
        let mut result = Vec::new();
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            result.push(ResolutionIncompleteReason::UnsupportedSemantic(
                semantic_from_cells(row.get(0)?, row.get(1)?),
            ));
        }
        Ok(Some(result))
    })
}

pub(in crate::analyzer::store) const ORDINARY_COMPLETION_SUPPRESSION_SQL: &str = r#"
SELECT semantic_key,semantic_shared FROM temp.selected_resolution_stage_closed_reasons
UNION
SELECT q.coarse_gap_reason_key,NULL FROM temp.selected_resolution_stage_qualified_routes q
CROSS JOIN temp.selected_resolution_mounts m ON m.mount_ordinal=q.host_ordinal
CROSS JOIN main.resolution_gap_reasons r ON r.blob_id=m.blob_id
 AND r.reason=q.coarse_gap_reason_key-(:local_base+(m.mount_ordinal<<32))
WHERE q.coarse_gap_reason_shared IS NULL
AND q.coarse_gap_reason_key BETWEEN (:local_base+(m.mount_ordinal<<32))
 AND (:local_base+(m.mount_ordinal<<32))+4294967295
AND r.origin=:qualified_origin
"#;

pub(in crate::analyzer::store) fn close_completions(
    selection: &SelectedResolutionMountInventory<'_>,
    completions: &[crate::analyzer::resolution::ResolutionCompletion],
    cancellation: &CancellationToken,
) -> Result<Option<Vec<crate::analyzer::resolution::ResolutionCompletion>>> {
    use crate::analyzer::resolution::{ResolutionCompletion, ResolutionIncompleteReason};
    let mut semantics = std::collections::BTreeSet::new();
    for completion in completions {
        if let ResolutionCompletion::Incomplete(reasons) = completion {
            for reason in reasons.iter() {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                if let ResolutionIncompleteReason::UnsupportedSemantic(semantic) = reason {
                    semantics.insert(*semantic);
                }
            }
        }
    }
    let semantics = semantics.into_iter().collect::<Vec<_>>();
    let parameters = serde_json::to_string(
        &semantics
            .iter()
            .copied()
            .map(super::lexical::semantic_cells)
            .collect::<Vec<_>>(),
    )
    .expect("stage closed reason requests serialize");
    let Some(closed) = read(selection, cancellation, |connection| {
        let mut closed = Vec::new();
        let mut statement=connection.prepare_cached("SELECT input.key FROM json_each(?1) input WHERE EXISTS(SELECT 1 FROM temp.selected_resolution_stage_closed_reasons reason WHERE reason.semantic_key IS input.value->>0 AND reason.semantic_shared IS input.value->>1)")?;
        let mut rows = statement.query([parameters])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            closed.push(ResolutionIncompleteReason::UnsupportedSemantic(
                semantics[row.get::<_, usize>(0)?],
            ));
        }
        Ok(Some(closed))
    })?
    else {
        return Ok(None);
    };
    let mut result = Vec::with_capacity(completions.len());
    for completion in completions {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        result.push(match completion {
            ResolutionCompletion::Complete => ResolutionCompletion::Complete,
            ResolutionCompletion::Incomplete(reasons) => {
                let Some(remaining) = reasons
                    .without_reasons_with_poll(closed.iter().copied(), &mut || {
                        cancellation.is_cancelled()
                    })
                else {
                    return Ok(None);
                };
                remaining.map_or(
                    ResolutionCompletion::Complete,
                    ResolutionCompletion::Incomplete,
                )
            }
        });
    }
    Ok(Some(result))
}

/// The staged semantics of one role whose site is exactly `start..end` in the
/// host's source. A capsule parses its invocation at the host's byte offsets,
/// so a staged site's range is the host token it lowered.
pub(in crate::analyzer::store) fn semantic_sites_at_range(
    selection: &SelectedResolutionMountInventory<'_>,
    host: SelectedResolutionMountOrdinal,
    start: usize,
    end: usize,
    role: crate::analyzer::resolution::LoweredSemanticRole,
    cancellation: &CancellationToken,
) -> Result<
    Option<
        Vec<(
            SemanticId,
            BindingNodeId,
            brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace,
        )>,
    >,
> {
    use crate::analyzer::store::resolution_prepare::resolution_rows::{
        namespace_from_code, semantic_role_code,
    };
    let sql = "SELECT s.semantic_key,s.semantic_shared,s.node,s.namespace FROM temp.selected_resolution_stage_semantics s JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=s.host_ordinal WHERE s.host_ordinal=?1 AND s.start_byte=?2 AND s.end_byte=?3 AND s.role=?4";
    let first = i64::try_from(start).expect("source byte offset fits SQLite integer");
    let second = i64::try_from(end).expect("source byte offset fits SQLite integer");
    read(selection, cancellation, |connection| {
        let mut result = Vec::new();
        let mut statement = connection.prepare_cached(sql)?;
        let mut rows = statement.query(rusqlite::params![
            host.get(),
            first,
            second,
            semantic_role_code(role)
        ])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let key: Option<i64> = row.get(0)?;
            let shared: Option<i64> = row.get(1)?;
            let semantic = codec::decode_semantic(match (key, shared) {
                (Some(key), None) => key,
                (None, Some(shared)) => -shared,
                _ => unreachable!("a stage semantic site has exactly one semantic coordinate"),
            });
            result.push((
                semantic,
                codec::decode_node(row.get(2)?),
                namespace_from_code(row.get(3)?),
            ));
        }
        result.sort_unstable();
        result.dedup();
        Ok(Some(result))
    })
}

pub(in crate::analyzer::store) fn lexical_definitions(
    selection: &SelectedResolutionMountInventory<'_>,
    requests: &[(SelectedResolutionMountOrdinal, SemanticId)],
    cancellation: &CancellationToken,
) -> Result<
    Option<
        Vec<(
            SemanticId,
            crate::analyzer::lexical_definitions::LexicalDefinition,
        )>,
    >,
> {
    use crate::analyzer::lexical_definitions::LexicalDefinition;
    use crate::analyzer::{DeclarationKind, Range};
    let parameters = serde_json::to_string(
        &requests
            .iter()
            .map(|(host, semantic)| {
                let (key, shared) = super::lexical::semantic_cells(*semantic);
                (host.get(), key, shared)
            })
            .collect::<Vec<_>>(),
    )
    .expect("stage lexical definition requests serialize");
    read(selection, cancellation, |connection| {
        let mut result = HashMap::default();
        let mut statement = connection.prepare_cached(
            "SELECT input.key,d.identifier,d.kind,d.name_start_byte,d.name_end_byte,d.name_start_line,d.name_end_line,d.declaration_start_byte,d.declaration_end_byte,d.declaration_start_line,d.declaration_end_line FROM json_each(?1) input CROSS JOIN temp.selected_resolution_stage_declarations d ON d.host_ordinal=input.value->>0 AND d.semantic_key IS input.value->>1 AND d.semantic_shared IS input.value->>2 CROSS JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=d.host_ordinal"
        )?;
        let mut rows = statement.query([parameters])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let ordinal: usize = row.get(0)?;
            let kind: String = row.get(2)?;
            let kind = DeclarationKind::from_label(&kind).ok_or_else(|| {
                StoreError::new(format!("invalid stage lexical declaration kind {kind:?}"))
            })?;
            let range = |column| -> rusqlite::Result<Range> {
                Ok(Range {
                    start_byte: row.get(column)?,
                    end_byte: row.get(column + 1)?,
                    start_line: row.get(column + 2)?,
                    end_line: row.get(column + 3)?,
                })
            };
            let definition = LexicalDefinition {
                source_file: None,
                identifier: row.get(1)?,
                kind,
                name_range: range(3)?,
                declaration_range: range(7)?,
            };
            if let Some(previous) = result.insert(ordinal, definition.clone())
                && previous != definition
            {
                return Err(StoreError::new(format!(
                    "stage lexical declaration payloads disagree: {:?}, {previous:?}, {definition:?}",
                    requests[ordinal]
                )));
            }
        }
        let mut result = result.into_iter().collect::<Vec<_>>();
        result.sort_unstable_by_key(|(ordinal, _)| *ordinal);
        Ok(Some(
            result
                .into_iter()
                .map(|(ordinal, definition)| (requests[ordinal].1, definition))
                .collect(),
        ))
    })
}

pub(in crate::analyzer::store) fn candidate_unconditional_sql() -> &'static str {
    static SQL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    SQL.get_or_init(|| {
        let sql = format!(
        "WITH raw_gaps(host,reason_key,origin,covers,gap_key) AS (SELECT fact.host_ordinal,fact.reason_key,fact.origin,fact.covers,fact.gap_key FROM temp.selected_resolution_stage_gaps fact JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal WHERE fact.covers IN(0,:inventory_cover) AND (:scope IS NULL OR fact.host_ordinal IN(SELECT value FROM json_each(:scope)))) SELECT g.reason_key FROM raw_gaps g WHERE {} AND (g.covers=0 OR (g.host,g.gap_key) NOT IN(SELECT input.value->>0,input.value->>1 FROM json_each(:excluded) input))",
        super::frontier_completion::effective_gap_remains_sql(),
    );
        #[cfg(test)]
        crate::analyzer::store::resolution_selection::note_selected_static_sql_capacity(11, sql.capacity());
        sql
    })
}

pub(in crate::analyzer::store) fn candidate_branches_sql() -> &'static str {
    static SQL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    SQL.get_or_init(|| {
        let sql = {
        let base = "SELECT input.key,fact.host_ordinal,fact.reason_key,fact.origin,fact.gap_key FROM json_each(:requests) input CROSS JOIN temp.selected_resolution_stage_gaps fact ON fact.covers=:endpoint_cover AND fact.endpoint_node=input.value->>0";
        let suffix = " CROSS JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal WHERE (:scope IS NULL OR fact.host_ordinal IN(SELECT value FROM json_each(:scope)))";
        format!("WITH raw_gaps(request_ordinal,host,reason_key,origin,gap_key) AS ({base} AND fact.lookup_key IS NULL AND fact.lookup_shared IS NULL{suffix} UNION ALL {base} AND fact.lookup_key IS input.value->>1 AND fact.lookup_shared IS input.value->>2{suffix} AND input.value->>3=1 UNION ALL {base}{suffix} AND input.value->>3=2 AND (fact.lookup_key IS NOT NULL OR fact.lookup_shared IS NOT NULL)) SELECT g.request_ordinal,g.reason_key FROM raw_gaps g WHERE {} AND (g.host,g.gap_key) NOT IN(SELECT input.value->>0,input.value->>1 FROM json_each(:excluded) input)",super::frontier_completion::effective_gap_remains_sql())
    };
        #[cfg(test)]
        crate::analyzer::store::resolution_selection::note_selected_static_sql_capacity(12, sql.capacity());
        sql
    })
}

pub(in crate::analyzer::store) fn candidate_completion(
    selection: &SelectedResolutionMountInventory<'_>,
    direction: crate::analyzer::resolution::LoweredCandidateDirection,
    requests: &[crate::analyzer::resolution::BatchCandidateRequest],
    scope: Option<&[SelectedResolutionMountOrdinal]>,
    excluded: &[crate::analyzer::resolution::ReverseCandidateGapIdentity],
    cancellation: &CancellationToken,
) -> Result<crate::analyzer::resolution::BatchCandidateCompletionOutcome> {
    use crate::analyzer::resolution::{
        BatchCandidateCompletionOutcome, ResolutionCompletion, ResolutionIncompleteReason,
    };
    use crate::analyzer::store::resolution_prepare::resolution_rows::{
        covers_candidate_endpoint, covers_candidate_inventory,
    };
    let excluded = serde_json::to_string(
        &excluded
            .iter()
            .map(|identity| {
                (
                    identity.fragment().ordinal(),
                    codec::encode_semantic(identity.gap_id()),
                )
            })
            .collect::<Vec<_>>(),
    )
    .expect("exact stage gap exclusions serialize");
    let parameters = serde_json::to_string(
        &requests
            .iter()
            .map(|request| {
                let endpoint = request.endpoint();
                let (key, shared, mode) = match endpoint.symbols().fixed().first() {
                    Some(symbol) => {
                        let (key, shared) = super::lexical::semantic_cells(symbol.symbol());
                        (key, shared, 1)
                    }
                    None => (
                        None,
                        None,
                        if endpoint.symbols().tail().is_some() {
                            2
                        } else {
                            0
                        },
                    ),
                };
                (codec::encode_node(endpoint.node()), key, shared, mode)
            })
            .collect::<Vec<_>>(),
    )
    .expect("stage completion requests serialize");
    let scope = scope.map(|scope| {
        serde_json::to_string(&scope.iter().map(|host| host.get()).collect::<Vec<_>>())
            .expect("stage completion scope serializes")
    });
    // Accumulators live outside the interruptible statement closure. An SQLite
    // interruption must preserve reasons already decoded from either query.
    let mut unconditional = Vec::new();
    let mut branches = vec![Vec::new(); requests.len()];
    let result = with_resolution_read_progress_handler(
        selection.connection(),
        cancellation,
        |connection| {
            let mut statement = connection.prepare_cached(candidate_unconditional_sql())?;
            let mut rows = statement.query(rusqlite::named_params! {
                ":inventory_cover":covers_candidate_inventory(direction), ":scope":scope, ":excluded":excluded,
                ":qualified_origin":crate::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code(crate::analyzer::resolution::LoweringGapOrigin::QualifiedReference),
                ":local_base":codec::encode_semantic(SemanticId::local(0,0)),
            })?;
            while let Some(row) = rows.next()? {
                let semantic = codec::decode_semantic(row.get(0)?);
                unconditional.push(ResolutionIncompleteReason::UnsupportedSemantic(semantic));
                if cancellation.is_cancelled() {
                    return Ok(());
                }
            }
            let mut statement = connection.prepare_cached(candidate_branches_sql())?;
            let mut rows = statement.query(rusqlite::named_params! {
                ":requests":parameters, ":scope":scope, ":endpoint_cover":covers_candidate_endpoint(direction), ":excluded":excluded,
                ":qualified_origin":crate::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code(crate::analyzer::resolution::LoweringGapOrigin::QualifiedReference),
                ":local_base":codec::encode_semantic(SemanticId::local(0,0)),
            })?;
            while let Some(row) = rows.next()? {
                let ordinal: usize = row.get(0)?;
                let semantic = codec::decode_semantic(row.get(1)?);
                branches[ordinal].push(ResolutionIncompleteReason::UnsupportedSemantic(semantic));
                if cancellation.is_cancelled() {
                    return Ok(());
                }
            }
            Ok(())
        },
    );
    match result {
        Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => {}
        Err(error) => return Err(error),
        Ok(()) => {}
    }
    if cancellation.is_cancelled() {
        unconditional.push(ResolutionIncompleteReason::Cancelled);
    }
    let completion = |reasons: Vec<_>| {
        if reasons.is_empty() {
            ResolutionCompletion::Complete
        } else {
            ResolutionCompletion::incomplete(reasons)
        }
    };
    Ok(BatchCandidateCompletionOutcome::new(
        requests.len(),
        completion(unconditional),
        branches.into_iter().map(completion),
    ))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::analyzer::store) struct ReferenceSeedRow {
    pub host: BindingFragmentId,
    pub node: BindingNodeId,
    pub metadata: Option<crate::analyzer::resolution::FactReferenceSiteMetadata>,
}

pub(in crate::analyzer::store) const REFERENCE_SEED_ROWS_SQL: &str = r#"
SELECT input.key,producer.host_ordinal,node.node,
 site.source_site,site.namespace,site.site_kind,site.start_byte,site.end_byte,site.unqualified,
 site.owner_kind,site.owner_key,site.owner_shared,site.receiver_origin,site.go_spelling_namespace,site.go_package_qualifier
FROM json_each(?1) input
CROSS JOIN temp.selected_resolution_stage_nodes node
 ON node.kind_semantic_key IS input.value->>0 AND node.kind_shared_id IS input.value->>1
CROSS JOIN temp.selected_resolution_stage_node_owners owner ON owner.node=node.node
CROSS JOIN temp.selected_resolution_stage_producers producer ON producer.producer_id=owner.producer_id
CROSS JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=producer.host_ordinal
LEFT JOIN temp.selected_resolution_stage_semantics site
 ON site.semantic_key IS input.value->>0 AND site.semantic_shared IS input.value->>1
 AND site.host_ordinal=producer.host_ordinal AND site.node=node.node AND site.role=0
WHERE node.kind IN(8,9) AND node.kind=8
"#;

pub(in crate::analyzer::store) fn reference_seed_rows(
    selection: &SelectedResolutionMountInventory<'_>,
    queries: &[crate::analyzer::resolution::ResolutionQuery],
    cancellation: &CancellationToken,
) -> Result<Option<Vec<Option<ReferenceSeedRow>>>> {
    use crate::analyzer::resolution::FactReferenceSiteMetadata;
    use crate::analyzer::store::resolution_prepare::resolution_rows::{
        from_code, namespace_from_code,
    };
    use brokk_bifrost_core::analyzer::resolution_facts::{
        ALL_RESOLUTION_CALLABLE_RECEIVER_ORIGINS, ALL_RESOLUTION_SITE_KINDS, ResolutionSiteId,
    };
    let parameters = serde_json::to_string(
        &queries
            .iter()
            .map(|query| super::lexical::semantic_cells(query.reference()))
            .collect::<Vec<_>>(),
    )
    .expect("stage reference seed requests serialize");
    read(selection, cancellation, |connection| {
        let mut result = vec![None; queries.len()];
        let mut statement = connection.prepare_cached(REFERENCE_SEED_ROWS_SQL)?;
        let mut rows = statement.query([parameters])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let ordinal: usize = row.get(0)?;
            let kind: Option<i64> = row.get(5)?;
            let metadata = if let Some(kind) = kind {
                let owner_kind: i64 = row.get(9)?;
                let owner = match owner_kind {
                    0 => None,
                    1 => Some(None),
                    2 => {
                        let key: Option<i64> = row.get(10)?;
                        let shared: Option<i64> = row.get(11)?;
                        Some(Some(codec::decode_semantic(key.unwrap_or_else(|| {
                            -shared.expect("stage reference owner coordinate")
                        }))))
                    }
                    other => unreachable!("invalid stage reference owner kind {other}"),
                };
                let origin: Option<i64> = row.get(12)?;
                Some(
                    FactReferenceSiteMetadata::new(
                        ResolutionSiteId::new(row.get(3)?),
                        namespace_from_code(row.get(4)?),
                        from_code(ALL_RESOLUTION_SITE_KINDS, kind, "stage reference site kind"),
                        row.get(6)?,
                        row.get(7)?,
                        row.get::<_, i64>(8)? != 0,
                        owner,
                        origin.map(|origin| {
                            from_code(
                                ALL_RESOLUTION_CALLABLE_RECEIVER_ORIGINS,
                                origin,
                                "stage reference receiver origin",
                            )
                        }),
                    )
                    .with_go_spelling_namespace(
                        row.get::<_, Option<i64>>(13)?.map(namespace_from_code),
                    )
                    .with_go_package_qualifier(row.get(14)?),
                )
            } else {
                None
            };
            let current = ReferenceSeedRow {
                host: BindingFragmentId::at_ordinal(row.get(1)?),
                node: codec::decode_node(row.get(2)?),
                metadata,
            };
            if let Some(previous) = &result[ordinal] {
                if previous != &current {
                    return Err(StoreError::new(format!(
                        "stage reference seed authority disagrees: {:?}, {previous:?}, {current:?}",
                        queries[ordinal]
                    )));
                }
            } else {
                result[ordinal] = Some(current);
            }
        }
        Ok(Some(result))
    })
}

pub(in crate::analyzer::store) const CONTEXT_FORWARD_CANDIDATES_SQL: &str = r#"
SELECT r.value->>0,p.host_ordinal,p.path
FROM json_each(?2) r CROSS JOIN temp.selected_resolution_context_paths p
 ON p.context_id=?1 AND p.start_node=r.value->>1
UNION ALL
SELECT r.value->>0,p.host_ordinal,p.path
FROM json_each(?3) r CROSS JOIN temp.selected_resolution_context_paths p
 ON p.context_id=?1 AND p.start_node=r.value->>1
 AND p.start_lead_key IS r.value->>2 AND p.start_lead_shared IS r.value->>3
UNION ALL
SELECT r.value->>0,p.host_ordinal,p.path
FROM json_each(?3) r CROSS JOIN temp.selected_resolution_context_paths p
 ON p.context_id=?1 AND p.start_node=r.value->>1
 AND p.start_lead_key IS NULL AND p.start_lead_shared IS NULL
"#;

pub(in crate::analyzer::store) const CONTEXT_REVERSE_CANDIDATES_SQL: &str = r#"
SELECT r.value->>0,p.host_ordinal,p.path
FROM json_each(?2) r CROSS JOIN temp.selected_resolution_context_paths p
 ON p.context_id=?1 AND p.end_node=r.value->>1
UNION ALL
SELECT r.value->>0,p.host_ordinal,p.path
FROM json_each(?3) r CROSS JOIN temp.selected_resolution_context_paths p
 ON p.context_id=?1 AND p.end_node=r.value->>1
 AND p.end_lead_key IS r.value->>2 AND p.end_lead_shared IS r.value->>3
UNION ALL
SELECT r.value->>0,p.host_ordinal,p.path
FROM json_each(?3) r CROSS JOIN temp.selected_resolution_context_paths p
 ON p.context_id=?1 AND p.end_node=r.value->>1
 AND p.end_lead_key IS NULL AND p.end_lead_shared IS NULL
"#;

pub(in crate::analyzer::store) fn context_candidate_rows(
    selection: &SelectedResolutionMountInventory<'_>,
    context: crate::analyzer::resolution::SelectedContextPathToken,
    requests: &[crate::analyzer::resolution::BatchCandidateRequest],
    sql: &str,
    cancellation: &CancellationToken,
) -> Result<Option<Vec<(usize, CandidatePathIdentity)>>> {
    let mut whole = Vec::new();
    let mut keyed = Vec::new();
    for (ordinal, request) in requests.iter().enumerate() {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        assert_eq!(ordinal, request.request_ordinal());
        let endpoint = request.endpoint();
        if endpoint.node() == BindingNodeId::universal_root()
            && let Some(first) = endpoint.symbols().fixed().first()
        {
            let (key, shared) = super::lexical::semantic_cells(first.symbol());
            keyed.push(serde_json::json!([
                ordinal,
                codec::encode_node(endpoint.node()),
                key,
                shared
            ]));
        } else {
            whole.push(serde_json::json!([
                ordinal,
                codec::encode_node(endpoint.node())
            ]));
        }
    }
    let whole = serde_json::to_string(&whole).expect("whole context requests serialize");
    let keyed = serde_json::to_string(&keyed).expect("keyed context requests serialize");
    read(selection, cancellation, |connection| {
        super::context::require_context(connection, context)?;
        let mut result = Vec::new();
        let mut statement = connection.prepare_cached(sql)?;
        let mut rows = statement.query(rusqlite::params![context.get(), whole, keyed])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            result.push((
                row.get::<_, usize>(0)?,
                CandidatePathIdentity::new(
                    BindingFragmentId::at_ordinal(row.get(1)?),
                    codec::decode_path_id(row.get(2)?),
                ),
            ));
        }
        result.sort_unstable();
        for pair in result.windows(2) {
            if pair[0] == pair[1] {
                return Err(StoreError::new(format!(
                    "selected context candidate query repeated identity: {:?}",
                    pair[0]
                )));
            }
        }
        Ok(Some(result))
    })
}

pub(in crate::analyzer::store) fn context_paths(
    selection: &SelectedResolutionMountInventory<'_>,
    context: crate::analyzer::resolution::SelectedContextPathToken,
    cancellation: &CancellationToken,
) -> Result<Option<Vec<(CandidatePathIdentity, PartialPath)>>> {
    read(selection, cancellation, |connection| {
        super::context::require_context(connection, context)?;
        let mut result = Vec::new();
        let mut statement=connection.prepare_cached("SELECT host_ordinal,path,start_node,end_node,json(body) FROM temp.selected_resolution_context_paths WHERE context_id=?1 ORDER BY host_ordinal,path")?;
        let mut rows = statement.query([context.get()])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let identity = CandidatePathIdentity::new(
                BindingFragmentId::at_ordinal(row.get(0)?),
                codec::decode_path_id(row.get(1)?),
            );
            let path = codec::decode_path(row.get(2)?, row.get(3)?, &row.get::<_, String>(4)?);
            result.push((identity, path));
        }
        Ok(Some(result))
    })
}

pub(in crate::analyzer::store) fn hydrate_context_paths(
    selection: &SelectedResolutionMountInventory<'_>,
    context: crate::analyzer::resolution::SelectedContextPathToken,
    candidates: &[CandidatePathIdentity],
    cancellation: &CancellationToken,
) -> Result<Option<Vec<(CandidatePathIdentity, PartialPath)>>> {
    let requests = serde_json::to_string(
        &candidates
            .iter()
            .map(|candidate| {
                (
                    candidate.fragment().ordinal(),
                    codec::encode_path_id(candidate.path()),
                )
            })
            .collect::<Vec<_>>(),
    )
    .expect("context hydration requests serialize");
    read(selection, cancellation, |connection| {
        super::context::require_context(connection, context)?;
        let mut result = Vec::new();
        let mut seen = crate::hash::HashSet::default();
        let mut statement=connection.prepare_cached("SELECT input.key,p.start_node,p.end_node,json(p.body) FROM json_each(?2) input CROSS JOIN temp.selected_resolution_context_paths p ON p.context_id=?1 AND p.host_ordinal=input.value->>0 AND p.path=input.value->>1 ORDER BY input.key")?;
        let mut rows = statement.query(rusqlite::params![context.get(), requests])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let ordinal: usize = row.get(0)?;
            let identity = candidates[ordinal];
            if !seen.insert(identity) {
                continue;
            }
            let path = codec::decode_path(row.get(1)?, row.get(2)?, &row.get::<_, String>(3)?);
            result.push((identity, path));
        }
        Ok(Some(result))
    })
}

pub(in crate::analyzer::store) fn reference_completions(
    selection: &SelectedResolutionMountInventory<'_>,
    queries: &[crate::analyzer::resolution::ResolutionQuery],
    seeds: &[Option<ReferenceSeedRow>],
    cancellation: &CancellationToken,
) -> Result<(
    Vec<crate::analyzer::resolution::ResolutionCompletion>,
    crate::analyzer::resolution::ResolutionCompletion,
    bool,
)> {
    use crate::analyzer::resolution::{ResolutionCompletion, ResolutionIncompleteReason};
    assert_eq!(queries.len(), seeds.len());
    let requests = serde_json::to_string(
        &queries
            .iter()
            .zip(seeds)
            .enumerate()
            .filter_map(|(ordinal, (query, seed))| {
                let seed = seed.as_ref()?;
                let (key, shared) = super::lexical::semantic_cells(query.reference());
                Some((
                    ordinal,
                    seed.host.ordinal(),
                    key,
                    shared,
                    codec::encode_node(seed.node),
                ))
            })
            .collect::<Vec<_>>(),
    )
    .expect("stage reference completion requests serialize");
    let sql = format!(
        "WITH raw_gaps(request_ordinal,host,reason_key,origin) AS (SELECT input.value->>0,fact.host_ordinal,fact.reason_key,fact.origin FROM json_each(:requests) input CROSS JOIN temp.selected_resolution_stage_gaps fact ON fact.host_ordinal=input.value->>1 AND fact.covers=0 UNION ALL SELECT input.value->>0,fact.host_ordinal,fact.reason_key,fact.origin FROM json_each(:requests) input CROSS JOIN temp.selected_resolution_stage_gaps fact ON fact.subject_key IS input.value->>2 AND fact.subject_shared IS input.value->>3 AND fact.covers=4 AND fact.host_ordinal=input.value->>1 AND fact.endpoint_node=input.value->>4) SELECT g.request_ordinal,g.reason_key FROM raw_gaps g JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=g.host WHERE {}",
        super::frontier_completion::effective_gap_remains_sql()
    );
    let mut reasons = vec![Vec::new(); queries.len()];
    let result = with_resolution_read_progress_handler(
        selection.connection(),
        cancellation,
        |connection| {
            let mut statement = connection.prepare_cached(&sql)?;
            let mut rows=statement.query(rusqlite::named_params! {
            ":requests":requests,
            ":qualified_origin":crate::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code(crate::analyzer::resolution::LoweringGapOrigin::QualifiedReference),
            ":local_base":codec::encode_semantic(SemanticId::local(0,0)),
        })?;
            while let Some(row) = rows.next()? {
                let ordinal: usize = row.get(0)?;
                let reason = codec::decode_semantic(row.get(1)?);
                reasons[ordinal].push(ResolutionIncompleteReason::UnsupportedSemantic(reason));
                if cancellation.is_cancelled() {
                    return Ok(());
                }
            }
            Ok(())
        },
    );
    match result {
        Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => {}
        Err(error) => return Err(error),
        Ok(()) => {}
    }
    let mut evidence = crate::analyzer::resolution::ResolutionCompletionAccumulator::default();
    let completions = reasons
        .into_iter()
        .map(|reasons| {
            let completion = if reasons.is_empty() {
                ResolutionCompletion::Complete
            } else {
                ResolutionCompletion::incomplete(reasons)
            };
            evidence.include(&completion);
            completion
        })
        .collect();
    Ok((completions, evidence.finish(), cancellation.is_cancelled()))
}

pub(in crate::analyzer::store) fn reference_inventory_completion(
    selection: &SelectedResolutionMountInventory<'_>,
    fragments: Option<&crate::hash::HashSet<BindingFragmentId>>,
    cancellation: &CancellationToken,
) -> Result<crate::analyzer::resolution::ResolutionCompletion> {
    use crate::analyzer::resolution::{ResolutionCompletion, ResolutionIncompleteReason};
    let fragments = fragments.map(|fragments| {
        serde_json::to_string(
            &fragments
                .iter()
                .map(|fragment| fragment.ordinal())
                .collect::<Vec<_>>(),
        )
        .expect("reference inventory fragments serialize")
    });
    let gap_sql = format!(
        "WITH wanted_hosts AS (SELECT scope.mount_ordinal FROM json_each(:fragments) input CROSS JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=input.value UNION ALL SELECT mount_ordinal FROM temp.selected_resolution_scope_mounts WHERE :fragments IS NULL), raw_gaps(host,reason_key,origin) AS (SELECT mount.mount_ordinal,:local_base+(mount.mount_ordinal<<32)+fact.reason,reason.origin FROM wanted_hosts host CROSS JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=host.mount_ordinal CROSS JOIN main.resolution_gaps fact ON fact.blob_id=mount.blob_id AND fact.covers IN(0,1) JOIN main.resolution_gap_reasons reason ON reason.blob_id=fact.blob_id AND reason.reason=fact.reason UNION ALL SELECT fact.host_ordinal,fact.reason_key,fact.origin FROM wanted_hosts host CROSS JOIN temp.selected_resolution_stage_gaps fact ON fact.host_ordinal=host.mount_ordinal AND fact.covers IN(0,1)) SELECT g.reason_key FROM raw_gaps g WHERE {}",
        super::frontier_completion::effective_gap_remains_sql()
    );
    let mut reasons = Vec::new();
    let result = with_resolution_read_progress_handler(
        selection.connection(),
        cancellation,
        |connection| {
            let mut statement = connection.prepare_cached(&gap_sql)?;
            let mut rows=statement.query(rusqlite::named_params! {
            ":fragments":fragments,
            ":qualified_origin":crate::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code(crate::analyzer::resolution::LoweringGapOrigin::QualifiedReference),
            ":local_base":codec::encode_semantic(SemanticId::local(0,0)),
        })?;
            while let Some(row) = rows.next()? {
                reasons.push(ResolutionIncompleteReason::UnsupportedSemantic(
                    codec::decode_semantic(row.get(0)?),
                ));
                if cancellation.is_cancelled() {
                    return Ok(());
                }
            }
            Ok(())
        },
    );
    match result {
        Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => {}
        Err(error) => return Err(error),
        Ok(()) => {}
    }
    if cancellation.is_cancelled() {
        reasons.push(ResolutionIncompleteReason::Cancelled);
    }
    Ok(if reasons.is_empty() {
        ResolutionCompletion::Complete
    } else {
        ResolutionCompletion::incomplete(reasons)
    })
}

pub(in crate::analyzer::store) fn reference_inventory(
    selection: &SelectedResolutionMountInventory<'_>,
    fragments: Option<&crate::hash::HashSet<BindingFragmentId>>,
    cancellation: &CancellationToken,
) -> Result<(
    Vec<crate::analyzer::resolution::ResolutionQuery>,
    crate::analyzer::resolution::ResolutionCompletion,
    bool,
)> {
    use crate::analyzer::resolution::{
        ResolutionCompletion, ResolutionIncompleteReason, ResolutionQuery,
    };
    let completion = reference_inventory_completion(selection, fragments, cancellation)?;
    if cancellation.is_cancelled() {
        return Ok((Vec::new(), completion, true));
    }
    let fragments = fragments.map(|fragments| {
        serde_json::to_string(
            &fragments
                .iter()
                .map(|fragment| fragment.ordinal())
                .collect::<Vec<_>>(),
        )
        .expect("reference inventory fragments serialize")
    });
    let mut references = Vec::new();
    let result = with_resolution_read_progress_handler(
        selection.connection(),
        cancellation,
        |connection| {
            // Read source-known inventory evidence before any seed can reach a
            // visitor, including gaps from admitted fragments with no references.
            let mut statement=connection.prepare_cached("WITH wanted_hosts AS (SELECT scope.mount_ordinal FROM json_each(?1) input CROSS JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=input.value UNION ALL SELECT mount_ordinal FROM temp.selected_resolution_scope_mounts WHERE ?1 IS NULL), producers AS (SELECT producer.producer_id,producer.host_ordinal FROM wanted_hosts host CROSS JOIN temp.selected_resolution_stage_producers producer INDEXED BY selected_resolution_stage_capsule ON producer.host_ordinal=host.mount_ordinal AND producer.admission_id IS NOT NULL UNION ALL SELECT producer.producer_id,producer.host_ordinal FROM wanted_hosts host CROSS JOIN temp.selected_resolution_stage_producers producer INDEXED BY selected_resolution_stage_bridge ON producer.host_ordinal=host.mount_ordinal AND producer.bridge_identity IS NOT NULL) SELECT 0,mount.mount_ordinal,?2+(mount.mount_ordinal<<32)+site.site,NULL FROM wanted_hosts host CROSS JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=host.mount_ordinal CROSS JOIN main.resolution_sites site ON site.blob_id=mount.blob_id AND site.role=0 UNION ALL SELECT 1,producer.host_ordinal,node.kind_semantic_key,node.kind_shared_id FROM producers producer CROSS JOIN temp.selected_resolution_stage_node_owners owner ON owner.producer_id=producer.producer_id CROSS JOIN temp.selected_resolution_stage_nodes node ON node.node=owner.node WHERE node.kind=8")?;
            let mut rows = statement.query(rusqlite::params![
                fragments,
                codec::encode_semantic(SemanticId::local(0, 0))
            ])?;
            while let Some(row) = rows.next()? {
                references.push((
                    row.get::<_, i64>(0)?,
                    row.get::<_, u32>(1)?,
                    semantic_from_cells(row.get(2)?, row.get(3)?),
                ));
                if cancellation.is_cancelled() {
                    return Ok(());
                }
            }
            Ok(())
        },
    );
    match result {
        Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => {}
        Err(error) => return Err(error),
        Ok(()) => {}
    }
    let cancelled = cancellation.is_cancelled();
    if cancelled {
        references.clear();
    }
    references.sort_unstable();
    let mut seen = crate::hash::HashSet::default();
    let queries = references
        .into_iter()
        .filter_map(|(_, _, semantic)| {
            seen.insert(semantic)
                .then_some(ResolutionQuery::new(semantic))
        })
        .collect();
    let completion = if cancelled {
        completion.combine(&ResolutionCompletion::incomplete([
            ResolutionIncompleteReason::Cancelled,
        ]))
    } else {
        completion
    };
    Ok((queries, completion, cancelled))
}

pub(in crate::analyzer::store) fn root_terminal_candidates_sql() -> &'static str {
    static SQL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    SQL.get_or_init(|| {
        let sql = {
            format!(
                r#"
SELECT input.key,path.host_ordinal,path.path
FROM json_each(?1) input
CROSS JOIN temp.selected_resolution_stage_paths path
 ON path.root_terminal_shared=input.value
 AND path.end_node={root} AND path.root_terminal_shared IS NOT NULL
CROSS JOIN temp.selected_resolution_scope_mounts scope
 ON scope.mount_ordinal=path.host_ordinal
"#,
                root = codec::encode_node(BindingNodeId::universal_root())
            )
        };
        #[cfg(test)]
        crate::analyzer::store::resolution_selection::note_selected_static_sql_capacity(
            13,
            sql.capacity(),
        );
        sql
    })
}

pub(in crate::analyzer::store) fn root_terminal_candidates(
    selection: &SelectedResolutionMountInventory<'_>,
    demands: &[SemanticId],
    cancellation: &CancellationToken,
) -> Result<Option<Vec<CandidatePathIdentity>>> {
    let names = demands
        .iter()
        .map(|demand| {
            demand
                .shared_name_id()
                .expect("a root terminal demand is a shared semantic")
                .get()
        })
        .collect::<Vec<_>>();
    let names = serde_json::to_string(&names).expect("terminal demands serialize");
    read(selection, cancellation, |connection| {
        let mut statement = connection.prepare_cached(root_terminal_candidates_sql())?;
        let mut rows = statement.query([names])?;
        let mut result = Vec::new();
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            result.push(CandidatePathIdentity::new(
                BindingFragmentId::at_ordinal(row.get(1)?),
                codec::decode_path_id(row.get(2)?),
            ));
        }
        result.sort_unstable();
        result.dedup();
        Ok(Some(result))
    })
}

/// Read all-host proof rows while classifying effective answer eligibility in
/// the same snapshot. Scope never removes a proof row.
pub(in crate::analyzer::store) fn raw_reverse_candidate_rows(
    selection: &SelectedResolutionMountInventory<'_>,
    requests: &[crate::analyzer::resolution::BatchCandidateRequest],
    excluded: &[crate::analyzer::resolution::ReverseCandidateGapIdentity],
    scope: Option<&[SelectedResolutionMountOrdinal]>,
    cancellation: &CancellationToken,
) -> Result<(
    Vec<crate::analyzer::store::resolution_lexical::ReverseCoverageEvidence>,
    bool,
)> {
    use crate::analyzer::resolution::{
        ResolutionIncompleteReason, ReverseCandidateGapIdentity, ReverseCandidateGapLocation,
        ReverseCandidateGapRow,
    };
    use crate::analyzer::store::resolution_lexical::ReverseCoverageEvidence;
    let endpoints = serde_json::to_string(
        &requests
            .iter()
            .map(|request| codec::encode_node(request.endpoint().node()))
            .collect::<Vec<_>>(),
    )
    .expect("raw reverse endpoints serialize");
    let excluded = serde_json::to_string(
        &excluded
            .iter()
            .map(|identity| {
                (
                    identity.fragment().ordinal(),
                    codec::encode_semantic(identity.gap_id()),
                )
            })
            .collect::<Vec<_>>(),
    )
    .expect("raw reverse exclusions serialize");
    let scope = scope.map(|scope| {
        serde_json::to_string(&scope.iter().map(|host| host.get()).collect::<Vec<_>>())
            .expect("reverse evidence scope serializes")
    });
    let columns = "fact.host_ordinal,fact.covers,fact.gap_key,fact.reason_key,fact.endpoint_node,fact.lookup_key,fact.lookup_shared,fact.origin";
    let sql = format!(
        "WITH raw_gaps(host,covers,gap_key,reason_key,endpoint_node,lookup_key,lookup_shared,origin) AS (SELECT {columns} FROM temp.selected_resolution_stage_gaps fact WHERE fact.covers IN(0,3) UNION SELECT {columns} FROM json_each(:endpoints) input CROSS JOIN temp.selected_resolution_stage_gaps fact ON fact.covers=6 AND fact.endpoint_node=input.value UNION SELECT {columns} FROM json_each(:excluded) input CROSS JOIN temp.selected_resolution_stage_gaps fact ON fact.host_ordinal=input.value->>0 AND fact.covers=6 AND fact.gap_key=input.value->>1) SELECT g.host,g.covers,g.gap_key,g.reason_key,g.endpoint_node,g.lookup_key,g.lookup_shared,EXISTS(SELECT 1 FROM temp.selected_resolution_scope_mounts scope WHERE scope.mount_ordinal=g.host) AND (:scope IS NULL OR g.host IN(SELECT value FROM json_each(:scope))) AND ({}) FROM raw_gaps g WHERE {}",
        super::frontier_completion::effective_gap_remains_sql(),
        super::frontier_completion::QUALIFIED_GAP_REMAINS_SQL
    );
    let mut result = Vec::new();
    let read = with_resolution_read_progress_handler(
        selection.connection(),
        cancellation,
        |connection| {
            let mut statement = connection.prepare_cached(&sql)?;
            let mut rows=statement.query(rusqlite::named_params! {
            ":endpoints":endpoints,":excluded":excluded,":scope":scope,
            ":qualified_origin":crate::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code(crate::analyzer::resolution::LoweringGapOrigin::QualifiedReference),
            ":local_base":codec::encode_semantic(SemanticId::local(0,0)),
        })?;
            while let Some(row) = rows.next()? {
                let host = BindingFragmentId::at_ordinal(row.get(0)?);
                let covers: i64 = row.get(1)?;
                let reason = ResolutionIncompleteReason::UnsupportedSemantic(
                    codec::decode_semantic(row.get(3)?),
                );
                let gap = if covers == 0 {
                    None
                } else {
                    let location = if covers == 3 {
                        ReverseCandidateGapLocation::Inventory
                    } else {
                        let key: Option<i64> = row.get(5)?;
                        let shared: Option<i64> = row.get(6)?;
                        ReverseCandidateGapLocation::Endpoint {
                            endpoint: codec::decode_node(row.get(4)?),
                            lookup: (key.is_some() || shared.is_some())
                                .then(|| semantic_from_cells(key, shared)),
                        }
                    };
                    Some(ReverseCandidateGapRow::new(
                        ReverseCandidateGapIdentity::new(host, codec::decode_semantic(row.get(2)?)),
                        location,
                        reason,
                    ))
                };
                result.push(ReverseCoverageEvidence {
                    host,
                    gap,
                    reason,
                    eligible: row.get(7)?,
                });
                if cancellation.is_cancelled() {
                    return Ok(());
                }
            }
            Ok(())
        },
    );
    match read {
        Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => {}
        Err(error) => return Err(error),
        Ok(()) => {}
    }
    Ok((result, cancellation.is_cancelled()))
}

/// The former stage service's fragment coverage is aggregate, unlike each
/// reference seed's source-owned fragment coverage.
pub(in crate::analyzer::store) fn fragment_completion(
    selection: &SelectedResolutionMountInventory<'_>,
    cancellation: &CancellationToken,
) -> Result<crate::analyzer::resolution::ResolutionCompletion> {
    use crate::analyzer::resolution::{ResolutionCompletion, ResolutionIncompleteReason};
    let sql = format!(
        "WITH raw_gaps(host,reason_key,origin) AS (SELECT fact.host_ordinal,fact.reason_key,fact.origin FROM temp.selected_resolution_stage_gaps fact CROSS JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal WHERE fact.covers=0) SELECT g.reason_key FROM raw_gaps g WHERE {}",
        super::frontier_completion::effective_gap_remains_sql()
    );
    let mut reasons = Vec::new();
    let read = with_resolution_read_progress_handler(
        selection.connection(),
        cancellation,
        |connection| {
            let mut statement = connection.prepare_cached(&sql)?;
            let mut rows=statement.query(rusqlite::named_params! {
            ":qualified_origin":crate::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code(crate::analyzer::resolution::LoweringGapOrigin::QualifiedReference),
            ":local_base":codec::encode_semantic(SemanticId::local(0,0)),
        })?;
            while let Some(row) = rows.next()? {
                reasons.push(ResolutionIncompleteReason::UnsupportedSemantic(
                    codec::decode_semantic(row.get(0)?),
                ));
                if cancellation.is_cancelled() {
                    return Ok(());
                }
            }
            Ok(())
        },
    );
    match read {
        Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => {}
        Err(error) => return Err(error),
        Ok(()) => {}
    }
    if cancellation.is_cancelled() {
        reasons.push(ResolutionIncompleteReason::Cancelled);
    }
    Ok(if reasons.is_empty() {
        ResolutionCompletion::Complete
    } else {
        ResolutionCompletion::incomplete(reasons)
    })
}
