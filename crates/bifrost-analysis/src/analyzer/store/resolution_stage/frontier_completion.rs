//! Effective frontier completion across both selected fact authorities.

use super::super::Result;
use super::super::resolution::with_resolution_read_progress_handler;
use super::super::resolution_prepare::resolution_rows::gap_origin_code;
use super::super::resolution_selection::SelectedResolutionMountInventory;
use super::{codec, lexical};
use crate::CancellationToken;
use crate::analyzer::resolution::{
    BindingFragmentId, LoweringGapOrigin, PolledCompletionAccumulator, ResolutionCompletion,
    ResolutionIncompleteReason, SelectedTypeFrontierCompletion, SemanticId, TypedFactPageVisitor,
    TypedFactReadOutcome, TypedFactRequest,
};
use rusqlite::named_params;
use serde_json::json;
use std::sync::OnceLock;

// Callers project their bounded raw gaps as g(host,reason_key,origin).
// Exclusion proofs apply only qualified suppression; effective answers also
// remove exact closed reasons after preserving those raw proof identities.
pub(in crate::analyzer::store) const QUALIFIED_GAP_REMAINS_SQL: &str = r#"NOT (g.origin=:qualified_origin AND (
   EXISTS (
     SELECT 1 FROM temp.selected_resolution_stage_qualified_routes q
     WHERE q.coarse_gap_reason_key=g.reason_key AND q.host_ordinal=g.host
   ) OR EXISTS (
     SELECT 1 FROM temp.selected_resolution_mounts m
     JOIN main.resolution_qualified_routes q ON q.blob_id=m.blob_id
       AND q.coarse_gap_reason=g.reason_key-(:local_base+(m.mount_ordinal<<32))
     WHERE m.mount_ordinal=g.host
       AND g.reason_key BETWEEN (:local_base+(m.mount_ordinal<<32))
                            AND (:local_base+(m.mount_ordinal<<32))+4294967295
   )
 ))"#;

pub(in crate::analyzer::store) fn effective_gap_remains_sql() -> &'static str {
    static SQL: OnceLock<String> = OnceLock::new();
    SQL.get_or_init(|| {
        let sql = {
            format!(
                r#"NOT EXISTS (
   SELECT 1 FROM temp.selected_resolution_stage_closed_reasons c
   WHERE c.semantic_key=g.reason_key
 ) AND ({})"#,
                QUALIFIED_GAP_REMAINS_SQL
            )
        };
        #[cfg(test)]
        crate::analyzer::store::resolution_selection::note_selected_static_sql_capacity(
            14,
            sql.capacity(),
        );
        sql
    })
}

// Main requests carry their actual mount and blob-local slot, independently
// of the stage request's full runtime/shared pair. Remount only main rows;
// stage rows already carry their complete semantic coordinates.
pub(in crate::analyzer::store) fn frontier_completion_sql() -> &'static str {
    static SQL: OnceLock<String> = OnceLock::new();
    SQL.get_or_init(|| {
        let sql = {
            format!(
                r#"
WITH main_requests AS (
 SELECT value->>0 AS host, value->>1 AS slot, value->>2 AS base FROM json_each(:main_requests)
), stage_requests AS (
 SELECT value->>0 AS key, value->>1 AS shared FROM json_each(:stage_requests)
), raw_gaps(host,subject_key,subject_shared,reason_key,origin) AS (
 SELECT m.mount_ordinal,k.base+g.subject,NULL,k.base+g.reason,r.origin
 FROM main_requests k
 JOIN temp.selected_resolution_mounts m ON m.mount_ordinal=k.host
 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=m.mount_ordinal
 JOIN main.resolution_gaps g ON g.blob_id=m.blob_id AND g.covers=7 AND g.subject=k.slot
 JOIN main.resolution_gap_reasons r ON r.blob_id=g.blob_id AND r.reason=g.reason
 UNION ALL
 SELECT g.host_ordinal,g.subject_key,g.subject_shared,g.reason_key,g.origin
 FROM stage_requests k
 CROSS JOIN temp.selected_resolution_stage_gaps g
   ON g.subject_key IS k.key AND g.subject_shared IS k.shared AND g.covers=7
 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=g.host_ordinal
), effective AS (
 SELECT g.* FROM raw_gaps g
 WHERE {effective_gap_remains}
), declared(host,subject_key,subject_shared) AS (
 SELECT m.mount_ordinal,k.base+f.slot,NULL FROM main_requests k
 JOIN temp.selected_resolution_mounts m ON m.mount_ordinal=k.host
 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=m.mount_ordinal
 JOIN main.resolution_type_frontiers f ON f.blob_id=m.blob_id AND f.slot=k.slot
 UNION
 SELECT f.host_ordinal,f.slot_key,f.slot_shared FROM stage_requests k
 CROSS JOIN temp.selected_resolution_stage_type_frontiers f
   ON f.slot_key IS k.key AND f.slot_shared IS k.shared
 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=f.host_ordinal
 UNION
 SELECT host,subject_key,subject_shared FROM effective
)
SELECT d.host,d.subject_key,d.subject_shared,
 json_group_array(DISTINCT e.reason_key) FILTER(WHERE e.reason_key IS NOT NULL)
FROM declared d LEFT JOIN effective e
 ON e.host=d.host AND e.subject_key IS d.subject_key AND e.subject_shared IS d.subject_shared
GROUP BY d.host,d.subject_key,d.subject_shared
ORDER BY d.host,d.subject_key,d.subject_shared
"#,
                effective_gap_remains = effective_gap_remains_sql()
            )
        };
        #[cfg(test)]
        crate::analyzer::store::resolution_selection::note_selected_static_sql_capacity(
            15,
            sql.capacity(),
        );
        sql
    })
}

pub(in crate::analyzer::store) fn visit_frontier_completion(
    selection: &SelectedResolutionMountInventory<'_>,
    main_requests: &str,
    frontiers: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedTypeFrontierCompletion>,
) -> Result<TypedFactReadOutcome> {
    let mut evidence = PolledCompletionAccumulator::new(cancellation);
    let mut requested = Vec::with_capacity(frontiers.as_slice().len());
    for &frontier in frontiers.as_slice() {
        if cancellation.is_cancelled() {
            return Ok(TypedFactReadOutcome::cancelled(
                evidence.finish_semantic().0,
            ));
        }
        let (key, shared) = lexical::semantic_cells(frontier);
        requested.push(json!([key, shared]));
    }
    let requested = serde_json::to_string(&requested).expect("frontier request JSON");
    let answer =
        with_resolution_read_progress_handler(selection.connection(), cancellation, |connection| {
            let mut statement = connection.prepare_cached(frontier_completion_sql())?;
            let mut rows = statement.query(named_params! {
                ":main_requests": main_requests,
                ":stage_requests": requested,
                ":qualified_origin": gap_origin_code(LoweringGapOrigin::QualifiedReference),
                ":local_base": codec::encode_semantic(SemanticId::local(0, 0)),
            })?;
            let mut answer = Vec::new();
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let host: u32 = row.get(0)?;
                let frontier = decode_pair(row.get(1)?, row.get(2)?);
                let reasons: Vec<i64> =
                    serde_json::from_str(&row.get::<_, String>(3)?).expect("frontier reasons JSON");
                let completion = if reasons.is_empty() {
                    ResolutionCompletion::Complete
                } else {
                    ResolutionCompletion::incomplete(reasons.into_iter().map(|key| {
                        ResolutionIncompleteReason::UnsupportedSemantic(codec::decode_semantic(key))
                    }))
                };
                evidence.include(&completion);
                answer.push(SelectedTypeFrontierCompletion::new(
                    BindingFragmentId::at_ordinal(host),
                    frontier,
                    completion,
                ));
            }
            Ok(Some(answer))
        });
    let answer = match answer {
        Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => None,
        result => result?,
    };
    let Some(answer) = answer else {
        return Ok(TypedFactReadOutcome::cancelled(
            evidence.finish_semantic().0,
        ));
    };
    for page in answer.chunks(visitor.maximum_rows()) {
        if cancellation.is_cancelled() {
            return Ok(TypedFactReadOutcome::cancelled(
                evidence.finish_semantic().0,
            ));
        }
        let keep_going = visitor.visit_page(page)?;
        if cancellation.is_cancelled() {
            return Ok(TypedFactReadOutcome::cancelled(
                evidence.finish_semantic().0,
            ));
        }
        if !keep_going {
            return Ok(TypedFactReadOutcome::stopped(evidence.finish_semantic().0));
        }
    }
    Ok(if cancellation.is_cancelled() {
        TypedFactReadOutcome::cancelled(evidence.finish_semantic().0)
    } else {
        TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
    })
}

fn decode_pair(key: Option<i64>, shared: Option<i64>) -> SemanticId {
    match (key, shared) {
        (Some(key), None) => codec::decode_semantic(key),
        (None, Some(shared)) => codec::decode_semantic(-shared),
        pair => panic!("frontier semantic has invalid exclusive pair: {pair:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::store::resolution_selection::tests::SelectionFixture;

    #[test]
    fn raw_exclusion_keeps_closed_identity_while_effective_gaps_remove_it() {
        let fixture = SelectionFixture::new(2);
        let selection = fixture.open_ready(&[]);
        selection.with_owned_temp_write(|connection| {
            connection.execute("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(0,?1,?2)", rusqlite::params![[21u8;32].as_slice(),[22u8;32].as_slice()])?;
            let producer=connection.last_insert_rowid();
            connection.execute("INSERT INTO temp.selected_resolution_stage_closed_reasons(producer_id,semantic_key) VALUES(?1,12)",[producer])?;
            connection.execute("INSERT INTO temp.selected_resolution_stage_qualified_routes(host_ordinal,producer_id,sequence,reference_key,qualifier_slot_key,lookup_key,source_lookup_key,projection_output_slot_key,coarse_gap_reason_key,precedence_ordinal,namespace,projection_kind) VALUES(0,?1,0,1,2,3,4,5,11,0,0,0)",[producer])?;
            Ok(())
        }).unwrap();
        let origin = gap_origin_code(LoweringGapOrigin::QualifiedReference);
        let requested = json!([
            [0, 11, origin],
            [1, 11, origin],
            [0, 12, origin],
            [1, 13, origin],
        ])
        .to_string();
        let read = |predicate: &str| {
            let sql = format!(
                "WITH raw(host,reason_key,origin) AS (SELECT value->>0,value->>1,value->>2 FROM json_each(:requested)) SELECT g.host,g.reason_key FROM raw g WHERE {predicate} ORDER BY g.host,g.reason_key"
            );
            selection
                .connection()
                .prepare(&sql)
                .unwrap()
                .query_map(
                    named_params! {
                        ":requested": requested,
                        ":qualified_origin": origin,
                        ":local_base": codec::encode_semantic(SemanticId::local(0,0)),
                    },
                    |row| Ok((row.get::<_, u32>(0)?, row.get::<_, i64>(1)?)),
                )
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        assert_eq!(
            read(QUALIFIED_GAP_REMAINS_SQL),
            vec![(0, 12), (1, 11), (1, 13)]
        );
        assert_eq!(read(effective_gap_remains_sql()), vec![(1, 11), (1, 13)]);
    }
}
