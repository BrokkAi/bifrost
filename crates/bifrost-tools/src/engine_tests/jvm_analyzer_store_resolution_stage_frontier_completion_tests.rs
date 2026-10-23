#[cfg(test)]
mod tests {
    use brokk_bifrost_analysis::analyzer::store::resolution_stage::codec;
    use brokk_bifrost_analysis::native_resolution_test_support::SemanticId;

    use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweringGapOrigin;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::frontier_completion::QUALIFIED_GAP_REMAINS_SQL;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::frontier_completion::effective_gap_remains_sql;

    use brokk_bifrost_analysis::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code;

    #[test]
    fn raw_exclusion_keeps_closed_identity_while_effective_gaps_remove_it() {
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(2);
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

    use rusqlite::named_params;
    use serde_json::json;
}
