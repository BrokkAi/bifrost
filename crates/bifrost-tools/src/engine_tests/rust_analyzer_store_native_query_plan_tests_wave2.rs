#[cfg(test)]
mod rust_departing_wave2_root_tests {
    use crate::engine_tests::rust_analyzer_store_resolution_operation_tests::rust_departing_root_tests::*;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_test_macros::hardwon;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::tests::native_query_plan_tests::shared_support::registry as registry;
    fn unindexed_main_tables(
        conn: &rusqlite::Connection,
        sql: &str,
        tables: &std::collections::HashMap<i64, String>,
    ) -> Vec<String> {
        let mut bytecode = conn.prepare(&format!("EXPLAIN {sql}")).unwrap();
        let args = vec![rusqlite::types::Value::Null; bytecode.parameter_count()];
        let ops: Vec<(i64, String, i64, i64, i64)> = bytecode
            .query_map(rusqlite::params_from_iter(args), |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        let mut cursors = std::collections::HashMap::new();
        let mut scans = Vec::new();
        for (address, op, cursor, root, database) in ops {
            // Trigger subprograms and reopened cursors reuse cursor numbers. A
            // later main-table OpenRead must not relabel an earlier TEMP scan.
            if address == 0 {
                cursors.clear();
            }
            match op.as_str() {
                "OpenRead" | "ReopenIdx" => {
                    cursors.remove(&cursor);
                    if database == 0
                        && let Some(table) = tables.get(&root)
                    {
                        cursors.insert(cursor, table);
                    }
                }
                "OpenDup" => {
                    if let Some(table) = cursors.get(&root).copied() {
                        cursors.insert(cursor, table);
                    } else {
                        cursors.remove(&cursor);
                    }
                }
                "OpenWrite" | "OpenEphemeral" | "OpenAutoindex" | "OpenPseudo" | "SorterOpen"
                | "VOpen" | "Close" => {
                    cursors.remove(&cursor);
                }
                "Rewind" => {
                    if let Some(table) = cursors.get(&cursor) {
                        scans.push((*table).clone());
                    }
                }
                _ => {}
            }
        }
        scans
    }

    #[test]
    #[hardwon("#5638+#5658: unbounded views and macro-hidden scheduler SQL escaped plan coverage")]
    fn native_query_plan_registry() {
        let fixture = RustRootResolutionOperationFixture::new();
        let cancellation = CancellationToken::new();
        let operation = fixture.open_ready(&cancellation);
        let conn = operation.ready.inventory.connection();
        let registry = registry();
        for sql in [
            brokk_bifrost_analysis::analyzer::store::resolution_operation::imports::POINT,
            brokk_bifrost_analysis::analyzer::store::resolution_operation::imports::ENUMERATE,
            brokk_bifrost_analysis::analyzer::store::resolution_operation::imports::AT_SITE,
            brokk_bifrost_analysis::analyzer::store::resolution_operation::imports::TOKEN_SITE,
        ] {
            assert!(
                registry
                    .statements
                    .iter()
                    .any(|(_, registered)| registered == sql),
                "shared import statement missing from the plan registry: {sql}"
            );
        }
        assert!(
            registry.statements.iter().any(|(_, sql)| {
                sql == brokk_bifrost_analysis::analyzer::store::unit_schedule::ORDER_SQL
            }),
            "the component-wave ordering query must be planned"
        );
        brokk_bifrost_analysis::analyzer::store::go_unit_summaries::register_go_summary_sql_functions(conn).unwrap();
        // The reader does not register the writer-only seal function, but the
        // source-fact seal UPDATE fires triggers that call it.
        brokk_bifrost_core::cache_db::register_seal_validation(conn).unwrap();
        for schema in &registry.schemas {
            conn.execute_batch(schema).unwrap();
        }
        let (_, package_members_sql) = registry
            .statements
            .iter()
            .find(|(name, _)| name.ends_with("::JVM_ACTIVE_PACKAGE_MEMBERS_SQL"))
            .expect("active package-member SQL is registered");
        assert!(
            package_members_sql.contains("member INDEXED BY jvm_external_owner_members_by_name")
        );
        assert!(
            package_members_sql
                .contains("CROSS JOIN jvm_external_owners owner USING(provider_id,owner_fqn)")
        );
        assert!(package_members_sql.contains("CROSS JOIN json_each(?1) AS provider"));
        // The selected inventory is read-only. Recreate these exact current
        // schema objects in a writable fixture so the populated plan is real.
        let plan_conn = rusqlite::Connection::open_in_memory().unwrap();
        for name in [
            "jvm_external_owners",
            "jvm_external_owner_members",
            "jvm_external_owner_members_by_name",
        ] {
            let ddl: String = conn
                .query_row(
                    "SELECT sql FROM main.sqlite_schema WHERE name=?1",
                    [name],
                    |row| row.get(0),
                )
                .unwrap();
            plan_conn.execute_batch(&ddl).unwrap();
        }
        for provider in ["plan-provider", "other-provider"] {
            for owner in ["plan.package", "plan.other", "plan.third"] {
                plan_conn.execute(
                    "INSERT INTO jvm_external_owners(provider_id,owner_fqn,callables_complete,values_complete,types_complete,supertypes_complete) VALUES(?1,?2,1,1,0,0)",
                    rusqlite::params![provider, owner],
                ).unwrap();
                for ordinal in 0..32 {
                    let name = if ordinal == 0 { "listOf" } else { "other" };
                    plan_conn.execute(
                        "INSERT INTO jvm_external_owner_members(provider_id,owner_fqn,ordinal,member_name,member_kind,visibility,is_static,signature_present,callable_family_complete,parameters_jsonb) VALUES(?1,?2,?3,?4,'function','public',1,1,1,jsonb('[]'))",
                        rusqlite::params![provider, owner, ordinal, name],
                    ).unwrap();
                }
            }
        }
        let params = rusqlite::params!["[\"plan-provider\"]", "[[\"plan.package\",\"listOf\"]]"];
        let matched: i64 = plan_conn
            .query_row(
                &format!("SELECT count(*) FROM ({package_members_sql})"),
                params,
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(matched, 1, "populated package-member plan fixture");
        let plan = plan_conn
            .prepare(&format!("EXPLAIN QUERY PLAN {package_members_sql}"))
            .unwrap()
            .query_map(params, |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let position = |prefix: &str| {
            plan.iter()
                .position(|detail| detail.starts_with(prefix))
                .unwrap_or_else(|| panic!("missing {prefix} in package-member plan: {plan:?}"))
        };
        let demand = position("SCAN demand VIRTUAL TABLE");
        let provider = position("SCAN provider VIRTUAL TABLE");
        let member = position(
            "SEARCH member USING INDEX jvm_external_owner_members_by_name (provider_id=? AND owner_fqn=? AND member_name=?)",
        );
        let owner = position("SEARCH owner USING PRIMARY KEY");
        assert!(
            demand < provider && provider < member && member < owner,
            "package-member loop order: {plan:?}"
        );
        let (_, package_owners_sql) = registry
            .statements
            .iter()
            .find(|(name, _)| name.ends_with("::JVM_ACTIVE_PACKAGE_OWNERS_SQL"))
            .expect("active package-owner SQL is registered");
        let owner_params =
            rusqlite::params!["[\"plan-provider\"]", "[\"plan.package\",\"plan.other\"]"];
        let matched: i64 = plan_conn
            .query_row(
                &format!("SELECT count(*) FROM ({package_owners_sql})"),
                owner_params,
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(matched, 2, "populated package-owner plan fixture");
        let owner_plan = plan_conn
            .prepare(&format!("EXPLAIN QUERY PLAN {package_owners_sql}"))
            .unwrap()
            .query_map(owner_params, |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(
            owner_plan.iter().any(|detail| detail
                == "SEARCH jvm_external_owners USING PRIMARY KEY (provider_id=? AND owner_fqn=?)"),
            "package-owner read must seek the full primary key: {owner_plan:?}"
        );
        assert!(
            owner_plan
                .iter()
                .filter(|detail| detail.contains("json_each VIRTUAL TABLE"))
                .count()
                == 2,
            "package-owner read must use both bounded input lists: {owner_plan:?}"
        );
        if let Some(path) = std::env::var_os("BIFROST_NATIVE_SQL_REPORT") {
            std::fs::write(
                path,
                serde_json::to_vec_pretty(&registry.statements).unwrap(),
            )
            .unwrap();
        }
        let views: Vec<String> = conn
        .prepare("SELECT name FROM main.sqlite_schema WHERE type='view' UNION SELECT name FROM temp.sqlite_schema WHERE type='view'")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
        let tables: std::collections::HashMap<i64, String> = conn
            .prepare(
                "SELECT rootpage, name FROM main.sqlite_schema WHERE type='table' AND rootpage>0",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(
            unindexed_main_tables(
                conn,
                "SELECT blob_oid FROM blobs NOT INDEXED WHERE blob_oid = ?1",
                &tables,
            )
            .iter()
            .any(|table| table == "blobs"),
            "the injected unindexed blob read escaped the gate"
        );
        let injected: Vec<String> = conn
            .prepare(
                "EXPLAIN QUERY PLAN SELECT blob.id FROM blobs AS blob
         LEFT JOIN main.source_occurrences AS occurrence ON occurrence.blob_id=blob.id
         WHERE blob.id=?1",
            )
            .unwrap()
            .query_map([1], |row| row.get(3))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(
            injected.iter().any(
                |detail| detail.strip_prefix("MATERIALIZE ").is_some_and(|name| views
                    .iter()
                    .any(|view| view == name.strip_prefix("main.").unwrap_or(name)))
            ),
            "the injected unbounded view join escaped the gate: {injected:#?}"
        );
        let mut failures = Vec::new();
        let mut unavailable = Vec::new();
        let mut pending = std::collections::VecDeque::from(registry.statements.clone());
        let mut planned = 0;
        while let Some((name, sql)) = pending.pop_front() {
            let mut statement = match conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")) {
                Ok(statement) => statement,
                Err(rusqlite::Error::MultipleStatement) => {
                    use rusqlite::fallible_iterator::FallibleIterator;
                    let mut batch = rusqlite::Batch::new(conn, &sql);
                    let mut statements = Vec::new();
                    while let Some(statement) = batch.next().unwrap() {
                        // execute_batch has no parameter bindings. With no binds,
                        // SQLite's expanded SQL is the original statement text.
                        assert_eq!(statement.parameter_count(), 0, "bound SQL batch: {name}");
                        statements.push(statement.expanded_sql().unwrap());
                    }
                    assert!(!statements.is_empty(), "empty SQL batch: {name}");
                    for (ordinal, sql) in statements.into_iter().enumerate().rev() {
                        pending.push_front((format!("{name}[{}]", ordinal + 1), sql));
                    }
                    continue;
                }
                Err(error) => {
                    let message = error.to_string();
                    let table = message
                        .strip_prefix("no such table: ")
                        .map(|table| table.strip_prefix("temp.").unwrap_or(table));
                    if table.is_some_and(|table| {
                        table.starts_with("selected_")
                            || matches!(
                                table,
                                "go_unit_summary_units"
                                    | "rust_unit_summary_units"
                                    | "unit_summary_work"
                            )
                    }) {
                        unavailable.push(format!("{name}: request TEMP family not initialized by this selected operation: {error}"));
                    } else {
                        failures.push(format!("{name}: cannot plan production SQL: {error}"));
                    }
                    continue;
                }
            };
            let params = vec![rusqlite::types::Value::Null; statement.parameter_count()];
            let plan: Vec<String> = statement
                .query_map(rusqlite::params_from_iter(params), |row| row.get(3))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            planned += 1;
            // Bytecode identifies base-table cursors even when EQP renders an SQL
            // alias. CTEs, JSON virtual tables and request TEMP tables have no main
            // schema root page and cannot be mistaken for workspace table scans.
            let compact: String = sql.chars().filter(|ch| !ch.is_ascii_whitespace()).collect();
            if [
                "blob_id=?",
                "blob_oid=?",
                "mount_ordinal=?",
                "blob_idIN(?",
                "mount_ordinalIN(?",
            ]
            .iter()
            .any(|binding| compact.contains(binding))
            {
                for table in unindexed_main_tables(conn, &sql, &tables) {
                    failures.push(format!(
                        "{name}: unindexed main table scan {table}: {plan:#?}"
                    ));
                }
            }
            for detail in &plan {
                if let Some(materialized) = detail.strip_prefix("MATERIALIZE ") {
                    let view = materialized
                        .strip_prefix("main.")
                        .or_else(|| materialized.strip_prefix("temp."))
                        .unwrap_or(materialized);
                    // A scoped CTE may deliberately reuse a view's name.
                    if views.iter().any(|name| name == view)
                        && !sql.contains(&format!("{view} AS MATERIALIZED"))
                    {
                        failures.push(format!("{name}: {plan:#?}"));
                    }
                }
            }
        }
        eprintln!(
            "registered={} planned={planned} dynamic={:#?} unavailable={unavailable:#?}",
            registry.statements.len(),
            registry.dynamic
        );
        assert!(
            failures.is_empty(),
            "native SQL plan regressions: {failures:#?}"
        );
    }
}
