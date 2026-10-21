#[cfg(test)]
mod rust_indirect_table_tests {
    use rusqlite::params;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_reverse_rows::OTHER_TARGET_WORKSPACE_DEPENDENCY_SQL;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::explain_pin;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::prepare_pin_context;
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
    use brokk_bifrost_test_macros::hardwon;
    use rusqlite::types::Value;

    #[test]
    #[hardwon("4aff4982486e: qualified exported macro paths lost their crate-root route")]
    fn qualified_workspace_macro_path_publishes_a_crate_root_reference() {
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[workspace]\nmembers=['api','client']\nresolver='2'\n",
            )
            .file(
                "api/Cargo.toml",
                "[package]\nname='api'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file(
                "client/Cargo.toml",
                "[package]\nname='client'\nversion='0.1.0'\nedition='2021'\n[dependencies]\napi={path='../api'}\n",
            )
            .file(
                "api/src/lib.rs",
                "#[macro_export]\nmacro_rules! exported { () => {} }\n",
            )
            .file("client/src/lib.rs", "api::exported!();\n")
            .build();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.conn.lock().unwrap();
        let api_key: Vec<u8> = conn
            .query_row(
                "SELECT crate_key FROM rust_crate_topologies
                 WHERE crate_name='api' AND target_kind='lib'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let routes = conn
            .prepare(
                "SELECT route.target_module_path, route.target_name
                 FROM rust_crate_root_references AS route
                 JOIN rust_crate_topologies AS owner USING(topology_id)
                 WHERE owner.crate_name='client' AND owner.target_kind='lib'
                   AND route.target_crate_key=?1
                   AND route.target_module_path='crate' AND route.target_name='exported'
                   AND route.blob_id=(
                     SELECT source.blob_id FROM rust_crate_container_sources AS source
                     WHERE source.topology_id=route.topology_id
                       AND source.rel_path='client/src/lib.rs'
                   )",
            )
            .unwrap()
            .query_map([api_key], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(routes, [("crate".into(), "exported".into())]);
    }

    #[test]
    fn other_target_workspace_dependency_uses_live_summary_aliases() {
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[workspace]\nmembers=['api','app']\nresolver='2'\n",
            )
            .file(
                "api/Cargo.toml",
                "[package]\nname='api'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file("api/src/lib.rs", "pub fn target() {}\n")
            .file(
                "app/Cargo.toml",
                "[package]\nname='app'\nversion='0.1.0'\nedition='2021'\n[dev-dependencies]\nrenamed_api={package='api',path='../api'}\n",
            )
            .file("app/src/lib.rs", "pub fn app() {}\n")
            .file("app/tests/integration.rs", "#[test] fn test() {}\n")
            .build();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.conn.lock().unwrap();
        brokk_bifrost_analysis::analyzer::store::ensure_revisioned_workspace_views(&conn).unwrap();
        conn.execute("DELETE FROM selected_workspace_revisions", [])
            .unwrap();
        conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'", []).unwrap();
        brokk_bifrost_analysis::analyzer::store::fill_selected_rust_units(&conn).unwrap();
        prepare_pin_context(&conn);
        conn.execute(
            "INSERT INTO temp.selected_resolution_mounts(
                mount_ordinal,blob_id,storage_language,persisted_relative_path)
             SELECT 0,blob_id,'rust','app/src/lib.rs'
             FROM selected_rust_crate_containers WHERE rel_path='app/src/lib.rs' LIMIT 1",
            [],
        )
        .unwrap();
        conn.execute_batch(brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_context::SELECTED_MODULE_PLACEMENTS_FILL_SQL).unwrap();

        let legacy_sql = r#"
SELECT
 EXISTS(
   SELECT 1
   FROM selected_rust_container_placements AS placement
   JOIN rust_crate_dependencies AS dependency USING(topology_id)
   WHERE placement.mount_ordinal=?1 AND dependency.extern_name=?2
 ),
 EXISTS(
   SELECT 1
   FROM selected_rust_container_placements AS placement
   JOIN rust_crate_versions AS current_version
     ON current_version.topology_id=placement.topology_id
    AND current_version.valid_until IS NULL
    AND current_version.manifest_file_version_id IS NOT NULL
   JOIN selected_rust_crates AS sibling
     ON sibling.topology_id<>current_version.topology_id
   JOIN rust_crate_versions AS sibling_version
     ON sibling_version.topology_id=sibling.topology_id
    AND sibling_version.workspace_id=current_version.workspace_id
    AND sibling_version.lang=current_version.lang
    AND sibling_version.generation=current_version.generation
    AND sibling_version.manifest_file_version_id=current_version.manifest_file_version_id
    AND sibling_version.valid_until IS NULL
   JOIN rust_crate_dependencies AS sibling_dependency
     ON sibling_dependency.topology_id=sibling_version.topology_id
    AND sibling_dependency.extern_name=?2
    AND sibling_dependency.boundary='workspace'
   WHERE placement.mount_ordinal=?1
 )
"#;
        let legacy: (bool, bool) = conn
            .query_row(legacy_sql, params![0, "renamed_api"], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        let summary: (bool, bool) = conn
            .query_row(
                OTHER_TARGET_WORKSPACE_DEPENDENCY_SQL,
                params![0, "renamed_api"],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(summary, legacy, "cross-target dependency alias");
        assert!(
            summary.1,
            "the sibling target sees the dev dependency: {summary:?}"
        );

        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            let pin = brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::PinnedQuery {
                name: "other_target_workspace_dependency".to_owned(),
                sql: OTHER_TARGET_WORKSPACE_DEPENDENCY_SQL.to_owned(),
                params: vec![Value::Integer(0), Value::Text("renamed_api".into())],
            };
            let plan = explain_pin(&conn, &pin);
            assert!(
                plan.iter().any(|row| row.contains(
                    "SEARCH resolution_unit_summary_dependency_names USING COVERING INDEX"
                ) && row.contains("name=?")
                    && row.contains("summary_id=?")),
                "{state:?}: dependency aliases must seek both name and owner: {plan:?}"
            );
            assert!(
                plan.iter()
                    .any(|row| row.contains("rust_resolution_unit_summary_versions_manifest")),
                "{state:?}: sibling targets must seek their manifest index: {plan:?}"
            );
            assert!(
                !plan.iter().any(|row| row.contains("AUTOMATIC")),
                "{state:?}: {plan:?}"
            );
        }
    }
}
