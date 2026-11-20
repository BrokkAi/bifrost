use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
use brokk_bifrost_core::analyzer::config::AnalyzerConfig;
use brokk_bifrost_core::cache_db::sql_profile::{ListenerEvent, attach_listener};
use brokk_bifrost_test_macros::hardwon;
use std::sync::{Arc, Mutex};

#[test]
#[hardwon("#13416: unrelated external commits changed repeated tool requests' reader SQL work")]
#[expect(
    clippy::disallowed_methods,
    reason = "#12820: non-answer (SQL listener setup on an ordinary reader); must not produce answers"
)]
fn workspace_selection_tool_sql_is_deterministic_across_unrelated_commit() {
    let project = crate::inline_project::InlineTestProject::new()
        .with_git()
        .file(
            "Cargo.toml",
            "[package]\nname='selection'\nversion='0.1.0'\nedition='2021'\n",
        )
        .file(
            "src/lib.rs",
            "pub fn target() {}\npub fn caller() { target(); }\n",
        )
        .build();
    let workspace =
        WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
            .unwrap();
    let store = workspace.store().unwrap();
    let writer = brokk_bifrost_core::cache_db::open_unified_connection(
        &workspace.persisted_store_path().unwrap(),
    )
    .unwrap();
    writer
        .execute_batch("CREATE TABLE unrelated_selection_test(value INTEGER);")
        .unwrap();
    let request = || {
        crate::searchtools::search_symbols(
            workspace.analyzer(),
            crate::searchtools::SearchSymbolsParams {
                patterns: vec!["target".into()],
                include_tests: true,
                limit: 10,
            },
        )
    };
    request(); // Populate request-independent content caches and the reader pool.
    let sql = Arc::new(Mutex::new(Vec::<String>::new()));
    let captured = Arc::clone(&sql);
    let listener = {
        let reader = store.read_conn().unwrap();
        attach_listener(
            &reader,
            Arc::new(move |event| {
                if let ListenerEvent::Statement { sql: Some(sql), .. } = event {
                    captured.lock().unwrap().push(sql.to_owned());
                }
            }),
        )
    };
    let first = request();
    let first_sql = std::mem::take(&mut *sql.lock().unwrap());
    assert!(
        first_sql.iter().any(|sql| {
            sql.contains("workspace_heads") || sql.contains("workspace_selection_epochs")
        }),
        "request must exercise ordinary selection loading: {first_sql:?}"
    );
    writer
        .execute("INSERT INTO unrelated_selection_test VALUES(1)", [])
        .unwrap();
    let second = request();
    let second_sql = std::mem::take(&mut *sql.lock().unwrap());
    drop(listener);
    assert_eq!(
        serde_json::to_value(first).unwrap(),
        serde_json::to_value(second).unwrap()
    );
    assert_eq!(
        first_sql, second_sql,
        "identical request, identical reader SQL after an unrelated commit"
    );
}

/// Reproducible operator comparison: both legs use the same binary and a fresh
/// private store, differing only in these eighteen invalidation triggers.
#[test]
#[ignore = "operator measurement: needs BIFROST_13416_CORPUS and an empty working directory"]
#[expect(
    clippy::disallowed_methods,
    reason = "#12820: non-answer (measurement-only reader for statement counts); must not produce answers"
)]
fn measure_workspace_selection_trigger_write_cost() {
    use brokk_bifrost_core::analyzer::model::Language;
    use brokk_bifrost_core::analyzer::project::{Project, TestProject};
    use std::sync::atomic::{AtomicU64, Ordering};

    let root =
        std::path::PathBuf::from(std::env::var_os("BIFROST_13416_CORPUS").expect("corpus path"))
            .canonicalize()
            .unwrap();
    let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
    let context = brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::ephemeral_store_context(
        project.as_ref(),
    )
    .unwrap();
    let without = std::env::var_os("BIFROST_13416_WITHOUT_TRIGGERS").is_some();
    let counters = Arc::new([AtomicU64::new(0), AtomicU64::new(0)]);
    let captured = Arc::clone(&counters);
    let listener = {
        let conn = context.store.conn.lock().unwrap();
        let triggers: Vec<String> = conn.prepare("SELECT name FROM sqlite_schema WHERE type='trigger' AND name GLOB 'workspace_selection_epochs_*'").unwrap()
            .query_map([], |row| row.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap();
        assert_eq!(triggers.len(), 18);
        if without {
            for trigger in triggers {
                conn.execute_batch(&format!("DROP TRIGGER {trigger};"))
                    .unwrap();
            }
        }
        attach_listener(
            &conn,
            Arc::new(move |event| {
                if let ListenerEvent::Profile { statement, .. } = event {
                    captured[0].fetch_add(1, Ordering::Relaxed);
                    // SAFETY: the PROFILE listener runs synchronously while SQLite
                    // owns this live statement. Reset only our VM-step instrument.
                    let steps = unsafe {
                        rusqlite::ffi::sqlite3_stmt_status(
                            statement as *mut rusqlite::ffi::sqlite3_stmt,
                            rusqlite::ffi::SQLITE_STMTSTATUS_VM_STEP,
                            1,
                        )
                    };
                    captured[1].fetch_add(
                        u64::try_from(steps).expect("nonnegative VM steps"),
                        Ordering::Relaxed,
                    );
                }
            }),
        )
    };
    let sql_before = brokk_bifrost_core::cache_db::sql_profile::totals_with_rows();
    let started = std::time::Instant::now();
    let workspace = WorkspaceAnalyzer::build_with_store_context_for_test(
        project,
        AnalyzerConfig::default(),
        context,
    )
    .unwrap();
    let elapsed = started.elapsed();
    let sql_after = brokk_bifrost_core::cache_db::sql_profile::totals_with_rows();
    let global_cost = sql_before
        .zip(sql_after)
        .map(|(before, after)| (after.0 - before.0, after.1 - before.1));
    let counts = counters
        .each_ref()
        .map(|counter| counter.load(Ordering::Relaxed));
    drop(listener);
    let conn = workspace.store().unwrap().read_conn().unwrap();
    let units: i64 = conn
        .query_row(
            "SELECT count(*) FROM resolution_unit_summary_versions WHERE lang='rust'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let dependencies: i64 = conn
        .query_row(
            "SELECT count(*) FROM resolution_unit_summary_dependencies",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let mut digest = brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(
        b"workspace-selection-trigger-measurement:v1",
    );
    let mut statement = conn.prepare("SELECT hex(unit_key),hex(output_digest) FROM resolution_unit_summaries WHERE lang='rust' ORDER BY unit_key,output_digest").unwrap();
    for row in statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .unwrap()
    {
        let (key, output) = row.unwrap();
        digest.field("unit", key.as_bytes());
        digest.field("output", output.as_bytes());
    }
    let digest = brokk_bifrost_core::analyzer::canonical_hash::lower_hex_string(&digest.finish());
    eprintln!(
        "SELECTION_GLOBAL_COST statements_and_rows={global_cost:?} publication_digest={digest}"
    );
    eprintln!(
        "SELECTION_WRITE_COST without_triggers={without} statements={} writer_vm_steps={} elapsed_seconds={} units={units} dependencies={dependencies}",
        counts[0],
        counts[1],
        elapsed.as_secs_f64()
    );
    brokk_bifrost_core::cache_db::sql_profile::flush();
}
