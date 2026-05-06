//! End-to-end tests for the SQLite-backed analyzer persistence layer.

use brokk_analyzer::analyzer::persistence::{
    AnalyzerStorage, PersistenceError, SymbolQueryMode, default_db_path,
};
use brokk_analyzer::{
    AnalyzerConfig, IAnalyzer, Language, PythonAnalyzer, TestProject, WorkspaceAnalyzer,
};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tempfile::TempDir;

fn write_file(root: &Path, rel: &str, body: &str) {
    let abs = root.join(rel);
    if let Some(parent) = abs.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&abs, body).unwrap();
}

fn fresh_python_workspace() -> (TempDir, Arc<TestProject>) {
    let tmp = tempfile::tempdir().unwrap();
    write_file(
        tmp.path(),
        "alpha.py",
        "def hello():\n    return 1\n\nclass Greeter:\n    def greet(self):\n        return 'hi'\n",
    );
    write_file(tmp.path(), "beta.py", "def world():\n    return 2\n");
    let canon = fs::canonicalize(tmp.path()).unwrap();
    let project = Arc::new(TestProject::new(canon, Language::Python));
    (tmp, project)
}

fn collect_fq_names<A: IAnalyzer>(analyzer: &A) -> BTreeSet<String> {
    analyzer.all_declarations().map(|cu| cu.fq_name()).collect()
}

fn contains_short(names: &BTreeSet<String>, short: &str) -> bool {
    names
        .iter()
        .any(|n| n == short || n.ends_with(&format!(".{}", short)))
}

#[test]
fn storage_opens_creates_parent_dir_and_runs_migrations() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("nested").join("subdir").join("analyzer.db");

    let storage = AnalyzerStorage::open(&path).expect("open should succeed");

    assert!(path.exists(), "DB file should be created");
    assert_eq!(storage.path(), path.as_path());
    // No rows for any language yet.
    assert_eq!(storage.row_count(Language::Python).unwrap(), 0);
}

#[test]
fn storage_rejects_corrupt_database() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("corrupt.db");
    // Write a file that is non-empty and not a valid SQLite header.
    fs::write(&path, b"this is definitely not sqlite").unwrap();

    let result = AnalyzerStorage::open(&path);
    assert!(
        result.is_err(),
        "corrupt file should not open as analyzer DB"
    );
    match result {
        Err(PersistenceError::Sqlite(_)) | Err(PersistenceError::IntegrityCheck(_)) => {}
        Err(other) => panic!("unexpected error variant: {other:?}"),
        Ok(_) => unreachable!(),
    }
}

#[test]
fn cold_then_warm_python_identical_results() {
    let (_tmp_workspace, project) = fresh_python_workspace();
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("analyzer.db");

    // Cold start: no baseline, full analysis.
    let cold = {
        let storage = Arc::new(AnalyzerStorage::open(&db_path).unwrap());
        let analyzer = PythonAnalyzer::new_with_config_and_storage(
            project.clone(),
            AnalyzerConfig::default(),
            Arc::clone(&storage),
        );
        let names = collect_fq_names(&analyzer);
        let row_count = storage.row_count(Language::Python).unwrap();
        (names, row_count)
    };
    assert_eq!(cold.1, 2, "cold start should persist one row per file");
    assert!(contains_short(&cold.0, "hello"), "names: {:?}", cold.0);
    assert!(contains_short(&cold.0, "world"), "names: {:?}", cold.0);

    // Warm start: a fresh analyzer reusing the same DB.
    let warm = {
        let storage = Arc::new(AnalyzerStorage::open(&db_path).unwrap());
        let analyzer = PythonAnalyzer::new_with_config_and_storage(
            project.clone(),
            AnalyzerConfig::default(),
            storage,
        );
        collect_fq_names(&analyzer)
    };

    assert_eq!(
        cold.0, warm,
        "warm-start declarations should match cold-start"
    );
}

#[test]
fn file_modification_triggers_partial_reanalysis() {
    let (tmp_workspace, project) = fresh_python_workspace();
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("analyzer.db");

    // Cold start.
    {
        let storage = Arc::new(AnalyzerStorage::open(&db_path).unwrap());
        let _ = PythonAnalyzer::new_with_config_and_storage(
            project.clone(),
            AnalyzerConfig::default(),
            storage,
        );
    }

    // Mutate alpha.py: replace `hello` with `goodbye` and force mtime
    // forward so the staleness key changes (some filesystems only have
    // second-level mtime resolution).
    let alpha_path = tmp_workspace.path().join("alpha.py");
    fs::write(&alpha_path, "def goodbye():\n    return 99\n").unwrap();
    let one_min_future = SystemTime::now() + Duration::from_secs(60);
    let ft = filetime::FileTime::from_system_time(one_min_future);
    filetime::set_file_mtime(&alpha_path, ft).unwrap();

    // Warm start.
    let storage = Arc::new(AnalyzerStorage::open(&db_path).unwrap());
    let analyzer = PythonAnalyzer::new_with_config_and_storage(
        project.clone(),
        AnalyzerConfig::default(),
        Arc::clone(&storage),
    );

    let names = collect_fq_names(&analyzer);
    assert!(
        contains_short(&names, "goodbye"),
        "modified symbol should appear: {:?}",
        names
    );
    assert!(
        !contains_short(&names, "hello"),
        "old symbol should be gone: {:?}",
        names
    );
    assert!(
        contains_short(&names, "world"),
        "untouched file should survive"
    );
    assert_eq!(
        storage.row_count(Language::Python).unwrap(),
        2,
        "row count unchanged: 2 files in workspace"
    );
}

#[test]
fn file_deletion_removes_row_from_baseline() {
    let (tmp_workspace, project) = fresh_python_workspace();
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("analyzer.db");

    // Cold start writes 2 rows.
    {
        let storage = Arc::new(AnalyzerStorage::open(&db_path).unwrap());
        let _ = PythonAnalyzer::new_with_config_and_storage(
            project.clone(),
            AnalyzerConfig::default(),
            storage,
        );
    }

    // Remove beta.py from the workspace.
    fs::remove_file(tmp_workspace.path().join("beta.py")).unwrap();

    // Warm start.
    let storage = Arc::new(AnalyzerStorage::open(&db_path).unwrap());
    let analyzer = PythonAnalyzer::new_with_config_and_storage(
        project.clone(),
        AnalyzerConfig::default(),
        Arc::clone(&storage),
    );

    let names = collect_fq_names(&analyzer);
    assert!(contains_short(&names, "hello"));
    assert!(
        !contains_short(&names, "world"),
        "deleted symbol should be gone: {:?}",
        names
    );
    assert_eq!(
        storage.row_count(Language::Python).unwrap(),
        1,
        "deleted file's row should be purged from baseline"
    );
}

#[test]
fn epoch_mismatch_invalidates_baseline() {
    let (_tmp, project) = fresh_python_workspace();
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("analyzer.db");

    // Cold start.
    {
        let storage = Arc::new(AnalyzerStorage::open(&db_path).unwrap());
        let _ = PythonAnalyzer::new_with_config_and_storage(
            project.clone(),
            AnalyzerConfig::default(),
            storage,
        );
    }

    // Forcibly rewrite the persisted epoch to something stale.
    {
        use rusqlite::Connection;
        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "UPDATE analyzer_epoch SET epoch = 'stale' WHERE language = 'python'",
            [],
        )
        .unwrap();
        // Also bump every file's epoch column so we know the rebuild rewrote them.
        conn.execute(
            "UPDATE analyzed_files SET epoch = 'stale' WHERE language = 'python'",
            [],
        )
        .unwrap();
    }

    // Warm start should treat every row as dirty and refresh the epoch.
    let storage = Arc::new(AnalyzerStorage::open(&db_path).unwrap());
    let analyzer = PythonAnalyzer::new_with_config_and_storage(
        project.clone(),
        AnalyzerConfig::default(),
        Arc::clone(&storage),
    );
    assert!(contains_short(&collect_fq_names(&analyzer), "hello"));

    let persisted_epoch = storage.read_epoch(Language::Python).unwrap().unwrap();
    assert_ne!(
        persisted_epoch, "stale",
        "epoch should have been refreshed on reconcile"
    );
    assert_eq!(persisted_epoch.len(), 64, "epoch is sha256 hex");
}

#[test]
fn workspace_analyzer_with_storage_round_trips() {
    let (_tmp, project) = fresh_python_workspace();
    let db_dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(AnalyzerStorage::open(db_dir.path().join("analyzer.db")).unwrap());

    let analyzer = WorkspaceAnalyzer::build_with_storage(
        project.clone() as Arc<dyn brokk_analyzer::Project>,
        AnalyzerConfig::default(),
        Arc::clone(&storage),
    );
    let cold_names: BTreeSet<String> = analyzer
        .analyzer()
        .all_declarations()
        .map(|cu| cu.fq_name())
        .collect();
    assert!(contains_short(&cold_names, "hello"));
    assert!(contains_short(&cold_names, "world"));

    // Re-open with the same storage; should hydrate identically.
    let warm = WorkspaceAnalyzer::build_with_storage(
        project as Arc<dyn brokk_analyzer::Project>,
        AnalyzerConfig::default(),
        storage,
    );
    let warm_names: BTreeSet<String> = warm
        .analyzer()
        .all_declarations()
        .map(|cu| cu.fq_name())
        .collect();
    assert_eq!(cold_names, warm_names);
}

#[test]
fn default_db_path_under_dot_bifrost() {
    let path = default_db_path("/tmp/some-project");
    assert!(path.ends_with(".bifrost/analyzer.db"));
}

/// Regression test: a workspace file that becomes unparseable between
/// runs (e.g. now contains a NUL byte, or invalid UTF-8) must have its
/// stale baseline row purged from SQLite. Otherwise on the next startup
/// the row's mtime/size/epoch could match and we would resurrect old
/// declarations from a file that can no longer be analyzed.
#[test]
fn parse_failure_at_cold_start_purges_baseline_row() {
    let (tmp_workspace, project) = fresh_python_workspace();
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("analyzer.db");

    // Cold start: analyzer parses both files, persists 2 rows.
    {
        let storage = Arc::new(AnalyzerStorage::open(&db_path).unwrap());
        let analyzer = PythonAnalyzer::new_with_config_and_storage(
            project.clone(),
            AnalyzerConfig::default(),
            Arc::clone(&storage),
        );
        assert!(contains_short(&collect_fq_names(&analyzer), "world"));
        assert_eq!(storage.row_count(Language::Python).unwrap(), 2);
    }

    // Replace beta.py with content that `analyze_file` rejects (NUL byte =
    // treated as binary). The file is still enumerated as a `.py`
    // candidate, so it lands in the "dirty" partition; its parse result
    // will be `None`.
    let beta_path = tmp_workspace.path().join("beta.py");
    fs::write(&beta_path, b"def world():\n    return \x00\n").unwrap();
    let one_min_future = SystemTime::now() + Duration::from_secs(60);
    filetime::set_file_mtime(
        &beta_path,
        filetime::FileTime::from_system_time(one_min_future),
    )
    .unwrap();

    // Warm start: parse failure on beta.py must purge its baseline row.
    let storage = Arc::new(AnalyzerStorage::open(&db_path).unwrap());
    let analyzer = PythonAnalyzer::new_with_config_and_storage(
        project.clone(),
        AnalyzerConfig::default(),
        Arc::clone(&storage),
    );

    let names = collect_fq_names(&analyzer);
    assert!(contains_short(&names, "hello"), "alpha.py must still parse");
    assert!(
        !contains_short(&names, "world"),
        "stale `world` should not be hydrated from a now-unparseable file: {:?}",
        names
    );
    assert_eq!(
        storage.row_count(Language::Python).unwrap(),
        1,
        "beta.py's baseline row should have been purged",
    );
}

// ---------- FTS5 symbol index (issue #26) ----------

#[test]
fn cold_start_populates_symbol_index() {
    let (_tmp, project) = fresh_python_workspace();
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("analyzer.db");
    let storage = Arc::new(AnalyzerStorage::open(&db_path).unwrap());
    let _ = PythonAnalyzer::new_with_config_and_storage(
        project.clone(),
        AnalyzerConfig::default(),
        Arc::clone(&storage),
    );

    // Three Python declarations are visible in fresh_python_workspace:
    // alpha.py: hello, Greeter, Greeter.greet ; beta.py: world.
    let count = storage.symbol_count(Language::Python).unwrap();
    assert!(
        count >= 4,
        "expected at least 4 persisted symbols, got {count}"
    );
}

#[test]
fn symbol_search_substring_finds_short_name() {
    let (_tmp, project) = fresh_python_workspace();
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("analyzer.db");
    let storage = Arc::new(AnalyzerStorage::open(&db_path).unwrap());
    let _ = PythonAnalyzer::new_with_config_and_storage(
        project.clone(),
        AnalyzerConfig::default(),
        Arc::clone(&storage),
    );

    // Trigram substring match: "ell" should find "hello".
    let hits = storage
        .search_symbols(Language::Python, "ell", SymbolQueryMode::Substring)
        .unwrap();
    assert!(
        hits.iter().any(|h| h.symbol.short_name == "hello"),
        "trigram substring search for 'ell' should find 'hello': {hits:?}"
    );
}

#[test]
fn symbol_search_token_finds_fqn_component() {
    let (_tmp, project) = fresh_python_workspace();
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("analyzer.db");
    let storage = Arc::new(AnalyzerStorage::open(&db_path).unwrap());
    let _ = PythonAnalyzer::new_with_config_and_storage(
        project.clone(),
        AnalyzerConfig::default(),
        Arc::clone(&storage),
    );

    // unicode61 splits FQNs on '.', so "Greeter" should hit
    // both "Greeter" itself and "Greeter.greet" via token match.
    let hits = storage
        .search_symbols(Language::Python, "Greeter", SymbolQueryMode::Token)
        .unwrap();
    // The Python analyzer derives a package from the file stem, so FQNs
    // are e.g. "alpha.Greeter" and "alpha.Greeter.greet". The unicode61
    // tokenizer with '.' as a separator should still match the
    // "Greeter" component of both.
    let names: BTreeSet<_> = hits.iter().map(|h| h.symbol.fq_name.clone()).collect();
    assert!(
        names
            .iter()
            .any(|n| n.split('.').any(|tok| tok == "Greeter")),
        "token search 'Greeter' should hit FQNs containing it as a component: {names:?}"
    );
    assert!(
        names.iter().any(|n| n.ends_with(".Greeter.greet")),
        "token search 'Greeter' should hit method whose FQN contains it: {names:?}"
    );
}

#[test]
fn search_definitions_persisted_returns_reconstructable_code_units() {
    let (_tmp, project) = fresh_python_workspace();
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("analyzer.db");
    let storage = Arc::new(AnalyzerStorage::open(&db_path).unwrap());
    let analyzer = PythonAnalyzer::new_with_config_and_storage(
        project.clone(),
        AnalyzerConfig::default(),
        Arc::clone(&storage),
    );

    let hits = analyzer.search_definitions_persisted("hello");
    assert_eq!(hits.len(), 1, "exactly one 'hello' declaration: {hits:?}");
    let cu = hits.into_iter().next().unwrap();
    assert_eq!(cu.short_name(), "hello");
    assert!(cu.is_function(), "hello is a Function: {cu:?}");
    assert!(
        cu.source().rel_path().ends_with("alpha.py"),
        "source rebuilt with rel_path: {cu:?}"
    );
}

#[test]
fn search_definitions_persisted_matches_in_memory_for_substring() {
    let (_tmp, project) = fresh_python_workspace();
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("analyzer.db");
    let storage = Arc::new(AnalyzerStorage::open(&db_path).unwrap());
    let analyzer = PythonAnalyzer::new_with_config_and_storage(
        project.clone(),
        AnalyzerConfig::default(),
        Arc::clone(&storage),
    );

    let in_memory: BTreeSet<String> = analyzer
        .search_definitions("greet", true)
        .into_iter()
        .map(|cu| cu.fq_name())
        .collect();
    let persisted: BTreeSet<String> = analyzer
        .search_definitions_persisted("greet")
        .into_iter()
        .map(|cu| cu.fq_name())
        .collect();
    assert_eq!(
        in_memory, persisted,
        "persisted FTS5 substring search should match in-memory regex search semantics"
    );
}

#[test]
fn file_deletion_clears_symbol_rows() {
    let (tmp_workspace, project) = fresh_python_workspace();
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("analyzer.db");

    // Cold start.
    {
        let storage = Arc::new(AnalyzerStorage::open(&db_path).unwrap());
        let _ = PythonAnalyzer::new_with_config_and_storage(
            project.clone(),
            AnalyzerConfig::default(),
            storage,
        );
    }

    // Remove beta.py.
    fs::remove_file(tmp_workspace.path().join("beta.py")).unwrap();

    // Warm start.
    let storage = Arc::new(AnalyzerStorage::open(&db_path).unwrap());
    let _ = PythonAnalyzer::new_with_config_and_storage(
        project.clone(),
        AnalyzerConfig::default(),
        Arc::clone(&storage),
    );

    // beta.py's only symbol was `world`. After deletion, no row should
    // remain referencing it.
    let world_hits = storage
        .search_symbols(Language::Python, "world", SymbolQueryMode::Substring)
        .unwrap();
    assert!(
        world_hits.is_empty(),
        "deleted file's symbols should be purged from FTS5 too: {world_hits:?}"
    );

    // alpha.py's symbols should still be there.
    let hello_hits = storage
        .search_symbols(Language::Python, "hello", SymbolQueryMode::Substring)
        .unwrap();
    assert!(
        !hello_hits.is_empty(),
        "untouched file's symbols should survive: {hello_hits:?}"
    );
}

#[test]
fn file_modification_replaces_symbol_rows() {
    let (tmp_workspace, project) = fresh_python_workspace();
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("analyzer.db");

    // Cold start.
    {
        let storage = Arc::new(AnalyzerStorage::open(&db_path).unwrap());
        let _ = PythonAnalyzer::new_with_config_and_storage(
            project.clone(),
            AnalyzerConfig::default(),
            storage,
        );
    }

    // Rename alpha.py's `hello` to `goodbye` and bump mtime.
    let alpha = tmp_workspace.path().join("alpha.py");
    fs::write(
        &alpha,
        "def goodbye():\n    return 99\n\nclass Greeter:\n    def greet(self):\n        return 'hi'\n",
    )
    .unwrap();
    let one_min_future = SystemTime::now() + Duration::from_secs(60);
    filetime::set_file_mtime(&alpha, filetime::FileTime::from_system_time(one_min_future)).unwrap();

    // Warm start.
    let storage = Arc::new(AnalyzerStorage::open(&db_path).unwrap());
    let _ = PythonAnalyzer::new_with_config_and_storage(
        project.clone(),
        AnalyzerConfig::default(),
        Arc::clone(&storage),
    );

    let hello = storage
        .search_symbols(Language::Python, "hello", SymbolQueryMode::Substring)
        .unwrap();
    assert!(
        hello.is_empty(),
        "stale symbol 'hello' should be gone: {hello:?}"
    );

    let goodbye = storage
        .search_symbols(Language::Python, "goodbye", SymbolQueryMode::Substring)
        .unwrap();
    assert!(
        goodbye.iter().any(|h| h.symbol.short_name == "goodbye"),
        "renamed symbol 'goodbye' should be indexed: {goodbye:?}"
    );

    // Greeter survived (file content kept it).
    let greeter = storage
        .search_symbols(Language::Python, "Greeter", SymbolQueryMode::Token)
        .unwrap();
    assert!(
        !greeter.is_empty(),
        "untouched class on the same file should survive: {greeter:?}"
    );
}

#[test]
fn empty_pattern_returns_no_symbol_hits() {
    let db_dir = tempfile::tempdir().unwrap();
    let storage = AnalyzerStorage::open(db_dir.path().join("analyzer.db")).unwrap();
    let hits = storage
        .search_symbols(Language::Python, "", SymbolQueryMode::Substring)
        .unwrap();
    assert!(hits.is_empty());
}

#[test]
fn v1_to_v2_migration_preserves_analyzed_files() {
    use rusqlite::Connection;
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("analyzer.db");

    // Hand-build a v1 schema: same DDL as `apply_v1`, no symbols/FTS, set
    // user_version=1 so the migrator only applies v2 on next open.
    {
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE schema_meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE analyzer_epoch (
                language TEXT PRIMARY KEY,
                epoch    TEXT NOT NULL
            );
            CREATE TABLE analyzed_files (
                language TEXT NOT NULL,
                rel_path TEXT NOT NULL,
                mtime_ns INTEGER NOT NULL,
                size     INTEGER NOT NULL,
                epoch    TEXT NOT NULL,
                payload  BLOB NOT NULL,
                PRIMARY KEY (language, rel_path)
            );
            INSERT INTO schema_meta(key, value) VALUES ('created_at', '0');
            INSERT INTO analyzed_files(language, rel_path, mtime_ns, size, epoch, payload)
                VALUES ('python', 'preexisting.py', 1, 1, 'old-epoch', x'00');
            INSERT INTO analyzer_epoch(language, epoch) VALUES ('python', 'old-epoch');
            PRAGMA user_version = 1;
            "#,
        )
        .unwrap();
    }

    // Open via the real storage path: should run the v2 migration only.
    let storage = AnalyzerStorage::open(&db_path).expect("v1 -> v2 migration must succeed");

    // The pre-existing analyzed_files row must still be there.
    assert_eq!(
        storage.row_count(Language::Python).unwrap(),
        1,
        "analyzed_files row from v1 should survive v2 migration"
    );

    // The new symbols and FTS tables exist and are empty.
    assert_eq!(storage.symbol_count(Language::Python).unwrap(), 0);
    let hits = storage
        .search_symbols(Language::Python, "anything", SymbolQueryMode::Substring)
        .unwrap();
    assert!(hits.is_empty());

    // user_version must now be 2.
    let conn = Connection::open(&db_path).unwrap();
    let v: u32 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(v, 2, "user_version should be bumped to 2");
}

#[test]
fn symbol_search_prefix_matches_token_starts() {
    let (_tmp, project) = fresh_python_workspace();
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("analyzer.db");
    let storage = Arc::new(AnalyzerStorage::open(&db_path).unwrap());
    let _ = PythonAnalyzer::new_with_config_and_storage(
        project.clone(),
        AnalyzerConfig::default(),
        Arc::clone(&storage),
    );

    // "Gree" is a partial prefix of the "Greeter" and "greet" tokens
    // but is not itself a token. Prefix mode should match both via the
    // FTS5 trailing `*` syntax; plain Token mode should not match
    // because unicode61 indexes whole tokens (after case-folding).
    let prefix_hits = storage
        .search_symbols(Language::Python, "Gree", SymbolQueryMode::Prefix)
        .unwrap();
    assert!(
        prefix_hits
            .iter()
            .any(|h| h.symbol.fq_name.contains("Greeter")),
        "prefix 'Gree' should match 'Greeter': {prefix_hits:?}"
    );

    let token_hits = storage
        .search_symbols(Language::Python, "Gree", SymbolQueryMode::Token)
        .unwrap();
    assert!(
        token_hits.is_empty(),
        "Token mode for partial token 'Gree' should not match (whole-token only): {token_hits:?}"
    );
}

#[test]
fn symbol_search_respects_limit() {
    let tmp = tempfile::tempdir().unwrap();
    // Generate a workspace with many distinct symbols all containing
    // "common" so a single substring query hits all of them.
    let mut body = String::new();
    for i in 0..50 {
        body.push_str(&format!("def common_fn_{i}():\n    return {i}\n\n"));
    }
    write_file(tmp.path(), "many.py", &body);
    let canon = fs::canonicalize(tmp.path()).unwrap();
    let project = Arc::new(TestProject::new(canon, Language::Python));

    let db_dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(AnalyzerStorage::open(db_dir.path().join("analyzer.db")).unwrap());
    let _ = PythonAnalyzer::new_with_config_and_storage(
        project,
        AnalyzerConfig::default(),
        Arc::clone(&storage),
    );

    // Sanity: many.py contributes ≥50 matching symbols.
    let unbounded = storage
        .search_symbols_with_limit(Language::Python, "common", SymbolQueryMode::Substring, 1000)
        .unwrap();
    assert!(
        unbounded.len() >= 50,
        "expected ≥50 hits without a tight limit, got {}",
        unbounded.len()
    );

    // Tight LIMIT must be respected.
    let bounded = storage
        .search_symbols_with_limit(Language::Python, "common", SymbolQueryMode::Substring, 5)
        .unwrap();
    assert_eq!(bounded.len(), 5, "LIMIT 5 must cap result count");

    // limit=0 returns nothing without erroring.
    let none = storage
        .search_symbols_with_limit(Language::Python, "common", SymbolQueryMode::Substring, 0)
        .unwrap();
    assert!(none.is_empty());
}
