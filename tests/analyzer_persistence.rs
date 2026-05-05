//! End-to-end tests for the SQLite-backed analyzer persistence layer.

use brokk_analyzer::analyzer::persistence::{
    AnalyzerStorage, PersistenceError, default_db_path,
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
    write_file(
        tmp.path(),
        "beta.py",
        "def world():\n    return 2\n",
    );
    let canon = fs::canonicalize(tmp.path()).unwrap();
    let project = Arc::new(TestProject::new(canon, Language::Python));
    (tmp, project)
}

fn collect_fq_names<A: IAnalyzer>(analyzer: &A) -> BTreeSet<String> {
    analyzer
        .all_declarations()
        .map(|cu| cu.fq_name())
        .collect()
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
    assert!(result.is_err(), "corrupt file should not open as analyzer DB");
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
