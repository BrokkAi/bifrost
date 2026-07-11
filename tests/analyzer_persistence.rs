//! Analyzer-level persistence behavior for the blob-keyed SQLite store.

use brokk_bifrost::analyzer::{BuildProgressEvent, BuildProgressPhase};
use brokk_bifrost::{
    AnalyzerConfig, IAnalyzer, Language, Project, ProjectFile, PythonAnalyzer, TestProject,
    WorkspaceAnalyzer,
};
use git2::{IndexAddOption, Repository, Signature};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::sync::Arc;

fn write_file(root: &Path, rel: &str, body: &str) {
    let abs = root.join(rel);
    if let Some(parent) = abs.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(abs, body).unwrap();
}

fn init_git_repo(root: &Path) -> Repository {
    let repo = Repository::init(root).unwrap();
    let mut config = repo.config().unwrap();
    config.set_str("user.name", "Bifrost Test").unwrap();
    config.set_str("user.email", "bifrost@example.com").unwrap();
    repo
}

fn commit_all(repo: &Repository, message: &str) {
    let mut index = repo.index().unwrap();
    index.add_all(["*"], IndexAddOption::DEFAULT, None).unwrap();
    index.write().unwrap();
    let tree_oid = index.write_tree().unwrap();
    let tree = repo.find_tree(tree_oid).unwrap();
    let sig = Signature::now("Bifrost Test", "bifrost@example.com").unwrap();
    let parents = repo
        .head()
        .ok()
        .and_then(|head| head.target())
        .and_then(|oid| repo.find_commit(oid).ok())
        .into_iter()
        .collect::<Vec<_>>();
    let parent_refs = parents.iter().collect::<Vec<_>>();
    repo.commit(Some("HEAD"), &sig, &sig, message, &tree, &parent_refs)
        .unwrap();
}

fn python_project(root: &Path) -> Arc<dyn Project> {
    Arc::new(TestProject::new(
        root.canonicalize().unwrap(),
        Language::Python,
    ))
}

fn parsed_file_count(events: &[BuildProgressEvent]) -> usize {
    events
        .iter()
        .filter(|event| event.phase == BuildProgressPhase::Parse)
        .filter(|event| event.file.is_some())
        .count()
}

fn declaration_names(analyzer: &dyn IAnalyzer) -> BTreeSet<String> {
    analyzer
        .all_declarations()
        .map(|unit| unit.fq_name())
        .collect()
}

#[test]
fn git_blob_store_warm_build_hydrates_without_reparse() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(root, "alpha.py", "class Alpha:\n    pass\n");
    write_file(root, "beta.py", "def beta():\n    return 1\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let project = python_project(root);

    let cold_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let cold = WorkspaceAnalyzer::build_persisted_with_progress(
        Arc::clone(&project),
        AnalyzerConfig::default(),
        {
            let events = Arc::clone(&cold_events);
            move |event| events.lock().unwrap().push(event)
        },
    );
    let cold_names = declaration_names(cold.analyzer());
    assert!(cold_names.contains("alpha.Alpha"));
    assert!(cold_names.contains("beta.beta"));
    assert_eq!(parsed_file_count(&cold_events.lock().unwrap()), 2);

    let warm_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let warm =
        WorkspaceAnalyzer::build_persisted_with_progress(project, AnalyzerConfig::default(), {
            let events = Arc::clone(&warm_events);
            move |event| events.lock().unwrap().push(event)
        });
    assert_eq!(cold_names, declaration_names(warm.analyzer()));
    assert_eq!(parsed_file_count(&warm_events.lock().unwrap()), 0);
}

#[test]
fn dirty_file_reconcile_parses_only_changed_blob() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(root, "alpha.py", "class Alpha:\n    pass\n");
    write_file(root, "beta.py", "def beta():\n    return 1\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let project = python_project(root);

    let _ = WorkspaceAnalyzer::build_persisted(Arc::clone(&project), AnalyzerConfig::default());
    write_file(root, "alpha.py", "class Renamed:\n    pass\n");

    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let rebuilt =
        WorkspaceAnalyzer::build_persisted_with_progress(project, AnalyzerConfig::default(), {
            let events = Arc::clone(&events);
            move |event| events.lock().unwrap().push(event)
        });
    let names = declaration_names(rebuilt.analyzer());
    assert!(names.contains("alpha.Renamed"));
    assert!(!names.contains("alpha.Alpha"));
    assert!(names.contains("beta.beta"));
    assert_eq!(parsed_file_count(&events.lock().unwrap()), 1);
}

#[test]
fn deleted_file_is_removed_from_live_results() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(root, "alpha.py", "class Alpha:\n    pass\n");
    write_file(root, "beta.py", "def beta():\n    return 1\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let project = python_project(root);

    let _ = WorkspaceAnalyzer::build_persisted(Arc::clone(&project), AnalyzerConfig::default());
    fs::remove_file(root.join("beta.py")).unwrap();

    let rebuilt = WorkspaceAnalyzer::build_persisted(project, AnalyzerConfig::default());
    let names = declaration_names(rebuilt.analyzer());
    assert!(names.contains("alpha.Alpha"));
    assert!(!names.contains("beta.beta"));
}

#[test]
fn plain_build_reparses_while_persisted_build_hydrates_parse_errors() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(root, "broken.py", "def x():\n    return 1)\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let project = python_project(root);
    let file = ProjectFile::new(root.canonicalize().unwrap(), "broken.py");

    let plain_first = WorkspaceAnalyzer::build(Arc::clone(&project), AnalyzerConfig::default());
    assert!(
        !plain_first
            .analyzer()
            .parse_errors(&file)
            .expect("plain build should freshly parse errors")
            .is_empty()
    );

    let plain_second = WorkspaceAnalyzer::build(Arc::clone(&project), AnalyzerConfig::default());
    assert!(
        !plain_second
            .analyzer()
            .parse_errors(&file)
            .expect("second plain build should freshly parse errors")
            .is_empty()
    );

    let cold_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let persisted_first = WorkspaceAnalyzer::build_persisted_with_progress(
        Arc::clone(&project),
        AnalyzerConfig::default(),
        {
            let events = Arc::clone(&cold_events);
            move |event| events.lock().unwrap().push(event)
        },
    );
    assert!(
        !persisted_first
            .analyzer()
            .parse_errors(&file)
            .expect("cold persisted build should freshly parse errors")
            .is_empty()
    );
    assert_eq!(parsed_file_count(&cold_events.lock().unwrap()), 1);

    let warm_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let persisted_second =
        WorkspaceAnalyzer::build_persisted_with_progress(project, AnalyzerConfig::default(), {
            let events = Arc::clone(&warm_events);
            move |event| events.lock().unwrap().push(event)
        });
    assert!(
        persisted_second.analyzer().parse_errors(&file).is_none(),
        "warm persisted build must hydrate and leave parse_errors unknown"
    );
    assert_eq!(parsed_file_count(&warm_events.lock().unwrap()), 0);
}

#[test]
fn update_repopulates_parse_errors_for_delta_only() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    write_file(&root, "evolving.py", "def x():\n    return 1)\n");
    let project = python_project(&root);
    let file = ProjectFile::new(root, "evolving.py");

    let analyzer = PythonAnalyzer::new(Arc::clone(&project));
    assert!(!analyzer.parse_errors(&file).unwrap().is_empty());

    file.write("def x():\n    return 1\n").unwrap();
    let mut changed = BTreeSet::new();
    changed.insert(file.clone());
    let updated = analyzer.update(&changed);
    assert_eq!(updated.parse_errors(&file), Some(Vec::new()));
}
