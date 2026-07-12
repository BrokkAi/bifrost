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

fn go_python_project(root: &Path) -> Arc<dyn Project> {
    Arc::new(TestProject::with_languages(
        root.canonicalize().unwrap(),
        BTreeSet::from([Language::Go, Language::Python]),
    ))
}

fn csharp_python_project(root: &Path) -> Arc<dyn Project> {
    Arc::new(TestProject::with_languages(
        root.canonicalize().unwrap(),
        BTreeSet::from([Language::CSharp, Language::Python]),
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
fn warm_multilanguage_go_definition_query_does_not_build_full_definition_index() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(root, "go.mod", "module example.com/app\n");
    write_file(
        root,
        "main.go",
        "package main\n\nimport \"example.com/app/generated/client\"\n\nfunc Run() { api.Helper() }\n",
    );
    write_file(
        root,
        "generated/client/client.go",
        "package api\n\nfunc Helper() {}\n",
    );
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let project = go_python_project(root);

    let _cold = WorkspaceAnalyzer::build_persisted(Arc::clone(&project), AnalyzerConfig::default());
    let warm_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let warm =
        WorkspaceAnalyzer::build_persisted_with_progress(project, AnalyzerConfig::default(), {
            let events = Arc::clone(&warm_events);
            move |event| events.lock().unwrap().push(event)
        });
    let analyzer = warm.analyzer();
    assert_eq!(parsed_file_count(&warm_events.lock().unwrap()), 0);
    assert_eq!(analyzer.definition_lookup_index_build_count_for_test(), 0);
    assert_eq!(analyzer.full_declaration_scan_count_for_test(), 0);

    let result = brokk_bifrost::searchtools::get_definitions_by_location(
        analyzer,
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: vec![brokk_bifrost::searchtools::DefinitionReferenceQuery {
                path: "main.go".to_string(),
                line: Some(5),
                column: Some(18),
            }],
        },
    );

    assert_eq!(result.results[0].status, "resolved");
    assert_eq!(
        result.results[0].definitions[0].fqn.as_deref(),
        Some("example.com/app/generated/client.Helper")
    );
    assert_eq!(analyzer.definition_lookup_index_build_count_for_test(), 0);
    assert_eq!(analyzer.full_declaration_scan_count_for_test(), 0);
}

#[test]
fn warm_multilanguage_csharp_definition_query_does_not_build_full_definition_index() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "Lib/Service.cs",
        "namespace Lib { public class Service { public void Run() {} } }\n",
    );
    let caller = "using Lib;\nnamespace App { public class Controller { public void Handle() { var service = new Service(); service.Run(); } } }\n";
    write_file(root, "App/Controller.cs", caller);
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let project = csharp_python_project(root);

    let _cold = WorkspaceAnalyzer::build_persisted(Arc::clone(&project), AnalyzerConfig::default());
    let warm_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let warm =
        WorkspaceAnalyzer::build_persisted_with_progress(project, AnalyzerConfig::default(), {
            let events = Arc::clone(&warm_events);
            move |event| events.lock().unwrap().push(event)
        });
    let analyzer = warm.analyzer();
    assert_eq!(parsed_file_count(&warm_events.lock().unwrap()), 0);
    assert_eq!(analyzer.definition_lookup_index_build_count_for_test(), 0);
    assert_eq!(analyzer.full_declaration_scan_count_for_test(), 0);

    let call_line = caller.lines().nth(1).unwrap();
    let result = brokk_bifrost::searchtools::get_definitions_by_location(
        analyzer,
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: vec![brokk_bifrost::searchtools::DefinitionReferenceQuery {
                path: "App/Controller.cs".to_string(),
                line: Some(2),
                column: Some(call_line.find("Run").unwrap() + 1),
            }],
        },
    );

    assert_eq!(result.results[0].status, "resolved");
    assert_eq!(
        result.results[0].definitions[0].fqn.as_deref(),
        Some("Lib.Service.Run")
    );
    assert_eq!(analyzer.definition_lookup_index_build_count_for_test(), 0);
    assert_eq!(analyzer.full_declaration_scan_count_for_test(), 0);
}

#[test]
fn csharp_package_existence_ignores_stale_complete_blobs() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "Types.cs",
        "namespace Removed { public class OldType {} }\n",
    );
    let caller =
        "using Removed;\nnamespace App { public class Controller { private Missing value; } }\n";
    write_file(root, "Controller.cs", caller);
    let repo = init_git_repo(root);
    commit_all(&repo, "initial namespace");
    let project = Arc::new(TestProject::new(
        root.canonicalize().unwrap(),
        Language::CSharp,
    ));

    let _cold = WorkspaceAnalyzer::build_persisted(project.clone(), AnalyzerConfig::default());
    write_file(
        root,
        "Types.cs",
        "namespace Replacement { public class NewType {} }\n",
    );
    commit_all(&repo, "replace namespace");
    let warm = WorkspaceAnalyzer::build_persisted(project, AnalyzerConfig::default());

    let type_line = caller.lines().nth(1).unwrap();
    let result = brokk_bifrost::searchtools::get_definitions_by_location(
        warm.analyzer(),
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: vec![brokk_bifrost::searchtools::DefinitionReferenceQuery {
                path: "Controller.cs".to_string(),
                line: Some(2),
                column: Some(type_line.find("Missing").unwrap() + 1),
            }],
        },
    );

    assert_eq!(
        result.results[0].status, "unresolvable_import_boundary",
        "the stale Removed namespace blob must not count as live"
    );
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
