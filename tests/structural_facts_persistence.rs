//! Analyzer-level validation for SQLite-backed compact structural facts.

use brokk_bifrost::{AnalyzerConfig, Language, Project, TestProject, WorkspaceAnalyzer};
use git2::{IndexAddOption, Repository, Signature};
use rusqlite::Connection;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq)]
struct MaterializedFacts {
    extractions: u64,
    hydrations: u64,
    facts: usize,
    roles: usize,
    source_by_path: BTreeMap<String, String>,
}

fn write_file(root: &Path, relative: &str, source: &str) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, source).unwrap();
}

fn init_git_repo(root: &Path) -> Repository {
    let repository = Repository::init(root).unwrap();
    let mut config = repository.config().unwrap();
    config.set_str("user.name", "Bifrost Test").unwrap();
    config.set_str("user.email", "bifrost@example.com").unwrap();
    repository
}

fn commit_all(repository: &Repository, message: &str) {
    let mut index = repository.index().unwrap();
    let mut skip_cache =
        |path: &Path, _matched: &[u8]| -> i32 { i32::from(path.starts_with(Path::new(".brokk"))) };
    index
        .add_all(["*"], IndexAddOption::DEFAULT, Some(&mut skip_cache))
        .unwrap();
    index.write().unwrap();
    let tree_id = index.write_tree().unwrap();
    let tree = repository.find_tree(tree_id).unwrap();
    let signature = Signature::now("Bifrost Test", "bifrost@example.com").unwrap();
    let parents = repository
        .head()
        .ok()
        .and_then(|head| head.target())
        .and_then(|oid| repository.find_commit(oid).ok())
        .into_iter()
        .collect::<Vec<_>>();
    let parent_refs = parents.iter().collect::<Vec<_>>();
    repository
        .commit(
            Some("HEAD"),
            &signature,
            &signature,
            message,
            &tree,
            &parent_refs,
        )
        .unwrap();
}

fn typescript_project(root: &Path) -> Arc<dyn Project> {
    Arc::new(TestProject::new(
        root.canonicalize().unwrap(),
        Language::TypeScript,
    ))
}

fn materialize(workspace: &WorkspaceAnalyzer) -> MaterializedFacts {
    let providers = workspace.analyzer().structural_search_providers();
    let extractions_before = providers
        .iter()
        .map(|provider| provider.structural_extraction_count())
        .sum::<u64>();
    let hydrations_before = providers
        .iter()
        .map(|provider| provider.structural_hydration_count())
        .sum::<u64>();
    let mut facts = 0usize;
    let mut roles = 0usize;
    let mut source_by_path = BTreeMap::new();
    for provider in &providers {
        let mut files = provider.structural_files();
        files.sort();
        for file in files {
            let entry = provider
                .structural_facts(&file)
                .unwrap_or_else(|| panic!("missing structural facts for {file}"));
            facts = facts.saturating_add(entry.nodes().len());
            roles = roles.saturating_add(entry.role_count());
            source_by_path.insert(
                file.rel_path().to_string_lossy().into_owned(),
                entry.source().to_owned(),
            );
        }
    }
    MaterializedFacts {
        extractions: providers
            .iter()
            .map(|provider| provider.structural_extraction_count())
            .sum::<u64>()
            .saturating_sub(extractions_before),
        hydrations: providers
            .iter()
            .map(|provider| provider.structural_hydration_count())
            .sum::<u64>()
            .saturating_sub(hydrations_before),
        facts,
        roles,
        source_by_path,
    }
}

#[test]
fn persisted_structural_facts_hydrate_by_exact_language_and_recover_corruption() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(root, ".gitignore", ".brokk/\n");
    write_file(root, "plain.ts", "export const value = call(1);\n");
    write_file(
        root,
        "component.tsx",
        "export const View = () => <section>{call(2)}</section>;\n",
    );
    let repository = init_git_repo(root);
    commit_all(&repository, "initial TypeScript fixtures");
    let project = typescript_project(root);
    let database = root.join(".brokk/bifrost_cache.db");

    let cold = WorkspaceAnalyzer::build_persisted(Arc::clone(&project), AnalyzerConfig::default())
        .expect("persisted analyzer should build");
    let expected = materialize(&cold);
    assert_eq!(expected.extractions, 2);
    assert_eq!(expected.hydrations, 0);
    drop(cold);

    let connection = Connection::open(&database).unwrap();
    let rows = connection
        .prepare(
            "SELECT lang, COUNT(*) FROM structural_facts_snapshots
             GROUP BY lang ORDER BY lang",
        )
        .unwrap()
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, usize>(1)?))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        rows,
        vec![
            ("typescript:ts".to_owned(), 1),
            ("typescript:tsx".to_owned(), 1),
        ]
    );
    drop(connection);

    let warm = WorkspaceAnalyzer::build_persisted(Arc::clone(&project), AnalyzerConfig::default())
        .expect("persisted analyzer should reopen");
    let hydrated = materialize(&warm);
    assert_eq!(hydrated.extractions, 0);
    assert_eq!(hydrated.hydrations, 2);
    assert_eq!(hydrated.facts, expected.facts);
    assert_eq!(hydrated.roles, expected.roles);
    assert_eq!(hydrated.source_by_path, expected.source_by_path);
    drop(warm);

    Connection::open(&database)
        .unwrap()
        .execute(
            "UPDATE structural_facts_snapshots SET payload = X'00'
             WHERE lang = 'typescript:ts'",
            [],
        )
        .unwrap();
    let repairing =
        WorkspaceAnalyzer::build_persisted(Arc::clone(&project), AnalyzerConfig::default())
            .expect("persisted analyzer should repair corrupt facts");
    let repaired = materialize(&repairing);
    assert_eq!(repaired.extractions, 1);
    assert_eq!(repaired.hydrations, 1);
    assert_eq!(repaired.facts, expected.facts);
    assert_eq!(repaired.roles, expected.roles);
    drop(repairing);

    let verified = WorkspaceAnalyzer::build_persisted(project, AnalyzerConfig::default())
        .expect("persisted analyzer should reopen after repair");
    let verified = materialize(&verified);
    assert_eq!(verified.extractions, 0);
    assert_eq!(verified.hydrations, 2);
    assert_eq!(verified.source_by_path, expected.source_by_path);
}

#[test]
fn changed_content_extracts_once_then_hydrates_its_new_blob() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(root, ".gitignore", ".brokk/\n");
    write_file(root, "app.ts", "export const first = call(1);\n");
    let repository = init_git_repo(root);
    commit_all(&repository, "initial source");
    let project = typescript_project(root);

    let initial = {
        let workspace =
            WorkspaceAnalyzer::build_persisted(Arc::clone(&project), AnalyzerConfig::default())
                .expect("persisted analyzer should build");
        materialize(&workspace)
    };
    assert_eq!((initial.extractions, initial.hydrations), (1, 0));

    write_file(
        root,
        "app.ts",
        "export const changed = call(1, 2);\nexport const added = call(3);\n",
    );
    commit_all(&repository, "change source");
    let changed = {
        let workspace =
            WorkspaceAnalyzer::build_persisted(Arc::clone(&project), AnalyzerConfig::default())
                .expect("persisted analyzer should rebuild changed content");
        materialize(&workspace)
    };
    assert_eq!((changed.extractions, changed.hydrations), (1, 0));
    assert_ne!(changed.facts, initial.facts);

    let reopened = {
        let workspace = WorkspaceAnalyzer::build_persisted(project, AnalyzerConfig::default())
            .expect("persisted analyzer should reopen");
        materialize(&workspace)
    };
    assert_eq!((reopened.extractions, reopened.hydrations), (0, 1));
    assert_eq!(reopened.facts, changed.facts);
    assert_eq!(reopened.roles, changed.roles);
    assert_eq!(reopened.source_by_path, changed.source_by_path);
}
