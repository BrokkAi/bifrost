use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;
use brokk_bifrost_analysis::analyzer::i_analyzer::{
    AnalyzerQueryScope, AnalyzerStreamingFileScope,
};
use brokk_bifrost_analysis::analyzer::read_ledger::ReadLedger;
use brokk_bifrost_analysis::analyzer::read_verification::WorkspaceFactIndex;
use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;
use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::{
    BulkFileStateSource, LanguageAdapter, TreeSitterAnalyzer, store_context_from_store,
};
use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
use brokk_bifrost_core::analyzer::config::AnalyzerConfig;
use brokk_bifrost_core::analyzer::model::{CodeUnitType, Language, ProjectFile};
use brokk_bifrost_core::analyzer::project::{Project, TestProject};
use brokk_bifrost_go_analysis::analyzer::go::adapter::GoAdapter;
use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;
use std::collections::BTreeSet;
use std::sync::Arc;

fn java_project(files: &[(&str, &str)]) -> (tempfile::TempDir, Arc<dyn Project>) {
    let temp = tempfile::tempdir().expect("temporary workspace");
    let root = temp.path().canonicalize().expect("absolute workspace");
    for (path, source) in files {
        let file = ProjectFile::new(root.clone(), *path);
        file.write(source).expect("write Java source");
    }
    let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Java));
    (temp, project)
}

fn persisted_java_analyzer(
    project: Arc<dyn Project>,
    db: &std::path::Path,
) -> TreeSitterAnalyzer<JavaAdapter> {
    let store = AnalyzerStore::open_persistent(db).expect("persistent analyzer store");
    let context = store_context_from_store(project.as_ref(), store, false);
    TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
        project,
        JavaAdapter,
        AnalyzerConfig::default(),
        context,
        None,
    )
    .expect("persisted Java analyzer")
}

fn persisted_go_analyzer(
    project: Arc<dyn Project>,
    db: &std::path::Path,
) -> TreeSitterAnalyzer<GoAdapter> {
    let store = AnalyzerStore::open_persistent(db).expect("persistent analyzer store");
    let context = store_context_from_store(project.as_ref(), store, false);
    TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
        project,
        GoAdapter,
        AnalyzerConfig::default(),
        context,
        None,
    )
    .expect("persisted Go analyzer")
}

fn fail_blob_writes<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    language: &'static str,
    install: bool,
) {
    let sql = if install {
        format!(
            "CREATE TEMP TRIGGER lane7_fail_blob_writes BEFORE INSERT ON blobs WHEN NEW.lang = '{language}' BEGIN SELECT RAISE(FAIL, 'forced dirty state'); END;"
        )
    } else {
        "DROP TRIGGER lane7_fail_blob_writes".to_string()
    };
    analyzer
        .analyzer_store()
        .conn
        .execute(move |connection| connection.execute_batch(&sql).expect("toggle test trigger"));
}

#[test]
fn bulk_file_state_admits_each_owned_live_file_once() {
    let (_temp, project) = java_project(&[
        ("Widget.java", "package demo; class Widget {}\n"),
        ("Other.go", "package demo\ntype Other struct{}\n"),
    ]);
    let analyzer = TreeSitterAnalyzer::new(Arc::clone(&project), JavaAdapter);
    let java = ProjectFile::new(project.root().to_path_buf(), "Widget.java");
    let go = ProjectFile::new(project.root().to_path_buf(), "Other.go");
    let states = analyzer.bulk_file_states(
        [java.clone(), java.clone(), go],
        BulkFileStateSource::Include,
    );
    assert_eq!(states.len(), 1);
    assert!(states.contains_key(&java));
}

#[test]
fn dirty_declaration_queries_match_the_updated_source_inventory() {
    let temp = tempfile::tempdir().expect("temporary workspace");
    let root = temp.path().canonicalize().expect("absolute workspace");
    let file = ProjectFile::new(root.clone(), "Widget.java");
    file.write("package oldpkg; class Widget {}\n")
        .expect("initial source");
    let repo = git2::Repository::init(&root).expect("initialize Git");
    let mut index = repo.index().expect("Git index");
    index.add_path(std::path::Path::new("Widget.java")).unwrap();
    index.write().unwrap();
    let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
    let signature = git2::Signature::now("Bifrost test", "bifrost-test@example.invalid").unwrap();
    repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
        .unwrap();
    let project: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Java));
    let db = root.join("analyzer.db");
    let analyzer = persisted_java_analyzer(Arc::clone(&project), &db);
    assert!(
        analyzer
            .get_all_declarations()
            .iter()
            .any(|unit| unit.fq_name() == "oldpkg.Widget")
    );
    drop(analyzer);
    let reopened = persisted_java_analyzer(Arc::clone(&project), &db);

    file.write(
        "package newpkg; class Widget {} interface Contract {} enum Flavor { ONE } record Value(int count) {}\n",
    )
        .expect("edit source");
    index.add_path(std::path::Path::new("Widget.java")).unwrap();
    index.write().unwrap();
    fail_blob_writes(&reopened, "java", true);
    let updated = reopened.update(&BTreeSet::from([file.clone()]));
    assert!(
        !updated.state.dirty_snapshot().is_empty(),
        "write failure must retain dirty file state"
    );
    fail_blob_writes(&updated, "java", false);
    assert!(updated.persisted_package_exists("newpkg"));
    assert!(!updated.persisted_package_exists("oldpkg"));
    let qualifier = updated
        .content_qualifier_of(&file)
        .expect("live content qualifier");
    assert_eq!(qualifier, "newpkg");
    let declarations = updated.get_all_declarations();
    assert!(
        declarations
            .iter()
            .any(|unit| unit.fq_name() == "newpkg.Widget")
    );
    assert!(
        !declarations
            .iter()
            .any(|unit| unit.fq_name() == "oldpkg.Widget")
    );
    let hierarchy = updated
        .hierarchy_declaration_facts_by_kind(CodeUnitType::Class)
        .expect("complete class facts");
    assert!(
        hierarchy
            .iter()
            .any(|fact| fact.declaration.fq_name() == "newpkg.Widget")
    );
    assert!(hierarchy.iter().all(|fact| fact.declaration.is_class()));
    let file_scope = updated
        .fetch_file_state(&file)
        .unwrap()
        .declarations
        .iter()
        .filter(|unit| unit.is_file_scope())
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        !file_scope.is_empty(),
        "fixture must include a file-scope unit"
    );
    let file_scope_name = file_scope[0].identifier();
    let candidates = updated.lookup_declarations_by_identifier(file_scope_name);
    assert!(candidates.iter().all(|unit| !unit.is_file_scope()));
    for name in ["Contract", "Flavor", "Value"] {
        assert!(declarations.iter().any(|unit| unit.identifier() == name));
    }
}

#[test]
fn persisted_java_startup_oids_survive_reopen_edit_delete_and_revert() {
    let temp = tempfile::tempdir().expect("temporary workspace");
    let root = temp.path().canonicalize().expect("absolute workspace");
    let first = ProjectFile::new(root.clone(), "src/First.java");
    let second = ProjectFile::new(root.clone(), "src/Second.java");
    let deleted = ProjectFile::new(root.clone(), "src/Deleted.java");
    first.write("package before; class First {}\n").unwrap();
    second.write("package before; class Second {}\n").unwrap();
    deleted.write("package before; class Deleted {}\n").unwrap();
    let second_modified = std::fs::metadata(second.abs_path())
        .unwrap()
        .modified()
        .unwrap();
    let repo = git2::Repository::init(&root).expect("initialize Git");
    let mut index = repo.index().expect("Git index");
    index
        .add_path(std::path::Path::new("src/First.java"))
        .unwrap();
    index
        .add_path(std::path::Path::new("src/Second.java"))
        .unwrap();
    index
        .add_path(std::path::Path::new("src/Deleted.java"))
        .unwrap();
    index.write().unwrap();
    let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
    let signature = git2::Signature::now("Bifrost test", "bifrost-test@example.invalid").unwrap();
    repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
        .unwrap();
    let db = root.join("analyzer.db");
    let project: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Java));
    let initial = persisted_java_analyzer(Arc::clone(&project), &db);
    let initial_declarations = initial.get_all_declarations();
    assert!(
        initial_declarations
            .iter()
            .any(|unit| unit.identifier() == "First")
    );
    assert!(
        initial_declarations
            .iter()
            .any(|unit| unit.identifier() == "Second")
    );
    drop(initial);

    let reopened = persisted_java_analyzer(Arc::clone(&project), &db);
    {
        let _stream = AnalyzerStreamingFileScope::new(&reopened, &first);
        let streamed = reopened
            .fetch_file_state(&first)
            .expect("streamed stored state");
        assert!(
            streamed
                .declarations
                .iter()
                .any(|unit| unit.identifier() == "First")
        );
    }
    first
        .write("package edited; class FirstEdited {}\n")
        .unwrap();
    second.write("package before; class Thirds {}\n").unwrap();
    std::fs::File::options()
        .write(true)
        .open(second.abs_path())
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(second_modified))
        .unwrap();
    assert_eq!(
        std::fs::metadata(second.abs_path())
            .unwrap()
            .modified()
            .unwrap(),
        second_modified,
        "same-size edit preserves the startup stat"
    );
    std::fs::remove_file(deleted.abs_path()).unwrap();
    index
        .add_path(std::path::Path::new("src/First.java"))
        .unwrap();
    index
        .add_path(std::path::Path::new("src/Second.java"))
        .unwrap();
    index
        .remove_path(std::path::Path::new("src/Deleted.java"))
        .unwrap();
    index.write().unwrap();
    let changed = BTreeSet::from([first.clone(), second.clone(), deleted.clone()]);
    fail_blob_writes(&reopened, "java", true);
    assert!(
        reopened
            .store_context
            .liveness
            .as_ref()
            .and_then(|liveness| liveness.taken_startup_identity())
            .is_some(),
        "persistent startup identity must be seeded before invalidation"
    );
    IAnalyzer::invalidate_cached_file_identities(&reopened);
    assert!(
        reopened
            .store_context
            .liveness
            .as_ref()
            .and_then(|liveness| liveness.taken_startup_identity())
            .is_none(),
        "startup identity invalidation must clear the retained identity"
    );
    let incremental = reopened.update(&changed);
    assert!(
        !incremental.state.dirty_snapshot().is_empty(),
        "failed persistence must retain dirty state"
    );
    fail_blob_writes(&incremental, "java", false);
    let fresh = TreeSitterAnalyzer::new(
        Arc::new(TestProject::new(root.clone(), Language::Java)),
        JavaAdapter,
    );
    let mut actual = incremental
        .get_all_declarations()
        .into_iter()
        .map(|unit| unit.fq_name())
        .collect::<Vec<_>>();
    let mut expected = fresh
        .get_all_declarations()
        .into_iter()
        .map(|unit| unit.fq_name())
        .collect::<Vec<_>>();
    actual.sort();
    expected.sort();
    assert_eq!(actual, expected);
    assert!(actual.iter().any(|name| name.ends_with("FirstEdited")));
    assert!(actual.iter().any(|name| name.ends_with("Thirds")));
    assert!(!actual.iter().any(|name| name.ends_with("Deleted")));
    drop(incremental);

    first.write("package before; class First {}\n").unwrap();
    second.write("package before; class Second {}\n").unwrap();
    std::fs::File::options()
        .write(true)
        .open(second.abs_path())
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(second_modified))
        .unwrap();
    deleted
        .write("package restored; class DeletedRestored {}\n")
        .unwrap();
    index
        .add_path(std::path::Path::new("src/First.java"))
        .unwrap();
    index
        .add_path(std::path::Path::new("src/Second.java"))
        .unwrap();
    index
        .add_path(std::path::Path::new("src/Deleted.java"))
        .unwrap();
    index.write().unwrap();
    let reopened = persisted_java_analyzer(Arc::clone(&project), &db);
    let changed = BTreeSet::from([first.clone(), second.clone(), deleted.clone()]);
    let liveness = reopened.store_context.liveness.as_ref().unwrap();
    let _startup = liveness
        .oids_for_files(&[first.clone(), second.clone(), deleted.clone()])
        .unwrap();
    IAnalyzer::invalidate_cached_file_identities_for(&reopened, &changed);
    let resolved = liveness
        .oids_for_files(&[first.clone(), second.clone(), deleted.clone()])
        .unwrap();
    for (file, source) in [
        (&first, "package before; class First {}\n"),
        (&second, "package before; class Second {}\n"),
        (&deleted, "package restored; class DeletedRestored {}\n"),
    ] {
        let expected_oid =
            git2::Oid::hash_object(git2::ObjectType::Blob, source.as_bytes()).unwrap();
        assert_eq!(resolved.get(file), Some(&expected_oid));
    }
    let incremental = reopened.update(&changed);
    let fresh = TreeSitterAnalyzer::new(
        Arc::new(TestProject::new(root, Language::Java)),
        JavaAdapter,
    );
    let mut actual = incremental
        .get_all_declarations()
        .into_iter()
        .map(|unit| unit.fq_name())
        .collect::<Vec<_>>();
    let mut expected = fresh
        .get_all_declarations()
        .into_iter()
        .map(|unit| unit.fq_name())
        .collect::<Vec<_>>();
    actual.sort();
    expected.sort();
    assert_eq!(actual, expected);
    assert!(actual.iter().any(|name| name.ends_with("First")));
    assert!(actual.iter().any(|name| name.ends_with("Second")));
    assert!(actual.iter().any(|name| name.ends_with("DeletedRestored")));
}

#[test]
fn stored_blob_keys_use_the_generation_for_each_language() {
    let temp = tempfile::tempdir().expect("temporary workspace");
    let root = temp.path().canonicalize().expect("absolute workspace");
    let java_file = ProjectFile::new(root.clone(), "src/Widget.java");
    let go_file = ProjectFile::new(root.clone(), "src/widget.go");
    let java_source = "package sample; class Widget {}\n";
    let go_source = "package sample\ntype Widget struct{}\n";
    java_file.write(java_source).unwrap();
    go_file.write(go_source).unwrap();
    let db = root.join("analyzer.db");

    let java_project: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Java));
    let java = persisted_java_analyzer(Arc::clone(&java_project), &db);
    assert!(
        java.get_all_declarations()
            .iter()
            .any(|unit| unit.identifier() == "Widget")
    );
    let go_project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Go));
    let store = AnalyzerStore::open_persistent(&db).expect("shared store");
    store
        .ensure_language_epoch_value("go", "distinct-generation-for-routing-test")
        .expect("set Go generation independently");
    let context = store_context_from_store(go_project.as_ref(), store, false);
    let go = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
        Arc::clone(&go_project),
        GoAdapter,
        AnalyzerConfig::default(),
        context,
        None,
    )
    .expect("persisted Go analyzer");
    assert!(
        go.get_all_declarations()
            .iter()
            .any(|unit| unit.identifier() == "Widget")
    );

    for (analyzer, file, source, language) in [
        (
            &java as &dyn WorkspaceFactIndex,
            &java_file,
            java_source,
            "java",
        ),
        (&go as &dyn WorkspaceFactIndex, &go_file, go_source, "go"),
    ] {
        let oid = git2::Oid::hash_object(git2::ObjectType::Blob, source.as_bytes()).unwrap();
        assert_eq!(
            analyzer.fact_index_language(),
            if language == "java" {
                Language::Java
            } else {
                Language::Go
            }
        );
        let live = analyzer
            .blob_index_keys(file, oid)
            .expect("live index keys");
        let stored = analyzer
            .stored_blob_index_keys(file, oid, source)
            .expect("stored index keys");
        let stable_families = |keys: Vec<_>| {
            keys.into_iter()
                .filter(|(family, _)| {
                    *family != brokk_bifrost_analysis::analyzer::read_ledger::IndexFamily::Supertype
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(stable_families(live), stable_families(stored));
    }
}

#[test]
fn dirty_type_alias_classification_tracks_each_live_revision() {
    let temp = tempfile::tempdir().expect("temporary workspace");
    let root = temp.path().canonicalize().expect("absolute workspace");
    let file = ProjectFile::new(root.clone(), "alias.go");
    file.write("package sample\ntype Item = string\n")
        .expect("initial Go source");
    let repo = git2::Repository::init(&root).expect("initialize Git");
    let mut index = repo.index().expect("Git index");
    index.add_path(std::path::Path::new("alias.go")).unwrap();
    index.write().unwrap();
    let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
    let signature = git2::Signature::now("Bifrost test", "bifrost-test@example.invalid").unwrap();
    repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
        .unwrap();
    let db = root.join("analyzer.db");
    let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Go));
    let analyzer = persisted_go_analyzer(Arc::clone(&project), &db);
    let alias = analyzer
        .get_all_declarations()
        .into_iter()
        .find(|unit| unit.identifier() == "Item")
        .expect("type alias declaration");
    assert!(analyzer.is_type_alias(&alias));
    drop(analyzer);
    let reopened = persisted_go_analyzer(Arc::clone(&project), &db);

    file.write("package sample\ntype Item string\n")
        .expect("replace alias with defined type");
    index.add_path(std::path::Path::new("alias.go")).unwrap();
    index.write().unwrap();
    fail_blob_writes(&reopened, "go", true);
    let updated = reopened.update(&BTreeSet::from([file.clone()]));
    assert!(
        !updated.state.dirty_snapshot().is_empty(),
        "write failure must retain dirty file state"
    );
    fail_blob_writes(&updated, "go", false);
    let defined = updated
        .get_all_declarations()
        .into_iter()
        .find(|unit| unit.identifier() == "Item")
        .expect("defined type declaration");
    assert!(!updated.is_type_alias(&defined));
}

#[test]
fn analyzed_blob_identity_tracks_live_file_content() {
    let (_temp, project) = java_project(&[("Widget.java", "class Widget {}\n")]);
    let analyzer = TreeSitterAnalyzer::new(Arc::clone(&project), JavaAdapter);
    let file = ProjectFile::new(project.root().to_path_buf(), "Widget.java");
    let first = analyzer
        .analyzed_blobs()
        .into_iter()
        .find(|(path, _)| path == &file)
        .expect("analyzed file identity")
        .1;
    file.write("class Widget { void changed() {} }\n")
        .expect("edit source");
    let updated = analyzer.update(&BTreeSet::from([file.clone()]));
    let actual = updated
        .analyzed_blobs()
        .into_iter()
        .find(|(path, _)| path == &file)
        .expect("updated analyzed file identity")
        .1;
    let expected = git2::Oid::hash_object(
        git2::ObjectType::Blob,
        b"class Widget { void changed() {} }\n",
    )
    .expect("blob identity");
    assert_ne!(actual, first);
    assert_eq!(actual, expected);
}

#[test]
fn relational_identifier_request_records_identifier_index_read() {
    use brokk_bifrost_analysis::analyzer::read_ledger::{IndexFamily, ReadKey};
    use brokk_bifrost_core::analyzer::{
        DefinitionLanguageScope, RelationalDefinitionLookup, RelationalDefinitionQuery,
        RelationalDefinitionRequest, RelationalName,
    };

    let (_temp, project) = java_project(&[("Widget.java", "package demo; class Widget {}\n")]);
    let root = project.root().to_path_buf();
    let repo = git2::Repository::init(&root).expect("initialize Git");
    let mut index = repo.index().expect("Git index");
    index.add_path(std::path::Path::new("Widget.java")).unwrap();
    index.write().unwrap();
    let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
    let signature = git2::Signature::now("Bifrost test", "bifrost-test@example.invalid").unwrap();
    repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
        .unwrap();
    let analyzer = persisted_java_analyzer(Arc::clone(&project), &root.join("analyzer.db"));
    let widget = analyzer
        .get_all_declarations()
        .into_iter()
        .find(|unit| unit.identifier() == "Widget")
        .unwrap();
    let request = RelationalDefinitionRequest {
        ordinal: 0,
        language_scope: DefinitionLanguageScope::Language(Language::Java),
        name: RelationalName::stable(widget.fq().clone()),
        query: RelationalDefinitionQuery::Identifier { file: None },
    };
    let ledger = Arc::new(ReadLedger::new());
    let _scope = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&ledger));
    let outcome = RelationalDefinitionLookup::batch(
        &analyzer,
        &[request],
        &brokk_bifrost_analysis::CancellationToken::new(),
    );
    assert!(matches!(
        outcome,
        brokk_bifrost_core::analyzer::RelationalBatchOutcome::Complete(_)
    ));
    assert!(ledger.keys().iter().any(|key| matches!(
        key,
        ReadKey::Index {
            family: IndexFamily::DefinitionIdentifier,
            ..
        }
    )));
}
