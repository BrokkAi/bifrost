use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;
use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;
use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::{
    DirtyFileStateStatus, FORCED_PARSE_TIMEOUT_PATHS, TreeSitterAnalyzer, store_context_from_store,
};
use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
use brokk_bifrost_core::analyzer::config::AnalyzerConfig;
use brokk_bifrost_core::analyzer::model::{Language, ProjectFile};
use brokk_bifrost_core::analyzer::project::{OverlayProject, Project, TestProject};
use brokk_bifrost_cpp_analysis::analyzer::cpp::adapter::CppAdapter;
use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

struct ForcedParseTimeoutPathsGuard(Vec<PathBuf>);

impl ForcedParseTimeoutPathsGuard {
    fn push(paths: impl IntoIterator<Item = PathBuf>) -> Self {
        let paths = paths.into_iter().collect::<Vec<_>>();
        FORCED_PARSE_TIMEOUT_PATHS
            .lock()
            .expect("forced parse timeout paths mutex poisoned")
            .extend(paths.iter().cloned());
        Self(paths)
    }
}

impl Drop for ForcedParseTimeoutPathsGuard {
    fn drop(&mut self) {
        FORCED_PARSE_TIMEOUT_PATHS
            .lock()
            .expect("forced parse timeout paths mutex poisoned")
            .retain(|path| !self.0.contains(path));
    }
}

#[test]
fn incremental_java_file_states_match_fresh_builds_after_multi_file_edits() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    let first = ProjectFile::new(root.clone(), "src/First.java");
    let second = ProjectFile::new(root.clone(), "src/Second.java");
    first
        .write("package before; class First {}\n")
        .expect("first initial source");
    second
        .write("package before; class Second {}\n")
        .expect("second initial source");

    let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
    let repo = git2::Repository::init(&root).expect("Git repository");
    let mut git_index = repo.index().expect("Git index");
    git_index
        .add_path(std::path::Path::new("src/First.java"))
        .unwrap();
    git_index
        .add_path(std::path::Path::new("src/Second.java"))
        .unwrap();
    git_index.write().expect("write initial Git index");
    let tree_oid = git_index.write_tree().expect("initial Git tree");
    let tree = repo.find_tree(tree_oid).expect("initial tree");
    let signature = git2::Signature::now("Bifrost test", "bifrost-test@example.invalid")
        .expect("Git test signature");
    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        "initial sources",
        &tree,
        &[],
    )
    .expect("initial commit");

    let db = root.join("analyzer.db");
    let store = AnalyzerStore::open_persistent(&db).expect("persistent store");
    let context = store_context_from_store(project.as_ref(), store, false);
    let analyzer = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
        Arc::clone(&project),
        JavaAdapter,
        AnalyzerConfig::default(),
        context,
        None,
    )
    .expect("initial persisted analyzer");
    let initial_names = analyzer
        .get_all_declarations()
        .into_iter()
        .map(|unit| unit.fq_name())
        .collect::<Vec<_>>();
    assert!(initial_names.iter().any(|name| name.ends_with("First")));
    assert!(initial_names.iter().any(|name| name.ends_with("Second")));

    first
        .write("package after.one; class FirstUpdated {}\n")
        .expect("first updated source");
    second
        .write("package after.two; class SecondUpdated {}\n")
        .expect("second updated source");
    git_index
        .add_path(std::path::Path::new("src/First.java"))
        .expect("stage first edit");
    git_index
        .add_path(std::path::Path::new("src/Second.java"))
        .expect("stage second edit");
    git_index.write().expect("write edited Git index");
    drop(analyzer);
    let reopened_store = AnalyzerStore::open_persistent(&db).expect("reopen store");
    let reopened_context = store_context_from_store(project.as_ref(), reopened_store, false);
    let reopened = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
        Arc::clone(&project),
        JavaAdapter,
        AnalyzerConfig::default(),
        reopened_context,
        None,
    )
    .expect("reopened persisted analyzer");
    let changed = BTreeSet::from([first.clone(), second.clone()]);
    let incremental = reopened.update(&changed);
    let fresh = TreeSitterAnalyzer::new(
        Arc::new(TestProject::new(&root, Language::Java)),
        JavaAdapter,
    );

    let mut incremental_names = incremental
        .get_all_declarations()
        .into_iter()
        .map(|unit| unit.fq_name())
        .collect::<Vec<_>>();
    let mut fresh_names = fresh
        .get_all_declarations()
        .into_iter()
        .map(|unit| unit.fq_name())
        .collect::<Vec<_>>();
    incremental_names.sort();
    fresh_names.sort();
    assert_eq!(incremental_names, fresh_names);
    assert!(
        incremental_names
            .iter()
            .any(|name| name.ends_with("FirstUpdated"))
    );
    assert!(
        incremental_names
            .iter()
            .any(|name| name.ends_with("SecondUpdated"))
    );
    assert!(!incremental_names.iter().any(|name| name.ends_with("First")));
    assert!(
        !incremental_names
            .iter()
            .any(|name| name.ends_with("Second"))
    );
}

#[test]
fn updating_one_dirty_java_file_retains_other_dirty_file_state() {
    let fixture = crate::inline_project::InlineTestProject::with_language(Language::Java)
        .file("First.java", "class First {}\n")
        .file("Second.java", "class Second {}\n")
        .build();
    let first = fixture.file("First.java");
    let second = fixture.file("Second.java");
    let timeout_paths = ForcedParseTimeoutPathsGuard::push([first.abs_path(), second.abs_path()]);
    let timed_out = TreeSitterAnalyzer::new(fixture.project_dyn(), JavaAdapter);
    drop(timeout_paths);
    assert_eq!(timed_out.state.dirty_snapshot().len(), 2);

    let updated = timed_out.update(&BTreeSet::from([first.clone()]));
    let remaining = updated
        .state
        .dirty_snapshot()
        .into_keys()
        .map(|key| key.rel_path)
        .collect::<Vec<_>>();
    assert_eq!(remaining, [second.rel_path().to_path_buf()]);
}

#[test]
fn persisted_cpp_imports_survive_a_missing_earlier_frontier_oid() {
    let fixture = crate::inline_project::InlineTestProject::with_language(Language::Cpp)
        .file("a_deleted.cpp", "int gone() { return 0; }\n")
        .file(
            "main.cpp",
            "#include \"claimed_header\"\nint main() { return Included::value; }\n",
        )
        .file(
            "claimed_header",
            "struct Included { static constexpr int value = 1; };\n",
        )
        .build();
    let project = fixture.project_dyn();
    let deleted = fixture.file("a_deleted.cpp");
    let main = fixture.file("main.cpp");
    let header = fixture.file("claimed_header");
    let db = fixture.root().join("analyzer.db");
    let store = AnalyzerStore::open_persistent(&db).expect("persistent C++ store");
    let context = store_context_from_store(project.as_ref(), store, false);
    let analyzer = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
        Arc::clone(&project),
        CppAdapter,
        AnalyzerConfig::default(),
        context,
        None,
    )
    .expect("initial C++ analyzer");
    let initial = analyzer.get_all_declarations();
    assert!(initial.iter().any(|unit| unit.source() == &header));
    drop(analyzer);

    let reopened_store = AnalyzerStore::open_persistent(&db).expect("reopen C++ store");
    let reopened_context = store_context_from_store(project.as_ref(), reopened_store, false);
    let reopened = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
        Arc::clone(&project),
        CppAdapter,
        AnalyzerConfig::default(),
        reopened_context,
        None,
    )
    .expect("reopened C++ analyzer");
    let stored = reopened
        .fetch_file_state(&main)
        .expect("stored main.cpp state");
    assert!(
        stored
            .imports
            .iter()
            .any(|import| import.raw_snippet.contains("claimed_header")),
        "reopened store supplies the .cpp include import fact"
    );

    std::fs::remove_file(deleted.abs_path()).expect("delete earlier frontier source");
    let updated = reopened.update(&BTreeSet::from([deleted, main]));
    let declarations = updated.get_all_declarations();
    assert!(
        declarations.iter().any(|unit| unit.source() == &header),
        "the later valid .cpp import still claims the extensionless header"
    );
}

#[test]
fn canonical_empty_java_source_is_reusable_from_the_file_state_cache() {
    let fixture = crate::inline_project::InlineTestProject::with_language(Language::Java)
        .file("Empty.java", "")
        .build();
    let file = fixture.file("Empty.java");
    let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), JavaAdapter);
    let state = analyzer
        .fetch_file_state(&file)
        .expect("empty source state");
    assert_eq!(state.source, "");
    assert!(
        state.source_facts.is_some(),
        "empty Java source has canonical facts"
    );

    let cached = analyzer.cached_canonical_source_state(&file, "");
    assert!(cached.is_some(), "an empty exact source remains cacheable");
}

#[test]
fn transient_disk_parse_is_not_published_as_an_overlay() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    let seed = ProjectFile::new(root.clone(), "Seed.java");
    seed.write("class Seed {}\n").expect("seed source");
    let repo = git2::Repository::init(&root).expect("Git repository");
    let mut index = repo.index().expect("Git index");
    index
        .add_path(std::path::Path::new("Seed.java"))
        .expect("add seed");
    index.write().expect("write index");
    let tree_oid = index.write_tree().expect("write tree");
    let tree = repo.find_tree(tree_oid).expect("tree");
    let signature = git2::Signature::now("Bifrost test", "bifrost-test@example.invalid")
        .expect("Git test signature");
    repo.commit(Some("HEAD"), &signature, &signature, "seed", &tree, &[])
        .expect("commit seed");

    let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
    let analyzer = TreeSitterAnalyzer::new(Arc::clone(&project), JavaAdapter);
    let late = ProjectFile::new(root, "Late.java");
    late.write("class Late {}\n").expect("late source");
    assert_eq!(
        analyzer
            .fetch_file_state(&late)
            .expect("transient state")
            .source,
        "class Late {}\n"
    );

    let snapshot = analyzer.live_path_snapshot();
    assert!(!snapshot.is_overlay_path(&late));
}

#[test]
fn transient_filesystem_identity_is_invalidated_after_an_out_of_band_edit() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    let seed = ProjectFile::new(root.clone(), "Seed.java");
    seed.write("class Seed {}\n").expect("seed source");
    let repo = git2::Repository::init(&root).expect("Git repository");
    let mut index = repo.index().expect("Git index");
    index
        .add_path(std::path::Path::new("Seed.java"))
        .expect("add seed");
    index.write().expect("write index");
    let tree_oid = index.write_tree().expect("write tree");
    let tree = repo.find_tree(tree_oid).expect("tree");
    let signature = git2::Signature::now("Bifrost test", "bifrost-test@example.invalid")
        .expect("Git test signature");
    repo.commit(Some("HEAD"), &signature, &signature, "seed", &tree, &[])
        .expect("commit seed");

    let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
    let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);
    let late = ProjectFile::new(root, "Late.java");
    late.write("class Late {}\n").expect("late source");
    assert_eq!(
        analyzer.fetch_file_state(&late).unwrap().source,
        "class Late {}\n"
    );
    let old_oid = analyzer
        .live_path_snapshot()
        .oid_for_path(&late)
        .expect("transient parse identity");
    assert!(!analyzer.live_path_snapshot().is_overlay_path(&late));

    late.write("class LateUpdated {}\n")
        .expect("out-of-band edit");
    assert_eq!(
        analyzer.live_path_snapshot().reusable_oid_for_path(&late),
        Some(old_oid),
        "the generation keeps its identity until an explicit update"
    );
    let updated = analyzer.update(&BTreeSet::from([late.clone()]));
    assert_ne!(
        updated.resolve_live_oid_for_file(&late),
        Some(old_oid),
        "the explicit update advances the live identity to replacement bytes"
    );
}

#[test]
fn source_snapshot_with_a_different_oid_does_not_supply_bytes_for_the_old_blob() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    let file = ProjectFile::new(root.clone(), "Broken.java");
    file.write("\0").expect("binary source");
    let repo = git2::Repository::init(&root).expect("Git repository");
    let mut index = repo.index().expect("Git index");
    index
        .add_path(std::path::Path::new("Broken.java"))
        .expect("add binary source");
    index.write().expect("write index");
    let tree_oid = index.write_tree().expect("write tree");
    let tree = repo.find_tree(tree_oid).expect("tree");
    let signature = git2::Signature::now("Bifrost test", "bifrost-test@example.invalid")
        .expect("Git test signature");
    repo.commit(Some("HEAD"), &signature, &signature, "binary", &tree, &[])
        .expect("commit binary");
    let old_oid = git2::Oid::hash_object(git2::ObjectType::Blob, b"\0").unwrap();

    let base: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
    let overlay = Arc::new(OverlayProject::new(base));
    assert!(overlay.set(file.abs_path(), "class Replacement {}\n".to_owned()));
    let project: Arc<dyn Project> = Arc::new(overlay.snapshot());
    let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);

    // The old identity resolves to its own Git blob bytes; NUL-bearing UTF-8
    // decodes exactly since #4479, and admission still refuses it below.
    assert_eq!(
        analyzer.source_for_oid(&file, old_oid).as_deref(),
        Some("\0"),
        "replacement overlay bytes cannot satisfy the old blob identity"
    );
    assert!(
        analyzer.record_structure_unavailable_if_unparseable(&file, old_oid),
        "the old binary blob is not made parseable by the replacement overlay"
    );
}

#[test]
fn conflicted_git_index_entry_does_not_supply_a_live_file_oid() {
    let temp = tempfile::tempdir().expect("temporary workspace");
    let root = temp
        .path()
        .canonicalize()
        .expect("canonical workspace root");
    let file = ProjectFile::new(root.clone(), "Conflict.java");
    file.write("class Conflict {}\n").expect("source");
    let repo = git2::Repository::init(&root).expect("Git repository");
    let mut index = repo.index().expect("Git index");
    index
        .add_path(std::path::Path::new("Conflict.java"))
        .expect("stage source");
    index.write().expect("write staged source");
    let mut staged = index
        .get_path(std::path::Path::new("Conflict.java"), 0)
        .expect("stage zero entry");
    index
        .remove_path(std::path::Path::new("Conflict.java"))
        .expect("remove stage zero");
    for stage in 1..=3 {
        staged.flags = (staged.flags & !0x3000) | (stage << 12);
        index.add(&staged).expect("add conflict stage");
    }
    index.write().expect("write conflicted index");
    assert!(index.has_conflicts());
    assert!(
        index
            .get_path(std::path::Path::new("Conflict.java"), 0)
            .is_none()
    );
    assert!(
        index
            .get_path(std::path::Path::new("Conflict.java"), 1)
            .is_some()
    );
    std::fs::remove_file(file.abs_path()).expect("remove working-tree source");

    let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
    let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);

    assert_eq!(
        analyzer.resolve_live_oid_for_file(&file),
        None,
        "a conflict-stage blob is not a live stage-zero file identity"
    );
}

#[test]
fn location_declarations_follow_live_source_after_an_indexed_edit() {
    let temp = tempfile::tempdir().expect("temporary workspace");
    let root = temp
        .path()
        .canonicalize()
        .expect("canonical workspace root");
    let file = ProjectFile::new(root.clone(), "Changed.java");
    file.write("class BeforeEdit {}\n").expect("initial source");
    let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
    let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);
    assert!(
        analyzer
            .location_declarations(&file)
            .iter()
            .any(|unit| unit.identifier() == "BeforeEdit")
    );

    file.write("class AfterEdit {}\n").expect("edited source");

    let declarations = analyzer.location_declarations(&file);
    assert!(
        declarations
            .iter()
            .any(|unit| unit.identifier() == "AfterEdit"),
        "source-derived location declarations must override the indexed state: {declarations:?}"
    );
    assert!(
        declarations
            .iter()
            .all(|unit| unit.identifier() != "BeforeEdit"),
        "stale indexed declarations must not survive: {declarations:?}"
    );
}

#[test]
fn retryable_parse_complete_state_reparses_retained_source_and_publishes() {
    let temp = tempfile::tempdir().expect("temporary workspace");
    let root = temp
        .path()
        .canonicalize()
        .expect("canonical workspace root");
    let file = ProjectFile::new(root.clone(), "Retry.java");
    file.write("package demo; class Retryable {}\n")
        .expect("source");
    let db = root.join("analyzer.db");
    let store = AnalyzerStore::open_persistent(&db).expect("persistent store");
    store
        .conn
        .execute(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER reject_parsed_blob
                 BEFORE INSERT ON blobs
                 BEGIN SELECT RAISE(ABORT, 'injected parsed blob failure'); END;",
            )?;
            Ok::<_, brokk_bifrost_analysis::analyzer::store::StoreError>(())
        })
        .expect("install parsed-blob failure trigger");

    let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
    let context = store_context_from_store(project.as_ref(), store, false);
    let analyzer = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
        Arc::clone(&project),
        JavaAdapter,
        AnalyzerConfig::default(),
        context,
        None,
    )
    .expect("analyzer retains source after the injected write failure");
    let dirty = analyzer.state.dirty_snapshot();
    let (key, dirty_state) = dirty
        .iter()
        .find(|(key, _)| key.rel_path == file.rel_path())
        .expect("failed publication leaves this file dirty");
    assert_eq!(dirty_state.status, DirtyFileStateStatus::Retryable);
    assert!(dirty_state.state.parse_complete);
    let key = key.clone();

    analyzer
        .store_context
        .store
        .conn
        .execute(|conn| {
            conn.execute_batch("DROP TRIGGER reject_parsed_blob")?;
            Ok::<_, brokk_bifrost_analysis::analyzer::store::StoreError>(())
        })
        .expect("remove failure trigger");
    let mut retried = None;
    for _ in 0..10 {
        std::thread::sleep(std::time::Duration::from_millis(600));
        let state = analyzer
            .retry_dirty_file_state(&key, "java")
            .expect("retry returns retained file state");
        if !analyzer.state.dirty_snapshot().contains_key(&key) {
            retried = Some(state);
            break;
        }
    }
    let retried = retried.expect("retryable parse-complete state is eventually published");
    assert!(retried.parse_complete);
    assert!(
        retried
            .declarations
            .iter()
            .any(|unit| unit.identifier() == "Retryable")
    );
    let remaining_dirty = analyzer.state.dirty_snapshot();
    assert!(
        !remaining_dirty.contains_key(&key),
        "successful retry removes its dirty source: {remaining_dirty:?}"
    );
    assert!(
        analyzer
            .store_context
            .store
            .contains_parsed_blob(&brokk_bifrost_core::gitblob::BlobKey::unvaried(
                key.oid, "java"
            ))
            .expect("check retried publication")
    );
}
