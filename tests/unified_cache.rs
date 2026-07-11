#![cfg(feature = "nlp")]

use brokk_bifrost::analyzer::store::AnalyzerStore;
use brokk_bifrost::cache_db;
use brokk_bifrost::cache_gc;
use brokk_bifrost::nlp::store::{BlobChunkIn, SemanticStore};
use git2::{IndexAddOption, ObjectType, Oid, Repository, Signature};
use std::path::Path;

fn chunk(ord: i64, hash: [u8; 32], composed: [u8; 32]) -> BlobChunkIn<'static> {
    BlobChunkIn {
        chunk_ord: ord,
        kind: "function",
        symbol: Some("pkg.Symbol"),
        start_line: Some(ord),
        end_line: Some(ord + 1),
        fts_tokens: "pkg symbol",
        hash,
        parent_summary_hash: None,
        composed_hash: composed,
    }
}

fn init_repo(root: &Path) -> Repository {
    let repo = Repository::init(root).unwrap();
    {
        let mut config = repo.config().unwrap();
        config.set_str("user.email", "t@example.com").unwrap();
        config.set_str("user.name", "T").unwrap();
    }
    repo
}

fn commit_all(repo: &Repository, message: &str) {
    let mut index = repo.index().unwrap();
    index
        .add_all(["*"].iter(), IndexAddOption::DEFAULT, None)
        .unwrap();
    index.write().unwrap();
    let tree_id = index.write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    let sig = Signature::now("T", "t@example.com").unwrap();
    let parent = repo.head().ok().and_then(|head| head.peel_to_commit().ok());
    match parent {
        Some(parent) => {
            repo.commit(Some("HEAD"), &sig, &sig, message, &tree, &[&parent])
                .unwrap();
        }
        None => {
            repo.commit(Some("HEAD"), &sig, &sig, message, &tree, &[])
                .unwrap();
        }
    }
}

fn put_semantic(store: &SemanticStore, oid: Oid, composed: [u8; 32]) {
    store
        .upsert_component_vectors(&[([1; 32], vec![1.0, 0.0])])
        .unwrap();
    store
        .upsert_composed_vectors(&[(composed, vec![1.0, 0.0])])
        .unwrap();
    store
        .put_blob(
            &oid.to_string(),
            Some("python"),
            &[chunk(1, [1; 32], composed)],
        )
        .unwrap();
}

#[test]
fn family_scoped_invalidation_keeps_other_family_rows() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join(cache_db::CACHE_DB_FILE_NAME);
    let semantic = SemanticStore::open(&db_path).unwrap();
    let analyzer = AnalyzerStore::open_persistent(&db_path).unwrap();
    let semantic_oid = Oid::hash_object(ObjectType::Blob, b"semantic").unwrap();
    let java_oid = Oid::hash_object(ObjectType::Blob, b"java").unwrap();
    let python_oid = Oid::hash_object(ObjectType::Blob, b"python").unwrap();

    semantic
        .ensure_index_compatible("fp1", "chunker1", "bm251")
        .unwrap();
    put_semantic(&semantic, semantic_oid, [5; 32]);
    analyzer
        .ensure_language_epoch_value("java", "epoch-a")
        .unwrap();
    analyzer
        .ensure_language_epoch_value("python", "epoch-a")
        .unwrap();
    analyzer.register_blobs(&[java_oid], "java").unwrap();
    analyzer.register_blobs(&[python_oid], "python").unwrap();

    assert!(
        semantic
            .ensure_index_compatible("fp2", "chunker1", "bm251")
            .unwrap()
    );
    assert!(
        semantic
            .chunks_for_oids(&[semantic_oid.to_string()])
            .unwrap()
            .is_empty()
    );
    assert!(analyzer.contains_blob(java_oid, "java").unwrap());
    assert!(analyzer.contains_blob(python_oid, "python").unwrap());

    put_semantic(&semantic, semantic_oid, [6; 32]);
    analyzer
        .ensure_language_epoch_value("java", "epoch-b")
        .unwrap();
    assert!(!analyzer.contains_blob(java_oid, "java").unwrap());
    assert!(analyzer.contains_blob(python_oid, "python").unwrap());
    assert_eq!(
        semantic
            .chunks_for_oids(&[semantic_oid.to_string()])
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn gc_trigger_math_uses_combined_registry_growth() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("repo");
    std::fs::create_dir(&root).unwrap();
    let repo = init_repo(&root);
    let db_path = brokk_bifrost::gitblob::cache_db_path(&root);
    let analyzer = AnalyzerStore::open_for_workspace(&root).unwrap();
    let semantic = SemanticStore::open(&db_path).unwrap();
    let _tuning = cache_gc::set_tuning_for_test(2, 24 * 3600);
    cache_gc::set_accounting_for_test(&db_path, cache_db::now_unix_seconds(), 0).unwrap();

    let a = Oid::hash_object(ObjectType::Blob, b"a").unwrap();
    let b = Oid::hash_object(ObjectType::Blob, b"b").unwrap();
    analyzer.register_blobs(&[a, b], "python").unwrap();
    let skipped = cache_gc::maybe_gc_for_analyzer(&analyzer, &repo).unwrap();
    assert!(!skipped.ran);
    assert_eq!(cache_gc::total_blob_count_for_test(&db_path).unwrap(), 2);

    let c = Oid::hash_object(ObjectType::Blob, b"c").unwrap();
    put_semantic(&semantic, c, [7; 32]);
    let swept = cache_gc::maybe_gc_for_analyzer(&analyzer, &repo).unwrap();
    assert!(swept.ran);
    assert_eq!(swept.total_blobs_after, 0);
    assert_eq!(cache_gc::total_blob_count_for_test(&db_path).unwrap(), 0);
}

#[test]
fn first_unified_open_deletes_legacy_cache_files() {
    let temp = tempfile::tempdir().unwrap();
    let brokk = temp.path().join(".brokk");
    std::fs::create_dir(&brokk).unwrap();
    for name in [
        cache_db::LEGACY_SEMANTIC_DB_FILE_NAME,
        cache_db::LEGACY_ANALYZER_DB_FILE_NAME,
    ] {
        let connection = rusqlite::Connection::open(brokk.join(name)).unwrap();
        connection
            .execute_batch("CREATE TABLE legacy_cache(value TEXT) STRICT;")
            .unwrap();
    }

    let db_path = brokk.join(cache_db::CACHE_DB_FILE_NAME);
    let _store = AnalyzerStore::open_persistent(&db_path).unwrap();
    for name in [
        cache_db::LEGACY_SEMANTIC_DB_FILE_NAME,
        cache_db::LEGACY_ANALYZER_DB_FILE_NAME,
    ] {
        for suffix in ["", "-wal", "-shm"] {
            assert!(!brokk.join(format!("{name}{suffix}")).exists());
        }
    }
    assert!(db_path.exists());
}

#[test]
fn forced_gc_sweeps_both_families_in_one_pass() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("repo");
    std::fs::create_dir(&root).unwrap();
    let repo = init_repo(&root);
    let reachable_source = b"class Keep:\n    pass\n";
    std::fs::create_dir_all(root.join("pkg")).unwrap();
    std::fs::write(root.join("pkg/keep.py"), reachable_source).unwrap();
    commit_all(&repo, "keep");

    let reachable = Oid::hash_object(ObjectType::Blob, reachable_source).unwrap();
    let unreachable = Oid::hash_object(ObjectType::Blob, b"class Drop:\n    pass\n").unwrap();
    let db_path = brokk_bifrost::gitblob::cache_db_path(&root);
    let analyzer = AnalyzerStore::open_for_workspace(&root).unwrap();
    let semantic = SemanticStore::open(&db_path).unwrap();
    analyzer
        .register_blobs(&[reachable, unreachable], "python")
        .unwrap();
    put_semantic(&semantic, reachable, [8; 32]);
    put_semantic(&semantic, unreachable, [9; 32]);

    let outcome = cache_gc::force_gc_for_analyzer(&analyzer, &repo).unwrap();
    assert!(outcome.ran);
    assert!(analyzer.contains_blob(reachable, "python").unwrap());
    assert!(!analyzer.contains_blob(unreachable, "python").unwrap());
    assert_eq!(
        semantic
            .chunks_for_oids(&[reachable.to_string()])
            .unwrap()
            .len(),
        1
    );
    assert!(
        semantic
            .chunks_for_oids(&[unreachable.to_string()])
            .unwrap()
            .is_empty()
    );
}
