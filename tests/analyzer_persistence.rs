use brokk_analyzer::{AnalyzerConfig, IAnalyzer, Language, ProjectFile, RustAnalyzer, TestProject};
use std::path::Path;
use std::sync::Arc;
use tempfile::tempdir;

fn persistent_config(cache_dir: &Path, analysis_epoch: u64) -> AnalyzerConfig {
    let mut config = AnalyzerConfig::default();
    config.parallelism = Some(1);
    config.persistence.cache_dir = Some(cache_dir.to_path_buf());
    config.persistence.analysis_epoch = analysis_epoch;
    config
}

fn rust_analyzer(root: &Path, cache_dir: &Path, analysis_epoch: u64) -> RustAnalyzer {
    RustAnalyzer::new_with_config(
        Arc::new(TestProject::new(root.to_path_buf(), Language::Rust)),
        persistent_config(cache_dir, analysis_epoch),
    )
}

fn rust_cache_file(cache_dir: &Path) -> std::path::PathBuf {
    cache_dir.join("rust.json")
}

#[test]
fn analyzer_persistence_hydrates_clean_file_payloads() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let cache_dir = root.join("cache");
    let file = ProjectFile::new(root.to_path_buf(), "lib.rs");
    file.write("pub fn foo() -> i32 { 1 }\n").unwrap();

    let initial = rust_analyzer(root, &cache_dir, 1);
    assert!(!initial.get_definitions("foo").is_empty());
    assert!(rust_cache_file(&cache_dir).exists());

    let raw_cache = std::fs::read_to_string(rust_cache_file(&cache_dir)).unwrap();
    std::fs::write(
        rust_cache_file(&cache_dir),
        raw_cache.replace("foo", "ghost"),
    )
    .unwrap();

    let hydrated = rust_analyzer(root, &cache_dir, 1);
    assert!(!hydrated.get_definitions("ghost").is_empty());
    assert!(hydrated.get_definitions("foo").is_empty());
}

#[test]
fn analyzer_persistence_reanalyzes_changed_files_and_removes_deleted_files() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let cache_dir = root.join("cache");
    let file = ProjectFile::new(root.to_path_buf(), "lib.rs");
    file.write("pub fn foo() -> i32 { 1 }\n").unwrap();

    let initial = rust_analyzer(root, &cache_dir, 1);
    assert!(!initial.get_definitions("foo").is_empty());

    file.write("pub fn bar() -> i32 { 2 }\n").unwrap();
    let changed = rust_analyzer(root, &cache_dir, 1);
    assert!(changed.get_definitions("foo").is_empty());
    assert!(!changed.get_definitions("bar").is_empty());

    std::fs::remove_file(file.abs_path()).unwrap();
    let deleted = rust_analyzer(root, &cache_dir, 1);
    assert!(deleted.get_definitions("bar").is_empty());
    assert_eq!(deleted.metrics().file_count, 0);
}

#[test]
fn analyzer_persistence_epoch_invalidates_clean_cache_rows() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let cache_dir = root.join("cache");
    let file = ProjectFile::new(root.to_path_buf(), "lib.rs");
    file.write("pub fn foo() -> i32 { 1 }\n").unwrap();

    let initial = rust_analyzer(root, &cache_dir, 1);
    assert!(!initial.get_definitions("foo").is_empty());

    let raw_cache = std::fs::read_to_string(rust_cache_file(&cache_dir)).unwrap();
    std::fs::write(
        rust_cache_file(&cache_dir),
        raw_cache.replace("foo", "ghost"),
    )
    .unwrap();

    let reparsed = rust_analyzer(root, &cache_dir, 2);
    assert!(!reparsed.get_definitions("foo").is_empty());
    assert!(reparsed.get_definitions("ghost").is_empty());
}

#[test]
fn analyzer_persistence_ignores_corrupt_cache_documents() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let cache_dir = root.join("cache");
    std::fs::create_dir_all(&cache_dir).unwrap();
    std::fs::write(rust_cache_file(&cache_dir), "not json").unwrap();
    let file = ProjectFile::new(root.to_path_buf(), "lib.rs");
    file.write("pub fn foo() -> i32 { 1 }\n").unwrap();

    let analyzer = rust_analyzer(root, &cache_dir, 1);
    assert!(!analyzer.get_definitions("foo").is_empty());

    let repaired_cache = std::fs::read_to_string(rust_cache_file(&cache_dir)).unwrap();
    assert!(repaired_cache.contains("\"schema_version\""));
}
