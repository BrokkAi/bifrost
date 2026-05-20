//! Regression tests for the analyzer-side parse-error cache that backs the
//! LSP diagnostic handler. See issue #102 + PR #101 review.

use brokk_analyzer::analyzer::persistence::AnalyzerStorage;
use brokk_analyzer::{
    AnalyzerConfig, IAnalyzer, Language, ParseErrorKind, ProjectFile, PythonAnalyzer, TestProject,
};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn write_file(root: &Path, rel: &str, body: &str) {
    let abs = root.join(rel);
    if let Some(parent) = abs.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&abs, body).unwrap();
}

fn project_file(root: &Path, rel: &str) -> ProjectFile {
    ProjectFile::new(root.to_path_buf(), PathBuf::from(rel))
}

#[test]
fn analyzer_caches_parse_errors_during_analyze_file() {
    // A Python file with a stray closing paren — tree-sitter flags an ERROR
    // node. The analyzer should capture that during `analyze_file` and expose
    // it via `parse_errors` without requiring a follow-up parse.
    let tmp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(tmp.path()).unwrap();
    write_file(&root, "broken.py", "def x():\n    return 1)\n");
    let project = Arc::new(TestProject::new(root.clone(), Language::Python));

    let analyzer = PythonAnalyzer::new_with_config(
        project as Arc<dyn brokk_analyzer::Project>,
        AnalyzerConfig::default(),
    );
    let file = project_file(&root, "broken.py");
    let errors = analyzer
        .parse_errors(&file)
        .expect("analyzer should hold state for broken.py");
    assert!(
        !errors.is_empty(),
        "broken.py should produce at least one parse error, got {errors:?}"
    );
}

#[test]
fn analyzer_returns_empty_vec_for_cleanly_parsed_file() {
    // The cache distinguishes "analyzer has authoritative info (clean)" from
    // "analyzer has no info" via `Some(vec)` vs `None`. A cleanly parsed file
    // must return `Some(empty)` so the diagnostic handler skips fallback
    // parsing.
    let tmp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(tmp.path()).unwrap();
    write_file(&root, "clean.py", "def x():\n    return 1\n");
    let project = Arc::new(TestProject::new(root.clone(), Language::Python));

    let analyzer = PythonAnalyzer::new_with_config(
        project as Arc<dyn brokk_analyzer::Project>,
        AnalyzerConfig::default(),
    );
    let file = project_file(&root, "clean.py");
    let errors = analyzer
        .parse_errors(&file)
        .expect("analyzer should hold state for clean.py");
    assert!(
        errors.is_empty(),
        "clean.py should produce zero parse errors, got {errors:?}"
    );
}

#[test]
fn analyzer_returns_none_for_unanalyzed_file() {
    // Outside the analyzer's language set → no FileState → `parse_errors`
    // returns None so the diagnostic handler falls back to a fresh parse.
    let tmp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(tmp.path()).unwrap();
    write_file(&root, "lib.py", "def x(): pass\n");
    let project = Arc::new(TestProject::new(root.clone(), Language::Python));

    let analyzer = PythonAnalyzer::new_with_config(
        project as Arc<dyn brokk_analyzer::Project>,
        AnalyzerConfig::default(),
    );
    // A path the analyzer never indexed.
    let phantom = project_file(&root, "phantom.py");
    assert!(
        analyzer.parse_errors(&phantom).is_none(),
        "unanalyzed file must return None"
    );
}

#[test]
fn parse_error_kind_distinguishes_error_vs_missing() {
    // Tree-sitter MISSING nodes encode the expected token in `node.kind()` —
    // verify our ParseErrorKind preserves that string so the diagnostic
    // message reads "missing X" instead of "syntax error".
    let tmp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(tmp.path()).unwrap();
    // Unclosed parenthesis — tree-sitter typically reports a MISSING node for
    // the closing token.
    write_file(&root, "missing.py", "def x(\n");
    let project = Arc::new(TestProject::new(root.clone(), Language::Python));

    let analyzer = PythonAnalyzer::new_with_config(
        project as Arc<dyn brokk_analyzer::Project>,
        AnalyzerConfig::default(),
    );
    let file = project_file(&root, "missing.py");
    let errors = analyzer
        .parse_errors(&file)
        .expect("analyzer should hold state for missing.py");
    assert!(
        !errors.is_empty(),
        "missing.py should produce at least one parse error, got {errors:?}"
    );
    // Mix of ERROR and MISSING is grammar-dependent; just assert both kinds
    // round-trip through the enum correctly when they appear.
    for err in &errors {
        match &err.kind {
            ParseErrorKind::Error => {}
            ParseErrorKind::Missing(kind) => {
                assert!(
                    !kind.is_empty(),
                    "MISSING node should carry a non-empty kind, got {err:?}"
                );
            }
        }
    }
}

#[test]
fn hydrated_baseline_returns_none_so_diagnostic_falls_back() {
    // Persistence does NOT carry parse_errors across sessions — the
    // diagnostic handler's `Some(empty) = clean` / `None = unknown`
    // distinction is what keeps a hydrated session from silently reporting
    // "no errors" on every file. If someone later persists parse_errors
    // thinking it's a free win, they invalidate the fallback contract and
    // hydrated files would mis-report cleanly. This test pins the contract.
    let tmp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(tmp.path()).unwrap();
    write_file(&root, "broken.py", "def x():\n    return 1)\n");
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("analyzer.db");

    // Cold start: writes a baseline row that captures everything except
    // parse_errors.
    {
        let storage = Arc::new(AnalyzerStorage::open(&db_path).unwrap());
        let project = Arc::new(TestProject::new(root.clone(), Language::Python));
        let analyzer = PythonAnalyzer::new_with_config_and_storage(
            project as Arc<dyn brokk_analyzer::Project>,
            AnalyzerConfig::default(),
            storage,
        );
        let file = project_file(&root, "broken.py");
        // Sanity: the cold-start analyzer DID populate parse_errors.
        let errors = analyzer
            .parse_errors(&file)
            .expect("cold-start analyzer should hold parse_errors");
        assert!(
            !errors.is_empty(),
            "cold-start parse_errors should reflect the broken file"
        );
    }

    // Warm start: a fresh analyzer reusing the same DB hydrates from the
    // baseline without re-parsing. `parse_errors` must return None so the
    // diagnostic handler knows to fall back to a fresh parse.
    let storage = Arc::new(AnalyzerStorage::open(&db_path).unwrap());
    let project = Arc::new(TestProject::new(root.clone(), Language::Python));
    let analyzer = PythonAnalyzer::new_with_config_and_storage(
        project as Arc<dyn brokk_analyzer::Project>,
        AnalyzerConfig::default(),
        storage,
    );
    let file = project_file(&root, "broken.py");
    assert!(
        analyzer.parse_errors(&file).is_none(),
        "hydrated baseline must return None so diagnostic falls back to fresh parse"
    );
}

#[test]
fn parse_errors_refresh_on_update() {
    // After `update`, the cached parse_errors must reflect the latest content
    // — proves the LSP didChange path actually refreshes errors instead of
    // serving stale ones from the previous parse.
    let tmp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(tmp.path()).unwrap();
    let rel = "evolving.py";
    write_file(&root, rel, "def x():\n    return 1)\n"); // starts broken
    let project = Arc::new(TestProject::new(root.clone(), Language::Python));

    let analyzer = PythonAnalyzer::new_with_config(
        project as Arc<dyn brokk_analyzer::Project>,
        AnalyzerConfig::default(),
    );
    let file = project_file(&root, rel);
    let before = analyzer
        .parse_errors(&file)
        .expect("analyzer should hold state");
    assert!(
        !before.is_empty(),
        "initial parse should report errors, got {before:?}"
    );

    // Rewrite the file with clean Python and re-trigger analysis.
    fs::write(root.join(rel), "def x():\n    return 1\n").unwrap();
    let mut changed = BTreeSet::new();
    changed.insert(file.clone());
    let updated = analyzer.update(&changed);
    let after = updated
        .parse_errors(&file)
        .expect("analyzer should still hold state after update");
    assert!(
        after.is_empty(),
        "post-update analyzer must reflect clean content, got {after:?}"
    );
}
