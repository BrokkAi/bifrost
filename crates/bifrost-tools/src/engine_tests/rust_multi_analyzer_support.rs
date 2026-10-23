use brokk_bifrost_analysis::analyzer::multi_analyzer::{AnalyzerDelegate, MultiAnalyzer};
use brokk_bifrost_analysis::analyzer::{FileSetProject, Language};
use std::collections::BTreeMap;
/// A two-language workspace on disk, as a `MultiAnalyzer` over real
/// per-language delegates.  The merged definition view is only meaningful
/// over delegates that actually hold declarations.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn two_language_analyzer() -> (tempfile::TempDir, MultiAnalyzer) {
    use brokk_bifrost_jvm_analysis::analyzer::JavaAnalyzer;

    use brokk_bifrost_rust_analysis::RustAnalyzer;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("src/App.java"),
        "package app;\npublic class App {}\n",
    )
    .unwrap();
    std::fs::write(root.join("src/lib.rs"), "pub struct Widget;\n").unwrap();
    std::fs::write(root.join("README.md"), "docs\n").unwrap();
    let project = FileSetProject::new(
        root,
        [
            std::path::PathBuf::from("src/App.java"),
            std::path::PathBuf::from("src/lib.rs"),
            std::path::PathBuf::from("README.md"),
        ],
    );
    let delegates = BTreeMap::from([
        (
            Language::Java,
            AnalyzerDelegate::new(JavaAnalyzer::from_project(project.clone())),
        ),
        (
            Language::Rust,
            AnalyzerDelegate::new(RustAnalyzer::from_project(project)),
        ),
    ]);
    (temp, MultiAnalyzer::new(delegates))
}
