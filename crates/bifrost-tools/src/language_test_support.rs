//! Fixture constructors that assemble JVM analyzers above the engine.
use brokk_bifrost_analysis::analyzer::{
    AnalyzerDelegate, FileSetProject, Language, MultiAnalyzer, TestProject,
};
use std::collections::BTreeMap;
use std::path::Path;

/// A two-language workspace on disk, as a `MultiAnalyzer` over real
/// per-language delegates.  The merged definition view is only meaningful
/// over delegates that actually hold declarations.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn two_language_analyzer() -> (tempfile::TempDir, MultiAnalyzer) {
    use brokk_bifrost_jvm_analysis::JavaAnalyzer;
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

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn java_analyzer(root: &Path) -> brokk_bifrost_jvm_analysis::analyzer::JavaAnalyzer {
    use brokk_bifrost_jvm_analysis::analyzer::JavaAnalyzer;

    JavaAnalyzer::from_project(TestProject::new(root.to_path_buf(), Language::Java))
}

use brokk_bifrost_analysis::analyzer::ProjectFile;
use brokk_bifrost_jvm_analysis::analyzer::{JavaAnalyzer, KotlinAnalyzer, ScalaAnalyzer};
use std::sync::Arc;

/// A persisted multi-language workspace, analyzed twice so the second
/// analyzer reads the same cache-backed summary projections a warm real
/// workspace reads.
#[doc(hidden)]
pub fn persisted_multilanguage_analyzer(root: std::path::PathBuf) -> MultiAnalyzer {
    ProjectFile::new(root.clone(), "module-info.java")
        .write("module example.module {}\n")
        .unwrap();
    ProjectFile::new(root.clone(), "app/Greeter.java")
            .write(
                "package app;\n\npublic class Greeter {\n    public String greet() { return \"hi\"; }\n}\n",
            )
            .unwrap();
    // Scala indexes the anonymous class as a synthetic owner and its `run`
    // as an ordinary declaration, and the Scala summary wrapper prunes
    // synthetic entries out of `children`. So `run` is reachable only
    // through the persisted declaration inventory (#2992).
    ProjectFile::new(root.clone(), "app/Service.scala")
            .write(
                "package app\n\nclass Service {\n  def task(): Runnable = new Runnable {\n    def run(): Unit = println(\"scala\")\n  }\n}\n",
            )
            .unwrap();
    // The Kotlin declaration tier deliberately does not index members of an
    // anonymous object, so this file has no equivalent hidden `run`. It is
    // here so the Kotlin summary wrapper's synthetic pruning is covered by
    // the exact-equality check below.
    ProjectFile::new(root.clone(), "app/Task.kt")
            .write(
                "package app\n\nclass Task(private val label: String) {\n    fun make(): Runnable = object : Runnable {\n        override fun run() {}\n    }\n}\n",
            )
            .unwrap();
    ProjectFile::new(root.clone(), "app/Caller.kt")
        .write("package app\n\nclass Caller {\n    fun call(): String = Greeter().greet()\n}\n")
        .unwrap();

    let project = TestProject::new(root, Language::Java);
    let make_analyzer = || {
        MultiAnalyzer::new(BTreeMap::from([
            (
                Language::Java,
                AnalyzerDelegate::new(JavaAnalyzer::new(Arc::new(project.clone()))),
            ),
            (
                Language::Scala,
                AnalyzerDelegate::new(ScalaAnalyzer::new(Arc::new(project.clone()))),
            ),
            (
                Language::Kotlin,
                AnalyzerDelegate::new(KotlinAnalyzer::new(Arc::new(project.clone()))),
            ),
        ]))
    };
    // The first generation persists the fixture. The second exercises the
    // same cache-backed summary projections used by a warm real workspace.
    drop(make_analyzer());
    make_analyzer()
}
