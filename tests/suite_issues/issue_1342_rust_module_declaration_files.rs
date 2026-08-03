//! A module's files are where it is defined, not where it is declared -- #1342.
//!
//! `resolve_module_files` extends its result with `definitions(resolved_module)`
//! filtered to module units. For an externally-declared module that unit is the
//! `pub mod svc;` item itself, which lives in the *declaring* file, so lib.rs
//! came back alongside svc.rs as if both backed the module's content. Every
//! consumer (import routing, module candidates) inherited the over-broad answer.
//!
//! The discriminator is structural, not positional: a bodiless `mod x;` item
//! forwards to a definition elsewhere, while `mod x { ... }` is the definition.
//! That is why the inline case below must keep resolving to its own file -- for
//! an inline module the declaring file genuinely is the defining file.
//!
//! Not covered, because it is not supported: `#[path = "other.rs"] mod svc;`.
//! Module-file resolution has no `#[path]` handling at all, so it never finds
//! other.rs -- measured before this change, `crate::svc` answered
//! `["src/lib.rs"]`, the declaring file and never the content file; it now
//! answers `[]`. Both are wrong about other.rs. This change only stops the
//! misleading non-empty answer; adding `#[path]` support is a separate piece of
//! work and no test here pins the current emptiness as desirable.

use crate::common::InlineTestProject;
use brokk_bifrost::{Language, ProjectFile, RustAnalyzer};

fn rel_paths(files: &[ProjectFile]) -> Vec<String> {
    files
        .iter()
        .map(|file| file.rel_path().to_string_lossy().replace('\\', "/"))
        .collect()
}

/// An external `pub mod svc;` resolves to the content file alone.
#[test]
fn external_module_resolves_to_its_content_file_only() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "pub mod consumer;\npub mod svc;\n")
        .file("src/svc.rs", "pub fn run() -> usize {\n    1\n}\n")
        .file(
            "src/consumer.rs",
            "use crate::svc;\n\npub fn call() -> usize {\n    svc::run()\n}\n",
        )
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    let consumer = project.file("src/consumer.rs");

    assert_eq!(
        rel_paths(&analyzer.resolve_module_files(&consumer, "crate::svc")),
        vec!["src/svc.rs".to_string()],
        "`crate::svc` is backed by svc.rs; lib.rs only declares it"
    );
    assert_eq!(
        rel_paths(&analyzer.resolve_module_files(&consumer, "svc")),
        vec!["src/svc.rs".to_string()],
        "the bare specifier must resolve the same way"
    );

    // Resolving from the declaring file itself is the same question: lib.rs
    // does not become a content file by being where the `mod` item sits.
    let lib = project.file("src/lib.rs");
    assert_eq!(
        rel_paths(&analyzer.resolve_module_files(&lib, "svc")),
        vec!["src/svc.rs".to_string()],
        "the declaring file must not list itself as its child module's content"
    );
}

/// An inline `mod svc { ... }` is defined where it is declared, so lib.rs is
/// the right and only answer. This is the case the fix must not break.
#[test]
fn inline_module_still_resolves_to_its_declaring_file() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            "pub mod consumer;\n\npub mod svc {\n    pub fn run() -> usize {\n        1\n    }\n}\n",
        )
        .file(
            "src/consumer.rs",
            "pub fn call() -> usize {\n    crate::svc::run()\n}\n",
        )
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    let consumer = project.file("src/consumer.rs");

    assert_eq!(
        rel_paths(&analyzer.resolve_module_files(&consumer, "crate::svc")),
        vec!["src/lib.rs".to_string()],
        "an inline module's defining file is the file holding its body"
    );
}

/// A `mod.rs`-backed directory module: the content lives in src/svc/mod.rs and
/// lib.rs still only declares it.
#[test]
fn directory_module_resolves_to_its_mod_file_only() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "pub mod consumer;\npub mod svc;\n")
        .file("src/svc/mod.rs", "pub fn run() -> usize {\n    1\n}\n")
        .file(
            "src/consumer.rs",
            "use crate::svc;\n\npub fn call() -> usize {\n    svc::run()\n}\n",
        )
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    let consumer = project.file("src/consumer.rs");

    let files = rel_paths(&analyzer.resolve_module_files(&consumer, "crate::svc"));
    assert!(
        !files.contains(&"src/lib.rs".to_string()),
        "the declaring file must not back a directory module: {files:?}"
    );
    assert!(
        files.contains(&"src/svc/mod.rs".to_string()),
        "the mod.rs content file must be resolved: {files:?}"
    );
}
