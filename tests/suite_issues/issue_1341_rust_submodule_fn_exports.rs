//! A `pub fn` in a named submodule is an export — issue #1341.
//!
//! `is_module_export_candidate` ended with
//! `!code_unit.is_function() || self.parent_of(code_unit).is_none()`. The
//! ancestry loop above it already rejects any declaration whose owner chain is
//! not an unbroken run of export-visible modules, so a method or associated
//! function never reached that line; all it actually excluded was the
//! module-level free function -- the very thing `pub mod svc;` exists to
//! publish. These pin the corrected reading: candidacy is decided by the
//! owner chain's kinds, not by whether an owner exists at all.

use crate::common::{InlineTestProject, call_search_tool_json};
use brokk_bifrost::CodeUnitIndex;
use brokk_bifrost::usages::UsageFinder;
use brokk_bifrost::{Language, RustAnalyzer};
use serde_json::json;

/// `lib.rs: pub mod svc;` plus a submodule holding one of each shape whose
/// candidacy the guard decides: a free function, a non-callable sibling, an
/// inherent method, and an associated function.
fn submodule_project() -> crate::common::BuiltInlineTestProject {
    InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "pub mod svc;\n")
        .file(
            "src/svc.rs",
            "pub const LIMIT: usize = 4;\n\
             \n\
             pub fn run() -> usize {\n    LIMIT\n}\n\
             \n\
             pub struct Runner;\n\
             \n\
             impl Runner {\n    \
             pub fn new() -> Self {\n        Runner\n    }\n\n    \
             pub fn step(&self) -> usize {\n        LIMIT\n    }\n}\n",
        )
        .build()
}

fn export_names(project: &crate::common::BuiltInlineTestProject, rel_path: &str) -> Vec<String> {
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    let index = analyzer.export_index_of(&project.file(rel_path));
    let mut names: Vec<_> = index.exports_by_name.keys().cloned().collect();
    names.sort();
    names
}

/// The repro from the issue, plus the three shapes that must be unaffected.
#[test]
fn submodule_free_function_is_an_export_candidate() {
    let project = submodule_project();
    let names = export_names(&project, "src/svc.rs");

    assert!(
        names.contains(&"run".to_string()),
        "a `pub fn` in a `pub mod svc;` submodule must be exported: {names:?}"
    );
    assert!(
        names.contains(&"LIMIT".to_string()),
        "the non-callable sibling must still be exported: {names:?}"
    );
    assert!(
        names.contains(&"Runner".to_string()),
        "the struct must still be exported: {names:?}"
    );
    // Methods and associated functions are reached through their type, never as
    // a module export: their owner chain leaves the module kinds immediately.
    assert!(
        !names.contains(&"step".to_string()),
        "an inherent method must not be a module export: {names:?}"
    );
    assert!(
        !names.contains(&"new".to_string()),
        "an associated function must not be a module export: {names:?}"
    );
}

/// A crate-root free function was already a candidate (no owner at all) and
/// stays one, so the fix is an addition rather than a swap.
#[test]
fn crate_root_free_function_is_still_an_export_candidate() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            "pub fn top() -> usize {\n    1\n}\n\npub const TOP: usize = 1;\n",
        )
        .build();
    let names = export_names(&project, "src/lib.rs");
    assert_eq!(
        names,
        vec!["TOP".to_string(), "top".to_string()],
        "a crate-root free function and const are both exports: {names:?}"
    );
}

/// A private submodule's function stays out: the ancestry loop, not the deleted
/// trailing guard, is what enforces visibility, and the fix must not weaken it.
///
/// Only the function is asserted. A package-level `const` is indexed under the
/// synthetic `_module_` scope segment and has no owner unit at all, so the
/// ancestry loop never runs for it and `BURIED` is listed here regardless of
/// `mod hidden;` being private. That is a separate pre-existing gap in how
/// `_module_`-scoped declarations get their owner, untouched by #1341.
#[test]
fn private_submodule_function_is_not_an_export_candidate() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "mod hidden;\n")
        .file(
            "src/hidden.rs",
            "pub fn buried() -> usize {\n    1\n}\n\npub const BURIED: usize = 1;\n",
        )
        .build();
    let names = export_names(&project, "src/hidden.rs");
    assert!(
        !names.contains(&"buried".to_string()),
        "a function under a private `mod hidden;` is not a crate export: {names:?}"
    );
}

/// An inline `mod svc { ... }` publishes its free functions the same way a
/// file-backed one does; the deleted guard rejected both.
#[test]
fn inline_submodule_free_function_is_an_export_candidate() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            "pub mod svc {\n    pub fn run() -> usize {\n        1\n    }\n\n    \
             pub const LIMIT: usize = 4;\n}\n",
        )
        .build();
    let names = export_names(&project, "src/lib.rs");
    assert!(
        names.contains(&"run".to_string()),
        "an inline module's `pub fn` must be exported: {names:?}"
    );
}

/// The end-to-end consequence. Only the glob *consumer* below actually
/// discriminates the fix: a `use crate::svc::*;` has no name of its own to
/// match, so expanding it is the one route that must read the submodule's
/// export index, and it returned nothing while the guard held.
///
/// The two `pub use` re-export shapes resolved even on the unfixed guard --
/// measured, not assumed. The Rust resolver reaches those through compensating
/// routes: `infer_graph_seeds`' owner-export-index lookup, and a
/// `target.is_function() && parent_of(target).is_none()` special case that
/// repeats the very predicate this issue corrects. They are kept as regression
/// coverage for whichever route survives if those compensations are removed.
fn usage_files(analyzer: &RustAnalyzer, target_fqn: &str) -> Vec<String> {
    let target = analyzer
        .get_definitions(target_fqn)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("no definition for {target_fqn}"));
    let hits = UsageFinder::new()
        .find_usages_default(analyzer, &[target])
        .into_either()
        .expect("Rust usage scan");
    let mut files: Vec<_> = hits
        .iter()
        .map(|hit| hit.file.rel_path().to_string_lossy().replace('\\', "/"))
        .collect();
    files.sort();
    files.dedup();
    files
}

#[test]
fn caller_resolves_through_a_named_reexport_to_the_submodule_function() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            "pub mod caller;\npub mod svc;\n\npub use svc::run;\n",
        )
        .file("src/svc.rs", "pub fn run() -> usize {\n    1\n}\n")
        .file(
            "src/caller.rs",
            "use crate::run;\n\npub fn call() -> usize {\n    run()\n}\n",
        )
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    let files = usage_files(&analyzer, "svc.run");
    assert!(
        files.contains(&"src/caller.rs".to_string()),
        "a call through `pub use svc::run;` must reach the submodule function: {files:?}"
    );
}

#[test]
fn caller_resolves_through_a_glob_reexport_to_the_submodule_function() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            "pub mod caller;\npub mod svc;\n\npub use svc::*;\n",
        )
        .file("src/svc.rs", "pub fn run() -> usize {\n    1\n}\n")
        .file(
            "src/caller.rs",
            "use crate::run;\n\npub fn call() -> usize {\n    run()\n}\n",
        )
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    let files = usage_files(&analyzer, "svc.run");
    assert!(
        files.contains(&"src/caller.rs".to_string()),
        "a call through the glob `pub use svc::*;` must reach the submodule function: {files:?}"
    );
}

/// The discriminating shape, and the direction that matters: forward navigation
/// from a glob-imported bare call to its definition. Expanding `use
/// crate::svc::*;` has no name of its own to route by, so it must read svc.rs's
/// export index; while the guard dropped `run` from that index this answered
/// `no_definition`. The reverse (usage-scan) direction above resolved either
/// way, which is why this one is stated over `get_definitions_by_location`.
#[test]
fn glob_importing_consumer_navigates_to_the_submodule_function() {
    let caller = "use crate::svc::*;\n\npub fn call() -> usize {\n    run()\n}\n";
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "pub mod caller;\npub mod svc;\n")
        .file("src/svc.rs", "pub fn run() -> usize {\n    1\n}\n")
        .file("src/caller.rs", caller)
        .build();

    let line = caller
        .lines()
        .position(|line| line.contains("run()"))
        .expect("call line")
        + 1;
    let column = caller
        .lines()
        .nth(line - 1)
        .expect("call line")
        .find("run()")
        .expect("call column")
        + 1;
    let args = json!({"references": [{"path": "src/caller.rs", "line": line, "column": column}]})
        .to_string();
    let outcome = call_search_tool_json(project.root(), "get_definitions_by_location", &args);

    assert_eq!(
        outcome["results"][0]["status"].as_str(),
        Some("resolved"),
        "a glob-imported bare call must navigate to the submodule function: {outcome:#?}"
    );
    assert_eq!(
        outcome["results"][0]["definitions"][0]["fqn"].as_str(),
        Some("svc.run"),
        "and it must land on the submodule's own declaration: {outcome:#?}"
    );
}
