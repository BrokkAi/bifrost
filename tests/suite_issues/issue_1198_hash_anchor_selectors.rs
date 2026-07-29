//! Anchored `path#symbol` selectors whose *anchor filename itself* contains
//! `#` (issue #1198).
//!
//! Autofac's source-generator snapshots live at
//! `test/Autofac.Test.CodeGen/Snapshots/DelegateRegisterGeneratorTests.VerifyGeneratedCode#01.verified.cs`
//! and re-declare the extension method the generator emits, so the snapshot
//! holds a *same-fq twin* of the real `Autofac.RegistrationExtensions.Register`.
//! The bare name is therefore ambiguous, and the anchored spelling the
//! ambiguity offers must select the snapshot twin — the I2 invariant that a
//! strictly more specific spelling never fails where a less specific one
//! succeeds.
//!
//! This is #1131's `src/bin-config#hash.js#default` shape one step further:
//! the selector carries *two* `#`, one of which belongs to the filename.
//! #1131 taught `split_definition_selector_with_resolver` to walk every `#`
//! and keep the split whose anchor names a real workspace file, but wired the
//! resolver-backed splitter into only three of its consumption sites;
//! `get_definitions_by_reference` (`resolve_definition_context_symbol`) kept
//! the shape-heuristic splitter, which accepts the *directory-shaped* first
//! split `…/Snapshots/DelegateRegisterGeneratorTests.VerifyGeneratedCode` and
//! never tries the real file. The walk also now runs longest-anchor-first, so
//! a genuine prefix collision resolves like #1216's historical rule.

use crate::common::{BuiltInlineTestProject, InlineTestProject, call_tool};
use brokk_bifrost::Language;
use serde_json::Value;

const SNAPSHOT_PATH: &str = "test/Autofac.Test.CodeGen/Snapshots/DelegateRegisterGeneratorTests.VerifyGeneratedCode#01.verified.cs";
const SRC_PATH: &str = "src/Autofac/RegistrationExtensions.cs";

fn definition_reference(
    project: &BuiltInlineTestProject,
    symbol: &str,
    context: &str,
    target: &str,
) -> Value {
    let args = serde_json::json!({
        "references": [{ "symbol": symbol, "context": context, "target": target }]
    })
    .to_string();
    let result = call_tool(project, "get_definitions_by_reference", &args);
    result["results"][0].clone()
}

fn status(result: &Value) -> &str {
    result["status"]
        .as_str()
        .unwrap_or_else(|| panic!("expected a status string, got {result}"))
}

fn sources(result: &Value) -> &[Value] {
    result["sources"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_else(|| panic!("expected `sources`, got {result}"))
}

fn not_found(result: &Value) -> &[Value] {
    result["not_found"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_else(|| panic!("expected `not_found`, got {result}"))
}

/// The Autofac shape: a snapshot file whose *name* contains `#` re-declares
/// `Autofac.RegistrationExtensions.Register`, twinning the src declaration
/// byte-for-byte in fq name. Each twin calls a helper that only exists beside
/// it, so a resolved reference proves *which* twin the selector chose.
fn autofac_snapshot_project() -> BuiltInlineTestProject {
    InlineTestProject::with_language(Language::CSharp)
        .file(
            SRC_PATH,
            "namespace Autofac;\n\npublic static class SrcHelper\n{\n    public static void Seal() { }\n}\n\npublic static class RegistrationExtensions\n{\n    public static void Register(ContainerBuilder builder)\n    {\n        SrcHelper.Seal();\n    }\n}\n",
        )
        .file(
            SNAPSHOT_PATH,
            "namespace Autofac;\n\npublic static class SnapshotHelper\n{\n    public static void Seal() { }\n}\n\npublic static class RegistrationExtensions\n{\n    public static void Register(ContainerBuilder builder)\n    {\n        SnapshotHelper.Seal();\n    }\n}\n",
        )
        .build()
}

/// The exact issue shape: `path#terminal` where the path's own filename
/// carries a `#`. Before the fix the splitter stopped at the first `#`,
/// anchored on the extensionless directory-shaped prefix, and reported
/// `symbol_not_found`.
#[test]
fn two_hash_snapshot_anchor_resolves_on_the_definitions_surface() {
    let project = autofac_snapshot_project();
    let result = definition_reference(
        &project,
        &format!("{SNAPSHOT_PATH}#Register"),
        "SnapshotHelper.Seal();",
        "SnapshotHelper",
    );
    assert_eq!(
        "resolved",
        status(&result),
        "two-# anchored selector must resolve: {result}"
    );
    let definitions = result["definitions"].as_array().expect("definitions");
    assert_eq!(1, definitions.len(), "{result}");
    assert_eq!(
        SNAPSHOT_PATH,
        definitions[0]["path"].as_str().expect("path"),
        "{result}"
    );
}

/// I2 pair on the surface that reported the violation: the bare name is
/// ambiguous (both twins), so the strictly more specific anchored spelling
/// must not be worse than ambiguous.
#[test]
fn bare_twin_name_is_ambiguous_where_the_anchored_spelling_resolves() {
    let project = autofac_snapshot_project();
    let bare = definition_reference(
        &project,
        "Register",
        "SnapshotHelper.Seal();",
        "SnapshotHelper",
    );
    assert_eq!("not_found", status(&bare), "{bare}");
    let kinds: Vec<&str> = bare["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .map(|item| item["kind"].as_str().expect("kind"))
        .collect();
    assert_eq!(
        vec!["ambiguous_symbol"],
        kinds,
        "the bare twin name must ambiguate (not merely miss): {bare}"
    );
}

/// The same disambiguation on `get_symbol_sources`: the anchored spelling
/// must return the SNAPSHOT twin's body, never the src twin's.
#[test]
fn hash_bearing_anchor_selects_the_snapshot_twin_not_the_src_twin() {
    let project = autofac_snapshot_project();
    for (anchor, marker) in [(SNAPSHOT_PATH, "SnapshotHelper"), (SRC_PATH, "SrcHelper")] {
        let result = call_tool(
            &project,
            "get_symbol_sources",
            &serde_json::json!({ "symbols": [format!("{anchor}#Register")] }).to_string(),
        );
        assert!(
            not_found(&result).is_empty(),
            "{anchor}#Register must resolve: {result}"
        );
        assert_eq!(1, sources(&result).len(), "{result}");
        assert_eq!(
            anchor,
            sources(&result)[0]["path"].as_str().expect("path"),
            "{result}"
        );
        assert!(
            sources(&result)[0]["text"]
                .as_str()
                .expect("text")
                .contains(marker),
            "anchored spelling must return the twin declared in {anchor}: {result}"
        );
    }
}

/// Prefix collision: both `a.cs` and `a.cs#x.cs` are real files and both
/// declare `Marker`. The longest resolvable anchor must win, matching
/// #1216's historical `REV:path#symbol` rule.
#[test]
fn longest_resolvable_anchor_wins_a_prefix_collision() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "snap/a.cs",
            "namespace Shorter;\n\npublic static class Marker\n{\n    public static void Seal() { }\n}\n",
        )
        .file(
            "snap/a.cs#x.cs",
            "namespace Longer;\n\npublic static class Marker\n{\n    public static void Seal() { }\n}\n",
        )
        .build();

    let result = call_tool(
        &project,
        "get_symbol_sources",
        &serde_json::json!({ "symbols": ["snap/a.cs#x.cs#Marker"] }).to_string(),
    );
    assert!(not_found(&result).is_empty(), "{result}");
    assert_eq!(1, sources(&result).len(), "{result}");
    assert_eq!(
        "snap/a.cs#x.cs",
        sources(&result)[0]["path"].as_str().expect("path"),
        "the longest anchor that names a real file must win: {result}"
    );

    // The shorter anchor stays addressable in its own right.
    let shorter = call_tool(
        &project,
        "get_symbol_sources",
        &serde_json::json!({ "symbols": ["snap/a.cs#Marker"] }).to_string(),
    );
    assert_eq!(
        "snap/a.cs",
        sources(&shorter)[0]["path"].as_str().expect("path"),
        "{shorter}"
    );
}

/// #1131's single-`#` filename shape stays green on the surface that was
/// missing the resolver-backed splitter.
#[test]
fn single_hash_filename_anchor_regression_pin() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "src/bin-config#hash.js",
            "export function breaks() {\n  return marker();\n}\n\nexport function marker() {\n  return 1;\n}\n",
        )
        .build();

    let result = definition_reference(
        &project,
        "src/bin-config#hash.js#breaks",
        "return marker();",
        "marker",
    );
    assert_eq!("resolved", status(&result), "{result}");
    assert_eq!(
        "src/bin-config#hash.js",
        result["definitions"][0]["path"].as_str().expect("path"),
        "{result}"
    );
}

/// An ordinary `path#symbol` selector and a Rust raw identifier whose escape
/// contributes the only (or the last) `#` must keep their existing splits:
/// `db_column.rs#r#type` anchors on `db_column.rs`, never on the
/// non-existent `db_column.rs#r`.
#[test]
fn ordinary_and_raw_identifier_selectors_are_unchanged() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/db_column.rs",
            "pub struct DbColumn {\n    pub r#type: String,\n}\n\nimpl DbColumn {\n    pub fn describe(&self) -> usize {\n        helper()\n    }\n}\n\npub fn helper() -> usize {\n    1\n}\n",
        )
        .build();

    let ordinary = call_tool(
        &project,
        "get_symbol_sources",
        &serde_json::json!({ "symbols": ["src/db_column.rs#describe"] }).to_string(),
    );
    assert!(not_found(&ordinary).is_empty(), "{ordinary}");

    for selector in [
        "src/db_column.rs#type",
        "src/db_column.rs#r#type",
        "src/db_column.rs#DbColumn.r#type",
    ] {
        let result = call_tool(
            &project,
            "get_symbol_sources",
            &serde_json::json!({ "symbols": [selector] }).to_string(),
        );
        assert!(not_found(&result).is_empty(), "{selector}: {result}");
        assert!(
            sources(&result)[0]["text"]
                .as_str()
                .expect("text")
                .contains("r#type"),
            "{selector}: {result}"
        );
    }

    // Same on the definitions surface, which is where the missing
    // resolver-backed splitter lived.
    let raw = definition_reference(&project, "src/db_column.rs#describe", "helper()", "helper");
    assert_eq!("resolved", status(&raw), "{raw}");
}
