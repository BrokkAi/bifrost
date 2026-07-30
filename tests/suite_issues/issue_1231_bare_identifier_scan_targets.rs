//! Regression coverage for issue #1231: `scan_usages_by_location` with a bare
//! (non-fully-qualified) `symbol` at a Rust location.
//!
//! `definition_selector` is `fq_name` outside module-scoped ecosystems
//! (JS/TS), so a bare identifier used to match no selector form at all and
//! the target fell through to `not_found` — even though the target's
//! `path`+`line` already pin the location precisely enough that the bare
//! name is unambiguous there. #1228 taught the resolver to accept a bare
//! short-name match at the exact location, but did not order it against the
//! existing exact selector forms (`fq_name` / `definition_selector` /
//! `display_symbol_for_target`): a short-name match anywhere in the location
//! pool could still interfere with (or, when it belongs to a different `fq_name`,
//! wrongly turn into `ambiguous`) an exact selector match at the very same
//! spot. This module pins:
//!
//!  1. a bare identifier at a pinned location, an explicit fully-qualified
//!     spelling at that location, and a line-only (no `symbol`) request all
//!     agree byte-for-byte;
//!  2. the same agreement holds when the location hosts an overload set
//!     (multiple declarations sharing one `fq_name`);
//!  3. match order: an exact selector match always wins over a
//!     same-location declaration whose *short name* merely happens to equal
//!     the requested symbol (previously misreported as `ambiguous`);
//!  4. a genuinely mismatched bare name gets a corrective `not_found`
//!     message naming the location's actual declaration and stating that
//!     selectors are fully-qualified, rather than a bare refusal;
//!  5. JS/TS module-scoped location resolution — already file-anchored via
//!     `definition_selector` before this change — is unchanged.

use brokk_bifrost::searchtools::{
    ScanUsagesByLocationParams, ScanUsagesEntry, ScanUsagesStatus, ScanUsagesTarget,
    scan_usages_by_location,
};
use brokk_bifrost::{IAnalyzer, JavascriptAnalyzer, Language, RustAnalyzer};

use crate::common::InlineTestProject;

/// Run one `scan_usages_by_location` request for `path`/`line`/`symbol` and
/// return its sole result entry.
fn scan_at(
    analyzer: &dyn IAnalyzer,
    path: &str,
    line: usize,
    symbol: Option<&str>,
) -> ScanUsagesEntry {
    let mut result = scan_usages_by_location(
        analyzer,
        ScanUsagesByLocationParams {
            targets: vec![ScanUsagesTarget {
                path: path.to_string(),
                line,
                column: None,
                symbol: symbol.map(str::to_string),
            }],
            include_tests: true,
            paths: None,
            include_same_owner: false,
            max_duration_secs: None,
        },
    );
    assert_eq!(result.results.len(), 1, "one requested target");
    result.results.remove(0)
}

/// Serialize an entry to JSON and drop the `input` field, which necessarily
/// differs across calls that vary only in the requested `symbol` (or its
/// absence). Everything else — `status`, `symbol`, `fq_name`,
/// `definition_path`, `definition_line`, `files`, `total_hits`, `message`,
/// etc. — is the actual scan *result*, and is what byte-for-byte agreement
/// is about.
fn normalized_result(entry: &ScanUsagesEntry) -> serde_json::Value {
    let mut value = serde_json::to_value(entry).expect("ScanUsagesEntry must serialize");
    if let Some(object) = value.as_object_mut() {
        object.remove("input");
    }
    value
}

// ---------------------------------------------------------------------
// 1. Bare identifier, fq spelling, and line-only requests all agree.
// ---------------------------------------------------------------------

fn single_declaration_project() -> crate::common::BuiltInlineTestProject {
    InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            "pub struct Widget;\n\
             \n\
             impl Widget {\n\
             \x20   pub fn helper(&self, value: usize) -> usize {\n\
             \x20       value + 1\n\
             \x20   }\n\
             }\n\
             \n\
             pub fn call_helper(widget: &Widget) -> usize {\n\
             \x20   widget.helper(41)\n\
             }\n",
        )
        .build()
}

#[test]
fn bare_identifier_fq_spelling_and_line_only_agree_byte_for_byte() {
    let project = single_declaration_project();
    let analyzer = RustAnalyzer::from_project(project.project().clone());

    // `src/lib.rs:4` is `    pub fn helper(&self, value: usize) -> usize {`.
    let line_only = scan_at(&analyzer, "src/lib.rs", 4, None);
    assert_eq!(
        line_only.status,
        ScanUsagesStatus::Found,
        "line-only target must resolve: {line_only:#?}"
    );
    let fq_spelling = line_only
        .symbol
        .clone()
        .expect("a resolved location target reports the selector it bound to");

    let fq_qualified = scan_at(&analyzer, "src/lib.rs", 4, Some(&fq_spelling));
    let bare = scan_at(&analyzer, "src/lib.rs", 4, Some("helper"));

    assert_eq!(
        fq_qualified.status,
        ScanUsagesStatus::Found,
        "{fq_qualified:#?}"
    );
    assert_eq!(bare.status, ScanUsagesStatus::Found, "{bare:#?}");
    assert_eq!(bare.total_hits, Some(1), "one call site: {bare:#?}");

    let line_only_json = normalized_result(&line_only);
    let fq_json = normalized_result(&fq_qualified);
    let bare_json = normalized_result(&bare);
    assert_eq!(
        line_only_json, fq_json,
        "line-only and fq-qualified requests must produce identical results"
    );
    assert_eq!(
        fq_json, bare_json,
        "fq-qualified and bare-identifier requests must produce identical results"
    );
}

// ---------------------------------------------------------------------
// 2. Overloads at the same location resolve to the same overload set that
//    line-only resolution finds.
// ---------------------------------------------------------------------

fn overload_set_project() -> crate::common::BuiltInlineTestProject {
    InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            "pub struct Wrapper(i32);\n\
             \n\
             impl Wrapper { pub fn value(&self) -> i32 { self.0 } pub fn value(&self) -> i32 { self.0 + 1 } }\n\
             \n\
             pub fn call_value(wrapper: &Wrapper) -> i32 {\n\
             \x20   wrapper.value()\n\
             }\n",
        )
        .build()
}

#[test]
fn overloads_at_same_location_resolve_to_line_only_overload_set() {
    let project = overload_set_project();
    let analyzer = RustAnalyzer::from_project(project.project().clone());

    // `src/lib.rs:3` carries both `value` declarations sharing one `fq_name`;
    // both name tokens sit on this line.
    let line_only = scan_at(&analyzer, "src/lib.rs", 3, None);
    assert_eq!(line_only.status, ScanUsagesStatus::Found, "{line_only:#?}");
    let fq_spelling = line_only
        .symbol
        .clone()
        .expect("resolved location target reports its selector");

    let bare = scan_at(&analyzer, "src/lib.rs", 3, Some("value"));
    assert_eq!(bare.status, ScanUsagesStatus::Found, "{bare:#?}");

    let fq_qualified = scan_at(&analyzer, "src/lib.rs", 3, Some(&fq_spelling));
    assert_eq!(
        fq_qualified.status,
        ScanUsagesStatus::Found,
        "{fq_qualified:#?}"
    );

    assert_eq!(
        normalized_result(&line_only),
        normalized_result(&bare),
        "a bare short name over an overload set must resolve to the same overload group as line-only"
    );
    assert_eq!(
        normalized_result(&line_only),
        normalized_result(&fq_qualified),
        "the fq-qualified spelling must resolve to the same overload group as line-only"
    );
}

// ---------------------------------------------------------------------
// 3. Match order: an exact selector match wins over a same-location
//    declaration whose short name merely coincides with the requested
//    symbol.
// ---------------------------------------------------------------------

fn short_name_collision_project() -> crate::common::BuiltInlineTestProject {
    InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            "pub fn value() -> i32 { 0 } pub struct SomeType; impl SomeType { pub fn value(&self) -> i32 { 1 } }\n",
        )
        .build()
}

#[test]
fn exact_selector_match_wins_over_coincidental_short_name_collision() {
    let project = short_name_collision_project();
    let analyzer = RustAnalyzer::from_project(project.project().clone());

    // Everything is packed onto line 1 on purpose: the free function
    // `value` (fq_name exactly `value`, a crate-root item) and
    // `SomeType::value` (short_name `value`, different fq_name) both have
    // their name token within this one line, so a line-only selection sees
    // both. Requesting the free function's exact fq spelling `value` must
    // resolve to *it*, never fall into `ambiguous` because
    // `SomeType::value`'s short name happens to also read `value`.
    let exact = scan_at(&analyzer, "src/lib.rs", 1, Some("value"));

    assert_eq!(
        exact.status,
        ScanUsagesStatus::Found,
        "an exact selector match at this location must resolve, not go ambiguous: {exact:#?}"
    );
    assert_eq!(
        exact.symbol.as_deref(),
        Some("value"),
        "must resolve to the free function `value`, not `SomeType::value`: {exact:#?}"
    );
}

// ---------------------------------------------------------------------
// 4. A genuinely mismatched bare name gets a corrective message.
// ---------------------------------------------------------------------

#[test]
fn mismatched_bare_name_names_the_actual_declaration_at_location() {
    let project = single_declaration_project();
    let analyzer = RustAnalyzer::from_project(project.project().clone());

    let line_only = scan_at(&analyzer, "src/lib.rs", 4, None);
    let actual_fq = line_only
        .symbol
        .clone()
        .expect("resolved location target reports its selector");

    let mismatched = scan_at(&analyzer, "src/lib.rs", 4, Some("totally_unrelated_name"));

    assert_eq!(
        mismatched.status,
        ScanUsagesStatus::NotFound,
        "{mismatched:#?}"
    );
    let message = mismatched
        .message
        .clone()
        .unwrap_or_else(|| panic!("not_found must carry a message: {mismatched:#?}"));
    assert!(
        message.contains("totally_unrelated_name"),
        "message must name the requested symbol: {message}"
    );
    assert!(
        message.to_ascii_lowercase().contains("fully-qualified")
            || message.to_ascii_lowercase().contains("fully qualified"),
        "message must state that selectors are fully-qualified: {message}"
    );
    assert!(
        message.contains(&actual_fq),
        "message must offer the resolvable candidate at this location (`{actual_fq}`): {message}"
    );
    assert!(
        !message
            .to_ascii_lowercase()
            .starts_with("no declaration matching")
            || message.contains(&actual_fq),
        "must never be a bare refusal that omits the resolvable candidate: {message}"
    );
}

// ---------------------------------------------------------------------
// 5. JS/TS module-scoped location resolution is unchanged.
// ---------------------------------------------------------------------

fn js_module_scoped_project() -> crate::common::BuiltInlineTestProject {
    InlineTestProject::with_language(Language::JavaScript)
        .file("src/a.js", "export function helper() {\n    return 1;\n}\n")
        .file("src/b.js", "export function helper() {\n    return 2;\n}\n")
        .file(
            "src/consumer.js",
            "import { helper } from './a.js';\n\n\
             export function useHelper() {\n    return helper();\n}\n",
        )
        .build()
}

#[test]
fn js_module_scoped_bare_selector_at_pinned_location_is_unchanged() {
    let project = js_module_scoped_project();
    let analyzer = JavascriptAnalyzer::from_project(project.project().clone());

    // `src/a.js:1` is `export function helper() {`. `src/b.js` declares a
    // same-named, unrelated `helper` purely to prove the pinned location
    // resolves against `a.js` alone, exactly as before this change: a
    // module-scoped ecosystem's `definition_selector` is already
    // file-anchored, so `a.js`'s `helper` was never reached via a bare
    // short-name match colliding with `b.js`'s.
    let line_only = scan_at(&analyzer, "src/a.js", 1, None);
    assert_eq!(line_only.status, ScanUsagesStatus::Found, "{line_only:#?}");
    let file_anchored = line_only
        .symbol
        .clone()
        .expect("resolved location target reports its selector");
    assert!(
        file_anchored.contains("a.js"),
        "module-scoped selector must be file-anchored to a.js, not b.js: {file_anchored}"
    );

    let bare = scan_at(&analyzer, "src/a.js", 1, Some("helper"));
    let fq_qualified = scan_at(&analyzer, "src/a.js", 1, Some(&file_anchored));

    assert_eq!(bare.status, ScanUsagesStatus::Found, "{bare:#?}");
    assert_eq!(
        fq_qualified.status,
        ScanUsagesStatus::Found,
        "{fq_qualified:#?}"
    );
    assert_eq!(
        bare.total_hits,
        Some(1),
        "consumer.js calls helper once: {bare:#?}"
    );

    assert_eq!(
        normalized_result(&line_only),
        normalized_result(&bare),
        "bare `helper` pinned to a.js must resolve exactly like line-only"
    );
    assert_eq!(
        normalized_result(&line_only),
        normalized_result(&fq_qualified),
        "the file-anchored selector must resolve exactly like line-only"
    );
}
