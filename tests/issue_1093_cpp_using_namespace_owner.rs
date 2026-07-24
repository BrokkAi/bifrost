//! Issue #1093: an out-of-line C++ member definition written as a bare
//! `Class::method` at file/namespace scope under an in-effect `using
//! namespace X;` directive (rather than an enclosing `namespace {}` block, as
//! in apache/logging-log4cxx's `htmllayout.cpp`) used to be indexed with an
//! empty package, splitting its identity from its header declaration's
//! namespace-qualified one. Every display spelling of the member (the exact
//! contract the property fuzzer's I2 invariant checks) must resolve, and must
//! resolve consistently to the *same* declaration set.

mod common;

use brokk_bifrost::{Language, SearchToolsService};
use common::InlineTestProject;
use serde_json::Value;

fn call_tool(project: &common::BuiltInlineTestProject, tool: &str, args: &str) -> Value {
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");
    let payload = service
        .call_tool_json(tool, args)
        .expect("tool call failed");
    serde_json::from_str(&payload).expect("tool returned invalid JSON")
}

fn symbol_sources(project: &common::BuiltInlineTestProject, symbol: &str) -> Value {
    call_tool(
        project,
        "get_symbol_sources",
        &serde_json::json!({ "symbols": [symbol] }).to_string(),
    )
}

fn sorted_source_paths(result: &Value) -> Vec<String> {
    let mut paths: Vec<String> = result["sources"]
        .as_array()
        .unwrap_or_else(|| panic!("expected `sources` array, got {result}"))
        .iter()
        .map(|source| source["path"].as_str().expect("source path").to_string())
        .collect();
    paths.sort();
    paths
}

fn definition_reference_status(
    project: &common::BuiltInlineTestProject,
    symbol: &str,
    context: &str,
    target: &str,
) -> String {
    let args = serde_json::json!({
        "references": [{ "symbol": symbol, "context": context, "target": target }]
    })
    .to_string();
    let result = call_tool(project, "get_definitions_by_reference", &args);
    result["results"][0]["status"]
        .as_str()
        .unwrap_or_else(|| panic!("expected a status string, got {result}"))
        .to_string()
}

/// The exact shape from the issue: a header declaration inside `namespace
/// log4cxx { ... }` and an out-of-line `.cpp` definition that relies on
/// `using namespace log4cxx;` (plus sibling using-directives for utility
/// namespaces, matching log4cxx's own `htmllayout.cpp`) instead of repeating
/// the namespace. Before the fix, the definition's package resolved to `""`,
/// splitting its identity from the declaration's `log4cxx.HTMLLayout.*`.
fn html_layout_project() -> common::BuiltInlineTestProject {
    InlineTestProject::with_language(Language::Cpp)
        .file(
            "htmllayout.h",
            r#"
namespace log4cxx {
class HTMLLayout {
public:
    int getContentType() const;
};
}
"#,
        )
        .file(
            "htmllayout.cpp",
            r#"
#include "htmllayout.h"

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

int doFormat() {
    return 1;
}

int HTMLLayout::getContentType() const {
    return doFormat();
}
"#,
        )
        .build()
}

#[test]
fn every_display_spelling_resolves_to_the_same_definition() {
    let project = html_layout_project();

    // Every spelling the surface can display for this member -- the display
    // fq itself, its `::` twin, the fully namespace-qualified forms, and the
    // bare terminal name -- must resolve, unambiguously, to the same `.cpp`
    // definition. The declaration remains physically addressable below.
    let spellings = [
        "getContentType",
        "HTMLLayout.getContentType",
        "log4cxx.HTMLLayout.getContentType",
        "HTMLLayout::getContentType",
        "log4cxx::HTMLLayout::getContentType",
    ];
    for spelling in spellings {
        let result = symbol_sources(&project, spelling);
        assert_eq!(
            result["not_found"].as_array().unwrap().len(),
            0,
            "`{spelling}` reported not_found: {result}"
        );
        assert_eq!(
            result["ambiguous"].as_array().unwrap().len(),
            0,
            "`{spelling}` reported ambiguous: {result}"
        );
        assert_eq!(
            sorted_source_paths(&result),
            vec!["htmllayout.cpp".to_string()],
            "`{spelling}` did not resolve to the definition: {result}"
        );
    }

    // File-anchored spellings narrow to the anchored file's own source, same
    // as any other C++ member.
    for (anchored, expected_path) in [
        ("htmllayout.cpp#getContentType", "htmllayout.cpp"),
        ("htmllayout.cpp#HTMLLayout.getContentType", "htmllayout.cpp"),
        ("htmllayout.h#getContentType", "htmllayout.h"),
        ("htmllayout.h#HTMLLayout.getContentType", "htmllayout.h"),
    ] {
        let result = symbol_sources(&project, anchored);
        assert_eq!(
            sorted_source_paths(&result),
            vec![expected_path.to_string()],
            "`{anchored}`: {result}"
        );
    }

    // I2 (property fuzzer): `get_definitions_by_reference` must report the
    // *same* status for the same context/target regardless of which display
    // spelling named the symbol -- the exact "spelling-status-drift" shape
    // from the issue's ledger (bare `getContentType` -> invalid_location,
    // `HTMLLayout.getContentType` -> no_definition, before the fix).
    let statuses: Vec<String> = spellings
        .iter()
        .map(|spelling| {
            definition_reference_status(&project, spelling, "return doFormat();", "doFormat")
        })
        .collect();
    assert!(
        statuses.iter().all(|status| status == &statuses[0]),
        "status drift across display spellings of the same member: {statuses:?}"
    );
    // The uniform status is `resolved`: a bare call to a global free function
    // from an out-of-line member defined at file scope under a using-directive
    // now resolves at the call site (#1120 fixed -- the member's true
    // enclosing scope is recovered from its indexed definition, so unqualified
    // lookup reaches the global namespace where `doFormat` is declared).
    assert_eq!(statuses[0], "resolved", "statuses: {statuses:?}");
}

/// Negative control: a spelling naming the *wrong* owner must still fail
/// cleanly (not_found), even though the fallback now resolves `HTMLLayout`'s
/// package from a `using namespace` directive. The fallback must not make
/// bogus owners resolve.
#[test]
fn wrong_owner_spelling_still_fails_cleanly() {
    let project = html_layout_project();

    for wrong_spelling in [
        "WrongLayout.getContentType",
        "log4cxx.WrongLayout.getContentType",
        "otherns.HTMLLayout.getContentType",
    ] {
        let result = symbol_sources(&project, wrong_spelling);
        assert_eq!(
            result["sources"].as_array().unwrap().len(),
            0,
            "`{wrong_spelling}` unexpectedly resolved: {result}"
        );
        assert_eq!(
            result["ambiguous"].as_array().unwrap().len(),
            0,
            "`{wrong_spelling}` unexpectedly ambiguous: {result}"
        );
        assert_eq!(
            result["not_found"].as_array().unwrap().len(),
            1,
            "`{wrong_spelling}` should report not_found: {result}"
        );
    }
}

/// A file with only a *narrower* `using namespace log4cxx::helpers;` (no
/// top-level `using namespace log4cxx;`) must not spuriously acquire the
/// unrelated namespace's identity: with nothing recovering the true owner
/// package, the definition still ends up with the shallowest in-scope
/// using-directive rather than accidentally matching the header's `log4cxx`
/// package, so the header and the out-of-line definition are (still,
/// correctly) treated as different declarations rather than silently
/// coalesced under a guess with no support.
#[test]
fn narrower_using_directive_does_not_fabricate_the_headers_namespace() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "layout2.h",
            r#"
namespace log4cxx {
class HTMLLayout2 {
public:
    int getContentType() const;
};
}
"#,
        )
        .file(
            "layout2.cpp",
            r#"
#include "layout2.h"

using namespace log4cxx::helpers;

int HTMLLayout2::getContentType() const {
    return 1;
}
"#,
        )
        .build();

    // The out-of-line definition's best-effort package is `log4cxx::helpers`
    // (the only in-scope using-directive), which does not match the header's
    // `log4cxx` -- so both spellings still resolve (each to its own single
    // declaration), and neither is a not_found/ambiguous crash, but they are
    // not coalesced into one two-source result the way the primary
    // single-using-directive case is.
    let by_declared_package = symbol_sources(&project, "log4cxx.HTMLLayout2.getContentType");
    assert_eq!(
        sorted_source_paths(&by_declared_package),
        vec!["layout2.h".to_string()],
        "{by_declared_package}"
    );

    let bare = symbol_sources(&project, "HTMLLayout2.getContentType");
    assert_eq!(
        bare["not_found"].as_array().unwrap().len(),
        0,
        "`HTMLLayout2.getContentType` unexpectedly not_found: {bare}"
    );
}

/// The real log4cxx shape: several `using namespace` directives in scope at
/// once (a primary top-level one plus deeper utility ones). The shallowest
/// (fewest `::`-separated segments) must win, so the out-of-line definition's
/// recovered package still matches the header's.
#[test]
fn shallowest_using_directive_wins_among_several_candidates() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "multi.h",
            r#"
namespace log4cxx {
namespace helpers { class Dummy {}; }
namespace spi { class Dummy {}; }
class HTMLLayout {
public:
    int getContentType() const;
};
}
"#,
        )
        .file(
            "multi.cpp",
            r#"
#include "multi.h"

using namespace log4cxx::spi;
using namespace log4cxx::helpers;
using namespace log4cxx;

int HTMLLayout::getContentType() const {
    return 1;
}
"#,
        )
        .build();

    let result = symbol_sources(&project, "log4cxx.HTMLLayout.getContentType");
    assert_eq!(
        sorted_source_paths(&result),
        vec!["multi.cpp".to_string()],
        "{result}"
    );
    let bare = symbol_sources(&project, "HTMLLayout.getContentType");
    assert_eq!(
        sorted_source_paths(&bare),
        vec!["multi.cpp".to_string()],
        "{bare}"
    );
}

/// A related but *separately-rooted* shape (issue #1121, fixed): an out-of-line
/// definition of a class-nested-in-class member (`Outer$Inner` in Bifrost's own
/// short-name convention) is always written with *two* owner segments
/// (`Outer::Inner::method`), which C++ requires regardless of any
/// using-directive -- nested-class access is never brought into unqualified
/// scope by `using namespace`. That two-segment shape takes a different branch
/// of `split_cpp_name` than #1093's single-segment case. When the definition is
/// written inside an enclosing `namespace {}` block, that branch now reads the
/// owner segments as the class-nesting chain they are (rather than dropping all
/// but the last as a namespace path), so the definition unifies with the
/// header declaration -- reproducing and fixing #1121 with no using-directive
/// involved at all. The file-scope using-directive variant now *also* unifies
/// (#1134): the resolution-time reconciliation overlay consults the
/// include-visible class table to confirm `Outer::Inner` is a nested class in
/// the used namespace and folds the definition onto the header identity.
#[test]
fn nested_class_two_segment_owner_unifies_in_namespace_block() {
    let with_namespace_block = InlineTestProject::with_language(Language::Cpp)
        .file(
            "nested_block.h",
            r#"
namespace log4cxx {
class Outer {
public:
    class Inner {
    public:
        int method() const;
    };
};
}
"#,
        )
        .file(
            "nested_block.cpp",
            r#"
#include "nested_block.h"

namespace log4cxx {
int Outer::Inner::method() const {
    return 2;
}
}
"#,
        )
        .build();

    let with_using_directive = InlineTestProject::with_language(Language::Cpp)
        .file(
            "nested_using.h",
            r#"
namespace log4cxx {
class Outer {
public:
    class Inner {
    public:
        int method() const;
    };
};
}
"#,
        )
        .file(
            "nested_using.cpp",
            r#"
#include "nested_using.h"

using namespace log4cxx;

int Outer::Inner::method() const {
    return 2;
}
"#,
        )
        .build();

    // Namespace-block variant (#1121 fixed): the header declaration and the
    // out-of-line definition unify onto `log4cxx.Outer$Inner.method`, so the
    // canonical symbol resolves to the preferred `.cpp` definition while its
    // identity remains anchored to the header declaration.
    let unified = symbol_sources(&with_namespace_block, "log4cxx.Outer$Inner.method");
    assert_eq!(
        unified["not_found"].as_array().unwrap().len(),
        0,
        "namespace-block variant: {unified}"
    );
    assert_eq!(
        sorted_source_paths(&unified),
        vec!["nested_block.cpp".to_string()],
        "namespace-block nested member did not unify: {unified}"
    );
    assert_eq!(
        unified["sources"][0]["canonical_selector"], "nested_block.h#log4cxx.Outer$Inner.method",
        "{unified}"
    );

    // File-scope using-directive variant: now unifies (#1134). The
    // resolution-time class-table reconciliation folds the `.cpp` definition
    // onto the header's `log4cxx.Outer$Inner.method` identity, so the canonical
    // symbol resolves to the preferred definition while its identity stays
    // anchored to the header declaration.
    let unified_using = symbol_sources(&with_using_directive, "log4cxx.Outer$Inner.method");
    assert_eq!(
        unified_using["not_found"].as_array().unwrap().len(),
        0,
        "using-directive variant: {unified_using}"
    );
    assert_eq!(
        sorted_source_paths(&unified_using),
        vec!["nested_using.cpp".to_string()],
        "using-directive variant did not unify: {unified_using}"
    );
    assert_eq!(
        unified_using["sources"][0]["canonical_selector"],
        "nested_using.h#log4cxx.Outer$Inner.method",
        "{unified_using}"
    );
}
