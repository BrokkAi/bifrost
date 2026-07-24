//! Issue #1120: a bare call to a global free function from inside an
//! out-of-line C++ member definition written at *file* scope under a
//! `using namespace X;` directive (rather than an enclosing `namespace {}`
//! block) failed to resolve at the call site -- `get_definition` returned
//! `no_definition` ("did not resolve to an indexed C++ callable"), even
//! though real C++ unqualified lookup finds the callee trivially (declared
//! earlier in the same translation unit at global scope).
//!
//! Root cause: `enclosing_lexical_scope_components` computed the enclosing
//! member's scope chain by resolving the out-of-line owner class
//! (`HTMLLayout::method`) through structural lexical resolution only, which
//! does not consult in-scope using-directives. When the owner class was
//! reachable *only* via a `using namespace`, owner resolution returned
//! `Missing`, the whole scope resolution bailed out with `Missing`, and the
//! bare-call machinery never reached the global-namespace tier that would
//! have found the callee.

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

/// The failing shape from the issue: header declares the class inside
/// `namespace log4cxx {}`, the `.cpp` defines the out-of-line member at file
/// scope under `using namespace log4cxx;`, and the member body makes a bare
/// call to a global free function declared earlier in the same file.
#[test]
fn bare_global_call_from_file_scope_out_of_line_member_under_using_directive_resolves() {
    let project = InlineTestProject::with_language(Language::Cpp)
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

int doFormat() {
    return 1;
}

int HTMLLayout::getContentType() const {
    return doFormat();
}
"#,
        )
        .build();

    let status = definition_reference_status(
        &project,
        "log4cxx.HTMLLayout.getContentType",
        "return doFormat();",
        "doFormat",
    );
    assert_eq!(
        status, "resolved",
        "bare call to global `doFormat` from a file-scope out-of-line member under a \
         using-directive must resolve"
    );
}

/// Regression pins for the three probe shapes that already resolved before the
/// fix, to prove the change does not regress them. Each defines a global free
/// function `doFormat` and an out-of-line/in-namespace member calling it.
#[test]
fn already_resolving_bare_call_probe_shapes_stay_resolved() {
    // Owner class at global scope, out-of-line at file scope, no directive.
    let global_owner = InlineTestProject::with_language(Language::Cpp)
        .file(
            "a.h",
            r#"
class Widget {
public:
    int render() const;
};
"#,
        )
        .file(
            "a.cpp",
            r#"
#include "a.h"

int doFormat() { return 1; }

int Widget::render() const {
    return doFormat();
}
"#,
        )
        .build();
    assert_eq!(
        definition_reference_status(
            &global_owner,
            "Widget.render",
            "return doFormat();",
            "doFormat"
        ),
        "resolved",
        "global-owner out-of-line member should resolve the bare global call"
    );

    // Out-of-line member wrapped in an explicit `namespace {}` block, no directive.
    let namespace_block = InlineTestProject::with_language(Language::Cpp)
        .file(
            "b.h",
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
            "b.cpp",
            r#"
#include "b.h"

namespace log4cxx {

int doFormat() { return 1; }

int HTMLLayout::getContentType() const {
    return doFormat();
}

}
"#,
        )
        .build();
    assert_eq!(
        definition_reference_status(
            &namespace_block,
            "log4cxx.HTMLLayout.getContentType",
            "return doFormat();",
            "doFormat"
        ),
        "resolved",
        "namespace-block out-of-line member should resolve the bare call"
    );

    // Out-of-line member inside a `namespace {}` block *and* a directive also present.
    let namespace_block_with_directive = InlineTestProject::with_language(Language::Cpp)
        .file(
            "c.h",
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
            "c.cpp",
            r#"
#include "c.h"

using namespace log4cxx;

namespace log4cxx {

int doFormat() { return 1; }

int HTMLLayout::getContentType() const {
    return doFormat();
}

}
"#,
        )
        .build();
    assert_eq!(
        definition_reference_status(
            &namespace_block_with_directive,
            "log4cxx.HTMLLayout.getContentType",
            "return doFormat();",
            "doFormat"
        ),
        "resolved",
        "namespace-block-with-directive out-of-line member should resolve the bare call"
    );
}

/// C++ unqualified lookup finds an inner-scope name before an outer free
/// function: a *local variable* named like the free function shadows it, so a
/// bare `doFormat` that names the local (not a call, but the same lookup)
/// must not resolve to the global function. Here the body declares a local
/// `int doFormat` and returns it; the reference must be seen as the local
/// value, never the global callable.
#[test]
fn local_variable_shadows_global_free_function() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "shadow.h",
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
            "shadow.cpp",
            r#"
#include "shadow.h"

using namespace log4cxx;

int doFormat() {
    return 1;
}

int HTMLLayout::getContentType() const {
    int doFormat = 7;
    return doFormat;
}
"#,
        )
        .build();

    // The bare `doFormat` here names the local `int doFormat`, not the global
    // free function, so it must NOT resolve to the callable definition.
    let status = definition_reference_status(
        &project,
        "log4cxx.HTMLLayout.getContentType",
        "return doFormat;",
        "doFormat",
    );
    assert_ne!(
        status, "resolved",
        "a local variable named `doFormat` must shadow the global free function per C++ lookup, \
         got status {status}"
    );
}

/// A class member named like the global free function wins over the global one
/// for a bare call inside a member of that class: C++ unqualified lookup
/// reaches the class scope before the enclosing-namespace/global scope, so the
/// bare `doFormat()` must resolve to the member, not the global function.
#[test]
fn class_member_wins_over_global_free_function() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "member.h",
            r#"
namespace log4cxx {
class HTMLLayout {
public:
    int getContentType() const;
    int doFormat() const;
};
}
"#,
        )
        .file(
            "member.cpp",
            r#"
#include "member.h"

using namespace log4cxx;

int doFormat() {
    return 1;
}

int HTMLLayout::doFormat() const {
    return 2;
}

int HTMLLayout::getContentType() const {
    return doFormat();
}
"#,
        )
        .build();

    // The bare `doFormat()` must resolve to the member `doFormat`, which
    // (unlike the global one) has a declaration in the header. A resolved
    // status is required, and it must be the member.
    let result = call_tool(
        &project,
        "get_definitions_by_reference",
        &serde_json::json!({
            "references": [{
                "symbol": "log4cxx.HTMLLayout.getContentType",
                "context": "return doFormat();",
                "target": "doFormat"
            }]
        })
        .to_string(),
    );
    let status = result["results"][0]["status"].as_str().unwrap_or("");
    assert_eq!(status, "resolved", "member call should resolve: {result}");
    // The resolved definition set must include the member declaration in the
    // header, proving the class-scope member won lookup rather than the global.
    let text = result.to_string();
    assert!(
        text.contains("member.h"),
        "class member `doFormat` (declared in member.h) should win lookup over the global one: {result}"
    );
}

/// Two global free functions with the same name but different arity: when the
/// call's arity picks exactly one, resolution succeeds; the presence of a
/// second, non-applicable overload does not make it ambiguous.
#[test]
fn arity_disambiguates_two_global_overloads() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "over.h",
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
            "over.cpp",
            r#"
#include "over.h"

using namespace log4cxx;

int doFormat() { return 1; }
int doFormat(int a, int b) { return a + b; }

int HTMLLayout::getContentType() const {
    return doFormat();
}
"#,
        )
        .build();

    let status = definition_reference_status(
        &project,
        "log4cxx.HTMLLayout.getContentType",
        "return doFormat();",
        "doFormat",
    );
    assert_eq!(
        status, "resolved",
        "arity 0 must select the nullary overload of `doFormat` unambiguously"
    );
}

/// Two same-arity `doFormat()` free functions, each in a distinct namespace
/// pulled into scope by its own `using namespace` directive, are an ambiguous
/// unqualified call in real C++. Arity cannot disambiguate (both are nullary),
/// so the lookup must not silently resolve to one -- it must report the
/// ambiguity rather than a single (arbitrary) definition.
#[test]
fn two_same_arity_candidates_from_distinct_directives_are_ambiguous() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "amb.h",
            r#"
namespace log4cxx {
class HTMLLayout {
public:
    int getContentType() const;
};
}
namespace alpha { int doFormat(); }
namespace beta { int doFormat(); }
"#,
        )
        .file(
            "amb.cpp",
            r#"
#include "amb.h"

using namespace log4cxx;
using namespace alpha;
using namespace beta;

namespace alpha { int doFormat() { return 1; } }
namespace beta { int doFormat() { return 2; } }

int HTMLLayout::getContentType() const {
    return doFormat();
}
"#,
        )
        .build();

    let status = definition_reference_status(
        &project,
        "log4cxx.HTMLLayout.getContentType",
        "return doFormat();",
        "doFormat",
    );
    assert_ne!(
        status, "resolved",
        "two same-arity `doFormat` candidates from distinct using-directives must not \
         silently resolve to one; got status {status}"
    );
}
