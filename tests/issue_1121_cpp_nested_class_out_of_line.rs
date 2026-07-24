//! Issue #1121: an out-of-line C++ definition of a class-nested-in-class member
//! is always written with a multi-segment owner qualifier
//! (`Outer::Inner::method`), which C++ requires regardless of any
//! using-directive -- nested-class access is never brought into unqualified
//! scope by `using namespace`. When such a definition is written inside an
//! enclosing `namespace {}` block, `split_cpp_name` used to treat every owner
//! segment before the last as a *namespace* path (indexing it as
//! `log4cxx.Inner.method`, dropping `Outer` entirely), so it never unified with
//! the header declaration's `log4cxx.Outer$Inner.method` identity. The fix
//! reads the owner segments of an in-namespace out-of-line definition as the
//! class-nesting chain they are (Bifrost's `Outer$Inner` short-name
//! convention), stripping only a redundant re-statement of the enclosing
//! namespace, so the definition unifies with its header declaration.

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

/// The exact shape from the issue: a header declaring a class-nested-in-class
/// member, and an out-of-line `.cpp` definition of it written inside a
/// re-opened `namespace {}` block (no using-directive at all -- reproduces on
/// its own).
fn namespace_block_project() -> common::BuiltInlineTestProject {
    InlineTestProject::with_language(Language::Cpp)
        .file(
            "nested.h",
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
            "nested.cpp",
            r#"
#include "nested.h"

namespace log4cxx {
int Outer::Inner::method() const {
    return 2;
}
}
"#,
        )
        .build()
}

/// Header declaration and out-of-line definition of a nested-class member now
/// unify: the header's `log4cxx.Outer$Inner.method` identity is shared by the
/// `.cpp` definition, so the canonical symbol resolves to *both* sources.
#[test]
fn namespace_block_nested_member_unifies_declaration_and_definition() {
    let project = namespace_block_project();

    let result = symbol_sources(&project, "log4cxx.Outer$Inner.method");
    assert_eq!(
        result["not_found"].as_array().unwrap().len(),
        0,
        "canonical symbol reported not_found: {result}"
    );
    assert_eq!(
        result["ambiguous"].as_array().unwrap().len(),
        0,
        "canonical symbol reported ambiguous: {result}"
    );
    assert_eq!(
        sorted_source_paths(&result),
        vec!["nested.cpp".to_string(), "nested.h".to_string()],
        "declaration and out-of-line definition did not unify: {result}"
    );
}

/// The full display-spelling matrix for the nested member -- the canonical fq,
/// its `::` twin, the owner-qualified and fully-qualified `::` forms, and the
/// bare terminal name -- must all resolve, unambiguously, to the *same* two
/// declarations (header declaration + `.cpp` out-of-line definition). This is
/// the #1093-style I2 contract: no display spelling of a symbol may resolve to
/// a different declaration set than any other.
#[test]
fn every_display_spelling_of_the_nested_member_resolves_to_the_same_pair() {
    let project = namespace_block_project();

    let spellings = [
        "log4cxx.Outer$Inner.method",
        "log4cxx::Outer::Inner::method",
        "Outer::Inner::method",
        "method",
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
            vec!["nested.cpp".to_string(), "nested.h".to_string()],
            "`{spelling}` did not resolve to both the declaration and the definition: {result}"
        );
    }
}

/// Deeper nesting (`A::B::C::method`) works to arbitrary depth: every
/// intermediate owner segment is a class-nesting step, so the definition's
/// owner is `A$B$C` and it unifies with the header's `log4cxx.A$B$C.method`.
#[test]
fn three_deep_nested_member_unifies() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "deep.h",
            r#"
namespace log4cxx {
class A {
public:
    class B {
    public:
        class C {
        public:
            int method() const;
        };
    };
};
}
"#,
        )
        .file(
            "deep.cpp",
            r#"
#include "deep.h"

namespace log4cxx {
int A::B::C::method() const {
    return 3;
}
}
"#,
        )
        .build();

    let result = symbol_sources(&project, "log4cxx.A$B$C.method");
    assert_eq!(
        sorted_source_paths(&result),
        vec!["deep.cpp".to_string(), "deep.h".to_string()],
        "three-deep nested member did not unify: {result}"
    );
}

/// Same-file (header-only) shape: the class and its out-of-line member
/// definition live in one translation unit. This also unifies now -- the owner
/// chain is read as `Outer$Inner` rather than dropping `Outer`.
#[test]
fn same_file_nested_member_unifies() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "same.cpp",
            r#"
namespace log4cxx {
class Outer {
public:
    class Inner {
    public:
        int method() const;
    };
};
int Outer::Inner::method() const {
    return 2;
}
}
"#,
        )
        .build();

    let result = symbol_sources(&project, "log4cxx.Outer$Inner.method");
    assert_eq!(result["not_found"].as_array().unwrap().len(), 0, "{result}");
    // Declaration and definition are both in `same.cpp`, so the one nested
    // identity spans two source blocks in that file (the in-class declaration
    // and the out-of-line definition) rather than the definition splitting off
    // as a separate `log4cxx.Inner.method`.
    assert_eq!(
        sorted_source_paths(&result),
        vec!["same.cpp".to_string(), "same.cpp".to_string()],
        "{result}"
    );
    // The mis-split identity (Outer dropped) must not exist: `Inner` is not a
    // top-level class in `log4cxx`, and the normalization that unifies `$` with
    // `::` still keeps `Outer` a required segment, so this must not resolve.
    let split = symbol_sources(&project, "log4cxx.Inner.method");
    assert_eq!(
        split["sources"].as_array().unwrap().len(),
        0,
        "the pre-fix mis-split identity `log4cxx.Inner.method` still resolves: {split}"
    );
}

/// A definition that redundantly re-states the enclosing namespace it already
/// sits in (`namespace log4cxx { void log4cxx::Outer::Inner::method() {} }`)
/// must still land on the same nested identity, not `log4cxx$Outer$Inner`. The
/// redundant namespace prefix is stripped before the class chain is read.
#[test]
fn redundant_namespace_requalification_lands_on_the_same_identity() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "requal.h",
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
            "requal.cpp",
            r#"
#include "requal.h"

namespace log4cxx {
int log4cxx::Outer::Inner::method() const {
    return 2;
}
}
"#,
        )
        .build();

    let result = symbol_sources(&project, "log4cxx.Outer$Inner.method");
    assert_eq!(
        sorted_source_paths(&result),
        vec!["requal.cpp".to_string(), "requal.h".to_string()],
        "redundant re-qualification did not unify onto the nested identity: {result}"
    );
}

/// CRITICAL negative control: a *genuine* namespace chain
/// (`ns1::ns2::Klass::method`) written out-of-line at file scope must keep the
/// correct namespace interpretation (`package = ns1::ns2`, `owner = Klass`) and
/// still unify its header declaration with its definition. Had the fix mangled
/// the chain by dropping a namespace segment (e.g. to `ns1.Klass.method`), the
/// definition's normalized identity would diverge from the header's and the
/// symbol would resolve to only one source; requiring *both* sources proves the
/// namespace interpretation is intact. (The `$`/`::`/`.` display normalization
/// is deliberately lenient, so spelling-level negative probes cannot
/// distinguish `ns1$ns2$Klass` from `ns1::ns2::Klass` -- the source-count
/// contract is the meaningful signal here.)
#[test]
fn genuine_namespace_chain_keeps_namespace_interpretation() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "ns.h",
            r#"
namespace ns1 {
namespace ns2 {
class Klass {
public:
    int method() const;
};
}
}
"#,
        )
        .file(
            "ns.cpp",
            r#"
#include "ns.h"

int ns1::ns2::Klass::method() const {
    return 1;
}
"#,
        )
        .build();

    // Correct namespace-qualified identity: declaration + definition unify to
    // both sources -- proof the definition's owner stayed `ns1::ns2.Klass` and
    // was not mangled (a mangled owner would drop a source).
    let correct = symbol_sources(&project, "ns1::ns2.Klass.method");
    assert_eq!(
        correct["ambiguous"].as_array().unwrap().len(),
        0,
        "genuine namespace chain reported ambiguous: {correct}"
    );
    assert_eq!(
        sorted_source_paths(&correct),
        vec!["ns.cpp".to_string(), "ns.h".to_string()],
        "genuine namespace chain lost its declaration/definition unification: {correct}"
    );
}

/// The file-scope using-directive variant of the nested member remains on
/// today's (non-unifying) behavior: at file scope with no enclosing namespace,
/// `Outer::Inner::method` under `using namespace log4cxx;` is genuinely
/// ambiguous between a nested class in the used namespace and a namespace path,
/// and per-file extraction has no class table to resolve it. The header
/// declaration still resolves cleanly on its own (no crash, no spurious
/// cross-match); it simply does not unify with the definition. Documented as a
/// remaining #1121 gap, not a masked failure.
#[test]
fn file_scope_using_directive_nested_member_stays_on_todays_behavior() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "using.h",
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
            "using.cpp",
            r#"
#include "using.h"

using namespace log4cxx;

int Outer::Inner::method() const {
    return 2;
}
"#,
        )
        .build();

    // The header declaration resolves on its own (single source): the fix does
    // not regress or crash this shape.
    let result = symbol_sources(&project, "log4cxx.Outer$Inner.method");
    assert_eq!(result["not_found"].as_array().unwrap().len(), 0, "{result}");
    assert_eq!(
        sorted_source_paths(&result),
        vec!["using.h".to_string()],
        "file-scope using-directive nested member unexpectedly changed: {result}"
    );
}
