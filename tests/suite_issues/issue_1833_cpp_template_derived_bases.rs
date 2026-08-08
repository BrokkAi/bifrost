//! Issue #1833: inherited-member lookup recovered a class's base list by
//! string-splitting the class's *rendered signature* at the first `:`. A class
//! template renders with a `template <...>` prefix, so the split found the
//! wrong `:` (or none), the base list came back empty, and every inherited
//! member of every class template was unreachable.
//!
//! The graph already holds the answer: `get_direct_ancestors` reads the
//! `base_class_clause` from the AST and is correct for the same classes. The
//! perturbation matrix proved the causal factor is exactly "the owner is a
//! class template": own members resolve, `Base::m()` resolves, plain `struct D
//! : B` resolves, and only `template <class T> struct D : B` fails.
//!
//! Secondary defect: an empty candidate set was reported as
//! `unsupported_cpp_receiver` even when the receiver resolved perfectly, which
//! is what disguised this family as a receiver-typing problem.

use crate::common::{InlineTestProject, definition_at, definition_paths};
use brokk_bifrost::Language;
use serde_json::Value;

fn diagnostic_kinds(result: &Value) -> Vec<String> {
    result["diagnostics"]
        .as_array()
        .map(|diagnostics| {
            diagnostics
                .iter()
                .filter_map(|diagnostic| diagnostic["kind"].as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Row 1 of the matrix, the control: a non-template derived class already
/// reached its base member and must keep doing so.
#[test]
fn plain_derived_class_resolves_inherited_member() {
    let source = r#"#pragma once
struct XB { void xbase() {} };
struct XD1 : XB { void g() { this->xbase(); } };
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("x.h", source)
        .build();
    let result = definition_at(&project, "x.h", source, "xbase(); }");
    assert_eq!(
        result["status"], "resolved",
        "the non-template control regressed: {result:#}"
    );
}

/// Rows 3-6: the derived class is a template and the base is an ordinary
/// class. Nothing about the base is dependent; only the derived head changed.
#[test]
fn template_derived_class_resolves_inherited_member() {
    let source = r#"#pragma once
struct XB {
    void alpha() {}
    void beta() {}
    void gamma() {}
};
template <class T> struct XD2 : XB { void g() { this->alpha(); } };
template <typename T> struct XD4 : public XB { void h() { this->beta(); } };
template <int N> struct XD5 : XB { void k() { this->gamma(); } };
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("x.h", source)
        .build();
    for needle in ["alpha(); }", "beta(); }", "gamma(); }"] {
        let result = definition_at(&project, "x.h", source, needle);
        assert_eq!(
            result["status"], "resolved",
            "a class template must reach its base member (`{needle}`): {result:#}"
        );
        let paths = definition_paths(&result);
        assert!(
            paths.iter().any(|path| path.ends_with("x.h")),
            "the inherited member must be reported, got {paths:?}: {result:#}"
        );
    }
}

/// Row 5: a dependent base `B<T>` behaves the same way once the base clause is
/// read from the graph rather than from the rendered head.
#[test]
fn template_derived_class_with_dependent_base_resolves_inherited_member() {
    let source = r#"#pragma once
template <class T> struct B2 { void construct() {} };
template <class T> struct D2 : B2<T> { void g() { this->construct(); } };
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("y.h", source)
        .build();
    let result = definition_at(&project, "y.h", source, "construct(); }");
    assert_eq!(
        result["status"], "resolved",
        "a dependent base of a class template must still be walked: {result:#}"
    );
}

/// Row 9: the bare-call spelling fails through the same base walk, so it must
/// be fixed by the same change.
#[test]
fn bare_call_in_template_derived_class_resolves_inherited_member() {
    let source = r#"#pragma once
struct WB { void wconstruct() {} };
template <class T> struct WD2 : WB { void g() { wconstruct(); } };
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("w.h", source)
        .build();
    let result = definition_at(&project, "w.h", source, "wconstruct(); }");
    assert_eq!(
        result["status"], "resolved",
        "a bare inherited call inside a class template must resolve: {result:#}"
    );
}

/// Row 12: a typed receiver whose type is a class template. Row 11 (the same
/// receiver reaching an *own* member) already resolved, which is what proves
/// the owner itself was never the problem.
#[test]
fn typed_receiver_of_template_type_resolves_inherited_member() {
    let source = r#"#pragma once
struct ZB { void zbm() {} };
template <class T> struct ZD : ZB { void zown() {} };
inline void driver(ZD<int>& r) {
    r.zown();
    r.zbm();
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("z.h", source)
        .build();
    let own = definition_at(&project, "z.h", source, "zown();\n");
    assert_eq!(
        own["status"], "resolved",
        "the own-member control regressed: {own:#}"
    );
    let inherited = definition_at(&project, "z.h", source, "zbm();\n}");
    assert_eq!(
        inherited["status"], "resolved",
        "an inherited member reached through a class-template receiver must resolve: {inherited:#}"
    );
}

/// The secondary defect: when the receiver type resolves and only the member
/// walk comes up empty, the answer must say the member was not found on that
/// owner. `unsupported_cpp_receiver` claims the receiver could not be typed,
/// which is false here and actively misdirects triage.
#[test]
fn resolved_receiver_with_unknown_member_is_not_blamed_on_the_receiver() {
    let source = r#"#pragma once
struct Owner { void known() {} };
inline void driver(Owner& o) {
    o.absent_member();
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("o.h", source)
        .build();
    let result = definition_at(&project, "o.h", source, "absent_member()");
    let kinds = diagnostic_kinds(&result);
    assert!(
        !kinds.iter().any(|kind| kind == "unsupported_cpp_receiver"),
        "a receiver that typed fine must not be blamed for a missing member, got {kinds:?}: {result:#}"
    );
}
