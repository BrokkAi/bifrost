//! Issue #1835: `using Base::name;` in a derived class un-hides the base
//! overloads, but the base walk never merged them into the derived overload
//! set.
//!
//! `cpp_inherited_member_candidates` implements C++ name hiding correctly - it
//! stops at the first derivation level that declares the name. The level that
//! answers declares only the override, the arity filter empties the set, and
//! the call reports `no_applicable_overload` even though the base overload is
//! indexed, visible, and explicitly re-exposed by the source.
//!
//! The negative control is what keeps the fix honest: without the
//! `using`-declaration C++ really does hide the base overloads, so the same
//! call must still answer `no_applicable_overload`. The fix must key on the
//! using-declaration, not loosen the arity filter.

use crate::common::{InlineTestProject, definition_at};
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

/// The `log4cxx` shape, reduced: `OptionHandler` declares `act()` and
/// `act(Pool&)`, `Layout` re-exposes both with `using` and overrides the
/// one-argument form, and a further-derived class calls the zero-argument one.
#[test]
fn using_declaration_merges_the_base_overload() {
    let header = r#"#pragma once
namespace ns {
struct Pool {};
struct OptionHandler {
  void act();
  virtual void act(Pool&) = 0;
};
struct Layout : OptionHandler {
  using OptionHandler::act;
  void act(Pool& p) override;
};
}  // namespace ns
"#;
    let body = r#"#include "a.h"
namespace ns {
void OptionHandler::act() {}
void Layout::act(Pool& p) { (void)p; }
struct Sub : Layout {
  void go() { act(); }
};
}  // namespace ns
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("a.h", header)
        .file("a.cpp", body)
        .build();
    let result = definition_at(&project, "a.cpp", body, "act(); }");
    assert_eq!(
        result["status"], "resolved",
        "`using OptionHandler::act;` re-exposes the zero-argument overload: {result:#}"
    );
}

/// The same call one derivation level nearer: the `using`-declaration and the
/// override are on the class that owns the call.
#[test]
fn using_declaration_on_the_calling_class_merges_the_base_overload() {
    let header = r#"#pragma once
namespace ns {
struct Pool {};
struct OptionHandler {
  void act();
  virtual void act(Pool&) = 0;
};
}  // namespace ns
"#;
    let body = r#"#include "a.h"
namespace ns {
void OptionHandler::act() {}
struct Layout : OptionHandler {
  using OptionHandler::act;
  void act(Pool& p) override { (void)p; }
  void go() { act(); }
};
}  // namespace ns
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("a.h", header)
        .file("a.cpp", body)
        .build();
    let result = definition_at(&project, "a.cpp", body, "act(); }");
    assert_eq!(
        result["status"], "resolved",
        "a `using`-declaration on the calling class must un-hide the base overload: {result:#}"
    );
}

/// The negative control: no `using`-declaration, so C++ name hiding really
/// does remove the zero-argument base overload from the candidate set.
#[test]
fn without_a_using_declaration_the_base_overload_stays_hidden() {
    let header = r#"#pragma once
namespace ns {
struct Pool {};
struct OptionHandler {
  void act();
  virtual void act(Pool&) = 0;
};
struct NoUsing : OptionHandler {
  void act(Pool& p) override;
};
}  // namespace ns
"#;
    let body = r#"#include "a.h"
namespace ns {
void OptionHandler::act() {}
void NoUsing::act(Pool& p) { (void)p; }
struct Sub2 : NoUsing {
  void go() { act(); }
};
}  // namespace ns
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("a.h", header)
        .file("a.cpp", body)
        .build();
    let result = definition_at(&project, "a.cpp", body, "act(); }");
    assert_ne!(
        result["status"], "resolved",
        "without a `using`-declaration the base overload is hidden: {result:#}"
    );
    let kinds = diagnostic_kinds(&result);
    assert!(
        kinds.iter().any(|kind| kind == "no_applicable_overload"),
        "name hiding must still report no applicable overload, got {kinds:?}: {result:#}"
    );
}

/// A `using`-declaration must not import a name the base never declares.
#[test]
fn using_declaration_does_not_invent_an_unrelated_member() {
    let source = r#"#pragma once
namespace ns {
struct Base { void present() {} };
struct Derived : Base {
  using Base::present;
  void go() { absent(); }
};
}  // namespace ns
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("a.h", source)
        .build();
    let result = definition_at(&project, "a.h", source, "absent()");
    assert_ne!(
        result["status"], "resolved",
        "a `using`-declaration must not conjure an undeclared member: {result:#}"
    );
}
