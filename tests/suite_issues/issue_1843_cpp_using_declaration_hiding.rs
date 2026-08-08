//! Issue #1843: the #1835 `using Base::name;` overload merge ignores C++
//! [namespace.udecl]/14.
//!
//! A using-declaration re-exposes the base overload set, but a member of the
//! deriving class with the same name *and the same parameter-type-list* hides
//! the base member the using-declaration would otherwise introduce. #1835
//! merged every base overload unconditionally, so `using Base::format;` next
//! to a `format(...) const override` turned a call that had resolved to the
//! derived override into an ambiguity between the override and the base
//! declaration it overrides.
//!
//! The #1835 contract is the other half of the pin: a base overload whose
//! signature the deriving class does *not* declare is not hidden and must stay
//! merged.

use crate::common::{InlineTestProject, definition_at};
use brokk_bifrost::Language;
use serde_json::Value;

/// The fully-qualified names a `get_definitions_by_location` result reports.
fn definition_fq_names(result: &Value) -> Vec<String> {
    result["definitions"]
        .as_array()
        .map(|definitions| {
            definitions
                .iter()
                .filter_map(|definition| definition["fqn"].as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// The fully-qualified name and signature of each reported definition, for the
/// cases that have to name one overload of a name rather than the name.
fn definition_signatures(result: &Value) -> Vec<(String, String)> {
    result["definitions"]
        .as_array()
        .map(|definitions| {
            definitions
                .iter()
                .filter_map(|definition| {
                    Some((
                        definition["fqn"].as_str()?.to_string(),
                        definition["signature"].as_str().unwrap_or("").to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The log4cxx `FullLocationPatternConverter` shape with the derived parameter
/// list spelled out: `using Base::format;` plus an override of the
/// three-parameter base virtual. The override hides the base declaration, so
/// the call answers the override alone.
#[test]
fn a_derived_override_hides_the_using_introduced_base_overload() {
    let header = r#"#pragma once
namespace pat {
class Event;
class Pool;
class LogString;

class Base {
 public:
  virtual void format(const Event& event, LogString& out, Pool& p) const;
  void format(const Event& event, LogString& out) const;
};

class Derived : public Base {
 public:
  using Base::format;
  void format(const Event& event, LogString& out, Pool& p) const override;
};
}  // namespace pat
"#;
    let body = r#"#include "a.h"
namespace pat {
void Base::format(const Event& event, LogString& out, Pool& p) const {}
void Base::format(const Event& event, LogString& out) const {}
void Derived::format(const Event& event, LogString& out, Pool& p) const {}
void drive(const Event& e, LogString& o, Pool& p) {
  Derived().format(e, o, p);
}
}  // namespace pat
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("a.h", header)
        .file("a.cpp", body)
        .build();
    let result = definition_at(&project, "a.cpp", body, "format(e, o, p)");
    assert_eq!(
        result["status"], "resolved",
        "the derived override hides the base overload it overrides: {result:#}"
    );
    let names = definition_fq_names(&result);
    assert!(
        names.iter().all(|name| !name.contains("Base.format")),
        "the hidden base overload must not be reported, got {names:?}: {result:#}"
    );
}

/// The `Y-a` fixture shape: the derived parameter list is spelled as an
/// object-like macro, which is how log4cxx writes it
/// (`LOG4CXX_FORMAT_EVENT_FORMAL_PARAMETERS`), and the macro expands to the
/// base's parameter list. The hiding verdict must not change.
#[test]
fn a_macro_spelled_derived_parameter_list_still_hides_the_base_overload() {
    let header = r#"#pragma once
namespace pat {
class Event;
class Pool;
class LogString;

#define FMT_PARAMS const Event& event, LogString& out, Pool& p

class Base {
 public:
  virtual void format(const Event& event, LogString& out, Pool& p) const;
  void format(const Event& event, LogString& out) const;
};

class Derived : public Base {
 public:
  using Base::format;
  void format(FMT_PARAMS) const override;
};
}  // namespace pat
"#;
    let body = r#"#include "a.h"
namespace pat {
void Base::format(const Event& event, LogString& out, Pool& p) const {}
void Base::format(const Event& event, LogString& out) const {}
void Derived::format(const Event& event, LogString& out, Pool& p) const {}
void drive(const Event& e, LogString& o, Pool& p) {
  Derived().format(e, o, p);
}
}  // namespace pat
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("a.h", header)
        .file("a.cpp", body)
        .build();
    let result = definition_at(&project, "a.cpp", body, "format(e, o, p)");
    assert_eq!(
        result["status"], "resolved",
        "a macro-spelled derived parameter list still hides the base overload: {result:#}"
    );
    let names = definition_fq_names(&result);
    assert!(
        names.iter().all(|name| !name.contains("Base.format")),
        "the hidden base overload must not be reported, got {names:?}: {result:#}"
    );
}

/// The macro-spelled derived parameter list with no out-of-line definition to
/// restate it, so the only record of the list is the macro token itself. The
/// header declares the macro plainly, so it expands and hides the base
/// overload it matches; the base declaration must not be the answer.
#[test]
fn a_macro_only_derived_parameter_list_hides_the_base_overload_it_expands_to() {
    let header = r#"#pragma once
namespace pat {
class Event;
class Pool;
class LogString;

#define FMT_PARAMS const Event& event, LogString& out, Pool& p

class Base {
 public:
  virtual void format(const Event& event, LogString& out, Pool& p) const;
  void format(const Event& event, LogString& out) const;
};

class Derived : public Base {
 public:
  using Base::format;
  void format(FMT_PARAMS) const override {}
};
}  // namespace pat
"#;
    let body = r#"#include "a.h"
namespace pat {
void Base::format(const Event& event, LogString& out, Pool& p) const {}
void Base::format(const Event& event, LogString& out) const {}
void drive(const Event& e, LogString& o, Pool& p) {
  Derived().format(e, o, p);
}
}  // namespace pat
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("a.h", header)
        .file("a.cpp", body)
        .build();
    let result = definition_at(&project, "a.cpp", body, "format(e, o, p)");
    // The two-parameter base overload has no counterpart in the deriving class
    // and stays merged; only the three-parameter one the macro expands onto is
    // hidden.
    let reported = definition_signatures(&result);
    assert!(
        !reported
            .iter()
            .any(|(fqn, signature)| fqn == "pat.Base.format" && signature.contains("Pool")),
        "the base overload the macro expands onto is hidden, got {reported:?}: {result:#}"
    );
}

/// The same shape with the macro defined in both branches of a `#if`, so the
/// macro environment records the name but cannot pin one replacement - the
/// log4cxx `LOG4CXX_ABI_VERSION` shape. An unpinnable macro is an unknown, and
/// an unknown parameter list in the deriving class must not let the base
/// overload through.
#[test]
fn an_unpinnable_macro_parameter_list_still_hides_the_base_overload() {
    let header = r#"#pragma once
namespace pat {
class Event;
class Pool;
class LogString;

#if PAT_ABI_VERSION > 1
#define FMT_PARAMS const Event& event, LogString& out, Pool& p
#else
#define FMT_PARAMS const Event& event, LogString& out, Pool& p, int extra
#endif

class Base {
 public:
  virtual void format(const Event& event, LogString& out, Pool& p) const;
};

class Derived : public Base {
 public:
  using Base::format;
  void format(FMT_PARAMS) const override {}
};
}  // namespace pat
"#;
    let body = r#"#include "a.h"
namespace pat {
void Base::format(const Event& event, LogString& out, Pool& p) const {}
void drive(const Event& e, LogString& o, Pool& p) {
  Derived().format(e, o, p);
}
}  // namespace pat
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("a.h", header)
        .file("a.cpp", body)
        .build();
    let result = definition_at(&project, "a.cpp", body, "format(e, o, p)");
    let names = definition_fq_names(&result);
    assert!(
        names.iter().all(|name| !name.contains("Base.format")),
        "an unreadable derived parameter list must not let the base overload through, got {names:?}: {result:#}"
    );
}

/// The #1835 contract: the two-parameter base overload has no counterpart in
/// the deriving class, so nothing hides it and the using-declaration must keep
/// it in the derived overload set.
#[test]
fn an_unmatched_base_overload_stays_merged() {
    let header = r#"#pragma once
namespace pat {
class Event;
class Pool;
class LogString;

class Base {
 public:
  virtual void format(const Event& event, LogString& out, Pool& p) const;
  void format(const Event& event, LogString& out) const;
};

class Derived : public Base {
 public:
  using Base::format;
  void format(const Event& event, LogString& out, Pool& p) const override;
};
}  // namespace pat
"#;
    let body = r#"#include "a.h"
namespace pat {
void Base::format(const Event& event, LogString& out, Pool& p) const {}
void Base::format(const Event& event, LogString& out) const {}
void Derived::format(const Event& event, LogString& out, Pool& p) const {}
void drive2(const Event& e, LogString& o) {
  Derived().format(e, o);
}
}  // namespace pat
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("a.h", header)
        .file("a.cpp", body)
        .build();
    let result = definition_at(&project, "a.cpp", body, "format(e, o)");
    assert_eq!(
        result["status"], "resolved",
        "an unmatched base overload stays merged by the using-declaration: {result:#}"
    );
    let names = definition_fq_names(&result);
    assert!(
        names.iter().any(|name| name.contains("Base.format")),
        "the two-parameter base overload is the answer, got {names:?}: {result:#}"
    );
}
