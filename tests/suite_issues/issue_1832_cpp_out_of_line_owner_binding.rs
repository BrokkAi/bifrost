//! Issue #1832: an out-of-line definition `Owner::member(...) { ... }` is
//! structured proof that `Owner` names a class-like entity in that file's
//! scope, but resolution ignored it and required an `#include` edge to the
//! header that declares `Owner`.
//!
//! google/wuffs `internal/cgen/auxiliary/image.cc` is a build fragment that is
//! concatenated rather than compiled, so it never includes `image.hh`. It does
//! define `DecodeImageResult::DecodeImageResult(...)` out of line, and every
//! `return DecodeImageResult(...)` in the same file failed to resolve.
//!
//! The controls (owner declared in the same file, owner declared in an included
//! header) already resolved and must keep resolving.

use crate::common::{InlineTestProject, call_tool};
use brokk_bifrost::Language;
use serde_json::{Value, json};

fn definition_at(
    project: &crate::common::BuiltInlineTestProject,
    path: &str,
    source: &str,
    needle: &str,
) -> Value {
    let start = source
        .find(needle)
        .unwrap_or_else(|| panic!("`{needle}` is not present in {path}"));
    let prefix = &source[..start];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix, |(_, current_line)| current_line)
        .chars()
        .count()
        + 1;
    let args = json!({"references": [{"path": path, "line": line, "column": column}]}).to_string();
    call_tool(project, "get_definitions_by_location", &args)["results"][0].clone()
}

const HEADER: &str = r#"#ifndef A_H
#define A_H
#include <string>
namespace ns {
struct Res {
  Res(std::string&& m);
  std::string msg;
};
}
#endif
"#;

/// The wuffs shape: the header exists in the workspace but the fragment does
/// not include it. The out-of-line constructor in the fragment is the owner
/// evidence.
#[test]
fn out_of_line_constructor_binds_its_owner_without_an_include_edge() {
    let fragment = r#"#include <string>
namespace ns {
Res::Res(std::string&& m) : msg(std::move(m)) {}
Res make() {
  return Res("boom");
}
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("a.h", HEADER)
        .file("a.cpp", fragment)
        .build();
    let result = definition_at(&project, "a.cpp", fragment, "Res(\"boom\")");
    assert_eq!(
        result["status"], "resolved",
        "an out-of-line definition proves the owner binding in its own file: {result:#}"
    );
}

/// Control: the owner declared in the same file already resolved.
#[test]
fn same_file_owner_control_stays_resolved() {
    let fragment = r#"#include <string>
namespace ns {
struct Res {
  Res(std::string&& m);
  std::string msg;
};
Res::Res(std::string&& m) : msg(std::move(m)) {}
Res make() {
  return Res("boom");
}
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("a.cpp", fragment)
        .build();
    let result = definition_at(&project, "a.cpp", fragment, "Res(\"boom\")");
    assert_eq!(
        result["status"], "resolved",
        "same-file owner control regressed: {result:#}"
    );
}

/// Control: the owner declared in an included header already resolved.
#[test]
fn included_header_owner_control_stays_resolved() {
    let fragment = r#"#include "a.h"
namespace ns {
Res::Res(std::string&& m) : msg(std::move(m)) {}
Res make() {
  return Res("boom");
}
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("a.h", HEADER)
        .file("a.cpp", fragment)
        .build();
    let result = definition_at(&project, "a.cpp", fragment, "Res(\"boom\")");
    assert_eq!(
        result["status"], "resolved",
        "included-header owner control regressed: {result:#}"
    );
}

/// Negative control: a bare call to a name that no out-of-line definition in
/// the file owns must still answer `no_definition`. The owner binding is
/// evidence for one name, not a wildcard.
#[test]
fn unrelated_bare_call_still_has_no_definition() {
    let fragment = r#"#include <string>
namespace ns {
Res::Res(std::string&& m) : msg(std::move(m)) {}
Res make() {
  Absent("boom");
  return Res("boom");
}
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("a.cpp", fragment)
        .build();
    let result = definition_at(&project, "a.cpp", fragment, "Absent(\"boom\")");
    assert_eq!(
        result["status"], "no_definition",
        "an owner binding must not answer for an unrelated name: {result:#}"
    );
}
