//! Issue #1828: a `using`/`typedef` alias whose target is not in the index is
//! *unresolvable*, not *ambiguous*. `canonical_type_unit` returned `None` for
//! both "the alias target is outside the index" and "the alias target has
//! several indexed declarations", and `resolve_imported_type_candidate` mapped
//! every `None` onto `LexicalTypeResolution::Ambiguous`. A unique alias to a
//! template parameter or to a standard-library type therefore answered
//! `ambiguous` with an empty target list.
//!
//! Ambiguity means "choose one of these"; an answer with nothing to choose from
//! is a missing answer. A genuinely ambiguous alias target - two indexed
//! declarations answering to the target name - must keep answering `ambiguous`.

use crate::common::{BuiltInlineTestProject, InlineTestProject, call_tool};
use brokk_bifrost::Language;
use serde_json::{Value, json};

fn definition_at(
    project: &BuiltInlineTestProject,
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

fn single_file_project(path: &str, source: &str) -> BuiltInlineTestProject {
    InlineTestProject::with_language(Language::Cpp)
        .file(path, source)
        .build()
}

/// q3, the abseil `linked_hash_map::hasher` shape: a member alias whose target
/// is a template parameter. The alias name is unique in the workspace, so
/// there is nothing to be ambiguous between.
#[test]
fn unique_alias_to_a_template_parameter_is_not_ambiguous() {
    let source = r#"#pragma once
template <class K, class KeyHash>
class linked_hash_map {
 public:
  using hasher = KeyHash;
  explicit linked_hash_map(int n) : linked_hash_map(n, hasher()) {}
  linked_hash_map(int n, const hasher& h) : n_(n) {}
  int n_;
};
"#;
    let project = single_file_project("a.h", source);
    let result = definition_at(&project, "a.h", source, "hasher())");
    assert_ne!(
        result["status"], "ambiguous",
        "an alias target outside the index is unresolvable, not ambiguous: {result:#}"
    );
    assert_eq!(result["status"], "no_definition", "{result:#}");
    assert!(
        result["definitions"]
            .as_array()
            .is_none_or(|definitions| definitions.is_empty()),
        "a missing answer must not carry definitions: {result:#}"
    );
}

/// q6: a file-scope alias to a standard-library template that the workspace
/// does not index.
#[test]
fn alias_to_an_unindexed_std_template_is_not_ambiguous() {
    let source = r#"#include <vector>
using JsonVector = std::vector<int>;
JsonVector make() { return JsonVector(); }
"#;
    let project = single_file_project("a.cc", source);
    let result = definition_at(&project, "a.cc", source, "JsonVector();");
    assert_ne!(
        result["status"], "ambiguous",
        "an alias to an unindexed std template is unresolvable, not ambiguous: {result:#}"
    );
    assert_eq!(result["status"], "no_definition", "{result:#}");
}

/// q5 control: the alias target is indexed, so the call still resolves to the
/// underlying class.
#[test]
fn alias_to_an_indexed_class_still_resolves() {
    let source = r#"struct Foo { int value; };
using Alias = Foo;
Alias make() { return Alias(); }
"#;
    let project = single_file_project("a.cc", source);
    let result = definition_at(&project, "a.cc", source, "Alias();");
    assert_eq!(result["status"], "resolved", "{result:#}");
}

/// q8 control: an alias to a builtin already answered the alias declaration
/// itself, and must keep doing so.
#[test]
fn alias_to_a_builtin_still_resolves() {
    let source = r#"using Alias = int;
Alias make() { return Alias(); }
"#;
    let project = single_file_project("a.cc", source);
    let result = definition_at(&project, "a.cc", source, "Alias();");
    assert_eq!(result["status"], "resolved", "{result:#}");
}

/// Negative control: when the alias target name really does have two indexed
/// declarations, the answer stays `ambiguous`.
#[test]
fn alias_to_an_ambiguous_indexed_target_stays_ambiguous() {
    let source = r#"namespace one { struct Target { int a; }; }
namespace two { struct Target { int b; }; }
using namespace one;
using namespace two;
using Alias = Target;
Alias make() { return Alias(); }
"#;
    let project = single_file_project("a.cc", source);
    let result = definition_at(&project, "a.cc", source, "Alias();");
    assert_eq!(
        result["status"], "ambiguous",
        "two indexed declarations of the alias target are a real ambiguity: {result:#}"
    );
}
