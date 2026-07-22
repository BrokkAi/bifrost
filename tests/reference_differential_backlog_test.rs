//! Empirical validation fixtures for the reference-differential backlog issues #933-#939.
//!
//! These tests encode the deciding shape from each issue's triage so that fix work can be
//! planned from a reproducible pass/fail signal rather than re-litigating the bug report.
//! This file intentionally does NOT fix anything; a FAIL here documents live behavior for the
//! evidence trail.
//!
//! #937 (Scala per-overload rescan perf contract) is not duplicated here: its existing
//! 128-replica regression already lives at
//! `scala_file_major_query_scans_one_candidate_once_for_many_physical_targets` in
//! `tests/usages_scala_graph_test.rs`.

mod common;

use brokk_bifrost::usages::{ScalaUsageGraphStrategy, UsageAnalyzer, UsageHit};
use brokk_bifrost::{
    CodeUnitType, CppAnalyzer, IAnalyzer, Language, ScalaAnalyzer, TypeHierarchyProvider,
};
use common::{InlineTestProject, call_search_tool_json};
use serde_json::{Value, json};

fn column_of(line: &str, needle: &str) -> usize {
    line.find(needle).expect("needle in line") + 1
}

fn lookup_by_location(root: &std::path::Path, args: &Value) -> Value {
    call_search_tool_json(root, "get_definitions_by_location", &args.to_string())
}

fn lookup_by_reference(root: &std::path::Path, args: &Value) -> Value {
    call_search_tool_json(root, "get_definitions_by_reference", &args.to_string())
}

fn lookup_declarations_by_location(root: &std::path::Path, args: &Value) -> Value {
    call_search_tool_json(root, "get_declarations_by_location", &args.to_string())
}

fn scan_usages_by_reference(root: &std::path::Path, args: &Value) -> Value {
    call_search_tool_json(root, "scan_usages_by_reference", &args.to_string())
}

fn hits(strategy_result: brokk_bifrost::usages::FuzzyResult) -> Vec<UsageHit> {
    strategy_result
        .into_either()
        .expect("expected usage graph success")
        .into_iter()
        .collect()
}

fn assert_hit_contains(hits: &[UsageHit], needle: &str) {
    assert!(
        hits.iter().any(|hit| hit.snippet.contains(needle)),
        "expected hit containing {needle:?}, got {hits:#?}"
    );
}

// ---------------------------------------------------------------------------------------------
// #933 - Scala export chains: inverse usage of the exported callable must find the caller
// site reached only through a re-export + wildcard import. Triage: fixed by 0350bdbf
// (`exported_member_bindings`).
// ---------------------------------------------------------------------------------------------

#[test]
fn issue_933_scala_export_chain_inverse_usage_finds_caller_through_facade_import() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "impl/Impl.scala",
            r#"package impl

object Impl {
  def work(): Int = 1
}
"#,
        )
        .file(
            "facade/Facade.scala",
            r#"package facade

import impl.Impl

object Facade {
  export Impl.work
}
"#,
        )
        .file(
            "caller/Caller.scala",
            r#"package caller

import facade.Facade._

object Caller {
  def caller(): Int = work() // positive-export-chain-call
}
"#,
        )
        .build();
    let analyzer = ScalaAnalyzer::from_project(project.project().clone());

    let target = analyzer
        .get_definitions("impl.Impl$.work")
        .into_iter()
        .next()
        .unwrap_or_else(|| {
            panic!(
                "missing definition for impl.Impl$.work, all decls: {:#?}",
                analyzer.get_all_declarations()
            )
        });
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let target_hits = hits(ScalaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    ));
    assert_hit_contains(&target_hits, "positive-export-chain-call");
}

// ---------------------------------------------------------------------------------------------
// #934 - C attribute visibility: a forward reference to a declared-and-attributed function
// (plain `__attribute__` and macro-wrapped `__dead2`-style attribute) must resolve to the
// included header, never to an unrelated same-named definition in a file that isn't part of
// the translation unit.
// ---------------------------------------------------------------------------------------------

#[test]
fn issue_934_c_attributed_declaration_resolves_to_included_header_not_unrelated_namesake() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "stand.h",
            r#"__attribute__((noreturn)) void panic(const char *);
#define __dead2 __attribute__((__noreturn__))
__dead2 void panic2(const char *);
"#,
        )
        .file(
            "main.c",
            r#"#include "stand.h"
void run() {
    panic("x");
    panic2("x");
}
"#,
        )
        .file(
            "other.c",
            r#"void panic(const char *s) {}
void panic2(const char *s) {}
"#,
        )
        .build();

    // `panic`/`panic2` are bodyless declarations in the included TU (their only bodies live in
    // the unrelated, non-included `other.c`), so declaration lookup -- not definition lookup --
    // is the right forward-navigation surface here.
    let call_line = "    panic(\"x\");";
    let value = lookup_declarations_by_location(
        project.root(),
        &json!({
            "references": [{"path": "main.c", "line": 3, "column": column_of(call_line, "panic")}]
        }),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["declarations"][0]["path"], "stand.h", "{value}");
    assert_ne!(result["declarations"][0]["path"], "other.c", "{value}");

    let call2_line = "    panic2(\"x\");";
    let value2 = lookup_declarations_by_location(
        project.root(),
        &json!({
            "references": [{"path": "main.c", "line": 4, "column": column_of(call2_line, "panic2")}]
        }),
    );
    let result2 = &value2["results"][0];
    assert_eq!(result2["status"], "resolved", "{value2}");
    assert_eq!(result2["declarations"][0]["path"], "stand.h", "{value2}");
    assert_ne!(result2["declarations"][0]["path"], "other.c", "{value2}");
}

// ---------------------------------------------------------------------------------------------
// #935 - C++ static member vs constructor: a qualified call to a static method on a class
// template must resolve to the static member, not the (same-named-class) constructor.
// Triage: fixed today by 433bc4a2 ("Fix C++ constructor navigation identity"); residual risk
// is template-argument stripping on the qualified scope (`Loader<int>::parse()`).
// ---------------------------------------------------------------------------------------------

#[test]
fn issue_935_cpp_templated_static_member_call_resolves_to_static_not_constructor() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "loader.h",
            r#"template<class T> struct Loader {
    Loader();
    static int parse();
};

template<class T> int Loader<T>::parse() { return 1; }
"#,
        )
        .file(
            "main.cpp",
            r#"#include "loader.h"
int x = Loader<int>::parse();
"#,
        )
        .build();

    let call_line = "int x = Loader<int>::parse();";
    let value = lookup_by_location(
        project.root(),
        &json!({
            "references": [{"path": "main.cpp", "line": 2, "column": column_of(call_line, "parse")}]
        }),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    let definitions = result["definitions"].as_array().expect("definitions array");
    assert_eq!(definitions.len(), 1, "{value}");
    let fqn = definitions[0]["fqn"].as_str().expect("fqn string");
    assert!(
        fqn.ends_with("parse"),
        "expected static member `parse`, got constructor-shaped fqn {fqn:?}: {value}"
    );
}

// ---------------------------------------------------------------------------------------------
// #936 - C++ field include-closure: two headers declare same-FQN structs with disjoint field
// sets; only one is included by the translation unit. Forward field access must resolve to the
// included header's field. Triage: forward path has `is_physically_visible`, but the
// reference-based ("field owner") resolution path is unverified -- probe both.
// ---------------------------------------------------------------------------------------------

#[test]
fn issue_936_cpp_field_include_closure_resolves_to_included_header_field() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("a.h", "struct BlockDescriptor { int fieldA; };\n")
        .file("b.h", "struct BlockDescriptor { int fieldB; };\n")
        .file(
            "main.c",
            r#"#include "a.h"
struct BlockDescriptor d;
void use_block() {
    d.fieldA = 1; // field-access-site
}
"#,
        )
        .build();

    // Forward: resolve the field access by location.
    let access_line = "    d.fieldA = 1; // field-access-site";
    let value = lookup_by_location(
        project.root(),
        &json!({
            "references": [{"path": "main.c", "line": 4, "column": column_of(access_line, "fieldA")}]
        }),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["path"], "a.h", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "BlockDescriptor.fieldA",
        "{value}"
    );
    assert_ne!(result["definitions"][0]["path"], "b.h", "{value}");

    // Field-owner probe: resolve the same field by reference (symbol/context/target), which is
    // a distinct resolution path from location-based lookup.
    let by_ref = lookup_by_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "use_block",
                "context": access_line,
                "target": "fieldA"
            }]
        }),
    );
    let ref_result = &by_ref["results"][0];
    eprintln!("issue_936 field-owner (by-reference) probe result: {by_ref}");
    assert_eq!(
        ref_result["status"], "resolved",
        "field-owner reference path did not resolve `fieldA`: {by_ref}"
    );
    assert_eq!(
        ref_result["definitions"][0]["path"], "a.h",
        "field-owner reference path resolved to the wrong header: {by_ref}"
    );
}

// ---------------------------------------------------------------------------------------------
// #938 - C++ fragmented multi-base export class: an undefined all-caps macro token between
// `class` and the class name, combined with multiple base classes, makes tree-sitter fragment
// the declaration. Recovery must still index the class once (with its bases) and attribute a
// member declared much later in the body to that class.
// ---------------------------------------------------------------------------------------------

#[test]
#[ignore = "issue #938 is live; un-ignore when the fix lands"]
fn issue_938_cpp_fragmented_multi_base_export_class_recovers_class_and_late_member_owner() {
    let source = r#"#define CORE_EXPORT
namespace core {
class A {};
class B {};
class C {};
}
class CORE_EXPORT Widget : public core::A, public core::B, public core::C {
public:
    void early();
    // padding to push the next declaration well past the fragmented opening
    // padding
    // padding
    // padding
    // padding
    // padding
    // padding
    // padding
    // padding
    // padding
    void lateMethod();
};
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("widget.h", source)
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());

    let classes: Vec<_> = analyzer
        .get_all_declarations()
        .into_iter()
        .filter(|unit| unit.kind() == CodeUnitType::Class && !unit.is_synthetic())
        .collect();
    let widget_matches: Vec<_> = classes
        .iter()
        .filter(|unit| unit.fq_name() == "Widget")
        .collect();
    assert_eq!(
        widget_matches.len(),
        1,
        "Widget must index as exactly one class despite fragmentation: {classes:#?}"
    );
    let widget = widget_matches[0].clone();

    let ancestors: std::collections::BTreeSet<_> = analyzer
        .get_direct_ancestors(&widget)
        .into_iter()
        .map(|unit| unit.fq_name())
        .collect();
    assert_eq!(
        ancestors,
        std::collections::BTreeSet::from([
            "core.A".to_string(),
            "core.B".to_string(),
            "core.C".to_string(),
        ]),
        "Widget must recover all three fragmented bases"
    );

    let declarations = analyzer.get_all_declarations();
    let early_method = declarations
        .iter()
        .find(|unit| unit.kind() == CodeUnitType::Function && unit.identifier() == "early");
    assert!(
        early_method.is_some(),
        "expected `early` (declared immediately after the fragmented class opening) to be \
         indexed as a Function at all; it is entirely missing from declarations: {declarations:#?}"
    );
    assert_eq!(
        analyzer.parent_of(early_method.expect("checked above")),
        Some(widget.clone()),
        "a member declared right at the fragmented opening must be owned by Widget"
    );

    let late_method = declarations
        .iter()
        .find(|unit| unit.kind() == CodeUnitType::Function && unit.identifier() == "lateMethod");
    assert!(
        late_method.is_some(),
        "expected `lateMethod` (declared many lines after the fragmented class opening) to be \
         indexed as a Function at all; it is entirely missing from declarations: {declarations:#?}"
    );
    assert_eq!(
        analyzer.parent_of(late_method.expect("checked above")),
        Some(widget.clone()),
        "a member declared long after the fragmented opening must still be owned by Widget"
    );
}

// ---------------------------------------------------------------------------------------------
// #939 - C++ relative qualified bases: a base class named relative to an enclosing namespace
// (`PCM::Base` written inside `namespace Outer`, resolving to `Outer::PCM::Base`, mirroring the
// already-passing `cpp_type_hierarchy_resolves_relative_qualified_sibling_bases_and_aliases`
// ancestor-resolution coverage) must let an unqualified inherited member call resolve forward to
// the base member, AND the inverse usage scan of that same base member must find the call site.
// Triage assumed forward already resolves and only inverse was broken; empirically (see the
// `issue_939_control_*` test below) the *forward* bare-inherited-call resolver also fails for a
// relatively-qualified base even though `TypeHierarchyProvider::get_direct_ancestors` (a separate
// structural code path) already resolves the same relative base correctly -- the gap is
// specifically in the call/usage resolver, not in base/ancestor computation.
// ---------------------------------------------------------------------------------------------

/// Active regression for the #939 FORWARD half: the unqualified inherited `value()` call must
/// resolve through the namespace-relative base spelling (`PCM::Base` inside `namespace Outer`).
/// Fixed by routing `cpp_direct_base_types` through `cpp_resolve_type_unit_in_namespace`.
#[test]
fn issue_939_cpp_relative_qualified_base_member_call_resolves_forward() {
    let source = r#"namespace Outer {
namespace PCM {
struct Base {
    int value() const { return 1; }
};
}
struct Derived : PCM::Base {
    int run() const { return value(); } // positive-relative-qualified-base-member-call
};
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("bases.cpp", source)
        .build();

    let call_line =
        "    int run() const { return value(); } // positive-relative-qualified-base-member-call";
    let value = lookup_by_location(
        project.root(),
        &json!({
            "references": [{"path": "bases.cpp", "line": 8, "column": column_of(call_line, "value")}]
        }),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    let fqn = result["definitions"][0]["fqn"]
        .as_str()
        .expect("resolved fqn")
        .to_string();
    assert!(
        fqn.contains("Base") && fqn.ends_with("value"),
        "expected the call to resolve to the relatively-qualified base member `Base.value`, got {fqn:?}: {value}"
    );
}

#[test]
#[ignore = "issue #939 forward half is fixed (see the active forward-only regression above); \
the inverse scan_usages_by_reference half still fails identically for the *absolute*-qualified \
control shape (see \
issue_939_control_cpp_absolute_qualified_base_member_call_forward_resolution), proving the \
remaining gap is a general bare-inherited-member-call attribution limitation in \
cpp_graph/inverted.rs's resolve_declaring_member_owner (usage-graph side), not something in \
get_definition or specific to relative qualification. Un-ignore once that usage-graph gap is \
fixed."]
fn issue_939_cpp_relative_qualified_base_member_call_resolves_forward_and_inverse() {
    let source = r#"namespace Outer {
namespace PCM {
struct Base {
    int value() const { return 1; }
};
}
struct Derived : PCM::Base {
    int run() const { return value(); } // positive-relative-qualified-base-member-call
};
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("bases.cpp", source)
        .build();

    // Forward: resolve the unqualified inherited `value()` call to the relatively-qualified base.
    let call_line =
        "    int run() const { return value(); } // positive-relative-qualified-base-member-call";
    let value = lookup_by_location(
        project.root(),
        &json!({
            "references": [{"path": "bases.cpp", "line": 8, "column": column_of(call_line, "value")}]
        }),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    let fqn = result["definitions"][0]["fqn"]
        .as_str()
        .expect("resolved fqn")
        .to_string();
    eprintln!("issue_939 forward-resolved fqn: {fqn}");
    assert!(
        fqn.contains("Base") && fqn.ends_with("value"),
        "expected the call to resolve to the relatively-qualified base member `Base.value`, got {fqn:?}: {value}"
    );

    // Inverse: scan usages of that same resolved definition and confirm the call site is found.
    let scan = scan_usages_by_reference(
        project.root(),
        &json!({"symbols": [fqn], "include_tests": true}),
    );
    eprintln!("issue_939 inverse scan_usages_by_reference result: {scan}");
    let usage = &scan["results"][0];
    assert_eq!(
        usage["status"], "found",
        "inverse scan could not find any usage of {fqn:?}: {scan}"
    );
    let files = usage["files"].as_array().expect("files array");
    let found_site = files.iter().any(|file| {
        file["hits"].as_array().is_some_and(|hits| {
            hits.iter().any(|hit| {
                hit["snippet"].as_str().is_some_and(|snippet| {
                    snippet.contains("positive-relative-qualified-base-member-call")
                })
            })
        })
    });
    assert!(
        found_site,
        "inverse scan did not find the relative-qualified-base member call site: {scan}"
    );
}

/// Control for #939: the same inherited-member-call shape, but with the base spelled with a
/// fully qualified path (`Outer::PCM::Base`) instead of the namespace-relative `PCM::Base`. This
/// isolates whether a forward-resolution gap is specific to relative qualification or is a more
/// general limitation of bare inherited-member calls through a namespace-qualified base.
#[test]
fn issue_939_control_cpp_absolute_qualified_base_member_call_forward_resolution() {
    let source = r#"namespace Outer {
namespace PCM {
struct Base {
    int value() const { return 1; }
};
}
struct Derived : Outer::PCM::Base {
    int run() const { return value(); } // positive-absolute-qualified-base-member-call
};
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("bases.cpp", source)
        .build();

    let call_line =
        "    int run() const { return value(); } // positive-absolute-qualified-base-member-call";
    let value = lookup_by_location(
        project.root(),
        &json!({
            "references": [{"path": "bases.cpp", "line": 8, "column": column_of(call_line, "value")}]
        }),
    );
    eprintln!("issue_939 control (absolute-qualified base) forward result: {value}");
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
}
