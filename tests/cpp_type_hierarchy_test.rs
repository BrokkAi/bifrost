mod common;

use brokk_bifrost::{CodeUnit, CppAnalyzer, IAnalyzer, Language, TypeHierarchyProvider};
use common::{BuiltInlineTestProject, InlineTestProject};
use std::collections::BTreeSet;
use std::path::Path;

fn cpp_analyzer_with_files(files: &[(&str, &str)]) -> (BuiltInlineTestProject, CppAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::Cpp);
    for (path, contents) in files {
        builder = builder.file(path, *contents);
    }
    let project = builder.build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn definition(analyzer: &CppAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
}

fn definition_in(analyzer: &CppAnalyzer, fq_name: &str, source: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .find(|unit| unit.source().rel_path() == Path::new(source))
        .unwrap_or_else(|| panic!("missing definition for {fq_name} in {source}"))
}

fn fq_names(units: impl IntoIterator<Item = CodeUnit>) -> BTreeSet<String> {
    units.into_iter().map(|unit| unit.fq_name()).collect()
}

#[test]
fn cpp_type_hierarchy_resolves_single_inheritance() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[(
        "types.cpp",
        r#"
struct Base {};
struct Child : Base {};
"#,
    )]);

    let child = definition(&analyzer, "Child");
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&child)),
        BTreeSet::from(["Base".to_string()])
    );
}

#[test]
fn cpp_type_hierarchy_resolves_multiple_inheritance() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[(
        "types.cpp",
        r#"
struct Runnable {};
struct Serializable {};
struct Worker : Runnable, Serializable {};
"#,
    )]);

    let worker = definition(&analyzer, "Worker");
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&worker)),
        BTreeSet::from(["Runnable".to_string(), "Serializable".to_string()])
    );
}

#[test]
fn cpp_type_hierarchy_resolves_namespace_qualified_base() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[(
        "types.cpp",
        r#"
namespace api {
struct Base {};
}
struct Child : api::Base {};
"#,
    )]);

    let child = definition(&analyzer, "Child");
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&child)),
        BTreeSet::from(["api.Base".to_string()])
    );
}

#[test]
fn cpp_type_hierarchy_resolves_base_from_included_header() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "base.h",
            r#"
namespace api {
struct Base {};
}
"#,
        ),
        (
            "child.cpp",
            r#"
#include "base.h"
struct Child : api::Base {};
"#,
        ),
    ]);

    let child = definition(&analyzer, "Child");
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&child)),
        BTreeSet::from(["api.Base".to_string()])
    );
}

#[test]
fn cpp_type_hierarchy_resolves_using_alias_base_to_real_class() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[(
        "types.cpp",
        r#"
struct Base {};
using Alias = Base;
struct Child : Alias {};
"#,
    )]);

    let child = definition(&analyzer, "Child");
    let base = definition(&analyzer, "Base");
    let alias = definition(&analyzer, "Alias");
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&child)),
        BTreeSet::from(["Base".to_string()])
    );
    assert_eq!(
        fq_names(analyzer.get_direct_descendants(&base)),
        BTreeSet::from(["Child".to_string()])
    );
    assert!(analyzer.get_direct_descendants(&alias).is_empty());
}

#[test]
fn cpp_type_hierarchy_resolves_typedef_alias_base_to_real_class() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[(
        "types.cpp",
        r#"
struct Base {};
typedef Base Alias;
struct Child : Alias {};
"#,
    )]);

    let child = definition(&analyzer, "Child");
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&child)),
        BTreeSet::from(["Base".to_string()])
    );
}

#[test]
fn cpp_type_hierarchy_prefers_base_in_declaring_namespace() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[(
        "types.cpp",
        r#"
namespace A {
struct Base {};
}
namespace B {
struct Base {};
struct Child : Base {};
}
"#,
    )]);

    let child = definition(&analyzer, "B.Child");
    let base_a = definition(&analyzer, "A.Base");
    let base_b = definition(&analyzer, "B.Base");
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&child)),
        BTreeSet::from(["B.Base".to_string()])
    );
    assert!(analyzer.get_direct_descendants(&base_a).is_empty());
    assert_eq!(
        fq_names(analyzer.get_direct_descendants(&base_b)),
        BTreeSet::from(["B.Child".to_string()])
    );
}

#[test]
fn cpp_type_hierarchy_skips_unresolved_bases() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[(
        "types.cpp",
        r#"
struct Child : MissingBase {};
"#,
    )]);

    let child = definition(&analyzer, "Child");
    assert!(analyzer.get_direct_ancestors(&child).is_empty());
}

#[test]
fn cpp_type_hierarchy_direct_descendants_are_not_transitive() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[(
        "types.cpp",
        r#"
struct Base {};
struct Child : Base {};
struct Grandchild : Child {};
"#,
    )]);

    let base = definition(&analyzer, "Base");
    assert_eq!(
        fq_names(analyzer.get_direct_descendants(&base)),
        BTreeSet::from(["Child".to_string()])
    );
}

#[test]
fn cpp_targeted_ancestor_lookups_do_not_scan_disconnected_declarations() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "queried/base.h",
            r#"
namespace queried {
struct Base {};
}
"#,
        ),
        (
            "queried/child.cpp",
            r#"
#include "base.h"
namespace queried {
struct Child : Base {};
}
"#,
        ),
        (
            "unrelated/base.h",
            r#"
namespace unrelated {
struct Base {};
}
"#,
        ),
        (
            "unrelated/child.cpp",
            r#"
#include "base.h"
namespace unrelated {
struct Child : Base {};
}
"#,
        ),
    ]);

    let queried = definition(&analyzer, "queried.Child");
    let unrelated = definition(&analyzer, "unrelated.Child");
    analyzer.reset_full_declaration_scan_count_for_test();

    let (queried_ancestors, unrelated_ancestors) = std::thread::scope(|scope| {
        let queried = scope.spawn(|| analyzer.get_direct_ancestors(&queried));
        let unrelated = scope.spawn(|| analyzer.get_direct_ancestors(&unrelated));
        (queried.join().unwrap(), unrelated.join().unwrap())
    });

    assert_eq!(
        fq_names(queried_ancestors),
        BTreeSet::from(["queried.Base".to_string()])
    );
    assert_eq!(
        fq_names(unrelated_ancestors),
        BTreeSet::from(["unrelated.Base".to_string()])
    );
    assert_eq!(analyzer.full_declaration_scan_count_for_test(), 0);
}

#[test]
fn cpp_type_hierarchy_keeps_same_fqn_disconnected_roots_source_local() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        (
            "left/base.h",
            r#"
namespace api {
struct Base {};
}
"#,
        ),
        (
            "left/child.cpp",
            r#"
#include "base.h"
namespace api {
struct Child : Base {};
}
"#,
        ),
        (
            "right/base.h",
            r#"
namespace api {
struct Base {};
}
"#,
        ),
        (
            "right/child.cpp",
            r#"
#include "base.h"
namespace api {
struct Child : Base {};
}
"#,
        ),
    ]);

    let left_base = definition_in(&analyzer, "api.Base", "left/base.h");
    let left_child = definition_in(&analyzer, "api.Child", "left/child.cpp");
    let right_base = definition_in(&analyzer, "api.Base", "right/base.h");
    let right_child = definition_in(&analyzer, "api.Child", "right/child.cpp");

    assert_eq!(
        analyzer.get_direct_ancestors(&left_child),
        vec![left_base.clone()]
    );
    assert_eq!(
        analyzer.get_direct_ancestors(&right_child),
        vec![right_base.clone()]
    );
    assert_eq!(
        analyzer.get_direct_descendants(&left_base),
        [left_child].into_iter().collect()
    );
    assert_eq!(
        analyzer.get_direct_descendants(&right_base),
        [right_child].into_iter().collect()
    );
}
