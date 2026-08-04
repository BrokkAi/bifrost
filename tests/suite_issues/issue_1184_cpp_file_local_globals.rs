//! Issue #1184: file-local C++ globals with the same logical name in separate
//! translation units used to collapse under inverse lookup, so references to
//! one `static` or anonymous-namespace declaration leaked onto its sibling.

use crate::common::InlineTestProject;
use brokk_bifrost::CodeUnitIndex;
use brokk_bifrost::usages::{ExplicitCandidateProvider, FuzzyResult, UsageFinder};
use brokk_bifrost::{CodeUnit, CodeUnitType, CppAnalyzer, Language, ProjectFile};
use std::collections::BTreeSet;
use std::sync::Arc;

fn cpp_analyzer_with_files(
    files: &[(&str, &str)],
) -> (crate::common::BuiltInlineTestProject, CppAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::Cpp);
    for (path, contents) in files {
        builder = builder.file(*path, *contents);
    }
    let project = builder.build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn definition_by<F>(analyzer: &CppAnalyzer, mut predicate: F) -> CodeUnit
where
    F: FnMut(&CodeUnit) -> bool,
{
    analyzer
        .get_all_declarations()
        .into_iter()
        .find(|unit| predicate(unit))
        .unwrap_or_else(|| panic!("missing matching C++ declaration"))
}

fn field_definition_in_source(analyzer: &CppAnalyzer, source: &str, name: &str) -> CodeUnit {
    definition_by(analyzer, |unit| {
        unit.kind() == CodeUnitType::Field
            && unit.identifier() == name
            && unit.source().rel_path().to_string_lossy().ends_with(source)
    })
}

fn fixture_token_range(source: &str, labeled_line: &str, token: &str) -> (usize, usize) {
    let line_start = source
        .find(labeled_line)
        .unwrap_or_else(|| panic!("missing fixture line {labeled_line:?}"));
    let token_start = labeled_line
        .find(token)
        .unwrap_or_else(|| panic!("missing token {token:?} in fixture line {labeled_line:?}"));
    let start = line_start + token_start;
    (start, start + token.len())
}

fn authoritative_exact_ranges(
    analyzer: &CppAnalyzer,
    target: &CodeUnit,
    candidate: &ProjectFile,
) -> BTreeSet<(usize, usize)> {
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(candidate.clone()).collect()));
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            analyzer,
            std::slice::from_ref(target),
            Some(&provider),
            1,
            1000,
        )
        .result
    else {
        panic!("expected authoritative C++ success");
    };
    hits_by_overload
        .values()
        .flatten()
        .filter(|hit| &hit.file == candidate)
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect()
}

fn whole_workspace_ranges(
    analyzer: &CppAnalyzer,
    target: &CodeUnit,
    candidate: &ProjectFile,
) -> BTreeSet<(usize, usize)> {
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = UsageFinder::new().find_usages_default(analyzer, std::slice::from_ref(target))
    else {
        panic!("expected whole-workspace C++ success");
    };
    hits_by_overload
        .values()
        .flatten()
        .filter(|hit| &hit.file == candidate)
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect()
}

#[test]
fn inverse_lookup_keeps_same_named_static_globals_file_local() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "a.cpp",
            r#"
static int local_value = 0;
int read_a() {
    return local_value; // target-a
}
"#,
        ),
        (
            "b.cpp",
            r#"
static int local_value = 0;
int read_b() {
    return local_value; // sibling-b
}
"#,
        ),
    ]);

    let target = field_definition_in_source(&analyzer, "a.cpp", "local_value");
    let a = project.file("a.cpp");
    let b = project.file("b.cpp");
    let a_source = a.read_to_string().expect("read a.cpp");
    let b_source = b.read_to_string().expect("read b.cpp");
    let expected = BTreeSet::from([fixture_token_range(
        &a_source,
        "    return local_value; // target-a",
        "local_value",
    )]);
    let wrong = fixture_token_range(
        &b_source,
        "    return local_value; // sibling-b",
        "local_value",
    );

    assert_eq!(authoritative_exact_ranges(&analyzer, &target, &a), expected);
    assert!(
        authoritative_exact_ranges(&analyzer, &target, &b).is_empty(),
        "authoritative inverse lookup must not leak to the sibling static global"
    );

    let public = whole_workspace_ranges(&analyzer, &target, &a);
    assert_eq!(public, expected);
    assert!(
        !whole_workspace_ranges(&analyzer, &target, &b).contains(&wrong),
        "whole-workspace inverse lookup must not leak to the sibling static global"
    );
}

#[test]
fn inverse_lookup_keeps_same_named_anonymous_namespace_globals_file_local() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "a.cpp",
            r#"
namespace {
int hidden_value = 0;
}
int read_a() {
    return hidden_value; // target-a
}
"#,
        ),
        (
            "b.cpp",
            r#"
namespace {
int hidden_value = 0;
}
int read_b() {
    return hidden_value; // sibling-b
}
"#,
        ),
    ]);

    let target = field_definition_in_source(&analyzer, "a.cpp", "hidden_value");
    let a = project.file("a.cpp");
    let b = project.file("b.cpp");
    let a_source = a.read_to_string().expect("read a.cpp");
    let b_source = b.read_to_string().expect("read b.cpp");
    let expected = BTreeSet::from([fixture_token_range(
        &a_source,
        "    return hidden_value; // target-a",
        "hidden_value",
    )]);
    let wrong = fixture_token_range(
        &b_source,
        "    return hidden_value; // sibling-b",
        "hidden_value",
    );

    assert_eq!(authoritative_exact_ranges(&analyzer, &target, &a), expected);
    assert!(
        authoritative_exact_ranges(&analyzer, &target, &b).is_empty(),
        "authoritative inverse lookup must not leak to the sibling anonymous-namespace global"
    );

    let public = whole_workspace_ranges(&analyzer, &target, &a);
    assert_eq!(public, expected);
    assert!(
        !whole_workspace_ranges(&analyzer, &target, &b).contains(&wrong),
        "whole-workspace inverse lookup must not leak to the sibling anonymous-namespace global"
    );
}

#[test]
fn inverse_lookup_still_coalesces_external_global_declarations_across_files() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "shared.hpp",
            r#"
#pragma once
extern int shared_value;
"#,
        ),
        (
            "definition.cpp",
            r#"
#include "shared.hpp"
int shared_value = 0;
"#,
        ),
        (
            "consumer.cpp",
            r#"
#include "shared.hpp"
int read_shared() {
    return shared_value; // external-use
}
"#,
        ),
    ]);

    let target = field_definition_in_source(&analyzer, "definition.cpp", "shared_value");
    let consumer = project.file("consumer.cpp");
    let source = consumer.read_to_string().expect("read consumer.cpp");
    let expected = BTreeSet::from([fixture_token_range(
        &source,
        "    return shared_value; // external-use",
        "shared_value",
    )]);

    assert_eq!(
        authoritative_exact_ranges(&analyzer, &target, &consumer),
        expected,
        "external-linkage declarations and definitions must retain logical identity"
    );
    assert_eq!(
        whole_workspace_ranges(&analyzer, &target, &consumer),
        expected,
        "whole-workspace lookup must preserve external global coalescing"
    );
}

#[test]
fn inverse_lookup_keeps_same_named_const_globals_file_local() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "a.cpp",
            r#"
const int local_value = 0;
int read_a() {
    return local_value; // target-a
}
"#,
        ),
        (
            "b.cpp",
            r#"
const int local_value = 0;
int read_b() {
    return local_value; // sibling-b
}
"#,
        ),
    ]);

    let target = field_definition_in_source(&analyzer, "a.cpp", "local_value");
    let a = project.file("a.cpp");
    let b = project.file("b.cpp");
    let a_source = a.read_to_string().expect("read a.cpp");
    let b_source = b.read_to_string().expect("read b.cpp");
    let expected = BTreeSet::from([fixture_token_range(
        &a_source,
        "    return local_value; // target-a",
        "local_value",
    )]);
    let wrong = fixture_token_range(
        &b_source,
        "    return local_value; // sibling-b",
        "local_value",
    );

    assert_eq!(authoritative_exact_ranges(&analyzer, &target, &a), expected);
    assert!(
        authoritative_exact_ranges(&analyzer, &target, &b).is_empty(),
        "authoritative inverse lookup must not leak to the sibling const global"
    );

    let public = whole_workspace_ranges(&analyzer, &target, &a);
    assert_eq!(public, expected);
    assert!(
        !whole_workspace_ranges(&analyzer, &target, &b).contains(&wrong),
        "whole-workspace inverse lookup must not leak to the sibling const global"
    );
}

#[test]
fn inverse_lookup_keeps_same_named_constexpr_globals_file_local() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "a.cpp",
            r#"
constexpr int local_value = 0;
int read_a() {
    return local_value; // target-a
}
"#,
        ),
        (
            "b.cpp",
            r#"
constexpr int local_value = 0;
int read_b() {
    return local_value; // sibling-b
}
"#,
        ),
    ]);

    let target = field_definition_in_source(&analyzer, "a.cpp", "local_value");
    let a = project.file("a.cpp");
    let b = project.file("b.cpp");
    let a_source = a.read_to_string().expect("read a.cpp");
    let b_source = b.read_to_string().expect("read b.cpp");
    let expected = BTreeSet::from([fixture_token_range(
        &a_source,
        "    return local_value; // target-a",
        "local_value",
    )]);
    let wrong = fixture_token_range(
        &b_source,
        "    return local_value; // sibling-b",
        "local_value",
    );

    assert_eq!(authoritative_exact_ranges(&analyzer, &target, &a), expected);
    assert!(
        authoritative_exact_ranges(&analyzer, &target, &b).is_empty(),
        "authoritative inverse lookup must not leak to the sibling constexpr global"
    );

    let public = whole_workspace_ranges(&analyzer, &target, &a);
    assert_eq!(public, expected);
    assert!(
        !whole_workspace_ranges(&analyzer, &target, &b).contains(&wrong),
        "whole-workspace inverse lookup must not leak to the sibling constexpr global"
    );
}

#[test]
fn inverse_lookup_keeps_same_named_anonymous_namespace_constexpr_globals_file_local() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "a.cpp",
            r#"
namespace {
constexpr int local_value = 0;
}
int read_a() {
    return local_value; // target-a
}
"#,
        ),
        (
            "b.cpp",
            r#"
namespace {
constexpr int local_value = 0;
}
int read_b() {
    return local_value; // sibling-b
}
"#,
        ),
    ]);

    let target = field_definition_in_source(&analyzer, "a.cpp", "local_value");
    let a = project.file("a.cpp");
    let b = project.file("b.cpp");
    let a_source = a.read_to_string().expect("read a.cpp");
    let b_source = b.read_to_string().expect("read b.cpp");
    let expected = BTreeSet::from([fixture_token_range(
        &a_source,
        "    return local_value; // target-a",
        "local_value",
    )]);
    let wrong = fixture_token_range(
        &b_source,
        "    return local_value; // sibling-b",
        "local_value",
    );

    assert_eq!(authoritative_exact_ranges(&analyzer, &target, &a), expected);
    assert!(
        authoritative_exact_ranges(&analyzer, &target, &b).is_empty(),
        "authoritative inverse lookup must not leak to the sibling anonymous-namespace constexpr global"
    );

    let public = whole_workspace_ranges(&analyzer, &target, &a);
    assert_eq!(public, expected);
    assert!(
        !whole_workspace_ranges(&analyzer, &target, &b).contains(&wrong),
        "whole-workspace inverse lookup must not leak to the sibling anonymous-namespace constexpr global"
    );
}

#[test]
fn inverse_lookup_still_coalesces_extern_const_globals_across_files() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "shared.hpp",
            r#"
#pragma once
extern const int shared_value;
"#,
        ),
        (
            "definition.cpp",
            r#"
#include "shared.hpp"
const int shared_value = 0;
"#,
        ),
        (
            "consumer.cpp",
            r#"
#include "shared.hpp"
int read_shared() {
    return shared_value; // external-use
}
"#,
        ),
    ]);

    let target = field_definition_in_source(&analyzer, "definition.cpp", "shared_value");
    let consumer = project.file("consumer.cpp");
    let source = consumer.read_to_string().expect("read consumer.cpp");
    let expected = BTreeSet::from([fixture_token_range(
        &source,
        "    return shared_value; // external-use",
        "shared_value",
    )]);

    assert_eq!(
        authoritative_exact_ranges(&analyzer, &target, &consumer),
        expected
    );
    assert_eq!(
        whole_workspace_ranges(&analyzer, &target, &consumer),
        expected
    );
}

#[test]
fn inverse_lookup_still_coalesces_inline_constexpr_globals_across_files() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "shared.hpp",
            r#"
#pragma once
inline constexpr int shared_value = 7;
"#,
        ),
        (
            "a.cpp",
            r#"
#include "shared.hpp"
int read_a() {
    return shared_value; // external-a
}
"#,
        ),
        (
            "b.cpp",
            r#"
#include "shared.hpp"
int read_b() {
    return shared_value; // external-b
}
"#,
        ),
    ]);

    let target = field_definition_in_source(&analyzer, "shared.hpp", "shared_value");
    let a = project.file("a.cpp");
    let b = project.file("b.cpp");
    let a_source = a.read_to_string().expect("read a.cpp");
    let b_source = b.read_to_string().expect("read b.cpp");
    let expected_a = BTreeSet::from([fixture_token_range(
        &a_source,
        "    return shared_value; // external-a",
        "shared_value",
    )]);
    let expected_b = BTreeSet::from([fixture_token_range(
        &b_source,
        "    return shared_value; // external-b",
        "shared_value",
    )]);

    assert_eq!(
        authoritative_exact_ranges(&analyzer, &target, &a),
        expected_a
    );
    assert_eq!(
        authoritative_exact_ranges(&analyzer, &target, &b),
        expected_b
    );
    assert_eq!(whole_workspace_ranges(&analyzer, &target, &a), expected_a);
    assert_eq!(whole_workspace_ranges(&analyzer, &target, &b), expected_b);
}
