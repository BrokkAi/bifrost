use crate::common::InlineTestProject;
use brokk_bifrost::usages::{ExplicitCandidateProvider, FuzzyResult, UsageFinder};
use brokk_bifrost::{CodeUnit, CodeUnitType, CppAnalyzer, IAnalyzer, Language, ProjectFile};
use std::collections::BTreeSet;
use std::sync::Arc;

fn usage_ranges(
    analyzer: &CppAnalyzer,
    target: &CodeUnit,
    caller: &ProjectFile,
) -> (BTreeSet<(usize, usize)>, BTreeSet<(usize, usize)>) {
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(caller.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            analyzer,
            std::slice::from_ref(target),
            Some(&provider),
            1,
            1000,
        );
    let FuzzyResult::Success {
        hits_by_overload,
        unproven_by_overload,
        ..
    } = query.result
    else {
        panic!("expected authoritative C++ success");
    };
    let proven = hits_by_overload
        .values()
        .flatten()
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect();
    let unproven = unproven_by_overload
        .values()
        .flatten()
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect();
    (proven, unproven)
}

fn token_range(source: &str, line: &str, token: &str) -> (usize, usize) {
    let line_start = source.find(line).expect("fixture line");
    let token_start = line.find(token).expect("fixture token");
    let start = line_start + token_start;
    (start, start + token.len())
}

#[test]
fn cpp_source_fragment_type_reference_is_unproven_without_visible_peer() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "types.h",
            r#"#pragma once
namespace demo {
struct Foo {};
}
"#,
        )
        .file(
            "fragment.cc",
            r#"namespace demo {
void use(Foo* value) { (void)value; }
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let caller = project.file("fragment.cc");
    let source = caller.read_to_string().expect("fragment source");
    let target = analyzer
        .get_all_declarations()
        .into_iter()
        .find(|unit| {
            unit.kind() == CodeUnitType::Class
                && unit.fq_name() == "demo.Foo"
                && !unit.is_synthetic()
                && unit.source().to_string().ends_with("types.h")
        })
        .expect("expected the source-fragment target");

    let (proven, unproven) = usage_ranges(&analyzer, &target, &caller);
    let expected = token_range(&source, "void use(Foo* value) { (void)value; }", "Foo");
    assert!(
        proven.is_empty(),
        "a source fragment without an include edge cannot prove the type: {proven:?}"
    );
    assert_eq!(
        BTreeSet::from([expected]),
        unproven,
        "the accepted source-fragment type reference must remain reviewable: {unproven:?}"
    );
}

#[test]
fn cpp_hidden_only_type_target_rejects_visible_peer_outside_group() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "visible.h",
            r#"#pragma once
namespace demo {
struct Foo;
}
"#,
        )
        .file(
            "hidden.h",
            r#"#pragma once
namespace demo {
struct Foo {};
}
"#,
        )
        .file(
            "consumer.cc",
            r#"#include "visible.h"
namespace demo {
void use(Foo* value) { (void)value; }
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let caller = project.file("consumer.cc");
    let targets = analyzer
        .get_all_declarations()
        .into_iter()
        .filter(|unit| {
            unit.kind() == CodeUnitType::Class
                && unit.fq_name() == "demo.Foo"
                && !unit.is_synthetic()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        2,
        targets.len(),
        "expected a forward peer and hidden target"
    );
    let hidden_target = targets
        .iter()
        .find(|unit| unit.source().to_string().ends_with("hidden.h"))
        .expect("expected the hidden target");

    let (proven, unproven) = usage_ranges(&analyzer, hidden_target, &caller);
    assert!(
        proven.is_empty(),
        "a hidden-only target with an excluded visible peer cannot be proven: {proven:?}"
    );
    assert!(
        unproven.is_empty(),
        "the excluded visible peer must reject the hidden-only group before fallback: {unproven:?}"
    );
}
