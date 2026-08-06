use crate::common::InlineTestProject;
use brokk_bifrost::usages::{ExplicitCandidateProvider, FuzzyResult, UsageFinder};
use brokk_bifrost::{CodeUnit, CodeUnitIndex, CodeUnitType, CppAnalyzer, Language, ProjectFile};
use std::collections::BTreeSet;
use std::sync::Arc;

fn authoritative_exact_ranges(
    analyzer: &CppAnalyzer,
    targets: &[CodeUnit],
    caller: &ProjectFile,
) -> BTreeSet<(usize, usize)> {
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(caller.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(analyzer, targets, Some(&provider), 1, 1000);
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = query.result
    else {
        panic!("expected authoritative C++ success");
    };
    hits_by_overload
        .values()
        .flatten()
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect()
}

fn token_range(source: &str, line: &str, token: &str) -> (usize, usize) {
    let line_start = source.find(line).expect("fixture line");
    let token_start = line.find(token).expect("fixture token");
    let start = line_start + token_start;
    (start, start + token.len())
}

fn forward_fqn(analyzer: &CppAnalyzer, caller: &str, source: &str, line: &str, token: &str) {
    let range = token_range(source, line, token);
    let line_number = source[..range.0]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1;
    let line_start = source[..range.0]
        .rfind('\n')
        .map_or(0, |newline| newline + 1);
    let column = source[line_start..range.0].chars().count() + 1;
    let result = brokk_bifrost::searchtools::get_definitions_by_location(
        analyzer,
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: vec![brokk_bifrost::searchtools::DefinitionReferenceQuery {
                path: caller.to_string(),
                line: Some(line_number),
                column: Some(column),
            }],
        },
    );
    assert!(
        matches!(result.results[0].status.as_str(), "resolved" | "ambiguous"),
        "forward lookup must resolve or expose the repeated tag group: {result:#?}"
    );
    assert!(
        result.results[0]
            .definitions
            .iter()
            .any(|definition| definition.fqn.as_deref() == Some(token)),
        "forward lookup must resolve the repeated tag: {result:#?}"
    );
}

#[test]
fn authoritative_cpp_repeated_tag_uses_visible_peer_and_rejects_hidden_only_target() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "visible.h",
            r#"#pragma once
struct archive_entry;
struct archive_entry_linkresolver;
struct local_only;
"#,
        )
        .file(
            "visible_repeat.h",
            r#"#pragma once
struct archive_entry;
struct archive_entry_linkresolver;
"#,
        )
        .file(
            "hidden.h",
            r#"#pragma once
struct archive_entry {};
struct archive_entry_linkresolver {};
"#,
        )
        .file(
            "consumer.cc",
            r#"#include "visible.h"
#include "visible_repeat.h"
extern "C" void use() {
    struct archive_entry *entry;
    struct archive_entry_linkresolver *resolver = nullptr;
    (void)entry;
    (void)resolver;
    struct local_only;
    struct local_only *local_pointer;
    (void)local_pointer;
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let caller = project.file("consumer.cc");
    let source = caller.read_to_string().expect("consumer source");

    for (name, line) in [
        ("archive_entry", "struct archive_entry *entry;"),
        (
            "archive_entry_linkresolver",
            "struct archive_entry_linkresolver *resolver = nullptr;",
        ),
    ] {
        let mut targets = analyzer
            .get_all_declarations()
            .into_iter()
            .filter(|unit| {
                unit.kind() == CodeUnitType::Class && unit.fq_name() == name && !unit.is_synthetic()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            targets.len(),
            3,
            "visible repeats and one hidden target: {name}"
        );
        targets.sort_by_key(|unit| !unit.source().to_string().ends_with("hidden.h"));
        let hidden_target = targets[0].clone();
        let expected = token_range(&source, line, name);
        forward_fqn(&analyzer, "consumer.cc", &source, line, name);

        let ranges = authoritative_exact_ranges(&analyzer, &targets, &caller);
        assert_eq!(
            ranges,
            BTreeSet::from([expected]),
            "inverse lookup must use a visible same-FQN peer: {name}"
        );

        let hidden_only_ranges =
            authoritative_exact_ranges(&analyzer, std::slice::from_ref(&hidden_target), &caller);
        assert!(
            hidden_only_ranges.is_empty(),
            "a same-FQN target outside the include closure must not match: {hidden_only_ranges:?}"
        );
    }

    let local_target = analyzer
        .get_all_declarations()
        .into_iter()
        .filter(|unit| {
            unit.kind() == CodeUnitType::Class
                && unit.fq_name() == "local_only"
                && !unit.is_synthetic()
                && unit.source().to_string().ends_with("visible.h")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        local_target.len(),
        1,
        "expected the header local_only target"
    );
    let local_use = token_range(&source, "struct local_only *local_pointer;", "local_only");
    let local_ranges = authoritative_exact_ranges(&analyzer, &local_target, &caller);
    assert!(
        !local_ranges.contains(&local_use),
        "a block-scope tag declaration must shadow the header target: {local_ranges:?}"
    );
}
