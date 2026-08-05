use crate::common::InlineTestProject;
use brokk_bifrost::usages::{ExplicitCandidateProvider, FuzzyResult, UsageFinder, UsageHitKind};
use brokk_bifrost::{CodeUnit, CodeUnitType, CppAnalyzer, CodeUnitIndex, Language, ProjectFile};
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

fn definition_by<F>(analyzer: &CppAnalyzer, mut predicate: F) -> CodeUnit
where
    F: FnMut(&CodeUnit) -> bool,
{
    let declarations = analyzer.get_all_declarations();
    declarations
        .iter()
        .find(|unit| predicate(unit))
        .cloned()
        .unwrap_or_else(|| panic!("missing matching C++ declaration in {declarations:#?}"))
}

fn authoritative_result(
    analyzer: &CppAnalyzer,
    targets: &[CodeUnit],
    candidate: &ProjectFile,
) -> FuzzyResult {
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(candidate.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(analyzer, targets, Some(&provider), 1, 1000);
    assert_eq!(
        query.candidate_files,
        std::iter::once(candidate.clone()).collect(),
        "authoritative query must remain limited to the fixture"
    );
    query.result
}

fn reference_ranges(result: &FuzzyResult, candidate: &ProjectFile) -> BTreeSet<(usize, usize)> {
    result
        .all_hits_including_imports()
        .into_iter()
        .filter(|hit| {
            &hit.file == candidate
                && matches!(
                    hit.kind,
                    UsageHitKind::Reference | UsageHitKind::SelfReceiver
                )
        })
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect()
}

fn token_range(source: &str, line: &str, token: &str) -> (usize, usize) {
    let line_start = source
        .find(line)
        .unwrap_or_else(|| panic!("missing fixture line {line:?}"));
    let token_start = line
        .find(token)
        .unwrap_or_else(|| panic!("missing token {token:?} in fixture line {line:?}"));
    let start = line_start + token_start;
    (start, start + token.len())
}

#[test]
fn authoritative_cpp_recursive_default_argument_calls_are_editor_visible_without_external_self_edges()
 {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "sourcelocation.h",
            r#"#pragma once
struct SourceLocation {
    static SourceLocation current();
};
"#,
        )
        .file(
            "api.h",
            r#"#pragma once
#include "sourcelocation.h"
class Token;
class Settings;
namespace ValueFlow { class Value; }
namespace ValueFlow {
void setTokenValue(Token*, Value, const Settings&, SourceLocation loc = SourceLocation::current());
void noDefault(Token*, Value, const Settings&, SourceLocation loc);
}
"#,
        )
        .file(
            "api.cc",
            r#"#include "api.h"
class Token {};
class Settings {};
namespace ValueFlow { class Value {}; }
SourceLocation SourceLocation::current() { return {}; }
namespace ValueFlow {
void setTokenValue(Token* token, Value value, const Settings& settings, SourceLocation location) {
    setTokenValue(token, value, settings);
    setTokenValue(token, value, settings, location);
    setTokenValue(token, value);
}
void noDefault(Token*, Value, const Settings&, SourceLocation) {}
void consume(Token* token, Value value, const Settings& settings, SourceLocation location) {
    setTokenValue(token, value, settings, location); // external call
    noDefault(token, value, settings);
    noDefault(token, value, settings, location);
}
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let consumer = project.file("api.cc");
    let source = consumer.read_to_string().expect("consumer source");

    let set_token_value = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.fq_name() == "ValueFlow.setTokenValue"
            && unit.signature() == Some("(Token *, Value, const Settings &, SourceLocation)")
            && unit.source().rel_path() == Path::new("api.h")
    });
    let no_default = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.fq_name() == "ValueFlow.noDefault"
            && unit.signature() == Some("(Token *, Value, const Settings &, SourceLocation)")
            && unit.source().rel_path() == Path::new("api.h")
    });
    let three = token_range(
        &source,
        "    setTokenValue(token, value, settings);",
        "setTokenValue",
    );
    let four = token_range(
        &source,
        "    setTokenValue(token, value, settings, location);",
        "setTokenValue",
    );
    let external_four = token_range(
        &source,
        "    setTokenValue(token, value, settings, location); // external call",
        "setTokenValue",
    );
    let two = token_range(&source, "    setTokenValue(token, value);", "setTokenValue");
    let no_default_three = token_range(
        &source,
        "    noDefault(token, value, settings);",
        "noDefault",
    );
    let no_default_four = token_range(
        &source,
        "    noDefault(token, value, settings, location);",
        "noDefault",
    );

    for (range, expected_fqn) in [
        (three, "ValueFlow.setTokenValue"),
        (four, "ValueFlow.setTokenValue"),
        (no_default_four, "ValueFlow.noDefault"),
    ] {
        let line_start = source[..range.0]
            .rfind('\n')
            .map_or(0, |newline| newline + 1);
        let forward = brokk_bifrost::searchtools::get_declarations_by_location(
            &analyzer,
            brokk_bifrost::searchtools::GetDefinitionParams {
                references: vec![brokk_bifrost::searchtools::DefinitionReferenceQuery {
                    path: "api.cc".to_string(),
                    line: Some(
                        source[..range.0]
                            .bytes()
                            .filter(|byte| *byte == b'\n')
                            .count()
                            + 1,
                    ),
                    column: Some(source[line_start..range.0].chars().count() + 1),
                }],
            },
        );
        assert_eq!(forward.results.len(), 1, "{forward:#?}");
        assert_eq!(forward.results[0].status, "resolved", "{forward:#?}");
        assert!(
            forward.results[0]
                .declarations
                .iter()
                .any(|declaration| declaration.fqn.as_deref() == Some(expected_fqn)),
            "forward lookup should resolve {expected_fqn}: {forward:#?}"
        );
    }

    let set_result =
        authoritative_result(&analyzer, std::slice::from_ref(&set_token_value), &consumer);
    let set_editor_hits = set_result.all_hits_including_imports();
    assert_eq!(
        reference_ranges(&set_result, &consumer),
        BTreeSet::from([three, four, external_four]),
        "the defaulted fourth parameter must make the three-argument call valid"
    );
    for range in [three, four] {
        assert!(
            set_editor_hits
                .iter()
                .any(|hit| (hit.start_offset, hit.end_offset) == range
                    && hit.kind == UsageHitKind::SelfReceiver),
            "recursive call at {range:?} must be editor-visible as a self reference"
        );
    }
    assert!(
        set_editor_hits
            .iter()
            .all(|hit| (hit.start_offset, hit.end_offset) != two),
        "the invalid two-argument call must remain absent"
    );
    assert!(
        set_result
            .all_hits()
            .iter()
            .all(|hit| (hit.start_offset, hit.end_offset) != three
                && (hit.start_offset, hit.end_offset) != four),
        "recursive self references must not become external usage edges"
    );
    assert!(
        set_result
            .all_hits()
            .iter()
            .any(|hit| (hit.start_offset, hit.end_offset) == external_four
                && hit.kind == UsageHitKind::Reference),
        "a non-recursive call must remain an ordinary external reference"
    );

    let no_default_result =
        authoritative_result(&analyzer, std::slice::from_ref(&no_default), &consumer);
    assert_eq!(
        reference_ranges(&no_default_result, &consumer),
        BTreeSet::from([no_default_four]),
        "a declaration without a default must reject the three-argument call"
    );
    assert!(
        no_default_result
            .all_hits_including_imports()
            .iter()
            .all(|hit| (hit.start_offset, hit.end_offset) != no_default_three),
        "the control declaration must not accept a missing required argument"
    );
    assert_ne!(three, two);
    assert_ne!(four, two);
    assert_ne!(no_default_three, no_default_four);
}
