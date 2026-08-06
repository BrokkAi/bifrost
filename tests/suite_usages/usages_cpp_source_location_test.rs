use crate::common::InlineTestProject;
use brokk_bifrost::usages::{
    ExplicitCandidateProvider, FuzzyResult, UsageFinder, cpp_graph::CppAuthoritativeUsageBatch,
};
use brokk_bifrost::{CodeUnit, CodeUnitIndex, CodeUnitType, CppAnalyzer, Language, ProjectFile};
use std::collections::BTreeSet;
use std::sync::Arc;

fn owner_token_range(source: &str, line: &str, token: &str) -> (usize, usize) {
    let line_start = source.find(line).expect("fixture line");
    let token_start = line.rfind(token).expect("fixture owner token");
    let start = line_start + token_start;
    (start, start + token.len())
}

fn usage_ranges(
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

fn authoritative_usage_ranges(
    analyzer: &CppAnalyzer,
    targets: &[CodeUnit],
    caller: &ProjectFile,
) -> BTreeSet<(usize, usize)> {
    let roots = std::iter::once(caller.clone()).collect();
    let batch = CppAuthoritativeUsageBatch::new(analyzer, &roots).expect("authoritative C++ batch");
    batch
        .find_usages(targets, &roots, 1000)
        .into_fuzzy_result()
        .all_hits_including_imports()
        .into_iter()
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect()
}

#[test]
fn authoritative_cpp_conditional_source_location_qualifier_is_retained() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "sourcelocation.h",
            r#"#pragma once
namespace std {
struct source_location {};
namespace experimental { struct source_location {}; }
}

#if defined(CPPCHECK_HAS_SOURCE_LOCATION)
#include <source_location>
using SourceLocation = std::source_location;
#elif defined(CPPCHECK_HAS_SOURCE_LOCATION_TS)
#include <experimental/source_location>
using SourceLocation = std::experimental::source_location;
#else
struct SourceLocation {
    static SourceLocation current();
};
#endif

#if defined(OPEN_SOURCE_LOCATION)
using OpenSourceLocation = std::source_location;
#elif !defined(OPEN_SOURCE_LOCATION)
using OpenSourceLocation = std::experimental::source_location;
#endif

#if defined(MUTATED_SOURCE_LOCATION)
using MutatedSourceLocation = std::source_location;
#endif
#define MUTATED_SOURCE_LOCATION
#if !defined(MUTATED_SOURCE_LOCATION)
struct MutatedSourceLocation {
    static MutatedSourceLocation current();
};
#endif
"#,
        )
        .file(
            "symboldatabase.h",
            r#"#pragma once
#include "sourcelocation.h"
struct Token {};
struct Variable {};
class SymbolDatabase {
public:
    void setValueType(Token* tok, const Variable& var,
                      const SourceLocation &loc = SourceLocation::current());
    void setOpenValueType(Token* tok, const Variable& var,
                          const OpenSourceLocation &loc = OpenSourceLocation::current());
    void setMutatedValueType(Token* tok, const Variable& var,
                             const MutatedSourceLocation &loc = MutatedSourceLocation::current());
};
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let source_file = project.file("sourcelocation.h");
    let caller = project.file("symboldatabase.h");
    let targets = analyzer
        .get_all_declarations()
        .into_iter()
        .filter(|unit| {
            unit.kind() == CodeUnitType::Class
                && unit.fq_name() == "SourceLocation"
                && unit.source() == &source_file
        })
        .collect::<Vec<_>>();
    assert_eq!(targets.len(), 3, "all conditional SourceLocation branches");

    let source = caller.read_to_string().expect("caller source");
    let expected = owner_token_range(
        &source,
        "                      const SourceLocation &loc = SourceLocation::current());",
        "SourceLocation",
    );
    let ranges = usage_ranges(&analyzer, &targets, &caller);
    assert!(
        ranges.contains(&expected),
        "missing SourceLocation owner component: {ranges:?}"
    );
    let authoritative_ranges = authoritative_usage_ranges(&analyzer, &targets, &caller);
    assert!(
        authoritative_ranges.contains(&expected),
        "authoritative batch must retain SourceLocation owner component: {authoritative_ranges:?}"
    );

    let open_targets = analyzer
        .get_all_declarations()
        .into_iter()
        .filter(|unit| {
            unit.kind() == CodeUnitType::Class
                && unit.fq_name() == "OpenSourceLocation"
                && unit.source() == &source_file
        })
        .collect::<Vec<_>>();
    assert_eq!(open_targets.len(), 2, "non-exhaustive conditional branches");
    let open_expected = owner_token_range(
        &source,
        "                          const OpenSourceLocation &loc = OpenSourceLocation::current());",
        "OpenSourceLocation",
    );
    let open_ranges = usage_ranges(&analyzer, &open_targets, &caller);
    assert!(
        !open_ranges.contains(&open_expected),
        "a conditional family without an else branch is not exhaustive: {open_ranges:?}"
    );
    let open_authoritative_ranges = authoritative_usage_ranges(&analyzer, &open_targets, &caller);
    assert!(
        !open_authoritative_ranges.contains(&open_expected),
        "authoritative batch must reject a non-exhaustive conditional family: \
         {open_authoritative_ranges:?}"
    );

    let mutated_targets = analyzer
        .get_all_declarations()
        .into_iter()
        .filter(|unit| {
            unit.kind() == CodeUnitType::Class
                && unit.fq_name() == "MutatedSourceLocation"
                && unit.source() == &source_file
        })
        .collect::<Vec<_>>();
    assert_eq!(
        mutated_targets.len(),
        2,
        "separate macro-mutation declarations"
    );
    let mutated_expected = owner_token_range(
        &source,
        "                             const MutatedSourceLocation &loc = MutatedSourceLocation::current());",
        "MutatedSourceLocation",
    );
    let mutated_ranges = usage_ranges(&analyzer, &mutated_targets, &caller);
    assert!(
        !mutated_ranges.contains(&mutated_expected),
        "separate conditionals split by macro mutation are not complementary: {mutated_ranges:?}"
    );
    let mutated_authoritative_ranges =
        authoritative_usage_ranges(&analyzer, &mutated_targets, &caller);
    assert!(
        !mutated_authoritative_ranges.contains(&mutated_expected),
        "authoritative batch must reject separate macro-mutation declarations: \
         {mutated_authoritative_ranges:?}"
    );
}
