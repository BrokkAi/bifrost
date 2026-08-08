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
    // Issue #1814: `sourcelocation.h` picks its branch before
    // `symboldatabase.h` is parsed. Both `OpenSourceLocation` branches are
    // compatible with the unguarded reference and both are in this target
    // group, so the owner component is reported.
    let open_ranges = usage_ranges(&analyzer, &open_targets, &caller);
    assert!(
        open_ranges.contains(&open_expected),
        "a compatible conditional family reports the owner component: {open_ranges:?}"
    );
    let open_authoritative_ranges = authoritative_usage_ranges(&analyzer, &open_targets, &caller);
    assert!(
        open_authoritative_ranges.contains(&open_expected),
        "authoritative batch must agree with the sequential query: \
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
    // Issue #1814 also relaxes this row. The analyzer has no macro-state
    // evaluation, so it cannot tell that `#define MUTATED_SOURCE_LOCATION`
    // between the two blocks makes BOTH branches inactive. The old refusal
    // came from the cross-file subset test, which the same rule change
    // removes. Each declaration guard set is individually compatible with the
    // unguarded reference, so the reference reports the owner component.
    let mutated_ranges = usage_ranges(&analyzer, &mutated_targets, &caller);
    assert!(
        mutated_ranges.contains(&mutated_expected),
        "macro-mutation branches are individually compatible: {mutated_ranges:?}"
    );
    let mutated_authoritative_ranges =
        authoritative_usage_ranges(&analyzer, &mutated_targets, &caller);
    assert!(
        mutated_authoritative_ranges.contains(&mutated_expected),
        "authoritative batch must agree with the sequential query: \
         {mutated_authoritative_ranges:?}"
    );
}

#[test]
fn authoritative_cpp_conditional_member_alias_is_retained() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "mathlib.h",
            r#"#pragma once
class MathLib {
public:
#if defined(HAVE_BOOST) && defined(HAVE_BOOST_INT128)
    using bigint = int;
    using biguint = unsigned int;
#else
    using bigint = long long;
    using biguint = unsigned long long;
#endif
};
"#,
        )
        .file(
            "use.cpp",
            r#"#include "mathlib.h"
MathLib::bigint value;
MathLib::biguint unsigned_value;
#if defined(HAVE_BOOST) && defined(HAVE_BOOST_INT128)
MathLib::bigint boost_value;
MathLib::biguint boost_unsigned_value;
#else
MathLib::bigint fallback_value;
MathLib::biguint fallback_unsigned_value;
#endif
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let source_file = project.file("mathlib.h");
    let caller = project.file("use.cpp");
    let source = caller.read_to_string().expect("caller source");
    for (fq_name, line, written_name) in [
        ("MathLib$bigint", "MathLib::bigint value;", "bigint"),
        (
            "MathLib$biguint",
            "MathLib::biguint unsigned_value;",
            "biguint",
        ),
    ] {
        let targets = analyzer
            .get_all_declarations()
            .into_iter()
            .filter(|unit| {
                unit.kind() == CodeUnitType::Class
                    && unit.fq_name() == fq_name
                    && unit.source() == &source_file
            })
            .collect::<Vec<_>>();
        assert_eq!(
            targets.len(),
            2,
            "both conditional member aliases are indexed"
        );
        let expected = owner_token_range(&source, line, written_name);
        let ranges = usage_ranges(&analyzer, &targets, &caller);
        assert!(
            ranges.contains(&expected),
            "missing {written_name} member alias owner: {ranges:?}"
        );
        let authoritative_ranges = authoritative_usage_ranges(&analyzer, &targets, &caller);
        assert!(
            authoritative_ranges.contains(&expected),
            "authoritative batch must retain {written_name} member alias owner: {authoritative_ranges:?}"
        );
    }

    let targets = analyzer
        .get_all_declarations()
        .into_iter()
        .filter(|unit| {
            unit.kind() == CodeUnitType::Class
                && unit.fq_name() == "MathLib$bigint"
                && unit.source() == &source_file
        })
        .collect::<Vec<_>>();
    assert_eq!(
        targets.len(),
        2,
        "both conditional bigint aliases are indexed"
    );
    let header_source = source_file.read_to_string().expect("header source");
    let boost_target = targets
        .iter()
        .find(|target| {
            analyzer
                .ranges(target)
                .iter()
                .any(|range| header_source[range.start_byte..range.end_byte].contains("int;"))
        })
        .cloned()
        .expect("boost bigint target");
    let fallback_target = targets
        .iter()
        .find(|target| {
            analyzer
                .ranges(target)
                .iter()
                .any(|range| header_source[range.start_byte..range.end_byte].contains("long long"))
        })
        .cloned()
        .expect("fallback bigint target");
    let boost_range = owner_token_range(&source, "MathLib::bigint boost_value;", "bigint");
    let fallback_range = owner_token_range(&source, "MathLib::bigint fallback_value;", "bigint");
    let boost_hits = usage_ranges(&analyzer, std::slice::from_ref(&boost_target), &caller);
    let fallback_hits = usage_ranges(&analyzer, std::slice::from_ref(&fallback_target), &caller);
    let boost_authoritative =
        authoritative_usage_ranges(&analyzer, std::slice::from_ref(&boost_target), &caller);
    let fallback_authoritative =
        authoritative_usage_ranges(&analyzer, std::slice::from_ref(&fallback_target), &caller);
    assert!(
        boost_hits.contains(&boost_range),
        "boost alias misses active branch: {boost_hits:?}"
    );
    assert!(
        !boost_hits.contains(&fallback_range),
        "boost alias leaks into fallback branch: {boost_hits:?}"
    );
    assert!(
        fallback_hits.contains(&fallback_range),
        "fallback alias misses active branch: {fallback_hits:?}"
    );
    assert!(
        !fallback_hits.contains(&boost_range),
        "fallback alias leaks into boost branch: {fallback_hits:?}"
    );
    assert!(
        boost_authoritative.contains(&boost_range)
            && !boost_authoritative.contains(&fallback_range),
        "authoritative boost alias branch isolation failed: {boost_authoritative:?}"
    );
    assert!(
        fallback_authoritative.contains(&fallback_range)
            && !fallback_authoritative.contains(&boost_range),
        "authoritative fallback alias branch isolation failed: {fallback_authoritative:?}"
    );
}

#[test]
fn authoritative_cpp_completed_conditional_alias_survives_later_macro_mutation() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "same_file.cpp",
            r#"class LocalMath {
public:
#if defined(USE_WIDE_VALUE)
    using value_type = long long;
#else
    using value_type = int;
#endif
};
#undef USE_WIDE_VALUE
LocalMath::value_type retained_value;
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let source_file = project.file("same_file.cpp");
    let source = source_file.read_to_string().expect("same-file source");
    let targets = analyzer
        .get_all_declarations()
        .into_iter()
        .filter(|unit| {
            unit.kind() == CodeUnitType::Class
                && unit.fq_name() == "LocalMath$value_type"
                && unit.source() == &source_file
        })
        .collect::<Vec<_>>();
    assert_eq!(targets.len(), 2, "both same-file aliases are indexed");
    let expected = owner_token_range(
        &source,
        "LocalMath::value_type retained_value;",
        "value_type",
    );
    assert!(
        usage_ranges(&analyzer, &targets, &source_file).contains(&expected),
        "the completed family keeps one active alias after the macro mutation"
    );
    assert!(
        authoritative_usage_ranges(&analyzer, &targets, &source_file).contains(&expected),
        "the authoritative batch keeps the completed family after the macro mutation"
    );
}
