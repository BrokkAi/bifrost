use crate::common::InlineTestProject;
use brokk_bifrost::usages::{ExplicitCandidateProvider, FuzzyResult, UsageFinder};
use brokk_bifrost::{CodeUnit, CodeUnitIndex, CodeUnitType, CppAnalyzer, Language, ProjectFile};
use std::collections::BTreeSet;
use std::sync::Arc;

fn definition_by<F>(analyzer: &CppAnalyzer, mut predicate: F) -> CodeUnit
where
    F: FnMut(&CodeUnit) -> bool,
{
    analyzer
        .get_all_declarations()
        .into_iter()
        .find(|unit| predicate(unit))
        .unwrap_or_else(|| panic!("missing matching declaration"))
}

fn slash_path(file: &ProjectFile) -> String {
    file.rel_path()
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn fixture_token_range(source: &str, line: &str, token: &str) -> (usize, usize) {
    let line_start = source
        .find(line)
        .unwrap_or_else(|| panic!("missing fixture line {line:?}"));
    let token_start = line
        .find(token)
        .unwrap_or_else(|| panic!("missing token {token:?} in fixture line {line:?}"));
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

#[test]
fn authoritative_cpp_abseil_member_pointer_alias_in_out_of_line_constructor() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "types.h",
            r#"#pragma once
#define ABSL_NAMESPACE_BEGIN inline namespace lts_20240116 {
#define ABSL_NAMESPACE_END }
namespace absl {
ABSL_NAMESPACE_BEGIN
#if defined(__cpp_lib_type_identity) && __cpp_lib_type_identity >= 201806L
template <typename T>
using type_identity = std::type_identity<T>;
#else
template <typename T>
struct type_identity {
  typedef T type;
};
#endif
ABSL_NAMESPACE_END
}
"#,
        )
        .file(
            "consumer.cc",
            r#"#include "types.h"
namespace absl {
ABSL_NAMESPACE_BEGIN
class Condition {
 public:
  template <typename T>
  Condition(const T* absl_nonnull object,
            bool (absl::type_identity<T>::type::* absl_nonnull method)());
};
template <typename T>
inline Condition::Condition(
    const T* absl_nonnull object,
    bool (absl::type_identity<T>::type::* absl_nonnull method)()) {}
ABSL_NAMESPACE_END
}
namespace unrelated {
template <typename T>
struct type_identity {
  typedef T type;
};
template <typename T>
void unrelated(bool (unrelated::type_identity<T>::type::* absl_nonnull method)()) {}
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.identifier() == "type"
            && unit.fq_name() == "absl.type_identity$type"
            && slash_path(unit.source()) == "types.h"
    });
    let consumer = project.file("consumer.cc");
    let source = consumer.read_to_string().expect("consumer source");
    let positive_line = "    bool (absl::type_identity<T>::type::* absl_nonnull method)()) {}";
    let positive = fixture_token_range(&source, positive_line, "type::*");
    let positive = (positive.0, positive.0 + "type".len());
    let unrelated_line =
        "void unrelated(bool (unrelated::type_identity<T>::type::* absl_nonnull method)()) {}";
    let unrelated = fixture_token_range(&source, unrelated_line, "type::*");
    let unrelated = (unrelated.0, unrelated.0 + "type".len());

    let hits = authoritative_exact_ranges(&analyzer, &target, &consumer);
    assert!(
        hits.contains(&positive),
        "out-of-line attributed member-pointer alias must hit terminal typedef: {hits:#?}"
    );
    assert!(
        !hits.contains(&unrelated),
        "same-shaped alias under unrelated owner must remain excluded: {hits:#?}"
    );
}
