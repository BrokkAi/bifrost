use crate::common::InlineTestProject;
use brokk_bifrost::usages::{
    ExplicitCandidateProvider, UsageFinder, cpp_graph::CppAuthoritativeUsageBatch,
};
use brokk_bifrost::{AnalyzerConfig, CodeUnitIndex, CodeUnitType, CppAnalyzer, Language};
use std::collections::BTreeSet;
use std::sync::Arc;

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

fn token_range_after(source: &str, anchor: &str, token: &str) -> (usize, usize) {
    let anchor_start = source
        .find(anchor)
        .unwrap_or_else(|| panic!("missing fixture anchor {anchor:?}"));
    let token_start = source[anchor_start..]
        .find(token)
        .unwrap_or_else(|| panic!("missing token {token:?} after fixture anchor {anchor:?}"));
    let start = anchor_start + token_start;
    (start, start + token.len())
}

#[test]
fn authoritative_cpp_nested_template_temporary_keeps_method_receiver() {
    let source = r#"#ifndef ABSL_BASE_INTERNAL_EXCEPTION_SAFETY_TESTING_H_
#define ABSL_BASE_INTERNAL_EXCEPTION_SAFETY_TESTING_H_

#include "absl/base/config.h"
#include "gtest/gtest.h"

#ifdef ABSL_HAVE_EXCEPTIONS

namespace testing {
namespace exceptions_internal {

struct UninitializedT {};

template <typename Factory = UninitializedT,
          typename Operation = UninitializedT, typename... Contracts>
class ExceptionSafetyTestBuilder;

}  // namespace exceptions_internal

exceptions_internal::ExceptionSafetyTestBuilder<> MakeExceptionSafetyTester();

namespace exceptions_internal {

template <typename T>
struct IsUniquePtr : std::false_type {};

template <typename T, typename D>
struct IsUniquePtr<std::unique_ptr<T, D>> : std::true_type {};

template <typename Factory>
struct FactoryPtrTypeHelper {
  using type = decltype(std::declval<const Factory&>()());
};

template <typename Factory>
using FactoryPtrType = typename FactoryPtrTypeHelper<Factory>::type;

template <typename Factory>
using FactoryElementType = typename FactoryPtrType<Factory>::element_type;

template <typename T>
class ExceptionSafetyTest {
  using Factory = std::function<std::unique_ptr<T>()>;
  using Operation = std::function<void(T*)>;
  using Contract = std::function<AssertionResult(T*)>;

 public:
  template <typename... Contracts>
  explicit ExceptionSafetyTest(const Factory& f, const Operation& op,
                               const Contracts&... contracts)
      : factory_(f), operation_(op), contracts_{contracts...} {}

  AssertionResult Test() const {
    return {};
  }

 private:
  Factory factory_;
  Operation operation_;
  std::tuple<Contracts...> contracts_;
};

template <typename T>
class OtherTest {
 public:
  template <typename... Args>
  explicit OtherTest(const Args&... args) {}
  bool Test() const { return true; }
};

template <typename Factory, typename Operation, typename... Contracts>
class ExceptionSafetyTestBuilder {
 public:
  template <typename SelectedOperation, size_t... Indices>
  AssertionResult TestImpl(SelectedOperation selected_operation,
                           std::index_sequence<Indices...>) const {
    return ExceptionSafetyTest<FactoryElementType<Factory>>(
               factory_, selected_operation, std::get<Indices>(contracts_)...)
        .Test();
  }

  template <typename SelectedOperation, size_t... Indices>
  bool OtherImpl(SelectedOperation selected_operation,
                 std::index_sequence<Indices...>) const {
    return OtherTest<Factory>(factory_, selected_operation,
                              std::get<Indices>(contracts_)...)
        .Test();
  }

 private:
  Factory factory_;
  std::tuple<Contracts...> contracts_;
};
}
}
#endif  // ABSL_HAVE_EXCEPTIONS
#endif  // ABSL_BASE_INTERNAL_EXCEPTION_SAFETY_TESTING_H_
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "absl/base/config.h",
            "#define ABSL_HAVE_EXCEPTIONS 1\n#define ABSL_INTERNAL_CPLUSPLUS_LANG 202002L\n#define ABSL_NAMESPACE_BEGIN inline namespace lts_20230802 {\n#define ABSL_NAMESPACE_END }\n",
        )
        .file("exception_safety_testing.h", source)
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let file = project.file("exception_safety_testing.h");
    let declarations = analyzer.get_all_declarations();
    let target = declarations
        .iter()
        .find(|unit| {
            unit.kind() == CodeUnitType::Function
                && unit.fq_name() == "testing::exceptions_internal.ExceptionSafetyTest.Test"
        })
        .cloned()
        .unwrap_or_else(|| panic!("missing ExceptionSafetyTest.Test: {declarations:#?}"));
    let positive = token_range_after(
        source,
        "return ExceptionSafetyTest<FactoryElementType<Factory>>(",
        ".Test",
    );
    let positive = (positive.0 + 1, positive.1);
    let negative = token_range_after(
        source,
        "return OtherTest<Factory>(factory_, selected_operation,",
        ".Test",
    );
    let negative = (negative.0 + 1, negative.1);

    let line = source[..positive.0]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1;
    let line_start = source[..positive.0]
        .rfind('\n')
        .map_or(0, |newline| newline + 1);
    let forward = brokk_bifrost::searchtools::get_declarations_by_location(
        &analyzer,
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: vec![brokk_bifrost::searchtools::DefinitionReferenceQuery {
                path: "exception_safety_testing.h".to_string(),
                line: Some(line),
                column: Some(source[line_start..positive.0].chars().count() + 1),
            }],
        },
    );
    assert_eq!(forward.results[0].status, "resolved", "{forward:#?}");
    assert!(
        forward.results[0].declarations.iter().any(|declaration| {
            declaration.fqn.as_deref()
                == Some("testing::exceptions_internal.ExceptionSafetyTest.Test")
        }),
        "forward lookup must select the templated temporary owner: {forward:#?}"
    );

    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(file.clone()).collect()));
    let result = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        )
        .result;
    let ranges = result
        .all_hits_including_imports()
        .into_iter()
        .filter(|hit| hit.file == file)
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect::<BTreeSet<_>>();
    assert!(
        ranges.contains(&positive),
        "inverse lookup must contain the exact nested temporary call: {ranges:#?}"
    );
    assert!(
        !ranges.contains(&negative),
        "inverse lookup must reject the unrelated same-name temporary call: {ranges:#?}"
    );
}

#[test]
fn authoritative_cpp_template_function_shadow_does_not_use_outer_type() {
    let source = r#"struct Foo {
  void Test();
};

struct B {
  void Test();
};

namespace inner {
template <typename T>
B Foo(T value);

void g() {
  Foo<int>(1).Test();
}
}  // namespace inner
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("shadow.cpp", source)
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let file = project.file("shadow.cpp");
    let target = analyzer
        .get_all_declarations()
        .into_iter()
        .find(|unit| unit.kind() == CodeUnitType::Function && unit.fq_name() == "Foo.Test")
        .unwrap_or_else(|| panic!("missing outer Foo.Test"));
    let positive = token_range_after(source, "Foo<int>(1)", ".Test");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(file.clone()).collect()));
    let result = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        )
        .result;
    let ranges = result
        .all_hits_including_imports()
        .into_iter()
        .filter(|hit| hit.file == file)
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect::<BTreeSet<_>>();
    assert!(
        !ranges.contains(&positive),
        "template function shadow must not resolve to outer Foo.Test: {ranges:#?}"
    );
}

#[test]
fn authoritative_cpp_unrelated_template_function_does_not_suppress_global_type() {
    let source = r#"#include "missing/config.h"

struct Foo {
  void Test();
};

struct B {
  void Test();
};

namespace unrelated {
template <typename T>
B Foo(T value);
}  // namespace unrelated

template <typename... Args>
void g(Args... pack) {
  Foo<int>(pack...).Test();
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("unrelated.cpp", source)
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let file = project.file("unrelated.cpp");
    let target = analyzer
        .get_all_declarations()
        .into_iter()
        .find(|unit| unit.kind() == CodeUnitType::Function && unit.fq_name() == "Foo.Test")
        .unwrap_or_else(|| panic!("missing global Foo.Test"));
    let positive = token_range_after(source, "Foo<int>(pack...)", ".Test");
    let positive = (positive.0 + 1, positive.1);
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(file.clone()).collect()));
    let result = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        )
        .result;
    let ranges = result
        .all_hits_including_imports()
        .into_iter()
        .filter(|hit| hit.file == file)
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect::<BTreeSet<_>>();
    assert!(
        ranges.contains(&positive),
        "unrelated namespace callable must not suppress the global type: {ranges:#?}"
    );
}

#[test]
fn authoritative_cpp_unrelated_explicit_arity_template_does_not_suppress_global_type() {
    let source = r#"struct Foo {
  void Test();
};

struct B {
  void Test();
};

namespace unrelated {
template <typename T>
B Foo(T value);
}  // namespace unrelated

void g() {
  Foo<int>(1).Test();
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("unrelated_explicit.cpp", source)
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let file = project.file("unrelated_explicit.cpp");
    let target = analyzer
        .get_all_declarations()
        .into_iter()
        .find(|unit| unit.kind() == CodeUnitType::Function && unit.fq_name() == "Foo.Test")
        .unwrap_or_else(|| panic!("missing global Foo.Test"));
    let positive = token_range_after(source, "Foo<int>(1)", ".Test");
    let positive = (positive.0 + 1, positive.1);
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(file.clone()).collect()));
    let result = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        )
        .result;
    let ranges = result
        .all_hits_including_imports()
        .into_iter()
        .filter(|hit| hit.file == file)
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect::<BTreeSet<_>>();
    assert!(
        ranges.contains(&positive),
        "unrelated namespace callable must not suppress the global type for exact arity: {ranges:#?}"
    );
}

#[test]
fn authoritative_cpp_preprocessor_constructor_parameter_keeps_class_alias() {
    let source = include_str!("../fixtures/cpp_macro_sentinel_raw_hash_set.h");
    let source = source.replace(
        "namespace container_internal {\n",
        "namespace container_internal {\n\n#ifdef ABSL_SWISSTABLE_ENABLE_GENERATIONS\n#error ABSL_SWISSTABLE_ENABLE_GENERATIONS cannot be directly set\n#elif (defined(ABSL_HAVE_ADDRESS_SANITIZER) || \\\n       defined(ABSL_HAVE_HWADDRESS_SANITIZER) || \\\n       defined(ABSL_HAVE_MEMORY_SANITIZER)) && \\\n    !defined(NDEBUG_SANITIZER)\n#define ABSL_SWISSTABLE_ENABLE_GENERATIONS\n#endif\n\n#ifdef ABSL_SWISSTABLE_ASSERT\n#error ABSL_SWISSTABLE_ASSERT cannot be directly set\n#else\n#define ABSL_SWISSTABLE_ASSERT(CONDITION) \\\n  assert((CONDITION) && \"Try enabling sanitizers.\")\n#endif\n",
    );
    let source = source.replace(
        "  template <class InputIter>\n  raw_hash_set(InputIter first, InputIter last, size_t reservation_size,\n               const allocator_type& alloc)\n      : raw_hash_set(first, last, reservation_size, hasher(), key_equal(),\n                     alloc) {}\n",
        r#"  template <class InputIter>
  raw_hash_set(InputIter first, InputIter last, size_t reservation_size,
               const allocator_type& alloc)
      : raw_hash_set(first, last, reservation_size, hasher(), key_equal(),
                     alloc) {}

#if defined(__cpp_lib_containers_ranges) && \
    __cpp_lib_containers_ranges >= 202202L
  template <typename R>
  raw_hash_set(std::from_range_t, R&& rg, size_type reservation_size = 0,
               const hasher& hash = hasher(), const key_equal& eq = key_equal(),
               const allocator_type& alloc = allocator_type())
      : raw_hash_set(std::begin(rg), std::end(rg), reservation_size, hash, eq,
                     alloc) {}

  template <typename R>
  raw_hash_set(std::from_range_t, R&& rg, size_type reservation_size,
               const allocator_type& alloc)
      : raw_hash_set(std::from_range, std::forward<R>(rg), reservation_size,
                     hasher(), key_equal(), alloc) {}

  template <typename R>
  raw_hash_set(std::from_range_t, R&& rg, size_type reservation_size,
               const hasher& hash, const allocator_type& alloc)
      : raw_hash_set(std::from_range, std::forward<R>(rg), reservation_size,
                     hash, key_equal(), alloc) {}
#endif
"#,
    );
    let source = format!(
        "{source}\nnamespace unrelated {{\nusing hasher = int;\nclass other_set {{\n public:\n  explicit other_set(const hasher& hash) {{}}\n}};\n}}\n"
    );
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "absl/base/config.h",
            "#define ABSL_HAVE_EXCEPTIONS 1\n#define ABSL_INTERNAL_CPLUSPLUS_LANG 202002L\n#define ABSL_NAMESPACE_BEGIN inline namespace lts_20230802 {\n#define ABSL_NAMESPACE_END }\n",
        )
        .file("raw_hash_set.h", &source)
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let file = project.file("raw_hash_set.h");
    let declarations = analyzer.get_all_declarations();
    let target = declarations
        .iter()
        .find(|unit| {
            unit.kind() == CodeUnitType::Class
                && unit.fq_name() == "absl::container_internal.raw_hash_set$hasher"
        })
        .cloned()
        .unwrap_or_else(|| panic!("missing raw_hash_set.hasher: {declarations:#?}"));
    let stable = token_range(
        &source,
        "  explicit raw_hash_set(size_t reservation_size, const hasher& hash = hasher(),",
        "hasher",
    );
    let fragmented = token_range(
        &source,
        "               const hasher& hash, const allocator_type& alloc)",
        "hasher",
    );
    let unrelated = token_range(
        &source,
        "  explicit other_set(const hasher& hash) {}",
        "hasher",
    );

    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(file.clone()).collect()));
    let result = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        )
        .result;
    let ranges = result
        .all_hits_including_imports()
        .into_iter()
        .filter(|hit| hit.file == file)
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect::<BTreeSet<_>>();
    assert!(
        ranges.contains(&stable),
        "ordinary constructor parameter must contain the class alias: {ranges:#?}"
    );
    assert!(
        ranges.contains(&fragmented),
        "preprocessor constructor parameter must contain the class alias: {ranges:#?}"
    );
    assert!(
        !ranges.contains(&unrelated),
        "same-named alias under an unrelated owner must stay excluded: {ranges:#?}"
    );

    // The workspace batch keeps the analyzer wrapper that the reference
    // differential uses. The target-guided owner proof must preserve the
    // malformed class parameter through that production boundary.
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let workspace_analyzer = workspace.analyzer();
    let workspace_target = workspace_analyzer
        .get_all_declarations()
        .into_iter()
        .find(|unit| {
            unit.kind() == CodeUnitType::Class
                && unit.fq_name() == "absl::container_internal.raw_hash_set$hasher"
        })
        .unwrap_or_else(|| panic!("missing workspace raw_hash_set.hasher"));
    let roots = std::iter::once(file.clone()).collect();
    let batch = CppAuthoritativeUsageBatch::new(workspace_analyzer, &roots)
        .expect("workspace C++ authoritative batch");
    let batch_result = batch
        .find_usages(std::slice::from_ref(&workspace_target), &roots, 1000)
        .into_fuzzy_result();
    let batch_ranges = batch_result
        .all_hits_including_imports()
        .into_iter()
        .filter(|hit| hit.file == file)
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect::<BTreeSet<_>>();
    assert!(
        batch_ranges.contains(&fragmented),
        "workspace inverse lookup must recover the ambiguous class alias parameter: {batch_result:#?}"
    );
    assert!(
        !batch_ranges.contains(&unrelated),
        "workspace inverse lookup must reject the unrelated owner alias: {batch_result:#?}"
    );
}
