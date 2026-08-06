use crate::common::InlineTestProject;
use brokk_bifrost::usages::{ExplicitCandidateProvider, FuzzyResult, UsageFinder};
use brokk_bifrost::{CodeUnit, CodeUnitIndex, CodeUnitType, CppAnalyzer, Language, ProjectFile};
use std::collections::BTreeSet;
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

fn last_token_range(source: &str, line: &str, token: &str) -> (usize, usize) {
    let line_start = source
        .find(line)
        .unwrap_or_else(|| panic!("missing fixture line {line:?}"));
    let token_start = line
        .rfind(token)
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
    assert_eq!(
        query.candidate_files,
        std::iter::once(candidate.clone()).collect(),
        "authoritative query must remain limited to the fixture file"
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
fn behaviortree_member_aliases_match_dependent_and_signature_references() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "contrib/json.hpp",
            r#"#define NLOHMANN_JSON_NAMESPACE_BEGIN namespace nlohmann { inline namespace abi {
#define NLOHMANN_JSON_NAMESPACE_END } }
#define NLOHMANN_BASIC_JSON_TPL basic_json<ObjectType, ArrayType, StringType, BooleanType, NumberIntegerType, NumberUnsignedType, NumberFloatType, AllocatorType, JSONSerializer, BinaryType, CustomBaseClass>
#define NLOHMANN_BASIC_JSON_TPL_DECLARATION template<template<typename, typename, typename...> class ObjectType, template<typename, typename...> class ArrayType, class StringType, class BooleanType, class NumberIntegerType, class NumberUnsignedType, class NumberFloatType, template<typename> class AllocatorType, template<typename, typename = void> class JSONSerializer, class BinaryType, class CustomBaseClass>
#define JSON_PRIVATE_UNLESS_TESTED private

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail {
template<class T> struct helper {};
template<class T> struct json_base_class {};
enum class value_t { null };
}

NLOHMANN_BASIC_JSON_TPL_DECLARATION
class basic_json : public ::nlohmann::detail::json_base_class<CustomBaseClass> {
private:
    using basic_json_t = NLOHMANN_BASIC_JSON_TPL;
    JSON_PRIVATE_UNLESS_TESTED:
    using private_helper = helper<basic_json_t>;
public:
    using value_type = basic_json;
    using reference = value_type&;
    using const_reference = const value_type&;
    using size_type = unsigned long;
    using iterator = helper<basic_json>;
    using const_iterator = helper<const basic_json>;
    using reverse_iterator = helper<basic_json_t>;
    using const_reverse_iterator = helper<basic_json_t>;
    using self_alias = helper<self_alias>;
    using value_t = detail::value_t;
    struct data {
        value_t m_type = value_t::null;
        data(const value_t v) : m_type(v) {}
    };

    template<typename PointerType, typename std::enable_if<
                 std::is_pointer<PointerType>::value, int>::type = 0>
    auto get_ptr() noexcept -> decltype(std::declval<basic_json_t&>().get_impl_ptr(std::declval<PointerType>()));
    template<typename PointerType, typename std::enable_if<
                 std::is_pointer<PointerType>::value, int>::type = 0>
    constexpr auto get_ptr() const noexcept -> decltype(std::declval<const basic_json_t&>().get_impl_ptr(std::declval<PointerType>()));
    reference front();
    const_reference front() const;
    reference at(size_type index);
    const_reference at(size_type index) const;
    size_type erase(size_type index);
    reverse_iterator rbegin() noexcept;
    const_reverse_iterator crbegin() const noexcept;
    void shadow() {
        using reference = int;
        reference local = 0;
        (void)local;
    }
};

class other_json {
public:
    using value_type = other_json;
    using reference = value_type&;
    using const_reference = const value_type&; // unrelated alias
    using size_type = unsigned long;
    using reverse_iterator = helper<other_json>;
    using const_reverse_iterator = helper<other_json>;
    const_reference front() const;
    void use(reference, size_type, reverse_iterator, const_reverse_iterator);
};

namespace unrelated {
using const_reference = int;
using size_type = unsigned long;
const_reference unrelated_front();
}

NLOHMANN_JSON_NAMESPACE_END
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let file = project.file("contrib/json.hpp");
    let source = file.read_to_string().expect("fixture source");
    let target = |name: &str| {
        definition_by(&analyzer, |unit| {
            unit.kind() == CodeUnitType::Class
                && unit.fq_name() == format!("basic_json${name}")
                && !unit.is_synthetic()
        })
    };

    let basic_json_t = target("basic_json_t");
    let basic_json_t_hits = authoritative_exact_ranges(&analyzer, &basic_json_t, &file);
    for line in [
        "    using private_helper = helper<basic_json_t>;",
        "    auto get_ptr() noexcept -> decltype(std::declval<basic_json_t&>().get_impl_ptr(std::declval<PointerType>()));",
        "    constexpr auto get_ptr() const noexcept -> decltype(std::declval<const basic_json_t&>().get_impl_ptr(std::declval<PointerType>()));",
        "    using reverse_iterator = helper<basic_json_t>;",
        "    using const_reverse_iterator = helper<basic_json_t>;",
    ] {
        assert!(
            basic_json_t_hits.contains(&token_range(source.as_str(), line, "basic_json_t")),
            "basic_json_t reference must be an inverse hit: {line}"
        );
    }

    let expected_alias_hits: Vec<(&str, Vec<&str>)> = vec![
        (
            "reference",
            vec![
                "    reference front();",
                "    reference at(size_type index);",
            ],
        ),
        (
            "const_reference",
            vec![
                "    const_reference front() const;",
                "    const_reference at(size_type index) const;",
            ],
        ),
        (
            "size_type",
            vec![
                "    reference at(size_type index);",
                "    const_reference at(size_type index) const;",
                "    size_type erase(size_type index);",
            ],
        ),
        (
            "reverse_iterator",
            vec!["    reverse_iterator rbegin() noexcept;"],
        ),
        (
            "const_reverse_iterator",
            vec!["    const_reverse_iterator crbegin() const noexcept;"],
        ),
    ];

    for (name, lines) in expected_alias_hits {
        let target = target(name);
        let expected = lines
            .into_iter()
            .map(|line| token_range(source.as_str(), line, name))
            .collect::<BTreeSet<_>>();
        let expected = if name == "size_type" {
            let mut expected = expected;
            expected.insert(last_token_range(
                source.as_str(),
                "    size_type erase(size_type index);",
                name,
            ));
            expected
        } else {
            expected
        };
        assert_eq!(
            expected,
            authoritative_exact_ranges(&analyzer, &target, &file),
            "inverse lookup must retain exact basic_json::{name} signatures"
        );
    }

    let reference_hits = authoritative_exact_ranges(&analyzer, &target("reference"), &file);
    for (line, token) in [
        ("        using reference = int;", "reference"),
        (
            "    void use(reference, size_type, reverse_iterator, const_reverse_iterator);",
            "reference",
        ),
    ] {
        let range = token_range(source.as_str(), line, token);
        assert!(
            !reference_hits.contains(&range),
            "same-spelled local or other-class alias must not match reference: {line}"
        );
    }

    let const_reference_hits =
        authoritative_exact_ranges(&analyzer, &target("const_reference"), &file);
    assert!(!const_reference_hits.contains(&token_range(
        source.as_str(),
        "const_reference unrelated_front();",
        "const_reference",
    )));
    assert!(!const_reference_hits.contains(&token_range(
        source.as_str(),
        "    using const_reference = const value_type&; // unrelated alias",
        "const_reference",
    )));

    assert_eq!(
        authoritative_exact_ranges(&analyzer, &target("self_alias"), &file),
        BTreeSet::new(),
        "a class alias name in its own right-hand side is not a reference to that alias"
    );

    let value_t = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.identifier() == "value_t"
            && !unit.fq_name().contains("basic_json")
            && !unit.is_synthetic()
    });
    assert!(
        authoritative_exact_ranges(&analyzer, &value_t, &file).contains(&token_range(
            source.as_str(),
            "        value_t m_type = value_t::null;",
            "value_t",
        )),
        "the canonical enum must retain a recovered class alias reference"
    );
    assert!(
        authoritative_exact_ranges(&analyzer, &value_t, &file).contains(&token_range(
            source.as_str(),
            "        data(const value_t v) : m_type(v) {}",
            "value_t",
        )),
        "the canonical enum must retain a class-alias constructor parameter reference"
    );
}

#[test]
fn behaviortree_flattened_namespace_enum_alias_matches_nested_parameter() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "contrib/json.hpp",
            r#"NLOHMANN_JSON_NAMESPACE_END
NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
enum class value_t;
enum class value_t { null };
}
NLOHMANN_JSON_NAMESPACE_END

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
template<class> struct detector { using value_t = int; };
}

template<class T>
class basic_json
{
public:
    using value_t = detail::value_t;
    struct data
    {
        data(const value_t value) {}
    };
};
}
NLOHMANN_JSON_NAMESPACE_END

namespace other {
namespace detail { enum class value_t { other }; }
class other_json {
public:
    using value_t = detail::value_t;
    struct data { data(const value_t value) {} };
};
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let file = project.file("contrib/json.hpp");
    let source = file.read_to_string().expect("fixture source");
    let target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.package_name() == "detail"
            && unit.identifier() == "value_t"
            && unit.signature().is_none()
            && !unit.is_synthetic()
    });
    let parameter = token_range(
        source.as_str(),
        "        data(const value_t value) {}",
        "value_t",
    );
    assert!(
        authoritative_exact_ranges(&analyzer, &target, &file).contains(&parameter),
        "a class alias must retain the direct enum target when a stale namespace sentinel flattens its indexed namespace"
    );

    let detector_alias = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.identifier() == "value_t"
            && unit
                .signature()
                .is_some_and(|signature| signature == "using value_t = int;")
    });
    assert!(
        !authoritative_exact_ranges(&analyzer, &detector_alias, &file).contains(&parameter),
        "the same-spelled detector alias must not absorb the nested parameter"
    );
    let other_parameter = token_range(
        source.as_str(),
        "    struct data { data(const value_t value) {} };",
        "value_t",
    );
    assert!(
        !authoritative_exact_ranges(&analyzer, &target, &file).contains(&other_parameter),
        "a nearer other::detail::value_t target must exclude the unrelated class alias parameter"
    );
}

#[test]
fn behaviortree_primary_alias_does_not_collapse_partial_specialization_identity() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "contrib/expected.hpp",
            r#"namespace expected_lite {
template<typename T, typename E>
class expected {
public:
    using error_type = E;

    template<typename F>
    expected<T, error_type> transform(F&&) const {
        return expected<T, error_type>();
    }
};

template<typename E>
class expected<void, E> {
public:
    using error_type = E;

    template<typename F>
    expected<void, error_type> transform(F&&) const {
        return expected<void, error_type>();
    }

    void construct_error(error_type const& error) {
        new (this) error_type(error);
    }
};
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let file = project.file("contrib/expected.hpp");
    let source = file.read_to_string().expect("fixture source");
    let primary = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.fq_name() == "expected_lite.expected$error_type"
            && !unit.is_synthetic()
    });
    let partial = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.fq_name() == "expected_lite.expected<void, E>$error_type"
            && !unit.is_synthetic()
    });
    let partial_references = BTreeSet::from([
        token_range(
            source.as_str(),
            "    expected<void, error_type> transform(F&&) const {",
            "error_type",
        ),
        token_range(
            source.as_str(),
            "        return expected<void, error_type>();",
            "error_type",
        ),
        token_range(
            source.as_str(),
            "    void construct_error(error_type const& error) {",
            "error_type",
        ),
        token_range(
            source.as_str(),
            "        new (this) error_type(error);",
            "error_type",
        ),
    ]);
    let primary_references = BTreeSet::from([
        token_range(
            source.as_str(),
            "    expected<T, error_type> transform(F&&) const {",
            "error_type",
        ),
        token_range(
            source.as_str(),
            "        return expected<T, error_type>();",
            "error_type",
        ),
    ]);
    let forward_reference = partial_references
        .iter()
        .next()
        .copied()
        .expect("partial specialization alias use");
    let line_start = source[..forward_reference.0]
        .rfind('\n')
        .map_or(0, |newline| newline + 1);
    let line = source[..forward_reference.0]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1;
    let column = source[line_start..forward_reference.0].chars().count() + 1;
    let forward = brokk_bifrost::searchtools::get_definitions_by_location(
        &analyzer,
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: vec![brokk_bifrost::searchtools::DefinitionReferenceQuery {
                path: "contrib/expected.hpp".to_string(),
                line: Some(line),
                column: Some(column),
            }],
        },
    );
    assert_eq!(forward.results[0].status, "resolved", "{forward:#?}");
    assert!(
        forward.results[0].definitions.iter().any(|definition| {
            definition.fqn.as_deref() == Some("expected_lite.expected<void, E>$error_type")
        }),
        "partial specialization alias use must forward-resolve to the specialized alias: {forward:#?}"
    );
    assert_eq!(
        authoritative_exact_ranges(&analyzer, &partial, &file),
        partial_references,
        "partial specialization alias must own its dependent uses"
    );
    assert_eq!(
        authoritative_exact_ranges(&analyzer, &primary, &file),
        primary_references,
        "primary alias must retain compatible redeclaration uses without absorbing partial specialization uses"
    );
}
