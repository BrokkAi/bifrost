use crate::common::InlineTestProject;
use brokk_bifrost::usages::{ExplicitCandidateProvider, FuzzyResult, UsageFinder};
use brokk_bifrost::{CodeUnit, CodeUnitType, CppAnalyzer, IAnalyzer, Language, ProjectFile};
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
        panic!("expected authoritative C++ success")
    };
    assert_eq!(
        query.candidate_files,
        std::iter::once(candidate.clone()).collect(),
        "authoritative query must remain limited to the fixture file"
    );
    hits_by_overload
        .values()
        .flatten()
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect()
}

#[test]
fn behaviortree_owner_qualifiers_match_forward_and_inverse() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "json.hpp",
            r#"#pragma once
namespace nlohmann {
namespace detail {
struct invalid_iterator { static int create(int, const char*); };
struct type_error { static int create(int, const char*); };
struct out_of_range { static int create(int, const char*); };
enum class error_handler_t { strict, ignore, replace };
enum class cbor_tag_handler_t { error, ignore };

#define JSON_THROW(value) value
template<typename BasicJsonType>
struct iter_impl {
    void check() {
        switch (0) {
            case 0:
                JSON_THROW(invalid_iterator::create(12, ""));
        }
    }
};
template<typename BasicJsonType>
struct serializer {
    error_handler_t error_handler;
    void check() {
        switch (error_handler) {
            case error_handler_t::strict:
                break;
            default:
                break;
        }
    }
};
}

template<typename T = int>
struct basic_json {
    using invalid_iterator = detail::invalid_iterator;
    using type_error = detail::type_error;
    using out_of_range = detail::out_of_range;
    using error_handler_t = detail::error_handler_t;
    using cbor_tag_handler_t = detail::cbor_tag_handler_t;
#if 0
    using hidden_iterator = detail::invalid_iterator;
#endif
    static void check() {
        invalid_iterator::create(9, "");
        type_error::create(10, "");
        out_of_range::create(11, "");
        error_handler_t::strict;
        cbor_tag_handler_t::error;
    }
};
using json = basic_json<>;
}
"#,
        )
        .file(
            "consumer.cpp",
            r#"#include "json.hpp"
void consume() {
    nlohmann::detail::invalid_iterator::create(1, "");
    nlohmann::detail::type_error::create(2, "");
    nlohmann::detail::out_of_range::create(3, "");
    nlohmann::detail::error_handler_t::strict;
    nlohmann::detail::cbor_tag_handler_t::error;
    nlohmann::json::invalid_iterator::create(4, "");
    nlohmann::json::type_error::create(5, "");
    nlohmann::json::out_of_range::create(6, "");
    nlohmann::json::error_handler_t::strict;
    nlohmann::json::cbor_tag_handler_t::error;
}
void absent_owner() {
    type_error::create(7, "");
}
void near_miss() {
    struct type_error { static int create(int, const char*); };
    type_error::create(8, "");
}
namespace unrelated {
struct type_error { static int create(int, const char*); };
}
namespace nested {
namespace nlohmann {
namespace detail {
struct invalid_iterator { static int create(int, const char*); };
}
}
}
void unrelated_owner() {
    unrelated::type_error::create(9, "");
}
void wrong_suffix_owner() {
    nested::nlohmann::detail::invalid_iterator::create(10, "");
}
namespace later {
void before_alias() {
    invalid_iterator::create(11, "");
    invalid_iterator value;
}
using invalid_iterator = nlohmann::detail::invalid_iterator;
}
void disabled_owner() {
    nlohmann::json::hidden_iterator::create(12, "");
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let consumer = project.file("consumer.cpp");
    let header = project.file("json.hpp");
    let source = consumer.read_to_string().expect("consumer source");
    let header_source = header.read_to_string().expect("header source");
    let target = |name: &str| {
        definition_by(&analyzer, |unit| {
            unit.kind() == CodeUnitType::Class
                && unit.package_name() == "nlohmann::detail"
                && unit.identifier() == name
                && !unit.is_synthetic()
        })
    };
    for (name, line, expected) in [
        (
            "invalid_iterator",
            "    nlohmann::detail::invalid_iterator::create(1, \"\");",
            "invalid_iterator",
        ),
        (
            "type_error",
            "    nlohmann::detail::type_error::create(2, \"\");",
            "type_error",
        ),
        (
            "out_of_range",
            "    nlohmann::detail::out_of_range::create(3, \"\");",
            "out_of_range",
        ),
        (
            "error_handler_t",
            "    nlohmann::detail::error_handler_t::strict;",
            "error_handler_t",
        ),
        (
            "cbor_tag_handler_t",
            "    nlohmann::detail::cbor_tag_handler_t::error;",
            "cbor_tag_handler_t",
        ),
    ] {
        let owner = token_range(source.as_str(), line, expected);
        let line_start = source[..owner.0]
            .rfind('\n')
            .map_or(0, |newline| newline + 1);
        let line_number = source[..owner.0]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1;
        let forward = brokk_bifrost::searchtools::get_definitions_by_location(
            &analyzer,
            brokk_bifrost::searchtools::GetDefinitionParams {
                references: vec![brokk_bifrost::searchtools::DefinitionReferenceQuery {
                    path: "consumer.cpp".to_string(),
                    line: Some(line_number),
                    column: Some(source[line_start..owner.0].chars().count() + 1),
                }],
            },
        );
        assert_eq!("resolved", forward.results[0].status, "{forward:#?}");
        assert!(
            forward.results[0].definitions.iter().any(
                |definition| definition.fqn.as_deref() == Some(target(name).fq_name().as_str())
            ),
            "owner token must forward-resolve to {name}: {forward:#?}"
        );
        assert!(
            authoritative_exact_ranges(&analyzer, &target(name), &consumer).contains(&owner),
            "inverse lookup must retain exact owner qualifier {name}: {owner:?}"
        );
    }

    for (name, line, expected) in [
        (
            "invalid_iterator",
            "                JSON_THROW(invalid_iterator::create(12, \"\"));",
            "invalid_iterator",
        ),
        (
            "error_handler_t",
            "            case error_handler_t::strict:",
            "error_handler_t",
        ),
    ] {
        let owner = token_range(header_source.as_str(), line, expected);
        assert!(
            authoritative_exact_ranges(&analyzer, &target(name), &header).contains(&owner),
            "inverse lookup must retain BehaviorTree switch qualifier {name}: {owner:?}"
        );
    }

    for (name, line, expected) in [
        (
            "invalid_iterator",
            "        invalid_iterator::create(9, \"\");",
            "invalid_iterator",
        ),
        (
            "type_error",
            "        type_error::create(10, \"\");",
            "type_error",
        ),
        (
            "out_of_range",
            "        out_of_range::create(11, \"\");",
            "out_of_range",
        ),
        (
            "error_handler_t",
            "        error_handler_t::strict;",
            "error_handler_t",
        ),
        (
            "cbor_tag_handler_t",
            "        cbor_tag_handler_t::error;",
            "cbor_tag_handler_t",
        ),
    ] {
        let owner = token_range(header_source.as_str(), line, expected);
        assert!(
            authoritative_exact_ranges(&analyzer, &target(name), &header).contains(&owner),
            "inverse lookup must retain in-class alias owner qualifier {name}: {owner:?}"
        );
    }

    for (name, line, expected) in [
        (
            "invalid_iterator",
            "    nlohmann::json::invalid_iterator::create(4, \"\");",
            "invalid_iterator",
        ),
        (
            "type_error",
            "    nlohmann::json::type_error::create(5, \"\");",
            "type_error",
        ),
        (
            "out_of_range",
            "    nlohmann::json::out_of_range::create(6, \"\");",
            "out_of_range",
        ),
        (
            "error_handler_t",
            "    nlohmann::json::error_handler_t::strict;",
            "error_handler_t",
        ),
        (
            "cbor_tag_handler_t",
            "    nlohmann::json::cbor_tag_handler_t::error;",
            "cbor_tag_handler_t",
        ),
    ] {
        let owner = token_range(source.as_str(), line, expected);
        let hits = authoritative_exact_ranges(&analyzer, &target(name), &consumer);
        assert!(
            hits.contains(&owner),
            "inverse lookup must retain class-alias owner qualifier {name}: {owner:?}"
        );
    }

    for (name, line, expected) in [
        (
            "type_error",
            "    type_error::create(7, \"\");",
            "type_error",
        ),
        (
            "type_error",
            "    type_error::create(8, \"\");",
            "type_error",
        ),
        (
            "type_error",
            "    unrelated::type_error::create(9, \"\");",
            "type_error",
        ),
    ] {
        let near_miss = token_range(source.as_str(), line, expected);
        assert!(
            !authoritative_exact_ranges(&analyzer, &target(name), &consumer).contains(&near_miss),
            "inverse lookup must reject unrelated owner qualifier {name}: {near_miss:?}"
        );
    }

    for (line, token) in [
        (
            "    nested::nlohmann::detail::invalid_iterator::create(10, \"\");",
            "invalid_iterator",
        ),
        (
            "    invalid_iterator::create(11, \"\");",
            "invalid_iterator",
        ),
        ("    invalid_iterator value;", "invalid_iterator"),
        (
            "    nlohmann::json::hidden_iterator::create(12, \"\");",
            "hidden_iterator",
        ),
    ] {
        let near_miss = token_range(source.as_str(), line, token);
        assert!(
            !authoritative_exact_ranges(&analyzer, &target("invalid_iterator"), &consumer)
                .contains(&near_miss),
            "inverse lookup must reject later, inactive, or suffix-only owners: {line}: {near_miss:?}"
        );
    }
}

#[test]
fn behaviortree_resolved_mismatch_alias_qualifier_is_inverse_hit() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "json.hpp",
            r#"
#define NLOHMANN_JSON_NAMESPACE_BEGIN namespace nlohmann { inline namespace json_abi_v3_11_3 {
#define NLOHMANN_JSON_NAMESPACE_END } }
NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail {
struct type_error {
    static int create(int, const char*);
};
}

template<typename T = int>
struct basic_json {
    using type_error = detail::type_error;

    static void check() {
        type_error::create(1, "");
    }
};
NLOHMANN_JSON_NAMESPACE_END
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let file = project.file("json.hpp");
    let source = file.read_to_string().expect("fixture source");
    let target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.package_name() == "detail"
            && unit.identifier() == "type_error"
            && !unit.is_synthetic()
    });
    let site = token_range(
        source.as_str(),
        "        type_error::create(1, \"\");",
        "type_error",
    );
    assert!(
        authoritative_exact_ranges(&analyzer, &target, &file).contains(&site),
        "resolved alias qualifier must retain the target class range: {site:?}"
    );
}

#[test]
fn behaviortree_bare_alias_chain_is_inverse_hit() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "json.hpp",
            r#"
namespace nlohmann {
namespace detail {
template<typename Base>
struct json_reverse_iterator {};
}

template<typename T = int>
struct basic_json {
    template<typename Base>
    using json_reverse_iterator = detail::json_reverse_iterator<Base>;
    using const_iterator = int;
    using const_reverse_iterator = json_reverse_iterator<typename basic_json::const_iterator>;

    const_reverse_iterator rbegin() const;
};
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let file = project.file("json.hpp");
    let source = file.read_to_string().expect("fixture source");
    let target = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.fq_name().ends_with("basic_json$json_reverse_iterator")
            && !unit.is_synthetic()
    });
    let site = token_range(
        source.as_str(),
        "    const_reverse_iterator rbegin() const;",
        "const_reverse_iterator",
    );
    assert!(
        authoritative_exact_ranges(&analyzer, &target, &file).contains(&site),
        "bare alias-chain return type must retain the target alias range: {site:?}"
    );
}
