mod common;

use brokk_bifrost::usages::{ExplicitCandidateProvider, FuzzyResult, UsageFinder};
use brokk_bifrost::{CodeUnitType, CppAnalyzer, IAnalyzer, Language, ProjectFile};
use common::InlineTestProject;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

fn signature_arity(signature: &str) -> usize {
    let parameters = signature
        .split_once('(')
        .and_then(|(_, rest)| rest.split_once(')'))
        .map(|(parameters, _)| parameters.trim())
        .unwrap_or_default();
    if parameters.is_empty() || parameters == "void" {
        0
    } else {
        parameters.split(',').count()
    }
}

#[test]
fn c_ts_field_resolves_included_multiline_declaration_on_all_surfaces() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "tree_sitter/api.h",
            r#"#ifndef TREE_SITTER_API_H_
#define TREE_SITTER_API_H_
typedef unsigned int uint32_t;
typedef struct TSNode { const void *tree; } TSNode;
#ifdef __cplusplus
extern "C" {
#endif
TSNode ts_node_child_by_field_name(
  TSNode self,
  const char *name,
  uint32_t name_length
);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
TSNode cpp_only_child_by_field_name(
  TSNode self,
  const char *name,
  uint32_t name_length
);
}
#endif
#endif
"#,
        )
        .file(
            "foundation/constants.h",
            r#"#ifndef CONSTANTS_H
#define CONSTANTS_H
#define SKIP_ONE 1
#define TS_FIELD(name) (name), (uint32_t)(sizeof(name) - SKIP_ONE)
#endif
"#,
        )
        .file(
            "node.c",
            r#"#include "tree_sitter/api.h"
TSNode ts_node_child_by_field_name(
  TSNode self,
  const char *name,
  uint32_t name_length
) { return self; }
"#,
        )
        .file(
            "extract_channels.c",
            r#"#include "foundation/constants.h"
#include "tree_sitter/api.h"
TSNode extract_value(TSNode node) {
    return ts_node_child_by_field_name(node, TS_FIELD("value"));
}
TSNode extract_cpp_only(TSNode node) {
    return cpp_only_child_by_field_name(node, TS_FIELD("value"));
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let consumer = project.file("extract_channels.c");
    let source = consumer
        .read_to_string()
        .expect("faithful TS_FIELD consumer");
    let line = "    return ts_node_child_by_field_name(node, TS_FIELD(\"value\"));";
    let expected = token_range(&source, line, "ts_node_child_by_field_name");
    let target = analyzer
        .get_all_declarations()
        .iter()
        .find(|unit| {
            unit.kind() == CodeUnitType::Function
                && unit.identifier() == "ts_node_child_by_field_name"
                && unit.source().rel_path() == Path::new("tree_sitter/api.h")
        })
        .cloned()
        .expect("included three-parameter declaration");

    let line_number = source[..expected.0]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1;
    let line_start = source[..expected.0]
        .rfind('\n')
        .map_or(0, |newline| newline + 1);
    let forward = brokk_bifrost::searchtools::get_definitions_by_location(
        &analyzer,
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: vec![brokk_bifrost::searchtools::DefinitionReferenceQuery {
                path: "extract_channels.c".to_string(),
                line: Some(line_number),
                column: Some(source[line_start..expected.0].chars().count() + 1),
            }],
        },
    )
    .results
    .into_iter()
    .next()
    .expect("one faithful forward result");
    assert_eq!(forward.status, "resolved", "{forward:#?}");
    assert!(
        forward.definitions.iter().any(|definition| {
            definition.path == "tree_sitter/api.h"
                && definition
                    .signature
                    .as_deref()
                    .is_some_and(|signature| signature_arity(signature) == 3)
        }),
        "forward must retain the included declaration: {forward:#?}"
    );
    let cpp_only_line = "    return cpp_only_child_by_field_name(node, TS_FIELD(\"value\"));";
    let cpp_only = token_range(&source, cpp_only_line, "cpp_only_child_by_field_name");
    let cpp_only_line_start = source[..cpp_only.0]
        .rfind('\n')
        .map_or(0, |newline| newline + 1);
    let cpp_only_forward = brokk_bifrost::searchtools::get_definitions_by_location(
        &analyzer,
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: vec![brokk_bifrost::searchtools::DefinitionReferenceQuery {
                path: "extract_channels.c".to_string(),
                line: Some(
                    source[..cpp_only.0]
                        .bytes()
                        .filter(|byte| *byte == b'\n')
                        .count()
                        + 1,
                ),
                column: Some(source[cpp_only_line_start..cpp_only.0].chars().count() + 1),
            }],
        },
    )
    .results
    .into_iter()
    .next()
    .expect("one conditional-linkage forward result");
    assert_eq!(
        cpp_only_forward.status, "no_definition",
        "a declaration genuinely inside the __cplusplus branch must stay hidden: {cpp_only_forward:#?}"
    );

    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let targeted = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            100,
        );
    assert_eq!(
        consumer_ranges(&targeted.result, &consumer),
        BTreeSet::from([expected]),
        "targeted inverse lookup"
    );
    let whole = UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target));
    assert_eq!(
        consumer_ranges(&whole, &consumer),
        BTreeSet::from([expected]),
        "whole inverse lookup"
    );
}

fn token_range(source: &str, labeled_line: &str, token: &str) -> (usize, usize) {
    let line = source
        .find(labeled_line)
        .unwrap_or_else(|| panic!("missing fixture line {labeled_line:?}"));
    let relative = labeled_line
        .find(token)
        .unwrap_or_else(|| panic!("missing token {token:?} in {labeled_line:?}"));
    let start = line + relative;
    (start, start + token.len())
}

fn consumer_ranges(result: &FuzzyResult, consumer: &ProjectFile) -> BTreeSet<(usize, usize)> {
    result
        .all_hits_including_imports()
        .into_iter()
        .filter(|hit| hit.file == *consumer)
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect()
}

#[test]
fn cpp_macro_expansion_drives_forward_inverse_and_return_arity() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "api.h",
            r#"#pragma once
struct Node {};
struct Service { void execute() const; };
struct Other { void execute() const; };
Service select(Node node, const char* name, unsigned length);
Other select(Node node, const char* name);
namespace Hidden {
Service select(Node node, const char* name, unsigned length, int flags);
}
"#,
        )
        .file(
            "macros.h",
            r#"#ifndef MACROS_H
#define MACROS_H
#define ONE 1
#define FIELD(name) (name), (unsigned)(sizeof(name) - ONE)
#define IDENTITY(value) (value)
#define VARIADIC(...) __VA_ARGS__
#define PASTE(left, right) left ## right
#define STRINGIFY(value) #value
#define LOOP LOOP
#define PAIR 1, 2
#define WRAP_PARAMETER(value) value + 0
#define WRAP_OBJECT PAIR + 0
#define SPREAD_CALL() 1, 2
#define WRAP_CALL() 0 + SPREAD_CALL()
#define CALLEES first, second
#define INVOKE(function) function()
#define ID(value) value
#define WRAP_ID(value) ID(value)
#endif
"#,
        )
        .file(
            "conditional_macros.h",
            r#"#define CONDITIONAL_HEADER(name) (name), 1
"#,
        )
        .file(
            "pragma_spread.h",
            r#"#pragma once
#define PRAGMA_SPREAD(name) (name), 1
"#,
        )
        .file(
            "conditional_once.h",
            r#"#pragma once
#define CONDITIONAL_ONCE(name) (name), 1
"#,
        )
        .file(
            "conditional_guard.h",
            r#"#ifndef CONDITIONAL_GUARD_H
// A comment between the guard name and matching define is canonical.
#define CONDITIONAL_GUARD_H
#define CONDITIONAL_GUARD(name) (name), 1
#endif
"#,
        )
        .file(
            "nested_feature_guard.h",
            r#"#define OUTSIDE_FEATURE_GUARD 1
#ifndef FEATURE_GUARD
#define FEATURE_GUARD
#define NESTED_FEATURE(name) (name), 1
#endif
"#,
        )
        .file(
            "diamond_shared.h",
            r#"#ifndef DIAMOND_SHARED_H
#define DIAMOND_SHARED_H
#define DIAMOND(name) (name), 1
#endif
"#,
        )
        .file(
            "diamond_left.h",
            r#"#ifndef DIAMOND_LEFT_H
#define DIAMOND_LEFT_H
#include "diamond_shared.h"
#endif
"#,
        )
        .file(
            "diamond_right.h",
            r#"#ifndef DIAMOND_RIGHT_H
#define DIAMOND_RIGHT_H
#include "diamond_shared.h"
#endif
"#,
        )
        .file(
            "left/ambiguous.h",
            r#"#define CONFLICTING_PAIR(name) (name)
"#,
        )
        .file(
            "right/ambiguous.h",
            r#"#define CONFLICTING_PAIR(name) (name), 1
"#,
        )
        .file(
            "api.cc",
            r#"#include "api.h"
Service select(Node node, const char* name, unsigned length) { return {}; }
Other select(Node node, const char* name) { return {}; }
Service Hidden::select(Node node, const char* name, unsigned length, int flags) { return {}; }
void Service::execute() const {}
void Other::execute() const {}
"#,
        )
        .file(
            "consumer.cc",
            r#"#include "api.h"
void consume(Node node) {
    auto before = select(node, FIELD("value")); // negative-include-after-call-two
#include "macros.h"
    auto spread = select(node, FIELD("value")); // positive-macro-three
#include <external.h>
    auto external_direct = select(node, "value", 5); // positive-external-boundary-direct
    auto external_macro = select(node, FIELD("value")); // positive-external-boundary-macro
#include "pragma_spread.h"
    auto pragma_first = select(node, PRAGMA_SPREAD("value")); // positive-pragma-once-first
#define PRAGMA_SPREAD(name) (name)
#include "pragma_spread.h"
    auto pragma_second = select(node, PRAGMA_SPREAD("value")); // negative-pragma-once-retains-local-two
#if FLAG
#include "conditional_once.h"
#endif
#define CONDITIONAL_ONCE(name) (name)
#include "conditional_once.h"
    auto conditional_once = select(node, CONDITIONAL_ONCE("value")); // unknown-conditional-pragma-once
#if FLAG
#include "conditional_guard.h"
#endif
#define CONDITIONAL_GUARD(name) (name)
#include "conditional_guard.h"
    auto conditional_guard = select(node, CONDITIONAL_GUARD("value")); // unknown-conditional-macro-guard
#include "nested_feature_guard.h"
    auto nested_feature = select(node, NESTED_FEATURE("value")); // unknown-nested-feature-guard
    auto direct = select(node, "value", 5); // positive-direct-three
    auto identity = select(node, IDENTITY("value")); // negative-exact-two
    auto variadic = select(node, VARIADIC("value", 5)); // unknown-variadic
    {
        auto select = [](Node, const char*, unsigned) { return Service{}; };
        auto local_shadow = select(node, VARIADIC("value", 5)); // negative-unknown-local-shadow
    }
    auto paste = select(node, PASTE("value", 5)); // unknown-token-paste
    auto stringify = select(node, STRINGIFY(value)); // unknown-stringify
    auto cycle = select(node, LOOP); // unknown-cycle
    auto wrapped_parameter = select(node, WRAP_PARAMETER(PAIR)); // unknown-nested-parameter-token
    auto wrapped_object = select(node, WRAP_OBJECT); // unknown-nested-object-token
    auto wrapped_call = select(node, WRAP_CALL()); // unknown-nested-bound-call
    auto source_object = select(node, 0 + PAIR); // unknown-source-nested-object
    auto source_call = select(node, 0 + SPREAD_CALL()); // unknown-source-nested-call
    auto parameter_callee = select(node, INVOKE(CALLEES)); // unknown-parameter-callee
    auto nested_uncontained_parameter = select(node, WRAP_ID(PAIR)); // unknown-nested-uncontained-parameter
#undef FIELD
    auto undefined = select(node, FIELD("value")); // negative-after-undef-two
#define FIELD(name) (name)
    auto redefine_two = select(node, FIELD("value")); // negative-redefine-two
#define FIELD(name) (name), (unsigned)(sizeof(name) - ONE)
    auto redefine_three = select(node, FIELD("value")); // positive-redefine-three
#define OUTER(name) FIELD(name)
    auto nested = select(node, OUTER("value")); // unknown-outer-uncontained-parameter
#if FLAG
#define CONDITIONAL(name) (name), 1
#else
#define CONDITIONAL(name) (name)
#endif
    auto conditional = select(node, CONDITIONAL("value")); // unknown-conditional-definition
#define CONDITIONAL(name) (name), 1
    auto restored = select(node, CONDITIONAL("value")); // positive-restored-definition
#define MAYBE_FIELD(name) (name), 1
#if FLAG
#undef MAYBE_FIELD
#endif
    auto conditional_undef = select(node, MAYBE_FIELD("value")); // unknown-conditional-undef
#define MAYBE_FIELD(name) (name), 1
    auto restored_undef = select(node, MAYBE_FIELD("value")); // positive-restored-undef
#if FLAG
#include "conditional_macros.h"
#endif
    auto conditional_include = select(node, CONDITIONAL_HEADER("value")); // unknown-conditional-include
#include "conditional_macros.h"
    auto restored_include = select(node, CONDITIONAL_HEADER("value")); // positive-restored-include
#include "diamond_left.h"
#include "diamond_right.h"
    auto diamond = select(node, DIAMOND("value")); // positive-guarded-diamond
#if FLAG
#include "diamond_shared.h"
#endif
    auto diamond_conditional_duplicate = select(node, DIAMOND("value")); // positive-exact-guard-skips-conditional-duplicate
#if FLAG
#undef DIAMOND_SHARED_H
#endif
#undef DIAMOND
#include "diamond_shared.h"
    auto ambiguous_guard_reinclude = select(node, DIAMOND("value")); // unknown-ambiguous-guard-reinclude
#undef DIAMOND_SHARED_H
#undef DIAMOND
#include "diamond_shared.h"
    auto reinclude = select(node, DIAMOND("value")); // positive-guard-undef-reinclude
#define OPAQUE(name) (name), 1
#undef OPAQUE trailing
    auto opaque_undef = select(node, OPAQUE("value")); // unknown-opaque-undef
#include "ambiguous.h"
    auto ambiguous_include = select(node, CONFLICTING_PAIR("value")); // unknown-ambiguous-include
#include "missing_macros.h"
    auto unresolved_literal = select(node, MISSING_PAIR); // unknown-unresolved-literal-include
#include UNKNOWN_HEADER
    auto unresolved_computed = select(node, PAIR); // unknown-unresolved-computed-include
    spread.execute(); // positive-return-inference
    variadic.execute(); // negative-unknown-return-inference
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let consumer = project.file("consumer.cc");
    let source = consumer.read_to_string().expect("macro arity consumer");
    let three_arg = analyzer
        .get_all_declarations()
        .iter()
        .find(|unit| {
            unit.kind() == CodeUnitType::Function
                && unit.identifier() == "select"
                && unit
                    .signature()
                    .is_some_and(|signature| signature_arity(signature) == 3)
        })
        .cloned()
        .expect("three-argument select");
    let expected = [
        "    auto spread = select(node, FIELD(\"value\")); // positive-macro-three",
        "    auto external_direct = select(node, \"value\", 5); // positive-external-boundary-direct",
        "    auto external_macro = select(node, FIELD(\"value\")); // positive-external-boundary-macro",
        "    auto pragma_first = select(node, PRAGMA_SPREAD(\"value\")); // positive-pragma-once-first",
        "    auto direct = select(node, \"value\", 5); // positive-direct-three",
        "    auto redefine_three = select(node, FIELD(\"value\")); // positive-redefine-three",
        "    auto restored = select(node, CONDITIONAL(\"value\")); // positive-restored-definition",
        "    auto restored_undef = select(node, MAYBE_FIELD(\"value\")); // positive-restored-undef",
        "    auto restored_include = select(node, CONDITIONAL_HEADER(\"value\")); // positive-restored-include",
        "    auto diamond = select(node, DIAMOND(\"value\")); // positive-guarded-diamond",
        "    auto diamond_conditional_duplicate = select(node, DIAMOND(\"value\")); // positive-exact-guard-skips-conditional-duplicate",
        "    auto reinclude = select(node, DIAMOND(\"value\")); // positive-guard-undef-reinclude",
    ]
    .map(|line| token_range(&source, line, "select"))
    .into_iter()
    .collect::<BTreeSet<_>>();

    let forward_at = |range: (usize, usize)| {
        let line_start = source[..range.0]
            .rfind('\n')
            .map_or(0, |newline| newline + 1);
        let line = source[..range.0]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1;
        let column = source[line_start..range.0].chars().count() + 1;
        brokk_bifrost::searchtools::get_definitions_by_location(
            &analyzer,
            brokk_bifrost::searchtools::GetDefinitionParams {
                references: vec![brokk_bifrost::searchtools::DefinitionReferenceQuery {
                    path: "consumer.cc".to_string(),
                    line: Some(line),
                    column: Some(column),
                }],
            },
        )
        .results
        .into_iter()
        .next()
        .expect("one forward result")
    };
    let spread_forward = forward_at(*expected.iter().next().expect("spread range"));
    assert_eq!("resolved", spread_forward.status, "{spread_forward:#?}");
    assert!(
        !spread_forward.definitions.is_empty()
            && spread_forward.definitions.iter().all(|definition| {
                definition
                    .signature
                    .as_deref()
                    .is_some_and(|signature| signature_arity(signature) == 3)
            }),
        "forward lookup must select only the expanded three-argument overload: {spread_forward:#?}"
    );
    let variadic_forward = forward_at(token_range(
        &source,
        "    auto variadic = select(node, VARIADIC(\"value\", 5)); // unknown-variadic",
        "select",
    ));
    assert_eq!(
        "ambiguous", variadic_forward.status,
        "{variadic_forward:#?}"
    );
    assert!(
        variadic_forward
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "ambiguous_definition"),
        "unknown macro arity must remain explicitly unproven: {variadic_forward:#?}"
    );
    let variadic_arities = variadic_forward
        .definitions
        .iter()
        .filter_map(|definition| definition.signature.as_deref())
        .map(signature_arity)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        variadic_arities,
        BTreeSet::from([2, 3]),
        "unknown expansion must not arity-select a forward overload"
    );
    assert!(
        variadic_forward.definitions.iter().all(|definition| {
            definition
                .fqn
                .as_deref()
                .is_some_and(|fqn| !fqn.starts_with("Hidden"))
        }),
        "unknown arity must retain only the nearest lexical callable tier: {variadic_forward:#?}"
    );
    let local_shadow_forward = forward_at(token_range(
        &source,
        "        auto local_shadow = select(node, VARIADIC(\"value\", 5)); // negative-unknown-local-shadow",
        "select",
    ));
    assert_eq!(
        "no_definition", local_shadow_forward.status,
        "an unknown-arity call through a local callable must not leak indexed free functions: {local_shadow_forward:#?}"
    );
    assert!(local_shadow_forward.definitions.is_empty());
    for line in [
        "    auto conditional = select(node, CONDITIONAL(\"value\")); // unknown-conditional-definition",
        "    auto conditional_undef = select(node, MAYBE_FIELD(\"value\")); // unknown-conditional-undef",
        "    auto conditional_include = select(node, CONDITIONAL_HEADER(\"value\")); // unknown-conditional-include",
        "    auto conditional_once = select(node, CONDITIONAL_ONCE(\"value\")); // unknown-conditional-pragma-once",
        "    auto conditional_guard = select(node, CONDITIONAL_GUARD(\"value\")); // unknown-conditional-macro-guard",
        "    auto nested_feature = select(node, NESTED_FEATURE(\"value\")); // unknown-nested-feature-guard",
        "    auto wrapped_parameter = select(node, WRAP_PARAMETER(PAIR)); // unknown-nested-parameter-token",
        "    auto wrapped_object = select(node, WRAP_OBJECT); // unknown-nested-object-token",
        "    auto wrapped_call = select(node, WRAP_CALL()); // unknown-nested-bound-call",
        "    auto source_object = select(node, 0 + PAIR); // unknown-source-nested-object",
        "    auto source_call = select(node, 0 + SPREAD_CALL()); // unknown-source-nested-call",
        "    auto parameter_callee = select(node, INVOKE(CALLEES)); // unknown-parameter-callee",
        "    auto nested_uncontained_parameter = select(node, WRAP_ID(PAIR)); // unknown-nested-uncontained-parameter",
        "    auto nested = select(node, OUTER(\"value\")); // unknown-outer-uncontained-parameter",
        "    auto opaque_undef = select(node, OPAQUE(\"value\")); // unknown-opaque-undef",
        "    auto ambiguous_include = select(node, CONFLICTING_PAIR(\"value\")); // unknown-ambiguous-include",
        "    auto ambiguous_guard_reinclude = select(node, DIAMOND(\"value\")); // unknown-ambiguous-guard-reinclude",
        "    auto unresolved_literal = select(node, MISSING_PAIR); // unknown-unresolved-literal-include",
        "    auto unresolved_computed = select(node, PAIR); // unknown-unresolved-computed-include",
    ] {
        let forward = forward_at(token_range(&source, line, "select"));
        assert_eq!(
            "ambiguous", forward.status,
            "unknown arity must remain explicit at {line:?}: {forward:#?}"
        );
        let arities = forward
            .definitions
            .iter()
            .filter_map(|definition| definition.signature.as_deref())
            .map(signature_arity)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            arities,
            BTreeSet::from([2, 3]),
            "mutually exclusive preprocessor branches must not claim exact arity at {line:?}"
        );
    }
    for line in [
        "    auto before = select(node, FIELD(\"value\")); // negative-include-after-call-two",
        "    auto undefined = select(node, FIELD(\"value\")); // negative-after-undef-two",
        "    auto redefine_two = select(node, FIELD(\"value\")); // negative-redefine-two",
        "    auto pragma_second = select(node, PRAGMA_SPREAD(\"value\")); // negative-pragma-once-retains-local-two",
    ] {
        let forward = forward_at(token_range(&source, line, "select"));
        assert!(
            !forward.definitions.is_empty()
                && forward.definitions.iter().all(|definition| {
                    definition
                        .signature
                        .as_deref()
                        .is_some_and(|signature| signature_arity(signature) == 2)
                }),
            "include order, undef, and redefinition must select the two-argument overload at {line:?}: {forward:#?}"
        );
    }

    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let targeted = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&three_arg),
            Some(&provider),
            1,
            1000,
        );
    let FuzzyResult::Success {
        hits_by_overload,
        unproven_total_by_overload,
        ..
    } = targeted.result
    else {
        panic!("expected targeted macro arity success");
    };
    let targeted_ranges = hits_by_overload
        .values()
        .flatten()
        .filter(|hit| hit.file == consumer)
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect::<BTreeSet<_>>();
    assert_eq!(targeted_ranges, expected, "{hits_by_overload:#?}");
    assert!(
        unproven_total_by_overload.values().sum::<usize>() >= 17,
        "unsupported and conditional expansions must remain unproven: {unproven_total_by_overload:#?}"
    );

    let whole = UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&three_arg));
    assert_eq!(consumer_ranges(&whole, &consumer), expected, "{whole:#?}");

    let two_arg = analyzer
        .get_all_declarations()
        .iter()
        .find(|unit| {
            unit.kind() == CodeUnitType::Function
                && unit.identifier() == "select"
                && unit
                    .signature()
                    .is_some_and(|signature| signature_arity(signature) == 2)
        })
        .cloned()
        .expect("two-argument select");
    let expected_two = [
        "    auto before = select(node, FIELD(\"value\")); // negative-include-after-call-two",
        "    auto identity = select(node, IDENTITY(\"value\")); // negative-exact-two",
        "    auto undefined = select(node, FIELD(\"value\")); // negative-after-undef-two",
        "    auto redefine_two = select(node, FIELD(\"value\")); // negative-redefine-two",
        "    auto pragma_second = select(node, PRAGMA_SPREAD(\"value\")); // negative-pragma-once-retains-local-two",
    ]
    .map(|line| token_range(&source, line, "select"))
    .into_iter()
    .collect::<BTreeSet<_>>();
    let targeted_two = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&two_arg),
            Some(&provider),
            1,
            1000,
        );
    assert_eq!(
        consumer_ranges(&targeted_two.result, &consumer),
        expected_two,
        "targeted inverse must honor include, undef, and redefinition order"
    );
    let whole_two =
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&two_arg));
    assert_eq!(
        consumer_ranges(&whole_two, &consumer),
        expected_two,
        "whole inverse must honor include, undef, and redefinition order"
    );

    let execute = analyzer
        .get_all_declarations()
        .iter()
        .find(|unit| {
            unit.kind() == CodeUnitType::Function && unit.short_name() == "Service.execute"
        })
        .cloned()
        .expect("Service.execute");
    let return_query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&execute),
            Some(&provider),
            1,
            1000,
        );
    assert_eq!(
        consumer_ranges(&return_query.result, &consumer),
        BTreeSet::from([token_range(
            &source,
            "    spread.execute(); // positive-return-inference",
            "execute",
        )]),
        "exact expansion should infer Service, while unknown expansion must not infer a return owner"
    );
}

#[test]
fn c_ts_field_macro_selects_three_parameter_target_on_all_surfaces() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "ts_api.h",
            r#"typedef unsigned int uint32_t;
int ts_select(int node, const char* name, uint32_t length);
"#,
        )
        .file(
            "ts_api.c",
            r#"#include "ts_api.h"
int ts_select(int node, const char* name, uint32_t length) {
    return node + (int)length + (name != 0);
}
"#,
        )
        .file(
            "ts_consumer.c",
            r#"#include "ts_api.h"
#define TS_FIELD(name) (name), (uint32_t)(sizeof(name) - 1)
int consume_ts_field(void) {
    return ts_select(0, TS_FIELD("value")); // faithful-ts-field-three
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let consumer = project.file("ts_consumer.c");
    let source = consumer.read_to_string().expect("C TS_FIELD consumer");
    let line = "    return ts_select(0, TS_FIELD(\"value\")); // faithful-ts-field-three";
    let expected = token_range(&source, line, "ts_select");
    let target = analyzer
        .get_all_declarations()
        .iter()
        .find(|unit| {
            unit.kind() == CodeUnitType::Function
                && unit.identifier() == "ts_select"
                && unit
                    .signature()
                    .is_some_and(|signature| signature_arity(signature) == 3)
                && unit.source().rel_path().to_string_lossy() == "ts_api.h"
        })
        .cloned()
        .expect("three-parameter C declaration");

    let line_number = source[..expected.0]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1;
    let line_start = source[..expected.0]
        .rfind('\n')
        .map_or(0, |newline| newline + 1);
    let column = source[line_start..expected.0].chars().count() + 1;
    let forward = brokk_bifrost::searchtools::get_definitions_by_location(
        &analyzer,
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: vec![brokk_bifrost::searchtools::DefinitionReferenceQuery {
                path: "ts_consumer.c".to_string(),
                line: Some(line_number),
                column: Some(column),
            }],
        },
    )
    .results
    .into_iter()
    .next()
    .expect("one C forward result");
    assert_eq!(forward.status, "resolved", "{forward:#?}");
    assert!(
        !forward.definitions.is_empty()
            && forward.definitions.iter().all(|definition| {
                definition
                    .signature
                    .as_deref()
                    .is_some_and(|signature| signature_arity(signature) == 3)
            }),
        "TS_FIELD must select the three-parameter C target: {forward:#?}"
    );

    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let targeted = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            100,
        );
    assert_eq!(
        consumer_ranges(&targeted.result, &consumer),
        BTreeSet::from([expected]),
        "targeted C inverse lookup"
    );
    let whole = UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target));
    assert_eq!(
        consumer_ranges(&whole, &consumer),
        BTreeSet::from([expected]),
        "whole C inverse lookup"
    );
}
