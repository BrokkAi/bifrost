use crate::common::InlineTestProject;
use brokk_bifrost::usages::{ExplicitCandidateProvider, FuzzyResult, UsageFinder};
use brokk_bifrost::{CodeUnit, CodeUnitType, CppAnalyzer, IAnalyzer, Language, ProjectFile};
use std::collections::BTreeSet;
use std::sync::Arc;

/// Line/column pairs of proven and unproven usage hits.
type UsageRanges = BTreeSet<(usize, usize)>;

fn usage_ranges(
    analyzer: &CppAnalyzer,
    target: &CodeUnit,
    caller: &ProjectFile,
) -> (UsageRanges, UsageRanges) {
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

fn target_by_source(analyzer: &CppAnalyzer, suffix: &str) -> CodeUnit {
    analyzer
        .get_all_declarations()
        .into_iter()
        .find(|unit| {
            unit.kind() == CodeUnitType::Class
                && unit.identifier() == "DecodeImageCallbacks"
                && unit.package_name() == "wuffs_aux"
                && !unit.is_synthetic()
                && unit.source().to_string().ends_with(suffix)
        })
        .expect("expected Wuffs callback target")
}

#[test]
fn wuffs_guarded_qualified_call_recovers_only_the_owner_prefix() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "visible.h",
            r#"#pragma once
#define WUFFS_BASE__HAVE_UNIQUE_PTR
#if defined(__cplusplus) && defined(WUFFS_BASE__HAVE_UNIQUE_PTR)
namespace wuffs_aux {
struct DecodeImageCallbacks {
  static int HandleMetadata(int x, int y) { return x + y; }
};
struct Other {
  static int HandleMetadata(int x, int y) { return x - y; }
};
}
#endif
"#,
        )
        .file(
            "hidden.h",
            r#"#pragma once
#define WUFFS_BASE__HAVE_UNIQUE_PTR
#if defined(__cplusplus) && defined(WUFFS_BASE__HAVE_UNIQUE_PTR)
namespace wuffs_aux {
struct DecodeImageCallbacks {
  static int HandleMetadata(int x, int y) { return x + y; }
};
}
#endif
"#,
        )
        .file(
            "consumer.cc",
            r#"#include "visible.h"
struct Derived : wuffs_aux::DecodeImageCallbacks {
  int run(int x, int y) {
    return wuffs_aux::DecodeImageCallbacks::HandleMetadata(x, y);
  }
  int wrong(int x, int y) {
    return wuffs_aux::Other::HandleMetadata(x, y);
  }
};
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let caller = project.file("consumer.cc");
    let source = caller.read_to_string().expect("consumer source");
    let target = target_by_source(&analyzer, "visible.h");

    let (proven, unproven) = usage_ranges(&analyzer, &target, &caller);
    let inheritance_owner = token_range(
        &source,
        "struct Derived : wuffs_aux::DecodeImageCallbacks {",
        "wuffs_aux::DecodeImageCallbacks",
    );
    let call_owner = token_range(
        &source,
        "    return wuffs_aux::DecodeImageCallbacks::HandleMetadata(x, y);",
        "DecodeImageCallbacks",
    );
    let call_method = token_range(
        &source,
        "    return wuffs_aux::DecodeImageCallbacks::HandleMetadata(x, y);",
        "HandleMetadata",
    );
    let wrong_owner = token_range(
        &source,
        "    return wuffs_aux::Other::HandleMetadata(x, y);",
        "wuffs_aux::Other",
    );
    assert!(
        unproven.contains(&call_owner),
        "the guarded qualified call must retain its owner class component: {unproven:?}"
    );
    assert!(
        unproven.contains(&inheritance_owner) || proven.contains(&inheritance_owner),
        "the visible base owner must remain indexed: proven={proven:?}, unproven={unproven:?}"
    );
    assert!(
        !proven.contains(&call_owner),
        "the guarded owner cannot be proven: {proven:?}"
    );
    assert!(
        !proven.contains(&call_method) && !unproven.contains(&call_method),
        "the terminal method must not be part of the owner hit: proven={proven:?}, unproven={unproven:?}"
    );
    assert!(!proven.contains(&wrong_owner) && !unproven.contains(&wrong_owner));

    let hidden_target = target_by_source(&analyzer, "hidden.h");
    let (hidden_proven, hidden_unproven) = usage_ranges(&analyzer, &hidden_target, &caller);
    assert!(
        hidden_proven.is_empty() && hidden_unproven.is_empty(),
        "the hidden callback target must not inherit the visible owner hit: proven={hidden_proven:?}, unproven={hidden_unproven:?}"
    );
}
