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

fn canonical_target(analyzer: &CppAnalyzer, suffix: &str) -> CodeUnit {
    analyzer
        .get_all_declarations()
        .into_iter()
        .find(|unit| {
            unit.kind() == CodeUnitType::Class
                && unit.identifier() == "wuffs_base__io_buffer__struct"
                && !unit.is_synthetic()
                && unit.source().to_string().ends_with(suffix)
        })
        .expect("expected canonical Wuffs target")
}

#[test]
fn wuffs_guarded_alias_uses_canonical_target_without_global_visibility_relaxation() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "visible.h",
            r#"#pragma once
struct wuffs_base__io_buffer__struct {};
using wuffs_base__io_buffer = wuffs_base__io_buffer__struct;
#define WUFFS_BASE__HAVE_UNIQUE_PTR
#if defined(__cplusplus) && defined(WUFFS_BASE__HAVE_UNIQUE_PTR)
namespace wuffs_aux {
using IOBuffer = wuffs_base__io_buffer;
}
#endif
namespace wuffs_aux_unconditional {
using IOBuffer = wuffs_base__io_buffer;
}
namespace wuffs_aux_wrong {
using IOBuffer = int;
}
"#,
        )
        .file(
            "hidden.h",
            r#"#pragma once
struct wuffs_base__io_buffer__struct {};
"#,
        )
        .file(
            "consumer.cc",
            r#"#include "visible.h"
void guarded(wuffs_aux::IOBuffer& buffer) { (void)buffer; }
void unguarded(wuffs_aux_unconditional::IOBuffer& buffer) { (void)buffer; }
void wrong_alias(wuffs_aux_wrong::IOBuffer& buffer) { (void)buffer; }
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let caller = project.file("consumer.cc");
    let source = caller.read_to_string().expect("consumer source");
    let target = canonical_target(&analyzer, "visible.h");

    let (proven, unproven) = usage_ranges(&analyzer, &target, &caller);
    let guarded = token_range(
        &source,
        "void guarded(wuffs_aux::IOBuffer& buffer) { (void)buffer; }",
        "IOBuffer",
    );
    let unguarded = token_range(
        &source,
        "void unguarded(wuffs_aux_unconditional::IOBuffer& buffer) { (void)buffer; }",
        "wuffs_aux_unconditional::IOBuffer",
    );
    let wrong = token_range(
        &source,
        "void wrong_alias(wuffs_aux_wrong::IOBuffer& buffer) { (void)buffer; }",
        "IOBuffer",
    );
    assert!(
        unproven.contains(&guarded),
        "the guarded namespace alias must remain reviewable: {unproven:?}"
    );
    assert!(
        proven.contains(&unguarded),
        "the unguarded alias must stay proven: {proven:?}"
    );
    assert!(
        !proven.contains(&guarded),
        "guarded alias cannot be proven: {proven:?}"
    );
    assert!(!proven.contains(&wrong) && !unproven.contains(&wrong));

    let hidden_target = canonical_target(&analyzer, "hidden.h");
    let (hidden_proven, hidden_unproven) = usage_ranges(&analyzer, &hidden_target, &caller);
    assert!(
        hidden_proven.is_empty() && hidden_unproven.is_empty(),
        "the hidden canonical target must not inherit the visible alias: proven={hidden_proven:?}, unproven={hidden_unproven:?}"
    );
}
