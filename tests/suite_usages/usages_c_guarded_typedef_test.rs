//! Issue #1814: C typedef references must stay visible when the header
//! declaration sits under a preprocessor conditional that a `.c` translation
//! unit never activates.
//!
//! The `extern "C"` idiom puts every declaration of a portable C header under
//! `#ifdef __cplusplus`. A `.c` reference can never satisfy that guard, so a
//! declaration-guards-subset-of-reference-guards test rejects every such
//! header. The correct cross-file rule is guard *compatibility*: an external
//! header selects its branch before the reference file is parsed.

use crate::common::InlineTestProject;
use brokk_bifrost::usages::{ExplicitCandidateProvider, FuzzyResult, UsageFinder};
use brokk_bifrost::{CodeUnit, CodeUnitIndex, CodeUnitType, CppAnalyzer, Language, ProjectFile};
use std::collections::BTreeSet;
use std::sync::Arc;

type SourceRange = (usize, usize);
type UsageRanges = (BTreeSet<SourceRange>, BTreeSet<SourceRange>);

fn usage_ranges(analyzer: &CppAnalyzer, target: &CodeUnit, caller: &ProjectFile) -> UsageRanges {
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
        panic!("expected authoritative C success");
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

fn struct_target(analyzer: &CppAnalyzer, fq_name: &str, source_suffix: &str) -> CodeUnit {
    analyzer
        .get_all_declarations()
        .into_iter()
        .find(|unit| {
            unit.kind() == CodeUnitType::Class
                && unit.fq_name() == fq_name
                && !unit.is_synthetic()
                && unit.source().to_string().ends_with(source_suffix)
        })
        .unwrap_or_else(|| panic!("expected a {fq_name} declaration in {source_suffix}"))
}

/// Build the exact expected range set from `(line, token)` pairs so each test
/// pins the reference sites it means, not every spelling in the file.
fn expected_ranges(source: &str, sites: &[(&str, &str)]) -> BTreeSet<SourceRange> {
    sites
        .iter()
        .map(|(line, token)| {
            let line_start = source
                .find(line)
                .unwrap_or_else(|| panic!("fixture line not found: {line}"));
            let token_start = line
                .find(token)
                .unwrap_or_else(|| panic!("fixture token {token} not in {line}"));
            let start = line_start + token_start;
            (start, start + token.len())
        })
        .collect()
}

/// The two alias reference sites shared by most fixtures in this module.
const ALIAS_SITES: [(&str, &str); 2] = [
    ("int use_alias(alias_t *p) {", "alias_t"),
    ("    alias_t local;", "alias_t"),
];

/// The extern-C idiom: the alias declaration is wrapped in
/// `#ifdef __cplusplus / extern "C" { / #endif`, which no `.c` reference can
/// satisfy. Every alias spelling must still count as a usage of the struct.
#[test]
fn c_extern_c_guarded_alias_references_reach_the_struct() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "thing.h",
            r#"#ifndef THING_H
#define THING_H
#ifdef __cplusplus
extern "C" {
#endif
struct impl_s { int x; };
typedef struct impl_s alias_t;
#ifdef __cplusplus
}
#endif
#endif
"#,
        )
        .file(
            "use.c",
            r#"#include "thing.h"

int use_alias(alias_t *p) {
    alias_t local;
    local.x = 1;
    return p->x + local.x;
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let caller = project.file("use.c");
    let source = caller.read_to_string().expect("use.c source");
    let target = struct_target(&analyzer, "impl_s", "thing.h");

    let (proven, unproven) = usage_ranges(&analyzer, &target, &caller);
    assert_eq!(
        expected_ranges(&source, &ALIAS_SITES),
        proven,
        "the extern-C guarded alias must resolve to the struct: proven={proven:?} unproven={unproven:?}"
    );
}

/// The defect is general, not specific to `__cplusplus`: a plain
/// `#ifdef HAVE_X` header block fails the same way.
#[test]
fn c_feature_guarded_alias_references_reach_the_struct() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "thing.h",
            r#"#ifndef THING_H
#define THING_H
#ifdef HAVE_X
struct impl_s { int x; };
typedef struct impl_s alias_t;
#endif
#endif
"#,
        )
        .file(
            "use.c",
            r#"#include "thing.h"

int use_alias(alias_t *p) {
    alias_t local;
    local.x = 1;
    return p->x + local.x;
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let caller = project.file("use.c");
    let source = caller.read_to_string().expect("use.c source");
    let target = struct_target(&analyzer, "impl_s", "thing.h");

    let (proven, unproven) = usage_ranges(&analyzer, &target, &caller);
    assert_eq!(
        expected_ranges(&source, &ALIAS_SITES),
        proven,
        "a feature-guarded header declaration must stay reachable: proven={proven:?} unproven={unproven:?}"
    );
}

/// Control: an unguarded cross-file typedef already worked and must not regress.
#[test]
fn c_unguarded_cross_file_alias_references_stay_proven() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "thing.h",
            r#"#ifndef THING_H
#define THING_H
struct impl_s { int x; };
typedef struct impl_s alias_t;
#endif
"#,
        )
        .file(
            "use.c",
            r#"#include "thing.h"

int use_alias(alias_t *p) {
    alias_t local;
    local.x = 1;
    return p->x + local.x;
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let caller = project.file("use.c");
    let source = caller.read_to_string().expect("use.c source");
    let target = struct_target(&analyzer, "impl_s", "thing.h");

    let (proven, _) = usage_ranges(&analyzer, &target, &caller);
    assert_eq!(
        expected_ranges(&source, &ALIAS_SITES),
        proven,
        "the unguarded control must stay proven: {proven:?}"
    );
}

/// Control: a same-file plain typedef is unaffected by the cross-file rule.
#[test]
fn c_same_file_alias_references_stay_proven() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "all.c",
            r#"struct impl_s { int x; };
typedef struct impl_s alias_t;

int use_alias(alias_t *p) {
    alias_t local;
    local.x = 1;
    return p->x + local.x;
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let caller = project.file("all.c");
    let source = caller.read_to_string().expect("all.c source");
    let target = struct_target(&analyzer, "impl_s", "all.c");

    let (proven, _) = usage_ranges(&analyzer, &target, &caller);
    assert_eq!(
        expected_ranges(&source, &ALIAS_SITES),
        proven,
        "the same-file control must stay proven: {proven:?}"
    );
}

/// Control: a same-file declaration and reference under the SAME guard stay
/// proven. The cross-file relaxation must not disturb the same-file rule.
#[test]
fn c_same_file_same_guard_alias_references_stay_proven() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "all.c",
            r#"#ifdef HAVE_X
struct impl_s { int x; };
typedef struct impl_s alias_t;

int use_alias(alias_t *p) {
    alias_t local;
    local.x = 1;
    return p->x + local.x;
}
#endif
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let caller = project.file("all.c");
    let source = caller.read_to_string().expect("all.c source");
    let target = struct_target(&analyzer, "impl_s", "all.c");

    let (proven, _) = usage_ranges(&analyzer, &target, &caller);
    assert_eq!(
        expected_ranges(&source, &ALIAS_SITES),
        proven,
        "the same-file same-guard control must stay proven: {proven:?}"
    );
}

/// Control: a raw `struct impl_s` tag reference through a guarded header is
/// unchanged by the alias work.
#[test]
fn c_raw_struct_tag_references_through_a_guarded_header_stay_proven() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "thing.h",
            r#"#ifndef THING_H
#define THING_H
#ifdef __cplusplus
extern "C" {
#endif
struct impl_s { int x; };
typedef struct impl_s alias_t;
#ifdef __cplusplus
}
#endif
#endif
"#,
        )
        .file(
            "use.c",
            r#"#include "thing.h"

int use_tag(struct impl_s *p) {
    struct impl_s local;
    local.x = 1;
    return p->x + local.x;
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let caller = project.file("use.c");
    let source = caller.read_to_string().expect("use.c source");
    let target = struct_target(&analyzer, "impl_s", "thing.h");

    let (proven, unproven) = usage_ranges(&analyzer, &target, &caller);
    assert_eq!(
        expected_ranges(
            &source,
            &[
                ("int use_tag(struct impl_s *p) {", "impl_s"),
                ("    struct impl_s local;", "impl_s"),
            ],
        ),
        proven,
        "the raw struct-tag control must stay proven: proven={proven:?} unproven={unproven:?}"
    );
}

/// Near miss: the header declares under `#ifdef HAVE_X` and the reference sits
/// under `#ifndef HAVE_X`. `merge_preprocessor_guards` rejects a guard set that
/// contains a guard and its negation, so this must NOT be a proven usage.
#[test]
fn c_contradicting_guard_regimes_do_not_prove_the_alias_reference() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "thing.h",
            r#"#ifndef THING_H
#define THING_H
#ifdef HAVE_X
struct impl_s { int x; };
typedef struct impl_s alias_t;
#endif
#endif
"#,
        )
        .file(
            "use.c",
            r#"#include "thing.h"

#ifndef HAVE_X
int use_alias(alias_t *p) {
    alias_t local;
    local.x = 1;
    return p->x + local.x;
}
#endif
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let caller = project.file("use.c");
    let target = struct_target(&analyzer, "impl_s", "thing.h");

    let source = caller.read_to_string().expect("use.c source");
    let (proven, unproven) = usage_ranges(&analyzer, &target, &caller);
    assert!(
        proven.is_empty(),
        "contradicting guard regimes must not prove the reference: {proven:?}"
    );
    assert_eq!(
        expected_ranges(&source, &ALIAS_SITES),
        unproven,
        "a proven alias-to-target chain that fails visibility must degrade to \
         unproven, not vanish: {unproven:?}"
    );
}

/// The C++ direction had the same defect, not only the C one: an unguarded
/// `.cc` reference could not satisfy the header's `__cplusplus` guard either,
/// so the site vanished there too. The compatibility rule proves both.
#[test]
fn cpp_reference_still_sees_the_extern_c_guarded_alias() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "thing.h",
            r#"#ifndef THING_H
#define THING_H
#ifdef __cplusplus
extern "C" {
#endif
struct impl_s { int x; };
typedef struct impl_s alias_t;
#ifdef __cplusplus
}
#endif
#endif
"#,
        )
        .file(
            "use.cc",
            r#"#include "thing.h"

int use_alias(alias_t *p) {
    alias_t local;
    local.x = 1;
    return p->x + local.x;
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let caller = project.file("use.cc");
    let source = caller.read_to_string().expect("use.cc source");
    let target = struct_target(&analyzer, "impl_s", "thing.h");

    let (proven, unproven) = usage_ranges(&analyzer, &target, &caller);
    assert_eq!(
        expected_ranges(&source, &ALIAS_SITES),
        proven,
        "the C++ direction must stay proven: proven={proven:?} unproven={unproven:?}"
    );
}
