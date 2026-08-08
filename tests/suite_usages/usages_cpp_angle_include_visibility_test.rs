//! Issue #1829: the C++ inverse honored only `#include "..."` when it decided
//! which files can see a header's declarations. A `.cpp` that reaches its own
//! project headers with `#include <...>` (the log4cxx layout: headers under
//! `src/main/include/`, sources under `src/main/cpp/`) was never even offered as
//! a usage candidate, so every reference in it was unattributed - while the
//! forward resolver, which uses the angle-aware `include_paths`, resolved the
//! same references.
//!
//! The two consumers below differ only in `<>` versus `""`.

use crate::common::InlineTestProject;
use brokk_bifrost::usages::{FuzzyResult, UsageFinder};
use brokk_bifrost::{CodeUnit, CodeUnitIndex, CodeUnitType, CppAnalyzer, Language};
use std::collections::BTreeSet;

const LEVEL_H: &str = r#"#ifndef L4_LEVEL_H
#define L4_LEVEL_H
namespace l4 {
class Pool { public: int v; };
}
#endif
"#;

const ANGLE_CPP: &str = r#"#include <log4cxx/level.h>
namespace l4 {
void useAngle(Pool& p) { (void)p; }
}
"#;

const QUOTED_CPP: &str = r#"#include "log4cxx/level.h"
namespace l4 {
void useQuoted(Pool& p) { (void)p; }
}
"#;

/// Every file that carries a proven or reviewable hit for `target`, using the
/// default (import-graph) candidate provider - the provider under test.
fn hit_files(analyzer: &CppAnalyzer, target: &CodeUnit) -> BTreeSet<String> {
    let query = UsageFinder::new().with_authoritative_scope(true).query(
        analyzer,
        std::slice::from_ref(target),
        100,
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
    hits_by_overload
        .values()
        .chain(unproven_by_overload.values())
        .flatten()
        .map(|hit| hit.file.to_string().replace('\\', "/"))
        .collect()
}

fn class_target(analyzer: &CppAnalyzer, fq_name: &str, source_suffix: &str) -> CodeUnit {
    analyzer
        .get_all_declarations()
        .into_iter()
        .find(|unit| {
            unit.kind() == CodeUnitType::Class
                && unit.fq_name() == fq_name
                && !unit.is_synthetic()
                && unit
                    .source()
                    .to_string()
                    .replace('\\', "/")
                    .ends_with(source_suffix)
        })
        .unwrap_or_else(|| panic!("expected an indexed {fq_name} in {source_suffix}"))
}

#[test]
fn angle_included_project_header_is_visible_to_the_inverse() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("src/main/include/log4cxx/level.h", LEVEL_H)
        .file("src/main/cpp/consumer_angle.cpp", ANGLE_CPP)
        .file("src/main/cpp/consumer_quoted.cpp", QUOTED_CPP)
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let target = class_target(&analyzer, "l4.Pool", "log4cxx/level.h");

    let files = hit_files(&analyzer, &target);
    assert!(
        files
            .iter()
            .any(|file| file.ends_with("src/main/cpp/consumer_quoted.cpp")),
        "the quoted-include control regressed: {files:?}"
    );
    assert!(
        files
            .iter()
            .any(|file| file.ends_with("src/main/cpp/consumer_angle.cpp")),
        "an angle include of a project header must make its declarations visible \
         to the inverse: {files:?}"
    );
}

/// Negative control: an angle include that resolves to nothing in the workspace
/// must not invent visibility. `<absent/nowhere.h>` names no analyzed file, so
/// the reference in that file stays unattributed.
#[test]
fn unresolvable_angle_include_does_not_invent_visibility() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("src/main/include/log4cxx/level.h", LEVEL_H)
        .file(
            "src/main/cpp/orphan.cpp",
            r#"#include <absent/nowhere.h>
namespace l4 {
void useOrphan(Pool& p) { (void)p; }
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let target = class_target(&analyzer, "l4.Pool", "log4cxx/level.h");

    let query = UsageFinder::new().with_authoritative_scope(true).query(
        &analyzer,
        std::slice::from_ref(&target),
        100,
        1000,
    );
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = query.result
    else {
        panic!("expected authoritative C++ success");
    };
    let proven: BTreeSet<String> = hits_by_overload
        .values()
        .flatten()
        .map(|hit| hit.file.to_string().replace('\\', "/"))
        .collect();
    assert!(
        !proven
            .iter()
            .any(|file| file.ends_with("src/main/cpp/orphan.cpp")),
        "an include that names no workspace file must not prove a reference: {proven:?}"
    );
}

/// Negative control: an angle include whose basename matches two project
/// headers is ambiguous, so it must not silently pick one of them.
#[test]
fn ambiguous_angle_include_does_not_prove_a_reference() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "first/dup.h",
            r#"#ifndef FIRST_DUP_H
#define FIRST_DUP_H
namespace demo {
class Alpha { public: int v; };
}
#endif
"#,
        )
        .file(
            "second/dup.h",
            r#"#ifndef SECOND_DUP_H
#define SECOND_DUP_H
namespace demo {
class Beta { public: int v; };
}
#endif
"#,
        )
        .file(
            "src/consumer.cpp",
            r#"#include <dup.h>
namespace demo {
void useAlpha(Alpha& a) { (void)a; }
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let target = class_target(&analyzer, "demo.Alpha", "first/dup.h");

    let query = UsageFinder::new().with_authoritative_scope(true).query(
        &analyzer,
        std::slice::from_ref(&target),
        100,
        1000,
    );
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = query.result
    else {
        panic!("expected authoritative C++ success");
    };
    let proven: BTreeSet<String> = hits_by_overload
        .values()
        .flatten()
        .map(|hit| hit.file.to_string().replace('\\', "/"))
        .collect();
    assert!(
        !proven.iter().any(|file| file.ends_with("src/consumer.cpp")),
        "an ambiguous basename include must not resolve to one of the candidates: {proven:?}"
    );
}
