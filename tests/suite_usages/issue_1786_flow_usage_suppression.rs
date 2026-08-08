//! #1786: the JS usage graph must contribute nothing from a Flow-annotated file
//! the JavaScript grammar could not parse.
//!
//! Error recovery over Flow syntax does not leave the call sites alone: a
//! return-type annotation turns the enclosing method into expression soup and
//! the call token inside it is demoted, so what the extractor grades is not the
//! program the author wrote. The control case is the same file without the
//! pragma, which still reports its hit exactly as it does today.

use crate::common::InlineTestProject;
use brokk_bifrost::hash::HashSet;
use brokk_bifrost::usages::{FuzzyResult, JsTsExportUsageGraphStrategy, UsageAnalyzer, UsageHit};
use brokk_bifrost::{CodeUnit, CodeUnitIndex, JavascriptAnalyzer, Language, ProjectFile};
use std::collections::BTreeSet;

const TARGET: &str = "export function target() {\n  return 1;\n}\n";

/// A caller whose Flow return-type annotation and nullable property destroy the
/// enclosing class, leaving `target()` inside an `ERROR` node.
const CALLER_BODY: &str = "import {target} from './a.js';\n\
\n\
class Caller {\n\
  ref: ?Caller;\n\
\n\
  run(): void {\n\
    target();\n\
  }\n\
}\n";

fn hits_in_caller(caller_source: &str) -> (BTreeSet<UsageHit>, ProjectFile) {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file("a.js", TARGET)
        .file("b.js", caller_source)
        .build();
    let analyzer = JavascriptAnalyzer::from_project(project.project().clone());
    let target_file = project.file("a.js");
    let caller_file = project.file("b.js");
    let target: CodeUnit = analyzer
        .all_declarations()
        .find(|unit| unit.is_function() && unit.source() == &target_file)
        .expect("the exported target function");

    let candidates: HashSet<ProjectFile> = std::iter::once(caller_file.clone()).collect();
    let result =
        JsTsExportUsageGraphStrategy::new().find_usages(&analyzer, &[target], &candidates, 1000);
    let FuzzyResult::Success {
        hits_by_overload,
        unproven_by_overload,
        ..
    } = result
    else {
        panic!("expected the JS graph strategy to succeed");
    };
    let hits: BTreeSet<UsageHit> = hits_by_overload
        .into_values()
        .chain(unproven_by_overload.into_values())
        .flat_map(BTreeSet::into_iter)
        .collect();
    (hits, caller_file)
}

#[test]
fn a_flow_pragma_caller_with_parse_errors_contributes_no_usage_hits() {
    let (hits, caller_file) = hits_in_caller(&format!("/* @flow */\n{CALLER_BODY}"));
    assert!(
        !hits.iter().any(|hit| hit.file == caller_file),
        "a Flow file the grammar could not read names no call site: {hits:#?}"
    );
}

#[test]
fn the_same_caller_without_a_pragma_still_reports_its_call_site() {
    // The control: nothing about the suppression widens to plain broken
    // JavaScript, and it is this hit the Flow case gives up.
    let (hits, caller_file) = hits_in_caller(CALLER_BODY);
    assert!(
        hits.iter().any(|hit| hit.file == caller_file),
        "an unflagged file keeps the call site it reports today: {hits:#?}"
    );
}
