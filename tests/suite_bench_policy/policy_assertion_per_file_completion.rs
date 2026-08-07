//! Per-file completion accounting for assertion policies (#1642).
//!
//! Assertion evaluation runs its row-family queries once per subject file. A
//! file whose row queries exhaust the pipeline row budget, or whose asserts
//! cannot conclude, contributes zero findings and is named as unconcluded;
//! every other file's findings still stand. Before this accounting a single
//! oversized file turned the whole workspace run inconclusive with zero
//! findings, which is what blocked the loop-invariance rule from shipping.
//!
//! The rule under test is the checked-in candidate
//! `tests/fixtures/policies/loop-invariant-receiver.rqlp`, whose
//! `assert-reaching` exercises the occurrence, reaching-binding and
//! lexical-scope families at once.

use std::sync::Arc;

use crate::common::InlineTestProject;
use brokk_bifrost::CodeQueryExecutionLimits;
use brokk_bifrost::policy::{
    CatalogRegistryLimits, DefaultPolicyEvaluator, PolicyBudget, PolicyEvaluationContext,
    PolicyEvaluator, PolicyIncompleteReason, PolicyRegistry, PolicyRegistryLimits, PolicyRun,
    PolicyRunCompletion, PolicySourceIdentity, TaintCatalogRegistry,
};
use brokk_bifrost::{Language, RustAnalyzer};

/// The checked-in candidate rule, read rather than inlined so the file that
/// ships is the file that is tested.
const RULE: &str = include_str!("../fixtures/policies/loop-invariant-receiver.rqlp");

/// A receiver declared outside the loop and re-sorted on every pass: the one
/// shape this rule reports.
const TRUE_POSITIVE: &str = "\
pub fn order(mut ready: Vec<usize>) -> Vec<usize> {
    let mut done = Vec::new();
    while !ready.is_empty() {
        ready.sort_unstable();
        done.push(ready.remove(0));
    }
    done
}
";

/// One subject that is clean for the right reason -- the receiver is declared
/// in the loop body -- followed by `filler` functions that carry no subject at
/// all but do carry scopes. The filler is what makes this file's own row
/// families expensive without adding to the workspace-wide subject query.
fn file_with_many_scopes(filler: usize) -> String {
    let mut source = String::from(
        "\
pub fn order_local(groups: Vec<Vec<usize>>) -> usize {
    let mut total = 0;
    for group in groups {
        let mut ready = group;
        ready.sort_unstable();
        total += ready.len();
    }
    total
}
",
    );
    for index in 0..filler {
        source.push_str(&format!(
            "\
pub fn filler_{index}(value: usize) -> usize {{
    let first_{index} = {{ value + 1 }};
    let second_{index} = {{ first_{index} + 1 }};
    {{ second_{index} + 1 }}
}}
"
        ));
    }
    source
}

/// Evaluate `rule` over a Rust project of `files` under `budget`.
fn run_files(rule: &str, files: &[(&str, &str)], budget: &mut PolicyBudget) -> PolicyRun {
    let mut project = InlineTestProject::with_language(Language::Rust);
    for (path, source) in files {
        project = project.file(*path, *source);
    }
    let project = project.build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());

    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    registry
        .register_policy_bytes(
            PolicySourceIdentity::new("test:assertion-per-file-completion"),
            rule.as_bytes(),
        )
        .expect("the candidate rule must load");
    let policy = registry.policies().next().expect("one policy");
    DefaultPolicyEvaluator::new()
        .evaluate(
            policy,
            &PolicyEvaluationContext {
                analyzer: &analyzer,
                workspace: None,
                cancellation: None,
                cvss_overlays: &[],
                organizational_risk: &[],
            },
            budget,
        )
        .expect("assertion evaluation")
}

fn budget_with_pipeline_rows(rows: usize) -> PolicyBudget {
    PolicyBudget::builder()
        .with_query_limits(CodeQueryExecutionLimits {
            max_pipeline_rows: rows,
            ..PolicyBudget::default().query_limits()
        })
        .expect("a lowered row budget is within the hard caps")
        .build()
        .expect("budget")
}

fn incomplete_reasons(run: &PolicyRun) -> &[PolicyIncompleteReason] {
    match run.completion() {
        PolicyRunCompletion::Inconclusive { reasons } => reasons,
        other => panic!(
            "expected an inconclusive run, got {other:?}: {:?}",
            run.diagnostics()
        ),
    }
}

fn assert_file_a_concludes_and_file_z_is_blamed(run: &PolicyRun) {
    assert!(
        run.diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.message().contains("src/z.rs")),
        "the oversized file must be named: {:?}",
        run.diagnostics()
    );
    assert!(
        run.diagnostics()
            .iter()
            .all(|diagnostic| !diagnostic.message().contains("src/a.rs")),
        "the file that concluded must not be blamed: {:?}",
        run.diagnostics()
    );
    assert_eq!(
        run.findings().len(),
        1,
        "the concluded file keeps its finding: {:?}",
        run.findings()
    );
    assert_eq!(
        run.findings()[0].primary().path(),
        "src/a.rs",
        "the surviving finding belongs to the file that concluded"
    );
}

/// The row budget below is calibrated empirically, not derived. It must sit
/// above the workspace-wide subject query -- which spans both files, so if it
/// exhausts first the run is inconclusive with zero findings, the pre-#1642
/// shape -- and below the per-file row families of `src/z.rs`, whose lexical
/// scope seed returns every scope in that file. Measured window with the
/// filler count below: the intended per-file degradation holds from 40 rows to
/// roughly 400, and the whole run concludes `Complete` by 600. 200 sits in the
/// middle with headroom on both sides.
const CALIBRATED_PIPELINE_ROWS: usize = 200;

const OVERSIZED_FILLER_COUNT: usize = 80;

#[test]
fn a_file_over_budget_degrades_only_itself() {
    let oversized = file_with_many_scopes(OVERSIZED_FILLER_COUNT);
    let run = run_files(
        RULE,
        &[("src/a.rs", TRUE_POSITIVE), ("src/z.rs", &oversized)],
        &mut budget_with_pipeline_rows(CALIBRATED_PIPELINE_ROWS),
    );

    assert!(
        incomplete_reasons(&run).contains(&PolicyIncompleteReason::PipelineRowBudget),
        "the row budget is what the oversized file exhausted: {:?}",
        run.completion()
    );
    assert_file_a_concludes_and_file_z_is_blamed(&run);
}

#[test]
fn all_files_fitting_conclude_complete() {
    let run = run_files(
        RULE,
        &[("src/a.rs", TRUE_POSITIVE), ("src/z.rs", TRUE_POSITIVE)],
        &mut PolicyBudget::default(),
    );

    assert_eq!(
        run.completion(),
        &PolicyRunCompletion::Complete,
        "{:?}",
        run.diagnostics()
    );
    assert_eq!(
        run.findings().len(),
        2,
        "per-file batching still evaluates every file: {:?}",
        run.findings()
    );
    let mut paths: Vec<&str> = run
        .findings()
        .iter()
        .map(|finding| finding.primary().path())
        .collect();
    paths.sort_unstable();
    assert_eq!(paths, vec!["src/a.rs", "src/z.rs"]);
}

/// The shipped rule constrains the receiver to an identifier precisely so that
/// expression receivers cannot turn a run inconclusive; that constraint is
/// what #1598 had to add as a workaround. Dropping the kind and keeping the
/// bare capture makes the gap reachable again: an array-expression receiver
/// carries no receiver-position occurrence, so the assert cannot conclude over
/// that file. The shipped fixture stays untouched -- the widening happens in
/// this test's copy.
const WIDENED_RULE_RECEIVER: &str = ":receiver (identifier :capture \"target\")";
const WIDENED_RULE_REPLACEMENT: &str = ":receiver (capture \"target\")";

const EXPRESSION_RECEIVER: &str = "\
pub fn order(times: usize) -> usize {
    let mut total = 0;
    for _ in 0..times {
        [3, 1, 2].sort();
        total += 1;
    }
    total
}
";

#[test]
fn per_file_capability_gaps_do_not_block_other_files() {
    let widened = RULE.replace(WIDENED_RULE_RECEIVER, WIDENED_RULE_REPLACEMENT);
    assert_ne!(
        widened, RULE,
        "the fixture's receiver spelling moved; update WIDENED_RULE_RECEIVER"
    );
    let run = run_files(
        &widened,
        &[
            ("src/a.rs", TRUE_POSITIVE),
            ("src/z.rs", EXPRESSION_RECEIVER),
        ],
        &mut PolicyBudget::default(),
    );

    assert!(
        incomplete_reasons(&run).contains(&PolicyIncompleteReason::CapabilityIncomplete),
        "the expression receiver has no occurrence identity: {:?}",
        run.completion()
    );
    assert_file_a_concludes_and_file_z_is_blamed(&run);
}

#[test]
fn no_subjects_stay_vacuously_complete() {
    let run = run_files(
        RULE,
        &[(
            "src/a.rs",
            "pub fn order(values: Vec<usize>) -> usize {\n    values.len()\n}\n",
        )],
        &mut PolicyBudget::default(),
    );

    assert_eq!(
        run.completion(),
        &PolicyRunCompletion::Complete,
        "{:?}",
        run.diagnostics()
    );
    assert!(
        run.findings().is_empty(),
        "no subjects, no findings: {:?}",
        run.findings()
    );
}
