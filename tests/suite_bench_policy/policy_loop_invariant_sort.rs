//! The loop-invariance rule prototype (#1474, Milestone 6).
//!
//! Motivation, from the issue's own corpus: running the built-in
//! `bifrost.code-smells` pack against this repository produced 284 findings
//! with a 100% false-positive rate, and roughly 250 of them reduce to one
//! missing predicate -- is the value operated on inside this loop declared
//! inside or outside the loop body? The in-loop rules ask only "is this call
//! written inside a loop", which every one of those findings answered yes to
//! and none of them should have.
//!
//! `tests/fixtures/policies/loop-invariant-receiver.rqlp` asks the real
//! question, and this module is the evidence that it separates the true
//! positive from every dominant false-positive family in that corpus, for all
//! five claimed languages (#1598 graduated the prototype's proof from Rust to
//! Rust, Python, Java, TypeScript, and JavaScript). The rule is *still* not in
//! the built-in pack, but no longer for proof reasons: workspace-scale
//! assertion evaluation exhausts the pipeline row budget on this repository
//! and took a 68-minute release-build pack run, so promotion waits on that
//! capability. The rule header records the numbers.
//!
//! Each near-miss must be clean for the right reason, so every test asserts the
//! run's completion before its findings.

use std::sync::Arc;

use crate::common::InlineTestProject;
use brokk_bifrost::analyzer::IAnalyzer;
use brokk_bifrost::policy::{
    CatalogRegistryLimits, DefaultPolicyEvaluator, PolicyBudget, PolicyEvaluationContext,
    PolicyEvaluator, PolicyFindingEvidence, PolicyRegistry, PolicyRegistryLimits, PolicyRun,
    PolicyRunCompletion, PolicySourceIdentity, TaintCatalogRegistry,
};
use brokk_bifrost::{
    JavaAnalyzer, JavascriptAnalyzer, Language, PythonAnalyzer, RustAnalyzer, TypescriptAnalyzer,
};

/// The checked-in prototype rule, read rather than inlined so the file that
/// ships is the file that is tested.
const RULE: &str = include_str!("../fixtures/policies/loop-invariant-receiver.rqlp");

fn run_rule(source: &str) -> PolicyRun {
    run_source(RULE, Language::Rust, "src/order.rs", source)
}

/// Evaluate `rule` over a one-file project in `language`.
fn run_source(rule: &str, language: Language, path: &str, source: &str) -> PolicyRun {
    let project = InlineTestProject::with_language(language)
        .file(path, source)
        .build();
    let owned = project.project().clone();
    let analyzer: Box<dyn IAnalyzer> = match language {
        Language::Rust => Box::new(RustAnalyzer::from_project(owned)),
        Language::Python => Box::new(PythonAnalyzer::from_project(owned)),
        Language::Java => Box::new(JavaAnalyzer::from_project(owned)),
        Language::TypeScript => Box::new(TypescriptAnalyzer::from_project(owned)),
        Language::JavaScript => Box::new(JavascriptAnalyzer::from_project(owned)),
        other => panic!("no promoted-rule analyzer for {other:?}"),
    };

    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    registry
        .register_policy_bytes(
            PolicySourceIdentity::new("test:loop-invariant-receiver"),
            rule.as_bytes(),
        )
        .expect("the prototype rule must load");
    let policy = registry.policies().next().expect("one policy");
    DefaultPolicyEvaluator::new()
        .evaluate(
            policy,
            &PolicyEvaluationContext {
                analyzer: analyzer.as_ref(),
                workspace: None,
                cancellation: None,
                cvss_overlays: &[],
                organizational_risk: &[],
            },
            &mut PolicyBudget::default(),
        )
        .expect("prototype evaluation")
}

/// A near-miss is clean *and* complete, or it proves nothing.
fn assert_clean(label: &str, source: &str) {
    assert_clean_in(label, Language::Rust, "src/order.rs", source);
}

fn assert_clean_in(label: &str, language: Language, path: &str, source: &str) {
    let run = run_source(RULE, language, path, source);
    assert_eq!(
        run.completion(),
        &PolicyRunCompletion::Complete,
        "{label}: a near-miss must reach a verdict, not fail to conclude: {:?}",
        run.diagnostics()
    );
    assert!(
        run.findings().is_empty(),
        "{label}: the near-miss must be clean: {:?}",
        run.findings()
    );
}

/// The true-positive shape, modelled on the ready-set re-sort at
/// `crates/bifrost-policy/src/composition/precedence.rs:135`: a collection
/// declared outside the `while` and sorted again on every pass. (Accepted
/// there for deterministic topological order over a small graph, but
/// structurally it is exactly what the rule should mean.)
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

#[test]
fn the_prototype_reports_a_receiver_declared_outside_the_loop() {
    let run = run_rule(TRUE_POSITIVE);
    assert_eq!(
        run.completion(),
        &PolicyRunCompletion::Complete,
        "{:?}",
        run.diagnostics()
    );
    assert_eq!(
        run.findings().len(),
        1,
        "one loop, one invariant receiver: {:?}",
        run.findings()
    );
    let PolicyFindingEvidence::Assertion { evidence } = run.findings()[0].evidence() else {
        panic!("assertion policies produce assertion evidence");
    };
    assert_eq!(evidence.assert_kind(), "reaching");
    assert_eq!(
        evidence.observed(),
        Some("binding `ready` is declared outside capture `region`"),
        "the finding names the binding and where it actually is"
    );
}

/// False-positive family 1, and the largest: 160 of the 160 `sort-in-loop`
/// findings were a collection built inside the loop body and canonicalized
/// once. The receiver is declared in the loop, so each iteration sorts a
/// different value.
const NEAR_MISS_LOOP_LOCAL: &str = "\
pub fn order(groups: Vec<Vec<usize>>) -> usize {
    let mut total = 0;
    for group in groups {
        let mut ready = group;
        ready.sort_unstable();
        total += ready.len();
    }
    total
}
";

#[test]
fn a_loop_local_declaration_is_not_a_finding() {
    assert_clean("loop-local declaration", NEAR_MISS_LOOP_LOCAL);
}

/// False-positive family 2: the value is produced by an iterator adapter into
/// a fresh binding inside the loop. The binding is loop-local exactly as
/// above, and the rule must not be fooled by the extra call chain between the
/// iteration variable and the receiver.
const NEAR_MISS_ITERATOR_ADAPTER: &str = "\
pub fn order(groups: Vec<Vec<usize>>) -> usize {
    let mut total = 0;
    for group in groups {
        let mut ready = group.iter().copied().collect::<Vec<usize>>();
        ready.sort_unstable();
        total += ready.len();
    }
    total
}
";

#[test]
fn an_iterator_adapter_binding_created_in_the_loop_is_not_a_finding() {
    assert_clean(
        "iterator adapter into a loop-local",
        NEAR_MISS_ITERATOR_ADAPTER,
    );
}

/// False-positive family 3: the receiver is a *field projection* of the
/// iteration variable (`group.packages.sort()`), so it is loop-variant through
/// the projection even though the projection's base is a loop-local binding.
///
/// The observed behaviour is recorded rather than assumed: the capture is the
/// field expression, which is not an occurrence of a receiver role, so the
/// assert does not apply to it and the run is clean and complete. That is the
/// right answer for the wrong-ish reason -- the rule abstains because it cannot
/// address a projection, not because it decided the projection was loop-variant
/// -- and the boundary is stated here so a promotion of this rule to the
/// built-in pack cannot quietly assume the analysis is deeper than it is.
const NEAR_MISS_FIELD_PROJECTION: &str = "\
pub struct Group {
    pub packages: Vec<usize>,
}

pub fn order(mut groups: Vec<Group>) -> usize {
    let mut total = 0;
    for group in groups.iter_mut() {
        group.packages.sort_unstable();
        total += group.packages.len();
    }
    total
}
";

#[test]
fn a_field_projection_of_the_loop_variable_is_not_a_finding() {
    assert_clean(
        "field projection of the loop variable",
        NEAR_MISS_FIELD_PROJECTION,
    );
}

/// False-positive family 4: an outer name is rebound inside the loop. Source
/// order alone cannot separate this from the true positive -- both spell the
/// same identifier and both have an outer declaration above the loop -- and
/// reaching-binding semantics can, because the nearer binder wins.
const NEAR_MISS_REBINDING: &str = "\
pub fn order(outer: Vec<usize>, groups: Vec<Vec<usize>>) -> usize {
    let ready = outer;
    let mut total = ready.len();
    for group in groups {
        let mut ready = group;
        ready.sort_unstable();
        total += ready.len();
    }
    total
}
";

#[test]
fn rebinding_an_outer_name_inside_the_loop_is_not_a_finding() {
    assert_clean("rebinding inside the loop", NEAR_MISS_REBINDING);
}

/// The fifth family is the one that is *not* clean, and deliberately so.
///
/// A call written inside a closure inside the loop is reported. Containment can
/// say where the call is written; it cannot say how many times the closure
/// runs. The repository's policy rules require such a case to be either
/// excluded or made an explicit, tested lexical positive with the boundary
/// stated in the message, and this rule takes the second option -- its message
/// says the match is lexical rather than proven per-iteration cost.
///
/// The alternative, silently excluding deferred bodies, would drop the real
/// positives too: a closure called once per iteration is exactly as wasteful as
/// a direct call.
const CLOSURE_BODY_IS_A_LEXICAL_POSITIVE: &str = "\
pub fn order(mut ready: Vec<usize>, times: usize) -> usize {
    let mut total = 0;
    for _ in 0..times {
        let mut sort_now = || ready.sort_unstable();
        sort_now();
        total += 1;
    }
    total
}
";

#[test]
fn a_closure_body_inside_the_loop_is_an_explicit_lexical_positive() {
    let run = run_rule(CLOSURE_BODY_IS_A_LEXICAL_POSITIVE);
    assert_eq!(
        run.completion(),
        &PolicyRunCompletion::Complete,
        "{:?}",
        run.diagnostics()
    );
    assert_eq!(
        run.findings().len(),
        1,
        "the deferred body is reported, and the rule's message says why: {:?}",
        run.findings()
    );
}

/// The polarity test for the abstention above, and the reason the field
/// projection is recorded as a boundary rather than as a separated near-miss.
///
/// Inverting the requirement to `:declared outside` -- which reports the
/// opposite half of every other fixture in this file -- still reports nothing
/// here. A rule that had *decided* the projection was loop-variant would fire
/// under one polarity or the other; a rule that cannot address the projection
/// at all fires under neither, which is what happens.
#[test]
fn the_field_projection_abstains_under_both_polarities() {
    let inverted = RULE.replace(":declared inside", ":declared outside");
    for (label, rule) in [("declared inside", RULE), ("declared outside", &inverted)] {
        let run = run_source(
            rule,
            Language::Rust,
            "src/order.rs",
            NEAR_MISS_FIELD_PROJECTION,
        );
        assert_eq!(
            run.completion(),
            &PolicyRunCompletion::Complete,
            "{label}: {:?}",
            run.diagnostics()
        );
        assert!(
            run.findings().is_empty(),
            "{label}: the rule cannot address a projection, so it decides nothing: {:?}",
            run.findings()
        );
    }
}

// ---------------------------------------------------------------------------
// Per-language proof for the promoted claim (#1598). Each claimed language
// gets the true-positive shape, the loop-local near-miss, the rebinding
// near-miss where the language can spell one, and a deferred-body lexical
// positive. Near-misses assert completion before cleanliness, exactly like
// the Rust originals above.
// ---------------------------------------------------------------------------

fn assert_positive(label: &str, language: Language, path: &str, source: &str, expected: usize) {
    let run = run_source(RULE, language, path, source);
    assert_eq!(
        run.completion(),
        &PolicyRunCompletion::Complete,
        "{label}: {:?}",
        run.diagnostics()
    );
    assert_eq!(
        run.findings().len(),
        expected,
        "{label}: {:?}",
        run.findings()
    );
}

const PYTHON_TRUE_POSITIVE: &str = "\
def order(ready, groups):
    total = 0
    for group in groups:
        ready.sort()
        total += len(ready)
    return total
";

const PYTHON_NEAR_MISS_LOOP_LOCAL: &str = "\
def order(groups):
    total = 0
    for group in groups:
        batch = list(group)
        batch.sort()
        total += len(batch)
    return total
";

const PYTHON_NEAR_MISS_REBINDING: &str = "\
def order(outer, groups):
    ready = outer
    total = len(ready)
    for group in groups:
        ready = list(group)
        ready.sort()
        total += len(ready)
    return total
";

const PYTHON_DEFERRED_LEXICAL_POSITIVE: &str = "\
def order(ready, times):
    total = 0
    for _ in range(times):
        def sort_now():
            ready.sort()
        sort_now()
        total += 1
    return total
";

#[test]
fn python_reports_a_receiver_declared_outside_the_loop() {
    assert_positive(
        "python true positive",
        Language::Python,
        "src/order.py",
        PYTHON_TRUE_POSITIVE,
        1,
    );
}

#[test]
fn python_loop_local_declaration_is_not_a_finding() {
    assert_clean_in(
        "python loop-local",
        Language::Python,
        "src/order.py",
        PYTHON_NEAR_MISS_LOOP_LOCAL,
    );
}

#[test]
fn python_rebinding_inside_the_loop_is_not_a_finding() {
    assert_clean_in(
        "python rebinding",
        Language::Python,
        "src/order.py",
        PYTHON_NEAR_MISS_REBINDING,
    );
}

#[test]
fn python_deferred_body_is_an_explicit_lexical_positive() {
    assert_positive(
        "python deferred body",
        Language::Python,
        "src/order.py",
        PYTHON_DEFERRED_LEXICAL_POSITIVE,
        1,
    );
}

const JAVA_TRUE_POSITIVE: &str = "\
import java.util.List;

class Order {
    int run(List<Integer> ready, List<List<Integer>> groups) {
        int total = 0;
        for (List<Integer> group : groups) {
            ready.sort(null);
            total += ready.size();
        }
        return total;
    }
}
";

const JAVA_NEAR_MISS_LOOP_LOCAL: &str = "\
import java.util.ArrayList;
import java.util.List;

class Order {
    int run(List<List<Integer>> groups) {
        int total = 0;
        for (List<Integer> group : groups) {
            List<Integer> batch = new ArrayList<>(group);
            batch.sort(null);
            total += batch.size();
        }
        return total;
    }
}
";

const JAVA_DEFERRED_LEXICAL_POSITIVE: &str = "\
import java.util.List;

class Order {
    int run(List<Integer> ready, int times) {
        int total = 0;
        for (int index = 0; index < times; index++) {
            Runnable sortNow = () -> ready.sort(null);
            sortNow.run();
            total += 1;
        }
        return total;
    }
}
";

#[test]
fn java_reports_a_receiver_declared_outside_the_loop() {
    assert_positive(
        "java true positive",
        Language::Java,
        "src/Order.java",
        JAVA_TRUE_POSITIVE,
        1,
    );
}

#[test]
fn java_loop_local_declaration_is_not_a_finding() {
    assert_clean_in(
        "java loop-local",
        Language::Java,
        "src/Order.java",
        JAVA_NEAR_MISS_LOOP_LOCAL,
    );
}

// Java forbids shadowing a local variable in a nested block, so the rebinding
// near-miss has no legal Java spelling; the loop-local near-miss carries the
// same reaching-binding burden for this language.

#[test]
fn java_deferred_body_is_an_explicit_lexical_positive() {
    assert_positive(
        "java deferred body",
        Language::Java,
        "src/Order.java",
        JAVA_DEFERRED_LEXICAL_POSITIVE,
        1,
    );
}

const TYPESCRIPT_TRUE_POSITIVE: &str = "\
export function order(ready: number[], groups: number[][]): number {
    let total = 0;
    for (const group of groups) {
        ready.sort();
        total += ready.length;
    }
    return total;
}
";

const TYPESCRIPT_NEAR_MISS_LOOP_LOCAL: &str = "\
export function order(groups: number[][]): number {
    let total = 0;
    for (const group of groups) {
        const batch = [...group];
        batch.sort();
        total += batch.length;
    }
    return total;
}
";

const TYPESCRIPT_NEAR_MISS_REBINDING: &str = "\
export function order(outer: number[], groups: number[][]): number {
    const ready = outer;
    let total = ready.length;
    for (const group of groups) {
        const ready = [...group];
        ready.sort();
        total += ready.length;
    }
    return total;
}
";

const TYPESCRIPT_DEFERRED_LEXICAL_POSITIVE: &str = "\
export function order(ready: number[], times: number): number {
    let total = 0;
    for (let index = 0; index < times; index++) {
        const sortNow = () => ready.sort();
        sortNow();
        total += 1;
    }
    return total;
}
";

#[test]
fn typescript_reports_a_receiver_declared_outside_the_loop() {
    assert_positive(
        "typescript true positive",
        Language::TypeScript,
        "src/order.ts",
        TYPESCRIPT_TRUE_POSITIVE,
        1,
    );
}

#[test]
fn typescript_loop_local_declaration_is_not_a_finding() {
    assert_clean_in(
        "typescript loop-local",
        Language::TypeScript,
        "src/order.ts",
        TYPESCRIPT_NEAR_MISS_LOOP_LOCAL,
    );
}

#[test]
fn typescript_rebinding_inside_the_loop_is_not_a_finding() {
    assert_clean_in(
        "typescript rebinding",
        Language::TypeScript,
        "src/order.ts",
        TYPESCRIPT_NEAR_MISS_REBINDING,
    );
}

#[test]
fn typescript_deferred_body_is_an_explicit_lexical_positive() {
    assert_positive(
        "typescript deferred body",
        Language::TypeScript,
        "src/order.ts",
        TYPESCRIPT_DEFERRED_LEXICAL_POSITIVE,
        1,
    );
}

const JAVASCRIPT_TRUE_POSITIVE: &str = "\
export function order(ready, groups) {
    let total = 0;
    for (const group of groups) {
        ready.sort();
        total += ready.length;
    }
    return total;
}
";

const JAVASCRIPT_NEAR_MISS_LOOP_LOCAL: &str = "\
export function order(groups) {
    let total = 0;
    for (const group of groups) {
        const batch = [...group];
        batch.sort();
        total += batch.length;
    }
    return total;
}
";

const JAVASCRIPT_NEAR_MISS_REBINDING: &str = "\
export function order(outer, groups) {
    const ready = outer;
    let total = ready.length;
    for (const group of groups) {
        const ready = [...group];
        ready.sort();
        total += ready.length;
    }
    return total;
}
";

#[test]
fn javascript_reports_a_receiver_declared_outside_the_loop() {
    assert_positive(
        "javascript true positive",
        Language::JavaScript,
        "src/order.js",
        JAVASCRIPT_TRUE_POSITIVE,
        1,
    );
}

#[test]
fn javascript_loop_local_declaration_is_not_a_finding() {
    assert_clean_in(
        "javascript loop-local",
        Language::JavaScript,
        "src/order.js",
        JAVASCRIPT_NEAR_MISS_LOOP_LOCAL,
    );
}

#[test]
fn javascript_rebinding_inside_the_loop_is_not_a_finding() {
    assert_clean_in(
        "javascript rebinding",
        Language::JavaScript,
        "src/order.js",
        JAVASCRIPT_NEAR_MISS_REBINDING,
    );
}

/// A workspace with no subjects must be clean, complete, and cheap. Before the
/// empty-path guard in the assertion evaluator, a subject-less run seeded its
/// occurrence/binding/scope queries with an empty exact-path list -- an
/// unrestricted seed -- and scanned every file in the workspace, inheriting
/// completeness verdicts (and hours of work) from files the policy had
/// nothing to say about.
#[test]
fn a_workspace_with_no_subjects_is_clean_and_complete() {
    assert_clean(
        "no subjects",
        "pub fn order(values: Vec<usize>) -> usize {\n    values.len()\n}\n",
    );
}
