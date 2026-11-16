//! A failure that removes evidence must leave a gap on every endpoint side it
//! can hide, so an empty side is never "proven" empty over a lost file (#12571).
use super::*;

// The rejection registry is process-wide and tests run in parallel, so each
// test names its own files.
const PROBE: &str = "fn source_12571() -> i32 { 1 }\n\
                     fn sink_12571(_: i32) {}\n\
                     fn main() { sink_12571(source_12571()); }\n";
const SOURCES_PATH: &str = "/analysis/sources/entries/input/selector";
const SINKS_PATH: &str = "/analysis/sinks/entries/out/selector";

/// A policy whose sink selector needs the semantic provider (`call-bindings`)
/// and whose source selector names `source`.
fn policy(source: &str, sink: &str) -> String {
    format!(
        r#"(policy :schema-version 1 :id "test.issue-12571" :name "Empty selection"
          :message "tainted data reached sink" :severity warning
          :analysis (analysis :type taint :mode may
            :call-modeling (call-modeling :unmodeled optimistic)
            :sources (endpoint-set :entries [
              (source :id input :display-name "input" :categories [input.user]
                :selector (rql :schema-version 1 (language rust (call :callee (name "{source}"))))
                :bind return-value :labels [attacker-controlled])])
            :sinks (endpoint-set :entries [
              (sink :id out :display-name "out" :categories [data.sensitive]
                :selector (rql :schema-version 1 (language rust
                  (call-argument :formal-index 0
                    (call-bindings (call-shape (call :callee (name "{sink}")))))))
                :dangerous-operand (argument :index 0) :accepts [attacker-controlled])])))"#
    )
}

struct Outcome {
    completion: PolicyRunCompletion,
    findings: usize,
    diagnostics: Vec<PolicyDiagnostic>,
    causes: serde_json::Value,
}

impl Outcome {
    fn messages(&self) -> Vec<&str> {
        self.diagnostics
            .iter()
            .map(PolicyDiagnostic::message)
            .collect()
    }

    fn mentions(&self, path: &str) -> bool {
        self.messages().iter().any(|message| message.contains(path))
    }

    fn run_incomplete_mentions(&self, path: &str) -> bool {
        self.diagnostics.iter().any(|diagnostic| {
            diagnostic.impact() == PolicyDiagnosticImpact::RunIncomplete
                && diagnostic.message().contains(path)
        })
    }

    fn assert_inconclusive(&self) {
        assert!(
            matches!(self.completion, PolicyRunCompletion::Inconclusive { .. }),
            "{:?} {:?}",
            self.completion,
            self.messages()
        );
    }
}

fn run(files: &[(&str, &str)], policy_text: &str) -> Outcome {
    let project = files
        .iter()
        .fold(
            InlineTestProject::with_language(Language::Rust).file(
                "Cargo.toml",
                "[package]\nname=\"probe12571\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
            ),
            |project, (path, source)| project.file(*path, *source),
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig {
        parallelism: Some(1),
        ..AnalyzerConfig::default()
    });
    let registry = registry_for(policy_text);
    let budget = PolicyBudget::builder().build().expect("default budget");
    let evaluator = super::super::with_composition_taint_engine_for_test(|| {
        ProductionTaintPolicyEvaluator::prepare(
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            registry.policies(),
            &analyzer,
            Ok(None),
            None,
            &budget,
        )
    });
    let payloads = evaluator.prepared.lock().expect("prepared payloads");
    let [(_, payload)] = payloads.iter().collect::<Vec<_>>()[..] else {
        panic!("one taint policy produces one payload");
    };
    Outcome {
        completion: payload.completion.clone(),
        findings: payload.projections.len(),
        diagnostics: payload.diagnostics.iter().cloned().collect(),
        causes: serde_json::to_value(payload.diagnostics.causes()).expect("causes serialize"),
    }
}

#[test]
fn the_fixture_flows_when_nothing_fails() {
    let outcome = run(
        &[("src/bin/flows_12571.rs", PROBE)],
        &policy("source_12571", "sink_12571"),
    );
    assert_eq!(outcome.findings, 1, "{:?}", outcome.messages());
    assert_eq!(outcome.completion, PolicyRunCompletion::Complete);
}

#[test]
fn a_selection_that_binds_nothing_is_complete_and_says_so() {
    let outcome = run(
        &[("src/bin/empty_12571.rs", PROBE)],
        &policy("never_12571", "never_sink_12571"),
    );
    assert_eq!(outcome.completion, PolicyRunCompletion::Complete);
    assert_eq!(outcome.findings, 0);
    assert!(
        outcome.messages().iter().any(|m| m.contains("bound no")),
        "{:?}",
        outcome.messages()
    );
}

#[test]
#[hardwon(
    "#12571: a rejected file hid every sink, so the never-run source side counted as empty and the sink gap was cleared"
)]
fn a_rejected_file_that_hid_every_sink_keeps_the_run_inconclusive_on_both_sides() {
    // The source selector matches nothing and is active; the only sink calls
    // sit in the file whose artifact the validator rejects.
    let rejected = "src/bin/hidden_12571.rs";
    let _rejection =
        brokk_bifrost_analysis::analyzer::semantic::reject_artifacts_at_path_for_test(rejected);
    let outcome = run(&[(rejected, PROBE)], &policy("never_12571", "sink_12571"));
    outcome.assert_inconclusive();
    assert_eq!(outcome.findings, 0);
    assert!(
        outcome.run_incomplete_mentions(SINKS_PATH),
        "the selector that ran records the failure: {:?}",
        outcome.messages()
    );
    assert!(
        outcome.run_incomplete_mentions(SOURCES_PATH),
        "the failure can hide a source too: {:?}",
        outcome.messages()
    );
    // The propagated gap carries the origin's typed cause and class exactly.
    let causes = outcome.causes.as_array().expect("causes are a list");
    let provider: Vec<_> = causes
        .iter()
        .filter(|cause| cause["code"] == "evaluation_failure")
        .map(|cause| cause["execution_cause"].clone())
        .collect();
    assert!(
        !provider.is_empty()
            && provider
                .iter()
                .all(|cause| cause == &serde_json::json!("provider")),
        "{:?}",
        outcome.causes
    );
}

#[test]
fn sinks_that_survive_leave_the_plans_arm_without_propagated_source_gaps() {
    // The rejected file holds a sink call with no source; the intact file holds
    // the source and a sink call. Sinks and sources both bind, so the compile
    // produces plans and the failure's own gap alone makes the run inconclusive.
    let rejected = "src/bin/lost_sink_12571.rs";
    let _rejection =
        brokk_bifrost_analysis::analyzer::semantic::reject_artifacts_at_path_for_test(rejected);
    let outcome = run(
        &[
            (
                rejected,
                "fn sink_12571(_: i32) {}\nfn main() { sink_12571(2); }\n",
            ),
            ("src/bin/kept_12571.rs", PROBE),
        ],
        &policy("source_12571", "sink_12571"),
    );
    outcome.assert_inconclusive();
    assert_eq!(outcome.findings, 1, "{:?}", outcome.messages());
    assert!(
        outcome.run_incomplete_mentions(SINKS_PATH),
        "{:?}",
        outcome.messages()
    );
    assert!(
        !outcome.mentions(SOURCES_PATH),
        "propagation applies only where a side is judged empty: {:?}",
        outcome.messages()
    );
}
