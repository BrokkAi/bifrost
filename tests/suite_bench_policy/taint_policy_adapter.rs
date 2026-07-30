use crate::common::InlineTestProject;
use brokk_bifrost::analyzer::policy::{
    HumanRenderColor, HumanRenderDetail, HumanRenderOptions, PolicyEvaluationDate,
    PolicyEvaluationInput, PolicyEvaluationOptions, PolicyFindingEvidence, PolicyIncompleteReason,
    PolicyRunCompletion, PolicySourceIdentity, SarifToolIdentity,
    evaluate_policy_inputs_with_analyzer, write_policy_human, write_policy_json,
    write_policy_sarif,
};
use brokk_bifrost::analyzer::structural::{
    TaintResultRef, TaintResultRegistration, TaintResultRegistrationError,
    TaintResultRegistrationLimits, TaintResultRegistrationOutcome, TaintResultRegistrationSet,
    TaintResultRegistrationSetError,
};
use brokk_bifrost::{AnalyzerConfig, Language};
use std::sync::Arc;

const SOURCE: &str = r#"
def source_one():
    return "one"

def source_two():
    return "two"

def sink_one(value):
    pass

def sink_two(value):
    pass

def run():
    first = source_one()
    second = source_two()
    sink_one(first)
    sink_two(second)
"#;

const INTERPROCEDURAL_SOURCE: &str = r#"
def source_one():
    return "one"

def sink_one(value):
    pass

def helper():
    return source_one()

def run():
    sink_one(helper())
"#;

const MATCHED_VALUE_SOURCE: &str = r#"
def source_one():
    return "one"

def sink_one(value):
    pass

def run():
    first = source_one()
    sink_one(first)
"#;

const SIBLING_CALLEE_SOURCE: &str = r#"
def source_one():
    return "one"

def sink_one(value):
    pass

def produce():
    return source_one()

def consume(value):
    sink_one(value)

def run():
    produced = produce()
    consume(produced)
"#;

fn policy(id: &str, message: &str, severity: &str) -> String {
    format!(
        r#"(policy
          :schema-version 1
          :id "{id}"
          :name "Production taint adapter"
          :message "{message}"
          :severity {severity}
          :analysis (analysis
            :type taint
            :mode may
            :call-modeling (call-modeling :unmodeled optimistic)
            :sources (endpoint-set :entries [
              (source :id first :display-name "first source" :categories [input.user]
                :selector (rql :schema-version 6
                  (language python (call :callee (name "source_one"))))
                :bind return-value :labels [untrusted])
              (source :id second :display-name "second source" :categories [input.user]
                :selector (rql :schema-version 6
                  (language python (call :callee (name "source_two"))))
                :bind return-value :labels [untrusted])])
            :sinks (endpoint-set :entries [
              (sink :id first-store :display-name "first sink" :categories [data.sensitive]
                :selector (rql :schema-version 6
                  (language python (call :callee (name "sink_one"))))
                :dangerous-operand (argument :index 0) :accepts [untrusted])
              (sink :id second-store :display-name "second sink" :categories [data.sensitive]
                :selector (rql :schema-version 6
                  (language python (call :callee (name "sink_two"))))
                :dangerous-operand (argument :index 0) :accepts [untrusted])]))
          :classification (classification
            :fallback (classification-id :taxonomy "Test" :id "BROAD-TAINT")))"#
    )
}

fn subset_policy(id: &str) -> String {
    format!(
        r#"(policy
          :schema-version 1
          :id "{id}"
          :name "Endpoint-neutral production taint adapter"
          :message "subset presentation"
          :severity note
          :analysis (analysis
            :type taint
            :mode may
            :call-modeling (call-modeling :unmodeled optimistic)
            :sources (endpoint-set :entries [
              (source :id first :display-name "first source" :categories [input.user]
                :selector (rql :schema-version 6
                  (language python (call :callee (name "source_one"))))
                :bind return-value :labels [untrusted])])
            :sinks (endpoint-set :entries [
              (sink :id first-store :display-name "first sink" :categories [data.sensitive]
                :selector (rql :schema-version 6
                  (language python (call :callee (name "sink_one"))))
                :dangerous-operand (argument :index 0) :accepts [untrusted])]))
          :classification (classification
            :fallback (classification-id :taxonomy "Test" :id "BROAD-TAINT")))"#
    )
}

fn single_policy(id: &str, source_selector: &str, source_binding: &str) -> String {
    format!(
        r#"(policy
          :schema-version 1
          :id "{id}"
          :name "Production taint adapter boundary"
          :message "taint boundary"
          :severity warning
          :analysis (analysis
            :type taint
            :mode may
            :call-modeling (call-modeling :unmodeled optimistic)
            :sources (endpoint-set :entries [
              (source :id first :display-name "first source" :categories [input.user]
                :selector (rql :schema-version 6 {source_selector})
                :bind {source_binding} :labels [untrusted])])
            :sinks (endpoint-set :entries [
              (sink :id first-store :display-name "first sink" :categories [data.sensitive]
                :selector (rql :schema-version 6
                  (language python (call :callee (name "sink_one"))))
                :dangerous-operand (argument :index 0) :accepts [untrusted])]))
          :classification (classification
            :fallback (classification-id :taxonomy "Test" :id "BROAD-TAINT")))"#
    )
}

fn evaluate_one(
    source: &str,
    policy_source: &str,
) -> brokk_bifrost::analyzer::policy::PolicyBatchOutcome {
    let project = InlineTestProject::with_language(Language::Python)
        .file("app.py", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let input = [PolicyEvaluationInput::embedded(
        PolicySourceIdentity::new("test:boundary.rqlp"),
        policy_source,
    )];
    let options = PolicyEvaluationOptions::new(
        PolicyEvaluationDate::from_ymd(2026, 7, 29).expect("fixed evaluation date"),
    );
    evaluate_policy_inputs_with_analyzer(project.root(), &input, &workspace, &options, None)
        .expect("production taint boundary evaluation")
}

#[test]
fn production_taint_keeps_caller_and_callee_endpoints_in_one_call_region() {
    let policy = single_policy(
        "test.interprocedural-taint",
        "(language python (call :callee (name \"source_one\")))",
        "return-value",
    );
    let outcome = evaluate_one(INTERPROCEDURAL_SOURCE, &policy);
    assert_eq!(
        outcome.report().runs().len(),
        1,
        "{:?}",
        outcome.report().diagnostics()
    );
    assert_eq!(outcome.report().runs()[0].findings().len(), 1);
    assert_eq!(outcome.taint_findings().len(), 1);
}

#[test]
fn production_taint_discovers_an_unselected_common_caller_for_sibling_callees() {
    let policy = single_policy(
        "test.sibling-callee-taint",
        "(language python (call :callee (name \"source_one\")))",
        "return-value",
    );
    let outcome = evaluate_one(SIBLING_CALLEE_SOURCE, &policy);
    assert_eq!(
        outcome.report().runs().len(),
        1,
        "{:?}",
        outcome.report().diagnostics()
    );
    let run = &outcome.report().runs()[0];
    assert!(matches!(
        run.completion(),
        PolicyRunCompletion::Inconclusive { reasons }
            if reasons.contains(&PolicyIncompleteReason::PartialDiscovery)
    ));
    assert!(run.findings().is_empty());
    assert_eq!(outcome.taint_findings().len(), 1);
    assert_eq!(
        run.work()
            .metrics()
            .iter()
            .find(|metric| metric.name() == "taint.propagation_solves")
            .map(|metric| metric.value()),
        Some(1)
    );
}

#[test]
fn production_taint_matched_value_uses_the_direct_source_observation() {
    let policy = single_policy(
        "test.matched-value-taint",
        "(language python (name \"first\"))",
        "matched-value",
    );
    let outcome = evaluate_one(MATCHED_VALUE_SOURCE, &policy);
    assert_eq!(
        outcome.report().runs().len(),
        1,
        "{:?}",
        outcome.report().diagnostics()
    );
    let run = &outcome.report().runs()[0];
    assert!(
        run.diagnostics()
            .iter()
            .all(|diagnostic| !diagnostic.message().contains("semantic call site")),
        "{:?}",
        run.diagnostics()
    );
    assert_eq!(run.findings().len(), 1, "{:?}", run.diagnostics());
    assert_eq!(outcome.taint_findings().len(), 1);
}

#[test]
fn production_taint_complete_zero_match_is_clean_without_propagation() {
    let policy = single_policy(
        "test.zero-match-taint",
        "(language python (call :callee (name \"source_one\")))",
        "return-value",
    );
    let outcome = evaluate_one(
        r#"
def sink_one(value):
    pass

def run():
    sink_one("constant")
"#,
        &policy,
    );
    let run = &outcome.report().runs()[0];
    assert!(matches!(run.completion(), PolicyRunCompletion::Complete));
    assert!(run.findings().is_empty());
    assert!(run.diagnostics().is_empty());
    assert!(outcome.taint_findings().is_empty());
    assert!(
        run.work()
            .metrics()
            .iter()
            .all(|metric| metric.name() != "taint.propagation_solves")
    );
}

#[test]
fn production_taint_policies_share_a_batch_and_all_renderers_keep_the_same_evidence() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("app.py", SOURCE)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let first = policy("test.taint-first", "first presentation", "warning");
    let second = subset_policy("test.taint-second");
    let inputs = [
        PolicyEvaluationInput::embedded(PolicySourceIdentity::new("test:first.rqlp"), &first),
        PolicyEvaluationInput::embedded(PolicySourceIdentity::new("test:second.rqlp"), &second),
    ];
    let options = PolicyEvaluationOptions::new(
        PolicyEvaluationDate::from_ymd(2026, 7, 29).expect("fixed evaluation date"),
    );
    let outcome =
        evaluate_policy_inputs_with_analyzer(project.root(), &inputs, &workspace, &options, None)
            .expect("production taint evaluation");

    assert_eq!(
        outcome.report().runs().len(),
        2,
        "report diagnostics: {:?}",
        outcome.report().diagnostics()
    );
    for run in outcome.report().runs() {
        assert!(
            matches!(
                run.completion(),
                PolicyRunCompletion::Complete | PolicyRunCompletion::Inconclusive { .. }
            ),
            "{:?}: {:?}",
            run.completion(),
            run.diagnostics()
        );
        let expected_findings = if run.policy_id().as_str() == "test.taint-first" {
            2
        } else {
            1
        };
        assert_eq!(run.findings().len(), expected_findings);
        assert_eq!(
            run.work()
                .metrics()
                .iter()
                .find(|metric| metric.name() == "taint.propagation_solves")
                .expect("taint solve metric")
                .value(),
            1
        );
        assert_eq!(
            run.work()
                .metrics()
                .iter()
                .find(|metric| metric.name() == "taint.propagation_shared_memberships")
                .expect("shared batch metric")
                .value(),
            1
        );
        for finding in run.findings() {
            assert_eq!(
                finding
                    .classification()
                    .broad()
                    .expect("broad fallback classification")
                    .identifier(),
                "BROAD-TAINT"
            );
            let PolicyFindingEvidence::Taint { evidence } = finding.evidence() else {
                panic!("expected taint evidence");
            };
            assert_eq!(evidence.reached_source_labels().len(), 1);
            assert_eq!(evidence.origins().len(), 1);
            assert!(!finding.witnesses().is_empty());
            assert_eq!(
                finding.completeness().is_complete(),
                matches!(run.completion(), PolicyRunCompletion::Complete)
            );
        }
    }

    assert_eq!(outcome.taint_findings().len(), 2);
    assert_eq!(outcome.taint_analysis_results().len(), 1);
    let retained = &outcome.taint_analysis_results()[0];
    assert!(retained.plan_report_match());
    assert!(retained.retained_plan_bytes() > std::mem::size_of_val(retained.plan().as_ref()));
    assert!(retained.retained_report_bytes() > std::mem::size_of_val(retained.report().as_ref()));
    assert!(!retained.artifact_keys().is_empty());
    assert!(retained.retained_artifact_bytes() > 0);
    assert_eq!(
        retained
            .project_findings(&workspace, retained.projection_limits())
            .expect("retained production taint projection"),
        outcome.taint_findings()
    );
    let first_ref = TaintResultRef::new("request", "primary").expect("bounded taint ref");
    let alias_ref = TaintResultRef::new("request", "alias").expect("bounded taint ref");
    let registration = TaintResultRegistration::new(7, vec![Arc::clone(retained)])
        .expect("valid retained taint registration");
    let mut registrations = TaintResultRegistrationSet::default();
    assert_eq!(
        registrations
            .register(first_ref.clone(), registration)
            .expect("insert retained taint result"),
        TaintResultRegistrationOutcome::Inserted
    );
    assert_eq!(
        registrations
            .register(
                alias_ref.clone(),
                TaintResultRegistration::new(7, vec![Arc::clone(retained)])
                    .expect("valid taint alias"),
            )
            .expect("alias retained taint result"),
        TaintResultRegistrationOutcome::Aliased
    );
    assert_eq!(registrations.reference_count(), 2);
    assert_eq!(registrations.registration_count(), 1);
    assert!(registrations.unregister(&first_ref));
    assert_eq!(registrations.reference_count(), 1);
    assert_eq!(registrations.registration_count(), 1);
    assert!(registrations.unregister(&alias_ref));
    assert_eq!(registrations.registration_count(), 0);

    assert!(matches!(
        TaintResultRegistration::new(7, vec![Arc::clone(retained), Arc::clone(retained)]),
        Err(TaintResultRegistrationError::DuplicateRoot)
    ));
    let mut bounded = TaintResultRegistrationSet::with_limits(
        TaintResultRegistrationLimits::bounded(1, 1, 0, usize::MAX, usize::MAX),
    );
    assert!(matches!(
        bounded.register(
            first_ref,
            TaintResultRegistration::new(7, vec![Arc::clone(retained)])
                .expect("valid bounded registration"),
        ),
        Err(TaintResultRegistrationSetError::RetainedPlanBytes(0))
    ));
    assert_eq!(bounded.reference_count(), 0);
    assert_eq!(bounded.registration_count(), 0);
    assert_eq!(outcome.taint_query_results().len(), 2);
    for result in outcome.taint_query_results() {
        let value = serde_json::to_value(result).expect("public taint query serialization");
        assert_eq!(value["result_type"], "taint_finding");
        assert!(value.get("plan_ref").is_none());
        assert!(
            value["witnesses"]
                .as_array()
                .expect("taint witness array")
                .iter()
                .all(|witness| witness.get("plan_ref").is_none()
                    && witness.get("finding_id").is_some())
        );
    }
    assert!(outcome.taint_findings().iter().all(|finding| {
        finding.reached_labels == ["untrusted"]
            && finding.origins.len() == 1
            && !finding.witnesses.is_empty()
            && finding
                .witnesses
                .iter()
                .all(|witness| witness.finding_id == finding.id)
    }));

    let finding_ids = outcome
        .report()
        .runs()
        .iter()
        .flat_map(|run| run.findings())
        .map(|finding| finding.id().to_string())
        .collect::<Vec<_>>();
    let mut human = Vec::new();
    write_policy_human(
        outcome.report(),
        &HumanRenderOptions::new(HumanRenderDetail::Verbose, HumanRenderColor::Plain),
        &mut human,
        usize::MAX,
    )
    .expect("human rendering");
    let mut json = Vec::new();
    write_policy_json(outcome.report(), &mut json, usize::MAX).expect("JSON rendering");
    let mut sarif = Vec::new();
    write_policy_sarif(
        outcome.report(),
        &SarifToolIdentity::default(),
        &mut sarif,
        usize::MAX,
    )
    .expect("SARIF rendering");
    let human = String::from_utf8(human).expect("human UTF-8");
    let json = String::from_utf8(json).expect("JSON UTF-8");
    let sarif = String::from_utf8(sarif).expect("SARIF UTF-8");
    for finding_id in finding_ids {
        assert!(human.contains(&finding_id));
        assert!(json.contains(&finding_id));
        assert!(sarif.contains(&finding_id));
    }
    for rendered in [&human, &json, &sarif] {
        assert!(rendered.contains("BROAD-TAINT"));
        assert!(rendered.contains("untrusted"));
    }
}
