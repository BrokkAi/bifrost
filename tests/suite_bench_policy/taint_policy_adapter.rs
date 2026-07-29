use crate::common::InlineTestProject;
use brokk_bifrost::analyzer::policy::{
    HumanRenderColor, HumanRenderDetail, HumanRenderOptions, PolicyEvaluationDate,
    PolicyEvaluationInput, PolicyEvaluationOptions, PolicyFindingEvidence, PolicyRunCompletion,
    PolicySourceIdentity, SarifToolIdentity, evaluate_policy_inputs_with_analyzer,
    write_policy_human, write_policy_json, write_policy_sarif,
};
use brokk_bifrost::{AnalyzerConfig, Language};

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

#[test]
fn production_taint_policies_share_a_batch_and_all_renderers_keep_the_same_evidence() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("app.py", SOURCE)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let first = policy("test.taint-first", "first presentation", "warning");
    let second = policy("test.taint-second", "second presentation", "error");
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

    assert_eq!(outcome.report().runs().len(), 2);
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
        assert_eq!(run.findings().len(), 2);
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
