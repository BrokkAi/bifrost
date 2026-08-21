//! Authoring, canonicalization, identity and validation coverage for
//! `(analysis :type flow ...)` (issue 2436).
//!
//! The execution half of the milestone -- direct, helper, kill, abstention and
//! near-miss behavior over the production solver -- lives in the workspace
//! suite, because it needs a real analyzer. What is checked here is everything
//! that happens before a solve: the neutral records decode into the shared
//! taint-shaped model, the canonical projection publishes only what a flow
//! author wrote, every flow-relevant field moves the semantic hash, and a
//! malformed binding is a load-time diagnostic at the exact token.

use std::sync::Arc;

use super::catalog::{CatalogRegistryLimits, TaintCatalogRegistry};
use super::definition::{
    FLOW_INTERNAL_CATEGORY, FLOW_INTERNAL_LABEL, PolicyAnalysis, PolicyAnalysisType, PolicyPort,
    RqlpDocument,
};
use super::identity::PolicySemanticHash;
use super::registry::{PolicyRegistry, PolicyRegistryLimits};
use super::source::{PolicySourceIdentity, parse_rqlp_source};

/// The reference rule, with every field a test may want to perturb spelled as
/// a parameter. Defaults reproduce the checked-in fixture's shape.
struct FlowRule {
    id: &'static str,
    mode_call_modeling: &'static str,
    origin_id: &'static str,
    origin_display_name: &'static str,
    origin_selector: &'static str,
    origin_bind: &'static str,
    observation_id: &'static str,
    observation_display_name: &'static str,
    observation_selector: &'static str,
    observation_operand: &'static str,
    kills: Option<&'static str>,
}

impl Default for FlowRule {
    fn default() -> Self {
        Self {
            id: "test.flow",
            mode_call_modeling: ":mode may :call-modeling (call-modeling :unmodeled paranoid)",
            origin_id: "raw-input",
            origin_display_name: "AcmeSource.read",
            origin_selector: r#"(rql (language java (call :callee (name "read"))))"#,
            origin_bind: "return-value",
            observation_id: "store-put",
            observation_display_name: "AcmeStore.put",
            observation_selector: r#"(rql (language java (call :callee (name "put"))))"#,
            observation_operand: "(argument :index 0)",
            kills: Some(
                r#"(kill :id validated
                     :selector (rql (language java (call :callee (name "validate"))))
                     :input (argument :index 0)
                     :output return-value)"#,
            ),
        }
    }
}

impl FlowRule {
    fn render(&self) -> String {
        let kills = self.kills.map_or_else(String::new, |entries| {
            format!(":kills (endpoint-set :entries [{entries}])")
        });
        format!(
            r#"(policy
              :id "{id}"
              :name "Flow"
              :message "the tracked value reached the observation"
              :severity warning
              :analysis (analysis :type flow {mode_call_modeling}
                :origins (endpoint-set :entries [
                  (origin :id {origin_id}
                    :display-name "{origin_display_name}"
                    :selector {origin_selector}
                    :bind {origin_bind})])
                :observations (endpoint-set :entries [
                  (observation :id {observation_id}
                    :display-name "{observation_display_name}"
                    :selector {observation_selector}
                    :observed-operand {observation_operand})])
                {kills}))"#,
            id = self.id,
            mode_call_modeling = self.mode_call_modeling,
            origin_id = self.origin_id,
            origin_display_name = self.origin_display_name,
            origin_selector = self.origin_selector,
            origin_bind = self.origin_bind,
            observation_id = self.observation_id,
            observation_display_name = self.observation_display_name,
            observation_selector = self.observation_selector,
            observation_operand = self.observation_operand,
        )
    }
}

fn parse(source: &str) -> RqlpDocument {
    parse_rqlp_source(source, PolicySourceIdentity::new("test.rqlp"))
        .expect("the flow policy parses")
        .document()
        .clone()
}

fn semantic_hash(source: &str) -> PolicySemanticHash {
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    registry
        .register_policy_bytes(
            PolicySourceIdentity::new("test:flow-identity"),
            source.as_bytes(),
        )
        .expect("the flow policy loads");
    registry
        .policies()
        .next()
        .expect("one loaded policy")
        .semantic_hash()
}

fn error_at(source: &str, code: &str, token: &str) {
    let error = parse_rqlp_source(source, PolicySourceIdentity::new("test.rqlp"))
        .expect_err("the flow policy must be rejected")
        .diagnostic;
    assert_eq!(error.code, code, "diagnostic: {error:?}");
    assert_eq!(&source[error.range], token);
}

#[test]
fn the_neutral_records_decode_into_the_shared_taint_shaped_model() {
    let RqlpDocument::Policy { definition } = parse(&FlowRule::default().render()) else {
        panic!("expected a policy document");
    };
    assert_eq!(
        definition.analysis.analysis_type(),
        PolicyAnalysisType::Flow
    );
    let PolicyAnalysis::Flow { spec } = &definition.analysis else {
        panic!("expected a flow analysis");
    };
    let [origin] = spec.sources.entries.as_slice() else {
        panic!("expected exactly one origin");
    };
    assert_eq!(origin.id.as_str(), "raw-input");
    assert_eq!(origin.bind, PolicyPort::ReturnValue);
    assert_eq!(
        origin.labels.iter().map(|l| l.as_str()).collect::<Vec<_>>(),
        vec![FLOW_INTERNAL_LABEL],
        "a flow origin is closed over exactly one internal label"
    );
    assert_eq!(
        origin
            .categories
            .iter()
            .map(|c| c.as_str())
            .collect::<Vec<_>>(),
        vec![FLOW_INTERNAL_CATEGORY]
    );
    assert!(origin.evidence.is_none());

    let [observation] = spec.sinks.entries.as_slice() else {
        panic!("expected exactly one observation");
    };
    assert_eq!(
        observation.dangerous_operand,
        PolicyPort::ArgumentIndex { index: 0 }
    );
    assert!(observation.tags.is_empty() && observation.impacts.is_empty());

    let [kill] = spec.sanitizers.entries.as_slice() else {
        panic!("expected exactly one kill");
    };
    assert_eq!(kill.input, PolicyPort::ArgumentIndex { index: 0 });
    assert_eq!(kill.output, PolicyPort::ReturnValue);
    assert_eq!(
        kill.removes.iter().map(|l| l.as_str()).collect::<Vec<_>>(),
        vec![FLOW_INTERNAL_LABEL]
    );

    assert!(spec.transforms.entries.is_empty());
    assert!(spec.external_models.entries.is_empty());
    assert!(spec.finding_combinations.is_empty());
}

#[test]
fn the_canonical_projection_publishes_only_authored_flow_fields() {
    let projected = parse(&FlowRule::default().render()).to_normalized_authored_json();
    let analysis = &projected["analysis"];
    assert_eq!(analysis["type"], "flow");
    assert_eq!(analysis["origins"][0]["id"], "raw-input");
    assert_eq!(analysis["origins"][0]["display_name"], "AcmeSource.read");
    assert_eq!(analysis["origins"][0]["bind"]["type"], "return_value");
    assert_eq!(analysis["observations"][0]["id"], "store-put");
    assert_eq!(analysis["kills"][0]["id"], "validated");
    assert_eq!(analysis["kills"][0]["output"]["type"], "return_value");
    // The synthetic label and category are constants of the analysis kind, not
    // authored facts, so they never reach the canonical document.
    for absent in [
        "sources",
        "sinks",
        "sanitizers",
        "transforms",
        "external_models",
        "finding_combinations",
    ] {
        assert!(
            analysis.get(absent).is_none(),
            "a flow projection must not publish `{absent}`"
        );
    }
    let encoded = serde_json::to_string(&projected).expect("the projection serializes");
    assert!(!encoded.contains(FLOW_INTERNAL_LABEL));
    assert!(!encoded.contains(FLOW_INTERNAL_CATEGORY));
}

#[test]
fn the_canonical_projection_round_trips_through_parse() {
    let source = FlowRule::default().render();
    let first = parse(&source).to_normalized_authored_json();
    let second = parse(&source).to_normalized_authored_json();
    assert_eq!(first, second, "the projection must be deterministic");
}

#[test]
fn every_flow_relevant_field_moves_the_semantic_hash() {
    let baseline = semantic_hash(&FlowRule::default().render());
    let variants: Vec<(&str, FlowRule)> = vec![
        (
            "call-modeling",
            FlowRule {
                mode_call_modeling: ":mode may :call-modeling (call-modeling :unmodeled require-model)",
                ..FlowRule::default()
            },
        ),
        (
            "origin id",
            FlowRule {
                origin_id: "other-input",
                ..FlowRule::default()
            },
        ),
        (
            "origin display name",
            FlowRule {
                origin_display_name: "AcmeSource.readOther",
                ..FlowRule::default()
            },
        ),
        (
            "origin selector",
            FlowRule {
                origin_selector: r#"(rql (language java (call :callee (name "readOther"))))"#,
                ..FlowRule::default()
            },
        ),
        (
            "origin bind",
            FlowRule {
                origin_bind: "receiver",
                ..FlowRule::default()
            },
        ),
        (
            "observation id",
            FlowRule {
                observation_id: "other-put",
                ..FlowRule::default()
            },
        ),
        (
            "observation display name",
            FlowRule {
                observation_display_name: "AcmeStore.putOther",
                ..FlowRule::default()
            },
        ),
        (
            "observation selector",
            FlowRule {
                observation_selector: r#"(rql (language java (call :callee (name "putOther"))))"#,
                ..FlowRule::default()
            },
        ),
        (
            "observed operand",
            FlowRule {
                observation_operand: "(argument :index 1)",
                ..FlowRule::default()
            },
        ),
        (
            "kill id",
            FlowRule {
                kills: Some(
                    r#"(kill :id other-validated
                         :selector (rql (language java (call :callee (name "validate"))))
                         :input (argument :index 0)
                         :output return-value)"#,
                ),
                ..FlowRule::default()
            },
        ),
        (
            "kill selector",
            FlowRule {
                kills: Some(
                    r#"(kill :id validated
                         :selector (rql (language java (call :callee (name "check"))))
                         :input (argument :index 0)
                         :output return-value)"#,
                ),
                ..FlowRule::default()
            },
        ),
        (
            "kill input",
            FlowRule {
                kills: Some(
                    r#"(kill :id validated
                         :selector (rql (language java (call :callee (name "validate"))))
                         :input (argument :index 1)
                         :output return-value)"#,
                ),
                ..FlowRule::default()
            },
        ),
        (
            "kill output",
            FlowRule {
                kills: Some(
                    r#"(kill :id validated
                         :selector (rql (language java (call :callee (name "validate"))))
                         :input (argument :index 0)
                         :output receiver)"#,
                ),
                ..FlowRule::default()
            },
        ),
        (
            "kill presence",
            FlowRule {
                kills: None,
                ..FlowRule::default()
            },
        ),
    ];
    let mut seen = vec![baseline];
    for (field, variant) in variants {
        let hash = semantic_hash(&variant.render());
        assert!(
            !seen.contains(&hash),
            "changing the {field} must move the flow policy's semantic hash"
        );
        seen.push(hash);
    }
}

#[test]
fn an_equal_flow_and_taint_model_do_not_share_a_semantic_hash() {
    // Both policies bind the same sites through the same ports with the same
    // call modeling. Only the analysis kind differs, and the kind is what makes
    // one a provenance rule and the other a taint classification.
    let flow = semantic_hash(
        &FlowRule {
            id: "test.same",
            kills: None,
            ..FlowRule::default()
        }
        .render(),
    );
    let taint = semantic_hash(
        r#"(policy
          :id "test.same"
          :name "Flow"
          :message "the tracked value reached the observation"
          :severity warning
          :analysis (analysis :type taint :mode may
            :call-modeling (call-modeling :unmodeled paranoid)
            :sources (endpoint-set :entries [
              (source :id raw-input :display-name "AcmeSource.read"
                :categories [flow.value]
                :selector (rql (language java (call :callee (name "read"))))
                :bind return-value :labels [flow-value])])
            :sinks (endpoint-set :entries [
              (sink :id store-put :display-name "AcmeStore.put"
                :categories [flow.value]
                :selector (rql (language java (call :callee (name "put"))))
                :dangerous-operand (argument :index 0)
                :accepts [flow-value])])))"#,
    );
    assert_ne!(flow, taint);
}

#[test]
fn flow_authoring_rejects_taint_vocabulary() {
    let source = FlowRule::default().render().replace(
        r#"(origin :id raw-input"#,
        r#"(source :id raw-input :labels [x] :categories [y]"#,
    );
    let error = parse_rqlp_source(&source, PolicySourceIdentity::new("test.rqlp"))
        .expect_err("a taint source record is not flow vocabulary")
        .diagnostic;
    assert_eq!(error.code, "wrong-record-kind", "diagnostic: {error:?}");
    assert!(
        error.message.contains("expected `origin`"),
        "diagnostic: {error:?}"
    );
}

#[test]
fn a_flow_binding_error_selects_the_exact_token() {
    let rule = FlowRule {
        observation_operand: "(argument :index -1)",
        ..FlowRule::default()
    };
    let source = rule.render();
    error_at(&source, "invalid-value-shape", "-1");
}

#[test]
fn a_missing_flow_binding_names_the_field_that_is_required() {
    let source = FlowRule::default()
        .render()
        .replace(":observed-operand (argument :index 0)", "");
    let error = parse_rqlp_source(&source, PolicySourceIdentity::new("test.rqlp"))
        .expect_err("an observation without an operand is not authorable")
        .diagnostic;
    assert_eq!(error.code, "missing-required-field");
    assert!(
        error.message.contains(":observed-operand"),
        "diagnostic: {error:?}"
    );
}

#[test]
fn a_flow_analysis_cannot_carry_cvss() {
    let rendered = FlowRule::default().render();
    let source = format!(
        "{} :classification (classification \
             :fallback (classification-id :taxonomy \"T\" :id \"T-1\") \
             :cvss (cvss :version \"4.0\" :emit when-base-complete :metric-rules [ \
               (metric :name AV :value N :when (analysis-type :is match) \
                 :basis policy-assertion :scope vulnerable-system \
                 :evidence-refs [policy:self] :rationale \"remote\")])))",
        rendered
            .strip_suffix(')')
            .expect("the rendered policy ends with its closing paren")
    );
    let error = parse_rqlp_source(&source, PolicySourceIdentity::new("test.rqlp"))
        .expect_err("a flow analysis carries no CVSS evidence")
        .diagnostic;
    assert_eq!(error.code, "cvss-not-allowed-for-flow");
}

#[test]
fn flow_entry_ids_share_one_namespace_with_every_other_local_entry() {
    let rule = FlowRule {
        observation_id: "raw-input",
        ..FlowRule::default()
    };
    let source = rule.render();
    let error = parse_rqlp_source(&source, PolicySourceIdentity::new("test.rqlp"))
        .expect_err("one entry ID cannot name both an origin and an observation")
        .diagnostic;
    assert_eq!(error.code, "duplicate-entry-id");
}
