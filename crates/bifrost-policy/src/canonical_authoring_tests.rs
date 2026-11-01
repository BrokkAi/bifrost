use crate::source::{PolicySourceIdentity, parse_rqlp_source};
use serde_json::{Value, json};

fn project(analysis: &str, options: &str) -> Value {
    let source = format!(
        r#"(policy :id "test.identity" :name "Identity" :message "M"
        :severity warning {options}
        :analysis (analysis :type {analysis}))"#
    );
    parse_rqlp_source(&source, PolicySourceIdentity::new("identity.rqlp"))
        .unwrap()
        .document()
        .to_normalized_authored_json()
}

#[test]
fn authored_source_metadata_and_indexed_ports_remain_distinct() {
    let actual = project(
        r#"taint :mode may
        :sources (endpoint-set :entries [
          (source :id first :display-name "External request" :categories [input]
            :selector (rql (call)) :bind (result :index 1) :labels [raw]
            :threat-model remote)
          (source :id second :display-name "Other input" :categories [input]
            :selector (rql (call)) :bind (argument :index 1) :labels [raw])])
        :sinks (endpoint-set :entries [
          (sink :id output :display-name "Output" :categories [output]
            :selector (rql (call)) :dangerous-operand (argument :index 0)
            :accepts [raw] :tags [audit] :impacts [injection])])"#,
        "",
    );
    let sources = &actual["analysis"]["sources"]["entries"];
    assert_eq!(sources.as_array().unwrap().len(), 2);
    assert_eq!(sources[0]["display_name"], "External request");
    assert_eq!(sources[0]["threat_model"], "remote");
    assert_eq!(sources[0]["bind"], json!({"type":"result_index","index":1}));
    assert_eq!(
        sources[1]["bind"],
        json!({"type":"argument_index","index":1})
    );
    assert_eq!(
        actual["analysis"]["sinks"]["entries"][0]["impacts"],
        json!(["injection"])
    );
}

#[test]
fn flow_observations_and_transforms_preserve_direction_and_categories() {
    let actual = project(
        r#"flow :mode may
        :origins (endpoint-set :entries [
          (origin :id input :display-name "Input" :selector (rql (call)) :bind return-value)])
        :observations (endpoint-set :entries [
          (observation :id output :display-name "Output" :selector (rql (call))
            :observed-operand (argument :index 1))])
        :transforms (endpoint-set :entries [
          (transform :id normalize :selector (rql (call))
            :input (argument :index 0) :output return-value :categories [normalize])])"#,
        "",
    );
    assert_eq!(
        actual["analysis"]["observations"][0]["observed_operand"],
        json!({"type":"argument_index","index":1})
    );
    assert_eq!(
        actual["analysis"]["transforms"][0]["output"],
        json!({"type":"return_value"})
    );
    assert_eq!(
        actual["analysis"]["transforms"][0]["categories"],
        json!(["normalize"])
    );
}

#[test]
fn file_only_flow_imports_preserve_the_dependency_and_content_pin() {
    let hash = "a".repeat(64);
    let actual = project(
        &format!(
            r#"flow :mode may
        :origins (endpoint-set :include-files [(endpoint-set-file :path "inputs.rqlp" :sha256 "{hash}")])
        :observations (endpoint-set :entries [])"#
        ),
        "",
    );
    assert_eq!(
        actual["analysis"]["origins"]["include_files"],
        json!([{"path":"inputs.rqlp","sha256":hash}])
    );
}

#[test]
fn wildcard_catalog_and_direct_directory_keep_authored_selection() {
    let actual = project(
        r#"taint :mode may
        :sources (endpoint-set :include-sets [(catalog :any-registered true :categories (any [input]))])
        :sinks (endpoint-set :include-matches [(match-directory :path "endpoints" :scope direct :categories (any [output]))])"#,
        "",
    );
    assert_eq!(
        actual["analysis"]["sources"]["include_sets"][0]["any_registered"],
        true
    );
    assert_eq!(
        actual["analysis"]["sinks"]["include_matches"][0]["reference"]["scope"],
        "direct"
    );
}

#[test]
fn conditional_sanitizers_preserve_receiver_and_argument_requirements() {
    let actual = project(
        r#"taint :mode may :sources (endpoint-set) :sinks (endpoint-set)
        :sanitizers (endpoint-set :entries [(sanitizer :id guard :selector (rql (call))
          :when (result false) :sanitizes (argument :index 0)
          :requires [(argument :index 1 :constant true) (receiver :equals false)]
          :removes [raw])])"#,
        "",
    );
    let requirements = actual["analysis"]["sanitizers"]["entries"][0]["requires"]
        .as_array()
        .unwrap();
    assert!(
        requirements
            .iter()
            .any(|r| r["operand"] == json!({"type":"argument","index":1}))
    );
    assert!(
        requirements
            .iter()
            .any(|r| r["operand"] == json!({"type":"receiver"}))
    );
}

#[test]
fn report_limits_preserve_independent_authored_values() {
    let actual = project(
        "taint :mode may :sources (endpoint-set) :sinks (endpoint-set)",
        ":report (report :witnesses-per-finding 2 :origins-per-finding 5)",
    );
    assert_eq!(actual["report"]["witnesses_per_finding"], 2);
    assert_eq!(actual["report"]["origins_per_finding"], 5);
}

#[test]
fn fieldless_barriers_and_entry_point_parameters_keep_their_contracts() {
    let actual = project(
        r#"taint :mode may :sources (endpoint-set) :sinks (endpoint-set)
        :barriers (endpoint-set :entries [(barrier :id status :value-type (enum :fieldless true))])
        :entry-points (endpoint-set :entries [(entry-point :id entry :selector (rql (function))
          :parameter (argument :index 1) :labels [raw])])"#,
        "",
    );
    assert_eq!(
        actual["analysis"]["barriers"]["entries"][0]["value_type"],
        json!({"type":"enum","fieldless":true})
    );
    assert_eq!(
        actual["analysis"]["entry_points"]["entries"][0]["parameter"],
        json!({"type":"argument_index","index":1})
    );
}

#[test]
fn endpoint_result_bindings_preserve_the_result_tag() {
    let source = r#"(endpoint :id "test.result" :name "Result" :display-name "Result"
      :role source :categories [input] :selector (rql (call)) :binding (result :index 1)
      :taint (source-semantics :labels [raw]) :supersedes [])"#;
    let actual = parse_rqlp_source(source, PolicySourceIdentity::new("endpoint.rqlp"))
        .unwrap()
        .document()
        .to_normalized_authored_json();
    assert_eq!(actual["binding"], json!({"type":"result_index","index":1}));
}

#[test]
fn finding_combinations_keep_severity_and_all_local_references() {
    let actual = project(
        r#"taint :mode may
      :sources (endpoint-set :entries [
        (source :id first :display-name "First" :categories [input] :selector (rql (call)) :bind return-value :labels [raw])
        (source :id second :display-name "Second" :categories [input] :selector (rql (call)) :bind return-value :labels [raw])])
      :sinks (endpoint-set :entries [(sink :id output :display-name "Output" :categories [output] :selector (rql (call)) :dangerous-operand (argument :index 0) :accepts [raw])])
      :finding-combinations [(finding-combination :id pair
        :source (endpoints [(endpoint-ref :local first) (endpoint-ref :local second)])
        :sink (endpoints [(endpoint-ref :local output)]) :message "Pair" :severity error)]"#,
        "",
    );
    let combination = &actual["analysis"]["finding_combinations"][0];
    assert_eq!(
        combination["severity"],
        json!({"type":"fixed","level":"error"})
    );
    assert_eq!(
        combination["source"]["endpoints"],
        json!([
            {"type":"local","entry_id":"first"}, {"type":"local","entry_id":"second"}
        ])
    );
}

#[test]
fn boundary_and_occurrence_assertions_keep_prohibition_and_namespace() {
    let actual = project(
        r#"assertion
      :subject (rql (identifier :capture "target"))
      :asserts [
        (assert-boundary :id boundary :at "target" :role receiver_position :forbid-fallback-past external_unknown)
        (assert :id declared :at "target" :role declaration_name :expect declaration :namespace value)]"#,
        "",
    );
    let assertions = actual["analysis"]["asserts"].as_array().unwrap();
    assert_eq!(assertions[0]["forbid_fallback_past"], "external_unknown");
    assert_eq!(assertions[1]["namespace"], "value");
}

#[test]
fn cvss_fallback_severities_remain_distinct() {
    let fixture = CVSS_SEVERITY_POLICY;
    for level in ["warning", "error"] {
        let source = fixture.replace(":when-unscored unrated", &format!(":when-unscored {level}"));
        let actual = parse_rqlp_source(&source, PolicySourceIdentity::new("cvss.rqlp"))
            .unwrap()
            .document()
            .to_normalized_authored_json();
        assert_eq!(
            actual["severity"],
            json!({"type":"cvss","when_unscored":level})
        );
    }
}

/// A match policy that derives severity from CVSS, authored for this test.
const CVSS_SEVERITY_POLICY: &str = r#"(policy
              :id "bifrost.security.network-input"
              :name "Network input"
              :message "Network input reaches a sensitive operation"
              :severity (cvss-severity :when-unscored unrated)
              :analysis
                (analysis :type match :selector (rql (call)))
              :classification
                (classification
                  :fallback
                    (classification-id :taxonomy "Bifrost" :id "NETWORK-INPUT")
                  :refinements [
                    (refinement
                      :when (analysis-type :is match)
                      :add [(classification-id :taxonomy "CWE" :id "CWE-20")])]
                  :cvss
                    (cvss
                      :version "4.0"
                      :emit when-base-complete
                      :metric-rules [
                        (metric
                          :name AV
                          :value N
                          :when (analysis-type :is match)
                          :basis policy-assertion
                          :scope vulnerable-system
                          :evidence-refs [policy:self]
                          :rationale "Input reaches the vulnerable system over the network")])))"#;
