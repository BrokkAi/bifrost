use crate::{PolicySourceIdentity, parse_rqlp_source};
use serde_json::{Value, json};

fn project(classification: &str) -> Value {
    let source = format!(
        r#"(policy :id "identity" :name "Identity" :message "M" :severity warning
        :analysis (analysis :type taint :mode may :sources (endpoint-set :entries [(source :id origin :display-name "Origin" :categories [input] :selector (rql (call)) :bind return-value :labels [secret])]) :sinks (endpoint-set))
        :classification (classification
          :fallback (classification-id :taxonomy "test" :id "fallback")
          {classification}))"#
    );
    parse_rqlp_source(&source, PolicySourceIdentity::new("identity.rqlp"))
        .unwrap()
        .document()
        .to_normalized_authored_json()
}

fn refinement(predicate: &str, additions: &str) -> String {
    format!("(refinement :when {predicate} :add [{additions}])")
}

fn metric(predicate: &str, value: &str) -> String {
    format!(
        r#"(metric :name AV :value {value} :when {predicate}
        :basis policy-assertion :scope vulnerable-system
        :evidence-refs [selector:/analysis/sources/entries/origin/selector] :rationale "Network")"#
    )
}

#[test]
fn classification_preserves_precedence_and_all_additions() {
    let a = r#"(classification-id :taxonomy "CWE" :id "CWE-20")"#;
    let b = r#"(classification-id :taxonomy "CWE" :id "CWE-74")"#;
    let first = refinement("(analysis-type :is match)", &format!("{a} {b}"));
    let second = refinement("(analysis-type :is taint)", b);
    let projected = project(&format!(":refinements [{first} {second}]"));
    let rules = &projected["classification"]["refinements"];
    assert_eq!(rules[0]["when"]["analysis_type"], "match");
    assert_eq!(rules[1]["when"]["analysis_type"], "taint");
    let additions = rules[0]["add"].as_array().unwrap();
    assert_eq!(additions.len(), 2);
    for identifier in ["CWE-20", "CWE-74"] {
        assert!(additions.contains(&json!({"taxonomy":"CWE", "identifier":identifier})));
    }
    assert_ne!(
        projected,
        project(&format!(":refinements [{second} {first}]"))
    );
    let permuted = refinement("(analysis-type :is match)", &format!("{b} {a}"));
    assert_eq!(
        projected,
        project(&format!(":refinements [{permuted} {second}]"))
    );
    let reduced = refinement("(analysis-type :is match)", a);
    assert_ne!(
        projected,
        project(&format!(":refinements [{reduced} {second}]"))
    );
}

#[test]
fn classification_connectives_and_endpoint_roles_remain_distinct() {
    let additions = r#"(classification-id :taxonomy "CWE" :id "CWE-20")"#;
    let render = |predicate: &str| {
        project(&format!(
            ":refinements [{}]",
            refinement(predicate, additions)
        ))
    };
    let a = "(analysis-type :is match)";
    let b = "(sink-categories :any [input])";
    assert_ne!(
        render(&format!("(all [{a} {b}])")),
        render(&format!("(any [{a} {b}])"))
    );
    assert_eq!(
        render(&format!("(all [{a} {b}])")),
        render(&format!("(all [{b} {a}])"))
    );
    assert_ne!(render(b), render("(source-categories :any [input])"));
}

#[test]
fn cvss_preserves_rule_precedence_and_selector_evidence() {
    let first = metric("(analysis-type :is match)", "N");
    let second = metric("(analysis-type :is taint)", "L");
    let render = |rules: &str| {
        project(&format!(
            ":cvss (cvss :version \"4.0\" :emit when-base-complete :metric-rules [{rules}])"
        ))
    };
    let projected = render(&format!("{first} {second}"));
    let rules = &projected["classification"]["cvss"]["metric_rules"];
    assert_eq!(rules[0]["value"], "N");
    assert_eq!(rules[1]["value"], "L");
    assert_eq!(
        rules[0]["evidence_refs"],
        json!([{"type":"selector", "path":"/analysis/sources/entries/origin/selector"}])
    );
    assert_ne!(projected, render(&format!("{second} {first}")));
}

#[test]
fn cvss_connectives_and_sink_evidence_remain_distinct() {
    let render = |predicate: &str| {
        project(&format!(
            ":cvss (cvss :version \"4.0\" :emit when-base-complete :metric-rules [{}])",
            metric(predicate, "N")
        ))
    };
    let a = "(analysis-type :is match)";
    let b = "(sink-tags :any [input])";
    assert_ne!(
        render(&format!("(all [{a} {b}])")),
        render(&format!("(any [{a} {b}])"))
    );
    assert_eq!(
        render(&format!("(all [{a} {b}])")),
        render(&format!("(all [{b} {a}])"))
    );
    assert_ne!(render(b), render("(sink-impacts :any [input])"));
}

fn analysis_project(kind: &str, body: &str) -> Value {
    let source = format!(
        r#"(policy :id "identity" :name "Identity" :message "M" :severity warning
        :analysis (analysis :type {kind} :mode may {body}))"#
    );
    parse_rqlp_source(&source, PolicySourceIdentity::new("identity.rqlp"))
        .unwrap()
        .document()
        .to_normalized_authored_json()
}

#[test]
fn sanitizer_requirements_and_results_preserve_authored_conditions() {
    let render = |condition: &str, result: &str| {
        analysis_project(
            "taint",
            &format!(
                ":sources (endpoint-set) :sinks (endpoint-set) :sanitizers (endpoint-set :entries [(sanitizer :id guard :selector (rql (call)) :when (result {result}) :sanitizes receiver :requires [(argument :index 0 {condition})] :removes [secret])])"
            ),
        )
    };
    let constant = render(":constant true", "nil");
    let equals = render(":equals true", "nil");
    assert_ne!(constant, equals);
    let sanitizer = &constant["analysis"]["sanitizers"]["entries"][0];
    assert_eq!(sanitizer["requires"][0]["constant"], true);
    assert_ne!(constant, render(":constant true", "non-nil"));
    assert_eq!(sanitizer["when"]["result"], "nil");
}

#[test]
fn transforms_preserve_direction_and_label_changes() {
    let result = analysis_project(
        "taint",
        ":sources (endpoint-set) :sinks (endpoint-set) :transforms (endpoint-set :entries [(transform :id change :selector (rql (call)) :input (argument :index 0) :output return-value :removes [secret] :adds [public])])",
    );
    let transform = &result["analysis"]["transforms"]["entries"][0];
    assert_eq!(transform["removes"], json!(["secret"]));
    assert_eq!(transform["adds"], json!(["public"]));
    assert_ne!(transform["input"], transform["output"]);
    assert_eq!(transform["output"]["type"], "return_value");
}

#[test]
fn external_models_keep_every_transfer_and_label_effect() {
    let transfer = |index: usize| {
        format!(
            "(transfer :from (argument :index {index}) :to return-value :labels [secret] :effect (transform :removes [secret] :adds [public]))"
        )
    };
    let render = |transfers: &str| {
        analysis_project(
            "taint",
            &format!(
                ":sources (endpoint-set) :sinks (endpoint-set) :external-models (endpoint-set :entries [(external-model :id copy :selector (rql (call)) :transfers [{transfers}])])"
            ),
        )
    };
    let a = transfer(0);
    let b = transfer(1);
    let result = render(&format!("{a} {b}"));
    assert_eq!(result, render(&format!("{b} {a}")));
    assert_ne!(result, render(&a));
    let transfers = result["analysis"]["external_models"]["entries"][0]["transfers"]
        .as_array()
        .unwrap();
    assert_eq!(transfers.len(), 2);
    for transfer in transfers {
        assert_eq!(transfer["effect"]["adds"], json!(["public"]));
    }
}

#[test]
fn store_reads_keep_instance_separate_from_key() {
    let result = analysis_project(
        "taint",
        ":sources (endpoint-set) :sinks (endpoint-set) :stores (endpoint-set :entries [(store-read :id read :selector (rql (call)) :store cache :key (argument :index 0) :instance receiver :output return-value)])",
    );
    let read = &result["analysis"]["stores"]["reads"][0];
    assert_ne!(read["instance"], read["key"]);
    assert_eq!(read["instance"]["type"], "receiver");
}

#[test]
fn typestate_subjects_events_and_terminal_states_survive_projection() {
    let result = analysis_project(
        "typestate",
        r#"
      :subjects (subject-set :entries [
        (subject :id alpha :selector (rql (call)) :subject matched-value)
        (subject :id beta :selector (rql (call)) :subject (argument :index 0))])
      :uncertainty (uncertainty :escape inconclusive)
      :automaton (automaton :states [open closed error] :initial open
        :accepting-states [closed open] :error-states [error]
        :events [
          (event :id close :calls (calls :selector (rql (call)) :subject (result :index 0) :phase after-normal-return :condition (argument-condition :argument (argument :index 0) :equals false)) :supersedes [finish])
          (event :id finish :on (normal-procedure-exit :scope analysis-root))]
        :transitions [(transition :from open :on close :to closed) (transition :from open :on finish :to closed)]
        :terminal-expectations [(terminal-expectation :id exit :on (normal-procedure-exit :scope analysis-root) :expected-states [closed open]) (terminal-expectation :id sink :matches (match-directory :path "endpoints" :scope recursive :role sink :phase after-normal-return :categories (all [resource.close])) :expected-states [closed])])"#,
    );
    let subjects = &result["analysis"]["subjects"]["entries"];
    assert_eq!(subjects.as_array().unwrap().len(), 2);
    assert_eq!(subjects[0]["id"], "alpha");
    assert_eq!(subjects[0]["subject"]["type"], "matched_value");
    assert_eq!(subjects[1]["subject"]["index"], 0);
    let automaton = &result["analysis"]["automaton"];
    assert_eq!(
        automaton["terminal_expectations"][1]["trigger"]["role"],
        "sink"
    );
    let events = &automaton["events"];
    assert_eq!(events[0]["supersedes"], json!(["finish"]));
    assert_eq!(
        events[0]["trigger"]["condition"],
        json!({"argument_index":0,"equals":false})
    );
    assert_eq!(events[0]["trigger"]["subject"]["type"], "result_index");
    assert_eq!(events[1]["trigger"]["type"], "semantic_event");
    assert_eq!(
        automaton["terminal_expectations"][0]["expected_states"],
        json!(["closed", "open"])
    );
}
