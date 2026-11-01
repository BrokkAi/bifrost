use crate::*;
use brokk_bifrost_rql::structural::CodeQuery;
use serde_json::{Value, json};

fn selector() -> Value {
    json!({"type":"inline", "schema_version":1,
        "query":CodeQuery::from_sexp("(call (arity 65))").unwrap().to_canonical_query_plan_json()})
}

fn catalog() -> Value {
    json!({"schema_version":1,"name":"test.authoring","version":1,"categories":["test.category"],
        "sources":[],"sinks":[],"sanitizers":[],"transforms":[],"external_models":[]})
}

fn source() -> Value {
    json!({"id":"input","display_name":"Input","categories":["test.category"],"selector":selector(),
        "bind":{"type":"receiver"},"labels":["untrusted"],"threat_model":null,"evidence":null})
}

fn load(value: &Value) -> Result<TaintCatalogRegistry, CatalogRegistryError> {
    let mut registry = TaintCatalogRegistry::new_without_workspace(Default::default());
    let result = registry.register_json_bytes(
        CatalogSourceIdentity::new("literal").unwrap(),
        &serde_json::to_vec(value).unwrap(),
    );
    if result.is_err() {
        assert_eq!(registry.iter().count(), 0);
    }
    result?;
    Ok(registry)
}

fn encoded(value: &Value) -> Value {
    let registry = load(value).unwrap();
    serde_json::from_slice(registry.iter().next().unwrap().canonical_json()).unwrap()
}

#[test]
fn source_evidence_and_matched_binding_preserve_author_intent() {
    for evidence in [
        Value::Null,
        json!({"trust_boundary":"external","system_entry":null}),
        json!({"trust_boundary":null,"system_entry":"local_input"}),
        json!({"trust_boundary":"external","system_entry":"local_input"}),
    ] {
        for port in ["receiver", "matched_value", "return_value"] {
            let mut value = catalog();
            let mut entry = source();
            entry["evidence"] = evidence.clone();
            entry["bind"] = json!({"type":port});
            value["sources"] = json!([entry.clone()]);
            assert_eq!(encoded(&value)["sources"][0], entry);
        }
    }
    let mut value = catalog();
    let mut entry = source();
    entry["evidence"] = json!({});
    value["sources"] = json!([entry]);
    assert!(load(&value).unwrap_err().to_string().contains("evidence"));
}

#[test]
fn author_display_text_accepts_exact_limit_and_rejects_controls() {
    for name in [
        " padded ".to_owned(),
        "x".repeat(MAX_POLICY_DISPLAY_TEXT_BYTES),
    ] {
        let mut value = catalog();
        let mut entry = source();
        entry["display_name"] = json!(name);
        value["sources"] = json!([entry.clone()]);
        assert_eq!(encoded(&value)["sources"][0], entry);
    }
    for (name, diagnostic) in [
        ("Input\n".to_owned(), "control"),
        ("x".repeat(MAX_POLICY_DISPLAY_TEXT_BYTES + 1), "4096"),
    ] {
        let mut value = catalog();
        let mut entry = source();
        entry["display_name"] = json!(name);
        value["sources"] = json!([entry]);
        assert!(load(&value).unwrap_err().to_string().contains(diagnostic));
    }
}

#[test]
fn field_writes_validate_both_field_and_base_names() {
    let mut value = catalog();
    value["sources"] = json!([source()]);
    load(&value).unwrap();
    value["sources"][0]["bind"] = json!({"type":"field","name":"value","of":{"type":"receiver"}});
    assert!(load(&value).unwrap_err().to_string().contains("field"));
    value["sources"] = json!([]);
    for (field, base, valid) in [
        ("value", "object", true),
        ("value\u{202e}", "object", false),
        ("value", "object\u{202e}", false),
    ] {
        value["external_models"] = json!([{"id":"write","categories":["test.category"],"selector":selector(),
            "transfers":[{"from":{"type":"argument_index","index":0},
            "to":{"type":"field","name":field,"of":{"type":"argument_name","name":base}},
            "labels":["untrusted"],"effect":{"type":"propagate"}}]}]);
        if valid {
            load(&value).unwrap();
        } else {
            assert!(load(&value).unwrap_err().to_string().contains("control"));
        }
    }
}

#[test]
fn sanitizer_wire_preserves_guards_operands_and_transfer_direction() {
    for result in ["true", "false", "nil", "non-nil"] {
        let mut value = catalog();
        let entry = json!({"id":"guard","selector":selector(),"when":{"result":result},
            "sanitizes":{"type":"receiver"},"requires":[{"operand":{"type":"receiver"},"constant":true}],"removes":["untrusted"]});
        value["sanitizers"] = json!([entry.clone()]);
        assert_eq!(encoded(&value)["sanitizers"][0], entry);
    }
    let mut value = catalog();
    let entry = json!({"id":"clean","selector":selector(),"input":{"type":"argument_index","index":0},
        "output":{"type":"return_value"},"removes":["untrusted"]});
    value["sanitizers"] = json!([entry.clone()]);
    assert_eq!(encoded(&value)["sanitizers"][0], entry);
}

#[test]
fn sanitizer_requirements_admit_sixty_four_and_report_overflow() {
    // Catalog normalization bounds requirements at 64, independent of arity.
    for count in [64, 65] {
        let mut value = catalog();
        let requires: Vec<_> = (0..count)
            .map(|index| json!({"operand":{"type":"argument","index":index},"constant":true}))
            .collect();
        value["sanitizers"] = json!([{"id":"guard","selector":selector(),"when":{"result":"true"},
            "sanitizes":{"type":"receiver"},"requires":requires,"removes":["untrusted"]}]);
        if count == 64 {
            load(&value).unwrap();
        } else {
            assert!(
                load(&value)
                    .unwrap_err()
                    .to_string()
                    .contains("too many sanitizer requirements")
            );
        }
    }
}

#[test]
fn sink_wire_retains_tags_and_impacts() {
    let mut value = catalog();
    let entry = json!({"id":"sink","display_name":"Sink","categories":["test.category"],"selector":selector(),
        "dangerous_operand":{"type":"argument_index","index":0},"accepts":["untrusted"],
        "tags":["injection","network"],"impacts":["confidentiality","integrity"]});
    value["sinks"] = json!([entry.clone()]);
    assert_eq!(encoded(&value)["sinks"][0], entry);
}

fn lifecycle(trigger: &str) -> String {
    format!(
        r#"(policy :id test.lifecycle :name "Lifecycle" :message "M" :severity warning
      :analysis (analysis :type typestate :mode may
        :subjects (subject-set :entries [(subject :id seed :selector (rql (call)) :subject return-value)])
        :uncertainty (uncertainty :escape inconclusive)
        :automaton (automaton :states [open closed error] :initial open
          :accepting-states [closed] :error-states [error]
          :events [(event :id close {trigger})]
          :transitions [(transition :from open :on close :to closed)]
          :terminal-expectations [(terminal-expectation :id exit
            :on (normal-procedure-exit :scope analysis-root) :expected-states [closed])])))"#
    )
}

#[test]
fn call_return_subject_requires_normal_return_observation() {
    for phase in [
        "after-normal-return",
        "before-call",
        "after-exceptional-return",
    ] {
        let text = lifecycle(&format!(
            ":calls (calls :selector (rql (call)) :subject return-value :phase {phase})"
        ));
        let mut registry = PolicyRegistry::new_without_workspace(
            std::sync::Arc::new(TaintCatalogRegistry::new_without_workspace(
                Default::default(),
            )),
            Default::default(),
        );
        let result =
            registry.register_policy_bytes(PolicySourceIdentity::new("lifecycle"), text.as_bytes());
        if phase == "after-normal-return" {
            result.unwrap();
        } else {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("normal results can be observed only after a normal return")
            );
        }
    }
}

#[test]
fn endpoint_observations_require_the_binding_to_exist_at_that_phase() {
    let root = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(root.path().join("endpoints")).unwrap();
    for (binding, accepted) in [
        ("matched-value", "at-match"),
        ("return-value", "after-normal-return"),
    ] {
        let endpoint = format!(
            r#"(endpoint :id test.observed :name "Observed" :display-name "Observed"
          :role sink :categories [resource.close] :selector (rql (call)) :binding {binding} :supersedes [])"#
        );
        std::fs::write(root.path().join("endpoints/observed.rqlp"), endpoint).unwrap();
        for phase in [
            "at-match",
            "after-normal-return",
            "before-call",
            "after-exceptional-return",
        ] {
            let text = lifecycle(&format!(
                r#":matches (match-directory :path "endpoints" :scope recursive
              :role sink :phase {phase} :categories (all [resource.close]))"#
            ));
            let mut registry = PolicyRegistry::new_for_workspace(
                root.path().to_path_buf(),
                std::sync::Arc::new(TaintCatalogRegistry::new_without_workspace(
                    Default::default(),
                )),
                Default::default(),
            )
            .unwrap();
            let result = registry
                .register_policy_bytes(PolicySourceIdentity::new("lifecycle"), text.as_bytes());
            if phase == accepted {
                result.unwrap();
            } else {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("observation phase")
                );
            }
        }
    }
}
