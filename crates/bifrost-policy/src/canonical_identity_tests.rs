//! Parser-to-canonical contract checks with author-specified expectations.
use crate::{PolicySourceIdentity, parse_rqlp_source};
use serde_json::{Value, json};

fn assertion_projection(assertion: &str) -> Value {
    let source = format!(
        r#"(policy :id "test.identity" :name "Identity" :message "Mismatch"
      :severity warning :analysis (analysis :type assertion
      :subject (rql (identifier :capture "site")) :asserts [{assertion}]))"#
    );
    parse_rqlp_source(&source, PolicySourceIdentity::new("test:identity"))
        .unwrap_or_else(|error| panic!("{source}: {error:?}"))
        .to_inline_local_canonical_semantic_json()
        .unwrap()["analysis"]["asserts"][0]
        .clone()
}

#[test]
fn assertion_canonical_fields_preserve_authored_constraints() {
    let actual =
        assertion_projection(r#"(assert-round-trip :id check :at "site" :role type_operand)"#);
    assert_eq!(actual["kind"], json!("round_trip"), "round-trip.kind");
    assert_eq!(actual["role"], json!("type_operand"), "round-trip.role");
    assert_eq!(actual["id"], json!("check"), "round-trip.id");
    assert_eq!(actual["at"], json!("site"), "round-trip.at");
    let actual = assertion_projection(
        r#"(assert-boundary :id check :at "site" :role type_operand :forbid-fallback-past external_unknown)"#,
    );
    assert_eq!(actual["kind"], json!("boundary"), "boundary.kind");
    assert_eq!(
        actual["forbid_fallback_past"],
        json!("external_unknown"),
        "boundary.forbid_fallback_past"
    );
    assert_eq!(actual["id"], json!("check"), "boundary.id");
    assert_eq!(actual["at"], json!("site"), "boundary.at");
    let actual =
        assertion_projection(r#"(assert-edge-parity :id check :at "site" :role type_operand)"#);
    assert_eq!(actual["kind"], json!("edge_parity"), "edge-parity.kind");
    assert_eq!(actual["surface"], json!(null), "edge-parity.surface");
    assert_eq!(actual["id"], json!("check"), "edge-parity.id");
    assert_eq!(actual["at"], json!("site"), "edge-parity.at");
    let actual = assertion_projection(
        r#"(assert-edge-class :id check :at "site" :role type_operand :axis relation :require [same_owner] :forbid [external])"#,
    );
    assert_eq!(actual["kind"], json!("edge_class"), "edge-class.kind");
    assert_eq!(
        actual["require"],
        json!(["same_owner"]),
        "edge-class.require"
    );
    assert_eq!(actual["forbid"], json!(["external"]), "edge-class.forbid");
    assert_eq!(actual["id"], json!("check"), "edge-class.id");
    assert_eq!(actual["at"], json!("site"), "edge-class.at");
    let actual = assertion_projection(
        r#"(assert-generation :id check :at "site" :cardinality (exactly 3) :forbid-dynamic true)"#,
    );
    assert_eq!(actual["kind"], json!("generation"), "generation.kind");
    assert_eq!(
        actual["cardinality"],
        json!({"mode": "exactly", "count": 3}),
        "generation.cardinality"
    );
    assert_eq!(
        actual["forbid_dynamic"],
        json!(true),
        "generation.forbid_dynamic"
    );
    assert_eq!(actual["id"], json!("check"), "generation.id");
    assert_eq!(actual["at"], json!("site"), "generation.at");
    let actual = assertion_projection(
        r#"(assert-declaration-state :id check :at "site" :origin parsed :declaration-only true :config-gated false)"#,
    );
    assert_eq!(
        actual["kind"],
        json!("declaration_state"),
        "declaration-state.kind"
    );
    assert_eq!(
        actual["expect_origin"],
        json!("parsed"),
        "declaration-state.expect_origin"
    );
    assert_eq!(
        actual["declaration_only"],
        json!(true),
        "declaration-state.declaration_only"
    );
    assert_eq!(
        actual["config_gated"],
        json!(false),
        "declaration-state.config_gated"
    );
    assert_eq!(actual["id"], json!("check"), "declaration-state.id");
    assert_eq!(actual["at"], json!("site"), "declaration-state.at");
    let actual = assertion_projection(
        r#"(assert-canonical :id check :at "site" :role type_operand :equals "other" :equals-role type_operand :distinct true)"#,
    );
    assert_eq!(actual["kind"], json!("canonical"), "canonical.kind");
    assert_eq!(actual["distinct"], json!(true), "canonical.distinct");
    assert_eq!(actual["id"], json!("check"), "canonical.id");
    assert_eq!(actual["at"], json!("site"), "canonical.at");
    let actual = assertion_projection(
        r#"(assert-route :id check :at "site" :role type_operand :to "other" :to-role value_reference :via alias)"#,
    );
    assert_eq!(actual["kind"], json!("route"), "route.kind");
    assert_eq!(actual["to_role"], json!("value_reference"), "route.to_role");
    assert_eq!(actual["id"], json!("check"), "route.id");
    assert_eq!(actual["at"], json!("site"), "route.at");
    let actual = assertion_projection(
        r#"(assert-resolution :id check :at "site" :role type_operand :expect-tier lexical_binding :forbid-tier explicit_import :require-unique true)"#,
    );
    assert_eq!(actual["kind"], json!("resolution"), "resolution.kind");
    assert_eq!(
        actual["require_unique"],
        json!(true),
        "resolution.require_unique"
    );
    assert_eq!(
        actual["forbid_tier"],
        json!("explicit_import"),
        "resolution.forbid_tier"
    );
    assert_eq!(actual["id"], json!("check"), "resolution.id");
    assert_eq!(actual["at"], json!("site"), "resolution.at");
    let actual = assertion_projection(
        r#"(assert-binding-scope :id check :at "site" :role type_operand :declared inside :relative-to "other")"#,
    );
    assert_eq!(actual["kind"], json!("binding_scope"), "binding-scope.kind");
    assert_eq!(
        actual["relative_to"],
        json!("other"),
        "binding-scope.relative_to"
    );
    assert_eq!(actual["id"], json!("check"), "binding-scope.id");
    assert_eq!(actual["at"], json!("site"), "binding-scope.at");
}

fn project(source: &str) -> Value {
    parse_rqlp_source(source, PolicySourceIdentity::new("test:canonical"))
        .unwrap_or_else(|error| panic!("{source}: {error:?}"))
        .document()
        .to_normalized_authored_json()
}

#[test]
fn flow_endpoint_documents_preserve_their_authored_schema() {
    for (kind, entry, operand) in [
        ("origins", "origin", ":bind return-value"),
        (
            "observations",
            "observation",
            ":observed-operand (argument :index 2)",
        ),
    ] {
        let source = format!(
            r#"(endpoint-set-document :schema-version 1 :kind {kind}
          :set (endpoint-set :entries [({entry} :id endpoint :display-name "Endpoint"
          :selector (rql (call :callee (name "target"))) {operand})]))"#
        );
        let value = project(&source);
        let endpoint = &value["set"]["entries"][0];
        assert_eq!(endpoint["id"], json!("endpoint"));
        assert!(endpoint.get("categories").is_none(), "{value}");
        assert!(endpoint.get("labels").is_none(), "{value}");
        assert!(endpoint.get("dangerous_operand").is_none(), "{value}");
        if kind == "observations" {
            assert_eq!(
                endpoint["observed_operand"],
                json!({"type":"argument_index", "index":2})
            );
        }
    }
}

fn relational(predicate: &str, value: &str) -> Value {
    project(&format!(
        r#"(policy :id "test.rows" :name "Rows" :message "M" :severity warning
      :analysis (analysis :type assertion
        (bind :name cand :query (rql (occurrences :role [member_position])))
        (group :name grouped :by (cand.ast_id)
          (aggregate :name reads :op max :value {value} :where (({predicate}))))
        (assert :group grouped :value reads :cardinality (exactly 1))))"#
    ))
}

#[test]
fn relational_canonical_operands_preserve_types_and_all_members() {
    let value = relational("cand.target_count eq 7", "cand.target_count");
    let aggregate = &value["analysis"]["plan"]["groups"][0]["aggregates"][0];
    assert_eq!(aggregate["where"][0]["value"], json!(7));
    assert_eq!(
        aggregate["value"],
        json!({"binding":"cand", "field":"target_count"})
    );
    let members = relational(
        "cand.role in (member_position value_reference)",
        "cand.target_count",
    );
    assert_eq!(
        members["analysis"]["plan"]["groups"][0]["aggregates"][0]["where"][0]["values"],
        json!(["member_position", "value_reference"])
    );
    assert_ne!(
        members,
        relational(
            "cand.role in (member_position type_operand)",
            "cand.target_count"
        )
    );
}

#[test]
fn unresolved_imports_cannot_claim_a_closed_semantic_identity() {
    use crate::InlineLocalSemanticProjectionError;
    let endpoint = SUPERSEDES_ENDPOINT;
    let dependency = endpoint.replace(":supersedes []", ":supersedes [external]");
    assert_eq!(
        parse_rqlp_source(&dependency, PolicySourceIdentity::new("test:endpoint"))
            .unwrap()
            .to_inline_local_canonical_semantic_json(),
        Err(InlineLocalSemanticProjectionError::EndpointSupersedes {
            endpoint_id: "external".into()
        })
    );
    for kind in ["sources", "sanitizers"] {
        let source = format!(
            r#"(endpoint-set-document :kind {kind}
          :set (endpoint-set :include-files [(endpoint-set-file :path "external.rqlp")]))"#
        );
        assert_eq!(
            parse_rqlp_source(&source, PolicySourceIdentity::new("test:import"))
                .unwrap()
                .to_inline_local_canonical_semantic_json(),
            Err(InlineLocalSemanticProjectionError::EndpointSetFile {
                path: "external.rqlp".into()
            })
        );
    }
}

#[test]
fn classification_evidence_names_declared_source_and_sink_selectors() {
    let source = r#"(policy :id "test.evidence" :name "Evidence" :message "M" :severity warning
      :analysis (analysis :type taint :mode may
        :sources (endpoint-set :entries [(source :categories [input] :labels [untrusted] :id input :display-name "Input"
          :selector (rql (call :callee (name "input"))) :bind return-value)])
        :sinks (endpoint-set :entries [(sink :categories [output] :accepts [untrusted] :id output :display-name "Output"
          :selector (rql (call :callee (name "output"))) :dangerous-operand (argument :index 0))]))
      :classification (classification :fallback (classification-id :taxonomy "CWE" :id "CWE-20") :cvss (cvss :version "4.0" :emit when-base-complete
        :metric-rules [(metric :name AV :value N :when (analysis-type :is taint)
          :basis policy-assertion :scope vulnerable-system
          :evidence-refs [selector:/analysis/sources/entries/input/selector selector:/analysis/sinks/entries/output/selector]
          :rationale "Author-selected endpoints")])) )"#;
    let parsed = parse_rqlp_source(source, PolicySourceIdentity::new("test:evidence")).unwrap();
    assert!(parsed.to_inline_local_canonical_semantic_json().is_ok());
}

#[test]
fn first_typestate_subject_import_requires_composition() {
    assert_eq!(
        parse_rqlp_source(
            SUBJECT_DIRECTORY_POLICY,
            PolicySourceIdentity::new("test:subjects")
        )
        .unwrap()
        .to_inline_local_canonical_semantic_json(),
        Err(crate::InlineLocalSemanticProjectionError::MatchDirectory {
            path: "subjects".into()
        })
    );
}

#[test]
fn first_relational_binding_requires_its_selector_file() {
    let source = r#"(policy :id "test.file" :name "File" :message "M" :severity warning
      :analysis (analysis :type assertion
        (bind :name cand :query (declaration-selection-file :path "query.rqlp" :language rust))
        (group :name grouped :by (cand.id) (aggregate :name reads :op count))
        (assert :group grouped :value reads :cardinality (exactly 1))))"#;
    assert_eq!(
        parse_rqlp_source(source, PolicySourceIdentity::new("test:binding"))
            .unwrap()
            .to_inline_local_canonical_semantic_json(),
        Err(crate::InlineLocalSemanticProjectionError::FileSelector {
            path: "query.rqlp".into()
        })
    );
}

#[test]
fn relational_boolean_literals_preserve_authored_truth() {
    for truth in [true, false] {
        let source = format!(
            r#"(policy :id "test.boolean" :name "Boolean" :message "M" :severity warning
          :analysis (analysis :type assertion
            (bind :name cand :query (rql (call-result-obligations (call-shape (call)))))
            (group :name grouped :by (cand.site_ast_id)
              (aggregate :name reads :op count :where ((cand.terminal eq {truth}))))
            (assert :group grouped :value reads :cardinality (exactly 1))))"#
        );
        let value = project(&source);
        assert_eq!(
            value["analysis"]["plan"]["groups"][0]["aggregates"][0]["where"][0]["value"],
            json!(truth)
        );
    }
}

#[test]
fn canonical_identity_ignores_record_field_order_and_preserves_meaning() {
    let first =
        r#"(assert-generation :id check :at "site" :cardinality (exactly 3) :forbid-dynamic true)"#;
    let reordered =
        r#"(assert-generation :forbid-dynamic true :cardinality (exactly 3) :at "site" :id check)"#;
    assert_eq!(assertion_projection(first), assertion_projection(reordered));
    assert_ne!(
        assertion_projection(first),
        assertion_projection(&first.replace("exactly 3", "exactly 2"))
    );
    let edge = r#"(assert-edge-parity :id check :at "site" :role type_operand)"#;
    assert_ne!(
        assertion_projection(edge),
        assertion_projection(
            r#"(assert-edge-parity :id check :at "site" :role type_operand :surface external_usages)"#
        )
    );
}

/// One source endpoint with an empty supersedes list, authored for this test.
const SUPERSEDES_ENDPOINT: &str = r#"(endpoint
  :schema-version 1
  :id "bifrost.test.supersedes-source"
  :name "Supersedes source"
  :display-name "supersedes source"
  :role source
  :categories [input.user]
  :selector (rql :schema-version 1 (language python (call :callee (name "request_parameter"))))
  :binding return-value
  :supersedes [])"#;

/// A typestate policy whose only subject import is the `subjects` match directory, authored for this test.
const SUBJECT_DIRECTORY_POLICY: &str = r#"(policy
  :schema-version 1
  :id "bifrost.test.detached-resource-lifecycle"
  :name "Detached resource lifecycle"
  :message "Resource lifecycle transferred to detached work"
  :severity error
  :analysis
    (analysis
      :type typestate
      :mode may
      :call-modeling (call-modeling :unmodeled paranoid)
      :subjects
        (subject-set
          :include-matches [
            (match-directory
              :path "subjects"
              :scope recursive
              :categories (all [resource.acquire]))]
          :entries [])
      :uncertainty (uncertainty :escape inconclusive)
      :automaton
        (automaton
          :states [open error]
          :initial open
          :accepting-states [open]
          :error-states [error]
          :events [
            (event :id finish :on (normal-procedure-exit :scope analysis-root))]
          :transitions [
            (transition :from open :on finish :to error)]
          :terminal-expectations [])))"#;
