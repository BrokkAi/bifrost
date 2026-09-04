//! Authoring, canonicalization, identity and validation coverage for the
//! `:stores` persistence-store declarations (issue 2693, milestone 1).
//!
//! Store lowering is a later milestone: the flow-engine half is owned by the
//! store-lowering work, so the one execution-facing behavior checked here is
//! that the production taint compiler refuses a store-bearing policy with the
//! typed `UnsupportedAuxiliarySemantics("store")` capability gap instead of
//! silently ignoring the declarations.

use std::sync::Arc;

use super::catalog::{CatalogRegistryLimits, TaintCatalogRegistry};
use super::definition::{PolicyAnalysis, PolicyPort, RqlpDocument};
use super::identity::PolicySemanticHash;
use super::registry::{PolicyRegistry, PolicyRegistryLimits};
use super::source::{PolicySourceIdentity, parse_rqlp_source, rqlp_source_help_at};

/// The reference rule, with every store-relevant field a test may want to
/// perturb spelled as a parameter. Defaults reproduce the issue 2693 fixture.
struct StoreRule {
    write_id: &'static str,
    write_selector: &'static str,
    write_store: &'static str,
    write_key: Option<&'static str>,
    write_instance: Option<&'static str>,
    write_input: &'static str,
    read_id: &'static str,
    read_store: &'static str,
    read_key: Option<&'static str>,
    read_output: &'static str,
    stores_extra: &'static str,
}

impl Default for StoreRule {
    fn default() -> Self {
        Self {
            write_id: "put-primary",
            write_selector: r#"(rql :schema-version 1 (language java (call :callee (name "put"))))"#,
            write_store: "primary",
            write_key: Some("(argument :index 0)"),
            write_instance: Some("receiver"),
            write_input: "(argument :index 1)",
            read_id: "get-primary",
            read_store: "primary",
            read_key: Some("(argument :index 0)"),
            read_output: "return-value",
            stores_extra: "",
        }
    }
}

impl StoreRule {
    fn render(&self) -> String {
        let write_key = self
            .write_key
            .map_or_else(String::new, |port| format!(":key {port}"));
        let write_instance = self
            .write_instance
            .map_or_else(String::new, |port| format!(":instance {port}"));
        let read_key = self
            .read_key
            .map_or_else(String::new, |port| format!(":key {port}"));
        format!(
            r#"(policy
              :id "test.stores"
              :name "Stores"
              :message "tainted value reached the sensitive write"
              :severity warning
              :analysis (analysis :type taint :mode may
                :sources (endpoint-set :entries [
                  (source :id raw-input :display-name "AcmeSource.read"
                    :categories [input.user]
                    :selector (rql (language java (call :callee (name "read"))))
                    :bind return-value :labels [untrusted])])
                :sinks (endpoint-set :entries [
                  (sink :id sensitive-write :display-name "AcmeSink.write"
                    :categories [data.sensitive]
                    :selector (rql (language java (call :callee (name "write"))))
                    :dangerous-operand (argument :index 0) :accepts [untrusted])])
                :stores (endpoint-set {stores_extra} :entries [
                  (store-write :id {write_id}
                    :selector {write_selector}
                    :store {write_store}
                    {write_key}
                    {write_instance}
                    :input {write_input})
                  (store-read :id {read_id}
                    :selector (rql :schema-version 1 (language java (call :callee (name "get"))))
                    :store {read_store}
                    {read_key}
                    :instance receiver
                    :output {read_output})])))"#,
            stores_extra = self.stores_extra,
            write_id = self.write_id,
            write_selector = self.write_selector,
            write_store = self.write_store,
            write_key = write_key,
            write_instance = write_instance,
            write_input = self.write_input,
            read_id = self.read_id,
            read_store = self.read_store,
            read_key = read_key,
            read_output = self.read_output,
        )
    }
}

fn parse(source: &str) -> RqlpDocument {
    parse_rqlp_source(source, PolicySourceIdentity::new("test.rqlp"))
        .expect("the store policy parses")
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
            PolicySourceIdentity::new("test:store-identity"),
            source.as_bytes(),
        )
        .expect("the store policy loads");
    registry
        .policies()
        .next()
        .expect("one loaded policy")
        .semantic_hash()
}

fn error_at(source: &str, code: &str, token: &str) {
    let error = parse_rqlp_source(source, PolicySourceIdentity::new("test.rqlp"))
        .expect_err("the store policy must be rejected")
        .diagnostic;
    assert_eq!(error.code, code, "diagnostic: {error:?}");
    assert_eq!(&source[error.range], token);
}

#[test]
fn the_store_records_decode_into_the_taint_spec() {
    let RqlpDocument::Policy { definition } = parse(&StoreRule::default().render()) else {
        panic!("expected a policy document");
    };
    let PolicyAnalysis::Taint { spec } = &definition.analysis else {
        panic!("expected a taint analysis");
    };
    let [write] = spec.store_writes.as_slice() else {
        panic!("expected exactly one store write");
    };
    assert_eq!(write.id.as_str(), "put-primary");
    assert_eq!(write.store.as_str(), "primary");
    assert_eq!(write.key, Some(PolicyPort::ArgumentIndex { index: 0 }));
    assert_eq!(write.instance, Some(PolicyPort::Receiver));
    assert_eq!(write.input, PolicyPort::ArgumentIndex { index: 1 });

    let [read] = spec.store_reads.as_slice() else {
        panic!("expected exactly one store read");
    };
    assert_eq!(read.id.as_str(), "get-primary");
    assert_eq!(read.store.as_str(), "primary");
    assert_eq!(read.key, Some(PolicyPort::ArgumentIndex { index: 0 }));
    assert_eq!(read.instance, Some(PolicyPort::Receiver));
    assert_eq!(read.output, PolicyPort::ReturnValue);
}

#[test]
fn optional_store_dimensions_decode_as_absent() {
    let rule = StoreRule {
        write_key: None,
        write_instance: None,
        ..StoreRule::default()
    };
    let RqlpDocument::Policy { definition } = parse(&rule.render()) else {
        panic!("expected a policy document");
    };
    let PolicyAnalysis::Taint { spec } = &definition.analysis else {
        panic!("expected a taint analysis");
    };
    assert_eq!(spec.store_writes[0].key, None);
    assert_eq!(spec.store_writes[0].instance, None);
}

#[test]
fn the_canonical_projection_is_deterministic_and_includes_stores() {
    let source = StoreRule::default().render();
    let first = parse(&source).to_normalized_authored_json();
    let second = parse(&source).to_normalized_authored_json();
    assert_eq!(first, second, "the projection must be deterministic");

    let stores = &first["analysis"]["stores"];
    assert_eq!(stores["writes"][0]["id"], "put-primary");
    assert_eq!(stores["writes"][0]["store"], "primary");
    assert_eq!(stores["writes"][0]["key"]["type"], "argument_index");
    assert_eq!(stores["writes"][0]["instance"]["type"], "receiver");
    assert_eq!(stores["writes"][0]["input"]["index"], 1);
    assert_eq!(stores["reads"][0]["id"], "get-primary");
    assert_eq!(stores["reads"][0]["store"], "primary");
    assert_eq!(stores["reads"][0]["output"]["type"], "return_value");
}

/// A taint policy that declares no stores must keep its pre-store canonical
/// document byte-identical, so its semantic hash, baselines, and suppressions
/// stay valid.
#[test]
fn a_policy_without_stores_omits_the_stores_key() {
    let source = StoreRule::default().render();
    let start = source.find(":stores").expect("the fixture declares stores");
    // The `:stores` value is the parenthesized endpoint-set that follows.
    let open = source[start..].find('(').unwrap() + start;
    let mut depth = 0usize;
    let mut end = open;
    for (offset, byte) in source[open..].bytes().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    end = open + offset + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    let without = format!("{}{}", &source[..start], &source[end..]);
    let projected = parse(&without).to_normalized_authored_json();
    assert!(
        projected["analysis"].get("stores").is_none(),
        "a store-free taint projection must not publish `stores`"
    );
}

#[test]
fn store_entry_ids_share_one_namespace_with_every_other_local_entry() {
    let rule = StoreRule {
        write_id: "raw-input",
        ..StoreRule::default()
    };
    let source = rule.render();
    let error = parse_rqlp_source(&source, PolicySourceIdentity::new("test.rqlp"))
        .expect_err("one entry ID cannot name both a source and a store write")
        .diagnostic;
    assert_eq!(error.code, "duplicate-entry-id", "diagnostic: {error:?}");
}

#[test]
fn a_store_set_rejects_catalog_composition() {
    let rule = StoreRule {
        stores_extra: r#":include-sets [(catalog :name "acme.stores" :version 1)]"#,
        ..StoreRule::default()
    };
    let source = rule.render();
    error_at(&source, "field-not-allowed", ":include-sets");
}

#[test]
fn a_store_set_rejects_match_composition() {
    let rule = StoreRule {
        stores_extra: r#":include-matches [(match-endpoints :ids ["acme.store"])]"#,
        ..StoreRule::default()
    };
    let source = rule.render();
    error_at(&source, "field-not-allowed", ":include-matches");
}

#[test]
fn an_unknown_store_write_field_is_rejected_at_its_token() {
    let source = StoreRule::default().render().replace(
        ":input (argument :index 1)",
        ":removes [x] :input (argument :index 1)",
    );
    error_at(&source, "unknown-field", ":removes");
}

#[test]
fn a_missing_store_name_names_the_required_field() {
    let source = StoreRule::default().render().replace(":store primary", "");
    let error = parse_rqlp_source(&source, PolicySourceIdentity::new("test.rqlp"))
        .expect_err("a store write without a store name is not authorable")
        .diagnostic;
    assert_eq!(
        error.code, "missing-required-field",
        "diagnostic: {error:?}"
    );
    assert!(error.message.contains(":store"), "diagnostic: {error:?}");
}

#[test]
fn hover_shows_the_store_signatures() {
    let source = StoreRule::default().render();
    let record_offset = source.find("store-write").unwrap() + 2;
    let record_help =
        rqlp_source_help_at(&source, record_offset).expect("the store-write record has hover help");
    assert!(
        record_help.signature.contains(":store STORE"),
        "signature: {}",
        record_help.signature
    );
    assert!(
        record_help.description.contains("persistence store"),
        "description: {}",
        record_help.description
    );

    let read_offset = source.find("store-read").unwrap() + 2;
    let read_help =
        rqlp_source_help_at(&source, read_offset).expect("the store-read record has hover help");
    assert!(
        read_help.signature.contains(":output PORT"),
        "signature: {}",
        read_help.signature
    );

    let store_field_offset = source.find(":store primary").unwrap() + 3;
    let field_help =
        rqlp_source_help_at(&source, store_field_offset).expect("the :store field has hover help");
    assert!(
        field_help.description.contains("persistence boundary"),
        "description: {}",
        field_help.description
    );
}

#[test]
fn every_store_relevant_field_moves_the_semantic_hash() {
    let baseline = semantic_hash(&StoreRule::default().render());
    let variants: Vec<(&str, StoreRule)> = vec![
        (
            "write id",
            StoreRule {
                write_id: "put-other",
                ..StoreRule::default()
            },
        ),
        (
            "write selector",
            StoreRule {
                write_selector: r#"(rql :schema-version 1 (language java (call :callee (name "putAll"))))"#,
                ..StoreRule::default()
            },
        ),
        (
            "store name",
            StoreRule {
                write_store: "secondary",
                ..StoreRule::default()
            },
        ),
        (
            "write key presence",
            StoreRule {
                write_key: None,
                ..StoreRule::default()
            },
        ),
        (
            "write instance presence",
            StoreRule {
                write_instance: None,
                ..StoreRule::default()
            },
        ),
        (
            "write input",
            StoreRule {
                write_input: "(argument :index 0)",
                ..StoreRule::default()
            },
        ),
        (
            "read store name",
            StoreRule {
                read_store: "secondary",
                ..StoreRule::default()
            },
        ),
        (
            "read key presence",
            StoreRule {
                read_key: None,
                ..StoreRule::default()
            },
        ),
        (
            "read output",
            StoreRule {
                read_output: "receiver",
                ..StoreRule::default()
            },
        ),
    ];
    let mut seen = vec![baseline];
    for (field, variant) in variants {
        let hash = semantic_hash(&variant.render());
        assert!(
            !seen.contains(&hash),
            "changing the {field} must move the store policy's semantic hash"
        );
        seen.push(hash);
    }
}

/// The production compiler lowers store declarations rather than refusing
/// them. In a workspace whose fixture never calls the declared store, the
/// store entries select nothing and stay inert: the run must not carry the
/// pre-lowering CapabilityIncomplete refusal, and the declaration alone must
/// not manufacture a finding. The end-to-end write-to-read behavior lives in
/// the shipped-CLI suite (tests/suite_bench_policy, issue #2693).
#[test]
fn store_lowering_no_longer_refuses_and_an_uncalled_store_stays_inert() {
    use super::coordinator::{PolicyEvaluationOptions, evaluate_policy_source};
    use super::suppression::PolicyEvaluationDate;
    use brokk_bifrost_analysis::analyzer::{
        AnalyzerConfig, FilesystemProject, Project, WorkspaceAnalyzer,
    };

    let workspace = tempfile::tempdir().expect("temporary workspace");
    std::fs::write(
        workspace.path().join("first.py"),
        "def read():\n    return \"one\"\n\ndef write(value):\n    pass\n",
    )
    .expect("fixture source");
    let project: Arc<dyn Project> =
        Arc::new(FilesystemProject::new(workspace.path()).expect("fixture project"));
    let analyzer = WorkspaceAnalyzer::build_ephemeral_footgun(
        project,
        AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        },
    )
    .expect("an analyzer over the fixture");

    let source = StoreRule::default().render();
    let options = PolicyEvaluationOptions::new(
        PolicyEvaluationDate::from_ymd(2026, 9, 3).expect("fixed evaluation date"),
    );
    let outcome = evaluate_policy_source(
        workspace.path(),
        PolicySourceIdentity::new("test:stores.rqlp"),
        &source,
        &analyzer,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &options,
        None,
    )
    .expect("production taint evaluation");

    let [run] = outcome.report().runs() else {
        panic!("one policy produces one run");
    };
    assert!(
        !run.diagnostics().iter().any(|diagnostic| diagnostic
            .message()
            .contains("production taint store lowering is not available")),
        "the pre-lowering refusal must be gone: {:#?}",
        run.diagnostics()
    );
    assert!(
        run.findings().is_empty(),
        "an uncalled store declaration must not manufacture a finding: {:#?}",
        run.findings()
    );
}
