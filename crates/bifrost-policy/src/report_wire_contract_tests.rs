use super::*;
use crate::definition::{
    DirectoryScope, EndpointId, GeneratedRelation, PolicyCategoryId, TaintEntryId,
};
use crate::resolved::PolicyDependencyPath;
use crate::retained::RetainedSize;
use crate::test_support::load_match_policy;
use brokk_bifrost_analysis::analyzer::semantic::WorkspaceRelativePath;
use serde_json::Value;

const POLICY: &str = r#"(policy
  :id "test.report-wire"
  :name "Wire contract"
  :message "wire"
  :severity warning
  :analysis (analysis :type match :selector (rql (language python (call :callee (name "eval")))))
)"#;

fn report_with_descriptor(edit: impl FnOnce(&mut PolicyRuleDescriptor)) -> Value {
    let loaded = load_match_policy(POLICY);
    let mut descriptor = PolicyRuleDescriptor::from_loaded(&loaded);
    edit(&mut descriptor);
    report_from_loaded(&loaded, descriptor, Vec::new())
}

fn report_from_loaded(
    loaded: &LoadedPolicy,
    descriptor: PolicyRuleDescriptor,
    diagnostics: Vec<PolicyReportDiagnostic>,
) -> Value {
    let run = PolicyRun::try_new(
        loaded.definition().metadata.id.clone(),
        loaded.semantic_hash(),
        loaded.definition().analysis.analysis_type(),
        PolicyRunCompletion::Complete,
        Vec::new(),
        Vec::new(),
        false,
        crate::finding::PolicyWorkReport::default(),
        &crate::budget::PolicyBudget::default(),
    )
    .unwrap();
    let report =
        PolicyReportDocument::try_new(vec![descriptor], vec![run], diagnostics, false, 0, None)
            .unwrap();
    serde_json::to_value(report).unwrap()
}

#[test]
fn catalog_endpoint_report_preserves_name_schema_and_receiver_binding() {
    let catalog = ResolvedCatalogIdentity::try_new(
        PolicyId::new("test.catalog").unwrap(),
        1,
        TaintCatalogHash::from_bytes([7; 32]),
    )
    .unwrap();
    let json = report_with_descriptor(|descriptor| {
        let dependency = ResolvedEndpointDependency::new(
            ResolvedEndpointIdentity::Catalog {
                catalog: catalog.clone(),
                entry_id: TaintEntryId::new("entry").unwrap(),
            },
            EndpointDefinitionSchemaResolution::CatalogDocument { schema_version: 1 },
            PolicySelectorPath::new("/analysis/selector").unwrap(),
            ResolvedEndpointSelectorSchemas::Query(descriptor.policy_schema),
            ResolvedEndpointModel::new(
                EndpointRole::Source,
                "Catalog receiver".to_owned(),
                vec![PolicyCategoryId::new("input.user").unwrap()],
                PolicyEndpointBinding::Receiver,
                None,
                Vec::new(),
            ),
            EndpointSemanticHash::from_bytes([1; 32]),
            EndpointAnalysisProjectionHash::from_bytes([2; 32]),
            vec![EndpointOrigin::Catalog {
                catalog: catalog.clone(),
            }],
        );
        descriptor.endpoint_dependencies.push(dependency);
    });
    let endpoint = &json["rules"][0]["endpoint_dependencies"][0];
    assert_eq!(endpoint["identity"]["catalog"]["name"], "test.catalog");
    assert_eq!(endpoint["definition_schema"]["type"], "catalog_document");
    assert_eq!(endpoint["model"]["binding"]["type"], "receiver");
}

#[test]
fn directory_manifest_report_preserves_any_and_all_category_meaning() {
    let json = report_with_descriptor(|descriptor| {
        for (path, categories) in [
            (
                "/directory/any",
                CategoryPredicate::Any {
                    categories: vec![
                        PolicyCategoryId::new("input.one").unwrap(),
                        PolicyCategoryId::new("input.two").unwrap(),
                    ],
                },
            ),
            (
                "/directory/all",
                CategoryPredicate::All {
                    categories: vec![
                        PolicyCategoryId::new("input.one").unwrap(),
                        PolicyCategoryId::new("input.two").unwrap(),
                    ],
                },
            ),
        ] {
            descriptor.match_directory_manifests.push(
                ResolvedMatchDirectoryManifest::try_new(
                    PolicyDependencyPath::new(path).unwrap(),
                    WorkspaceRelativePath::new("src").unwrap(),
                    DirectoryScope::Recursive,
                    None,
                    categories,
                    vec![ResolvedEndpointManifestEntry {
                        identity: ResolvedEndpointIdentity::MatchEndpoint {
                            endpoint_id: EndpointId::new("test.manifest-entry").unwrap(),
                        },
                        definition_schema: EndpointDefinitionSchemaResolution::PolicyDocument {
                            resolution: descriptor.policy_schema,
                        },
                        selector_schemas: ResolvedEndpointSelectorSchemas::Query(
                            descriptor.policy_schema,
                        ),
                        semantic_hash: EndpointSemanticHash::from_bytes([3; 32]),
                        analysis_projection_hash: EndpointAnalysisProjectionHash::from_bytes(
                            [if path == "/directory/any" { 4 } else { 5 }; 32],
                        ),
                    }],
                )
                .unwrap(),
            );
        }
    });
    let manifests = json["rules"][0]["match_directory_manifests"]
        .as_array()
        .unwrap();
    assert_eq!(manifests.len(), 2);
    assert_eq!(
        manifests[0]["selected"][0]["semantic_hash"],
        manifests[1]["selected"][0]["semantic_hash"]
    );
    assert_ne!(
        manifests[0]["selected"][0]["analysis_projection_hash"],
        manifests[1]["selected"][0]["analysis_projection_hash"]
    );
    for manifest in manifests {
        let expected = if manifest["path"] == "/directory/any" {
            "any"
        } else {
            "all"
        };
        assert_eq!(manifest["categories"]["type"], expected);
        assert_eq!(manifest["directory"], "src");
        assert_ne!(manifest["path"], manifest["directory"]);
        let selected = &manifest["selected"][0];
        assert_eq!(selected["identity"]["endpoint_id"], "test.manifest-entry");
        assert_eq!(selected["identity"]["type"], "match_endpoint");
        assert_ne!(
            selected["semantic_hash"],
            selected["analysis_projection_hash"]
        );
        assert_eq!(
            manifest["categories"]["categories"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }
}

#[test]
fn endpoint_set_origin_and_generated_rule_fields_survive_report_serialization() {
    let json = report_with_descriptor(|descriptor| {
        descriptor.message = PolicyMessageSpec::Generated {
            relation: GeneratedRelation::CanReach,
        };
        descriptor.severity = PolicySeveritySpec::Unrated;
        descriptor
            .endpoint_dependencies
            .push(ResolvedEndpointDependency::new(
                ResolvedEndpointIdentity::MatchEndpoint {
                    endpoint_id: EndpointId::new("test.file-endpoint").unwrap(),
                },
                EndpointDefinitionSchemaResolution::PolicyDocument {
                    resolution: descriptor.policy_schema,
                },
                PolicySelectorPath::new("/analysis/selector").unwrap(),
                ResolvedEndpointSelectorSchemas::Query(descriptor.policy_schema),
                ResolvedEndpointModel::new(
                    EndpointRole::Source,
                    "File endpoint".to_owned(),
                    Vec::new(),
                    PolicyEndpointBinding::MatchedValue,
                    None,
                    Vec::new(),
                ),
                EndpointSemanticHash::from_bytes([5; 32]),
                EndpointAnalysisProjectionHash::from_bytes([6; 32]),
                vec![EndpointOrigin::EndpointSetFile {
                    path: PolicyDependencyPath::new("/files/endpoints.rqlp").unwrap(),
                    source: crate::source::PolicySourceIdentity::new("endpoints.rqlp"),
                }],
            ));
    });
    let rule = &json["rules"][0];
    assert_eq!(rule["message"]["relation"], "can_reach");
    assert_eq!(rule["severity"]["type"], "unrated");
    let endpoint = &rule["endpoint_dependencies"][0];
    assert_eq!(endpoint["identity"]["endpoint_id"], "test.file-endpoint");
    assert_eq!(endpoint["origins"][0]["type"], "endpoint_set_file");
}

#[test]
fn descriptor_tags_count_toward_the_exact_policy_skeleton_byte_limit() {
    let loaded = load_match_policy(POLICY);
    let mut descriptor = PolicyRuleDescriptor::from_loaded(&loaded);
    descriptor.tags = vec!["long-tag".repeat(256)];
    let mut without_tags = descriptor.clone();
    without_tags.tags.clear();
    assert!(descriptor.retained_size() >= without_tags.retained_size() + 256 * "long-tag".len());
    let run = PolicyRun::try_new(
        loaded.definition().metadata.id.clone(),
        loaded.semantic_hash(),
        PolicyAnalysisType::Match,
        PolicyRunCompletion::Complete,
        Vec::new(),
        Vec::new(),
        false,
        crate::finding::PolicyWorkReport::default(),
        &crate::budget::PolicyBudget::default(),
    )
    .unwrap();
    let bound = descriptor.retained_size()
        + run.retained_size()
        + super::PER_POLICY_INCOMPLETE_REASON_ALLOWANCE;
    for (max_bytes, admitted) in [(bound, true), (bound - 1, false)] {
        let per_policy = crate::budget::PolicyBudget::builder()
            .with_max_retained_report_bytes(max_bytes)
            .unwrap()
            .build()
            .unwrap();
        let budget = PolicyBatchBudget::builder()
            .with_per_policy(per_policy)
            .unwrap()
            .build()
            .unwrap();
        let mut builder = PolicyReportBuilder::new(budget, 1).unwrap();
        assert_eq!(
            builder
                .register_policy(descriptor.clone(), run.clone())
                .is_ok(),
            admitted
        );
    }
}

#[test]
fn related_diagnostic_allocations_count_toward_the_report_byte_limit() {
    let source = crate::source::PolicySourceIdentity::new("policy.rqlp");
    let make_diagnostic = || {
        let mut diagnostic = PolicyReportDiagnostic::try_new(
            PolicyReportDiagnosticCode::PolicyValidationFailed,
            PolicyDiagnosticSeverity::Error,
            "invalid policy",
            Some(source.clone()),
            None,
            vec![crate::source::PolicySourceRelatedDiagnostic {
                source: source.clone(),
                range: 2..4,
                message: "related detail".to_owned(),
            }],
        )
        .unwrap();
        diagnostic.related[0].message.reserve(4096);
        diagnostic
    };
    let diagnostic = make_diagnostic();
    let mut without_related = diagnostic.clone();
    without_related.related.clear();
    assert!(diagnostic.retained_size() > without_related.retained_size() + 4096);

    let mut compact_related = diagnostic.related[0].clone();
    compact_related.message.shrink_to_fit();
    assert!(diagnostic.related[0].retained_size() >= compact_related.retained_size() + 4096);

    let probe = PolicyReportBuilder::new(PolicyBatchBudget::default(), 0).unwrap();
    let candidate = vec![make_diagnostic()];
    let bound = super::report_storage_size(
        &probe.evaluation,
        &probe.rules,
        &probe.runs,
        &probe.suppressions,
        &probe.scope,
        &candidate,
    ) + probe.emergency_allowance;
    for (max_bytes, admitted) in [(bound, true), (bound - 1, false)] {
        let per_policy = crate::budget::PolicyBudget::builder()
            .with_max_retained_report_bytes(max_bytes)
            .unwrap()
            .build()
            .unwrap();
        let budget = PolicyBatchBudget::builder()
            .with_max_retained_report_bytes(max_bytes)
            .unwrap()
            .with_per_policy(per_policy)
            .unwrap()
            .build()
            .unwrap();
        let mut builder = PolicyReportBuilder::new(budget, 0).unwrap();
        let outcome = builder.retain_report_diagnostic(make_diagnostic()).unwrap();
        assert_eq!(outcome == PolicyRetentionOutcome::Retained, admitted);
        let report = builder.finish().unwrap();
        assert_eq!(report.diagnostics_truncated(), !admitted);
    }
}

#[test]
fn related_diagnostic_message_and_source_have_distinct_report_fields() {
    let loaded = load_match_policy(POLICY);
    let diagnostic = PolicyReportDiagnostic::try_new(
        PolicyReportDiagnosticCode::PolicyValidationFailed,
        PolicyDiagnosticSeverity::Error,
        "invalid policy",
        Some(crate::source::PolicySourceIdentity::new("policy.rqlp")),
        None,
        vec![crate::source::PolicySourceRelatedDiagnostic {
            source: crate::source::PolicySourceIdentity::new("related.rqlp"),
            range: 2..4,
            message: "Related explanation".to_owned(),
        }],
    )
    .unwrap();
    let json = report_from_loaded(
        &loaded,
        PolicyRuleDescriptor::from_loaded(&loaded),
        vec![diagnostic],
    );
    let related = &json["diagnostics"][0]["related"][0];
    assert_eq!(related["source"], "related.rqlp");
    assert_eq!(related["message"], "Related explanation");
}

#[test]
fn authored_endpoint_precedence_keeps_its_direction_in_the_report() {
    use std::sync::Arc;
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp.path().join("matches")).unwrap();
    std::fs::create_dir_all(temp.path().join("policies")).unwrap();
    for (file, id, supersedes) in [
        ("old.rqlp", "test.endpoint.old", ""),
        ("new.rqlp", "test.endpoint.new", "test.endpoint.old"),
    ] {
        let source = format!(
            r#"(endpoint :schema-version 1 :id "{id}" :name "Input"
                :display-name "Input" :role source :categories [input.user]
                :selector (rql :schema-version 1 (call :callee (name "input")))
                :binding return-value :taint (source-semantics :labels [untrusted])
                :supersedes [{supersedes}])"#
        );
        std::fs::write(temp.path().join("matches").join(file), source).unwrap();
    }
    let policy = r#"(policy :schema-version 1 :id "test.precedence"
        :name "Precedence" :message "M" :severity warning
        :analysis (analysis :type taint :mode may
          :sources (endpoint-set :include-matches [
            (match-directory :path "matches" :scope direct :categories (any [input.user]))])
          :sinks (endpoint-set :entries [
            (sink :id sink :display-name "Sink" :categories [sink.data]
              :selector (rql :schema-version 1 (call :callee (name "sink")))
              :dangerous-operand (argument :index 0) :accepts [untrusted])])))"#;
    std::fs::write(temp.path().join("policies/policy.rqlp"), policy).unwrap();
    let catalogs = Arc::new(crate::catalog::TaintCatalogRegistry::new_without_workspace(
        crate::catalog::CatalogRegistryLimits::default(),
    ));
    let mut registry = crate::registry::PolicyRegistry::new_for_workspace(
        temp.path().to_path_buf(),
        catalogs,
        crate::registry::PolicyRegistryLimits::default(),
    )
    .unwrap();
    let loaded = registry.load_policy_path("policies/policy.rqlp").unwrap();
    let json = report_from_loaded(
        loaded,
        PolicyRuleDescriptor::from_loaded(loaded),
        Vec::new(),
    );
    let edges = json["rules"][0]["precedence_manifest"]["edges"]
        .as_array()
        .unwrap();
    assert_eq!(edges.len(), 1, "one authored supersedes edge: {json:#}");
    let edge = &edges[0];
    assert_eq!(edge["type"], "endpoint");
    assert_eq!(edge["dominant"]["endpoint_id"], "test.endpoint.new");
    assert_eq!(edge["dominated"]["endpoint_id"], "test.endpoint.old");
}

#[test]
fn authored_typestate_expectation_precedence_uses_its_own_type_label() {
    let policy = r#"(policy :schema-version 1 :id "test.expectation-precedence"
        :name "Expectation precedence" :message "M" :severity warning
        :analysis (analysis :type typestate :mode may
          :subjects (subject-set :entries [
            (subject :id resource
              :selector (rql :schema-version 1
                (language typescript (call :callee (name "openResource"))))
              :subject return-value)])
          :uncertainty (uncertainty :escape inconclusive)
          :automaton (automaton :states [open closed error] :initial open
            :accepting-states [closed] :error-states [error]
            :events [(event :id finish :on (normal-procedure-exit :scope analysis-root))]
            :transitions [(transition :from open :on finish :to closed)]
            :terminal-expectations [
              (terminal-expectation :id base
                :on (normal-procedure-exit :scope analysis-root)
                :expected-states [closed])
              (terminal-expectation :id preferred
                :on (normal-procedure-exit :scope analysis-root)
                :expected-states [closed] :supersedes [base])])))"#;
    let registry = crate::test_support::registry_with_policy(
        "test:expectation-precedence",
        policy,
        "valid typestate precedence policy",
    );
    let loaded = registry.policies().next().unwrap();
    let json = report_from_loaded(
        loaded,
        PolicyRuleDescriptor::from_loaded(loaded),
        Vec::new(),
    );
    let edges = json["rules"][0]["precedence_manifest"]["edges"]
        .as_array()
        .unwrap();
    assert_eq!(edges.len(), 1, "one authored expectation edge: {json:#}");
    assert_eq!(edges[0]["type"], "typestate_expectation");
    assert_eq!(edges[0]["dominant"], "preferred");
    assert_eq!(edges[0]["dominated"], "base");
}
