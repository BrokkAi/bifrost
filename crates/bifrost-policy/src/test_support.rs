use std::sync::Arc;

use brokk_bifrost_rql::structural::{CodeQuery, SCHEMA_VERSION};

use crate::catalog::{CatalogRegistryLimits, TaintCatalogRegistry};
use crate::cvss::{CvssEvidenceBasis, CvssEvidenceContentHash, CvssMetricEvidence};
use crate::definition::{
    CvssBaseMetric, CvssMetric, CvssMetricValue, CvssMetricValueToken, PolicyCategoryId,
    PolicyPort, PolicySelector, PolicySelectorPath, RqlpDocument, TaintEntryId, TaintLabel,
    TaintSourceSpec,
};
use crate::finding_identity::EvidenceRef;
use crate::identity::{EndpointAnalysisProjectionHash, EndpointSemanticHash};
use crate::registry::{PolicyRegistry, PolicyRegistryLimits};
use crate::resolved::{
    EndpointDefinitionSchemaResolution, EndpointOrigin, LoadedPolicy, PolicyDependencyPath,
    PolicyPrecedenceManifest, ResolvedEndpointDependency, ResolvedEndpointIdentity,
    ResolvedEndpointModel, ResolvedEndpointSelectorSchemas, ResolvedPolicySelector, SelectorOrigin,
};
use crate::source::{PolicySourceIdentity, parse_rqlp_source};
use crate::{
    PolicyAnalysis, PolicyBudget, PolicyReportDocument, PolicyRuleDescriptor, PolicyRun,
    PolicyRunCompletion, PolicyWorkReport, SchemaVersionOrigin, SchemaVersionResolution,
};

pub(crate) fn close_match_snapshot()
-> std::sync::Arc<brokk_bifrost_analysis::analyzer::semantic_model::ActiveSemanticModelSnapshot> {
    close_match_snapshot_with_completeness("complete")
}

pub(crate) fn close_match_snapshot_with_completeness(
    completeness: &str,
) -> std::sync::Arc<brokk_bifrost_analysis::analyzer::semantic_model::ActiveSemanticModelSnapshot> {
    rust_dependency_snapshot(completeness, true, &["0.4.25"], false)
}

pub(crate) fn close_match_snapshot_with_versions(
    versions: &[&str],
) -> std::sync::Arc<brokk_bifrost_analysis::analyzer::semantic_model::ActiveSemanticModelSnapshot> {
    rust_dependency_snapshot("complete", true, versions, false)
}

pub(crate) fn close_match_callable_snapshot()
-> std::sync::Arc<brokk_bifrost_analysis::analyzer::semantic_model::ActiveSemanticModelSnapshot> {
    rust_dependency_snapshot("complete", true, &["0.4.25"], true)
}

pub(crate) fn exact_rust_dependency_snapshot()
-> std::sync::Arc<brokk_bifrost_analysis::analyzer::semantic_model::ActiveSemanticModelSnapshot> {
    rust_dependency_snapshot("complete", false, &["0.4.25"], false)
}

pub(crate) fn close_match_callable_pack()
-> brokk_bifrost_analysis::analyzer::semantic_model::CompiledSemanticModelPack {
    rust_dependency_compiled_pack("complete", true, true)
}

pub(crate) fn exact_other_callable_pack()
-> brokk_bifrost_analysis::analyzer::semantic_model::CompiledSemanticModelPack {
    rust_dependency_compiled_pack_for_package("complete", false, true, "other")
}

/// The close-match `widget` pack with a fieldless enum `widget::Flag` beside
/// its callable: a declaration a value-type barrier could consult if type
/// resolution read model declarations.
pub(crate) fn close_match_enum_pack()
-> brokk_bifrost_analysis::analyzer::semantic_model::CompiledSemanticModelPack {
    compile_rust_dependency_pack(
        "complete",
        true,
        true,
        "widget",
        &[serde_json::json!({
            "id": "type.widget.flag", "name": "Flag", "type_kind": "enum",
            "visibility": "public", "aliases": [],
            "locator": {"kind": "artifact", "path": "rustdoc/api.json", "symbol": "widget.Flag"}
        })],
        0,
    )
}

fn rust_dependency_compiled_pack(
    completeness: &str,
    approximate: bool,
    include_callable: bool,
) -> brokk_bifrost_analysis::analyzer::semantic_model::CompiledSemanticModelPack {
    rust_dependency_compiled_pack_for_package(completeness, approximate, include_callable, "widget")
}

fn rust_dependency_compiled_pack_for_package(
    completeness: &str,
    approximate: bool,
    include_callable: bool,
    package: &str,
) -> brokk_bifrost_analysis::analyzer::semantic_model::CompiledSemanticModelPack {
    compile_rust_dependency_pack(completeness, approximate, include_callable, package, &[], 0)
}

/// The close-match `widget` pack whose `build` takes one positional argument,
/// so a call that passes a value to it binds completely.
pub(crate) fn close_match_unary_callable_pack()
-> brokk_bifrost_analysis::analyzer::semantic_model::CompiledSemanticModelPack {
    compile_rust_dependency_pack("complete", true, true, "widget", &[], 1)
}

/// The exact `other` pack whose `build` takes one positional argument.
pub(crate) fn exact_other_unary_callable_pack()
-> brokk_bifrost_analysis::analyzer::semantic_model::CompiledSemanticModelPack {
    compile_rust_dependency_pack("complete", false, true, "other", &[], 1)
}

/// A pack whose one complete `std.string.String.replace` summary covers
/// overrides, activated by the `widget` package. Close-match when
/// `approximate`, exact otherwise. It declares no type or member, so a call it
/// makes exact takes its declaration from another pack.
pub(crate) fn widget_override_summary_pack(
    approximate: bool,
) -> brokk_bifrost_analysis::analyzer::semantic_model::CompiledSemanticModelPack {
    use brokk_bifrost_analysis::analyzer::semantic_model::{
        CompilerOptions, RustArtifactApproximation, RustArtifactMismatchKind, SourceFormat,
        compile_source,
    };
    use serde_json::json;
    let (provenance, compatibility) = if approximate {
        let claim = RustArtifactApproximation {
            built_from_version: "0.4.23".to_owned(),
            built_from_features: vec!["std".to_owned()],
            built_from_cfgs: vec!["docsrs".to_owned()],
            target: "x86_64-unknown-linux-gnu".to_owned(),
            format_version: 61,
            toolchain: "nightly-2026-08-24".to_owned(),
            docsrs_build: true,
            original_sha256: "11".repeat(32),
            produced_sha256: "11".repeat(32),
            activation_version_requirement: ">=0.4.0, <0.5.0".to_owned(),
            mismatch_kinds: vec![RustArtifactMismatchKind::VersionNearby],
            selection_rule_id: "cargo-compatible-nearest".to_owned(),
            selection_rule_version: 1,
        };
        (
            json!({"source": "test:close-match", "rust_artifact_approximation": claim}),
            json!({"toolchains": []}),
        )
    } else {
        (
            json!({"source": "test:exact"}),
            json!({"bifrost": "*", "toolchains": []}),
        )
    };
    let source = json!({
        "schema_version": if approximate { 28 } else { 2 },
        "pack_id": "test.widget-replace-summary",
        "version": "1.0.0",
        "producer": {"name": "test-fixture", "version": "1.0.0"},
        "language": "rust", "ecosystem": "cargo",
        "compatibility": compatibility,
        "provenance": provenance,
        "license": "NOASSERTION", "completeness": "complete",
        "safety": {"generated_code_only": false, "review_required": false},
        "shards": [{
            "id": "summaries.rust.replace",
            "activation": [{"package": {"name": "widget"}}],
            "payload": {
                "kind": "procedure_summaries",
                "summaries": [{
                    "id": "summary.widget.string-replace",
                    "target": {
                        "path": "library/alloc/src/string.rs",
                        "symbol": "std.string.String.replace",
                        "has_receiver": true,
                        "parameter_count": 2
                    },
                    "completeness": "complete",
                    "covers_overrides": true,
                    "locations": [],
                    "transfers": [{
                        "input": {"kind": "parameter", "ordinal": 0},
                        "exit_kind": "normal",
                        "output": {"kind": "normal_return"}
                    }],
                    "effects": []
                }]
            }
        }]
    });
    compile_source(
        SourceFormat::Json,
        &serde_json::to_vec(&source).unwrap(),
        &CompilerOptions::default(),
    )
    .unwrap_or_else(|diagnostics| panic!("override summary fixture: {diagnostics:#?}"))
}

fn compile_rust_dependency_pack(
    completeness: &str,
    approximate: bool,
    include_callable: bool,
    package: &str,
    extra_types: &[serde_json::Value],
    callable_parameters: usize,
) -> brokk_bifrost_analysis::analyzer::semantic_model::CompiledSemanticModelPack {
    use brokk_bifrost_analysis::analyzer::semantic_model::{
        CompilerOptions, RustArtifactApproximation, RustArtifactMismatchKind, SourceFormat,
        compile_source,
    };
    use serde_json::json;
    let approximation = RustArtifactApproximation {
        built_from_version: "0.4.23".to_owned(),
        built_from_features: vec!["std".to_owned()],
        built_from_cfgs: vec!["docsrs".to_owned()],
        target: "x86_64-unknown-linux-gnu".to_owned(),
        format_version: 61,
        toolchain: "nightly-2026-08-24".to_owned(),
        docsrs_build: true,
        original_sha256: "11".repeat(32),
        produced_sha256: "11".repeat(32),
        activation_version_requirement: ">=0.4.0, <0.5.0".to_owned(),
        mismatch_kinds: vec![RustArtifactMismatchKind::VersionNearby],
        selection_rule_id: "cargo-compatible-nearest".to_owned(),
        selection_rule_version: 1,
    };
    let provenance = if approximate {
        json!({"source": "test:close-match", "rust_artifact_approximation": approximation})
    } else {
        json!({"source": "test:exact"})
    };
    let compatibility = if approximate {
        json!({"toolchains": []})
    } else {
        json!({"bifrost": "*", "toolchains": []})
    };
    let members = if include_callable {
        vec![json!({
            "id": format!("member.{package}.build"), "owner": format!("type.{package}.root"),
            "name": "build", "member_kind": "function", "visibility": "public",
            "is_static": true,
            "signature": {"parameters": (0..callable_parameters).map(|_| json!({
                "type": {"kind": "named", "name": "()"}, "passing_mode": "positional_only"
            })).collect::<Vec<_>>()},
            "locator": {"kind": "artifact", "path": "rustdoc/api.json", "symbol": format!("{package}.build")}
        })]
    } else {
        Vec::new()
    };
    let mut types = vec![json!({
        "id": format!("type.{package}.root"), "name": package, "type_kind": "module",
        "visibility": "public", "aliases": [],
        "locator": {"kind": "artifact", "path": "rustdoc/api.json", "symbol": package}
    })];
    types.extend(extra_types.iter().cloned());
    let source = json!({
        "schema_version": if approximate { 28 } else { 2 },
        "pack_id": if package == "widget" { "test.close-match-widget".to_owned() } else { format!("test.exact-{package}") },
        "version": "1.0.0",
        "producer": {"name": "test-fixture", "version": "1.0.0"},
        "language": "rust", "ecosystem": "cargo",
        "compatibility": compatibility,
        "provenance": provenance,
        "license": "NOASSERTION", "completeness": completeness,
        "safety": {"generated_code_only": false, "review_required": false},
        "shards": [{
            "id": "declarations.rust.external",
            "activation": [{"package": {"name": package}}],
            "payload": {"kind": "declaration_facts", "types": types, "members": members, "relations": []}
        }]
    });
    compile_source(
        SourceFormat::Json,
        &serde_json::to_vec(&source).unwrap(),
        &CompilerOptions::default(),
    )
    .unwrap_or_else(|diagnostics| panic!("close-match fixture: {diagnostics:#?}"))
}

fn rust_dependency_snapshot(
    completeness: &str,
    approximate: bool,
    versions: &[&str],
    include_callable: bool,
) -> std::sync::Arc<brokk_bifrost_analysis::analyzer::semantic_model::ActiveSemanticModelSnapshot> {
    use brokk_bifrost_analysis::analyzer::semantic_model::{
        CatalogCoordinate, CatalogPackSourceKind, SemanticModelActivationEvidence,
        test_snapshot_from_compiled_pack_with_evidences,
    };
    let compiled = rust_dependency_compiled_pack(completeness, approximate, include_callable);
    let evidences = versions
        .iter()
        .map(|version| SemanticModelActivationEvidence {
            language: "rust".to_owned(),
            ecosystem: "cargo".to_owned(),
            package: Some(CatalogCoordinate {
                name: "widget".to_owned(),
                version: Some(semver::Version::parse(version).unwrap()),
            }),
            module: None,
            toolchain: None,
            target: Some("x86_64-unknown-linux-gnu".to_owned()),
            configuration: None,
            artifact_sha256: None,
        })
        .collect();
    test_snapshot_from_compiled_pack_with_evidences(
        compiled,
        evidences,
        CatalogPackSourceKind::EphemeralWorkspace,
    )
}

#[path = "../../../test-support/cvss_vectors.rs"]
pub(crate) mod cvss_vectors;

pub(crate) fn evaluation_options(date: &str) -> crate::PolicyEvaluationOptions {
    crate::PolicyEvaluationOptions::new(date.parse().expect("fixed test date"))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn resolved_endpoint_dependency(
    identity: ResolvedEndpointIdentity,
    definition_schema: SchemaVersionResolution,
    selector_path: PolicySelectorPath,
    selector_schema: SchemaVersionResolution,
    model: ResolvedEndpointModel,
    origin_path: PolicyDependencyPath,
    semantic_hash_seed: u8,
    projection_hash_seed: u8,
) -> ResolvedEndpointDependency {
    ResolvedEndpointDependency::new(
        identity,
        EndpointDefinitionSchemaResolution::PolicyDocument {
            resolution: definition_schema,
        },
        selector_path,
        ResolvedEndpointSelectorSchemas::Query(selector_schema),
        model,
        EndpointSemanticHash::from_bytes([semantic_hash_seed; 32]),
        EndpointAnalysisProjectionHash::from_bytes([projection_hash_seed; 32]),
        vec![EndpointOrigin::PolicyLocal { path: origin_path }],
    )
}

pub(crate) fn registry_with_policy(
    identity: &str,
    source: &str,
    invalid_message: &str,
) -> PolicyRegistry {
    registry_with_policies(&[(identity, source)], invalid_message)
}

pub(crate) fn registry_with_policies<S: AsRef<str>>(
    sources: &[(&str, S)],
    invalid_message: &str,
) -> PolicyRegistry {
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    for (identity, source) in sources {
        registry
            .register_policy_bytes(
                PolicySourceIdentity::new(*identity),
                source.as_ref().as_bytes(),
            )
            .expect(invalid_message);
    }
    registry
}

pub(crate) fn report_with_run_completion(
    source_identity: &str,
    source: &str,
    completion: PolicyRunCompletion,
) -> PolicyReportDocument {
    let registry = registry_with_policy(source_identity, source, "valid test policy");
    let policy = registry.policies().next().expect("one policy");
    let descriptor = PolicyRuleDescriptor::from_loaded(policy);
    let run = PolicyRun::try_new(
        policy.definition().metadata.id.clone(),
        policy.semantic_hash(),
        policy.definition().analysis.analysis_type(),
        completion,
        Vec::new(),
        Vec::new(),
        false,
        PolicyWorkReport::default(),
        &PolicyBudget::default(),
    )
    .expect("synthetic run");
    PolicyReportDocument::try_new(vec![descriptor], vec![run], Vec::new(), false, 0, None)
        .expect("canonical report")
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn taint_source_projection_fact(
    identity: crate::resolved::ResolvedEndpointIdentity,
    semantic_hash: EndpointSemanticHash,
    analysis_projection_hash: EndpointAnalysisProjectionHash,
    display_name: String,
    categories: Vec<PolicyCategoryId>,
    label: TaintLabel,
    evidence: Option<crate::definition::TaintSourceEvidence>,
    scenarios: Vec<crate::finding_identity::SourceScenarioId>,
    evidence_ref: EvidenceRef,
) -> crate::future_evidence::TaintSourceProjectionFact {
    crate::future_evidence::TaintSourceProjectionFact::try_new(
        identity,
        semantic_hash,
        analysis_projection_hash,
        display_name,
        categories,
        label,
        evidence,
        scenarios,
        evidence_ref,
    )
    .unwrap()
}

pub(crate) fn cvss_base_metric_token(metric: CvssBaseMetric) -> CvssMetricValueToken {
    match metric {
        CvssBaseMetric::Ac => CvssMetricValueToken::L,
        CvssBaseMetric::At | CvssBaseMetric::Av | CvssBaseMetric::Pr | CvssBaseMetric::Ui => {
            CvssMetricValueToken::N
        }
        CvssBaseMetric::Vc
        | CvssBaseMetric::Vi
        | CvssBaseMetric::Va
        | CvssBaseMetric::Sc
        | CvssBaseMetric::Si
        | CvssBaseMetric::Sa => CvssMetricValueToken::H,
    }
}

pub(crate) fn cvss_base_metric_value(metric: CvssBaseMetric) -> CvssMetricValue {
    CvssMetricValue::try_new(CvssMetric::Base { metric }, cvss_base_metric_token(metric)).unwrap()
}

pub(crate) fn cvss_test_metric_evidence(
    metric: CvssBaseMetric,
    byte: u8,
    evidence_namespace: &str,
) -> CvssMetricEvidence {
    CvssMetricEvidence::try_new(
        CvssMetric::Base { metric },
        cvss_base_metric_value(metric),
        CvssEvidenceBasis::PolicyAssertion,
        vec![EvidenceRef::try_new(evidence_namespace, metric.first_label()).unwrap()],
        "Verified policy assertion".to_owned(),
        vec!["Deployment matches the policy model".to_owned()],
        "bifrost-policy".to_owned(),
        None,
        metric.required_scope(),
        CvssEvidenceContentHash::from_bytes([byte; 32]),
    )
    .unwrap()
}

pub(crate) fn error_at(source: &str, code: &str, token: &str) {
    let error = parse_rqlp_source(source, PolicySourceIdentity::new("test.rqlp"))
        .expect_err("the policy must be rejected")
        .diagnostic;
    assert_eq!(error.code, code, "diagnostic: {error:?}");
    assert_eq!(&source[error.range], token);
}

pub(crate) fn parse_rqlp_document(source: &str) -> RqlpDocument {
    parse_rqlp_source(source, PolicySourceIdentity::new("test.rqlp"))
        .expect("the test policy parses")
        .document()
        .clone()
}

pub(crate) fn cvss_assessment_provenance() -> crate::CvssAssessmentProvenance {
    crate::CvssAssessmentProvenance::try_new(
        "bifrost.cvss-v4".to_string(),
        Vec::new(),
        vec![crate::PolicyOverlayScope::AllFindings],
        Vec::new(),
    )
    .unwrap()
}

pub(crate) fn load_match_policy(source: &str) -> LoadedPolicy {
    let identity = PolicySourceIdentity::new("policy.rqlp");
    let parsed = parse_rqlp_source(source, identity.clone()).unwrap();
    let schema_resolution = parsed.schema_resolution();
    let RqlpDocument::Policy { definition } = parsed.into_document() else {
        panic!("fixture must be a policy");
    };
    let definition = *definition;
    let PolicyAnalysis::Match { spec } = &definition.analysis else {
        panic!("fixture must be a match policy");
    };
    let PolicySelector::Inline { schema, query, .. } = &spec.selector else {
        panic!("fixture selector must be inline");
    };
    let selector = ResolvedPolicySelector::try_new(
        PolicySelectorPath::new("/analysis/selector").unwrap(),
        *schema,
        query.clone(),
        SelectorOrigin::Document {
            source: identity.clone(),
        },
    )
    .unwrap();
    LoadedPolicy::try_new(
        definition,
        identity,
        source.as_bytes(),
        schema_resolution,
        vec![selector],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        PolicyPrecedenceManifest::default(),
        None,
        None,
        None,
    )
    .unwrap()
}

pub(crate) fn inline_match_selector(name: &str) -> PolicySelector {
    PolicySelector::Inline {
        schema: SchemaVersionResolution {
            version: SCHEMA_VERSION as u32,
            origin: SchemaVersionOrigin::Explicit,
        },
        query: CodeQuery::from_sexp(&format!(r#"(call :callee (name "{name}"))"#)).unwrap(),
        resolved_locators: Vec::new(),
    }
}

pub(crate) fn taint_source_spec(
    id: &str,
    display_name: &str,
    selector_name: &str,
    label: &str,
) -> TaintSourceSpec {
    TaintSourceSpec {
        id: TaintEntryId::new(id).unwrap(),
        display_name: display_name.to_string(),
        categories: vec![PolicyCategoryId::new("input.user").unwrap()],
        selector: inline_match_selector(selector_name),
        bind: PolicyPort::ReturnValue,
        labels: vec![TaintLabel::new(label).unwrap()],
        threat_model: None,
        evidence: None,
    }
}

pub(crate) fn policy_test_location(
    path: &str,
    start_byte: u64,
    end_byte: u64,
    line: u64,
) -> crate::finding::PolicySourceLocation {
    crate::finding::PolicySourceLocation::span(
        brokk_bifrost_analysis::analyzer::semantic::WorkspaceRelativePath::new(path).unwrap(),
        crate::finding::PolicyByteSpan::new(start_byte, end_byte).unwrap(),
        crate::finding::PolicyDisplayRegion::new(line, 1, line, 2).unwrap(),
    )
}

pub(crate) fn projected_finding_report(
    primary: crate::finding::PolicySourceLocation,
    proof_reason: crate::finding::ProofReason,
) -> crate::projection::ProjectedFindingReport {
    crate::projection::ProjectedFindingReport {
        value_type_barrier_notes: Default::default(),
        primary,
        certainty: crate::finding::FindingCertainty::Definite,
        completeness: crate::finding::FindingCompleteness::Complete,
        related: Vec::new(),
        related_truncated: false,
        omitted_related_locations_lower_bound: 0,
        evidence_refs_truncated: false,
        omitted_evidence_refs_lower_bound: 0,
        proof: crate::finding::ProofMetadata::try_new(
            crate::finding::ProofState::Proven,
            vec![proof_reason],
            Vec::new(),
        )
        .unwrap(),
        witnesses: Vec::new(),
        witnesses_truncated: false,
        omitted_witnesses_lower_bound: 0,
        display_path: None,
    }
}

pub(crate) fn typestate_policy_source(id: &str, name: &str) -> String {
    format!(
        r#"(policy
          :id "{id}"
          :name "{name}"
          :message "Resource was not closed"
          :severity error
          :analysis (analysis
            :type typestate
            :mode may
            :subjects (subject-set :entries [
              (subject :id resource :selector (rql (name "resource"))
                :subject return-value)])
            :uncertainty (uncertainty :escape inconclusive)
            :automaton (automaton
              :states [open closed violated]
              :initial open
              :accepting-states [closed]
              :error-states [violated]
              :events [
                (event :id finish :on (normal-procedure-exit :scope analysis-root))]
              :transitions [
                (transition :from open :on finish :to closed)]
              :terminal-expectations [
                (terminal-expectation :id normal-exit
                  :on (normal-procedure-exit :scope analysis-root)
                  :expected-states [closed])])))"#
    )
}
