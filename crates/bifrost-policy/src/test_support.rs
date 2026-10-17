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
