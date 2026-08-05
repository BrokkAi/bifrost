use std::sync::Arc;

use super::*;
use crate::catalog::{CatalogRegistryLimits, TaintCatalogRegistry};
use crate::definition::{
    PolicySemanticEvent, TaintLabel, TypestateExitScope, TypestateExpectationId, TypestateStateId,
};
use crate::finding_identity::{
    AnalysisEventRef, AnalysisFindingId, AnalysisSubjectRef, StableSemanticIdentity,
    TypestateScenarioId,
};
use crate::future_evidence::{
    ResolvedTypestateTerminal, TaintFindingAnchor, TaintPolicyProjectionFacts,
    TaintSourceProjectionFact, TypestateBindingPlanHash, TypestateFindingAnchor,
    TypestatePolicyProjectionFacts, TypestateProtocolHash,
};
use crate::projection::{
    ProjectedFindingReport, TaintOriginProjection, TaintPairProjection, TaintProjectedFinding,
    TypestateProjectedFinding,
};
use crate::registry::{PolicyRegistry, PolicyRegistryLimits};
use crate::source::PolicySourceIdentity;
use crate::{CvssMetricValueToken, EvidenceRef};
use brokk_bifrost_analysis::analyzer::Language;
use brokk_bifrost_analysis::analyzer::structural::search::{
    CodeQueryStableOwnerCandidate, execute_code_query_detailed,
};
use brokk_bifrost_analysis::analyzer::structural::{
    CodeQuery, CodeQueryCallSite, CodeQueryDeclaration,
};
use brokk_bifrost_analysis::analyzer::{ProjectFile, TestProject, TypescriptAnalyzer};
use serde_json::json;

fn risk(rating: &str, refs: &[&str]) -> OrganizationalRiskAssessment {
    OrganizationalRiskAssessment::try_new(
        "test-risk".to_string(),
        rating.to_string(),
        format!("{rating} rationale"),
        refs.iter()
            .map(|value| EvidenceRef::try_new("risk", value).unwrap())
            .collect(),
        None,
    )
    .unwrap()
}

fn classified_match_run(source: &str, budget: PolicyBudget) -> PolicyRun {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), "app.ts")
        .write(source)
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let policy_source = r#"(policy
          :id "test.classified-retention"
          :name "Classified retention"
          :message "Matched alpha"
          :severity warning
          :analysis (analysis
            :type match
            :selector (rql (language typescript (call :callee (name "alpha")))))
          :classification (classification
            :fallback (classification-id :taxonomy "Test" :id "BROAD")
            :refinements [
              (refinement
                :when (analysis-type :is match)
                :add [(classification-id :taxonomy "CWE" :id "CWE-1")])]))"#;
    let registry = policy_registry("test:classified-retention", policy_source);
    let policy = registry.policies().next().unwrap();
    let context = PolicyEvaluationContext {
        analyzer: &analyzer,
        workspace: None,
        cancellation: None,
        cvss_overlays: &[],
        organizational_risk: &[],
    };
    let mut budget = budget;
    DefaultPolicyEvaluator::new()
        .evaluate(policy, &context, &mut budget)
        .unwrap()
}

fn policy_registry(identity: &str, source: &str) -> PolicyRegistry {
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    registry
        .register_policy_bytes(PolicySourceIdentity::new(identity), source.as_bytes())
        .unwrap();
    registry
}

fn assembly_analyzer() -> (tempfile::TempDir, TypescriptAnalyzer) {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), "app.ts")
        .write("export function run() {}\n")
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    (temp, analyzer)
}

struct SizedEvidence(usize);

impl RetainedSize for SizedEvidence {
    fn retained_size(&self) -> usize {
        self.0
    }
}

fn projection_location() -> PolicySourceLocation {
    PolicySourceLocation::span(
        WorkspaceRelativePath::new("app.ts").unwrap(),
        PolicyByteSpan::new(0, 1).unwrap(),
        PolicyDisplayRegion::new(1, 1, 1, 2).unwrap(),
    )
}

fn projected_report(proof_reason: ProofReason) -> ProjectedFindingReport {
    ProjectedFindingReport {
        primary: projection_location(),
        certainty: FindingCertainty::Definite,
        completeness: FindingCompleteness::Complete,
        related: Vec::new(),
        related_truncated: false,
        omitted_related_locations_lower_bound: 0,
        evidence_refs_truncated: false,
        omitted_evidence_refs_lower_bound: 0,
        proof: ProofMetadata::try_new(ProofState::Proven, vec![proof_reason], Vec::new()).unwrap(),
        witnesses: Vec::new(),
        witnesses_truncated: false,
        omitted_witnesses_lower_bound: 0,
    }
}

fn taint_policy_source() -> &'static str {
    r#"(policy
          :id "test.taint-assembly"
          :name "Taint assembly"
          :message (generated-message :relation can-reach)
          :severity warning
          :analysis (analysis
            :type taint
            :mode may
            :sources (endpoint-set :entries [
              (source :id alpha :display-name "user input" :categories [input.user]
                :selector (rql (name "alpha")) :bind return-value :labels [untrusted])])
            :sinks (endpoint-set :entries [
              (sink :id store :display-name "sensitive store" :categories [data.sensitive]
                :selector (rql (name "store")) :dangerous-operand matched-value
                :accepts [untrusted])]))
          :classification (classification
            :fallback (classification-id :taxonomy "Test" :id "TAINT")
            :cvss (cvss
              :version "4.0"
              :emit when-base-complete
              :metric-rules [
                (metric :name AV :value N
                  :when (analysis-type :is taint)
                  :basis policy-assertion
                  :scope vulnerable-system
                  :evidence-refs [policy:self]
                  :rationale "The sink is reachable over the network")])))"#
}

fn typestate_policy_source() -> &'static str {
    r#"(policy
          :id "test.typestate-assembly"
          :name "Typestate assembly"
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
}

fn raw_taint_projection(
    spec: &ResolvedTaintPolicySpec,
    sink_key: &str,
    scenarios: Vec<SourceScenarioId>,
    origins_truncated: bool,
) -> TaintProjectedFinding {
    let source = &spec.sources[0];
    let sink = &spec.sinks[0];
    let evidence_ref = EvidenceRef::try_new("test", "source-alpha").unwrap();
    let source_fact = TaintSourceProjectionFact::try_new(
        source.identity.clone(),
        source.semantic_hash,
        source.analysis_projection_hash,
        source.definition.display_name.clone(),
        source.definition.categories.clone(),
        TaintLabel::new("untrusted").unwrap(),
        source.definition.evidence.clone(),
        scenarios.clone(),
        evidence_ref.clone(),
    )
    .unwrap();
    let facts = TaintPolicyProjectionFacts::try_new(
        sink.identity.clone(),
        sink.semantic_hash,
        sink.analysis_projection_hash,
        sink.definition.display_name.clone(),
        sink.definition.categories.clone(),
        sink.definition.tags.clone(),
        sink.definition.impacts.clone(),
        vec![TaintLabel::new("untrusted").unwrap()],
        vec![source_fact.clone()],
        &PolicyBudget::default(),
    )
    .unwrap();
    let scenario_hash =
        super::super::cvss::SourceScenarioSetHash::try_from_scenarios(scenarios.clone()).unwrap();
    let sink_identity = StableSemanticIdentity::analyzer_declaration_id(
        "typescript",
        WorkspaceRelativePath::new("app.ts").unwrap(),
        format!("function:{sink_key}"),
    )
    .unwrap();
    let anchor = TaintFindingAnchor::strong(
        sink_identity,
        source.analysis_projection_hash,
        sink.analysis_projection_hash,
        scenario_hash,
    )
    .unwrap();
    let origins = if origins_truncated {
        Vec::new()
    } else {
        scenarios
            .into_iter()
            .map(|scenario_id| TaintOriginProjection {
                source_endpoint: source.identity.clone(),
                source_label: TaintLabel::new("untrusted").unwrap(),
                source_evidence: source.definition.evidence.clone(),
                primary: projection_location(),
                scenario_id,
                evidence_refs: vec![evidence_ref.clone()],
            })
            .collect()
    };
    let pair = TaintPairProjection {
        source_endpoint: source.identity.clone(),
        analysis_finding_id: AnalysisFindingId::try_new("test", sink_key).unwrap(),
        anchor,
        sink: AnalysisEventRef::try_new("test", sink_key).unwrap(),
        origins,
        origins_truncated,
        witness_refs: Vec::new(),
        witness_refs_truncated: false,
        report: projected_report(ProofReason::DataflowWitness),
    };
    TaintProjectedFinding {
        facts,
        pairs: vec![pair],
    }
}

fn raw_typestate_projection(
    spec: &ResolvedTypestatePolicySpec,
    protocol_hash: TypestateProtocolHash,
    binding_plan_hash: TypestateBindingPlanHash,
) -> TypestateProjectedFinding {
    let subject = &spec.subjects[0];
    let dependency = spec
        .endpoint_dependencies
        .iter()
        .find(|dependency| dependency.identity() == &subject.identity)
        .unwrap();
    let site = StableSemanticIdentity::protocol_violation_site(
        "typescript",
        WorkspaceRelativePath::new("app.ts").unwrap(),
        "normal-exit",
    )
    .unwrap();
    let violation = TypestateViolationEvidence::try_terminal_expectation(
        TypestateExpectationId::new("normal-exit").unwrap(),
        ResolvedTypestateTerminal::SemanticEvent {
            event: PolicySemanticEvent::NormalProcedureExit {
                scope: TypestateExitScope::AnalysisRoot,
            },
        },
        TypestateStateId::new("open").unwrap(),
        vec![TypestateStateId::new("closed").unwrap()],
    )
    .unwrap();
    let facts = TypestatePolicyProjectionFacts::try_new(
        spec.authoring_projection_hash,
        protocol_hash,
        binding_plan_hash,
        subject.identity.clone(),
        subject.semantic_hash,
        subject.analysis_projection_hash,
        dependency.model().categories.clone(),
        dependency.model().display_name.clone(),
        Some(site.clone()),
        violation.clone(),
        vec![TypestateScenarioId::try_new("test", "root").unwrap()],
        &PolicyBudget::default(),
    )
    .unwrap();
    let subject_identity = StableSemanticIdentity::protocol_subject(
        "typescript",
        WorkspaceRelativePath::new("app.ts").unwrap(),
        "resource-instance",
    )
    .unwrap();
    let anchor = TypestateFindingAnchor::strong(
        protocol_hash,
        binding_plan_hash,
        subject_identity,
        site,
        facts.scenario_set_hash,
        &violation,
    )
    .unwrap();
    TypestateProjectedFinding {
        facts,
        analysis_finding_id: AnalysisFindingId::try_new("test", "typestate-finding").unwrap(),
        anchor,
        subject: AnalysisSubjectRef::try_new("test", "resource-instance").unwrap(),
        witness_refs: Vec::new(),
        witness_refs_truncated: false,
        report: projected_report(ProofReason::TypestateWitness),
    }
}

struct FakeTaintAdapter {
    sink_key: &'static str,
    scenarios: Vec<SourceScenarioId>,
    origins_truncated: bool,
    completion: PolicyRunCompletion,
}

impl FakeTaintAdapter {
    fn complete(
        sink_key: &'static str,
        scenarios: Vec<SourceScenarioId>,
        origins_truncated: bool,
    ) -> Self {
        Self {
            sink_key,
            scenarios,
            origins_truncated,
            completion: PolicyRunCompletion::Complete,
        }
    }
}

impl crate::projection::sealed::TaintAdapter for FakeTaintAdapter {}

impl TaintPolicyEvaluator for FakeTaintAdapter {
    fn evaluate_taint(
        &self,
        _authority: &TaintProjectionAuthority,
        _policy: &LoadedPolicy,
        spec: &ResolvedTaintPolicySpec,
        _context: &PolicyEvaluationContext<'_>,
        _budget: &PolicyBudget,
    ) -> TaintProjectionPayload {
        TaintProjectionPayload {
            projections: vec![raw_taint_projection(
                spec,
                self.sink_key,
                self.scenarios.clone(),
                self.origins_truncated,
            )],
            completion: self.completion.clone(),
            diagnostics: Vec::new(),
            diagnostics_truncated: false,
            work: PolicyWorkReport::default(),
        }
    }
}

struct FakeTypestateAdapter {
    protocol_hash: TypestateProtocolHash,
    binding_plan_hash: TypestateBindingPlanHash,
}

impl crate::projection::sealed::TypestateAdapter for FakeTypestateAdapter {}

impl TypestatePolicyEvaluator for FakeTypestateAdapter {
    fn compilation_hashes(
        &self,
        _policy: &LoadedPolicy,
        _spec: &ResolvedTypestatePolicySpec,
        _context: &PolicyEvaluationContext<'_>,
        _budget: &PolicyBudget,
    ) -> Result<TypestateCompilationHashes, TypestateCompilationFailure> {
        Ok(TypestateCompilationHashes::new(
            self.protocol_hash,
            self.binding_plan_hash,
        ))
    }

    fn evaluate_typestate(
        &self,
        _authority: &TypestateProjectionAuthority,
        _policy: &LoadedPolicy,
        spec: &ResolvedTypestatePolicySpec,
        _context: &PolicyEvaluationContext<'_>,
        _budget: &PolicyBudget,
    ) -> TypestateProjectionPayload {
        TypestateProjectionPayload {
            projections: vec![raw_typestate_projection(
                spec,
                self.protocol_hash,
                self.binding_plan_hash,
            )],
            completion: PolicyRunCompletion::Complete,
            diagnostics: Vec::new(),
            diagnostics_truncated: false,
            work: PolicyWorkReport::default(),
        }
    }
}

struct IncompleteTypestateAdapter;

impl crate::projection::sealed::TypestateAdapter for IncompleteTypestateAdapter {}

impl TypestatePolicyEvaluator for IncompleteTypestateAdapter {
    fn compilation_hashes(
        &self,
        _policy: &LoadedPolicy,
        _spec: &ResolvedTypestatePolicySpec,
        _context: &PolicyEvaluationContext<'_>,
        _budget: &PolicyBudget,
    ) -> Result<TypestateCompilationHashes, TypestateCompilationFailure> {
        Err(TypestateCompilationFailure::incomplete_many_with_work(
            vec![
                PolicyIncompleteReason::PartialDiscovery,
                PolicyIncompleteReason::Cancelled,
                PolicyIncompleteReason::PartialDiscovery,
            ],
            "typestate selector execution was cancelled",
            PolicyWorkReport::try_new(7, 11, 13, 17, 19, 0, 0, 0, Vec::new())
                .expect("valid compilation work report"),
        ))
    }

    fn evaluate_typestate(
        &self,
        _authority: &TypestateProjectionAuthority,
        _policy: &LoadedPolicy,
        _spec: &ResolvedTypestatePolicySpec,
        _context: &PolicyEvaluationContext<'_>,
        _budget: &PolicyBudget,
    ) -> TypestateProjectionPayload {
        unreachable!("incomplete compilation must stop before evaluation")
    }
}

#[test]
fn typestate_compilation_incompleteness_remains_typed_and_non_clean() {
    let (_temp, analyzer) = assembly_analyzer();
    let registry = policy_registry("test:typestate-incomplete", typestate_policy_source());
    let policy = registry.policies().next().unwrap();
    let adapter = IncompleteTypestateAdapter;
    let run = DefaultPolicyEvaluator::new()
        .with_typestate(&adapter)
        .evaluate(
            policy,
            &PolicyEvaluationContext {
                analyzer: &analyzer,
                workspace: None,
                cancellation: None,
                cvss_overlays: &[],
                organizational_risk: &[],
            },
            &mut PolicyBudget::default(),
        )
        .unwrap();

    assert_eq!(
        run.completion(),
        &PolicyRunCompletion::Inconclusive {
            reasons: vec![
                PolicyIncompleteReason::Cancelled,
                PolicyIncompleteReason::PartialDiscovery,
            ],
        }
    );
    assert_eq!(run.diagnostics().len(), 1);
    assert_eq!(run.work().scanned_files(), 7);
    assert_eq!(run.work().scanned_source_bytes(), 11);
    assert_eq!(run.work().fact_nodes(), 13);
    assert_eq!(run.work().pipeline_rows(), 17);
    assert_eq!(run.work().examined_references(), 19);
    assert_eq!(
        run.diagnostics()[0].impact(),
        PolicyDiagnosticImpact::RunIncomplete
    );
}

#[test]
fn default_evaluator_dispatches_valid_taint_and_typestate_adapters() {
    let (_temp, analyzer) = assembly_analyzer();
    let context = PolicyEvaluationContext {
        analyzer: &analyzer,
        workspace: None,
        cancellation: None,
        cvss_overlays: &[],
        organizational_risk: &[],
    };

    let taint_registry = policy_registry("test:taint-assembly", taint_policy_source());
    let taint_policy = taint_registry.policies().next().unwrap();
    let taint_adapter = FakeTaintAdapter::complete(
        "sink-valid",
        vec![SourceScenarioId::try_new("test", "root").unwrap()],
        false,
    );
    let protocol_hash = TypestateProtocolHash::from_canonical_bytes(b"protocol");
    let binding_plan_hash = TypestateBindingPlanHash::from_canonical_bytes(b"bindings");
    let typestate_adapter = FakeTypestateAdapter {
        protocol_hash,
        binding_plan_hash,
    };
    let evaluator = DefaultPolicyEvaluator::new()
        .with_taint(&taint_adapter)
        .with_typestate(&typestate_adapter);
    let mut budget = PolicyBudget::default();
    let taint_run = evaluator
        .evaluate(taint_policy, &context, &mut budget)
        .unwrap();
    assert_eq!(taint_run.completion(), &PolicyRunCompletion::Complete);
    assert_eq!(taint_run.findings().len(), 1);
    assert_eq!(
        taint_run.findings()[0].message(),
        "user input can reach sensitive store"
    );
    assert!(matches!(
        taint_run.findings()[0].evidence(),
        PolicyFindingEvidence::Taint { .. }
    ));

    let typestate_registry = policy_registry("test:typestate-assembly", typestate_policy_source());
    let typestate_policy = typestate_registry.policies().next().unwrap();
    let mut budget = PolicyBudget::default();
    let typestate_run = evaluator
        .evaluate(typestate_policy, &context, &mut budget)
        .unwrap();
    assert_eq!(typestate_run.completion(), &PolicyRunCompletion::Complete);
    assert_eq!(typestate_run.findings().len(), 1);
    assert_eq!(
        typestate_run.findings()[0].message(),
        "Resource was not closed"
    );
    assert!(matches!(
        typestate_run.findings()[0].evidence(),
        PolicyFindingEvidence::Typestate { .. }
    ));
}

#[test]
fn duplicate_taint_projection_fails_but_preserves_unrelated_strong_positive() {
    let (_temp, analyzer) = assembly_analyzer();
    let registry = policy_registry("test:taint-assembly", taint_policy_source());
    let policy = registry.policies().next().unwrap();
    let authority = TaintProjectionAuthority::from_loaded(policy).unwrap();
    let scenarios = vec![SourceScenarioId::try_new("test", "root").unwrap()];
    let duplicate = raw_taint_projection(
        policy.resolved_taint().unwrap(),
        "sink-duplicate",
        scenarios.clone(),
        false,
    );
    let unique = raw_taint_projection(
        policy.resolved_taint().unwrap(),
        "sink-unique",
        scenarios,
        false,
    );
    let unique_id = PolicyFindingId::from_taint_anchor(
        &policy.definition().metadata.id,
        &unique.pairs[0].anchor,
    );
    let batch = authority.seal_batch(TaintProjectionPayload {
        projections: vec![duplicate.clone(), unique, duplicate],
        completion: PolicyRunCompletion::Complete,
        diagnostics: Vec::new(),
        diagnostics_truncated: false,
        work: PolicyWorkReport::default(),
    });
    let run = assemble_taint_projection_batch(
        policy,
        &authority,
        batch,
        &PolicyEvaluationContext {
            analyzer: &analyzer,
            workspace: None,
            cancellation: None,
            cvss_overlays: &[],
            organizational_risk: &[],
        },
        &PolicyBudget::default(),
    )
    .unwrap();

    assert!(matches!(
        run.completion(),
        PolicyRunCompletion::Failed { reasons }
            if reasons == &[PolicyFailureReason::InternalInvariant]
    ));
    assert_eq!(run.findings().len(), 1);
    assert_eq!(run.findings()[0].id(), unique_id);
}

#[test]
fn taint_assembly_keeps_cvss_scenario_display_joined_after_byte_truncation() {
    let (_temp, analyzer) = assembly_analyzer();
    let registry = policy_registry("test:taint-assembly", taint_policy_source());
    let policy = registry.policies().next().unwrap();
    let scenarios = (0..32)
        .map(|index| {
            SourceScenarioId::try_new("test", format!("scenario-{index:03}-{}", "x".repeat(220)))
                .unwrap()
        })
        .collect::<Vec<_>>();
    let adapter = FakeTaintAdapter::complete("sink-scenarios", scenarios, true);
    let evaluator = DefaultPolicyEvaluator::new().with_taint(&adapter);
    let context = PolicyEvaluationContext {
        analyzer: &analyzer,
        workspace: None,
        cancellation: None,
        cvss_overlays: &[],
        organizational_risk: &[],
    };
    let mut baseline_budget = PolicyBudget::default();
    let baseline = evaluator
        .evaluate(policy, &context, &mut baseline_budget)
        .unwrap();
    let baseline_finding = &baseline.findings()[0];
    let baseline_cvss = baseline_finding.cvss().unwrap();
    let non_cvss_bytes = baseline_finding
        .evidence()
        .retained_size()
        .saturating_add(baseline_finding.classification().retained_size())
        .saturating_add(baseline_finding.proof().retained_size());
    let evidence_cap = non_cvss_bytes
        .saturating_add(baseline_cvss.retained_size())
        .saturating_sub(1);
    let mut budget = PolicyBudget::builder()
        .with_max_evidence_bytes_per_finding(evidence_cap)
        .unwrap()
        .build()
        .unwrap();
    let run = evaluator.evaluate(policy, &context, &mut budget).unwrap();
    let finding = &run.findings()[0];
    let PolicyFindingEvidence::Taint { evidence } = finding.evidence() else {
        panic!("expected taint evidence");
    };
    let cvss = finding
        .cvss()
        .expect("CVSS retained under reduced headroom");
    assert!(cvss.has_truncated_source_scenarios());
    assert!(
        finding
            .completeness()
            .reasons()
            .contains(&FindingIncompleteReason::SourceScenariosTruncated)
    );
    assert!(cvss.variants().iter().all(|variant| {
        variant
            .source_scenarios()
            .iter()
            .all(|scenario| evidence.source_scenarios().contains(scenario))
    }));
}

#[test]
fn terminal_adapter_completion_survives_secondary_overlay_budget() {
    let (_temp, analyzer) = assembly_analyzer();
    let registry = policy_registry("test:taint-assembly", taint_policy_source());
    let policy = registry.policies().next().unwrap();
    let authority = TaintProjectionAuthority::from_loaded(policy).unwrap();
    let projection = raw_taint_projection(
        policy.resolved_taint().unwrap(),
        "sink-terminal",
        vec![SourceScenarioId::try_new("test", "root").unwrap()],
        false,
    );
    let overlays = vec![OrganizationalRiskOverlay {
        scope: PolicyOverlayScope::AllFindings,
        assessment: risk("high", &["terminal"]),
    }];
    let budget = PolicyBudget::builder()
        .with_max_organizational_risk_overlays(0)
        .unwrap()
        .build()
        .unwrap();
    let run = assemble_taint_projection_batch(
        policy,
        &authority,
        authority.seal_batch(TaintProjectionPayload {
            projections: vec![projection],
            completion: PolicyRunCompletion::Failed {
                reasons: vec![PolicyFailureReason::WorkspaceIo],
            },
            diagnostics: Vec::new(),
            diagnostics_truncated: false,
            work: PolicyWorkReport::default(),
        }),
        &PolicyEvaluationContext {
            analyzer: &analyzer,
            workspace: None,
            cancellation: None,
            cvss_overlays: &[],
            organizational_risk: &overlays,
        },
        &budget,
    )
    .unwrap();

    assert!(matches!(
        run.completion(),
        PolicyRunCompletion::Failed { reasons }
            if reasons == &[PolicyFailureReason::WorkspaceIo]
    ));
    assert_eq!(run.findings().len(), 1);
}

#[test]
fn organizational_risk_uses_scope_partial_order_and_shared_ref_retention() {
    let policy_id = PolicyId::new("test.risk").unwrap();
    let anchor = MatchFindingAnchor::strong(
        MatchResultDomain::File,
        WorkspaceRelativePath::new("src/test.rs").unwrap(),
        None,
        None,
        0,
    )
    .unwrap();
    let finding_id = PolicyFindingId::from_match_anchor(&policy_id, &anchor);
    let scenario = SourceScenarioId::try_new("test", "scenario").unwrap();
    let policy_risk = risk("high", &["shared", "policy"]);
    let overlays = vec![
        OrganizationalRiskOverlay {
            scope: PolicyOverlayScope::AllFindings,
            assessment: risk("low", &["all"]),
        },
        OrganizationalRiskOverlay {
            scope: PolicyOverlayScope::Policy {
                policy_id: policy_id.clone(),
            },
            assessment: policy_risk.clone(),
        },
        OrganizationalRiskOverlay {
            scope: PolicyOverlayScope::Finding { finding_id },
            assessment: policy_risk.clone(),
        },
    ];
    assert!(matches!(
        reduce_organizational_risk(
            &overlays,
            &policy_id,
            &finding_id,
            std::slice::from_ref(&scenario),
            &PolicyBudget::default(),
        ),
        OrganizationalRiskReduction::Selected(Some(value)) if value == policy_risk
    ));

    let mut conflicting = overlays;
    conflicting.push(OrganizationalRiskOverlay {
        scope: PolicyOverlayScope::SourceScenario {
            scenario_id: scenario,
        },
        assessment: risk("critical", &["scenario"]),
    });
    assert!(matches!(
        reduce_organizational_risk(
            &conflicting,
            &policy_id,
            &finding_id,
            &[],
            &PolicyBudget::default(),
        ),
        OrganizationalRiskReduction::Selected(Some(_))
    ));
    let scenario = SourceScenarioId::try_new("test", "scenario").unwrap();
    assert!(matches!(
        reduce_organizational_risk(
            &conflicting,
            &policy_id,
            &finding_id,
            std::slice::from_ref(&scenario),
            &PolicyBudget::default(),
        ),
        OrganizationalRiskReduction::Conflict
    ));

    let scenario_a = SourceScenarioId::try_new("test", "scenario-a").unwrap();
    let scenario_b = SourceScenarioId::try_new("test", "scenario-b").unwrap();
    let mismatched_scenarios = vec![
        OrganizationalRiskOverlay {
            scope: PolicyOverlayScope::FindingScenario {
                finding: finding_id,
                scenario: scenario_a.clone(),
            },
            assessment: risk("high", &["finding-scenario"]),
        },
        OrganizationalRiskOverlay {
            scope: PolicyOverlayScope::SourceScenario {
                scenario_id: scenario_b.clone(),
            },
            assessment: risk("critical", &["source-scenario"]),
        },
    ];
    assert!(matches!(
        reduce_organizational_risk(
            &mismatched_scenarios,
            &policy_id,
            &finding_id,
            &[scenario_a, scenario_b],
            &PolicyBudget::default(),
        ),
        OrganizationalRiskReduction::Conflict
    ));

    let mut retained = vec![EvidenceRef::try_new("risk", "shared").unwrap()];
    let budget = PolicyBudget::builder()
        .with_max_evidence_refs_per_finding(2)
        .unwrap()
        .build()
        .unwrap();
    let (filtered, omitted) = retain_organizational_risk_evidence(
        Some(risk("high", &["shared", "policy", "third"])),
        &mut retained,
        &budget,
    );
    assert_eq!(omitted.len(), 1);
    assert_eq!(filtered.unwrap().evidence_refs().len(), 2);
    assert_eq!(retained.len(), 2);
    assert_eq!(
        combined_evidence_omission_lower_bound(0, &omitted, &omitted),
        1
    );
}

#[test]
fn classified_match_finding_over_host_evidence_cap_is_omitted_not_failed() {
    let source = r#"export function run() {
    alpha();
}
"#;
    let budget = PolicyBudget::builder()
        .with_max_evidence_bytes_per_finding(0)
        .unwrap()
        .build()
        .unwrap();
    let run = classified_match_run(source, budget);
    assert!(run.findings().is_empty());
    assert!(matches!(
        run.completion(),
        PolicyRunCompletion::Inconclusive { reasons }
            if reasons.contains(&PolicyIncompleteReason::ReportRetentionBudget)
    ));
    assert_eq!(run.work().omitted_findings_lower_bound(), 1);
    assert!(
        run.diagnostics().iter().any(|diagnostic| {
            diagnostic.code() == &PolicyDiagnosticCode::ReportRetentionBudget
        })
    );
}

#[test]
fn scenario_display_prefix_selection_is_logarithmic_and_maximal() {
    let calls = std::cell::Cell::new(0_usize);
    let (evidence, omitted) =
        largest_fitting_future_evidence_prefix(16_384, 16_384, 100, |retained, _, _| {
            calls.set(calls.get().saturating_add(1));
            Ok(SizedEvidence(retained))
        })
        .unwrap()
        .unwrap();

    assert_eq!(evidence.retained_size(), 100);
    assert_eq!(omitted, 16_284);
    assert!(calls.get() <= 15);
}

#[test]
fn aggregate_report_cap_omits_a_stable_finding_prefix() {
    let single_source = r#"export function run() {
    alpha();
}
"#;
    let single_baseline = classified_match_run(single_source, PolicyBudget::default());
    assert_eq!(single_baseline.findings().len(), 1);
    let single_cap = single_baseline.retained_size().saturating_sub(1);
    let single_budget = PolicyBudget::builder()
        .with_max_retained_report_bytes(single_cap)
        .unwrap()
        .build()
        .unwrap();
    let single = classified_match_run(single_source, single_budget);
    assert!(single.findings().is_empty());
    assert_eq!(single.work().omitted_findings_lower_bound(), 1);

    let multi_source = r#"export function run() {
    alpha();
    alpha();
}
"#;
    let multi_baseline = classified_match_run(multi_source, PolicyBudget::default());
    assert_eq!(multi_baseline.findings().len(), 2);
    let multi_cap = multi_baseline.retained_size().saturating_sub(1);
    let multi_budget = PolicyBudget::builder()
        .with_max_retained_report_bytes(multi_cap)
        .unwrap()
        .build()
        .unwrap();
    let multi = classified_match_run(multi_source, multi_budget);
    assert!(multi.findings().len() < multi_baseline.findings().len());
    assert_eq!(
        multi
            .findings()
            .iter()
            .map(PolicyFinding::id)
            .collect::<Vec<_>>(),
        multi_baseline
            .findings()
            .iter()
            .take(multi.findings().len())
            .map(PolicyFinding::id)
            .collect::<Vec<_>>()
    );
    assert!(matches!(
        multi.completion(),
        PolicyRunCompletion::Inconclusive { reasons }
            if reasons.contains(&PolicyIncompleteReason::ReportRetentionBudget)
    ));
}

#[test]
fn cvss_overlay_hash_uses_canonical_labels_and_utc_time() {
    let metadata = |assessed_at: &str, rationale: &str| {
        CvssOverlayEvidenceMetadata::try_new(
            vec![EvidenceRef::try_new("feed", "record-17").expect("evidence ref")],
            rationale.to_string(),
            vec!["applies to production".to_string()],
            "test-feed".to_string(),
            assessed_at.to_string(),
            CvssEvidenceScope::Global,
            Some(CvssExternalArtifactHash::from_bytes([23; 32])),
        )
        .expect("metadata")
    };
    let metric = CvssMetric::Threat {
        metric: CvssThreatMetric::E,
    };
    let value = CvssMetricValue::try_new(metric, CvssMetricValueToken::A).expect("value");
    let local = CvssThreatOverlayEvidence::try_new(
        CvssThreatMetric::E,
        value,
        metadata("2026-07-18T12:34:56+02:00", "trusted feed record"),
    )
    .expect("local-time evidence");
    let utc = CvssThreatOverlayEvidence::try_new(
        CvssThreatMetric::E,
        value,
        metadata("2026-07-18T10:34:56Z", "trusted feed record"),
    )
    .expect("UTC evidence");
    let changed = CvssThreatOverlayEvidence::try_new(
        CvssThreatMetric::E,
        value,
        metadata("2026-07-18T10:34:56Z", "different trusted feed record"),
    )
    .expect("changed evidence");

    assert_eq!(local.metadata().assessed_at(), "2026-07-18T10:34:56Z");
    assert_eq!(local.content_hash(), utc.content_hash());
    assert_ne!(local.content_hash(), changed.content_hash());
    assert_eq!(
        cvss_evidence_basis_label(CvssEvidenceBasis::ThreatFeed),
        "threat_feed"
    );
    assert_eq!(
        cvss_evidence_scope_labels(CvssEvidenceScope::System {
            system: CvssSystemScope::SubsequentSystem,
        }),
        ("system", Some("subsequent_system"))
    );
}

#[test]
fn broad_advisory_stays_complete_and_untruncated_capability_gap_is_inconclusive() {
    let broad = CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::BroadQuery,
        impact: CodeQueryDiagnosticImpact::Advisory,
        branch: Vec::new(),
        language: "workspace",
        message: "broad query".to_string(),
    };
    assert!(certainty_reasons(&[broad], &[]).is_empty());
    assert!(incomplete_reasons(&CodeQueryCompletion::Complete, false).is_empty());

    let completion = CodeQueryCompletion::Incomplete {
        codes: vec![CodeQueryDiagnosticCode::UnsupportedStructuralFeature],
    };
    assert_eq!(
        incomplete_reasons(&completion, false),
        vec![PolicyIncompleteReason::CapabilityIncomplete]
    );
}

#[test]
fn secondary_incomplete_cause_does_not_corrupt_terminal_completion() {
    let mut completion = PolicyRunCompletion::Failed {
        reasons: vec![PolicyFailureReason::WorkspaceIo],
    };
    let mut diagnostics = Vec::new();
    let mut diagnostics_truncated = false;

    record_run_incomplete(
        &mut completion,
        &mut diagnostics,
        &mut diagnostics_truncated,
        PolicyIncompleteReason::ReportRetentionBudget,
        "secondary report budget",
        &PolicyBudget::default(),
    );

    assert!(matches!(
        completion,
        PolicyRunCompletion::Failed { reasons }
            if reasons == vec![PolicyFailureReason::WorkspaceIo]
    ));
    assert!(diagnostics.is_empty());
    assert!(!diagnostics_truncated);
}

#[test]
fn rejected_query_diagnostic_marks_truncation_without_hiding_later_valid_diagnostics() {
    let rejected = CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::BroadQuery,
        impact: CodeQueryDiagnosticImpact::Advisory,
        branch: Vec::new(),
        language: "workspace",
        message: "x".repeat(4_097),
    };
    let valid = CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::ReferenceTargetsAmbiguous,
        impact: CodeQueryDiagnosticImpact::Advisory,
        branch: Vec::new(),
        language: "typescript",
        message: "later valid diagnostic".to_string(),
    };

    let adapted = adapt_query_diagnostics(&[rejected, valid], 1);

    assert!(adapted.adaptation_failed);
    assert!(adapted.truncated);
    assert_eq!(adapted.diagnostics.len(), 1);
    assert_eq!(adapted.diagnostics[0].message(), "later valid diagnostic");
}

#[test]
fn rejected_detailed_row_does_not_hide_later_positive_candidates() {
    let source = r#"export function run() {
    alpha();
    beta();
}
"#;
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), "app.ts")
        .write(source)
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let mut query = CodeQuery::from_json(&json!({ "match": { "kind": "call" } })).expect("query");
    query.result_detail = CodeQueryResultDetail::Full;
    let detailed = execute_code_query_detailed(
        &analyzer,
        &query,
        PolicyBudget::default().query_limits(),
        None,
    );
    assert_eq!(detailed.result.results.len(), 2);
    assert_eq!(detailed.evidence.len(), 2);
    let query_diagnostics = detailed.result.diagnostics.clone();
    let results = detailed.result.results;
    let mut evidence = detailed.evidence;
    let retained_span = evidence[1].byte_span.clone();
    evidence[0].domain = DetailedCodeQueryDomain::ReceiverAnalysis;

    let adapted = adapt_match_candidates(
        &PolicyId::new("test.partial-row-conversion").expect("policy id"),
        results,
        evidence,
        &query_diagnostics,
    );

    assert!(adapted.conversion_failed);
    assert_eq!(adapted.omitted_findings_lower_bound, 1);
    assert_eq!(adapted.candidates.len(), 1);
    assert_eq!(
        adapted.candidates[0]
            .location
            .byte_span()
            .map(|span| span.start()..span.end()),
        retained_span.map(|span| {
            u64::try_from(span.start).expect("start")..u64::try_from(span.end).expect("end")
        })
    );
}

#[test]
fn cancellation_after_query_rows_retains_partial_match_candidates() {
    let source = r#"export function caller() {
    alpha();
    beta();
    gamma();
}
"#;
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), "app.ts")
        .write(source)
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({ "match": { "kind": "call" } })).expect("query");
    let policy_id = PolicyId::new("test.partial-cancellation").expect("policy id");

    let evaluated = (2..96)
        .find_map(|checks| {
            let cancellation = CancellationToken::cancel_after_checks_for_test(checks);
            let evaluated = evaluate_match_query_candidates(
                &policy_id,
                &analyzer,
                &query,
                &PolicyBudget::default(),
                Some(&cancellation),
            );
            (matches!(
                evaluated.completion,
                PolicyRunCompletion::Inconclusive { ref reasons }
                    if reasons.contains(&PolicyIncompleteReason::Cancelled)
            ) && !evaluated.candidates.is_empty()
                && evaluated.candidates.len() < 3)
                .then_some(evaluated)
        })
        .expect("deterministic cancellation retains some positive candidates");

    assert!(!evaluated.candidates.is_empty());
    assert!(evaluated.candidates.len() < 3);
    assert_eq!(
        evaluated.work.retained_findings(),
        evaluated.candidates.len() as u64
    );
}

#[test]
fn match_candidate_conversion_accepts_all_positive_domains_and_rejects_receiver_terminal() {
    let source = r#"export function target(payload: string) { return payload; }
export function caller() { return target("secret"); }
class Service { run() {} }
export function invoke(service: Service) { service.run(); }
"#;
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let file = ProjectFile::new(root.clone(), "app.ts");
    file.write(source).expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let policy_id = PolicyId::new("test.match-domains").expect("policy id");
    let cases = [
        json!({ "match": { "kind": "function", "name": "target" } }),
        json!({
            "match": { "kind": "function", "name": "target" },
            "steps": [{ "op": "enclosing_decl" }]
        }),
        json!({
            "match": { "kind": "function", "name": "target" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "references_of", "proof": "proven" }
            ]
        }),
        json!({
            "match": { "kind": "function", "name": "target" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "call_sites_to", "proof": "proven" }
            ]
        }),
        json!({
            "match": { "kind": "function", "name": "target" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "call_sites_to", "proof": "proven" },
                { "op": "call_input", "parameter_index": 0 }
            ]
        }),
        json!({
            "match": { "kind": "function", "name": "target" },
            "steps": [{ "op": "file_of" }]
        }),
    ];
    let expected = [
        MatchResultDomain::StructuralMatch,
        MatchResultDomain::Declaration,
        MatchResultDomain::ReferenceSite,
        MatchResultDomain::CallSite,
        MatchResultDomain::ExpressionSite,
        MatchResultDomain::File,
    ];
    for (query, expected) in cases.into_iter().zip(expected) {
        let query = CodeQuery::from_json(&query).expect("query");
        let evaluated = evaluate_match_query_candidates(
            &policy_id,
            &analyzer,
            &query,
            &PolicyBudget::default(),
            None,
        );
        assert_eq!(evaluated.completion, PolicyRunCompletion::Complete);
        assert_eq!(evaluated.candidates.len(), 1);
        assert_eq!(evaluated.candidates[0].evidence.result_domain(), expected);
        assert_eq!(
            evaluated.candidates[0].evidence.anchor().result_domain(),
            expected
        );
        assert_eq!(
            evaluated.candidates[0].evidence.terminal().result_domain(),
            Some(expected)
        );
        assert_eq!(
            evaluated.candidates[0].evidence.terminal().path(),
            Some(evaluated.candidates[0].location.path())
        );
        assert_eq!(
            evaluated.candidates[0].evidence.terminal().location(),
            (expected != MatchResultDomain::File).then_some(&evaluated.candidates[0].location)
        );
        assert_eq!(
            evaluated.candidates[0].location.is_artifact_only(),
            expected == MatchResultDomain::File
        );
    }

    let receiver = CodeQuery::from_json(&json!({
        "match": { "kind": "call", "callee": { "name": "run" } },
        "steps": [{ "op": "receiver_targets" }]
    }))
    .expect("query");
    let evaluated = evaluate_match_query_candidates(
        &policy_id,
        &analyzer,
        &receiver,
        &PolicyBudget::default(),
        None,
    );
    assert!(matches!(
        evaluated.completion,
        PolicyRunCompletion::Failed { .. }
    ));
    assert_eq!(evaluated.work.pipeline_rows(), 0);
}

#[test]
fn direct_call_terminal_downgrades_proven_proof_when_caller_identity_is_unavailable() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let file = ProjectFile::new(root, "app.ts");
    let policy_id = PolicyId::new("test.direct-terminal-identity").expect("policy id");
    let call_range = CodeQueryRange {
        start_line: 2,
        start_column: 1,
        end_line: 2,
        end_column: 10,
    };
    let declaration = |fq_name: &str, id: Option<&str>| CodeQueryDeclaration {
        path: "app.ts".to_string(),
        language: "typescript",
        kind: "function",
        fq_name: fq_name.to_string(),
        start_line: 1,
        end_line: 2,
        signature: None,
        id: id.map(str::to_string),
        node_range: Some(call_range),
        semantic_model: None,
    };
    let item = CodeQueryResultItem {
        value: CodeQueryResultValue::CallSite {
            value: Box::new(CodeQueryCallSite {
                path: "app.ts".to_string(),
                language: "typescript",
                range: call_range,
                callee_range: call_range,
                caller: declaration("<anonymous>", None),
                callee: declaration("target", Some("function:target")),
                call_kind: "direct",
                proof: "proven",
                receiver: None,
                arguments: Vec::new(),
            }),
        },
        provenance: Vec::new(),
        provenance_truncated: false,
    };
    let evidence = DetailedCodeQueryEvidence {
        result_index: 0,
        domain: DetailedCodeQueryDomain::CallSite,
        key: DetailedCodeQueryKey::CallSite {
            caller_fq_name: "<anonymous>".to_string(),
            callee_fq_name: "target".to_string(),
        },
        file: file.clone(),
        byte_span: Some(30..39),
        stable_owner_candidate: None,
        identities: DetailedCodeQueryProvenanceIdentities::Call {
            caller: None,
            callee: Some(DetailedCodeQueryIdentityCandidate {
                file,
                candidate: CodeQueryStableOwnerCandidate {
                    namespace: "typescript".to_string(),
                    derivation: CodeQueryStableOwnerDerivation::AnalyzerDeclarationId,
                    semantic_key: "function:target".to_string(),
                },
            }),
        },
        source_slice_sha256: Some([7; 32]),
        provenance: Vec::new(),
    };
    let candidate = adapt_match_candidate(&policy_id, item, evidence, &[], &mut HashMap::new())
        .expect("synthetic detailed/public terminal pair adapts");

    assert!(
        matches!(
            candidate.evidence.terminal(),
            PolicyQueryResultRef::CallSite {
                caller_identity: None,
                callee_identity: Some(_),
                proof: PolicyQueryProof::NameBased,
                ..
            }
        ),
        "unexpected terminal: {:?}",
        candidate.evidence.terminal()
    );
    assert!(matches!(
        candidate.certainty,
        FindingCertainty::Possible { ref reasons }
            if reasons.contains(&CertaintyReason::NameBasedResolution)
    ));
    assert_eq!(candidate.proof.state(), ProofState::Unproven);
}

#[test]
fn strong_fingerprint_ignores_preceding_coordinates_but_tracks_selected_bytes() {
    let policy_id = PolicyId::new("test.fingerprint").expect("policy id");
    let path = WorkspaceRelativePath::new("src/app.ts").expect("path");
    let owner = StableSemanticIdentity::analyzer_declaration_id(
        "typescript",
        path.clone(),
        "function:target(payload: string)",
    )
    .expect("owner");
    let anchor = |hash, ordinal| {
        MatchFindingAnchor::strong(
            MatchResultDomain::StructuralMatch,
            path.clone(),
            Some(owner.clone()),
            Some(SourceSliceHash::from_bytes(hash)),
            ordinal,
        )
        .expect("anchor")
    };
    let first = PolicyFindingId::from_match_anchor(&policy_id, &anchor([7; 32], 0));
    let shifted = PolicyFindingId::from_match_anchor(&policy_id, &anchor([7; 32], 0));
    let changed = PolicyFindingId::from_match_anchor(&policy_id, &anchor([8; 32], 0));
    let duplicate = PolicyFindingId::from_match_anchor(&policy_id, &anchor([7; 32], 1));
    assert_eq!(first, shifted);
    assert_ne!(first, changed);
    assert_ne!(first, duplicate);
}

#[test]
fn cross_file_provenance_keeps_target_caller_and_callee_identities_distinct() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), "target.ts")
        .write("export function target() {}\n")
        .expect("write target");
    ProjectFile::new(root.clone(), "caller.ts")
        .write("import { target } from './target';\nexport function caller() { target(); }\n")
        .expect("write caller");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let policy_id = PolicyId::new("test.cross-file-provenance").expect("policy id");
    let evaluate = |operation: &str| {
        let query = CodeQuery::from_json(&json!({
            "where": ["target.ts"],
            "match": { "kind": "function", "name": "target" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": operation, "proof": "proven" }
            ]
        }))
        .expect("query");
        evaluate_match_query_candidates(
            &policy_id,
            &analyzer,
            &query,
            &PolicyBudget::default(),
            None,
        )
    };

    let reference = evaluate("references_of");
    assert_eq!(reference.candidates.len(), 1);
    let reference_step = reference.candidates[0].evidence.provenance()[0]
        .steps()
        .last()
        .expect("reference step");
    let PolicyQueryResultRef::ReferenceSite {
        target_identity: Some(target_identity),
        ..
    } = reference_step.result()
    else {
        panic!("reference provenance must retain its target identity");
    };
    assert_eq!(target_identity.path().as_str(), "target.ts");

    let call = evaluate("call_sites_to");
    assert_eq!(call.candidates.len(), 1);
    let call_step = call.candidates[0].evidence.provenance()[0]
        .steps()
        .last()
        .expect("call step");
    let PolicyQueryResultRef::CallSite {
        caller_identity: Some(caller_identity),
        callee_identity: Some(callee_identity),
        ..
    } = call_step.result()
    else {
        panic!("call provenance must retain caller and callee identities");
    };
    assert_eq!(caller_identity.path().as_str(), "caller.ts");
    assert_eq!(callee_identity.path().as_str(), "target.ts");
}

#[test]
fn proven_call_without_a_stable_caller_identity_is_name_based_but_keeps_strong_anchor() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), "target.ts")
        .write("export function target() {}\n")
        .expect("write target");
    ProjectFile::new(root.clone(), "caller.ts")
        .write("import { target } from './target';\nexport function caller() { target(); }\n")
        .expect("write caller");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let policy_id = PolicyId::new("test.missing-caller-identity").expect("policy id");
    let query = CodeQuery::from_json(&json!({
        "where": ["target.ts"],
        "match": { "kind": "function", "name": "target" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "call_sites_to", "proof": "proven" }
        ],
        "result_detail": "full"
    }))
    .expect("query");

    let mut detailed = execute_code_query_detailed(
        &analyzer,
        &query,
        brokk_bifrost_analysis::analyzer::structural::CodeQueryExecutionLimits::default(),
        None,
    );
    assert_eq!(detailed.result.results.len(), 1);
    assert_eq!(detailed.evidence.len(), 1);
    let mut evidence = detailed.evidence.pop().expect("call evidence");
    let call_step = evidence.provenance[0].steps.last_mut().expect("call step");
    let DetailedCodeQueryProvenanceIdentities::Call { caller, .. } =
        &mut call_step.result.identities
    else {
        panic!("expected call identities");
    };
    *caller = None;
    let item = detailed.result.results.pop().expect("call result");
    let mut ordinals = HashMap::new();
    let candidate = adapt_match_candidate(
        &policy_id,
        item,
        evidence,
        &detailed.result.diagnostics,
        &mut ordinals,
    )
    .expect("candidate");

    assert!(matches!(
        candidate.evidence.anchor(),
        MatchFindingAnchor::Strong(_)
    ));
    assert!(matches!(
        candidate.certainty,
        FindingCertainty::Possible { reasons }
            if reasons.contains(&CertaintyReason::NameBasedResolution)
    ));
    assert_eq!(candidate.proof.state(), ProofState::Unproven);
    let step = candidate.evidence.provenance()[0]
        .steps()
        .last()
        .expect("call step");
    assert!(matches!(
        step.result(),
        PolicyQueryResultRef::CallSite {
            caller_identity: None,
            callee_identity: Some(_),
            proof: PolicyQueryProof::NameBased,
            ..
        }
    ));
}

#[test]
fn advisory_ambiguity_only_lowers_findings_from_the_affected_set_branch() {
    let file = ProjectFile::new(std::env::temp_dir(), "app.ts");
    let provenance = |branch| DetailedCodeQueryProvenanceEvidence {
        branch: vec![branch],
        seed: DetailedCodeQueryProvenanceRefEvidence {
            domain: DetailedCodeQueryDomain::File,
            key: DetailedCodeQueryKey::File,
            file: file.clone(),
            byte_span: None,
            display_range: None,
            identities: DetailedCodeQueryProvenanceIdentities::None,
            source_slice_sha256: None,
        },
        steps: Vec::new(),
    };
    let diagnostic = CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::ReferenceTargetsAmbiguous,
        impact: CodeQueryDiagnosticImpact::Advisory,
        branch: vec![0],
        language: "typescript",
        message: "branch-local ambiguity".to_string(),
    };

    assert_eq!(
        certainty_reasons(std::slice::from_ref(&diagnostic), &[provenance(0)]).len(),
        1
    );
    assert!(certainty_reasons(&[diagnostic], &[provenance(1)]).is_empty());
}

#[test]
fn invalid_owner_candidate_forces_weak_anchor() {
    let file = ProjectFile::new(std::env::temp_dir(), "src/app.ts");
    let evidence = DetailedCodeQueryEvidence {
        result_index: 0,
        domain: DetailedCodeQueryDomain::StructuralMatch,
        key: DetailedCodeQueryKey::StructuralMatch {
            kind: "call".to_string(),
            analyzer_id: None,
        },
        file,
        byte_span: Some(0..4),
        identities: DetailedCodeQueryProvenanceIdentities::Primary(None),
        stable_owner_candidate: Some(
            brokk_bifrost_analysis::analyzer::structural::search::CodeQueryStableOwnerCandidate {
                namespace: "INVALID".to_string(),
                derivation: CodeQueryStableOwnerDerivation::CanonicalAstIdentity,
                semantic_key: "call:sink".to_string(),
            },
        ),
        source_slice_sha256: Some([1; 32]),
        provenance: Vec::new(),
    };
    assert!(matches!(OwnerCandidate::Rejected, OwnerCandidate::Rejected));
    let key = weak_finding_key(&evidence);
    assert!(key.as_str().starts_with("code-query:"));
}

#[test]
fn unicode_location_conversion_preserves_byte_and_codepoint_coordinates() {
    let path = WorkspaceRelativePath::new("src/unicode.ts").expect("path");
    let location = policy_span_location(
        path,
        &(3..7),
        CodeQueryRange {
            start_line: 2,
            start_column: 4,
            end_line: 2,
            end_column: 6,
        },
    )
    .expect("location");
    assert_eq!(location.byte_span().expect("bytes").start(), 3);
    assert_eq!(location.byte_span().expect("bytes").end(), 7);
    assert_eq!(location.region().expect("region").start_column(), 4);
    assert_eq!(location.region().expect("region").end_column(), 6);
}

#[test]
fn weak_key_is_domain_and_span_separated() {
    let file = ProjectFile::new(std::env::temp_dir(), "src/app.ts");
    let evidence = |span| DetailedCodeQueryEvidence {
        result_index: 0,
        domain: DetailedCodeQueryDomain::StructuralMatch,
        key: DetailedCodeQueryKey::StructuralMatch {
            kind: "call".to_string(),
            analyzer_id: None,
        },
        file: file.clone(),
        byte_span: Some(span),
        identities: DetailedCodeQueryProvenanceIdentities::Primary(None),
        stable_owner_candidate: None,
        source_slice_sha256: None,
        provenance: Vec::new(),
    };
    assert_ne!(
        weak_finding_key(&evidence(0..4)),
        weak_finding_key(&evidence(5..9))
    );
}

#[test]
fn file_anchor_never_uses_a_span() {
    let path = WorkspaceRelativePath::new("src/app.ts").expect("path");
    let anchor = MatchFindingAnchor::strong(MatchResultDomain::File, path, None, None, 0)
        .expect("file anchor");
    assert_eq!(anchor.result_domain(), MatchResultDomain::File);
}
