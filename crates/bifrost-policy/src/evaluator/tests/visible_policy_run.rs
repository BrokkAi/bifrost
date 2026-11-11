use super::*;
use brokk_bifrost_jvm_analysis::JavaAnalyzer;
use brokk_bifrost_test_macros::hardwon;

fn typestate_policy() -> PolicyRegistry {
    let source = crate::test_support::typestate_policy_source(
        "test.visible-typestate",
        "Visible typestate result",
    );
    policy_registry("test:visible-typestate", &source)
}

#[test]
fn unsupported_typestate_reports_its_type_and_one_diagnostic() {
    let (_temp, analyzer) = assembly_analyzer();
    let registry = typestate_policy();
    let policy = registry.policies().next().unwrap();
    let flow_state = brokk_bifrost_flow::FlowWorkspaceState::new();
    let context = PolicyEvaluationContext {
        analyzer: &analyzer,
        workspace: None,
        flow_state: &flow_state,
        root_memo: None,
        cancellation: None,
        cvss_overlays: &[],
        organizational_risk: &[],
        incremental: None,
        identifier_typos: None,
    };
    let mut budget = PolicyBudget::builder()
        .with_max_diagnostics(1)
        .unwrap()
        .build()
        .unwrap();
    let run = DefaultPolicyEvaluator::new()
        .evaluate(policy, &context, &mut budget)
        .unwrap();
    assert_eq!(run.analysis_type(), PolicyAnalysisType::Typestate);
    assert!(matches!(
        run.completion(),
        PolicyRunCompletion::Unsupported {
            capability: PolicyCapability::TypestateEvaluation
        }
    ));
    assert_eq!(run.diagnostics().len(), 1);
    assert_eq!(
        run.diagnostics()[0].code(),
        &PolicyDiagnosticCode::UnsupportedAnalysis
    );
    assert!(!run.diagnostics_truncated());
}

#[test]
fn explicit_scope_refuses_typestate_with_scope_capability() {
    let (_temp, analyzer) = assembly_analyzer();
    let registry = typestate_policy();
    let policy = registry.policies().next().unwrap();
    let flow_state = brokk_bifrost_flow::FlowWorkspaceState::new();
    let context = PolicyEvaluationContext {
        analyzer: &analyzer,
        workspace: None,
        flow_state: &flow_state,
        root_memo: None,
        cancellation: None,
        cvss_overlays: &[],
        organizational_risk: &[],
        incremental: None,
        identifier_typos: None,
    };
    let mut budget = PolicyBudget::default();
    let run = DefaultPolicyEvaluator::new()
        .evaluate_in_scope(
            policy,
            &context,
            &mut budget,
            CodeQueryExecutionScope::whole_workspace(),
        )
        .unwrap();
    assert!(matches!(
        run.completion(),
        PolicyRunCompletion::Unsupported {
            capability: PolicyCapability::QueryDomain { domain, reason, .. }
        } if domain == "execution_scope" && reason == "query_source_not_scope_aware"
    ));
}

#[test]
fn incomplete_typestate_compile_keeps_caller_budget_and_diagnostic() {
    let (_temp, analyzer) = assembly_analyzer();
    let registry = typestate_policy();
    let policy = registry.policies().next().unwrap();
    let flow_state = brokk_bifrost_flow::FlowWorkspaceState::new();
    let context = PolicyEvaluationContext {
        analyzer: &analyzer,
        workspace: None,
        flow_state: &flow_state,
        root_memo: None,
        cancellation: None,
        cvss_overlays: &[],
        organizational_risk: &[],
        incremental: None,
        identifier_typos: None,
    };
    let mut budget = PolicyBudget::builder()
        .with_max_diagnostics(1)
        .unwrap()
        .build()
        .unwrap();
    let adapter = IncompleteTypestateAdapter;
    let run = DefaultPolicyEvaluator::new()
        .with_typestate(&adapter)
        .evaluate(policy, &context, &mut budget)
        .unwrap();
    assert!(matches!(
        run.completion(),
        PolicyRunCompletion::Inconclusive { .. }
    ));
    assert_eq!(budget.max_diagnostics(), 1);
    assert_eq!(run.diagnostics().len(), 1);
    assert_eq!(
        run.diagnostics()[0].code(),
        &PolicyDiagnosticCode::EvaluationFailure
    );
    assert!(!run.diagnostics_truncated());
}

struct FailedTypestateAdapter;

impl crate::projection::sealed::TypestateAdapter for FailedTypestateAdapter {}

impl TypestatePolicyEvaluator for FailedTypestateAdapter {
    fn compilation_hashes(
        &self,
        _policy: &LoadedPolicy,
        _spec: &ResolvedTypestatePolicySpec,
        _context: &PolicyEvaluationContext<'_>,
        _subject_scope: brokk_bifrost_rql::structural::search::CodeQueryExecutionScope<'_>,
        _budget: &PolicyBudget,
    ) -> Result<TypestateCompilationHashes, TypestateCompilationFailure> {
        Err(TypestateCompilationFailure::failed(
            PolicyFailureReason::InternalInvariant,
            "compilation failed",
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
        unreachable!("failed compilation stops before evaluation")
    }
}

#[test]
fn failed_typestate_compile_retains_one_failure_diagnostic() {
    let (_temp, analyzer) = assembly_analyzer();
    let registry = typestate_policy();
    let policy = registry.policies().next().unwrap();
    let flow_state = brokk_bifrost_flow::FlowWorkspaceState::new();
    let context = PolicyEvaluationContext {
        analyzer: &analyzer,
        workspace: None,
        flow_state: &flow_state,
        root_memo: None,
        cancellation: None,
        cvss_overlays: &[],
        organizational_risk: &[],
        incremental: None,
        identifier_typos: None,
    };
    let mut budget = PolicyBudget::builder()
        .with_max_diagnostics(1)
        .unwrap()
        .build()
        .unwrap();
    let adapter = FailedTypestateAdapter;
    let run = DefaultPolicyEvaluator::new()
        .with_typestate(&adapter)
        .evaluate(policy, &context, &mut budget)
        .unwrap();
    assert!(matches!(
        run.completion(),
        PolicyRunCompletion::Failed { .. }
    ));
    assert_eq!(run.diagnostics().len(), 1);
    assert_eq!(
        run.diagnostics()[0].code(),
        &PolicyDiagnosticCode::EvaluationFailure
    );
    assert!(!run.diagnostics_truncated());
}

#[test]
fn match_finding_keeps_organizational_risk_overlay() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    ProjectFile::new(root.clone(), "app.ts")
        .write("alpha();\n")
        .unwrap();
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let registry = policy_registry(
        "test:visible-risk",
        r#"(policy :id "test.visible-risk" :name "Visible risk"
            :message "Matched alpha" :severity warning
            :analysis (analysis :type match :selector
              (rql (language typescript (call :callee (name "alpha"))))))"#,
    );
    let policy = registry.policies().next().unwrap();
    let overlays = [OrganizationalRiskOverlay {
        scope: PolicyOverlayScope::AllFindings,
        assessment: risk("high", &["record-17"]),
    }];
    let flow_state = brokk_bifrost_flow::FlowWorkspaceState::new();
    let context = PolicyEvaluationContext {
        analyzer: &analyzer,
        workspace: None,
        flow_state: &flow_state,
        root_memo: None,
        cancellation: None,
        cvss_overlays: &[],
        organizational_risk: &overlays,
        incremental: None,
        identifier_typos: None,
    };
    let run = DefaultPolicyEvaluator::new()
        .evaluate(policy, &context, &mut PolicyBudget::default())
        .unwrap();
    assert_eq!(run.findings().len(), 1);
    assert_eq!(
        run.findings()[0].organizational_risk().unwrap().rating(),
        "high"
    );
}

#[test]
fn explicit_scope_refuses_relational_binding_outside_scope() {
    let (_temp, analyzer) = assembly_analyzer();
    let registry = policy_registry(
        "test:scope-relational",
        r#"(policy :schema-version 1 :id "test.scope-relational"
            :name "Scope relational" :message "Matched" :severity warning
            :analysis (analysis :type assertion
              (bind :name read :query (rql (occurrences :role [value_reference])))
              (bind :name config :query (rql (configuration-facts :format json)))
              (group :name by-read :by (read.ast_id)
                (aggregate :name reads :op count))
              (assert :group by-read :value reads :cardinality (exactly 0))))"#,
    );
    let policy = registry.policies().next().unwrap();
    let flow_state = brokk_bifrost_flow::FlowWorkspaceState::new();
    let context = PolicyEvaluationContext {
        analyzer: &analyzer,
        workspace: None,
        flow_state: &flow_state,
        root_memo: None,
        cancellation: None,
        cvss_overlays: &[],
        organizational_risk: &[],
        incremental: None,
        identifier_typos: None,
    };
    let run = DefaultPolicyEvaluator::new()
        .evaluate_in_scope(
            policy,
            &context,
            &mut PolicyBudget::default(),
            CodeQueryExecutionScope::whole_workspace(),
        )
        .unwrap();
    assert!(matches!(
        run.completion(),
        PolicyRunCompletion::Unsupported {
            capability: PolicyCapability::QueryDomain { domain, reason, .. }
        } if domain == "execution_scope" && reason == "query_source_not_scope_aware"
    ));
}

#[test]
fn proven_subset_and_overlay_cap_report_distinct_reasons() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    ProjectFile::new(root.clone(), "Smells.java")
        .write(
            "class Smells { void terminate() { System.exit(1); }\n\
             void directTerminate() { this.terminate(); }\n\
             void secondOrderTerminate() { this.directTerminate(); } }\n",
        )
        .unwrap();
    let analyzer = JavaAnalyzer::from_project(TestProject::new(root, Language::Java));
    let registry = policy_registry(
        "test:proven-subset",
        r#"(policy :id "test.proven-subset" :name "Proven callers"
            :message "Calls System.exit" :severity warning
            :analysis (analysis :type match :selector
              (rql (language java
                (callers :depth 2 :proof proven :completeness proven-subset
                  (enclosing-decl
                    (call :receiver (name "System") :callee (name "exit"))))))))"#,
    );
    let policy = registry.policies().next().unwrap();
    let overlays = [OrganizationalRiskOverlay {
        scope: PolicyOverlayScope::AllFindings,
        assessment: risk("high", &["record-1", "record-2"]),
    }];
    let flow_state = brokk_bifrost_flow::FlowWorkspaceState::new();
    let context = PolicyEvaluationContext {
        analyzer: &analyzer,
        workspace: None,
        flow_state: &flow_state,
        root_memo: None,
        cancellation: None,
        cvss_overlays: &[],
        organizational_risk: &overlays,
        incremental: None,
        identifier_typos: None,
    };
    let mut budget = PolicyBudget::builder()
        .with_max_evidence_refs_per_finding(1)
        .unwrap()
        .build()
        .unwrap();
    let run = DefaultPolicyEvaluator::new()
        .evaluate(policy, &context, &mut budget)
        .unwrap();
    assert!(matches!(
        run.completion(),
        PolicyRunCompletion::ProvenSubset { .. }
    ));
    assert!(!run.findings().is_empty());
    for finding in run.findings() {
        assert!(
            finding
                .completeness()
                .reasons()
                .contains(&FindingIncompleteReason::DeclaredNonExhaustive)
        );
        assert!(
            finding
                .completeness()
                .reasons()
                .contains(&FindingIncompleteReason::EvidenceTruncated)
        );
    }
}

#[test]
#[hardwon("#10047: a zero diagnostic cap turned declared subset runs into failed runs")]
fn declared_subset_survives_zero_diagnostic_budget() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    ProjectFile::new(root.clone(), "Smells.java")
        .write("class Smells { void run() { System.exit(1); } }\n")
        .unwrap();
    let analyzer = JavaAnalyzer::from_project(TestProject::new(root, Language::Java));
    let registry = policy_registry(
        "test:declared-subset-zero-budget",
        r#"(policy :id "test.declared-subset-zero-budget" :name "Subset"
            :message "Exit" :severity warning
            :coverage (proven-subset :reason "Only direct calls")
            :analysis (analysis :type match :selector
              (rql (language java (call :callee (name "exit"))))) )"#,
    );
    let flow_state = brokk_bifrost_flow::FlowWorkspaceState::new();
    let context = PolicyEvaluationContext {
        analyzer: &analyzer,
        workspace: None,
        flow_state: &flow_state,
        root_memo: None,
        cancellation: None,
        cvss_overlays: &[],
        organizational_risk: &[],
        incremental: None,
        identifier_typos: None,
    };
    let mut budget = PolicyBudget::builder()
        .with_max_diagnostics(0)
        .unwrap()
        .build()
        .unwrap();
    let run = DefaultPolicyEvaluator::new()
        .evaluate(registry.policies().next().unwrap(), &context, &mut budget)
        .unwrap();
    assert!(matches!(
        run.completion(),
        PolicyRunCompletion::Inconclusive { reasons, .. }
            if reasons.contains(&PolicyIncompleteReason::ReportRetentionBudget)
    ));
    assert_eq!(run.findings().len(), 1);
    assert!(
        run.findings()[0]
            .completeness()
            .reasons()
            .contains(&FindingIncompleteReason::DeclaredNonExhaustive)
    );
    assert!(run.diagnostics().is_empty());
    assert!(run.diagnostics_truncated());
}

#[test]
fn match_evidence_budget_charges_proof_and_accepts_exact_fit() {
    let source = "alpha();\n";
    let baseline = classified_match_run(source, PolicyBudget::default());
    assert_eq!(baseline.findings().len(), 1);
    let finding = &baseline.findings()[0];
    // The per-finding cap includes classification, proof and core evidence.
    let exact_cap = finding
        .classification()
        .retained_size()
        .saturating_add(finding.proof().retained_size())
        .saturating_add(finding.evidence().retained_size());
    let exact = classified_match_run(
        source,
        PolicyBudget::builder()
            .with_max_evidence_bytes_per_finding(exact_cap)
            .unwrap()
            .build()
            .unwrap(),
    );
    assert_eq!(exact.findings().len(), 1);
    let below = classified_match_run(
        source,
        PolicyBudget::builder()
            .with_max_evidence_bytes_per_finding(exact_cap - 1)
            .unwrap()
            .build()
            .unwrap(),
    );
    assert!(below.findings().is_empty());
    assert!(matches!(
        below.completion(),
        PolicyRunCompletion::Inconclusive { reasons, .. }
            if reasons.contains(&PolicyIncompleteReason::ReportRetentionBudget)
    ));
}

fn two_match_run_with_budget(
    overlays: &[OrganizationalRiskOverlay],
    mut budget: PolicyBudget,
) -> Result<PolicyRun, PolicyRunError> {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    ProjectFile::new(root.clone(), "app.ts")
        .write("alpha();\nalpha();\n")
        .unwrap();
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let registry = policy_registry(
        "test:two-match",
        r#"(policy :id "test.two-match" :name "Two matches"
            :message "Matched alpha" :severity warning
            :analysis (analysis :type match :selector
              (rql (language typescript (call :callee (name "alpha"))))))"#,
    );
    let policy = registry.policies().next().unwrap();
    let flow_state = brokk_bifrost_flow::FlowWorkspaceState::new();
    let context = PolicyEvaluationContext {
        analyzer: &analyzer,
        workspace: None,
        flow_state: &flow_state,
        root_memo: None,
        cancellation: None,
        cvss_overlays: &[],
        organizational_risk: overlays,
        incremental: None,
        identifier_typos: None,
    };
    DefaultPolicyEvaluator::new().evaluate(policy, &context, &mut budget)
}

fn two_match_run(overlays: &[OrganizationalRiskOverlay]) -> PolicyRun {
    two_match_run_with_budget(overlays, PolicyBudget::default()).unwrap()
}

#[test]
fn failed_match_retains_a_prior_valid_finding() {
    let baseline = two_match_run(&[]);
    assert_eq!(baseline.findings().len(), 2);
    let baseline_ids = baseline
        .findings()
        .iter()
        .map(PolicyFinding::id)
        .collect::<Vec<_>>();
    let retained = baseline_ids.iter().any(|id| {
        let overlays = [
            OrganizationalRiskOverlay {
                scope: PolicyOverlayScope::Finding { finding_id: *id },
                assessment: risk("high", &["review-high"]),
            },
            OrganizationalRiskOverlay {
                scope: PolicyOverlayScope::Finding { finding_id: *id },
                assessment: risk("low", &["review-low"]),
            },
        ];
        let run = two_match_run(&overlays);
        assert!(matches!(
            run.completion(),
            PolicyRunCompletion::Failed { .. }
        ));
        run.findings().len() == 1 && baseline_ids.contains(&run.findings()[0].id())
    });
    assert!(
        retained,
        "a later conflict must retain a prior valid finding"
    );
}

#[test]
fn aggregate_report_budget_exhaustion_returns_error() {
    let budget = PolicyBudget::builder()
        .with_max_retained_report_bytes(1)
        .unwrap()
        .build()
        .unwrap();
    assert!(matches!(
        two_match_run_with_budget(&[], budget),
        Err(PolicyRunError::RetainedReportBytesExceeded { .. })
    ));
}

#[test]
fn distinct_overlay_evidence_omissions_are_counted_once_each() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    ProjectFile::new(root.clone(), "app.ts")
        .write("export function target() { return 1; }\n")
        .unwrap();
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let rules = [
        ("AV", "N"),
        ("AC", "L"),
        ("AT", "N"),
        ("PR", "N"),
        ("UI", "N"),
        ("VC", "H"),
        ("VI", "H"),
        ("VA", "H"),
        ("SC", "N"),
        ("SI", "N"),
        ("SA", "N"),
    ]
    .into_iter()
    .map(|(metric, value)| {
        let scope = if matches!(metric, "SC" | "SI" | "SA") {
            "subsequent-system"
        } else {
            "vulnerable-system"
        };
        format!(
            "(metric :name {metric} :value {value} :when (analysis-type :is match) \
             :basis policy-assertion :scope {scope} :evidence-refs [policy:self] \
             :rationale \"policy evidence\")"
        )
    })
    .collect::<Vec<_>>()
    .join(" ");
    let source = format!(
        r#"(policy :id "test.overlay-omissions" :name "Overlay omissions"
            :message "Selected target" :severity warning
            :analysis (analysis :type match :selector (rql (function :name "target")))
            :classification (classification
              :fallback (classification-id :taxonomy "Test" :id "OVERLAY")
              :cvss (cvss :version "4.0" :emit when-base-complete
                :metric-rules [{rules}])))"#
    );
    let registry = policy_registry("test:overlay-omissions", &source);
    let policy = registry.policies().next().unwrap();
    let metric = CvssMetric::Threat {
        metric: CvssThreatMetric::E,
    };
    let cvss_overlays = [CvssEvaluationOverlay::ThreatFeed {
        scope: PolicyOverlayScope::AllFindings,
        evidence: CvssThreatOverlayEvidence::try_new(
            CvssThreatMetric::E,
            CvssMetricValue::try_new(metric, crate::CvssMetricValueToken::A).unwrap(),
            CvssOverlayEvidenceMetadata::try_new(
                vec![EvidenceRef::try_new("cvss", "feed-record").unwrap()],
                "feed evidence".into(),
                Vec::new(),
                "test-feed".into(),
                "2026-07-18T00:00:00Z".into(),
                CvssEvidenceScope::Global,
                None,
            )
            .unwrap(),
        )
        .unwrap(),
    }];
    let organizational_risk = [OrganizationalRiskOverlay {
        scope: PolicyOverlayScope::AllFindings,
        assessment: risk("high", &["review-record"]),
    }];
    let flow_state = brokk_bifrost_flow::FlowWorkspaceState::new();
    let context = PolicyEvaluationContext {
        analyzer: &analyzer,
        workspace: None,
        flow_state: &flow_state,
        root_memo: None,
        cancellation: None,
        cvss_overlays: &cvss_overlays,
        organizational_risk: &organizational_risk,
        incremental: None,
        identifier_typos: None,
    };
    let mut budget = PolicyBudget::builder()
        .with_max_evidence_refs_per_finding(0)
        .unwrap()
        .build()
        .unwrap();
    let run = DefaultPolicyEvaluator::new()
        .evaluate(policy, &context, &mut budget)
        .unwrap();
    assert_eq!(run.findings().len(), 1);
    assert!(run.findings()[0].omitted_evidence_refs_lower_bound() >= 2);
}

struct ReferenceRichTaintAdapter;

impl crate::projection::sealed::TaintAdapter for ReferenceRichTaintAdapter {}

impl TaintPolicyEvaluator for ReferenceRichTaintAdapter {
    fn evaluate_taint(
        &self,
        _authority: &TaintProjectionAuthority,
        _policy: &LoadedPolicy,
        spec: &ResolvedTaintPolicySpec,
        _context: &PolicyEvaluationContext<'_>,
        _budget: &PolicyBudget,
    ) -> TaintProjectionPayload {
        let scenarios = ["first", "second"]
            .into_iter()
            .map(|value| SourceScenarioId::try_new("test", value).unwrap())
            .collect();
        let mut projection = raw_taint_projection(spec, "sink-rich", scenarios, false);
        for (index, origin) in projection.pairs[0].origins.iter_mut().enumerate() {
            origin
                .evidence_refs
                .push(EvidenceRef::try_new("test", format!("origin-{}", index + 1)).unwrap());
        }
        projection.pairs[0].report.proof = ProofMetadata::try_new(
            ProofState::Proven,
            vec![ProofReason::DataflowWitness],
            ["proof-1", "proof-2"]
                .into_iter()
                .map(|value| EvidenceRef::try_new("test", value).unwrap())
                .collect(),
        )
        .unwrap();
        TaintProjectionPayload {
            engine: None,
            scope: None,
            projections: vec![projection],
            completion: PolicyRunCompletion::Complete,
            diagnostics: Vec::new(),
            diagnostics_truncated: false,
            work: PolicyWorkReport::default(),
            authored_arm_closures: Vec::new(),
        }
    }
}

#[test]
fn risk_overlay_preserves_proof_and_origin_reference_priority() {
    let (_temp, analyzer) = assembly_analyzer();
    let registry = policy_registry("test:rich-taint", taint_policy_source());
    let policy = registry.policies().next().unwrap();
    let assessment = OrganizationalRiskAssessment::try_new(
        "test-risk".into(),
        "high".into(),
        "four independent references".into(),
        [
            "a-extra",
            "origin-1",
            "origin-2",
            "proof-1",
            "proof-2",
            "source-alpha",
        ]
        .into_iter()
        .map(|value| EvidenceRef::try_new("test", value).unwrap())
        .collect(),
        None,
    )
    .unwrap();
    let overlays = [OrganizationalRiskOverlay {
        scope: PolicyOverlayScope::AllFindings,
        assessment,
    }];
    let flow_state = brokk_bifrost_flow::FlowWorkspaceState::new();
    let context = PolicyEvaluationContext {
        analyzer: &analyzer,
        workspace: None,
        flow_state: &flow_state,
        root_memo: None,
        cancellation: None,
        cvss_overlays: &[],
        organizational_risk: &overlays,
        incremental: None,
        identifier_typos: None,
    };
    let mut budget = PolicyBudget::builder()
        .with_max_evidence_refs_per_finding(5)
        .unwrap()
        .build()
        .unwrap();
    let adapter = ReferenceRichTaintAdapter;
    let run = DefaultPolicyEvaluator::new()
        .with_taint(&adapter)
        .evaluate(policy, &context, &mut budget)
        .unwrap();
    assert_eq!(run.findings().len(), 1, "{run:#?}");
    let retained = run.findings()[0]
        .organizational_risk()
        .unwrap()
        .evidence_refs()
        .iter()
        .map(|reference| reference.to_string())
        .collect::<Vec<_>>();
    let expected = ["origin-1", "origin-2", "proof-1", "proof-2", "source-alpha"]
        .into_iter()
        .map(|value| EvidenceRef::try_new("test", value).unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(retained, expected);
}
