use std::path::{Path, PathBuf};

use super::*;
use crate::DEFAULT_POLICY_SUPPRESSION_PATH;
use crate::inline_project::run_git;
use crate::{PolicyAnalysisType, PolicyFindingEvidence, PolicyRunScopeKind};

fn report_for_file(root: &Path, path: PathBuf) -> PolicyBatchOutcome {
    evaluate_policy_files(
        root,
        &[path],
        &crate::test_support::evaluation_options("2026-07-27"),
    )
    .unwrap()
}

fn report_for_document(source: &str) -> PolicyBatchOutcome {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("policy.rqlp"), source).unwrap();
    report_for_file(root.path(), PathBuf::from("policy.rqlp"))
}

#[test]
fn nested_missing_policy_reports_requested_file() {
    let root = tempfile::tempdir().unwrap();
    let outcome = report_for_file(root.path(), PathBuf::from("rules/missing.rqlp"));
    let diagnostics = outcome.report().diagnostics();
    assert!(
        diagnostics.iter().any(|d| {
            d.code() == PolicyReportDiagnosticCode::PolicyLoadFailed
                && d.source().map(PolicySourceIdentity::as_str) == Some("rules/missing.rqlp")
        }),
        "{diagnostics:?}"
    );
}

#[test]
fn unsupported_rql_schema_keeps_its_diagnostic_code() {
    let outcome = report_for_document(
        r#"(policy :id "test.unsupported" :name "Unsupported" :message "M" :severity warning :analysis (analysis :type match :selector (rql :schema-version 999 (call))))"#,
    );
    let diagnostics = outcome.report().diagnostics();
    assert!(
        diagnostics
            .iter()
            .any(|d| { d.code() == PolicyReportDiagnosticCode::UnsupportedRqlSchemaVersion }),
        "{diagnostics:?}"
    );
}

#[test]
fn loaded_policy_path_uses_normalized_source_identity() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("rules")).unwrap();
    std::fs::write(
        root.path().join("rules/policy.rqlp"),
        r#"(policy :schema-version 1 :id "test.normalized" :name "Normalized" :message "M" :severity warning :analysis (analysis :type match :selector (rql :schema-version 1 (call))))"#,
    )
    .unwrap();
    std::fs::write(
        root.path().join("other.rqlp"),
        r#"(policy :schema-version 1 :id "test.normalized" :name "Other" :message "M" :severity warning :analysis (analysis :type match :selector (rql :schema-version 1 (call))))"#,
    )
    .unwrap();
    let outcome = evaluate_policy_files(
        root.path(),
        &[
            PathBuf::from("rules//policy.rqlp"),
            PathBuf::from("other.rqlp"),
        ],
        &crate::test_support::evaluation_options("2026-07-27"),
    )
    .unwrap();
    let diagnostics = outcome.report().diagnostics();
    assert!(
        diagnostics.iter().any(|d| {
            d.code() == PolicyReportDiagnosticCode::DuplicatePolicyId
                && d.source().map(PolicySourceIdentity::as_str) == Some("rules/policy.rqlp")
        }),
        "{diagnostics:?}"
    );
}

#[test]
fn match_policy_reports_requested_range_as_workspace_scope() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("app.ts"), "export function target() {}\n").unwrap();
    std::fs::write(
        root.path().join("policy.rqlp"),
        r#"(policy :schema-version 1 :id "test.range" :name "Range" :message "M" :severity warning :analysis (analysis :type match :selector (rql :schema-version 1 (language typescript (function :name "target")))))"#,
    )
    .unwrap();
    let options = crate::test_support::evaluation_options("2026-07-27")
        .with_range(PolicyRangeRequest::Files(vec!["app.ts".to_owned()]));
    let outcome =
        evaluate_policy_files(root.path(), &[PathBuf::from("policy.rqlp")], &options).unwrap();
    let runs = outcome.report().runs();
    assert_eq!(runs.len(), 1);
    let scope = runs[0].scope().expect("requested range is reported");
    assert_eq!(scope.kind(), PolicyRunScopeKind::Workspace);
    assert!(!scope.widened().is_empty());
}

#[test]
fn diff_with_no_runnable_base_marks_report_unreliable() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("app.py"),
        "def create(): return 1\nvalue = create()\n",
    )
    .unwrap();
    std::fs::write(
        root.path().join("policy.rqlp"),
        r#"(policy :schema-version 1 :id "test.qualified" :name "Qualified" :message "M" :severity warning :analysis (analysis :type assertion (bind :name calls :query (rql :schema-version 1 (resolved-call :resolves-to "Widget.create" :proof exact (call-bindings (call-shape (call :callee "create")))))) (group :name by-call :by (calls.id) (aggregate :name violations :op count)) (assert :group by-call :value violations :cardinality (exactly 0))))"#,
    )
    .unwrap();
    run_git(root.path(), &["init"]);
    run_git(root.path(), &["config", "user.email", "test@example.com"]);
    run_git(root.path(), &["config", "user.name", "Test User"]);
    run_git(root.path(), &["add", "."]);
    run_git(root.path(), &["commit", "-m", "base"]);
    let options =
        crate::test_support::evaluation_options("2026-07-27").with_diff_base("HEAD".to_owned());
    let outcome =
        evaluate_policy_files(root.path(), &[PathBuf::from("policy.rqlp")], &options).unwrap();
    assert_eq!(outcome.exit_status(), POLICY_EXIT_UNRELIABLE);
    assert!(outcome.report().diff().expect("diff review").degraded());
    assert!(
        outcome
            .report()
            .diagnostics()
            .iter()
            .any(|d| { d.code() == PolicyReportDiagnosticCode::DiffBaseUnreliable })
    );
}

#[test]
fn built_in_scope_uses_manifest_category() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("src")).unwrap();
    std::fs::create_dir_all(root.path().join(".bifrost")).unwrap();
    std::fs::write(
        root.path().join("src/app.py"),
        "def run(user_code):\n    return eval(user_code)\n",
    )
    .unwrap();
    std::fs::write(
        root.path().join(".bifrost/policy-scope.json"),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "scopes": [{
                "path": "src",
                "reason": "Accepted category scope",
                "policy_categories": ["correctness"]
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    let catalog = crate::builtin::built_in_policy_catalog().unwrap();
    let selection = crate::builtin::BuiltInPolicySelection {
        policy_ids: vec!["bifrost.correctness.dynamic-evaluation".to_owned()],
        ..Default::default()
    };
    let selected = catalog.select(&selection).unwrap();
    assert_eq!(selected.len(), 1);
    let record = crate::builtin::BuiltInPolicySelectionRecord::new(catalog, &selected, &[]);
    let inputs = selected
        .iter()
        .copied()
        .map(PolicyEvaluationInput::selected_builtin)
        .collect::<Vec<_>>();
    let options =
        crate::test_support::evaluation_options("2026-07-27").with_builtin_selection(record);
    let outcome = evaluate_policy_inputs(root.path(), &inputs, &options).unwrap();
    assert!(
        outcome.report().scope()[0].applied(),
        "{:#?}",
        outcome.report()
    );
    assert!(
        outcome.report().runs()[0]
            .findings()
            .iter()
            .any(|finding| finding.scope().is_some())
    );
}

fn partial_head_fixture() -> (tempfile::TempDir, PolicyBatchBudget, PolicyBatchOutcome) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("target.ts"),
        "export function target() {}\n",
    )
    .unwrap();
    std::fs::write(
        root.path().join("caller.ts"),
        "import { target } from './target';\nexport function caller() { target(); }\n",
    )
    .unwrap();
    std::fs::write(
        root.path().join("policy.rqlp"),
        r#"(policy :schema-version 1 :id "test.weak-anchor" :name "Weak anchor" :message "Call selected" :severity warning :analysis (analysis :type match :selector (rql :schema-version 1 (call-sites-to :proof proven (enclosing-decl (where "target.ts" (function :name "target")))))))"#,
    )
    .unwrap();
    run_git(root.path(), &["init"]);
    run_git(root.path(), &["config", "user.email", "test@example.com"]);
    run_git(root.path(), &["config", "user.name", "Test User"]);
    run_git(root.path(), &["add", "."]);
    run_git(root.path(), &["commit", "-m", "base"]);

    let base = report_for_file(root.path(), PathBuf::from("policy.rqlp"));
    assert_eq!(base.report().runs()[0].findings().len(), 1);
    assert!(base.report().runs()[0].completion().is_exhaustive());
    std::fs::write(
        root.path().join("target.ts"),
        "export function target() {          }\n",
    )
    .unwrap();
    let full_head = report_for_file(root.path(), PathBuf::from("policy.rqlp"));
    let head_bytes = usize::try_from(full_head.report().runs()[0].work().scanned_source_bytes())
        .expect("source bytes fit usize");
    let base_bytes = usize::try_from(base.report().runs()[0].work().scanned_source_bytes())
        .expect("source bytes fit usize");
    assert!(
        head_bytes > base_bytes,
        "base={base_bytes} head={head_bytes}"
    );
    let budget = PolicyBudget::builder()
        .with_query_limits(CodeQueryExecutionLimits {
            max_scanned_source_bytes: base_bytes,
            ..CodeQueryExecutionLimits::default()
        })
        .unwrap()
        .build()
        .unwrap();
    let batch_budget = PolicyBatchBudget::builder()
        .with_per_policy(budget)
        .unwrap()
        .build()
        .unwrap();
    (root, batch_budget, base)
}

#[test]
fn weak_head_finding_keeps_weak_diff_identity() {
    use crate::finding::MatchFindingEvidence;
    use crate::finding_identity::{MatchFindingAnchor, OpaqueFindingKey};

    let (_, _, source) = partial_head_fixture();
    let source_run = &source.report().runs()[0];
    let source_finding = &source_run.findings()[0];
    assert_eq!(
        source_finding.identity_stability(),
        FindingIdentityStability::Strong
    );
    let PolicyFindingEvidence::Match { evidence } = source_finding.evidence() else {
        panic!("expected match evidence");
    };
    let weak_evidence = PolicyFindingEvidence::Match {
        evidence: MatchFindingEvidence::try_new(
            evidence.result_domain(),
            MatchFindingAnchor::weak(
                evidence.result_domain(),
                evidence.anchor().path().clone(),
                OpaqueFindingKey::try_new("test", "weak-call").unwrap(),
            ),
            evidence.terminal().clone(),
            evidence.provenance().to_vec(),
            evidence.provenance_truncated(),
        )
        .unwrap(),
    };
    let budget = PolicyBudget::default();
    let weak = PolicyFinding::try_new(
        source_finding.policy_id().clone(),
        source_finding.policy_hash(),
        source_finding.severity(),
        source_finding.message().to_owned(),
        source_finding.classification().clone(),
        source_finding.certainty().clone(),
        crate::FindingCompleteness::partial(vec![crate::FindingIncompleteReason::StableAnchorWeak])
            .unwrap(),
        source_finding.primary().clone(),
        Vec::new(),
        false,
        0,
        weak_evidence,
        false,
        0,
        None,
        None,
        source_finding.proof().clone(),
        Vec::new(),
        false,
        0,
        &budget,
    )
    .unwrap();
    assert_eq!(weak.identity_stability(), FindingIdentityStability::Weak);
    let run = PolicyRun::try_new(
        source_run.policy_id().clone(),
        source_run.policy_hash(),
        PolicyAnalysisType::Match,
        PolicyRunCompletion::inconclusive(vec![PolicyIncompleteReason::StableAnchorUnavailable])
            .unwrap(),
        vec![weak],
        Vec::new(),
        false,
        PolicyWorkReport::default(),
        &budget,
    )
    .unwrap();
    let policy_id = run.policy_id().clone();
    let baseline = PolicyDiffBaseline {
        requested_revision: "HEAD".to_owned(),
        resolved_commit: "0".repeat(40),
        identities: HashMap::from([(policy_id.clone(), HashSet::from([run.findings()[0].id()]))]),
        unqualified_policies: Vec::new(),
        unreliable_detail: None,
        aggregate_unreliable: false,
    };
    let mut runs = HashMap::from([(policy_id.clone(), run)]);
    let review = apply_policy_diff(&baseline, &mut runs).unwrap();
    let finding = &runs[&policy_id].findings()[0];
    assert_eq!(review.new_count(), 1);
    assert_eq!(review.persisting_count(), 0);
    assert_eq!(
        finding.diff().unwrap().disposition(),
        FindingDiffDisposition::New
    );
    assert!(finding.diff().unwrap().weak_identity());
}

#[test]
fn incomplete_head_does_not_mark_absent_baseline_finding() {
    let (root, batch_budget, base) = partial_head_fixture();
    let (baseline, weak_excluded) = PolicyBaselineDocument::from_completed_report(
        base.report(),
        "Accepted base finding",
        None,
        "2026-07-27".parse().unwrap(),
    )
    .unwrap();
    assert_eq!(weak_excluded, 0);
    assert_eq!(baseline.entry_count(), 1);
    std::fs::create_dir_all(root.path().join(".bifrost")).unwrap();
    std::fs::write(
        root.path().join(".bifrost/baseline.json"),
        baseline.to_canonical_json(),
    )
    .unwrap();
    let outcome = evaluate_policy_files_with_limits(
        root.path(),
        &[PathBuf::from("policy.rqlp")],
        &crate::test_support::evaluation_options("2026-07-27"),
        batch_budget,
        PolicyRegistryLimits::default(),
    )
    .unwrap();
    let run = &outcome.report().runs()[0];
    assert!(!run.completion().is_exhaustive(), "{run:?}");
    let review = outcome.report().baseline().expect("baseline review");
    assert!(
        review
            .entries()
            .iter()
            .any(|entry| { entry.match_state() == PolicyBaselineMatchState::PolicyIncomplete }),
        "{review:?}"
    );
}

#[test]
fn one_subset_run_makes_mixed_batch_unreliable() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("Smells.java"),
        r#"class Smells {
    void terminate() { System.exit(1); }
    void directTerminate() { this.terminate(); }
    void secondOrderTerminate() { this.directTerminate(); }
}"#,
    )
    .unwrap();
    std::fs::write(
        root.path().join("subset.rqlp"),
        r#"(policy :schema-version 1 :id "test.subset" :name "Subset" :message "Caller" :severity warning :analysis (analysis :type match :selector (rql :schema-version 1 (language java (callers :depth 2 :proof proven :completeness proven-subset (enclosing-decl (call :receiver (name "System") :callee (name "exit"))))))))"#,
    )
    .unwrap();
    std::fs::write(
        root.path().join("clean.rqlp"),
        r#"(policy :schema-version 1 :id "test.clean" :name "Clean" :message "Absent" :severity warning :analysis (analysis :type match :selector (rql :schema-version 1 (language java (call :callee (name "absent"))))))"#,
    )
    .unwrap();
    let outcome = evaluate_policy_files(
        root.path(),
        &[PathBuf::from("subset.rqlp"), PathBuf::from("clean.rqlp")],
        &crate::test_support::evaluation_options("2026-07-27"),
    )
    .unwrap();
    let runs = outcome.report().runs();
    assert_eq!(runs.len(), 2, "{runs:?}");
    assert!(
        runs.iter()
            .any(|run| matches!(run.completion(), PolicyRunCompletion::ProvenSubset { .. })),
        "{runs:?}"
    );
    assert!(runs.iter().any(|run| run.completion().is_exhaustive()));
    assert_eq!(outcome.exit_status(), POLICY_EXIT_UNRELIABLE);
}

#[test]
fn suppression_rekey_stays_in_the_original_file() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("src")).unwrap();
    std::fs::write(
        root.path().join("src/a.py"),
        "def run(value):\n    return eval(value)\n",
    )
    .unwrap();
    std::fs::write(root.path().join("src/b.py"), "def idle():\n    return 1\n").unwrap();
    std::fs::write(
        root.path().join("policy.rqlp"),
        r#"(policy :schema-version 1 :id "test.rekey" :name "Rekey" :message "Dynamic evaluation" :severity warning :analysis (analysis :type match :selector (rql :schema-version 1 (language python (call :callee (name "eval"))))))"#,
    )
    .unwrap();
    let original = report_for_file(root.path(), PathBuf::from("policy.rqlp"));
    let rule = &original.report().rules()[0];
    let finding = &original.report().runs()[0].findings()[0];
    assert_eq!(finding.primary().path(), "src/a.py");
    let record = crate::policy_suppressions::accepted_suppression_record(
        rule.policy_id().as_str(),
        &finding.id().to_string(),
        Some(&rule.policy_hash().to_string()),
        "Accepted original file",
        None,
        None,
        Some("src/a.py"),
    );
    crate::policy_suppressions::write_policy_suppressions(
        root.path(),
        DEFAULT_POLICY_SUPPRESSION_PATH,
        vec![record],
    );
    std::fs::write(root.path().join("src/a.py"), "def idle():\n    return 1\n").unwrap();
    std::fs::write(
        root.path().join("src/b.py"),
        "def run(value):\n    return eval(value)\n",
    )
    .unwrap();
    let moved = report_for_file(root.path(), PathBuf::from("policy.rqlp"));
    assert_eq!(moved.report().runs()[0].findings().len(), 1);
    let reviews = moved.report().suppressions();
    assert!(
        reviews
            .iter()
            .any(|review| { review.is_orphaned() && review.rekey_candidates().is_empty() }),
        "{reviews:?}"
    );
}

#[test]
fn unqualified_diff_base_keeps_tree_diagnostics() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join(".bifrost")).unwrap();
    std::fs::write(
        root.path().join("service.ts"),
        "class Service { run() {} }\nexport function call(s: Service) { s.run(); }\n",
    )
    .unwrap();
    std::fs::write(root.path().join(".bifrost/suppressions.json"), "{").unwrap();
    std::fs::write(
        root.path().join("receiver.rqlp"),
        r#"(policy :schema-version 1 :id "test.receiver" :name "Receiver" :message "M" :severity warning :analysis (analysis :type match :selector (rql :schema-version 1 (receiver-targets (call :callee (name "run"))))) )"#,
    )
    .unwrap();
    run_git(root.path(), &["init"]);
    run_git(root.path(), &["config", "user.email", "test@example.com"]);
    run_git(root.path(), &["config", "user.name", "Test User"]);
    run_git(root.path(), &["add", "."]);
    run_git(root.path(), &["commit", "-m", "base"]);
    let budget = PolicyBatchBudget::builder()
        .with_per_policy(
            PolicyBudget::builder()
                .with_max_diagnostics(0)
                .unwrap()
                .build()
                .unwrap(),
        )
        .unwrap()
        .build()
        .unwrap();
    let outcome = evaluate_policy_files_with_limits(
        root.path(),
        &[PathBuf::from("receiver.rqlp")],
        &crate::test_support::evaluation_options("2026-07-27").with_diff_base("HEAD".to_owned()),
        budget,
        PolicyRegistryLimits::default(),
    )
    .unwrap();
    let unqualified = outcome
        .report()
        .diff()
        .expect("diff review")
        .unqualified_policies()
        .iter()
        .find(|policy| policy.policy_id().as_str() == "test.receiver")
        .unwrap_or_else(|| {
            panic!(
                "diff={:#?} diagnostics={:#?}",
                outcome.report().diff(),
                outcome.report().diagnostics()
            )
        });
    assert!(
        unqualified.diagnostics().iter().any(|entry| {
            serde_json::from_str::<serde_json::Value>(entry)
                .ok()
                .is_some_and(|value| value["code"] == "suppression-load-failed")
        }),
        "{unqualified:?}"
    );
}

#[test]
fn truncated_base_diagnostics_remain_unqualified_on_reuse() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("service.ts"),
        "class Service { run() {} }\nexport function call(s: Service) { s.run(); }\n",
    )
    .unwrap();
    std::fs::write(
        root.path().join("receiver.rqlp"),
        r#"(policy :schema-version 1 :id "test.receiver" :name "Receiver" :message "M" :severity warning :analysis (analysis :type match :selector (rql :schema-version 1 (receiver-targets (call :callee (name "run"))))) )"#,
    )
    .unwrap();
    run_git(root.path(), &["init"]);
    run_git(root.path(), &["config", "user.email", "test@example.com"]);
    run_git(root.path(), &["config", "user.name", "Test User"]);
    run_git(root.path(), &["add", "."]);
    run_git(root.path(), &["commit", "-m", "base"]);
    let budget = PolicyBatchBudget::builder()
        .with_per_policy(
            PolicyBudget::builder()
                .with_max_diagnostics(0)
                .unwrap()
                .build()
                .unwrap(),
        )
        .unwrap()
        .build()
        .unwrap();
    let options =
        crate::test_support::evaluation_options("2026-07-27").with_diff_base("HEAD".to_owned());
    for iteration in 0..2 {
        let outcome = evaluate_policy_files_with_limits(
            root.path(),
            &[PathBuf::from("receiver.rqlp")],
            &options,
            budget,
            PolicyRegistryLimits::default(),
        )
        .unwrap();
        let review = outcome.report().diff().expect("diff review");
        assert_eq!(
            outcome.incremental().expect("incremental review").base(),
            if iteration == 0 {
                IncrementalBaseState::Evaluated
            } else {
                IncrementalBaseState::Reused
            }
        );
        assert_eq!(review.unqualified_policies().len(), 1, "{review:?}");
        assert_eq!(
            review.unqualified_policies()[0].policy_id().as_str(),
            "test.receiver"
        );
        assert_eq!(review.fixed_count(), 0);
    }
}

#[test]
fn completed_unqualified_persisted_base_is_not_admitted() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("app.ts"), "export function target() {}\n").unwrap();
    run_git(root.path(), &["init"]);
    run_git(root.path(), &["config", "user.email", "test@example.com"]);
    run_git(root.path(), &["config", "user.name", "Test User"]);
    run_git(root.path(), &["add", "."]);
    run_git(root.path(), &["commit", "-m", "base"]);
    let workspace = WorkspaceAnalyzer::build_persisted(
        Arc::new(owned_policy_project(root.path()).unwrap()),
        AnalyzerConfig::default(),
    )
    .unwrap();
    let store = BatchUnitStore::of(Some(&workspace));
    let catalogs = Arc::new(
        TaintCatalogRegistry::new_for_workspace(
            root.path().to_path_buf(),
            CatalogRegistryLimits::default(),
        )
        .unwrap(),
    );
    let mut registry = PolicyRegistry::new_for_workspace(
        root.path().to_path_buf(),
        catalogs,
        PolicyRegistryLimits::default(),
    )
    .unwrap();
    let source = r#"(policy :schema-version 1 :id "test.persisted" :name "Persisted" :message "M" :severity warning :analysis (analysis :type match :selector (rql :schema-version 1 (function :name "target"))))"#;
    let policy = registry
        .register_policy_bytes_with_analyzer(
            PolicySourceIdentity::new("policy.rqlp"),
            source.as_bytes(),
            workspace.analyzer(),
        )
        .unwrap();
    let policies = [policy];
    let subtree = resolve_revision_subtree(root.path(), "HEAD").unwrap();
    let inputs = WorkspaceUnitInputs::of(&workspace, None);
    let mut key = base_evaluation_key(
        &crate::test_support::evaluation_options("2026-07-27"),
        None,
        PolicyBatchBudget::default(),
        PolicyRegistryLimits::default(),
        inputs,
    );
    key.base_tree_oid = subtree.tree_id().to_string();
    let row = PolicyEvaluationRow {
        key: key.clone(),
        resolved_commit: subtree.commit_id().to_string(),
        policy_set_digest: policy_set_digest(&policies),
        unreliable_detail: Some("base report diagnostics were truncated".to_owned()),
        aggregate_unreliable: true,
        base_content_identity: [1; 32],
        unqualified_policy_ids: vec!["test.persisted".to_owned()],
        policies: vec![PolicyEvaluationPolicyRow {
            policy_id: "test.persisted".to_owned(),
            source_hash: policy.source_hash().to_string(),
            semantic_hash: policy.semantic_hash().to_string(),
            completion: "complete".to_owned(),
            completion_detail: "\"complete\"".to_owned(),
            qualified: false,
            qualification_detail: "base report diagnostics were truncated".to_owned(),
            diagnostics: Vec::new(),
            identities: Vec::new(),
            units: Vec::new(),
        }],
    };
    store
        .persisted()
        .expect("persisted store")
        .lock()
        .unwrap()
        .store()
        .publish_policy_evaluation(row)
        .unwrap();
    let replay =
        reuse_persisted_diff_baseline(root.path(), &workspace, "HEAD", &policies, &store, &key)
            .expect("persisted base reused");
    assert_eq!(replay.state, IncrementalBaseState::Reused);
    assert_eq!(replay.baseline.unqualified_policies.len(), 1);
    assert_eq!(
        replay.baseline.unqualified_policies[0].completion(),
        "complete"
    );
    assert!(
        !replay
            .baseline
            .identities
            .contains_key(&policy.definition().metadata.id)
    );
}

fn conflicting_schema_report() -> PolicyBatchOutcome {
    report_for_document(
        r#"(policy :id "test.conflict" :name "Conflict" :message "M" :severity warning :analysis (analysis :type match :rql-schema-version 1 :selector (rql :schema-version 3 (call))))"#,
    )
}

#[test]
fn conflicting_rql_schema_keeps_its_diagnostic_code() {
    let outcome = conflicting_schema_report();
    let diagnostics = outcome.report().diagnostics();
    assert!(
        diagnostics
            .iter()
            .any(|d| { d.code() == PolicyReportDiagnosticCode::ConflictingRqlSchemaVersion }),
        "{diagnostics:?}"
    );
}

#[test]
fn conflicting_rql_schema_keeps_related_location() {
    let outcome = conflicting_schema_report();
    let diagnostics = outcome.report().diagnostics();
    assert!(
        diagnostics.iter().any(|d| {
            d.code() == PolicyReportDiagnosticCode::ConflictingRqlSchemaVersion
                && !d.related().is_empty()
        }),
        "{diagnostics:?}"
    );
}

#[test]
fn control_character_policy_filename_is_rejected() {
    let root = tempfile::tempdir().unwrap();
    let source = r#"(policy :schema-version 1 :id "test.invalid-source" :name "Invalid source" :message "M" :severity warning :analysis (analysis :type match :selector (rql :schema-version 1 (call))))"#;
    let input =
        PolicyEvaluationInput::embedded(PolicySourceIdentity::new("rules/bad\nname.rqlp"), source);
    let outcome = evaluate_policy_inputs(
        root.path(),
        &[input],
        &crate::test_support::evaluation_options("2026-07-27"),
    )
    .unwrap();
    let diagnostics = outcome.report().diagnostics();
    assert!(
        diagnostics.iter().any(|d| {
            d.code() == PolicyReportDiagnosticCode::PolicyValidationFailed
                && d.source()
                    .is_some_and(|s| s.as_str().starts_with("invalid-source:sha256:"))
        }),
        "{diagnostics:?}"
    );
}

#[test]
fn backslash_policy_path_uses_slashes_in_diagnostic_source() {
    let root = tempfile::tempdir().unwrap();
    let outcome = report_for_file(root.path(), PathBuf::from(r"rules\missing.rqlp"));
    let diagnostics = outcome.report().diagnostics();
    assert!(
        diagnostics.iter().any(|d| {
            d.code() == PolicyReportDiagnosticCode::PolicyLoadFailed
                && d.source().map(PolicySourceIdentity::as_str) == Some("rules/missing.rqlp")
        }),
        "{diagnostics:?}"
    );
}

#[test]
fn long_missing_policy_path_keeps_diagnostic_tail() {
    let root = tempfile::tempdir().unwrap();
    let path = PathBuf::from("a".repeat(180))
        .join("b".repeat(180))
        .join("missing.rqlp");
    let outcome = report_for_file(root.path(), path);
    let diagnostics = outcome.report().diagnostics();
    assert!(
        diagnostics.iter().any(|d| {
            d.code() == PolicyReportDiagnosticCode::PolicyLoadFailed
                && d.message().contains(&"b".repeat(100))
        }),
        "{diagnostics:?}"
    );
}

#[test]
fn invalid_enum_newline_is_escaped_in_report_diagnostic() {
    let source = r#"(policy :id "test.newline" :name "Newline" :message "M" :severity (cvss-severity :when-unscored "bad\nvalue") :analysis (analysis :type match :selector (rql :schema-version 1 (call))))"#;
    let outcome = report_for_document(source);
    let diagnostics = outcome.report().diagnostics();
    assert!(
        diagnostics
            .iter()
            .any(|d| { d.message().contains("\\u{A}") && !d.message().contains('\n') }),
        "{diagnostics:?}"
    );
}
