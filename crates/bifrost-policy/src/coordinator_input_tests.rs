use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::*;
use crate::DEFAULT_POLICY_SUPPRESSION_PATH;
use crate::inline_project::run_git;
use crate::{PolicyAnalysisType, PolicyFindingEvidence, PolicyRunScopeKind};
use brokk_bifrost_analysis::analyzer::reuse_verdict::{SelectionEvidence, SelectionView};

fn report_for_file(root: &Path, path: PathBuf) -> PolicyBatchOutcome {
    evaluate_policy_files(
        root,
        &[path],
        &crate::test_support::evaluation_options("2026-07-27"),
        &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
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
        &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
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
    let outcome = evaluate_policy_files(
        root.path(),
        &[PathBuf::from("policy.rqlp")],
        &options,
        &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
    )
    .unwrap();
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
    let outcome = evaluate_policy_files(
        root.path(),
        &[PathBuf::from("policy.rqlp")],
        &options,
        &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
    )
    .unwrap();
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
    let outcome = evaluate_policy_inputs(
        root.path(),
        &inputs,
        &options,
        &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
    )
    .unwrap();
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
        &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
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
#[brokk_bifrost_test_macros::hardwon(
    "#9030: the subset-run test passed or failed depending on the host JAVA_HOME"
)]
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
    let project =
        brokk_bifrost_analysis::analyzer::FilesystemProject::new(root.path().to_path_buf())
            .unwrap();
    let project: Arc<dyn brokk_bifrost_analysis::analyzer::Project> = Arc::new(project);
    let mut analyzer_config = brokk_bifrost_analysis::analyzer::AnalyzerConfig::default();
    analyzer_config
        .jvm
        .standard_library_discovery
        .discover_java_home = false;
    analyzer_config
        .jvm
        .standard_library_discovery
        .jdk_homes
        .clear();
    analyzer_config
        .jvm
        .standard_library_discovery
        .source_toolchains
        .clear();
    let workspace = brokk_bifrost_analysis::analyzer::WorkspaceAnalyzer::build_ephemeral_footgun(
        project,
        analyzer_config,
    )
    .unwrap();
    let outcome = evaluate_policy_files_with_analyzer(
        root.path(),
        &[PathBuf::from("subset.rqlp"), PathBuf::from("clean.rqlp")],
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &crate::test_support::evaluation_options("2026-07-27"),
        None,
        &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
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
        &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
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
            &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
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
    let inputs = WorkspaceUnitInputs::of(&workspace, None, None);
    let mut key = base_evaluation_key(
        &crate::test_support::evaluation_options("2026-07-27"),
        None,
        inputs,
    );
    key.base_tree_oid = subtree.tree_id().to_string();
    let evidence = replay_evidence(
        effective_grant(
            PolicyBatchBudget::default(),
            certified_source_census(&workspace, &subtree).unwrap(),
        ),
        PolicyRegistryLimits::default(),
        certified_source_census(&workspace, &subtree).unwrap(),
    );
    let row = PolicyEvaluationRow {
        cut_hint_digest: None,
        evidence: Some(evidence.clone()),
        evidence_complete: Some(false),
        key: key.clone(),
        resolved_commit: subtree.commit_id().to_string(),
        policy_set_digest: policy_set_digest(&policies),
        unreliable_detail: Some("base report diagnostics were truncated".to_owned()),
        aggregate_unreliable: true,
        base_content_identity: [1; 32],
        unqualified_policy_ids: vec!["test.persisted".to_owned()],
        selection_reads: Vec::new(),
        selection_view: SelectionView::Worktree,
        policies: vec![PolicyEvaluationPolicyRow {
            evidence: Some(evidence.clone()),
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
        .publish_policy_evaluation(
            admit(
                brokk_bifrost_analysis::analyzer::reuse_verdict::CapBinding::Unbound,
                row,
                ReuseVerdict::Content,
                ReuseVerdict::Content,
                SelectionEvidence::NotApplicable,
            )
            .unwrap(),
        )
        .unwrap();
    let replay = reuse_persisted_diff_baseline(
        root.path(),
        &workspace,
        "HEAD",
        &policies,
        &store,
        &key,
        PolicyBatchBudget::default(),
        PolicyRegistryLimits::default(),
        &HashMap::new(),
    )
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

/// A stored evaluation row is selected by its key, and the key does not state
/// the discovery or environment its answer was computed under. The row carries
/// the selection reads it consumed, and replay recomputes each against the head
/// through the same admission as the write (#11482).
#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#11482: a stored aggregate was replayed without checking the Go selection it consumed"
)]
fn persisted_base_replays_only_while_its_selection_reads_hold() {
    use brokk_bifrost_analysis::analyzer::read_ledger::{LookupKind, LookupQuestion};
    use brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest;
    use brokk_bifrost_analysis::analyzer::{FactSubject, Language, WorkspaceFactFamily};
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("go.mod"),
        "module example.com/repro\n\ngo 1.23\n",
    )
    .unwrap();
    std::fs::write(
        root.path().join("app.go"),
        "package repro\nfunc target() {}\n",
    )
    .unwrap();
    run_git(root.path(), &["init"]);
    run_git(root.path(), &["config", "user.email", "test@example.com"]);
    run_git(root.path(), &["config", "user.name", "Test User"]);
    run_git(root.path(), &["add", "."]);
    run_git(root.path(), &["commit", "-m", "base"]);
    let build = || {
        WorkspaceAnalyzer::build_persisted(
            Arc::new(owned_policy_project(root.path()).unwrap()),
            AnalyzerConfig::default(),
        )
        .unwrap()
    };
    let workspace = build();
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
    let mut key = base_evaluation_key(
        &crate::test_support::evaluation_options("2026-07-27"),
        None,
        WorkspaceUnitInputs::of(&workspace, None, None),
    );
    key.base_tree_oid = subtree.tree_id().to_string();
    let census = certified_source_census(&workspace, &subtree).unwrap();
    let evidence = replay_evidence(
        effective_grant(PolicyBatchBudget::default(), census),
        PolicyRegistryLimits::default(),
        certified_source_census(&workspace, &subtree).unwrap(),
    );
    // The reads a Go evaluation consumed, as the authority answers them now.
    let read = |name: &str, answer: Option<StableDigest>| {
        let subject = FactSubject::Named { name: name.into() };
        let answer = answer.unwrap_or_else(|| {
            brokk_bifrost_analysis::analyzer::languages::language_support(Language::Go)
                .expect("Go language support")
                .workspace_fact_answer(
                    workspace.analyzer(),
                    WorkspaceFactFamily::GoBuildSelection,
                    Language::Go,
                    &subject,
                )
                .unwrap_or_else(|| panic!("the Go {name} selection answers"))
        });
        brokk_bifrost_analysis::analyzer::ReadKey::lookup(
            LookupKind::WorkspaceFact,
            LookupQuestion::WorkspaceFact {
                family: WorkspaceFactFamily::GoBuildSelection,
                language: Language::Go,
                subject,
            },
            answer,
        )
    };
    let publish = |selection_reads: Vec<brokk_bifrost_analysis::analyzer::ReadKey>| {
        let row = PolicyEvaluationRow {
            cut_hint_digest: None,
            evidence: Some(evidence.clone()),
            evidence_complete: Some(true),
            key: key.clone(),
            resolved_commit: subtree.commit_id().to_string(),
            policy_set_digest: policy_set_digest(&policies),
            unreliable_detail: None,
            aggregate_unreliable: false,
            base_content_identity: [1; 32],
            unqualified_policy_ids: Vec::new(),
            selection_reads: selection_reads
                .iter()
                .cloned()
                .map(brokk_bifrost_analysis::analyzer::read_ledger::SelectionRead::keyed)
                .collect(),
            selection_view: SelectionView::Worktree,
            policies: vec![PolicyEvaluationPolicyRow {
                evidence: Some(evidence.clone()),
                policy_id: "test.persisted".to_owned(),
                source_hash: policies[0].source_hash().to_string(),
                semantic_hash: policies[0].semantic_hash().to_string(),
                completion: "complete".to_owned(),
                completion_detail: "\"complete\"".to_owned(),
                qualified: true,
                qualification_detail: String::new(),
                diagnostics: Vec::new(),
                identities: Vec::new(),
                units: Vec::new(),
            }],
        };
        let reads = brokk_bifrost_analysis::analyzer::read_ledger::recordable_selection_evidence(
            &selection_reads,
        );
        store
            .persisted()
            .expect("persisted store")
            .lock()
            .unwrap()
            .store()
            .publish_policy_evaluation(
                admit(
                    brokk_bifrost_analysis::analyzer::reuse_verdict::CapBinding::RecordedGrant,
                    row,
                    ReuseVerdict::Content,
                    ReuseVerdict::Content,
                    reads,
                )
                .unwrap(),
            )
            .unwrap();
    };
    let replay = |head: &WorkspaceAnalyzer| {
        reuse_persisted_diff_baseline(
            root.path(),
            head,
            "HEAD",
            &policies,
            &store,
            &key,
            PolicyBatchBudget::default(),
            PolicyRegistryLimits::default(),
            &HashMap::new(),
        )
    };
    // The head is the committed base tree.
    publish(vec![read("profile", None)]);
    assert!(replay(&workspace).is_some(), "the recorded profile holds");
    // The same tree and key, discovered under a different environment: the
    // recorded profile answer no longer holds.
    publish(vec![read(
        "profile",
        Some(StableDigest::from_array([9; 32])),
    )]);
    assert!(replay(&workspace).is_none());
    publish(vec![read(
        "domains",
        Some(StableDigest::from_array([9; 32])),
    )]);
    assert!(replay(&workspace).is_none());
    // The head is the base tree, so tree-dependent selection can be checked.
    publish(vec![read("profile", None), read("domains", None)]);
    assert!(replay(&workspace).is_some());
    // The membership of the root domain certifies every discovery output analysis
    // reads, not only package and file names: the same names with another
    // completeness, gap list or provider version must not replay (#11482).
    let membership = || {
        let subject = FactSubject::NamedMember {
            owner: "".into(),
            member: "".into(),
        };
        let answer = brokk_bifrost_analysis::analyzer::languages::language_support(Language::Go)
            .expect("Go language support")
            .workspace_fact_answer(
                workspace.analyzer(),
                WorkspaceFactFamily::GoBuildSelection,
                Language::Go,
                &subject,
            )
            .expect("the root domain membership answers");
        brokk_bifrost_analysis::analyzer::ReadKey::lookup(
            LookupKind::WorkspaceFact,
            LookupQuestion::WorkspaceFact {
                family: WorkspaceFactFamily::GoBuildSelection,
                language: Language::Go,
                subject,
            },
            answer,
        )
    };
    publish(vec![read("profile", None), membership()]);
    assert!(
        replay(&workspace).is_some(),
        "the recorded membership holds"
    );
    for change in [
        "UPDATE go_package_instances SET complete=1-complete",
        "UPDATE go_package_instances SET gaps=jsonb(json_insert(json(gaps),'$[#]',json('{\"code\":\"gone\"}')))",
        "UPDATE go_package_instances SET provider_module_version=coalesce(provider_module_version,'')||'v9'",
    ] {
        publish(vec![read("profile", None), membership()]);
        assert!(replay(&workspace).is_some(), "{change}: before the change");
        let analyzer_store = store
            .persisted()
            .expect("persisted store")
            .lock()
            .unwrap()
            .store()
            .clone();
        analyzer_store.conn.execute(move |conn| {
            assert!(conn.execute(change, []).unwrap() > 0, "{change}");
        });
        assert!(
            replay(&workspace).is_none(),
            "{change}: same names, changed discovery state"
        );
    }
    // A head that differs from the base can check only the environment.
    std::fs::write(
        root.path().join("app.go"),
        "package repro\nfunc target() {}\nfunc added() {}\n",
    )
    .unwrap();
    let edited = build();
    assert!(
        replay(&edited).is_none(),
        "tree-dependent selection cannot be verified against a different head"
    );
    publish(vec![read("profile", None)]);
    assert!(
        replay(&edited).is_some(),
        "an environment-only read verifies against the head, whatever tree it holds"
    );
}

/// A stored evaluation row is selected by its key alone, with no read
/// verification, so a query-time dispatch change that moves the ICFG provider
/// pair (and no policy substrate token) must make the row unreachable.
/// Moving the literals in a test is not possible, so the bumped pair is stated
/// through the key seam; the row itself is the one a real run stored.
#[test]
fn stored_evaluation_row_is_not_served_under_a_bumped_icfg_pair() {
    use brokk_bifrost_analysis::analyzer::semantic::icfg::{
        workspace_icfg_provider_behavior_domain, workspace_icfg_provider_read_behavior_domain,
    };
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("app.ts"), "export function target() {}\n").unwrap();
    std::fs::write(
        root.path().join("policy.rqlp"),
        r#"(policy :schema-version 1 :id "test.persisted" :name "Persisted" :message "M" :severity warning :analysis (analysis :type match :selector (rql :schema-version 1 (function :name "target"))))"#,
    )
    .unwrap();
    run_git(root.path(), &["init"]);
    run_git(root.path(), &["config", "user.email", "test@example.com"]);
    run_git(root.path(), &["config", "user.name", "Test User"]);
    run_git(root.path(), &["add", "."]);
    run_git(root.path(), &["commit", "-m", "base"]);
    let options =
        crate::test_support::evaluation_options("2026-07-27").with_diff_base("HEAD".to_owned());
    let outcome = evaluate_policy_files_with_limits(
        root.path(),
        &[PathBuf::from("policy.rqlp")],
        &options,
        PolicyBatchBudget::default(),
        PolicyRegistryLimits::default(),
        &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
    )
    .unwrap();
    assert_eq!(
        outcome.incremental().expect("incremental review").base(),
        IncrementalBaseState::Evaluated
    );

    let workspace = WorkspaceAnalyzer::build_persisted(
        Arc::new(owned_policy_project(root.path()).unwrap()),
        AnalyzerConfig::default(),
    )
    .unwrap();
    let activation = activate_owned_policy_workspace(
        root.path(),
        &workspace,
        None,
        &CancellationToken::default(),
    )
    .unwrap();
    let models = ready_policy_semantic_model_snapshot(activation.as_ref());
    let inputs = WorkspaceUnitInputs::of(&workspace, models.as_deref(), None);
    let tree_id = resolve_revision_subtree(root.path(), "HEAD")
        .unwrap()
        .tree_id()
        .to_string();
    let with_pair = |behavior: &[u8], read: &[u8]| PolicyEvaluationRowKey {
        base_tree_oid: tree_id.clone(),
        ..base_evaluation_key_under_icfg_domains(&options, None, inputs, (behavior, read))
    };
    let current = with_pair(
        workspace_icfg_provider_behavior_domain(),
        workspace_icfg_provider_read_behavior_domain(),
    );
    assert_eq!(
        current,
        PolicyEvaluationRowKey {
            base_tree_oid: tree_id.clone(),
            ..base_evaluation_key(&options, None, inputs)
        }
    );
    let bumped_behavior = [workspace_icfg_provider_behavior_domain(), b"-next"].concat();
    let bumped_read = [workspace_icfg_provider_read_behavior_domain(), b"-next"].concat();
    // Either half alone is enough to change the key: they are two identities
    // of one lever file, and the key folds both.
    let bumped = with_pair(&bumped_behavior, &bumped_read);
    let behavior_only = with_pair(
        &bumped_behavior,
        workspace_icfg_provider_read_behavior_domain(),
    );
    let read_only = with_pair(workspace_icfg_provider_behavior_domain(), &bumped_read);
    for other in [&bumped, &behavior_only, &read_only] {
        assert_ne!(&current, other);
    }

    let store = workspace.store().expect("persisted store");
    assert!(
        store
            .policy_evaluation_for_key(&current, &[0; 32])
            .unwrap()
            .is_some(),
        "the real run stored its base row under the current pair"
    );
    for other in [&bumped, &behavior_only, &read_only] {
        assert!(
            store
                .policy_evaluation_for_key(other, &[0; 32])
                .unwrap()
                .is_none(),
            "a row stored under the old pair must not be served under {other:?}"
        );
    }
    // #12527: a policy-substrate change retires rendered diagnostic prose in
    // base evidence as well as unit outputs. The store deliberately returns
    // opaque diagnostic JSON; the current renderer must never see this row.
    let previous = PolicyEvaluationRowKey {
        base_tree_oid: tree_id,
        ..base_evaluation_key(
            &options,
            None,
            inputs.with_previous_epoch(&workspace, models.as_deref()),
        )
    };
    assert_ne!(previous.engine_epoch, current.engine_epoch);
    let diagnostic = PolicyDiagnostic::try_new(
        PolicyDiagnosticCode::CodeQuery {
            code: crate::finding::PolicyCodeQueryDiagnostic::try_from(
                brokk_bifrost_rql::CodeQueryDiagnosticCode::SemanticAnalysisPartial,
            )
            .unwrap(),
        },
        PolicyDiagnosticSeverity::Warning,
        PolicyDiagnosticImpact::RunIncomplete,
        "ownership lexical guard refused",
        None,
        Vec::new(),
        crate::finding::RelatedLocationOmissions::Known(0),
    )
    .unwrap();
    let mut old_wire = serde_json::to_value(&diagnostic).unwrap();
    old_wire["message"] = serde_json::Value::String("x".repeat(4_785));
    let old_diagnostic = serde_json::to_string(&old_wire).unwrap();
    let diagnostics = serde_json::to_string(&vec![old_diagnostic.clone()]).unwrap();
    let old_epoch = previous.engine_epoch.clone();
    let new_key = current.clone();
    store.execute_selection_publication(move |conn| {
        assert_eq!(conn.execute(
            "UPDATE policy_evaluations SET engine_epoch=?1 WHERE base_tree_oid=?2 AND options_digest=?3 AND configuration_fingerprint=?4 AND active_model_set_hash=?5 AND engine_epoch=?6",
            (&old_epoch, &new_key.base_tree_oid, &new_key.options_digest, &new_key.configuration_fingerprint, &new_key.active_model_set_hash, &new_key.engine_epoch),
        ).unwrap(), 1);
        assert_eq!(conn.execute(
            "UPDATE policy_evaluation_policies SET diagnostics=?1 WHERE evaluation_id IN (SELECT evaluation_id FROM policy_evaluations WHERE engine_epoch=?2)",
            (&diagnostics, &old_epoch),
        ).unwrap(), 1);
    });
    let stored_old = store
        .policy_evaluation_for_key(&previous, &[0; 32])
        .unwrap()
        .unwrap();
    assert_eq!(
        stored_old.policies[0].diagnostics.as_slice(),
        std::slice::from_ref(&old_diagnostic)
    );
    assert!(
        store
            .policy_evaluation_for_key(&current, &[0; 32])
            .unwrap()
            .is_none(),
        "old prose cannot be served under the new substrate"
    );
    let refreshed = evaluate_policy_files_with_limits(
        root.path(),
        &[PathBuf::from("policy.rqlp")],
        &options,
        PolicyBatchBudget::default(),
        PolicyRegistryLimits::default(),
        &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
    )
    .unwrap();
    assert_eq!(
        refreshed.incremental().unwrap().base(),
        IncrementalBaseState::Evaluated
    );
    let current_row = store
        .policy_evaluation_for_key(&current, &[0; 32])
        .unwrap()
        .unwrap();
    assert!(
        current_row
            .policies
            .iter()
            .all(|policy| !policy.diagnostics.contains(&old_diagnostic))
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
        &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
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

/// Reuse of a stored diff base across a head that differs from the base tree
/// (#11607). Each fixture commits a project, evaluates it against `HEAD`, and
/// then evaluates again with one unrelated tracked file edited at the head.
mod export_determined_base_reuse {
    use super::*;
    use brokk_bifrost_analysis::analyzer::WorkspaceFactFamily;
    use brokk_bifrost_analysis::analyzer::read_ledger::{LookupKind, LookupQuestion, ReadKey};

    static ENVIRONMENT: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn commit_repo(files: &[(&str, &str)]) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        for (path, content) in files {
            let path = root.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, content).unwrap();
        }
        run_git(root.path(), &["init"]);
        run_git(root.path(), &["config", "user.email", "test@example.com"]);
        run_git(root.path(), &["config", "user.name", "Test User"]);
        run_git(root.path(), &["add", "."]);
        run_git(root.path(), &["commit", "-m", "base"]);
        root
    }

    fn options() -> PolicyEvaluationOptions {
        crate::test_support::evaluation_options("2026-07-27").with_diff_base("HEAD".to_owned())
    }

    fn base_state(root: &Path) -> IncrementalBaseState {
        evaluate_policy_files_with_limits(
            root,
            &[PathBuf::from("policy.rqlp")],
            &options(),
            PolicyBatchBudget::default(),
            PolicyRegistryLimits::default(),
            &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
        )
        .unwrap()
        .incremental()
        .expect("incremental review")
        .base()
    }

    /// The evaluation row the last run stored for the base tree.
    fn stored_row(
        root: &Path,
    ) -> brokk_bifrost_analysis::analyzer::store::policy_units::LoadedPolicyEvaluation {
        base_row(root).expect("the run stored a base row")
    }

    fn base_row(
        root: &Path,
    ) -> Option<brokk_bifrost_analysis::analyzer::store::policy_units::LoadedPolicyEvaluation> {
        let workspace = WorkspaceAnalyzer::build_persisted(
            Arc::new(owned_policy_project(root).unwrap()),
            AnalyzerConfig::default(),
        )
        .unwrap();
        let activation =
            activate_owned_policy_workspace(root, &workspace, None, &CancellationToken::default())
                .unwrap();
        let models = ready_policy_semantic_model_snapshot(activation.as_ref());
        let inputs = WorkspaceUnitInputs::of(&workspace, models.as_deref(), None);
        let key = PolicyEvaluationRowKey {
            base_tree_oid: resolve_revision_subtree(root, "HEAD")
                .unwrap()
                .tree_id()
                .to_string(),
            ..base_evaluation_key(&options(), None, inputs)
        };
        workspace
            .store()
            .expect("persisted store")
            .policy_evaluation_for_key(&key, &[0; 32])
            .unwrap()
    }

    fn families(
        row: &brokk_bifrost_analysis::analyzer::store::policy_units::LoadedPolicyEvaluation,
    ) -> Vec<WorkspaceFactFamily> {
        row.selection_reads
            .iter()
            .filter_map(|read| match &read.key {
                ReadKey::Lookup {
                    question: LookupQuestion::WorkspaceFact { family, .. },
                    ..
                } => Some(*family),
                _ => None,
            })
            .collect()
    }

    fn touch(root: &Path, path: &str, text: &str) {
        let path = root.join(path);
        let mut content = std::fs::read_to_string(&path).unwrap();
        content.push_str(text);
        std::fs::write(path, content).unwrap();
    }

    const POLICY: &str = r#"(policy :schema-version 1 :id "test.persisted" :name "Persisted" :message "M" :severity warning :analysis (analysis :type match :selector (rql :schema-version 1 (function :name "Target"))))"#;
    const PROJECT: &str = r#"<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>"#;

    fn csharp_fixture() -> tempfile::TempDir {
        commit_repo(&[
            ("policy.rqlp", POLICY),
            ("App.csproj", PROJECT),
            ("Directory.Build.props", "<Project />"),
            ("Target.cs", "class A { void Target() {} }\n"),
            ("Other.cs", "class B { void Other() {} }\n"),
        ])
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11607: a base recorded over an export was refused for every head that differed from its tree"
    )]
    fn a_csharp_configuration_read_replays_over_an_edited_head() {
        let root = csharp_fixture();
        assert_eq!(base_state(root.path()), IncrementalBaseState::Evaluated);
        let row = stored_row(root.path());
        assert!(
            families(&row).contains(&WorkspaceFactFamily::CSharpCompilationConfiguration),
            "{:?}",
            row.selection_reads
        );
        assert!(
            row.selection_view.is_export_of(
                &resolve_revision_subtree(root.path(), "HEAD")
                    .unwrap()
                    .tree_id()
                    .to_string()
            )
        );
        assert_eq!(base_state(root.path()), IncrementalBaseState::Reused);
        touch(root.path(), "Other.cs", "// an unrelated edit\n");
        assert_eq!(
            base_state(root.path()),
            IncrementalBaseState::Reused,
            "an unrelated tracked edit at the head leaves the exported base's answer as recorded"
        );
    }

    /// An uninitialized submodule contributes no listing omission and an
    /// initialized one an unknown omission, so the export is not a function of
    /// its tree and its row is not admitted as an export.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11607: a tree holding a gitlink was admitted as an export although its listing depends on the checkout"
    )]
    fn a_tree_with_a_gitlink_is_not_admitted_as_an_export() {
        let root = csharp_fixture();
        let head = String::from_utf8(
            std::process::Command::new("git")
                .args(["rev-parse", "HEAD"])
                .current_dir(root.path())
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap();
        run_git(
            root.path(),
            &[
                "update-index",
                "--add",
                "--cacheinfo",
                &format!("160000,{},vendored", head.trim()),
            ],
        );
        run_git(root.path(), &["commit", "-m", "gitlink"]);
        std::fs::create_dir_all(root.path().join("vendored")).unwrap();
        assert_eq!(base_state(root.path()), IncrementalBaseState::Evaluated);
        let row = stored_row(root.path());
        assert!(
            families(&row).contains(&WorkspaceFactFamily::CSharpCompilationConfiguration),
            "{:?}",
            row.selection_reads
        );
        assert_eq!(row.selection_view, SelectionView::Worktree);
        // The head is the base tree, so the checkout-dependent read still holds.
        assert_eq!(base_state(root.path()), IncrementalBaseState::Reused);
        touch(root.path(), "Other.cs", "// an unrelated edit\n");
        assert_eq!(base_state(root.path()), IncrementalBaseState::Evaluated);
    }

    /// An initialized submodule is an export that is not a function of its
    /// tree, so its base replays only against a head that is the base tree.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12280: incomplete submodule inventory removed the ICFG content identity and panicked"
    )]
    #[brokk_bifrost_test_macros::hardwon(
        "#11607: a tree holding an initialized submodule was admitted as an export although its listing depends on the checkout"
    )]
    fn an_initialized_submodule_replays_only_against_the_base_tree() {
        let root = csharp_fixture();
        let capture = || {
            let export =
                brokk_bifrost_tools::diff_analysis::export_revision(root.path(), "HEAD").unwrap();
            let revision = export
                .build_workspace(
                    root.path(),
                    AnalyzerConfig::default(),
                    &CancellationToken::default(),
                    &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
                )
                .unwrap();
            let workspace = revision.workspace();
            let inventory = workspace.analyzer().source_file_inventory();
            let analyzer = workspace.analyzer();
            let store = workspace.store().unwrap();
            let snapshot = store
                .workspace_snapshots_for_current_languages(
                    &brokk_bifrost_analysis::analyzer::store::WorkspaceId::for_root(export.root()),
                    &["csharp".to_owned()],
                )
                .unwrap()["csharp"]
                .clone();
            let input_digest = store
                .selected_csharp_compilations(&snapshot)
                .unwrap()
                .unwrap()
                .input_digest();
            let connection = store.read_conn().unwrap();
            assert_eq!(
                analyzer.certify_selected_configuration(
                    Language::CSharp,
                    &snapshot,
                    &input_digest,
                    &connection
                ),
                if inventory.complete {
                    brokk_bifrost_analysis::analyzer::store::resolution_operation::ConfigurationCertificate::Certified
                } else {
                    brokk_bifrost_analysis::analyzer::store::resolution_operation::ConfigurationCertificate::Uncertified
                },
                "a submodule under the project glob refuses certification",
            );
            (
                inventory.complete,
                workspace
                    .analyzer()
                    .workspace_content_identity()
                    .expect("partial inventories retain a content identity"),
            )
        };
        let (complete, original_identity) = capture();
        assert!(complete);
        let nested = root.path().join("vendored");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("lib.txt"), "x\n").unwrap();
        run_git(&nested, &["init"]);
        run_git(&nested, &["config", "user.email", "test@example.com"]);
        run_git(&nested, &["config", "user.name", "Test User"]);
        run_git(&nested, &["add", "."]);
        run_git(&nested, &["commit", "-m", "nested"]);
        run_git(root.path(), &["add", "vendored"]);
        run_git(root.path(), &["commit", "-m", "gitlink"]);
        let (complete, partial_identity) = capture();
        assert!(!complete);
        assert_ne!(original_identity, partial_identity);
        assert_eq!(capture().1, partial_identity);
        assert_eq!(base_state(root.path()), IncrementalBaseState::Evaluated);
        // #12280: hidden configuration inputs make the base row unpublishable; reuse returns with #12455.
        let stored = base_row(root.path());
        assert!(
            stored.is_none(),
            "an uncertified gitlink base stored {stored:?}"
        );
        // #12280: an initialized submodule under App.csproj's default glob can hide compile items;
        // reuse returns with #12455 submodule inventory.
        assert_eq!(base_state(root.path()), IncrementalBaseState::Evaluated);
        touch(root.path(), "Other.cs", "// an unrelated edit\n");
        assert_eq!(base_state(root.path()), IncrementalBaseState::Evaluated);
    }

    /// MSBuild also reads `Directory.Build.props` above a project, but the
    /// configuration identity stops at the workspace root: a file above it is not
    /// an input, so an export of the workspace subtree answers as recorded
    /// whatever that file holds (#11607).
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11607: an ancestor props file above the workspace root could be an input an export does not hold"
    )]
    fn a_props_file_above_the_workspace_root_is_not_an_input() {
        let repo = commit_repo(&[
            ("Directory.Build.props", "<Project />"),
            ("ws/policy.rqlp", POLICY),
            ("ws/App.csproj", PROJECT),
            ("ws/Target.cs", "class A { void Target() {} }\n"),
            ("ws/Other.cs", "class B { void Other() {} }\n"),
        ]);
        let root = repo.path().join("ws");
        assert_eq!(base_state(&root), IncrementalBaseState::Evaluated);
        let row = stored_row(&root);
        assert!(families(&row).contains(&WorkspaceFactFamily::CSharpCompilationConfiguration));
        assert!(matches!(row.selection_view, SelectionView::Export { .. }));
        std::fs::write(
            repo.path().join("Directory.Build.props"),
            "<Project><PropertyGroup><DefineConstants>X</DefineConstants></PropertyGroup></Project>",
        )
        .unwrap();
        touch(&root, "Other.cs", "// an unrelated edit\n");
        assert_eq!(base_state(&root), IncrementalBaseState::Reused);
    }

    /// An `ExportDetermined` read is admitted by the row's provenance alone, a
    /// `TreeDependent` one only against a head that is the base tree. The
    /// collector names no subject: the class decides.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11607: a read taken over a live worktree was replayable as if it came from an export"
    )]
    fn an_export_determined_read_is_admitted_by_provenance_alone() {
        use brokk_bifrost_analysis::analyzer::read_ledger::SelectionRead;
        use brokk_bifrost_analysis::analyzer::read_verification::{
            BaseView, ChangedFacts, LookupMemo, LookupReplayLimits, NoSummaryAnswers,
            verify_selection_reads,
        };
        use brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest;
        use brokk_bifrost_analysis::analyzer::{FactSubject, Language};
        let root = csharp_fixture();
        let workspace = WorkspaceAnalyzer::build_persisted(
            Arc::new(owned_policy_project(root.path()).unwrap()),
            AnalyzerConfig::default(),
        )
        .unwrap();
        let read = |digest: StableDigest| {
            vec![SelectionRead::keyed(ReadKey::lookup(
                LookupKind::WorkspaceFact,
                LookupQuestion::WorkspaceFact {
                    family: WorkspaceFactFamily::CSharpCompilationConfiguration,
                    language: Language::CSharp,
                    subject: FactSubject::Whole,
                },
                digest,
            ))]
        };
        let current =
            brokk_bifrost_analysis::analyzer::languages::language_support(Language::CSharp)
                .expect("C# language support")
                .workspace_fact_answer(
                    workspace.analyzer(),
                    WorkspaceFactFamily::CSharpCompilationConfiguration,
                    Language::CSharp,
                    &FactSubject::Whole,
                )
                .expect("the C# configuration answers");
        let moved = StableDigest::from_array([9; 32]);
        let changed = ChangedFacts::between(&workspace, &workspace);
        let verify = |reads: &[SelectionRead], view, export| {
            verify_selection_reads(
                &workspace,
                &changed,
                reads,
                view,
                export,
                LookupReplayLimits::default(),
                &NoSummaryAnswers,
                &mut LookupMemo::new(),
            )
        };
        // Over an export of the key's tree nothing is recomputed, whatever
        // the head holds.
        assert_eq!(
            verify(&read(moved), BaseView::HeadMayDiffer, true),
            SelectionEvidence::Complete
        );
        // Over a live worktree it is answered by the head alone, and only when
        // the head is the base tree.
        assert_eq!(
            verify(&read(moved), BaseView::HeadMayDiffer, false),
            SelectionEvidence::Incomplete
        );
        assert_eq!(
            verify(&read(current), BaseView::HeadMayDiffer, false),
            SelectionEvidence::Incomplete
        );
        assert_eq!(
            verify(&read(current), BaseView::HeadIsBase, false),
            SelectionEvidence::Complete
        );
        assert_eq!(
            verify(&read(moved), BaseView::HeadIsBase, false),
            SelectionEvidence::Incomplete
        );
    }

    const JAVA_POLICY: &str = r#"(policy :schema-version 1 :id "test.persisted" :name "Persisted" :message "M" :severity warning :analysis (analysis :type match :selector (rql :schema-version 1 (call :callee "add"))))"#;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11607: a base recorded over an export was refused for every head that differed from its tree"
    )]
    fn a_jvm_dependency_selection_replays_by_resolving_its_coordinates_again() {
        let _environment = ENVIRONMENT
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let home = tempfile::tempdir().unwrap();
        let jar = home
            .path()
            .join(".m2/repository/com/example/lib/1.0/lib-1.0.jar");
        std::fs::create_dir_all(jar.parent().unwrap()).unwrap();
        std::fs::write(&jar, b"not a jar").unwrap();
        let (old_home, old_java) = (std::env::var_os("HOME"), std::env::var_os("JAVA_HOME"));
        // SAFETY: the lock above serializes every test that reads these.
        unsafe {
            std::env::set_var("HOME", home.path());
            std::env::remove_var("JAVA_HOME");
        }
        let root = commit_repo(&[
            ("policy.rqlp", JAVA_POLICY),
            (
                "pom.xml",
                r#"<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId><artifactId>app</artifactId><version>1</version><dependencies><dependency><groupId>com.example</groupId><artifactId>lib</artifactId><version>1.0</version></dependency></dependencies></project>"#,
            ),
            (
                "src/A.java",
                "import java.util.List;\nclass A { void f(List<String> l) { l.add(\"x\"); } }\n",
            ),
            ("src/Other.java", "class Other { void g() {} }\n"),
        ]);
        let outcome = std::panic::catch_unwind(|| {
            assert_eq!(base_state(root.path()), IncrementalBaseState::Evaluated);
            let row = stored_row(root.path());
            let gaps = row
                .selection_reads
                .iter()
                .find(|read| {
                    matches!(
                        &read.key,
                        ReadKey::Lookup {
                            question: LookupQuestion::WorkspaceFact {
                                family: WorkspaceFactFamily::JvmExternalGaps,
                                ..
                            },
                            ..
                        }
                    )
                })
                .unwrap_or_else(|| panic!("a JVM gap read: {:?}", row.selection_reads));
            let basis = gaps
                .basis
                .as_ref()
                .expect("the declared coordinates are recorded");
            assert_eq!(basis.entries.len(), 1, "{basis:?}");
            assert_eq!(base_state(root.path()), IncrementalBaseState::Reused);
            touch(root.path(), "src/Other.java", "// an unrelated edit\n");
            assert_eq!(
                base_state(root.path()),
                IncrementalBaseState::Reused,
                "the coordinates resolve to the same artifacts in the same environment"
            );
            // An artifact of the local Maven repository that changed.
            std::fs::remove_file(&jar).unwrap();
            assert_eq!(
                base_state(root.path()),
                IncrementalBaseState::Evaluated,
                "the environment part changed"
            );
            std::fs::write(&jar, b"not a jar").unwrap();
            // A changed JDK.
            // SAFETY: as above.
            unsafe { std::env::set_var("JAVA_HOME", home.path().join("no-such-jdk")) };
            assert_eq!(base_state(root.path()), IncrementalBaseState::Evaluated);
        });
        // SAFETY: as above.
        unsafe {
            match old_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
            match old_java {
                Some(value) => std::env::set_var("JAVA_HOME", value),
                None => std::env::remove_var("JAVA_HOME"),
            }
        }
        outcome.unwrap();
    }
}
