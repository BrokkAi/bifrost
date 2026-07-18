mod common;

use std::sync::Arc;

#[cfg(windows)]
use brokk_bifrost::analyzer::semantic::WorkspaceRelativePath;
use brokk_bifrost::analyzer::structural::CodeQueryExecutionLimits;
use brokk_bifrost::policy::{
    CatalogRegistryLimits, DefaultPolicyEvaluator, FindingClassification, FindingIdentityStability,
    FindingSeverity, MatchResultDomain, PolicyAnalysisType, PolicyBudget, PolicyCapability,
    PolicyEvaluationContext, PolicyEvaluator, PolicyFailureReason, PolicyFindingEvidence,
    PolicyFindingId, PolicyIncompleteReason, PolicyRegistry, PolicyRegistryLimits, PolicyRun,
    PolicyRunCompletion, PolicyRunError, PolicySourceIdentity, TaintCatalogRegistry,
};
use brokk_bifrost::{CancellationToken, Language, TypescriptAnalyzer};
use common::InlineTestProject;

fn registry_with_policy(source: &str) -> PolicyRegistry {
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    registry
        .register_policy_bytes(PolicySourceIdentity::new("test:policy"), source.as_bytes())
        .expect("valid policy");
    registry
}

fn evaluate(
    source: &str,
    analyzer: &TypescriptAnalyzer,
    budget: &mut PolicyBudget,
    cancellation: Option<&CancellationToken>,
) -> brokk_bifrost::policy::PolicyRun {
    try_evaluate(source, analyzer, budget, cancellation).expect("policy evaluation")
}

fn try_evaluate(
    source: &str,
    analyzer: &TypescriptAnalyzer,
    budget: &mut PolicyBudget,
    cancellation: Option<&CancellationToken>,
) -> Result<PolicyRun, PolicyRunError> {
    let registry = registry_with_policy(source);
    let policy = registry.policies().next().expect("one policy");
    DefaultPolicyEvaluator::new().evaluate(
        policy,
        &PolicyEvaluationContext {
            analyzer,
            cancellation,
            cvss_overlays: &[],
            organizational_risk: &[],
        },
        budget,
    )
}

fn typescript_analyzer(source: &str) -> (common::BuiltInlineTestProject, TypescriptAnalyzer) {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("app.ts", source)
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

#[test]
fn public_match_evaluator_returns_a_complete_typed_finding_and_clean_empty_run() {
    let (_project, analyzer) =
        typescript_analyzer("export function target() {}\nexport function other() {}\n");
    let matching = r#"(policy
      :id "test.match"
      :name "Match"
      :message "Avoid target"
      :severity warning
      :analysis (analysis :type match :selector (rql (function :name "target"))))"#;
    let run = evaluate(matching, &analyzer, &mut PolicyBudget::default(), None);

    assert_eq!(run.analysis_type(), PolicyAnalysisType::Match);
    assert_eq!(run.completion(), &PolicyRunCompletion::Complete);
    assert_eq!(run.findings().len(), 1);
    let finding = &run.findings()[0];
    assert_eq!(finding.message(), "Avoid target");
    assert_eq!(finding.severity(), FindingSeverity::Warning);
    assert_eq!(finding.primary().path(), "app.ts");
    assert_eq!(
        finding.identity_stability(),
        FindingIdentityStability::Strong
    );
    assert_eq!(
        finding.classification(),
        &FindingClassification::Unclassified
    );
    assert!(matches!(
        finding.evidence(),
        PolicyFindingEvidence::Match { evidence }
            if evidence.result_domain() == MatchResultDomain::StructuralMatch
    ));

    let clean = r#"(policy
      :id "test.clean"
      :name "Clean"
      :message "No missing function"
      :severity note
      :analysis (analysis :type match :selector (rql (function :name "missing"))))"#;
    let run = evaluate(clean, &analyzer, &mut PolicyBudget::default(), None);
    assert_eq!(run.completion(), &PolicyRunCompletion::Complete);
    assert!(run.findings().is_empty());
}

#[test]
fn public_evaluator_emits_normalized_unicode_workspace_paths() {
    #[cfg(windows)]
    assert_eq!(
        WorkspaceRelativePath::try_from_path(std::path::Path::new(r"src\données.ts"))
            .expect("normalized native Windows path")
            .as_str(),
        "src/données.ts"
    );
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/données.ts",
            "const π = 1;\nexport function target() { return π; }\n",
        )
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    let policy = r#"(policy
      :id "test.unicode-path"
      :name "Unicode path"
      :message "Target selected"
      :severity warning
      :analysis (analysis :type match :selector
        (rql (where "src/données.ts" (function :name "target")))))"#;
    let run = evaluate(policy, &analyzer, &mut PolicyBudget::default(), None);

    assert_eq!(run.completion(), &PolicyRunCompletion::Complete);
    assert_eq!(run.findings().len(), 1);
    let location = run.findings()[0].primary();
    assert_eq!(location.path(), "src/données.ts");
    assert!(location.byte_span().is_some());
    assert!(location.region().is_some());
}

fn target_finding_id(source: &str, message: &str, severity: &str) -> PolicyFindingId {
    let (_project, analyzer) = typescript_analyzer(source);
    let policy = format!(
        r#"(policy
          :id "test.fingerprint-public"
          :name "Fingerprint"
          :message "{message}"
          :severity {severity}
          :analysis (analysis :type match :selector
            (rql (function :name "target"))))"#
    );
    let run = evaluate(&policy, &analyzer, &mut PolicyBudget::default(), None);
    assert_eq!(run.findings().len(), 1);
    run.findings()[0].id()
}

#[test]
fn public_fingerprints_are_stable_for_unrelated_edits_and_presentation_changes() {
    let original = "export function target() { return 1; }\n";
    let shifted = "// unrelated preceding text\n\nexport function target() { return 1; }\n";
    let changed = "export function target() { return 2; }\n";

    let id = target_finding_id(original, "First message", "warning");
    assert_eq!(id, target_finding_id(shifted, "First message", "warning"));
    assert_eq!(id, target_finding_id(original, "Changed message", "error"));
    assert_ne!(id, target_finding_id(changed, "First message", "warning"));
}

#[test]
fn public_findings_are_deterministically_sorted() {
    let (_project, analyzer) = typescript_analyzer(
        "export function beta() {}\nexport function alpha() {}\nexport function gamma() {}\n",
    );
    let policy = r#"(policy
      :id "test.order"
      :name "Order"
      :message "Function selected"
      :severity warning
      :analysis (analysis :type match :selector (rql (function))))"#;
    let ids = |run: &PolicyRun| {
        run.findings()
            .iter()
            .map(|finding| finding.id())
            .collect::<Vec<_>>()
    };
    let first = evaluate(policy, &analyzer, &mut PolicyBudget::default(), None);
    let second = evaluate(policy, &analyzer, &mut PolicyBudget::default(), None);
    let first_ids = ids(&first);

    assert!(first_ids.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(first_ids, ids(&second));
}

#[test]
fn host_limit_and_cancellation_are_never_reported_as_clean() {
    let (_project, analyzer) =
        typescript_analyzer("export function alpha() {}\nexport function beta() {}\n");
    let policy = r#"(policy
      :id "test.bounded"
      :name "Bounded"
      :message "Function selected"
      :severity warning
      :analysis (analysis :type match :selector (rql (function))))"#;
    let mut limited = PolicyBudget::builder()
        .with_max_findings(1)
        .expect("bounded findings")
        .build()
        .expect("budget");
    let run = evaluate(policy, &analyzer, &mut limited, None);
    assert_eq!(run.findings().len(), 1);
    assert!(matches!(
        run.completion(),
        PolicyRunCompletion::Inconclusive { reasons }
            if reasons.contains(&PolicyIncompleteReason::QueryResultLimit)
    ));
    assert!(run.work().omitted_findings_lower_bound() > 0);

    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let run = evaluate(
        policy,
        &analyzer,
        &mut PolicyBudget::default(),
        Some(&cancellation),
    );
    assert!(run.findings().is_empty());
    assert!(matches!(
        run.completion(),
        PolicyRunCompletion::Inconclusive { reasons }
            if reasons.contains(&PolicyIncompleteReason::Cancelled)
    ));
}

#[test]
fn zero_diagnostic_budget_still_returns_a_failed_match_run() {
    let (_project, analyzer) = typescript_analyzer(
        "class Service { run() {} }\nexport function call(s: Service) { s.run(); }\n",
    );
    let receiver_terminal = r#"(policy
      :id "test.receiver-terminal"
      :name "Receiver terminal"
      :message "Receiver terminal is not a match finding"
      :severity warning
      :analysis (analysis :type match
        :selector (rql (receiver-targets (call :callee (name "run"))))))"#;
    let mut budget = PolicyBudget::builder()
        .with_max_diagnostics(0)
        .expect("zero diagnostics is allowed")
        .build()
        .expect("budget");
    let run = evaluate(receiver_terminal, &analyzer, &mut budget, None);

    assert!(matches!(
        run.completion(),
        PolicyRunCompletion::Failed { reasons }
            if reasons.contains(&PolicyFailureReason::InvalidExecutionPlan)
    ));
    assert!(run.diagnostics().is_empty());
    assert!(run.diagnostics_truncated());
}

fn taint_policy(id: &str) -> String {
    format!(
        r#"(policy
          :id "{id}"
          :name "Taint"
          :message "Taint reached sink"
          :severity warning
          :analysis (analysis
            :type taint
            :mode may
            :sources (endpoint-set :entries [
              (source :id request :display-name "request" :categories [input.user]
                :selector (rql (name "request")) :bind return-value
                :labels [untrusted])])
            :sinks (endpoint-set :entries [
              (sink :id store :display-name "store" :categories [data.sensitive]
                :selector (rql (name "store")) :dangerous-operand matched-value
                :accepts [untrusted])])))"#
    )
}

fn typestate_policy() -> &'static str {
    r#"(policy
      :id "test.typestate"
      :name "Typestate"
      :message "Resource was not closed"
      :severity error
      :analysis (analysis
        :type typestate
        :mode may
        :subjects (subject-set :entries [
          (subject :id resource :selector (rql (call :callee (name "open_resource")))
            :subject return-value)])
        :uncertainty (uncertainty :unknown-call inconclusive :escape inconclusive)
        :automaton (automaton
          :states [open closed violated]
          :initial open
          :accepting-states [closed]
          :error-states [violated]
          :events [
            (event :id close
              :calls (calls :selector (rql (call :callee (name "close_resource")))
                :subject receiver :phase after-normal-return))]
          :transitions [(transition :from open :on close :to closed)]
          :terminal-expectations [
            (terminal-expectation :id normal-exit
              :on (normal-procedure-exit :scope analysis-root)
              :expected-states [closed])])))"#
}

#[test]
fn zero_diagnostic_budget_preserves_unsupported_taint_and_typestate_completion() {
    let (_project, analyzer) = typescript_analyzer("export function noop() {}\n");
    let mut budget = PolicyBudget::builder()
        .with_max_diagnostics(0)
        .expect("zero diagnostics is allowed")
        .build()
        .expect("budget");
    let taint = taint_policy("test.taint");
    let run = evaluate(&taint, &analyzer, &mut budget, None);
    assert_eq!(
        run.completion(),
        &PolicyRunCompletion::Unsupported {
            capability: PolicyCapability::TaintEvaluation,
        }
    );
    assert!(run.diagnostics().is_empty());
    assert!(run.diagnostics_truncated());

    let run = evaluate(typestate_policy(), &analyzer, &mut budget, None);
    assert_eq!(
        run.completion(),
        &PolicyRunCompletion::Unsupported {
            capability: PolicyCapability::TypestateEvaluation,
        }
    );
    assert!(run.diagnostics().is_empty());
    assert!(run.diagnostics_truncated());
}

#[test]
fn zero_and_tiny_retained_caps_propagate_exact_policy_run_errors() {
    let (_project, analyzer) = typescript_analyzer(
        "class Service { run() {} }\nexport function call(s: Service) { s.run(); }\n",
    );
    let matching = r#"(policy
      :id "test.retained-match"
      :name "Retained match"
      :message "Function selected"
      :severity warning
      :analysis (analysis :type match :selector (rql (function))))"#;
    let mut zero = PolicyBudget::builder()
        .with_max_retained_report_bytes(0)
        .expect("zero retained bytes")
        .build()
        .expect("budget");
    assert_eq!(
        try_evaluate(matching, &analyzer, &mut zero, None).unwrap_err(),
        PolicyRunError::RetainedReportBytesExceeded { max: 0 }
    );

    let mut tiny = PolicyBudget::builder()
        .with_max_retained_report_bytes(1)
        .expect("tiny retained cap")
        .build()
        .expect("budget");
    let taint = taint_policy("test.retained-unsupported");
    assert_eq!(
        try_evaluate(&taint, &analyzer, &mut tiny, None).unwrap_err(),
        PolicyRunError::RetainedReportBytesExceeded { max: 1 }
    );

    let failed_match = r#"(policy
      :id "test.retained-failed"
      :name "Retained failed"
      :message "Receiver terminal is not a match finding"
      :severity warning
      :analysis (analysis :type match
        :selector (rql (receiver-targets (call :callee (name "run"))))))"#;
    assert_eq!(
        try_evaluate(failed_match, &analyzer, &mut tiny, None).unwrap_err(),
        PolicyRunError::RetainedReportBytesExceeded { max: 1 }
    );
}

#[test]
fn omitted_stable_anchor_diagnostic_marks_diagnostics_truncated() {
    let target_source = "export function target() {}\n";
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("target.ts", target_source)
        .file(
            "caller.ts",
            "import { target } from './target';\nexport function caller() { target(); }\n",
        )
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    let policy = r#"(policy
      :id "test.weak-anchor"
      :name "Weak anchor"
      :message "Call selected"
      :severity warning
      :analysis (analysis :type match :selector
        (rql (call-sites-to :proof proven
          (enclosing-decl (where "target.ts" (function :name "target")))))))"#;
    let complete = evaluate(policy, &analyzer, &mut PolicyBudget::default(), None);
    assert_eq!(complete.findings().len(), 1);
    let tight_source_bytes = usize::try_from(complete.work().scanned_source_bytes())
        .expect("work fits usize")
        .saturating_sub(1);
    let query_limits = CodeQueryExecutionLimits {
        max_scanned_files: 2,
        max_scanned_source_bytes: tight_source_bytes,
        ..CodeQueryExecutionLimits::default()
    };
    let mut budget = PolicyBudget::builder()
        .with_query_limits(query_limits)
        .expect("query limits")
        .with_max_diagnostics(1)
        .expect("one diagnostic")
        .build()
        .expect("budget");
    let run = evaluate(policy, &analyzer, &mut budget, None);

    assert_eq!(run.findings().len(), 1);
    assert_eq!(
        run.findings()[0].identity_stability(),
        FindingIdentityStability::Weak
    );
    assert!(matches!(
        run.completion(),
        PolicyRunCompletion::Inconclusive { reasons }
            if reasons.contains(&PolicyIncompleteReason::StableAnchorUnavailable)
    ));
    assert_eq!(run.diagnostics().len(), 1);
    assert!(run.diagnostics_truncated());
}
