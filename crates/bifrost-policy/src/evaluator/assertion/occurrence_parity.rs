//! Test-only parity seam for occurrence assertion lowering.
//!
//! The production assertion evaluator calls [`evaluate`] while tests run.  By
//! default this forwards to the lowered relational plan; a scoped override
//! installs the copied pre-lowering oracle so complete policy reports can be
//! compared byte-for-byte.

use std::cell::Cell;
use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use brokk_bifrost_rql::structural::search::{CodeQueryOccurrence, CodeQueryOccurrenceTarget};

use super::{AssertionViolation, OccurrenceAssert, RelationalPlanIr};

type OccurrenceEvaluator = for<'rows> fn(
    &OccurrenceAssert,
    &[&str],
    &HashMap<&str, Vec<&'rows CodeQueryOccurrence>>,
    &RelationalPlanIr,
) -> Option<AssertionViolation<'rows>>;

thread_local! {
    static EVALUATOR: Cell<OccurrenceEvaluator> = const { Cell::new(evaluate_lowered) };
}

/// Evaluate one occurrence assertion through the currently selected path.
pub(super) fn evaluate<'rows>(
    assertion: &OccurrenceAssert,
    ast_ids: &[&str],
    rows_by_ast_id: &HashMap<&str, Vec<&'rows CodeQueryOccurrence>>,
    lowered: &RelationalPlanIr,
) -> Option<AssertionViolation<'rows>> {
    EVALUATOR.with(|slot| (slot.get())(assertion, ast_ids, rows_by_ast_id, lowered))
}

/// Run `body` against the copied pre-lowering oracle, restoring the prior
/// evaluator even if `body` panics. Nested scopes therefore compose safely.
pub(super) fn with_bespoke<R>(body: impl FnOnce() -> R) -> R {
    EVALUATOR.with(|slot| {
        let previous = slot.replace(evaluate_legacy);
        let result = catch_unwind(AssertUnwindSafe(body));
        slot.set(previous);
        match result {
            Ok(value) => value,
            Err(payload) => resume_unwind(payload),
        }
    })
}

fn evaluate_lowered<'rows>(
    assertion: &OccurrenceAssert,
    ast_ids: &[&str],
    rows_by_ast_id: &HashMap<&str, Vec<&'rows CodeQueryOccurrence>>,
    lowered: &RelationalPlanIr,
) -> Option<AssertionViolation<'rows>> {
    super::evaluate_lowered_occurrence_assert(assertion, ast_ids, rows_by_ast_id, lowered)
}

/// The pre-relational occurrence evaluator, retained solely as an independent
/// test oracle. Keep its role, namespace, and target filters aligned with the
/// old production behavior; source loading validates the expected class.
fn evaluate_legacy<'rows>(
    assertion: &OccurrenceAssert,
    ast_ids: &[&str],
    rows_by_ast_id: &HashMap<&str, Vec<&'rows CodeQueryOccurrence>>,
    _lowered: &RelationalPlanIr,
) -> Option<AssertionViolation<'rows>> {
    let mut actual: Vec<&CodeQueryOccurrence> = Vec::new();
    for ast_id in ast_ids {
        let Some(rows) = rows_by_ast_id.get(ast_id) else {
            continue;
        };
        actual.extend(
            rows.iter()
                .copied()
                .filter(|row| legacy_row_matches(assertion, row)),
        );
    }
    if assertion
        .cardinality
        .satisfied_by(u32::try_from(actual.len()).unwrap_or(u32::MAX))
    {
        return None;
    }
    let mut violation = AssertionViolation::new(
        assertion.expect.label(),
        assertion.cardinality.to_string(),
        None,
    );
    violation.actual_count = u64::try_from(actual.len()).unwrap_or(u64::MAX);
    violation.occurrences = actual;
    Some(violation)
}

fn legacy_row_matches(assertion: &OccurrenceAssert, row: &CodeQueryOccurrence) -> bool {
    if row.role != assertion.role.label() {
        return false;
    }
    if let Some(namespace) = assertion.namespace
        && row.namespace != namespace.label()
    {
        return false;
    }
    if assertion.require_target && !matches!(row.target, CodeQueryOccurrenceTarget::Resolved { .. })
    {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use brokk_bifrost_analysis::CancellationToken;
    use brokk_bifrost_analysis::analyzer::{
        IAnalyzer, JavaAnalyzer, Language, PythonAnalyzer, RustAnalyzer, TypescriptAnalyzer,
    };
    use brokk_bifrost_rql::structural::CodeQueryExecutionLimits;

    use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
    use crate::{
        CatalogRegistryLimits, DefaultPolicyEvaluator, PolicyBudget, PolicyEvaluationContext,
        PolicyEvaluator, PolicyRegistry, PolicyRegistryLimits, PolicyReportDocument,
        PolicyRuleDescriptor, PolicySourceIdentity, TaintCatalogRegistry,
    };

    use super::with_bespoke;

    /// One assertion policy source used by all report comparisons. The policy
    /// is decoded independently for each path, so source identity, semantic
    /// hash, and rule descriptor remain part of the byte comparison.
    fn policy(
        language: &str,
        subject: &str,
        role: &str,
        expect: &str,
        cardinality: &str,
        namespace: Option<&str>,
        require_target: bool,
    ) -> String {
        let namespace = namespace.map_or_else(String::new, |value| format!(" :namespace {value}"));
        let target = if require_target {
            " :require-target true"
        } else {
            ""
        };
        format!(
            r#"(policy
  :schema-version 1
  :id "test.occurrence.parity"
  :name "Occurrence parity"
  :message "the occurrence invariant does not hold"
  :severity warning
  :analysis (analysis
    :type assertion
    :subject (rql (language {language} {subject}))
    :asserts [
      (assert :id occurrence :at "target" :role {role} :expect {expect}
              :cardinality {cardinality}{namespace}{target})]))"#
        )
    }

    fn analyzer_for(
        language: Language,
        path: &str,
        source: &str,
    ) -> (BuiltInlineTestProject, Box<dyn IAnalyzer>) {
        let project = InlineTestProject::with_language(language)
            .file(path, source)
            .build();
        let owned = project.project().clone();
        let analyzer: Box<dyn IAnalyzer> = match language {
            Language::Java => Box::new(JavaAnalyzer::from_project(owned)),
            Language::Python => Box::new(PythonAnalyzer::from_project(owned)),
            Language::Rust => Box::new(RustAnalyzer::from_project(owned)),
            Language::TypeScript => Box::new(TypescriptAnalyzer::from_project(owned)),
            other => panic!("occurrence parity has no fixture adapter for {other:?}"),
        };
        (project, analyzer)
    }

    fn report_bytes(
        language: Language,
        path: &str,
        source: &str,
        policy_source: &str,
        budget: PolicyBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Vec<u8> {
        let (_project, analyzer) = analyzer_for(language, path, source);
        let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
            CatalogRegistryLimits::default(),
        ));
        let mut registry =
            PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
        registry
            .register_policy_bytes(
                PolicySourceIdentity::new("test:occurrence-parity"),
                policy_source.as_bytes(),
            )
            .expect("occurrence parity policy loads");
        let policy = registry.policies().next().expect("one parity policy");
        let descriptor = PolicyRuleDescriptor::from_loaded(policy);
        let flow_state = brokk_bifrost_flow::FlowWorkspaceState::default();
        let context = PolicyEvaluationContext {
            analyzer: analyzer.as_ref(),
            workspace: None,
            flow_state: &flow_state,
            cancellation,
            cvss_overlays: &[],
            organizational_risk: &[],
            incremental: None,
        };
        let mut budget = budget;
        let run = DefaultPolicyEvaluator::new()
            .evaluate(policy, &context, &mut budget)
            .expect("occurrence policy evaluates");
        let report =
            PolicyReportDocument::try_new(vec![descriptor], vec![run], Vec::new(), false, 0, None)
                .expect("canonical occurrence report");
        let mut bytes = Vec::new();
        crate::render::write_policy_json(&report, &mut bytes, usize::MAX)
            .expect("canonical report serializes");
        bytes
    }

    fn assert_report_parity(
        language: Language,
        path: &str,
        source: &str,
        policy_source: &str,
        budget: PolicyBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Vec<u8> {
        let legacy = with_bespoke(|| {
            report_bytes(language, path, source, policy_source, budget, cancellation)
        });
        let lowered = report_bytes(language, path, source, policy_source, budget, cancellation);
        assert_eq!(
            lowered, legacy,
            "legacy and lowered occurrence paths must publish identical canonical reports"
        );
        let value: serde_json::Value =
            serde_json::from_slice(&lowered).expect("canonical report is JSON");
        for field in ["evaluation", "execution", "rules", "runs", "diagnostics"] {
            assert!(
                value.get(field).is_some(),
                "canonical report omitted {field}"
            );
        }
        lowered
    }

    fn pipeline_budget(max_pipeline_rows: usize) -> PolicyBudget {
        PolicyBudget::builder()
            .with_query_limits(CodeQueryExecutionLimits {
                max_pipeline_rows,
                ..PolicyBudget::default().query_limits()
            })
            .expect("pipeline row limit is within the host cap")
            .build()
            .expect("valid policy budget")
    }

    const TYPESCRIPT_ONE_READ: &str =
        "const alpha = 1;\nexport function read() { return alpha; }\n";
    const TYPESCRIPT_DECLARATION_ONLY: &str = "const alpha = 1;\n";
    const TYPESCRIPT_NO_READ: &str = "const alpha = 1;\nexport function read() { return 1; }\n";
    const TYPESCRIPT_UNRESOLVED: &str = "export function read() { return missing; }\n";
    const VALUE_SUBJECT: &str = r#"(identifier :text/regex "^alpha$" :capture "target")"#;

    #[test]
    fn positive_absent_and_clean_occurrence_reports_are_byte_equal() {
        let positive = policy(
            "typescript",
            VALUE_SUBJECT,
            "value_reference",
            "none",
            "(exactly 0)",
            None,
            false,
        );
        let positive_report = assert_report_parity(
            Language::TypeScript,
            "widget.ts",
            TYPESCRIPT_ONE_READ,
            &positive,
            PolicyBudget::default(),
            None,
        );
        let absent = policy(
            "typescript",
            VALUE_SUBJECT,
            "value_reference",
            "reference",
            "(exactly 1)",
            None,
            false,
        );
        let absent_report = assert_report_parity(
            Language::TypeScript,
            "widget.ts",
            TYPESCRIPT_DECLARATION_ONLY,
            &absent,
            PolicyBudget::default(),
            None,
        );
        let clean_report = assert_report_parity(
            Language::TypeScript,
            "widget.ts",
            TYPESCRIPT_NO_READ,
            &positive,
            PolicyBudget::default(),
            None,
        );
        for (bytes, expected_counts) in [
            (&positive_report, vec![1]),
            (&absent_report, vec![0]),
            (&clean_report, vec![]),
        ] {
            let report: serde_json::Value = serde_json::from_slice(bytes).unwrap();
            assert_eq!(report["runs"][0]["completion"]["type"], "complete");
            let counts = report["runs"][0]["findings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|finding| {
                    finding["evidence"]["evidence"]["actual_count"]
                        .as_u64()
                        .unwrap()
                })
                .collect::<Vec<_>>();
            assert_eq!(counts, expected_counts);
        }
    }

    #[test]
    fn cardinality_bounds_and_expected_class_preserve_report_parity() {
        let cases = [
            ("exactly-one", "(exactly 1)"),
            ("exactly-two", "(exactly 2)"),
            ("at-most-one", "(at-most 1)"),
            ("at-most-zero", "(at-most 0)"),
            ("at-least-one", "(at-least 1)"),
            ("at-least-two", "(at-least 2)"),
        ];
        for (name, cardinality) in cases {
            let source = policy(
                "typescript",
                VALUE_SUBJECT,
                "value_reference",
                "reference",
                cardinality,
                None,
                false,
            );
            let report = assert_report_parity(
                Language::TypeScript,
                "widget.ts",
                TYPESCRIPT_ONE_READ,
                &source,
                PolicyBudget::default(),
                None,
            );
            assert!(!report.is_empty(), "{name} produced an empty report");
        }
    }

    #[test]
    fn namespace_and_require_target_filters_preserve_report_parity() {
        let value = policy(
            "typescript",
            VALUE_SUBJECT,
            "value_reference",
            "reference",
            "(exactly 1)",
            Some("value"),
            true,
        );
        assert_report_parity(
            Language::TypeScript,
            "widget.ts",
            TYPESCRIPT_ONE_READ,
            &value,
            PolicyBudget::default(),
            None,
        );

        let type_namespace = policy(
            "typescript",
            VALUE_SUBJECT,
            "value_reference",
            "reference",
            "(exactly 1)",
            Some("type"),
            false,
        );
        assert_report_parity(
            Language::TypeScript,
            "widget.ts",
            TYPESCRIPT_ONE_READ,
            &type_namespace,
            PolicyBudget::default(),
            None,
        );

        let unresolved = policy(
            "typescript",
            r#"(identifier :text/regex "^missing$" :capture "target")"#,
            "value_reference",
            "reference",
            "(exactly 1)",
            None,
            true,
        );
        assert_report_parity(
            Language::TypeScript,
            "widget.ts",
            TYPESCRIPT_UNRESOLVED,
            &unresolved,
            PolicyBudget::default(),
            None,
        );
    }

    #[test]
    fn python_adapter_and_multi_capture_rows_preserve_report_parity() {
        let python = policy(
            "python",
            r#"(identifier :text/regex "^needle$" :capture "target")"#,
            "value_reference",
            "none",
            "(exactly 0)",
            Some("value"),
            false,
        );
        assert_report_parity(
            Language::Python,
            "widget.py",
            "needle = 1\ndef read():\n    return needle\n",
            &python,
            PolicyBudget::default(),
            None,
        );

        let multi_capture_subject = r#"(call :callee (name "consume") :args [
          (identifier :text/regex "^needle$" :capture "target")
          (identifier :text/regex "^needle$" :capture "target")
          (identifier :text/regex "^needle$" :capture "target")
          (identifier :text/regex "^needle$" :capture "target")
          (identifier :text/regex "^needle$" :capture "target")
          (identifier :text/regex "^needle$" :capture "target")
          (identifier :text/regex "^needle$" :capture "target")
          (identifier :text/regex "^needle$" :capture "target")
          (identifier :text/regex "^needle$" :capture "target")])"#;
        let multi_capture = policy(
            "typescript",
            multi_capture_subject,
            "value_reference",
            "reference",
            "(exactly 1)",
            None,
            false,
        );
        let budget = PolicyBudget::builder()
            .with_max_related_locations_per_finding(1)
            .expect("related location limit is within the host cap")
            .build()
            .expect("valid related location budget");
        for budget in [PolicyBudget::default(), budget] {
            let cap = budget.max_related_locations_per_finding();
            let bytes = assert_report_parity(
                Language::TypeScript,
                "widget.ts",
                "const needle = 1;\nfunction consume(...args: number[]) {}\nconsume(needle, needle, needle, needle, needle, needle, needle, needle, needle);\n",
                &multi_capture,
                budget,
                None,
            );
            let report: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let findings = report["runs"][0]["findings"].as_array().unwrap();
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0]["evidence"]["evidence"]["actual_count"], 9);
            assert_eq!(
                findings[0]["related"].as_array().unwrap().len(),
                cap.min(10)
            );
            assert_eq!(
                findings[0]["omitted_related_locations_lower_bound"],
                10 - cap.min(10)
            );
        }
    }

    #[test]
    fn cancelled_and_truncated_inputs_preserve_complete_report_bytes() {
        let source = policy(
            "typescript",
            VALUE_SUBJECT,
            "value_reference",
            "none",
            "(exactly 0)",
            None,
            false,
        );
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let cancelled = assert_report_parity(
            Language::TypeScript,
            "widget.ts",
            TYPESCRIPT_ONE_READ,
            &source,
            PolicyBudget::default(),
            Some(&cancellation),
        );
        let cancelled: serde_json::Value = serde_json::from_slice(&cancelled).unwrap();
        assert_eq!(cancelled["runs"][0]["completion"]["type"], "inconclusive");
        assert!(
            cancelled["runs"][0]["findings"]
                .as_array()
                .unwrap()
                .is_empty()
        );

        let truncated_source = "const alpha = 1;\n".to_owned()
            + "export const a = alpha;\n"
            + "export const b = alpha;\n";
        let truncated = assert_report_parity(
            Language::TypeScript,
            "widget.ts",
            &truncated_source,
            &source,
            pipeline_budget(1),
            None,
        );
        let truncated: serde_json::Value = serde_json::from_slice(&truncated).unwrap();
        assert_eq!(truncated["runs"][0]["completion"]["type"], "inconclusive");
        assert!(
            truncated["runs"][0]["findings"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    /// The two TypeScript witnesses in suite_bench_policy's occurrence and
    /// incremental suites, and the occurrence assertion used by the policy
    /// crate's explanation fixtures. Both the original policy IDs and their
    /// assertion IDs participate in the canonical report comparison.
    #[test]
    fn existing_occurrence_fixture_reports_are_byte_equal() {
        let cases = [
            (
                "test.assertion.forbid-reads",
                "Render is never read",
                "render must only be declared, never read",
                "warning",
                "(assert :id no-reads :at \"target\" :role value_reference :expect none)",
            ),
            (
                "test.incremental.forbid-reads",
                "Render is never read",
                "render must only be declared, never read",
                "warning",
                "(assert :id no-reads :at \"target\" :role value_reference :expect none)",
            ),
            (
                "test.assertion.require-declaration",
                "Render is always a declaration",
                "render must be a declaration name",
                "error",
                "(assert :id declared :at \"target\" :role declaration_name :expect declaration :cardinality (exactly 1))",
            ),
            (
                "test.explain.assertion",
                "Assertion",
                "render must be a declaration name",
                "warning",
                "(assert :id declared :at \"target\" :role declaration_name :expect declaration :cardinality (exactly 1))",
            ),
        ];
        for (id, name, message, severity, assertion) in cases {
            let policy = format!(
                r#"(policy :id "{id}" :name "{name}" :message "{message}"
              :severity {severity} :analysis (analysis :type assertion
              :subject (rql (identifier :text/regex "^render$" :capture "target"))
              :asserts [{assertion}]))"#
            );
            for (source, count) in [
                (
                    "export function render(): number {\n  return 1;\n}\n\nexport const alias = render;\n",
                    1,
                ),
                ("export function render(): number {\n  return 1;\n}\n", 0),
            ] {
                let bytes = assert_report_parity(
                    Language::TypeScript,
                    "src/widget.ts",
                    source,
                    &policy,
                    PolicyBudget::default(),
                    None,
                );
                let report: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(
                    report["runs"][0]["findings"].as_array().unwrap().len(),
                    count,
                    "{id}"
                );
            }
        }
    }

    /// Reuse all six production shapes from policy_assertion_conformance.rs:
    /// destructuring, annotations, computed keys, static qualifiers, escaped
    /// identifiers, and declaration heads. Each positive/near-miss pair differs
    /// only in structural position and publishes the old report byte for byte.
    #[test]
    fn existing_conformance_pairs_preserve_complete_report_bytes() {
        let pairs = [
            (
                Language::TypeScript,
                "src/destructure.ts",
                "destructuring",
                "alpha",
                "const source = { first: 1 };\nconst { first: alpha } = source;\nexport const echo = { alpha };\n",
                "const source = { first: 1 };\nconst { first: alpha } = source;\nexport const echo = { first: 2 };\n",
            ),
            (
                Language::Python,
                "src/widget.py",
                "annotation",
                "Widget",
                "class Widget:\n    pass\n\ndef render(widget: Widget) -> int:\n    return 1\n\ndef build():\n    return Widget()\n",
                "class Widget:\n    pass\n\ndef render(widget: Widget) -> int:\n    return 1\n\ndef build():\n    return 2\n",
            ),
            (
                Language::TypeScript,
                "src/keyed.ts",
                "keyed",
                "label",
                "const label = 1;\nexport const record = { [label]: 2 };\n",
                "const label = 1;\nexport const record = { label: 2 };\n",
            ),
            (
                Language::Java,
                "app/Config.java",
                "qualifier",
                "Config",
                "class Config {\n    static int LIMIT = 7;\n    int qualified() { return Config.LIMIT; }\n    int shadowed() { int Config = 1; return Config; }\n}\n",
                "class Config {\n    static int LIMIT = 7;\n    int qualified() { return Config.LIMIT; }\n    int plain() { int limit = 1; return limit; }\n}\n",
            ),
            (
                Language::Rust,
                "src/raw.rs",
                "escaped",
                "r#match",
                "pub fn make(r#match: u32) -> u32 { r#match }\n",
                "pub fn make(r#match: u32) -> u32 { 0 }\n",
            ),
            (
                Language::Rust,
                "src/heads.rs",
                "heads",
                "render",
                "pub fn render() -> u32 {\n    1\n}\n\npub fn caller() -> u32 {\n    render()\n}\n",
                "pub fn render() -> u32 {\n    1\n}\n",
            ),
        ];
        for (language, path, name, spelling, positive, near_miss) in pairs {
            let source = format!(
                r#"(policy :id "test.conformance.{name}" :name "Conformance {name}"
              :message "{spelling} must never occur as value_reference" :severity warning
              :analysis (analysis :type assertion
                :subject (rql (identifier :text/regex "^{spelling}$" :capture "target"))
                :asserts [(assert :id forbidden :at "target" :role value_reference :expect none)]))"#
            );
            for (fixture, count) in [(positive, 1), (near_miss, 0)] {
                let bytes = assert_report_parity(
                    language,
                    path,
                    fixture,
                    &source,
                    PolicyBudget::default(),
                    None,
                );
                let report: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(
                    report["runs"][0]["completion"]["type"], "complete",
                    "{name}"
                );
                assert_eq!(
                    report["runs"][0]["findings"].as_array().unwrap().len(),
                    count,
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn shipped_policy_inventory_contains_no_typed_occurrence_assertions() {
        let catalog = crate::built_in_policy_catalog().expect("built-in catalog loads");
        let selection = crate::BuiltInPolicySelection {
            packs: catalog
                .document()
                .packs
                .iter()
                .map(|pack| pack.id.clone())
                .collect(),
            ..crate::BuiltInPolicySelection::default()
        };
        let selected = catalog.select(&selection).expect("all packs select");
        assert!(!selected.is_empty(), "the shipped inventory is nonempty");
        let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
            CatalogRegistryLimits::default(),
        ));
        let mut registry =
            PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
        let mut occurrence_assertions = Vec::new();
        for entry in selected {
            let loaded = registry
                .register_policy_bytes(entry.source_identity(), entry.source().as_bytes())
                .expect("shipped policy loads");
            if let crate::PolicyAnalysis::Assertion { spec } = &loaded.definition().analysis {
                occurrence_assertions.extend(
                    spec.asserts
                        .iter()
                        .filter(|assertion| matches!(assertion, crate::PolicyAssert::Occurrence(_)))
                        .map(|_| loaded.definition().metadata.id.to_string()),
                );
            }
        }
        assert!(
            occurrence_assertions.is_empty(),
            "inventory must be based on typed policy asserts: {occurrence_assertions:?}"
        );
    }
}
