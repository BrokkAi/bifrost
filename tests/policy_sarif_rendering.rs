mod common;

use std::io::{self, Write};
use std::sync::Arc;

use brokk_bifrost::policy::{
    BoundedWitness, CatalogRegistryLimits, DefaultPolicyEvaluator, FindingIdentityStability,
    PolicyBatchBudget, PolicyBudget, PolicyEvaluationContext, PolicyEvaluator,
    PolicyIncompleteReason, PolicyRegistry, PolicyRegistryLimits, PolicyReportBuilder,
    PolicyReportDocument, PolicyRuleDescriptor, PolicyRun, PolicyRunCompletion,
    PolicySourceIdentity, ReportValueError, SarifToolIdentity, TaintCatalogRegistry, WitnessId,
    write_policy_sarif,
};
use brokk_bifrost::{CancellationToken, Language, TypescriptAnalyzer};
use jsonschema::Validator;
use serde_json::Value;
use sha2::{Digest, Sha256};

const SCHEMA_BYTES: &[u8] = include_bytes!("fixtures/sarif/sarif-schema-2.1.0.json");
const SCHEMA_SHA256: &str = "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e";

#[test]
fn zero_step_witness_is_rejected_before_sarif_projection() {
    assert!(matches!(
        BoundedWitness::try_new(
            WitnessId::try_new("test", "empty-flow").unwrap(),
            Vec::new(),
            false,
            0,
        ),
        Err(ReportValueError::EmptyCollection {
            field: "witness_steps"
        })
    ));
}

fn registry_with_policy(source: &str) -> PolicyRegistry {
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    registry
        .register_policy_bytes(
            PolicySourceIdentity::new("test:sarif-rendering"),
            source.as_bytes(),
        )
        .expect("valid policy");
    registry
}

fn evaluate(
    policy: &brokk_bifrost::policy::LoadedPolicy,
    files: &[(&str, &str)],
    budget: &mut PolicyBudget,
    cancellation: Option<&CancellationToken>,
) -> PolicyRun {
    let mut project = common::InlineTestProject::with_language(Language::TypeScript);
    for (path, source) in files {
        project = project.file(*path, *source);
    }
    let project = project.build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    DefaultPolicyEvaluator::new()
        .evaluate(
            policy,
            &PolicyEvaluationContext {
                analyzer: &analyzer,
                cancellation,
                cvss_overlays: &[],
                organizational_risk: &[],
            },
            budget,
        )
        .expect("policy evaluation")
}

fn assemble_report(
    policy: &brokk_bifrost::policy::LoadedPolicy,
    clean_skeleton: PolicyRun,
    evaluated: PolicyRun,
) -> PolicyReportDocument {
    let mut builder = PolicyReportBuilder::new(PolicyBatchBudget::default(), 1).unwrap();
    let findings = evaluated.findings().to_vec();
    let skeleton = if findings.is_empty() {
        evaluated
    } else {
        clean_skeleton
    };
    builder
        .register_policy(PolicyRuleDescriptor::from_loaded(policy), skeleton)
        .unwrap();
    for finding in findings {
        builder.retain_finding(finding).unwrap();
    }
    builder.finish().unwrap()
}

fn fixed_policy(id: &str, severity: &str, path: &str, target: &str) -> String {
    format!(
        r#"(policy
          :id "{id}"
          :name "SARIF rendering"
          :message "Selected target is reportable"
          :severity {severity}
          :description "A representative policy report"
          :help-uri "https://example.test/policies/{id}"
          :tags ["deterministic" "security"]
          :analysis (analysis :type match :selector
            (rql (where "{path}" (function :name "{target}")))))"#
    )
}

fn cvss_policy(id: &str, values: &[(&str, &str)]) -> String {
    let metrics = values
        .iter()
        .map(|(metric, value)| {
            let scope = if matches!(*metric, "SC" | "SI" | "SA") {
                "subsequent-system"
            } else {
                "vulnerable-system"
            };
            format!(
                r#"(metric
                  :name {metric}
                  :value {value}
                  :when (analysis-type :is match)
                  :basis policy-assertion
                  :scope {scope}
                  :evidence-refs [policy:self]
                  :rationale "SARIF CVSS evidence")"#
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        r#"(policy
          :id "{id}"
          :name "SARIF CVSS"
          :message "Selected target has CVSS evidence"
          :severity (cvss-severity :when-unscored warning)
          :analysis (analysis :type match :selector
            (rql (function :name "target")))
          :classification (classification
            :fallback (classification-id :taxonomy "Bifrost" :id "SARIF-CVSS")
            :cvss (cvss
              :version "4.0"
              :emit when-base-complete
              :metric-rules [{metrics}])))"#
    )
}

fn ordinary_report() -> PolicyReportDocument {
    let path = "src/café #%.ts";
    let source = fixed_policy("test.sarif-complete", "warning", path, "target");
    let registry = registry_with_policy(&source);
    let policy = registry.policies().next().unwrap();
    let skeleton = evaluate(
        policy,
        &[(path, "export function other() {}\n")],
        &mut PolicyBudget::default(),
        None,
    );
    let evaluated = evaluate(
        policy,
        &[(path, "export function target() { return 1; }\n")],
        &mut PolicyBudget::default(),
        None,
    );
    assemble_report(policy, skeleton, evaluated)
}

fn incomplete_empty_report() -> PolicyReportDocument {
    let source = fixed_policy("test.sarif-incomplete", "warning", "app.ts", "target");
    let registry = registry_with_policy(&source);
    let policy = registry.policies().next().unwrap();
    let clean = evaluate(
        policy,
        &[("app.ts", "export function other() {}\n")],
        &mut PolicyBudget::default(),
        None,
    );
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let incomplete = evaluate(
        policy,
        &[("app.ts", "export function target() {}\n")],
        &mut PolicyBudget::default(),
        Some(&cancellation),
    );
    assert!(matches!(
        incomplete.completion(),
        PolicyRunCompletion::Inconclusive { reasons }
            if reasons.contains(&PolicyIncompleteReason::Cancelled)
    ));
    assemble_report(policy, clean, incomplete)
}

fn partial_finding_report() -> PolicyReportDocument {
    let source = r#"(policy
      :id "test.sarif-partial"
      :name "SARIF partial"
      :message "Call selected"
      :severity warning
      :analysis (analysis :type match :selector
        (rql (call-sites-to :proof proven
          (enclosing-decl (where "target.ts" (function :name "target")))))))"#;
    let registry = registry_with_policy(source);
    let policy = registry.policies().next().unwrap();
    let skeleton = evaluate(
        policy,
        &[("target.ts", "export function target() {}\n")],
        &mut PolicyBudget::default(),
        None,
    );
    let files = [
        ("target.ts", "export function target() {}\n"),
        (
            "caller.ts",
            "import { target } from './target';\nexport function caller() { target(); }\n",
        ),
    ];
    let complete = evaluate(policy, &files, &mut PolicyBudget::default(), None);
    let source_limit = usize::try_from(complete.work().scanned_source_bytes())
        .unwrap()
        .saturating_sub(1);
    let mut budget = PolicyBudget::builder()
        .with_query_limits(
            brokk_bifrost::analyzer::structural::CodeQueryExecutionLimits {
                max_scanned_files: 2,
                max_scanned_source_bytes: source_limit,
                ..Default::default()
            },
        )
        .unwrap()
        .with_max_diagnostics(1)
        .unwrap()
        .build()
        .unwrap();
    let partial = evaluate(policy, &files, &mut budget, None);
    assert_eq!(partial.findings().len(), 1);
    assert_eq!(
        partial.findings()[0].identity_stability(),
        FindingIdentityStability::Weak
    );
    assemble_report(policy, skeleton, partial)
}

fn cvss_report(scored: bool) -> PolicyReportDocument {
    let mut values = vec![
        ("AV", "L"),
        ("AC", "L"),
        ("AT", "P"),
        ("PR", "L"),
        ("UI", "N"),
        ("VC", "H"),
        ("VI", "H"),
        ("VA", "H"),
        ("SC", "N"),
        ("SI", "N"),
        ("SA", "N"),
    ];
    if !scored {
        values.remove(0);
    }
    let id = if scored {
        "test.sarif-cvss-scored"
    } else {
        "test.sarif-cvss-unscored"
    };
    let source = cvss_policy(id, &values);
    let registry = registry_with_policy(&source);
    let policy = registry.policies().next().unwrap();
    let skeleton = evaluate(
        policy,
        &[("app.ts", "export function other() {}\n")],
        &mut PolicyBudget::default(),
        None,
    );
    let evaluated = evaluate(
        policy,
        &[("app.ts", "export function target() { return 1; }\n")],
        &mut PolicyBudget::default(),
        None,
    );
    assemble_report(policy, skeleton, evaluated)
}

fn unrated_report() -> PolicyReportDocument {
    let source = fixed_policy("test.sarif-unrated", "unrated", "app.ts", "target");
    let registry = registry_with_policy(&source);
    let policy = registry.policies().next().unwrap();
    let skeleton = evaluate(
        policy,
        &[("app.ts", "export function other() {}\n")],
        &mut PolicyBudget::default(),
        None,
    );
    let evaluated = evaluate(
        policy,
        &[("app.ts", "export function target() {}\n")],
        &mut PolicyBudget::default(),
        None,
    );
    assemble_report(policy, skeleton, evaluated)
}

fn unsupported_empty_report() -> PolicyReportDocument {
    let source = r#"(policy
      :id "test.sarif-unsupported"
      :name "SARIF unsupported"
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
            :accepts [untrusted])])))"#;
    let registry = registry_with_policy(source);
    let policy = registry.policies().next().unwrap();
    let unsupported = evaluate(
        policy,
        &[("app.ts", "export function noop() {}\n")],
        &mut PolicyBudget::default(),
        None,
    );
    assert!(matches!(
        unsupported.completion(),
        PolicyRunCompletion::Unsupported { .. }
    ));
    assemble_report(policy, unsupported.clone(), unsupported)
}

fn failed_empty_report() -> PolicyReportDocument {
    let source = r#"(policy
      :id "test.sarif-failed"
      :name "SARIF failed"
      :message "Receiver terminal is not a match finding"
      :severity warning
      :analysis (analysis :type match
        :selector (rql (receiver-targets (call :callee (name "run"))))))"#;
    let registry = registry_with_policy(source);
    let policy = registry.policies().next().unwrap();
    let failed = evaluate(
        policy,
        &[(
            "app.ts",
            "class Service { run() {} }\nexport function call(s: Service) { s.run(); }\n",
        )],
        &mut PolicyBudget::default(),
        None,
    );
    assert!(matches!(
        failed.completion(),
        PolicyRunCompletion::Failed { .. }
    ));
    assemble_report(policy, failed.clone(), failed)
}

fn mixed_complete_and_unsupported_report() -> PolicyReportDocument {
    let complete_source = fixed_policy("test.sarif-mixed-complete", "warning", "app.ts", "target");
    let complete_registry = registry_with_policy(&complete_source);
    let complete_policy = complete_registry.policies().next().unwrap();
    let complete_skeleton = evaluate(
        complete_policy,
        &[("app.ts", "export function other() {}\n")],
        &mut PolicyBudget::default(),
        None,
    );
    let complete = evaluate(
        complete_policy,
        &[("app.ts", "export function target() {}\n")],
        &mut PolicyBudget::default(),
        None,
    );

    let unsupported = unsupported_empty_report();
    let mut builder = PolicyReportBuilder::new(PolicyBatchBudget::default(), 2).unwrap();
    builder
        .register_policy(
            PolicyRuleDescriptor::from_loaded(complete_policy),
            complete_skeleton,
        )
        .unwrap();
    builder
        .register_policy(
            unsupported.rules()[0].clone(),
            unsupported.runs()[0].clone(),
        )
        .unwrap();
    for finding in complete.findings() {
        builder.retain_finding(finding.clone()).unwrap();
    }
    builder.finish().unwrap()
}

fn render(report: &PolicyReportDocument) -> (Vec<u8>, Value) {
    let mut bytes = Vec::new();
    let written = write_policy_sarif(
        report,
        &SarifToolIdentity::default(),
        &mut bytes,
        4 * 1024 * 1024,
    )
    .unwrap();
    assert_eq!(written, u64::try_from(bytes.len()).unwrap());
    let value = serde_json::from_slice(&bytes).unwrap();
    (bytes, value)
}

fn schema_validator(schema: &Value) -> Validator {
    jsonschema::draft4::new(schema).expect("vendored SARIF schema is valid draft 4")
}

#[test]
fn vendored_schema_has_the_exact_reviewed_oasis_checksum() {
    let digest = Sha256::digest(SCHEMA_BYTES);
    assert_eq!(format!("{digest:x}"), SCHEMA_SHA256);
}

#[test]
fn complete_incomplete_partial_scored_and_unscored_reports_validate_offline() {
    let schema: Value = serde_json::from_slice(SCHEMA_BYTES).unwrap();
    let validator = schema_validator(&schema);
    let reports = [
        ordinary_report(),
        incomplete_empty_report(),
        partial_finding_report(),
        cvss_report(true),
        cvss_report(false),
        unsupported_empty_report(),
        failed_empty_report(),
    ];

    for report in &reports {
        let (_, value) = render(report);
        let errors = validator
            .iter_errors(&value)
            .map(|error| format!("{} at {}", error, error.instance_path()))
            .collect::<Vec<_>>();
        assert!(
            errors.is_empty(),
            "SARIF validation errors:\n{}",
            errors.join("\n")
        );
    }
}

#[test]
fn complete_result_has_rule_parity_unicode_region_relative_uri_and_strong_fingerprint() {
    let report = ordinary_report();
    let (first, value) = render(&report);
    let (second, _) = render(&report);
    assert_eq!(first, second);
    assert_eq!(value["version"], "2.1.0");
    let run = &value["runs"][0];
    assert_eq!(run["columnKind"], "unicodeCodePoints");
    assert_eq!(run["invocations"][0]["executionSuccessful"], true);
    let rule = &run["tool"]["driver"]["rules"][0];
    let result = &run["results"][0];
    assert_eq!(result["ruleId"], rule["id"]);
    assert_eq!(result["ruleIndex"], 0);
    assert_eq!(result["level"], "warning");
    assert_eq!(
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "src/caf%C3%A9%20%23%25.ts"
    );
    assert_eq!(
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"],
        "SRCROOT"
    );
    assert!(
        !result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            .as_str()
            .unwrap()
            .contains("%2F")
    );
    assert_eq!(
        result["partialFingerprints"]["bifrostFinding/v1"],
        report.runs()[0].findings()[0].id().to_string()
    );
    assert_eq!(
        result["properties"]["bifrost.findingId"],
        report.runs()[0].findings()[0].id().to_string()
    );
    assert!(!String::from_utf8(first).unwrap().contains("baselineState"));
}

#[test]
fn incomplete_empty_and_weak_finding_reports_are_never_presented_as_clean() {
    let (_, incomplete) = render(&incomplete_empty_report());
    let invocation = &incomplete["runs"][0]["invocations"][0];
    assert_eq!(invocation["executionSuccessful"], false);
    assert_eq!(
        incomplete["runs"][0]["results"].as_array().unwrap().len(),
        0
    );
    assert!(
        !invocation["toolExecutionNotifications"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let partial_report = partial_finding_report();
    let (_, partial) = render(&partial_report);
    let result = &partial["runs"][0]["results"][0];
    assert!(result.get("partialFingerprints").is_none());
    assert_eq!(
        result["properties"]["bifrost.findingId"],
        partial_report.runs()[0].findings()[0].id().to_string()
    );
    assert_eq!(result["properties"]["bifrost.identityStability"], "weak");
    assert_eq!(
        partial["runs"][0]["invocations"][0]["executionSuccessful"],
        false
    );
}

#[test]
fn unsupported_failed_and_mixed_runs_have_stable_unsuccessful_invocations() {
    let (_, unsupported) = render(&unsupported_empty_report());
    let unsupported_invocation = &unsupported["runs"][0]["invocations"][0];
    assert_eq!(unsupported_invocation["executionSuccessful"], false);
    assert_eq!(
        unsupported_invocation["toolExecutionNotifications"][0]["descriptor"]["id"],
        "BIFROST_POLICY_UNSUPPORTED"
    );
    assert_eq!(
        unsupported_invocation["toolExecutionNotifications"][0]["level"],
        "warning"
    );

    let (_, failed) = render(&failed_empty_report());
    let failed_invocation = &failed["runs"][0]["invocations"][0];
    assert_eq!(failed_invocation["executionSuccessful"], false);
    assert_eq!(
        failed_invocation["toolExecutionNotifications"][0]["descriptor"]["id"],
        "BIFROST_POLICY_FAILED"
    );
    assert_eq!(
        failed_invocation["toolExecutionNotifications"][0]["level"],
        "error"
    );

    let (_, mixed) = render(&mixed_complete_and_unsupported_report());
    assert_eq!(mixed["runs"][0]["results"].as_array().unwrap().len(), 1);
    assert_eq!(
        mixed["runs"][0]["invocations"][0]["executionSuccessful"],
        false
    );
    assert_eq!(
        mixed["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn cvss_variants_and_unrated_semantics_are_explicit() {
    let (_, scored) = render(&cvss_report(true));
    assert_eq!(
        scored["runs"][0]["results"][0]["properties"]["bifrost.cvss"]["variants"][0]["assessment"]
            ["type"],
        "scored"
    );
    let (_, unscored) = render(&cvss_report(false));
    assert_eq!(
        unscored["runs"][0]["results"][0]["properties"]["bifrost.cvss"]["variants"][0]["assessment"]
            ["type"],
        "unscored"
    );

    let (_, unrated) = render(&unrated_report());
    let rule = &unrated["runs"][0]["tool"]["driver"]["rules"][0];
    let result = &unrated["runs"][0]["results"][0];
    assert_eq!(rule["defaultConfiguration"]["level"], "none");
    assert_eq!(result["level"], "none");
    assert_eq!(result["kind"], "informational");
    assert_eq!(result["properties"]["bifrost.unrated"], true);
}

#[test]
fn sarif_streaming_respects_the_encoded_byte_bound() {
    let report = ordinary_report();
    let (full, _) = render(&report);
    let mut exact = Vec::new();
    assert_eq!(
        write_policy_sarif(
            &report,
            &SarifToolIdentity::default(),
            &mut exact,
            full.len(),
        )
        .unwrap(),
        u64::try_from(full.len()).unwrap()
    );
    assert_eq!(exact, full);

    let mut bounded = Vec::new();
    let error = write_policy_sarif(
        &report,
        &SarifToolIdentity::default(),
        &mut bounded,
        full.len() - 1,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        brokk_bifrost::policy::PolicyRenderError::SerializedReportLimit {
            max_serialized_bytes
        } if max_serialized_bytes == full.len() - 1
    ));
    assert!(bounded.len() < full.len());
}

#[test]
fn invalid_tool_identity_is_rejected_before_any_sarif_bytes_are_written() {
    let report = ordinary_report();
    for tool in [
        SarifToolIdentity::new(""),
        SarifToolIdentity::new("Bifrost").with_version(""),
        SarifToolIdentity::new("Bifrost").with_information_uri("relative/tool"),
    ] {
        let mut output = Vec::new();
        let error = write_policy_sarif(&report, &tool, &mut output, 4 * 1024 * 1024).unwrap_err();
        assert!(matches!(
            error,
            brokk_bifrost::policy::PolicyRenderError::InvalidCanonicalReport { .. }
        ));
        assert!(output.is_empty());
    }
}

#[test]
fn sarif_preserves_broken_pipe_as_an_output_error() {
    struct BrokenPipe;

    impl Write for BrokenPipe {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let error = write_policy_sarif(
        &ordinary_report(),
        &SarifToolIdentity::default(),
        BrokenPipe,
        4 * 1024 * 1024,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        brokk_bifrost::policy::PolicyRenderError::Output(error)
            if error.kind() == io::ErrorKind::BrokenPipe
    ));
}
