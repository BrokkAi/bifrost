use std::sync::Arc;

use super::{HumanRenderColor, HumanRenderDetail, HumanRenderOptions};
use crate::finding::{PolicyFailureReason, PolicyRun, PolicyRunCompletion, PolicyWorkReport};
use crate::{
    CatalogRegistryLimits, PolicyBudget, PolicyRegistry, PolicyRegistryLimits,
    PolicyReportDocument, PolicyRuleDescriptor, PolicySourceIdentity, TaintCatalogRegistry,
};

fn report_with_completions(completions: &[PolicyRunCompletion]) -> PolicyReportDocument {
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    for index in 0..completions.len() {
        let source = format!(
            r#"(policy :schema-version 1 :id "test.round2-{index}"
                :name "Round two" :message "Matched" :severity warning
                :analysis (analysis :type match :selector
                  (rql :schema-version 1 (language typescript (function :name "target")))))"#
        );
        registry
            .register_policy_bytes(
                PolicySourceIdentity::new(format!("test:round2-{index}")),
                source.as_bytes(),
            )
            .unwrap();
    }
    let mut rules = Vec::new();
    let mut runs = Vec::new();
    for (policy, completion) in registry.policies().zip(completions) {
        let descriptor = PolicyRuleDescriptor::from_loaded(policy);
        runs.push(
            PolicyRun::try_new(
                policy.definition().metadata.id.clone(),
                policy.semantic_hash(),
                policy.definition().analysis.analysis_type(),
                completion.clone(),
                Vec::new(),
                Vec::new(),
                false,
                PolicyWorkReport::default(),
                &PolicyBudget::default(),
            )
            .unwrap(),
        );
        rules.push(descriptor);
    }
    PolicyReportDocument::try_new(rules, runs, Vec::new(), false, 0, None).unwrap()
}

#[test]
fn three_failed_runs_are_counted_independently_of_one_complete_run() {
    let failed = PolicyRunCompletion::failed(vec![PolicyFailureReason::SourceReadFailed]).unwrap();
    let report = report_with_completions(&[
        PolicyRunCompletion::Complete,
        failed.clone(),
        failed.clone(),
        failed,
    ]);
    let mut bytes = Vec::new();
    super::write_policy_human(
        &report,
        &HumanRenderOptions::new(HumanRenderDetail::Verbose, HumanRenderColor::Plain),
        &mut bytes,
        usize::MAX,
    )
    .unwrap();
    let output = String::from_utf8(bytes).unwrap();
    assert!(output.contains("1 complete policy run"), "{output}");
    assert!(output.contains("3 failed policy runs"), "{output}");
}
