//! Query projection for direct procedure-local C/C++ provenance rules.

use super::call_binding::CallBindingValue;
use super::results::{CodeQueryDiagnostic, CodeQueryDiagnosticCode, CodeQueryDiagnosticImpact};
use super::*;
use brokk_bifrost_analysis::analyzer::{
    cpp_provenance_for_anchor, cpp_provenance_for_anchor_with_model_key,
};
use brokk_bifrost_core::analyzer::cpp_facts::{CppProvenanceFact, CppProvenanceRule};
use brokk_bifrost_rql::CppProvenanceFilter;

pub(super) fn provenance_expansions_for_call_binding(
    workspace: Option<&WorkspaceAnalyzer>,
    semantic: &mut Option<SemanticQueryContext<'_>>,
    value: &CallBindingValue,
    filter: &CppProvenanceFilter,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    let seed = value
        .site
        .shape
        .seed
        .as_ref()
        .expect("source call bindings retain their structural seed");
    provenance_expansions_with_model_key(
        workspace,
        semantic,
        seed,
        filter,
        value
            .site
            .selector
            .exact
            .then_some(value.site.modeled_key.as_ref())
            .flatten(),
        cancellation,
        diagnostics,
    )
}

pub(super) fn provenance_expansions(
    workspace: Option<&WorkspaceAnalyzer>,
    semantic: &mut Option<SemanticQueryContext<'_>>,
    seed: &Arc<SeedMatch>,
    filter: &CppProvenanceFilter,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    provenance_expansions_with_model_key(
        workspace,
        semantic,
        seed,
        filter,
        None,
        cancellation,
        diagnostics,
    )
}

fn provenance_expansions_with_model_key(
    workspace: Option<&WorkspaceAnalyzer>,
    semantic: &mut Option<SemanticQueryContext<'_>>,
    seed: &Arc<SeedMatch>,
    filter: &CppProvenanceFilter,
    modeled_key: Option<&brokk_bifrost_analysis::analyzer::usages::effects::ModeledProcedureKey>,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    if seed.language != Language::Cpp {
        return Vec::new();
    }
    let Some(workspace) = workspace else {
        diagnostics.push(CodeQueryDiagnostic {
            source: None,
            code: CodeQueryDiagnosticCode::EffectDerivationIncomplete,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: seed.language.config_label(),
            message: "C/C++ provenance requires a semantic workspace".to_string(),
            exhausted_roots: Vec::new(),
            withheld_rows_path: None,
        });
        return Vec::new();
    };
    let Some(semantic) = semantic.as_mut() else {
        diagnostics.push(CodeQueryDiagnostic {
            source: None,
            code: CodeQueryDiagnosticCode::EffectDerivationIncomplete,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: seed.language.config_label(),
            message: "C/C++ provenance requires procedure semantics".to_string(),
            exhausted_roots: Vec::new(),
            withheld_rows_path: None,
        });
        return Vec::new();
    };
    let rules = if filter.rules.is_empty() {
        CppProvenanceRule::ALL.to_vec()
    } else {
        filter.rules.clone()
    };
    let anchor = seed.facts.node(seed.fact_match.node).range;
    let procedures = semantic.procedure_of_match(seed);
    let mut matched = false;
    for procedure in procedures {
        for rule in rules.iter().copied() {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                diagnostics.push(CodeQueryDiagnostic {
                    source: None,
                    code: CodeQueryDiagnosticCode::EffectDerivationIncomplete,
                    impact: CodeQueryDiagnosticImpact::Incomplete,
                    branch: Vec::new(),
                    language: seed.language.config_label(),
                    message: "C/C++ provenance selection was cancelled".to_string(),
                    exhausted_roots: Vec::new(),
                    withheld_rows_path: None,
                });
                return Vec::new();
            }
            let outcome = if let Some(modeled_key) = modeled_key {
                cpp_provenance_for_anchor_with_model_key(
                    workspace,
                    &procedure.handle,
                    anchor,
                    rule,
                    Some(modeled_key),
                    cancellation,
                )
            } else {
                cpp_provenance_for_anchor(workspace, &procedure.handle, anchor, rule, cancellation)
            };
            if !outcome.complete {
                report_incomplete(diagnostics, seed, rule, outcome.reason);
            }
            if outcome
                .fact
                .is_some_and(|fact| fact_matches_rule(&fact, rule))
            {
                matched = true;
            }
        }
    }
    matched
        .then(|| pipeline_expansion(PipelineValue::StructuralMatch(seed.clone())))
        .into_iter()
        .collect()
}

fn fact_matches_rule(fact: &CppProvenanceFact, rule: CppProvenanceRule) -> bool {
    fact.rule == rule
}

fn report_incomplete(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    seed: &SeedMatch,
    rule: CppProvenanceRule,
    reason: Option<&'static str>,
) {
    diagnostics.push(CodeQueryDiagnostic {
        source: None,
        code: CodeQueryDiagnosticCode::EffectDerivationIncomplete,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: seed.language.config_label(),
        message: format!(
            "C/C++ provenance rule {} is incomplete for {}: {}",
            rule.label(),
            rel_path_string(&seed.file),
            reason.unwrap_or("unknown")
        ),
        exhausted_roots: Vec::new(),
        withheld_rows_path: None,
    });
}
