use std::sync::Arc;

use super::*;
use brokk_bifrost_analysis::analyzer::nested_loop_facts;
use brokk_bifrost_core::analyzer::statement_facts::StatementFactKind;

pub(super) fn statement_fact_expansions(
    workspace: Option<&WorkspaceAnalyzer>,
    analyzer: &dyn IAnalyzer,
    semantic: &mut Option<SemanticQueryContext<'_>>,
    seed: &Arc<SeedMatch>,
    kind: StatementFactKind,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    if kind == StatementFactKind::NestedLoopsWithSameVariable {
        return nested_loop_fact_expansions(workspace, semantic, seed, cancellation, diagnostics);
    }
    if seed.language != Language::Cpp {
        return Vec::new();
    }
    let Some(rows) = analyzer.cpp_statement_source_facts(&seed.file) else {
        return Vec::new();
    };
    let range = super::relations::seed_range(seed);
    let matches = match kind {
        StatementFactKind::ComplexCondition => rows
            .conditions
            .iter()
            .any(|fact| range.contains(&fact.range) && fact.logical_operator_count > 5),
        StatementFactKind::LongSwitch => rows
            .switches
            .iter()
            .any(|fact| fact.range == range && fact.long_case),
        StatementFactKind::MissingCaseInSwitch => rows
            .switches
            .iter()
            .any(|fact| fact.range == range && fact.missing_enum_case),
        _ => rows
            .statements
            .iter()
            .any(|fact| fact.range == range && fact.kind == kind),
    };
    if matches {
        vec![pipeline_expansion(PipelineValue::StructuralMatch(
            Arc::clone(seed),
        ))]
    } else {
        Vec::new()
    }
}

fn report_nested_loop_incomplete(
    seed: &SeedMatch,
    reason: impl std::fmt::Debug,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) {
    let language = seed.language.config_label();
    let message = format!(
        "nested-loops-with-same-variable: loop relation evidence is incomplete ({reason:?})"
    );
    if diagnostics.iter().any(|diagnostic| {
        diagnostic.code == CodeQueryDiagnosticCode::LoopRelationDerivationIncomplete
            && diagnostic.language == language
            && diagnostic.message == message
    }) {
        return;
    }
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::LoopRelationDerivationIncomplete,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language,
        message,
        exhausted_roots: Vec::new(),
    });
}

fn nested_loop_fact_expansions(
    workspace: Option<&WorkspaceAnalyzer>,
    semantic: &mut Option<SemanticQueryContext<'_>>,
    seed: &Arc<SeedMatch>,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    if !matches!(seed.language, Language::Cpp | Language::CSharp) {
        return Vec::new();
    }
    let Some(workspace) = workspace else {
        report_nested_loop_incomplete(seed, "workspace_unavailable", diagnostics);
        return Vec::new();
    };
    let Some(semantic) = semantic.as_mut() else {
        report_nested_loop_incomplete(seed, "semantic_workspace_unavailable", diagnostics);
        return Vec::new();
    };
    let procedures = semantic.cfg().procedure_of_match(seed);
    if procedures.is_empty() {
        report_nested_loop_incomplete(seed, "no_enclosing_procedure", diagnostics);
        return Vec::new();
    }
    let range = super::relations::seed_range(seed);
    let mut incomplete = false;
    let mut matches = false;
    for procedure in procedures {
        let facts = nested_loop_facts(workspace, &procedure.handle, cancellation);
        if !facts.complete {
            incomplete = true;
            report_nested_loop_incomplete(seed, facts.reason, diagnostics);
            continue;
        }
        if facts.rows.contains(&range) {
            matches = true;
        }
    }
    if incomplete && !matches {
        return Vec::new();
    }
    if matches {
        vec![pipeline_expansion(PipelineValue::StructuralMatch(
            Arc::clone(seed),
        ))]
    } else {
        Vec::new()
    }
}
