use std::sync::Arc;

use super::*;
use brokk_bifrost_analysis::analyzer::nested_loop_facts;
use brokk_bifrost_analysis::analyzer::read_ledger::reason as derivation_reason;
use brokk_bifrost_core::analyzer::statement_facts::StatementFactKind;

pub(super) fn supports_kind(language: Language, kind: StatementFactKind) -> bool {
    let syntax = brokk_bifrost_analysis::analyzer::structural_spec_for(language)
        .and_then(|spec| spec.statement_fact_syntax());
    if kind == StatementFactKind::NestedLoopsWithSameVariable {
        return matches!(language, Language::Cpp | Language::CSharp | Language::Java)
            && syntax.is_none_or(|syntax| syntax.supports_kind(kind));
    }
    syntax.is_some_and(|syntax| syntax.supports_kind(kind))
}

pub(super) fn statement_fact_expansions(
    workspace: Option<&WorkspaceAnalyzer>,
    analyzer: &dyn IAnalyzer,
    semantic: &mut Option<SemanticQueryContext<'_>>,
    seed: &Arc<SeedMatch>,
    kind: StatementFactKind,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    if !supports_kind(seed.language, kind) {
        return Vec::new();
    }
    if kind == StatementFactKind::NestedLoopsWithSameVariable {
        return nested_loop_fact_expansions(
            analyzer,
            workspace,
            semantic,
            seed,
            cancellation,
            diagnostics,
        );
    }
    let rows = analyzer.statement_source_facts(&seed.file);
    let range = super::relations::seed_range(seed);
    report_undecided(
        seed,
        kind,
        rows.iter()
            .flat_map(|rows| &rows.undecided)
            .filter(|site| site.kind == kind)
            .map(|site| site.range),
        "conditional-compilation activation is unproven",
        diagnostics,
    );
    if kind == StatementFactKind::MissingCaseInSwitch {
        report_undecided(
            seed,
            kind,
            rows.iter()
                .flat_map(|rows| &rows.switches)
                .filter(|switch| switch.range == range && switch.enum_proof_undecided)
                .map(|switch| switch.range)
                .chain((rows.is_none() && seed.language == Language::Java).then_some(range)),
            "enum-switch exhaustiveness proof is unavailable",
            diagnostics,
        );
    }
    let Some(rows) = rows else {
        return Vec::new();
    };
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

fn report_undecided(
    seed: &SeedMatch,
    kind: StatementFactKind,
    sites: impl Iterator<Item = Range>,
    reason: &'static str,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) {
    let range = super::relations::seed_range(seed);
    let undecided = sites
        .filter(|site| range.contains(site))
        .map(|site| super::language_rules::UndecidedSite::at(site, reason))
        .collect();
    diagnostics.extend(
        super::language_rules::LanguageRuleMatches::decided(
            Vec::<Range>::new(),
            undecided,
            seed.language.config_label(),
            kind.label(),
            &seed.file,
        )
        .diagnostics,
    );
}

fn report_nested_loop_incomplete(
    analyzer: &dyn IAnalyzer,
    seed: &SeedMatch,
    reason: impl std::fmt::Debug,
    cause: Option<DerivationExecutionCause>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) {
    let code = CodeQueryDiagnosticCode::LoopRelationDerivationIncomplete;
    let language = seed.language.config_label();
    let message = format!(
        "nested-loops-with-same-variable: loop relation evidence is incomplete ({reason:?})"
    );
    if diagnostics.iter().any(|diagnostic| {
        diagnostic.code == code && diagnostic.language == language && diagnostic.message == message
    }) {
        return;
    }
    diagnostics.push(super::QueryExecutionState::diagnostic(
        analyzer,
        CodeQueryDiagnostic::new(CodeQueryDiagnostic {
            incompleteness: match cause {
                Some(cause) => brokk_bifrost_rql::Incompleteness::Operational(cause),
                None => brokk_bifrost_rql::Incompleteness::Content,
            },
            related: Vec::new(),
            source: None,
            code,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language,
            message,
            exhausted_roots: Vec::new(),
            withheld_rows_path: None,
        }),
        cause,
    ));
}

fn nested_loop_fact_expansions(
    analyzer: &dyn IAnalyzer,
    workspace: Option<&WorkspaceAnalyzer>,
    semantic: &mut Option<SemanticQueryContext<'_>>,
    seed: &Arc<SeedMatch>,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    if !supports_kind(
        seed.language,
        StatementFactKind::NestedLoopsWithSameVariable,
    ) {
        return Vec::new();
    }
    let Some(workspace) = workspace else {
        report_nested_loop_incomplete(
            analyzer,
            seed,
            "workspace_unavailable",
            Some(DerivationExecutionCause::Provider),
            diagnostics,
        );
        return Vec::new();
    };
    let Some(semantic) = semantic.as_mut() else {
        report_nested_loop_incomplete(
            analyzer,
            seed,
            "semantic_workspace_unavailable",
            Some(DerivationExecutionCause::Provider),
            diagnostics,
        );
        return Vec::new();
    };
    let procedures = semantic.cfg().procedure_of_match(seed);
    if procedures.is_empty() {
        report_nested_loop_incomplete(
            analyzer,
            seed,
            derivation_reason::NO_ENCLOSING_PROCEDURE,
            None,
            diagnostics,
        );
        return Vec::new();
    }
    let range = super::relations::seed_range(seed);
    let mut incomplete = false;
    let mut matches = false;
    for procedure in procedures {
        let facts = nested_loop_facts(workspace, &procedure.handle, cancellation);
        if !facts.complete {
            if DerivationExecutionCause::from_reason(
                facts.reason.unwrap_or(derivation_reason::UNKNOWN),
            )
            .is_some()
            {
                brokk_bifrost_core::profiling::note_with(|| {
                    format!(
                        "policy.units unbounded origin={}:{} cause=candidate_derivation detail={:?}",
                        file!(),
                        line!(),
                        facts.reason
                    )
                });
                workspace.analyzer().mark_execution_dependent();
            }
            incomplete = true;
            report_nested_loop_incomplete(
                analyzer,
                seed,
                facts.reason,
                CodeQueryDiagnosticCode::from_execution_reason(
                    CodeQueryDiagnosticCode::LoopRelationDerivationIncomplete,
                    facts.reason.unwrap_or(derivation_reason::UNKNOWN),
                )
                .1,
                diagnostics,
            );
            continue;
        }
        report_undecided(
            seed,
            StatementFactKind::NestedLoopsWithSameVariable,
            facts.undecided.iter().copied(),
            "conditional-compilation activation is unproven",
            diagnostics,
        );
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
