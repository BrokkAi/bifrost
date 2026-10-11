//! Query-local C/C++ range relations for the direct CodeQL parity slice.
//!
//! The call relations deliberately operate on an existing call-binding row.
//! Policies must establish the exact declared library identity with
//! `resolved-call` before selecting one of these relations; this module only
//! asks the bounded C++ producer about the already-selected call range.

use super::call_binding::CallBindingValue;
use super::*;
use brokk_bifrost_analysis::analyzer::range_facts::{
    bad_strncpy_size, inconsistent_loop_direction, network_to_host_function_as_array_bound,
    unsafe_array_for_days_of_the_year,
};
use brokk_bifrost_core::analyzer::cpp_facts::CppRangeFactOutcome;

fn report_incomplete(
    file: &ProjectFile,
    rule: &'static str,
    reason: &'static str,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) {
    let language = crate::analyzer::common::language_for_file(file).config_label();
    let message = format!(
        "{rule}: C/C++ range evidence is incomplete ({reason}) for {}",
        rel_path_string(file)
    );
    if diagnostics.iter().any(|diagnostic| {
        diagnostic.code == CodeQueryDiagnosticCode::SemanticAnalysisPartial
            && diagnostic.language == language
            && diagnostic.message == message
    }) {
        return;
    }
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::SemanticAnalysisPartial,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language,
        message,
        exhausted_roots: Vec::new(),
    });
}

fn retain_structural_match_for_binding(
    outcome: CppRangeFactOutcome,
    value: &CallBindingValue,
    rule: &'static str,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    match outcome {
        CppRangeFactOutcome::Proven(_) => vec![pipeline_expansion(PipelineValue::StructuralMatch(
            value
                .site
                .shape
                .seed
                .as_ref()
                .expect("source call bindings retain their structural seed")
                .clone(),
        ))],
        CppRangeFactOutcome::NotApplicable => Vec::new(),
        CppRangeFactOutcome::Incomplete(reason) => {
            report_incomplete(value.file(), rule, reason, diagnostics);
            Vec::new()
        }
    }
}

pub(super) fn bad_strncpy_size_expansions(
    analyzer: &dyn IAnalyzer,
    value: &CallBindingValue,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    if value.row().formal_index != Some(2) {
        return Vec::new();
    }
    retain_structural_match_for_binding(
        bad_strncpy_size(
            analyzer,
            value.file(),
            value.site.report.range,
            cancellation,
        ),
        value,
        "cpp-bad-strncpy-size",
        diagnostics,
    )
}

pub(super) fn network_to_host_function_as_array_bound_expansions(
    analyzer: &dyn IAnalyzer,
    value: &CallBindingValue,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    if value.row().formal_index != Some(0) {
        return Vec::new();
    }
    retain_structural_match_for_binding(
        network_to_host_function_as_array_bound(
            analyzer,
            value.file(),
            value.site.report.range,
            cancellation,
        ),
        value,
        "cpp-network-to-host-function-as-array-bound",
        diagnostics,
    )
}

fn retain_structural_match(
    outcome: CppRangeFactOutcome,
    seed: &Arc<SeedMatch>,
    rule: &'static str,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    match outcome {
        CppRangeFactOutcome::Proven(_) => {
            vec![pipeline_expansion(PipelineValue::StructuralMatch(
                seed.clone(),
            ))]
        }
        CppRangeFactOutcome::NotApplicable => Vec::new(),
        CppRangeFactOutcome::Incomplete(reason) => {
            report_incomplete(&seed.file, rule, reason, diagnostics);
            Vec::new()
        }
    }
}

pub(super) fn inconsistent_loop_direction_expansions(
    analyzer: &dyn IAnalyzer,
    seed: &Arc<SeedMatch>,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    if seed.language != Language::Cpp {
        return Vec::new();
    }
    let range = seed.facts.node(seed.fact_match.node).range;
    retain_structural_match(
        inconsistent_loop_direction(analyzer, &seed.file, range, cancellation),
        seed,
        "cpp-inconsistent-loop-direction",
        diagnostics,
    )
}

pub(super) fn unsafe_array_for_days_of_the_year_expansions(
    analyzer: &dyn IAnalyzer,
    seed: &Arc<SeedMatch>,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    if seed.language != Language::Cpp {
        return Vec::new();
    }
    let range = seed.facts.node(seed.fact_match.node).range;
    retain_structural_match(
        unsafe_array_for_days_of_the_year(analyzer, &seed.file, range, cancellation),
        seed,
        "cpp-leap-year-unsafe-array-for-days-of-the-year",
        diagnostics,
    )
}
