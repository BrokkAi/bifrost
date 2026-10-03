//! Exact native failure-handler body state over prepared syntax.

use super::super::provider::StructuralSyntaxLimitedOutcome;
use super::results::{
    CodeQueryDiagnostic, CodeQueryDiagnosticCode, CodeQueryDiagnosticImpact,
    CodeQueryFailureHandlerState, CodeQueryRange, CodeQueryResultRef, DetailedCodeQueryKey,
};
use super::*;
use crate::analyzer::semantic::{ContentIdentity, StableDigest};
use brokk_bifrost_analysis::analyzer::structural::failure_handlers::{
    HandlerBodyShape, HandlerBodyState, cpp_catch_body_shape, csharp_catch_body_shape,
    java_catch_body_shape, js_ts_catch_body_shape, kotlin_catch_body_shape, php_catch_body_shape,
    python_except_body_shape, ruby_rescue_body_shape,
};
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;

const MAX_HANDLER_SOURCE_BYTES: usize = 1024 * 1024;

#[derive(Default)]
pub(super) struct FailureHandlerStateCache {
    syntax: HashMap<ProjectFile, StructuralSyntaxLimitedOutcome>,
    reported: HashSet<(String, &'static str)>,
}

#[derive(Debug, Clone)]
pub(super) struct FailureHandlerStateValue {
    pub(super) row: CodeQueryFailureHandlerState,
    pub(super) file: ProjectFile,
    pub(super) anchor: Range,
}

impl FailureHandlerStateValue {
    pub(super) fn key(&self) -> String {
        self.row.id.clone()
    }
}

fn public_range(facts: &FileFacts, range: Range) -> CodeQueryRange {
    super::render::range_for_span(
        facts,
        Span {
            start_byte: range.start_byte,
            end_byte: range.end_byte,
        },
    )
}

fn make_value(
    seed: &SeedMatch,
    body: Option<Range>,
    verdict: &'static str,
    reason: Option<&'static str>,
) -> FailureHandlerStateValue {
    let anchor = seed.facts.node(seed.fact_match.node).range;
    let catch_ast_id = crate::analyzer::structural::occurrence_rows::ast_id(
        seed.facts.source_identity(),
        seed.fact_match.node,
    );
    let id = format!(
        "failure_handler_state:{}:{catch_ast_id}",
        rel_path_string(&seed.file)
    );
    FailureHandlerStateValue {
        row: CodeQueryFailureHandlerState {
            id,
            path: rel_path_string(&seed.file),
            language: seed.language.config_label(),
            range: public_range(&seed.facts, anchor),
            catch_ast_id,
            body_range: body.map(|body| public_range(&seed.facts, body)),
            verdict,
            proof: if reason.is_some() { "unknown" } else { "exact" },
            coverage: if reason.is_some() {
                "incomplete"
            } else {
                "exhaustive"
            },
            reason,
        },
        file: seed.file.clone(),
        anchor,
    }
}

fn expansion(
    cache: &mut FailureHandlerStateCache,
    seed: &SeedMatch,
    body: Option<Range>,
    verdict: &'static str,
    reason: Option<&'static str>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    let value = make_value(seed, body, verdict, reason);
    if let Some(reason) = reason
        && cache.reported.insert((value.row.id.clone(), reason))
    {
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::FailureHandlerDerivationIncomplete,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: seed.language.config_label(),
            message: format!(
                "failure handler {} in {} is incomplete: {reason}",
                value.row.catch_ast_id, value.row.path
            ),
            exhausted_roots: Vec::new(),
        });
    }
    vec![pipeline_expansion(PipelineValue::FailureHandlerState(
        Box::new(value),
    ))]
}

pub(super) fn failure_handler_state_expansions(
    analyzer: &dyn IAnalyzer,
    cache: &mut FailureHandlerStateCache,
    seed: &Arc<SeedMatch>,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    if seed.facts.node(seed.fact_match.node).kind != NormalizedKind::Catch {
        return Vec::new();
    }
    let classify: fn(&PreparedSyntaxTree, Range) -> HandlerBodyShape = match seed.language {
        Language::Java => java_catch_body_shape,
        Language::JavaScript | Language::TypeScript => js_ts_catch_body_shape,
        Language::Python => python_except_body_shape,
        Language::CSharp => csharp_catch_body_shape,
        Language::Php => php_catch_body_shape,
        Language::Cpp => cpp_catch_body_shape,
        Language::Kotlin => kotlin_catch_body_shape,
        Language::Ruby => ruby_rescue_body_shape,
        _ => {
            return expansion(
                cache,
                seed,
                None,
                "unknown",
                Some("unsupported_language"),
                diagnostics,
            );
        }
    };
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return expansion(cache, seed, None, "unknown", Some("cancelled"), diagnostics);
    }
    if !cache.syntax.contains_key(&seed.file) {
        let outcome = analyzer
            .structural_fact_providers()
            .into_iter()
            .find(|provider| provider.structural_language() == seed.language)
            .map_or(StructuralSyntaxLimitedOutcome::Unavailable, |provider| {
                provider.structural_syntax_limited(
                    &seed.file,
                    MAX_HANDLER_SOURCE_BYTES,
                    cancellation,
                )
            });
        cache.syntax.insert(seed.file.clone(), outcome);
    }
    let syntax = match cache.syntax.get(&seed.file).expect("syntax was cached") {
        StructuralSyntaxLimitedOutcome::Available(syntax) => {
            let actual = ContentIdentity::from_digest(StableDigest::from_array(
                syntax.prepared().source_sha256(),
            ));
            if actual != seed.facts.source_identity() {
                return expansion(
                    cache,
                    seed,
                    None,
                    "unknown",
                    Some("snapshot_mismatch"),
                    diagnostics,
                );
            }
            syntax.clone_prepared()
        }
        StructuralSyntaxLimitedOutcome::Exceeded { .. } => {
            return expansion(
                cache,
                seed,
                None,
                "unknown",
                Some("source_limit"),
                diagnostics,
            );
        }
        StructuralSyntaxLimitedOutcome::Cancelled => {
            return expansion(cache, seed, None, "unknown", Some("cancelled"), diagnostics);
        }
        StructuralSyntaxLimitedOutcome::Unavailable => {
            return expansion(
                cache,
                seed,
                None,
                "unknown",
                Some("syntax_unavailable"),
                diagnostics,
            );
        }
    };
    let catch = seed.facts.node(seed.fact_match.node).range;
    let shape = classify(&syntax, catch);
    match shape.state {
        HandlerBodyState::Open(gap) => expansion(
            cache,
            seed,
            shape.body,
            "unknown",
            Some(gap.label()),
            diagnostics,
        ),
        HandlerBodyState::Nonempty => {
            expansion(cache, seed, shape.body, "nonempty", None, diagnostics)
        }
        HandlerBodyState::Empty => expansion(cache, seed, shape.body, "empty", None, diagnostics),
    }
}

pub(super) fn detailed_key(value: &FailureHandlerStateValue) -> DetailedCodeQueryKey {
    DetailedCodeQueryKey::FailureHandlerState {
        id: value.row.id.clone(),
        catch_ast_id: value.row.catch_ast_id.clone(),
        verdict: value.row.verdict.to_owned(),
    }
}

pub(super) fn result_ref(value: &FailureHandlerStateValue) -> CodeQueryResultRef {
    CodeQueryResultRef::FailureHandlerState {
        id: value.row.id.clone(),
        path: value.row.path.clone(),
        range: value.row.range,
        catch_ast_id: value.row.catch_ast_id.clone(),
        verdict: value.row.verdict,
    }
}
