//! Exact native failure-handler body state over prepared syntax.

use super::super::provider::StructuralSyntaxLimitedOutcome;
use super::results::{
    CodeQueryDiagnostic, CodeQueryDiagnosticCode, CodeQueryDiagnosticImpact,
    CodeQueryFailureHandlerState, CodeQueryResultRef, DetailedCodeQueryKey,
};
use super::*;
use crate::analyzer::semantic::{ContentIdentity, StableDigest};
use brokk_bifrost_analysis::analyzer::structural::failure_handlers::{
    HandlerBodyShape, HandlerBodyState, NativeFailureBranch, ScalaCatchBodyShape,
    cpp_catch_body_shape, java_catch_body_shape, js_ts_catch_body_shape, kotlin_catch_body_shape,
    php_catch_body_shape, python_except_body_shape, ruby_rescue_body_shape,
    scala_catch_body_shapes,
};
use brokk_bifrost_analysis::analyzer::{
    CSharpAnalyzer, WorkspaceAnalyzer, csharp_catch_facts, go_failure_handler_body_shapes,
    resolve_analyzer, rust_failure_handler_body_shapes,
};
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;

const MAX_HANDLER_SOURCE_BYTES: usize = 1024 * 1024;

type NativeFailureHook =
    fn(&WorkspaceAnalyzer, &ProjectFile, &PreparedSyntaxTree, Range) -> Vec<NativeFailureBranch>;

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

struct ExpansionSpec {
    anchor: Range,
    catch_ast_id: String,
    body: Option<Range>,
    verdict: &'static str,
    reason: Option<&'static str>,
    csharp_facts: Option<brokk_bifrost_analysis::analyzer::CSharpCatchFacts>,
}

/// Whether the adapter publishes any failure-handler state rows for this
/// language. The query preflight shares this declaration so a language with
/// no handler producer cannot appear as a complete empty relation.
pub(super) fn supports_language(language: Language) -> bool {
    matches!(
        language,
        Language::Rust
            | Language::Go
            | Language::Java
            | Language::JavaScript
            | Language::TypeScript
            | Language::Python
            | Language::CSharp
            | Language::Php
            | Language::Cpp
            | Language::Kotlin
            | Language::Ruby
            | Language::Scala
    )
}

fn make_value(
    seed: &SeedMatch,
    anchor: Range,
    catch_ast_id: String,
    body: Option<Range>,
    verdict: &'static str,
    reason: Option<&'static str>,
    csharp_facts: Option<&brokk_bifrost_analysis::analyzer::CSharpCatchFacts>,
) -> FailureHandlerStateValue {
    let id = format!(
        "failure_handler_state:{}:{catch_ast_id}",
        rel_path_string(&seed.file)
    );
    FailureHandlerStateValue {
        row: CodeQueryFailureHandlerState {
            id,
            path: rel_path_string(&seed.file),
            language: seed.language.config_label(),
            range: super::render::public_range(&seed.facts, anchor),
            catch_ast_id,
            body_range: body.map(|body| super::render::public_range(&seed.facts, body)),
            verdict,
            proof: if reason.is_some() { "unknown" } else { "exact" },
            coverage: if reason.is_some() {
                "incomplete"
            } else {
                "exhaustive"
            },
            reason,
            caught_type: csharp_facts.and_then(|facts| facts.caught_type.clone()),
            caught_type_relation: csharp_facts.map(|facts| facts.caught_type_relation.label()),
            has_filter: csharp_facts.map(|facts| facts.has_filter),
            rethrow_kind: csharp_facts.map(|facts| facts.rethrow.label()),
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
    let anchor = seed.facts.node(seed.fact_match.node).range;
    let catch_ast_id = crate::analyzer::structural::occurrence_rows::ast_id(
        seed.facts.source_identity(),
        seed.fact_match.node,
    );
    expansion_at(
        cache,
        seed,
        ExpansionSpec {
            anchor,
            catch_ast_id,
            body,
            verdict,
            reason,
            csharp_facts: None,
        },
        diagnostics,
    )
}

fn expansion_at(
    cache: &mut FailureHandlerStateCache,
    seed: &SeedMatch,
    spec: ExpansionSpec,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    let value = make_value(
        seed,
        spec.anchor,
        spec.catch_ast_id,
        spec.body,
        spec.verdict,
        spec.reason,
        spec.csharp_facts.as_ref(),
    );
    if let Some(reason) = spec.reason
        && cache.reported.insert((value.row.id.clone(), reason))
    {
        diagnostics.push(CodeQueryDiagnostic {
            source: None,
            code: CodeQueryDiagnosticCode::FailureHandlerDerivationIncomplete,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: seed.language.config_label(),
            message: format!(
                "failure handler {} in {} is incomplete: {reason}",
                value.row.catch_ast_id, value.row.path
            ),
            exhausted_roots: Vec::new(),
            withheld_rows_path: None,
        });
    }
    vec![pipeline_expansion(PipelineValue::FailureHandlerState(
        Box::new(value),
    ))]
}

pub(super) fn failure_handler_state_expansions(
    analyzer: &dyn IAnalyzer,
    workspace: Option<&WorkspaceAnalyzer>,
    cache: &mut FailureHandlerStateCache,
    seed: &Arc<SeedMatch>,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    let seed_kind = seed.facts.node(seed.fact_match.node).kind;
    let native_hook: Option<NativeFailureHook> = match seed.language {
        Language::Rust => Some(rust_failure_handler_body_shapes),
        Language::Go => Some(go_failure_handler_body_shapes),
        _ => None,
    };
    let native_seed = native_hook.is_some() && seed_kind.satisfies(NormalizedKind::Callable);
    if !native_seed && seed_kind != NormalizedKind::Catch {
        return Vec::new();
    }
    // Rust's native branches are selected below from callable seeds. A stale
    // or hand-written Catch query must not reintroduce the shared vocabulary
    // that the adapter deliberately does not publish.
    if seed.language == Language::Rust && !native_seed {
        return Vec::new();
    }
    let classify: Option<fn(&PreparedSyntaxTree, Range) -> HandlerBodyShape> = if native_seed {
        None
    } else {
        match seed.language {
            Language::Java => Some(java_catch_body_shape),
            Language::JavaScript | Language::TypeScript => Some(js_ts_catch_body_shape),
            Language::Python => Some(python_except_body_shape),
            Language::CSharp => None,
            Language::Php => Some(php_catch_body_shape),
            Language::Cpp => Some(cpp_catch_body_shape),
            Language::Kotlin => Some(kotlin_catch_body_shape),
            Language::Ruby => Some(ruby_rescue_body_shape),
            Language::Scala => None,
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
    let handler_seed = seed.facts.node(seed.fact_match.node).range;
    if native_seed {
        let workspace = workspace.expect("native failure-handler hooks require a workspace");
        let branches = native_hook.expect("native hook exists for native seed")(
            workspace,
            &seed.file,
            &syntax,
            handler_seed,
        );
        let callable_ast_id = crate::analyzer::structural::occurrence_rows::ast_id(
            seed.facts.source_identity(),
            seed.fact_match.node,
        );
        let mut expansions = Vec::with_capacity(branches.len());
        for branch in branches {
            let (verdict, reason) = match branch.shape.state {
                HandlerBodyState::Open(gap) => ("unknown", Some(gap.label())),
                HandlerBodyState::Nonempty => ("nonempty", None),
                HandlerBodyState::Empty => ("empty", None),
            };
            let catch_ast_id = format!(
                "{callable_ast_id}:native_failure:{:x}",
                branch.handler.start_byte
            );
            expansions.extend(expansion_at(
                cache,
                seed,
                ExpansionSpec {
                    anchor: branch.handler,
                    catch_ast_id,
                    body: branch.shape.body,
                    verdict,
                    reason,
                    csharp_facts: None,
                },
                diagnostics,
            ));
        }
        return expansions;
    }
    if seed.language == Language::Scala {
        let shapes = scala_catch_body_shapes(&syntax, handler_seed);
        let mut expansions = Vec::with_capacity(shapes.len());
        for ScalaCatchBodyShape { handler, shape } in shapes {
            let node_id = seed
                .facts
                .nodes()
                .iter()
                .enumerate()
                .find(|(_, node)| node.range == handler)
                .map(|(id, _)| id as u32);
            let Some(node_id) = node_id else {
                expansions.extend(expansion(
                    cache,
                    seed,
                    shape.body,
                    "unknown",
                    Some("unsupported_case_fact"),
                    diagnostics,
                ));
                continue;
            };
            let catch_ast_id = crate::analyzer::structural::occurrence_rows::ast_id(
                seed.facts.source_identity(),
                node_id,
            );
            let (verdict, reason) = match shape.state {
                HandlerBodyState::Open(gap) => ("unknown", Some(gap.label())),
                HandlerBodyState::Nonempty => ("nonempty", None),
                HandlerBodyState::Empty => ("empty", None),
            };
            expansions.extend(expansion_at(
                cache,
                seed,
                ExpansionSpec {
                    anchor: handler,
                    catch_ast_id,
                    body: shape.body,
                    verdict,
                    reason,
                    csharp_facts: None,
                },
                diagnostics,
            ));
        }
        return expansions;
    }
    if seed.language == Language::CSharp {
        let Some(csharp) = resolve_analyzer::<CSharpAnalyzer>(analyzer) else {
            return expansion(
                cache,
                seed,
                None,
                "unknown",
                Some("caught_type_unresolved"),
                diagnostics,
            );
        };
        let scope =
            brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::with_semantic_model_overlay(
                csharp,
                analyzer.semantic_model_overlay(),
            );
        let facts = csharp_catch_facts(csharp, scope.token(), &seed.file, &syntax, handler_seed);
        let (verdict, body_reason) = match facts.body.state {
            HandlerBodyState::Open(gap) => ("unknown", Some(gap.label())),
            HandlerBodyState::Nonempty => ("nonempty", None),
            HandlerBodyState::Empty => ("empty", None),
        };
        let reason = body_reason.or(facts.type_reason);
        let anchor = seed.facts.node(seed.fact_match.node).range;
        let catch_ast_id = crate::analyzer::structural::occurrence_rows::ast_id(
            seed.facts.source_identity(),
            seed.fact_match.node,
        );
        return expansion_at(
            cache,
            seed,
            ExpansionSpec {
                anchor,
                catch_ast_id,
                body: facts.body.body,
                verdict,
                reason,
                csharp_facts: Some(facts),
            },
            diagnostics,
        );
    }
    let shape = classify.expect("catch language has a classifier")(&syntax, handler_seed);
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
