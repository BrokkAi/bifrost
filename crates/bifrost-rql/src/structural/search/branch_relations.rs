//! Query projection of branch relations over one exact source snapshot.

use super::super::branch_relations::{
    self, BranchOpenReason, BranchRelationVerdict, JavaMemberKind, JavaMemberProofs,
};
use super::super::provider::StructuralSyntaxLimitedOutcome;
use super::results::{
    CodeQueryBranchRelation, CodeQueryDiagnostic, CodeQueryDiagnosticCode,
    CodeQueryDiagnosticImpact, CodeQueryRange, CodeQueryResultRef, DetailedCodeQueryKey,
};
use super::scalar_conditions::{
    ScalarConditionGap, ScalarConditionOutcome, ScalarConditionVerdict, scalar_condition_outcomes,
};
use super::*;
use crate::analyzer::semantic::ProcedureHandle;
use crate::analyzer::semantic::{ContentIdentity, StableDigest};
use crate::analyzer::usages::get_definition::{
    DefinitionLookupRequest, DefinitionLookupStatus,
    resolve_definition_batch_with_source_and_cancellation,
};
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_rql::{BranchRelationFilter, BranchRelationKind};

const MAX_BRANCH_SOURCE_BYTES: usize = 1024 * 1024;

#[derive(Default)]
pub(super) struct BranchRelationTraversalCache {
    syntax: HashMap<ProjectFile, StructuralSyntaxLimitedOutcome>,
    java_members: HashMap<ProjectFile, JavaMemberProofs>,
    scalar: HashMap<ProcedureHandle, Result<Vec<ScalarConditionOutcome>, ScalarConditionGap>>,
    reported: HashSet<(ProjectFile, &'static str, &'static str)>,
}

#[derive(Debug, Clone)]
pub(super) struct BranchRelationValue {
    pub(super) row: CodeQueryBranchRelation,
    pub(super) file: ProjectFile,
    pub(super) anchor: Range,
}

impl BranchRelationValue {
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

#[allow(clippy::too_many_arguments)]
fn make_value(
    seed: &SeedMatch,
    relation: &'static str,
    verdict: &'static str,
    reason: Option<&'static str>,
    earlier: Range,
    later: Range,
    earlier_ordinal: usize,
    later_ordinal: usize,
    orientation: Option<&'static str>,
) -> BranchRelationValue {
    let owner = seed.facts.node(seed.fact_match.node).range;
    let owner_id = crate::analyzer::structural::occurrence_rows::ast_id(
        seed.facts.source_identity(),
        seed.fact_match.node,
    );
    let id = format!(
        "branch_relation:{}:{owner_id}:{relation}:{earlier_ordinal}:{later_ordinal}",
        rel_path_string(&seed.file)
    );
    BranchRelationValue {
        row: CodeQueryBranchRelation {
            id,
            path: rel_path_string(&seed.file),
            language: seed.language.config_label(),
            range: public_range(&seed.facts, later),
            owner_id,
            owner_range: public_range(&seed.facts, owner),
            earlier_range: public_range(&seed.facts, earlier),
            later_range: public_range(&seed.facts, later),
            earlier_ordinal,
            later_ordinal,
            relation,
            verdict,
            reason,
            orientation,
        },
        file: seed.file.clone(),
        anchor: later,
    }
}

fn report(
    cache: &mut BranchRelationTraversalCache,
    seed: &SeedMatch,
    relation: &'static str,
    cause: &'static str,
    message: String,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) {
    if cache.reported.insert((seed.file.clone(), relation, cause)) {
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::BranchRelationDerivationIncomplete,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: seed.language.config_label(),
            message,
            exhausted_roots: Vec::new(),
        });
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn branch_relation_expansions(
    analyzer: &dyn IAnalyzer,
    workspace: Option<&WorkspaceAnalyzer>,
    semantic: &mut Option<SemanticQueryContext<'_>>,
    cache: &mut BranchRelationTraversalCache,
    environment_cache: &mut EnvironmentTraversalCache,
    seed: &Arc<SeedMatch>,
    filter: &BranchRelationFilter,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    if seed.facts.node(seed.fact_match.node).kind != NormalizedKind::If {
        return Vec::new();
    }
    let selected = if filter.relations.is_empty() {
        BranchRelationKind::ALL.to_vec()
    } else {
        filter.relations.clone()
    };
    // These languages answer the structural relations but have no scalar
    // condition producer.
    let pilot = matches!(
        seed.language,
        Language::Java
            | Language::JavaScript
            | Language::TypeScript
            | Language::Python
            | Language::Go
    );
    let structural_only = matches!(
        seed.language,
        Language::CSharp
            | Language::Kotlin
            | Language::Rust
            | Language::Scala
            | Language::Php
            | Language::Ruby
            | Language::Cpp
    );
    let (unsupported, selected): (Vec<_>, Vec<_>) = selected.into_iter().partition(|relation| {
        !pilot && !(structural_only && *relation != BranchRelationKind::ContradictoryCondition)
    });
    for relation in &unsupported {
        report(
            cache,
            seed,
            relation.label(),
            "unsupported_language",
            format!(
                "{} {} branch relations are not implemented for {}",
                seed.language.config_label(),
                relation.label(),
                rel_path_string(&seed.file)
            ),
            diagnostics,
        );
    }
    if selected.is_empty() {
        return Vec::new();
    }
    for relation in selected.iter().copied().filter(|relation| {
        !matches!(
            relation,
            BranchRelationKind::IdenticalBodies
                | BranchRelationKind::RepeatedCondition
                | BranchRelationKind::ContradictoryCondition
                | BranchRelationKind::RedundantBooleanReturn
        )
    }) {
        report(
            cache,
            seed,
            relation.label(),
            "unsupported_relation",
            format!(
                "{} has no complete {} branch-relation producer for {}",
                seed.language.config_label(),
                relation.label(),
                rel_path_string(&seed.file)
            ),
            diagnostics,
        );
    }
    let supported: Vec<_> = selected
        .into_iter()
        .filter(|relation| {
            matches!(
                relation,
                BranchRelationKind::IdenticalBodies
                    | BranchRelationKind::RepeatedCondition
                    | BranchRelationKind::ContradictoryCondition
                    | BranchRelationKind::RedundantBooleanReturn
            )
        })
        .collect();
    if supported.is_empty() {
        return Vec::new();
    }
    let owner = seed.facts.node(seed.fact_match.node).range;
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return open_selected(cache, seed, &supported, "cancelled", owner, diagnostics);
    }

    if !cache.syntax.contains_key(&seed.file) {
        let outcome = analyzer
            .structural_fact_providers()
            .into_iter()
            .find(|provider| provider.structural_language() == seed.language)
            .map_or(StructuralSyntaxLimitedOutcome::Unavailable, |provider| {
                provider.structural_syntax_limited(
                    &seed.file,
                    MAX_BRANCH_SOURCE_BYTES,
                    cancellation,
                )
            });
        cache.syntax.insert(seed.file.clone(), outcome);
    }
    let (syntax, failure) = match cache.syntax.get(&seed.file).expect("syntax was cached") {
        StructuralSyntaxLimitedOutcome::Available(syntax) => {
            let actual = ContentIdentity::from_digest(StableDigest::from_array(
                syntax.prepared().source_sha256(),
            ));
            if actual == seed.facts.source_identity() {
                (Some(syntax.clone_prepared()), None)
            } else {
                (None, Some("snapshot_mismatch"))
            }
        }
        StructuralSyntaxLimitedOutcome::Exceeded { .. } => (None, Some("source_limit")),
        StructuralSyntaxLimitedOutcome::Cancelled => (None, Some("cancelled")),
        StructuralSyntaxLimitedOutcome::Unavailable => (None, Some("syntax_unavailable")),
    };
    let Some(syntax) = syntax else {
        let reason = failure.expect("syntax failure has a reason");
        return open_selected(cache, seed, &supported, reason, owner, diagnostics);
    };
    let rows = if supported.iter().any(|relation| {
        matches!(
            relation,
            BranchRelationKind::IdenticalBodies
                | BranchRelationKind::RepeatedCondition
                | BranchRelationKind::RedundantBooleanReturn
        )
    }) {
        if seed.language == Language::Java
            && supported.contains(&BranchRelationKind::IdenticalBodies)
            && !cache.java_members.contains_key(&seed.file)
        {
            let members = resolve_java_members(analyzer, seed, &syntax, cancellation);
            cache.java_members.insert(seed.file.clone(), members);
        }
        let env = environment_cache.environment_for(analyzer, &seed.file);
        let empty = JavaMemberProofs::default();
        let members = cache.java_members.get(&seed.file).unwrap_or(&empty);
        branch_relations::relations_for_if(&syntax, seed.language, owner, &env, members)
    } else {
        Vec::new()
    };
    let mut expansions: Vec<_> = rows
        .into_iter()
        .filter(|row| filter.accepts(row.kind.label()))
        .map(|row| {
            let reason = match row.verdict {
                BranchRelationVerdict::Open(reason) => Some(reason.label()),
                _ => None,
            };
            if let Some(reason) = reason {
                report(
                    cache,
                    seed,
                    row.kind.label(),
                    reason,
                    format!(
                        "{} branch relations for {} are incomplete: {reason}",
                        row.kind.label(),
                        rel_path_string(&seed.file)
                    ),
                    diagnostics,
                );
            }
            pipeline_expansion(PipelineValue::BranchRelation(Box::new(make_value(
                seed,
                row.kind.label(),
                row.verdict.label(),
                reason,
                row.earlier,
                row.later,
                row.earlier_ordinal,
                row.later_ordinal,
                row.orientation,
            ))))
        })
        .collect();
    if supported.contains(&BranchRelationKind::ContradictoryCondition) {
        expansions.extend(scalar_condition_expansions(
            workspace.expect("scalar condition selection requires a semantic workspace"),
            semantic
                .as_mut()
                .expect("scalar condition selection requires semantic context"),
            cache,
            seed,
            &syntax,
            cancellation,
            diagnostics,
        ));
    }
    expansions
}

fn resolve_java_members(
    analyzer: &dyn IAnalyzer,
    seed: &SeedMatch,
    syntax: &PreparedSyntaxTree,
    cancellation: Option<&CancellationToken>,
) -> JavaMemberProofs {
    let mut proofs = JavaMemberProofs::default();
    let sites = match branch_relations::java_member_sites(syntax) {
        Ok(sites) => sites,
        Err(reason) => {
            proofs.collection_gap = Some(reason);
            return proofs;
        }
    };
    if sites.is_empty() {
        return proofs;
    }
    let requests = sites
        .iter()
        .map(|site| DefinitionLookupRequest {
            file: seed.file.clone(),
            line: None,
            column: None,
            start_byte: Some(site.range.0),
            end_byte: Some(site.range.1),
        })
        .collect();
    let idle_cancellation = CancellationToken::new();
    let outcomes = resolve_definition_batch_with_source_and_cancellation(
        analyzer,
        requests,
        seed.file.clone(),
        Arc::<str>::from(syntax.source()),
        cancellation.unwrap_or(&idle_cancellation),
    );
    assert_eq!(
        sites.len(),
        outcomes.len(),
        "definition batch must answer every requested Java member site"
    );
    for (site, outcome) in sites.into_iter().zip(outcomes) {
        let exact_focus = outcome.reference.as_ref().is_some_and(|reference| {
            (reference.focus_start_byte, reference.focus_end_byte) == site.range
        });
        let proof = if outcome.status == DefinitionLookupStatus::Resolved
            && exact_focus
            && outcome.definitions.len() == 1
            && match site.kind {
                JavaMemberKind::Field => outcome.definitions[0].is_field(),
                JavaMemberKind::Method => outcome.definitions[0].is_callable(),
            }
            && outcome.lexical_definition.is_none()
            && outcome.diagnostics.is_empty()
        {
            Ok(outcome.definitions[0].clone())
        } else if outcome.status == DefinitionLookupStatus::Ambiguous
            || outcome.definitions.len() > 1
        {
            Err(BranchOpenReason::AmbiguousMember)
        } else {
            Err(BranchOpenReason::MemberResolutionUnavailable)
        };
        proofs.sites.insert(site.range, proof);
    }
    proofs
}

fn scalar_condition_expansions(
    workspace: &WorkspaceAnalyzer,
    semantic: &mut SemanticQueryContext<'_>,
    cache: &mut BranchRelationTraversalCache,
    seed: &SeedMatch,
    syntax: &Arc<PreparedSyntaxTree>,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    const RELATION: &str = "contradictory_condition";
    let owner = seed.facts.node(seed.fact_match.node).range;
    let Some(node) = syntax
        .tree()
        .root_node()
        .named_descendant_for_byte_range(owner.start_byte, owner.end_byte)
        .filter(|node| {
            node.kind() == "if_statement"
                && node.start_byte() == owner.start_byte
                && node.end_byte() == owner.end_byte
        })
    else {
        return open_selected(
            cache,
            seed,
            &[BranchRelationKind::ContradictoryCondition],
            "syntax_recovery",
            owner,
            diagnostics,
        );
    };
    let Some(condition) = node.child_by_field_name("condition") else {
        return open_selected(
            cache,
            seed,
            &[BranchRelationKind::ContradictoryCondition],
            "missing_branch_field",
            owner,
            diagnostics,
        );
    };
    if node.has_error() || condition.has_error() {
        return open_selected(
            cache,
            seed,
            &[BranchRelationKind::ContradictoryCondition],
            "syntax_recovery",
            owner,
            diagnostics,
        );
    }
    let mut conditions = vec![condition];
    if seed.language == Language::Python {
        let mut cursor = node.walk();
        for alternative in node.children_by_field_name("alternative", &mut cursor) {
            match alternative.kind() {
                "elif_clause" => {
                    let Some(condition) = alternative.child_by_field_name("condition") else {
                        return open_selected(
                            cache,
                            seed,
                            &[BranchRelationKind::ContradictoryCondition],
                            "missing_branch_field",
                            owner,
                            diagnostics,
                        );
                    };
                    conditions.push(condition);
                }
                "else_clause" => {}
                _ => {
                    return open_selected(
                        cache,
                        seed,
                        &[BranchRelationKind::ContradictoryCondition],
                        "missing_branch_field",
                        owner,
                        diagnostics,
                    );
                }
            }
            if conditions.len() > 16 {
                return open_selected(
                    cache,
                    seed,
                    &[BranchRelationKind::ContradictoryCondition],
                    "comparison_budget",
                    owner,
                    diagnostics,
                );
            }
        }
    }
    let condition_range = brokk_bifrost_core::analyzer::tree_walk::node_range(condition);
    let procedures = semantic.cfg().procedure_of_match(seed);
    let [procedure] = procedures.as_slice() else {
        let reason = if procedures.is_empty() {
            "no_enclosing_procedure"
        } else {
            "ambiguous_procedure"
        };
        return open_selected(
            cache,
            seed,
            &[BranchRelationKind::ContradictoryCondition],
            reason,
            condition_range,
            diagnostics,
        );
    };
    let uncancelled = CancellationToken::new();
    let outcome = cache
        .scalar
        .entry(procedure.handle.clone())
        .or_insert_with(|| {
            scalar_condition_outcomes(
                workspace,
                &seed.file,
                &procedure.handle,
                Arc::clone(syntax),
                cancellation.unwrap_or(&uncancelled),
            )
        });
    let verdicts = conditions
        .into_iter()
        .enumerate()
        .map(|(ordinal, mut condition)| {
            let range = brokk_bifrost_core::analyzer::tree_walk::node_range(condition);
            while condition.kind() == "parenthesized_expression"
                && condition.named_child_count() == 1
            {
                condition = condition
                    .named_child(0)
                    .expect("one named expression child");
            }
            let verdict = match outcome {
                Err(gap) => Ok(ScalarConditionVerdict::Open(*gap)),
                Ok(outcomes) => {
                    let exact = |outcome: &&ScalarConditionOutcome| {
                        outcome.condition_start_byte == condition.start_byte()
                            && outcome.condition_end_byte == condition.end_byte()
                    };
                    // A Python comparison's guard carries its operator's span;
                    // a composed outcome over a chained comparison carries the
                    // whole condition's span and decides it.
                    let python_operator = |outcome: &&ScalarConditionOutcome| {
                        seed.language == Language::Python
                            && condition.kind() == "comparison_operator"
                            && outcome.condition_start_byte >= condition.start_byte()
                            && outcome.condition_end_byte <= condition.end_byte()
                    };
                    let matching: Box<dyn Iterator<Item = &ScalarConditionOutcome>> =
                        if outcomes.iter().any(|outcome| exact(&outcome)) {
                            Box::new(outcomes.iter().filter(exact))
                        } else {
                            Box::new(outcomes.iter().filter(python_operator))
                        };
                    // A condition in a `finally` block is lowered once per
                    // continuation, so each clone decides the same source
                    // condition. The condition is fixed only when every
                    // reachable clone agrees.
                    let matched = matching.map(|outcome| outcome.verdict).collect::<Vec<_>>();
                    match matched.as_slice() {
                        [] => Ok(ScalarConditionVerdict::Open(
                            ScalarConditionGap::UnsupportedPredicate,
                        )),
                        [verdict] => Ok(*verdict),
                        verdicts => {
                            let reachable = verdicts
                                .iter()
                                .copied()
                                .filter(|verdict| {
                                    *verdict
                                        != ScalarConditionVerdict::Open(
                                            ScalarConditionGap::UnreachableDecision,
                                        )
                                })
                                .collect::<Vec<_>>();
                            if let Some(open) = reachable
                                .iter()
                                .find(|verdict| matches!(verdict, ScalarConditionVerdict::Open(_)))
                            {
                                Ok(*open)
                            } else if reachable.is_empty() {
                                Ok(ScalarConditionVerdict::Open(
                                    ScalarConditionGap::UnreachableDecision,
                                ))
                            } else if reachable.iter().all(|verdict| *verdict == reachable[0]) {
                                Ok(reachable[0])
                            } else {
                                Ok(ScalarConditionVerdict::BothFeasible)
                            }
                        }
                    }
                }
            };
            (ordinal, range, verdict)
        })
        .collect::<Vec<_>>();
    verdicts
        .into_iter()
        .map(|(ordinal, range, verdict)| {
            let (verdict, reason, orientation) = match verdict {
                Ok(ScalarConditionVerdict::AlwaysFalse) => ("proven", None, Some("always_false")),
                Ok(ScalarConditionVerdict::AlwaysTrue) => ("proven", None, Some("always_true")),
                Ok(ScalarConditionVerdict::BothFeasible) => ("distinct", None, None),
                Ok(ScalarConditionVerdict::Open(gap)) => ("open", Some(gap.label()), None),
                Err(reason) => ("open", Some(reason), None),
            };
            if let Some(reason) = reason {
                report(
                    cache,
                    seed,
                    RELATION,
                    reason,
                    format!(
                        "{RELATION} branch relation for {} is incomplete: {reason}",
                        rel_path_string(&seed.file)
                    ),
                    diagnostics,
                );
            }
            pipeline_expansion(PipelineValue::BranchRelation(Box::new(make_value(
                seed,
                RELATION,
                verdict,
                reason,
                range,
                range,
                ordinal,
                ordinal,
                orientation,
            ))))
        })
        .collect()
}

fn open_selected(
    cache: &mut BranchRelationTraversalCache,
    seed: &SeedMatch,
    relations: &[BranchRelationKind],
    reason: &'static str,
    owner: Range,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    relations
        .iter()
        .copied()
        .map(|relation| {
            report(
                cache,
                seed,
                relation.label(),
                reason,
                format!(
                    "{} branch relations for {} are incomplete: {reason}",
                    relation.label(),
                    rel_path_string(&seed.file)
                ),
                diagnostics,
            );
            pipeline_expansion(PipelineValue::BranchRelation(Box::new(make_value(
                seed,
                relation.label(),
                "open",
                Some(reason),
                owner,
                owner,
                0,
                0,
                None,
            ))))
        })
        .collect()
}

pub(super) fn detailed_key(value: &BranchRelationValue) -> DetailedCodeQueryKey {
    DetailedCodeQueryKey::BranchRelation {
        id: value.row.id.clone(),
        owner_id: value.row.owner_id.clone(),
        relation: value.row.relation.to_owned(),
        verdict: value.row.verdict.to_owned(),
    }
}

pub(super) fn result_ref(value: &BranchRelationValue) -> CodeQueryResultRef {
    CodeQueryResultRef::BranchRelation {
        id: value.row.id.clone(),
        path: value.row.path.clone(),
        range: value.row.range,
        owner_id: value.row.owner_id.clone(),
        relation: value.row.relation,
        verdict: value.row.verdict,
    }
}
