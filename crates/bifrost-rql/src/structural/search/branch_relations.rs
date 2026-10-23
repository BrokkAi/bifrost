//! Query projection of branch relations over one exact source snapshot.

use super::super::branch_relations::{
    self, BranchOpenReason, BranchReferenceKind, BranchReferenceProofs, BranchReferenceSite,
    BranchRelationVerdict,
};
use super::super::provider::StructuralSyntaxLimitedOutcome;
use super::results::{
    CodeQueryBranchRelation, CodeQueryDiagnostic, CodeQueryDiagnosticCode,
    CodeQueryDiagnosticImpact, CodeQueryResultRef, DetailedCodeQueryKey,
};
use super::scalar_conditions::{
    ScalarConditionDerivation, ScalarConditionGap, ScalarConditionOutcome, ScalarConditionVerdict,
    scalar_condition_outcomes,
};
use super::*;
use crate::analyzer::semantic::ProcedureHandle;
use crate::analyzer::semantic::{ContentIdentity, StableDigest};
use crate::analyzer::usages::get_definition::{
    DefinitionLookupOutcome, DefinitionLookupRequest, DefinitionLookupStatus,
    resolve_definition_batch_with_source_and_cancellation,
};
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_rql::{BranchRelationFilter, BranchRelationKind};
use tree_sitter::Node;

const MAX_BRANCH_SOURCE_BYTES: usize = 1024 * 1024;

#[derive(Default)]
pub(super) struct BranchRelationTraversalCache {
    syntax: HashMap<ProjectFile, StructuralSyntaxLimitedOutcome>,
    reference_proofs: HashMap<ProjectFile, BranchReferenceProofs>,
    scalar: HashMap<ProcedureHandle, Result<ScalarConditionDerivation, ScalarConditionGap>>,
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

/// Whether one branch-relation kind has a producer for this language.
///
/// The preflight uses the same table as row expansion. A relation omitted by
/// this table is an explicit unsupported capability, not an empty supported
/// relation.
pub(super) fn supports_relation(language: Language, relation: BranchRelationKind) -> bool {
    let pilot = matches!(
        language,
        Language::Java
            | Language::JavaScript
            | Language::TypeScript
            | Language::Python
            | Language::Go
            | Language::CSharp
            | Language::Rust
            | Language::Scala
    );
    let structural_only = matches!(
        language,
        Language::Kotlin | Language::Php | Language::Ruby | Language::Cpp
    );
    let scalar_producer = matches!(
        language,
        Language::Kotlin | Language::Php | Language::Ruby | Language::Cpp
    );
    let empty_arm_supported = matches!(language, Language::CSharp | Language::Cpp);
    match relation {
        BranchRelationKind::IdenticalBodies
        | BranchRelationKind::RepeatedCondition
        | BranchRelationKind::RedundantBooleanReturn => pilot || structural_only,
        BranchRelationKind::ContradictoryCondition => pilot || (structural_only && scalar_producer),
        BranchRelationKind::SubsumedCondition => false,
        BranchRelationKind::EmptyArm => empty_arm_supported,
    }
}

/// The relation kinds selected by the branch step's filter semantics.
pub(super) fn requested_relations(
    language: Language,
    filter: &BranchRelationFilter,
) -> Vec<BranchRelationKind> {
    if filter.relations.is_empty() {
        BranchRelationKind::ALL
            .iter()
            .copied()
            .filter(|relation| {
                *relation != BranchRelationKind::EmptyArm
                    || supports_relation(language, BranchRelationKind::EmptyArm)
            })
            .collect()
    } else {
        filter.relations.clone()
    }
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
            range: super::render::public_range(&seed.facts, later),
            owner_id,
            owner_range: super::render::public_range(&seed.facts, owner),
            earlier_range: super::render::public_range(&seed.facts, earlier),
            later_range: super::render::public_range(&seed.facts, later),
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
            related: Vec::new(),
            source: None,
            code: CodeQueryDiagnosticCode::BranchRelationDerivationIncomplete,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: seed.language.config_label(),
            message,
            exhausted_roots: Vec::new(),
            // A branch relation row is a row of its seed's file.
            withheld_rows_path: Some(rel_path_string(&seed.file)),
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
    let selected = requested_relations(seed.language, filter);
    let (unsupported, selected): (Vec<_>, Vec<_>) = selected
        .into_iter()
        .partition(|relation| !supports_relation(seed.language, *relation));
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
                | BranchRelationKind::EmptyArm
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
                    | BranchRelationKind::EmptyArm
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
    let mut rows = if supported.iter().any(|relation| {
        matches!(
            relation,
            BranchRelationKind::IdenticalBodies
                | BranchRelationKind::RepeatedCondition
                | BranchRelationKind::RedundantBooleanReturn
                | BranchRelationKind::EmptyArm
        )
    }) {
        let env = environment_cache.environment_for(analyzer, &seed.file);
        if matches!(seed.language, Language::Java | Language::Rust)
            && supported.contains(&BranchRelationKind::IdenticalBodies)
            && !cache.reference_proofs.contains_key(&seed.file)
        {
            let proofs = resolve_branch_references(analyzer, seed, &syntax, &env, cancellation);
            cache.reference_proofs.insert(seed.file.clone(), proofs);
        }
        let empty = BranchReferenceProofs::default();
        let members = cache.reference_proofs.get(&seed.file).unwrap_or(&empty);
        branch_relations::relations_for_if(&syntax, seed.language, owner, &env, members)
    } else {
        Vec::new()
    };
    if seed.language == Language::Php && supported.contains(&BranchRelationKind::RepeatedCondition)
    {
        qualify_php_repeated_conditions(
            workspace,
            semantic,
            cache,
            seed,
            &syntax,
            cancellation,
            &mut rows,
        );
    }
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

/// Structural comparison can establish that two PHP conditions have the same
/// spelling, but PHP's dynamic values still need the scalar proof used by A5.
/// Qualify only repeated-condition rows: a distinct condition is already a
/// complete near miss, while an equal condition with an unknown value must
/// keep the policy result open.
#[allow(clippy::too_many_arguments)]
fn qualify_php_repeated_conditions(
    workspace: Option<&WorkspaceAnalyzer>,
    semantic: &mut Option<SemanticQueryContext<'_>>,
    cache: &mut BranchRelationTraversalCache,
    seed: &SeedMatch,
    syntax: &Arc<PreparedSyntaxTree>,
    cancellation: Option<&CancellationToken>,
    rows: &mut [branch_relations::BranchRelationRow],
) {
    let Some(workspace) = workspace else {
        open_php_repeated_rows(rows);
        return;
    };
    let Some(semantic) = semantic.as_mut() else {
        open_php_repeated_rows(rows);
        return;
    };
    let procedures = semantic.cfg().procedure_of_match(seed);
    let [procedure] = procedures.as_slice() else {
        open_php_repeated_rows(rows);
        return;
    };
    let uncancelled = CancellationToken::new();
    let outcomes = scalar_outcomes_for_procedure(
        workspace,
        cache,
        &seed.file,
        procedure,
        syntax,
        cancellation.unwrap_or(&uncancelled),
    );
    for row in rows.iter_mut().filter(|row| {
        row.kind == branch_relations::BranchRelationKind::RepeatedCondition
            && row.verdict == BranchRelationVerdict::Proven
    }) {
        let stable = match &outcomes {
            Ok(outcomes) => php_chain_condition_ranges(syntax, row.owner).is_some_and(|chain| {
                chain
                    .get(row.earlier_ordinal..=row.later_ordinal)
                    .is_some_and(|conditions| {
                        conditions.iter().all(|range| {
                            php_condition_has_stable_outcome(syntax, *range, &outcomes.outcomes)
                        })
                    })
            }),
            Err(_) => false,
        };
        if !stable {
            row.verdict = BranchRelationVerdict::Open(BranchOpenReason::UnsupportedCondition);
        }
    }
}

fn open_php_repeated_rows(rows: &mut [branch_relations::BranchRelationRow]) {
    for row in rows.iter_mut().filter(|row| {
        row.kind == branch_relations::BranchRelationKind::RepeatedCondition
            && row.verdict == BranchRelationVerdict::Proven
    }) {
        row.verdict = BranchRelationVerdict::Open(BranchOpenReason::LexicalBindingUnavailable);
    }
}

fn scalar_outcomes_for_procedure(
    workspace: &WorkspaceAnalyzer,
    cache: &mut BranchRelationTraversalCache,
    file: &ProjectFile,
    procedure: &SemanticProcedureValue,
    syntax: &Arc<PreparedSyntaxTree>,
    cancellation: &CancellationToken,
) -> Result<ScalarConditionDerivation, ScalarConditionGap> {
    if let Some(outcomes) = cache.scalar.get(&procedure.handle) {
        return outcomes.clone();
    }
    let outcomes = scalar_condition_outcomes(
        workspace,
        file,
        &procedure.handle,
        Arc::clone(syntax),
        cancellation,
    );
    cache
        .scalar
        .insert(procedure.handle.clone(), outcomes.clone());
    outcomes
}

fn php_condition_has_stable_outcome(
    syntax: &PreparedSyntaxTree,
    range: (usize, usize),
    outcomes: &[ScalarConditionOutcome],
) -> bool {
    let Some(mut condition) = syntax
        .tree()
        .root_node()
        .named_descendant_for_byte_range(range.0, range.1)
        .filter(|node| node.start_byte() == range.0 && node.end_byte() == range.1)
    else {
        return false;
    };
    let mut ranges = vec![(condition.start_byte(), condition.end_byte())];
    while condition.kind() == "parenthesized_expression" && condition.named_child_count() == 1 {
        condition = condition.named_child(0).expect("one named condition child");
        ranges.push((condition.start_byte(), condition.end_byte()));
    }
    let matching = outcomes.iter().filter(|outcome| {
        ranges.iter().any(|(start, end)| {
            (*start <= outcome.condition_start_byte && outcome.condition_end_byte <= *end)
                || (outcome.condition_start_byte <= *start && *end <= outcome.condition_end_byte)
        })
    });
    let matching = matching.map(|outcome| outcome.verdict).collect::<Vec<_>>();
    !matching.is_empty()
        && matching.iter().all(|verdict| {
            matches!(
                verdict,
                ScalarConditionVerdict::AlwaysFalse
                    | ScalarConditionVerdict::AlwaysTrue
                    | ScalarConditionVerdict::BothFeasible
                    | ScalarConditionVerdict::Open(ScalarConditionGap::UnreachableDecision)
            ) || (php_strict_null_identity_condition(condition)
                && matches!(
                    verdict,
                    ScalarConditionVerdict::Open(ScalarConditionGap::UnknownScalar)
                ))
        })
}

/// Strict identity against `null` has no coercion or user dispatch. An exact
/// local or parameter can therefore be compared repeatedly even when its
/// incoming value is unknown; the structural relation has already proved
/// that no intervening write or call changes that binding.
fn php_strict_null_identity_condition(mut condition: Node<'_>) -> bool {
    loop {
        match condition.kind() {
            "parenthesized_expression" if condition.named_child_count() == 1 => {
                condition = condition.named_child(0).expect("one named condition child");
            }
            "unary_op_expression"
                if condition
                    .child_by_field_name("operator")
                    .is_some_and(|operator| operator.kind() == "!") =>
            {
                let Some(operand) = condition.child_by_field_name("argument") else {
                    return false;
                };
                condition = operand;
            }
            _ => break,
        }
    }
    if condition.kind() != "binary_expression"
        || !condition
            .child_by_field_name("operator")
            .is_some_and(|operator| matches!(operator.kind(), "===" | "!=="))
    {
        return false;
    }
    let (Some(left), Some(right)) = (
        condition.child_by_field_name("left"),
        condition.child_by_field_name("right"),
    ) else {
        return false;
    };
    let left = peel_php_condition_parentheses(left);
    let right = peel_php_condition_parentheses(right);
    (left.kind() == "null" && right.kind() == "variable_name")
        || (right.kind() == "null" && left.kind() == "variable_name")
}

fn peel_php_condition_parentheses(mut node: Node<'_>) -> Node<'_> {
    while node.kind() == "parenthesized_expression" && node.named_child_count() == 1 {
        node = node.named_child(0).expect("one named expression child");
    }
    node
}

fn php_chain_condition_ranges(
    syntax: &PreparedSyntaxTree,
    owner: Range,
) -> Option<Vec<(usize, usize)>> {
    let mut current = syntax
        .tree()
        .root_node()
        .named_descendant_for_byte_range(owner.start_byte, owner.end_byte)
        .filter(|node| {
            node.kind() == "if_statement"
                && node.start_byte() == owner.start_byte
                && node.end_byte() == owner.end_byte
        })?;
    let mut ranges = Vec::new();
    loop {
        let condition = current.child_by_field_name("condition")?;
        ranges.push((condition.start_byte(), condition.end_byte()));
        let mut next = None;
        let mut cursor = current.walk();
        for alternative in current.children_by_field_name("alternative", &mut cursor) {
            match alternative.kind() {
                "else_if_clause" => {
                    let condition = alternative.child_by_field_name("condition")?;
                    ranges.push((condition.start_byte(), condition.end_byte()));
                }
                "else_clause"
                    if alternative
                        .child_by_field_name("body")
                        .is_some_and(|body| body.kind() == "if_statement") =>
                {
                    next = alternative.child_by_field_name("body");
                }
                "else_clause" => {}
                _ => return None,
            }
        }
        if ranges.len() > 16 {
            return None;
        }
        match next {
            Some(next) => current = next,
            None => return Some(ranges),
        }
    }
}

fn resolve_branch_references(
    analyzer: &dyn IAnalyzer,
    seed: &SeedMatch,
    syntax: &PreparedSyntaxTree,
    env: &super::super::lexical_environment::EnvironmentFileResult,
    cancellation: Option<&CancellationToken>,
) -> BranchReferenceProofs {
    let mut proofs = BranchReferenceProofs::default();
    let sites = match branch_relations::reference_sites(syntax, seed.language, &seed.facts, env) {
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
        "definition batch must answer every requested branch reference site"
    );
    for (site, outcome) in sites.into_iter().zip(outcomes) {
        proofs
            .sites
            .insert(site.range, admit_reference_proof(site, &outcome));
    }
    proofs
}

fn admit_reference_proof(
    site: BranchReferenceSite,
    outcome: &DefinitionLookupOutcome,
) -> Result<CodeUnit, BranchOpenReason> {
    let exact_focus = outcome.reference.as_ref().is_some_and(|reference| {
        (reference.focus_start_byte, reference.focus_end_byte) == site.range
    });
    if outcome.status == DefinitionLookupStatus::Resolved
        && exact_focus
        && outcome.definitions.len() == 1
        && match site.kind {
            BranchReferenceKind::Field => outcome.definitions[0].is_field(),
            BranchReferenceKind::Method => outcome.definitions[0].is_callable(),
        }
        && outcome.lexical_definition.is_none()
        && outcome.diagnostics.is_empty()
    {
        Ok(outcome.definitions[0].clone())
    } else if outcome.status == DefinitionLookupStatus::Ambiguous || outcome.definitions.len() > 1 {
        Err(BranchOpenReason::AmbiguousMember)
    } else {
        Err(BranchOpenReason::MemberResolutionUnavailable)
    }
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
            matches!(
                node.kind(),
                "if_statement"
                    | "if_expression"
                    | "if"
                    | "unless"
                    | "if_modifier"
                    | "unless_modifier"
                    | "conditional"
            ) && node.start_byte() == owner.start_byte
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
                Ok(derivation) => {
                    let outcomes = &derivation.outcomes;
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
    let related = match outcome {
        Ok(derivation) => Some((&derivation.procedure_gaps, &derivation.producer_gaps)),
        Err(_) => None,
    };
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
                let source = procedure.diagnostic_source();
                let message = format!(
                    "{RELATION} branch relation for {} is incomplete: {reason}",
                    rel_path_string(&seed.file)
                );
                if !diagnostics.iter().any(|diagnostic| {
                    diagnostic.code == CodeQueryDiagnosticCode::BranchRelationDerivationIncomplete
                        && diagnostic.source == source
                        && diagnostic.message == message
                }) {
                    let mut diagnostic = super::incomplete_diagnostic(
                        CodeQueryDiagnosticCode::BranchRelationDerivationIncomplete,
                        seed.language.config_label(),
                        message,
                        Vec::new(),
                    );
                    diagnostic.source = source;
                    diagnostic.related = match (reason, related) {
                        ("partial_procedure", Some((gaps, _)))
                        | ("partial_producer", Some((_, gaps))) => gaps.clone(),
                        _ => Vec::new(),
                    };
                    diagnostic.withheld_rows_path = Some(rel_path_string(&seed.file));
                    diagnostics.push(diagnostic);
                }
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
