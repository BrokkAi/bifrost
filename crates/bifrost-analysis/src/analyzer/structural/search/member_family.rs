//! Pipeline execution for the `member_family` and `family_edges` steps
//! (issue #1477 Milestone 4).
//!
//! Both steps project [`crate::analyzer::usages::MemberFamilyProvider`]. No
//! override relation is re-derived here: the provider owns the hierarchy walk
//! and the overload-identity rule, and this module only turns its answer into
//! rows.
//!
//! `member_family` is mandatory per member input. A member whose language has
//! no family, whose modifiers were never recorded, or whose overload identity
//! the analyzer cannot prove still emits exactly one row stating that, so zero
//! edge rows can never be read as a proven-empty family. `family_edges` emits
//! the forward edges (`overrides`, `implements`) and the bounded inversion of
//! the same relation (`overridden_by`, `implemented_by`) for the same member,
//! and only ever from a proven answer.

use super::*;

use crate::analyzer::usages::{MemberFamilyAnswer, member_family_id};
use brokk_bifrost_core::analyzer::structural::resolution::{
    MemberFamilyOutcome, MethodFamilyRelation,
};

/// Domain separator for one member-family outcome row's stable id.
const MEMBER_FAMILY_ROW_ID_DOMAIN: &[u8] = b"bifrost.code_query.member_family.v1";
/// Domain separator for one family-edge row's stable id.
const MEMBER_FAMILY_EDGE_ID_DOMAIN: &[u8] = b"bifrost.code_query.member_family_edge.v1";

/// One member's whole family answer, shared by its outcome row and each of its
/// edge rows so every row of one member states one family id -- the digest of
/// that member's own proven root closure.
#[derive(Debug, Clone)]
pub(super) struct MemberFamilyValue {
    pub(super) member: DeclarationValue,
    /// The digest of the member's structured canonical identity, minted by the
    /// same recipe candidate rows use for `canonical_member_id`.
    pub(super) member_id: String,
    pub(super) family_id: Option<String>,
    pub(super) answer: Arc<MemberFamilyAnswer>,
    /// Forward edges followed by inverse edges, each already ordered by target
    /// identity, so a row's ordinal is deterministic.
    pub(super) edges: Arc<Vec<MemberFamilyRowEdge>>,
}

impl MemberFamilyValue {
    pub(super) fn file(&self) -> &ProjectFile {
        self.member.unit.source()
    }

    pub(super) fn id(&self) -> String {
        let mut digest = LengthDelimitedDigest::new(MEMBER_FAMILY_ROW_ID_DOMAIN);
        digest.push(self.member_id.as_bytes());
        digest.finish().to_string()
    }
}

/// One family edge, already reduced to the row vocabulary.
#[derive(Debug, Clone)]
pub(super) struct MemberFamilyRowEdge {
    pub(super) target: CodeUnit,
    pub(super) target_id: String,
    pub(super) relation: MethodFamilyRelation,
    pub(super) depth: usize,
    /// `proven` when the ancestor's candidate set held exactly one member of
    /// that name and recorded arity, so structure alone singled the target
    /// out. `unproven` when only the recorded parameter-type *spellings*
    /// separated an overload set: a spelling is not a resolved or erased type,
    /// so the pairing is the analyzer's best structured answer rather than a
    /// proof.
    pub(super) proof: &'static str,
}

/// One retained edge row of one member.
#[derive(Debug, Clone)]
pub(super) struct MemberFamilyEdgeValue {
    pub(super) family: MemberFamilyValue,
    pub(super) ordinal: usize,
}

impl MemberFamilyEdgeValue {
    pub(super) fn file(&self) -> &ProjectFile {
        self.family.file()
    }

    pub(super) fn edge(&self) -> &MemberFamilyRowEdge {
        &self.family.edges[self.ordinal]
    }

    pub(super) fn id(&self) -> String {
        let mut digest = LengthDelimitedDigest::new(MEMBER_FAMILY_EDGE_ID_DOMAIN);
        digest.push(self.family.member_id.as_bytes());
        digest.push(self.edge().relation.label().as_bytes());
        digest.push(self.edge().target_id.as_bytes());
        digest.finish().to_string()
    }
}

/// Derive the family answer for one member declaration and project the
/// requested rows.
///
/// The provider answers both directions from one walk. The inversion is not an
/// independent resolution: it reads the forward edges of the members below this
/// one and turns them around, so the two directions of one edge cannot
/// disagree. Asking once is also what caps the work: the forward relation is
/// resolved a single time, and the ancestor walk, the root closure, and the
/// inversion share one visit budget and the request's cancellation token.
pub(super) fn member_family_expansions_for_declaration(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    cancellation: Option<&CancellationToken>,
    edges: bool,
) -> Vec<PipelineExpansion> {
    let member_id = render::canonical_member_digest(analyzer, &declaration.unit);
    let Some(provider) = analyzer.member_family_provider() else {
        return finish(
            analyzer,
            declaration,
            member_id,
            MemberFamilyAnswer::unsupported_answer(),
            Vec::new(),
            edges,
        );
    };
    let answer = provider.member_family(&declaration.unit, cancellation);
    if !answer.is_proven() {
        return finish(analyzer, declaration, member_id, answer, Vec::new(), edges);
    }
    let row_edges = answer
        .edges
        .iter()
        .map(|edge| MemberFamilyRowEdge {
            target_id: render::canonical_member_digest(analyzer, &edge.target),
            target: edge.target.clone(),
            relation: edge.relation,
            depth: edge.depth,
            proof: if edge.arity_unique {
                "proven"
            } else {
                "unproven"
            },
        })
        .collect();
    finish(analyzer, declaration, member_id, answer, row_edges, edges)
}

fn finish(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    member_id: String,
    answer: MemberFamilyAnswer,
    row_edges: Vec<MemberFamilyRowEdge>,
    edges: bool,
) -> Vec<PipelineExpansion> {
    let family_id = member_family_id(analyzer, &answer);
    let value = MemberFamilyValue {
        member: declaration.clone(),
        member_id,
        family_id,
        answer: Arc::new(answer),
        edges: Arc::new(row_edges),
    };
    if !edges {
        return vec![pipeline_expansion(PipelineValue::MemberFamily(Box::new(
            value,
        )))];
    }
    (0..value.edges.len())
        .map(|ordinal| {
            pipeline_expansion(PipelineValue::MemberFamilyEdge(Box::new(
                MemberFamilyEdgeValue {
                    family: value.clone(),
                    ordinal,
                },
            )))
        })
        .collect()
}

/// The coverage a family answer justifies.
///
/// `exhaustive` only for the two complete answers: a proven family whose edges
/// were all enumerated, and a proven exclusion whose empty edge set is the
/// whole truth. Everything else is `open`, so an exact-set assertion over an
/// unsupported or unproven member can never come out clean.
pub(super) fn family_coverage(outcome: MemberFamilyOutcome) -> &'static str {
    match outcome {
        MemberFamilyOutcome::Proven | MemberFamilyOutcome::NoFamily => "exhaustive",
        MemberFamilyOutcome::Incomplete | MemberFamilyOutcome::Unsupported => "open",
    }
}
