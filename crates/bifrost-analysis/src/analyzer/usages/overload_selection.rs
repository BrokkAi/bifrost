//! Per-candidate applicability rows and the per-site selection summary
//! (issue #1478, Milestone 3).
//!
//! Milestone 1 gave a call site its ordered shape and Milestone 2 gave each
//! candidate callable its declared signature. This module joins the two through
//! the answer the production resolver already computed: for this exact call
//! site, which candidates did the language's own applicability check accept,
//! which did it refuse and for which typed reason, and what does that make the
//! site's selection outcome.
//!
//! Nothing here decides applicability. The verdicts arrive on the resolution
//! trace, recorded by the same function that produced the resolver's winners
//! (see [`crate::analyzer::usages::applicability`]), so a row can never claim a
//! verdict the binding did not use. This module is a pure projection of that
//! trace.
//!
//! Two contract rules from the issue are enforced here rather than left to a
//! caller.
//!
//! - Candidate order is never a tie breaker. The selection summary is computed
//!   from verdict *counts*: zero applicable candidates stay `unresolved`, and
//!   several equally applicable candidates stay `ambiguous` with every row
//!   retained. Reordering the candidate vector cannot change the summary.
//! - An undecidable site says so. A language whose resolver does not report the
//!   callable axis, a site with no trace at all, or a site where any considered
//!   candidate's verdict is `unknown` yields `unknown_shape` -- never a
//!   confident `unresolved` that a policy would read as a proven-empty overload
//!   set.
//!
//! The site's *shape* coverage is deliberately not duplicated here. It is the
//! `call_shape` row's field, joined on the same `site_ast_id`; deriving it a
//! second time in this module would be a second derivation that could drift
//! from the first.
//!
//! Not represented yet: generic substitutions. No language resolver records a
//! structured substitution map at its applicability check today, so publishing
//! a substitutions field would publish an empty list that reads as "no
//! substitutions were needed". That is a resolver-side addition, not a
//! derivation, and it is stated as a gap rather than approximated.

use crate::analyzer::semantic::LengthDelimitedDigest;
use crate::analyzer::structural::resolution::{EnvironmentAxis, PrecedenceTier};
use crate::analyzer::usages::get_definition::trace::{ResolutionTraceResult, TraceCandidateRef};
use crate::analyzer::{CodeUnit, Language};
use brokk_bifrost_core::analyzer::structural::callable::{
    ApplicabilityVerdict, CallableRejectionReason, SelectionResolution,
};

const APPLICABILITY_ROW_ID_DOMAIN: &[u8] = b"bifrost.code_query.callable_applicability.v1";
const OVERLOAD_SELECTION_ID_DOMAIN: &[u8] = b"bifrost.code_query.overload_selection.v1";

/// Whether `language`'s resolver reports the callable-applicability axis.
///
/// There is no default `supported`: the axis is declared per structural adapter
/// and every adapter starts unsupported, so a language reaches this milestone's
/// rows only by opting in when its own applicability check has been factored to
/// emit verdicts.
pub fn supports_callable_applicability(language: Language) -> bool {
    crate::analyzer::structural_spec_for(language).is_some_and(|spec| {
        spec.lexical_environment_support()
            .is_supported(EnvironmentAxis::CallableApplicability)
    })
}

/// One considered candidate's applicability to one call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicabilityRow {
    pub id: String,
    /// The facts-arena AST identity of the call site, shared with the
    /// `call_shape` row so the two join without a second derivation.
    pub site_ast_id: String,
    /// Position of this candidate in the resolver's own consideration order.
    /// Present so two rows are distinguishable, never as a precedence signal:
    /// the selection summary ignores it.
    pub ordinal: usize,
    /// The candidate declaration, when the trace names an indexed workspace
    /// declaration. A lexical binder, an import route, or an external route is
    /// a candidate the resolver considered but not a callable declaration, and
    /// carries none.
    pub candidate: Option<CodeUnit>,
    pub verdict: ApplicabilityVerdict,
    /// Set only when `verdict` is `inapplicable`.
    pub reason: Option<CallableRejectionReason>,
    /// The precedence tier the resolver considered the candidate at, when the
    /// seam that recorded it could name one. `None` is unattributed, never
    /// weakest.
    pub tier: Option<PrecedenceTier>,
    /// Whether the resolver bound this candidate. A row can be `applicable` and
    /// unselected (a peer in an ambiguous set, or a candidate a stronger tier
    /// outranked), which is exactly the evidence a wrong-overload policy needs.
    pub selected: bool,
}

/// The mandatory per-site summary of overload selection.
///
/// Exactly one row per input site, always. A site whose language does not
/// report the axis, or whose trace is absent, is `unknown_shape` with zero
/// counts rather than an absent row, so an empty relation can never be read as
/// a proven-empty candidate set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverloadSelectionRow {
    pub id: String,
    pub site_ast_id: String,
    pub resolution: SelectionResolution,
    /// Whether the language's resolver reports the callable axis at all.
    pub supported: bool,
    /// How many candidates the resolver considered at this site.
    pub considered: usize,
    pub applicable: usize,
    pub inapplicable: usize,
    /// Candidates whose applicability nobody could decide. Any non-zero count
    /// forces `unknown_shape`.
    pub unknown: usize,
}

/// One site's complete applicability evidence: the mandatory summary plus one
/// row per considered candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverloadSelectionReport {
    pub selection: OverloadSelectionRow,
    pub applicability: Vec<ApplicabilityRow>,
}

/// Project one site's resolution trace into applicability rows and a summary.
///
/// `trace` is `None` when the language produced no candidate trace for the
/// site; `supported` is [`supports_callable_applicability`] for the site's
/// language. Both absences reach the same honest answer rather than a
/// confident one.
pub fn overload_selection_report(
    site_ast_id: &str,
    supported: bool,
    trace: Option<&ResolutionTraceResult>,
) -> OverloadSelectionReport {
    let applicability: Vec<ApplicabilityRow> = trace
        .map(|trace| trace.candidates.as_slice())
        .unwrap_or_default()
        .iter()
        .enumerate()
        .map(|(ordinal, candidate)| {
            let record = candidate.callable;
            ApplicabilityRow {
                id: applicability_row_id(site_ast_id, ordinal),
                site_ast_id: site_ast_id.to_owned(),
                ordinal,
                candidate: match &candidate.candidate {
                    TraceCandidateRef::Unit(unit) => Some(unit.clone()),
                    _ => None,
                },
                verdict: record
                    .map(|record| record.verdict)
                    .unwrap_or(ApplicabilityVerdict::Unknown),
                reason: record.and_then(|record| record.reason),
                tier: candidate.tier,
                selected: candidate.is_selected(),
            }
        })
        .collect();

    let applicable = count_of(&applicability, ApplicabilityVerdict::Applicable);
    let inapplicable = count_of(&applicability, ApplicabilityVerdict::Inapplicable);
    let unknown = count_of(&applicability, ApplicabilityVerdict::Unknown);
    OverloadSelectionReport {
        selection: OverloadSelectionRow {
            id: selection_row_id(site_ast_id),
            site_ast_id: site_ast_id.to_owned(),
            resolution: resolution_of(
                supported,
                trace.is_some(),
                applicability.len(),
                applicable,
                unknown,
            ),
            supported,
            considered: applicability.len(),
            applicable,
            inapplicable,
            unknown,
        },
        applicability,
    }
}

fn count_of(rows: &[ApplicabilityRow], verdict: ApplicabilityVerdict) -> usize {
    rows.iter().filter(|row| row.verdict == verdict).count()
}

/// The site's selection outcome, from verdict counts alone.
///
/// Order-independent by construction: the inputs are counts, so no permutation
/// of the candidate vector can change the answer.
fn resolution_of(
    supported: bool,
    traced: bool,
    considered: usize,
    applicable: usize,
    unknown: usize,
) -> SelectionResolution {
    // Zero considered candidates is not zero *applicable* candidates. A site
    // whose resolver enumerated nothing -- a call that left the workspace, a
    // seam that recorded no candidate -- has proved nothing about an overload
    // set, and calling that `unresolved` would let a policy read "the resolver
    // rejected every overload" out of "the resolver never looked".
    if !supported || !traced || considered == 0 || unknown > 0 {
        return SelectionResolution::UnknownShape;
    }
    match applicable {
        0 => SelectionResolution::Unresolved,
        1 => SelectionResolution::ResolvedUnique,
        _ => SelectionResolution::Ambiguous,
    }
}

fn applicability_row_id(site_ast_id: &str, ordinal: usize) -> String {
    let mut digest = LengthDelimitedDigest::new(APPLICABILITY_ROW_ID_DOMAIN);
    digest.push(site_ast_id.as_bytes());
    digest.push(&ordinal.to_le_bytes());
    digest.finish().to_string()
}

fn selection_row_id(site_ast_id: &str) -> String {
    let mut digest = LengthDelimitedDigest::new(OVERLOAD_SELECTION_ID_DOMAIN);
    digest.push(site_ast_id.as_bytes());
    digest.finish().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::structural::resolution::RejectionReason;
    use crate::analyzer::usages::get_definition::trace::{
        CallableApplicabilityRecord, TraceCandidate, TraceCompleteness,
    };
    use brokk_bifrost_core::analyzer::model::{CodeUnitType, ProjectFile};

    fn unit(name: &str) -> CodeUnit {
        let file = ProjectFile::new(std::env::temp_dir(), "Main.java");
        CodeUnit::new(
            file,
            CodeUnitType::Function,
            "app",
            format!("Widget.{name}"),
        )
    }

    fn record(
        verdict: ApplicabilityVerdict,
        reason: Option<CallableRejectionReason>,
    ) -> CallableApplicabilityRecord {
        CallableApplicabilityRecord { verdict, reason }
    }

    fn selected(name: &str, verdict: ApplicabilityVerdict) -> TraceCandidate {
        TraceCandidate::selected(
            TraceCandidateRef::Unit(unit(name)),
            Some(PrecedenceTier::OwnMember),
        )
        .with_callable(record(verdict, None))
    }

    fn rejected(name: &str, reason: CallableRejectionReason) -> TraceCandidate {
        TraceCandidate::rejected(
            TraceCandidateRef::Unit(unit(name)),
            Some(PrecedenceTier::OwnMember),
            RejectionReason::CallableApplicabilityDeferred,
        )
        .with_callable(record(ApplicabilityVerdict::Inapplicable, Some(reason)))
    }

    fn trace(candidates: Vec<TraceCandidate>) -> ResolutionTraceResult {
        ResolutionTraceResult {
            candidates,
            completeness: TraceCompleteness::Full,
        }
    }

    /// The selected overload is applicable and every refused overload stays
    /// visible with the exact reason it lost.
    #[test]
    fn one_winner_beside_refused_overloads_resolves_uniquely() {
        let traced = trace(vec![
            selected("render", ApplicabilityVerdict::Applicable),
            rejected("render", CallableRejectionReason::ArityBelowRequired),
            rejected("render", CallableRejectionReason::ArityAboveTotal),
        ]);
        let report = overload_selection_report("site", true, Some(&traced));
        assert_eq!(
            report.selection.resolution,
            SelectionResolution::ResolvedUnique
        );
        assert_eq!(report.selection.considered, 3);
        assert_eq!(report.selection.applicable, 1);
        assert_eq!(report.selection.inapplicable, 2);
        assert!(report.applicability[0].selected);
        assert_eq!(
            report.applicability[1].reason,
            Some(CallableRejectionReason::ArityBelowRequired)
        );
        assert_eq!(
            report.applicability[2].reason,
            Some(CallableRejectionReason::ArityAboveTotal)
        );
    }

    /// Two equally applicable winners stay ambiguous with both rows retained,
    /// and no permutation of the candidate vector changes that.
    #[test]
    fn two_equal_winners_stay_ambiguous_in_any_order() {
        let first = selected("render", ApplicabilityVerdict::Applicable);
        let second = selected("draw", ApplicabilityVerdict::Applicable);
        let forward = overload_selection_report(
            "site",
            true,
            Some(&trace(vec![first.clone(), second.clone()])),
        );
        let reverse = overload_selection_report("site", true, Some(&trace(vec![second, first])));
        assert_eq!(forward.selection.resolution, SelectionResolution::Ambiguous);
        assert_eq!(forward.selection.resolution, reverse.selection.resolution);
        assert_eq!(forward.selection.applicable, 2);
        assert_eq!(forward.applicability.len(), 2);
    }

    /// Zero applicable candidates stay unresolved with every rejection
    /// retained, rather than collapsing into an empty relation.
    #[test]
    fn zero_applicable_candidates_stay_unresolved() {
        let traced = trace(vec![
            rejected("render", CallableRejectionReason::ArityAboveTotal),
            rejected("render", CallableRejectionReason::ArityBelowRequired),
        ]);
        let report = overload_selection_report("site", true, Some(&traced));
        assert_eq!(report.selection.resolution, SelectionResolution::Unresolved);
        assert_eq!(report.applicability.len(), 2);
    }

    /// One undecidable candidate makes the whole site undecidable: an
    /// exact-cardinality assertion over it must never come out clean.
    #[test]
    fn any_undecidable_candidate_makes_the_site_unknown() {
        let traced = trace(vec![
            selected("render", ApplicabilityVerdict::Applicable),
            selected("render", ApplicabilityVerdict::Unknown),
        ]);
        let report = overload_selection_report("site", true, Some(&traced));
        assert_eq!(
            report.selection.resolution,
            SelectionResolution::UnknownShape
        );
        assert_eq!(report.selection.unknown, 1);
    }

    /// A language that does not report the axis, and a site with no trace at
    /// all, both produce the mandatory row saying so rather than no row.
    #[test]
    fn unsupported_and_untraced_sites_still_produce_the_mandatory_row() {
        let unsupported = overload_selection_report(
            "site",
            false,
            Some(&trace(vec![selected(
                "render",
                ApplicabilityVerdict::Applicable,
            )])),
        );
        assert_eq!(
            unsupported.selection.resolution,
            SelectionResolution::UnknownShape
        );
        assert!(!unsupported.selection.supported);

        let untraced = overload_selection_report("site", true, None);
        assert_eq!(
            untraced.selection.resolution,
            SelectionResolution::UnknownShape
        );
        assert_eq!(untraced.selection.considered, 0);
        assert!(untraced.applicability.is_empty());
    }

    /// A trace that enumerated no candidate at all proves nothing about an
    /// overload set. "The resolver rejected every overload" and "the resolver
    /// never looked" are different answers, and only the first is
    /// `unresolved`.
    #[test]
    fn zero_considered_candidates_is_unknown_not_unresolved() {
        let report = overload_selection_report("site", true, Some(&trace(Vec::new())));
        assert_eq!(
            report.selection.resolution,
            SelectionResolution::UnknownShape
        );
        assert_eq!(report.selection.considered, 0);
    }

    /// A candidate the resolver considered but which is not an indexed
    /// declaration still gets a row, with no candidate rather than a fabricated
    /// one.
    #[test]
    fn a_non_declaration_candidate_keeps_its_row_without_a_unit() {
        let traced = trace(vec![TraceCandidate::rejected(
            TraceCandidateRef::ExternalRoute {
                name: "render".to_owned(),
            },
            None,
            RejectionReason::BoundaryBlocked,
        )]);
        let report = overload_selection_report("site", true, Some(&traced));
        assert_eq!(report.applicability.len(), 1);
        assert_eq!(report.applicability[0].candidate, None);
        assert_eq!(
            report.applicability[0].verdict,
            ApplicabilityVerdict::Unknown
        );
    }

    /// Row identities are deterministic and distinct per candidate, which is
    /// what keeps two rows of one site from deduplicating into one.
    #[test]
    fn row_identities_are_deterministic_and_distinct() {
        let traced = trace(vec![
            selected("render", ApplicabilityVerdict::Applicable),
            rejected("render", CallableRejectionReason::ArityAboveTotal),
        ]);
        let first = overload_selection_report("site", true, Some(&traced));
        let second = overload_selection_report("site", true, Some(&traced));
        assert_eq!(first, second);
        assert_ne!(first.applicability[0].id, first.applicability[1].id);
        assert_ne!(
            overload_selection_report("other", true, Some(&traced))
                .selection
                .id,
            first.selection.id
        );
    }
}
