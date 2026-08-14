//! The one place a callable-applicability check produces both a production
//! answer and its evidence (issue #1478, Milestone 3).
//!
//! Every language resolver already decides which overloads a call site can
//! reach: Java filters constructor and member candidates by arity, C matches a
//! variadic parameter list, Scala matches curried and contextual lists, C#
//! matches named arguments. Each of those checks computed a verdict per
//! candidate and returned only the survivors, so the losers -- and the reason
//! each one lost -- were discarded.
//!
//! This module does not add a second overload solver. It is the shape a
//! language's *existing* check is factored into: one call computes the winners
//! the resolver binds **and** an [`ApplicabilityVerdict`] with a typed
//! [`CallableRejectionReason`] for every candidate the check considered. The
//! production path reads [`ApplicabilityOutcome::winners`]; the trace reads
//! [`ApplicabilityOutcome::verdicts`]. Because both come from one function, a
//! later change to the check cannot make the rows disagree with the binding --
//! there is no second computation to drift from.
//!
//! Two rules are load-bearing.
//!
//! - A verdict is never invented. When the call shape is unreadable, or when
//!   the language never recorded the candidate's declared arity, the verdict is
//!   [`ApplicabilityVerdict::Unknown`] with no reason, which a policy must not
//!   read as applicable.
//! - Candidate order is never a tie breaker. This module reports verdicts; it
//!   never picks between two equally applicable candidates. The selection
//!   summary derived from these verdicts stays `ambiguous` in that case.

use brokk_bifrost_core::analyzer::model::{CallableArity, CodeUnit};
use brokk_bifrost_core::analyzer::structural::callable::{
    ApplicabilityVerdict, CallableRejectionReason,
};

/// One candidate's applicability to one call site, exactly as the production
/// check computed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateApplicability {
    pub candidate: CodeUnit,
    pub verdict: ApplicabilityVerdict,
    /// Set only when the verdict is [`ApplicabilityVerdict::Inapplicable`]: a
    /// candidate that was accepted, or one nobody could decide, has no reason.
    pub reason: Option<CallableRejectionReason>,
}

impl CandidateApplicability {
    pub fn applicable(candidate: CodeUnit) -> Self {
        Self {
            candidate,
            verdict: ApplicabilityVerdict::Applicable,
            reason: None,
        }
    }

    pub fn inapplicable(candidate: CodeUnit, reason: CallableRejectionReason) -> Self {
        Self {
            candidate,
            verdict: ApplicabilityVerdict::Inapplicable,
            reason: Some(reason),
        }
    }

    pub fn unknown(candidate: CodeUnit) -> Self {
        Self {
            candidate,
            verdict: ApplicabilityVerdict::Unknown,
            reason: None,
        }
    }
}

/// The complete answer of one applicability check: what the resolver binds, and
/// why each considered candidate did or did not survive.
///
/// `winners` is the production result and is what a resolver must use. It is
/// derived from `verdicts` here rather than computed separately, which is the
/// whole point of the factoring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicabilityOutcome {
    pub winners: Vec<CodeUnit>,
    pub verdicts: Vec<CandidateApplicability>,
}

impl ApplicabilityOutcome {
    /// Build an outcome from per-candidate verdicts. A candidate whose verdict
    /// is not [`ApplicabilityVerdict::Inapplicable`] is a winner: an
    /// undecidable candidate must stay reachable, because refusing it would be
    /// the resolver claiming a check it never performed.
    pub fn from_verdicts(verdicts: Vec<CandidateApplicability>) -> Self {
        let winners = verdicts
            .iter()
            .filter(|verdict| verdict.verdict != ApplicabilityVerdict::Inapplicable)
            .map(|verdict| verdict.candidate.clone())
            .collect();
        Self { winners, verdicts }
    }

    /// Every candidate is undecidable, because the call shape itself is not
    /// readable at this site. No candidate is refused.
    pub fn undecidable(candidates: &[CodeUnit]) -> Self {
        Self {
            winners: candidates.to_vec(),
            verdicts: candidates
                .iter()
                .cloned()
                .map(CandidateApplicability::unknown)
                .collect(),
        }
    }

    /// Chain a second check that ran over this check's winners.
    ///
    /// A language can refuse a candidate on more than one axis: C# refuses an
    /// explicit type-argument count before it ever measures the value argument
    /// list, so the value check never sees what the generic check discarded.
    /// Without composing them, the discarded candidate reaches the trace with no
    /// verdict at all and its typed reason -- the one thing that distinguishes
    /// "wrong number of type arguments" from "wrong number of arguments" -- is
    /// lost, which is exactly the discard this module exists to remove.
    ///
    /// The composition keeps one verdict per considered candidate: whatever the
    /// first check refused keeps the first check's reason, and everything the
    /// first check let through carries the second check's answer. The winners
    /// are the second check's, because it ran last.
    pub fn then(self, next: ApplicabilityOutcome) -> ApplicabilityOutcome {
        let mut verdicts: Vec<CandidateApplicability> = self
            .verdicts
            .into_iter()
            .filter(|verdict| verdict.verdict == ApplicabilityVerdict::Inapplicable)
            .collect();
        verdicts.extend(next.verdicts);
        ApplicabilityOutcome {
            winners: next.winners,
            verdicts,
        }
    }

    /// Whether any candidate was refused. A check that refused nothing did not
    /// discriminate, which is what the `Unknown` verdict already says per
    /// candidate; callers use this to keep their existing "filter changed
    /// nothing" fast paths.
    pub fn refused_any(&self) -> bool {
        self.verdicts
            .iter()
            .any(|verdict| verdict.verdict == ApplicabilityVerdict::Inapplicable)
    }
}

/// Check an ordered positional argument count against each candidate's declared
/// arity, and report both the survivors and the per-candidate verdicts.
///
/// `arity_of` is the language's own reader of the declared parameter list -- the
/// same one its filter already used -- so this function adds no language
/// knowledge. A candidate whose arity the language never recorded is
/// [`ApplicabilityVerdict::Unknown`]; "nobody recorded a parameter list" and
/// "the parameter list accepts this call" are different answers.
pub fn arity_applicability(
    candidates: &[CodeUnit],
    actual: Option<usize>,
    arity_of: impl Fn(&CodeUnit) -> Option<CallableArity>,
) -> ApplicabilityOutcome {
    arity_applicability_over_entries(candidates, actual, |candidate| {
        arity_of(candidate).map(|arity| vec![arity])
    })
}

/// The same check for a candidate whose language records several declared
/// parameter lists under one declaration -- a C++ header beside its definition,
/// a Kotlin declaration with several persisted signature entries.
///
/// `arities_of` returns `None` when nothing about the candidate's parameter
/// list is recorded, and a list of every recorded arity otherwise. The
/// candidate is applicable when any recorded arity accepts the call, which is
/// what every language's own filter already does.
pub fn arity_applicability_over_entries(
    candidates: &[CodeUnit],
    actual: Option<usize>,
    arities_of: impl Fn(&CodeUnit) -> Option<Vec<CallableArity>>,
) -> ApplicabilityOutcome {
    let Some(actual) = actual else {
        return ApplicabilityOutcome::undecidable(candidates);
    };
    ApplicabilityOutcome::from_verdicts(
        candidates
            .iter()
            .map(|candidate| arity_verdict(candidate, arities_of(candidate).as_deref(), actual))
            .collect(),
    )
}

/// The verdict one candidate's declared parameter lists give an ordered
/// positional argument count.
///
/// `arities` is `None`, or empty, when nothing about the candidate's parameter
/// list is recorded, which is undecidable rather than accepted. Exposed so a
/// language whose filter refuses candidates on other axes too -- C++ refuses a
/// non-callable member at a call seam -- can produce those verdicts itself
/// while still taking the arity answer from here rather than restating it.
pub fn arity_verdict(
    candidate: &CodeUnit,
    arities: Option<&[CallableArity]>,
    actual: usize,
) -> CandidateApplicability {
    match arities {
        None | Some([]) => CandidateApplicability::unknown(candidate.clone()),
        Some(arities) if arities.iter().any(|arity| arity.accepts(actual)) => {
            CandidateApplicability::applicable(candidate.clone())
        }
        Some(arities) => CandidateApplicability::inapplicable(
            candidate.clone(),
            arity_rejection_reason(arities, actual),
        ),
    }
}

/// Which end of the declared arity range the call missed, over every recorded
/// parameter list of one candidate.
///
/// A call below every declared requirement missed the low end; a call above
/// every declared total missed the high end. A call that is neither fell in a
/// gap *between* two declared lists, which is a list-shape mismatch rather than
/// an arity-range miss, and saying so is more honest than picking one end. A
/// repeating trailing parameter has no upper bound, so an arity that repeats
/// can only be missed from below.
fn arity_rejection_reason(arities: &[CallableArity], actual: usize) -> CallableRejectionReason {
    debug_assert!(
        !arities.is_empty() && !arities.iter().any(|arity| arity.accepts(actual)),
        "a rejection reason is only asked for a refused arity"
    );
    if arities.iter().all(|arity| actual < arity.required()) {
        CallableRejectionReason::ArityBelowRequired
    } else if arities
        .iter()
        .all(|arity| !arity.is_repeated() && actual > arity.total())
    {
        CallableRejectionReason::ArityAboveTotal
    } else {
        CallableRejectionReason::ListShapeMismatch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    /// The winners a resolver binds and the rows a policy reads come from one
    /// pass: the survivors are exactly the candidates that were not refused.
    #[test]
    fn winners_are_the_candidates_the_verdicts_did_not_refuse() {
        let one = unit("one");
        let two = unit("two");
        let candidates = vec![one.clone(), two.clone()];
        let outcome = arity_applicability(&candidates, Some(1), |candidate| {
            Some(if *candidate == one {
                CallableArity::exact(1)
            } else {
                CallableArity::exact(2)
            })
        });
        assert_eq!(outcome.winners, vec![one]);
        assert_eq!(
            outcome.verdicts[0].verdict,
            ApplicabilityVerdict::Applicable
        );
        assert_eq!(
            outcome.verdicts[1].verdict,
            ApplicabilityVerdict::Inapplicable
        );
        assert_eq!(
            outcome.verdicts[1].reason,
            Some(CallableRejectionReason::ArityBelowRequired)
        );
    }

    /// Which end of the range the call missed is stated exactly, so a policy
    /// can tell "too few arguments" from "too many".
    #[test]
    fn the_reason_names_the_end_of_the_range_that_was_missed() {
        let candidates = vec![unit("f")];
        let too_many = arity_applicability(&candidates, Some(5), |_| {
            Some(CallableArity::new(1, 2, false))
        });
        assert_eq!(
            too_many.verdicts[0].reason,
            Some(CallableRejectionReason::ArityAboveTotal)
        );
        let too_few = arity_applicability(&candidates, Some(0), |_| {
            Some(CallableArity::new(1, 2, false))
        });
        assert_eq!(
            too_few.verdicts[0].reason,
            Some(CallableRejectionReason::ArityBelowRequired)
        );
    }

    /// A repeating trailing parameter has no upper bound, so a call that
    /// exceeds the declared total is still applicable.
    #[test]
    fn a_repeating_parameter_accepts_more_arguments_than_it_declares() {
        let candidates = vec![unit("f")];
        let outcome = arity_applicability(&candidates, Some(9), |_| {
            Some(CallableArity::new(1, 2, true))
        });
        assert_eq!(outcome.winners.len(), 1);
        assert!(!outcome.refused_any());
    }

    /// A call that falls in the gap between two declared parameter lists missed
    /// neither end of a single range, and saying so beats picking one.
    #[test]
    fn a_call_between_two_declared_lists_is_a_list_shape_mismatch() {
        let candidates = vec![unit("f")];
        let outcome = arity_applicability_over_entries(&candidates, Some(2), |_| {
            Some(vec![CallableArity::exact(1), CallableArity::exact(3)])
        });
        assert_eq!(
            outcome.verdicts[0].reason,
            Some(CallableRejectionReason::ListShapeMismatch)
        );
    }

    /// A candidate with several declared lists is applicable when any of them
    /// accepts the call, which is what every language's own filter does.
    #[test]
    fn any_accepting_declared_list_makes_the_candidate_applicable() {
        let candidates = vec![unit("f")];
        let outcome = arity_applicability_over_entries(&candidates, Some(3), |_| {
            Some(vec![CallableArity::exact(1), CallableArity::exact(3)])
        });
        assert_eq!(
            outcome.verdicts[0].verdict,
            ApplicabilityVerdict::Applicable
        );
    }

    /// An unreadable call shape refuses nothing and claims nothing: every
    /// candidate stays reachable with an undecided verdict.
    #[test]
    fn an_unreadable_call_shape_decides_nothing() {
        let candidates = vec![unit("one"), unit("two")];
        let outcome = arity_applicability(&candidates, None, |_| Some(CallableArity::exact(0)));
        assert_eq!(outcome.winners, candidates);
        assert!(
            outcome
                .verdicts
                .iter()
                .all(|verdict| verdict.verdict == ApplicabilityVerdict::Unknown)
        );
        assert!(
            outcome
                .verdicts
                .iter()
                .all(|verdict| verdict.reason.is_none())
        );
    }

    /// A declared arity nobody recorded is undecidable rather than accepted,
    /// and it never becomes a rejection either.
    #[test]
    fn an_unrecorded_declared_arity_is_undecidable_not_applicable() {
        let candidates = vec![unit("f")];
        let outcome = arity_applicability(&candidates, Some(3), |_| None);
        assert_eq!(outcome.verdicts[0].verdict, ApplicabilityVerdict::Unknown);
        assert_eq!(outcome.winners.len(), 1);
        assert!(!outcome.refused_any());
    }
}
