//! Stage 3: the blind-then-graded adjudication harness.
//!
//! Routing follows stage 1's typed incompleteness, exactly as the plan requires:
//!
//! * a fully derivable entry (the derivation met no boundary) ships from the
//!   derived slot and never sees the model;
//! * an underivable entry that CodeQL covers ships the CodeQL translation, and
//!   the model is run over it blind purely to be graded, its proposal discarded;
//! * an underivable entry that no corpus covers enters model proposal, whose
//!   output ships only if it later survives the stage-4 proof gate.
//!
//! The load-bearing property is the calibration discipline. The model proposes
//! BLIND first: [`BlindProposalRequest`] carries the pinned body facts, the
//! partial derivation, and its typed boundaries, but by construction it CANNOT
//! carry the corpus answer, so the blind pass cannot leak it. First-pass
//! agreement against the CodeQL overlap is graded and recorded as the trust
//! metric, stratified by difficulty class (native-boundary versus pure code,
//! arity, receiver-ness). ONLY THEN does the mismatch detail return to the model
//! through [`Adjudicator::reconsider`] as a self-correction signal, after which
//! the model either concedes and repairs or produces a refutation dossier that
//! cross-examines the corpus entry.
//!
//! The model itself is a seam: [`Adjudicator`] is the only interface to it, so a
//! later harness fills it with a real workflow or agent call and the foundry
//! code never names a model API. Tests drive it with a hand-written
//! [`FakeAdjudicator`], so calibration is deterministic and network-free.

use std::collections::{BTreeMap, BTreeSet};

use brokk_bifrost_analysis::analyzer::semantic_model::AuthoredSummaryTransfer;
use serde::Serialize;

use super::ir::{
    FoundryBoundary, FoundryCorpus, FoundryDerivationBoundary, FoundryEntry, FoundryTarget,
    render_transfer, summary_id,
};

/// The stage code version. Bump it when the adjudication logic changes, so the
/// store invalidates every cached adjudication artifact.
pub const ADJUDICATE_STAGE_CODE_VERSION: u32 = 1;

/// Which route the harness took for one target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdjudicationRoute {
    /// Fully derivable: shipped from the derived slot, no model call.
    DerivedComplete,
    /// Underivable but CodeQL-covered: the CodeQL translation ships and the
    /// model is graded blind over it, its proposal discarded.
    TranslateAndVerify,
    /// Underivable and uncovered: the model proposes and its output ships if it
    /// survives stage 4.
    LlmProposal,
}

impl AdjudicationRoute {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DerivedComplete => "derived_complete",
            Self::TranslateAndVerify => "translate_and_verify",
            Self::LlmProposal => "llm_proposal",
        }
    }
}

/// The incompleteness axis of a difficulty class.
///
/// The plan strata split on native-boundary versus pure code: a native callee's
/// behavior is in no source the pins carry, so it is a different kind of hard
/// than a body the derivation could read but did not finish.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryClass {
    NativeBoundary,
    PureCode,
}

impl BoundaryClass {
    /// A derivation whose boundaries include a native callee is native-bounded;
    /// every other incompleteness is pure code.
    fn of(boundaries: &[FoundryDerivationBoundary]) -> Self {
        if boundaries
            .iter()
            .any(|boundary| matches!(boundary, FoundryDerivationBoundary::NativeCallee { .. }))
        {
            Self::NativeBoundary
        } else {
            Self::PureCode
        }
    }
}

/// The difficulty stratum first-pass agreement is measured against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct DifficultyClass {
    pub boundary: BoundaryClass,
    pub arity: u32,
    pub has_receiver: bool,
}

/// One target handed to the harness, with everything the routing needs.
///
/// The derived facts and the corpus overlap are separate fields on purpose: the
/// blind request is built from the derived facts alone, and the corpus answer is
/// only ever read inside the harness for grading, never handed to the model
/// before the blind proposal exists.
#[derive(Debug, Clone)]
pub struct AdjudicationCandidate {
    pub target: FoundryTarget,
    pub boundary: FoundryBoundary,
    /// The derived slot's answer, present when the derivation ran on this
    /// target. Its boundaries decide derivability and the difficulty class.
    pub derived: Option<DerivedFacts>,
    /// The CodeQL overlap at the argument-level projection, present when the
    /// corpus covers this target. This is the grading oracle; the model never
    /// sees it before it proposes.
    pub codeql: Option<CorpusFacts>,
}

/// The derived slot's answer for one target.
#[derive(Debug, Clone)]
pub struct DerivedFacts {
    pub entry: FoundryEntry,
    pub boundaries: Vec<FoundryDerivationBoundary>,
}

impl DerivedFacts {
    fn is_complete(&self) -> bool {
        self.boundaries.is_empty()
    }
}

/// The corpus slot's answer for one target.
#[derive(Debug, Clone)]
pub struct CorpusFacts {
    pub entry: FoundryEntry,
}

/// The blind request handed to the model.
///
/// It carries the body facts a proposer needs and, by construction, nothing of
/// the corpus answer. The absence is enforced by the type: there is no field a
/// caller could put the CodeQL transfers into, so the blind pass cannot see them
/// even by mistake.
#[derive(Debug, Clone)]
pub struct BlindProposalRequest<'a> {
    pub target: &'a FoundryTarget,
    pub boundary: FoundryBoundary,
    /// The partial derivation's transfers: what the analyzer could establish
    /// before it hit a boundary. A proposer may extend or correct them.
    pub derivation_hint: &'a [AuthoredSummaryTransfer],
    /// The typed reasons the derivation stopped, spelled as their kinds. Owned
    /// because they are projected from the derived boundaries, not stored in
    /// that shape anywhere the request could borrow from.
    pub boundaries: Vec<String>,
    pub prompt_version: u32,
}

/// What the model proposes when it cannot see the answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlindProposal {
    Transfers(Vec<AuthoredSummaryTransfer>),
    /// The model declines to propose. An abstention grades as disagreement with
    /// any non-empty corpus claim, which is the honest outcome.
    Abstain,
}

impl BlindProposal {
    fn rendered(&self) -> BTreeSet<String> {
        match self {
            Self::Transfers(transfers) => transfers.iter().map(render_transfer).collect(),
            Self::Abstain => BTreeSet::new(),
        }
    }
}

/// The self-correction signal handed back after grading.
///
/// It carries the structured corpus transfers, because this is exactly the point
/// where the mismatch detail is allowed to reach the model.
#[derive(Debug, Clone)]
pub struct GradedMismatch {
    pub expected: Vec<AuthoredSummaryTransfer>,
    pub expected_rendered: Vec<String>,
    pub proposed_rendered: Vec<String>,
}

/// What the model does once it has seen the mismatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reconsideration {
    /// The model concedes and repairs to the given transfer set.
    Concede(Vec<AuthoredSummaryTransfer>),
    /// The model maintains its disagreement and files a refutation dossier
    /// against the corpus entry.
    Refute(String),
}

/// The model seam. A real harness implements it over a workflow or agent call;
/// tests implement it with [`FakeAdjudicator`].
pub trait Adjudicator {
    /// Propose blind, without the corpus answer.
    fn propose_blind(&self, request: &BlindProposalRequest<'_>) -> BlindProposal;

    /// Reconsider after grading, with the mismatch detail.
    fn reconsider(
        &self,
        request: &BlindProposalRequest<'_>,
        mismatch: &GradedMismatch,
    ) -> Reconsideration;
}

/// First-pass agreement counts for one stratum, and the correction outcomes of
/// the entries that disagreed first.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CalibrationCounts {
    /// Entries in this stratum that entered the blind grading pass.
    pub graded: u32,
    /// Entries whose blind proposal matched the corpus on the first pass. This
    /// is the trust metric.
    pub first_pass_agree: u32,
    /// Entries that disagreed first and conceded after seeing the mismatch.
    pub conceded_after_grading: u32,
    /// Entries that disagreed first and held their ground, producing a
    /// refutation dossier.
    pub refutations: u32,
}

impl CalibrationCounts {
    fn record(&mut self, agree_first_pass: bool, conceded: Option<bool>) {
        self.graded += 1;
        if agree_first_pass {
            self.first_pass_agree += 1;
        }
        match conceded {
            Some(true) => self.conceded_after_grading += 1,
            Some(false) => self.refutations += 1,
            None => {}
        }
    }

    fn add(&mut self, other: &Self) {
        self.graded += other.graded;
        self.first_pass_agree += other.first_pass_agree;
        self.conceded_after_grading += other.conceded_after_grading;
        self.refutations += other.refutations;
    }
}

/// First-pass agreement in one difficulty class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CalibrationStratum {
    pub class: DifficultyClass,
    pub counts: CalibrationCounts,
}

/// The calibration report: first-pass agreement stratified by difficulty class,
/// the acceptance instrument for this milestone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CalibrationReport {
    pub prompt_version: u32,
    pub strata: Vec<CalibrationStratum>,
    pub totals: CalibrationCounts,
}

/// A refutation dossier: the model maintained disagreement with the corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RefutationDossier {
    pub target: String,
    pub class: DifficultyClass,
    pub proposed: Vec<String>,
    pub corpus: Vec<String>,
    pub dossier: String,
}

/// How a shipping entry was decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShippingProvenance {
    /// Bifrost's own derivation, fully traversed.
    Derived,
    /// A corpus translation imported because the derivation could not reach it
    /// and the corpus covers it.
    CorpusTranslation,
    /// A model proposal, held to the stage-4 proof gate before it ships.
    Adjudicated,
}

/// One entry the harness would ship, with how it was decided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ShippingEntry {
    pub provenance: ShippingProvenance,
    pub route: AdjudicationRoute,
    pub entry: FoundryEntry,
}

/// One module's adjudication result: the shipping set, the calibration report,
/// and every refutation dossier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdjudicationOutcome {
    pub shipping: Vec<ShippingEntry>,
    pub calibration: CalibrationReport,
    pub refutations: Vec<RefutationDossier>,
}

/// Run stage 3 over a module's candidates.
///
/// The candidates are processed in the given order, so the outcome is
/// deterministic for a deterministic adjudicator.
pub fn run_adjudication(
    candidates: &[AdjudicationCandidate],
    adjudicator: &dyn Adjudicator,
    prompt_version: u32,
) -> AdjudicationOutcome {
    let mut shipping = Vec::new();
    let mut refutations = Vec::new();
    let mut by_class: BTreeMap<DifficultyClass, CalibrationCounts> = BTreeMap::new();

    for candidate in candidates {
        match route_of(candidate) {
            AdjudicationRoute::DerivedComplete => {
                let derived = candidate
                    .derived
                    .as_ref()
                    .expect("a derived-complete candidate has a derived slot");
                shipping.push(ShippingEntry {
                    provenance: ShippingProvenance::Derived,
                    route: AdjudicationRoute::DerivedComplete,
                    entry: derived.entry.clone(),
                });
            }
            AdjudicationRoute::TranslateAndVerify => {
                let codeql = candidate
                    .codeql
                    .as_ref()
                    .expect("a translate-and-verify candidate has a corpus slot");
                // The CodeQL translation ships for this stratum.
                shipping.push(ShippingEntry {
                    provenance: ShippingProvenance::CorpusTranslation,
                    route: AdjudicationRoute::TranslateAndVerify,
                    entry: codeql.entry.clone(),
                });
                // The dedicated blind grading pass. Its proposal never ships; it
                // exists only to produce the calibration datum.
                let class = difficulty_class(candidate);
                let (agree, conceded, dossier) =
                    grade_blind(candidate, codeql, adjudicator, prompt_version);
                by_class.entry(class).or_default().record(agree, conceded);
                if let Some(dossier) = dossier {
                    refutations.push(dossier);
                }
            }
            AdjudicationRoute::LlmProposal => {
                let request = blind_request(candidate, prompt_version);
                if let BlindProposal::Transfers(transfers) = adjudicator.propose_blind(&request)
                    && !transfers.is_empty()
                {
                    shipping.push(ShippingEntry {
                        provenance: ShippingProvenance::Adjudicated,
                        route: AdjudicationRoute::LlmProposal,
                        entry: proposal_entry(candidate, transfers),
                    });
                }
                // An abstention or an empty proposal ships nothing: an
                // underivable, uncovered target with no proposal stays a gap, it
                // does not become a manufactured claim.
            }
        }
    }

    let strata = by_class
        .into_iter()
        .map(|(class, counts)| CalibrationStratum { class, counts })
        .collect::<Vec<_>>();
    let mut totals = CalibrationCounts::default();
    for stratum in &strata {
        totals.add(&stratum.counts);
    }

    AdjudicationOutcome {
        shipping,
        calibration: CalibrationReport {
            prompt_version,
            strata,
            totals,
        },
        refutations,
    }
}

/// Grade one translate-and-verify candidate blind, then reconsider on a
/// mismatch. Returns `(first_pass_agree, conceded_after_grading, dossier)`.
fn grade_blind(
    candidate: &AdjudicationCandidate,
    codeql: &CorpusFacts,
    adjudicator: &dyn Adjudicator,
    prompt_version: u32,
) -> (bool, Option<bool>, Option<RefutationDossier>) {
    let request = blind_request(candidate, prompt_version);
    let proposal = adjudicator.propose_blind(&request);

    let proposed = proposal.rendered();
    let expected = codeql
        .entry
        .transfers
        .iter()
        .map(render_transfer)
        .collect::<BTreeSet<String>>();
    if proposed == expected {
        return (true, None, None);
    }

    // First-pass disagreement. Only now does the mismatch detail return.
    let mismatch = GradedMismatch {
        expected: codeql.entry.transfers.clone(),
        expected_rendered: expected.iter().cloned().collect(),
        proposed_rendered: proposed.iter().cloned().collect(),
    };
    match adjudicator.reconsider(&request, &mismatch) {
        Reconsideration::Concede(_) => (false, Some(true), None),
        Reconsideration::Refute(dossier) => (
            false,
            Some(false),
            Some(RefutationDossier {
                target: format!(
                    "{}#{}",
                    candidate.target.artifact_path,
                    candidate.target.signature.symbol(&candidate.target.member)
                ),
                class: difficulty_class(candidate),
                proposed: mismatch.proposed_rendered,
                corpus: mismatch.expected_rendered,
                dossier,
            }),
        ),
    }
}

fn route_of(candidate: &AdjudicationCandidate) -> AdjudicationRoute {
    match &candidate.derived {
        Some(derived) if derived.is_complete() => AdjudicationRoute::DerivedComplete,
        _ => {
            if candidate.codeql.is_some() {
                AdjudicationRoute::TranslateAndVerify
            } else {
                AdjudicationRoute::LlmProposal
            }
        }
    }
}

fn difficulty_class(candidate: &AdjudicationCandidate) -> DifficultyClass {
    let boundary = candidate
        .derived
        .as_ref()
        .map_or(BoundaryClass::PureCode, |derived| {
            BoundaryClass::of(&derived.boundaries)
        });
    DifficultyClass {
        boundary,
        arity: candidate.boundary.parameter_count,
        has_receiver: candidate.boundary.has_receiver,
    }
}

fn blind_request(
    candidate: &AdjudicationCandidate,
    prompt_version: u32,
) -> BlindProposalRequest<'_> {
    static NO_TRANSFERS: &[AuthoredSummaryTransfer] = &[];
    let (hint, boundaries) = match &candidate.derived {
        Some(derived) => (
            derived.entry.transfers.as_slice(),
            derived
                .boundaries
                .iter()
                .map(|boundary| boundary.kind().to_owned())
                .collect::<Vec<_>>(),
        ),
        None => (NO_TRANSFERS, Vec::new()),
    };
    BlindProposalRequest {
        target: &candidate.target,
        boundary: candidate.boundary,
        derivation_hint: hint,
        boundaries,
        prompt_version,
    }
}

/// Build the FoundryEntry a model proposal ships.
fn proposal_entry(
    candidate: &AdjudicationCandidate,
    transfers: Vec<AuthoredSummaryTransfer>,
) -> FoundryEntry {
    let mut entry = candidate
        .derived
        .as_ref()
        .map(|derived| derived.entry.clone())
        .unwrap_or_else(|| base_entry(candidate));
    entry.transfers = transfers;
    entry.derivation = None;
    entry
}

/// A minimal entry for a target the derivation never reached.
fn base_entry(candidate: &AdjudicationCandidate) -> FoundryEntry {
    FoundryEntry {
        id: summary_id(FoundryCorpus::Derived, &candidate.target),
        corpus: FoundryCorpus::Derived,
        target: candidate.target.clone(),
        boundary: candidate.boundary,
        claim: super::ir::FoundryClaim::Flows,
        completeness: super::ir::FoundryCompleteness::Partial,
        transfers: Vec::new(),
        artifact: super::ir::FoundryArtifactBinding::Unresolved,
        evidence: Vec::new(),
        notes: Vec::new(),
        derivation: None,
    }
}

/// A hand-written deterministic adjudicator for driving the harness without a
/// model. It proposes exactly the derivation hint it is shown, so a test fixes
/// first-pass agreement by choosing whether the hint matches the corpus. On a
/// mismatch it concedes to the corpus, except for a configured set of members it
/// refutes, which produces a refutation dossier.
///
/// This is the "deterministic fake" the milestone requires, not a mocking
/// framework: it is a plain struct with one field and a fixed rule.
#[derive(Debug, Clone, Default)]
pub struct FakeAdjudicator {
    stubborn_members: BTreeSet<String>,
}

impl FakeAdjudicator {
    /// A fake that always concedes on a mismatch.
    pub fn conceding() -> Self {
        Self::default()
    }

    /// A fake that refuses to concede for the named members, filing a refutation
    /// dossier instead.
    pub fn refuting_on(members: impl IntoIterator<Item = &'static str>) -> Self {
        Self {
            stubborn_members: members.into_iter().map(ToOwned::to_owned).collect(),
        }
    }
}

impl Adjudicator for FakeAdjudicator {
    fn propose_blind(&self, request: &BlindProposalRequest<'_>) -> BlindProposal {
        BlindProposal::Transfers(request.derivation_hint.to_vec())
    }

    fn reconsider(
        &self,
        request: &BlindProposalRequest<'_>,
        mismatch: &GradedMismatch,
    ) -> Reconsideration {
        if self.stubborn_members.contains(&request.target.member) {
            Reconsideration::Refute(format!(
                "maintains {:?} against corpus {:?}",
                mismatch.proposed_rendered, mismatch.expected_rendered
            ))
        } else {
            Reconsideration::Concede(mismatch.expected.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use brokk_bifrost_analysis::analyzer::semantic_model::{
        AuthoredSummaryExitKind, AuthoredSummaryInput, AuthoredSummaryOutput,
    };

    use super::*;
    use crate::summary_foundry::ir::{
        FoundryArtifactBinding, FoundryClaim, FoundryCompleteness, FoundrySignature,
    };

    fn transfer(input: AuthoredSummaryInput) -> AuthoredSummaryTransfer {
        AuthoredSummaryTransfer {
            input,
            exit_kind: AuthoredSummaryExitKind::Normal,
            output: AuthoredSummaryOutput::NormalReturn {},
            value_transfer: None,
        }
    }

    fn param(ordinal: u32) -> AuthoredSummaryTransfer {
        transfer(AuthoredSummaryInput::Parameter { ordinal })
    }

    fn receiver() -> AuthoredSummaryTransfer {
        transfer(AuthoredSummaryInput::Receiver {})
    }

    fn target(member: &str, types: &[&str]) -> FoundryTarget {
        FoundryTarget {
            artifact_path: "java/lang/Fixture.class".to_owned(),
            member: member.to_owned(),
            signature: FoundrySignature::Overload {
                types: types.iter().map(|value| (*value).to_owned()).collect(),
            },
        }
    }

    fn entry(
        member: &str,
        types: &[&str],
        has_receiver: bool,
        transfers: Vec<AuthoredSummaryTransfer>,
    ) -> FoundryEntry {
        let target = target(member, types);
        FoundryEntry {
            id: summary_id(FoundryCorpus::Derived, &target),
            corpus: FoundryCorpus::Derived,
            target,
            boundary: FoundryBoundary {
                has_receiver,
                parameter_count: types.len() as u32,
            },
            claim: FoundryClaim::Flows,
            completeness: FoundryCompleteness::Partial,
            transfers,
            artifact: FoundryArtifactBinding::Unresolved,
            evidence: Vec::new(),
            notes: Vec::new(),
            derivation: None,
        }
    }

    /// A translate-and-verify candidate: underivable (has boundaries) and
    /// CodeQL-covered. `hint` drives the blind proposal; `corpus` is graded
    /// against it.
    fn verify_candidate(
        member: &str,
        types: &[&str],
        has_receiver: bool,
        boundaries: Vec<FoundryDerivationBoundary>,
        hint: Vec<AuthoredSummaryTransfer>,
        corpus: Vec<AuthoredSummaryTransfer>,
    ) -> AdjudicationCandidate {
        AdjudicationCandidate {
            target: target(member, types),
            boundary: FoundryBoundary {
                has_receiver,
                parameter_count: types.len() as u32,
            },
            derived: Some(DerivedFacts {
                entry: entry(member, types, has_receiver, hint),
                boundaries,
            }),
            codeql: Some(CorpusFacts {
                entry: entry(member, types, has_receiver, corpus),
            }),
        }
    }

    /// An adjudicator that must never be called: it proves a route made no model
    /// call.
    struct PanickingAdjudicator;
    impl Adjudicator for PanickingAdjudicator {
        fn propose_blind(&self, _request: &BlindProposalRequest<'_>) -> BlindProposal {
            panic!("a fully derivable entry must not call the model");
        }
        fn reconsider(
            &self,
            _request: &BlindProposalRequest<'_>,
            _mismatch: &GradedMismatch,
        ) -> Reconsideration {
            panic!("a fully derivable entry must not call the model");
        }
    }

    #[test]
    fn a_fully_derivable_entry_ships_the_derived_slot_without_a_model_call() {
        let candidate = AdjudicationCandidate {
            target: target("pure", &["String"]),
            boundary: FoundryBoundary {
                has_receiver: false,
                parameter_count: 1,
            },
            derived: Some(DerivedFacts {
                entry: entry("pure", &["String"], false, vec![param(0)]),
                boundaries: Vec::new(),
            }),
            codeql: None,
        };

        let outcome = run_adjudication(&[candidate], &PanickingAdjudicator, 1);

        assert_eq!(outcome.shipping.len(), 1);
        assert_eq!(outcome.shipping[0].provenance, ShippingProvenance::Derived);
        assert_eq!(
            outcome.shipping[0].route,
            AdjudicationRoute::DerivedComplete
        );
        assert!(outcome.calibration.strata.is_empty());
        assert_eq!(outcome.calibration.totals, CalibrationCounts::default());
    }

    #[test]
    fn calibration_shows_first_pass_agreement_stratified_by_difficulty_class() {
        let candidates = vec![
            // {PureCode, arity 1, no receiver}: two entries whose blind proposal
            // matches the corpus.
            verify_candidate(
                "a",
                &["String"],
                false,
                vec![FoundryDerivationBoundary::UnresolvedCall],
                vec![param(0)],
                vec![param(0)],
            ),
            verify_candidate(
                "b",
                &["String"],
                false,
                vec![FoundryDerivationBoundary::UnresolvedCall],
                vec![param(0)],
                vec![param(0)],
            ),
            // {NativeBoundary, arity 0, receiver}: blind proposal is empty, the
            // corpus is not, so first-pass disagrees, then concedes.
            verify_candidate(
                "c",
                &[],
                true,
                vec![FoundryDerivationBoundary::NativeCallee {
                    callee: "Native.c".to_owned(),
                }],
                Vec::new(),
                vec![receiver()],
            ),
            // {NativeBoundary, arity 1, receiver}: disagrees and the model is
            // stubborn on `d`, so it refutes.
            verify_candidate(
                "d",
                &["int"],
                true,
                vec![FoundryDerivationBoundary::NativeCallee {
                    callee: "Native.d".to_owned(),
                }],
                vec![receiver()],
                vec![receiver(), param(0)],
            ),
        ];

        let outcome = run_adjudication(&candidates, &FakeAdjudicator::refuting_on(["d"]), 7);

        // The CodeQL translation ships for all four; no calibration proposal
        // ships.
        assert_eq!(outcome.shipping.len(), 4);
        assert!(
            outcome
                .shipping
                .iter()
                .all(|entry| entry.provenance == ShippingProvenance::CorpusTranslation)
        );

        let report = &outcome.calibration;
        assert_eq!(report.prompt_version, 7);
        assert_eq!(report.totals.graded, 4);
        assert_eq!(report.totals.first_pass_agree, 2);
        assert_eq!(report.totals.conceded_after_grading, 1);
        assert_eq!(report.totals.refutations, 1);

        // Strata are sorted; NativeBoundary sorts before PureCode.
        let classes = report
            .strata
            .iter()
            .map(|stratum| stratum.class)
            .collect::<Vec<_>>();
        assert_eq!(
            classes,
            vec![
                DifficultyClass {
                    boundary: BoundaryClass::NativeBoundary,
                    arity: 0,
                    has_receiver: true
                },
                DifficultyClass {
                    boundary: BoundaryClass::NativeBoundary,
                    arity: 1,
                    has_receiver: true
                },
                DifficultyClass {
                    boundary: BoundaryClass::PureCode,
                    arity: 1,
                    has_receiver: false
                },
            ]
        );
        let pure = &report.strata[2].counts;
        assert_eq!(pure.graded, 2);
        assert_eq!(pure.first_pass_agree, 2);

        assert_eq!(outcome.refutations.len(), 1);
        assert_eq!(
            outcome.refutations[0].target,
            "java/lang/Fixture.class#d(int)"
        );
        assert_eq!(
            outcome.refutations[0].corpus,
            vec![
                "parameter[0]->normal_return@normal".to_owned(),
                "receiver->normal_return@normal".to_owned(),
            ]
        );
    }

    #[test]
    fn an_uncovered_underivable_target_ships_the_model_proposal() {
        let candidate = AdjudicationCandidate {
            target: target("uncovered", &["String"]),
            boundary: FoundryBoundary {
                has_receiver: false,
                parameter_count: 1,
            },
            derived: Some(DerivedFacts {
                entry: entry("uncovered", &["String"], false, vec![param(0)]),
                boundaries: vec![FoundryDerivationBoundary::UnresolvedCall],
            }),
            codeql: None,
        };

        let outcome = run_adjudication(&[candidate], &FakeAdjudicator::conceding(), 1);

        assert_eq!(outcome.shipping.len(), 1);
        assert_eq!(
            outcome.shipping[0].provenance,
            ShippingProvenance::Adjudicated
        );
        assert_eq!(outcome.shipping[0].route, AdjudicationRoute::LlmProposal);
        assert_eq!(outcome.shipping[0].entry.transfers, vec![param(0)]);
        // No corpus to grade against, so no calibration datum.
        assert!(outcome.calibration.strata.is_empty());
    }

    #[test]
    fn an_uncovered_target_with_no_proposal_ships_nothing() {
        let candidate = AdjudicationCandidate {
            target: target("empty", &["String"]),
            boundary: FoundryBoundary {
                has_receiver: false,
                parameter_count: 1,
            },
            // No derived slot at all: the hint is empty, so the fake proposes
            // nothing.
            derived: None,
            codeql: None,
        };

        let outcome = run_adjudication(&[candidate], &FakeAdjudicator::conceding(), 1);

        assert!(outcome.shipping.is_empty());
    }

    #[test]
    fn two_runs_over_the_same_candidates_are_identical() {
        let candidates = vec![verify_candidate(
            "a",
            &["String"],
            false,
            vec![FoundryDerivationBoundary::UnresolvedCall],
            vec![param(0)],
            vec![param(0)],
        )];

        let first = run_adjudication(&candidates, &FakeAdjudicator::conceding(), 3);
        let second = run_adjudication(&candidates, &FakeAdjudicator::conceding(), 3);
        assert_eq!(
            serde_json::to_value(&first).unwrap(),
            serde_json::to_value(&second).unwrap()
        );
    }
}
