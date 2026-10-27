//! Request-local reverse nomination evidence and whole-file confirmation.
//!
//! Nominations are a relation, not a set of physical sites: several surfaces
//! and selected contexts can nominate one locator. Grouping never removes
//! those witnesses. This module retains no data beyond the selected query.

use super::*;

use crate::analyzer::resolution::ResolutionIdentityDigestKey;
use crate::analyzer::resolution::worker_transport::{WorkerAnswer, schedule_selected_queue};

pub(super) use super::reverse_candidates::*;

/// The producer of evidence is independent of the lookup route it nominates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(any(test, feature = "test-support"))]
pub(crate) enum ReverseNominationEvidence {
    NamedIndex,
    ImportedRoot,
    Gap,
    Observation,
    MacroRange,
}

#[derive(Clone, Debug)]
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub struct ReverseNomination {
    #[doc(hidden)]
    pub locator: SelectedSemanticLocator,
    pub(crate) surface: Option<SemanticId>,
    pub(crate) context: ReverseContextWitness,
    pub(crate) route: ReverseNominationRoute,
    pub(crate) evidence: ReverseNominationEvidence,
    pub(crate) input_ordinal: usize,
    pub(crate) binder_scope: Option<ResolutionScopeId>,
    pub(crate) obligations: Vec<ReverseObligationLink>,
}

/// Links name an obligation on one independent completion axis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ReverseEvidenceAxis {
    Enumeration,
    Binding,
    Metadata,
}

/// A request-local obligation identity, including its independent reason ordinal.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ReverseObligationId {
    axis: ReverseEvidenceAxis,
    target: SemanticId,
    subject: ReverseSubject,
    ordinal: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct ReverseObligationLink {
    pub(crate) obligation: ReverseObligationId,
}

#[derive(Debug)]
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub struct ReverseTarget {
    #[doc(hidden)]
    pub semantic: SemanticId,
    pub(crate) declaration: CodeUnit,
    pub(crate) context: ReverseContextWitness,
    pub(crate) surfaces: Vec<SemanticId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub enum ReverseSubject {
    Target(SemanticId),
    Context(ReverseContextWitness),
    Site(SelectedSemanticLocator, ReverseContextWitness),
}

/// Attribution is a stage of the shared pipeline, not a language vocabulary.
/// The completion retains the producer's original typed reasons.
#[derive(Clone, Copy, Debug)]
#[doc(hidden)]
pub enum ReverseEvidenceOrigin {
    Inventory,
    // Consumers may render this boundary separately from resolution completion.
    InventoryBoundary,
    Nomination,
    Import,
    Context,
    Access,
    Hierarchy,
    Binding,
    Projection,
}

#[derive(Debug)]
#[doc(hidden)]
pub struct ReverseObligation {
    id: ReverseObligationId,
    #[doc(hidden)]
    pub origin: ReverseEvidenceOrigin,
    #[doc(hidden)]
    pub completion: ResolutionCompletion,
}

impl ReverseObligation {
    #[doc(hidden)]
    pub fn subject(&self) -> &ReverseSubject {
        &self.id.subject
    }
}

#[derive(Debug)]
pub(crate) struct ReverseDischarge {
    pub(crate) obligation: ReverseObligationId,
    pub(crate) origin: ReverseEvidenceOrigin,
}

/// One existing completion value with its exact obligations and discharges.
/// Completion is independent on each of the three result axes.
#[derive(Debug)]
#[doc(hidden)]
pub struct AttributedResolutionCompletion {
    axis: ReverseEvidenceAxis,
    target: SemanticId,
    #[doc(hidden)]
    pub obligations: Vec<ReverseObligation>,
    pub(crate) discharges: Vec<ReverseDischarge>,
}

impl AttributedResolutionCompletion {
    pub(crate) fn new(axis: ReverseEvidenceAxis, target: SemanticId) -> Self {
        Self {
            axis,
            target,
            obligations: Vec::new(),
            discharges: Vec::new(),
        }
    }

    pub(crate) fn record(
        &mut self,
        subject: ReverseSubject,
        origin: ReverseEvidenceOrigin,
        completion: ResolutionCompletion,
    ) -> ReverseObligationId {
        let id = ReverseObligationId {
            axis: self.axis,
            target: self.target,
            subject,
            ordinal: self.obligations.len(),
        };
        self.obligations.push(ReverseObligation {
            id: id.clone(),
            origin,
            completion,
        });
        id
    }

    /// Only an explicit link can discharge a previously recorded obligation.
    pub(crate) fn discharge(
        &mut self,
        obligation: ReverseObligationId,
        origin: ReverseEvidenceOrigin,
    ) {
        self.assert_obligation(&obligation);
        self.discharges
            .push(ReverseDischarge { obligation, origin });
    }

    fn assert_obligation(&self, id: &ReverseObligationId) {
        assert_eq!(id.axis, self.axis, "obligation belongs to another axis");
        assert_eq!(
            id.target, self.target,
            "obligation belongs to another target"
        );
        assert_eq!(
            self.obligations.get(id.ordinal).map(|row| &row.id),
            Some(id),
            "obligation identity does not match the ledger row"
        );
    }

    /// Reduce after all contexts have supplied their evidence. A complete row
    /// is neutral; it never cancels an earlier, unrelated gap.
    #[doc(hidden)]
    pub fn completion(&self) -> ResolutionCompletion {
        self.completion_for(|_| true)
    }

    #[doc(hidden)]
    pub fn completion_for(
        &self,
        include: impl Fn(&ReverseObligation) -> bool,
    ) -> ResolutionCompletion {
        let discharged = self
            .discharges
            .iter()
            .map(|row| {
                self.assert_obligation(&row.obligation);
                row.obligation.ordinal
            })
            .collect::<HashSet<_>>();
        self.obligations
            .iter()
            .enumerate()
            .filter(|(index, row)| !discharged.contains(index) && include(row))
            .fold(ResolutionCompletion::Complete, |completion, (_, row)| {
                completion.combine(&row.completion)
            })
    }
}

#[derive(Debug)]
pub(crate) enum ReverseConfirmation {
    Answered {
        locator: SelectedSemanticLocator,
        context: ReverseContextWitness,
        target: SemanticId,
        relation: ReverseTargetRelation,
    },
    Unavailable {
        locator: SelectedSemanticLocator,
        context: ReverseContextWitness,
        target: SemanticId,
    },
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ReverseTargetRelation {
    Matches,
    Excluded,
    Undecided,
}

#[derive(Debug)]
#[doc(hidden)]
pub struct ReverseEvidence {
    #[doc(hidden)]
    pub enumeration: AttributedResolutionCompletion,
    #[doc(hidden)]
    pub binding: AttributedResolutionCompletion,
    #[doc(hidden)]
    pub metadata: AttributedResolutionCompletion,
    pub(crate) confirmations: Vec<ReverseConfirmation>,
}

impl ReverseEvidence {
    pub(crate) fn new(target: SemanticId) -> Self {
        Self {
            enumeration: AttributedResolutionCompletion::new(
                ReverseEvidenceAxis::Enumeration,
                target,
            ),
            binding: AttributedResolutionCompletion::new(ReverseEvidenceAxis::Binding, target),
            metadata: AttributedResolutionCompletion::new(ReverseEvidenceAxis::Metadata, target),
            confirmations: Vec::new(),
        }
    }
}

/// Selected view identity stays structured and language-owned.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ReverseContextId<C> {
    pub(crate) selected: ReverseContextWitness,
    pub(crate) view: C,
}

/// The shared barrier knows conjunction, not a language's closure vocabulary.
pub(crate) trait ReverseClosure {
    fn meet(&mut self, other: Self);
}

impl ReverseClosure for () {
    fn meet(&mut self, _other: Self) {}
}

/// Classify one semantic answer before combining its required contexts.
pub(crate) struct ReverseViewVerdict<A, C> {
    pub(crate) relation: ReverseTargetRelation,
    pub(crate) closes_site: bool,
    pub(crate) closure: C,
    pub(crate) answer: A,
}

/// Binding alternatives and rejecting evidence remain separate at the barrier.
pub(crate) struct ReverseSiteReduction<A, C> {
    pub(crate) binding: Vec<A>,
    pub(crate) rejecting: Vec<A>,
    pub(crate) undecided: Vec<A>,
    pub(crate) every_context_closed: bool,
    pub(crate) closure: Option<C>,
}

/// A report is required even for a successful negative binding. A missing view
/// leaves the barrier open; an empty domain cannot prove an absence.
pub(crate) fn reduce_reverse_site<D: Eq + std::hash::Hash, A, C: ReverseClosure>(
    required: &[D],
    reports: Vec<(D, Vec<ReverseViewVerdict<A, C>>)>,
) -> ReverseSiteReduction<A, C> {
    let mut reduced: ReverseSiteReduction<A, C> = ReverseSiteReduction {
        binding: Vec::new(),
        rejecting: Vec::new(),
        undecided: Vec::new(),
        every_context_closed: !required.is_empty(),
        closure: None,
    };
    let positions = required
        .iter()
        .enumerate()
        .map(|(index, context)| (context, index))
        .collect::<HashMap<_, _>>();
    assert_eq!(positions.len(), required.len());
    let mut seen = vec![false; required.len()];
    let mut reported = !required.is_empty();
    for (context, verdicts) in reports {
        let index = *positions
            .get(&context)
            .expect("a reverse report belongs to the required context domain");
        assert!(!seen[index], "a required reverse context reports once");
        seen[index] = true;
        reported &= !verdicts.is_empty();
        reduced.every_context_closed &= !verdicts.is_empty();
        for verdict in verdicts {
            reduced.every_context_closed &= verdict.closes_site;
            match reduced.closure.as_mut() {
                Some(closure) => closure.meet(verdict.closure),
                None => reduced.closure = Some(verdict.closure),
            }
            match verdict.relation {
                ReverseTargetRelation::Matches => reduced.binding.push(verdict.answer),
                ReverseTargetRelation::Excluded => reduced.rejecting.push(verdict.answer),
                ReverseTargetRelation::Undecided => reduced.undecided.push(verdict.answer),
            }
        }
    }
    if !reported || seen.iter().any(|seen| !seen) {
        reduced.every_context_closed = false;
        reduced.closure = None;
    }
    reduced
}

/// Analysis outcomes remain typed until the consumer's existing boundary.
#[doc(hidden)]
pub enum ReverseBatch<T, L> {
    Ready(T),
    Bounded(L),
    Stale(SelectedResolutionStale),
    Unavailable(SelectedResolutionUnavailable),
    UnsupportedContext,
    TimeStopped,
    Cancelled {
        stage: ReverseCancellationStage,
        completion: ResolutionCompletion,
    },
}

impl<T, L> ReverseBatch<T, L> {
    pub(crate) fn map<U>(self, f: impl FnOnce(T) -> U) -> ReverseBatch<U, L> {
        match self {
            Self::Ready(value) => ReverseBatch::Ready(f(value)),
            Self::Bounded(limit) => ReverseBatch::Bounded(limit),
            Self::Stale(reason) => ReverseBatch::Stale(reason),
            Self::Unavailable(reason) => ReverseBatch::Unavailable(reason),
            Self::UnsupportedContext => ReverseBatch::UnsupportedContext,
            Self::TimeStopped => ReverseBatch::TimeStopped,
            Self::Cancelled { stage, completion } => ReverseBatch::Cancelled { stage, completion },
        }
    }
    pub(crate) fn map_limit<M>(self, f: impl FnOnce(L) -> M) -> ReverseBatch<T, M> {
        match self {
            Self::Ready(value) => ReverseBatch::Ready(value),
            Self::Bounded(limit) => ReverseBatch::Bounded(f(limit)),
            Self::Stale(reason) => ReverseBatch::Stale(reason),
            Self::Unavailable(reason) => ReverseBatch::Unavailable(reason),
            Self::UnsupportedContext => ReverseBatch::UnsupportedContext,
            Self::TimeStopped => ReverseBatch::TimeStopped,
            Self::Cancelled { stage, completion } => ReverseBatch::Cancelled { stage, completion },
        }
    }
}

impl<T, L> From<SelectedResolutionOperationOutcome<T>> for ReverseBatch<T, L> {
    fn from(value: SelectedResolutionOperationOutcome<T>) -> Self {
        match value {
            SelectedResolutionOperationOutcome::Native(value) => Self::Ready(value),
            SelectedResolutionOperationOutcome::Stale(reason) => Self::Stale(reason),
            SelectedResolutionOperationOutcome::Unavailable(reason) => Self::Unavailable(reason),
            SelectedResolutionOperationOutcome::Cancelled(completion) => Self::Cancelled {
                stage: ReverseCancellationStage::Projection,
                completion,
            },
        }
    }
}

/// Explicit association is retained even when one locator has several meanings.
#[doc(hidden)]
pub enum ReverseSessionReport<A> {
    Found {
        locator: SelectedSemanticLocator,
        meanings: Vec<(SemanticId, Vec<A>)>,
    },
    Missing {
        locator: SelectedSemanticLocator,
    },
}

#[cfg(any(test, feature = "test-support"))]
impl<A> ReverseSessionReport<A> {
    #[doc(hidden)]
    pub fn answers_mut(&mut self) -> impl Iterator<Item = &mut A> {
        let meanings = match self {
            Self::Found { meanings, .. } => meanings.as_mut_slice(),
            Self::Missing { .. } => &mut [],
        };
        meanings.iter_mut().flat_map(|(_, answers)| answers)
    }
    #[doc(hidden)]
    pub fn into_answers(self) -> impl Iterator<Item = A> {
        let meanings = match self {
            Self::Found { meanings, .. } => meanings,
            Self::Missing { .. } => Vec::new(),
        };
        meanings.into_iter().flat_map(|(_, answers)| answers)
    }
}

pub(crate) type ReverseSessionOutcome<A, L> = Result<ReverseBatch<Vec<ReverseSessionReport<A>>, L>>;

/// Scoped stage hooks hold language guards without storing self-references.
pub(super) trait ReverseScopedLifecycle {
    type Answer;
    type Limit;
    fn blueprint(
        &mut self,
        context: SelectedResolutionContextInputs,
    ) -> Result<ReverseBatch<SelectedFactOperationBlueprint, Self::Limit>>;
    fn register(
        &mut self,
        blueprint: &SelectedFactOperationBlueprint,
    ) -> Result<ReverseBatch<(), Self::Limit>>;
    fn locate(
        &mut self,
        locator: &SelectedSemanticLocator,
    ) -> Result<ReverseBatch<LocatedSemantics, Self::Limit>>;
    fn with_evaluator<T>(
        &mut self,
        blueprint: &SelectedFactOperationBlueprint,
        run: impl FnOnce(
            &mut dyn ReverseSessionEvaluator<Answer = Self::Answer, Limit = Self::Limit>,
        ) -> Result<ReverseBatch<T, Self::Limit>>,
    ) -> Result<ReverseBatch<T, Self::Limit>>;
}

/// Language hooks own preparation, scope and charging; shared code owns traversal.
pub(super) trait ReverseLifecycle {
    type Answer;
    type Limit;
    type Prepared;
    type Scoped<'a>: ReverseScopedLifecycle<Answer = Self::Answer, Limit = Self::Limit>
    where
        Self: 'a;
    fn prepare(
        &mut self,
        locators: &[&SelectedSemanticLocator],
    ) -> Result<ReverseBatch<Self::Prepared, Self::Limit>>;
    fn validate(
        &mut self,
        prepared: &Self::Prepared,
    ) -> Result<ReverseBatch<SelectedResolutionContextInputs, Self::Limit>>;
    fn with_scope<'a, T>(
        &'a mut self,
        prepared: &'a Self::Prepared,
        run: impl FnOnce(&mut Self::Scoped<'a>) -> Result<ReverseBatch<T, Self::Limit>>,
    ) -> Result<ReverseBatch<T, Self::Limit>>;
    fn finish(
        &mut self,
        reports: Vec<ReverseSessionReport<Self::Answer>>,
    ) -> ReverseSessionOutcome<Self::Answer, Self::Limit>;
}

pub(crate) trait ReverseSessionEvaluator {
    type Answer;
    type Limit;
    fn evaluate(
        &mut self,
        locator: &SelectedSemanticLocator,
        semantic: SemanticId,
    ) -> Result<ReverseBatch<Vec<Self::Answer>, Self::Limit>>;
}

/// Closure adapter keeps the forward provider's concrete borrowing types local.
pub(crate) struct ReverseEvaluatorFn<A, L, F> {
    pub(crate) run: F,
    pub(crate) marker: std::marker::PhantomData<fn() -> (A, L)>,
}
impl<A, L, F> ReverseSessionEvaluator for ReverseEvaluatorFn<A, L, F>
where
    F: FnMut(&SelectedSemanticLocator, SemanticId) -> Result<ReverseBatch<Vec<A>, L>>,
{
    type Answer = A;
    type Limit = L;
    fn evaluate(
        &mut self,
        locator: &SelectedSemanticLocator,
        semantic: SemanticId,
    ) -> Result<ReverseBatch<Vec<A>, L>> {
        (self.run)(locator, semantic)
    }
}

macro_rules! reverse_ready {
    ($value:expr) => {
        match $value? {
            ReverseBatch::Ready(value) => value,
            ReverseBatch::Bounded(limit) => return Ok(ReverseBatch::Bounded(limit)),
            ReverseBatch::Stale(reason) => return Ok(ReverseBatch::Stale(reason)),
            ReverseBatch::Unavailable(reason) => return Ok(ReverseBatch::Unavailable(reason)),
            ReverseBatch::UnsupportedContext => return Ok(ReverseBatch::UnsupportedContext),
            ReverseBatch::TimeStopped => return Ok(ReverseBatch::TimeStopped),
            ReverseBatch::Cancelled { stage, completion } => {
                return Ok(ReverseBatch::Cancelled { stage, completion })
            }
        }
    };
}

/// Reports carry indices into one blob's independently enumerated context arena.
pub(crate) struct ReverseSemanticAnswer<A> {
    pub(crate) semantic: SemanticId,
    pub(crate) answer: A,
}

pub(crate) struct ReverseContextSite<A> {
    pub(crate) reports: Vec<(usize, Vec<ReverseSemanticAnswer<A>>)>,
}

pub(crate) struct ReverseContextBatch<C, A> {
    pub(crate) required: Vec<C>,
    pub(crate) sites: Vec<ReverseContextSite<A>>,
}

/// A stopped context discards all provisional reports for this blob. Missing
/// reports are retained as missing; only the independent domain defines closure.
pub(crate) fn confirm_reverse_contexts<C, A, L>(
    domain: Vec<C>,
    locators: &[&SelectedSemanticLocator],
    cancellation: &CancellationToken,
    mut confirm: impl FnMut(&C) -> ReverseSessionOutcome<A, L>,
) -> Result<ReverseBatch<ReverseContextBatch<C, A>, L>> {
    let mut sites = (0..locators.len())
        .map(|_| ReverseContextSite {
            reports: Vec::with_capacity(domain.len()),
        })
        .collect::<Vec<_>>();
    let positions = locators
        .iter()
        .enumerate()
        .map(|(index, &locator)| (locator, index))
        .collect::<HashMap<_, _>>();
    for (index, context) in domain.iter().enumerate() {
        if cancellation.is_cancelled() {
            return Ok(ReverseBatch::Cancelled {
                stage: ReverseCancellationStage::Context,
                completion: cancelled_completion(),
            });
        }
        let found = reverse_ready!(confirm(context));
        let mut seen = HashSet::default();
        for report in found {
            match report {
                ReverseSessionReport::Found { locator, meanings } => {
                    let position = *positions
                        .get(&locator)
                        .expect("a context reports only requested sites");
                    assert!(seen.insert(position), "a context reports each site once");
                    let answers = meanings
                        .into_iter()
                        .flat_map(|(semantic, answers)| {
                            answers
                                .into_iter()
                                .map(move |answer| ReverseSemanticAnswer { semantic, answer })
                        })
                        .collect::<Vec<_>>();
                    if !answers.is_empty() {
                        sites[position].reports.push((index, answers));
                    }
                }
                ReverseSessionReport::Missing { .. } => {}
            }
        }
    }
    Ok(ReverseBatch::Ready(ReverseContextBatch {
        required: domain,
        sites,
    }))
}

/// Preserve report order while applying a consumer projection through the same
/// context barrier. Incoming consumers need rich answers rather than closures.
pub(crate) fn project_reverse_context_site<A, V>(
    required: &[usize],
    site: ReverseContextSite<A>,
    mut project: impl FnMut(A) -> V,
) -> ReverseSiteReduction<V, ()> {
    let reports = site
        .reports
        .into_iter()
        .map(|(context, answers)| {
            (
                context,
                answers
                    .into_iter()
                    .map(|answer| ReverseViewVerdict {
                        relation: ReverseTargetRelation::Undecided,
                        closes_site: false,
                        closure: (),
                        answer: project(answer.answer),
                    })
                    .collect(),
            )
        })
        .collect();
    reduce_reverse_site(required, reports)
}

/// One ordered session lifecycle, shared by mutable and immutable language drivers.
pub(super) fn confirm_reverse_session<H: ReverseLifecycle>(
    locators: &[&SelectedSemanticLocator],
    hooks: &mut H,
) -> ReverseSessionOutcome<H::Answer, H::Limit> {
    let prepared = reverse_ready!(hooks.prepare(locators));
    let context = reverse_ready!(hooks.validate(&prepared));
    let reports = reverse_ready!(hooks.with_scope(&prepared, |scope| {
        let blueprint = reverse_ready!(scope.blueprint(context));
        reverse_ready!(scope.register(&blueprint));
        // Lookup precedes evaluator construction and preserves semantic order.
        let mut located = Vec::with_capacity(locators.len());
        for &locator in locators {
            let found = reverse_ready!(scope.locate(locator));
            located.push((locator, found));
        }
        scope.with_evaluator(&blueprint, |evaluator| {
            let mut reports = Vec::with_capacity(located.len());
            for (locator, found) in located {
                match found {
                    LocatedSemantics::Found(semantics) => {
                        assert!(!semantics.is_empty(), "found locator has semantic meanings");
                        let mut meanings = Vec::with_capacity(semantics.len());
                        for semantic in semantics {
                            let answers = reverse_ready!(evaluator.evaluate(locator, semantic));
                            assert!(
                                !answers.is_empty(),
                                "successful semantic reports a binding or exclusion"
                            );
                            meanings.push((semantic, answers));
                        }
                        reports.push(ReverseSessionReport::Found {
                            locator: locator.clone(),
                            meanings,
                        });
                    }
                    LocatedSemantics::Missing => reports.push(ReverseSessionReport::Missing {
                        locator: locator.clone(),
                    }),
                    LocatedSemantics::Cancelled => {
                        unreachable!("cancellation is a typed stage outcome")
                    }
                }
            }
            Ok(ReverseBatch::Ready(reports))
        })
    }));
    hooks.finish(reports)
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) struct ReverseFileContext<T> {
    pub(crate) context: SelectedResolutionContextSet,
    pub(crate) payload: T,
}

pub(crate) struct ReverseFileSession<A> {
    pub(crate) reports: Vec<ReverseSessionReport<A>>,
    pub(crate) inventory: ResolutionCompletion,
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) trait ReverseFileEvaluator {
    type Answer;
    #[allow(clippy::too_many_arguments)]
    fn session(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        language: Language,
        storage_language: &str,
        path: &str,
        locators: &[&SelectedSemanticLocator],
        cancellation: &CancellationToken,
        metrics: &SelectedResolutionContextMetrics,
    ) -> Result<ReverseBatch<ReverseFileSession<Self::Answer>, std::convert::Infallible>>;
}

/// Plural answers retain the evaluator's payload until reduction. Richer
/// projected-target evidence need not fit a singular forward answer.
#[cfg(test)]
pub(crate) trait ReverseEvaluator {
    type Answer;

    fn evaluate(
        &mut self,
        locator: &SelectedSemanticLocator,
        reference: SemanticId,
        context: &ReverseContextWitness,
    ) -> Result<Vec<Self::Answer>>;
}

#[derive(Clone, Copy, Debug)]
#[doc(hidden)]
pub enum ReverseCancellationStage {
    File,
    Context,
    Prepare,
    Blueprint,
    Register,
    Locator,
    Projection,
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) struct ReverseConfirmedReference<A = FactResolutionAnswer> {
    pub(crate) locator: SelectedSemanticLocator,
    pub(crate) answer: A,
}

/// Consumers choose which answer completion they require, how to project a
/// file, and how cancellation is exposed. None changes the shared traversal.
#[cfg(any(test, feature = "test-support"))]
pub(crate) trait ReverseFileReducer {
    type Answer;
    fn target(&self) -> SemanticId;
    fn cancelled(&self, _stage: ReverseCancellationStage) -> Result<()> {
        Ok(())
    }
    fn missing_locator(&self, locator: &SelectedSemanticLocator) -> StoreError;
    fn unavailable(&self) -> ResolutionCompletion {
        ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
            self.target(),
        )])
    }
    fn target_relation(&self, answer: &Self::Answer) -> ReverseTargetRelation;
    fn metadata_evidence(
        &self,
        answer: &Self::Answer,
        relation: ReverseTargetRelation,
    ) -> Option<(ReverseEvidenceOrigin, ResolutionCompletion)>;
    fn binding_completion<'a>(&self, answer: &'a Self::Answer) -> &'a ResolutionCompletion;
    /// Reduce the complete answer set before consumer-specific projection.
    fn reduce_answers(
        &self,
        locator: &SelectedSemanticLocator,
        context: &ReverseContextWitness,
        answers: Vec<Self::Answer>,
        evidence: &mut ReverseEvidence,
        confirmed: &mut Vec<ReverseConfirmedReference<Self::Answer>>,
    ) {
        let verdicts = answers
            .into_iter()
            .enumerate()
            .map(|(index, answer)| {
                let relation = self.target_relation(&answer);
                ReverseViewVerdict {
                    relation,
                    closes_site: matches!(
                        relation,
                        ReverseTargetRelation::Matches | ReverseTargetRelation::Excluded
                    ),
                    closure: (),
                    answer: (index, relation, answer),
                }
            })
            .collect();
        let reduced = reduce_reverse_site(
            std::slice::from_ref(context),
            vec![(context.clone(), verdicts)],
        );
        let mut answers = reduced
            .binding
            .into_iter()
            .chain(reduced.rejecting)
            .chain(reduced.undecided)
            .collect::<Vec<_>>();
        answers.sort_by_key(|(index, _, _)| *index);
        for (_, relation, answer) in answers {
            evidence.confirmations.push(ReverseConfirmation::Answered {
                locator: locator.clone(),
                context: context.clone(),
                target: self.target(),
                relation,
            });
            evidence.binding.record(
                ReverseSubject::Site(locator.clone(), context.clone()),
                ReverseEvidenceOrigin::Binding,
                self.binding_completion(&answer).clone(),
            );
            if let Some((origin, completion)) = self.metadata_evidence(&answer, relation) {
                evidence.metadata.record(
                    ReverseSubject::Site(locator.clone(), context.clone()),
                    origin,
                    completion,
                );
            }
            #[cfg(test)]
            if std::env::var_os("BIFROST_REVERSE_EVIDENCE").is_some() {
                eprintln!("REVERSE-FORWARD {locator:?}");
            }
            confirmed.push(ReverseConfirmedReference {
                locator: locator.clone(),
                answer,
            });
        }
    }
    fn file(
        &mut self,
        operation: &SelectedResolutionOperation<'_, '_>,
        context: &ReverseContextWitness,
        answers: Vec<ReverseConfirmedReference<Self::Answer>>,
        axes: &mut ReverseEvidence,
        cancellation: &CancellationToken,
    ) -> Result<bool>;
}

/// Cancellation inside the forward callback deliberately remains completion
/// evidence; consumers historically discard that file's partial answers.
/// Cancellation in the surrounding lifecycle goes through the reducer.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn confirm_reverse_nominations<A>(
    operation: &SelectedResolutionOperation<'_, '_>,
    nominations: &[ReverseNomination],
    axes: &mut ReverseEvidence,
    adapter: &impl ReverseFileEvaluator<Answer = A>,
    reducer: &mut impl ReverseFileReducer<Answer = A>,
    cancellation: &CancellationToken,
    context_metrics: &SelectedResolutionContextMetrics,
) -> Result<bool> {
    execute_reverse_inline(|| {
        confirm_reverse_partition(
            operation,
            nominations,
            axes,
            adapter,
            reducer,
            cancellation,
            context_metrics,
        )
    })
}

#[cfg(any(test, feature = "test-support"))]
fn confirm_reverse_partition<A>(
    operation: &SelectedResolutionOperation<'_, '_>,
    nominations: &[ReverseNomination],
    axes: &mut ReverseEvidence,
    adapter: &impl ReverseFileEvaluator<Answer = A>,
    reducer: &mut impl ReverseFileReducer<Answer = A>,
    cancellation: &CancellationToken,
    context_metrics: &SelectedResolutionContextMetrics,
) -> Result<bool> {
    let mut groups = HashMap::<(String, String), Vec<&ReverseNomination>>::default();
    for nomination in nominations {
        for link in &nomination.obligations {
            let axis = match link.obligation.axis {
                ReverseEvidenceAxis::Enumeration => &axes.enumeration,
                ReverseEvidenceAxis::Binding => &axes.binding,
                ReverseEvidenceAxis::Metadata => &axes.metadata,
            };
            axis.assert_obligation(&link.obligation);
        }
        groups
            .entry((
                nomination.locator.storage_language().to_owned(),
                nomination.locator.relative_path().to_owned(),
            ))
            .or_default()
            .push(nomination);
    }
    let mut groups = groups.into_iter().flat_map(|((language, path), rows)| {
        let mut contexts = HashMap::<ReverseContextWitness, Vec<&ReverseNomination>>::default();
        for row in rows {
            contexts.entry(row.context.clone()).or_default().push(row);
        }
        contexts
            .into_iter()
            .map(move |(context, rows)| ((language.clone(), path.clone(), context), rows))
    });
    let mut groups = groups.by_ref().collect::<Vec<_>>();
    groups.sort_by(|left, right| {
        (&left.0.0, &left.0.1, left.0.2.mount, left.0.2.blob).cmp(&(
            &right.0.0,
            &right.0.1,
            right.0.2.mount,
            right.0.2.blob,
        ))
    });
    let files = groups
        .into_iter()
        .enumerate()
        .map(|(index, payload)| ReverseFile {
            range: index..index + 1,
            payload,
        });
    let mut hooks = ReverseNominationFiles {
        operation,
        axes,
        adapter,
        reducer,
        cancellation,
        context_metrics,
    };
    let progress = confirm_reverse_files(files, 0, &mut hooks)?;
    Ok(matches!(progress.stopped, ReverseBlobControl::Continue))
}

#[cfg(any(test, feature = "test-support"))]
type ReverseNominationFile<'a> = (
    (String, String, ReverseContextWitness),
    Vec<&'a ReverseNomination>,
);

#[cfg(any(test, feature = "test-support"))]
struct ReverseNominationFiles<'a, 'store, 'input, E, R> {
    operation: &'a SelectedResolutionOperation<'store, 'input>,
    axes: &'a mut ReverseEvidence,
    adapter: &'a E,
    reducer: &'a mut R,
    cancellation: &'a CancellationToken,
    context_metrics: &'a SelectedResolutionContextMetrics,
}

#[cfg(any(test, feature = "test-support"))]
impl<'row, E, R> ReverseFileHooks<ReverseNominationFile<'row>>
    for ReverseNominationFiles<'_, '_, '_, E, R>
where
    E: ReverseFileEvaluator,
    R: ReverseFileReducer<Answer = E::Answer>,
{
    type Session = ReverseFileSession<E::Answer>;
    type Limit = std::convert::Infallible;
    fn cancellation(&self) -> &CancellationToken {
        self.cancellation
    }
    fn boundary(&mut self) -> Result<ReverseBatch<(), Self::Limit>> {
        // This adapter has never imposed a soft file deadline.
        Ok(if self.cancellation.is_cancelled() {
            ReverseBatch::Cancelled {
                stage: ReverseCancellationStage::File,
                completion: cancelled_completion(),
            }
        } else {
            ReverseBatch::Ready(())
        })
    }
    fn confirm(
        &mut self,
        file: &mut ReverseFile<ReverseNominationFile<'row>>,
    ) -> Result<ReverseBatch<Self::Session, Self::Limit>> {
        let ((language, path, witness), group) = &mut file.payload;
        group.sort_by(|left, right| left.locator.cmp(&right.locator));
        let mount = self
            .operation
            .ready
            .inventory
            .mount_record_for_path(language, path)?
            .expect("reverse candidate has a selected mount");
        witness.assert_selected(self.operation);
        assert_eq!(mount.ordinal().get(), witness.mount);
        assert_eq!(mount.blob_id(), witness.blob);
        let mut locators = group.iter().map(|row| &row.locator).collect::<Vec<_>>();
        locators.dedup();
        self.adapter.session(
            self.operation,
            mount.semantic_language(),
            language,
            path,
            &locators,
            self.cancellation,
            self.context_metrics,
        )
    }
    fn commit(
        &mut self,
        file: ReverseFile<ReverseNominationFile<'row>>,
        session: Self::Session,
    ) -> Result<ReverseBlobControl> {
        let ((_, _, witness), _) = file.payload;
        let mut staged = ReverseEvidence::new(self.reducer.target());
        staged.enumeration.record(
            ReverseSubject::Context(witness.clone()),
            ReverseEvidenceOrigin::Context,
            session.inventory,
        );
        let mut confirmed = Vec::new();
        for report in session.reports {
            match report {
                ReverseSessionReport::Found { locator, meanings } => {
                    for (_, answers) in meanings {
                        self.reducer.reduce_answers(
                            &locator,
                            &witness,
                            answers,
                            &mut staged,
                            &mut confirmed,
                        );
                    }
                }
                ReverseSessionReport::Missing { locator } => {
                    return Err(self.reducer.missing_locator(&locator));
                }
            }
        }
        if !self.reducer.file(
            self.operation,
            &witness,
            confirmed,
            &mut staged,
            self.cancellation,
        )? {
            self.reducer
                .cancelled(ReverseCancellationStage::Projection)?;
            return Ok(ReverseBlobControl::Cancelled);
        }
        drop(append_reverse_evidence(self.axes, staged));
        Ok(ReverseBlobControl::Continue)
    }
    fn stopped(
        &mut self,
        file: ReverseFile<ReverseNominationFile<'row>>,
        outcome: ReverseBatch<std::convert::Infallible, Self::Limit>,
    ) -> Result<ReverseBlobControl> {
        match outcome {
            ReverseBatch::Ready(never) | ReverseBatch::Bounded(never) => match never {},
            ReverseBatch::UnsupportedContext | ReverseBatch::Unavailable(_) => {
                let ((_, _, witness), group) = file.payload;
                for nomination in group {
                    self.axes
                        .confirmations
                        .push(ReverseConfirmation::Unavailable {
                            locator: nomination.locator.clone(),
                            context: witness.clone(),
                            target: self.reducer.target(),
                        });
                }
                let incomplete = self.reducer.unavailable();
                self.axes.enumeration.record(
                    ReverseSubject::Context(witness.clone()),
                    ReverseEvidenceOrigin::Context,
                    incomplete.clone(),
                );
                self.axes.binding.record(
                    ReverseSubject::Context(witness),
                    ReverseEvidenceOrigin::Context,
                    incomplete,
                );
                Ok(ReverseBlobControl::Continue)
            }
            ReverseBatch::Cancelled { stage, .. } => {
                self.reducer.cancelled(stage)?;
                Ok(ReverseBlobControl::Cancelled)
            }
            ReverseBatch::TimeStopped | ReverseBatch::Stale(_) => unreachable!(
                "unbounded selected nomination session has no deadline or stale preparation"
            ),
        }
    }
}

pub(crate) fn append_reverse_evidence(
    into: &mut ReverseEvidence,
    other: ReverseEvidence,
) -> HashMap<ReverseObligationId, ReverseObligationId> {
    fn append(
        into: &mut AttributedResolutionCompletion,
        other: AttributedResolutionCompletion,
    ) -> HashMap<ReverseObligationId, ReverseObligationId> {
        let mut translation = HashMap::default();
        for row in other.obligations {
            let new = into.record(row.subject().clone(), row.origin, row.completion.clone());
            assert!(translation.insert(row.id, new).is_none());
        }
        for discharge in other.discharges {
            let new = translation
                .get(&discharge.obligation)
                .expect("imported discharge names an imported obligation")
                .clone();
            into.discharge(new, discharge.origin);
        }
        translation
    }
    let mut handles = append(&mut into.enumeration, other.enumeration);
    handles.extend(append(&mut into.binding, other.binding));
    handles.extend(append(&mut into.metadata, other.metadata));
    into.confirmations.extend(other.confirmations);
    handles
}

/// Context and domain indices resolve through their transported request arena.
pub(crate) struct ReverseSiteEvidence {
    pub(crate) target: SemanticId,
    pub(crate) input_ordinal: usize,
    pub(crate) locator: SelectedSemanticLocator,
    pub(crate) context: usize,
    pub(crate) domain: Vec<usize>,
    pub(crate) obligations: Vec<ReverseObligationId>,
    pub(crate) meanings: Vec<SemanticId>,
}

pub(crate) struct ReverseProofBatch<C> {
    pub(crate) obligation_contexts: HashMap<ReverseObligationId, usize>,
    pub(crate) required: Vec<ReverseContextId<C>>,
    pub(crate) sites: Vec<ReverseSiteEvidence>,
    pub(crate) evidence: ReverseEvidence,
    context_buckets: HashMap<u64, Vec<usize>>,
}

impl<C: Eq + std::hash::Hash> ReverseProofBatch<C> {
    pub(crate) fn new(target: SemanticId, required: Vec<ReverseContextId<C>>) -> Self {
        let mut proof = Self {
            required: Vec::new(),
            sites: Vec::new(),
            obligation_contexts: HashMap::default(),
            evidence: ReverseEvidence::new(target),
            context_buckets: HashMap::default(),
        };
        proof.extend_contexts(required);
        proof
    }

    /// Hash buckets are only an index: full structured equality is authoritative.
    pub(crate) fn extend_contexts(&mut self, contexts: Vec<ReverseContextId<C>>) -> Vec<usize> {
        use std::hash::{Hash, Hasher};
        contexts
            .into_iter()
            .map(|context| {
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                context.hash(&mut hasher);
                let bucket = self.context_buckets.entry(hasher.finish()).or_default();
                if let Some(&index) = bucket
                    .iter()
                    .find(|&&index| self.required[index] == context)
                {
                    index
                } else {
                    let index = self.required.len();
                    self.required.push(context);
                    bucket.push(index);
                    index
                }
            })
            .collect()
    }
}

type ReverseViewReports<A, L> = Vec<(ReverseSiteEvidence, Vec<ReverseViewVerdict<A, L>>)>;

pub(crate) struct ReverseClassifiedView<A, L> {
    pub(crate) verdict: ReverseViewVerdict<A, L>,
    pub(crate) applicability: ResolutionCompletion,
    pub(crate) binding: ResolutionCompletion,
}

/// Shared evidence assembly surrounds only the language's per-answer classifier.
pub(crate) fn classify_reverse_context_site<C, A, V, L: ReverseClosure>(
    proof: &mut ReverseProofBatch<C>,
    locator: &SelectedSemanticLocator,
    required: &[usize],
    site: ReverseContextSite<A>,
    mut classify: impl FnMut(A) -> Result<Option<ReverseClassifiedView<V, L>>>,
) -> Result<Option<ReverseSiteReduction<V, L>>> {
    let target = proof.evidence.enumeration.target;
    let mut reports = Vec::with_capacity(site.reports.len());
    for (context, answers) in site.reports {
        let mut verdicts = Vec::with_capacity(answers.len());
        let mut obligations = Vec::new();
        let mut meanings = Vec::new();
        for answer in answers {
            let meaning = answer.semantic;
            let Some(answer) = classify(answer.answer)? else {
                return Ok(None);
            };
            meanings.push(meaning);
            let subject =
                ReverseSubject::Site(locator.clone(), proof.required[context].selected.clone());
            obligations.push(proof.evidence.enumeration.record(
                subject.clone(),
                ReverseEvidenceOrigin::Binding,
                answer.applicability,
            ));
            obligations.push(proof.evidence.binding.record(
                subject,
                ReverseEvidenceOrigin::Binding,
                answer.binding,
            ));
            proof
                .evidence
                .confirmations
                .push(ReverseConfirmation::Answered {
                    locator: locator.clone(),
                    context: proof.required[context].selected.clone(),
                    target,
                    relation: answer.verdict.relation,
                });
            verdicts.push(answer.verdict);
        }
        for handle in &obligations {
            assert!(
                proof
                    .obligation_contexts
                    .insert(handle.clone(), context)
                    .is_none()
            );
        }
        reports.push((
            ReverseSiteEvidence {
                target,
                input_ordinal: 0,
                locator: locator.clone(),
                context,
                domain: required.to_vec(),
                obligations,
                meanings,
            },
            verdicts,
        ));
    }
    Ok(Some(reduce_reverse_evidenced_site(
        proof, required, reports,
    )))
}

/// Required indices come from the site's file domain, independently of reports.
pub(crate) fn reduce_reverse_evidenced_site<C, A, L: ReverseClosure>(
    proof: &mut ReverseProofBatch<C>,
    required: &[usize],
    reports: ReverseViewReports<A, L>,
) -> ReverseSiteReduction<A, L> {
    let domain = required.iter().copied().collect::<HashSet<_>>();
    assert_eq!(domain.len(), required.len());
    assert!(required.iter().all(|&index| index < proof.required.len()));
    let mut links = Vec::new();
    let mut views = Vec::with_capacity(reports.len());
    for (site, verdicts) in reports {
        assert_eq!(site.target, proof.evidence.enumeration.target);
        assert_eq!(site.domain, required);
        assert!(
            domain.contains(&site.context),
            "report belongs to the exact file domain"
        );
        let context = &proof.required[site.context];
        for handle in &site.obligations {
            assert_eq!(
                proof.obligation_contexts.get(handle),
                Some(&site.context),
                "obligation belongs to its exact required context"
            );
            let axis = match handle.axis {
                ReverseEvidenceAxis::Enumeration => &proof.evidence.enumeration,
                ReverseEvidenceAxis::Binding => &proof.evidence.binding,
                ReverseEvidenceAxis::Metadata => &proof.evidence.metadata,
            };
            axis.assert_obligation(handle);
            assert_eq!(
                handle.subject,
                ReverseSubject::Site(site.locator.clone(), context.selected.clone())
            );
        }
        links.extend(
            site.obligations
                .iter()
                .filter(|handle| handle.axis == ReverseEvidenceAxis::Enumeration)
                .cloned(),
        );
        views.push((site.context, verdicts));
        proof.sites.push(site);
    }
    let reduced = reduce_reverse_site(required, views);
    if reduced.every_context_closed {
        for handle in links {
            proof
                .evidence
                .enumeration
                .discharge(handle, ReverseEvidenceOrigin::Binding);
        }
    }
    reduced
}

pub(crate) fn append_reverse_proof<C: Eq + std::hash::Hash>(
    into: &mut ReverseProofBatch<C>,
    other: ReverseProofBatch<C>,
) {
    let handles = append_reverse_evidence(&mut into.evidence, other.evidence);
    let contexts = into.extend_contexts(other.required);
    into.obligation_contexts
        .extend(
            other
                .obligation_contexts
                .into_iter()
                .map(|(handle, context)| {
                    (
                        handles
                            .get(&handle)
                            .expect("imported context names an imported obligation")
                            .clone(),
                        contexts[context],
                    )
                }),
        );
    into.sites.extend(other.sites.into_iter().map(|mut site| {
        site.context = contexts[site.context];
        site.domain = site
            .domain
            .into_iter()
            .map(|index| contexts[index])
            .collect();
        site.obligations = site
            .obligations
            .into_iter()
            .map(|handle| {
                handles
                    .get(&handle)
                    .expect("imported site names an imported obligation")
                    .clone()
            })
            .collect();
        site
    }));
}

/// Cheap applicability certificates use the same independent file-domain indices.
pub(crate) fn exclude_reverse_site<C>(
    proof: &mut ReverseProofBatch<C>,
    locator: &SelectedSemanticLocator,
    required: &[usize],
    completion: ResolutionCompletion,
) {
    let target = proof.evidence.enumeration.target;
    let reports = required
        .iter()
        .map(|&context| {
            let handle = proof.evidence.enumeration.record(
                ReverseSubject::Site(locator.clone(), proof.required[context].selected.clone()),
                ReverseEvidenceOrigin::Nomination,
                completion.clone(),
            );
            assert!(
                proof
                    .obligation_contexts
                    .insert(handle.clone(), context)
                    .is_none()
            );
            (
                ReverseSiteEvidence {
                    target,
                    input_ordinal: 0,
                    locator: locator.clone(),
                    context,
                    domain: required.to_vec(),
                    obligations: vec![handle],
                    meanings: Vec::new(),
                },
                vec![ReverseViewVerdict {
                    relation: ReverseTargetRelation::Excluded,
                    closes_site: completion == ResolutionCompletion::Complete,
                    closure: (),
                    answer: (),
                }],
            )
        })
        .collect();
    drop(reduce_reverse_evidenced_site(proof, required, reports));
}

/// Re-intern meanings, selected mounts and opaque handles together, never by ordinal arithmetic.
pub(crate) fn translate_reverse_proof<C: Eq + std::hash::Hash>(
    batch: ReverseProofBatch<C>,
    translation: &impl crate::analyzer::resolution::ResolutionIdentityTranslation,
) -> ReverseProofBatch<C> {
    use crate::analyzer::resolution::SpliceMount;
    fn witness(
        mut value: ReverseContextWitness,
        translation: &impl crate::analyzer::resolution::ResolutionIdentityTranslation,
    ) -> ReverseContextWitness {
        value.mount = translation
            .fragment(crate::analyzer::resolution::BindingFragmentId::at_ordinal(
                value.mount,
            ))
            .ordinal();
        value
    }
    fn subject(
        value: ReverseSubject,
        translation: &impl crate::analyzer::resolution::ResolutionIdentityTranslation,
    ) -> ReverseSubject {
        match value {
            ReverseSubject::Target(target) => ReverseSubject::Target(translation.semantic(target)),
            ReverseSubject::Context(context) => {
                ReverseSubject::Context(witness(context, translation))
            }
            ReverseSubject::Site(locator, context) => {
                ReverseSubject::Site(locator, witness(context, translation))
            }
        }
    }
    let mut evidence =
        ReverseEvidence::new(translation.semantic(batch.evidence.enumeration.target));
    let mut handles = HashMap::default();
    for (old, new) in [
        (batch.evidence.enumeration, &mut evidence.enumeration),
        (batch.evidence.binding, &mut evidence.binding),
        (batch.evidence.metadata, &mut evidence.metadata),
    ] {
        for row in old.obligations {
            let translated = new.record(
                subject(row.id.subject.clone(), translation),
                row.origin,
                row.completion.splice(translation),
            );
            assert!(handles.insert(row.id, translated).is_none());
        }
        for discharge in old.discharges {
            let translated = handles
                .get(&discharge.obligation)
                .expect("worker discharge names an imported obligation")
                .clone();
            new.discharge(translated, discharge.origin);
        }
    }
    evidence.confirmations = batch
        .evidence
        .confirmations
        .into_iter()
        .map(|row| match row {
            ReverseConfirmation::Answered {
                locator,
                context,
                target,
                relation,
            } => ReverseConfirmation::Answered {
                locator,
                context: witness(context, translation),
                target: translation.semantic(target),
                relation,
            },
            ReverseConfirmation::Unavailable {
                locator,
                context,
                target,
            } => ReverseConfirmation::Unavailable {
                locator,
                context: witness(context, translation),
                target: translation.semantic(target),
            },
        })
        .collect();
    let mut translated = ReverseProofBatch::new(evidence.enumeration.target, Vec::new());
    let contexts = translated.extend_contexts(
        batch
            .required
            .into_iter()
            .map(|context| ReverseContextId {
                selected: witness(context.selected, translation),
                view: context.view,
            })
            .collect(),
    );
    translated.obligation_contexts = batch
        .obligation_contexts
        .into_iter()
        .map(|(handle, context)| {
            (
                handles
                    .get(&handle)
                    .expect("worker context names an imported obligation")
                    .clone(),
                contexts[context],
            )
        })
        .collect();
    translated.sites = batch
        .sites
        .into_iter()
        .map(|site| ReverseSiteEvidence {
            target: translation.semantic(site.target),
            input_ordinal: site.input_ordinal,
            meanings: site
                .meanings
                .into_iter()
                .map(|id| translation.semantic(id))
                .collect(),
            locator: site.locator,
            context: contexts[site.context],
            domain: site
                .domain
                .into_iter()
                .map(|index| contexts[index])
                .collect(),
            obligations: site
                .obligations
                .into_iter()
                .map(|handle| {
                    handles
                        .get(&handle)
                        .expect("worker site link names an imported obligation")
                        .clone()
                })
                .collect(),
        })
        .collect();
    translated.evidence = evidence;
    translated
}

/// Select original typed obligations after exact dependency discharges. Empty
/// input is neutral here; only the producer can establish that its answer is complete.
pub(crate) fn reverse_completion_for_obligations(
    evidence: &ReverseEvidence,
    handles: &[ReverseObligationId],
) -> ResolutionCompletion {
    for handle in handles {
        match handle.axis {
            ReverseEvidenceAxis::Enumeration => &evidence.enumeration,
            ReverseEvidenceAxis::Binding => &evidence.binding,
            ReverseEvidenceAxis::Metadata => &evidence.metadata,
        }
        .assert_obligation(handle);
    }
    let handles = handles.iter().collect::<HashSet<_>>();
    [&evidence.enumeration, &evidence.binding, &evidence.metadata]
        .into_iter()
        .fold(ResolutionCompletion::Complete, |completion, axis| {
            completion.combine(&axis.completion_for(|row| handles.contains(&row.id)))
        })
}

/// Render only request evidence; language-specific names are supplied by its hook.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn observe_reverse_proof<C>(
    batch: &ReverseProofBatch<C>,
    mut view: impl FnMut(&C) -> serde_json::Value,
    mut names: impl FnMut(&ResolutionCompletion) -> Result<serde_json::Value>,
) -> Result<serde_json::Value> {
    fn handle(value: &ReverseObligationId) -> serde_json::Value {
        serde_json::json!({"axis":format!("{:?}",value.axis),"target":format!("{:?}",value.target),
            "subject":format!("{:?}",value.subject),"ordinal":value.ordinal})
    }
    let mut contexts = Vec::new();
    for context in &batch.required {
        contexts.push(serde_json::json!({"selected":format!("{:?}",context.selected),"view":view(&context.view)}));
    }
    let mut rows = Vec::new();
    for axis in [
        &batch.evidence.enumeration,
        &batch.evidence.binding,
        &batch.evidence.metadata,
    ] {
        for row in &axis.obligations {
            rows.push(
                serde_json::json!({"obligation":handle(&row.id),"origin":format!("{:?}",row.origin),
                "completion":format!("{:?}",row.completion),"names":names(&row.completion)?,
                "discharged":axis.discharges.iter().any(|discharge| discharge.obligation==row.id)}),
            );
        }
    }
    let sites = batch
        .sites
        .iter()
        .map(|site| {
            serde_json::json!({"target":format!("{:?}",site.target),
        "input_ordinal":site.input_ordinal,"meanings":format!("{:?}",site.meanings),"locator":format!("{:?}",site.locator),
        "selected":format!("{:?}",batch.required[site.context].selected),"view":view(&batch.required[site.context].view),
        "obligations":site.obligations.iter().map(handle).collect::<Vec<_>>() })
        })
        .collect::<Vec<_>>();
    Ok(serde_json::json!({"contexts":contexts,"sites":sites,"rows":rows}))
}

/// Dependency prerequisites are language-independent; certification supplies exact handles.
pub(crate) struct ReverseDependency<K, P> {
    pub(crate) dependent: K,
    pub(crate) prerequisites: Vec<K>,
    pub(crate) proof: P,
}

pub(crate) fn close_reverse_dependencies<K: Copy + Eq + std::hash::Hash, P>(
    dependencies: &[ReverseDependency<K, P>],
    established: &HashSet<K>,
    evidence: &mut ReverseEvidence,
    mut certify: impl FnMut(&ReverseDependency<K, P>) -> Result<Option<Vec<ReverseObligationId>>>,
) -> Result<HashSet<K>> {
    let mut closed = HashSet::default();
    for dependency in dependencies {
        assert!(
            !dependency.prerequisites.is_empty(),
            "a dependency has concrete prerequisites"
        );
        if dependency
            .prerequisites
            .iter()
            .all(|key| established.contains(key))
            && let Some(handles) = certify(dependency)?
        {
            for handle in handles {
                match handle.axis {
                    ReverseEvidenceAxis::Enumeration => &mut evidence.enumeration,
                    ReverseEvidenceAxis::Binding => &mut evidence.binding,
                    ReverseEvidenceAxis::Metadata => &mut evidence.metadata,
                }
                .discharge(handle, ReverseEvidenceOrigin::Binding);
            }
            closed.insert(dependency.dependent);
        }
    }
    Ok(closed)
}

/// Missing projection data is distinct from a proved absence of an owner.
#[derive(Clone, Debug)]
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub enum ReverseEnclosingUnit {
    Unit(CodeUnit),
    NoEnclosingUnit,
    MissingSource,
}

#[cfg(any(test, feature = "test-support"))]
impl ReverseEnclosingUnit {
    #[doc(hidden)]
    pub fn into_unit(self) -> Result<Option<CodeUnit>> {
        match self {
            Self::Unit(unit) => Ok(Some(unit)),
            Self::NoEnclosingUnit => Ok(None),
            Self::MissingSource => Err(StoreError::corrupt(
                "selected reverse caller owner is absent from selected source",
            )),
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub struct ReverseOwnedReference {
    #[doc(hidden)]
    pub locator: SelectedSemanticLocator,
    #[doc(hidden)]
    pub answer: FactResolutionAnswer,
    #[doc(hidden)]
    pub owner: ReverseEnclosingUnit,
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) struct ReverseOwnerProjection {
    pub(crate) references: Vec<ReverseOwnedReference>,
}

/// Project forward owners through the shared native declaration bridge, while
/// retaining the consumer's historical projection-completion policy.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn project_reverse_owners(
    operation: &SelectedResolutionOperation<'_, '_>,
    context: &ReverseContextWitness,
    answers: Vec<ReverseConfirmedReference>,
    target: SemanticId,
    evidence: &mut ReverseEvidence,
    cancellation: &CancellationToken,
) -> Result<Option<ReverseOwnerProjection>> {
    let mut references = Vec::with_capacity(answers.len());
    let mut definition_semantics = Vec::new();
    for reference in &answers {
        let answer = &reference.answer;
        if let Some(Some(owner)) = answer.reference_owner() {
            definition_semantics.push(owner);
        }
        definition_semantics.extend(answer.binding().targets().iter().copied());
    }
    definition_semantics.sort_unstable();
    definition_semantics.dedup();
    let definitions = match native_units::project_native_definition_units(
        &operation.ready,
        &definition_semantics,
        cancellation,
        &ResolutionSession::unbounded(),
    )? {
        SelectedNativeDefinitions::Ready(rows) => rows,
        SelectedNativeDefinitions::Unavailable => {
            evidence.metadata.record(
                ReverseSubject::Context(context.clone()),
                ReverseEvidenceOrigin::Projection,
                ResolutionCompletion::incomplete(
                    definition_semantics
                        .iter()
                        .copied()
                        .map(ResolutionIncompleteReason::UnsupportedSemantic),
                ),
            );
            Vec::new()
        }
        SelectedNativeDefinitions::Cancelled => {
            return Ok(None);
        }
    };
    let units = definitions
        .into_iter()
        .filter_map(|(semantic, definition)| match definition {
            SelectedNativeDefinition::Unit(unit) => Some((semantic, unit)),
            SelectedNativeDefinition::Lexical(_) | SelectedNativeDefinition::Intrinsic { .. } => {
                None
            }
        })
        .collect::<HashMap<_, _>>();
    for reference in answers {
        let answer = reference.answer;
        let owner = match answer.reference_owner() {
            Some(None) => ReverseEnclosingUnit::NoEnclosingUnit,
            Some(Some(semantic)) => match units.get(&semantic) {
                Some(unit) => ReverseEnclosingUnit::Unit(unit.clone()),
                None => ReverseEnclosingUnit::MissingSource,
            },
            None => ReverseEnclosingUnit::MissingSource,
        };
        if matches!(owner, ReverseEnclosingUnit::MissingSource)
            && answer
                .reference_owner()
                .is_some_and(|owner| owner.is_some())
        {
            evidence.metadata.record(
                ReverseSubject::Site(reference.locator.clone(), context.clone()),
                ReverseEvidenceOrigin::Projection,
                ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(target),
                ]),
            );
        }
        references.push(ReverseOwnedReference {
            locator: reference.locator,
            answer,
            owner,
        });
    }
    Ok(Some(ReverseOwnerProjection { references }))
}

/// Fixed whole-blob partitions shared by reverse discovery and incoming rechecks.
/// Results remain query-owned and are consumed in partition order.
pub(crate) fn confirmation_partitions(
    admitted: &[(&SelectedSemanticLocator, SemanticId)],
) -> Vec<std::ops::Range<usize>> {
    // Four complete blobs per partition. Both this count and the sorted
    // locator order are fixed, independent of pool width or completion time.
    let mut partitions = Vec::new();
    let mut start = 0;
    while start < admitted.len() {
        let mut end = start;
        for _ in 0..4 {
            if end == admitted.len() {
                break;
            }
            let path = admitted[end].0.relative_path();
            while end < admitted.len() && admitted[end].0.relative_path() == path {
                end += 1;
            }
        }
        partitions.push(start..end);
        start = end;
    }
    partitions
}

pub(crate) struct ReversePartitionResult<A> {
    pub(crate) range: std::ops::Range<usize>,
    pub(crate) outcome: Option<SelectedResolutionOperationOutcome<A>>,
}

/// Consumer projection supplies only payload policy; ordering and stop assembly
/// are the same for references and incoming-call rechecks.
pub(crate) fn fold_reverse_partitions<A, T>(
    results: Vec<ReversePartitionResult<A>>,
    mut value: T,
    mut merge: impl FnMut(&mut T, A),
    mut undispatched: impl FnMut(&mut T, std::ops::Range<usize>),
) -> SelectedResolutionOperationOutcome<T> {
    for result in results {
        match result.outcome {
            None => undispatched(&mut value, result.range),
            Some(SelectedResolutionOperationOutcome::Native(partition)) => {
                merge(&mut value, partition)
            }
            Some(SelectedResolutionOperationOutcome::Unavailable(reason)) => {
                return SelectedResolutionOperationOutcome::Unavailable(reason);
            }
            Some(SelectedResolutionOperationOutcome::Stale(reason)) => {
                return SelectedResolutionOperationOutcome::Stale(reason);
            }
            Some(SelectedResolutionOperationOutcome::Cancelled(completion)) => {
                return SelectedResolutionOperationOutcome::Cancelled(completion);
            }
        }
    }
    SelectedResolutionOperationOutcome::Native(value)
}

/// Execute whole-blob work on independent selected readers, or on the owning
/// connection when no reader can be borrowed. The caller supplies checked
/// payload policy; this boundary owns scheduling and identity transport.
pub(crate) fn execute_reverse_partitions<A: WorkerAnswer>(
    selected: &mut SelectedResolutionOperation<'_, '_>,
    admitted: &[(&SelectedSemanticLocator, SemanticId)],
    cancellation: &CancellationToken,
    worker: impl Fn(
        &mut SelectedResolutionOperation<'_, '_>,
        std::ops::Range<usize>,
    ) -> Result<SelectedResolutionOperationOutcome<A>>
    + Sync,
    inline: impl FnOnce(
        &mut SelectedResolutionOperation<'_, '_>,
    ) -> Result<SelectedResolutionOperationOutcome<A>>,
    anchors: impl Fn(&A) -> Vec<(ResolutionIdentityDigestKey, ResolutionIdentityDigestKey)>,
) -> Result<Vec<ReversePartitionResult<A>>> {
    let partitions = confirmation_partitions(admitted);
    let worker_count = crate::analyzer::default_parallelism().min(partitions.len().max(1));
    if worker_count == 1 || selected.worker_store().uses_single_connection_reads() {
        return Ok(vec![ReversePartitionResult {
            range: 0..admitted.len(),
            outcome: if cancellation.soft_deadline_passed() {
                None
            } else {
                Some(execute_reverse_inline(|| inline(selected))?)
            },
        }]);
    }
    let store = selected.worker_store();
    let input = selected.worker_input();
    let dispatch_order = (0..partitions.len()).collect::<Vec<_>>();
    let mut answers = (0..partitions.len()).map(|_| None).collect::<Vec<_>>();
    let results = schedule_selected_queue(
        store,
        input,
        &partitions,
        &dispatch_order,
        worker_count,
        cancellation,
        |operation, range| worker(operation, range.clone()),
        |index, answer| {
            let anchors = anchors(answer.answer());
            answers[index] = Some(answer.reintern(selected, anchors, cancellation)?);
            Ok(())
        },
    )?;
    let mut imported = Vec::with_capacity(partitions.len());
    for (range, result) in partitions.into_iter().zip(results) {
        let result = match result.transpose()? {
            None => None,
            Some(SelectedResolutionOperationOutcome::Native(())) => {
                Some(SelectedResolutionOperationOutcome::Native(
                    answers[imported.len()]
                        .take()
                        .expect("successful ordered delivery"),
                ))
            }
            Some(SelectedResolutionOperationOutcome::Unavailable(reason)) => {
                Some(SelectedResolutionOperationOutcome::Unavailable(reason))
            }
            Some(SelectedResolutionOperationOutcome::Stale(reason)) => {
                Some(SelectedResolutionOperationOutcome::Stale(reason))
            }
            Some(SelectedResolutionOperationOutcome::Cancelled(completion)) => {
                Some(SelectedResolutionOperationOutcome::Cancelled(completion))
            }
        };
        let successful = matches!(
            &result,
            None | Some(SelectedResolutionOperationOutcome::Native(_))
        );
        imported.push(ReversePartitionResult {
            range,
            outcome: result,
        });
        if !successful {
            break;
        }
    }
    Ok(imported)
}

/// A blob is committed only after both its solve and retention finish.
pub(crate) enum ReverseBlobControl {
    Continue,
    Cancelled,
    TimeBudgetExceeded,
}

pub(crate) struct ReverseBlobProgress {
    pub(crate) next: usize,
    pub(crate) stopped: ReverseBlobControl,
}

pub(crate) struct ReverseFile<F> {
    pub(crate) range: std::ops::Range<usize>,
    pub(crate) payload: F,
}

/// A language owns preparation and projection; the shared facade owns typed
/// outcome dispatch, atomic commit and the ordered file lifecycle.
pub(crate) trait ReverseFileHooks<F> {
    type Session;
    type Limit;
    fn cancellation(&self) -> &CancellationToken;
    fn boundary(&mut self) -> Result<ReverseBatch<(), Self::Limit>> {
        let cancellation = self.cancellation();
        Ok(if cancellation.is_cancelled() {
            ReverseBatch::Cancelled {
                stage: ReverseCancellationStage::File,
                completion: cancelled_completion(),
            }
        } else if cancellation.soft_deadline_passed() {
            ReverseBatch::TimeStopped
        } else {
            ReverseBatch::Ready(())
        })
    }
    fn confirm(
        &mut self,
        file: &mut ReverseFile<F>,
    ) -> Result<ReverseBatch<Self::Session, Self::Limit>>;
    fn commit(
        &mut self,
        file: ReverseFile<F>,
        session: Self::Session,
    ) -> Result<ReverseBlobControl>;
    fn stopped(
        &mut self,
        file: ReverseFile<F>,
        outcome: ReverseBatch<std::convert::Infallible, Self::Limit>,
    ) -> Result<ReverseBlobControl>;
}

pub(crate) fn confirm_reverse_files<F>(
    files: impl IntoIterator<Item = ReverseFile<F>>,
    start: usize,
    hooks: &mut impl ReverseFileHooks<F>,
) -> Result<ReverseBlobProgress> {
    let mut next = start;
    for mut file in files {
        let end = file.range.end;
        let session = match hooks.boundary()? {
            ReverseBatch::Ready(()) => hooks.confirm(&mut file)?,
            other => other.map(|_| unreachable!("ready boundary was handled")),
        };
        let stopped = match session {
            ReverseBatch::Ready(session) => hooks.commit(file, session)?,
            other => hooks.stopped(
                file,
                other.map(|_| unreachable!("ready session was handled")),
            )?,
        };
        if !matches!(stopped, ReverseBlobControl::Continue) {
            return Ok(ReverseBlobProgress { next, stopped });
        }
        next = end;
    }
    Ok(ReverseBlobProgress {
        next,
        stopped: ReverseBlobControl::Continue,
    })
}

/// Whole-blob planning adds no work or cancellation observations; typed file
/// sessions pass through one facade for workers, inline runs and rechecks.
pub(crate) fn execute_reverse_blobs(
    admitted: &[(&SelectedSemanticLocator, SemanticId)],
    range: std::ops::Range<usize>,
    hooks: &mut impl ReverseFileHooks<()>,
) -> Result<ReverseBlobProgress> {
    let mut cursor = range.start;
    let start = cursor;
    let files = std::iter::from_fn(|| {
        if cursor == range.end {
            return None;
        }
        let start = cursor;
        cursor += 1;
        while cursor < range.end
            && admitted[cursor].0.relative_path() == admitted[start].0.relative_path()
        {
            cursor += 1;
        }
        Some(ReverseFile {
            range: start..cursor,
            payload: (),
        })
    });
    confirm_reverse_files(files, start, hooks)
}

/// Evaluators which require the owning connection run exactly one partition.
/// No added cancellation observation may precede their lifecycle's pinned
/// observation points.
fn execute_reverse_inline<A>(work: impl FnOnce() -> Result<A>) -> Result<A> {
    work()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(test)]
    use brokk_bifrost_test_macros::hardwon;

    fn two_root_file() -> (
        Vec<ReverseContextId<&'static str>>,
        SelectedSemanticLocator,
        SemanticId,
    ) {
        let selected = ReverseContextWitness {
            mount: 1,
            blob: 7,
            selection: [0; 32],
            analysis_generation: 0,
        };
        let domain = ["src/lib.rs", "src/main.rs"]
            .into_iter()
            .map(|view| ReverseContextId {
                selected: selected.clone(),
                view,
            })
            .collect();
        let locator = SelectedSemanticLocator::new(
            "fixture",
            "src/shared.rs",
            ResolutionSiteId::new(1),
            LoweredSemanticRole::Reference,
        );
        (domain, locator, SemanticId::local(1, 1))
    }

    fn test_context_reports(
        locator: &SelectedSemanticLocator,
        target: SemanticId,
    ) -> Vec<ReverseSessionReport<()>> {
        vec![ReverseSessionReport::Found {
            locator: locator.clone(),
            meanings: vec![(target, vec![()])],
        }]
    }

    fn test_reduce_root_reports(
        mut batch: ReverseContextBatch<ReverseContextId<&'static str>, ()>,
        locator: &SelectedSemanticLocator,
        target: SemanticId,
    ) -> (
        ReverseProofBatch<&'static str>,
        ReverseSiteReduction<(), ()>,
    ) {
        let mut proof = ReverseProofBatch::new(target, batch.required);
        let required = (0..proof.required.len()).collect::<Vec<_>>();
        let reduced = classify_reverse_context_site(
            &mut proof,
            locator,
            &required,
            batch.sites.remove(0),
            |_| {
                Ok(Some(ReverseClassifiedView {
                    verdict: ReverseViewVerdict {
                        relation: ReverseTargetRelation::Matches,
                        closes_site: true,
                        closure: (),
                        answer: (),
                    },
                    applicability: ResolutionCompletion::Complete,
                    binding: ResolutionCompletion::Complete,
                }))
            },
        )
        .unwrap()
        .unwrap();
        (proof, reduced)
    }

    #[cfg(test)]
    #[test]
    #[hardwon("#5658: a nonreporting caller root must stay in the required file domain")]
    fn reverse_file_domain_keeps_missing_root_report_open() {
        let (domain, locator, target) = two_root_file();
        let result =
            confirm_reverse_contexts(domain, &[&locator], &CancellationToken::new(), |context| {
                Ok(ReverseBatch::<_, ()>::Ready(
                    if context.view == "src/lib.rs" {
                        test_context_reports(&locator, target)
                    } else {
                        Vec::new()
                    },
                ))
            })
            .unwrap();
        let ReverseBatch::Ready(batch) = result else {
            panic!("completed file");
        };
        let (proof, reduced) = test_reduce_root_reports(batch, &locator, target);
        assert_eq!(proof.required.len(), 2);
        assert!(!reduced.every_context_closed);
        assert!(reduced.closure.is_none());
        assert_eq!(reduced.binding.len(), 1);
        assert!(proof.evidence.enumeration.discharges.is_empty());
    }

    #[cfg(test)]
    #[test]
    fn reverse_second_context_cancellation_is_atomic_and_retry_matches() {
        let (domain, locator, target) = two_root_file();
        let cancellation = CancellationToken::new();
        let stopped =
            confirm_reverse_contexts(domain.clone(), &[&locator], &cancellation, |context| {
                Ok(if context.view == "src/main.rs" {
                    cancellation.cancel();
                    ReverseBatch::<_, ()>::Cancelled {
                        stage: ReverseCancellationStage::Projection,
                        completion: cancelled_completion(),
                    }
                } else {
                    ReverseBatch::Ready(test_context_reports(&locator, target))
                })
            })
            .unwrap();
        assert!(matches!(stopped, ReverseBatch::Cancelled { .. }));
        let uncommitted = ReverseProofBatch::new(target, domain.clone());
        assert!(uncommitted.evidence.enumeration.obligations.is_empty());
        assert!(uncommitted.evidence.enumeration.discharges.is_empty());
        let run = || {
            let ReverseBatch::Ready(batch) = confirm_reverse_contexts(
                domain.clone(),
                &[&locator],
                &CancellationToken::new(),
                |_| {
                    Ok(ReverseBatch::<_, ()>::Ready(test_context_reports(
                        &locator, target,
                    )))
                },
            )
            .unwrap() else {
                panic!("uncancelled file");
            };
            let (proof, reduced) = test_reduce_root_reports(batch, &locator, target);
            assert!(reduced.every_context_closed);
            assert_eq!(proof.evidence.enumeration.discharges.len(), 2);
            observe_reverse_proof(
                &proof,
                |root| serde_json::json!(root),
                |_| Ok(serde_json::json!([])),
            )
            .unwrap()
        };
        assert_eq!(run(), run(), "retry is exactly the uncancelled answer");
    }

    #[cfg(test)]
    #[test]
    fn reverse_worker_proof_transport_round_trip_preserves_context_handles() {
        use crate::analyzer::resolution::{
            BindingFragmentId, BindingNodeId, PartialPathId, ResolutionIdentityTranslation,
            StackVariableId,
        };
        struct Remount {
            from: u32,
            to: u32,
        }
        impl ResolutionIdentityTranslation for Remount {
            fn semantic(&self, semantic: SemanticId) -> SemanticId {
                assert_eq!(semantic, SemanticId::local(self.from, 1));
                SemanticId::local(self.to, 1)
            }
            fn node(&self, node: BindingNodeId) -> BindingNodeId {
                node
            }
            fn path(&self, path: PartialPathId) -> PartialPathId {
                path
            }
            fn stack_variable(&self, variable: StackVariableId) -> StackVariableId {
                variable
            }
            fn fragment(&self, fragment: BindingFragmentId) -> BindingFragmentId {
                assert_eq!(fragment.ordinal(), self.from);
                BindingFragmentId::at_ordinal(self.to)
            }
        }
        let (domain, locator, target) = two_root_file();
        let ReverseBatch::Ready(batch) =
            confirm_reverse_contexts(domain, &[&locator], &CancellationToken::new(), |_| {
                Ok(ReverseBatch::<_, ()>::Ready(test_context_reports(
                    &locator, target,
                )))
            })
            .unwrap()
        else {
            panic!("complete file");
        };
        let (proof, _) = test_reduce_root_reports(batch, &locator, target);
        let before = observe_reverse_proof(
            &proof,
            |root| serde_json::json!(root),
            |_| Ok(serde_json::json!([])),
        )
        .unwrap();
        let imported = translate_reverse_proof(proof, &Remount { from: 1, to: 9 });
        let mut parent = ReverseProofBatch::new(SemanticId::local(9, 1), Vec::new());
        append_reverse_proof(&mut parent, imported);
        assert_eq!(parent.obligation_contexts.len(), 4);
        assert!(
            parent
                .required
                .iter()
                .all(|context| context.selected.mount == 9)
        );
        for site in &parent.sites {
            for handle in &site.obligations {
                assert_eq!(parent.obligation_contexts.get(handle), Some(&site.context));
            }
            assert_eq!(site.domain, vec![0, 1]);
        }
        let returned = translate_reverse_proof(parent, &Remount { from: 9, to: 1 });
        let after = observe_reverse_proof(
            &returned,
            |root| serde_json::json!(root),
            |_| Ok(serde_json::json!([])),
        )
        .unwrap();
        assert_eq!(before, after);
    }

    #[cfg(test)]
    #[test]
    #[hardwon(
        "#5658: a missing required view must not close reverse evidence or donate alternatives"
    )]
    fn reverse_context_barrier_keeps_missing_views_open() {
        struct Closure(bool);
        impl ReverseClosure for Closure {
            fn meet(&mut self, other: Self) {
                self.0 &= other.0;
            }
        }
        let verdict = |answer, relation, closed| ReverseViewVerdict {
            answer,
            relation,
            closes_site: closed,
            closure: Closure(closed),
        };
        let reduced = reduce_reverse_site(
            &[0, 1],
            vec![
                (
                    0,
                    vec![verdict("binding", ReverseTargetRelation::Matches, true)],
                ),
                (
                    1,
                    vec![verdict(
                        "other target",
                        ReverseTargetRelation::Excluded,
                        false,
                    )],
                ),
            ],
        );
        assert_eq!(reduced.binding, ["binding"]);
        assert_eq!(reduced.rejecting, ["other target"]);
        assert!(!reduced.every_context_closed);
        assert!(!reduced.closure.expect("both contexts reported").0);
        let missing = reduce_reverse_site(
            &[0, 1],
            vec![(
                0,
                vec![verdict("binding", ReverseTargetRelation::Matches, true)],
            )],
        );
        assert!(!missing.every_context_closed);
        assert!(missing.closure.is_none());
        let empty = reduce_reverse_site::<i32, (), ()>(&[], Vec::new());
        assert!(!empty.every_context_closed);
    }

    #[cfg(test)]
    #[test]
    #[should_panic(expected = "obligation belongs to its exact required context")]
    #[hardwon(
        "#5658: equal selected witnesses must not allow swapping different views' obligation handles"
    )]
    fn reverse_barrier_rejects_a_handle_from_another_view() {
        let selected = ReverseContextWitness {
            mount: 1,
            blob: 1,
            selection: [0; 32],
            analysis_generation: 0,
        };
        let first = ReverseContextId {
            selected: selected.clone(),
            view: 0,
        };
        let second = ReverseContextId {
            selected: selected.clone(),
            view: 1,
        };
        let target = SemanticId::local(1, 1);
        let locator = SelectedSemanticLocator::new(
            "java",
            "Caller.java",
            ResolutionSiteId::new(0),
            LoweredSemanticRole::Reference,
        );
        let mut evidence = ReverseEvidence::new(target);
        let foreign = evidence.enumeration.record(
            ReverseSubject::Site(locator.clone(), selected),
            ReverseEvidenceOrigin::Context,
            ResolutionCompletion::Complete,
        );
        let mut proof = ReverseProofBatch::new(target, vec![first, second]);
        proof.evidence = evidence;
        proof.obligation_contexts.insert(foreign.clone(), 1);
        reduce_reverse_evidenced_site(
            &mut proof,
            &[0, 1],
            vec![(
                ReverseSiteEvidence {
                    target,
                    input_ordinal: 0,
                    locator,
                    context: 0,
                    domain: vec![0, 1],
                    obligations: vec![foreign],
                    meanings: vec![target],
                },
                vec![ReverseViewVerdict {
                    relation: ReverseTargetRelation::Matches,
                    closes_site: true,
                    closure: (),
                    answer: (),
                }],
            )],
        );
    }

    #[cfg(test)]
    #[test]
    fn plural_evaluator_answers_reach_reducer_before_projection() {
        struct Evaluator;
        impl ReverseEvaluator for Evaluator {
            type Answer = (ResolutionCompletion, ResolutionCompletion);
            fn evaluate(
                &mut self,
                _locator: &SelectedSemanticLocator,
                _reference: SemanticId,
                _context: &ReverseContextWitness,
            ) -> Result<Vec<Self::Answer>> {
                Ok([1, 2]
                    .map(|id| {
                        (
                            ResolutionCompletion::Complete,
                            ResolutionCompletion::incomplete([
                                ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::local(
                                    1, id,
                                )),
                            ]),
                        )
                    })
                    .into())
            }
        }
        struct Reducer;
        impl ReverseFileReducer for Reducer {
            type Answer = (ResolutionCompletion, ResolutionCompletion);
            fn target(&self) -> SemanticId {
                SemanticId::local(1, 0)
            }
            fn missing_locator(&self, _locator: &SelectedSemanticLocator) -> StoreError {
                unreachable!()
            }
            fn target_relation(&self, _answer: &Self::Answer) -> ReverseTargetRelation {
                ReverseTargetRelation::Matches
            }
            fn binding_completion<'a>(&self, answer: &'a Self::Answer) -> &'a ResolutionCompletion {
                &answer.0
            }
            fn metadata_evidence(
                &self,
                answer: &Self::Answer,
                _relation: ReverseTargetRelation,
            ) -> Option<(ReverseEvidenceOrigin, ResolutionCompletion)> {
                Some((ReverseEvidenceOrigin::Hierarchy, answer.1.clone()))
            }
            fn file(
                &mut self,
                _operation: &SelectedResolutionOperation<'_, '_>,
                _context: &ReverseContextWitness,
                _answers: Vec<ReverseConfirmedReference<Self::Answer>>,
                _axes: &mut ReverseEvidence,
                _cancellation: &CancellationToken,
            ) -> Result<bool> {
                unreachable!()
            }
        }
        let context = ReverseContextWitness {
            mount: 1,
            blob: 1,
            selection: [0; 32],
            analysis_generation: 0,
        };
        let locator = SelectedSemanticLocator::new(
            "java",
            "Caller.java",
            ResolutionSiteId::new(0),
            LoweredSemanticRole::Reference,
        );
        let answers = Evaluator
            .evaluate(&locator, SemanticId::local(1, 3), &context)
            .unwrap();
        assert_eq!(answers.len(), 2);
        let expected = answers[0].1.combine(&answers[1].1);
        let mut evidence = ReverseEvidence::new(SemanticId::local(1, 0));
        let mut confirmed = Vec::new();
        Reducer.reduce_answers(&locator, &context, answers, &mut evidence, &mut confirmed);
        assert_eq!(confirmed.len(), 2);
        assert_eq!(evidence.confirmations.len(), 2);
        assert_eq!(
            evidence.binding.completion(),
            ResolutionCompletion::Complete
        );
        assert_eq!(evidence.metadata.completion(), expected);
        assert!(
            evidence
                .metadata
                .obligations
                .iter()
                .all(|row| matches!(row.origin, ReverseEvidenceOrigin::Hierarchy))
        );
    }

    #[cfg(test)]
    #[test]
    #[hardwon(
        "#5965: review: discharge took a bare index, so another axis or target could be closed"
    )]
    fn reverse_evidence_reduces_named_obligations_independently_of_order() {
        let context = ReverseContextWitness {
            mount: 1,
            blob: 1,
            selection: [0; 32],
            analysis_generation: 0,
        };
        let site = SelectedSemanticLocator::new(
            "java",
            "Caller.java",
            ResolutionSiteId::new(0),
            LoweredSemanticRole::Reference,
        );
        let subject = ReverseSubject::Site(site, context);
        let target_a = SemanticId::local(1, 0);
        let target_b = SemanticId::local(2, 0);
        let reason = |ordinal| {
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                SemanticId::local(1, ordinal),
            )])
        };
        let enumeration_gap = reason(1);
        let binding_gap = reason(2);
        let metadata_gap = reason(3);
        let other_target_gap = reason(4);
        let independent_enumeration_gap = reason(5);
        for order in [[0, 1, 2, 3, 4], [4, 3, 2, 1, 0], [2, 0, 4, 3, 1]] {
            let mut a = ReverseEvidence::new(target_a);
            let mut b = ReverseEvidence::new(target_b);
            let mut discharged = None;
            for index in order {
                let (ledger, completion) = match index {
                    0 => (&mut a.enumeration, &enumeration_gap),
                    1 => (&mut a.binding, &binding_gap),
                    2 => (&mut a.metadata, &metadata_gap),
                    3 => (&mut b.enumeration, &other_target_gap),
                    4 => (&mut a.enumeration, &independent_enumeration_gap),
                    _ => unreachable!(),
                };
                let id = ledger.record(
                    subject.clone(),
                    ReverseEvidenceOrigin::Inventory,
                    completion.clone(),
                );
                if index == 0 {
                    discharged = Some(id);
                }
            }
            assert_eq!(
                a.enumeration.completion(),
                enumeration_gap.combine(&independent_enumeration_gap)
            );
            a.enumeration
                .discharge(discharged.unwrap(), ReverseEvidenceOrigin::Binding);
            assert_eq!(
                a.enumeration.completion_for(|_| true),
                independent_enumeration_gap
            );
            assert_eq!(a.binding.completion_for(|_| true), binding_gap);
            assert_eq!(a.metadata.completion_for(|_| true), metadata_gap);
            assert_eq!(b.enumeration.completion_for(|_| true), other_target_gap);
        }
    }

    #[cfg(test)]
    #[test]
    #[should_panic(expected = "obligation belongs to another axis")]
    #[hardwon("#5965: review: a same-numbered handle from another axis must not discharge a row")]
    fn reverse_discharge_rejects_another_ledger() {
        let target = SemanticId::local(1, 0);
        let mut evidence = ReverseEvidence::new(target);
        let id = evidence.binding.record(
            ReverseSubject::Target(target),
            ReverseEvidenceOrigin::Binding,
            ResolutionCompletion::Complete,
        );
        evidence.enumeration.record(
            ReverseSubject::Target(target),
            ReverseEvidenceOrigin::Inventory,
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                target,
            )]),
        );
        evidence
            .enumeration
            .discharge(id, ReverseEvidenceOrigin::Binding);
    }
}
