//! Completeness certification for the finite cycle fragment of stitching.
//!
//! General reachability in this algebra is not decidable: a [`PartialPath`]
//! can transform two independently unbounded stacks, and two stacks can encode
//! a Turing-machine tape.  This module therefore does not call a repeated path
//! "complete" merely because a worklist guard stopped expanding it.
//!
//! Instead, [`CycleCompletenessCertifier`] recognizes one explicitly finite
//! fragment.  It quotients paths by their joint, alpha-normalized endpoint
//! stack effect and by the observations used after stitching (precedence,
//! witness footprint, and completion).  On a branch, the first use of each
//! stored partial path records its stack effect.  A later use is certified only
//! when either:
//!
//! * the complete observable state was already explored; or
//! * its stack effect is unchanged, so only finite, idempotent evidence can
//!   still be added before the observable state repeats.
//!
//! A repeated path with a different joint stack effect is returned as an
//! [`UncertifiedCycle`].  The caller must propagate that as incomplete and may
//! not use the pruned branch to prove a negative answer.  This accepts neutral
//! SCCs exactly while staying honest about productive or otherwise unproved
//! pushdown cycles.

use std::hash::Hash;

#[cfg(test)]
use crate::analyzer::structural::CandidateOutcome;
use crate::hash::HashMap;

use super::model::{
    PartialPath, PartialPathId, PrecedenceStep, ResolutionCompletion, StackEffectAlphaKey,
    WitnessStep, clone_completion_with_poll, completion_values_equal_with_poll,
    first_occurrences_with_poll,
};
use super::never_cancelled;

/// Per-branch proof state carried by the stitching worklist.
///
/// Checkpoints are operation-local and bounded by the number of distinct
/// partial-path rows: a certified neutral repeat reuses its existing
/// checkpoint rather than appending another one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct SaturationBranch {
    checkpoints: Box<[CycleCheckpoint]>,
}

impl SaturationBranch {
    fn checkpoint_with_poll<P>(
        &self,
        transition: PartialPathId,
        cancelled: &mut P,
    ) -> Option<Option<&StackEffectAlphaKey>>
    where
        P: FnMut() -> bool,
    {
        for checkpoint in self.checkpoints.iter() {
            if cancelled() {
                return None;
            }
            if checkpoint.transition == transition {
                return Some(Some(&checkpoint.stack_effect));
            }
        }
        Some(None)
    }

    fn clone_with_poll<P>(&self, cancelled: &mut P) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        let checkpoints = self.clone_checkpoints_with_poll(0, cancelled)?;
        Some(Self {
            checkpoints: checkpoints.into_boxed_slice(),
        })
    }

    fn with_checkpoint_with_poll<P>(
        &self,
        transition: PartialPathId,
        stack_effect: StackEffectAlphaKey,
        cancelled: &mut P,
    ) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        let mut checkpoints = self.clone_checkpoints_with_poll(1, cancelled)?;
        debug_assert!(
            checkpoints
                .iter()
                .all(|checkpoint| checkpoint.transition != transition)
        );
        checkpoints.push(CycleCheckpoint {
            transition,
            stack_effect,
        });
        Some(Self {
            checkpoints: checkpoints.into_boxed_slice(),
        })
    }

    fn clone_checkpoints_with_poll<P>(
        &self,
        extra_capacity: usize,
        cancelled: &mut P,
    ) -> Option<Vec<CycleCheckpoint>>
    where
        P: FnMut() -> bool,
    {
        let mut checkpoints = Vec::with_capacity(self.checkpoints.len() + extra_capacity);
        for checkpoint in self.checkpoints.iter() {
            if cancelled() {
                return None;
            }
            checkpoints.push(CycleCheckpoint {
                transition: checkpoint.transition,
                stack_effect: checkpoint.stack_effect.clone_with_poll(cancelled)?,
            });
        }
        Some(checkpoints)
    }

    #[cfg(test)]
    fn checkpoint_count(&self) -> usize {
        self.checkpoints.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CycleCheckpoint {
    transition: PartialPathId,
    stack_effect: StackEffectAlphaKey,
}

/// A repeated transition whose stack transform is outside the certified
/// finite fragment.
///
/// This is deliberately named `Uncertified`, not `Productive`: a changed
/// effect might belong to a decidable one-stack or regular relation that a
/// future representation can summarize.  The current pair-of-stack-patterns
/// representation contains no such summary or proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct UncertifiedCycle {
    transition: PartialPathId,
}

impl UncertifiedCycle {
    pub(super) const fn transition(self) -> PartialPathId {
        self.transition
    }
}

/// Result of considering one successfully composed path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SaturationDecision {
    /// This observable state is new and belongs to the certified fragment.
    Expand(SaturationBranch),
    /// An alpha-equivalent state was already scheduled or explored.
    Subsumed,
    /// Continuing could require an unbounded stack-relation summary.
    Uncertified(UncertifiedCycle),
}

/// Operation-local alpha quotient and cycle-completeness certifier.
///
/// The source presented to one instance must be finite.  The certifier keeps
/// no workspace-global state and is not a cache.
#[derive(Debug)]
pub(super) struct CycleCompletenessCertifier {
    seen_by_key: HashMap<ObservablePathBucketKey, Vec<ResolutionCompletion>>,
}

impl CycleCompletenessCertifier {
    /// Seed an operation with the identity path already on its worklist.
    pub(super) fn new(seed: &PartialPath) -> Self {
        let Some(certifier) = Self::new_with_poll(seed, &mut never_cancelled) else {
            unreachable!("the never-cancelled cycle seed poll returned cancellation")
        };
        certifier
    }

    pub(super) fn new_with_poll<P>(seed: &PartialPath, cancelled: &mut P) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        Self::from_initial_paths_with_poll(std::iter::once(seed), cancelled)
    }

    /// Seed an operation with every path already on its initial worklist.
    ///
    /// There is deliberately no distinguished semantic authority here. Each
    /// canonical observable is inserted into the quotient before expansion,
    /// so a derivation reached from one alternative may only subsume another
    /// when the same proof used for ordinary worklist states says that their
    /// future behavior is alpha-equivalent. Exact duplicates are harmless.
    pub(super) fn from_initial_paths_with_poll<'a, P>(
        paths: impl IntoIterator<Item = &'a PartialPath>,
        cancelled: &mut P,
    ) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        let mut seen_by_key: HashMap<ObservablePathBucketKey, Vec<ResolutionCompletion>> =
            HashMap::default();
        let mut path_count = 0_usize;
        for path in paths {
            if cancelled() {
                return None;
            }
            path_count += 1;
            let observable = ObservablePathKey::of_with_poll(path, cancelled)?;
            let (key, completion) = observable.into_bucket_with_poll(cancelled)?;
            let bucket = seen_by_key.entry(key).or_default();
            let mut duplicate = false;
            for prior in bucket.iter() {
                if cancelled() {
                    return None;
                }
                if completion_values_equal_with_poll(prior, &completion, cancelled)? {
                    duplicate = true;
                    break;
                }
            }
            if !duplicate {
                bucket.push(completion);
            }
        }
        assert!(
            path_count > 0,
            "cycle certification requires an initial path"
        );
        if cancelled() {
            return None;
        }
        Some(Self { seen_by_key })
    }

    /// Decide whether `path` may be expanded without making a heuristic cycle
    /// cut look complete.
    pub(super) fn admit(
        &mut self,
        branch: &SaturationBranch,
        transition: PartialPathId,
        path: &PartialPath,
    ) -> SaturationDecision {
        let Some(decision) = self.admit_with_poll(branch, transition, path, &mut never_cancelled)
        else {
            unreachable!("the never-cancelled cycle-admission poll returned cancellation")
        };
        decision
    }

    pub(super) fn admit_with_poll<P>(
        &mut self,
        branch: &SaturationBranch,
        transition: PartialPathId,
        path: &PartialPath,
        cancelled: &mut P,
    ) -> Option<SaturationDecision>
    where
        P: FnMut() -> bool,
    {
        if cancelled() {
            return None;
        }
        let stack_effect = path.stack_effect_alpha_key_with_poll(cancelled)?;
        let observable =
            ObservablePathKey::with_stack_effect_with_poll(path, stack_effect, cancelled)?;
        let (key, completion) = observable.into_bucket_with_poll(cancelled)?;

        // Branch history is only a termination certificate, never semantic
        // input to composition.  Once two prefixes have the same observable
        // key, every suffix has the same stack/precedence/completion behavior
        // modulo alpha-renaming.  Keeping either prefix is therefore sound.
        // A less favorable retained history can reject a later changed repeat,
        // but that rejection is explicitly incomplete; it cannot manufacture
        // a complete negative.  The convergent-history regression below pins
        // this conservative direction.
        if let Some(bucket) = self.seen_by_key.get(&key) {
            for prior in bucket {
                if cancelled() {
                    return None;
                }
                if completion_values_equal_with_poll(prior, &completion, cancelled)? {
                    return Some(SaturationDecision::Subsumed);
                }
            }
        }

        let next_branch = match branch.checkpoint_with_poll(transition, cancelled)? {
            Some(previous) if !previous.equals_with_poll(&key.stack_effect, cancelled)? => {
                return Some(SaturationDecision::Uncertified(UncertifiedCycle {
                    transition,
                }));
            }
            Some(_) => branch.clone_with_poll(cancelled)?,
            None => branch.with_checkpoint_with_poll(
                transition,
                key.stack_effect.clone_with_poll(cancelled)?,
                cancelled,
            )?,
        };

        // All fallible construction and exact comparison finishes before the
        // quotient mutates, so cancellation cannot install a partial state.
        if cancelled() {
            return None;
        }
        self.seen_by_key.entry(key).or_default().push(completion);
        Some(SaturationDecision::Expand(next_branch))
    }

    #[cfg(test)]
    fn state_count(&self) -> usize {
        self.seen_by_key.values().map(Vec::len).sum()
    }
}

/// Everything about a composed path that can affect future composition or a
/// resolution result.
///
/// The actual `PartialPath` remains on the worklist and retains a replayable
/// witness.  This key only identifies equivalent derivations.  Repeating an
/// identical precedence or witness step cannot add a new choice or proof fact,
/// so the first occurrence is its finite canonical representative.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ObservablePathKey {
    stack_effect: StackEffectAlphaKey,
    precedence: Box<[PrecedenceStep]>,
    witness_footprint: Box<[WitnessStep]>,
    completion: ResolutionCompletion,
}

/// Typed operation-local bucket. Completion's shared fingerprint preserves
/// cheap base reuse; exact ordered completion comparison resolves collisions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ObservablePathBucketKey {
    stack_effect: StackEffectAlphaKey,
    precedence: Box<[PrecedenceStep]>,
    witness_footprint: Box<[WitnessStep]>,
    completion: Option<(usize, u64, u64)>,
}

impl ObservablePathKey {
    fn of_with_poll<P>(path: &PartialPath, cancelled: &mut P) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        let stack_effect = path.stack_effect_alpha_key_with_poll(cancelled)?;
        Self::with_stack_effect_with_poll(path, stack_effect, cancelled)
    }

    fn with_stack_effect_with_poll<P>(
        path: &PartialPath,
        stack_effect: StackEffectAlphaKey,
        cancelled: &mut P,
    ) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        Some(Self {
            stack_effect,
            precedence: first_occurrences_with_poll(path.precedence(), cancelled)?,
            witness_footprint: first_occurrences_with_poll(path.witness(), cancelled)?,
            completion: clone_completion_with_poll(path.completion(), cancelled)?,
        })
    }

    fn into_bucket_with_poll<P>(
        self,
        cancelled: &mut P,
    ) -> Option<(ObservablePathBucketKey, ResolutionCompletion)>
    where
        P: FnMut() -> bool,
    {
        for _ in self.precedence.iter() {
            if cancelled() {
                return None;
            }
        }
        for _ in self.witness_footprint.iter() {
            if cancelled() {
                return None;
            }
        }
        let completion = completion_bucket_key_with_poll(&self.completion, cancelled)?;
        Some((
            ObservablePathBucketKey {
                stack_effect: self.stack_effect,
                precedence: self.precedence,
                witness_footprint: self.witness_footprint,
                completion,
            },
            self.completion,
        ))
    }

    #[cfg(test)]
    fn equals_with_poll<P>(&self, other: &Self, cancelled: &mut P) -> Option<bool>
    where
        P: FnMut() -> bool,
    {
        if !self
            .stack_effect
            .equals_with_poll(&other.stack_effect, cancelled)?
            || self.precedence.len() != other.precedence.len()
            || self.witness_footprint.len() != other.witness_footprint.len()
        {
            return Some(false);
        }
        for (left, right) in self.precedence.iter().zip(other.precedence.iter()) {
            if cancelled() {
                return None;
            }
            if left != right {
                return Some(false);
            }
        }
        for (left, right) in self
            .witness_footprint
            .iter()
            .zip(other.witness_footprint.iter())
        {
            if cancelled() {
                return None;
            }
            if left != right {
                return Some(false);
            }
        }
        completion_values_equal_with_poll(&self.completion, &other.completion, cancelled)
    }
}

fn completion_bucket_key_with_poll<P>(
    completion: &ResolutionCompletion,
    cancelled: &mut P,
) -> Option<Option<(usize, u64, u64)>>
where
    P: FnMut() -> bool,
{
    Some(match completion {
        ResolutionCompletion::Complete => None,
        ResolutionCompletion::Incomplete(reasons) => {
            Some(reasons.fingerprint_with_poll(cancelled)?)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::super::engine::identity_path;
    use super::super::partial_path_id_for_test as path_id;
    use super::*;
    use crate::CancellationToken;
    use crate::analyzer::resolution::engine::CANCELLATION_QUANTUM;
    use crate::analyzer::resolution::model::{
        BindingNodeId, EndpointSignature, PartialScopedSymbol, SemanticId, StackPattern,
    };
    use crate::analyzer::resolution::test_support::{endpoint, node, semantic};
    use crate::analyzer::structural::{CandidateOutcome, PrecedenceTier, RejectionReason};

    fn variable(value: &str) -> super::super::model::StackVariableId {
        super::super::model::StackVariableId::for_test(value)
    }

    /// A path whose variables are renamed away from `path`'s own, which is
    /// what composing it against a path that already holds one renamed
    /// variable would do.
    fn alpha_renamed(path: &PartialPath) -> PartialPath {
        path.alpha_renamed_from_for_test(1)
    }

    fn certifier_from_initial_paths<'a>(
        paths: impl IntoIterator<Item = &'a PartialPath>,
    ) -> CycleCompletenessCertifier {
        CycleCompletenessCertifier::from_initial_paths_with_poll(paths, &mut || false)
            .expect("live test cycle seeding completes")
    }

    fn first_occurrences<T: Copy + Eq + Hash>(values: &[T]) -> Box<[T]> {
        first_occurrences_with_poll(values, &mut || false)
            .expect("live test observable quotient completes")
    }

    #[test]
    fn completion_digest_shares_base_work_and_exact_comparison_resolves_collisions() {
        use super::super::completion_reasons::CompletionReasons;
        use super::super::model::ResolutionIncompleteReason;

        let reasons = (0..4_096_usize)
            .map(|index| {
                ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::for_test(
                    index.to_le_bytes(),
                ))
            })
            .collect::<Vec<_>>();
        let raw = ResolutionCompletion::incomplete(reasons.iter().copied());
        let shared = ResolutionCompletion::Incomplete(
            CompletionReasons::from(reasons.clone())
                .to_shared_with_poll(&mut || false)
                .expect("the test does not cancel base promotion"),
        );
        let mut raw_work = 0;
        let raw_key = completion_bucket_key_with_poll(&raw, &mut || {
            raw_work += 1;
            false
        })
        .expect("the test does not cancel raw hashing");
        let mut shared_work = 0;
        let shared_key = completion_bucket_key_with_poll(&shared, &mut || {
            shared_work += 1;
            false
        })
        .expect("the test does not cancel shared hashing");
        assert_eq!(raw_key, shared_key);
        assert_eq!(raw_work, reasons.len());
        assert_eq!(shared_work, 1);

        let first = identity_path(node("completion-hash-collision")).with_additional_completion(
            &ResolutionCompletion::Incomplete(vec![reasons[0], reasons[1]].into()),
        );
        let second = identity_path(node("completion-hash-collision")).with_additional_completion(
            &ResolutionCompletion::Incomplete(vec![reasons[1], reasons[0]].into()),
        );
        let first_key = ObservablePathKey::of_with_poll(&first, &mut || false).unwrap();
        let second_key = ObservablePathKey::of_with_poll(&second, &mut || false).unwrap();
        assert_eq!(
            first_key
                .clone()
                .into_bucket_with_poll(&mut || false)
                .map(|(key, _)| key),
            second_key
                .clone()
                .into_bucket_with_poll(&mut || false)
                .map(|(key, _)| key),
        );
        assert!(
            !first_key
                .equals_with_poll(&second_key, &mut || false)
                .unwrap()
        );
        let mut certifier = certifier_from_initial_paths([&first]);
        assert!(matches!(
            certifier.admit(
                &SaturationBranch::default(),
                path_id("collision-transition"),
                &second
            ),
            SaturationDecision::Expand(_),
        ));
        assert_eq!(certifier.state_count(), 2);
    }

    #[allow(clippy::too_many_arguments)]
    fn closed_path(
        start: BindingNodeId,
        end: BindingNodeId,
        before_symbols: Vec<SemanticId>,
        after_symbols: Vec<SemanticId>,
        before_scopes: Vec<BindingNodeId>,
        after_scopes: Vec<BindingNodeId>,
        precedence: Vec<PrecedenceStep>,
        witness: Vec<WitnessStep>,
        completion: ResolutionCompletion,
    ) -> PartialPath {
        PartialPath::new(
            endpoint(start, before_symbols, before_scopes),
            endpoint(end, after_symbols, after_scopes),
            precedence,
            witness,
            completion,
        )
    }

    fn concatenate(left: &PartialPath, right: &PartialPath) -> PartialPath {
        left.concatenate(right).expect("test paths compose")
    }

    #[test]
    fn alpha_equivalent_open_states_are_subsumed() {
        let at = node("at");
        let tail = variable("tail");
        let scope_tail = variable("scope-tail");
        let open = PartialPath::new(
            EndpointSignature::new_scoped(
                at,
                StackPattern::open(Vec::new(), tail),
                StackPattern::open(Vec::new(), scope_tail),
            ),
            EndpointSignature::new_scoped(
                at,
                StackPattern::open(Vec::new(), tail),
                StackPattern::open(Vec::new(), scope_tail),
            ),
            Vec::new(),
            vec![WitnessStep::Node(at)],
            ResolutionCompletion::Complete,
        );
        let renamed = alpha_renamed(&open);
        let mut certifier = CycleCompletenessCertifier::new(&open);

        assert!(matches!(
            certifier.admit(&SaturationBranch::default(), path_id("same"), &renamed),
            SaturationDecision::Subsumed
        ));
        assert_eq!(certifier.state_count(), 1);
    }

    #[test]
    fn attached_scope_aliasing_participates_in_the_alpha_quotient() {
        let at = node("at");
        let shared = variable("shared-scope-tail");
        let different = variable("different-scope-tail");
        let symbol = semantic("name");
        let scoped = |attached_tail, outer_tail| {
            PartialPath::new(
                EndpointSignature::new_scoped(
                    at,
                    StackPattern::closed([PartialScopedSymbol::scoped(
                        symbol,
                        StackPattern::open(Vec::new(), attached_tail),
                    )]),
                    StackPattern::open(Vec::new(), outer_tail),
                ),
                EndpointSignature::new_scoped(
                    at,
                    StackPattern::closed(Vec::new()),
                    StackPattern::closed(Vec::new()),
                ),
                Vec::new(),
                Vec::new(),
                ResolutionCompletion::Complete,
            )
        };
        let aliased = scoped(shared, shared);
        let unaliased = scoped(shared, different);
        let mut certifier = CycleCompletenessCertifier::new(&aliased);

        assert!(matches!(
            certifier.admit(
                &SaturationBranch::default(),
                path_id("different-aliasing"),
                &unaliased
            ),
            SaturationDecision::Expand(_)
        ));
        assert_eq!(certifier.state_count(), 2);
    }

    #[test]
    fn neutral_self_loop_is_certified_without_degrading_completeness() {
        let at = node("at");
        let transition = path_id("neutral-loop");
        let seed = identity_path(at);
        let loop_path = closed_path(
            at,
            at,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![WitnessStep::Node(at)],
            ResolutionCompletion::Complete,
        );
        let once = concatenate(&seed, &loop_path);
        let twice = concatenate(&once, &loop_path);
        let mut certifier = CycleCompletenessCertifier::new(&seed);

        assert!(matches!(
            certifier.admit(&SaturationBranch::default(), transition, &once),
            SaturationDecision::Subsumed
        ));
        assert!(matches!(
            certifier.admit(&SaturationBranch::default(), transition, &twice),
            SaturationDecision::Subsumed
        ));
        assert_eq!(SaturationBranch::default().checkpoint_count(), 0);
        assert_eq!(certifier.state_count(), 1);
    }

    #[test]
    fn productive_scope_cycle_is_explicitly_uncertified() {
        let at = node("at");
        let pushed_scope = node("pushed-scope");
        let tail = variable("scope-tail");
        let transition = path_id("push-scope");
        let seed = identity_path(at);
        let push = PartialPath::new(
            EndpointSignature::new_scoped(
                at,
                StackPattern::closed(Vec::new()),
                StackPattern::open(Vec::new(), tail),
            ),
            EndpointSignature::new_scoped(
                at,
                StackPattern::closed(Vec::new()),
                StackPattern::open([pushed_scope], tail),
            ),
            Vec::new(),
            [WitnessStep::Node(at)],
            ResolutionCompletion::Complete,
        );
        let once = concatenate(&seed, &push);
        let twice = concatenate(&once, &push);
        assert_productive_stack_cycle_is_uncertified(&seed, transition, &once, &twice);
    }

    #[test]
    fn convergent_history_subsumption_cannot_hide_a_changed_repeat() {
        let at = node("at");
        let first_route = path_id("first-route");
        let convergent_route = path_id("convergent-route");
        let choice = semantic("choice");
        let arrived = closed_path(
            at,
            at,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![PrecedenceStep {
                tier: PrecedenceTier::LexicalBinding,
                ordinal: 0,
                semantic: choice,
            }],
            vec![WitnessStep::Node(at)],
            ResolutionCompletion::Complete,
        );
        let grown = closed_path(
            at,
            at,
            Vec::new(),
            vec![semantic("grown")],
            Vec::new(),
            Vec::new(),
            arrived.precedence().to_vec(),
            arrived.witness().to_vec(),
            ResolutionCompletion::Complete,
        );
        let seed = identity_path(at);
        let mut certifier = CycleCompletenessCertifier::new(&seed);
        let SaturationDecision::Expand(retained_branch) =
            certifier.admit(&SaturationBranch::default(), first_route, &arrived)
        else {
            panic!("the first route to an observable state must expand");
        };

        assert!(matches!(
            certifier.admit(&SaturationBranch::default(), convergent_route, &arrived),
            SaturationDecision::Subsumed
        ));
        assert!(matches!(
            certifier.admit(&retained_branch, first_route, &grown),
            SaturationDecision::Uncertified(UncertifiedCycle { transition })
                if transition == first_route
        ));
    }

    #[test]
    fn canonical_precedence_preserves_shadowing_exhaustively() {
        let semantics = [semantic("a"), semantic("b")];
        let ranks = [
            (PrecedenceTier::LexicalBinding, 0),
            (PrecedenceTier::ExplicitImport, 1),
        ];
        let alphabet = semantics
            .into_iter()
            .flat_map(|semantic| {
                ranks
                    .into_iter()
                    .map(move |(tier, ordinal)| PrecedenceStep {
                        tier,
                        ordinal,
                        semantic,
                    })
            })
            .collect::<Vec<_>>();
        let traces = traces_through_len(&alphabet, 4);

        for left in &traces {
            for right in &traces {
                let canonical_left = first_occurrences(left);
                let canonical_right = first_occurrences(right);
                assert_eq!(
                    shadows(left, right),
                    shadows(&canonical_left, &canonical_right),
                    "canonicalization changed shadowing: left={left:?}, right={right:?}"
                );
            }
        }
    }

    #[test]
    fn first_occurrence_quotient_is_append_congruent_exhaustively() {
        let alphabet = [0_u8, 1, 2];
        let traces = traces_through_len(&alphabet, 3);

        for prefix in &traces {
            for suffix in &traces {
                let mut already_canonical = first_occurrences(prefix).into_vec();
                already_canonical.extend_from_slice(suffix);
                let left = first_occurrences(&already_canonical);

                let mut concatenated = prefix.clone();
                concatenated.extend_from_slice(suffix);
                let right = first_occurrences(&concatenated);
                assert_eq!(left, right, "prefix={prefix:?}, suffix={suffix:?}");
            }
        }
    }

    fn traces_through_len<T: Copy>(alphabet: &[T], maximum: usize) -> Vec<Vec<T>> {
        let mut traces = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..maximum {
            let mut next = Vec::new();
            for prefix in &frontier {
                for &value in alphabet {
                    let mut trace = prefix.clone();
                    trace.push(value);
                    next.push(trace);
                }
            }
            traces.extend(next.iter().cloned());
            frontier = next;
        }
        traces
    }

    fn shadows(left: &[PrecedenceStep], right: &[PrecedenceStep]) -> bool {
        for left_step in left {
            let Some(right_step) = right
                .iter()
                .find(|right_step| right_step.semantic == left_step.semantic)
            else {
                continue;
            };
            match (left_step.tier, left_step.ordinal).cmp(&(right_step.tier, right_step.ordinal)) {
                std::cmp::Ordering::Less => return true,
                std::cmp::Ordering::Greater => return false,
                std::cmp::Ordering::Equal => {}
            }
        }
        false
    }

    #[test]
    fn shallow_polled_certification_gates_before_construction_and_quotient_mutation() {
        let at = node("shallow-polled-at");
        let other = node("shallow-polled-other");
        let seed = identity_path(at);
        let candidate = closed_path(
            at,
            other,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            ResolutionCompletion::Complete,
        );

        let mut initial_poll_count = 0_usize;
        CycleCompletenessCertifier::from_initial_paths_with_poll([&seed], &mut || {
            initial_poll_count += 1;
            false
        })
        .expect("uncancelled shallow construction completes");
        let mut final_initial_polls = 0_usize;
        assert!(
            CycleCompletenessCertifier::from_initial_paths_with_poll([&seed], &mut || {
                final_initial_polls += 1;
                final_initial_polls == initial_poll_count
            })
            .is_none(),
            "the final construction gate must cancel before publishing the quotient"
        );

        let transition = path_id("shallow-polled-transition");
        let mut baseline = CycleCompletenessCertifier::new(&seed);
        let mut admission_poll_count = 0_usize;
        assert!(matches!(
            baseline.admit_with_poll(
                &SaturationBranch::default(),
                transition,
                &candidate,
                &mut || {
                    admission_poll_count += 1;
                    false
                }
            ),
            Some(SaturationDecision::Expand(_))
        ));

        let mut cancelled = CycleCompletenessCertifier::new(&seed);
        let initial_states = cancelled.state_count();
        let mut final_admission_polls = 0_usize;
        assert!(
            cancelled
                .admit_with_poll(
                    &SaturationBranch::default(),
                    transition,
                    &candidate,
                    &mut || {
                        final_admission_polls += 1;
                        final_admission_polls == admission_poll_count
                    }
                )
                .is_none(),
            "the precommit gate must cancel before quotient mutation"
        );
        assert_eq!(cancelled.state_count(), initial_states);
    }

    #[test]
    fn cycle_admission_cancels_within_one_large_observable_without_mutation() {
        let at = node("large-polled-admit-at");
        let seed = identity_path(at);
        let path = closed_path(
            at,
            at,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            std::iter::repeat_n(WitnessStep::Node(at), CANCELLATION_QUANTUM + 1).collect(),
            ResolutionCompletion::Complete,
        );
        let mut certifier = CycleCompletenessCertifier::new(&seed);
        let initial_states = certifier.state_count();
        let cancellation = CancellationToken::cancel_after_checks_for_test(1);
        let mut work = 0_usize;

        let decision = certifier.admit_with_poll(
            &SaturationBranch::default(),
            path_id("large-polled-admit-transition"),
            &path,
            &mut || {
                work += 1;
                work.is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled()
            },
        );

        assert!(decision.is_none());
        assert!(work >= CANCELLATION_QUANTUM);
        assert_eq!(certifier.state_count(), initial_states);
    }

    #[test]
    fn finite_precedence_and_witness_evidence_saturates_before_subsumption() {
        let left = node("left");
        let right = node("right");
        let choice = semantic("choice");
        let first_id = path_id("first-half");
        let second_id = path_id("second-half");
        let seed = identity_path(left);
        let first = closed_path(
            left,
            right,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![WitnessStep::Node(right)],
            ResolutionCompletion::Complete,
        );
        let second = closed_path(
            right,
            left,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![PrecedenceStep {
                tier: PrecedenceTier::LexicalBinding,
                ordinal: 0,
                semantic: choice,
            }],
            vec![WitnessStep::Candidate {
                semantic: choice,
                outcome: CandidateOutcome::Selected,
            }],
            ResolutionCompletion::Complete,
        );
        let first_once = concatenate(&seed, &first);
        let round_once = concatenate(&first_once, &second);
        let first_twice = concatenate(&round_once, &first);
        let round_twice = concatenate(&first_twice, &second);
        let first_thrice = concatenate(&round_twice, &first);
        let mut certifier = CycleCompletenessCertifier::new(&seed);

        let SaturationDecision::Expand(first_branch) =
            certifier.admit(&SaturationBranch::default(), first_id, &first_once)
        else {
            panic!("first half must expand");
        };
        let SaturationDecision::Expand(round_branch) =
            certifier.admit(&first_branch, second_id, &round_once)
        else {
            panic!("first round must expand");
        };
        let SaturationDecision::Expand(enriched_branch) =
            certifier.admit(&round_branch, first_id, &first_twice)
        else {
            panic!("one evidence-enriching neutral round must expand");
        };
        assert_eq!(enriched_branch.checkpoint_count(), 2);
        assert!(matches!(
            certifier.admit(&enriched_branch, second_id, &round_twice),
            SaturationDecision::Subsumed
        ));
        assert!(matches!(
            certifier.admit(&enriched_branch, first_id, &first_thrice),
            SaturationDecision::Subsumed
        ));
    }

    #[test]
    fn productive_symbol_cycle_is_explicitly_uncertified() {
        let at = node("at");
        let name = semantic("name");
        let tail = variable("symbol-tail");
        let transition = path_id("push-symbol");
        let seed = identity_path(at);
        let push = PartialPath::new(
            EndpointSignature::new_scoped(
                at,
                StackPattern::open(Vec::new(), tail),
                StackPattern::closed(Vec::new()),
            ),
            EndpointSignature::new_scoped(
                at,
                StackPattern::open([PartialScopedSymbol::unscoped(name)], tail),
                StackPattern::closed(Vec::new()),
            ),
            Vec::new(),
            [WitnessStep::Node(at)],
            ResolutionCompletion::Complete,
        );
        let once = concatenate(&seed, &push);
        let twice = concatenate(&once, &push);
        assert_eq!(
            assert_productive_stack_cycle_is_uncertified(&seed, transition, &once, &twice),
            2
        );
    }

    #[test]
    fn globally_explored_state_subsumes_an_unfavorable_branch_history() {
        let at = node("at");
        let cyclic_route = path_id("cyclic-route");
        let acyclic_route = path_id("acyclic-route");
        let arrived = closed_path(
            at,
            at,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![PrecedenceStep {
                tier: PrecedenceTier::LexicalBinding,
                ordinal: 0,
                semantic: semantic("choice"),
            }],
            vec![WitnessStep::Node(at)],
            ResolutionCompletion::Complete,
        );
        let grown = closed_path(
            at,
            at,
            Vec::new(),
            vec![semantic("grown")],
            Vec::new(),
            Vec::new(),
            arrived.precedence().to_vec(),
            arrived.witness().to_vec(),
            ResolutionCompletion::Complete,
        );
        let seed = identity_path(at);
        let root = SaturationBranch::default();
        let mut certifier = CycleCompletenessCertifier::new(&seed);
        let SaturationDecision::Expand(cyclic_branch) =
            certifier.admit(&root, cyclic_route, &arrived)
        else {
            panic!("the first route must expand");
        };
        assert!(matches!(
            certifier.admit(&root, acyclic_route, &grown),
            SaturationDecision::Expand(_)
        ));

        assert!(matches!(
            certifier.admit(&cyclic_branch, cyclic_route, &grown),
            SaturationDecision::Subsumed
        ));
    }
    fn assert_productive_stack_cycle_is_uncertified(
        seed: &PartialPath,
        transition: PartialPathId,
        once: &PartialPath,
        twice: &PartialPath,
    ) -> usize {
        let mut certifier = CycleCompletenessCertifier::new(seed);
        let SaturationDecision::Expand(branch) =
            certifier.admit(&SaturationBranch::default(), transition, once)
        else {
            panic!("first push must expand");
        };
        let SaturationDecision::Uncertified(gap) = certifier.admit(&branch, transition, twice)
        else {
            panic!("a repeated growing stack must be uncertified");
        };
        assert_eq!(gap.transition(), transition);
        certifier.state_count()
    }
}
