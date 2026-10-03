//! Compact completion-reason values shared by resolution answers.
//!
//! Most incomplete answers in a selected operation carry the same source-wide
//! evidence.  A factored value keeps that immutable evidence in one `Arc` and
//! stores only the answer-local additions and sparse removals.  Raw values are
//! intentionally retained for the public one-sided constructor: their order
//! and duplicate shape is observable by existing callers.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::slice;
use std::sync::Arc;

use super::ResolutionIncompleteReason;

type Reason = ResolutionIncompleteReason;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fingerprint {
    len: usize,
    sum: u64,
    xor: u64,
}

impl Fingerprint {
    fn empty() -> Self {
        Self {
            len: 0,
            sum: 0,
            xor: 0,
        }
    }

    fn include(&mut self, reason: Reason) {
        let value = reason_fingerprint(reason);
        self.len += 1;
        self.sum = self.sum.wrapping_add(value);
        self.xor ^= value;
    }

    fn exclude(&mut self, reason: Reason) {
        let value = reason_fingerprint(reason);
        self.len -= 1;
        self.sum = self.sum.wrapping_sub(value);
        self.xor ^= value;
    }
}

fn reason_fingerprint(reason: Reason) -> u64 {
    let mut hasher = DefaultHasher::new();
    reason.hash(&mut hasher);
    hasher.finish()
}

fn fingerprint(reasons: &[Reason]) -> Fingerprint {
    let mut fingerprint = Fingerprint::empty();
    for &reason in reasons {
        fingerprint.include(reason);
    }
    fingerprint
}

#[derive(Debug)]
struct CanonicalReasonBase {
    reasons: Box<[Reason]>,
    fingerprint: Fingerprint,
}

#[derive(Debug, Clone)]
enum CompletionReasonsRepr {
    Raw(Box<[Reason]>),
    Factored {
        base: Arc<CanonicalReasonBase>,
        excluded: Box<[usize]>,
        additions: Box<[Reason]>,
    },
}

/// Completion reasons with either their original public shape or factored
/// operation-wide evidence plus small answer-local deltas.
#[derive(Debug, Clone)]
pub struct CompletionReasons(CompletionReasonsRepr);

/// Mutable operation-local union over one shared completion base.
///
/// The builder keeps the common base in its original `Arc` and updates only
/// sparse removals and additions. Callers must discard it when a cancellable
/// mutation returns `None`; no partial state is ever published as a finished
/// immutable value.
#[derive(Debug, Clone)]
pub(super) struct CompletionReasonUnion {
    base: Arc<CanonicalReasonBase>,
    excluded: BTreeSet<usize>,
    additions: BTreeSet<Reason>,
}

impl CompletionReasonUnion {
    /// Effective canonical view used at publication and test boundaries.
    pub(super) fn iter(&self) -> impl Iterator<Item = &Reason> {
        let mut base = self
            .base
            .reasons
            .iter()
            .enumerate()
            .filter(|(index, _)| !self.excluded.contains(index))
            .map(|(_, reason)| reason)
            .peekable();
        let mut additions = self.additions.iter().peekable();
        std::iter::from_fn(move || match (base.peek(), additions.peek()) {
            (Some(left), Some(right)) if left < right => base.next(),
            (Some(_), Some(_)) => additions.next(),
            (Some(_), None) => base.next(),
            (None, _) => additions.next(),
        })
    }

    pub(super) fn from_shared_with_poll<P>(
        shared: &CompletionReasons,
        cancelled: &mut P,
    ) -> Option<Self>
    where
        P: FnMut() -> bool + ?Sized,
    {
        assert!(
            shared.is_shared(),
            "completion union requires a shared completion base"
        );
        let CompletionReasonsRepr::Factored {
            base,
            excluded,
            additions,
        } = &shared.0
        else {
            unreachable!("shared completion representation was not factored")
        };
        if cancelled() {
            return None;
        }
        let mut retained_excluded = BTreeSet::new();
        for &index in excluded.iter() {
            if cancelled() {
                return None;
            }
            assert!(
                index < base.reasons.len(),
                "shared completion exclusion must name its base"
            );
            retained_excluded.insert(index);
        }
        let mut retained_additions = BTreeSet::new();
        for &reason in additions.iter() {
            if cancelled() {
                return None;
            }
            assert!(
                base.reasons.binary_search(&reason).is_err(),
                "shared completion addition must be outside its base"
            );
            retained_additions.insert(reason);
        }
        Some(Self {
            base: base.clone(),
            excluded: retained_excluded,
            additions: retained_additions,
        })
    }

    pub(super) fn include_with_poll<P>(
        &mut self,
        incoming: &CompletionReasons,
        cancelled: &mut P,
    ) -> Option<()>
    where
        P: FnMut() -> bool + ?Sized,
    {
        if cancelled() {
            return None;
        }
        match &incoming.0 {
            CompletionReasonsRepr::Factored {
                base,
                excluded,
                additions,
            } if Arc::ptr_eq(&self.base, base) => {
                let mut intersection = BTreeSet::new();
                for &index in self.excluded.iter() {
                    if cancelled() {
                        return None;
                    }
                    if excluded.binary_search(&index).is_ok() {
                        intersection.insert(index);
                    }
                }
                self.excluded = intersection;
                // Only incoming sparse additions are visited; accumulated
                // additions are never rebuilt on ordinary inclusion.
                for &reason in additions.iter() {
                    if cancelled() {
                        return None;
                    }
                    self.additions.insert(reason);
                }
                Some(())
            }
            _ => {
                for &reason in incoming.iter() {
                    self.include_reason_with_poll(reason, cancelled)?;
                }
                Some(())
            }
        }
    }

    pub(super) fn include_reason_with_poll<P>(
        &mut self,
        reason: Reason,
        cancelled: &mut P,
    ) -> Option<()>
    where
        P: FnMut() -> bool + ?Sized,
    {
        if cancelled() {
            return None;
        }
        match binary_search_with_poll(&self.base.reasons, &reason, cancelled)? {
            Ok(index) => {
                self.excluded.remove(&index);
            }
            Err(_) => {
                self.additions.insert(reason);
            }
        }
        Some(())
    }

    pub(super) fn finish_with_poll<P>(self, cancelled: &mut P) -> Option<CompletionReasons>
    where
        P: FnMut() -> bool + ?Sized,
    {
        if cancelled() {
            return None;
        }
        let mut excluded = Vec::with_capacity(self.excluded.len());
        for index in self.excluded {
            if cancelled() {
                return None;
            }
            excluded.push(index);
        }
        let mut additions = Vec::with_capacity(self.additions.len());
        for reason in self.additions {
            if cancelled() {
                return None;
            }
            additions.push(reason);
        }
        Some(
            CompletionReasons::from_validated_base_parts(
                self.base,
                excluded.into_boxed_slice(),
                additions.into_boxed_slice(),
            )
            .expect("a union of nonempty shared evidence remains nonempty"),
        )
    }

    pub(super) fn contains_with_poll<P>(&self, reason: &Reason, cancelled: &mut P) -> Option<bool>
    where
        P: FnMut() -> bool + ?Sized,
    {
        if cancelled() {
            return None;
        }
        match binary_search_with_poll(&self.base.reasons, reason, cancelled)? {
            Ok(index) => Some(!self.excluded.contains(&index)),
            Err(_) => Some(self.additions.contains(reason)),
        }
    }

    pub(super) fn clone_with_poll<P>(&self, cancelled: &mut P) -> Option<Self>
    where
        P: FnMut() -> bool + ?Sized,
    {
        if cancelled() {
            return None;
        }
        let mut excluded = BTreeSet::new();
        for &index in &self.excluded {
            if cancelled() {
                return None;
            }
            excluded.insert(index);
        }
        let mut additions = BTreeSet::new();
        for &reason in &self.additions {
            if cancelled() {
                return None;
            }
            additions.insert(reason);
        }
        Some(Self {
            base: self.base.clone(),
            excluded,
            additions,
        })
    }
}

impl From<Box<[ResolutionIncompleteReason]>> for CompletionReasons {
    fn from(reasons: Box<[ResolutionIncompleteReason]>) -> Self {
        Self(CompletionReasonsRepr::Raw(reasons))
    }
}

impl From<Vec<ResolutionIncompleteReason>> for CompletionReasons {
    fn from(reasons: Vec<ResolutionIncompleteReason>) -> Self {
        Self::from(reasons.into_boxed_slice())
    }
}

impl CompletionReasons {
    pub(crate) fn canonical(reasons: Vec<Reason>) -> Self {
        assert!(
            !reasons.is_empty(),
            "incomplete resolution requires a reason"
        );
        Self(CompletionReasonsRepr::Raw(reasons.into_boxed_slice()))
    }

    pub(crate) fn from_validated_canonical_box(reasons: Box<[Reason]>) -> Self {
        debug_assert!(!reasons.is_empty());
        debug_assert!(reasons.windows(2).all(|pair| pair[0] < pair[1]));
        Self(CompletionReasonsRepr::Raw(reasons))
    }

    /// One operation-wide evidence set, published directly as a shared base.
    ///
    /// The candidate gap box is the same set of reasons for every read in one
    /// direction of one request, it is already canonical when its reader
    /// builds it, and the request then combines it with a small per-reference
    /// completion thousands of times. Publishing it as a base makes each of
    /// those a merge of two sparse deltas over one `Arc`; the raw form makes
    /// each one a copy, a sort and a set insertion of the whole box.
    /// `to_shared_with_poll` would reach the same value through a `BTreeSet`
    /// of every reason, which is the cost this constructor exists to avoid.
    ///
    /// `reasons` must be strictly sorted and deduplicated; the caller owns
    /// that order, because the positions it passes to
    /// [`Self::shared_without_positions`] index it.
    pub(crate) fn shared_from_canonical(reasons: Box<[Reason]>) -> Self {
        assert!(
            !reasons.is_empty(),
            "incomplete resolution requires a reason"
        );
        debug_assert!(reasons.windows(2).all(|pair| pair[0] < pair[1]));
        Self(CompletionReasonsRepr::Factored {
            base: Arc::new(CanonicalReasonBase {
                fingerprint: fingerprint(&reasons),
                reasons,
            }),
            excluded: Box::new([]),
            additions: Box::new([]),
        })
    }

    /// The same shared base with a sparse set of its positions removed.
    ///
    /// `excluded` names positions of the base in strictly increasing order.
    /// `None` says every reason was removed, which is a complete answer. The
    /// result keeps the base, so a union with any other value over that base
    /// stays a merge of two sparse deltas rather than a set rebuild.
    ///
    /// This is for a reader that publishes one base and then hands out
    /// filtered views of it, so the value it is called on carries the whole
    /// base and no deltas of its own.
    pub(crate) fn shared_without_positions(&self, excluded: Box<[usize]>) -> Option<Self> {
        let CompletionReasonsRepr::Factored {
            base,
            excluded: base_excluded,
            additions,
        } = &self.0
        else {
            panic!("a filtered view requires a shared completion base")
        };
        assert!(
            base_excluded.is_empty() && additions.is_empty(),
            "a filtered view requires the whole shared base, not a delta of it"
        );
        Self::from_validated_base_parts(base.clone(), excluded, Box::new([]))
    }

    fn from_validated_base_parts(
        base: Arc<CanonicalReasonBase>,
        excluded: Box<[usize]>,
        additions: Box<[Reason]>,
    ) -> Option<Self> {
        debug_assert!(
            excluded.windows(2).all(|pair| pair[0] < pair[1])
                && excluded.iter().all(|&index| index < base.reasons.len())
                && additions.windows(2).all(|pair| pair[0] < pair[1])
                && additions
                    .iter()
                    .all(|reason| base.reasons.binary_search(reason).is_err())
        );
        if base.reasons.len() == excluded.len() && additions.is_empty() {
            return None;
        }
        Some(Self(CompletionReasonsRepr::Factored {
            base,
            excluded,
            additions,
        }))
    }

    pub(crate) fn is_shared(&self) -> bool {
        matches!(&self.0, CompletionReasonsRepr::Factored { .. })
    }

    /// Promote one canonical source-wide completion to a shared-base value.
    ///
    /// A factored value is already promoted and is only cooperatively cloned.
    /// A raw value is canonicalized once while polling each source reason;
    /// the resulting immutable base is then shared by every local union.
    pub(crate) fn to_shared_with_poll<P>(&self, cancelled: &mut P) -> Option<Self>
    where
        P: FnMut() -> bool + ?Sized,
    {
        match &self.0 {
            CompletionReasonsRepr::Factored { .. } => self.clone_with_poll(cancelled),
            CompletionReasonsRepr::Raw(reasons) => {
                let mut canonical = BTreeSet::new();
                for &reason in reasons.iter() {
                    if cancelled() {
                        return None;
                    }
                    canonical.insert(reason);
                }
                if canonical.is_empty() {
                    return self.clone_with_poll(cancelled);
                }
                let mut canonical_reasons = Vec::with_capacity(canonical.len());
                let mut base_fingerprint = Fingerprint::empty();
                while let Some(reason) = canonical.pop_first() {
                    if cancelled() {
                        return None;
                    }
                    base_fingerprint.include(reason);
                    canonical_reasons.push(reason);
                }
                let canonical_reasons = canonical_reasons.into_boxed_slice();
                let base = Arc::new(CanonicalReasonBase {
                    fingerprint: base_fingerprint,
                    reasons: canonical_reasons,
                });
                Some(
                    Self::from_validated_base_parts(base, Box::new([]), Box::new([]))
                        .expect("canonical promotion retains nonempty evidence"),
                )
            }
        }
    }

    /// Number of represented copy units in the cooperative clone path.  A raw
    /// value retains its historical one-unit-per-reason charge; a factored
    /// value charges its shared handle once and then its local deltas.
    pub(crate) fn clone_work_len(&self) -> usize {
        match &self.0 {
            CompletionReasonsRepr::Raw(reasons) => reasons.len(),
            CompletionReasonsRepr::Factored {
                excluded,
                additions,
                ..
            } => 1 + excluded.len() + additions.len(),
        }
    }

    /// Return the commutative hash payload without materializing shared base
    /// evidence.  Raw values poll once per represented reason; factored values
    /// poll once for the shared handle and once per sparse delta.
    pub(crate) fn fingerprint_with_poll<P>(&self, cancelled: &mut P) -> Option<(usize, u64, u64)>
    where
        P: FnMut() -> bool + ?Sized,
    {
        match &self.0 {
            CompletionReasonsRepr::Raw(reasons) => {
                let mut fingerprint = Fingerprint::empty();
                for &reason in reasons.iter() {
                    if cancelled() {
                        return None;
                    }
                    fingerprint.include(reason);
                }
                Some((fingerprint.len, fingerprint.sum, fingerprint.xor))
            }
            CompletionReasonsRepr::Factored {
                base,
                excluded,
                additions,
            } => {
                if cancelled() {
                    return None;
                }
                let mut fingerprint = base.fingerprint;
                for &index in excluded.iter() {
                    if cancelled() {
                        return None;
                    }
                    fingerprint.exclude(base.reasons[index]);
                }
                for &reason in additions.iter() {
                    if cancelled() {
                        return None;
                    }
                    fingerprint.include(reason);
                }
                Some((fingerprint.len, fingerprint.sum, fingerprint.xor))
            }
        }
    }

    pub fn iter(&self) -> CompletionReasonIter<'_> {
        match &self.0 {
            CompletionReasonsRepr::Raw(reasons) => CompletionReasonIter {
                repr: CompletionReasonIterRepr::Raw(reasons.iter()),
            },
            CompletionReasonsRepr::Factored {
                base,
                excluded,
                additions,
            } => CompletionReasonIter {
                repr: CompletionReasonIterRepr::Factored {
                    base: &base.reasons,
                    excluded,
                    additions,
                    base_position: 0,
                    excluded_position: 0,
                    additions_position: 0,
                },
            },
        }
    }

    pub fn len(&self) -> usize {
        match &self.0 {
            CompletionReasonsRepr::Raw(reasons) => reasons.len(),
            CompletionReasonsRepr::Factored {
                base,
                excluded,
                additions,
            } => base.reasons.len() - excluded.len() + additions.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get(&self, index: usize) -> Option<&ResolutionIncompleteReason> {
        match &self.0 {
            CompletionReasonsRepr::Raw(reasons) => reasons.get(index),
            CompletionReasonsRepr::Factored {
                base,
                excluded,
                additions,
            } if excluded.is_empty() && additions.is_empty() => base.reasons.get(index),
            _ => self.iter().nth(index),
        }
    }

    pub fn contains(&self, reason: &ResolutionIncompleteReason) -> bool {
        match &self.0 {
            CompletionReasonsRepr::Raw(reasons) => reasons.contains(reason),
            CompletionReasonsRepr::Factored {
                base,
                excluded,
                additions,
            } => match base.reasons.binary_search(reason) {
                Ok(index) => excluded.binary_search(&index).is_err(),
                Err(_) => additions.binary_search(reason).is_ok(),
            },
        }
    }

    pub fn into_vec(self) -> Vec<ResolutionIncompleteReason> {
        match self.0 {
            CompletionReasonsRepr::Raw(reasons) => reasons.into_vec(),
            CompletionReasonsRepr::Factored {
                base,
                excluded,
                additions,
            } => {
                let mut reasons =
                    Vec::with_capacity(base.reasons.len() - excluded.len() + additions.len());
                let iterator = CompletionReasonIter {
                    repr: CompletionReasonIterRepr::Factored {
                        base: &base.reasons,
                        excluded: &excluded,
                        additions: &additions,
                        base_position: 0,
                        excluded_position: 0,
                        additions_position: 0,
                    },
                };
                for reason in iterator {
                    reasons.push(*reason);
                }
                reasons
            }
        }
    }

    pub(crate) fn clone_with_poll<P>(&self, cancelled: &mut P) -> Option<Self>
    where
        P: FnMut() -> bool + ?Sized,
    {
        match &self.0 {
            CompletionReasonsRepr::Raw(reasons) => {
                if cancelled() {
                    return None;
                }
                let mut copy = Vec::with_capacity(reasons.len());
                for &reason in reasons.iter() {
                    if cancelled() {
                        return None;
                    }
                    copy.push(reason);
                }
                Some(Self::from(copy))
            }
            CompletionReasonsRepr::Factored {
                base,
                excluded,
                additions,
            } => {
                if cancelled() {
                    return None;
                }
                let excluded = copy_slice_with_poll(excluded, cancelled)?;
                let additions = copy_slice_with_poll(additions, cancelled)?;
                Some(
                    Self::from_validated_base_parts(base.clone(), excluded, additions)
                        .expect("cloning a nonempty factored completion preserves evidence"),
                )
            }
        }
    }

    pub(crate) fn contains_with_poll<P>(&self, reason: &Reason, cancelled: &mut P) -> Option<bool>
    where
        P: FnMut() -> bool + ?Sized,
    {
        match &self.0 {
            CompletionReasonsRepr::Raw(reasons) => {
                for &candidate in reasons.iter() {
                    if cancelled() {
                        return None;
                    }
                    if candidate == *reason {
                        return Some(true);
                    }
                }
                Some(false)
            }
            CompletionReasonsRepr::Factored {
                base,
                excluded,
                additions,
            } => {
                if cancelled() {
                    return None;
                }
                match binary_search_with_poll(&base.reasons, reason, cancelled)? {
                    Ok(index) => {
                        Some(binary_search_with_poll(excluded, &index, cancelled)?.is_err())
                    }
                    Err(_) => Some(binary_search_with_poll(additions, reason, cancelled)?.is_ok()),
                }
            }
        }
    }

    pub(crate) fn union_with_poll<P>(&self, other: &Self, cancelled: &mut P) -> Option<Self>
    where
        P: FnMut() -> bool + ?Sized,
    {
        match (&self.0, &other.0) {
            (CompletionReasonsRepr::Raw(left), CompletionReasonsRepr::Raw(right)) => {
                canonical_union_with_poll(left.iter().copied(), right.iter().copied(), cancelled)
            }
            (CompletionReasonsRepr::Factored { .. }, CompletionReasonsRepr::Raw(raw)) => {
                factored_union_raw_with_poll(self, raw, cancelled)
            }
            (CompletionReasonsRepr::Raw(raw), CompletionReasonsRepr::Factored { .. }) => {
                factored_union_raw_with_poll(other, raw, cancelled)
            }
            (
                CompletionReasonsRepr::Factored {
                    base: left_base,
                    excluded: left_excluded,
                    additions: left_additions,
                },
                CompletionReasonsRepr::Factored {
                    base: right_base,
                    excluded: right_excluded,
                    additions: right_additions,
                },
            ) if Arc::ptr_eq(left_base, right_base) => {
                if cancelled() {
                    return None;
                }
                let mut excluded =
                    Vec::with_capacity(left_excluded.len().min(right_excluded.len()));
                let mut left_position = 0;
                let mut right_position = 0;
                while left_position < left_excluded.len() && right_position < right_excluded.len() {
                    if cancelled() {
                        return None;
                    }
                    match left_excluded[left_position].cmp(&right_excluded[right_position]) {
                        Ordering::Less => left_position += 1,
                        Ordering::Greater => right_position += 1,
                        Ordering::Equal => {
                            excluded.push(left_excluded[left_position]);
                            left_position += 1;
                            right_position += 1;
                        }
                    }
                }
                let additions = canonical_additions_union_with_poll(
                    left_additions.iter().copied(),
                    right_additions.iter().copied(),
                    cancelled,
                )?;
                Some(
                    Self::from_validated_base_parts(
                        left_base.clone(),
                        excluded.into_boxed_slice(),
                        additions,
                    )
                    .expect("a union of nonempty factored values is nonempty"),
                )
            }
            _ => canonical_union_with_poll(self.iter().copied(), other.iter().copied(), cancelled),
        }
    }

    pub fn union(&self, other: &Self) -> Self {
        let mut never_cancelled = || false;
        self.union_with_poll(other, &mut never_cancelled)
            .expect("the non-cancellable completion union cannot be cancelled")
    }

    pub(crate) fn without_reasons_with_poll<I, P>(
        &self,
        reasons: I,
        cancelled: &mut P,
    ) -> Option<Option<Self>>
    where
        I: IntoIterator<Item = Reason>,
        P: FnMut() -> bool + ?Sized,
    {
        let mut removed = BTreeSet::new();
        for reason in reasons {
            if cancelled() {
                return None;
            }
            removed.insert(reason);
        }
        match &self.0 {
            CompletionReasonsRepr::Raw(current) => {
                let mut filtered = Vec::with_capacity(current.len());
                for &reason in current.iter() {
                    if cancelled() {
                        return None;
                    }
                    if !removed.contains(&reason) {
                        filtered.push(reason);
                    }
                }
                Some(if filtered.is_empty() {
                    current.is_empty().then(|| Self::from(filtered))
                } else {
                    Some(Self::from(filtered))
                })
            }
            CompletionReasonsRepr::Factored {
                base,
                excluded: current_excluded,
                additions: current_additions,
            } => {
                if cancelled() {
                    return None;
                }
                let mut excluded = copy_slice_with_poll(current_excluded, cancelled)?.into_vec();
                for reason in removed.iter() {
                    if cancelled() {
                        return None;
                    }
                    if let Ok(index) = binary_search_with_poll(&base.reasons, reason, cancelled)? {
                        match binary_search_with_poll(&excluded, &index, cancelled)? {
                            Ok(_) => {}
                            Err(position) => excluded.insert(position, index),
                        }
                    }
                }
                let mut additions = Vec::with_capacity(current_additions.len());
                for &reason in current_additions.iter() {
                    if cancelled() {
                        return None;
                    }
                    if !removed.contains(&reason) {
                        additions.push(reason);
                    }
                }
                Some(Self::from_validated_base_parts(
                    base.clone(),
                    excluded.into_boxed_slice(),
                    additions.into_boxed_slice(),
                ))
            }
        }
    }

    pub fn without_reasons(
        &self,
        reasons: impl IntoIterator<Item = ResolutionIncompleteReason>,
    ) -> Option<Self> {
        let mut never_cancelled = || false;
        self.without_reasons_with_poll(reasons, &mut never_cancelled)
            .expect("the non-cancellable completion filter cannot be cancelled")
    }

    pub(crate) fn equals_with_poll<P>(&self, other: &Self, cancelled: &mut P) -> Option<bool>
    where
        P: FnMut() -> bool + ?Sized,
    {
        match (&self.0, &other.0) {
            (
                CompletionReasonsRepr::Factored {
                    base: left_base,
                    excluded: left_excluded,
                    additions: left_additions,
                },
                CompletionReasonsRepr::Factored {
                    base: right_base,
                    excluded: right_excluded,
                    additions: right_additions,
                },
            ) if Arc::ptr_eq(left_base, right_base) => {
                if cancelled() {
                    return None;
                }
                if left_excluded.len() != right_excluded.len()
                    || left_additions.len() != right_additions.len()
                {
                    return Some(false);
                }
                for (left, right) in left_excluded.iter().zip(right_excluded.iter()) {
                    if cancelled() {
                        return None;
                    }
                    if left != right {
                        return Some(false);
                    }
                }
                for (left, right) in left_additions.iter().zip(right_additions.iter()) {
                    if cancelled() {
                        return None;
                    }
                    if left != right {
                        return Some(false);
                    }
                }
                Some(true)
            }
            _ => {
                if self.len() != other.len() {
                    return Some(false);
                }
                for (left, right) in self.iter().zip(other.iter()) {
                    if cancelled() {
                        return None;
                    }
                    if left != right {
                        return Some(false);
                    }
                }
                Some(true)
            }
        }
    }
}

fn copy_slice_with_poll<T: Copy, P>(values: &[T], cancelled: &mut P) -> Option<Box<[T]>>
where
    P: FnMut() -> bool + ?Sized,
{
    let mut copy = Vec::with_capacity(values.len());
    for &value in values {
        if cancelled() {
            return None;
        }
        copy.push(value);
    }
    Some(copy.into_boxed_slice())
}

fn binary_search_with_poll<T, P>(
    values: &[T],
    key: &T,
    cancelled: &mut P,
) -> Option<Result<usize, usize>>
where
    T: Ord,
    P: FnMut() -> bool + ?Sized,
{
    let mut lower = 0;
    let mut upper = values.len();
    while lower < upper {
        if cancelled() {
            return None;
        }
        let middle = lower + (upper - lower) / 2;
        match values[middle].cmp(key) {
            Ordering::Less => lower = middle + 1,
            Ordering::Greater => upper = middle,
            Ordering::Equal => return Some(Ok(middle)),
        }
    }
    Some(Err(lower))
}

fn canonical_additions_union_with_poll<I, J, P>(
    left: I,
    right: J,
    cancelled: &mut P,
) -> Option<Box<[Reason]>>
where
    I: IntoIterator<Item = Reason>,
    J: IntoIterator<Item = Reason>,
    P: FnMut() -> bool + ?Sized,
{
    let mut canonical = BTreeSet::new();
    for reason in left.into_iter().chain(right) {
        if cancelled() {
            return None;
        }
        canonical.insert(reason);
    }
    let mut reasons = Vec::with_capacity(canonical.len());
    while let Some(reason) = canonical.pop_first() {
        if cancelled() {
            return None;
        }
        reasons.push(reason);
    }
    Some(reasons.into_boxed_slice())
}

fn canonical_union_with_poll<I, J, P>(
    left: I,
    right: J,
    cancelled: &mut P,
) -> Option<CompletionReasons>
where
    I: IntoIterator<Item = Reason>,
    J: IntoIterator<Item = Reason>,
    P: FnMut() -> bool + ?Sized,
{
    let reasons = canonical_additions_union_with_poll(left, right, cancelled)?;
    assert!(
        !reasons.is_empty(),
        "incomplete resolution requires a reason"
    );
    Some(CompletionReasons::canonical(reasons.into_vec()))
}

fn factored_union_raw_with_poll<P>(
    factored: &CompletionReasons,
    raw: &[Reason],
    cancelled: &mut P,
) -> Option<CompletionReasons>
where
    P: FnMut() -> bool + ?Sized,
{
    let CompletionReasonsRepr::Factored {
        base,
        excluded,
        additions,
    } = &factored.0
    else {
        unreachable!("factored union helper requires a factored value")
    };
    if raw.is_empty() {
        return factored.clone_with_poll(cancelled);
    }

    let mut activated = BTreeSet::new();
    let mut merged_additions = BTreeSet::new();
    for &reason in additions.iter() {
        if cancelled() {
            return None;
        }
        merged_additions.insert(reason);
    }
    for &reason in raw {
        if cancelled() {
            return None;
        }
        match binary_search_with_poll(&base.reasons, &reason, cancelled)? {
            Ok(index) => {
                activated.insert(index);
            }
            Err(_) => {
                merged_additions.insert(reason);
            }
        }
    }
    let mut merged_excluded = Vec::with_capacity(excluded.len());
    for &index in excluded.iter() {
        if cancelled() {
            return None;
        }
        if !activated.contains(&index) {
            merged_excluded.push(index);
        }
    }
    let merged_additions = merged_additions.into_iter().collect::<Vec<_>>();
    Some(
        CompletionReasons::from_validated_base_parts(
            base.clone(),
            merged_excluded.into_boxed_slice(),
            merged_additions.into_boxed_slice(),
        )
        .expect("a union with a nonempty factored value is nonempty"),
    )
}

/// Iterator over the effective ordered reason sequence.
pub struct CompletionReasonIter<'a> {
    repr: CompletionReasonIterRepr<'a>,
}

enum CompletionReasonIterRepr<'a> {
    Raw(slice::Iter<'a, Reason>),
    Factored {
        base: &'a [Reason],
        excluded: &'a [usize],
        additions: &'a [Reason],
        base_position: usize,
        excluded_position: usize,
        additions_position: usize,
    },
}

impl<'a> Iterator for CompletionReasonIter<'a> {
    type Item = &'a ResolutionIncompleteReason;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.repr {
            CompletionReasonIterRepr::Raw(reasons) => reasons.next(),
            CompletionReasonIterRepr::Factored {
                base,
                excluded,
                additions,
                base_position,
                excluded_position,
                additions_position,
            } => {
                while *base_position < base.len()
                    && excluded.get(*excluded_position) == Some(&*base_position)
                {
                    *base_position += 1;
                    *excluded_position += 1;
                }
                match (base.get(*base_position), additions.get(*additions_position)) {
                    (Some(base_reason), Some(addition)) if addition < base_reason => {
                        *additions_position += 1;
                        Some(addition)
                    }
                    (Some(base_reason), _) => {
                        *base_position += 1;
                        Some(base_reason)
                    }
                    (None, Some(addition)) => {
                        *additions_position += 1;
                        Some(addition)
                    }
                    (None, None) => None,
                }
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = match &self.repr {
            CompletionReasonIterRepr::Raw(reasons) => reasons.len(),
            CompletionReasonIterRepr::Factored {
                base,
                excluded,
                additions,
                base_position,
                excluded_position,
                additions_position,
            } => {
                let excluded_remaining = excluded.len() - *excluded_position;
                let base_remaining = base.len() - *base_position;
                base_remaining - excluded_remaining + additions.len() - *additions_position
            }
        };
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for CompletionReasonIter<'_> {}

impl<'a> IntoIterator for &'a CompletionReasons {
    type Item = &'a Reason;
    type IntoIter = CompletionReasonIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl PartialEq for CompletionReasons {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (
                CompletionReasonsRepr::Factored {
                    base: left_base,
                    excluded: left_excluded,
                    additions: left_additions,
                },
                CompletionReasonsRepr::Factored {
                    base: right_base,
                    excluded: right_excluded,
                    additions: right_additions,
                },
            ) if Arc::ptr_eq(left_base, right_base) => {
                left_excluded == right_excluded && left_additions == right_additions
            }
            _ => self.iter().eq(other.iter()),
        }
    }
}

impl Eq for CompletionReasons {}

impl PartialOrd for CompletionReasons {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CompletionReasons {
    fn cmp(&self, other: &Self) -> Ordering {
        if matches!(
            (&self.0, &other.0),
            (CompletionReasonsRepr::Factored { base: left, .. },
             CompletionReasonsRepr::Factored { base: right, .. }) if Arc::ptr_eq(left, right)
        ) && self == other
        {
            return Ordering::Equal;
        }
        self.iter().cmp(other.iter())
    }
}

impl Hash for CompletionReasons {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let (len, sum, xor) = match &self.0 {
            CompletionReasonsRepr::Raw(reasons) => {
                let fingerprint = fingerprint(reasons);
                (fingerprint.len, fingerprint.sum, fingerprint.xor)
            }
            CompletionReasonsRepr::Factored {
                base,
                excluded,
                additions,
            } => {
                let mut fingerprint = base.fingerprint;
                for &index in excluded.iter() {
                    fingerprint.exclude(base.reasons[index]);
                }
                for &reason in additions.iter() {
                    fingerprint.include(reason);
                }
                (fingerprint.len, fingerprint.sum, fingerprint.xor)
            }
        };
        state.write_usize(len);
        state.write_u64(sum);
        state.write_u64(xor);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reason(name: &str) -> Reason {
        Reason::UnsupportedSemantic(super::super::SemanticId::for_test(name.as_bytes()))
    }

    #[test]
    fn factored_union_and_sparse_removal_are_extensional() {
        let a = reason("a");
        let b = reason("b");
        let c = reason("c");
        let base = CompletionReasons::from(vec![a, b]);
        let mut never_cancelled = || false;
        let factored = base
            .to_shared_with_poll(&mut never_cancelled)
            .unwrap()
            .union(&CompletionReasons::from(vec![c]));
        let mut expected = vec![a, b, c];
        expected.sort_unstable();
        assert_eq!(factored.clone().into_vec(), expected);

        let activated = factored.union(&CompletionReasons::from(vec![b]));
        assert_eq!(activated, factored);

        let removed = activated.without_reasons([b]).unwrap();
        let mut expected = vec![a, c];
        expected.sort_unstable();
        assert_eq!(removed.into_vec(), expected);
        assert_eq!(activated.without_reasons([a, b, c]), None);
    }

    #[test]
    fn raw_shape_is_preserved_and_empty_raw_unions_are_valid_with_factored() {
        let a = reason("a");
        let b = reason("b");
        let raw = CompletionReasons::from(vec![b, a, b]);
        assert_eq!(raw.clone().into_vec(), vec![b, a, b]);
        let empty = CompletionReasons::from(Vec::<Reason>::new());
        let mut expected = vec![a, b];
        expected.sort_unstable();
        assert_eq!(empty.union(&raw).into_vec(), expected);
        assert_eq!(empty.without_reasons([a]).unwrap().into_vec(), Vec::new());

        let base = CompletionReasons::from(vec![a]);
        let mut never_cancelled = || false;
        let factored = base.to_shared_with_poll(&mut never_cancelled).unwrap();
        assert_eq!(factored.union(&empty), factored);
    }

    #[test]
    fn alternate_bases_compare_and_hash_by_effective_sequence() {
        let a = reason("a");
        let b = reason("b");
        let first = CompletionReasons::from(vec![a, b]);
        let second = CompletionReasons::from(vec![a]);
        let mut never_cancelled = || false;
        let first = first.to_shared_with_poll(&mut never_cancelled).unwrap();
        let second = second.to_shared_with_poll(&mut never_cancelled).unwrap();
        let second = second.union(&CompletionReasons::from(vec![b]));
        assert_eq!(first, second);
        let mut canonical = vec![a, b];
        canonical.sort_unstable();
        let raw = CompletionReasons::from(canonical);
        assert_eq!(first, raw);

        let mut left_hasher = DefaultHasher::new();
        first.hash(&mut left_hasher);
        let mut right_hasher = DefaultHasher::new();
        raw.hash(&mut right_hasher);
        assert_eq!(left_hasher.finish(), right_hasher.finish());
        assert_eq!(first.cmp(&second), Ordering::Equal);
        let mut never_cancelled = || false;
        assert_eq!(
            first.fingerprint_with_poll(&mut never_cancelled),
            second.fingerprint_with_poll(&mut never_cancelled)
        );
    }

    #[test]
    fn small_factored_algebra_matches_set_oracle() {
        let reasons = [reason("law-a"), reason("law-b"), reason("law-c")];
        for base_mask in 1_u8..8 {
            let base_values = reasons
                .iter()
                .enumerate()
                .filter_map(|(index, &reason)| (base_mask & (1 << index) != 0).then_some(reason))
                .collect::<Vec<_>>();
            let base = CompletionReasons::from(base_values);
            let mut never_cancelled = || false;
            let base = base.to_shared_with_poll(&mut never_cancelled).unwrap();
            for additions_mask in 0_u8..8 {
                let additions = reasons
                    .iter()
                    .enumerate()
                    .filter_map(|(index, &reason)| {
                        (additions_mask & (1 << index) != 0).then_some(reason)
                    })
                    .collect::<Vec<_>>();
                let factored = base.union(&CompletionReasons::from(additions));
                for removed_mask in 0_u8..8 {
                    let mut expected = reasons
                        .iter()
                        .enumerate()
                        .filter_map(|(index, &reason)| {
                            let present =
                                base_mask & (1 << index) != 0 || additions_mask & (1 << index) != 0;
                            let removed = removed_mask & (1 << index) != 0;
                            (present && !removed).then_some(reason)
                        })
                        .collect::<Vec<_>>();
                    expected.sort_unstable();
                    let actual = factored.without_reasons(reasons.iter().enumerate().filter_map(
                        |(index, &reason)| (removed_mask & (1 << index) != 0).then_some(reason),
                    ));
                    if expected.is_empty() {
                        assert_eq!(actual, None);
                    } else {
                        assert_eq!(actual.unwrap().into_vec(), expected);
                    }
                }
            }
        }
    }

    #[test]
    fn mutable_union_merges_same_and_different_bases_exactly() {
        let a = reason("union-a");
        let b = reason("union-b");
        let c = reason("union-c");
        let d = reason("union-d");
        let shared = CompletionReasons::from(vec![a, b, c])
            .to_shared_with_poll(&mut || false)
            .unwrap();
        let left = shared.without_reasons([b]).unwrap();
        let right = shared
            .without_reasons([c])
            .unwrap()
            .union(&CompletionReasons::from(vec![d]));
        let mut union = CompletionReasonUnion::from_shared_with_poll(&left, &mut || false).unwrap();
        union.include_with_poll(&right, &mut || false).unwrap();
        union
            .include_with_poll(&CompletionReasons::from(Vec::<Reason>::new()), &mut || {
                false
            })
            .unwrap();
        assert_eq!(
            union
                .finish_with_poll(&mut || false)
                .unwrap()
                .iter()
                .copied()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([a, b, c, d])
        );

        let mut restored =
            CompletionReasonUnion::from_shared_with_poll(&left, &mut || false).unwrap();
        restored
            .include_with_poll(&CompletionReasons::from(vec![b, b]), &mut || false)
            .unwrap();
        assert_eq!(
            restored
                .finish_with_poll(&mut || false)
                .unwrap()
                .iter()
                .copied()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([a, b, c])
        );

        let alternate_base = CompletionReasons::from(vec![b, c])
            .to_shared_with_poll(&mut || false)
            .unwrap();
        let mut different =
            CompletionReasonUnion::from_shared_with_poll(&shared, &mut || false).unwrap();
        different
            .include_with_poll(&alternate_base, &mut || false)
            .unwrap();
        assert_eq!(
            different
                .finish_with_poll(&mut || false)
                .unwrap()
                .iter()
                .copied()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([a, b, c])
        );
    }

    #[test]
    fn mutable_union_exhaustive_small_set_laws() {
        let reasons = [
            reason("exhaustive-a"),
            reason("exhaustive-b"),
            reason("exhaustive-c"),
        ];
        let shared = CompletionReasons::from(reasons.to_vec())
            .to_shared_with_poll(&mut || false)
            .unwrap();
        for left_removed in 0_u8..8 {
            let left =
                shared.without_reasons(reasons.iter().enumerate().filter_map(|(index, &value)| {
                    (left_removed & (1 << index) != 0).then_some(value)
                }));
            let Some(left) = left else { continue };
            for right_removed in 0_u8..8 {
                let right = shared.without_reasons(reasons.iter().enumerate().filter_map(
                    |(index, &value)| (right_removed & (1 << index) != 0).then_some(value),
                ));
                let Some(right) = right else { continue };
                let mut union =
                    CompletionReasonUnion::from_shared_with_poll(&left, &mut || false).unwrap();
                union.include_with_poll(&right, &mut || false).unwrap();
                let expected = reasons
                    .iter()
                    .enumerate()
                    .filter_map(|(index, &value)| {
                        ((left_removed & (1 << index) == 0) || (right_removed & (1 << index) == 0))
                            .then_some(value)
                    })
                    .collect::<BTreeSet<_>>();
                assert_eq!(
                    union
                        .finish_with_poll(&mut || false)
                        .unwrap()
                        .iter()
                        .copied()
                        .collect::<BTreeSet<_>>(),
                    expected
                );
            }
        }

        for left_mask in 1_u8..8 {
            let left_values = reasons
                .iter()
                .enumerate()
                .filter_map(|(index, &value)| (left_mask & (1 << index) != 0).then_some(value))
                .collect::<Vec<_>>();
            let left = CompletionReasons::from(left_values)
                .to_shared_with_poll(&mut || false)
                .unwrap();
            for right_mask in 1_u8..8 {
                let right_values = reasons
                    .iter()
                    .enumerate()
                    .filter_map(|(index, &value)| (right_mask & (1 << index) != 0).then_some(value))
                    .collect::<Vec<_>>();
                let right = CompletionReasons::from(right_values)
                    .to_shared_with_poll(&mut || false)
                    .unwrap();
                let mut union =
                    CompletionReasonUnion::from_shared_with_poll(&left, &mut || false).unwrap();
                union.include_with_poll(&right, &mut || false).unwrap();
                let expected = reasons
                    .iter()
                    .enumerate()
                    .filter_map(|(index, &value)| {
                        (left_mask & (1 << index) != 0 || right_mask & (1 << index) != 0)
                            .then_some(value)
                    })
                    .collect::<BTreeSet<_>>();
                assert_eq!(
                    union
                        .finish_with_poll(&mut || false)
                        .unwrap()
                        .iter()
                        .copied()
                        .collect::<BTreeSet<_>>(),
                    expected
                );
            }
        }
    }

    #[test]
    fn mutable_union_contains_and_cancellation_are_transactional() {
        let a = reason("transaction-a");
        let b = reason("transaction-b");
        let c = reason("transaction-c");
        let shared = CompletionReasons::from(vec![a, b])
            .to_shared_with_poll(&mut || false)
            .unwrap();
        let mut builder =
            CompletionReasonUnion::from_shared_with_poll(&shared, &mut || false).unwrap();
        assert!(builder.contains_with_poll(&a, &mut || false).unwrap());
        assert!(!builder.contains_with_poll(&c, &mut || false).unwrap());
        assert!(builder.contains_with_poll(&a, &mut || true).is_none());

        let incoming = CompletionReasons::from(vec![c, c, a]);
        let mut polls = 0;
        assert!(
            builder
                .include_with_poll(&incoming, &mut || {
                    polls += 1;
                    polls >= 3
                })
                .is_none()
        );
        drop(builder);

        let mut retry =
            CompletionReasonUnion::from_shared_with_poll(&shared, &mut || false).unwrap();
        retry.include_with_poll(&incoming, &mut || false).unwrap();
        let retried = retry.finish_with_poll(&mut || false).unwrap();
        assert_eq!(
            retried.iter().copied().collect::<BTreeSet<_>>(),
            BTreeSet::from([a, b, c])
        );

        let staged = CompletionReasonUnion::from_shared_with_poll(&shared, &mut || false).unwrap();
        assert!(staged.clone_with_poll(&mut || true).is_none());
        assert!(staged.finish_with_poll(&mut || true).is_none());
        assert!(CompletionReasonUnion::from_shared_with_poll(&shared, &mut || true).is_none());
    }

    #[test]
    fn mutable_union_reason_includes_do_not_scan_prior_deltas() {
        let base = CompletionReasons::from(
            (0..1024)
                .map(|index| reason(&format!("large-union-base-{index}")))
                .collect::<Vec<_>>(),
        )
        .to_shared_with_poll(&mut || false)
        .unwrap();
        let target = reason("large-union-target");
        let mut early = CompletionReasonUnion::from_shared_with_poll(&base, &mut || false).unwrap();
        let mut early_polls = 0;
        early
            .include_reason_with_poll(target, &mut || {
                early_polls += 1;
                false
            })
            .unwrap();

        let mut late = CompletionReasonUnion::from_shared_with_poll(&base, &mut || false).unwrap();
        for index in 0..128 {
            late.include_reason_with_poll(
                reason(&format!("large-union-addition-{index}")),
                &mut || false,
            )
            .unwrap();
        }
        let mut late_polls = 0;
        late.include_reason_with_poll(target, &mut || {
            late_polls += 1;
            false
        })
        .unwrap();
        assert!(early_polls > 1);
        assert_eq!(late_polls, early_polls);
        assert!(early.contains_with_poll(&target, &mut || false).unwrap());
        assert!(late.contains_with_poll(&target, &mut || false).unwrap());
    }

    #[test]
    fn shared_union_intersects_exclusions_and_matches_materialized_value_laws() {
        let universe = [
            reason("base-a"),
            reason("base-b"),
            reason("base-c"),
            reason("extra"),
        ];
        let shared = CompletionReasons::from(universe[..3].to_vec())
            .to_shared_with_poll(&mut || false)
            .unwrap();
        let mut values = Vec::new();
        for excluded in 0_u8..8 {
            for extra in [false, true] {
                let with_extra = if extra {
                    shared.union(&CompletionReasons::from(vec![universe[3]]))
                } else {
                    shared.clone()
                };
                let filtered =
                    with_extra.without_reasons(universe[..3].iter().enumerate().filter_map(
                        |(index, &reason)| (excluded & (1 << index) != 0).then_some(reason),
                    ));
                let Some(value) = filtered else { continue };
                let expected = universe
                    .iter()
                    .enumerate()
                    .filter_map(|(index, &reason)| {
                        ((index < 3 && excluded & (1 << index) == 0) || (index == 3 && extra))
                            .then_some(reason)
                    })
                    .collect::<BTreeSet<_>>();
                assert_eq!(value.iter().copied().collect::<BTreeSet<_>>(), expected);
                values.push((value, expected));
            }
        }
        for (left, left_set) in &values {
            for (right, right_set) in &values {
                let combined = left.union(right);
                let expected =
                    CompletionReasons::from(left_set.union(right_set).copied().collect::<Vec<_>>());
                let alternate_base = expected.to_shared_with_poll(&mut || false).unwrap();
                for equivalent in [&expected, &alternate_base] {
                    assert_eq!(&combined, equivalent);
                    assert_eq!(combined.cmp(equivalent), Ordering::Equal);
                    let mut actual_hash = DefaultHasher::new();
                    let mut expected_hash = DefaultHasher::new();
                    combined.hash(&mut actual_hash);
                    equivalent.hash(&mut expected_hash);
                    assert_eq!(actual_hash.finish(), expected_hash.finish());
                }
            }
        }
    }

    #[test]
    fn empty_shared_deltas_still_observe_cancellation() {
        let shared = CompletionReasons::from(vec![reason("base")])
            .to_shared_with_poll(&mut || false)
            .unwrap();
        assert!(shared.clone_with_poll(&mut || true).is_none());
        assert!(shared.union_with_poll(&shared, &mut || true).is_none());
        assert!(shared.without_reasons_with_poll([], &mut || true).is_none());
        assert!(shared.equals_with_poll(&shared, &mut || true).is_none());
        assert!(shared.fingerprint_with_poll(&mut || true).is_none());
        let mut first_poll = true;
        assert!(
            shared
                .contains_with_poll(&reason("base"), &mut || { std::mem::take(&mut first_poll) })
                .is_none()
        );
    }

    #[test]
    fn shared_clone_does_not_poll_the_base() {
        let base = CompletionReasons::from(
            (0..100)
                .map(|index| reason(&format!("base-{index}")))
                .collect::<Vec<_>>(),
        );
        let mut never_cancelled = || false;
        let base = base.to_shared_with_poll(&mut never_cancelled).unwrap();
        let value = base.union(&CompletionReasons::from(vec![reason("local")]));
        let mut polls = 0;
        let clone = value.clone_with_poll(&mut || {
            polls += 1;
            false
        });
        assert!(clone.is_some());
        assert_eq!(polls, 2);
        assert_eq!(value.clone_work_len(), 2);
    }
}
