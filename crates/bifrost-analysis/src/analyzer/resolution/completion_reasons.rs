//! Completion evidence preserving the public sequence shape.
//!
//! Raw construction retains order and duplicates. Union canonicalizes evidence;
//! cooperative operations retain the donor's per-reason cancellation polls.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::slice;

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

/// Completion reasons in their original public sequence shape.
#[derive(Debug, Clone)]
pub struct CompletionReasons(Box<[Reason]>);

impl From<Box<[ResolutionIncompleteReason]>> for CompletionReasons {
    fn from(reasons: Box<[ResolutionIncompleteReason]>) -> Self {
        Self(reasons)
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
        Self(reasons.into_boxed_slice())
    }

    pub fn iter(&self) -> CompletionReasonIter<'_> {
        CompletionReasonIter {
            reasons: self.0.iter(),
        }
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn get(&self, index: usize) -> Option<&ResolutionIncompleteReason> {
        self.0.get(index)
    }
    pub fn contains(&self, reason: &ResolutionIncompleteReason) -> bool {
        self.0.contains(reason)
    }
    pub fn into_vec(self) -> Vec<ResolutionIncompleteReason> {
        self.0.into_vec()
    }

    pub(crate) fn clone_work_len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn clone_with_poll<P>(&self, cancelled: &mut P) -> Option<Self>
    where
        P: FnMut() -> bool + ?Sized,
    {
        let reasons = &self.0;
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

    pub(crate) fn equals_with_poll<P>(&self, other: &Self, cancelled: &mut P) -> Option<bool>
    where
        P: FnMut() -> bool + ?Sized,
    {
        if self.0.len() != other.0.len() {
            return Some(false);
        }
        for (left, right) in self.0.iter().zip(other.0.iter()) {
            if cancelled() {
                return None;
            }
            if left != right {
                return Some(false);
            }
        }
        Some(true)
    }
    pub(crate) fn union_with_poll<P>(&self, other: &Self, cancelled: &mut P) -> Option<Self>
    where
        P: FnMut() -> bool + ?Sized,
    {
        canonical_union_with_poll(self.0.iter().copied(), other.0.iter().copied(), cancelled)
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
        let current = &self.0;
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
    pub fn without_reasons(
        &self,
        reasons: impl IntoIterator<Item = ResolutionIncompleteReason>,
    ) -> Option<Self> {
        let mut never_cancelled = || false;
        self.without_reasons_with_poll(reasons, &mut never_cancelled)
            .expect("the non-cancellable completion filter cannot be cancelled")
    }

    pub(crate) fn fingerprint_with_poll<P>(&self, cancelled: &mut P) -> Option<(usize, u64, u64)>
    where
        P: FnMut() -> bool + ?Sized,
    {
        let mut fingerprint = Fingerprint::empty();
        for &reason in self.0.iter() {
            if cancelled() {
                return None;
            }
            fingerprint.include(reason);
        }
        Some((fingerprint.len, fingerprint.sum, fingerprint.xor))
    }
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

/// Iterator over the effective ordered reason sequence.
pub struct CompletionReasonIter<'a> {
    reasons: slice::Iter<'a, Reason>,
}
impl<'a> Iterator for CompletionReasonIter<'a> {
    type Item = &'a ResolutionIncompleteReason;
    fn next(&mut self) -> Option<Self::Item> {
        self.reasons.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.reasons.len();
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
        self.iter().eq(other.iter())
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
        self.iter().cmp(other.iter())
    }
}
impl Hash for CompletionReasons {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let fingerprint = fingerprint(&self.0);
        state.write_usize(fingerprint.len);
        state.write_u64(fingerprint.sum);
        state.write_u64(fingerprint.xor);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reason(name: &str) -> Reason {
        Reason::UnsupportedSemantic(super::super::SemanticId::hash_bytes(name.as_bytes()))
    }

    #[test]
    fn raw_shape_is_preserved_and_union_canonicalizes_evidence() {
        let a = reason("a");
        let b = reason("b");
        let raw = CompletionReasons::from(vec![b, a, b]);
        assert_eq!(raw.clone().into_vec(), vec![b, a, b]);
        let empty = CompletionReasons::from(Vec::<Reason>::new());
        let mut expected = vec![a, b];
        expected.sort_unstable();
        assert_eq!(empty.union(&raw).into_vec(), expected);
        assert_eq!(empty.without_reasons([a]).unwrap().into_vec(), Vec::new());
        assert_eq!(raw.without_reasons([a]).unwrap().into_vec(), vec![b, b]);
        assert_eq!(raw.without_reasons([a, b]), None);
    }

    #[test]
    fn canonical_union_equality_order_and_hash_agree() {
        let a = reason("a");
        let b = reason("b");
        let left = CompletionReasons::from(vec![b, a, b]);
        let right = CompletionReasons::from(vec![a, b]);
        assert_ne!(left, right);
        let first = left.union(&right);
        let second = right.union(&left);
        assert_eq!(first, second);
        assert_eq!(first.cmp(&second), Ordering::Equal);
        let digest = |value: &CompletionReasons| {
            let mut hasher = DefaultHasher::new();
            value.hash(&mut hasher);
            hasher.finish()
        };
        assert_eq!(digest(&first), digest(&second));
        assert_eq!(first.union(&first), first);
    }

    #[test]
    fn raw_cooperative_operations_stop_without_publishing_prefixes() {
        let a = reason("a");
        let b = reason("b");
        let raw = CompletionReasons::from(vec![a, b, a]);
        let mut clone_polls = 0;
        assert!(
            raw.clone_with_poll(&mut || {
                clone_polls += 1;
                clone_polls == 3
            })
            .is_none()
        );
        assert_eq!(clone_polls, 3);
        let mut union_polls = 0;
        assert!(
            raw.union_with_poll(&raw, &mut || {
                union_polls += 1;
                union_polls == 4
            })
            .is_none()
        );
        assert_eq!(union_polls, 4);
        let mut removal_polls = 0;
        assert!(
            raw.without_reasons_with_poll([a], &mut || {
                removal_polls += 1;
                removal_polls == 3
            })
            .is_none()
        );
        assert_eq!(removal_polls, 3);
        assert_eq!(raw.into_vec(), vec![a, b, a]);
    }

    #[test]
    #[should_panic(expected = "incomplete resolution requires a reason")]
    fn union_of_two_empty_raw_values_rejects_missing_evidence() {
        let empty = CompletionReasons::from(Vec::<Reason>::new());
        empty.union(&empty);
    }
}
