use std::{error::Error, fmt, mem::size_of_val};

use sha2::{Digest, Sha256};

use crate::hash::HashMap;
use crate::value_flow::ValueFlowEventKey;
use brokk_bifrost_core::analyzer::dense_id::define_dense_id;

pub const MAX_TAINT_CLASSES: usize = 4_096;

define_dense_id! {
    /// Run-local dense bit position for one stable taint class.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub(crate) struct TaintClassId {
        new: pub(crate),
        get: pub(crate),
        index: pub(crate),
        try_from_index: pub(crate),
    }
}

/// Stable propagation-class identity; unlike a dense bit, this may cross runs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceClassId(Box<str>);

impl SourceClassId {
    pub fn new(value: impl Into<String>) -> Result<Self, TaintModelError> {
        let value = value.into();
        if value.is_empty()
            || value.trim() != value
            || value.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(TaintModelError::InvalidSourceClassId);
        }
        Ok(Self(value.into_boxed_str()))
    }

    pub const fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stable structured identity for one concrete source occurrence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceEventKey(ValueFlowEventKey);

impl SourceEventKey {
    pub const fn new(key: ValueFlowEventKey) -> Self {
        Self(key)
    }

    pub const fn value_flow_key(&self) -> &ValueFlowEventKey {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaintUniverseHash([u8; 32]);

impl TaintUniverseHash {
    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Display for TaintUniverseHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Canonical stable-to-dense class mapping for one analysis batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintUniverse {
    classes: Box<[SourceClassId]>,
    ids: HashMap<SourceClassId, TaintClassId>,
    hash: TaintUniverseHash,
}

impl TaintUniverse {
    pub fn new(mut classes: Vec<SourceClassId>) -> Result<Self, TaintModelError> {
        classes.sort();
        if classes.is_empty() || classes.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(TaintModelError::InvalidUniverse);
        }
        if classes.len() > MAX_TAINT_CLASSES {
            return Err(TaintModelError::UniverseTooLarge);
        }
        let mut digest = Sha256::new();
        digest.update(b"bifrost-taint-universe-v1\0");
        let mut ids = HashMap::default();
        for (index, class) in classes.iter().enumerate() {
            let id = TaintClassId::try_from_index(index)
                .map_err(|_| TaintModelError::UniverseTooLarge)?;
            digest.update((class.as_str().len() as u64).to_le_bytes());
            digest.update(class.as_str().as_bytes());
            ids.insert(class.clone(), id);
        }
        let hash = TaintUniverseHash(digest.finalize().into());
        Ok(Self {
            classes: classes.into_boxed_slice(),
            ids,
            hash,
        })
    }

    pub fn classes(&self) -> &[SourceClassId] {
        &self.classes
    }

    pub(crate) fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(size_of_val(&*self.classes))
            .saturating_add(
                self.classes
                    .iter()
                    .map(|class| class.as_str().len())
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(
                self.ids
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(SourceClassId, TaintClassId)>()),
            )
            .saturating_add(
                self.ids
                    .keys()
                    .map(|class| class.as_str().len())
                    .fold(0usize, usize::saturating_add),
            )
    }

    pub const fn hash(&self) -> TaintUniverseHash {
        self.hash
    }

    pub(crate) fn class_id(&self, stable: &SourceClassId) -> Option<TaintClassId> {
        self.ids.get(stable).copied()
    }

    pub(crate) fn stable_id(&self, dense: TaintClassId) -> Option<&SourceClassId> {
        self.classes.get(dense.get() as usize)
    }

    pub fn empty_set(&self) -> TaintClassSet {
        TaintClassSet::empty(self.hash, self.classes.len())
    }

    pub fn class_set<'a>(
        &self,
        classes: impl IntoIterator<Item = &'a SourceClassId>,
    ) -> Result<TaintClassSet, TaintModelError> {
        let mut set = self.empty_set();
        for class in classes {
            set.insert_dense(
                self.class_id(class)
                    .ok_or(TaintModelError::UnknownSourceClass)?,
            );
        }
        Ok(set)
    }

    pub fn set_contains(
        &self,
        set: &TaintClassSet,
        class: &SourceClassId,
    ) -> Result<bool, TaintModelError> {
        self.validate_set(set)?;
        Ok(self
            .class_id(class)
            .is_some_and(|class| set.contains_dense(class)))
    }

    pub fn stable_classes<'set>(
        &'set self,
        set: &'set TaintClassSet,
    ) -> Result<Vec<&'set SourceClassId>, TaintModelError> {
        self.validate_set(set)?;
        Ok(set
            .iter_dense()
            .filter_map(|class| self.stable_id(class))
            .collect())
    }

    pub(crate) fn validate_set(&self, set: &TaintClassSet) -> Result<(), TaintModelError> {
        if set.universe != self.hash || set.class_count() != self.classes.len() {
            return Err(TaintModelError::UniverseMismatch);
        }
        Ok(())
    }
}

/// Finite set of dense class positions branded by its exact bit width.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaintClassSet {
    universe: TaintUniverseHash,
    class_count: u32,
    words: Box<[u64]>,
}

impl TaintClassSet {
    pub(crate) fn empty(universe: TaintUniverseHash, class_count: usize) -> Self {
        Self {
            universe,
            class_count: u32::try_from(class_count).expect("taint universe already fits u32"),
            words: vec![0; class_count.div_ceil(64)].into_boxed_slice(),
        }
    }

    pub const fn class_count(&self) -> usize {
        self.class_count as usize
    }

    pub const fn universe(&self) -> TaintUniverseHash {
        self.universe
    }

    pub(crate) fn retained_heap_bytes(&self) -> usize {
        size_of_val(&*self.words)
    }

    pub(crate) fn empty_like(&self) -> Self {
        Self::empty(self.universe, self.class_count())
    }

    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|word| *word == 0)
    }

    pub(crate) fn contains_dense(&self, class: TaintClassId) -> bool {
        let index = class.index();
        index < self.class_count() && self.words[index / 64] & (1_u64 << (index % 64)) != 0
    }

    pub(crate) fn insert_dense(&mut self, class: TaintClassId) -> bool {
        let index = class.index();
        if index >= self.class_count() {
            return false;
        }
        let mask = 1_u64 << (index % 64);
        let word = &mut self.words[index / 64];
        let changed = *word & mask == 0;
        *word |= mask;
        changed
    }

    pub(crate) fn remove_dense(&mut self, class: TaintClassId) -> bool {
        let index = class.index();
        if index >= self.class_count() {
            return false;
        }
        let mask = 1_u64 << (index % 64);
        let word = &mut self.words[index / 64];
        let changed = *word & mask != 0;
        *word &= !mask;
        changed
    }

    pub fn union(&self, other: &Self) -> Self {
        self.zip(other, |left, right| left | right)
    }

    pub fn subtract(&self, removed: &Self) -> Self {
        self.zip(removed, |left, right| left & !right)
    }

    pub fn intersection(&self, other: &Self) -> Self {
        self.zip(other, |left, right| left & right)
    }

    pub fn intersects(&self, other: &Self) -> bool {
        self.assert_compatible(other);
        self.words
            .iter()
            .zip(&other.words)
            .any(|(left, right)| left & right != 0)
    }

    pub fn len(&self) -> usize {
        self.words
            .iter()
            .map(|word| word.count_ones() as usize)
            .sum()
    }

    pub(crate) fn union_with(&mut self, other: &Self) {
        self.assert_compatible(other);
        for (target, incoming) in self.words.iter_mut().zip(&other.words) {
            *target |= incoming;
        }
    }

    pub(crate) fn iter_dense(&self) -> impl Iterator<Item = TaintClassId> + '_ {
        (0..self.class_count()).filter_map(|index| {
            let id = TaintClassId::try_from_index(index).ok()?;
            self.contains_dense(id).then_some(id)
        })
    }

    fn zip(&self, other: &Self, operation: impl Fn(u64, u64) -> u64) -> Self {
        self.assert_compatible(other);
        Self {
            universe: self.universe,
            class_count: self.class_count,
            words: self
                .words
                .iter()
                .zip(&other.words)
                .map(|(left, right)| operation(*left, *right))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        }
    }

    fn assert_compatible(&self, other: &Self) {
        assert_eq!(
            (self.universe, self.class_count),
            (other.universe, other.class_count),
            "taint class sets require one universe"
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintModelError {
    InvalidSourceClassId,
    InvalidUniverse,
    UniverseTooLarge,
    UnknownSourceClass,
    UniverseMismatch,
}

impl fmt::Display for TaintModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSourceClassId => formatter.write_str("invalid stable source-class ID"),
            Self::InvalidUniverse => {
                formatter.write_str("taint universe must be non-empty and unique")
            }
            Self::UniverseTooLarge => {
                formatter.write_str("taint universe exceeds dense ID capacity")
            }
            Self::UnknownSourceClass => {
                formatter.write_str("source class is not in the taint universe")
            }
            Self::UniverseMismatch => {
                formatter.write_str("taint class set belongs to a different universe")
            }
        }
    }
}

impl Error for TaintModelError {}
