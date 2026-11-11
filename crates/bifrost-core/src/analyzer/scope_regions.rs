//! Byte-region scope lookup: which lexical scope value governs one byte of a
//! source file.
//!
//! Several languages have scopes that are not tree nodes: a C# file-scoped
//! `namespace X;` and a PHP unbraced `namespace X;` govern their following
//! siblings, and a PHP `use` becomes visible only after its declaration. Each
//! language supplies the hook that walks its tree once and emits the regions in
//! source order; this type owns the ordering invariant and the lookup, so the
//! sites that ask "what governs this byte" share one answer instead of each
//! re-walking the tree with its own rule.

use std::ops::Range;

/// One half-open byte region `[start, end)` and the scope value governing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeRegion<T> {
    pub range: Range<usize>,
    pub value: T,
}

/// Disjoint byte regions of one source file sorted by start, each carrying the
/// scope value that governs its bytes.
///
/// Regions need not cover the file: a byte outside every region has no value.
/// An empty range governs no byte, so [`ScopeRegionsBuilder::push`] drops it
/// rather than storing a region no lookup can return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeRegions<T> {
    regions: Vec<ScopeRegion<T>>,
}

impl<T> ScopeRegions<T> {
    /// The region containing `byte`, if any.
    pub fn region_at(&self, byte: usize) -> Option<&ScopeRegion<T>> {
        let index = self
            .regions
            .partition_point(|region| region.range.start <= byte)
            .checked_sub(1)?;
        let region = &self.regions[index];
        (byte < region.range.end).then_some(region)
    }

    /// The value governing `byte`, if any region contains it.
    pub fn value_at(&self, byte: usize) -> Option<&T> {
        self.region_at(byte).map(|region| &region.value)
    }

    /// The regions in source order.
    pub fn iter(&self) -> std::slice::Iter<'_, ScopeRegion<T>> {
        self.regions.iter()
    }

    pub fn last(&self) -> Option<&ScopeRegion<T>> {
        self.regions.last()
    }

    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }
}

/// Collects regions in source order for one [`ScopeRegions`].
#[derive(Debug, Clone)]
pub struct ScopeRegionsBuilder<T> {
    regions: Vec<ScopeRegion<T>>,
}

impl<T> Default for ScopeRegionsBuilder<T> {
    fn default() -> Self {
        Self {
            regions: Vec::new(),
        }
    }
}

impl<T> ScopeRegionsBuilder<T> {
    /// Append `[start, end)`. Regions arrive in source order and never overlap;
    /// a language hook that emits them out of order has a broken walk, so
    /// this asserts instead of sorting.
    pub fn push(&mut self, range: Range<usize>, value: T) {
        assert!(
            range.start <= range.end,
            "scope region {range:?} ends before it starts"
        );
        if range.is_empty() {
            return;
        }
        if let Some(previous) = self.regions.last() {
            assert!(
                previous.range.end <= range.start,
                "scope region {range:?} overlaps or precedes {:?}",
                previous.range
            );
        }
        self.regions.push(ScopeRegion { range, value });
    }

    pub fn finish(self) -> ScopeRegions<T> {
        ScopeRegions {
            regions: self.regions,
        }
    }
}
