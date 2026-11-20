//! Temporary, blob-local source span queries. No persisted or retained state.

use std::cell::Cell;

/// Deterministic work count for blob-local span indexing and queries.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SpanScanWork {
    pub(crate) indexed_entries: usize,
    pub(crate) query_steps: usize,
}

impl SpanScanWork {
    pub(crate) fn record_index<T>(&mut self, index: &SpanIndex<T>) {
        self.indexed_entries += index.indexed_entries();
        self.query_steps += index.query_steps();
    }

    pub(crate) fn total(self) -> usize {
        self.indexed_entries + self.query_steps
    }
}

/// Starts are sorted for contained queries. A balanced max-end tree prunes
/// overlap queries, including long intervals starting far before the query.
pub(crate) struct SpanIndex<T> {
    entries: Vec<(usize, usize, T)>,
    max_end: Vec<usize>,
    query_steps: Cell<usize>,
}

impl<T> SpanIndex<T> {
    pub(crate) fn new(entries: impl IntoIterator<Item = (usize, usize, T)>) -> Self {
        let mut entries: Vec<_> = entries.into_iter().collect();
        assert!(entries.iter().all(|(start, end, _)| start <= end));
        entries.sort_unstable_by_key(|entry| entry.0);
        let mut result = Self {
            max_end: vec![0; entries.len() * 4],
            entries,
            query_steps: Cell::new(0),
        };
        if !result.entries.is_empty() {
            result.build(0, 0, result.entries.len());
        }
        result
    }

    pub(crate) fn indexed_entries(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn query_steps(&self) -> usize {
        self.query_steps.get()
    }

    fn record_step(&self) {
        self.query_steps.set(self.query_steps.get() + 1);
    }

    fn build(&mut self, node: usize, first: usize, last: usize) -> usize {
        let end = if last - first == 1 {
            self.entries[first].1
        } else {
            let mid = first + (last - first) / 2;
            let left = self.build(node * 2 + 1, first, mid);
            left.max(self.build(node * 2 + 2, mid, last))
        };
        self.max_end[node] = end;
        end
    }

    pub(crate) fn contained(&self, start: usize, end: usize) -> impl Iterator<Item = &T> {
        let first = self.entries.partition_point(|entry| {
            self.record_step();
            entry.0 < start
        });
        let last = self.entries.partition_point(|entry| {
            self.record_step();
            entry.0 <= end
        });
        self.entries[first..last]
            .iter()
            .inspect(|_| self.record_step())
            .filter(move |entry| entry.1 <= end)
            .map(|entry| &entry.2)
    }

    /// Closed intersection is used by glob imports. Other uncertainty spans
    /// use half-open intersection, except empty source spans include endpoints.
    pub(crate) fn overlaps(&self, start: usize, end: usize, closed: bool) -> bool {
        !self.entries.is_empty()
            && self.overlaps_node(0, 0, self.entries.len(), (start, end), closed)
    }

    fn overlaps_node(
        &self,
        node: usize,
        first: usize,
        last: usize,
        query: (usize, usize),
        closed: bool,
    ) -> bool {
        self.record_step();
        let (start, end) = query;
        if self.max_end[node] < start || self.entries[first].0 > end {
            return false;
        }
        if last - first == 1 {
            let (s, e, _) = &self.entries[first];
            return if closed || s == e {
                *s <= end && start <= *e
            } else {
                *s < end && start < *e
            };
        }
        let mid = first + (last - first) / 2;
        self.overlaps_node(node * 2 + 1, first, mid, query, closed)
            || self.overlaps_node(node * 2 + 2, mid, last, query, closed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlap_and_containment_match_original_predicates_including_empty_spans() {
        let entries = (0..6)
            .flat_map(|s| (s..6).map(move |e| (s, e, (s, e))))
            .collect::<Vec<_>>();
        let index = SpanIndex::new(entries.iter().copied());
        for start in 0..7 {
            for end in start..7 {
                let expected = entries
                    .iter()
                    .filter(|(s, e, _)| start <= *s && *e <= end)
                    .map(|entry| entry.2)
                    .collect::<std::collections::BTreeSet<_>>();
                assert_eq!(
                    index
                        .contained(start, end)
                        .copied()
                        .collect::<std::collections::BTreeSet<_>>(),
                    expected
                );
                for closed in [true, false] {
                    assert_eq!(
                        index.overlaps(start, end, closed),
                        entries.iter().any(|(s, e, _)| if closed || s == e {
                            *s <= end && start <= *e
                        } else {
                            *s < end && start < *e
                        })
                    );
                }
            }
        }
        for s in 0..6 {
            for e in s..6 {
                let index = SpanIndex::new([(s, e, ())]);
                for start in 0..6 {
                    for end in start..6 {
                        assert_eq!(
                            index.contained(start, end).count(),
                            usize::from(start <= s && e <= end)
                        );
                        assert_eq!(index.overlaps(start, end, true), s <= end && start <= e);
                        assert_eq!(
                            index.overlaps(start, end, false),
                            if s == e {
                                start <= s && s <= end
                            } else {
                                s < end && start < e
                            }
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn seeded_sparse_collections_match_linear_scan() {
        // Fixed seed and explicit gaps exercise pruning without timing or randomness.
        let mut seed = 0x12997_u64;
        let mut next = || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            (seed >> 32) as usize
        };
        for count in 0..64 {
            let mut entries = Vec::new();
            for id in 0..count {
                let start = (next() % 32) * 8;
                let end = start + next() % 4;
                entries.push((start, end, id * 2));
                // Separate identities ensure containment preserves multiplicity.
                entries.push((start, end, id * 2 + 1));
            }
            for i in (1..entries.len()).rev() {
                entries.swap(i, next() % (i + 1));
            }
            let index = SpanIndex::new(entries.iter().copied());
            for start in 0..260 {
                for width in [0, 1, 3, 9, 260] {
                    let end = start + width;
                    let mut expected = entries
                        .iter()
                        .filter(|(s, e, _)| start <= *s && *e <= end)
                        .map(|entry| entry.2)
                        .collect::<Vec<_>>();
                    let mut actual = index.contained(start, end).copied().collect::<Vec<_>>();
                    expected.sort_unstable();
                    actual.sort_unstable();
                    assert_eq!(actual, expected, "count={count} query={start}..{end}");
                    for closed in [false, true] {
                        let expected = entries.iter().any(|(s, e, _)| {
                            if closed || s == e {
                                *s <= end && start <= *e
                            } else {
                                *s < end && start < *e
                            }
                        });
                        assert_eq!(
                            index.overlaps(start, end, closed),
                            expected,
                            "count={count} query={start}..{end} closed={closed}"
                        );
                    }
                }
            }
        }
    }
}
