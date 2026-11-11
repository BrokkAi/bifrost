//! The hit set one usage query builds while it scans files, and the callsite
//! budget that decides when the scan may stop.
//!
//! Every graph strategy collects the same three things -- proven hits, unproven
//! hits, and the number of raw syntactic matches -- and stops once the
//! deduplicated external hits exceed the request's `max_usages`. The language
//! crates keep their own hit filtering; this type owns the counting, the stop
//! decision and the final `TooManyCallsites`-or-success verdict.

use crate::analyzer::usages::model::{FuzzyResult, UsageHit, UsageHitSurface};
use crate::analyzer::{CodeUnit, ProjectFile};
use std::collections::BTreeSet;

/// Whether a scan may keep visiting sites after a hit was recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageFlow {
    Continue,
    /// The deduplicated external hits exceed the callsite budget. Inserting or
    /// merging more hits never returns the scan to `Continue`; only
    /// [`UsageAccumulator::reclassify_hit_at`] taking a site off the external
    /// surface can, which is why the flow is derived from the count rather
    /// than latched.
    LimitReached,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageAccumulator {
    hits: BTreeSet<UsageHit>,
    unproven_hits: BTreeSet<UsageHit>,
    raw_match_count: usize,
    /// External hits in `hits`, maintained on every insertion and
    /// reclassification so the budget check never recounts the set.
    external_hit_count: usize,
    /// `None` collects every hit: a per-file evidence build must not be
    /// truncated by whichever request first asked for it.
    limit: Option<usize>,
}

impl UsageAccumulator {
    /// Collect hits until more than `max_usages` distinct external sites are
    /// seen.
    pub fn bounded(max_usages: usize) -> Self {
        Self::with_limit(Some(max_usages))
    }

    /// Collect every hit. The flow is always `Continue`.
    pub fn unbounded() -> Self {
        Self::with_limit(None)
    }

    /// An empty collection with this one's budget, for a sub-scan (one file,
    /// one parallel item) whose result is absorbed back into this one.
    pub fn empty_like(&self) -> Self {
        Self::with_limit(self.limit)
    }

    fn with_limit(limit: Option<usize>) -> Self {
        Self {
            hits: BTreeSet::new(),
            unproven_hits: BTreeSet::new(),
            raw_match_count: 0,
            external_hit_count: 0,
            limit,
        }
    }

    /// Record one proven hit. A site already recorded keeps its first
    /// classification, because `UsageHit` equality ignores the kind.
    pub fn insert_hit(&mut self, hit: UsageHit) -> UsageFlow {
        let external = hit.kind.included_in(UsageHitSurface::ExternalUsages);
        if self.hits.insert(hit) && external {
            self.external_hit_count += 1;
        }
        self.flow()
    }

    pub fn insert_unproven_hit(&mut self, hit: UsageHit) {
        self.unproven_hits.insert(hit.into_unproven());
    }

    /// Count one syntactic candidate the scan examined, whether or not it
    /// became a hit.
    pub fn note_raw_match(&mut self) {
        self.raw_match_count += 1;
    }

    /// Replace the proven hit recorded at `[start, end)` of `file` with
    /// `reclassify(hit)`.
    ///
    /// The JVM scanners record a site and then refine its kind (an import, a
    /// same-owner receiver). A refinement can take the site off the external
    /// surface, so the count follows it; scanners check the flow only after
    /// the refinement, which keeps the stop decision exact.
    pub fn reclassify_hit_at(
        &mut self,
        file: &ProjectFile,
        start: usize,
        end: usize,
        reclassify: impl FnOnce(UsageHit) -> UsageHit,
    ) {
        let Some(hit) = self
            .hits
            .iter()
            .find(|hit| hit.file == *file && hit.start_offset == start && hit.end_offset == end)
            .cloned()
        else {
            return;
        };
        self.hits.remove(&hit);
        let was_external = hit.kind.included_in(UsageHitSurface::ExternalUsages);
        let hit = reclassify(hit);
        let is_external = hit.kind.included_in(UsageHitSurface::ExternalUsages);
        self.hits.insert(hit);
        match (was_external, is_external) {
            (true, false) => self.external_hit_count -= 1,
            (false, true) => self.external_hit_count += 1,
            _ => {}
        }
    }

    /// Add one file's (or one sub-scan's) hits. Merging is a set union, so a
    /// site two files report is counted once.
    pub fn merge(
        &mut self,
        hits: impl IntoIterator<Item = UsageHit>,
        unproven_hits: impl IntoIterator<Item = UsageHit>,
        raw_match_count: usize,
    ) -> UsageFlow {
        for hit in hits {
            self.insert_hit(hit);
        }
        self.unproven_hits.extend(unproven_hits);
        self.raw_match_count += raw_match_count;
        self.flow()
    }

    /// Merge everything `other` collected. Its own limit is irrelevant here:
    /// the union has at least as many external sites as `other`, so an
    /// exhausted sub-scan always exhausts this budget too.
    pub fn absorb(&mut self, other: UsageAccumulator) -> UsageFlow {
        self.merge(other.hits, other.unproven_hits, other.raw_match_count)
    }

    pub fn flow(&self) -> UsageFlow {
        if self.limit_reached() {
            UsageFlow::LimitReached
        } else {
            UsageFlow::Continue
        }
    }

    pub fn limit_reached(&self) -> bool {
        self.limit
            .is_some_and(|limit| self.external_hit_count > limit)
    }

    pub fn hits(&self) -> &BTreeSet<UsageHit> {
        &self.hits
    }

    pub fn unproven_hits(&self) -> &BTreeSet<UsageHit> {
        &self.unproven_hits
    }

    pub fn raw_match_count(&self) -> usize {
        self.raw_match_count
    }

    /// The collected hits, unproven hits and raw match count of an unbounded
    /// collection, for a producer that publishes them as uncapped evidence.
    pub fn into_unbounded_parts(self) -> (BTreeSet<UsageHit>, BTreeSet<UsageHit>, usize) {
        assert!(
            self.limit.is_none(),
            "only an unbounded collection is complete evidence"
        );
        (self.hits, self.unproven_hits, self.raw_match_count)
    }

    /// The query's answer for `target`: `TooManyCallsites` when the budget was
    /// exceeded, with every collected hit as the sample, and otherwise the
    /// proven hits plus at most `max_unproven` unproven ones.
    pub fn finish(self, target: &CodeUnit, max_unproven: usize) -> FuzzyResult {
        let limit = self
            .limit
            .expect("a usage query's answer is decided against its callsite budget");
        if self.external_hit_count > limit {
            return FuzzyResult::TooManyCallsites {
                short_name: target.short_name().to_string(),
                total_callsites: self.external_hit_count,
                limit,
                sample_hits: self.hits,
            };
        }
        FuzzyResult::success_with_unproven_limit(
            target.clone(),
            self.hits,
            self.unproven_hits,
            max_unproven,
        )
    }
}
