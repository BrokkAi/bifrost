//! What a generation asked for and could not resolve, keyed by information
//! tier (#2414 step 4).
//!
//! Deriving information above a file event's own tier is the expensive half of
//! an incremental update, and the cheap half of avoiding it is knowing whether
//! the event could possibly change that information. The rule the ladder states
//! is "record demand, do not just populate on demand": at the moment a tier's
//! relation is derived, the derivation also records the targets it *wanted* and
//! did not find, so a later event can be answered locally by a lookup instead
//! of by re-deriving the relation.
//!
//! The first (and today the only) consumer is the imports tier: C++ is the one
//! language that adopts workspace files by `#include`
//! (`LanguageAdapter::claims_included_files`), and #1865 is the defect where
//! creating any `.md`/`.txt`/`.json` file in a C++ workspace re-derived the
//! whole include-claim relation because *some* not-yet-existing include target
//! might have been that file. The record turns that into a set membership test.
//!
//! Keyed by tier rather than hard-coded to imports because the shape is the
//! ladder's, not C++'s -- but it is deliberately a keyed table and nothing
//! more. There is no per-tier plumbing, no persistence and no eviction policy
//! for tiers that have no consumer yet.

use std::collections::BTreeSet;

use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::hash::HashMap;
use brokk_bifrost_core::path_utils::path_suffix_keys;

use crate::analyzer::InformationTier;

/// Unresolved demand recorded for one generation, per tier.
///
/// Lifecycle mirrors the relation it is recorded with. The include-claim
/// relation (`AnalyzerRuntimeState::claim_edges`) is in-memory, per generation,
/// and carried forward across an update by re-deriving only the changed
/// sources' edges; this record is carried forward the same way and by the same
/// code, so the two can never describe different generations.
#[derive(Debug, Default, Clone)]
pub struct TierDemand {
    by_tier: HashMap<InformationTier, TierDemandEntries>,
}

/// One tier's demand: the per-source record that gives it its lifecycle, plus
/// the flat key index that answers the question.
///
/// Two structures rather than one because the two questions differ. Retiring a
/// source's demand needs the source key; asking whether a created file answers
/// *anyone's* demand must not walk every source. The counts make the flat index
/// exact under retirement: two sources including the same missing target both
/// hold the key, and it retires when the second one drops it.
#[derive(Debug, Default, Clone)]
struct TierDemandEntries {
    by_source: HashMap<ProjectFile, BTreeSet<String>>,
    key_counts: HashMap<String, usize>,
}

impl TierDemandEntries {
    fn clear_source(&mut self, source: &ProjectFile) {
        let Some(keys) = self.by_source.remove(source) else {
            return;
        };
        for key in keys {
            let Some(count) = self.key_counts.get_mut(&key) else {
                debug_assert!(
                    false,
                    "demand key {key} recorded for a source but not counted"
                );
                continue;
            };
            *count -= 1;
            if *count == 0 {
                self.key_counts.remove(&key);
            }
        }
    }

    fn set_source(&mut self, source: ProjectFile, keys: BTreeSet<String>) {
        self.clear_source(&source);
        if keys.is_empty() {
            return;
        }
        for key in &keys {
            *self.key_counts.entry(key.clone()).or_default() += 1;
        }
        self.by_source.insert(source, keys);
    }
}

impl TierDemand {
    /// Record the demand `source` has at `tier`, replacing whatever it had.
    ///
    /// Empty keys retire the source outright, which is what "this file's
    /// directives all resolve now" has to mean.
    pub(crate) fn set_source(
        &mut self,
        tier: InformationTier,
        source: ProjectFile,
        keys: BTreeSet<String>,
    ) {
        self.by_tier
            .entry(tier)
            .or_default()
            .set_source(source, keys);
    }

    /// Retire everything `source` demanded at `tier`.
    pub(crate) fn clear_source(&mut self, tier: InformationTier, source: &ProjectFile) {
        if let Some(entries) = self.by_tier.get_mut(&tier) {
            entries.clear_source(source);
        }
    }

    /// Whether `file` could satisfy demand recorded at `tier`.
    ///
    /// True is a "re-derive to find out", never a claim that the file *is*
    /// wanted: the recorded keys are path suffixes, and the tier's own
    /// resolution decides. False is the load-bearing answer -- it says the
    /// event is local to `file` and no relation above `tier` can have changed.
    pub(crate) fn is_demanded(&self, tier: InformationTier, file: &ProjectFile) -> bool {
        let Some(entries) = self.by_tier.get(&tier) else {
            return false;
        };
        path_suffix_keys(file.rel_path())
            .iter()
            .any(|key| entries.key_counts.contains_key(key))
    }

    /// Fold `other` into this record, source by source. Used where the runtime
    /// state of a two-pass build is folded into one generation's state.
    pub(crate) fn absorb(&mut self, other: TierDemand) {
        for (tier, entries) in other.by_tier {
            for (source, keys) in entries.by_source {
                self.set_source(tier, source, keys);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn file(rel_path: &str) -> ProjectFile {
        ProjectFile::new(
            PathBuf::from(if cfg!(windows) { r"C:\ws" } else { "/ws" }),
            PathBuf::from(rel_path),
        )
    }

    fn keys(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn a_recorded_key_matches_every_path_suffix_that_spells_it() {
        let mut demand = TierDemand::default();
        demand.set_source(
            InformationTier::Imports,
            file("src/main.cc"),
            keys(&["tables.inc"]),
        );

        assert!(demand.is_demanded(InformationTier::Imports, &file("tables.inc")));
        assert!(demand.is_demanded(InformationTier::Imports, &file("gen/deep/tables.inc")));
        assert!(!demand.is_demanded(InformationTier::Imports, &file("notes.md")));
        assert!(!demand.is_demanded(InformationTier::Imports, &file("tables.inc.bak")));
        // A tier nothing recorded demand for answers no, not "maybe".
        assert!(!demand.is_demanded(InformationTier::Supertypes, &file("tables.inc")));
    }

    #[test]
    fn a_key_retires_only_when_its_last_demanding_source_drops_it() {
        let mut demand = TierDemand::default();
        demand.set_source(
            InformationTier::Imports,
            file("a.cc"),
            keys(&["shared.inc"]),
        );
        demand.set_source(
            InformationTier::Imports,
            file("b.cc"),
            keys(&["shared.inc"]),
        );

        demand.clear_source(InformationTier::Imports, &file("a.cc"));
        assert!(
            demand.is_demanded(InformationTier::Imports, &file("shared.inc")),
            "b.cc still includes it"
        );

        demand.set_source(InformationTier::Imports, file("b.cc"), BTreeSet::new());
        assert!(
            !demand.is_demanded(InformationTier::Imports, &file("shared.inc")),
            "the last include naming it is gone"
        );
    }
}
