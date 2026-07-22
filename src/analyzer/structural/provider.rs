//! The capability surface a language analyzer exposes to structural search,
//! plus the per-analyzer facts cache behind it.
//!
//! Follows the `import_analysis_provider()` idiom: `IAnalyzer` has a default
//! `structural_search_providers()` returning nothing; each language analyzer
//! whose adapter supplies a [`super::spec::StructuralSpec`] exposes its inner
//! `TreeSitterAnalyzer` as a provider, and `MultiAnalyzer` concatenates its
//! delegates'. Each provider covers exactly one language.

use super::extract::extract_file_facts;
use super::facts::{FileFacts, STRUCTURAL_FACTS_SNAPSHOT_VERSION};
use super::kinds::{NormalizedKind, Role};
use crate::analyzer::tree_sitter_analyzer::{LanguageAdapter, TreeSitterAnalyzer};
use crate::analyzer::{Language, ProjectFile};
use moka::sync::Cache;
use std::hash::Hasher;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

pub trait StructuralSearchProvider: Send + Sync {
    fn structural_language(&self) -> Language;

    /// Every analyzed file of this provider's language, unsorted; callers
    /// order for determinism.
    fn structural_files(&self) -> Vec<ProjectFile>;

    /// Source for an analyzed file. Store-backed analyzers may hydrate this on
    /// demand instead of retaining every file's source in aggregate state.
    fn structural_source(&self, file: &ProjectFile) -> Option<String>;

    /// Normalized facts for one file, served from the facts cache and
    /// extracted from the in-memory source on miss. `None` when the file is
    /// not held by this analyzer, is empty, or the adapter has no structural
    /// spec.
    fn structural_facts(&self, file: &ProjectFile) -> Option<Arc<FileFacts>>;

    /// Normalized facts plus the exact analyzer-generation cache outcome when
    /// the provider can report it. Third-party providers may retain the
    /// default `Unknown` outcome while still supplying facts normally.
    fn structural_facts_with_outcome(
        &self,
        file: &ProjectFile,
    ) -> (Option<Arc<FileFacts>>, StructuralFactsCacheOutcome) {
        (
            self.structural_facts(file),
            StructuralFactsCacheOutcome::Unknown,
        )
    }

    /// How many extraction (parse + normalize) runs this provider has
    /// performed — i.e. facts-cache misses. Lets planner tests assert that
    /// pruning skipped a file and that repeated queries hit the cache.
    fn structural_extraction_count(&self) -> u64;

    /// How many facts-cache misses were satisfied by a persisted compact
    /// snapshot rather than a tree-sitter parse and normalization pass.
    fn structural_hydration_count(&self) -> u64;

    fn structural_supports_kind(&self, kind: NormalizedKind) -> bool;

    fn structural_supports_role(&self, role: Role) -> bool;
}

/// Where one structural-facts lookup was satisfied. This distinguishes the
/// analyzer-generation cache from request-local CodeQuery caches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructuralFactsCacheOutcome {
    MemoryHit,
    PersistedHydration,
    Extracted,
    Unavailable,
    Unknown,
}

/// Byte-budgeted facts cache keyed by file and validated by a hash of the
/// in-memory source, so entries surviving an analyzer update (the cache is
/// shared across `update()` generations) are self-healing rather than stale.
/// Follows the moka weigher idiom of the per-language memo caches
/// (`src/analyzer/java/cache.rs`).
pub struct StructuralFactsCache {
    cache: Cache<ProjectFile, Arc<CachedFacts>>,
    extractions: AtomicU64,
    hydrations: AtomicU64,
}

struct CachedFacts {
    source_hash: u64,
    facts: Arc<FileFacts>,
}

fn hash_source(source: &str) -> u64 {
    let mut hasher = rustc_hash::FxHasher::default();
    hasher.write(source.as_bytes());
    hasher.finish()
}

fn weigh_entry(key: &ProjectFile, value: &Arc<CachedFacts>) -> u32 {
    let bytes = key.rel_path().as_os_str().len() as u64 + value.facts.estimated_bytes();
    bytes.clamp(1, u32::MAX as u64) as u32
}

impl StructuralFactsCache {
    pub(crate) fn new(budget_bytes: u64) -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(budget_bytes.max(1))
                .weigher(weigh_entry)
                .build(),
            extractions: AtomicU64::new(0),
            hydrations: AtomicU64::new(0),
        }
    }

    /// Return cached facts when the stored source hash still matches;
    /// otherwise try durable hydration before falling back to extraction.
    fn get_or_materialize(
        &self,
        file: &ProjectFile,
        source: &str,
        load: impl FnOnce() -> Option<FileFacts>,
        extract: impl FnOnce() -> Option<FileFacts>,
    ) -> (Option<Arc<FileFacts>>, StructuralFactsCacheOutcome) {
        let source_hash = hash_source(source);
        if let Some(entry) = self.cache.get(file)
            && entry.source_hash == source_hash
        {
            return (
                Some(Arc::clone(&entry.facts)),
                StructuralFactsCacheOutcome::MemoryHit,
            );
        }
        let (facts, outcome) = if let Some(facts) = load() {
            self.hydrations.fetch_add(1, Ordering::Relaxed);
            (
                Arc::new(facts),
                StructuralFactsCacheOutcome::PersistedHydration,
            )
        } else {
            self.extractions.fetch_add(1, Ordering::Relaxed);
            let Some(facts) = extract() else {
                return (None, StructuralFactsCacheOutcome::Unavailable);
            };
            (Arc::new(facts), StructuralFactsCacheOutcome::Extracted)
        };
        self.cache.insert(
            file.clone(),
            Arc::new(CachedFacts {
                source_hash,
                facts: Arc::clone(&facts),
            }),
        );
        (Some(facts), outcome)
    }

    pub fn extraction_count(&self) -> u64 {
        self.extractions.load(Ordering::Relaxed)
    }

    pub fn hydration_count(&self) -> u64 {
        self.hydrations.load(Ordering::Relaxed)
    }
}

impl<A: LanguageAdapter> StructuralSearchProvider for TreeSitterAnalyzer<A> {
    fn structural_language(&self) -> Language {
        self.adapter().language()
    }

    fn structural_files(&self) -> Vec<ProjectFile> {
        self.all_files()
    }

    fn structural_source(&self, file: &ProjectFile) -> Option<String> {
        self.file_source(file)
    }

    fn structural_facts(&self, file: &ProjectFile) -> Option<Arc<FileFacts>> {
        self.structural_facts_with_outcome(file).0
    }

    fn structural_facts_with_outcome(
        &self,
        file: &ProjectFile,
    ) -> (Option<Arc<FileFacts>>, StructuralFactsCacheOutcome) {
        let Some(spec) = self.adapter().structural_spec() else {
            return (None, StructuralFactsCacheOutcome::Unavailable);
        };
        let Some(source) = self.file_source(file) else {
            return (None, StructuralFactsCacheOutcome::Unavailable);
        };
        let snapshot_key = self.structural_snapshot_key(file, &source);
        self.structural_cache().get_or_materialize(
            file,
            &source,
            || {
                let key = snapshot_key.as_ref()?;
                let payload = self
                    .load_structural_facts_snapshot(key, STRUCTURAL_FACTS_SNAPSHOT_VERSION)
                    .ok()??;
                FileFacts::decode_snapshot(source.clone(), &payload).ok()
            },
            || {
                let grammar = self.adapter().parser_language_for_file(file);
                let facts = extract_file_facts(spec, &grammar, &source)?;
                if let Some(key) = snapshot_key.as_ref()
                    && let Ok(payload) = facts.encode_snapshot()
                {
                    let _ = self.persist_structural_facts_snapshot(
                        key,
                        STRUCTURAL_FACTS_SNAPSHOT_VERSION,
                        &payload,
                    );
                }
                Some(facts)
            },
        )
    }

    fn structural_extraction_count(&self) -> u64 {
        self.structural_cache().extraction_count()
    }

    fn structural_hydration_count(&self) -> u64 {
        self.structural_cache().hydration_count()
    }

    fn structural_supports_kind(&self, kind: NormalizedKind) -> bool {
        self.adapter()
            .structural_spec()
            .is_some_and(|spec| spec.supports_kind(kind))
    }

    fn structural_supports_role(&self, role: Role) -> bool {
        self.adapter()
            .structural_spec()
            .is_some_and(|spec| spec.supports_role(role))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compact_graph::CompactRows;

    fn empty_facts(source: &str) -> FileFacts {
        FileFacts::new(
            source.to_owned(),
            vec![0],
            Vec::new(),
            CompactRows::from_parts(vec![0], Vec::new()),
        )
    }

    #[test]
    fn structural_facts_cache_reports_exact_materialization_outcomes() {
        let temp = tempfile::tempdir().expect("temp dir");
        let file = ProjectFile::new(temp.path().to_path_buf(), "app.ts");
        let source = "export function demo() {}\n";
        let hydrated = StructuralFactsCache::new(1024 * 1024);

        let (facts, outcome) = hydrated.get_or_materialize(
            &file,
            source,
            || Some(empty_facts(source)),
            || panic!("persisted hydration must avoid extraction"),
        );
        assert!(facts.is_some());
        assert_eq!(outcome, StructuralFactsCacheOutcome::PersistedHydration);
        assert_eq!(hydrated.hydration_count(), 1);
        assert_eq!(hydrated.extraction_count(), 0);

        let (facts, outcome) = hydrated.get_or_materialize(
            &file,
            source,
            || panic!("memory hit must avoid persistence"),
            || panic!("memory hit must avoid extraction"),
        );
        assert!(facts.is_some());
        assert_eq!(outcome, StructuralFactsCacheOutcome::MemoryHit);
        assert_eq!(hydrated.hydration_count(), 1);
        assert_eq!(hydrated.extraction_count(), 0);

        let extracted = StructuralFactsCache::new(1024 * 1024);
        let (facts, outcome) =
            extracted.get_or_materialize(&file, source, || None, || Some(empty_facts(source)));
        assert!(facts.is_some());
        assert_eq!(outcome, StructuralFactsCacheOutcome::Extracted);
        assert_eq!(extracted.hydration_count(), 0);
        assert_eq!(extracted.extraction_count(), 1);

        let unavailable = StructuralFactsCache::new(1024 * 1024);
        let (facts, outcome) = unavailable.get_or_materialize(&file, source, || None, || None);
        assert!(facts.is_none());
        assert_eq!(outcome, StructuralFactsCacheOutcome::Unavailable);
        assert_eq!(unavailable.hydration_count(), 0);
        assert_eq!(unavailable.extraction_count(), 1);
    }
}
