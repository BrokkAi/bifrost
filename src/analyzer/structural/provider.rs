//! The capability surface a language analyzer exposes to structural search,
//! plus the per-analyzer facts cache behind it.
//!
//! Follows the `import_analysis_provider()` idiom: `IAnalyzer` has a default
//! `structural_search_providers()` returning nothing; each language analyzer
//! whose adapter supplies a [`StructuralSpec`] exposes its inner
//! `TreeSitterAnalyzer` as a provider, and `MultiAnalyzer` concatenates its
//! delegates'. Each provider covers exactly one language.

use super::extract::extract_file_facts;
use super::facts::FileFacts;
use super::kinds::{NormalizedKind, Role};
use super::spec::StructuralSpec;
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

    /// The retained in-memory source of an analyzed file. The planner reads
    /// this for anchor prefiltering without forcing a parse.
    fn structural_source(&self, file: &ProjectFile) -> Option<&str>;

    /// Normalized facts for one file, served from the facts cache and
    /// extracted from the in-memory source on miss. `None` when the file is
    /// not held by this analyzer, is empty, or the adapter has no structural
    /// spec.
    fn structural_facts(&self, file: &ProjectFile) -> Option<Arc<FileFacts>>;

    /// How many extraction (parse + normalize) runs this provider has
    /// performed — i.e. facts-cache misses. Lets planner tests assert that
    /// pruning skipped a file and that repeated queries hit the cache.
    fn structural_extraction_count(&self) -> u64;

    fn structural_supports_kind(&self, kind: NormalizedKind) -> bool;

    fn structural_supports_role(&self, role: Role) -> bool;
}

/// Byte-budgeted facts cache keyed by file and validated by a hash of the
/// in-memory source, so entries surviving an analyzer update (the cache is
/// shared across `update()` generations) are self-healing rather than stale.
/// Follows the moka weigher idiom of the per-language memo caches
/// (`src/analyzer/java/cache.rs`).
pub struct StructuralFactsCache {
    cache: Cache<ProjectFile, Arc<CachedFacts>>,
    extractions: AtomicU64,
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
        }
    }

    /// Return cached facts when the stored source hash still matches;
    /// otherwise run `extract` and cache its result.
    fn get_or_extract(
        &self,
        file: &ProjectFile,
        source: &str,
        extract: impl FnOnce() -> Option<FileFacts>,
    ) -> Option<Arc<FileFacts>> {
        let source_hash = hash_source(source);
        if let Some(entry) = self.cache.get(file)
            && entry.source_hash == source_hash
        {
            return Some(Arc::clone(&entry.facts));
        }
        self.extractions.fetch_add(1, Ordering::Relaxed);
        let facts = Arc::new(extract()?);
        self.cache.insert(
            file.clone(),
            Arc::new(CachedFacts {
                source_hash,
                facts: Arc::clone(&facts),
            }),
        );
        Some(facts)
    }

    pub fn extraction_count(&self) -> u64 {
        self.extractions.load(Ordering::Relaxed)
    }
}

impl<A: LanguageAdapter> StructuralSearchProvider for TreeSitterAnalyzer<A> {
    fn structural_language(&self) -> Language {
        self.adapter().language()
    }

    fn structural_files(&self) -> Vec<ProjectFile> {
        self.all_files().cloned().collect()
    }

    fn structural_source(&self, file: &ProjectFile) -> Option<&str> {
        self.file_source(file)
    }

    fn structural_facts(&self, file: &ProjectFile) -> Option<Arc<FileFacts>> {
        let spec: &'static dyn StructuralSpec = self.adapter().structural_spec()?;
        let source = self.file_source(file)?;
        self.structural_cache().get_or_extract(file, source, || {
            let grammar = self.adapter().parser_language_for_file(file);
            extract_file_facts(spec, &grammar, source)
        })
    }

    fn structural_extraction_count(&self) -> u64 {
        self.structural_cache().extraction_count()
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
