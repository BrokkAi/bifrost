//! The capability surface a language analyzer exposes to structural search,
//! plus the per-analyzer facts cache behind it.
//!
//! Follows the `import_analysis_provider()` idiom: `IAnalyzer` has a default
//! `structural_search_providers()` returning nothing; each language analyzer
//! whose adapter supplies a [`super::spec::StructuralSpec`] exposes its inner
//! `TreeSitterAnalyzer` as a provider, and `MultiAnalyzer` concatenates its
//! delegates'. Each provider covers exactly one language.

use super::extract::{LimitedFileFacts, extract_file_facts, extract_file_facts_limited};
use super::facts::{FileFacts, STRUCTURAL_FACTS_SNAPSHOT_VERSION};
use super::kinds::{NormalizedKind, Role};
use crate::analyzer::tree_sitter_analyzer::{
    LanguageAdapter, PreparedSyntaxLimitedOutcome, PreparedSyntaxTree, TreeSitterAnalyzer,
};
use crate::analyzer::{Language, ProjectFile};
use crate::cancellation::CancellationToken;
use moka::sync::Cache;
use std::hash::Hasher;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Opaque snapshot-local acceleration capability for built-in structural
/// providers. This type is public only so external implementations of
/// [`StructuralSearchProvider`] can name the defaulted method's return type;
/// concrete cache representation and lifecycle remain crate-private.
#[doc(hidden)]
pub struct StructuralSearchSnapshotCache {
    inner: super::index::SnapshotStructuralIndexCache,
}

impl StructuralSearchSnapshotCache {
    pub(crate) fn new(max_retained_bytes: u64) -> Self {
        Self {
            inner: super::index::SnapshotStructuralIndexCache::new(max_retained_bytes),
        }
    }

    pub(crate) fn inner(&self) -> &super::index::SnapshotStructuralIndexCache {
        &self.inner
    }
}

pub trait StructuralSearchProvider: Send + Sync {
    fn structural_language(&self) -> Language;

    /// Every analyzed file of this provider's language, unsorted; callers
    /// order for determinism.
    fn structural_files(&self) -> Vec<ProjectFile>;

    /// Source for an analyzed file. Store-backed analyzers may hydrate this on
    /// demand instead of retaining every file's source in aggregate state.
    fn structural_source(&self, file: &ProjectFile) -> Option<String>;

    /// Capture one source snapshot without hydrating more than
    /// `max_source_bytes`. The default is deliberately unavailable so an
    /// external provider cannot accidentally satisfy a bounded request by
    /// calling the unbounded [`Self::structural_source`] method.
    fn structural_source_limited(
        &self,
        _file: &ProjectFile,
        _max_source_bytes: usize,
        cancellation: Option<&CancellationToken>,
    ) -> StructuralSourceLimitedOutcome {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            StructuralSourceLimitedOutcome::Cancelled
        } else {
            StructuralSourceLimitedOutcome::Unavailable
        }
    }

    /// Prepare syntax from the already-admitted source snapshot with
    /// cooperative parse cancellation. The default is unavailable so bounded
    /// receiver analysis cannot silently fall back to an uncancellable parse
    /// through a third-party provider.
    fn structural_syntax_limited(
        &self,
        _file: &ProjectFile,
        _max_source_bytes: usize,
        cancellation: Option<&CancellationToken>,
    ) -> StructuralSyntaxLimitedOutcome {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            StructuralSyntaxLimitedOutcome::Cancelled
        } else {
            StructuralSyntaxLimitedOutcome::Unavailable
        }
    }

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

    /// Materialize one complete facts snapshot without crossing
    /// `max_fact_nodes` total normalized nodes and semantic role edges, and
    /// stop cooperatively when `cancellation` fires.
    ///
    /// The exact source is supplied by the request so the source-byte
    /// admission and the normalized facts remain generation-coherent. The
    /// default is deliberately unavailable: third-party providers must opt
    /// into a genuinely bounded implementation rather than wrapping an
    /// unbounded [`Self::structural_facts`] call.
    fn structural_facts_limited(
        &self,
        _file: &ProjectFile,
        _source: &str,
        _max_fact_nodes: usize,
        cancellation: Option<&CancellationToken>,
    ) -> StructuralFactsLimitedOutcome {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            StructuralFactsLimitedOutcome::Cancelled
        } else {
            StructuralFactsLimitedOutcome::Unavailable
        }
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

    /// Monotonic source generation for providers backed by a live overlay.
    /// Ordinary immutable analyzer generations keep the zero default.
    fn structural_source_generation(&self) -> u64 {
        0
    }

    /// Snapshot-owned immutable posting cache. Third-party providers may keep
    /// the default and use scan-only execution.
    fn snapshot_structural_index_cache(&self) -> Option<&StructuralSearchSnapshotCache> {
        None
    }
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

/// Result of bounded syntax preparation for receiver analysis.
#[doc(hidden)]
#[derive(Debug)]
pub enum StructuralSyntaxLimitedOutcome {
    Available(StructuralPreparedSyntax),
    Exceeded { minimum_source_bytes: usize },
    Cancelled,
    Unavailable,
}

/// Opaque prepared syntax returned by a structural provider. Its concrete
/// tree and declaration state remain internal to the analyzer.
#[doc(hidden)]
#[derive(Debug)]
pub struct StructuralPreparedSyntax {
    inner: Arc<PreparedSyntaxTree>,
}

impl StructuralPreparedSyntax {
    pub(crate) fn into_inner(self) -> Arc<PreparedSyntaxTree> {
        self.inner
    }
}

#[derive(Debug)]
pub enum StructuralFactsLimitedOutcome {
    Available {
        facts: Arc<FileFacts>,
        cache_outcome: StructuralFactsCacheOutcome,
    },
    Exceeded {
        minimum_fact_nodes: usize,
    },
    Cancelled,
    Unavailable,
}

#[derive(Debug)]
pub enum StructuralSourceLimitedOutcome {
    Available(Arc<str>),
    Exceeded { minimum_source_bytes: usize },
    Cancelled,
    Unavailable,
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
        if let Some(facts) = self.get_complete(file, source) {
            return (Some(facts), StructuralFactsCacheOutcome::MemoryHit);
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
        self.insert_complete(file, source, Arc::clone(&facts));
        (Some(facts), outcome)
    }

    fn get_complete(&self, file: &ProjectFile, source: &str) -> Option<Arc<FileFacts>> {
        let source_hash = hash_source(source);
        self.cache.get(file).and_then(|entry| {
            (entry.source_hash == source_hash && entry.facts.source() == source)
                .then(|| Arc::clone(&entry.facts))
        })
    }

    fn insert_complete(&self, file: &ProjectFile, source: &str, facts: Arc<FileFacts>) {
        debug_assert_eq!(facts.source(), source);
        self.cache.insert(
            file.clone(),
            Arc::new(CachedFacts {
                source_hash: hash_source(source),
                facts,
            }),
        );
    }

    fn record_extraction(&self) {
        self.extractions.fetch_add(1, Ordering::Relaxed);
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

    fn structural_source_limited(
        &self,
        file: &ProjectFile,
        max_source_bytes: usize,
        cancellation: Option<&CancellationToken>,
    ) -> StructuralSourceLimitedOutcome {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return StructuralSourceLimitedOutcome::Cancelled;
        }
        let snapshot = match self.source_snapshot_limited(file, max_source_bytes) {
            Ok(Some(snapshot)) => snapshot,
            Ok(None) => return StructuralSourceLimitedOutcome::Unavailable,
            Err(exceeded) => {
                return StructuralSourceLimitedOutcome::Exceeded {
                    minimum_source_bytes: exceeded.minimum_source_bytes(),
                };
            }
        };
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            StructuralSourceLimitedOutcome::Cancelled
        } else {
            StructuralSourceLimitedOutcome::Available(snapshot.into_source())
        }
    }

    fn structural_syntax_limited(
        &self,
        file: &ProjectFile,
        max_source_bytes: usize,
        cancellation: Option<&CancellationToken>,
    ) -> StructuralSyntaxLimitedOutcome {
        match self.prepared_syntax_limited_cancellable(file, max_source_bytes, cancellation) {
            PreparedSyntaxLimitedOutcome::Available(inner) => {
                StructuralSyntaxLimitedOutcome::Available(StructuralPreparedSyntax { inner })
            }
            PreparedSyntaxLimitedOutcome::Exceeded(exceeded) => {
                StructuralSyntaxLimitedOutcome::Exceeded {
                    minimum_source_bytes: exceeded.minimum_source_bytes(),
                }
            }
            PreparedSyntaxLimitedOutcome::Cancelled => StructuralSyntaxLimitedOutcome::Cancelled,
            PreparedSyntaxLimitedOutcome::Unavailable => {
                StructuralSyntaxLimitedOutcome::Unavailable
            }
        }
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

    fn structural_facts_limited(
        &self,
        file: &ProjectFile,
        source: &str,
        max_fact_nodes: usize,
        cancellation: Option<&CancellationToken>,
    ) -> StructuralFactsLimitedOutcome {
        let Some(spec) = self.adapter().structural_spec() else {
            return StructuralFactsLimitedOutcome::Unavailable;
        };
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return StructuralFactsLimitedOutcome::Cancelled;
        }
        if let Some(facts) = self.structural_cache().get_complete(file, source) {
            let work_items = facts.work_item_count();
            return if work_items > max_fact_nodes {
                StructuralFactsLimitedOutcome::Exceeded {
                    minimum_fact_nodes: work_items,
                }
            } else {
                StructuralFactsLimitedOutcome::Available {
                    facts,
                    cache_outcome: StructuralFactsCacheOutcome::MemoryHit,
                }
            };
        }

        self.structural_cache().record_extraction();
        let grammar = self.adapter().parser_language_for_file(file);
        let facts = match extract_file_facts_limited(
            spec,
            &grammar,
            source,
            max_fact_nodes,
            cancellation,
        ) {
            LimitedFileFacts::Complete(facts) => facts,
            LimitedFileFacts::Exceeded { minimum_fact_nodes } => {
                return StructuralFactsLimitedOutcome::Exceeded { minimum_fact_nodes };
            }
            LimitedFileFacts::Cancelled => {
                return StructuralFactsLimitedOutcome::Cancelled;
            }
            LimitedFileFacts::Unavailable => {
                return StructuralFactsLimitedOutcome::Unavailable;
            }
        };
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return StructuralFactsLimitedOutcome::Cancelled;
        }

        let facts = Arc::new(facts);
        // The bounded query path must remain promptly cancellable. Durable snapshot encoding
        // clones every normalized node and role edge before serialization, so leave that
        // optional optimization to the ordinary materialization path rather than performing
        // an unmetered post-extraction traversal here.
        self.structural_cache()
            .insert_complete(file, source, Arc::clone(&facts));
        StructuralFactsLimitedOutcome::Available {
            facts,
            cache_outcome: StructuralFactsCacheOutcome::Extracted,
        }
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

    fn structural_source_generation(&self) -> u64 {
        self.project().analysis_generation()
    }

    fn snapshot_structural_index_cache(&self) -> Option<&StructuralSearchSnapshotCache> {
        Some(self.structural_index_cache())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{IAnalyzer, TestProject, TypescriptAnalyzer};
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

    #[test]
    fn limited_source_snapshot_rejects_oversized_input_before_fact_materialization() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(root.clone(), "app.ts");
        let source = "export function demo(): void {}\n";
        file.write(source).expect("write source");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
        let provider = analyzer
            .structural_search_providers()
            .into_iter()
            .next()
            .expect("TypeScript structural provider");
        let before = provider.structural_extraction_count();

        assert!(matches!(
            provider.structural_source_limited(&file, source.len() - 1, None),
            StructuralSourceLimitedOutcome::Exceeded {
                minimum_source_bytes
            } if minimum_source_bytes >= source.len()
        ));
        assert_eq!(provider.structural_extraction_count(), before);

        let StructuralSourceLimitedOutcome::Available(snapshot) =
            provider.structural_source_limited(&file, source.len(), None)
        else {
            panic!("source should fit its exact byte budget");
        };
        assert_eq!(snapshot.as_ref(), source);
        assert_eq!(provider.structural_extraction_count(), before);
    }

    #[test]
    fn limited_materialization_stops_early_and_caches_only_complete_facts() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(root.clone(), "app.ts");
        file.write(
            "class Service { run(): void {} }\n\
             export function call(service: Service): void { service.run(); }\n",
        )
        .expect("write source");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
        let provider = analyzer
            .structural_search_providers()
            .into_iter()
            .next()
            .expect("TypeScript structural provider");
        let source = provider.structural_source(&file).expect("source");
        let before = provider.structural_extraction_count();

        assert!(matches!(
            provider.structural_facts_limited(&file, &source, 1, None),
            StructuralFactsLimitedOutcome::Exceeded {
                minimum_fact_nodes: 2
            }
        ));
        assert_eq!(provider.structural_extraction_count(), before + 1);

        let complete = provider.structural_facts_limited(&file, &source, usize::MAX, None);
        let StructuralFactsLimitedOutcome::Available {
            facts,
            cache_outcome: StructuralFactsCacheOutcome::Extracted,
        } = complete
        else {
            panic!("expected complete extraction after the capped attempt");
        };
        assert!(facts.nodes().len() > 1);
        assert_eq!(provider.structural_extraction_count(), before + 2);

        assert!(matches!(
            provider.structural_facts_limited(&file, &source, 1, None),
            StructuralFactsLimitedOutcome::Exceeded { .. }
        ));
        assert_eq!(
            provider.structural_extraction_count(),
            before + 2,
            "the complete retry is cached, while the capped prefix was not"
        );
    }

    #[test]
    fn limited_materialization_caps_role_edges_before_caching() {
        let arguments = std::iter::repeat_n("this", 256)
            .collect::<Vec<_>>()
            .join(", ");
        let source = format!(
            "export function f(...args: unknown[]): void {{}}\n\
             f({arguments});\n"
        );

        let measured_temp = tempfile::tempdir().expect("measured temp dir");
        let measured_root = measured_temp.path().canonicalize().expect("measured root");
        let measured_file = ProjectFile::new(measured_root.clone(), "app.ts");
        measured_file.write(&source).expect("write measured source");
        let measured_analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(measured_root, Language::TypeScript));
        let measured_provider = measured_analyzer
            .structural_search_providers()
            .into_iter()
            .next()
            .expect("measured TypeScript provider");
        let StructuralFactsLimitedOutcome::Available {
            facts: measured, ..
        } = measured_provider.structural_facts_limited(&measured_file, &source, usize::MAX, None)
        else {
            panic!("unbounded measurement should complete");
        };
        assert!(
            measured.role_count() > measured.nodes().len(),
            "fixture must put most bounded work in raw-span role edges"
        );
        let cap = measured.work_item_count() - 1;
        assert!(
            measured.nodes().len() <= cap,
            "the node arena alone must fit so the role cap is exercised"
        );

        let capped_temp = tempfile::tempdir().expect("capped temp dir");
        let capped_root = capped_temp.path().canonicalize().expect("capped root");
        let capped_file = ProjectFile::new(capped_root.clone(), "app.ts");
        capped_file.write(&source).expect("write capped source");
        let capped_analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(capped_root, Language::TypeScript));
        let capped_provider = capped_analyzer
            .structural_search_providers()
            .into_iter()
            .next()
            .expect("capped TypeScript provider");
        let before = capped_provider.structural_extraction_count();
        assert!(matches!(
            capped_provider.structural_facts_limited(&capped_file, &source, cap, None),
            StructuralFactsLimitedOutcome::Exceeded {
                minimum_fact_nodes
            } if minimum_fact_nodes == cap + 1
        ));
        assert_eq!(capped_provider.structural_extraction_count(), before + 1);

        let StructuralFactsLimitedOutcome::Available {
            facts,
            cache_outcome: StructuralFactsCacheOutcome::Extracted,
        } = capped_provider.structural_facts_limited(&capped_file, &source, usize::MAX, None)
        else {
            panic!("complete retry should materialize and cache every role edge");
        };
        assert_eq!(facts.work_item_count(), measured.work_item_count());
        assert_eq!(capped_provider.structural_extraction_count(), before + 2);
    }

    #[test]
    fn limited_materialization_honors_cancellation_before_work() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(root.clone(), "app.ts");
        file.write("export function call(): void {}\n")
            .expect("write source");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
        let provider = analyzer
            .structural_search_providers()
            .into_iter()
            .next()
            .expect("TypeScript structural provider");
        let source = provider.structural_source(&file).expect("source");
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let before = provider.structural_extraction_count();

        assert!(matches!(
            provider.structural_facts_limited(&file, &source, usize::MAX, Some(&cancellation)),
            StructuralFactsLimitedOutcome::Cancelled
        ));
        assert_eq!(provider.structural_extraction_count(), before);
    }
}
