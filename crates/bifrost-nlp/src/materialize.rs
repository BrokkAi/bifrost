//! Blob materialization: turn a (parsed) working-tree file into cached chunks,
//! summaries, and vectors keyed by its git blob OID.
//!
//! Mirrors the per-file extraction the old `index_file_group` did, but writes the
//! content-addressed schema: embeddings are skipped for component texts already
//! cached (by content hash), and a blob whose OID is already present is never
//! re-materialized. A group is materialized together so embedding batches well.

use std::collections::{BTreeSet, HashSet};

use rayon::prelude::*;

use brokk_bifrost_analysis::analyzer::{IAnalyzer, ProjectFile};

use super::bm25::fts_text;
use super::chunker::extract_file_chunks;
use super::engine::Embedder;
use super::keys::{Key, component_key, compose, composed_key};
use super::metrics;
use super::store::{BlobChunkIn, SemanticStore};

/// A working-tree file paired with the blob OID it currently resolves to.
pub struct BlobTarget {
    pub file: ProjectFile,
    pub oid: String,
    pub language: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct PendingChunk {
    chunk_ord: i64,
    kind: &'static str,
    symbol: Option<String>,
    start_line: Option<i64>,
    end_line: Option<i64>,
    fts_tokens: String,
    hash: Key,
    parent_summary_hash: Option<Key>,
    composed_hash: Key,
}

#[derive(Debug, PartialEq, Eq)]
struct PendingBlob {
    oid: String,
    language: Option<String>,
    chunks: Vec<PendingChunk>,
}

struct ExtractedBlob {
    pending_blob: PendingBlob,
    component_texts: Vec<(Key, String)>,
}

/// Phase 1 of materialization (CPU only): tree-sitter extraction + content hashing.
/// Carries no store/embedder handles, so it can run on a producer thread ahead of
/// the GPU embed (see the indexer pipeline). `count_tokens` uses the embedder's
/// tokenizer (cheap, CPU) to size chunks.
#[derive(Debug, PartialEq, Eq)]
pub struct ExtractedGroup {
    pending_blobs: Vec<PendingBlob>,
    component_texts: Vec<(Key, String)>,
}

/// Materialize a group of blobs: extract + embed only what the cache is missing,
/// then persist each blob's chunks. Caller should pre-filter to blobs whose OID
/// is not already present (see `SemanticStore::missing_blobs`).
pub fn materialize_blobs(
    store: &SemanticStore,
    embedder: &dyn Embedder,
    analyzer: &dyn IAnalyzer,
    group: &[BlobTarget],
) -> Result<(), String> {
    let extracted = extract_group(embedder, analyzer, group);
    analyzer.release_streaming_readers();
    finish_group(store, embedder, extracted)
}

/// The distinct component texts a group of files would embed (chunk bodies +
/// parent summaries), in extraction order. Diagnostic helper for embed-stage
/// profiling; uses placeholder OIDs since only the texts are needed.
pub fn extract_group_texts(
    embedder: &dyn Embedder,
    analyzer: &dyn IAnalyzer,
    files: &[ProjectFile],
) -> Vec<String> {
    let targets: Vec<BlobTarget> = files
        .iter()
        .map(|file| BlobTarget {
            file: file.clone(),
            oid: String::new(),
            language: None,
        })
        .collect();
    extract_group(embedder, analyzer, &targets)
        .component_texts
        .into_iter()
        .map(|(_, text)| text)
        .collect()
}

/// Phase 1 (CPU): extract chunks and the distinct component texts to embed.
pub fn extract_group(
    embedder: &dyn Embedder,
    analyzer: &dyn IAnalyzer,
    group: &[BlobTarget],
) -> ExtractedGroup {
    let extracted = group
        .par_iter()
        .map(|target| extract_blob(embedder, analyzer, target))
        .collect();
    assemble_group(extracted)
}

#[cfg(test)]
fn extract_group_serial(
    embedder: &dyn Embedder,
    analyzer: &dyn IAnalyzer,
    group: &[BlobTarget],
) -> ExtractedGroup {
    let extracted = group
        .iter()
        .map(|target| extract_blob(embedder, analyzer, target))
        .collect();
    assemble_group(extracted)
}

fn assemble_group(extracted: Vec<ExtractedBlob>) -> ExtractedGroup {
    // IndexedParallelIterator preserves the input order. Merge and globally
    // deduplicate components in that order so batching and persisted output remain
    // deterministic regardless of worker scheduling.
    let mut pending_blobs: Vec<PendingBlob> = Vec::with_capacity(extracted.len());
    let mut component_texts: Vec<(Key, String)> = Vec::new();
    let mut seen_components: HashSet<Key> = HashSet::new();
    for extracted_blob in extracted {
        pending_blobs.push(extracted_blob.pending_blob);
        for (key, text) in extracted_blob.component_texts {
            if seen_components.insert(key) {
                component_texts.push((key, text));
            }
        }
    }

    ExtractedGroup {
        pending_blobs,
        component_texts,
    }
}

fn extract_blob(
    embedder: &dyn Embedder,
    analyzer: &dyn IAnalyzer,
    target: &BlobTarget,
) -> ExtractedBlob {
    let count_tokens = |text: &str| embedder.count_tokens(text);
    let mut component_texts: Vec<(Key, String)> = Vec::new();
    let mut seen_components: HashSet<Key> = HashSet::new();

    metrics::trace(format_args!(
        "extract file {}",
        target.file.rel_path().display()
    ));
    let extracted = extract_file_chunks(
        analyzer,
        &target.file,
        &count_tokens,
        embedder.profile().max_seq_tokens,
    );
    metrics::trace(format_args!(
        "extract done {} ({} chunks)",
        target.file.rel_path().display(),
        extracted.chunks.len()
    ));
    let mut chunks = Vec::with_capacity(extracted.chunks.len());
    for chunk in extracted.chunks {
        let hash = component_key(&chunk.text);
        let parent_hash = chunk.parent_text.as_deref().map(component_key);
        let composed_hash = match parent_hash {
            Some(parent) => composed_key(&hash, &parent, embedder.profile().parent_alpha),
            None => hash,
        };
        let fts_tokens = fts_text(&chunk.text);
        if seen_components.insert(hash) {
            component_texts.push((hash, chunk.text));
        }
        if let (Some(key), Some(text)) = (parent_hash, chunk.parent_text)
            && seen_components.insert(key)
        {
            component_texts.push((key, text));
        }
        chunks.push(PendingChunk {
            chunk_ord: chunk.ord,
            kind: chunk.kind.as_str(),
            symbol: chunk.symbol,
            start_line: chunk.start_line,
            end_line: chunk.end_line,
            fts_tokens,
            hash,
            parent_summary_hash: parent_hash,
            composed_hash,
        });
    }
    metrics::trace(format_args!(
        "fts/hash done {}",
        target.file.rel_path().display()
    ));

    ExtractedBlob {
        pending_blob: PendingBlob {
            oid: target.oid.clone(),
            language: target.language.clone(),
            chunks,
        },
        component_texts,
    }
}

/// A group's composed vectors + blob metadata, ready to persist. Produced by
/// [`embed_group`] (GPU) and consumed by [`write_group`] (DB) on a separate thread so
/// the DB writes overlap the next group's embed.
pub struct EmbeddedGroup {
    pending_blobs: Vec<PendingBlob>,
    /// Just-embedded component vectors to persist (kept in-memory so embed_group does
    /// no writes — it only reads, which WAL runs concurrently with the writer).
    component_items: Vec<(Key, Vec<f32>)>,
    composed_items: Vec<(Key, Vec<f32>)>,
}

impl EmbeddedGroup {
    pub fn blob_count(&self) -> usize {
        self.pending_blobs.len()
    }
}

/// Embed + compose (phases 2-3) then persist (phase 4), in one call. The pipelined
/// indexer splits these into [`embed_group`] and [`write_group`]; this is the simple
/// path used by `materialize_blobs`.
pub fn finish_group(
    store: &SemanticStore,
    embedder: &dyn Embedder,
    extracted: ExtractedGroup,
) -> Result<(), String> {
    write_group(store, embed_group(store, embedder, extracted)?)
}

/// Phases 2-3 (GPU): embed the missing components and compose the missing chunk
/// vectors. Component vectors are upserted here (compose reads them back), but the
/// composed vectors and blob rows are returned for [`write_group`] to persist so those
/// writes can overlap the next group's embed.
pub fn embed_group(
    store: &SemanticStore,
    embedder: &dyn Embedder,
    extracted: ExtractedGroup,
) -> Result<EmbeddedGroup, String> {
    let ExtractedGroup {
        pending_blobs,
        component_texts,
    } = extracted;

    // 2. Load cached components, then embed the ones absent from that exact read.
    // Keeping the decoded vectors in memory closes a cross-process GC race: a GC may
    // delete a cached row after this read, but composition no longer needs to read it
    // again. Concurrent inserts are harmless because persistence uses upserts.
    let all_component_keys: Vec<Key> = component_texts.iter().map(|(key, _)| *key).collect();
    let mut available = metrics::time(&metrics::SQLITE_NS, || {
        store.component_vectors(&all_component_keys)
    })
    .map_err(|e| e.to_string())?;
    let to_embed: Vec<&(Key, String)> = component_texts
        .iter()
        .filter(|(key, _)| !available.contains_key(key))
        .collect();
    // Just-embedded component vectors, kept in-memory; the writer persists them so
    // embed_group never holds the DB write lock during the GPU forward.
    let mut component_items: Vec<(Key, Vec<f32>)> = Vec::new();
    if !to_embed.is_empty() {
        let texts: Vec<&str> = to_embed.iter().map(|(_, text)| text.as_str()).collect();
        let max_bytes = texts.iter().map(|t| t.len()).max().unwrap_or(0);
        let vectors = metrics::traced(
            &metrics::EMBED_NS,
            format_args!("embed {} texts (max_bytes={max_bytes})", texts.len()),
            || embedder.embed_passages(&texts),
        )?;
        if vectors.len() != to_embed.len() {
            return Err(format!(
                "embedder returned {} component vectors for {} texts",
                vectors.len(),
                to_embed.len()
            ));
        }
        component_items = to_embed.iter().map(|(key, _)| *key).zip(vectors).collect();
        available.extend(component_items.iter().map(|(key, vector)| {
            let rounded = super::quant::decode_vector(&super::quant::encode_vector(vector))
                .unwrap_or_else(|_| vector.clone());
            (*key, rounded)
        }));
    }

    // 3. Compose missing chunk vectors from their (now cached) components.
    let composed_keys: Vec<Key> = pending_blobs
        .iter()
        .flat_map(|blob| blob.chunks.iter().map(|chunk| chunk.composed_hash))
        .collect();
    let missing_composed: BTreeSet<Key> = metrics::time(&metrics::SQLITE_NS, || {
        store.missing_composed_hashes(&composed_keys)
    })
    .map_err(|e| e.to_string())?
    .into_iter()
    .collect();
    let mut composed_items: Vec<(Key, Vec<f32>)> = Vec::new();
    if !missing_composed.is_empty() {
        let mut needed: BTreeSet<Key> = BTreeSet::new();
        for blob in &pending_blobs {
            for chunk in &blob.chunks {
                if missing_composed.contains(&chunk.composed_hash) {
                    needed.insert(chunk.hash);
                    if let Some(parent) = chunk.parent_summary_hash {
                        needed.insert(parent);
                    }
                }
            }
        }
        debug_assert!(needed.iter().all(|key| available.contains_key(key)));
        let mut emitted: BTreeSet<Key> = BTreeSet::new();
        metrics::trace(format_args!("compose {} vectors", missing_composed.len()));
        metrics::time(&metrics::COMPOSE_NS, || -> Result<(), String> {
            for blob in &pending_blobs {
                for chunk in &blob.chunks {
                    if !missing_composed.contains(&chunk.composed_hash)
                        || !emitted.insert(chunk.composed_hash)
                    {
                        continue;
                    }
                    let child = available
                        .get(&chunk.hash)
                        .ok_or_else(|| "component vector missing after embed".to_string())?;
                    let vector = match chunk.parent_summary_hash {
                        Some(parent) => {
                            let parent_vec = available
                                .get(&parent)
                                .ok_or_else(|| "parent vector missing after embed".to_string())?;
                            compose(child, parent_vec, embedder.profile().parent_alpha)
                        }
                        None => child.clone(),
                    };
                    composed_items.push((chunk.composed_hash, vector));
                }
            }
            Ok(())
        })?;
    }

    Ok(EmbeddedGroup {
        pending_blobs,
        component_items,
        composed_items,
    })
}

/// Phase 4 (DB): persist a group's composed vectors and blob metadata. Runs on the
/// writer thread so these writes overlap the next group's embed.
pub fn write_group(store: &SemanticStore, embedded: EmbeddedGroup) -> Result<(), String> {
    let EmbeddedGroup {
        pending_blobs,
        component_items,
        composed_items,
    } = embedded;
    if !component_items.is_empty() {
        metrics::trace(format_args!(
            "upsert_component {} vectors",
            component_items.len()
        ));
        store
            .upsert_component_vectors(&component_items)
            .map_err(|e| e.to_string())?;
    }
    if !composed_items.is_empty() {
        metrics::trace(format_args!(
            "upsert_composed {} vectors",
            composed_items.len()
        ));
        store
            .upsert_composed_vectors(&composed_items)
            .map_err(|e| e.to_string())?;
    }

    // Persist all blobs' chunk metadata in a single transaction (vs ~one per blob).
    let all_rows: Vec<Vec<BlobChunkIn>> = pending_blobs
        .iter()
        .map(|blob| {
            blob.chunks
                .iter()
                .map(|chunk| BlobChunkIn {
                    chunk_ord: chunk.chunk_ord,
                    kind: chunk.kind,
                    symbol: chunk.symbol.as_deref(),
                    start_line: chunk.start_line,
                    end_line: chunk.end_line,
                    fts_tokens: &chunk.fts_tokens,
                    hash: chunk.hash,
                    parent_summary_hash: chunk.parent_summary_hash,
                    composed_hash: chunk.composed_hash,
                })
                .collect()
        })
        .collect();
    let blob_args: Vec<(&str, Option<&str>, &[BlobChunkIn])> = pending_blobs
        .iter()
        .zip(&all_rows)
        .map(|(blob, rows)| (blob.oid.as_str(), blob.language.as_deref(), rows.as_slice()))
        .collect();
    metrics::trace(format_args!("put_blobs ({} blobs)", blob_args.len()));
    metrics::time(&metrics::SQLITE_NS, || store.put_blobs(&blob_args))
        .map_err(|e| e.to_string())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Embedder, FakeHashEmbedder, ModelProfile};
    use brokk_bifrost_analysis::analyzer::{JavaAnalyzer, Language, TestProject};
    use std::sync::atomic::{AtomicBool, Ordering};

    struct GcOnProfile<'a> {
        store: &'a SemanticStore,
        fired: AtomicBool,
    }

    impl Embedder for GcOnProfile<'_> {
        fn profile(&self) -> ModelProfile {
            if !self.fired.swap(true, Ordering::SeqCst) {
                self.store.gc(&HashSet::new()).unwrap();
            }
            crate::engine::VOYAGE_PROFILE
        }

        fn embed_passages(&self, _texts: &[&str]) -> Result<Vec<Vec<f32>>, String> {
            panic!("cached components must not be re-embedded")
        }

        fn embed_query(&self, _text: &str) -> Result<Vec<f32>, String> {
            unreachable!()
        }

        fn count_tokens(&self, _text: &str) -> usize {
            unreachable!()
        }

        fn fingerprint(&self) -> String {
            unreachable!()
        }
    }

    #[test]
    fn parallel_extraction_preserves_serial_chunk_and_component_order() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let files = [
            ProjectFile::new(root.clone(), "Alpha.java"),
            ProjectFile::new(root.clone(), "Beta.java"),
            ProjectFile::new(root.clone(), "Gamma.java"),
        ];
        files[0]
            .write("class Alpha { void shared() {} void alpha() {} }\n")
            .unwrap();
        files[1]
            .write("class Beta { void shared() {} void beta() {} }\n")
            .unwrap();
        files[2].write("class Gamma { void gamma() {} }\n").unwrap();
        let analyzer = JavaAnalyzer::from_project(TestProject::new(root, Language::Java));
        let embedder = FakeHashEmbedder::new(16);
        let targets: Vec<_> = files
            .into_iter()
            .enumerate()
            .map(|(index, file)| BlobTarget {
                file,
                oid: format!("oid-{index}"),
                language: Some("java".to_string()),
            })
            .collect();

        let serial = extract_group_serial(&embedder, &analyzer, &targets);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(3)
            .build()
            .unwrap();
        let parallel = pool.install(|| extract_group(&embedder, &analyzer, &targets));

        assert_eq!(parallel, serial);
    }

    #[test]
    fn compose_survives_cached_component_gc_after_the_read() {
        let temp = tempfile::tempdir().unwrap();
        let store = SemanticStore::open(&temp.path().join("cache.db")).unwrap();
        let child = component_key("child");
        let parent = component_key("parent");
        let composed = composed_key(&child, &parent, 0.5);
        store
            .upsert_component_vectors(&[(child, vec![1.0, 0.0]), (parent, vec![0.0, 1.0])])
            .unwrap();
        let extracted = ExtractedGroup {
            pending_blobs: vec![PendingBlob {
                oid: "oid".to_string(),
                language: None,
                chunks: vec![PendingChunk {
                    chunk_ord: 0,
                    kind: "function",
                    symbol: None,
                    start_line: None,
                    end_line: None,
                    fts_tokens: String::new(),
                    hash: child,
                    parent_summary_hash: Some(parent),
                    composed_hash: composed,
                }],
            }],
            component_texts: vec![(child, "child".to_string()), (parent, "parent".to_string())],
        };
        let embedder = GcOnProfile {
            store: &store,
            fired: AtomicBool::new(false),
        };

        let embedded = embed_group(&store, &embedder, extracted).unwrap();

        assert!(embedder.fired.load(Ordering::SeqCst));
        assert_eq!(embedded.composed_items.len(), 1);
        assert_eq!(
            store
                .missing_component_hashes(&[child, parent])
                .unwrap()
                .len(),
            2
        );
    }
}
