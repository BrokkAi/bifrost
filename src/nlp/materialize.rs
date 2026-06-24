//! Blob materialization: turn a (parsed) working-tree file into cached chunks,
//! summaries, and vectors keyed by its git blob OID.
//!
//! Mirrors the per-file extraction the old `index_file_group` did, but writes the
//! content-addressed schema: embeddings are skipped for component texts already
//! cached (by content hash), and a blob whose OID is already present is never
//! re-materialized. A group is materialized together so embedding batches well.

use std::collections::BTreeSet;

use crate::analyzer::{IAnalyzer, ProjectFile};

use super::bm25::fts_text;
use super::chunker::extract_file_chunks;
use super::engine::Embedder;
use super::keys::{Key, component_key, compose, composed_key};
use super::store::{BlobChunkIn, SemanticStore};

/// A working-tree file paired with the blob OID it currently resolves to.
pub struct BlobTarget {
    pub file: ProjectFile,
    pub oid: String,
    pub language: Option<String>,
}

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

struct PendingBlob {
    oid: String,
    language: Option<String>,
    chunks: Vec<PendingChunk>,
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
    let count_tokens = |text: &str| embedder.count_tokens(text);

    // 1. Extract chunks; collect distinct component texts (chunk bodies + parent
    //    summaries) keyed by content hash.
    let mut pending_blobs: Vec<PendingBlob> = Vec::with_capacity(group.len());
    let mut component_texts: Vec<(Key, String)> = Vec::new();
    let mut seen_components: BTreeSet<Key> = BTreeSet::new();

    for target in group {
        let extracted = extract_file_chunks(analyzer, &target.file, &count_tokens);
        let mut chunks = Vec::with_capacity(extracted.chunks.len());
        for chunk in extracted.chunks {
            let hash = component_key(&chunk.text);
            if seen_components.insert(hash) {
                component_texts.push((hash, chunk.text.clone()));
            }
            let parent_hash = chunk.parent_text.as_deref().map(component_key);
            if let (Some(key), Some(text)) = (parent_hash, chunk.parent_text.as_deref())
                && seen_components.insert(key)
            {
                component_texts.push((key, text.to_string()));
            }
            let composed_hash = match parent_hash {
                Some(parent) => composed_key(&hash, &parent),
                None => hash,
            };
            chunks.push(PendingChunk {
                chunk_ord: chunk.ord,
                kind: chunk.kind.as_str(),
                symbol: chunk.symbol,
                start_line: chunk.start_line,
                end_line: chunk.end_line,
                fts_tokens: fts_text(&chunk.text),
                hash,
                parent_summary_hash: parent_hash,
                composed_hash,
            });
        }
        pending_blobs.push(PendingBlob {
            oid: target.oid.clone(),
            language: target.language.clone(),
            chunks,
        });
    }

    // 2. Embed component texts the store has never seen.
    let all_component_keys: Vec<Key> = component_texts.iter().map(|(key, _)| *key).collect();
    let missing: BTreeSet<Key> = store
        .missing_component_hashes(&all_component_keys)
        .map_err(|e| e.to_string())?
        .into_iter()
        .collect();
    let to_embed: Vec<&(Key, String)> = component_texts
        .iter()
        .filter(|(key, _)| missing.contains(key))
        .collect();
    if !to_embed.is_empty() {
        let texts: Vec<&str> = to_embed.iter().map(|(_, text)| text.as_str()).collect();
        let vectors = embedder.embed_passages(&texts)?;
        let items: Vec<(Key, Vec<f32>)> =
            to_embed.iter().map(|(key, _)| *key).zip(vectors).collect();
        store
            .upsert_component_vectors(&items)
            .map_err(|e| e.to_string())?;
    }

    // 3. Compose missing chunk vectors from their (now cached) components.
    let composed_keys: Vec<Key> = pending_blobs
        .iter()
        .flat_map(|blob| blob.chunks.iter().map(|chunk| chunk.composed_hash))
        .collect();
    let missing_composed: BTreeSet<Key> = store
        .missing_composed_hashes(&composed_keys)
        .map_err(|e| e.to_string())?
        .into_iter()
        .collect();
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
        let component_vectors = store
            .component_vectors(&needed.iter().copied().collect::<Vec<_>>())
            .map_err(|e| e.to_string())?;
        let mut composed_items: Vec<(Key, Vec<f32>)> = Vec::new();
        let mut emitted: BTreeSet<Key> = BTreeSet::new();
        for blob in &pending_blobs {
            for chunk in &blob.chunks {
                if !missing_composed.contains(&chunk.composed_hash)
                    || !emitted.insert(chunk.composed_hash)
                {
                    continue;
                }
                let child = component_vectors
                    .get(&chunk.hash)
                    .ok_or_else(|| "component vector missing after embed".to_string())?;
                let vector = match chunk.parent_summary_hash {
                    Some(parent) => {
                        let parent_vec = component_vectors
                            .get(&parent)
                            .ok_or_else(|| "parent vector missing after embed".to_string())?;
                        compose(child, parent_vec)
                    }
                    None => child.clone(),
                };
                composed_items.push((chunk.composed_hash, vector));
            }
        }
        store
            .upsert_composed_vectors(&composed_items)
            .map_err(|e| e.to_string())?;
    }

    // 4. Persist each blob's chunk metadata.
    for blob in &pending_blobs {
        let rows: Vec<BlobChunkIn> = blob
            .chunks
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
            .collect();
        store
            .put_blob(&blob.oid, blob.language.as_deref(), &rows)
            .map_err(|e| e.to_string())?;
    }

    Ok(())
}
