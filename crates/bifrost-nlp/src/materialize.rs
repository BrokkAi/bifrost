//! Path-aware semantic materialization.
//!
//! A materialized file is identified by both its git blob OID and its
//! workspace-relative path because the path is part of every embedding document.
//! Raw source is tokenized for BM25, while the canonical headered document is
//! retained only through the embedding call.

use std::collections::HashSet;
use std::ops::Range;

use rayon::prelude::*;

use brokk_bifrost_analysis::analyzer::{IAnalyzer, ProjectFile};

use super::bm25::fts_text;
use super::chunker::extract_file_chunks;
use super::engine::Embedder;
use super::keys::{Key, document_key};
use super::metrics;
use super::store::{FileChunkIn, SemanticStore};

const EMBED_REQUEST_DOCUMENTS: usize = 2_048;
const EMBED_REQUEST_BYTES: usize = 4 * 1024 * 1024;

/// Partition stable input order by both item count and an additive byte estimate.
/// An oversized item is emitted alone so a budget is never an admission limit.
pub(super) fn bounded_batch_ranges(
    item_bytes: impl IntoIterator<Item = usize>,
    max_items: usize,
    max_bytes: usize,
) -> Vec<Range<usize>> {
    assert!(max_items > 0, "batch item limit must be positive");
    assert!(max_bytes > 0, "batch byte limit must be positive");

    let mut ranges = Vec::new();
    let mut start = 0;
    let mut count = 0;
    let mut bytes = 0usize;
    for (index, item_bytes) in item_bytes.into_iter().enumerate() {
        let exceeds_bytes = bytes > max_bytes || item_bytes > max_bytes - bytes;
        if count > 0 && (count == max_items || exceeds_bytes) {
            ranges.push(start..index);
            start = index;
            count = 0;
            bytes = 0;
        }
        count += 1;
        bytes = bytes.saturating_add(item_bytes);
    }
    if count > 0 {
        ranges.push(start..start + count);
    }
    ranges
}

/// A working-tree file paired with the blob OID it currently resolves to.
pub struct FileTarget {
    pub file: ProjectFile,
    pub oid: String,
    pub language: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct PendingChunk {
    chunk_ord: i64,
    symbol: String,
    start_line: Option<i64>,
    end_line: Option<i64>,
    fts_tokens: String,
    vector_hash: Key,
}

#[derive(Debug, PartialEq, Eq)]
struct PendingFile {
    oid: String,
    rel_path: String,
    language: Option<String>,
    chunks: Vec<PendingChunk>,
}

struct ExtractedFile {
    pending_file: PendingFile,
    documents: Vec<(Key, String)>,
}

/// CPU extraction output passed to the GPU stage.
#[derive(Debug, PartialEq, Eq)]
pub struct ExtractedGroup {
    pending_files: Vec<PendingFile>,
    documents: Vec<(Key, String)>,
}

pub fn materialize_files(
    store: &SemanticStore,
    embedder: &dyn Embedder,
    analyzer: &dyn IAnalyzer,
    group: &[FileTarget],
) -> Result<(), String> {
    let extracted = extract_group(analyzer, group);
    analyzer.release_streaming_readers();
    finish_group(store, embedder, extracted)
}

/// Distinct canonical documents a file group would embed, for diagnostics.
pub fn extract_group_texts(analyzer: &dyn IAnalyzer, files: &[ProjectFile]) -> Vec<String> {
    let targets: Vec<FileTarget> = files
        .iter()
        .map(|file| FileTarget {
            file: file.clone(),
            oid: String::new(),
            language: None,
        })
        .collect();
    extract_group(analyzer, &targets)
        .documents
        .into_iter()
        .map(|(_, text)| text)
        .collect()
}

pub fn extract_group(analyzer: &dyn IAnalyzer, group: &[FileTarget]) -> ExtractedGroup {
    let extracted = group
        .par_iter()
        .map(|target| extract_file(analyzer, target))
        .collect();
    assemble_group(extracted)
}

#[cfg(test)]
fn extract_group_serial(analyzer: &dyn IAnalyzer, group: &[FileTarget]) -> ExtractedGroup {
    assemble_group(
        group
            .iter()
            .map(|target| extract_file(analyzer, target))
            .collect(),
    )
}

fn assemble_group(extracted: Vec<ExtractedFile>) -> ExtractedGroup {
    // IndexedParallelIterator preserves input order. Deduplicate documents in
    // that order so batching stays deterministic regardless of scheduling.
    let mut pending_files = Vec::with_capacity(extracted.len());
    let mut documents = Vec::new();
    let mut seen = HashSet::new();
    for extracted_file in extracted {
        pending_files.push(extracted_file.pending_file);
        for (key, text) in extracted_file.documents {
            if seen.insert(key) {
                documents.push((key, text));
            }
        }
    }
    ExtractedGroup {
        pending_files,
        documents,
    }
}

fn extract_file(analyzer: &dyn IAnalyzer, target: &FileTarget) -> ExtractedFile {
    metrics::trace(format_args!(
        "extract file {}",
        target.file.rel_path().display()
    ));
    let extracted = extract_file_chunks(analyzer, &target.file);
    metrics::trace(format_args!(
        "extract done {} ({} functions)",
        target.file.rel_path().display(),
        extracted.chunks.len()
    ));

    let mut documents = Vec::with_capacity(extracted.chunks.len());
    let mut seen = HashSet::new();
    let mut chunks = Vec::with_capacity(extracted.chunks.len());
    for chunk in extracted.chunks {
        let document = chunk.embedding_document(&extracted.file_path);
        let vector_hash = document_key(&document);
        let fts_tokens = fts_text(&chunk.source_text);
        if seen.insert(vector_hash) {
            documents.push((vector_hash, document));
        }
        chunks.push(PendingChunk {
            chunk_ord: chunk.ord,
            symbol: chunk.symbol,
            start_line: chunk.start_line,
            end_line: chunk.end_line,
            fts_tokens,
            vector_hash,
        });
    }
    metrics::trace(format_args!(
        "fts/hash done {}",
        target.file.rel_path().display()
    ));

    ExtractedFile {
        pending_file: PendingFile {
            oid: target.oid.clone(),
            rel_path: extracted.file_path,
            language: target.language.clone(),
            chunks,
        },
        documents,
    }
}

/// GPU output retained for the single SQLite writer stage.
pub struct EmbeddedGroup {
    pending_files: Vec<PendingFile>,
    vector_items: Vec<(Key, Vec<f32>)>,
}

impl EmbeddedGroup {
    pub fn file_count(&self) -> usize {
        self.pending_files.len()
    }
}

pub fn finish_group(
    store: &SemanticStore,
    embedder: &dyn Embedder,
    extracted: ExtractedGroup,
) -> Result<(), String> {
    write_group(store, embed_group(store, embedder, extracted)?)
}

pub fn embed_group(
    store: &SemanticStore,
    embedder: &dyn Embedder,
    extracted: ExtractedGroup,
) -> Result<EmbeddedGroup, String> {
    let ExtractedGroup {
        pending_files,
        documents,
    } = extracted;
    let keys: Vec<Key> = documents.iter().map(|(key, _)| *key).collect();
    let missing: HashSet<Key> =
        metrics::time(&metrics::SQLITE_NS, || store.missing_vector_hashes(&keys))
            .map_err(|error| error.to_string())?
            .into_iter()
            .collect();
    let to_embed: Vec<&(Key, String)> = documents
        .iter()
        .filter(|(key, _)| missing.contains(key))
        .collect();

    let mut vector_items = Vec::with_capacity(to_embed.len());
    for range in bounded_batch_ranges(
        to_embed.iter().map(|(_, text)| text.len()),
        EMBED_REQUEST_DOCUMENTS,
        EMBED_REQUEST_BYTES,
    ) {
        let batch = &to_embed[range];
        let texts: Vec<&str> = batch.iter().map(|(_, text)| text.as_str()).collect();
        let total_bytes: usize = texts.iter().map(|text| text.len()).sum();
        let max_bytes = texts.iter().map(|text| text.len()).max().unwrap_or(0);
        let vectors = metrics::traced(
            &metrics::EMBED_NS,
            format_args!(
                "embed {} documents (total_bytes={total_bytes}, max_bytes={max_bytes})",
                texts.len()
            ),
            || embedder.embed_passages(&texts),
        )?;
        if vectors.len() != batch.len() {
            return Err(format!(
                "embedder returned {} vectors for {} documents",
                vectors.len(),
                batch.len()
            ));
        }
        vector_items.extend(batch.iter().map(|(key, _)| *key).zip(vectors));
    }

    Ok(EmbeddedGroup {
        pending_files,
        vector_items,
    })
}

pub fn write_group(store: &SemanticStore, embedded: EmbeddedGroup) -> Result<(), String> {
    let EmbeddedGroup {
        pending_files,
        vector_items,
    } = embedded;
    if !vector_items.is_empty() {
        metrics::trace(format_args!("upsert {} vectors", vector_items.len()));
        store
            .upsert_vectors(&vector_items)
            .map_err(|error| error.to_string())?;
    }

    let all_rows: Vec<Vec<FileChunkIn>> = pending_files
        .iter()
        .map(|file| {
            file.chunks
                .iter()
                .map(|chunk| FileChunkIn {
                    chunk_ord: chunk.chunk_ord,
                    symbol: &chunk.symbol,
                    start_line: chunk.start_line,
                    end_line: chunk.end_line,
                    fts_tokens: &chunk.fts_tokens,
                    vector_hash: chunk.vector_hash,
                })
                .collect()
        })
        .collect();
    let file_args: Vec<(&str, &str, Option<&str>, &[FileChunkIn])> = pending_files
        .iter()
        .zip(&all_rows)
        .map(|(file, rows)| {
            (
                file.oid.as_str(),
                file.rel_path.as_str(),
                file.language.as_deref(),
                rows.as_slice(),
            )
        })
        .collect();
    metrics::trace(format_args!("put_files ({} files)", file_args.len()));
    metrics::time(&metrics::SQLITE_NS, || store.put_files(&file_args))
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Embedder, FakeHashEmbedder, ModelProfile};
    use brokk_bifrost_analysis::analyzer::{JavaAnalyzer, Language, TestProject};
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingEmbedder {
        calls: Mutex<Vec<Vec<String>>>,
    }

    impl Embedder for RecordingEmbedder {
        fn profile(&self) -> ModelProfile {
            ModelProfile {
                dimension: 1,
                ..crate::engine::VOYAGE_PROFILE
            }
        }

        fn embed_passages(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, String> {
            self.calls
                .lock()
                .unwrap()
                .push(texts.iter().map(|text| (*text).to_string()).collect());
            Ok(texts.iter().map(|_| vec![1.0]).collect())
        }

        fn embed_query(&self, _text: &str) -> Result<Vec<f32>, String> {
            unreachable!()
        }

        fn fingerprint(&self) -> String {
            "recording".to_string()
        }
    }

    fn extracted_documents(texts: Vec<String>) -> ExtractedGroup {
        ExtractedGroup {
            pending_files: Vec::new(),
            documents: texts
                .into_iter()
                .map(|text| (document_key(&text), text))
                .collect(),
        }
    }

    #[test]
    fn bounded_batches_respect_both_limits_and_admit_oversized_items() {
        assert_eq!(bounded_batch_ranges([1, 1, 1], 2, 100), vec![0..2, 2..3]);
        assert_eq!(bounded_batch_ranges([4, 4, 4], 10, 8), vec![0..2, 2..3]);
        assert_eq!(bounded_batch_ranges([11, 1], 10, 10), vec![0..1, 1..2]);
    }

    #[test]
    fn embed_group_batches_direct_documents_and_preserves_order() {
        let temp = tempfile::tempdir().unwrap();
        let store = SemanticStore::open(&temp.path().join("cache.db")).unwrap();
        let texts: Vec<String> = (0..EMBED_REQUEST_DOCUMENTS + 1)
            .map(|index| format!("document-{index}"))
            .collect();
        let embedder = RecordingEmbedder::default();

        let embedded = embed_group(&store, &embedder, extracted_documents(texts)).unwrap();

        let calls = embedder.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].len(), EMBED_REQUEST_DOCUMENTS);
        assert_eq!(calls[1].len(), 1);
        assert_eq!(embedded.vector_items.len(), EMBED_REQUEST_DOCUMENTS + 1);
    }

    #[test]
    fn parallel_extraction_matches_serial_and_embeds_path_headers() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let files = [
            ProjectFile::new(root.clone(), "Alpha.java"),
            ProjectFile::new(root.clone(), "Beta.java"),
        ];
        files[0].write("class Alpha { void run() {} }\n").unwrap();
        files[1].write("class Beta { void run() {} }\n").unwrap();
        let analyzer = JavaAnalyzer::from_project(TestProject::new(root, Language::Java));
        let targets: Vec<_> = files
            .into_iter()
            .enumerate()
            .map(|(index, file)| FileTarget {
                file,
                oid: format!("oid-{index}"),
                language: Some("java".to_string()),
            })
            .collect();

        let serial = extract_group_serial(&analyzer, &targets);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap();
        let parallel = pool.install(|| extract_group(&analyzer, &targets));

        assert_eq!(parallel, serial);
        assert!(
            parallel.documents[0]
                .1
                .starts_with("Alpha.java/Alpha/run\nclass Alpha:")
        );
        assert!(
            parallel.documents[1]
                .1
                .starts_with("Beta.java/Beta/run\nclass Beta:")
        );
        assert_ne!(parallel.documents[0].0, parallel.documents[1].0);
    }

    #[test]
    fn identical_blobs_at_different_paths_have_distinct_documents() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let files = [
            ProjectFile::new(root.clone(), "left/Same.java"),
            ProjectFile::new(root.clone(), "right/Same.java"),
        ];
        let source = "class Same { void run() {} }\n";
        for file in &files {
            file.write(source).unwrap();
        }
        let analyzer = JavaAnalyzer::from_project(TestProject::new(root, Language::Java));
        let targets: Vec<_> = files
            .into_iter()
            .map(|file| FileTarget {
                file,
                oid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                language: Some("java".to_string()),
            })
            .collect();

        let extracted = extract_group_serial(&analyzer, &targets);

        assert_eq!(extracted.pending_files.len(), 2);
        assert_eq!(extracted.documents.len(), 2);
        assert!(extracted.documents[0].1.starts_with("left/Same.java/"));
        assert!(extracted.documents[1].1.starts_with("right/Same.java/"));
        assert_ne!(extracted.documents[0].0, extracted.documents[1].0);
    }

    #[test]
    fn path_and_class_prefixes_do_not_enter_bm25_tokens() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = ProjectFile::new(root.clone(), "onlyheader/Widget.java");
        file.write("class Widget { void execute() {} }\n").unwrap();
        let analyzer = JavaAnalyzer::from_project(TestProject::new(root, Language::Java));
        let extracted = extract_group_serial(
            &analyzer,
            &[FileTarget {
                file,
                oid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                language: Some("java".to_string()),
            }],
        );

        assert!(extracted.documents[0].1.contains("onlyheader/Widget.java"));
        let tokens = &extracted.pending_files[0].chunks[0].fts_tokens;
        assert!(
            !tokens.contains("onlyheader"),
            "raw-source tokens: {tokens}"
        );
        assert!(tokens.contains("execute"), "raw-source tokens: {tokens}");
    }

    #[test]
    fn materialization_sends_the_canonical_document_to_the_embedder() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = ProjectFile::new(root.clone(), "src/Worker.java");
        file.write("class Worker { void execute() {} }\n").unwrap();
        let analyzer = JavaAnalyzer::from_project(TestProject::new(root, Language::Java));
        let store = SemanticStore::open(&temp.path().join("cache.db")).unwrap();
        let embedder = RecordingEmbedder::default();

        materialize_files(
            &store,
            &embedder,
            &analyzer,
            &[FileTarget {
                file,
                oid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                language: Some("java".to_string()),
            }],
        )
        .unwrap();

        let calls = embedder.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].len(), 1);
        assert!(
            calls[0][0].starts_with("src/Worker.java/Worker/execute\nclass Worker:void execute()")
        );
    }

    #[test]
    fn cached_documents_are_not_reembedded() {
        let temp = tempfile::tempdir().unwrap();
        let store = SemanticStore::open(&temp.path().join("cache.db")).unwrap();
        let embedder = FakeHashEmbedder::new(16);
        let text = "src/lib.rs/run\nfn run() {}".to_string();
        let hash = document_key(&text);
        store.upsert_vectors(&[(hash, vec![1.0; 16])]).unwrap();

        let embedded = embed_group(&store, &embedder, extracted_documents(vec![text])).unwrap();

        assert!(embedded.vector_items.is_empty());
        assert_eq!(embedder.texts_embedded(), 0);
    }
}
