//! The semantic_search query pipeline.
//!
//! Retrieval = exhaustive vector scan (file score = max chunk dot product),
//! blended with git co-edit relevance via reciprocal-rank fusion, unioned
//! with grounded-strings BM25 candidates, then cross-encoder reranked.
//! Constants come from the prototype's dev sweeps (see `nlp/mod.rs`).

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::analyzer::{IAnalyzer, ProjectFile, WorkspaceAnalyzer};
use crate::path_utils::rel_path_string;
use crate::searchtools::{MostRelevantFilesParams, most_relevant_files};

use super::bm25::{RepoEntityUniverse, build_match_query, grounded_prompt_text, tokenize};
use super::chunker::{ChunkKind, FileChunks, extract_file_chunks};
use super::indexer::{DEFAULT_READY_TIMEOUT, SemanticIndexer};
use super::keys::dot;
use super::{COEDIT_HALF_LIFE, COEDIT_LAMBDA, COEDIT_SEEDS, FILE_CHUNK_CAP, PROTECT_N, RRF_K};

/// Rows decoded per scan batch.
const SCAN_BATCH: usize = 8192;
const MAX_K: usize = 100;

#[derive(Debug, Clone, Deserialize)]
pub struct SemanticSearchParams {
    pub query: String,
    #[serde(default = "default_k")]
    pub k: usize,
}

fn default_k() -> usize {
    10
}

#[derive(Debug, Clone, Serialize)]
pub struct SemanticSearchHit {
    pub path: String,
    pub score: f32,
    /// The file's summary-or-symbols text, re-derived from the live snapshot.
    pub summary: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SemanticSearchResult {
    pub hits: Vec<SemanticSearchHit>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub notes: Vec<String>,
}

pub fn semantic_search(
    workspace: &WorkspaceAnalyzer,
    indexer: &SemanticIndexer,
    params: SemanticSearchParams,
) -> Result<SemanticSearchResult, String> {
    let query = params.query.trim();
    if query.is_empty() {
        return Err("query must not be empty".to_string());
    }
    let k = params.k.clamp(1, MAX_K);
    let candidate_limit = k * 2;

    indexer.wait_ready(DEFAULT_READY_TIMEOUT)?;
    let store = indexer
        .store()
        .ok_or_else(|| "semantic index store unavailable".to_string())?;
    let embedder = indexer
        .embedder()
        .ok_or_else(|| "embedding model unavailable".to_string())?;
    let workspace_id = indexer
        .workspace_id()
        .ok_or_else(|| "semantic index workspace unavailable".to_string())?;
    let analyzer = workspace.analyzer();
    let mut notes = Vec::new();

    // 1. Exhaustive vector scan; file score = max over its chunk vectors.
    let query_vector = embedder.embed_query(query)?;
    let mut file_best: HashMap<String, f32> = HashMap::new();
    store
        .scan_vectors(workspace_id, SCAN_BATCH, &mut |batch| {
            for row in batch {
                let score = dot(&row.vector, &query_vector);
                file_best
                    .entry(row.file_path)
                    .and_modify(|best| *best = best.max(score))
                    .or_insert(score);
            }
        })
        .map_err(|err| err.to_string())?;
    let mut vector_ranked: Vec<(String, f32)> = file_best.into_iter().collect();
    vector_ranked.sort_by(|(path_a, score_a), (path_b, score_b)| {
        score_b
            .partial_cmp(score_a)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| path_a.cmp(path_b))
    });
    let vector_paths: Vec<String> = vector_ranked.iter().map(|(path, _)| path.clone()).collect();
    let vector_scores: HashMap<&str, f32> = vector_ranked
        .iter()
        .map(|(path, score)| (path.as_str(), *score))
        .collect();

    // 2. Co-edit relevance seeded by the top vector hit, RRF-blended.
    let coedit_ranked = if vector_paths.is_empty() {
        Vec::new()
    } else {
        let seeds: Vec<String> = vector_paths.iter().take(COEDIT_SEEDS).cloned().collect();
        match most_relevant_files(
            analyzer,
            MostRelevantFilesParams {
                seed_file_paths: seeds,
                seed_weights: None,
                recency_half_life: Some(COEDIT_HALF_LIFE),
                limit: candidate_limit * 2,
            },
        ) {
            Ok(result) => result.files,
            Err(err) => {
                notes.push(format!("co-edit blend skipped: {err}"));
                Vec::new()
            }
        }
    };
    let mut blended = rrf_blend(
        &vector_paths,
        &coedit_ranked,
        PROTECT_N,
        RRF_K,
        COEDIT_LAMBDA,
    );
    blended.truncate(candidate_limit);

    // 3. Grounded-strings BM25 candidates.
    let bm25_files = bm25_candidates(analyzer, &store, workspace_id, query, candidate_limit)
        .unwrap_or_else(|err| {
            notes.push(format!("bm25 retrieval skipped: {err}"));
            Vec::new()
        });

    // 4. Union, blended order first (bounded by 2 * candidate_limit).
    let mut candidates = blended.clone();
    let mut seen: HashSet<String> = candidates.iter().cloned().collect();
    for path in &bm25_files {
        if seen.insert(path.clone()) {
            candidates.push(path.clone());
        }
    }

    // 5. Re-derive candidate texts from the live snapshot.
    let files_by_path: HashMap<String, ProjectFile> = analyzer
        .analyzed_files()
        .map(|file| (rel_path_string(file), file.clone()))
        .collect();
    let count_tokens = |text: &str| embedder.count_tokens(text);
    let mut dropped = 0usize;
    let mut candidate_chunks: Vec<(String, FileChunks)> = Vec::new();
    for path in &candidates {
        match files_by_path.get(path) {
            Some(file) => {
                let chunks = extract_file_chunks(analyzer, file, &count_tokens);
                candidate_chunks.push((path.clone(), chunks));
            }
            None => dropped += 1,
        }
    }
    if dropped > 0 {
        notes.push(format!(
            "{dropped} stale candidate(s) no longer in the workspace were dropped"
        ));
    }

    // 6. Cross-encoder rerank: per-chunk docs, file score = max, blended
    //    top-PROTECT_N keep their positions.
    let ordering = match indexer.reranker() {
        Ok(reranker) => {
            let mut docs = Vec::new();
            let mut spans: Vec<(usize, usize)> = Vec::new();
            for (path, chunks) in &candidate_chunks {
                let selected = rerank_chunk_texts(chunks);
                let start = docs.len();
                docs.extend(selected.iter().map(|text| format!("{path}\n{text}")));
                spans.push((start, docs.len()));
            }
            match reranker.score_pairs(query, &docs) {
                Ok(scores) => Some(
                    spans
                        .iter()
                        .map(|(start, end)| {
                            scores[*start..*end]
                                .iter()
                                .copied()
                                .fold(f32::NEG_INFINITY, f32::max)
                        })
                        .collect::<Vec<f32>>(),
                ),
                Err(err) => {
                    notes.push(format!("reranker failed; returning blended order: {err}"));
                    None
                }
            }
        }
        Err(err) => {
            notes.push(format!(
                "reranker unavailable; returning blended order: {err}"
            ));
            None
        }
    };

    let mut ranked: Vec<(String, f32)> = match ordering {
        Some(ce_scores) => {
            let blended_rank: HashMap<&str, usize> = candidate_chunks
                .iter()
                .enumerate()
                .map(|(rank, (path, _))| (path.as_str(), rank))
                .collect();
            let mut protected = Vec::new();
            let mut rest = Vec::new();
            for (index, (path, _)) in candidate_chunks.iter().enumerate() {
                let entry = (path.clone(), ce_scores[index]);
                if blended_rank[path.as_str()] < PROTECT_N {
                    protected.push(entry);
                } else {
                    rest.push(entry);
                }
            }
            rest.sort_by(|(path_a, score_a), (path_b, score_b)| {
                score_b
                    .partial_cmp(score_a)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| blended_rank[path_a.as_str()].cmp(&blended_rank[path_b.as_str()]))
            });
            protected.into_iter().chain(rest).collect()
        }
        None => candidate_chunks
            .iter()
            .map(|(path, _)| {
                let score = vector_scores.get(path.as_str()).copied().unwrap_or(0.0);
                (path.clone(), score)
            })
            .collect(),
    };
    ranked.truncate(k);

    // 7. Hits carry the file's summary-or-symbols text.
    let summaries: HashMap<&str, Option<&str>> = candidate_chunks
        .iter()
        .map(|(path, chunks)| (path.as_str(), chunks.summary_text.as_deref()))
        .collect();
    let hits = ranked
        .into_iter()
        .map(|(path, score)| {
            let summary = summaries
                .get(path.as_str())
                .copied()
                .flatten()
                .unwrap_or("")
                .to_string();
            SemanticSearchHit {
                path,
                score,
                summary,
            }
        })
        .collect();

    Ok(SemanticSearchResult { hits, notes })
}

/// Port of the prototype's `rerank_task` (coedit-reranker/harness.py):
/// the top `protect` vector files keep their positions; everything else is
/// scored `1/(k+vector_rank) + lambda/(k+coedit_rank)` with missing terms
/// omitted; coedit-only candidates may enter when lambda > 0.
fn rrf_blend(
    vector_ranked: &[String],
    coedit_ranked: &[String],
    protect: usize,
    k_value: f64,
    lambda: f64,
) -> Vec<String> {
    const UNRANKED: usize = usize::MAX;
    let vector_ranks: HashMap<&str, usize> = vector_ranked
        .iter()
        .enumerate()
        .map(|(index, path)| (path.as_str(), index + 1))
        .collect();
    let coedit_ranks: HashMap<&str, usize> = coedit_ranked
        .iter()
        .enumerate()
        .map(|(index, path)| (path.as_str(), index + 1))
        .collect();

    let protected: Vec<String> = vector_ranked.iter().take(protect).cloned().collect();
    let protected_set: HashSet<&str> = protected.iter().map(String::as_str).collect();

    let mut candidate_order: Vec<&str> = vector_ranked.iter().map(String::as_str).collect();
    let mut seen: HashSet<&str> = candidate_order.iter().copied().collect();
    for path in coedit_ranked {
        if seen.insert(path.as_str()) {
            candidate_order.push(path.as_str());
        }
    }

    let mut scored: Vec<(f64, usize, usize, &str)> = Vec::new();
    for path in candidate_order {
        if protected_set.contains(path) {
            continue;
        }
        let vector_rank = vector_ranks.get(path).copied();
        let coedit_rank = coedit_ranks.get(path).copied();
        if vector_rank.is_none() && lambda == 0.0 {
            continue;
        }
        let mut score = 0.0;
        if let Some(rank) = vector_rank {
            score += 1.0 / (k_value + rank as f64);
        }
        if let Some(rank) = coedit_rank
            && lambda != 0.0
        {
            score += lambda * (1.0 / (k_value + rank as f64));
        }
        scored.push((
            -score,
            vector_rank.unwrap_or(UNRANKED),
            coedit_rank.unwrap_or(UNRANKED),
            path,
        ));
    }
    scored.sort_by(|left, right| {
        left.0
            .partial_cmp(&right.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.2.cmp(&right.2))
            .then_with(|| left.3.cmp(right.3))
    });

    protected
        .into_iter()
        .chain(scored.into_iter().map(|(_, _, _, path)| path.to_string()))
        .collect()
}

/// Grounded-strings BM25: reduce the query to repo-grounded words + quoted
/// spans, then MATCH the FTS index.
fn bm25_candidates(
    analyzer: &dyn IAnalyzer,
    store: &super::store::SemanticStore,
    workspace_id: i64,
    query: &str,
    limit: usize,
) -> Result<Vec<String>, String> {
    let paths: Vec<String> = analyzer.analyzed_files().map(rel_path_string).collect();
    let symbols: Vec<String> = analyzer
        .all_declarations()
        .map(|unit| unit.fq_name())
        .collect();
    let universe = RepoEntityUniverse::new(
        paths.iter().map(String::as_str),
        symbols.iter().map(String::as_str),
    );
    let grounded = grounded_prompt_text(query, &universe);
    let tokens = tokenize(&grounded);
    let Some(match_query) = build_match_query(&tokens) else {
        return Ok(Vec::new());
    };
    let scored = store
        .bm25_file_scores(workspace_id, &match_query, limit)
        .map_err(|err| err.to_string())?;
    Ok(scored.into_iter().map(|(path, _)| path).collect())
}

/// Chunk texts fed to the cross-encoder for one file: the first
/// `FILE_CHUNK_CAP` function chunks in source order, plus the file-summary
/// chunk (ce_harness.py `choose_chunks_for_file`).
fn rerank_chunk_texts(chunks: &FileChunks) -> Vec<&str> {
    let mut selected: Vec<&str> = chunks
        .chunks
        .iter()
        .filter(|chunk| chunk.kind == ChunkKind::Function)
        .take(FILE_CHUNK_CAP)
        .map(|chunk| chunk.text.as_str())
        .collect();
    if let Some(summary) = chunks
        .chunks
        .iter()
        .find(|chunk| chunk.kind == ChunkKind::FileSummary)
    {
        selected.push(summary.text.as_str());
    }
    if selected.is_empty() {
        // Files with no usable chunks still get their path scored.
        selected.push("");
    }
    selected
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| v.to_string()).collect()
    }

    #[test]
    fn rrf_blend_protects_top_vector_files() {
        let vector = paths(&["a", "b", "c", "d"]);
        let coedit = paths(&["d", "c"]);
        let blended = rrf_blend(&vector, &coedit, 2, 30.0, 0.3);
        assert_eq!(blended[0], "a");
        assert_eq!(blended[1], "b");
        // d gets the stronger coedit boost (rank 1 vs c's rank 2) but c's
        // vector rank (3 vs 4) still dominates at lambda 0.3.
        assert_eq!(blended[2..], ["c".to_string(), "d".to_string()]);
    }

    #[test]
    fn rrf_blend_boost_reorders_close_vector_ranks() {
        // Long tail: vector ranks 29 and 30 are nearly tied, so a top coedit
        // rank flips the order.
        let vector: Vec<String> = (0..30).map(|i| format!("f{i}")).collect();
        let coedit = paths(&["f29"]);
        let blended = rrf_blend(&vector, &coedit, 2, 30.0, 0.3);
        let pos28 = blended.iter().position(|p| p == "f28").unwrap();
        let pos29 = blended.iter().position(|p| p == "f29").unwrap();
        assert!(
            pos29 < pos28,
            "coedit-boosted f29 must outrank f28: {blended:?}"
        );
    }

    #[test]
    fn rrf_blend_admits_coedit_only_candidates() {
        let vector = paths(&["a", "b"]);
        let coedit = paths(&["z"]);
        let blended = rrf_blend(&vector, &coedit, 2, 30.0, 0.3);
        assert!(blended.contains(&"z".to_string()));
        // With lambda = 0 the coedit-only candidate must vanish (baseline
        // parity with the prototype).
        let baseline = rrf_blend(&vector, &coedit, 2, 30.0, 0.0);
        assert!(!baseline.contains(&"z".to_string()));
    }

    #[test]
    fn rrf_blend_ranks_missing_coedit_below_boosted_peer() {
        // Identical vector tail ranks: the one with a coedit rank wins.
        let vector = paths(&["a", "b", "x", "y"]);
        let coedit = paths(&["y"]);
        let blended = rrf_blend(&vector, &coedit, 2, 30.0, 0.3);
        let pos_x = blended.iter().position(|p| p == "x").unwrap();
        let pos_y = blended.iter().position(|p| p == "y").unwrap();
        assert!(pos_y < pos_x);
    }
}
