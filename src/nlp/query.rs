//! The semantic_search query pipeline.
//!
//! Returns three independent retrieval signals over function chunks, leaving any
//! reranking to the caller: an exhaustive vector scan (cosine per fqfn), a
//! grounded-strings BM25 ranking (per fqfn), and git co-edit relevance (per file)
//! seeded from the union of the top vector + BM25 files. The file-summary chunk is
//! not searched directly; it survives only as parent context averaged into the
//! function-chunk vectors. Constants come from the prototype's dev sweeps
//! (see `nlp/mod.rs`).

use std::collections::HashMap;

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::analyzer::{IAnalyzer, WorkspaceAnalyzer};
use crate::path_utils::rel_path_string;
use crate::searchtools::{MostRelevantFilesParams, most_relevant_files};

use super::active_index::ActiveIndex;
use super::bm25::{RepoEntityUniverse, build_match_query, grounded_prompt_text, tokenize};
use std::time::Duration;

use super::indexer::{READY_TIMEOUT_MESSAGE, SemanticIndexer};
use super::{COEDIT_HALF_LIFE, RRF_K};

/// Rows decoded per scan batch.
const SCAN_BATCH: usize = 8192;
const MAX_K: usize = 100;
const SEMANTIC_SEARCH_READY_TIMEOUT: Duration = Duration::from_secs(1);
/// Floor for normalized co-edit seed weights; `most_relevant_files` rejects
/// non-positive weights, and the lowest min-max normalized score is zero.
const MIN_SEED_WEIGHT: f64 = 0.01;

#[derive(Debug, Clone, Deserialize)]
pub struct SemanticSearchParams {
    pub query: String,
    #[serde(default = "default_k")]
    pub k: usize,
}

fn default_k() -> usize {
    10
}

/// A function chunk ranked by one retrieval leg, keyed by fully-qualified name.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RankedSymbol {
    pub fqfn: String,
    pub score: f32,
}

/// A file ranked by git co-edit relevance.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RankedFile {
    pub path: String,
    pub score: f32,
}

/// The constituent retrieval signals for a query. Each leg is independent and
/// capped at `k`; fusing/reranking them is the caller's job.
#[derive(Debug, Clone, Serialize)]
pub struct SemanticSearchResult {
    pub vector_ranked: Vec<RankedSymbol>,
    pub bm25_ranked: Vec<RankedSymbol>,
    pub coedit_ranked: Vec<RankedFile>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub notes: Vec<String>,
}

impl SemanticSearchResult {
    fn empty(notes: Vec<String>) -> Self {
        Self {
            vector_ranked: Vec::new(),
            bm25_ranked: Vec::new(),
            coedit_ranked: Vec::new(),
            notes,
        }
    }
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

    let mut notes = Vec::new();
    let timed_out = match indexer.wait_ready(SEMANTIC_SEARCH_READY_TIMEOUT) {
        Ok(()) => false,
        Err(err) if err == READY_TIMEOUT_MESSAGE => {
            notes.push(
                "semantic index is still building; returning currently indexed results".to_string(),
            );
            true
        }
        Err(err) => return Err(err),
    };
    let Some(store) = indexer.store() else {
        if timed_out {
            notes.push("semantic index store is not loaded yet".to_string());
            return Ok(SemanticSearchResult::empty(notes));
        }
        return Err("semantic index store unavailable".to_string());
    };
    let Some(embedder) = indexer.embedder() else {
        if timed_out {
            notes.push("embedding model is not loaded yet".to_string());
            return Ok(SemanticSearchResult::empty(notes));
        }
        return Err("embedding model unavailable".to_string());
    };
    let active_lock = indexer.active_index();
    let active_guard = active_lock
        .read()
        .map_err(|_| "semantic active index lock poisoned".to_string())?;
    let Some(active) = active_guard.as_ref() else {
        if timed_out {
            notes.push("semantic active index is not built yet".to_string());
            return Ok(SemanticSearchResult::empty(notes));
        }
        return Err("semantic active index unavailable".to_string());
    };
    let analyzer = workspace.analyzer();

    // 1. Exhaustive vector scan over the active set. The store streams batches
    //    (producer); cosine is scored in parallel (consumers); each composed
    //    vector is then resolved to its function occurrences (fqfn + file).
    //    Summary chunks have no fqfn and are dropped by `resolve`.
    let query_vector = embedder.embed_query(query)?;
    let scorer = super::quant::query_scorer(&query_vector);
    let mut hash_scores: Vec<([u8; 32], f32)> = Vec::new();
    store
        .scan_active_vectors(SCAN_BATCH, &mut |batch| {
            let scored: Vec<([u8; 32], f32)> = batch
                .par_iter()
                .filter_map(|row| {
                    scorer
                        .score(&row.code)
                        .ok()
                        .map(|score| (row.composed_hash, score))
                })
                .collect();
            hash_scores.extend(scored);
        })
        .map_err(|err| err.to_string())?;
    let mut vector_by_symbol: HashMap<String, f32> = HashMap::new();
    let mut symbol_file: HashMap<String, String> = HashMap::new();
    for (hash, score) in &hash_scores {
        for hit in active.resolve(hash) {
            symbol_file
                .entry(hit.fqfn.to_string())
                .or_insert_with(|| hit.path.to_string());
            vector_by_symbol
                .entry(hit.fqfn.to_string())
                .and_modify(|best| *best = best.max(*score))
                .or_insert(*score);
        }
    }
    let vector_ranked = top_ranked_symbols(&vector_by_symbol, k);

    // 2. Grounded-strings BM25 over the in-memory active corpus.
    let bm25_scores = bm25_symbol_candidates(analyzer, active, query, k).unwrap_or_else(|err| {
        notes.push(format!("bm25 retrieval skipped: {err}"));
        Vec::new()
    });
    let bm25_ranked: Vec<RankedSymbol> = bm25_scores
        .iter()
        .map(|(fqfn, score)| RankedSymbol {
            fqfn: fqfn.clone(),
            score: *score as f32,
        })
        .collect();

    // 3. Co-edit relevance, seeded by the union of the top vector + BM25 files.
    //    Seeds carry their own-leg normalized weight (summed when a file is in both
    //    legs), which sidesteps the cosine-vs-BM25 scale mismatch.
    let vector_files = aggregate_symbols_to_files(
        vector_by_symbol
            .iter()
            .map(|(sym, score)| (sym.as_str(), *score)),
        &symbol_file,
    );
    let bm25_files = aggregate_symbols_to_files(
        bm25_scores
            .iter()
            .map(|(sym, score)| (sym.as_str(), *score as f32)),
        &symbol_file,
    );
    let (seed_paths, seed_weights) = build_seeds(&vector_files, &bm25_files, k);
    let coedit_ranked = if seed_paths.is_empty() {
        Vec::new()
    } else {
        match most_relevant_files(
            analyzer,
            MostRelevantFilesParams {
                seed_file_paths: seed_paths,
                seed_weights: Some(seed_weights),
                recency_half_life: Some(COEDIT_HALF_LIFE),
                limit: k,
            },
        ) {
            Ok(result) => result
                .files
                .into_iter()
                .enumerate()
                .map(|(rank, path)| RankedFile {
                    path,
                    score: 1.0 / (RRF_K as f32 + rank as f32),
                })
                .collect(),
            Err(err) => {
                notes.push(format!("co-edit relevance skipped: {err}"));
                Vec::new()
            }
        }
    };

    Ok(SemanticSearchResult {
        vector_ranked,
        bm25_ranked,
        coedit_ranked,
        notes,
    })
}

/// Top-`k` symbols by score (desc), tie-broken by fqfn for determinism.
fn top_ranked_symbols(scores: &HashMap<String, f32>, k: usize) -> Vec<RankedSymbol> {
    let mut ranked: Vec<RankedSymbol> = scores
        .iter()
        .map(|(fqfn, score)| RankedSymbol {
            fqfn: fqfn.clone(),
            score: *score,
        })
        .collect();
    ranked.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.fqfn.cmp(&b.fqfn))
    });
    ranked.truncate(k);
    ranked
}

/// Roll per-symbol scores up to their files, keeping the max chunk score per file.
fn aggregate_symbols_to_files<'a>(
    scored: impl Iterator<Item = (&'a str, f32)>,
    symbol_file: &HashMap<String, String>,
) -> HashMap<String, f32> {
    let mut files: HashMap<String, f32> = HashMap::new();
    for (symbol, score) in scored {
        if let Some(file) = symbol_file.get(symbol) {
            files
                .entry(file.clone())
                .and_modify(|best| *best = best.max(score))
                .or_insert(score);
        }
    }
    files
}

/// Co-edit seed set: the union of the top-`m` files from each leg, each weighted by
/// its own-leg min-max normalized score (floored so weights stay positive). A file
/// present in both legs accumulates both weights.
fn build_seeds(
    vector_files: &HashMap<String, f32>,
    bm25_files: &HashMap<String, f32>,
    m: usize,
) -> (Vec<String>, Vec<f64>) {
    let mut weights: HashMap<String, f64> = HashMap::new();
    for leg in [vector_files, bm25_files] {
        for (path, weight) in normalized_top(leg, m) {
            *weights.entry(path).or_insert(0.0) += weight;
        }
    }
    let mut seeds: Vec<(String, f64)> = weights.into_iter().collect();
    seeds.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    seeds.into_iter().unzip()
}

/// Top-`m` files by score, min-max normalized within the selection to
/// `[MIN_SEED_WEIGHT, 1.0]`. A single-element (or all-equal) leg yields weight 1.0.
fn normalized_top(files: &HashMap<String, f32>, m: usize) -> Vec<(String, f64)> {
    let mut ranked: Vec<(String, f32)> = files
        .iter()
        .map(|(path, score)| (path.clone(), *score))
        .collect();
    ranked.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    ranked.truncate(m);
    if ranked.is_empty() {
        return Vec::new();
    }
    let max = ranked.first().map(|(_, s)| *s as f64).unwrap_or(0.0);
    let min = ranked.last().map(|(_, s)| *s as f64).unwrap_or(0.0);
    let span = max - min;
    ranked
        .into_iter()
        .map(|(path, score)| {
            let weight = if span > f64::EPSILON {
                MIN_SEED_WEIGHT + (1.0 - MIN_SEED_WEIGHT) * (score as f64 - min) / span
            } else {
                1.0
            };
            (path, weight)
        })
        .collect()
}

/// Grounded-strings BM25: reduce the query to repo-grounded words + quoted spans,
/// then MATCH the FTS index, returning per-fqfn scores.
fn bm25_symbol_candidates(
    analyzer: &dyn IAnalyzer,
    active: &ActiveIndex,
    query: &str,
    limit: usize,
) -> Result<Vec<(String, f64)>, String> {
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
    active.bm25_symbol_scores(&match_query, limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(pairs: &[(&str, f32)]) -> HashMap<String, f32> {
        pairs.iter().map(|(p, s)| (p.to_string(), *s)).collect()
    }

    #[test]
    fn normalized_top_caps_and_floors_weights() {
        let leg = files(&[("a", 0.9), ("b", 0.5), ("c", 0.1), ("d", 0.05)]);
        let top = normalized_top(&leg, 3);
        assert_eq!(top.len(), 3);
        assert_eq!(top[0].0, "a");
        assert!((top[0].1 - 1.0).abs() < 1e-9);
        // The lowest of the selected files gets the epsilon floor, never zero,
        // so `most_relevant_files`' positive-weight validation passes.
        assert!((top[2].1 - MIN_SEED_WEIGHT).abs() < 1e-9);
        assert!(top.iter().all(|(_, w)| *w >= MIN_SEED_WEIGHT));
    }

    #[test]
    fn normalized_top_single_element_is_full_weight() {
        let leg = files(&[("only", 0.42)]);
        let top = normalized_top(&leg, 5);
        assert_eq!(top, vec![("only".to_string(), 1.0)]);
    }

    #[test]
    fn build_seeds_unions_legs_and_adds_shared_weight() {
        let vector = files(&[("shared", 0.9), ("v_only", 0.4)]);
        let bm25 = files(&[("shared", 8.0), ("b_only", 2.0)]);
        let (paths, weights) = build_seeds(&vector, &bm25, 5);
        // Union of both legs, deduplicated.
        assert_eq!(paths.len(), 3);
        // `shared` tops both legs (weight 1.0 each), so its summed weight (~2.0)
        // sorts it first ahead of the leg-only files.
        assert_eq!(paths[0], "shared");
        assert!((weights[0] - 2.0).abs() < 1e-9);
        assert!(weights.iter().all(|w| *w > 0.0));
    }

    #[test]
    fn top_ranked_symbols_orders_and_truncates() {
        let scores = files(&[("a.foo", 0.2), ("a.bar", 0.9), ("a.baz", 0.5)]);
        let ranked = top_ranked_symbols(&scores, 2);
        assert_eq!(ranked.len(), 2);
        assert_eq!(ranked[0].fqfn, "a.bar");
        assert_eq!(ranked[1].fqfn, "a.baz");
    }

    #[test]
    fn aggregate_symbols_to_files_keeps_max_per_file() {
        let symbol_file: HashMap<String, String> =
            [("a.foo", "a.rs"), ("a.bar", "a.rs"), ("b.qux", "b.rs")]
                .iter()
                .map(|(s, f)| (s.to_string(), f.to_string()))
                .collect();
        let scored = [("a.foo", 0.3f32), ("a.bar", 0.8), ("b.qux", 0.5)];
        let files =
            aggregate_symbols_to_files(scored.iter().map(|(s, sc)| (*s, *sc)), &symbol_file);
        assert_eq!(files.get("a.rs"), Some(&0.8));
        assert_eq!(files.get("b.rs"), Some(&0.5));
    }
}
