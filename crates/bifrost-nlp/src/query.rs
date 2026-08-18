//! The semantic_search query pipeline.
//!
//! Retrieval is dense only. A query is embedded once, scored against the stored
//! quantized vectors, and the best candidates are resolved to live function
//! occurrences one at a time (see `super::retrieval`). Two independent signals
//! come back -- ranked symbols from the dense arm and files ranked by the
//! co-edit cascade -- and reranking stays with the caller. Symbol scores are
//! min-max normalized within the returned window so a caller does not have to
//! know the raw cosine scale.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use brokk_bifrost_analysis::analyzer::WorkspaceAnalyzer;
use brokk_bifrost_analysis::searchtools::{MostRelevantFilesParams, most_relevant_files};
use brokk_bifrost_analysis::searchtools_render::{RenderOptions, RenderText};

use super::indexer::{DEFAULT_READY_TIMEOUT, READY_TIMEOUT_MESSAGE, SemanticIndexer};
use super::{COEDIT_HALF_LIFE, RRF_K};

const MAX_K: usize = 100;
/// Depth of the dense arm relative to the requested `k`. The CodeScaleBench
/// arm sweep (`.agents/plans/bifrost-localizer-cim-eval.md`, "Results") ran
/// vector/BM25/co-edit budgets of b/b/b, 3b/0/0, and 2b/0/b at a constant
/// nominal pool of 3b. The 2b dense plus b co-edit arm scored best (54.9%
/// resolve) and the lexical arm worst of the three (53.8%), so the winning
/// depths are now the only behavior and the total pool is unchanged.
const VECTOR_LEG_DEPTH: usize = 2;
/// Candidate vectors scored per returned symbol. The candidate stream comes
/// straight from the persistent store and may include chunks of blobs this
/// worktree no longer has, so the walk over-retrieves and skips. A warmed exact
/// checkout has a near-zero dead fraction; the factor only has to cover a cache
/// that has drifted between garbage collections, plus the several chunk vectors
/// a single symbol can legitimately own.
const CANDIDATE_OVER_RETRIEVE: usize = 8;
/// Once a live set exists, keep interactive queries responsive while a newer
/// snapshot is building by falling back to that live set promptly.
const SEMANTIC_SEARCH_STALE_TIMEOUT: Duration = Duration::from_secs(1);
/// Floor for min-max normalized retrieval scores. Co-edit seed weights must be
/// positive for `most_relevant_files`, and callers should not see a selected
/// result collapse to zero.
const MIN_NORMALIZED_SCORE: f64 = 0.01;

#[derive(Debug, Clone, Deserialize)]
pub struct SemanticSearchParams {
    pub query: String,
    #[serde(default = "default_k")]
    pub k: usize,
}

fn default_k() -> usize {
    10
}

/// A function chunk ranked by the dense arm, keyed by fully-qualified name.
/// `score` is min-max normalized within this leg's returned top-k window.
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

/// The constituent retrieval signals for a query. Each leg is independent;
/// fusing/reranking them is the caller's job.
#[derive(Debug, Clone, Serialize)]
pub struct SemanticSearchResult {
    pub vector_ranked: Vec<RankedSymbol>,
    pub coedit_ranked: Vec<RankedFile>,
    pub requested_leg_counts: RetrievalLegCounts,
    pub timings: SemanticSearchTimings,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct RetrievalLegCounts {
    pub vector: usize,
    pub coedit: usize,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct SemanticSearchTimings {
    pub wait_ready_ms: f64,
    pub embedding_queue_ms: f64,
    pub embedding_service_ms: f64,
    pub total_ms: f64,
}

impl SemanticSearchResult {
    fn empty(
        notes: Vec<String>,
        requested_leg_counts: RetrievalLegCounts,
        wait_ready_ms: f64,
        started: Instant,
    ) -> Self {
        Self {
            vector_ranked: Vec::new(),
            coedit_ranked: Vec::new(),
            requested_leg_counts,
            timings: SemanticSearchTimings {
                wait_ready_ms,
                embedding_queue_ms: 0.0,
                embedding_service_ms: 0.0,
                total_ms: started.elapsed().as_secs_f64() * 1_000.0,
            },
            notes,
        }
    }
}

// The `RenderText` trait belongs to brokk-bifrost-analysis and this type belongs
// here, so the orphan rule leaves this crate as the only place the impl can
// live. It sits next to the type it renders rather than next to the trait.
impl RenderText for SemanticSearchResult {
    fn render_text(&self, _options: RenderOptions) -> String {
        let mut blocks: Vec<String> = Vec::new();
        if !self.notes.is_empty() {
            blocks.push(
                self.notes
                    .iter()
                    .map(|note| format!("note: {note}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
            );
        }

        let mut any_results = false;
        if !self.vector_ranked.is_empty() {
            any_results = true;
            let mut block = "=== vector ===".to_string();
            for row in &self.vector_ranked {
                block.push_str(&format!("\n{} (score {:.3})", row.fqfn, row.score));
            }
            blocks.push(block);
        }
        if !self.coedit_ranked.is_empty() {
            any_results = true;
            let mut block = "=== co-edit ===".to_string();
            for row in &self.coedit_ranked {
                block.push_str(&format!("\n{} (score {:.3})", row.path, row.score));
            }
            blocks.push(block);
        }

        if !any_results {
            blocks.push("No semantically similar code found.".to_string());
        }
        blocks.join("\n\n")
    }
}

pub fn semantic_search(
    workspace: &WorkspaceAnalyzer,
    indexer: &SemanticIndexer,
    params: SemanticSearchParams,
) -> Result<SemanticSearchResult, String> {
    let started = Instant::now();
    let query = params.query.trim();
    if query.is_empty() {
        return Err("query must not be empty".to_string());
    }
    let k = params.k.clamp(1, MAX_K);
    let vector_limit = VECTOR_LEG_DEPTH * k;
    let requested_leg_counts = RetrievalLegCounts {
        vector: vector_limit,
        coedit: k,
    };

    let has_live_set = indexer
        .live_set()
        .read()
        .map_err(|_| "semantic live set lock poisoned".to_string())?
        .is_some();
    let ready_timeout = if has_live_set {
        SEMANTIC_SEARCH_STALE_TIMEOUT
    } else {
        DEFAULT_READY_TIMEOUT
    };

    let mut notes = Vec::new();
    let wait_started = Instant::now();
    let timed_out = match indexer.wait_ready(ready_timeout) {
        Ok(()) => false,
        Err(err) if err == READY_TIMEOUT_MESSAGE => {
            notes.push(
                "semantic index is still building; returning currently indexed results".to_string(),
            );
            true
        }
        Err(err) => return Err(err),
    };
    let wait_ready_ms = wait_started.elapsed().as_secs_f64() * 1_000.0;
    let Some(embedder) = indexer.embedder() else {
        if timed_out {
            notes.push("embedding model is not loaded yet".to_string());
            return Ok(SemanticSearchResult::empty(
                notes,
                requested_leg_counts,
                wait_ready_ms,
                started,
            ));
        }
        return Err("embedding model unavailable".to_string());
    };
    let live_lock = indexer.live_set();
    let live_guard = live_lock
        .read()
        .map_err(|_| "semantic live set lock poisoned".to_string())?;
    let Some(live) = live_guard.as_ref() else {
        if timed_out {
            notes.push("semantic live set is not built yet".to_string());
            return Ok(SemanticSearchResult::empty(
                notes,
                requested_leg_counts,
                wait_ready_ms,
                started,
            ));
        }
        return Err("semantic live set unavailable".to_string());
    };

    // 1. Dense arm. Score every stored vector against the query, keep a bounded
    //    candidate pool, then resolve candidates in descending score to live
    //    function occurrences. Candidates whose chunks all belong to blobs this
    //    worktree no longer has resolve to nothing and are simply skipped.
    let (query_vector, embedding_timing) = embedder.embed_query_timed(query)?;
    let scorer = super::quant::query_scorer(&query_vector);
    let pool = CANDIDATE_OVER_RETRIEVE * vector_limit;
    let candidates = live.top_candidates(&scorer, pool)?;
    let mut vector_by_symbol: HashMap<String, f32> = HashMap::new();
    let mut symbol_file: HashMap<String, String> = HashMap::new();
    let mut leg_filled = false;
    for (hash, score) in &candidates {
        // Candidates arrive in descending score and a symbol scores as its best
        // chunk, so the leg is complete as soon as it is full.
        if vector_by_symbol.len() >= vector_limit {
            leg_filled = true;
            break;
        }
        for hit in live.resolve_live(hash)? {
            symbol_file.entry(hit.fqfn.clone()).or_insert(hit.path);
            vector_by_symbol
                .entry(hit.fqfn)
                .and_modify(|best| *best = best.max(*score))
                .or_insert(*score);
        }
    }
    // A short candidate list just means the store holds fewer vectors than the
    // pool. A full list that still did not fill the leg means dead blobs (or
    // one symbol owning many vectors) consumed the whole over-retrieve budget.
    if !leg_filled && candidates.len() == pool {
        notes.push(format!(
            "dense candidate pool of {pool} was consumed before {vector_limit} live symbols were found"
        ));
    }
    let mut vector_ranked = top_ranked_symbols(&vector_by_symbol, vector_limit);
    normalize_ranked_symbol_scores(&mut vector_ranked);

    // 2. Co-edit relevance, seeded by the top dense files. Seeds carry their
    //    normalized dense weight so `most_relevant_files` sees positive weights.
    let vector_files = aggregate_symbols_to_files(
        vector_by_symbol
            .iter()
            .map(|(sym, score)| (sym.as_str(), *score)),
        &symbol_file,
    );
    let (seed_paths, seed_weights) = build_seeds(&vector_files, k);
    let coedit_ranked = if seed_paths.is_empty() {
        Vec::new()
    } else {
        match most_relevant_files(
            workspace.analyzer(),
            MostRelevantFilesParams {
                seed_file_paths: seed_paths,
                seed_weights: Some(seed_weights),
                recency_half_life: Some(COEDIT_HALF_LIFE),
                // The cascade, which is the default. This leg used to be the
                // git history ranking alone, because the alternative was the
                // two-level import graph and that can expand for minutes in a
                // large Java workspace. The cascade reads import adjacency one
                // level deep instead, and it answers in the repositories where
                // the history leg returns nothing at all.
                ranking_mode: Default::default(),
                limit: k,
            },
        ) {
            Ok(result) => result
                .files
                .into_iter()
                .enumerate()
                .map(|(rank, file)| RankedFile {
                    path: file.path,
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
        coedit_ranked,
        requested_leg_counts,
        timings: SemanticSearchTimings {
            wait_ready_ms,
            embedding_queue_ms: embedding_timing.queue_wait.as_secs_f64() * 1_000.0,
            embedding_service_ms: embedding_timing.service.as_secs_f64() * 1_000.0,
            total_ms: started.elapsed().as_secs_f64() * 1_000.0,
        },
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

/// Normalize an already-ranked symbol leg to `[MIN_NORMALIZED_SCORE, 1.0]`.
/// Single-element and all-equal legs are maximally informative by rank alone.
fn normalize_ranked_symbol_scores(ranked: &mut [RankedSymbol]) {
    if ranked.is_empty() {
        return;
    }
    let max = ranked
        .iter()
        .map(|row| row.score as f64)
        .fold(f64::NEG_INFINITY, f64::max);
    let min = ranked
        .iter()
        .map(|row| row.score as f64)
        .fold(f64::INFINITY, f64::min);
    let span = max - min;
    for row in ranked {
        row.score = if span > f64::EPSILON {
            (MIN_NORMALIZED_SCORE + (1.0 - MIN_NORMALIZED_SCORE) * (row.score as f64 - min) / span)
                as f32
        } else {
            1.0
        };
    }
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

/// Co-edit seed set: the top-`m` dense files, each weighted by its min-max
/// normalized score (floored so weights stay positive).
fn build_seeds(vector_files: &HashMap<String, f32>, m: usize) -> (Vec<String>, Vec<f64>) {
    let mut seeds = normalized_top(vector_files, m);
    seeds.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    seeds.into_iter().unzip()
}

/// Top-`m` files by score, min-max normalized within the selection to
/// `[MIN_NORMALIZED_SCORE, 1.0]`. A single-element (or all-equal) leg yields weight 1.0.
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
                MIN_NORMALIZED_SCORE + (1.0 - MIN_NORMALIZED_SCORE) * (score as f64 - min) / span
            } else {
                1.0
            };
            (path, weight)
        })
        .collect()
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
        assert!((top[2].1 - MIN_NORMALIZED_SCORE).abs() < 1e-9);
        assert!(top.iter().all(|(_, w)| *w >= MIN_NORMALIZED_SCORE));
    }

    #[test]
    fn normalized_top_single_element_is_full_weight() {
        let leg = files(&[("only", 0.42)]);
        let top = normalized_top(&leg, 5);
        assert_eq!(top, vec![("only".to_string(), 1.0)]);
    }

    #[test]
    fn build_seeds_ranks_the_dense_files_by_weight() {
        let vector = files(&[("top.rs", 0.9), ("middle.rs", 0.5), ("low.rs", 0.1)]);
        let (paths, weights) = build_seeds(&vector, 5);
        assert_eq!(paths, vec!["top.rs", "middle.rs", "low.rs"]);
        assert!((weights[0] - 1.0).abs() < 1e-9);
        assert!(weights.iter().all(|w| *w > 0.0));
        assert!(weights.windows(2).all(|pair| pair[0] >= pair[1]));
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
    fn normalize_ranked_symbol_scores_maps_leg_to_common_scale() {
        let mut ranked = vec![
            RankedSymbol {
                fqfn: "dense.top".to_string(),
                score: 30.0,
            },
            RankedSymbol {
                fqfn: "dense.middle".to_string(),
                score: 10.0,
            },
            RankedSymbol {
                fqfn: "dense.bottom".to_string(),
                score: 5.0,
            },
        ];
        normalize_ranked_symbol_scores(&mut ranked);

        assert_eq!(ranked[0].fqfn, "dense.top");
        assert!((ranked[0].score - 1.0).abs() < 1e-6);
        assert!((ranked[2].score as f64 - MIN_NORMALIZED_SCORE).abs() < 1e-6);
        assert!(ranked.windows(2).all(|pair| pair[0].score >= pair[1].score));
        assert!(
            ranked
                .iter()
                .all(|row| row.score >= MIN_NORMALIZED_SCORE as f32 && row.score <= 1.0)
        );
    }

    #[test]
    fn normalize_ranked_symbol_scores_all_equal_scores_are_full_weight() {
        let mut ranked = vec![
            RankedSymbol {
                fqfn: "a.one".to_string(),
                score: 0.42,
            },
            RankedSymbol {
                fqfn: "a.two".to_string(),
                score: 0.42,
            },
        ];
        normalize_ranked_symbol_scores(&mut ranked);

        assert!(ranked.iter().all(|row| row.score == 1.0));
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

    #[test]
    fn empty_result_serializes_leg_budgets_and_timings() {
        let result = SemanticSearchResult::empty(
            vec!["building".to_string()],
            RetrievalLegCounts {
                vector: 120,
                coedit: 40,
            },
            12.5,
            Instant::now(),
        );

        let value = serde_json::to_value(result).unwrap();
        assert_eq!(value["requested_leg_counts"]["vector"], 120);
        assert_eq!(value["requested_leg_counts"]["coedit"], 40);
        assert!(value.get("bm25_ranked").is_none());
        assert_eq!(value["timings"]["wait_ready_ms"], 12.5);
        assert_eq!(value["timings"]["embedding_queue_ms"], 0.0);
        assert!(value["timings"]["total_ms"].as_f64().unwrap() >= 0.0);
    }
}
