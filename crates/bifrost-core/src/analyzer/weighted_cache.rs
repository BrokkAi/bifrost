//! Language-neutral construction and weighing of the analyzers' bounded memo
//! caches. Every language adapter sizes its caches from a byte budget, so the
//! builder and the weighers for the common value shapes live here rather than
//! in any one language module.
//!
//! In core rather than in `brokk-bifrost-analysis` because the language crates
//! size their own caches too: the builder is generic over `moka` and the
//! weighers name only `CodeUnit` and `ProjectFile`, so nothing here needs an
//! `IAnalyzer`, a store, a grammar or a language module.

use crate::analyzer::{CodeUnit, ProjectFile};
use crate::hash::HashSet;
use moka::sync::Cache;
use std::mem::size_of;
use std::sync::Arc;

pub fn build_weighted_cache<K, V>(
    budget_bytes: u64,
    weigher: impl Fn(&K, &V) -> u32 + Send + Sync + 'static,
) -> Cache<K, V>
where
    K: Clone + Eq + std::hash::Hash + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    Cache::builder()
        .max_capacity(budget_bytes.max(1))
        .weigher(weigher)
        .build()
}

pub fn weight_project_file_set(_key: &ProjectFile, value: &Arc<HashSet<ProjectFile>>) -> u32 {
    let size = value
        .iter()
        .map(|item| item.rel_path().to_string_lossy().len() + size_of::<ProjectFile>())
        .sum::<usize>()
        + size_of::<HashSet<ProjectFile>>();
    size.min(u32::MAX as usize) as u32
}

pub fn weight_code_unit_set(_key: &ProjectFile, value: &Arc<HashSet<CodeUnit>>) -> u32 {
    let size = value
        .iter()
        .map(|item| item.fq_name().len() + size_of::<CodeUnit>())
        .sum::<usize>()
        + size_of::<HashSet<CodeUnit>>();
    size.min(u32::MAX as usize) as u32
}

pub fn weight_code_unit_vec_by_unit(_key: &CodeUnit, value: &Arc<Vec<CodeUnit>>) -> u32 {
    weight_bytes(size_of::<Vec<CodeUnit>>() + value.iter().map(estimate_code_unit).sum::<usize>())
}

fn estimate_code_unit(code_unit: &CodeUnit) -> usize {
    size_of::<CodeUnit>()
        + code_unit.fq_name().len()
        + code_unit.signature().map_or(0, str::len)
        + code_unit.source().rel_path().to_string_lossy().len()
}

fn weight_bytes(bytes: usize) -> u32 {
    bytes.clamp(1, u32::MAX as usize) as u32
}
