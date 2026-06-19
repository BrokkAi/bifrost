use crate::analyzer::{CodeUnit, ProjectFile};
use crate::hash::HashSet;
use moka::sync::Cache;
use std::mem::size_of;
use std::sync::Arc;

pub(crate) fn build_weighted_cache<K, V>(
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

pub(crate) fn weight_string_set(_key: &CodeUnit, value: &Arc<HashSet<String>>) -> u32 {
    let size = value
        .iter()
        .map(|item| item.len() + size_of::<String>())
        .sum::<usize>()
        + size_of::<HashSet<String>>();
    size.min(u32::MAX as usize) as u32
}

pub(crate) fn weight_project_file_set(
    _key: &ProjectFile,
    value: &Arc<HashSet<ProjectFile>>,
) -> u32 {
    let size = value
        .iter()
        .map(|item| item.rel_path().to_string_lossy().len() + size_of::<ProjectFile>())
        .sum::<usize>()
        + size_of::<HashSet<ProjectFile>>();
    size.min(u32::MAX as usize) as u32
}

pub(crate) fn weight_code_unit_set(_key: &ProjectFile, value: &Arc<HashSet<CodeUnit>>) -> u32 {
    let size = value
        .iter()
        .map(|item| item.fq_name().len() + size_of::<CodeUnit>())
        .sum::<usize>()
        + size_of::<HashSet<CodeUnit>>();
    size.min(u32::MAX as usize) as u32
}

pub(crate) fn weight_code_unit_vec_by_unit(_key: &CodeUnit, value: &Arc<Vec<CodeUnit>>) -> u32 {
    weight_bytes(size_of::<Vec<CodeUnit>>() + value.iter().map(estimate_code_unit).sum::<usize>())
}

pub(crate) fn weight_code_unit_set_by_unit(_key: &CodeUnit, value: &Arc<HashSet<CodeUnit>>) -> u32 {
    weight_bytes(
        size_of::<HashSet<CodeUnit>>() + value.iter().map(estimate_code_unit).sum::<usize>(),
    )
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
