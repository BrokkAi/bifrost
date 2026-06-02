use crate::analyzer::{CodeUnit, ProjectFile};
use crate::hash::{HashMap, HashSet};
use moka::sync::Cache;
use std::mem::size_of;
use std::sync::{Arc, OnceLock};

use crate::analyzer::js_ts::build_weighted_cache;

pub(super) struct CSharpMemoCaches {
    budget_bytes: u64,
    pub(super) using_namespaces: Cache<ProjectFile, Arc<Vec<String>>>,
    pub(super) imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    pub(super) referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    pub(super) direct_ancestors: Cache<CodeUnit, Arc<Vec<CodeUnit>>>,
    pub(super) direct_descendants: Cache<CodeUnit, Arc<HashSet<CodeUnit>>>,
    pub(super) reverse_import_index: OnceLock<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>,
    pub(super) global_using_namespaces: OnceLock<HashSet<String>>,
}

impl CSharpMemoCaches {
    pub(super) fn new(budget_bytes: u64) -> Self {
        Self {
            budget_bytes,
            using_namespaces: build_weighted_cache(budget_bytes / 8, weight_string_vec),
            imported_code_units: build_weighted_cache(
                budget_bytes / 4,
                weight_project_code_unit_set,
            ),
            referencing_files: build_weighted_cache(budget_bytes / 8, weight_project_file_set),
            direct_ancestors: build_weighted_cache(budget_bytes / 8, weight_code_unit_vec),
            direct_descendants: build_weighted_cache(
                budget_bytes / 8,
                weight_hierarchy_code_unit_set,
            ),
            reverse_import_index: OnceLock::new(),
            global_using_namespaces: OnceLock::new(),
        }
    }

    pub(super) fn budget_bytes(&self) -> u64 {
        self.budget_bytes
    }
}

fn weight_string_vec(_key: &ProjectFile, value: &Arc<Vec<String>>) -> u32 {
    weight_bytes(
        size_of::<Vec<String>>() as u64 + value.iter().map(|item| item.len() as u64).sum::<u64>(),
    )
}

fn weight_project_code_unit_set(_key: &ProjectFile, value: &Arc<HashSet<CodeUnit>>) -> u32 {
    weight_bytes(estimate_code_unit_set(value.as_ref()))
}

fn weight_code_unit_vec(_key: &CodeUnit, value: &Arc<Vec<CodeUnit>>) -> u32 {
    weight_bytes(estimate_code_unit_vec(value.as_ref()))
}

fn weight_hierarchy_code_unit_set(_key: &CodeUnit, value: &Arc<HashSet<CodeUnit>>) -> u32 {
    weight_bytes(estimate_code_unit_set(value.as_ref()))
}

fn weight_project_file_set(_key: &ProjectFile, value: &Arc<HashSet<ProjectFile>>) -> u32 {
    weight_bytes(estimate_project_file_set(value.as_ref()))
}

fn weight_bytes(bytes: u64) -> u32 {
    bytes.clamp(1, u32::MAX as u64) as u32
}

fn estimate_project_file(file: &ProjectFile) -> u64 {
    size_of::<ProjectFile>() as u64
        + file.root().as_os_str().to_string_lossy().len() as u64
        + file.rel_path().as_os_str().to_string_lossy().len() as u64
}

fn estimate_code_unit(code_unit: &CodeUnit) -> u64 {
    size_of::<CodeUnit>() as u64
        + estimate_project_file(code_unit.source())
        + code_unit.package_name().len() as u64
        + code_unit.short_name().len() as u64
        + code_unit
            .signature()
            .map_or(0, |signature| signature.len() as u64)
}

fn estimate_code_unit_set(values: &HashSet<CodeUnit>) -> u64 {
    size_of::<HashSet<CodeUnit>>() as u64 + values.iter().map(estimate_code_unit).sum::<u64>()
}

fn estimate_code_unit_vec(values: &[CodeUnit]) -> u64 {
    size_of::<Vec<CodeUnit>>() as u64 + values.iter().map(estimate_code_unit).sum::<u64>()
}

fn estimate_project_file_set(files: &HashSet<ProjectFile>) -> u64 {
    size_of::<HashSet<ProjectFile>>() as u64 + files.iter().map(estimate_project_file).sum::<u64>()
}
