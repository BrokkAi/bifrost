use super::graph_support::RustReferenceContext;
use crate::analyzer::usages::{ExportEntry, ExportIndex};
use crate::analyzer::{CodeUnit, ProjectFile};
use crate::hash::{HashMap, HashSet};
use std::mem::size_of;
use std::sync::Arc;

pub(super) fn weight_reference_context(
    _key: &ProjectFile,
    value: &Arc<RustReferenceContext>,
) -> u32 {
    let map_bytes = |map: &HashMap<String, String>| {
        map.iter()
            .map(|(key, val)| key.len() + val.len() + size_of::<(String, String)>())
            .sum::<usize>()
    };
    let size = map_bytes(&value.named)
        + map_bytes(&value.namespace)
        + map_bytes(&value.same_file)
        + size_of::<RustReferenceContext>();
    size.min(u32::MAX as usize) as u32
}

pub(super) fn weight_export_index(_key: &ProjectFile, value: &Arc<ExportIndex>) -> u32 {
    let exports = value
        .exports_by_name
        .iter()
        .map(|(exported, entry)| {
            exported.len()
                + match entry {
                    ExportEntry::Local { local_name } => local_name.len(),
                    ExportEntry::Default { local_name } => {
                        local_name.as_ref().map_or(0, String::len)
                    }
                    ExportEntry::ReexportedNamed {
                        module_specifier,
                        imported_name,
                    } => module_specifier.len() + imported_name.len(),
                }
        })
        .sum::<usize>();
    let stars = value
        .reexport_stars
        .iter()
        .map(|star| star.module_specifier.len())
        .sum::<usize>();
    (exports + stars + size_of::<ExportIndex>()).min(u32::MAX as usize) as u32
}

pub(super) fn weight_project_file_set(
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

pub(super) fn weight_code_unit_set(_key: &ProjectFile, value: &Arc<HashSet<CodeUnit>>) -> u32 {
    let size = value
        .iter()
        .map(|item| item.fq_name().len() + size_of::<CodeUnit>())
        .sum::<usize>()
        + size_of::<HashSet<CodeUnit>>();
    size.min(u32::MAX as usize) as u32
}
