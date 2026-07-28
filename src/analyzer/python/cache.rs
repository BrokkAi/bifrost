use super::*;
use std::mem::size_of;
use std::sync::Arc;

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

pub(super) fn weight_code_unit_vec(_key: &CodeUnit, value: &Arc<Vec<CodeUnit>>) -> u32 {
    let size = value
        .iter()
        .map(|item| item.fq_name().len() + size_of::<CodeUnit>())
        .sum::<usize>()
        + size_of::<Vec<CodeUnit>>();
    size.min(u32::MAX as usize) as u32
}

pub(super) fn weight_export_index(_key: &ProjectFile, value: &Arc<ExportIndex>) -> u32 {
    let exports_size = value
        .exports_by_name
        .iter()
        .map(|(name, entry)| {
            name.len()
                + match entry {
                    ExportEntry::Local { local_name } => local_name.len(),
                    ExportEntry::ReexportedNamed {
                        module_specifier,
                        imported_name,
                    } => module_specifier.len() + imported_name.len(),
                    ExportEntry::Default { local_name } => {
                        local_name.as_deref().map_or(0, str::len)
                    }
                }
                + size_of::<ExportEntry>()
        })
        .sum::<usize>();
    let reexport_stars_size = value
        .reexport_stars
        .iter()
        .map(|star| star.module_specifier.len() + size_of::<ReexportStar>())
        .sum::<usize>();
    (exports_size + reexport_stars_size + size_of::<ExportIndex>()).min(u32::MAX as usize) as u32
}
