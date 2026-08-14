use crate::analyzer::ProjectFile;
use crate::analyzer::usages::{ExportEntry, ExportIndex};
use std::mem::size_of;
use std::sync::Arc;

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
                    ExportEntry::ReexportedModule { module_specifier } => module_specifier.len(),
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
