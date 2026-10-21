use super::{CodeUnit, ProjectFile};
use std::mem::size_of;
use std::sync::Arc;

#[doc(hidden)]
pub fn estimate_project_file(file: &ProjectFile) -> u64 {
    size_of::<ProjectFile>() as u64
        + file.root().as_os_str().to_string_lossy().len() as u64
        + file.rel_path().as_os_str().to_string_lossy().len() as u64
}

#[doc(hidden)]
pub fn estimate_code_unit(code_unit: &CodeUnit) -> u64 {
    size_of::<CodeUnit>() as u64
        + estimate_project_file(code_unit.source())
        + code_unit.package_name().len() as u64
        + code_unit.short_name().len() as u64
        + code_unit
            .signature()
            .map_or(0, |signature| signature.len() as u64)
}

#[doc(hidden)]
pub fn weight_code_unit_vec(_key: &CodeUnit, value: &Arc<Vec<CodeUnit>>) -> u32 {
    let size = value
        .iter()
        .map(|item| item.fq_name().len() + size_of::<CodeUnit>())
        .sum::<usize>()
        + size_of::<Vec<CodeUnit>>();
    size.min(u32::MAX as usize) as u32
}
