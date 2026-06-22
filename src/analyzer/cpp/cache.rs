use super::*;
use std::mem::size_of;
use std::sync::Arc;

pub(super) fn weight_code_unit_set_by_file(
    _key: &ProjectFile,
    value: &Arc<HashSet<CodeUnit>>,
) -> u32 {
    let size = value.iter().fold(0usize, |acc, item| {
        acc + size_of::<CodeUnit>()
            + item.fq_name().len()
            + item.short_name().len()
            + item.package_name().len()
            + item.signature().map_or(0, str::len)
    });
    size.saturating_add(size_of::<HashSet<CodeUnit>>()) as u32
}

pub(super) fn weight_project_file_set(
    _key: &ProjectFile,
    value: &Arc<HashSet<ProjectFile>>,
) -> u32 {
    let size = value.iter().fold(0usize, |acc, item| {
        acc + size_of::<ProjectFile>()
            + item.root().as_os_str().len()
            + item.rel_path().as_os_str().len()
    });
    size.saturating_add(size_of::<HashSet<ProjectFile>>()) as u32
}
