use brokk_bifrost_core::analyzer::common::language_for_file;

use crate::analyzer::Language;
use crate::analyzer::ProjectFile;
use std::ffi::OsStr;
use std::path::Path;

pub fn is_java_module_descriptor_file(file: &ProjectFile) -> bool {
    language_for_file(file) == Language::Java
        && file.rel_path().file_name() == Some(OsStr::new("module-info.java"))
}

pub fn rebase_project_file_to_root(file: &ProjectFile, root: &Path) -> Option<ProjectFile> {
    if file.root() == root {
        return Some(file.clone());
    }
    let abs_path = file.abs_path();
    let rel = if let Ok(rel) = abs_path.strip_prefix(root) {
        rel.to_path_buf()
    } else {
        let canonical_abs = abs_path.canonicalize().ok()?;
        let canonical_root = root.canonicalize().ok()?;
        canonical_abs
            .strip_prefix(canonical_root)
            .ok()?
            .to_path_buf()
    };
    Some(ProjectFile::new(root.to_path_buf(), rel))
}
