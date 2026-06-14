//! Canonical Go package identity.
//!
//! A Go symbol's machine identity must be its *import path*, not the bare
//! `package` clause. Three directories that all declare `package list` are
//! distinct packages (`.../discussion/list`, `.../issue/list`,
//! `.../pr/list`); collapsing them to `list` makes `list.TestListRun`
//! ambiguous before any lookup happens. This module derives the import path
//! from the nearest `go.mod` (falling back to directory layout when no module
//! is present) so that `CodeUnit::fq_name()` is unique per declaration.

use crate::analyzer::ProjectFile;
use std::path::Path;

/// Canonical Go package identity (import path) for `file`, given the
/// `declared_package` from its `package` clause.
///
/// External test packages (`package foo_test`) live in the same directory as
/// the package under test but form their own import path, so the canonical
/// name keeps the `_test` suffix on top of the directory's import path.
pub(super) fn canonical_go_package_name(file: &ProjectFile, declared_package: &str) -> String {
    let (declared_base, is_external_test) = match declared_package.strip_suffix("_test") {
        Some(stripped) if !stripped.is_empty() => (stripped, true),
        _ => (declared_package, false),
    };

    let base = match nearest_go_module(file) {
        Some((module_path, rel_dir)) => join_import_path(&module_path, &rel_dir),
        None => no_module_base(file, declared_base),
    };

    if is_external_test {
        format!("{base}_test")
    } else {
        base
    }
}

/// Walk from `file`'s directory up to the project root, returning the module
/// path and the file directory's path relative to the nearest `go.mod`.
fn nearest_go_module(file: &ProjectFile) -> Option<(String, String)> {
    let root = file.root();
    let abs = file.abs_path();
    let file_dir = abs.parent()?;
    let mut cursor = file_dir;
    loop {
        if let Some(module_path) = read_go_module_path(cursor) {
            let rel_dir = file_dir
                .strip_prefix(cursor)
                .ok()?
                .to_string_lossy()
                .replace('\\', "/");
            return Some((module_path, rel_dir));
        }
        if cursor == root {
            return None;
        }
        cursor = cursor.parent()?;
    }
}

/// Import path with no `go.mod`: the project-relative parent directory, or the
/// declared package name for files sitting at the project root. This preserves
/// the historical `package.Symbol` shape for flat, module-less fixtures.
fn no_module_base(file: &ProjectFile, declared_base: &str) -> String {
    let parent = file.parent().to_string_lossy().replace('\\', "/");
    let parent = parent.trim_matches('/');
    if parent.is_empty() {
        declared_base.to_string()
    } else {
        parent.to_string()
    }
}

fn join_import_path(module_path: &str, rel_dir: &str) -> String {
    let module_path = module_path.trim_matches('/');
    let rel_dir = rel_dir.trim_matches('/');
    if rel_dir.is_empty() {
        module_path.to_string()
    } else {
        format!("{module_path}/{rel_dir}")
    }
}

/// Read the `module` path from the `go.mod` in `dir`, if present.
pub(crate) fn read_go_module_path(dir: &Path) -> Option<String> {
    let contents = std::fs::read_to_string(dir.join("go.mod")).ok()?;
    contents.lines().find_map(|line| {
        let trimmed = line.trim();
        trimmed
            .strip_prefix("module ")
            .map(str::trim)
            .filter(|module| !module.is_empty())
            .map(str::to_string)
    })
}
