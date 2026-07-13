//! Canonical Go package identity.
//!
//! A Go symbol's machine identity must be its *import path*, not the bare
//! `package` clause. Three directories that all declare `package list` are
//! distinct packages (`.../discussion/list`, `.../issue/list`,
//! `.../pr/list`); collapsing them to `list` makes `list.TestListRun`
//! ambiguous before any lookup happens. This module derives the import path
//! from the nearest `go.mod` (falling back to directory layout when no module
//! is present) so that `CodeUnit::fq_name()` is unique per declaration.

use crate::analyzer::{Project, ProjectFile};
use crate::hash::HashMap;
use std::path::{Path, PathBuf};

pub(crate) struct GoModuleRoot {
    pub import_path: String,
    pub workspace_dir: PathBuf,
}

pub(crate) struct GoWorkspacePathIndex {
    module_roots: Vec<GoModuleRoot>,
    representative_by_directory: HashMap<PathBuf, ProjectFile>,
}

impl GoWorkspacePathIndex {
    pub(crate) fn build(project: &dyn Project) -> Self {
        let files = project.all_files().unwrap_or_default();
        let module_roots = go_module_roots_from_files(project, &files);
        let mut representative_by_directory: HashMap<PathBuf, ProjectFile> = HashMap::default();
        for file in files {
            if file
                .rel_path()
                .extension()
                .is_some_and(|extension| extension == "go")
            {
                representative_by_directory
                    .entry(file.parent())
                    .and_modify(|representative| {
                        if is_go_test_file(representative) && !is_go_test_file(&file) {
                            *representative = file.clone();
                        }
                    })
                    .or_insert(file);
            }
        }
        Self {
            module_roots,
            representative_by_directory,
        }
    }

    pub(crate) fn import_files(
        &self,
        source_file: &ProjectFile,
        import_path: &str,
    ) -> Vec<ProjectFile> {
        let import_path = import_path.trim().trim_matches('/');
        if import_path.is_empty() {
            return Vec::new();
        }
        let mut directories = Vec::new();
        if let Some(relative) = import_path.strip_prefix("./") {
            directories.push(source_file.parent().join(relative));
        } else {
            let mut cursor = Some(source_file.parent());
            while let Some(directory) = cursor {
                directories.push(directory.join("vendor").join(import_path));
                cursor = directory.parent().map(Path::to_path_buf);
            }
            for module in &self.module_roots {
                if let Some(relative) = module_relative_import(&module.import_path, import_path) {
                    directories.push(module.workspace_dir.join(relative));
                }
            }
            directories.push(PathBuf::from(import_path));
        }
        directories.sort();
        directories.dedup();

        directories
            .into_iter()
            .filter_map(|directory| self.representative_by_directory.get(&directory).cloned())
            .collect()
    }

    pub(crate) fn package_prefix_exists(&self, prefix: &str) -> bool {
        self.module_roots.iter().any(|module| {
            module_relative_import(&module.import_path, prefix).is_some_and(|relative| {
                self.representative_by_directory
                    .contains_key(&module.workspace_dir.join(relative))
            })
        }) || self
            .representative_by_directory
            .contains_key(Path::new(prefix))
    }
}

fn is_go_test_file(file: &ProjectFile) -> bool {
    file.rel_path()
        .file_name()
        .is_some_and(|name| name.to_string_lossy().ends_with("_test.go"))
}

fn module_relative_import<'a>(module: &str, import_path: &'a str) -> Option<&'a str> {
    if import_path == module {
        Some("")
    } else {
        import_path
            .strip_prefix(module)
            .and_then(|suffix| suffix.strip_prefix('/'))
    }
}

pub(crate) fn go_module_roots(project: &dyn Project) -> Vec<GoModuleRoot> {
    let files = project.all_files().unwrap_or_default();
    go_module_roots_from_files(project, &files)
}

fn go_module_roots_from_files<'a>(
    project: &dyn Project,
    files: impl IntoIterator<Item = &'a ProjectFile>,
) -> Vec<GoModuleRoot> {
    let mut module_roots: Vec<_> = files
        .into_iter()
        .filter(|file| {
            file.rel_path()
                .file_name()
                .is_some_and(|name| name == "go.mod")
        })
        .filter_map(|manifest| {
            let contents = project.read_source(manifest).ok()?;
            let import_path = go_module_path_from_source(&contents)?;
            Some(GoModuleRoot {
                import_path,
                workspace_dir: manifest.parent(),
            })
        })
        .collect();
    module_roots.sort_by(|left, right| {
        right
            .import_path
            .len()
            .cmp(&left.import_path.len())
            .then_with(|| left.workspace_dir.cmp(&right.workspace_dir))
    });
    module_roots
}

/// Canonical Go package identity (import path) for `file`, given the
/// `declared_package` from its `package` clause.
///
/// External test packages (`package foo_test`) live in the same directory as
/// the package under test but form their own import path, so the canonical
/// name keeps the `_test` suffix on top of the directory's import path.
pub(crate) fn canonical_go_package_name(file: &ProjectFile, declared_package: &str) -> String {
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
    go_module_path_from_source(&contents)
}

fn go_module_path_from_source(contents: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let trimmed = line.trim();
        trimmed
            .strip_prefix("module ")
            .map(str::trim)
            .filter(|module| !module.is_empty())
            .map(str::to_string)
    })
}
