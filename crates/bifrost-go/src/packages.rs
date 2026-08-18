//! Canonical Go package identity.
//!
//! A Go symbol's machine identity must be its *import path*, not the bare
//! `package` clause. Three directories that all declare `package list` are
//! distinct packages (`.../discussion/list`, `.../issue/list`,
//! `.../pr/list`); collapsing them to `list` makes `list.TestListRun`
//! ambiguous before any lookup happens. This module derives the import path
//! from the nearest `go.mod` (falling back to directory layout when no module
//! is present) so that `CodeUnit::fq_name()` is unique per declaration.

use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::project::Project;
use brokk_bifrost_core::hash::HashMap;
use std::path::{Path, PathBuf};

/// Synthetic scope segment owning a Go package's module-level `var`, `const`
/// and type-alias declarations, which have no enclosing type of their own.
pub const GO_MODULE_SCOPE_SEGMENT: &str = "_module_";

pub struct GoModuleRoot {
    pub import_path: String,
    pub workspace_dir: PathBuf,
}

pub struct GoWorkspacePathIndex {
    module_roots: Vec<GoModuleRoot>,
    representative_by_directory: HashMap<PathBuf, ProjectFile>,
}

impl GoWorkspacePathIndex {
    pub fn build(project: &dyn Project) -> Self {
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

    pub fn import_files(&self, source_file: &ProjectFile, import_path: &str) -> Vec<ProjectFile> {
        let import_path = import_path.trim().trim_matches('/');
        if import_path.is_empty() {
            return Vec::new();
        }
        if let Some(relative) = import_path.strip_prefix("./") {
            return self
                .representative_by_directory
                .get(&source_file.parent().join(relative))
                .cloned()
                .into_iter()
                .collect();
        }

        // The nearest vendor package shadows both ancestor vendor copies and
        // workspace modules with the same import path.
        let mut cursor = Some(source_file.parent());
        while let Some(directory) = cursor {
            let vendored = directory.join("vendor").join(import_path);
            if let Some(file) = self.representative_by_directory.get(&vendored) {
                return vec![file.clone()];
            }
            cursor = directory.parent().map(Path::to_path_buf);
        }

        let mut module_files = self
            .module_roots
            .iter()
            .filter_map(|module| {
                let relative = module_relative_import(&module.import_path, import_path)?;
                self.representative_by_directory
                    .get(&module.workspace_dir.join(relative))
                    .cloned()
            })
            .collect::<Vec<_>>();
        module_files.sort();
        module_files.dedup();
        if !module_files.is_empty() {
            return module_files;
        }

        self.module_roots
            .is_empty()
            .then(|| {
                self.representative_by_directory
                    .get(Path::new(import_path))
                    .cloned()
            })
            .flatten()
            .into_iter()
            .collect()
    }

    pub fn package_prefix_exists(&self, prefix: &str) -> bool {
        self.module_roots.iter().any(|module| {
            module_relative_import(&module.import_path, prefix).is_some_and(|relative| {
                self.representative_by_directory
                    .contains_key(&module.workspace_dir.join(relative))
            })
        }) || (self.module_roots.is_empty()
            && self
                .representative_by_directory
                .contains_key(Path::new(prefix)))
    }

    /// Canonical package identity using the module roots already indexed for
    /// this workspace. Unlike [`canonical_go_package_name`], this performs no
    /// ancestor filesystem walk and no repeated `go.mod` reads.
    pub fn canonical_package_name(&self, file: &ProjectFile, declared_package: &str) -> String {
        let (declared_base, is_external_test) = declared_package
            .strip_suffix("_test")
            .filter(|stripped| !stripped.is_empty())
            .map_or((declared_package, false), |stripped| (stripped, true));
        let file_dir = file.parent();
        let base = self
            .module_roots
            .iter()
            .filter(|module| file_dir.starts_with(&module.workspace_dir))
            .max_by_key(|module| module.workspace_dir.components().count())
            .and_then(|module| {
                let relative = file_dir.strip_prefix(&module.workspace_dir).ok()?;
                Some(join_import_path(
                    &module.import_path,
                    &relative.to_string_lossy().replace('\\', "/"),
                ))
            })
            .unwrap_or_else(|| no_module_base(file, declared_base));
        if is_external_test {
            format!("{base}_test")
        } else {
            base
        }
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

pub fn go_module_roots(project: &dyn Project) -> Vec<GoModuleRoot> {
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
pub fn canonical_go_package_name(file: &ProjectFile, declared_package: &str) -> String {
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

pub fn go_internal_import_allowed(importer: &str, imported: &str) -> bool {
    let imported_segments = imported.split('/').collect::<Vec<_>>();
    let internal_indices = imported_segments
        .iter()
        .enumerate()
        .filter_map(|(index, segment)| (*segment == "internal").then_some(index));
    for internal_index in internal_indices {
        if internal_index == 0 {
            return false;
        }
        let parent = imported_segments[..internal_index].join("/");
        if importer != parent
            && !importer
                .strip_prefix(&parent)
                .is_some_and(|suffix| suffix.starts_with('/'))
        {
            return false;
        }
    }
    true
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
///
/// Invariant: the returned path (like [`go_module_path_from_source`]'s) is a
/// single clean token -- no embedded whitespace, no `//` comment text, no
/// surrounding quotes. Callers may join it with `/`-separated path segments
/// without re-normalizing.
pub fn read_go_module_path(dir: &Path) -> Option<String> {
    let contents = std::fs::read_to_string(dir.join("go.mod")).ok()?;
    go_module_path_from_source(&contents)
}

/// Extract the `module` directive's path from `go.mod` source.
///
/// This follows the go.mod lexical grammar
/// (<https://go.dev/ref/mod#go-mod-file-lexical>), which this function
/// implements directly as a small tokenizer rather than pulling in a grammar
/// dependency for a config format this simple:
///
/// - Whitespace (spaces, tabs, carriage returns) separates tokens; it is
///   never part of a token, so `module` can be followed by a tab as well as
///   a space.
/// - `//` starts a line comment that runs to the end of the line. A comment
///   is not part of the preceding token even when it abuts it with no
///   intervening space.
/// - A token is either an unquoted run of non-whitespace, non-comment
///   characters, or a double-quoted (`"..."`) or backquoted (`` `...` ``)
///   string, whose contents (including any `/` or whitespace inside the
///   quotes) are taken verbatim.
///
/// The module path is the single token following the `module` keyword. This
/// only recognizes the single-line `module path` form: `go.mod` permits at
/// most one `module` directive per file, so the parenthesized block form
/// that other directives (`require`, `replace`, ...) use does not apply here.
fn go_module_path_from_source(contents: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let after_keyword = strip_module_keyword(line.trim_start())?;
        let module_path = next_go_mod_token(after_keyword)?;
        // Documents and enforces the invariant on `read_go_module_path`: a
        // well-formed module path can never contain whitespace or a `//`
        // once the tokenizer above has stripped comments and quoting. If
        // this ever fires, the tokenizer has a bug -- fail at the
        // construction point (per #1189's model) instead of handing a
        // corrupted path to `join_import_path` and `go_package_fq`, whose
        // divergent `/`-joining is exactly what produced this issue.
        debug_assert!(
            !module_path.contains(char::is_whitespace) && !module_path.contains("//"),
            "go.mod module path token must be a single clean path, got {module_path:?}"
        );
        Some(module_path)
    })
}

/// Strips the leading `module` keyword and the whitespace that must
/// separate it from its argument. Rejects lines like `modules foo` where
/// `module` is only a prefix of a longer identifier.
fn strip_module_keyword(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("module")?;
    let mut chars = rest.chars();
    if !chars.next()?.is_whitespace() {
        return None;
    }
    Some(rest.trim_start())
}

/// Reads one go.mod token from the start of `text` (already past the
/// `module` keyword and its separating whitespace). Returns `None` when
/// there is no token: `text` is empty, or it opens with a `//` comment.
fn next_go_mod_token(text: &str) -> Option<String> {
    if text.is_empty() || text.starts_with("//") {
        return None;
    }
    if let Some(rest) = text.strip_prefix('"') {
        let end = rest.find('"')?;
        return Some(rest[..end].to_string());
    }
    if let Some(rest) = text.strip_prefix('`') {
        let end = rest.find('`')?;
        return Some(rest[..end].to_string());
    }
    // Unquoted token: ends at the first whitespace character or at the
    // start of a `//` comment, whichever comes first -- a comment can abut
    // the token with no separating space, as in the go2hx fixture this
    // handles (`module github.com/go2hx/go4hx //not a real repo...`, where
    // the space before `//` already ends the token; this branch also covers
    // the case with no such space).
    let end = text
        .char_indices()
        .find(|&(i, ch)| ch.is_whitespace() || text[i..].starts_with("//"))
        .map(|(i, _)| i)
        .unwrap_or(text.len());
    let token = &text[..end];
    (!token.is_empty()).then(|| token.to_string())
}

#[cfg(test)]
mod tests {
    use super::go_module_path_from_source;

    #[test]
    fn plain_module_path() {
        assert_eq!(
            Some("example.com/repo".to_string()),
            go_module_path_from_source("module example.com/repo\n")
        );
    }

    #[test]
    fn trailing_line_comment_is_excluded() {
        assert_eq!(
            Some("example.com/repo".to_string()),
            go_module_path_from_source("module example.com/repo // comment\n")
        );
    }

    #[test]
    fn comment_with_slashes_in_its_text_is_excluded() {
        // The go2hx/go4hx go.mod line verbatim: the comment's own text
        // contains `/` characters, which must not be mistaken for part of
        // the module path.
        assert_eq!(
            Some("github.com/go2hx/go4hx".to_string()),
            go_module_path_from_source(
                "module github.com/go2hx/go4hx //not a real repo, used to set the name to go4hx\n"
            )
        );
    }

    #[test]
    fn comment_directly_abutting_the_path_with_no_space_is_excluded() {
        assert_eq!(
            Some("example.com/repo".to_string()),
            go_module_path_from_source("module example.com/repo//comment\n")
        );
    }

    #[test]
    fn quoted_module_path() {
        assert_eq!(
            Some("example.com/repo".to_string()),
            go_module_path_from_source("module \"example.com/repo\"\n")
        );
    }

    #[test]
    fn quoted_module_path_with_trailing_comment() {
        assert_eq!(
            Some("example.com/repo".to_string()),
            go_module_path_from_source("module \"example.com/repo\" // comment\n")
        );
    }

    #[test]
    fn tab_after_module_keyword() {
        assert_eq!(
            Some("example.com/repo".to_string()),
            go_module_path_from_source("module\texample.com/repo\n")
        );
    }

    #[test]
    fn module_line_that_is_only_a_comment_has_no_path() {
        assert_eq!(
            None,
            go_module_path_from_source("module // just a comment, no path\n")
        );
    }

    #[test]
    fn empty_go_mod_has_no_path() {
        assert_eq!(None, go_module_path_from_source(""));
    }

    #[test]
    fn identifier_that_merely_starts_with_module_is_not_the_keyword() {
        assert_eq!(
            None,
            go_module_path_from_source("modules example.com/repo\n")
        );
    }

    #[test]
    fn module_path_is_found_among_other_directives() {
        assert_eq!(
            Some("example.com/repo".to_string()),
            go_module_path_from_source(
                "go 1.22\n\nmodule example.com/repo\n\nrequire foo v1.0.0\n"
            )
        );
    }
}
