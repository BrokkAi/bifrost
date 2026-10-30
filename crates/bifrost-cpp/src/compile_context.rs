//! `compile_commands.json` ingestion.
//!
//! `analyzer/cpp/mod.rs` keeps the `OnceLock<CppCompileContexts>` that memoizes
//! [`CppCompileContexts::load`] per analyzer generation; the database format and
//! the argument grammar are here.

use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::project::Project;
use brokk_bifrost_core::hash::{HashMap, HashSet};
use brokk_bifrost_core::path_normalization::NormalizePath;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

const COMPILATION_DATABASE_PATH: &str = "compile_commands.json";

/// The maximum number of workspace-relative source paths retained in the
/// compile-database coverage report. The count remains exact; the sample is
/// intentionally bounded so a generated database cannot make discovery
/// evidence unbounded.
const MAX_MISSING_WORKSPACE_SOURCE_SAMPLE: usize = 32;

/// Whether `file` is the workspace compilation database consumed by
/// [`CppCompileContexts::load`].
pub fn is_cpp_compile_context_input(file: &ProjectFile) -> bool {
    file.rel_path() == Path::new(COMPILATION_DATABASE_PATH)
}

/// The compiler configuration Bifrost can safely use for one source file.
///
/// This is deliberately narrower than a compiler invocation. It records only
/// context that later semantic diagnostics need and never executes `command`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppCompileContext {
    pub project_include_roots: Vec<PathBuf>,
    pub system_include_roots: Vec<PathBuf>,
    pub forced_includes: Vec<PathBuf>,
    pub defined_macros: HashSet<String>,
    /// Explicit -D/-U flags invalidate the compiler's default builtin state.
    pub(crate) cplusplus_macro_configured: bool,
    include_search_roots: Vec<CppIncludeSearchRoot>,
    /// The invocation's driver basename (`arguments[0]`, minus one trailing
    /// extension such as `.exe`), used by [`Self::tu_language`] only when
    /// nothing stronger settles the language.
    driver_basename: Option<String>,
    /// Language forced by `-x <lang>` / `-xc` / `-xc++` or MSVC `/TC` / `/TP`.
    /// The strongest evidence [`Self::tu_language`] considers.
    explicit_language: Option<CompiledLanguage>,
    /// Language implied by `-std=<value>`: the C family (`c11`, `gnu17`, ...)
    /// versus the C++ family (`c++17`, `gnu++20`, ...), told apart by whether
    /// the value contains `++`.
    std_language: Option<CompiledLanguage>,
}

/// The language a compile-database entry says its translation unit is
/// compiled as. See [`CppCompileContext::tu_language`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompiledLanguage {
    C,
    Cpp,
}

/// Why one compiler include-search entry exists.
///
/// The distinction is semantic. `-isystem` declares an external surface even
/// when a test places that surface below the temporary workspace root, while an
/// ordinary `-I` entry is external only when it points outside the workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CppIncludeSearchRootKind {
    Project,
    Quote,
    System,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CppIncludeSearchRoot {
    path: PathBuf,
    kind: CppIncludeSearchRootKind,
}

/// What all compile configurations for one source prove about an angle include.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CppExternalIncludeResolution {
    /// No compile command names the source file.
    MissingCompileContext,
    /// Every configuration agrees that no explicit external root contains it.
    Undeclared,
    /// Configurations select different headers, or only some select a header.
    Conflicting,
    /// Every configuration selects this exact external header.
    Declared { root: PathBuf, header: PathBuf },
}

/// Informational coverage from one compile database against the analyzer's
/// C++ workspace listing.
///
/// A missing source is not a discovery failure. Build systems routinely leave
/// generated translation units in `compile_commands.json` after a clean or
/// partial checkout. This report is therefore kept separate from compile
/// contexts and dependency-discovery completeness. The count is exact over
/// distinct canonical workspace-relative paths; the sample is deterministic
/// and bounded by [`MAX_MISSING_WORKSPACE_SOURCE_SAMPLE`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CppCompileDatabaseCoverage {
    missing_workspace_source_count: usize,
    missing_workspace_source_sample: Vec<PathBuf>,
}

impl CppCompileDatabaseCoverage {
    /// The exact number of distinct in-workspace compile-database source paths
    /// absent from the supplied analyzer listing.
    pub fn missing_workspace_source_count(&self) -> usize {
        self.missing_workspace_source_count
    }

    /// A sorted, workspace-relative sample of missing source paths.
    pub fn missing_workspace_source_sample(&self) -> &[PathBuf] {
        &self.missing_workspace_source_sample
    }
}

#[derive(Debug, Default)]
pub struct CppCompileContexts {
    by_source: HashMap<PathBuf, Vec<CppCompileContext>>,
    /// Every distinct source path named by an in-workspace compile-database
    /// entry, including entries whose compiler arguments are malformed. The
    /// source identity is retained independently of whether a context can be
    /// used for include resolution so coverage can report stale generated
    /// entries without turning them into diagnostics.
    database_sources: HashSet<PathBuf>,
}

impl CppCompileContexts {
    pub fn load(project: &dyn Project) -> Self {
        Self::load_with_io_error(project, |_| {})
    }

    /// Keep the legacy best-effort value while its analyzer observes provider
    /// failures before a persistent memo can install that value (#7311).
    pub fn load_with_io_error(
        project: &dyn Project,
        on_error: impl FnOnce(&std::io::Error),
    ) -> Self {
        let workspace_root = canonical_or_normalized_path(project.root());
        let database_path = workspace_root.join(COMPILATION_DATABASE_PATH);
        let database = match std::fs::read_to_string(database_path) {
            Ok(database) => database,
            Err(error) => {
                on_error(&error);
                return Self::default();
            }
        };
        let Ok(entries) = serde_json::from_str::<Vec<CompilationDatabaseEntry>>(&database) else {
            return Self::default();
        };

        let mut by_source: HashMap<PathBuf, Vec<CppCompileContext>> = HashMap::default();
        let mut database_sources = HashSet::default();
        for entry in entries {
            let Some(source) = entry.source_path(&workspace_root) else {
                continue;
            };
            let source_identity = canonical_or_normalized_path(&source);
            if source_identity.strip_prefix(&workspace_root).is_err() {
                continue;
            }
            database_sources.insert(source_identity.clone());
            let Some(context) = entry.compile_context(&workspace_root) else {
                continue;
            };
            // A build that compiles one file in several configurations records
            // one entry per configuration. Keeping every distinct one lets the
            // caller decide per name whether the configurations agree; dropping
            // them would make "compiled two ways" look like "never compiled".
            // Entries that parse to the same context are one configuration.
            let candidates = by_source.entry(source_identity).or_default();
            if !candidates.contains(&context) {
                candidates.push(context);
            }
        }
        Self {
            by_source,
            database_sources,
        }
    }

    /// Compare compile-database source identities with the analyzer's exact
    /// C++ workspace listing.
    ///
    /// The listing is supplied by the caller so discovery can preserve its
    /// listing-driven scan and avoid a second workspace walk. Both sides are
    /// compared as canonical [`PathBuf`] identities under `workspace_root`;
    /// no source text, display path, or string-prefix identity participates.
    /// Entries outside `workspace_root` are ordinary build inputs and are
    /// silently excluded.
    pub fn missing_workspace_sources<'a>(
        &self,
        workspace_root: &Path,
        workspace_files: impl IntoIterator<Item = &'a ProjectFile>,
    ) -> CppCompileDatabaseCoverage {
        let workspace_root = canonical_or_normalized_path(workspace_root);
        let listed_sources = workspace_files
            .into_iter()
            .map(|file| canonical_or_normalized_path(&file.abs_path()))
            .collect::<HashSet<_>>();
        let mut missing_count = 0usize;
        let mut sample = BTreeSet::new();
        for source in &self.database_sources {
            let Some(relative) = (|| {
                let relative = source.strip_prefix(&workspace_root).ok()?;
                (!relative.as_os_str().is_empty() && !listed_sources.contains(source))
                    .then(|| relative.to_path_buf().normalize())
            })() else {
                continue;
            };
            missing_count = missing_count.saturating_add(1);
            sample.insert(relative);
            if sample.len() > MAX_MISSING_WORKSPACE_SOURCE_SAMPLE {
                sample.pop_last();
            }
        }
        CppCompileDatabaseCoverage {
            missing_workspace_source_count: missing_count,
            missing_workspace_source_sample: sample.into_iter().collect(),
        }
    }

    /// Every distinct compile configuration the database records for `file`,
    /// empty when no entry names it.
    ///
    /// Exactly one context is an unambiguous selection. More than one means the
    /// include closures can differ, so a name is absent only where every
    /// candidate agrees that it is.
    pub fn contexts_for(&self, file: &ProjectFile) -> &[CppCompileContext] {
        self.by_source
            .get(&canonical_or_normalized_path(&file.abs_path()))
            .map_or(&[], Vec::as_slice)
    }

    /// Resolve one literal include through explicit external roots in every
    /// compile configuration for `file`.
    ///
    /// This method never probes an implicit compiler sysroot and never executes
    /// the compiler. A result is declared only when every configuration selects
    /// the same existing file. This preserves the multi-configuration honesty
    /// required by C++ diagnostics and external semantic packs.
    pub fn resolve_external_angle_include(
        &self,
        file: &ProjectFile,
        include: &Path,
    ) -> CppExternalIncludeResolution {
        self.resolve_external_include(file, &file.abs_path(), include, false)
    }

    /// Resolve one literal include using C include search semantics.
    ///
    /// A quoted include first checks the directory containing `including_file`,
    /// then the explicit compiler search roots in command order. An angle
    /// include skips the including-file directory and quote-only roots. The
    /// result is declared only when every configuration selects the same
    /// existing external file.
    pub fn resolve_external_include(
        &self,
        file: &ProjectFile,
        including_file: &Path,
        include: &Path,
        quoted: bool,
    ) -> CppExternalIncludeResolution {
        let contexts = self.contexts_for(file);
        let Some(first_context) = contexts.first() else {
            return CppExternalIncludeResolution::MissingCompileContext;
        };
        let first =
            first_context.resolve_external_include(file.root(), including_file, include, quoted);
        if contexts.iter().skip(1).any(|context| {
            context.resolve_external_include(file.root(), including_file, include, quoted) != first
        }) {
            return CppExternalIncludeResolution::Conflicting;
        }
        match first {
            Some((root, header)) => CppExternalIncludeResolution::Declared { root, header },
            None => CppExternalIncludeResolution::Undeclared,
        }
    }
}

impl CppCompileContext {
    /// The language this compile configuration says `source_path` is
    /// compiled as, strongest evidence first:
    ///
    /// 1. An explicit `-x <lang>` / `-xc` / `-xc++` or MSVC `/TC` / `/TP`.
    /// 2. A `-std=<value>` family (C when the value has no `++`, C++ when it
    ///    does).
    /// 3. The driver basename: `g++`, `clang++`, `c++`, and similar names
    ///    ending in `++` compile as C++ regardless of extension.
    /// 4. `source_path`'s extension: exactly `c` (case-sensitive, matching
    ///    `is_c_source_file`) is C, everything else is C++. This is also the
    ///    rule `cl.exe` itself uses when neither `/TC` nor `/TP` is given.
    pub fn tu_language(&self, source_path: &Path) -> CompiledLanguage {
        if let Some(language) = self.explicit_language {
            return language;
        }
        if let Some(language) = self.std_language {
            return language;
        }
        if self
            .driver_basename
            .as_deref()
            .is_some_and(|driver| driver.ends_with("++"))
        {
            return CompiledLanguage::Cpp;
        }
        if source_path
            .extension()
            .and_then(|extension| extension.to_str())
            == Some("c")
        {
            CompiledLanguage::C
        } else {
            CompiledLanguage::Cpp
        }
    }

    fn external_include_roots<'a>(
        &'a self,
        workspace_root: &'a Path,
        quoted: bool,
    ) -> impl Iterator<Item = &'a Path> + 'a {
        self.include_search_roots.iter().filter_map(move |root| {
            (quoted || root.kind != CppIncludeSearchRootKind::Quote)
                .then_some(root)
                .filter(|root| {
                    root.kind == CppIncludeSearchRootKind::System
                        || !root.path.starts_with(workspace_root)
                })
                .map(|root| root.path.as_path())
        })
    }

    fn resolve_external_include(
        &self,
        workspace_root: &Path,
        including_file: &Path,
        include: &Path,
        quoted: bool,
    ) -> Option<(PathBuf, PathBuf)> {
        if include.is_absolute()
            || (!quoted
                && include
                    .components()
                    .any(|component| !matches!(component, Component::Normal(_))))
            || (quoted
                && include.components().any(|component| {
                    matches!(component, Component::RootDir | Component::Prefix(_))
                }))
        {
            return None;
        }

        let workspace_root = canonical_or_normalized_path(workspace_root);
        if quoted {
            let including_directory = including_file.parent()?;
            if let Ok(candidate) = including_directory.join(include).canonicalize()
                && candidate.is_file()
            {
                // `canonicalize` keeps the Windows verbatim prefix that
                // `workspace_root` normalizes away; compare in one spelling.
                if candidate.clone().normalize().starts_with(&workspace_root) {
                    return None;
                }
                if let Some(root) = self
                    .external_include_roots(&workspace_root, true)
                    .filter_map(|root| {
                        let root = root.canonicalize().ok()?;
                        candidate.starts_with(&root).then_some(root)
                    })
                    .next()
                {
                    return Some((root, candidate));
                }
                return None;
            }
        }

        self.external_include_roots(&workspace_root, quoted)
            .filter_map(|root| {
                let root = root.canonicalize().ok()?;
                let candidate = root.join(include).canonicalize().ok()?;
                (candidate.starts_with(&root) && candidate.is_file()).then_some((root, candidate))
            })
            .next()
    }
}

#[derive(Debug, Deserialize)]
struct CompilationDatabaseEntry {
    directory: PathBuf,
    file: PathBuf,
    arguments: Option<Vec<String>>,
    command: Option<String>,
}

impl CompilationDatabaseEntry {
    fn source_path(&self, workspace_root: &Path) -> Option<PathBuf> {
        absolute_path(
            &command_directory(workspace_root, &self.directory)?,
            &self.file,
        )
    }

    fn compile_context(&self, workspace_root: &Path) -> Option<CppCompileContext> {
        let arguments = match &self.arguments {
            Some(arguments) if !arguments.is_empty() => arguments.clone(),
            Some(_) => return None,
            None => shlex::split(self.command.as_deref()?)?,
        };
        parse_compile_arguments(
            &command_directory(workspace_root, &self.directory)?,
            &arguments,
        )
    }
}

fn command_directory(workspace_root: &Path, directory: &Path) -> Option<PathBuf> {
    absolute_path(workspace_root, directory)
}

fn parse_compile_arguments(directory: &Path, arguments: &[String]) -> Option<CppCompileContext> {
    if arguments.is_empty() {
        return None;
    }

    let driver_basename = driver_basename(&arguments[0]);
    let mut project_include_roots = Vec::new();
    let mut system_include_roots = Vec::new();
    let mut forced_includes = Vec::new();
    let mut defined_macros = HashSet::default();
    let mut cplusplus_macro_configured = false;
    let mut include_search_roots = Vec::new();
    let mut explicit_language = None;
    let mut std_language = None;
    let mut index = 1;
    while index < arguments.len() {
        let argument = &arguments[index];
        match argument.as_str() {
            "-x" => {
                if let Some(language) = language_from_x_value(arguments.get(index + 1)?) {
                    explicit_language = Some(language);
                }
                index += 2;
            }
            "/TC" => {
                explicit_language = Some(CompiledLanguage::C);
                index += 1;
            }
            "/TP" => {
                explicit_language = Some(CompiledLanguage::Cpp);
                index += 1;
            }
            "-I" | "/I" => {
                let path = argument_path(directory, arguments.get(index + 1)?)?;
                project_include_roots.push(path.clone());
                include_search_roots.push(CppIncludeSearchRoot {
                    path,
                    kind: CppIncludeSearchRootKind::Project,
                });
                index += 2;
            }
            "-iquote" => {
                let path = argument_path(directory, arguments.get(index + 1)?)?;
                project_include_roots.push(path.clone());
                include_search_roots.push(CppIncludeSearchRoot {
                    path,
                    kind: CppIncludeSearchRootKind::Quote,
                });
                index += 2;
            }
            "-isystem" | "/external:I" | "/imsvc" => {
                let path = argument_path(directory, arguments.get(index + 1)?)?;
                system_include_roots.push(path.clone());
                include_search_roots.push(CppIncludeSearchRoot {
                    path,
                    kind: CppIncludeSearchRootKind::System,
                });
                index += 2;
            }
            "-include" => {
                forced_includes.push(argument_path(directory, arguments.get(index + 1)?)?);
                index += 2;
            }
            "-D" => {
                let name = macro_name(arguments.get(index + 1)?)?;
                cplusplus_macro_configured |= name == "__cplusplus";
                defined_macros.insert(name);
                index += 2;
            }
            // The compiler applies -D and -U in command order, so a later -U
            // removes an earlier -D. An -U proves nothing on its own: a header
            // can still define the name, so only the surviving defines are
            // positive facts (#2011).
            "-U" => {
                let name = macro_name(arguments.get(index + 1)?)?;
                cplusplus_macro_configured |= name == "__cplusplus";
                defined_macros.remove(&name);
                index += 2;
            }
            _ => {
                if let Some(path) = argument
                    .strip_prefix("/external:I")
                    .or_else(|| argument.strip_prefix("/imsvc"))
                {
                    let path = argument_path(directory, path)?;
                    system_include_roots.push(path.clone());
                    include_search_roots.push(CppIncludeSearchRoot {
                        path,
                        kind: CppIncludeSearchRootKind::System,
                    });
                } else if let Some(path) = argument
                    .strip_prefix("-I")
                    .or_else(|| argument.strip_prefix("/I"))
                {
                    let path = argument_path(directory, path)?;
                    project_include_roots.push(path.clone());
                    include_search_roots.push(CppIncludeSearchRoot {
                        path,
                        kind: CppIncludeSearchRootKind::Project,
                    });
                } else if let Some(path) = argument.strip_prefix("-iquote") {
                    let path = argument_path(directory, path)?;
                    project_include_roots.push(path.clone());
                    include_search_roots.push(CppIncludeSearchRoot {
                        path,
                        kind: CppIncludeSearchRootKind::Quote,
                    });
                } else if let Some(path) = argument.strip_prefix("-isystem") {
                    let path = argument_path(directory, path)?;
                    system_include_roots.push(path.clone());
                    include_search_roots.push(CppIncludeSearchRoot {
                        path,
                        kind: CppIncludeSearchRootKind::System,
                    });
                } else if let Some(definition) = argument.strip_prefix("-D") {
                    let name = macro_name(definition)?;
                    cplusplus_macro_configured |= name == "__cplusplus";
                    defined_macros.insert(name);
                } else if let Some(name) = argument.strip_prefix("-U") {
                    let name = macro_name(name)?;
                    cplusplus_macro_configured |= name == "__cplusplus";
                    defined_macros.remove(&name);
                } else if let Some(value) = argument.strip_prefix("-std=") {
                    std_language = Some(if value.contains("++") {
                        CompiledLanguage::Cpp
                    } else {
                        CompiledLanguage::C
                    });
                } else if let Some(value) = argument.strip_prefix("-x")
                    && let Some(language) = language_from_x_value(value)
                {
                    explicit_language = Some(language);
                }
                index += 1;
            }
        }
    }

    Some(CppCompileContext {
        project_include_roots,
        system_include_roots,
        forced_includes,
        defined_macros,
        cplusplus_macro_configured,
        include_search_roots,
        driver_basename,
        explicit_language,
        std_language,
    })
}

/// The driver invocation's basename, with one trailing extension (`.exe` on
/// Windows) stripped. `-c++`-style drivers such as `g++`, `clang++`, and
/// `arm-none-eabi-g++` keep their identifying `++` suffix; `cl.exe` reduces to
/// `cl`, which decides nothing by itself.
fn driver_basename(driver: &str) -> Option<String> {
    Path::new(driver)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .map(str::to_owned)
}

/// The C/C++ family named by an `-x` value, split (`-x c++`) or glued
/// (`-xc++`) alike. `None` for a value this evidence hierarchy does not
/// classify, such as `-x assembler`.
fn language_from_x_value(value: &str) -> Option<CompiledLanguage> {
    let family = value
        .strip_suffix("-header")
        .or_else(|| value.strip_suffix("-cpp-output"))
        .unwrap_or(value);
    match family {
        "c" => Some(CompiledLanguage::C),
        "c++" => Some(CompiledLanguage::Cpp),
        _ => None,
    }
}

fn argument_path(directory: &Path, raw: &str) -> Option<PathBuf> {
    if raw.is_empty() {
        return None;
    }
    absolute_path(directory, Path::new(raw))
}

fn absolute_path(directory: &Path, path: &Path) -> Option<PathBuf> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        directory.join(path)
    }
    .normalize();
    path.is_absolute().then_some(path)
}

/// Canonicalize an existing path, or canonicalize its nearest existing
/// ancestor and append the missing tail. The latter is required for stale
/// generated entries, whose source path is precisely the path that does not
/// exist. Keeping the operation component-based also preserves platform
/// prefixes and avoids string path identity.
fn canonical_or_normalized_path(path: &Path) -> PathBuf {
    let path = path.to_path_buf().normalize();
    let mut missing_tail: Vec<OsString> = Vec::new();
    let mut current = path.as_path();
    loop {
        if let Ok(canonical) = current.canonicalize() {
            let mut result = canonical.normalize();
            for component in missing_tail.iter().rev() {
                result.push(component);
            }
            return result.normalize();
        }
        let Some(name) = current.file_name() else {
            return path;
        };
        missing_tail.push(name.to_owned());
        let Some(parent) = current.parent() else {
            return path;
        };
        current = parent;
    }
}

fn macro_name(definition: &str) -> Option<String> {
    let end = definition.find('=').unwrap_or(definition.len());
    let name = &definition[..end];
    (!name.is_empty()).then(|| name.to_string())
}

/// Pins one compile database while borrowing a source file's configurations.
#[derive(Debug, Clone)]
pub struct CppCompileContextView {
    contexts: std::sync::Arc<CppCompileContexts>,
    source: PathBuf,
}
impl std::ops::Deref for CppCompileContextView {
    type Target = [CppCompileContext];
    fn deref(&self) -> &Self::Target {
        self.contexts
            .by_source
            .get(&self.source)
            .map_or(&[], Vec::as_slice)
    }
}
impl CppCompileContexts {
    pub fn shared_contexts_for(
        self: &std::sync::Arc<Self>,
        file: &ProjectFile,
    ) -> CppCompileContextView {
        CppCompileContextView {
            contexts: std::sync::Arc::clone(self),
            source: canonical_or_normalized_path(&file.abs_path()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CompiledLanguage, CppCompileContexts, CppExternalIncludeResolution};
    use brokk_bifrost_core::analyzer::project::{FilesystemProject, Project, TestProject};
    use brokk_bifrost_core::analyzer::{Language, ProjectFile};
    use brokk_bifrost_test_macros::hardwon;
    use std::path::{Path, PathBuf};

    /// Parses one argument vector into a compile context the same way
    /// [`super::CompilationDatabaseEntry::compile_context`] does, without a
    /// project or a `compile_commands.json` fixture.
    fn context(arguments: &[&str]) -> super::CppCompileContext {
        let arguments = arguments
            .iter()
            .map(|argument| argument.to_string())
            .collect::<Vec<_>>();
        super::parse_compile_arguments(Path::new("/workspace"), &arguments)
            .expect("non-empty argument vector parses")
    }

    fn project_with_database(database: Option<&str>) -> (tempfile::TempDir, TestProject) {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), "src/main.cpp")
            .write("int main() { return 0; }")
            .expect("source");
        if let Some(database) = database {
            ProjectFile::new(root.clone(), "compile_commands.json")
                .write(database)
                .expect("database");
        }
        (temp, TestProject::new(root, Language::Cpp))
    }

    #[test]
    fn arguments_entry_collects_include_paths_and_macro_names() {
        let (_temp, project) = project_with_database(Some(
            r#"[{"directory":".","file":"src/main.cpp","arguments":["clang++","-I","include","-iquotequotes","-isystem","system-include","-DDEBUG=1","-D","FEATURE=a=b","-c","src/main.cpp"]}]"#,
        ));
        let file = ProjectFile::new(project.root_path().to_path_buf(), "src/main.cpp");
        let contexts = CppCompileContexts::load(&project);
        let [context] = contexts.contexts_for(&file) else {
            panic!("one matching context");
        };

        assert_eq!(
            vec![
                project.root_path().join("include"),
                project.root_path().join("quotes"),
            ],
            context.project_include_roots
        );
        assert_eq!(
            vec![project.root_path().join("system-include")],
            context.system_include_roots
        );
        assert!(context.defined_macros.contains("DEBUG"));
        assert!(context.defined_macros.contains("FEATURE"));
        assert!(!context.defined_macros.contains("FEATURE=a"));
    }

    #[test]
    fn quoted_command_entry_is_tokenized_without_executing_it() {
        let (_temp, project) = project_with_database(Some(
            r#"[{"directory":".","file":"src/main.cpp","command":"clang++ -I 'project include' -DNAME=\\\"two words\\\" -c src/main.cpp"}]"#,
        ));
        let file = ProjectFile::new(project.root_path().to_path_buf(), "src/main.cpp");
        let contexts = CppCompileContexts::load(&project);
        let [context] = contexts.contexts_for(&file) else {
            panic!("one matching context");
        };

        assert_eq!(
            vec![project.root_path().join("project include")],
            context.project_include_roots
        );
        assert!(context.defined_macros.contains("NAME"));
    }

    #[test]
    #[hardwon("#2011: conditional C visibility ignored command-order macro state")]
    fn undefine_flags_apply_in_command_order() {
        let context = context(&[
            "cc",
            "-DKEPT",
            "-DCANCELLED",
            "-U",
            "CANCELLED",
            "-UREVIVED",
            "-DREVIVED",
            "-UNEVER_DEFINED",
        ]);
        assert!(context.defined_macros.contains("KEPT"));
        assert!(context.defined_macros.contains("REVIVED"));
        assert!(!context.defined_macros.contains("CANCELLED"));
        assert!(!context.defined_macros.contains("NEVER_DEFINED"));
        assert!(!context.cplusplus_macro_configured);
        for flags in [
            vec!["c++", "-U__cplusplus"],
            vec!["c++", "-U", "__cplusplus"],
            vec!["c++", "-D__cplusplus=1", "-U__cplusplus"],
            vec!["c++", "-U__cplusplus", "-D", "__cplusplus=1"],
        ] {
            let configured = super::parse_compile_arguments(
                Path::new("."),
                &flags
                    .iter()
                    .map(|flag| (*flag).to_string())
                    .collect::<Vec<_>>(),
            )
            .expect("compiler flags");
            assert!(configured.cplusplus_macro_configured, "{flags:?}");
            assert_eq!(
                configured.defined_macros.contains("__cplusplus"),
                flags.last() == Some(&"__cplusplus=1"),
                "{flags:?}"
            );
        }
    }

    #[test]
    fn a_file_compiled_in_two_configurations_keeps_both() {
        let (_temp, project) = project_with_database(Some(
            r#"[
                {"directory":".","file":"src/main.cpp","arguments":["clang++","-c","src/main.cpp"]},
                {"directory":".","file":"src/main.cpp","arguments":["clang++","-DOTHER","-c","src/main.cpp"]},
                {"directory":".","file":"src/other.cpp","arguments":["clang++","-c","src/other.cpp"]}
            ]"#,
        ));
        let file = ProjectFile::new(project.root_path().to_path_buf(), "src/main.cpp");
        let contexts = CppCompileContexts::load(&project);
        let candidates = contexts.contexts_for(&file);

        // Before #1627 a second entry deleted the first and the file lost its
        // context entirely, which read downstream as "never compiled".
        assert_eq!(2, candidates.len());
        assert!(candidates[0].defined_macros.is_empty());
        assert!(candidates[1].defined_macros.contains("OTHER"));
    }

    #[test]
    fn repeated_identical_entries_are_one_configuration() {
        let (_temp, project) = project_with_database(Some(
            r#"[
                {"directory":".","file":"src/main.cpp","arguments":["clang++","-I","include","-c","src/main.cpp"]},
                {"directory":".","file":"src/main.cpp","arguments":["clang++","-I","include","-c","src/main.cpp"]}
            ]"#,
        ));
        let file = ProjectFile::new(project.root_path().to_path_buf(), "src/main.cpp");
        let contexts = CppCompileContexts::load(&project);

        // Two entries that parse to the same flags are not a disagreement, so
        // the selection stays unambiguous.
        assert_eq!(1, contexts.contexts_for(&file).len());
    }

    #[test]
    fn missing_workspace_sources_are_canonical_bounded_and_deterministic() {
        let (_temp, project) = project_with_database(None);
        let root = project.root_path().to_path_buf();
        ProjectFile::new(root.clone(), "src/present.cpp")
            .write("int present() { return 0; }")
            .expect("present source");
        ProjectFile::new(root.clone(), "src/present.c")
            .write("int present_c(void) { return 0; }")
            .expect("present C source");
        ProjectFile::new(root.clone(), "include/present.hin")
            .write("int generated_declaration(void);")
            .expect("present C header template");

        let mut entries = vec![serde_json::json!({
            "directory": ".",
            "file": "src/./present.cpp",
            "arguments": ["clang++", "-c", "src/present.cpp"]
        })];
        entries.push(serde_json::json!({
            "directory": ".",
            "file": "src/present.c",
            "arguments": ["clang", "-c", "src/present.c"]
        }));
        entries.push(serde_json::json!({
            "directory": ".",
            "file": "include/present.hin",
            "arguments": ["clang", "-x", "c-header", "include/present.hin"]
        }));
        entries.extend(
            (0..(super::MAX_MISSING_WORKSPACE_SOURCE_SAMPLE + 3)).map(|index| {
                serde_json::json!({
                    "directory": ".",
                    "file": format!("generated/./unit-{index:02}.cpp"),
                    "arguments": ["clang++", "-c", format!("generated/unit-{index:02}.cpp")]
                })
            }),
        );
        // This duplicate resolves to the same canonical path and must not
        // inflate the exact count or change the sample.
        entries.push(serde_json::json!({
            "directory": "generated",
            "file": "../generated/unit-00.cpp",
            "arguments": ["clang++", "-c", "../generated/unit-00.cpp"]
        }));
        ProjectFile::new(root.clone(), "compile_commands.json")
            .write(serde_json::to_string(&entries).expect("database JSON"))
            .expect("database");

        let contexts = CppCompileContexts::load(&project);
        let listed = project
            .analyzable_files(Language::Cpp)
            .expect("C++ listing");
        let coverage = contexts.missing_workspace_sources(&root, &listed);

        assert_eq!(
            super::MAX_MISSING_WORKSPACE_SOURCE_SAMPLE + 3,
            coverage.missing_workspace_source_count()
        );
        assert_eq!(
            (0..super::MAX_MISSING_WORKSPACE_SOURCE_SAMPLE)
                .map(|index| Path::new("generated").join(format!("unit-{index:02}.cpp")))
                .collect::<Vec<_>>(),
            coverage.missing_workspace_source_sample()
        );
        assert!(
            !coverage
                .missing_workspace_source_sample()
                .contains(&PathBuf::from("src/present.cpp"))
        );

        let reversed = entries.into_iter().rev().collect::<Vec<_>>();
        ProjectFile::new(root.clone(), "compile_commands.json")
            .write(serde_json::to_string(&reversed).expect("reversed database JSON"))
            .expect("reversed database");
        let reversed_coverage =
            CppCompileContexts::load(&project).missing_workspace_sources(&root, &listed);
        assert_eq!(coverage, reversed_coverage);
    }

    #[test]
    fn missing_workspace_sources_excludes_outside_root_and_ignored_files() {
        let temp = tempfile::tempdir().expect("workspace root");
        let root = temp.path().canonicalize().expect("canonical root");
        let outside = tempfile::tempdir().expect("outside root");
        let outside_source = outside
            .path()
            .canonicalize()
            .expect("canonical outside root")
            .join("outside.cpp")
            .to_string_lossy()
            .into_owned();
        ProjectFile::new(root.clone(), "src/present.cpp")
            .write("int present() { return 0; }")
            .expect("present source");
        ProjectFile::new(root.clone(), "ignored.cpp")
            .write("int ignored() { return 0; }")
            .expect("ignored source");
        ProjectFile::new(root.clone(), ".bifrostignore")
            .write("ignored.cpp\n")
            .expect("ignore file");
        let database = serde_json::json!([
            {
                "directory": ".",
                "file": "src/../src/present.cpp",
                "arguments": ["clang++", "-c", "src/present.cpp"]
            },
            {
                "directory": ".",
                "file": "ignored.cpp",
                "arguments": ["clang++", "-c", "ignored.cpp"]
            },
            {
                "directory": ".",
                "file": outside_source.clone(),
                "arguments": ["clang++", "-c", outside_source]
            }
        ]);
        ProjectFile::new(root.clone(), "compile_commands.json")
            .write(database.to_string())
            .expect("database");
        let project = FilesystemProject::new(root.clone()).expect("filesystem project");
        let listed = project
            .analyzable_files(Language::Cpp)
            .expect("C++ listing");
        assert!(
            listed
                .iter()
                .any(|file| file.rel_path() == Path::new("src/present.cpp"))
        );
        assert!(
            !listed
                .iter()
                .any(|file| file.rel_path() == Path::new("ignored.cpp"))
        );

        let coverage = CppCompileContexts::load(&project).missing_workspace_sources(&root, &listed);
        assert_eq!(1, coverage.missing_workspace_source_count());
        assert_eq!(
            &[PathBuf::from("ignored.cpp")],
            coverage.missing_workspace_source_sample()
        );
    }

    #[test]
    fn a_quoted_include_checks_the_including_directory_before_external_roots() {
        let external = tempfile::tempdir().expect("external root");
        let external_root = external
            .path()
            .canonicalize()
            .expect("canonical external root");
        std::fs::write(external_root.join("vendor.hpp"), "class External {};\n")
            .expect("external vendor header");
        std::fs::write(external_root.join("from-search.hpp"), "class Search {};\n")
            .expect("external search header");
        let database = serde_json::json!([{
            "directory": ".",
            "file": "src/main.cpp",
            "arguments": [
                "clang++",
                "-I",
                external_root,
                "-c",
                "src/main.cpp"
            ]
        }])
        .to_string();
        let (_temp, project) = project_with_database(Some(&database));
        let file = ProjectFile::new(project.root_path().to_path_buf(), "src/main.cpp");
        let source_path = file.abs_path();
        let source_directory = source_path.parent().expect("source directory");
        std::fs::create_dir_all(source_directory).expect("source directory");
        std::fs::write(source_directory.join("vendor.hpp"), "class Local {};\n")
            .expect("local vendor header");
        let contexts = CppCompileContexts::load(&project);

        assert_eq!(
            CppExternalIncludeResolution::Undeclared,
            contexts.resolve_external_include(
                &file,
                &file.abs_path(),
                std::path::Path::new("vendor.hpp"),
                true,
            )
        );
        assert!(matches!(
            contexts.resolve_external_include(
                &file,
                &file.abs_path(),
                std::path::Path::new("from-search.hpp"),
                true,
            ),
            CppExternalIncludeResolution::Declared { .. }
        ));
        assert!(matches!(
            contexts.resolve_external_include(
                &file,
                &file.abs_path(),
                std::path::Path::new("vendor.hpp"),
                false,
            ),
            CppExternalIncludeResolution::Declared { .. }
        ));
    }

    #[test]
    fn configurations_must_agree_on_the_external_header() {
        let first = tempfile::tempdir().expect("first root");
        let second = tempfile::tempdir().expect("second root");
        let first = first.path().canonicalize().expect("canonical first root");
        let second = second.path().canonicalize().expect("canonical second root");
        std::fs::write(first.join("vector"), "namespace std { class vector {}; }")
            .expect("first header");
        std::fs::write(second.join("vector"), "namespace std { class vector {}; }")
            .expect("second header");
        let database = serde_json::json!([
            {
                "directory": ".",
                "file": "src/main.cpp",
                "arguments": ["clang++", "-isystem", first, "-c", "src/main.cpp"]
            },
            {
                "directory": ".",
                "file": "src/main.cpp",
                "arguments": ["clang++", "-isystem", second, "-c", "src/main.cpp"]
            }
        ])
        .to_string();
        let (_temp, project) = project_with_database(Some(&database));
        let file = ProjectFile::new(project.root_path().to_path_buf(), "src/main.cpp");

        assert_eq!(
            CppExternalIncludeResolution::Conflicting,
            CppCompileContexts::load(&project)
                .resolve_external_angle_include(&file, std::path::Path::new("vector"))
        );
    }

    #[test]
    fn external_include_cannot_escape_its_declared_root() {
        let external = tempfile::tempdir().expect("external root");
        let root = external.path().canonicalize().expect("canonical root");
        std::fs::create_dir_all(root.join("include")).expect("include directory");
        std::fs::write(root.join("outside.hpp"), "class Outside {};").expect("outside header");
        let database = serde_json::json!([{
            "directory": ".",
            "file": "src/main.cpp",
            "arguments": [
                "clang++",
                "-isystem",
                root.join("include"),
                "-c",
                "src/main.cpp"
            ]
        }])
        .to_string();
        let (_temp, project) = project_with_database(Some(&database));
        let file = ProjectFile::new(project.root_path().to_path_buf(), "src/main.cpp");

        assert_eq!(
            CppExternalIncludeResolution::Undeclared,
            CppCompileContexts::load(&project)
                .resolve_external_angle_include(&file, std::path::Path::new("../outside.hpp"))
        );
        assert_eq!(
            CppExternalIncludeResolution::Undeclared,
            CppCompileContexts::load(&project)
                .resolve_external_angle_include(&file, &root.join("outside.hpp"))
        );
    }

    #[test]
    fn msvc_project_and_system_include_flags_preserve_search_order() {
        let (_temp, project) = project_with_database(Some(
            r#"[{"directory":".","file":"src/main.cpp","arguments":["cl.exe","/I","vendor/include","/external:Ifake-system/include","/imsvc","toolchain/include","/c","src/main.cpp"]}]"#,
        ));
        let file = ProjectFile::new(project.root_path().to_path_buf(), "src/main.cpp");
        let contexts = CppCompileContexts::load(&project);
        let [context] = contexts.contexts_for(&file) else {
            panic!("one MSVC compile context");
        };

        assert_eq!(1, context.project_include_roots.len());
        assert_eq!(2, context.system_include_roots.len());
    }

    #[test]
    fn driver_basename_ending_in_plus_plus_selects_cpp_over_a_c_extension() {
        let cx = context(&["clang++", "-c", "file.c"]);
        assert_eq!(CompiledLanguage::Cpp, cx.tu_language(Path::new("file.c")));

        // A driver that does not end in `++` (even a cross-compiler prefix
        // form) falls through to extension evidence.
        let cx = context(&["arm-none-eabi-gcc", "-c", "file.c"]);
        assert_eq!(CompiledLanguage::C, cx.tu_language(Path::new("file.c")));

        // Prefixed driver names ending in `++` are still recognized.
        let cx = context(&["arm-none-eabi-g++", "-c", "file.h"]);
        assert_eq!(CompiledLanguage::Cpp, cx.tu_language(Path::new("file.h")));
    }

    #[test]
    fn driver_exe_suffix_is_stripped_before_the_plus_plus_check() {
        let cx = context(&["clang++.exe", "-c", "file.c"]);
        assert_eq!(CompiledLanguage::Cpp, cx.tu_language(Path::new("file.c")));
    }

    #[test]
    fn std_family_outranks_the_driver_basename() {
        // -std outranks the driver: a g++ invocation pinned to a C standard
        // compiles as C even though the driver name ends in `++`.
        let cx = context(&["g++", "-std=gnu11", "-c", "file.c"]);
        assert_eq!(CompiledLanguage::C, cx.tu_language(Path::new("file.c")));

        let cx = context(&["gcc", "-std=c++17", "-c", "file.cc"]);
        assert_eq!(CompiledLanguage::Cpp, cx.tu_language(Path::new("file.cc")));

        let cx = context(&["gcc", "-std=c17", "-c", "file.cc"]);
        assert_eq!(CompiledLanguage::C, cx.tu_language(Path::new("file.cc")));

        let cx = context(&["gcc", "-std=gnu++20", "-c", "file.c"]);
        assert_eq!(CompiledLanguage::Cpp, cx.tu_language(Path::new("file.c")));
    }

    #[test]
    fn explicit_x_split_form_outranks_std_and_driver() {
        let cx = context(&["clang", "-x", "c", "-std=c++17", "-c", "file.cpp"]);
        assert_eq!(CompiledLanguage::C, cx.tu_language(Path::new("file.cpp")));
    }

    #[test]
    fn explicit_x_glued_form_is_recognized() {
        let cx = context(&["gcc", "-xc++", "-c", "file.c"]);
        assert_eq!(CompiledLanguage::Cpp, cx.tu_language(Path::new("file.c")));

        let cx = context(&["g++", "-xc", "-c", "file.cpp"]);
        assert_eq!(CompiledLanguage::C, cx.tu_language(Path::new("file.cpp")));
    }

    #[test]
    fn explicit_x_on_a_c_file_overrides_the_extension() {
        // The precedence example from the ExecPlan: `-x c++` on a `.c` file
        // compiles as C++.
        let cx = context(&["gcc", "-x", "c++", "-c", "file.c"]);
        assert_eq!(CompiledLanguage::Cpp, cx.tu_language(Path::new("file.c")));
    }

    #[test]
    fn msvc_tc_and_tp_force_the_language_regardless_of_extension() {
        let cx = context(&["cl.exe", "/TC", "/c", "file.cpp"]);
        assert_eq!(CompiledLanguage::C, cx.tu_language(Path::new("file.cpp")));

        let cx = context(&["cl.exe", "/TP", "/c", "file.c"]);
        assert_eq!(CompiledLanguage::Cpp, cx.tu_language(Path::new("file.c")));
    }

    #[test]
    fn missing_or_malformed_database_has_no_context() {
        let (_temp, project) = project_with_database(None);
        let file = ProjectFile::new(project.root_path().to_path_buf(), "src/main.cpp");
        assert!(
            CppCompileContexts::load(&project)
                .contexts_for(&file)
                .is_empty()
        );

        let (_temp, project) = project_with_database(Some("not json"));
        let file = ProjectFile::new(project.root_path().to_path_buf(), "src/main.cpp");
        assert!(
            CppCompileContexts::load(&project)
                .contexts_for(&file)
                .is_empty()
        );
    }

    #[test]
    fn an_explicit_system_root_declares_an_angle_include() {
        let (_temp, project) = project_with_database(Some(
            r#"[{"directory":".","file":"src/main.cpp","arguments":["clang++","-isystem","fake-system/include","-c","src/main.cpp"]}]"#,
        ));
        let header = ProjectFile::new(
            project.root_path().to_path_buf(),
            "fake-system/include/vector",
        );
        header
            .write("namespace std { class vector {}; }")
            .expect("header");
        let file = ProjectFile::new(project.root_path().to_path_buf(), "src/main.cpp");

        assert_eq!(
            CppExternalIncludeResolution::Declared {
                root: project
                    .root_path()
                    .join("fake-system/include")
                    .canonicalize()
                    .expect("canonical root"),
                header: header.abs_path().canonicalize().expect("canonical header"),
            },
            CppCompileContexts::load(&project)
                .resolve_external_angle_include(&file, std::path::Path::new("vector"))
        );
    }

    #[test]
    fn an_external_project_root_declares_but_a_workspace_project_root_does_not() {
        let external = tempfile::tempdir().expect("external root");
        let external_root = external
            .path()
            .canonicalize()
            .expect("canonical external root");
        std::fs::write(external_root.join("vendor.hpp"), "class Vendor {};")
            .expect("external header");
        let database = serde_json::json!([{
            "directory": ".",
            "file": "src/main.cpp",
            "arguments": [
                "clang++",
                "-I",
                external_root,
                "-I",
                "include",
                "-c",
                "src/main.cpp"
            ]
        }])
        .to_string();
        let (_temp, project) = project_with_database(Some(&database));
        ProjectFile::new(project.root_path().to_path_buf(), "include/local.hpp")
            .write("class Local {};")
            .expect("local header");
        let file = ProjectFile::new(project.root_path().to_path_buf(), "src/main.cpp");
        let contexts = CppCompileContexts::load(&project);

        assert!(matches!(
            contexts.resolve_external_angle_include(&file, std::path::Path::new("vendor.hpp")),
            CppExternalIncludeResolution::Declared { .. }
        ));
        assert_eq!(
            CppExternalIncludeResolution::Undeclared,
            contexts.resolve_external_angle_include(&file, std::path::Path::new("local.hpp"))
        );
    }

    #[test]
    fn default_by_extension_c_is_c_and_everything_else_is_cpp() {
        let cx = context(&["cc", "-c", "file.c"]);
        assert_eq!(CompiledLanguage::C, cx.tu_language(Path::new("file.c")));

        let cx = context(&["cc", "-c", "file.cc"]);
        assert_eq!(CompiledLanguage::Cpp, cx.tu_language(Path::new("file.cc")));
        assert_eq!(CompiledLanguage::Cpp, cx.tu_language(Path::new("file.hpp")));
        let cx = context(&["cl.exe", "/c", "file.c"]);
        assert_eq!(CompiledLanguage::C, cx.tu_language(Path::new("file.c")));

        let cx = context(&["cl.exe", "/c", "file.cpp"]);
        assert_eq!(CompiledLanguage::Cpp, cx.tu_language(Path::new("file.cpp")));
    }

    #[test]
    #[hardwon("#6929: a Windows verbatim prefix made an in-workspace sibling external")]
    fn quoted_sibling_external_header_respects_workspace_boundary() {
        // Filesystem identity is the oracle: quoted lookup first chooses a
        // sibling; only a sibling outside the workspace belongs to this API.
        let outer = tempfile::tempdir().unwrap();
        let outer_root = outer.path().canonicalize().unwrap();
        let workspace = outer_root.join("workspace");
        let external = outer_root.join("external");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&external).unwrap();
        for directory in [&workspace, &external] {
            std::fs::write(directory.join("caller.hpp"), "#include \"sibling.hpp\"\n").unwrap();
            std::fs::write(directory.join("sibling.hpp"), "struct S {};\n").unwrap();
        }
        // A declared root can contain the workspace; it still must not turn
        // an in-workspace sibling into an external artifact.
        let cx = super::parse_compile_arguments(
            &workspace,
            &[
                "clang++".into(),
                "-I".into(),
                outer_root.to_string_lossy().into_owned(),
            ],
        )
        .unwrap();
        assert_eq!(
            cx.resolve_external_include(
                &workspace,
                &workspace.join("caller.hpp"),
                Path::new("sibling.hpp"),
                true
            ),
            None
        );
        assert_eq!(
            cx.resolve_external_include(
                &workspace,
                &external.join("caller.hpp"),
                Path::new("sibling.hpp"),
                true
            ),
            Some((outer_root, external.join("sibling.hpp")))
        );
    }
}
