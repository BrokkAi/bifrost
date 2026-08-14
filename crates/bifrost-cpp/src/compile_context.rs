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
use std::path::{Component, Path, PathBuf};

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
    include_search_roots: Vec<CppIncludeSearchRoot>,
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

#[derive(Debug, Default)]
pub struct CppCompileContexts {
    by_source: HashMap<PathBuf, Vec<CppCompileContext>>,
}

impl CppCompileContexts {
    pub fn load(project: &dyn Project) -> Self {
        let database_path = project.root().join("compile_commands.json");
        let Ok(database) = std::fs::read_to_string(database_path) else {
            return Self::default();
        };
        let Ok(entries) = serde_json::from_str::<Vec<CompilationDatabaseEntry>>(&database) else {
            return Self::default();
        };

        let mut by_source: HashMap<PathBuf, Vec<CppCompileContext>> = HashMap::default();
        for entry in entries {
            let Some(source) = entry.source_path(project.root()) else {
                continue;
            };
            if !source.starts_with(project.root()) {
                continue;
            }
            let Some(context) = entry.compile_context(project.root()) else {
                continue;
            };
            // A build that compiles one file in several configurations records
            // one entry per configuration. Keeping every distinct one lets the
            // caller decide per name whether the configurations agree; dropping
            // them would make "compiled two ways" look like "never compiled".
            // Entries that parse to the same context are one configuration.
            let candidates = by_source.entry(source).or_default();
            if !candidates.contains(&context) {
                candidates.push(context);
            }
        }
        Self { by_source }
    }

    /// Every distinct compile configuration the database records for `file`,
    /// empty when no entry names it.
    ///
    /// Exactly one context is an unambiguous selection. More than one means the
    /// include closures can differ, so a name is absent only where every
    /// candidate agrees that it is.
    pub fn contexts_for(&self, file: &ProjectFile) -> &[CppCompileContext] {
        self.by_source
            .get(&file.abs_path().normalize())
            .map_or(&[], Vec::as_slice)
    }

    /// Resolve one angle include through explicit external roots in every
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
        let contexts = self.contexts_for(file);
        let Some(first_context) = contexts.first() else {
            return CppExternalIncludeResolution::MissingCompileContext;
        };
        let first = first_context.resolve_external_angle_include(file.root(), include);
        if contexts
            .iter()
            .skip(1)
            .any(|context| context.resolve_external_angle_include(file.root(), include) != first)
        {
            return CppExternalIncludeResolution::Conflicting;
        }
        match first {
            Some((root, header)) => CppExternalIncludeResolution::Declared { root, header },
            None => CppExternalIncludeResolution::Undeclared,
        }
    }

    /// Every distinct explicit root that can supply an external angle include.
    ///
    /// The result is sorted for deterministic dependency discovery. It is a
    /// source-set inventory, not proof that every compile configuration reaches
    /// every root; per-reference resolution must still use
    /// [`Self::resolve_external_angle_include`].
    pub fn external_angle_include_roots(&self, workspace_root: &Path) -> Vec<PathBuf> {
        let mut roots = self
            .by_source
            .values()
            .flatten()
            .flat_map(|context| context.external_angle_include_roots(workspace_root))
            .map(Path::to_path_buf)
            .collect::<Vec<_>>();
        roots.sort();
        roots.dedup();
        roots
    }
}

impl CppCompileContext {
    /// Explicit external roots in compiler search order for angle includes.
    pub fn external_angle_include_roots<'a>(
        &'a self,
        workspace_root: &'a Path,
    ) -> impl Iterator<Item = &'a Path> + 'a {
        self.include_search_roots.iter().filter_map(move |root| {
            (root.kind != CppIncludeSearchRootKind::Quote
                && (root.kind == CppIncludeSearchRootKind::System
                    || !root.path.starts_with(workspace_root)))
            .then_some(root.path.as_path())
        })
    }

    fn resolve_external_angle_include(
        &self,
        workspace_root: &Path,
        include: &Path,
    ) -> Option<(PathBuf, PathBuf)> {
        if include.is_absolute()
            || include
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return None;
        }
        self.external_angle_include_roots(workspace_root)
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

    let mut project_include_roots = Vec::new();
    let mut system_include_roots = Vec::new();
    let mut forced_includes = Vec::new();
    let mut defined_macros = HashSet::default();
    let mut include_search_roots = Vec::new();
    let mut index = 1;
    while index < arguments.len() {
        let argument = &arguments[index];
        match argument.as_str() {
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
                defined_macros.insert(macro_name(arguments.get(index + 1)?)?);
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
                    defined_macros.insert(macro_name(definition)?);
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
        include_search_roots,
    })
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

fn macro_name(definition: &str) -> Option<String> {
    let end = definition.find('=').unwrap_or(definition.len());
    let name = &definition[..end];
    (!name.is_empty()).then(|| name.to_string())
}

#[cfg(test)]
mod tests {
    use super::{CppCompileContexts, CppExternalIncludeResolution};
    use brokk_bifrost_core::analyzer::project::TestProject;
    use brokk_bifrost_core::analyzer::{Language, ProjectFile};

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
    fn arguments_entry_collects_include_paths_and_macro_names() {
        let (_temp, project) = project_with_database(Some(
            r#"[{"directory":".","file":"src/main.cpp","arguments":["clang++","-I","include","-iquotequotes","-isystem","system-include","-DDEBUG=1","-D","FEATURE","-c","src/main.cpp"]}]"#,
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
    fn an_unmatched_file_has_no_context() {
        let (_temp, project) = project_with_database(Some(
            r#"[{"directory":".","file":"src/other.cpp","arguments":["clang++","-c","src/other.cpp"]}]"#,
        ));
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
        let database = format!(
            r#"[{{"directory":".","file":"src/main.cpp","arguments":["clang++","-I","{}","-I","include","-c","src/main.cpp"]}}]"#,
            external_root.display()
        );
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
    fn configurations_must_agree_on_the_external_header() {
        let first = tempfile::tempdir().expect("first root");
        let second = tempfile::tempdir().expect("second root");
        let first = first.path().canonicalize().expect("canonical first root");
        let second = second.path().canonicalize().expect("canonical second root");
        std::fs::write(first.join("vector"), "namespace std { class vector {}; }")
            .expect("first header");
        std::fs::write(second.join("vector"), "namespace std { class vector {}; }")
            .expect("second header");
        let database = format!(
            r#"[
                {{"directory":".","file":"src/main.cpp","arguments":["clang++","-isystem","{}","-c","src/main.cpp"]}},
                {{"directory":".","file":"src/main.cpp","arguments":["clang++","-isystem","{}","-c","src/main.cpp"]}}
            ]"#,
            first.display(),
            second.display()
        );
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
        let database = format!(
            r#"[{{"directory":".","file":"src/main.cpp","arguments":["clang++","-isystem","{}","-c","src/main.cpp"]}}]"#,
            root.join("include").display()
        );
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
}
