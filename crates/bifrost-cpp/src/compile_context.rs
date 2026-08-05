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
use std::path::{Path, PathBuf};

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
}

#[derive(Debug, Default)]
pub struct CppCompileContexts {
    by_source: HashMap<PathBuf, CppCompileContext>,
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

        let mut by_source = HashMap::default();
        let mut ambiguous_sources = HashSet::default();
        for entry in entries {
            let Some(source) = entry.source_path(project.root()) else {
                continue;
            };
            if !source.starts_with(project.root()) || ambiguous_sources.contains(&source) {
                continue;
            }
            let Some(context) = entry.compile_context(project.root()) else {
                continue;
            };
            if by_source.insert(source.clone(), context).is_some() {
                by_source.remove(&source);
                ambiguous_sources.insert(source);
            }
        }
        Self { by_source }
    }

    pub fn for_file(&self, file: &ProjectFile) -> Option<&CppCompileContext> {
        self.by_source.get(&file.abs_path().normalize())
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
    let mut index = 1;
    while index < arguments.len() {
        let argument = &arguments[index];
        match argument.as_str() {
            "-I" => {
                project_include_roots.push(argument_path(directory, arguments.get(index + 1)?)?);
                index += 2;
            }
            "-iquote" => {
                project_include_roots.push(argument_path(directory, arguments.get(index + 1)?)?);
                index += 2;
            }
            "-isystem" => {
                system_include_roots.push(argument_path(directory, arguments.get(index + 1)?)?);
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
                if let Some(path) = argument.strip_prefix("-I") {
                    project_include_roots.push(argument_path(directory, path)?);
                } else if let Some(path) = argument.strip_prefix("-iquote") {
                    project_include_roots.push(argument_path(directory, path)?);
                } else if let Some(path) = argument.strip_prefix("-isystem") {
                    system_include_roots.push(argument_path(directory, path)?);
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
    use super::CppCompileContexts;
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
        assert!(CppCompileContexts::load(&project).for_file(&file).is_none());

        let (_temp, project) = project_with_database(Some("not json"));
        let file = ProjectFile::new(project.root_path().to_path_buf(), "src/main.cpp");
        assert!(CppCompileContexts::load(&project).for_file(&file).is_none());
    }

    #[test]
    fn arguments_entry_collects_include_paths_and_macro_names() {
        let (_temp, project) = project_with_database(Some(
            r#"[{"directory":".","file":"src/main.cpp","arguments":["clang++","-I","include","-iquotequotes","-isystem","system-include","-DDEBUG=1","-D","FEATURE","-c","src/main.cpp"]}]"#,
        ));
        let file = ProjectFile::new(project.root_path().to_path_buf(), "src/main.cpp");
        let contexts = CppCompileContexts::load(&project);
        let context = contexts.for_file(&file).expect("matching context");

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
        let context = contexts.for_file(&file).expect("matching context");

        assert_eq!(
            vec![project.root_path().join("project include")],
            context.project_include_roots
        );
        assert!(context.defined_macros.contains("NAME"));
    }

    #[test]
    fn duplicate_or_unmatched_entries_do_not_supply_context() {
        let (_temp, project) = project_with_database(Some(
            r#"[
                {"directory":".","file":"src/main.cpp","arguments":["clang++","-c","src/main.cpp"]},
                {"directory":".","file":"src/main.cpp","arguments":["clang++","-DOTHER","-c","src/main.cpp"]},
                {"directory":".","file":"src/other.cpp","arguments":["clang++","-c","src/other.cpp"]}
            ]"#,
        ));
        let file = ProjectFile::new(project.root_path().to_path_buf(), "src/main.cpp");
        assert!(CppCompileContexts::load(&project).for_file(&file).is_none());
    }
}
