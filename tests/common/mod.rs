mod inline_project;
pub mod lsp_click;
pub mod lsp_client;
pub mod semantic_graph;
pub mod usage_graph;

use brokk_bifrost::{
    CodeUnit, GoAnalyzer, IAnalyzer, Language, ProjectFile, RubyAnalyzer, SearchToolsService,
    TestProject,
};
use pretty_assertions::assert_eq;
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex};
static SEARCH_TOOL_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
use tempfile::TempDir;

#[allow(dead_code)]
pub fn copy_fixture_to_temp(name: &str) -> TempDir {
    let temp = TempDir::new().unwrap();
    copy_dir_recursively(&fixture_root(name), temp.path()).unwrap();
    temp
}

#[allow(dead_code)]
fn fixture_root(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn copy_dir_recursively(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let target = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_recursively(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

#[allow(unused_imports)]
pub use inline_project::{BuiltInlineTestProject, InlineTestProject};

#[allow(dead_code)]
pub fn line_of(source: &str, needle: &str) -> usize {
    source
        .lines()
        .position(|line| line.contains(needle))
        .map(|line| line + 1)
        .unwrap_or_else(|| panic!("missing line containing {needle:?}"))
}

#[allow(dead_code)]
pub const RUST_ASSOCIATED_PATH_MAIN: &str = r#"
pub mod state;

use state::AppState;

pub struct Repositories;
pub struct Environment;
pub struct Router;

fn app_with_state(_state: AppState) -> Router {
    Router
}

fn app_with_environment(repositories: Repositories, environment: Environment) -> Router {
    let _ = state::AppState::with_environment(Repositories, Environment);
    app_with_state(AppState::with_environment(repositories, environment))
}
"#;

#[allow(dead_code)]
pub const RUST_ASSOCIATED_PATH_STATE: &str = r#"
use crate::{Environment, Repositories};

pub struct AppState;

impl AppState {
    pub fn with_environment(_repositories: Repositories, _environment: Environment) -> Self {
        Self
    }
}
"#;

#[allow(dead_code)]
pub fn js_fixture_project() -> TestProject {
    TestProject::new(
        std::fs::canonicalize("tests/fixtures/testcode-js").unwrap(),
        Language::JavaScript,
    )
}

#[allow(dead_code)]
pub fn ts_fixture_project() -> TestProject {
    TestProject::new(
        std::fs::canonicalize("tests/fixtures/testcode-ts").unwrap(),
        Language::TypeScript,
    )
}

#[allow(dead_code)]
pub fn py_fixture_project() -> TestProject {
    TestProject::new(
        std::fs::canonicalize("tests/fixtures/testcode-py").unwrap(),
        Language::Python,
    )
}

#[allow(dead_code)]
pub fn cpp_fixture_project() -> TestProject {
    TestProject::new(
        std::fs::canonicalize("tests/fixtures/testcode-cpp").unwrap(),
        Language::Cpp,
    )
}

#[allow(dead_code)]
pub fn csharp_fixture_project() -> TestProject {
    TestProject::new(
        std::fs::canonicalize("tests/fixtures/testcode-cs").unwrap(),
        Language::CSharp,
    )
}

#[allow(dead_code)]
pub fn csharp_nested_partial_cacheinfo_project() -> InlineTestProject {
    InlineTestProject::with_language(Language::CSharp)
        .file("Mapper.CacheInfo.cs", CSHARP_NESTED_PARTIAL_CACHEINFO)
        .file("Mapper.cs", CSHARP_NESTED_PARTIAL_MAPPER)
}

#[allow(dead_code)]
pub const CSHARP_NESTED_PARTIAL_CACHEINFO: &str = r#"
namespace Dapper {
    public static partial class SqlMapper {
        private sealed class CacheInfo {}
    }
}
"#;

#[allow(dead_code)]
pub const CSHARP_NESTED_PARTIAL_MAPPER: &str = r#"
namespace Dapper {
    public static partial class SqlMapper {
        private static CacheInfo GetCacheInfo() {
            CacheInfo? info = null;
            info = new CacheInfo();
            return info;
        }
    }
}
"#;

#[allow(dead_code)]
pub fn php_fixture_project() -> TestProject {
    TestProject::new(
        std::fs::canonicalize("tests/fixtures/testcode-php").unwrap(),
        Language::Php,
    )
}

#[allow(dead_code)]
pub fn go_fixture_project() -> TestProject {
    TestProject::new(
        std::fs::canonicalize("tests/fixtures/testcode-go").unwrap(),
        Language::Go,
    )
}

#[allow(dead_code)]
pub fn go_analyzer_with_files(files: &[(&str, &str)]) -> (BuiltInlineTestProject, GoAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::Go);
    if !files.iter().any(|(path, _)| *path == "go.mod") {
        builder = builder.file("go.mod", "module example.com/app\n\ngo 1.22\n");
    }
    for (path, contents) in files {
        builder = builder.file(*path, *contents);
    }
    let project = builder.build();
    let analyzer = GoAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

#[allow(dead_code)]
pub fn ruby_analyzer_with_files(files: &[(&str, &str)]) -> (BuiltInlineTestProject, RubyAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::Ruby);
    for (path, contents) in files {
        builder = builder.file(*path, *contents);
    }
    let project = builder.build();
    let analyzer = RubyAnalyzer::new(project.project_dyn());
    (project, analyzer)
}

#[allow(dead_code)]
pub fn assert_code_eq(expected: &str, actual: &str) {
    assert_eq!(normalize_code(expected), normalize_code(actual));
}

#[allow(dead_code)]
pub fn assert_linewise_eq(expected: &str, actual: &str) {
    assert_eq!(
        normalize_nonempty_lines(expected),
        normalize_nonempty_lines(actual)
    );
}

#[allow(dead_code)]
pub fn call_search_tool_json(root: &Path, tool: &str, args: &str) -> Value {
    let _guard = SEARCH_TOOL_LOCK.lock().expect("search tool lock poisoned");
    let service = SearchToolsService::new_manual_without_semantic_index(root.to_path_buf())
        .unwrap_or_else(|err| panic!("failed to build searchtools service for {tool}: {err}"));
    let payload = service
        .call_tool_json(tool, args)
        .unwrap_or_else(|err| panic!("{tool} call failed: {err}"));
    serde_json::from_str(&payload)
        .unwrap_or_else(|err| panic!("{tool} returned invalid JSON: {err}"))
}

#[allow(dead_code)]
pub fn normalize_code(value: &str) -> String {
    let normalized = normalize_line_endings(value);
    let lines: Vec<_> = normalized.lines().collect();
    let start = lines
        .iter()
        .position(|line| !line.trim().is_empty())
        .unwrap_or(0);
    let end = lines
        .iter()
        .rposition(|line| !line.trim().is_empty())
        .map(|index| index + 1)
        .unwrap_or(start);
    let slice = &lines[start..end];
    let indent = slice
        .iter()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            line.chars()
                .take_while(|ch| *ch == ' ' || *ch == '\t')
                .count()
        })
        .min()
        .unwrap_or(0);
    slice
        .iter()
        .map(|line| line.chars().skip(indent).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
}

#[allow(dead_code)]
pub fn normalize_nonempty_lines(value: &str) -> String {
    normalize_line_endings(value)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

#[allow(dead_code)]
pub fn normalize_line_endings(value: &str) -> String {
    value.replace("\r\n", "\n").replace('\r', "\n")
}

#[allow(dead_code)]
pub fn write_file(root: &Path, rel_path: &str, contents: &str) -> ProjectFile {
    let file = ProjectFile::new(root.to_path_buf(), rel_path);
    file.write(contents).unwrap();
    file
}

#[allow(dead_code)]
pub fn definition<A: IAnalyzer>(analyzer: &A, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
}
