mod common;

use brokk_bifrost::analyzer::{StructuredImportPath, StructuredImportPathKind};
use brokk_bifrost::{ImportAnalysisProvider, ImportInfo, Language, PythonAnalyzer};
use common::InlineTestProject;

fn import_info(
    raw_snippet: &str,
    identifier: Option<&str>,
    path: &[&str],
    kind: StructuredImportPathKind,
) -> ImportInfo {
    ImportInfo {
        raw_snippet: raw_snippet.to_string(),
        is_wildcard: false,
        identifier: identifier.map(str::to_string),
        alias: None,
        path: Some(StructuredImportPath {
            segments: path.iter().map(|segment| (*segment).to_string()).collect(),
            kind: Some(kind),
            lexical_prefixes: Vec::new(),
            lexical_scopes: Vec::new(),
            declaration_start_byte: 0,
        }),
    }
}

#[test]
fn test_could_import_file_relative_parent_import() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("pkg/sub/module.py", "from .. import utils")
        .file("pkg/utils.py", "def some_fn(): pass")
        .build();
    let source = project.file("pkg/sub/module.py");
    let target = project.file("pkg/utils.py");
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let import = import_info(
        "from .. import utils",
        Some("utils"),
        &["..", "utils"],
        StructuredImportPathKind::ImportFrom,
    );
    assert!(analyzer.could_import_file(&source, &[import], &target));
}

#[test]
fn test_could_import_file_relative_parent_module_import() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("pkg/sub/module.py", "from ..other import something")
        .file("pkg/other.py", "something = 1")
        .build();
    let source = project.file("pkg/sub/module.py");
    let target = project.file("pkg/other.py");
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let import = import_info(
        "from ..other import something",
        Some("something"),
        &["..other", "something"],
        StructuredImportPathKind::ImportFrom,
    );
    assert!(analyzer.could_import_file(&source, &[import], &target));
}

#[test]
fn test_could_import_file_invalid_relative_import_conservative_return() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("pkg/module.py", "from ... import utils")
        .file("some_other.py", "")
        .build();
    let source = project.file("pkg/module.py");
    let target = project.file("some_other.py");
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let import = import_info(
        "from ... import utils",
        Some("utils"),
        &["...", "utils"],
        StructuredImportPathKind::ImportFrom,
    );
    assert!(analyzer.could_import_file(&source, &[import], &target));
}

#[test]
fn test_could_import_file_negative_match() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("pkg/module.py", "import unrelated")
        .file("pkg/target.py", "")
        .build();
    let source = project.file("pkg/module.py");
    let target = project.file("pkg/target.py");
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let import = import_info(
        "import unrelated",
        Some("unrelated"),
        &["unrelated"],
        StructuredImportPathKind::Namespace,
    );
    assert!(!analyzer.could_import_file(&source, &[import], &target));
}
