use crate::common::InlineTestProject;
use brokk_bifrost::analyzer::{StructuredImportPath, StructuredImportPathKind};
use brokk_bifrost::{ImportAnalysisProvider, ImportInfo, Language, PythonAnalyzer};

fn import_info(
    raw_snippet: &str,
    identifier: Option<&str>,
    path: &[&str],
    kind: StructuredImportPathKind,
) -> ImportInfo {
    ImportInfo {
        raw_snippet: raw_snippet.to_string(),
        is_wildcard: false,
        is_global: false,
        identifier: identifier.map(str::to_string),
        alias: None,
        path: Some(StructuredImportPath {
            segments: path.iter().map(|segment| (*segment).to_string()).collect(),
            kind: Some(kind),
            lexical_prefixes: Vec::new(),
            lexical_scopes: Vec::new(),
            declaration_start_byte: 0,
        }),
        binder_span: None,
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

/// `imported_code_units_from_infos` must not lose a target when two of a file's imports bind the
/// same local name (a try/except fallback import is the common real-world shape). Its result used to
/// be built by delegating to `imported_code_units_of`, which is keyed by binding name and silently
/// drops one target on a name collision -- fixed to resolve from the batched-but-uncollapsed path
/// instead. This pins that both targets survive.
#[test]
fn test_imported_code_units_from_infos_keeps_both_targets_for_shared_binding_name() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "consumer.py",
            "try:\n    import first_lib as lib\nexcept ImportError:\n    import second_lib as lib\n",
        )
        .file("first_lib.py", "VALUE = 1\n")
        .file("second_lib.py", "VALUE = 2\n")
        .build();
    let consumer = project.file("consumer.py");
    let first_lib = project.file("first_lib.py");
    let second_lib = project.file("second_lib.py");
    let analyzer = PythonAnalyzer::from_project(project.project().clone());

    let imports = analyzer.import_info_of(&consumer);
    assert_eq!(
        imports.len(),
        2,
        "both try/except branches should parse as separate imports: {imports:#?}"
    );

    let resolved = analyzer
        .imported_code_units_from_infos(&consumer, &imports)
        .expect("Python always answers this hook");
    let resolved_sources: std::collections::HashSet<_> =
        resolved.iter().map(|unit| unit.source().clone()).collect();

    assert!(
        resolved_sources.contains(&first_lib),
        "first_lib should still resolve even though `lib` is also bound by second_lib: {resolved_sources:?}"
    );
    assert!(
        resolved_sources.contains(&second_lib),
        "second_lib should still resolve even though `lib` is also bound by first_lib: {resolved_sources:?}"
    );
}
