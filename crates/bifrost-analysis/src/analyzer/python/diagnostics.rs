//! The analysis-side entry point for Python's semantic diagnostics.
//!
//! The language logic lives in [`brokk_bifrost_python::diagnostics`]. What stays
//! here is the one downcast that turns an `&dyn IAnalyzer` into the arguments
//! that function takes: the Python analysis source and the bounded definition
//! lookup.

use crate::analyzer::{IAnalyzer, ProjectFile, PythonAnalyzer, resolve_analyzer};
use brokk_bifrost_python::diagnostics::PythonSemanticDiagnostic;

pub(crate) fn collect_python_semantic_diagnostics(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
) -> Vec<PythonSemanticDiagnostic> {
    let Some(py) = resolve_analyzer::<PythonAnalyzer>(analyzer) else {
        return Vec::new();
    };
    let support = analyzer.global_usage_definition_index();
    brokk_bifrost_python::diagnostics::collect_python_semantic_diagnostics(
        py, &support, file, source,
    )
}

#[cfg(test)]
mod tests {
    use super::collect_python_semantic_diagnostics;
    use crate::analyzer::{Language, ProjectFile, PythonAnalyzer, TestProject};
    use brokk_bifrost_python::diagnostics::{
        MAX_PYTHON_SEMANTIC_DIAGNOSTICS, PYTHON_UNRECOGNIZED_SYMBOL, PythonSemanticDiagnostic,
    };
    use tempfile::TempDir;

    struct Fixture {
        _temp: TempDir,
        analyzer: PythonAnalyzer,
        root: std::path::PathBuf,
    }

    impl Fixture {
        fn diagnostics_for(&self, rel_path: &str) -> Vec<PythonSemanticDiagnostic> {
            let file = self.file(rel_path);
            let source = file.read_to_string().expect("read source");
            collect_python_semantic_diagnostics(&self.analyzer, &file, &source)
        }

        fn file(&self, rel_path: &str) -> ProjectFile {
            ProjectFile::new(self.root.clone(), rel_path)
        }
    }

    fn fixture(files: &[(&str, &str)]) -> Fixture {
        let temp = TempDir::new().expect("temp dir");
        let root = temp.path().to_path_buf();
        for (path, source) in files {
            ProjectFile::new(root.clone(), path)
                .write(*source)
                .unwrap_or_else(|err| panic!("write {path}: {err}"));
        }
        let project = TestProject::new(root.clone(), Language::Python);
        let analyzer = PythonAnalyzer::from_project(project);
        Fixture {
            _temp: temp,
            analyzer,
            root,
        }
    }

    #[test]
    fn python_semantic_diagnostics_report_unknown_local_identifier() {
        let fixture = fixture(&[(
            "app.py",
            r#"
def run():
    missing_value
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("app.py");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(PYTHON_UNRECOGNIZED_SYMBOL, diagnostics[0].kind);
        assert!(diagnostics[0].message.contains("missing_value"));
    }

    #[test]
    fn python_semantic_diagnostics_suppress_known_names_and_imports() {
        let fixture = fixture(&[
            (
                "pkg/service.py",
                r#"
class Service:
    pass

def build():
    return Service()
"#,
            ),
            (
                "app.py",
                r#"
from pkg.service import Service, build

LOCAL = 1

class Runner:
    pass

def run(param):
    value = LOCAL
    for item in range(1):
        alias = item
    with open(__file__) as handle:
        data = handle
    try:
        build()
    except Exception as exc:
        print(exc)
    return Service(), Runner(), value, alias, data, param, True, None
"#,
            ),
        ]);

        let diagnostics = fixture.diagnostics_for("app.py");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn python_semantic_diagnostics_suppress_relative_imports_and_reexports() {
        let fixture = fixture(&[
            (
                "pkg/core.py",
                r#"
class Service:
    pass
"#,
            ),
            (
                "pkg/__init__.py",
                r#"
from .core import Service
"#,
            ),
            (
                "app.py",
                r#"
from pkg import Service

def run():
    return Service()
"#,
            ),
        ]);

        let diagnostics = fixture.diagnostics_for("app.py");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn python_semantic_diagnostics_report_unknown_type_references() {
        let fixture = fixture(&[(
            "app.py",
            r#"
class Known:
    pass

def run(value: Known) -> MissingType:
    return value
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("app.py");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(PYTHON_UNRECOGNIZED_SYMBOL, diagnostics[0].kind);
        assert!(diagnostics[0].message.contains("MissingType"));
    }

    #[test]
    fn python_semantic_diagnostics_report_unknown_parameter_annotations_and_defaults() {
        let fixture = fixture(&[(
            "app.py",
            r#"
def run(value: MissingType = missing_default):
    return value
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("app.py");
        assert_eq!(2, diagnostics.len(), "{diagnostics:#?}");
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("MissingType"))
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("missing_default"))
        );
    }

    #[test]
    fn python_semantic_diagnostics_check_attribute_receiver_but_not_member() {
        let fixture = fixture(&[(
            "app.py",
            r#"
def run():
    return missing_client.fetch()
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("app.py");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert!(diagnostics[0].message.contains("missing_client"));
        assert!(!diagnostics[0].message.contains("fetch"));
    }

    #[test]
    fn python_semantic_diagnostics_handle_comprehension_scopes() {
        let fixture = fixture(&[(
            "app.py",
            r#"
def run(rows):
    values = [item for item in rows if item]
    return item
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("app.py");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert!(diagnostics[0].message.contains("item"));
    }

    #[test]
    fn python_semantic_diagnostics_suppress_match_pattern_uncertainty() {
        let fixture = fixture(&[(
            "app.py",
            r#"
def run(value):
    match value:
        case {"id": ident}:
            return ident
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("app.py");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn python_semantic_diagnostics_suppress_builtin_exceptions() {
        let fixture = fixture(&[(
            "app.py",
            r#"
def run():
    try:
        raise RuntimeError("boom")
    except ValueError as exc:
        return exc
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("app.py");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn python_semantic_diagnostics_suppress_unresolved_import_boundaries() {
        let fixture = fixture(&[
            (
                "external.py",
                r#"
from missing_package import *

def run():
    missing_name
"#,
            ),
            (
                "named.py",
                r#"
from missing_package import maybe

def run():
    maybe
"#,
            ),
        ]);

        assert!(fixture.diagnostics_for("external.py").is_empty());
        assert!(fixture.diagnostics_for("named.py").is_empty());
    }

    #[test]
    fn python_semantic_diagnostics_suppress_dynamic_constructs_and_attributes() {
        let fixture = fixture(&[
            (
                "dynamic.py",
                r#"
def run():
    globals()
    missing_name
"#,
            ),
            (
                "module_getattr.py",
                r#"
def __getattr__(name):
    return 1

def run():
    missing_name
"#,
            ),
            (
                "attribute.py",
                r#"
def run(obj):
    obj.missing_name
"#,
            ),
        ]);

        assert!(fixture.diagnostics_for("dynamic.py").is_empty());
        assert!(fixture.diagnostics_for("module_getattr.py").is_empty());
        assert!(fixture.diagnostics_for("attribute.py").is_empty());
    }

    #[test]
    fn python_semantic_diagnostics_suppress_malformed_files() {
        let fixture = fixture(&[(
            "broken.py",
            r#"
def run(
    missing_name
"#,
        )]);

        assert!(fixture.diagnostics_for("broken.py").is_empty());
    }

    #[test]
    fn python_semantic_diagnostics_cap_reported_items() {
        let mut source = String::from("def run():\n");
        for index in 0..(MAX_PYTHON_SEMANTIC_DIAGNOSTICS + 25) {
            source.push_str(&format!("    missing_{index}\n"));
        }
        let fixture = fixture(&[("app.py", &source)]);

        let diagnostics = fixture.diagnostics_for("app.py");
        assert_eq!(MAX_PYTHON_SEMANTIC_DIAGNOSTICS, diagnostics.len());
    }
}
