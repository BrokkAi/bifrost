//! The analysis-side entry point for Rust's semantic diagnostics.
//!
//! The language logic lives in [`brokk_bifrost_rust::diagnostics`]. What stays
//! here is the one downcast that turns an `&dyn IAnalyzer` into the arguments
//! that function takes: the Rust usage source and the bounded definition
//! lookup.

use crate::analyzer::{IAnalyzer, ProjectFile, RustAnalyzer, resolve_analyzer};
use brokk_bifrost_rust::diagnostics::RustSemanticDiagnostic;

pub(crate) fn collect_rust_semantic_diagnostics(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
) -> Vec<RustSemanticDiagnostic> {
    let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) else {
        return Vec::new();
    };
    let support = analyzer.global_usage_definition_index();
    brokk_bifrost_rust::diagnostics::collect_rust_semantic_diagnostics(rust, &support, file, source)
}

#[cfg(test)]
mod tests {
    use super::collect_rust_semantic_diagnostics;
    use crate::analyzer::CodeUnitIndex;
    use crate::analyzer::{Language, ProjectFile, RustAnalyzer, TestProject};
    use brokk_bifrost_rust::diagnostics::RUST_UNRECOGNIZED_SYMBOL;
    use tempfile::tempdir;

    fn rust_project(files: &[(&str, &str)]) -> (tempfile::TempDir, RustAnalyzer) {
        let temp = tempdir().unwrap();
        for (path, contents) in files {
            ProjectFile::new(temp.path().to_path_buf(), path)
                .write(*contents)
                .unwrap();
        }
        let project = TestProject::new(temp.path().to_path_buf(), Language::Rust);
        let analyzer = RustAnalyzer::from_project(project);
        (temp, analyzer)
    }

    fn diagnostics_for(
        analyzer: &RustAnalyzer,
        rel_path: &str,
    ) -> Vec<super::RustSemanticDiagnostic> {
        let file = ProjectFile::new(analyzer.project().root().to_path_buf(), rel_path);
        let source = analyzer.project().read_source(&file).unwrap();
        collect_rust_semantic_diagnostics(analyzer, &file, &source)
    }

    #[test]
    fn rust_semantic_diagnostics_report_unknown_type_and_value_references() {
        let (_temp, analyzer) = rust_project(&[(
            "src/main.rs",
            r#"
fn run(input: MissingType) {
    missing_value;
    missing_function();
}
"#,
        )]);

        let diagnostics = diagnostics_for(&analyzer, "src/main.rs");
        assert_eq!(3, diagnostics.len(), "{diagnostics:#?}");
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.kind == RUST_UNRECOGNIZED_SYMBOL)
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("MissingType"))
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("missing_value"))
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("missing_function"))
        );
    }

    #[test]
    fn rust_semantic_diagnostics_suppress_locals_declarations_imports_and_module_paths() {
        let (_temp, analyzer) = rust_project(&[
            (
                "src/models.rs",
                "pub struct Service;\npub type Handler = fn();\npub fn build_service() -> Service { Service }\n",
            ),
            (
                "src/main.rs",
                r#"
mod models;
use crate::models::{Service as RenamedService, Handler, build_service};

struct LocalType;
type LocalHandler = fn();
fn local_function() {}

fn run(param: RenamedService, handler: Handler, local_handler: LocalHandler) {
    let local = build_service();
    let typed: LocalType = LocalType;
    local_function();
    crate::models::build_service();
    param;
    handler;
    local_handler;
    local;
    typed;
}
"#,
            ),
        ]);

        let diagnostics = diagnostics_for(&analyzer, "src/main.rs");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn rust_semantic_diagnostics_handle_rust_item_scope_edges() {
        let (_temp, analyzer) = rust_project(&[(
            "src/main.rs",
            r#"
fn nested_item_does_not_capture_local() {
    let captured = 1;
    fn inner() {
        captured;
    }
}

fn block_item_is_visible_before_declaration() {
    helper();
    fn helper() {}
}

trait Service {
    fn get<T>(input: T) -> T;
}

struct Boxed<T> {
    value: T,
}

fn leaked_generic(value: T) {}
"#,
        )]);

        let diagnostics = diagnostics_for(&analyzer, "src/main.rs");
        assert_eq!(2, diagnostics.len(), "{diagnostics:#?}");
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("captured")),
            "{diagnostics:#?}"
        );
        assert_eq!(
            1,
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.message.contains("`T`"))
                .count(),
            "{diagnostics:#?}"
        );
    }

    #[test]
    fn rust_semantic_diagnostics_suppress_builtin_macro_cfg_external_and_glob_uncertainty() {
        let (_temp, analyzer) = rust_project(&[(
            "src/main.rs",
            r#"
use external_crate::ExternalType;
use crate::missing::*;

#[cfg(feature = "generated")]
fn generated(value: CfgType) {
    cfg_value;
}

fn run(value: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    println!("{:?}", value);
    external_crate::call();
    let _: ExternalType = external_crate::make();
    macro_rules! local_macro { () => { generated_name } }
    local_macro!();
    Ok(())
}
"#,
        )]);

        let diagnostics = diagnostics_for(&analyzer, "src/main.rs");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn rust_semantic_diagnostics_suppress_malformed_files() {
        let (_temp, analyzer) =
            rust_project(&[("src/main.rs", "fn run( {\n    missing_value;\n}\n")]);

        let diagnostics = diagnostics_for(&analyzer, "src/main.rs");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn rust_semantic_diagnostics_cap_reported_items() {
        let mut source = String::from("fn run() {\n");
        for index in 0..250 {
            source.push_str(&format!("    missing_{index};\n"));
        }
        source.push_str("}\n");
        let (_temp, analyzer) = rust_project(&[("src/main.rs", &source)]);

        let diagnostics = diagnostics_for(&analyzer, "src/main.rs");
        assert_eq!(
            brokk_bifrost_rust::diagnostics::MAX_RUST_SEMANTIC_DIAGNOSTICS,
            diagnostics.len()
        );
    }
}
