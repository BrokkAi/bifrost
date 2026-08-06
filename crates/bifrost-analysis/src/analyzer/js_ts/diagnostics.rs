//! The two analyzer-guarded entry points into the JS/TS semantic-diagnostic
//! collector.
//!
//! The collector itself, its constants and `JsTsSemanticDiagnostic` live in
//! `brokk-bifrost-js-ts`. What stays here is the pair of guards -- each names a
//! concrete analyzer through `resolve_analyzer` to answer "does this workspace
//! actually analyze this dialect" -- and the analyzer-bound tests.

use crate::analyzer::{IAnalyzer, Language, ProjectFile, resolve_analyzer};
use brokk_bifrost_js_ts::diagnostics::{
    JAVASCRIPT_SEMANTIC_DIAGNOSTIC_SOURCE, JsTsSemanticDiagnostic,
    TYPESCRIPT_SEMANTIC_DIAGNOSTIC_SOURCE, collect_js_ts_semantic_diagnostics,
};
use brokk_bifrost_js_ts::tsconfig::AliasResolver;

pub(crate) fn collect_javascript_semantic_diagnostics(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    aliases: &AliasResolver,
) -> Vec<JsTsSemanticDiagnostic> {
    if resolve_analyzer::<crate::analyzer::JavascriptAnalyzer>(analyzer).is_none() {
        return Vec::new();
    }
    collect_js_ts_semantic_diagnostics(
        analyzer,
        file,
        source,
        Language::JavaScript,
        JAVASCRIPT_SEMANTIC_DIAGNOSTIC_SOURCE,
        aliases,
    )
}

pub(crate) fn collect_typescript_semantic_diagnostics(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    aliases: &AliasResolver,
) -> Vec<JsTsSemanticDiagnostic> {
    if resolve_analyzer::<crate::analyzer::TypescriptAnalyzer>(analyzer).is_none() {
        return Vec::new();
    }
    collect_js_ts_semantic_diagnostics(
        analyzer,
        file,
        source,
        Language::TypeScript,
        TYPESCRIPT_SEMANTIC_DIAGNOSTIC_SOURCE,
        aliases,
    )
}

#[cfg(test)]
mod tests {
    use super::{collect_javascript_semantic_diagnostics, collect_typescript_semantic_diagnostics};
    use crate::analyzer::CodeUnitIndex;
    use crate::analyzer::{
        AliasResolver, JavascriptAnalyzer, Language, ProjectFile, TestProject, TypescriptAnalyzer,
    };
    use brokk_bifrost_js_ts::diagnostics::JS_TS_UNRECOGNIZED_SYMBOL;
    use std::path::PathBuf;
    use std::sync::Arc;

    struct JsTsFixture<A> {
        _temp: tempfile::TempDir,
        analyzer: A,
        root: PathBuf,
        aliases: AliasResolver,
    }

    fn javascript_project(files: &[(&str, &str)]) -> JsTsFixture<JavascriptAnalyzer> {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        for (path, source) in files {
            ProjectFile::new(root.clone(), *path).write(source).unwrap();
        }
        let analyzer =
            JavascriptAnalyzer::from_project(TestProject::new(root.clone(), Language::JavaScript));
        let aliases = AliasResolver::new(root.clone());
        JsTsFixture {
            _temp: temp,
            analyzer,
            root,
            aliases,
        }
    }

    fn typescript_project(files: &[(&str, &str)]) -> JsTsFixture<TypescriptAnalyzer> {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        for (path, source) in files {
            ProjectFile::new(root.clone(), *path).write(source).unwrap();
        }
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root.clone(), Language::TypeScript));
        let aliases = AliasResolver::new(root.clone());
        JsTsFixture {
            _temp: temp,
            analyzer,
            root,
            aliases,
        }
    }

    fn js_diagnostics(fixture: &JsTsFixture<JavascriptAnalyzer>, rel_path: &str) -> Vec<String> {
        let file = ProjectFile::new(fixture.root.clone(), rel_path);
        let source = fixture.analyzer.project().read_source(&file).unwrap();
        collect_javascript_semantic_diagnostics(&fixture.analyzer, &file, &source, &fixture.aliases)
            .into_iter()
            .map(|diagnostic| diagnostic.message)
            .collect()
    }

    fn ts_diagnostics(fixture: &JsTsFixture<TypescriptAnalyzer>, rel_path: &str) -> Vec<String> {
        let file = ProjectFile::new(fixture.root.clone(), rel_path);
        let source = fixture.analyzer.project().read_source(&file).unwrap();
        collect_typescript_semantic_diagnostics(&fixture.analyzer, &file, &source, &fixture.aliases)
            .into_iter()
            .map(|diagnostic| diagnostic.message)
            .collect()
    }

    #[test]
    fn js_ts_semantic_diagnostics_report_unknown_local_identifiers() {
        let fixture = javascript_project(&[(
            "app.js",
            "function run(known) {\n  const local = known;\n  missingValue;\n  local;\n}\n",
        )]);
        let diagnostics = js_diagnostics(&fixture, "app.js");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert!(diagnostics[0].contains("missingValue"));

        let fixture = typescript_project(&[(
            "app.ts",
            "type Present = string;\nfunction run(value: Present): MissingType {\n  return missingValue;\n}\n",
        )]);
        let diagnostics = ts_diagnostics(&fixture, "app.ts");
        assert_eq!(2, diagnostics.len(), "{diagnostics:#?}");
        assert!(
            diagnostics
                .iter()
                .any(|message| message.contains("MissingType"))
        );
        assert!(
            diagnostics
                .iter()
                .any(|message| message.contains("missingValue"))
        );
    }

    #[test]
    fn js_ts_semantic_diagnostics_suppress_imports_and_aliases() {
        let fixture = typescript_project(&[
            (
                "tsconfig.json",
                r#"{"compilerOptions":{"baseUrl":".","paths":{"@lib/*":["src/lib/*"]}}}"#,
            ),
            ("src/lib/util.ts", "export const helper = 1;\n"),
            (
                "src/app.ts",
                "import { helper } from '@lib/util';\nimport pkgDefault from 'external-package';\nimport { externalThing } from 'external-package';\nimport { localThing } from './local';\nhelper;\npkgDefault;\nexternalThing;\nlocalThing;\n",
            ),
            ("src/local.ts", "export const localThing = 2;\n"),
        ]);
        let diagnostics = ts_diagnostics(&fixture, "src/app.ts");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn js_ts_semantic_diagnostics_suppress_properties_jsx_globals_and_malformed_files() {
        let fixture = javascript_project(&[
            (
                "component.jsx",
                "function View(props) {\n  const options = { missingKey: props.value, shorthand };\n  console.log(options.missingMember);\n  return <div className=\"x\"><span /></div>;\n}\n",
            ),
            ("broken.js", "function run( {\n  missingValue;\n}\n"),
        ]);
        let diagnostics = js_diagnostics(&fixture, "component.jsx");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert!(diagnostics[0].contains("shorthand"));

        let broken = js_diagnostics(&fixture, "broken.js");
        assert!(broken.is_empty(), "{broken:#?}");
    }

    #[test]
    fn js_ts_semantic_diagnostics_suppress_type_only_import_uncertainty() {
        let fixture = typescript_project(&[(
            "app.ts",
            "import type { ExternalType } from 'external-package';\nconst value = ExternalType;\n",
        )]);
        let diagnostics = ts_diagnostics(&fixture, "app.ts");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn js_ts_semantic_diagnostics_report_missing_imports_across_modules() {
        let fixture = typescript_project(&[
            ("src/a.ts", "export const config = 1;\n"),
            ("src/b.ts", "function run() {\n  return config;\n}\n"),
        ]);
        let diagnostics = ts_diagnostics(&fixture, "src/b.ts");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert!(diagnostics[0].contains("config"));
    }

    #[test]
    fn js_ts_semantic_diagnostics_handle_var_and_nested_function_scope() {
        let fixture = javascript_project(&[(
            "app.js",
            "function outer(ok) {\n  if (ok) { var value = 1; }\n  function inner() { return value; }\n  return inner();\n}\n",
        )]);
        let diagnostics = js_diagnostics(&fixture, "app.js");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn js_ts_semantic_diagnostics_scan_parameter_default_values() {
        let fixture = javascript_project(&[(
            "app.js",
            "function run(value = missingDefault) {\n  return value;\n}\n",
        )]);
        let diagnostics = js_diagnostics(&fixture, "app.js");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert!(
            diagnostics
                .iter()
                .any(|message| message.contains("missingDefault"))
        );
    }

    #[test]
    fn js_ts_semantic_diagnostics_cap_reported_items() {
        let source = (0..250)
            .map(|index| format!("missing{index};"))
            .collect::<Vec<_>>()
            .join("\n");
        let fixture = javascript_project(&[("app.js", &source)]);
        let file = ProjectFile::new(fixture.root.clone(), "app.js");
        let source = fixture.analyzer.project().read_source(&file).unwrap();
        let diagnostics = collect_javascript_semantic_diagnostics(
            &fixture.analyzer,
            &file,
            &source,
            &fixture.aliases,
        );
        assert_eq!(200, diagnostics.len());
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.kind == JS_TS_UNRECOGNIZED_SYMBOL)
        );
    }

    #[test]
    fn js_ts_semantic_diagnostics_multi_analyzer_routes_to_language_delegate() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        ProjectFile::new(root.clone(), "app.js")
            .write("missingValue;\n")
            .unwrap();
        let project = Arc::new(TestProject::new(root.clone(), Language::JavaScript));
        let analyzer = crate::analyzer::WorkspaceAnalyzer::build(
            project,
            crate::analyzer::AnalyzerConfig::default(),
        );
        let file = ProjectFile::new(root.clone(), "app.js");
        let source = analyzer.analyzer().project().read_source(&file).unwrap();
        let diagnostics = analyzer.analyzer().semantic_diagnostics(&file, &source);
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(JS_TS_UNRECOGNIZED_SYMBOL, diagnostics[0].kind);
    }
}
