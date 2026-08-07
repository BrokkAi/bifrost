//! The two analyzer-guarded entry points into the JS/TS semantic-diagnostic
//! collector, and the retained npm surface they judge external imports against.
//!
//! The collector itself and its constants live in `brokk-bifrost-js-ts`. What
//! stays here is the pair of guards -- each names a concrete analyzer through
//! `resolve_analyzer` to answer "does this workspace actually analyze this
//! dialect" -- the evidence types that read retained analyzer state, and the
//! analyzer-bound tests.
//!
//! Both call sites -- each dialect analyzer's own `semantic_diagnostics` and
//! `MultiAnalyzer`'s JS/TS arms -- pass the *dispatching* analyzer, exactly as
//! Java's shim does. The activated semantic-model overlay and the retained npm
//! discovery evidence hang off the analyzer that owns the workspace snapshot,
//! not off the dialect delegate, so a delegate passed on its own would report
//! every npm import as an unknown boundary. The dialect analyzer is recovered
//! from the dispatcher through `resolve_analyzer`, which is also where the
//! alias resolver and its `tsconfig` memo come from.
//!
//! The evidence types read the activated semantic-model overlay and the
//! retained npm discovery evidence. They never walk `node_modules`, read a
//! lockfile, or start discovery: discovery runs during host activation
//! (`WorkspaceAnalyzer::activate_dependency_packs`), and a diagnostic request
//! sees only what that run retained. Where nothing was retained, the request
//! reports a typed incomplete outcome.

use std::sync::Arc;

use crate::analyzer::semantic_model::{
    DependencyDiscoveryEvidence, SemanticModelCompleteness, SemanticModelOverlay,
    SemanticModelSymbolKind, retained_evidence_declares,
};
use crate::analyzer::structural::BoundaryStatus;
use crate::analyzer::{
    IAnalyzer, Language, ProjectFile, SemanticDiagnosticIncompleteReason, SemanticDiagnosticReport,
    resolve_analyzer,
};
use brokk_bifrost_js_ts::diagnostics::{
    JAVASCRIPT_SEMANTIC_DIAGNOSTIC_SOURCE, JsTsExportedNameEvidence, JsTsExternalSurfaceEvidence,
    JsTsModuleEvidence, TYPESCRIPT_SEMANTIC_DIAGNOSTIC_SOURCE, collect_js_ts_semantic_diagnostics,
};
use brokk_bifrost_js_ts::imports::npm_package_of_module_specifier;
use brokk_bifrost_js_ts::providers::JsTsSource;

pub(crate) fn collect_javascript_semantic_diagnostics(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
) -> SemanticDiagnosticReport {
    let Some(javascript) = resolve_analyzer::<crate::analyzer::JavascriptAnalyzer>(analyzer) else {
        return SemanticDiagnosticReport::new();
    };
    let evidence = JavaScriptNpmSurface(RetainedNpmSurface::read(analyzer, Language::JavaScript));
    collect_js_ts_semantic_diagnostics(
        analyzer,
        &evidence,
        file,
        source,
        Language::JavaScript,
        JAVASCRIPT_SEMANTIC_DIAGNOSTIC_SOURCE,
        javascript.alias_resolver(),
    )
}

pub(crate) fn collect_typescript_semantic_diagnostics(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
) -> SemanticDiagnosticReport {
    let Some(typescript) = resolve_analyzer::<crate::analyzer::TypescriptAnalyzer>(analyzer) else {
        return SemanticDiagnosticReport::new();
    };
    let evidence = TypeScriptNpmSurface(RetainedNpmSurface::read(analyzer, Language::TypeScript));
    collect_js_ts_semantic_diagnostics(
        analyzer,
        &evidence,
        file,
        source,
        Language::TypeScript,
        TYPESCRIPT_SEMANTIC_DIAGNOSTIC_SOURCE,
        typescript.alias_resolver(),
    )
}

/// The retained npm surface one diagnostic request may read.
///
/// Both handles are snapshots the host published. A `None` overlay means no
/// pack has been activated; `None` discovery evidence means no discovery run
/// has been retained. Neither is a reason to go looking.
struct RetainedNpmSurface {
    overlay: Option<Arc<SemanticModelOverlay>>,
    discovery: Option<Arc<DependencyDiscoveryEvidence>>,
}

/// Whether every pack contributing a module's surface is complete.
struct ModuleSurface {
    complete: bool,
}

impl RetainedNpmSurface {
    fn read(analyzer: &dyn IAnalyzer, language: Language) -> Self {
        Self {
            overlay: analyzer.semantic_model_overlay(),
            discovery: analyzer.dependency_discovery_evidence(language),
        }
    }

    /// The activated surface for `module_specifier`, or `None` when no pack
    /// declares the module.
    ///
    /// A declaration pack names its root module type exactly as the module
    /// specifier that reaches it, so more than one pack can contribute one
    /// module: `@types/left-pad` and `left-pad` both carry the module
    /// coordinate `left-pad`, and a pack that spells `declare module '@scope/x'`
    /// adds to that module's surface too. The surface is their union, and it is
    /// complete only when every contributing pack is.
    fn module_surface(&self, module_specifier: &str) -> Option<ModuleSurface> {
        let overlay = self.overlay.as_ref()?;
        let mut surface: Option<ModuleSurface> = None;
        for symbol in overlay.symbols_named(module_specifier).records {
            if symbol.kind != SemanticModelSymbolKind::Module
                || symbol.qualified_name != module_specifier
            {
                continue;
            }
            let complete = symbol.provenance.completeness == SemanticModelCompleteness::Complete;
            surface = Some(match surface {
                Some(existing) => ModuleSurface {
                    complete: existing.complete && complete,
                },
                None => ModuleSurface { complete },
            });
        }
        surface
    }

    /// Whether the activated surface for `module_specifier` declares `name`.
    ///
    /// A pack qualifies every declaration with the module that reaches it, and
    /// the overlay indexes each symbol under its bare name, its qualified name,
    /// and every alias -- including the module-qualified alias an
    /// `export { local as Public }` records. Asking for the qualified name is
    /// therefore an exact question about one module's surface, not a global
    /// name search.
    fn exports_name(&self, module_specifier: &str, name: &str) -> bool {
        let Some(overlay) = self.overlay.as_ref() else {
            return false;
        };
        let qualified = format!("{module_specifier}.{name}");
        overlay
            .symbols_named(&qualified)
            .records
            .iter()
            .any(|symbol| {
                symbol.qualified_name == qualified
                    || symbol.aliases.iter().any(|alias| alias == &qualified)
            })
    }

    /// Why a module with no activated surface cannot be decided.
    fn unindexed_reasons(&self, module_specifier: &str) -> Vec<SemanticDiagnosticIncompleteReason> {
        let discovery = self.discovery.as_deref();
        // Discovery records both the package identity and each module entry
        // point it routed, so a deep import is declared when its package is.
        // `declares_module_path` walks dotted Python paths, not npm subpaths,
        // which is why the package fallback is spelled here.
        let declared = retained_evidence_declares(discovery, module_specifier)
            || npm_package_of_module_specifier(module_specifier)
                .is_some_and(|(package, _)| retained_evidence_declares(discovery, package));
        let boundary = if declared {
            BoundaryStatus::ExternalDeclaredUnindexed
        } else {
            BoundaryStatus::ExternalUnknown
        };
        vec![SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery { boundary }]
    }

    fn classify_module(&self, module_specifier: &str) -> JsTsModuleEvidence {
        match self.module_surface(module_specifier) {
            Some(_) => JsTsModuleEvidence::Indexed,
            None => JsTsModuleEvidence::Undecided(self.unindexed_reasons(module_specifier)),
        }
    }
}

/// TypeScript judged against the retained npm surface.
///
/// A TypeScript file and a `.d.ts` declaration describe the same surface in the
/// same language, so a name that a complete declaration surface does not
/// declare is absent from it. A partial surface is not: the producer marks a
/// pack partial when it could not follow everything the declaration file
/// spelled -- an unresolved `export * from`, an incompatible declaration merge,
/// a record limit -- and each of those can hide the very name being looked up.
struct TypeScriptNpmSurface(RetainedNpmSurface);

impl JsTsExternalSurfaceEvidence for TypeScriptNpmSurface {
    fn classify_exported_name(
        &self,
        module_specifier: &str,
        name: &str,
    ) -> JsTsExportedNameEvidence {
        match self.0.module_surface(module_specifier) {
            Some(surface) => {
                if self.0.exports_name(module_specifier, name) {
                    JsTsExportedNameEvidence::Indexed
                } else if surface.complete {
                    JsTsExportedNameEvidence::AbsentFromCompleteSurface
                } else {
                    JsTsExportedNameEvidence::Undecided(vec![
                        SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                            boundary: BoundaryStatus::ExternalDeclaredUnindexed,
                        },
                    ])
                }
            }
            None => JsTsExportedNameEvidence::Undecided(self.0.unindexed_reasons(module_specifier)),
        }
    }

    fn classify_module(&self, module_specifier: &str) -> JsTsModuleEvidence {
        self.0.classify_module(module_specifier)
    }
}

/// JavaScript reads the same retained npm surface, and never proves a name
/// absent from it.
///
/// The surface comes from TypeScript declarations. What a JavaScript file
/// imports is the module's runtime shape, and the two differ in ways the
/// declaration cannot show: a hand-written `@types` package routinely describes
/// a subset of the runtime API, and CommonJS interop binds names no `.d.ts`
/// spells. A name missing from the declarations is therefore evidence about the
/// declarations, not about the module JavaScript loads.
struct JavaScriptNpmSurface(RetainedNpmSurface);

impl JsTsExternalSurfaceEvidence for JavaScriptNpmSurface {
    fn classify_exported_name(
        &self,
        module_specifier: &str,
        name: &str,
    ) -> JsTsExportedNameEvidence {
        if self.0.exports_name(module_specifier, name) {
            return JsTsExportedNameEvidence::Indexed;
        }
        match self.0.module_surface(module_specifier) {
            Some(_) => JsTsExportedNameEvidence::Undecided(vec![
                SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                    detail: format!(
                        "a JavaScript import of `{name}` is judged against the TypeScript declaration surface of `{module_specifier}`, which does not describe the module's runtime exports"
                    ),
                },
            ]),
            None => JsTsExportedNameEvidence::Undecided(self.0.unindexed_reasons(module_specifier)),
        }
    }

    fn classify_module(&self, module_specifier: &str) -> JsTsModuleEvidence {
        self.0.classify_module(module_specifier)
    }
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
        let report = collect_javascript_semantic_diagnostics(
            &fixture.analyzer,
            &file,
            &source,
            &fixture.aliases,
        );
        assert_eq!(200, report.diagnostics().len());
        assert!(
            report
                .diagnostics()
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
