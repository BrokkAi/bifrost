//! JS/TS semantic diagnostics judged against exact npm declaration packs
//! (#1620).
//!
//! Every case activates packs from fixture `node_modules` trees that are
//! written into the temporary workspace. Nothing here downloads anything or
//! runs npm: discovery reads the checked-in lockfile and package manifests
//! during activation, and the diagnostic requests that follow read only what
//! activation retained.

use brokk_bifrost::analyzer::semantic_model::{
    CatalogOptions, DependencyPackLimits, SemanticModelActivationRequest,
    SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome, SemanticPackCatalog,
    acquire_active_semantic_models, prepare_discovered_dependency_semantic_packs,
};
use brokk_bifrost::analyzer::{
    DependencyPackEcosystem, DependencyPackWorkspaceContext, JsTsDependencyDiscoveryConfig,
    JsTsDependencyPackAdapter, WorkspaceAnalyzer, resolve_js_ts_semantic_pack_dependencies,
};
use brokk_bifrost::{AnalyzerConfig, CancellationToken, Language};
use brokk_bifrost_analysis::analyzer::structural::BoundaryStatus;
use brokk_bifrost_analysis::analyzer::{
    SemanticDiagnosticDomain, SemanticDiagnosticIncompleteReason, SemanticDiagnosticOutcome,
    SemanticDiagnosticReport,
};
use semver::Version;
use std::sync::Arc;

use crate::common::{BuiltInlineTestProject, InlineTestProject};

/// A workspace whose npm declaration packs are active, plus the catalog that
/// owns them. The catalog is returned so it outlives the published overlay.
struct ActivatedWorkspace {
    project: BuiltInlineTestProject,
    analyzer: WorkspaceAnalyzer,
    _catalog: SemanticPackCatalog,
}

impl ActivatedWorkspace {
    fn report(&self, rel_path: &str) -> SemanticDiagnosticReport {
        let file = self.project.file(rel_path);
        let source = self
            .analyzer
            .analyzer()
            .project()
            .read_source(&file)
            .expect("workspace source");
        self.analyzer
            .analyzer()
            .semantic_diagnostics(&file, &source)
    }
}

fn activation_request() -> SemanticModelActivationRequest {
    SemanticModelActivationRequest {
        bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
        evidence: Vec::new(),
        controls: Vec::new(),
        limits: SemanticModelRuntimeLimits::default(),
    }
}

/// The npm packages every complete-surface case shares.
///
/// `widget` carries an ordinary named surface plus two declaration merges;
/// `@scope/widget` proves a scoped package is a separate surface from the
/// unscoped package whose tail matches it; `deep` routes an `exports` subpath;
/// `@types/left-pad` proves a companion types package serves the module name it
/// describes rather than its own package name.
fn complete_surface_packages() -> Vec<(&'static str, String)> {
    vec![
        (".gitignore", "node_modules/\n".to_string()),
        (
            "package-lock.json",
            r#"{
              "lockfileVersion": 3,
              "packages": {
                "": { "name": "app", "version": "1.0.0" },
                "node_modules/widget": { "version": "2.1.0" },
                "node_modules/@scope/widget": { "version": "1.0.0" },
                "node_modules/deep": { "version": "1.0.0" },
                "node_modules/@types/left-pad": { "version": "1.3.0" }
              }
            }"#
            .to_string(),
        ),
        (
            "node_modules/widget/package.json",
            r#"{ "name": "widget", "version": "2.1.0", "types": "index.d.ts" }"#.to_string(),
        ),
        (
            "node_modules/widget/index.d.ts",
            r#"export interface Widget<T> { value: T }
export declare function create<T>(value: T): Widget<T>;
export interface Options { first: string }
export interface Options { second: number }
declare class Local { id: string }
export { Local as Public };
"#
            .to_string(),
        ),
        (
            "node_modules/@scope/widget/package.json",
            r#"{ "name": "@scope/widget", "version": "1.0.0", "types": "index.d.ts" }"#.to_string(),
        ),
        (
            "node_modules/@scope/widget/index.d.ts",
            "export interface ScopedOnly { id: string }\n".to_string(),
        ),
        (
            "node_modules/deep/package.json",
            r#"{
              "name": "deep",
              "version": "1.0.0",
              "exports": {
                ".": { "types": "./index.d.ts" },
                "./extra": { "types": "./extra.d.ts" }
              }
            }"#
            .to_string(),
        ),
        (
            "node_modules/deep/index.d.ts",
            "export interface Root { id: string }\n".to_string(),
        ),
        (
            "node_modules/deep/extra.d.ts",
            "export interface Extra { id: string }\n".to_string(),
        ),
        (
            "node_modules/@types/left-pad/package.json",
            r#"{ "name": "@types/left-pad", "version": "1.3.0", "types": "index.d.ts" }"#
                .to_string(),
        ),
        (
            "node_modules/@types/left-pad/index.d.ts",
            "export declare function leftPad(value: string, length: number): string;\n".to_string(),
        ),
    ]
}

fn activated_workspace(language: Language, extra_files: Vec<(&str, String)>) -> ActivatedWorkspace {
    let mut builder = InlineTestProject::with_language(language);
    for (path, contents) in complete_surface_packages() {
        builder = builder.file(path, contents);
    }
    for (path, contents) in extra_files {
        builder = builder.file(path, contents);
    }
    let project = builder.build();
    let config = AnalyzerConfig::default();
    let analyzer = project.workspace_analyzer(config.clone());
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let activation = activation_request();
    let cancellation = CancellationToken::default();
    let outcome = analyzer.activate_dependency_packs(
        &config,
        &[DependencyPackEcosystem::Npm],
        DependencyPackWorkspaceContext {
            catalog: &catalog,
            persistence: None,
            activation: &activation,
            limits: DependencyPackLimits::default(),
            cancellation: &cancellation,
        },
    );
    assert!(outcome.complete(), "{outcome:#?}");
    assert!(
        analyzer.analyzer().semantic_model_overlay().is_some(),
        "activation must publish an overlay"
    );
    ActivatedWorkspace {
        project,
        analyzer,
        _catalog: catalog,
    }
}

fn typescript_workspace(source: &str) -> ActivatedWorkspace {
    activated_workspace(
        Language::TypeScript,
        vec![("src/app.ts", source.to_string())],
    )
}

fn javascript_workspace(source: &str) -> ActivatedWorkspace {
    activated_workspace(
        Language::JavaScript,
        vec![("src/app.js", source.to_string())],
    )
}

fn missing_export_messages(report: &SemanticDiagnosticReport) -> Vec<&str> {
    report
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.message.as_str())
        .collect()
}

fn proves_module_absence(report: &SemanticDiagnosticReport, module: &str) -> bool {
    report.outcomes().iter().any(|outcome| {
        matches!(
            outcome,
            SemanticDiagnosticOutcome::Absent(proof)
                if proof.domain == SemanticDiagnosticDomain::Module { name: module.to_string() }
                    && proof.boundary == BoundaryStatus::ExternalIndexed
        )
    })
}

fn resolves_externally(report: &SemanticDiagnosticReport) -> bool {
    report.outcomes().iter().any(|outcome| {
        matches!(
            outcome,
            SemanticDiagnosticOutcome::Resolved {
                boundary: BoundaryStatus::ExternalIndexed,
                ..
            }
        )
    })
}

fn suppressed_at_boundary(report: &SemanticDiagnosticReport, expected: BoundaryStatus) -> bool {
    report.outcomes().iter().any(|outcome| {
        matches!(
            outcome,
            SemanticDiagnosticOutcome::Incomplete { reasons, .. }
                if reasons.iter().any(|reason| matches!(
                    reason,
                    SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery { boundary }
                        if *boundary == expected
                ))
        )
    })
}

#[test]
fn indexed_npm_and_types_declarations_resolve_without_an_error() {
    let workspace = typescript_workspace(
        "import { Widget, create, Options, Public } from 'widget';\n\
         import { leftPad } from 'left-pad';\n\
         import { Extra } from 'deep/extra';\n\
         import { ScopedOnly } from '@scope/widget';\n\
         const widget: Widget<string> = create('x');\n\
         const options: Options = { first: 'a', second: 1 };\n\
         const padded = leftPad('a', 2);\n\
         export { widget, options, padded, Extra, ScopedOnly, Public };\n",
    );
    let report = workspace.report("src/app.ts");
    assert!(
        report.diagnostics().is_empty(),
        "{:#?}",
        missing_export_messages(&report)
    );
    assert!(resolves_externally(&report), "{:#?}", report.outcomes());
}

#[test]
fn a_missing_export_from_a_complete_surface_is_an_error() {
    let workspace =
        typescript_workspace("import { NoSuchExport } from 'widget';\nexport { NoSuchExport };\n");
    let report = workspace.report("src/app.ts");
    let messages = missing_export_messages(&report);
    assert_eq!(1, messages.len(), "{messages:#?}");
    assert!(
        messages[0].contains("NoSuchExport") && messages[0].contains("widget"),
        "{messages:#?}"
    );
    assert!(
        proves_module_absence(&report, "widget"),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn a_scoped_package_is_a_different_surface_from_its_unscoped_namesake() {
    let workspace = typescript_workspace(
        "import { ScopedOnly } from 'widget';\n\
         import { Widget } from '@scope/widget';\n\
         export type Pair = [ScopedOnly, Widget<string>];\n",
    );
    let report = workspace.report("src/app.ts");
    let messages = missing_export_messages(&report);
    assert_eq!(2, messages.len(), "{messages:#?}");
    assert!(proves_module_absence(&report, "widget"));
    assert!(proves_module_absence(&report, "@scope/widget"));
}

#[test]
fn a_declared_package_whose_subpath_has_no_surface_suppresses() {
    let workspace =
        typescript_workspace("import { Anything } from 'deep/unmapped';\nexport { Anything };\n");
    let report = workspace.report("src/app.ts");
    assert!(
        report.diagnostics().is_empty(),
        "{:#?}",
        missing_export_messages(&report)
    );
    assert!(
        suppressed_at_boundary(&report, BoundaryStatus::ExternalDeclaredUnindexed),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn a_package_no_retained_evidence_knows_stays_at_an_unknown_boundary() {
    let workspace =
        typescript_workspace("import { Anything } from 'never-installed';\nexport { Anything };\n");
    let report = workspace.report("src/app.ts");
    assert!(
        report.diagnostics().is_empty(),
        "{:#?}",
        missing_export_messages(&report)
    );
    assert!(
        suppressed_at_boundary(&report, BoundaryStatus::ExternalUnknown),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn declaration_merging_keeps_a_surface_complete_and_resolvable() {
    // `Options` is declared twice in `widget`'s surface. Interface merging is
    // ordinary TypeScript, so it must neither split the surface nor make it
    // partial: the merged name still resolves and a genuinely absent name in
    // the same file is still proved.
    let workspace = typescript_workspace(
        "import { Options, NotDeclared } from 'widget';\nexport type { Options, NotDeclared };\n",
    );
    let report = workspace.report("src/app.ts");
    let messages = missing_export_messages(&report);
    assert_eq!(1, messages.len(), "{messages:#?}");
    assert!(messages[0].contains("NotDeclared"), "{messages:#?}");
    assert!(resolves_externally(&report), "{:#?}", report.outcomes());
}

#[test]
fn an_exported_alias_resolves_under_its_exported_name() {
    // `export { Local as Public }` publishes `Public`. The pack records that
    // alias next to the declaration name, so the exported name resolves. The
    // declaration name resolves too: the surface keeps both spellings and
    // cannot say which one an importer may use, so it reports neither missing.
    // A name the surface carries under no spelling is still proved absent.
    let workspace = typescript_workspace(
        "import { Public, Local, NotDeclared } from 'widget';\n\
         export type { Public, Local, NotDeclared };\n",
    );
    let report = workspace.report("src/app.ts");
    let messages = missing_export_messages(&report);
    assert_eq!(1, messages.len(), "{messages:#?}");
    assert!(messages[0].contains("NotDeclared"), "{messages:#?}");
}

#[test]
fn type_only_and_value_imports_read_the_same_module_surface() {
    // A type-only import binds a name in the module's surface exactly as a
    // value import does. Neither form may report a declared name missing, and
    // a type-only import of an absent name is still proved absent.
    let workspace = typescript_workspace(
        "import type { Widget } from 'widget';\n\
         import type { create } from 'widget';\n\
         import { Options } from 'widget';\n\
         import type { NoSuchType } from 'widget';\n\
         export type Alias = Widget<string> | Options | NoSuchType | typeof create;\n",
    );
    let report = workspace.report("src/app.ts");
    let messages = missing_export_messages(&report);
    assert_eq!(1, messages.len(), "{messages:#?}");
    assert!(messages[0].contains("NoSuchType"), "{messages:#?}");
}

#[test]
fn default_namespace_and_side_effect_bindings_are_never_reported_missing() {
    // A declaration surface records a default export under its own declaration
    // name, and `esModuleInterop` lets a default binding stand for a CommonJS
    // module object. Neither is checkable, so a module-shaped binding resolves
    // against the module and never proves a missing export.
    let workspace = typescript_workspace(
        "import anything from 'widget';\n\
         import * as everything from 'widget';\n\
         import 'widget';\n\
         export { anything, everything };\n",
    );
    let report = workspace.report("src/app.ts");
    assert!(
        report.diagnostics().is_empty(),
        "{:#?}",
        missing_export_messages(&report)
    );
    assert!(resolves_externally(&report), "{:#?}", report.outcomes());
}

#[test]
fn a_re_export_from_an_external_module_reads_that_module_surface() {
    let workspace = typescript_workspace(
        "export { create } from 'widget';\nexport { NoSuchExport } from 'widget';\n",
    );
    let report = workspace.report("src/app.ts");
    let messages = missing_export_messages(&report);
    assert_eq!(1, messages.len(), "{messages:#?}");
    assert!(messages[0].contains("NoSuchExport"), "{messages:#?}");
}

#[test]
fn javascript_never_proves_a_name_absent_from_a_typescript_declaration_surface() {
    let workspace =
        javascript_workspace("import { NoSuchExport } from 'widget';\nexport { NoSuchExport };\n");
    let report = workspace.report("src/app.js");
    assert!(
        report.diagnostics().is_empty(),
        "{:#?}",
        missing_export_messages(&report)
    );
    assert!(
        report.outcomes().iter().any(|outcome| matches!(
            outcome,
            SemanticDiagnosticOutcome::Incomplete { reasons, .. }
                if reasons.iter().any(|reason| matches!(
                    reason,
                    SemanticDiagnosticIncompleteReason::UnsupportedSemantics { .. }
                ))
        )),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn javascript_still_resolves_a_name_the_declaration_surface_declares() {
    let workspace = javascript_workspace("import { create } from 'widget';\nexport { create };\n");
    let report = workspace.report("src/app.js");
    assert!(
        report.diagnostics().is_empty(),
        "{:#?}",
        missing_export_messages(&report)
    );
    assert!(resolves_externally(&report), "{:#?}", report.outcomes());
}

#[test]
fn a_commonjs_require_binding_is_judged_against_the_module_not_one_name() {
    let workspace = javascript_workspace(
        "const widget = require('widget');\n\
         const { create, nothingLikeThis } = require('widget');\n\
         module.exports = { widget, create, nothingLikeThis };\n",
    );
    let report = workspace.report("src/app.js");
    assert!(
        report.diagnostics().is_empty(),
        "{:#?}",
        missing_export_messages(&report)
    );
    assert!(resolves_externally(&report), "{:#?}", report.outcomes());
}

#[test]
fn a_dynamic_require_is_suppressed_with_a_typed_dynamic_reason() {
    let workspace = javascript_workspace(
        "function load(name) {\n  return require(name);\n}\nmodule.exports = load;\n",
    );
    let report = workspace.report("src/app.js");
    assert!(
        report.diagnostics().is_empty(),
        "{:#?}",
        missing_export_messages(&report)
    );
    assert!(
        report.outcomes().iter().any(|outcome| matches!(
            outcome,
            SemanticDiagnosticOutcome::Incomplete { reasons, .. }
                if reasons.iter().any(|reason| matches!(
                    reason,
                    SemanticDiagnosticIncompleteReason::DynamicBehavior { .. }
                ))
        )),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn a_local_ambient_module_declaration_answers_for_its_own_specifier() {
    let workspace = typescript_workspace(
        "declare module 'never-installed' {\n  export interface Shim { id: string }\n}\n\
         import { Shim } from 'never-installed';\n\
         export type { Shim };\n",
    );
    let report = workspace.report("src/app.ts");
    assert!(
        report.diagnostics().is_empty(),
        "{:#?}",
        missing_export_messages(&report)
    );
    assert!(
        report.outcomes().iter().any(|outcome| matches!(
            outcome,
            SemanticDiagnosticOutcome::Resolved {
                boundary: BoundaryStatus::WorkspaceLocal,
                ..
            }
        )),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn a_diagnostic_request_before_activation_never_discovers_dependencies() {
    // Without activation nothing is retained, so the same file that errors
    // above must stay silent here. A request that walked `node_modules` or
    // read the lockfile itself would prove absence instead.
    let mut builder = InlineTestProject::with_language(Language::TypeScript);
    for (path, contents) in complete_surface_packages() {
        builder = builder.file(path, contents);
    }
    let project = builder
        .file(
            "src/app.ts",
            "import { NoSuchExport } from 'widget';\nexport { NoSuchExport };\n",
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let file = project.file("src/app.ts");
    let source = analyzer.analyzer().project().read_source(&file).unwrap();
    let report = analyzer.analyzer().semantic_diagnostics(&file, &source);
    assert!(
        report.diagnostics().is_empty(),
        "{:#?}",
        missing_export_messages(&report)
    );
    assert!(
        suppressed_at_boundary(&report, BoundaryStatus::ExternalUnknown),
        "{:#?}",
        report.outcomes()
    );
    assert!(analyzer.analyzer().semantic_model_overlay().is_none());
}

#[test]
fn invalidating_npm_dependency_state_refreshes_diagnostics() {
    let workspace =
        typescript_workspace("import { NoSuchExport } from 'widget';\nexport { NoSuchExport };\n");
    let before = workspace.report("src/app.ts");
    assert_eq!(1, before.diagnostics().len(), "{:#?}", before.outcomes());

    assert!(
        workspace
            .analyzer
            .invalidate_dependency_pack_state(&[DependencyPackEcosystem::Npm])
    );

    let after = workspace.report("src/app.ts");
    assert!(
        after.diagnostics().is_empty(),
        "invalidated dependency state must stop proving absence: {:#?}",
        missing_export_messages(&after)
    );
    assert!(
        suppressed_at_boundary(&after, BoundaryStatus::ExternalUnknown),
        "{:#?}",
        after.outcomes()
    );
}

#[test]
fn a_partial_declaration_surface_suppresses_instead_of_proving_absence() {
    // `export * from './inner'` is a re-export the declaration producer cannot
    // follow, so the pack it produces is partial. A name the partial surface
    // does not carry may well be behind that re-export, so it must not be
    // reported missing.
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(".gitignore", "node_modules/\n")
        .file(
            "package-lock.json",
            r#"{
              "lockfileVersion": 3,
              "packages": {
                "": { "name": "app", "version": "1.0.0" },
                "node_modules/reexporter": { "version": "1.0.0" }
              }
            }"#,
        )
        .file(
            "node_modules/reexporter/package.json",
            r#"{ "name": "reexporter", "version": "1.0.0", "types": "index.d.ts" }"#,
        )
        .file(
            "node_modules/reexporter/index.d.ts",
            "export interface Local { id: string }\nexport * from './inner';\n",
        )
        .file(
            "node_modules/reexporter/inner.d.ts",
            "export interface Inner { id: string }\n",
        )
        .file(
            "src/app.ts",
            "import { Local, Inner } from 'reexporter';\nexport type { Local, Inner };\n",
        )
        .build();

    // The workspace activation path refuses a partial preparation outright, so
    // the partial pack is activated through the same discovery, preparation and
    // acquisition steps that path runs, without its all-or-nothing gate.
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let limits = DependencyPackLimits::default();
    let discovery = resolve_js_ts_semantic_pack_dependencies(
        &JsTsDependencyDiscoveryConfig::default(),
        Arc::clone(&project.project_dyn()).as_ref(),
        &limits,
        None,
    );
    assert!(discovery.complete, "{:#?}", discovery.diagnostics);
    let prepared = prepare_discovered_dependency_semantic_packs(
        &catalog,
        &JsTsDependencyPackAdapter,
        discovery,
        &limits,
        None,
    );
    assert!(
        !prepared.complete,
        "an unresolved re-export must make preparation partial"
    );
    let request = prepared
        .compose_activation_request(activation_request())
        .expect("a partial pack still composes activation evidence");
    let SemanticModelRuntimeOutcome::Ready { .. } = acquire_active_semantic_models(
        analyzer.analyzer(),
        &catalog,
        None,
        &request,
        &CancellationToken::default(),
    ) else {
        panic!("the partial npm pack must activate");
    };

    let file = project.file("src/app.ts");
    let source = analyzer.analyzer().project().read_source(&file).unwrap();
    let report = analyzer.analyzer().semantic_diagnostics(&file, &source);
    assert!(
        report.diagnostics().is_empty(),
        "a partial surface must not prove absence: {:#?}",
        missing_export_messages(&report)
    );
    assert!(
        suppressed_at_boundary(&report, BoundaryStatus::ExternalDeclaredUnindexed),
        "{:#?}",
        report.outcomes()
    );
}
