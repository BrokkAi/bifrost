//! Rust's semantic diagnostics against exact Cargo API packs (#1625).
//!
//! Every assertion is outcome-level: what a report *claims* matters more than
//! how many diagnostics it printed, because the contract is that a diagnostic
//! exists only where a complete surface proved absence.
//!
//! The packs here are authored offline and registered as session packs. No test
//! runs `cargo` or `rustdoc`, reads `target/doc`, or reaches the network.

use crate::common::InlineTestProject;
use brokk_bifrost::analyzer::semantic_model::{
    CatalogCoordinate, CatalogOptions, CompiledSemanticModelPack, CompilerOptions,
    DependencyDiscoveryEvidence, DependencyDiscoveryOutcome, ResolvedDependency,
    SemanticModelActivationControl, SemanticModelActivationEvidence,
    SemanticModelActivationRequest, SemanticModelControlAction, SemanticModelControlScope,
    SemanticModelPackSelector, SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome,
    SemanticPackCatalog, SessionPackSource, SessionPackSourceKind, SourceFormat,
    acquire_active_semantic_models_with_evidence, compile_source,
};
use brokk_bifrost::{AnalyzerConfig, CancellationToken, Language, WorkspaceAnalyzer};
use brokk_bifrost_analysis::analyzer::structural::BoundaryStatus;
use brokk_bifrost_analysis::analyzer::{
    SemanticDiagnosticIncompleteReason, SemanticDiagnosticOutcome, SemanticDiagnosticReport,
    SemanticDiagnosticReportStatus,
};
use semver::Version;
use serde_json::{Value, json};

/// The package the fixture packs describe, and the name its own code spells.
const PACKAGE: &str = "widget";
/// What the consuming Cargo.toml renames it to, published as a pack alias
/// exactly as `add_cargo_dependency_aliases` does for a real rustdoc pack.
const RENAMED: &str = "renamed_widget";

fn locator(symbol: &str) -> Value {
    json!({ "kind": "artifact", "path": "rustdoc/api.json", "symbol": symbol })
}

/// A pack publishing crate `widget`: its root module, a `Widget` struct with an
/// inherent `render`, and a nested `widget::nested::Deep`. Every fact also
/// carries the renamed spelling as an alias, which is how a Cargo `package =`
/// rename reaches the overlay.
fn widget_pack(completeness: &str) -> CompiledSemanticModelPack {
    let aliased = |name: &str| json!([name.replacen(PACKAGE, RENAMED, 1)]);
    let type_fact = |id: &str, name: &str, kind: &str| {
        json!({
            "id": id,
            "name": name,
            "type_kind": kind,
            "visibility": "public",
            "aliases": aliased(name),
            "locator": locator(name)
        })
    };
    let value = json!({
        "schema_version": 1,
        "pack_id": "fixture.rust.widget",
        "version": "1.0.0",
        "producer": { "name": "rust-fixture", "version": "1.0.0" },
        "language": "rust",
        "ecosystem": "cargo",
        "compatibility": { "bifrost": "*", "toolchains": [] },
        "provenance": { "source": "fixture" },
        "license": "NOASSERTION",
        "completeness": completeness,
        "safety": { "generated_code_only": false, "review_required": false },
        "shards": [{
            "id": "declarations.rust.external",
            "activation": [{ "package": { "name": PACKAGE } }],
            "payload": {
                "kind": "declaration_facts",
                "types": [
                    type_fact("type.widget.root", PACKAGE, "module"),
                    type_fact("type.widget.widget", "widget.Widget", "struct"),
                    type_fact("type.widget.nested", "widget.nested", "module"),
                    type_fact("type.widget.deep", "widget.nested.Deep", "struct"),
                ],
                "members": [
                    json!({
                        "id": "member.widget.render",
                        "owner": "type.widget.widget",
                        "name": "render",
                        "member_kind": "method",
                        "visibility": "public",
                        "signature": { "parameters": [] },
                        "locator": locator("widget.Widget#render")
                    }),
                    json!({
                        "id": "member.widget.build",
                        "owner": "type.widget.root",
                        "name": "build",
                        "member_kind": "function",
                        "visibility": "public",
                        "signature": { "parameters": [] },
                        "locator": locator("widget.build")
                    }),
                ],
                "relations": []
            }
        }]
    });
    compile_source(
        SourceFormat::Json,
        &serde_json::to_vec(&value).unwrap(),
        &CompilerOptions::default(),
    )
    .unwrap_or_else(|diagnostics| panic!("fixture pack must compile: {diagnostics:#?}"))
}

fn activation_request() -> SemanticModelActivationRequest {
    SemanticModelActivationRequest {
        bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
        evidence: vec![SemanticModelActivationEvidence {
            language: "rust".to_owned(),
            ecosystem: "cargo".to_owned(),
            package: Some(CatalogCoordinate {
                name: PACKAGE.to_owned(),
                version: None,
            }),
            module: None,
            toolchain: None,
            target: None,
            configuration: None,
            artifact_sha256: None,
        }],
        controls: vec![SemanticModelActivationControl {
            scope: SemanticModelControlScope::Workspace,
            action: SemanticModelControlAction::Enable,
            selector: SemanticModelPackSelector {
                pack_id: "fixture.rust.widget".to_owned(),
                version: None,
                manifest_digest: None,
            },
        }],
        limits: SemanticModelRuntimeLimits::default(),
    }
}

/// Retained evidence that the build declares `crate_name` and nothing indexed
/// it. This is the residue a Cargo discovery run leaves behind; constructing it
/// directly keeps the test offline.
fn declared_crate_evidence(crate_name: &str) -> DependencyDiscoveryEvidence {
    DependencyDiscoveryEvidence::from_outcome(&DependencyDiscoveryOutcome::complete(vec![
        ResolvedDependency {
            id: format!("rust:{crate_name}"),
            evidence: SemanticModelActivationEvidence {
                language: "rust".to_owned(),
                ecosystem: "cargo".to_owned(),
                package: Some(CatalogCoordinate {
                    name: crate_name.to_owned(),
                    version: None,
                }),
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            },
            provenance: Vec::new(),
            artifacts: Vec::new(),
        },
    ]))
}

fn activate(
    analyzer: &WorkspaceAnalyzer,
    pack: &CompiledSemanticModelPack,
    discovery: Option<DependencyDiscoveryEvidence>,
) {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    catalog
        .register_session_pack(
            pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "rust-diagnostics-fixture".to_owned(),
            },
        )
        .unwrap();
    let published = discovery.map(|evidence| [(Box::from([Language::Rust]), evidence)]);
    let SemanticModelRuntimeOutcome::Ready { .. } = acquire_active_semantic_models_with_evidence(
        analyzer.analyzer(),
        &catalog,
        None,
        &activation_request(),
        published.as_ref().map(|published| published.as_slice()),
        &CancellationToken::default(),
    ) else {
        panic!("Rust fixture pack must activate");
    };
    assert!(analyzer.analyzer().semantic_model_overlay().is_some());
}

struct RustFixture {
    project: crate::common::BuiltInlineTestProject,
    analyzer: WorkspaceAnalyzer,
}

impl RustFixture {
    fn new(files: &[(&str, &str)]) -> Self {
        let mut builder = InlineTestProject::with_language(Language::Rust);
        for (path, source) in files {
            builder = builder.file(*path, *source);
        }
        let project = builder.build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        Self { project, analyzer }
    }

    fn with_pack(files: &[(&str, &str)], completeness: &str) -> Self {
        let fixture = Self::new(files);
        activate(&fixture.analyzer, &widget_pack(completeness), None);
        fixture
    }

    fn with_declared_crate(files: &[(&str, &str)], crate_name: &str) -> Self {
        let fixture = Self::new(files);
        activate(
            &fixture.analyzer,
            &widget_pack("complete"),
            Some(declared_crate_evidence(crate_name)),
        );
        fixture
    }

    fn report(&self, rel_path: &str) -> SemanticDiagnosticReport {
        let file = self.project.file(rel_path);
        let source = file.read_to_string().expect("read fixture source");
        self.analyzer
            .analyzer()
            .semantic_diagnostics(&file, &source)
    }
}

fn resolved_at(report: &SemanticDiagnosticReport, boundary: BoundaryStatus) -> bool {
    report.outcomes().iter().any(|outcome| {
        matches!(outcome, SemanticDiagnosticOutcome::Resolved { boundary: found, .. }
            if *found == boundary)
    })
}

fn incomplete_reasons(
    report: &SemanticDiagnosticReport,
) -> Vec<&SemanticDiagnosticIncompleteReason> {
    report
        .outcomes()
        .iter()
        .filter_map(|outcome| match outcome {
            SemanticDiagnosticOutcome::Incomplete { reasons, .. } => Some(reasons),
            _ => None,
        })
        .flatten()
        .collect()
}

fn missing_dependency_boundaries(report: &SemanticDiagnosticReport) -> Vec<BoundaryStatus> {
    incomplete_reasons(report)
        .into_iter()
        .filter_map(|reason| match reason {
            SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery { boundary } => {
                Some(*boundary)
            }
            _ => None,
        })
        .collect()
}

/// An indexed dependency API never errors: the acceptance criterion that a path
/// into an activated pack resolves rather than being reported unrecognized.
#[test]
fn indexed_dependency_paths_resolve_at_the_external_boundary() {
    let fixture = RustFixture::with_pack(
        &[(
            "src/lib.rs",
            "pub fn consume() {\n    widget::Widget;\n    widget::nested::Deep;\n}\n",
        )],
        "complete",
    );

    let report = fixture.report("src/lib.rs");
    assert!(
        report.diagnostics().is_empty(),
        "an indexed dependency API must never error: {:#?}",
        report.diagnostics()
    );
    assert!(
        resolved_at(&report, BoundaryStatus::ExternalIndexed),
        "{:#?}",
        report.outcomes()
    );
}

/// A complete crate surface proves a missing exported name.
#[test]
fn complete_crate_surface_proves_a_missing_exported_item() {
    let fixture = RustFixture::with_pack(
        &[(
            "src/lib.rs",
            "pub fn consume() {\n    widget::Missing;\n}\n",
        )],
        "complete",
    );

    let report = fixture.report("src/lib.rs");
    let absent: Vec<_> = report
        .outcomes()
        .iter()
        .filter_map(|outcome| match outcome {
            SemanticDiagnosticOutcome::Absent(proof) => Some(proof),
            _ => None,
        })
        .collect();
    assert_eq!(1, absent.len(), "{:#?}", report.outcomes());
    assert_eq!(BoundaryStatus::ExternalIndexed, absent[0].boundary);
    assert!(
        report
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.message.contains("Missing")),
        "{:#?}",
        report.diagnostics()
    );
}

/// A pack that records its own surface partial cannot support an absence
/// claim. This is the re-export case too: the rustdoc producer marks a pack
/// partial exactly when it could not follow a `pub use` chain or a glob
/// re-export, so an unfollowed re-export suppresses instead of accusing.
#[test]
fn a_partial_crate_surface_suppresses_instead_of_proving_absence() {
    let fixture = RustFixture::with_pack(
        &[(
            "src/lib.rs",
            "pub fn consume() {\n    widget::Missing;\n}\n",
        )],
        "partial",
    );

    let report = fixture.report("src/lib.rs");
    assert!(
        report.diagnostics().is_empty(),
        "a partial surface must not accuse: {:#?}",
        report.diagnostics()
    );
    assert_eq!(SemanticDiagnosticReportStatus::Incomplete, report.status());
    assert!(
        incomplete_reasons(&report).iter().any(|reason| matches!(
            reason,
            SemanticDiagnosticIncompleteReason::UnsupportedSemantics { detail }
                if detail.contains("partial") && detail.contains(PACKAGE)
        )),
        "{:#?}",
        report.outcomes()
    );
}

/// A Cargo `package = "..."` rename is published as a pack alias, so the source
/// spelling resolves and diagnostics and definitions share one crate identity.
#[test]
fn a_renamed_dependency_resolves_under_the_spelling_the_source_uses() {
    let fixture = RustFixture::with_pack(
        &[(
            "src/lib.rs",
            "use renamed_widget::Widget;\npub fn consume() {\n    Widget;\n    renamed_widget::nested::Deep;\n}\n",
        )],
        "complete",
    );

    let report = fixture.report("src/lib.rs");
    assert!(
        report.diagnostics().is_empty(),
        "a renamed dependency must resolve under its renamed spelling: {:#?}",
        report.diagnostics()
    );
    assert!(
        resolved_at(&report, BoundaryStatus::ExternalIndexed),
        "{:#?}",
        report.outcomes()
    );
}

/// A missing extraction artifact suppresses, and says which rung it stopped on:
/// the build declares the crate but nothing indexed it.
#[test]
fn a_declared_but_unindexed_crate_reports_the_declared_boundary() {
    let fixture = RustFixture::with_declared_crate(
        &[(
            "src/lib.rs",
            "pub fn consume() {\n    other_dep::Thing;\n}\n",
        )],
        "other_dep",
    );

    let report = fixture.report("src/lib.rs");
    assert!(
        report.diagnostics().is_empty(),
        "{:#?}",
        report.diagnostics()
    );
    assert!(
        missing_dependency_boundaries(&report).contains(&BoundaryStatus::ExternalDeclaredUnindexed),
        "{:#?}",
        report.outcomes()
    );
}

/// Nothing retained at all is an unknown boundary, never an error.
#[test]
fn an_unknown_crate_reports_the_unknown_boundary() {
    let fixture = RustFixture::with_pack(
        &[(
            "src/lib.rs",
            "pub fn consume() {\n    never_seen::Thing;\n}\n",
        )],
        "complete",
    );

    let report = fixture.report("src/lib.rs");
    assert!(
        report.diagnostics().is_empty(),
        "{:#?}",
        report.diagnostics()
    );
    assert!(
        missing_dependency_boundaries(&report).contains(&BoundaryStatus::ExternalUnknown),
        "{:#?}",
        report.outcomes()
    );
}

/// A name a macro may synthesize is a generated surface, not an absence.
#[test]
fn macro_generated_names_are_typed_as_a_generated_surface() {
    let fixture = RustFixture::with_pack(
        &[(
            "src/lib.rs",
            "pub fn consume() {\n    println!(\"{}\", never_declared_anywhere);\n}\n",
        )],
        "complete",
    );

    let report = fixture.report("src/lib.rs");
    assert!(
        report.diagnostics().is_empty(),
        "{:#?}",
        report.diagnostics()
    );
    assert!(
        incomplete_reasons(&report).iter().any(|reason| matches!(
            reason,
            SemanticDiagnosticIncompleteReason::UnsupportedGeneratedSurface { .. }
        )),
        "{:#?}",
        report.outcomes()
    );
}

/// A `cfg`-gated item names the configuration this pass does not evaluate.
#[test]
fn cfg_gated_references_name_the_configuration_they_could_not_evaluate() {
    let fixture = RustFixture::with_pack(
        &[(
            "src/lib.rs",
            "#[cfg(feature = \"extras\")]\npub fn gated() {\n    only_under_extras;\n}\n",
        )],
        "complete",
    );

    let report = fixture.report("src/lib.rs");
    assert!(
        report.diagnostics().is_empty(),
        "{:#?}",
        report.diagnostics()
    );
    assert!(
        incomplete_reasons(&report).iter().any(|reason| matches!(
            reason,
            SemanticDiagnosticIncompleteReason::UnsupportedSemantics { detail }
                if detail.contains("cfg") && detail.contains("extras")
        )),
        "{:#?}",
        report.outcomes()
    );
}

/// A glob import puts an unenumerated set of names in scope, so a bare name it
/// could supply is suppressed with that exact reason.
#[test]
fn a_glob_import_suppresses_the_bare_names_it_could_supply() {
    let fixture = RustFixture::with_pack(
        &[(
            "src/lib.rs",
            "use widget::*;\npub fn consume() {\n    possibly_glob_supplied;\n}\n",
        )],
        "complete",
    );

    let report = fixture.report("src/lib.rs");
    assert!(
        report.diagnostics().is_empty(),
        "{:#?}",
        report.diagnostics()
    );
    assert!(
        incomplete_reasons(&report).iter().any(|reason| matches!(
            reason,
            SemanticDiagnosticIncompleteReason::UnsupportedSemantics { detail }
                if detail.contains("glob")
        )),
        "{:#?}",
        report.outcomes()
    );
}

/// A miss under a *type* owner is never proof, even when the crate surface is
/// complete. rustdoc skips blanket impls, and a trait bound or a `Deref` chain
/// can supply an associated item that a type's own impls never mention, so
/// "this method does not exist" is not something the surface can say. A miss
/// under a *module* owner stays provable, which is the other half of the rule.
#[test]
fn an_associated_item_miss_is_incomplete_while_a_module_item_miss_is_proof() {
    let fixture = RustFixture::with_pack(
        &[(
            "src/lib.rs",
            "pub fn consume() {\n    widget::Widget::not_an_inherent_item;\n    widget::nested::NotThere;\n}\n",
        )],
        "complete",
    );

    let report = fixture.report("src/lib.rs");
    assert!(
        incomplete_reasons(&report).iter().any(|reason| matches!(
            reason,
            SemanticDiagnosticIncompleteReason::UnsupportedSemantics { detail }
                if detail.contains("Deref") && detail.contains("widget::Widget")
        )),
        "an associated-item miss must not be proved absent: {:#?}",
        report.outcomes()
    );
    assert!(
        report.outcomes().iter().any(|outcome| matches!(
            outcome,
            SemanticDiagnosticOutcome::Absent(proof)
                if proof.boundary == BoundaryStatus::ExternalIndexed
        )),
        "a module-owned miss stays provable: {:#?}",
        report.outcomes()
    );
    assert!(
        report
            .diagnostics()
            .iter()
            .all(|diagnostic| !diagnostic.message.contains("not_an_inherent_item")),
        "{:#?}",
        report.diagnostics()
    );
}

/// A workspace-local name keeps its workspace proof: the external ladder never
/// takes over a reference the workspace already explains.
#[test]
fn workspace_references_keep_a_workspace_local_proof() {
    let fixture = RustFixture::with_pack(
        &[(
            "src/lib.rs",
            "pub fn consume() {\n    let bound = 1;\n    bound;\n    missing_local;\n}\n",
        )],
        "complete",
    );

    let report = fixture.report("src/lib.rs");
    assert!(
        resolved_at(&report, BoundaryStatus::WorkspaceLocal),
        "{:#?}",
        report.outcomes()
    );
    assert!(
        report.outcomes().iter().any(|outcome| matches!(
            outcome,
            SemanticDiagnosticOutcome::Absent(proof)
                if proof.boundary == BoundaryStatus::WorkspaceLocal
        )),
        "{:#?}",
        report.outcomes()
    );
}
