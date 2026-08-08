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
/// What a consuming Cargo.toml renames it to with `package = "widget"`.
const RENAMED: &str = "renamed_widget";

/// How the consuming workspace reaches the crate the fixture pack describes.
///
/// This is the distinction `apply_cargo_dependency_spellings` draws for a real
/// rustdoc pack, reproduced here so the offline packs model both workspaces.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CrateSpelling {
    /// Declared under its own name, so that name is what source writes.
    Own,
    /// Declared with `package = "..."`, so only [`RENAMED`] reaches it. The
    /// crate's own name stays on the inner facts, where the pack's own
    /// recorded type paths are spelled with it, and leaves the crate root.
    Renamed,
}

fn locator(symbol: &str) -> Value {
    json!({ "kind": "artifact", "path": "rustdoc/api.json", "symbol": symbol })
}

/// A pack publishing crate `widget`: its root module, a `Widget` struct with an
/// inherent `render`, and a nested `widget::nested::Deep`.
///
/// Under [`CrateSpelling::Renamed`] every fact also carries the renamed
/// spelling as an alias and the root module fact is published under the
/// renamed spelling alone, which is how a Cargo `package =` rename reaches the
/// overlay.
fn widget_pack(completeness: &str, spelling: CrateSpelling) -> CompiledSemanticModelPack {
    let aliased = |name: &str| match spelling {
        CrateSpelling::Own => json!([]),
        CrateSpelling::Renamed => json!([name.replacen(PACKAGE, RENAMED, 1)]),
    };
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
    // The crate root is the one fact whose name plays only the "what source
    // writes" role, so a rename replaces it rather than aliasing it.
    let root_fact = |id: &str| match spelling {
        CrateSpelling::Own => type_fact(id, PACKAGE, "module"),
        CrateSpelling::Renamed => json!({
            "id": id,
            "name": RENAMED,
            "type_kind": "module",
            "visibility": "public",
            "aliases": json!([]),
            "locator": locator(PACKAGE)
        }),
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
                    root_fact("type.widget.root"),
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

/// A pack for a crate whose `Serialize` is declared at `widget::internal` and
/// re-exported from the crate root with `pub use`.
///
/// `followed` is the whole point of the fixture. A rustdoc producer that walks
/// the `pub use` chain publishes the *re-exported* spelling `widget.Serialize`
/// alongside the declaration, and records a complete surface. One that cannot
/// walk it publishes only `widget.internal.Serialize` and records itself
/// partial -- which is what stops the ladder proving `widget::Serialize`
/// absent when it plainly is not.
fn reexport_pack(followed: bool) -> CompiledSemanticModelPack {
    let type_fact = |id: &str, name: &str, kind: &str| {
        json!({
            "id": id,
            "name": name,
            "type_kind": kind,
            "visibility": "public",
            "aliases": json!([]),
            "locator": locator(name)
        })
    };
    let mut types = vec![
        type_fact("type.reexport.root", PACKAGE, "module"),
        type_fact("type.reexport.internal", "widget.internal", "module"),
        type_fact(
            "type.reexport.declared",
            "widget.internal.Serialize",
            "struct",
        ),
    ];
    if followed {
        types.push(type_fact(
            "type.reexport.surfaced",
            "widget.Serialize",
            "struct",
        ));
    }
    let value = json!({
        "schema_version": 1,
        "pack_id": "fixture.rust.reexport",
        "version": "1.0.0",
        "producer": { "name": "rust-fixture", "version": "1.0.0" },
        "language": "rust",
        "ecosystem": "cargo",
        "compatibility": { "bifrost": "*", "toolchains": [] },
        "provenance": { "source": "fixture" },
        "license": "NOASSERTION",
        "completeness": if followed { "complete" } else { "partial" },
        "safety": { "generated_code_only": false, "review_required": false },
        "shards": [{
            "id": "declarations.rust.external",
            "activation": [{ "package": { "name": PACKAGE } }],
            "payload": {
                "kind": "declaration_facts",
                "types": types,
                "members": [],
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

/// A complete `widget` pack whose shard activates only for `pack_target`.
fn target_pinned_pack(pack_target: &str) -> CompiledSemanticModelPack {
    let type_fact = |id: &str, name: &str, kind: &str| {
        json!({
            "id": id,
            "name": name,
            "type_kind": kind,
            "visibility": "public",
            "aliases": json!([]),
            "locator": locator(name)
        })
    };
    let value = json!({
        "schema_version": 1,
        "pack_id": "fixture.rust.target",
        "version": "1.0.0",
        "producer": { "name": "rust-fixture", "version": "1.0.0" },
        "language": "rust",
        "ecosystem": "cargo",
        "compatibility": { "bifrost": "*", "toolchains": [] },
        "provenance": { "source": "fixture" },
        "license": "NOASSERTION",
        "completeness": "complete",
        "safety": { "generated_code_only": false, "review_required": false },
        "shards": [{
            "id": "declarations.rust.external",
            "activation": [{
                "package": { "name": PACKAGE },
                "targets": [pack_target]
            }],
            "payload": {
                "kind": "declaration_facts",
                "types": [
                    type_fact("type.target.root", PACKAGE, "module"),
                    type_fact("type.target.widget", "widget.Widget", "struct"),
                ],
                "members": [],
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

fn activation_request_for(
    pack_id: &str,
    evidence_target: Option<&str>,
) -> SemanticModelActivationRequest {
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
            target: evidence_target.map(str::to_owned),
            configuration: None,
            artifact_sha256: None,
        }],
        controls: vec![SemanticModelActivationControl {
            scope: SemanticModelControlScope::Workspace,
            action: SemanticModelControlAction::Enable,
            selector: SemanticModelPackSelector {
                pack_id: pack_id.to_owned(),
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
    activate_pack(analyzer, pack, "fixture.rust.widget", discovery, None);
    assert!(analyzer.analyzer().semantic_model_overlay().is_some());
}

/// Register `pack` as a session pack and activate it under `pack_id`.
///
/// Unlike [`activate`] this asserts nothing about the resulting overlay,
/// because one caller deliberately activates a pack whose shard cannot match
/// the workspace evidence.
fn activate_pack(
    analyzer: &WorkspaceAnalyzer,
    pack: &CompiledSemanticModelPack,
    pack_id: &str,
    discovery: Option<DependencyDiscoveryEvidence>,
    evidence_target: Option<&str>,
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
        &activation_request_for(pack_id, evidence_target),
        published.as_ref().map(|published| published.as_slice()),
        &CancellationToken::default(),
    ) else {
        panic!("Rust fixture pack must activate");
    };
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

    /// A workspace that declares `widget` under its own name.
    fn with_pack(files: &[(&str, &str)], completeness: &str) -> Self {
        let fixture = Self::new(files);
        activate(
            &fixture.analyzer,
            &widget_pack(completeness, CrateSpelling::Own),
            None,
        );
        fixture
    }

    /// A workspace whose Cargo.toml renames `widget` to `renamed_widget`.
    fn with_renamed_pack(files: &[(&str, &str)], completeness: &str) -> Self {
        let fixture = Self::new(files);
        activate(
            &fixture.analyzer,
            &widget_pack(completeness, CrateSpelling::Renamed),
            None,
        );
        fixture
    }

    fn with_declared_crate(files: &[(&str, &str)], crate_name: &str) -> Self {
        let fixture = Self::new(files);
        activate(
            &fixture.analyzer,
            &widget_pack("complete", CrateSpelling::Own),
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
    let fixture = RustFixture::with_renamed_pack(
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

/// A `pub use` chain the producer followed: the re-exported spelling is
/// published, so the source path into it resolves at the external boundary.
#[test]
fn a_followed_reexport_resolves_at_the_external_boundary() {
    let fixture = RustFixture::new(&[(
        "src/lib.rs",
        "pub fn consume() {\n    widget::Serialize;\n}\n",
    )]);
    activate_pack(
        &fixture.analyzer,
        &reexport_pack(true),
        "fixture.rust.reexport",
        None,
        None,
    );

    let report = fixture.report("src/lib.rs");
    assert!(
        report.diagnostics().is_empty(),
        "a followed re-export must resolve: {:#?}",
        report.diagnostics()
    );
    assert!(
        resolved_at(&report, BoundaryStatus::ExternalIndexed),
        "{:#?}",
        report.outcomes()
    );
}

/// A `pub use` chain the producer could not follow. The re-exported spelling is
/// missing from the pack even though the crate really exports it, so proving it
/// absent would be a false accusation. The producer records the surface partial
/// for exactly this reason, and the ladder answers Incomplete.
///
/// The declaration the chain points at is still published, which is what
/// distinguishes "the pack could not follow the re-export" from "the pack knows
/// nothing about this crate".
#[test]
fn an_unfollowed_reexport_suppresses_instead_of_proving_absence() {
    let fixture = RustFixture::new(&[(
        "src/lib.rs",
        "pub fn consume() {\n    widget::Serialize;\n    widget::internal::Serialize;\n}\n",
    )]);
    activate_pack(
        &fixture.analyzer,
        &reexport_pack(false),
        "fixture.rust.reexport",
        None,
        None,
    );

    let report = fixture.report("src/lib.rs");
    assert!(
        report.diagnostics().is_empty(),
        "an unfollowed re-export must not be accused: {:#?}",
        report.diagnostics()
    );
    assert!(
        resolved_at(&report, BoundaryStatus::ExternalIndexed),
        "the declaration the chain points at must still resolve: {:#?}",
        report.outcomes()
    );
    assert!(
        incomplete_reasons(&report).iter().any(|reason| matches!(
            reason,
            SemanticDiagnosticIncompleteReason::UnsupportedSemantics { detail }
                if detail.contains("partial")
        )),
        "{:#?}",
        report.outcomes()
    );
}

/// A pack produced for a different target cannot prove absence, because the
/// activation runtime never publishes it: its shard pins a target the workspace
/// evidence does not name, so the crate reads as unindexed rather than as a
/// complete surface with a missing item.
#[test]
fn a_pack_for_another_target_cannot_prove_absence() {
    let fixture = RustFixture::new(&[(
        "src/lib.rs",
        "pub fn consume() {\n    widget::Missing;\n}\n",
    )]);
    activate_pack(
        &fixture.analyzer,
        &target_pinned_pack("aarch64-apple-darwin"),
        "fixture.rust.target",
        None,
        Some("x86_64-unknown-linux-gnu"),
    );

    let report = fixture.report("src/lib.rs");
    assert!(
        report.diagnostics().is_empty(),
        "a pack for another target must not accuse: {:#?}",
        report.diagnostics()
    );
    assert!(
        missing_dependency_boundaries(&report).contains(&BoundaryStatus::ExternalUnknown),
        "{:#?}",
        report.outcomes()
    );
}

/// The other direction of the same rule: when the pack's target is the one the
/// workspace resolves, the shard activates and the complete surface proves the
/// missing item. Without this the test above would pass for the wrong reason.
#[test]
fn a_pack_for_the_workspace_target_proves_absence() {
    let fixture = RustFixture::new(&[(
        "src/lib.rs",
        "pub fn consume() {\n    widget::Missing;\n}\n",
    )]);
    activate_pack(
        &fixture.analyzer,
        &target_pinned_pack("x86_64-unknown-linux-gnu"),
        "fixture.rust.target",
        None,
        Some("x86_64-unknown-linux-gnu"),
    );

    let report = fixture.report("src/lib.rs");
    assert!(
        report.outcomes().iter().any(|outcome| matches!(
            outcome,
            SemanticDiagnosticOutcome::Absent(proof)
                if proof.boundary == BoundaryStatus::ExternalIndexed
        )),
        "a matching-target pack must still prove absence: {:#?}",
        report.outcomes()
    );
}

/// The rename end to end, both halves.
///
/// A Cargo `package = "..."` rename reaches the overlay as an *alias* on every
/// inner fact and as a *replacement* at the crate root
/// (`apply_cargo_dependency_spellings`), so the renamed spelling resolves and a
/// name absent under it is still proved absent against the same complete
/// surface.
///
/// The crate's own spelling is the other half. Under a rename `widget::Widget`
/// is not a path Cargo accepts and rustc would reject it, so the ladder must
/// not resolve it. It does not claim absence either: the crate root the source
/// named is unpublished, which is the same rung an entirely unknown crate
/// stops on. This is the behaviour #1795 asked for, and it replaces the
/// deliberate both-spellings record this test carried before (commit
/// 86c8cd0a), which pinned the gap so this change would have to flip it.
#[test]
fn a_cargo_rename_resolves_the_renamed_spelling_and_refuses_the_original() {
    let fixture = RustFixture::with_renamed_pack(
        &[(
            "src/lib.rs",
            "pub fn consume() {\n    renamed_widget::Widget;\n    renamed_widget::Missing;\n}\n",
        )],
        "complete",
    );

    let report = fixture.report("src/lib.rs");
    assert!(
        resolved_at(&report, BoundaryStatus::ExternalIndexed),
        "the renamed spelling must resolve: {:#?}",
        report.outcomes()
    );
    assert!(
        report.outcomes().iter().any(|outcome| matches!(
            outcome,
            SemanticDiagnosticOutcome::Absent(proof)
                if proof.boundary == BoundaryStatus::ExternalIndexed
        )),
        "a miss under the renamed spelling is proved against the same surface: {:#?}",
        report.outcomes()
    );
    assert!(
        report
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.message.contains("Missing")),
        "{:#?}",
        report.diagnostics()
    );

    // The crate's own spelling is not a path this workspace can write, so it
    // resolves to nothing and proves nothing.
    let original = RustFixture::with_renamed_pack(
        &[("src/lib.rs", "pub fn consume() {\n    widget::Widget;\n}\n")],
        "complete",
    );
    let original_report = original.report("src/lib.rs");
    assert!(
        original_report.diagnostics().is_empty(),
        "a renamed-away spelling accuses nothing: {:#?}",
        original_report.diagnostics()
    );
    assert!(
        !resolved_at(&original_report, BoundaryStatus::ExternalIndexed),
        "the crate's own spelling must not resolve under a rename: {:#?}",
        original_report.outcomes()
    );
    assert!(
        missing_dependency_boundaries(&original_report).contains(&BoundaryStatus::ExternalUnknown),
        "a renamed-away crate root is unindexed, exactly as an unknown crate is: {:#?}",
        original_report.outcomes()
    );
}

/// The pack keeps its own name for its own paths.
///
/// A rename replaces the crate root only. Every inner fact keeps the crate's
/// own name, because that is how the rustdoc JSON spells the type paths the
/// pack recorded -- a signature naming `widget::Error`, a hierarchy target, a
/// member's owner path -- and those must keep resolving against the pack after
/// the workspace can no longer write `widget` itself.
#[test]
fn a_rename_leaves_the_packs_own_type_paths_resolvable() {
    let fixture = RustFixture::with_renamed_pack(
        &[(
            "src/lib.rs",
            "pub fn consume() {\n    renamed_widget::nested::Deep;\n}\n",
        )],
        "complete",
    );
    let overlay = fixture
        .analyzer
        .analyzer()
        .semantic_model_overlay()
        .expect("the renamed pack must publish an overlay");

    for own_path in ["widget.Widget", "widget.nested", "widget.nested.Deep"] {
        assert_eq!(
            overlay.symbols_named(own_path).records.len(),
            1,
            "the pack's own recorded path `{own_path}` must stay resolvable: {:#?}",
            overlay.symbols()
        );
    }
    let publishes_crate_root = |spelling: &str| {
        overlay
            .symbols_named(spelling)
            .records
            .iter()
            .any(|symbol| symbol.qualified_name == spelling)
    };
    assert!(
        !publishes_crate_root(PACKAGE),
        "the renamed-away crate root must not be published: {:#?}",
        overlay.symbols_named(PACKAGE).records
    );
    assert!(
        publishes_crate_root(RENAMED),
        "the crate root is published under the spelling the workspace writes: {:#?}",
        overlay.symbols_named(RENAMED).records
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
