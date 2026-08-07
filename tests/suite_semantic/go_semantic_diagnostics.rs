//! Go's semantic diagnostics against exact module API packs (#1623).
//!
//! Every assertion is outcome-level: what a report *claims* matters more than
//! how many diagnostics it printed, because the contract is that a diagnostic
//! exists only where a complete surface proved absence.
//!
//! The packs here are authored offline and registered as session packs. No
//! test runs `go`, reads a module cache, or reaches the network.

use crate::common::InlineTestProject;
use brokk_bifrost::analyzer::DependencyPackEcosystem;
use brokk_bifrost::analyzer::semantic_model::{
    CatalogCoordinate, CatalogOptions, CompiledSemanticModelPack, CompilerOptions,
    SemanticModelActivationControl, SemanticModelActivationEvidence,
    SemanticModelActivationRequest, SemanticModelControlAction, SemanticModelControlScope,
    SemanticModelPackSelector, SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome,
    SemanticPackCatalog, SessionPackSource, SessionPackSourceKind, SourceFormat,
    acquire_active_semantic_models, compile_source,
};
use brokk_bifrost::{AnalyzerConfig, CancellationToken, Language, WorkspaceAnalyzer};
use brokk_bifrost_analysis::analyzer::structural::BoundaryStatus;
use brokk_bifrost_analysis::analyzer::{
    SemanticDiagnosticDomain, SemanticDiagnosticIncompleteReason, SemanticDiagnosticOutcome,
    SemanticDiagnosticReport,
};
use semver::Version;
use serde_json::{Value, json};

const MODULE: &str = "example.com/dep";
const API: &str = "example.com/dep/api";
const VIEWS: &str = "example.com/dep/presentation";
/// The name the Go pack producer scopes package-level functions, variables,
/// and constants under. Types carry the plain `<import path>.<Name>` instead.
const MODULE_SCOPE: &str = "_module_";

fn locator(symbol: &str) -> Value {
    json!({ "kind": "artifact", "path": "api/api.go", "symbol": symbol })
}

/// A pack that publishes two packages of module `example.com/dep`:
/// `api` (a type, a package function, and an embedded-promotion pair) and
/// `presentation`, whose `package` clause is `views` rather than its last
/// import-path segment.
fn dep_pack(completeness: &str) -> CompiledSemanticModelPack {
    let module_type = |id: &str, name: &str, aliases: Value| {
        json!({
            "id": id,
            "name": name,
            "type_kind": "module",
            "visibility": "package",
            "aliases": aliases,
            "locator": locator(name)
        })
    };
    let value = json!({
        "schema_version": 1,
        "pack_id": "fixture.go.dep",
        "version": "1.0.0",
        "producer": { "name": "go-fixture", "version": "1.0.0" },
        "language": "go",
        "ecosystem": "go-module",
        "compatibility": { "bifrost": "*", "toolchains": [] },
        "provenance": { "source": "fixture" },
        "license": "NOASSERTION",
        "completeness": completeness,
        "safety": { "generated_code_only": false, "review_required": false },
        "shards": [{
            "id": "declarations.external",
            "activation": [{ "module": { "name": MODULE } }],
            "payload": {
                "kind": "declaration_facts",
                "types": [
                    module_type("type.api.module", API, json!(["api"])),
                    module_type(
                        "type.api.scope",
                        &format!("{API}.{MODULE_SCOPE}"),
                        json!([]),
                    ),
                    module_type("type.views.module", VIEWS, json!(["views"])),
                    module_type(
                        "type.views.scope",
                        &format!("{VIEWS}.{MODULE_SCOPE}"),
                        json!([]),
                    ),
                    json!({
                        "id": "type.api.client",
                        "name": format!("{API}.Client"),
                        "type_kind": "struct",
                        "visibility": "public",
                        "locator": locator(&format!("{API}.Client")),
                        "embedded_types": [{
                            "target": { "kind": "named", "name": format!("{API}.base") },
                            "pointer": false
                        }]
                    }),
                    json!({
                        "id": "type.api.base",
                        "name": format!("{API}.base"),
                        "type_kind": "struct",
                        "visibility": "package",
                        "locator": locator(&format!("{API}.base"))
                    }),
                ],
                "members": [
                    json!({
                        "id": "member.api.exported",
                        "owner": "type.api.scope",
                        "name": "Exported",
                        "member_kind": "function",
                        "visibility": "public",
                        "signature": { "parameters": [] },
                        "locator": locator(&format!("{API}.Exported"))
                    }),
                    json!({
                        "id": "member.views.render",
                        "owner": "type.views.scope",
                        "name": "Render",
                        "member_kind": "function",
                        "visibility": "public",
                        "signature": { "parameters": [] },
                        "locator": locator(&format!("{VIEWS}.Render"))
                    }),
                    json!({
                        "id": "member.api.base.promoted",
                        "owner": "type.api.base",
                        "name": "Promoted",
                        "member_kind": "method",
                        "visibility": "public",
                        "signature": { "parameters": [] },
                        "receiver": { "pointer": false },
                        "locator": locator(&format!("{API}.base.Promoted"))
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
            language: "go".to_owned(),
            ecosystem: "go-module".to_owned(),
            package: None,
            module: Some(CatalogCoordinate {
                name: MODULE.to_owned(),
                version: None,
            }),
            toolchain: None,
            target: None,
            configuration: None,
            artifact_sha256: None,
        }],
        controls: vec![SemanticModelActivationControl {
            scope: SemanticModelControlScope::Workspace,
            action: SemanticModelControlAction::Enable,
            selector: SemanticModelPackSelector {
                pack_id: "fixture.go.dep".to_owned(),
                version: None,
                manifest_digest: None,
            },
        }],
        limits: SemanticModelRuntimeLimits::default(),
    }
}

/// Activate `pack` against `analyzer`. The catalog is ephemeral and the pack is
/// a session pack, so nothing is installed and nothing is downloaded.
fn activate(analyzer: &WorkspaceAnalyzer, pack: &CompiledSemanticModelPack) {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    catalog
        .register_session_pack(
            pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "go-diagnostics-fixture".to_owned(),
            },
        )
        .unwrap();
    let SemanticModelRuntimeOutcome::Ready { .. } = acquire_active_semantic_models(
        analyzer.analyzer(),
        &catalog,
        None,
        &activation_request(),
        &CancellationToken::default(),
    ) else {
        panic!("Go fixture pack must activate");
    };
    assert!(analyzer.analyzer().semantic_model_overlay().is_some());
}

struct GoFixture {
    project: crate::common::BuiltInlineTestProject,
    analyzer: WorkspaceAnalyzer,
}

impl GoFixture {
    fn new(files: &[(&str, &str)]) -> Self {
        let mut builder = InlineTestProject::with_language(Language::Go);
        for (path, source) in files {
            builder = builder.file(*path, *source);
        }
        let project = builder.build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        Self { project, analyzer }
    }

    fn with_pack(files: &[(&str, &str)], completeness: &str) -> Self {
        let fixture = Self::new(files);
        activate(&fixture.analyzer, &dep_pack(completeness));
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

fn go_mod() -> (&'static str, &'static str) {
    ("go.mod", "module example.com/app\n\ngo 1.22\n")
}

fn resolved_at(report: &SemanticDiagnosticReport, boundary: BoundaryStatus) -> bool {
    report.outcomes().iter().any(|outcome| {
        matches!(outcome, SemanticDiagnosticOutcome::Resolved { boundary: found, .. }
            if *found == boundary)
    })
}

fn absent_member(report: &SemanticDiagnosticReport, owner: &str, member: &str) -> bool {
    report.outcomes().iter().any(|outcome| {
        matches!(outcome, SemanticDiagnosticOutcome::Absent(proof)
        if proof.domain == SemanticDiagnosticDomain::MemberSurface {
            owner: owner.to_owned(),
            member: member.to_owned(),
        })
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

#[test]
fn workspace_package_member_is_resolved_and_a_miss_names_the_member_surface() {
    let fixture = GoFixture::new(&[
        go_mod(),
        ("store/store.go", "package store\n\nfunc Present() {}\n"),
        (
            "main.go",
            "package main\n\nimport \"example.com/app/store\"\n\nfunc Run() {\n\tstore.Present()\n\tstore.Missing()\n}\n",
        ),
    ]);

    let report = fixture.report("main.go");
    assert!(resolved_at(&report, BoundaryStatus::WorkspaceLocal));
    // The surface a package-member lookup checked is the package, not the
    // file's lexical scope: before #1623 every Go absence claimed the latter.
    assert!(
        absent_member(&report, "example.com/app/store", "Missing"),
        "{:#?}",
        report.outcomes()
    );
    assert_eq!(report.diagnostics().len(), 1, "{:#?}", report.diagnostics());
}

#[test]
fn external_import_without_any_retained_evidence_claims_nothing() {
    let fixture = GoFixture::new(&[
        go_mod(),
        (
            "main.go",
            "package main\n\nimport \"fmt\"\n\nfunc Run() {\n\tfmt.Println(\"ok\")\n}\n",
        ),
    ]);

    let report = fixture.report("main.go");
    assert!(
        report.diagnostics().is_empty(),
        "{:#?}",
        report.diagnostics()
    );
    assert!(
        incomplete_reasons(&report).iter().any(|reason| matches!(
            reason,
            SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                boundary: BoundaryStatus::ExternalUnknown
            }
        )),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn indexed_module_export_never_errors() {
    let fixture = GoFixture::with_pack(
        &[
            go_mod(),
            (
                "main.go",
                "package main\n\nimport \"example.com/dep/api\"\n\nfunc Run() {\n\tapi.Exported()\n\tvar c api.Client\n\t_ = c\n}\n",
            ),
        ],
        "complete",
    );

    let report = fixture.report("main.go");
    assert!(
        report.diagnostics().is_empty(),
        "{:#?}",
        report.diagnostics()
    );
    assert!(
        resolved_at(&report, BoundaryStatus::ExternalIndexed),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn complete_package_proves_a_missing_exported_member() {
    let fixture = GoFixture::with_pack(
        &[
            go_mod(),
            (
                "main.go",
                "package main\n\nimport \"example.com/dep/api\"\n\nfunc Run() {\n\tapi.Missing()\n}\n",
            ),
        ],
        "complete",
    );

    let report = fixture.report("main.go");
    assert!(
        absent_member(&report, API, "Missing"),
        "{:#?}",
        report.outcomes()
    );
    let diagnostics = report.diagnostics();
    assert_eq!(diagnostics.len(), 1, "{diagnostics:#?}");
    assert!(diagnostics[0].message.contains("Missing"));
}

#[test]
fn partial_package_surface_suppresses_the_member_claim() {
    let fixture = GoFixture::with_pack(
        &[
            go_mod(),
            (
                "main.go",
                "package main\n\nimport \"example.com/dep/api\"\n\nfunc Run() {\n\tapi.Missing()\n}\n",
            ),
        ],
        "partial",
    );

    let report = fixture.report("main.go");
    // A package whose pack recorded generated, cgo, or build-constrained
    // sources cannot prove that an exported member is missing.
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

#[test]
fn import_alias_resolves_through_the_same_package_identity() {
    let fixture = GoFixture::with_pack(
        &[
            go_mod(),
            (
                "main.go",
                "package main\n\nimport a \"example.com/dep/api\"\n\nfunc Run() {\n\ta.Exported()\n\ta.Missing()\n}\n",
            ),
        ],
        "complete",
    );

    let report = fixture.report("main.go");
    assert!(resolved_at(&report, BoundaryStatus::ExternalIndexed));
    // The alias binds the same package identity, so the absence proof names
    // the import path rather than the alias.
    assert!(
        absent_member(&report, API, "Missing"),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn declared_package_clause_binds_an_unaliased_import() {
    let fixture = GoFixture::with_pack(
        &[
            go_mod(),
            (
                "main.go",
                "package main\n\nimport \"example.com/dep/presentation\"\n\nfunc Run() {\n\tviews.Render()\n}\n",
            ),
        ],
        "complete",
    );

    let report = fixture.report("main.go");
    // `presentation` declares `package views`. Only the pack knows that, and
    // both the definition route and this one read it from the same place.
    assert!(
        report.diagnostics().is_empty(),
        "{:#?}",
        report.diagnostics()
    );
    assert!(
        resolved_at(&report, BoundaryStatus::ExternalIndexed),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn a_module_replacement_inside_the_workspace_stays_a_workspace_lookup() {
    let fixture = GoFixture::with_pack(
        &[
            (
                "go.mod",
                "module example.com/app\n\ngo 1.22\n\nreplace example.com/dep => ./local\n",
            ),
            ("local/go.mod", "module example.com/dep\n\ngo 1.22\n"),
            ("local/api/api.go", "package api\n\nfunc Local() {}\n"),
            (
                "main.go",
                "package main\n\nimport \"example.com/dep/api\"\n\nfunc Run() {\n\tapi.Local()\n}\n",
            ),
        ],
        "complete",
    );

    let report = fixture.report("main.go");
    // The replacement's source is in the workspace, so the workspace answers
    // the import and the pack's surface is never consulted. `Local` exists
    // only in the replacement, so an external claim here would be wrong.
    assert!(
        report.diagnostics().is_empty(),
        "{:#?}",
        report.diagnostics()
    );
    assert!(
        resolved_at(&report, BoundaryStatus::WorkspaceLocal),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn a_vendored_copy_stays_a_workspace_lookup() {
    let fixture = GoFixture::with_pack(
        &[
            go_mod(),
            (
                "vendor/example.com/dep/api/api.go",
                "package api\n\nfunc Vendored() {}\n",
            ),
            (
                "main.go",
                "package main\n\nimport \"example.com/dep/api\"\n\nfunc Run() {\n\tapi.Vendored()\n}\n",
            ),
        ],
        "complete",
    );

    let report = fixture.report("main.go");
    assert!(
        report.diagnostics().is_empty(),
        "{:#?}",
        report.diagnostics()
    );
    assert!(
        resolved_at(&report, BoundaryStatus::WorkspaceLocal),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn a_promoted_member_of_an_external_type_produces_no_false_absence() {
    let fixture = GoFixture::with_pack(
        &[
            go_mod(),
            (
                "main.go",
                "package main\n\nimport \"example.com/dep/api\"\n\nfunc Run(c api.Client) {\n\tc.Promoted()\n}\n",
            ),
        ],
        "complete",
    );

    let report = fixture.report("main.go");
    // `c` is a value, not a package qualifier, so this request checked no
    // package surface. Embedded promotion belongs to `get_definition`; a
    // diagnostic must never turn it into an absence claim.
    assert!(
        report.diagnostics().is_empty(),
        "{:#?}",
        report.diagnostics()
    );
}

#[test]
fn one_local_name_for_two_packages_claims_neither() {
    let fixture = GoFixture::new(&[
        go_mod(),
        ("first/api/api.go", "package api\n\nfunc First() {}\n"),
        ("second/api/api.go", "package api\n\nfunc Second() {}\n"),
        (
            "main.go",
            "package main\n\nimport (\n\t\"example.com/app/first/api\"\n\t\"example.com/app/second/api\"\n)\n\nfunc Run() {\n\tapi.Missing()\n}\n",
        ),
    ]);

    let report = fixture.report("main.go");
    // Two packages answer `api`, so no single package surface can prove the
    // member absent.
    assert!(
        report.diagnostics().is_empty(),
        "{:#?}",
        report.diagnostics()
    );
    assert!(
        report
            .outcomes()
            .iter()
            .any(|outcome| matches!(outcome, SemanticDiagnosticOutcome::Ambiguous { .. })),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn invalidating_the_go_ecosystem_withdraws_every_external_claim() {
    let source =
        "package main\n\nimport \"example.com/dep/api\"\n\nfunc Run() {\n\tapi.Missing()\n}\n";
    let fixture = GoFixture::with_pack(&[go_mod(), ("main.go", source)], "complete");
    assert_eq!(fixture.report("main.go").diagnostics().len(), 1);

    // A configuration change that drops Go's activated packs must refresh
    // diagnostics: the proof those diagnostics rested on is gone.
    assert!(
        fixture
            .analyzer
            .invalidate_dependency_pack_state(&[DependencyPackEcosystem::Go])
    );
    assert!(
        fixture
            .analyzer
            .analyzer()
            .semantic_model_overlay()
            .is_none()
    );

    let report = fixture.report("main.go");
    assert!(
        report.diagnostics().is_empty(),
        "{:#?}",
        report.diagnostics()
    );
    assert!(
        incomplete_reasons(&report).iter().any(|reason| matches!(
            reason,
            SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery { .. }
        )),
        "{:#?}",
        report.outcomes()
    );
}
