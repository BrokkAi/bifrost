use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use brokk_bifrost::CancellationToken;
use brokk_bifrost::analyzer::GoDependencyPackAdapter;
use brokk_bifrost::analyzer::semantic_model::{
    AuthoredSemanticModelPack, CatalogCoordinate, CatalogOpenMode, CatalogOptions, Completeness,
    DependencyArtifactRole, DependencyPackAdapter, DependencyPackLimits,
    DependencyPackPreparationStatus, DependencyPackProduction, DependencyProvenance,
    DurablePackSource, DurablePackSourceKind, ExactDependencyArtifact, ExternalArtifactKind,
    Producer, ResolvedActiveSemanticModels, ResolvedDependency, ResolvedDependencyArtifact,
    SemanticModelActivationEvidence, SemanticModelActivationRequest,
    SemanticModelResolutionOutcome, SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome,
    SemanticPackCatalog, SourceFormat, acquire_active_semantic_models, compile_pack,
    compile_source, prepare_dependency_semantic_packs, resolve_active_semantic_models,
};
use brokk_bifrost::searchtools::{
    DefinitionReferenceQuery, GetDefinitionParams, ScanUsagesByReferenceParams, ScanUsagesStatus,
    SearchSymbolsParams, SymbolLookupParams, get_definitions_by_location, get_symbol_ancestors,
    scan_usages_by_reference, search_symbols,
};
use brokk_bifrost::{AnalyzerConfig, Language};
use lsp_types::{
    GotoDefinitionParams, GotoDefinitionResponse, HoverContents, HoverParams, Position,
    SignatureHelpParams, TextDocumentIdentifier, TextDocumentPositionParams, Uri,
    WorkDoneProgressParams,
};
use semver::Version;

use crate::common::InlineTestProject;

const DECLARATIONS_JSON: &[u8] =
    include_bytes!("../fixtures/semantic-model-packs/declarations-v1.json");

#[derive(Default)]
struct FixtureAdapter {
    productions: AtomicUsize,
}

impl DependencyPackAdapter for FixtureAdapter {
    fn adapter_name(&self) -> &str {
        "fixture-maven"
    }

    fn adapter_version(&self) -> &str {
        "1"
    }

    fn producer(&self) -> Producer {
        Producer {
            name: "artifact-scanner".to_owned(),
            version: "2.0.0".to_owned(),
        }
    }

    fn produce(
        &self,
        _dependency: &ResolvedDependency,
        artifacts: &[ExactDependencyArtifact],
        _limits: &brokk_bifrost::analyzer::semantic_model::ArtifactProducerLimits,
        _cancellation: Option<&CancellationToken>,
    ) -> DependencyPackProduction {
        self.productions.fetch_add(1, Ordering::Relaxed);
        assert_eq!(artifacts.len(), 1);
        assert!(!artifacts[0].bytes().is_empty());
        DependencyPackProduction {
            pack: Some(serde_json::from_slice(DECLARATIONS_JSON).unwrap()),
            diagnostics: Vec::new(),
            suppressed_diagnostics: 0,
        }
    }
}

fn dependency(path: std::path::PathBuf) -> ResolvedDependency {
    ResolvedDependency {
        id: "com.acme:widget:1.5.0".to_owned(),
        evidence: SemanticModelActivationEvidence {
            language: "java".to_owned(),
            ecosystem: "maven".to_owned(),
            package: Some(CatalogCoordinate {
                name: "com.acme:widget".to_owned(),
                version: Some(Version::parse("1.5.0").unwrap()),
            }),
            module: None,
            toolchain: None,
            target: Some("jvm".to_owned()),
            configuration: Some("release".to_owned()),
            artifact_sha256: None,
        },
        provenance: Vec::new(),
        artifacts: vec![ResolvedDependencyArtifact::file(
            DependencyArtifactRole::Binary,
            ExternalArtifactKind::JavaClassJar,
            path,
        )],
    }
}

fn activation_request() -> SemanticModelActivationRequest {
    SemanticModelActivationRequest {
        bifrost_version: Version::parse("0.8.17").unwrap(),
        evidence: Vec::new(),
        controls: Vec::new(),
        limits: SemanticModelRuntimeLimits::default(),
    }
}

#[test]
fn exact_go_source_set_produces_and_compiles_api_pack() {
    let root = tempfile::tempdir().unwrap();
    let source_root = root.path().join("module");
    let standard_library_root = root.path().join("goroot/src");
    std::fs::create_dir_all(source_root.join("api")).unwrap();
    std::fs::create_dir_all(source_root.join("presentation")).unwrap();
    std::fs::create_dir_all(standard_library_root.join("io")).unwrap();
    std::fs::write(
        source_root.join("api/api.go"),
        r#"
package api
import "io"
type Constraint interface { ~int | ~string }
type Box[T Constraint] struct { Value T }
func (Box[T]) Read(value T) T { return value }
func (*Box[T]) Write(value T) {}
func Exported(value Box[int]) Box[string] { return Box[string]{} }
type hidden struct{}
func (hidden) Promoted() {}
type Public struct { hidden }
type Reader interface { Read() }
type ReadWriter interface { Reader; Write() }
type Embedded struct { io.Reader }
type Concrete struct{}
func (Concrete) Read() {}
"#,
    )
    .unwrap();
    std::fs::write(
        standard_library_root.join("io/io.go"),
        "package io\ntype Reader interface { Read() }\n",
    )
    .unwrap();
    std::fs::write(
        source_root.join("presentation/view.go"),
        "package views\nfunc Render() {}\n",
    )
    .unwrap();
    let module_dependency = ResolvedDependency {
        id: "go:module:example.com/dep@v1.2.3".to_owned(),
        evidence: SemanticModelActivationEvidence {
            language: "go".to_owned(),
            ecosystem: "go-module".to_owned(),
            package: None,
            module: Some(CatalogCoordinate {
                name: "example.com/dep".to_owned(),
                version: Some(Version::new(1, 2, 3)),
            }),
            toolchain: Some(CatalogCoordinate {
                name: "go".to_owned(),
                version: Some(Version::new(1, 26, 0)),
            }),
            target: Some("go-linux-arm64".to_owned()),
            configuration: Some(format!("go-config-{}", "0".repeat(64))),
            artifact_sha256: None,
        },
        provenance: vec![
            DependencyProvenance {
                key: "go.packages".to_owned(),
                value: serde_json::json!([{
                    "import_path": "example.com/dep/api",
                    "name": "api",
                    "directory": "api",
                    "files": ["api/api.go"],
                    "ignored_go_files": [],
                    "cgo_files": []
                }, {
                    "import_path": "example.com/dep/presentation",
                    "name": "views",
                    "directory": "presentation",
                    "files": ["presentation/view.go"],
                    "ignored_go_files": [],
                    "cgo_files": []
                }])
                .to_string(),
            },
            DependencyProvenance {
                key: "module.sum".to_owned(),
                value: "h1:exact".to_owned(),
            },
        ],
        artifacts: vec![ResolvedDependencyArtifact::source_set(
            DependencyArtifactRole::Sources,
            ExternalArtifactKind::GoSourceSet,
            source_root,
            vec![
                std::path::PathBuf::from("api/api.go"),
                std::path::PathBuf::from("presentation/view.go"),
            ],
        )],
    };
    let standard_library_dependency = ResolvedDependency {
        id: "go:stdlib:go1.26.0".to_owned(),
        evidence: SemanticModelActivationEvidence {
            language: "go".to_owned(),
            ecosystem: "go-stdlib".to_owned(),
            package: None,
            module: None,
            toolchain: Some(CatalogCoordinate {
                name: "go".to_owned(),
                version: Some(Version::new(1, 26, 0)),
            }),
            target: Some("go-linux-arm64".to_owned()),
            configuration: Some(format!("go-config-{}", "0".repeat(64))),
            artifact_sha256: None,
        },
        provenance: vec![DependencyProvenance {
            key: "go.packages".to_owned(),
            value: serde_json::json!([{
                "import_path": "io",
                "name": "io",
                "directory": "io",
                "files": ["io/io.go"],
                "ignored_go_files": [],
                "cgo_files": []
            }])
            .to_string(),
        }],
        artifacts: vec![ResolvedDependencyArtifact::source_set(
            DependencyArtifactRole::Sources,
            ExternalArtifactKind::GoSourceSet,
            standard_library_root,
            vec![std::path::PathBuf::from("io/io.go")],
        )],
    };
    let catalog = SemanticPackCatalog::open(
        &root.path().join("catalog"),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let prepare_started = Instant::now();
    let outcome = prepare_dependency_semantic_packs(
        &catalog,
        &GoDependencyPackAdapter,
        &[module_dependency, standard_library_dependency],
        &DependencyPackLimits::default(),
        None,
    );
    let prepare_elapsed = prepare_started.elapsed();
    assert!(outcome.complete, "{:#?}", outcome.diagnostics);
    assert_eq!(outcome.packs.len(), 2);
    assert!(outcome.packs.iter().all(|pack| {
        pack.status == DependencyPackPreparationStatus::Generated
            && pack.completeness == Completeness::Complete
    }));
    assert_eq!(outcome.profile.artifacts_read, 2);
    assert_eq!(outcome.profile.generated_packs, 2);

    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main
import api "example.com/dep/api"
import "example.com/dep/presentation"
func main() {
    api.Exported()
    views.Render()
}
type localAPI struct{}
func (localAPI) Exported() {}
var _ = api.Concrete.Read
func shadow(api localAPI) { api.Exported() }
"#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let files_before = analyzer.analyzer().project().all_files().unwrap();
    let mut request = activation_request();
    request.bifrost_version = Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
    let request = outcome.compose_activation_request(request).unwrap();
    let activation_started = Instant::now();
    let SemanticModelRuntimeOutcome::Ready { active, .. } = acquire_active_semantic_models(
        analyzer.analyzer(),
        &catalog,
        None,
        &request,
        &CancellationToken::default(),
    ) else {
        panic!("Go dependency pack must activate");
    };
    let activation_elapsed = activation_started.elapsed();
    assert_eq!(
        files_before,
        analyzer.analyzer().project().all_files().unwrap(),
        "external Go sources must remain outside the workspace"
    );
    let overlay = analyzer.analyzer().semantic_model_overlay().unwrap();
    assert_eq!(
        overlay
            .symbols_named("example.com/dep/api.Exported")
            .records
            .len(),
        1,
        "{:#?}",
        overlay.symbols()
    );
    let definition_query = GetDefinitionParams {
        references: vec![
            DefinitionReferenceQuery {
                path: "main.go".to_owned(),
                line: Some(5),
                column: Some(9),
            },
            DefinitionReferenceQuery {
                path: "main.go".to_owned(),
                line: Some(6),
                column: Some(11),
            },
            DefinitionReferenceQuery {
                path: "main.go".to_owned(),
                line: Some(10),
                column: Some(23),
            },
        ],
    };
    let cold_lookup_started = Instant::now();
    let definitions = get_definitions_by_location(analyzer.analyzer(), definition_query.clone());
    let cold_lookup_elapsed = cold_lookup_started.elapsed();
    let warm_lookup_started = Instant::now();
    let warm_definitions = get_definitions_by_location(analyzer.analyzer(), definition_query);
    let warm_lookup_elapsed = warm_lookup_started.elapsed();
    assert_eq!(
        warm_definitions.results[0].definitions[0].fqn,
        definitions.results[0].definitions[0].fqn
    );
    assert!(cold_lookup_elapsed.as_secs() < 5);
    assert!(warm_lookup_elapsed.as_secs() < 5);
    eprintln!(
        "exact Go API pack lifecycle: prepare={prepare_elapsed:?}, activation={activation_elapsed:?}, retained={} bytes, cold_definition={cold_lookup_elapsed:?}, warm_definition={warm_lookup_elapsed:?}, input={} bytes",
        active.retained_bytes(),
        outcome.profile.artifact_bytes_read,
    );
    assert_eq!(
        definitions.results[0].status, "resolved",
        "{definitions:#?}"
    );
    assert_eq!(
        definitions.results[0].definitions[0].fqn.as_deref(),
        Some("example.com/dep/api.Exported")
    );
    assert!(
        definitions.results[0].definitions[0]
            .path
            .starts_with("bifrost-model://v1/")
    );
    assert!(
        definitions.results[0].definitions[0]
            .signature
            .as_deref()
            .is_some_and(|signature| signature.contains("Exported(value")),
        "{definitions:#?}"
    );
    assert_eq!(
        definitions.results[1].status, "resolved",
        "{definitions:#?}"
    );
    assert_eq!(
        definitions.results[1].definitions[0].fqn.as_deref(),
        Some("example.com/dep/presentation.Render")
    );
    assert_eq!(
        definitions.results[2].definitions[0].fqn.as_deref(),
        Some("example.com/dep/api.Concrete.Read"),
        "{definitions:#?}"
    );
    let main_file = analyzer
        .analyzer()
        .project()
        .file_by_rel_path(std::path::Path::new("main.go"))
        .unwrap();
    let uri: Uri = brokk_bifrost_lsp::lsp::conversion::path_to_uri_string(&main_file.abs_path())
        .parse()
        .unwrap();
    let text_position = |line, character| TextDocumentPositionParams {
        text_document: TextDocumentIdentifier { uri: uri.clone() },
        position: Position { line, character },
    };
    let lsp_definition = brokk_bifrost_lsp::lsp::benchmark_api::definition::handle(
        &analyzer,
        analyzer.analyzer().project(),
        &GotoDefinitionParams {
            text_document_position_params: text_position(4, 10),
            work_done_progress_params: WorkDoneProgressParams::default(),
            partial_result_params: Default::default(),
        },
        brokk_bifrost::NavigationOperation::Definition,
    )
    .unwrap();
    let GotoDefinitionResponse::Array(lsp_locations) = lsp_definition else {
        panic!("expected model definition locations");
    };
    assert_eq!(lsp_locations.len(), 1);
    assert!(
        lsp_locations[0]
            .uri
            .as_str()
            .starts_with("bifrost-model://v1/")
    );
    let hover = brokk_bifrost_lsp::lsp::benchmark_api::hover::handle(
        &analyzer,
        analyzer.analyzer().project(),
        &HoverParams {
            text_document_position_params: text_position(4, 10),
            work_done_progress_params: WorkDoneProgressParams::default(),
        },
    )
    .unwrap();
    let HoverContents::Markup(markup) = hover.contents else {
        panic!("expected model hover markup");
    };
    assert!(markup.value.contains("Exported"), "{markup:#?}");
    let signature = brokk_bifrost_lsp::lsp::benchmark_api::signature_help::handle(
        &analyzer,
        analyzer.analyzer().project(),
        &SignatureHelpParams {
            text_document_position_params: text_position(4, 17),
            work_done_progress_params: WorkDoneProgressParams::default(),
            context: None,
        },
    )
    .unwrap();
    assert!(signature.signatures[0].label.contains("Exported"));
    let symbols = search_symbols(
        analyzer.analyzer(),
        SearchSymbolsParams {
            patterns: vec![
                "Promoted".to_owned(),
                "Embedded.Read".to_owned(),
                "hidden".to_owned(),
            ],
            include_tests: false,
            limit: 20,
        },
    );
    assert!(
        symbols
            .model_symbols
            .iter()
            .any(|symbol| { symbol.qualified_name == "example.com/dep/api.Public.Promoted" })
    );
    assert!(
        symbols
            .model_symbols
            .iter()
            .any(|symbol| { symbol.qualified_name == "example.com/dep/api.Embedded.Read" }),
        "cross-pack embedding must expose the promoted standard-library method"
    );
    assert!(
        !symbols
            .model_symbols
            .iter()
            .any(|symbol| { symbol.qualified_name == "example.com/dep/api.hidden" })
    );
    let hierarchy = get_symbol_ancestors(
        analyzer.analyzer(),
        SymbolLookupParams {
            symbols: vec!["example.com/dep/api.ReadWriter".to_owned()],
        },
    );
    assert_eq!(hierarchy.ancestors.len(), 1, "{hierarchy:#?}");
    assert!(
        hierarchy.ancestors[0]
            .ancestors
            .contains(&"example.com/dep/api.Reader".to_owned()),
        "{hierarchy:#?}"
    );
    let concrete_hierarchy = get_symbol_ancestors(
        analyzer.analyzer(),
        SymbolLookupParams {
            symbols: vec!["example.com/dep/api.Concrete".to_owned()],
        },
    );
    assert!(
        concrete_hierarchy.ancestors[0]
            .ancestors
            .contains(&"example.com/dep/api.Reader".to_owned()),
        "{concrete_hierarchy:#?}"
    );
    assert!(
        concrete_hierarchy.ancestors[0]
            .ancestors
            .contains(&"io.Reader".to_owned()),
        "cross-pack structural interface satisfaction must be visible: {concrete_hierarchy:#?}"
    );
    let usages = scan_usages_by_reference(
        analyzer.analyzer(),
        ScanUsagesByReferenceParams {
            symbols: vec![
                "example.com/dep/api.Exported".to_owned(),
                "example.com/dep/api.Concrete.Read".to_owned(),
            ],
            include_tests: false,
            paths: None,
            include_same_owner: false,
            max_duration_secs: None,
        },
    );
    assert_eq!(
        usages.results[0].status,
        ScanUsagesStatus::Found,
        "{usages:#?}"
    );
    assert!(
        usages.results[0]
            .files
            .iter()
            .any(|file| { file.path == "main.go" && file.hits.iter().any(|hit| hit.line == 5) })
    );
    assert!(
        usages.results[0]
            .files
            .iter()
            .flat_map(|file| &file.hits)
            .all(|hit| hit.line != 11),
        "the local api parameter shadows the imported package: {usages:#?}"
    );
    assert_eq!(
        usages.results[1].status,
        ScanUsagesStatus::Found,
        "{usages:#?}"
    );
    assert!(
        usages.results[1]
            .files
            .iter()
            .any(|file| file.path == "main.go" && file.hits.iter().any(|hit| hit.line == 10))
    );
}

fn ready(outcome: SemanticModelResolutionOutcome) -> ResolvedActiveSemanticModels {
    match outcome {
        SemanticModelResolutionOutcome::Ready(active) => active,
        other => panic!("expected ready semantic models, got {other:#?}"),
    }
}

#[test]
fn identical_bytes_reuse_one_generated_production_across_paths() {
    let root = tempfile::tempdir().unwrap();
    let first_path = root.path().join("workspace-a/widget.jar");
    let second_path = root.path().join("workspace-b/widget.jar");
    std::fs::create_dir_all(first_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(second_path.parent().unwrap()).unwrap();
    std::fs::write(&first_path, b"same exact artifact bytes").unwrap();
    std::fs::write(&second_path, b"same exact artifact bytes").unwrap();
    let catalog = SemanticPackCatalog::open(
        &root.path().join("catalog"),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let adapter = FixtureAdapter::default();

    let first = prepare_dependency_semantic_packs(
        &catalog,
        &adapter,
        &[dependency(first_path)],
        &DependencyPackLimits::default(),
        None,
    );
    let accounting = catalog.accounting().unwrap();
    let second = prepare_dependency_semantic_packs(
        &catalog,
        &adapter,
        &[dependency(second_path)],
        &DependencyPackLimits::default(),
        None,
    );

    assert!(first.complete, "{:#?}", first.diagnostics);
    assert!(second.complete, "{:#?}", second.diagnostics);
    assert_eq!(
        first.packs[0].status,
        DependencyPackPreparationStatus::Generated
    );
    assert_eq!(
        second.packs[0].status,
        DependencyPackPreparationStatus::Reused
    );
    assert_eq!(first.packs[0].production, second.packs[0].production);
    assert_eq!(first.evidence, second.evidence);
    assert_eq!(adapter.productions.load(Ordering::Relaxed), 1);
    assert_eq!(catalog.accounting().unwrap(), accounting);
    assert_eq!(
        second
            .compose_activation_request(activation_request())
            .unwrap()
            .evidence,
        second.evidence
    );
}

#[test]
fn identical_source_sets_reuse_one_production_across_roots_and_file_order() {
    struct SourceSetAdapter(FixtureAdapter);

    impl DependencyPackAdapter for SourceSetAdapter {
        fn adapter_name(&self) -> &str {
            self.0.adapter_name()
        }

        fn adapter_version(&self) -> &str {
            self.0.adapter_version()
        }

        fn producer(&self) -> Producer {
            self.0.producer()
        }

        fn produce(
            &self,
            dependency: &ResolvedDependency,
            artifacts: &[ExactDependencyArtifact],
            limits: &brokk_bifrost::analyzer::semantic_model::ArtifactProducerLimits,
            cancellation: Option<&CancellationToken>,
        ) -> DependencyPackProduction {
            assert_eq!(
                artifacts[0]
                    .source_entries()
                    .iter()
                    .map(|entry| entry.relative_path())
                    .collect::<Vec<_>>(),
                ["pkg/a.go", "pkg/b.go"]
            );
            self.0.produce(dependency, artifacts, limits, cancellation)
        }
    }

    fn source_set(root: &std::path::Path, reversed: bool) -> ResolvedDependency {
        std::fs::create_dir_all(root.join("pkg")).unwrap();
        std::fs::write(root.join("pkg/a.go"), b"package pkg\ntype A struct{}\n").unwrap();
        std::fs::write(root.join("pkg/b.go"), b"package pkg\nfunc B() {}\n").unwrap();
        let mut dependency = dependency(root.to_path_buf());
        let mut paths = vec![
            std::path::PathBuf::from("pkg/a.go"),
            std::path::PathBuf::from("pkg/b.go"),
        ];
        if reversed {
            paths.reverse();
        }
        dependency.artifacts = vec![ResolvedDependencyArtifact::source_set(
            DependencyArtifactRole::Sources,
            ExternalArtifactKind::GoSourceSet,
            root.to_path_buf(),
            paths,
        )];
        dependency
    }

    let temp = tempfile::tempdir().unwrap();
    let first_root = temp.path().join("first");
    let second_root = temp.path().join("second");
    let catalog = SemanticPackCatalog::open(
        &temp.path().join("catalog"),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let adapter = SourceSetAdapter(FixtureAdapter::default());

    let first = prepare_dependency_semantic_packs(
        &catalog,
        &adapter,
        &[source_set(&first_root, true)],
        &DependencyPackLimits::default(),
        None,
    );
    let second = prepare_dependency_semantic_packs(
        &catalog,
        &adapter,
        &[source_set(&second_root, false)],
        &DependencyPackLimits::default(),
        None,
    );

    assert!(first.complete, "{:#?}", first.diagnostics);
    assert!(second.complete, "{:#?}", second.diagnostics);
    assert_eq!(
        first.packs[0].status,
        DependencyPackPreparationStatus::Generated
    );
    assert_eq!(
        second.packs[0].status,
        DependencyPackPreparationStatus::Reused
    );
    assert_eq!(first.packs[0].production, second.packs[0].production);
    assert_eq!(adapter.0.productions.load(Ordering::Relaxed), 1);
}

#[test]
fn evidence_only_dependency_uses_compatible_installed_pack() {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let compiled =
        compile_source(SourceFormat::Json, DECLARATIONS_JSON, &Default::default()).unwrap();
    catalog
        .install(
            &compiled,
            &DurablePackSource {
                kind: DurablePackSourceKind::PreShipped,
                source_id: "github-release:test".to_owned(),
            },
        )
        .unwrap();
    let mut dependency = dependency(std::path::PathBuf::new());
    dependency.artifacts.clear();
    let adapter = FixtureAdapter::default();

    let prepared = prepare_dependency_semantic_packs(
        &catalog,
        &adapter,
        &[dependency],
        &DependencyPackLimits::default(),
        None,
    );

    assert!(prepared.complete, "{:#?}", prepared.diagnostics);
    assert!(prepared.packs.is_empty());
    assert_eq!(prepared.installed_packs.len(), 1);
    assert_eq!(prepared.profile.installed_packs, 1);
    assert_eq!(prepared.evidence.len(), 1);
    assert!(prepared.evidence[0].artifact_sha256.is_none());
    assert_eq!(adapter.productions.load(Ordering::Relaxed), 0);
    assert!(
        prepared
            .compose_activation_request(activation_request())
            .is_some()
    );
}

#[test]
fn evidence_only_dependency_never_selects_a_pack_without_exact_version() {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let compiled =
        compile_source(SourceFormat::Json, DECLARATIONS_JSON, &Default::default()).unwrap();
    catalog
        .install(
            &compiled,
            &DurablePackSource {
                kind: DurablePackSourceKind::PreShipped,
                source_id: "github-release:test".to_owned(),
            },
        )
        .unwrap();
    let mut dependency = dependency(std::path::PathBuf::new());
    dependency.artifacts.clear();
    dependency.evidence.package.as_mut().unwrap().version = None;
    let adapter = FixtureAdapter::default();

    let prepared = prepare_dependency_semantic_packs(
        &catalog,
        &adapter,
        &[dependency],
        &DependencyPackLimits::default(),
        None,
    );

    assert!(!prepared.complete);
    assert!(prepared.installed_packs.is_empty());
    assert!(prepared.evidence.is_empty());
    assert_eq!(prepared.diagnostics[0].code, "dependency.pack_unavailable");
    assert_eq!(adapter.productions.load(Ordering::Relaxed), 0);
}

#[test]
fn partial_installed_pack_composes_evidence_without_claiming_complete_coverage() {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let mut authored: AuthoredSemanticModelPack =
        serde_json::from_slice(DECLARATIONS_JSON).unwrap();
    authored.completeness = Completeness::Partial;
    let compiled = compile_pack(&authored, &Default::default()).unwrap();
    catalog
        .install(
            &compiled,
            &DurablePackSource {
                kind: DurablePackSourceKind::PreShipped,
                source_id: "github-release:partial-test".to_owned(),
            },
        )
        .unwrap();
    let mut dependency = dependency(std::path::PathBuf::new());
    dependency.artifacts.clear();

    let prepared = prepare_dependency_semantic_packs(
        &catalog,
        &FixtureAdapter::default(),
        &[dependency],
        &DependencyPackLimits::default(),
        None,
    );

    assert!(!prepared.complete);
    assert_eq!(prepared.installed_packs.len(), 1);
    assert_eq!(
        prepared.installed_packs[0].completeness,
        Completeness::Partial
    );
    assert!(
        prepared
            .compose_activation_request(activation_request())
            .is_some()
    );
}

#[test]
fn changed_artifact_bytes_invalidate_only_the_exact_production() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("widget.jar");
    std::fs::write(&path, b"first artifact revision").unwrap();
    let catalog = SemanticPackCatalog::open(
        &root.path().join("catalog"),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let adapter = FixtureAdapter::default();
    let first = prepare_dependency_semantic_packs(
        &catalog,
        &adapter,
        &[dependency(path.clone())],
        &DependencyPackLimits::default(),
        None,
    );

    std::fs::write(&path, b"second artifact revision").unwrap();
    let second = prepare_dependency_semantic_packs(
        &catalog,
        &adapter,
        &[dependency(path)],
        &DependencyPackLimits::default(),
        None,
    );

    assert!(first.complete && second.complete);
    assert_ne!(
        first.packs[0].production.key.input_digest(),
        second.packs[0].production.key.input_digest()
    );
    assert_ne!(
        first.packs[0].production.manifest_digest,
        second.packs[0].production.manifest_digest
    );
    assert_eq!(adapter.productions.load(Ordering::Relaxed), 2);
    assert_eq!(catalog.accounting().unwrap().source_count, 2);
}

#[test]
fn output_affecting_generation_limits_have_distinct_production_keys() {
    let root = tempfile::tempdir().unwrap();
    let artifact = root.path().join("widget.jar");
    std::fs::write(&artifact, b"same artifact").unwrap();
    let catalog = SemanticPackCatalog::open(
        &root.path().join("catalog"),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let adapter = FixtureAdapter::default();
    let default_limits = DependencyPackLimits::default();
    let mut constrained_limits = default_limits;
    constrained_limits.producer.max_records -= 1;

    let first = prepare_dependency_semantic_packs(
        &catalog,
        &adapter,
        &[dependency(artifact.clone())],
        &default_limits,
        None,
    );
    let second = prepare_dependency_semantic_packs(
        &catalog,
        &adapter,
        &[dependency(artifact)],
        &constrained_limits,
        None,
    );

    assert!(first.complete && second.complete);
    assert_ne!(
        first.packs[0].production.key,
        second.packs[0].production.key
    );
    assert_eq!(adapter.productions.load(Ordering::Relaxed), 2);
}

#[test]
fn cancellation_before_artifact_read_publishes_nothing() {
    let root = tempfile::tempdir().unwrap();
    let artifact = root.path().join("widget.jar");
    std::fs::write(&artifact, b"artifact").unwrap();
    let catalog = SemanticPackCatalog::open(
        &root.path().join("catalog"),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let adapter = FixtureAdapter::default();
    let cancellation = CancellationToken::default();
    cancellation.cancel();

    let outcome = prepare_dependency_semantic_packs(
        &catalog,
        &adapter,
        &[dependency(artifact)],
        &DependencyPackLimits::default(),
        Some(&cancellation),
    );

    assert!(outcome.cancelled);
    assert!(!outcome.complete);
    assert!(outcome.packs.is_empty());
    assert!(outcome.evidence.is_empty());
    assert_eq!(adapter.productions.load(Ordering::Relaxed), 0);
    assert_eq!(catalog.accounting().unwrap().object_count, 0);
    assert!(
        outcome
            .compose_activation_request(activation_request())
            .is_none()
    );
}

#[test]
fn missing_artifact_is_partial_and_never_claims_empty_success() {
    let root = tempfile::tempdir().unwrap();
    let catalog = SemanticPackCatalog::open(
        &root.path().join("catalog"),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let adapter = FixtureAdapter::default();

    let outcome = prepare_dependency_semantic_packs(
        &catalog,
        &adapter,
        &[dependency(root.path().join("missing.jar"))],
        &DependencyPackLimits::default(),
        None,
    );

    assert!(!outcome.complete);
    assert!(!outcome.cancelled);
    assert!(outcome.packs.is_empty());
    assert!(outcome.evidence.is_empty());
    assert_eq!(outcome.diagnostics[0].code, "artifact.metadata");
    assert_eq!(adapter.productions.load(Ordering::Relaxed), 0);
    assert!(
        outcome
            .compose_activation_request(activation_request())
            .is_none()
    );
}

#[test]
fn partial_generated_pack_is_reproduced_with_actionable_diagnostic() {
    struct PartialAdapter(FixtureAdapter);

    impl DependencyPackAdapter for PartialAdapter {
        fn adapter_name(&self) -> &str {
            self.0.adapter_name()
        }

        fn adapter_version(&self) -> &str {
            self.0.adapter_version()
        }

        fn producer(&self) -> Producer {
            self.0.producer()
        }

        fn produce(
            &self,
            dependency: &ResolvedDependency,
            artifacts: &[ExactDependencyArtifact],
            limits: &brokk_bifrost::analyzer::semantic_model::ArtifactProducerLimits,
            cancellation: Option<&CancellationToken>,
        ) -> DependencyPackProduction {
            let mut production = self.0.produce(dependency, artifacts, limits, cancellation);
            production.pack.as_mut().unwrap().completeness = Completeness::Partial;
            production
        }
    }

    let root = tempfile::tempdir().unwrap();
    let artifact = root.path().join("widget.jar");
    std::fs::write(&artifact, b"artifact").unwrap();
    let catalog = SemanticPackCatalog::open(
        &root.path().join("catalog"),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let adapter = PartialAdapter(FixtureAdapter::default());
    let first = prepare_dependency_semantic_packs(
        &catalog,
        &adapter,
        &[dependency(artifact.clone())],
        &DependencyPackLimits::default(),
        None,
    );
    let second = prepare_dependency_semantic_packs(
        &catalog,
        &adapter,
        &[dependency(artifact)],
        &DependencyPackLimits::default(),
        None,
    );

    assert!(!first.complete && !second.complete);
    assert_eq!(first.packs[0].completeness, Completeness::Partial);
    assert_eq!(second.packs[0].completeness, Completeness::Partial);
    assert_eq!(
        second.packs[0].status,
        DependencyPackPreparationStatus::Generated
    );
    assert_eq!(second.diagnostics[0].code, "production.partial");
    assert_eq!(adapter.0.productions.load(Ordering::Relaxed), 2);
}

#[test]
fn changing_one_dependency_preserves_unrelated_production_and_overlay() {
    struct DistinctAdapter;

    impl DependencyPackAdapter for DistinctAdapter {
        fn adapter_name(&self) -> &str {
            "distinct-fixture"
        }

        fn adapter_version(&self) -> &str {
            "1"
        }

        fn producer(&self) -> Producer {
            Producer {
                name: "artifact-scanner".to_owned(),
                version: "2.0.0".to_owned(),
            }
        }

        fn produce(
            &self,
            dependency: &ResolvedDependency,
            artifacts: &[ExactDependencyArtifact],
            _limits: &brokk_bifrost::analyzer::semantic_model::ArtifactProducerLimits,
            _cancellation: Option<&CancellationToken>,
        ) -> DependencyPackProduction {
            let revision = artifacts[0].bytes()[0] as char;
            let mut pack: brokk_bifrost::analyzer::semantic_model::AuthoredSemanticModelPack =
                serde_json::from_slice(DECLARATIONS_JSON).unwrap();
            pack.pack_id = format!("fixture.{}", dependency.id);
            pack.compatibility.toolchains.clear();
            pack.shards[0].id = format!("declarations.{}", dependency.id);
            pack.shards[0].activation = vec![
                brokk_bifrost::analyzer::semantic_model::ActivationSelector {
                    package: None,
                    module: Some(brokk_bifrost::analyzer::semantic_model::NameSelector {
                        name: dependency.id.clone(),
                        version: None,
                    }),
                    toolchain: None,
                    targets: Vec::new(),
                    configurations: Vec::new(),
                    artifact_sha256: None,
                },
            ];
            let brokk_bifrost::analyzer::semantic_model::AuthoredPayload::DeclarationFacts {
                types,
                members,
                relations,
            } = &mut pack.shards[0].payload
            else {
                unreachable!()
            };
            types.truncate(1);
            types[0].id = format!("type.{}", dependency.id);
            types[0].name = format!("com.acme.{}{revision}", dependency.id);
            members.clear();
            relations.clear();
            DependencyPackProduction {
                pack: Some(pack),
                diagnostics: Vec::new(),
                suppressed_diagnostics: 0,
            }
        }
    }

    fn distinct_dependency(id: &str, path: std::path::PathBuf) -> ResolvedDependency {
        ResolvedDependency {
            id: id.to_owned(),
            evidence: SemanticModelActivationEvidence {
                language: "java".to_owned(),
                ecosystem: "maven".to_owned(),
                package: None,
                module: Some(CatalogCoordinate {
                    name: id.to_owned(),
                    version: None,
                }),
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            },
            provenance: vec![DependencyProvenance {
                key: "fixture".to_owned(),
                value: id.to_owned(),
            }],
            artifacts: vec![ResolvedDependencyArtifact::file(
                DependencyArtifactRole::Binary,
                ExternalArtifactKind::JavaClassJar,
                path,
            )],
        }
    }

    let root = tempfile::tempdir().unwrap();
    let alpha = root.path().join("alpha.jar");
    let beta = root.path().join("beta.jar");
    std::fs::write(&alpha, b"1-alpha").unwrap();
    std::fs::write(&beta, b"1-beta").unwrap();
    let catalog = SemanticPackCatalog::open(
        &root.path().join("catalog"),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let first = prepare_dependency_semantic_packs(
        &catalog,
        &DistinctAdapter,
        &[
            distinct_dependency("alpha", alpha.clone()),
            distinct_dependency("beta", beta.clone()),
        ],
        &DependencyPackLimits::default(),
        None,
    );
    assert!(first.complete, "{:#?}", first.diagnostics);
    let first_active = ready(resolve_active_semantic_models(
        &catalog,
        &first
            .compose_activation_request(activation_request())
            .unwrap(),
        &CancellationToken::default(),
    ));

    std::fs::write(&alpha, b"2-alpha").unwrap();
    let second = prepare_dependency_semantic_packs(
        &catalog,
        &DistinctAdapter,
        &[
            distinct_dependency("alpha", alpha),
            distinct_dependency("beta", beta),
        ],
        &DependencyPackLimits::default(),
        None,
    );
    let second_active = ready(resolve_active_semantic_models(
        &catalog,
        &second
            .compose_activation_request(activation_request())
            .unwrap(),
        &CancellationToken::default(),
    ));

    assert!(first.complete && second.complete);
    assert_eq!(
        second.packs[0].status,
        DependencyPackPreparationStatus::Generated
    );
    assert_eq!(
        second.packs[1].status,
        DependencyPackPreparationStatus::Reused
    );
    assert_ne!(first.packs[0].production, second.packs[0].production);
    assert_eq!(first.packs[1].production, second.packs[1].production);
    assert_eq!(
        first_active.shards().len(),
        2,
        "{:#?}",
        first_active.activation_report()
    );
    assert_eq!(
        second_active.shards().len(),
        2,
        "{:#?}",
        second_active.activation_report()
    );
    assert_ne!(
        first_active.active_model_set_hash(),
        second_active.active_model_set_hash()
    );
    assert_eq!(first_active.types_named("com.acme.alpha1").records.len(), 1);
    assert!(
        second_active
            .types_named("com.acme.alpha1")
            .records
            .is_empty()
    );
    assert_eq!(
        second_active.types_named("com.acme.alpha2").records.len(),
        1
    );
    assert_eq!(first_active.types_named("com.acme.beta1").records.len(), 1);
    assert_eq!(second_active.types_named("com.acme.beta1").records.len(), 1);
}
