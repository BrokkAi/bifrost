use std::collections::HashMap;
use std::fs;
use std::time::Instant;

use brokk_bifrost::analyzer::semantic_model::{
    CatalogOptions, Completeness, DependencyPackLimits, DependencyPackPreparationStatus,
    SemanticModelActivationRequest, SemanticModelRuntimeOutcome, SemanticPackCatalog,
    acquire_active_semantic_models, prepare_dependency_semantic_packs,
};
use brokk_bifrost::searchtools::{
    DefinitionReferenceQuery, GetDefinitionParams, ScanUsagesByReferenceParams, ScanUsagesStatus,
    SearchSymbolsParams, SymbolLookupParams, get_definitions_by_location, get_symbol_sources,
    scan_usages_by_reference, search_symbols,
};
use brokk_bifrost::{
    AnalyzerConfig, CancellationToken, Language, RustAnalyzerConfig, RustDependencyApiEvidence,
    RustDependencyPackAdapter, RustPackageApiArtifact, RustSelectedTarget,
};
use rustdoc_types::{
    Abi, Constant as RustdocConstant, Crate as RustdocCrate, Enum, Function, FunctionHeader,
    FunctionSignature, GenericBound, GenericParamDef, GenericParamDefKind, Generics, Id, Impl,
    Item, ItemEnum, ItemKind, ItemSummary, MacroKind, Module, Path as RustdocPath, ProcMacro,
    Static, Struct, StructKind, Target, Trait, TraitBoundModifier, Type, TypeAlias, Union, Use,
    Variant, VariantKind, Visibility as RustVisibility, WherePredicate,
};
use semver::Version;
use serde_json::json;

use crate::common::InlineTestProject;

const ROOT_ID: &str = "path+file:///workspace#consumer@0.1.0";
const REGISTRY_ID: &str = "registry+https://github.com/rust-lang/crates.io-index#widget@1.2.3";
const GIT_SOURCE: &str = "git+https://github.com/acme/git-api?rev=abc#abc123";
const GIT_ID: &str = "git+https://github.com/acme/git-api?rev=abc#abc123#git-api@0.4.0";
const PATH_ID: &str = "path+file:///workspace/vendor/path-api#path-api@0.7.0";
const TARGET: &str = "x86_64-unknown-linux-gnu";

#[test]
fn exact_cargo_evidence_activates_registry_git_and_path_dependency_apis() {
    let fixture = RustDependencyFixture::new();
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            "use renamed_widget::Widget;\npub fn consume(value: Widget) -> Widget { value }\n",
        )
        .build();
    let analyzer_config = AnalyzerConfig {
        rust: RustAnalyzerConfig {
            dependency_api_evidence: vec![fixture.evidence.clone()],
        },
        ..Default::default()
    };
    let analyzer = project.workspace_analyzer(analyzer_config.clone());
    let files_before = analyzer.analyzer().project().all_files().unwrap();
    let limits = DependencyPackLimits::default();

    let discovery_started = Instant::now();
    let discovery = brokk_bifrost::resolve_rust_semantic_pack_dependencies(
        &analyzer_config.rust,
        analyzer.analyzer().project(),
        &limits,
        None,
    );
    let discovery_elapsed = discovery_started.elapsed();
    assert!(discovery.complete, "{:#?}", discovery.diagnostics);
    assert_eq!(discovery.dependencies.len(), 3);
    let repeated_discovery = brokk_bifrost::resolve_rust_semantic_pack_dependencies(
        &analyzer_config.rust,
        analyzer.analyzer().project(),
        &limits,
        None,
    );
    assert_eq!(repeated_discovery.dependencies, discovery.dependencies);
    assert_eq!(
        discovery
            .dependencies
            .iter()
            .map(|dependency| dependency.evidence.package.as_ref().unwrap().name.as_str())
            .collect::<Vec<_>>(),
        ["git-api", "path-api", "widget"]
    );
    let widget = discovery
        .dependencies
        .iter()
        .find(|dependency| dependency.id.contains("widget@1.2.3"))
        .unwrap();
    assert!(
        widget.provenance.iter().any(|entry| {
            entry.key == "cargo.dependency_name" && entry.value == "renamed_widget"
        })
    );
    assert!(
        widget
            .provenance
            .iter()
            .any(|entry| { entry.key == "cargo.feature" && entry.value == "derive" })
    );
    assert!(widget.provenance.iter().any(|entry| {
        entry.key == "cargo.selected_target" && entry.value == "consumer@0.1.0:consumer:lib"
    }));

    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let cold_started = Instant::now();
    let cold = prepare_dependency_semantic_packs(
        &catalog,
        &RustDependencyPackAdapter,
        &discovery.dependencies,
        &limits,
        None,
    );
    let cold_elapsed = cold_started.elapsed();
    assert!(cold.complete, "{:#?}", cold.diagnostics);
    assert_eq!(cold.profile.generated_packs, 3);
    assert!(
        cold.packs
            .iter()
            .all(|pack| pack.status == DependencyPackPreparationStatus::Generated)
    );

    let warm_started = Instant::now();
    let warm = prepare_dependency_semantic_packs(
        &catalog,
        &RustDependencyPackAdapter,
        &discovery.dependencies,
        &limits,
        None,
    );
    let warm_elapsed = warm_started.elapsed();
    assert!(warm.complete, "{:#?}", warm.diagnostics);
    assert_eq!(warm.profile.reused_packs, 3);
    assert!(
        warm.packs
            .iter()
            .all(|pack| pack.status == DependencyPackPreparationStatus::Reused)
    );

    let request = warm
        .compose_activation_request(SemanticModelActivationRequest {
            bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
            evidence: Vec::new(),
            controls: Vec::new(),
            limits: Default::default(),
        })
        .unwrap();
    let SemanticModelRuntimeOutcome::Ready { active, .. } = acquire_active_semantic_models(
        analyzer.analyzer(),
        &catalog,
        None,
        &request,
        &CancellationToken::default(),
    ) else {
        panic!("exact Rust dependency models must activate");
    };
    assert_eq!(active.shards().len(), 3);
    let overlay = analyzer
        .analyzer()
        .semantic_model_overlay()
        .expect("activation must publish the dependency overlay");
    let widget = overlay.symbols_named("widget.Widget");
    assert_eq!(widget.records.len(), 1, "{:#?}", overlay.symbols());
    assert!(
        widget.records[0]
            .aliases
            .iter()
            .any(|alias| alias.ends_with(".Gadget")),
        "{:?}",
        widget.records[0].aliases
    );
    let widget_uri = widget.records[0].location.identity().to_owned();
    assert!(widget_uri.starts_with("bifrost-model://v1/"));
    assert!(!widget_uri.contains(project.root().to_string_lossy().as_ref()));
    assert_eq!(
        overlay.symbols_named("renamed_widget.Widget").records.len(),
        1,
        "Cargo dependency renames must be navigable aliases"
    );
    let members = overlay.members_of(&widget.records[0].id);
    let render = members
        .records
        .iter()
        .find(|member| member.name == "render")
        .unwrap();
    assert!(render.signature.as_ref().unwrap().contains("str"));
    let ancestors = overlay.ancestors_of(widget.records[0]);
    assert!(
        ancestors
            .records
            .iter()
            .any(|ancestor| ancestor.qualified_name == "widget.Display")
    );
    assert!(
        !overlay
            .relations_to(&widget.records[0].id)
            .records
            .is_empty()
    );
    for expected in ["widget.Packet", "widget.Mode", "widget.WidgetAlias"] {
        assert_eq!(
            overlay.symbols_named(expected).records.len(),
            1,
            "{expected}"
        );
    }
    for expected in ["DeriveWidget", "DEFAULT_WIDGET", "WIDGET_COUNT"] {
        assert!(
            overlay
                .symbols()
                .iter()
                .any(|symbol| symbol.name == expected)
        );
    }

    let search = search_symbols(
        analyzer.analyzer(),
        SearchSymbolsParams {
            patterns: vec!["Widget".to_owned()],
            include_tests: false,
            limit: 10,
        },
    );
    assert!(
        search
            .model_symbols
            .iter()
            .any(|symbol| symbol.qualified_name == "widget.Widget")
    );
    let sources = get_symbol_sources(
        analyzer.analyzer(),
        SymbolLookupParams {
            symbols: vec![widget_uri.clone()],
        },
    );
    assert_eq!(sources.sources.len(), 1);
    assert!(sources.sources[0].semantic_model.is_some());
    let definitions = get_definitions_by_location(
        analyzer.analyzer(),
        GetDefinitionParams {
            references: vec![DefinitionReferenceQuery {
                path: widget_uri,
                line: None,
                column: None,
            }],
        },
    );
    assert_eq!(definitions.results[0].status, "resolved");
    let authored_definition = get_definitions_by_location(
        analyzer.analyzer(),
        GetDefinitionParams {
            references: vec![
                DefinitionReferenceQuery {
                    path: "src/lib.rs".to_owned(),
                    line: Some(1),
                    column: Some(21),
                },
                DefinitionReferenceQuery {
                    path: "src/lib.rs".to_owned(),
                    line: Some(2),
                    column: Some(23),
                },
            ],
        },
    );
    for result in &authored_definition.results {
        assert_eq!(result.status, "resolved", "{result:#?}");
        assert!(
            result
                .definitions
                .iter()
                .any(|definition| definition.path.starts_with("bifrost-model://v1/")),
            "{result:#?}"
        );
    }
    let usages = scan_usages_by_reference(
        analyzer.analyzer(),
        ScanUsagesByReferenceParams {
            symbols: vec!["widget.Widget".to_owned()],
            include_tests: false,
            paths: None,
            include_same_owner: false,
            max_duration_secs: None,
        },
    );
    assert_eq!(usages.results[0].status, ScanUsagesStatus::Found);
    assert!(!usages.results[0].model_relations.is_empty());
    assert_eq!(
        files_before,
        analyzer.analyzer().project().all_files().unwrap()
    );

    let decoded_records = fixture
        .evidence
        .packages
        .iter()
        .map(|package| {
            serde_json::from_slice::<RustdocCrate>(&fs::read(&package.rustdoc_json_path).unwrap())
                .unwrap()
                .index
                .len()
        })
        .sum::<usize>();
    let (type_count, member_count, relation_count) = active
        .shards()
        .iter()
        .filter_map(|shard| shard.shard.payload().declaration_facts())
        .fold((0, 0, 0), |counts, facts| {
            (
                counts.0 + facts.0.len(),
                counts.1 + facts.1.len(),
                counts.2 + facts.2.len(),
            )
        });
    eprintln!(
        "rust_dependency_pack_measurement={{\"input_bytes\":{},\"decoded_records\":{},\"produced_facts\":{},\"type_facts\":{},\"member_facts\":{},\"relation_facts\":{},\"retained_bytes\":{},\"discovery_us\":{},\"cold_generation_us\":{},\"warm_reuse_us\":{}}}",
        cold.profile.artifact_bytes_read,
        decoded_records,
        type_count + member_count + relation_count,
        type_count,
        member_count,
        relation_count,
        active.retained_bytes(),
        discovery_elapsed.as_micros(),
        cold_elapsed.as_micros(),
        warm_elapsed.as_micros(),
    );
}

/// Crate-aware Rust naming lets a workspace crate render the same qualified
/// names as a rustdoc dependency of the same crate name (`widget.Widget` for
/// both a local `widget` crate and the `widget` registry pack). The two must
/// stay separate: authored references resolve to the authored declaration and
/// the pack overlay keeps exactly its own record.
#[test]
fn a_local_crate_named_like_a_dependency_keeps_its_own_declarations() {
    let library = "pub struct Widget;\npub fn make() -> Widget { Widget }\n";
    let fixture = RustDependencyFixture::new();
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"widget\"\nversion = \"0.1.0\"\n",
        )
        .file("src/lib.rs", library)
        .build();
    let analyzer_config = AnalyzerConfig {
        rust: RustAnalyzerConfig {
            dependency_api_evidence: vec![fixture.evidence.clone()],
        },
        ..Default::default()
    };
    let analyzer = project.workspace_analyzer(analyzer_config.clone());
    let limits = DependencyPackLimits::default();
    let discovery = brokk_bifrost::resolve_rust_semantic_pack_dependencies(
        &analyzer_config.rust,
        analyzer.analyzer().project(),
        &limits,
        None,
    );
    assert!(discovery.complete, "{:#?}", discovery.diagnostics);
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let prepared = prepare_dependency_semantic_packs(
        &catalog,
        &RustDependencyPackAdapter,
        &discovery.dependencies,
        &limits,
        None,
    );
    assert!(prepared.complete, "{:#?}", prepared.diagnostics);
    let request = prepared
        .compose_activation_request(SemanticModelActivationRequest {
            bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
            evidence: Vec::new(),
            controls: Vec::new(),
            limits: Default::default(),
        })
        .unwrap();
    let SemanticModelRuntimeOutcome::Ready { .. } = acquire_active_semantic_models(
        analyzer.analyzer(),
        &catalog,
        None,
        &request,
        &CancellationToken::default(),
    ) else {
        panic!("dependency models must activate");
    };

    let overlay = analyzer
        .analyzer()
        .semantic_model_overlay()
        .expect("activation must publish the dependency overlay");
    assert_eq!(
        overlay.symbols_named("widget.Widget").records.len(),
        1,
        "the pack keeps exactly its own record even though a local crate renders the same name",
    );

    let authored = analyzer.analyzer().get_definitions("widget.Widget");
    assert!(
        authored
            .iter()
            .any(|unit| unit.source().rel_path() == std::path::Path::new("src/lib.rs")),
        "the local crate declaration must be reachable under its own crate-anchored name: {authored:#?}",
    );

    let return_type = library.find("-> Widget").expect("return type") + "-> ".len();
    let line = library[..return_type].matches('\n').count() + 1;
    let column = return_type
        - library[..return_type]
            .rfind('\n')
            .map_or(0, |index| index + 1)
        + 1;
    let definitions = get_definitions_by_location(
        analyzer.analyzer(),
        GetDefinitionParams {
            references: vec![DefinitionReferenceQuery {
                path: "src/lib.rs".to_owned(),
                line: Some(line),
                column: Some(column),
            }],
        },
    );
    let result = &definitions.results[0];
    assert_eq!(result.status, "resolved", "{result:#?}");
    assert!(
        result
            .definitions
            .iter()
            .all(|definition| definition.path == "src/lib.rs"),
        "a local type reference must not resolve into the same-named dependency pack: {result:#?}",
    );
}

#[test]
fn blanket_impl_is_preserved_as_an_explicit_partial_pack() {
    let fixture = RustDependencyFixture::new();
    fs::write(
        &fixture.evidence.packages[0].rustdoc_json_path,
        serde_json::to_vec(&rich_document(true)).unwrap(),
    )
    .unwrap();
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "pub fn local_only() {}\n")
        .build();
    let limits = DependencyPackLimits::default();
    let discovery = brokk_bifrost::resolve_rust_semantic_pack_dependencies(
        &RustAnalyzerConfig {
            dependency_api_evidence: vec![fixture.evidence.clone()],
        },
        project.project(),
        &limits,
        None,
    );
    assert!(discovery.complete, "{:#?}", discovery.diagnostics);
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let prepared = prepare_dependency_semantic_packs(
        &catalog,
        &RustDependencyPackAdapter,
        &discovery.dependencies,
        &limits,
        None,
    );
    assert!(!prepared.complete, "{:#?}", prepared.diagnostics);
    let widget = prepared
        .packs
        .iter()
        .find(|pack| pack.dependency_id.contains("widget@1.2.3"))
        .unwrap();
    assert_eq!(widget.completeness, Completeness::Partial);
    assert!(
        prepared
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.code == "rust.rustdoc.blanket_impl_unprojected" })
    );
}

#[test]
fn missing_and_unsupported_rustdoc_evidence_are_explicitly_incomplete() {
    let fixture = RustDependencyFixture::new();
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "pub fn local_only() {}\n")
        .build();
    let mut missing = fixture.evidence.clone();
    missing.packages[0].rustdoc_json_path = fixture.root.path().join("missing.json");
    let outcome = brokk_bifrost::resolve_rust_semantic_pack_dependencies(
        &RustAnalyzerConfig {
            dependency_api_evidence: vec![missing],
        },
        project.project(),
        &DependencyPackLimits::default(),
        None,
    );
    assert!(!outcome.complete);
    assert!(outcome.dependencies.is_empty());
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.code == "artifact.metadata" })
    );

    fs::write(
        &fixture.evidence.packages[0].rustdoc_json_path,
        serde_json::to_vec(&json!({
            "format_version": rustdoc_types::FORMAT_VERSION + 1
        }))
        .unwrap(),
    )
    .unwrap();
    let outcome = brokk_bifrost::resolve_rust_semantic_pack_dependencies(
        &RustAnalyzerConfig {
            dependency_api_evidence: vec![fixture.evidence.clone()],
        },
        project.project(),
        &DependencyPackLimits::default(),
        None,
    );
    assert!(!outcome.complete);
    assert!(outcome.dependencies.is_empty());
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "rust.rustdoc.unsupported_version")
    );
}

struct RustDependencyFixture {
    root: tempfile::TempDir,
    evidence: RustDependencyApiEvidence,
}

impl RustDependencyFixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let metadata_path = root.path().join("metadata.json");
        let lockfile_path = root.path().join("Cargo.lock");
        let registry_path = root.path().join("widget.json");
        let git_path = root.path().join("git_api.json");
        let path_path = root.path().join("path_api.json");
        fs::write(
            &lockfile_path,
            format!(
                "version = 4\n\n[[package]]\nname = \"widget\"\nversion = \"1.2.3\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"abc123\"\n\n[[package]]\nname = \"git-api\"\nversion = \"0.4.0\"\nsource = \"{GIT_SOURCE}\"\n\n[[package]]\nname = \"path-api\"\nversion = \"0.7.0\"\n"
            ),
        )
        .unwrap();
        let packages = [
            (
                REGISTRY_ID,
                "widget",
                "1.2.3",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
            ),
            (GIT_ID, "git-api", "0.4.0", Some(GIT_SOURCE)),
            (PATH_ID, "path-api", "0.7.0", None),
        ];
        let deps = [
            ("renamed_widget", REGISTRY_ID),
            ("git_api", GIT_ID),
            ("path_api", PATH_ID),
        ];
        fs::write(
            &metadata_path,
            serde_json::to_vec(&json!({
                "version": 1,
                "packages": std::iter::once(json!({
                    "id": ROOT_ID, "name": "consumer", "version": "0.1.0", "source": null,
                    "targets": [{"name": "consumer", "kind": ["lib"]}]
                })).chain(packages.iter().map(|(id, name, version, source)| json!({
                    "id": id, "name": name, "version": version, "source": source,
                    "targets": [{"name": name.replace('-', "_"), "kind": ["lib"]}]
                }))).collect::<Vec<_>>(),
                "resolve": {"nodes": std::iter::once(json!({
                    "id": ROOT_ID, "features": ["target-feature"],
                    "deps": deps.iter().map(|(name, pkg)| json!({"name": name, "pkg": pkg})).collect::<Vec<_>>()
                })).chain(packages.iter().map(|(id, _, _, _)| json!({
                    "id": id,
                    "features": if *id == REGISTRY_ID { vec!["derive"] } else { Vec::<&str>::new() },
                    "deps": []
                }))).collect::<Vec<_>>()}
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            &registry_path,
            serde_json::to_vec(&rich_document(false)).unwrap(),
        )
        .unwrap();
        fs::write(
            &git_path,
            serde_json::to_vec(&minimal_document("git_api", "GitApi", "0.4.0")).unwrap(),
        )
        .unwrap();
        fs::write(
            &path_path,
            serde_json::to_vec(&minimal_document("path_api", "PathApi", "0.7.0")).unwrap(),
        )
        .unwrap();
        let evidence = RustDependencyApiEvidence {
            metadata_path,
            lockfile_path,
            target: TARGET.to_owned(),
            configuration: "library".to_owned(),
            selected_targets: vec![RustSelectedTarget {
                package_id: ROOT_ID.to_owned(),
                target_name: "consumer".to_owned(),
                target_kind: "lib".to_owned(),
            }],
            packages: vec![
                package_artifact(REGISTRY_ID, "widget", vec!["derive"], registry_path),
                package_artifact(GIT_ID, "git_api", Vec::new(), git_path),
                package_artifact(PATH_ID, "path_api", Vec::new(), path_path),
            ],
        };
        Self { root, evidence }
    }
}

fn package_artifact(
    package_id: &str,
    crate_name: &str,
    enabled_features: Vec<&str>,
    rustdoc_json_path: std::path::PathBuf,
) -> RustPackageApiArtifact {
    RustPackageApiArtifact {
        package_id: package_id.to_owned(),
        crate_name: crate_name.to_owned(),
        enabled_features: enabled_features.into_iter().map(str::to_owned).collect(),
        rustdoc_json_path,
        rustdoc_toolchain: "nightly-2026-07-14".to_owned(),
        rustdoc_format_version: rustdoc_types::FORMAT_VERSION,
    }
}

fn item(id: u32, name: Option<&str>, visibility: RustVisibility, inner: ItemEnum) -> Item {
    Item {
        id: Id(id),
        crate_id: 0,
        name: name.map(str::to_owned),
        span: None,
        visibility,
        docs: None,
        links: HashMap::new(),
        attrs: Vec::new(),
        deprecation: None,
        stability: None,
        const_stability: None,
        inner,
    }
}

fn generics() -> Generics {
    Generics {
        params: Vec::new(),
        where_predicates: Vec::new(),
    }
}

fn path(id: u32, path: &str) -> RustdocPath {
    RustdocPath {
        path: path.to_owned(),
        id: Id(id),
        args: None,
    }
}

fn function(inputs: Vec<(String, Type)>, output: Option<Type>, generics: Generics) -> Function {
    Function {
        sig: FunctionSignature {
            inputs,
            output,
            is_c_variadic: false,
        },
        generics,
        header: FunctionHeader {
            is_const: false,
            is_unsafe: false,
            is_async: false,
            abi: Abi::Rust,
        },
        has_body: true,
        default_unstable: None,
    }
}

fn minimal_document(crate_name: &str, type_name: &str, version: &str) -> RustdocCrate {
    let index = HashMap::from([
        (
            Id(0),
            item(
                0,
                Some(crate_name),
                RustVisibility::Default,
                ItemEnum::Module(Module {
                    is_crate: true,
                    items: vec![Id(1)],
                    is_stripped: false,
                }),
            ),
        ),
        (
            Id(1),
            item(
                1,
                Some(type_name),
                RustVisibility::Public,
                ItemEnum::Struct(Struct {
                    kind: StructKind::Unit,
                    generics: generics(),
                    impls: Vec::new(),
                }),
            ),
        ),
    ]);
    rustdoc_crate(
        version,
        index,
        HashMap::from([
            (Id(0), summary(&[crate_name], ItemKind::Module)),
            (Id(1), summary(&[crate_name, type_name], ItemKind::Struct)),
        ]),
    )
}

fn rich_document(blanket_impl: bool) -> RustdocCrate {
    let widget = path(2, "widget::Widget");
    let display = path(3, "widget::Display");
    let index = HashMap::from([
        (
            Id(0),
            item(
                0,
                Some("widget"),
                RustVisibility::Default,
                ItemEnum::Module(Module {
                    is_crate: true,
                    items: vec![Id(1)],
                    is_stripped: false,
                }),
            ),
        ),
        (
            Id(1),
            item(
                1,
                Some("widget"),
                RustVisibility::Public,
                ItemEnum::Module(Module {
                    is_crate: false,
                    items: vec![
                        Id(2),
                        Id(3),
                        Id(4),
                        Id(5),
                        Id(6),
                        Id(10),
                        Id(11),
                        Id(12),
                        Id(13),
                        Id(14),
                        Id(15),
                    ],
                    is_stripped: false,
                }),
            ),
        ),
        (
            Id(2),
            item(
                2,
                Some("Widget"),
                RustVisibility::Public,
                ItemEnum::Struct(Struct {
                    kind: StructKind::Unit,
                    generics: generics(),
                    impls: vec![Id(7)],
                }),
            ),
        ),
        (
            Id(3),
            item(
                3,
                Some("Display"),
                RustVisibility::Public,
                ItemEnum::Trait(Trait {
                    is_auto: false,
                    is_unsafe: false,
                    is_dyn_compatible: true,
                    items: vec![Id(9)],
                    generics: generics(),
                    bounds: Vec::new(),
                    implementations: vec![Id(7)],
                }),
            ),
        ),
        (
            Id(4),
            item(
                4,
                Some("convert"),
                RustVisibility::Public,
                ItemEnum::Function(function(
                    vec![("value".to_owned(), Type::Generic("T".to_owned()))],
                    Some(Type::ResolvedPath(widget.clone())),
                    Generics {
                        params: vec![GenericParamDef {
                            name: "T".to_owned(),
                            kind: GenericParamDefKind::Type {
                                bounds: Vec::new(),
                                default: None,
                                is_synthetic: false,
                            },
                        }],
                        where_predicates: vec![WherePredicate::BoundPredicate {
                            type_: Type::Generic("T".to_owned()),
                            bounds: vec![GenericBound::TraitBound {
                                trait_: display.clone(),
                                generic_params: Vec::new(),
                                modifier: TraitBoundModifier::None,
                            }],
                            generic_params: Vec::new(),
                        }],
                    },
                )),
            ),
        ),
        (
            Id(5),
            item(
                5,
                Some("Gadget"),
                RustVisibility::Public,
                ItemEnum::Use(Use {
                    source: "widget::Widget".to_owned(),
                    name: "Gadget".to_owned(),
                    id: Some(Id(2)),
                    is_glob: false,
                }),
            ),
        ),
        (
            Id(6),
            item(
                6,
                Some("make_widget"),
                RustVisibility::Public,
                ItemEnum::Macro("macro_rules! make_widget".to_owned()),
            ),
        ),
        (
            Id(7),
            item(
                7,
                None,
                RustVisibility::Default,
                ItemEnum::Impl(Impl {
                    is_unsafe: false,
                    generics: generics(),
                    provided_trait_methods: Vec::new(),
                    trait_: Some(display),
                    for_: if blanket_impl {
                        Type::Generic("T".to_owned())
                    } else {
                        Type::ResolvedPath(widget)
                    },
                    items: vec![Id(8)],
                    is_negative: false,
                    is_synthetic: false,
                    blanket_impl: blanket_impl.then(|| Type::Generic("T".to_owned())),
                }),
            ),
        ),
        (
            Id(8),
            item(
                8,
                Some("render"),
                RustVisibility::Default,
                ItemEnum::Function(function(
                    vec![(
                        "&self".to_owned(),
                        Type::BorrowedRef {
                            lifetime: None,
                            is_mutable: false,
                            type_: Box::new(Type::Generic("Self".to_owned())),
                        },
                    )],
                    Some(Type::Primitive("str".to_owned())),
                    generics(),
                )),
            ),
        ),
        (
            Id(9),
            item(
                9,
                Some("render"),
                RustVisibility::Default,
                ItemEnum::Function(function(
                    vec![("&self".to_owned(), Type::Generic("Self".to_owned()))],
                    None,
                    generics(),
                )),
            ),
        ),
        (
            Id(10),
            item(
                10,
                Some("DeriveWidget"),
                RustVisibility::Public,
                ItemEnum::ProcMacro(ProcMacro {
                    kind: MacroKind::Derive,
                    helpers: vec!["widget".to_owned()],
                }),
            ),
        ),
        (
            Id(11),
            item(
                11,
                Some("Packet"),
                RustVisibility::Public,
                ItemEnum::Union(Union {
                    generics: generics(),
                    has_stripped_fields: false,
                    fields: Vec::new(),
                    impls: Vec::new(),
                }),
            ),
        ),
        (
            Id(12),
            item(
                12,
                Some("WidgetAlias"),
                RustVisibility::Public,
                ItemEnum::TypeAlias(TypeAlias {
                    type_: Type::ResolvedPath(path(2, "widget::Widget")),
                    generics: generics(),
                }),
            ),
        ),
        (
            Id(13),
            item(
                13,
                Some("WIDGET_COUNT"),
                RustVisibility::Public,
                ItemEnum::Constant {
                    type_: Type::Primitive("usize".to_owned()),
                    const_: RustdocConstant {
                        expr: "1".to_owned(),
                        value: Some("1".to_owned()),
                        is_literal: true,
                    },
                },
            ),
        ),
        (
            Id(14),
            item(
                14,
                Some("DEFAULT_WIDGET"),
                RustVisibility::Public,
                ItemEnum::Static(Static {
                    type_: Type::ResolvedPath(path(2, "widget::Widget")),
                    is_mutable: false,
                    expr: "Widget".to_owned(),
                    is_unsafe: false,
                }),
            ),
        ),
        (
            Id(15),
            item(
                15,
                Some("Mode"),
                RustVisibility::Public,
                ItemEnum::Enum(Enum {
                    generics: generics(),
                    has_stripped_variants: false,
                    variants: vec![Id(16)],
                    impls: Vec::new(),
                }),
            ),
        ),
        (
            Id(16),
            item(
                16,
                Some("Fast"),
                RustVisibility::Public,
                ItemEnum::Variant(Variant {
                    kind: VariantKind::Plain,
                    discriminant: None,
                }),
            ),
        ),
    ]);
    rustdoc_crate(
        "1.2.3",
        index,
        HashMap::from([
            (Id(0), summary(&["widget"], ItemKind::Module)),
            (Id(1), summary(&["widget", "widget"], ItemKind::Module)),
            (Id(2), summary(&["widget", "Widget"], ItemKind::Struct)),
            (Id(3), summary(&["widget", "Display"], ItemKind::Trait)),
            (Id(4), summary(&["widget", "convert"], ItemKind::Function)),
            (Id(6), summary(&["widget", "make_widget"], ItemKind::Macro)),
            (
                Id(10),
                summary(&["widget", "DeriveWidget"], ItemKind::ProcDerive),
            ),
            (Id(11), summary(&["widget", "Packet"], ItemKind::Union)),
            (
                Id(12),
                summary(&["widget", "WidgetAlias"], ItemKind::TypeAlias),
            ),
            (
                Id(13),
                summary(&["widget", "WIDGET_COUNT"], ItemKind::Constant),
            ),
            (
                Id(14),
                summary(&["widget", "DEFAULT_WIDGET"], ItemKind::Static),
            ),
            (Id(15), summary(&["widget", "Mode"], ItemKind::Enum)),
            (
                Id(16),
                summary(&["widget", "Mode", "Fast"], ItemKind::Variant),
            ),
        ]),
    )
}

fn summary(path: &[&str], kind: ItemKind) -> ItemSummary {
    ItemSummary {
        crate_id: 0,
        path: path.iter().map(|part| (*part).to_owned()).collect(),
        kind,
    }
}

fn rustdoc_crate(
    version: &str,
    index: HashMap<Id, Item>,
    paths: HashMap<Id, ItemSummary>,
) -> RustdocCrate {
    RustdocCrate {
        root: Id(0),
        crate_version: Some(version.to_owned()),
        includes_private: false,
        index,
        paths,
        external_crates: HashMap::new(),
        target: Target {
            triple: TARGET.to_owned(),
            target_features: Vec::new(),
        },
        format_version: rustdoc_types::FORMAT_VERSION,
    }
}
