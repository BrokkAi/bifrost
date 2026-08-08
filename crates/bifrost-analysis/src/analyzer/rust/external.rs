use std::path::PathBuf;

use crate::CancellationToken;
use crate::analyzer::semantic_model::{
    ActivationSelector, ArtifactProducerLimits, ArtifactProductionRequest, AuthoredPayload,
    AuthoredSemanticModelPack, CatalogCoordinate, Compatibility, Completeness,
    DependencyArtifactRole, DependencyPackAdapter, DependencyPackProduction,
    ExactDependencyArtifact, ExternalArtifactKind, NameSelector, Producer, ProducerDiagnostic,
    ProducerDiagnosticSeverity, Provenance, ResolvedDependency, Safety, VersionConstraint,
    normalize_artifact_locator_paths,
};

use super::RustdocJsonPackProducer;

#[derive(Debug, Clone, Copy, Default)]
pub struct RustDependencyPackAdapter;

impl DependencyPackAdapter for RustDependencyPackAdapter {
    fn adapter_name(&self) -> &str {
        "bifrost-rust-dependency"
    }

    fn adapter_version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn producer(&self) -> Producer {
        Producer {
            name: "bifrost-rustdoc-json".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    fn can_produce(&self, dependency: &ResolvedDependency) -> bool {
        dependency.evidence.language == "rust" && dependency.evidence.ecosystem == "cargo"
    }

    fn produce(
        &self,
        dependency: &ResolvedDependency,
        artifacts: &[ExactDependencyArtifact],
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
    ) -> DependencyPackProduction {
        let Some(artifact) = artifacts.first().filter(|_| artifacts.len() == 1) else {
            return failed_production(
                "artifact.count",
                "Rust dependency production requires exactly one rustdoc JSON artifact",
            );
        };
        if artifact.kind() != ExternalArtifactKind::RustdocJson
            || artifact.role() != DependencyArtifactRole::Reference
        {
            return failed_production(
                "artifact.kind",
                "Rust dependency production requires one reference-role rustdoc JSON artifact",
            );
        }

        let mut request = rust_dependency_production_request(dependency);
        request.path = artifact.path().to_owned();
        let mut production = RustdocJsonPackProducer.produce_loaded_artifact(
            &request,
            limits,
            cancellation,
            artifact.exact(),
        );
        debug_assert_eq!(
            production.artifact_sha256.as_deref(),
            Some(artifact.sha256())
        );
        let mut diagnostics = production.diagnostics;
        if let Some(pack) = production.pack.as_mut() {
            normalize_artifact_locator_paths(
                pack,
                &format!("sha256-{}.rustdoc.json", artifact.sha256()),
            );
            apply_cargo_dependency_spellings(pack, dependency);
            if let Some(missing) = features_the_pack_never_saw(dependency) {
                diagnostics.push(ProducerDiagnostic {
                    code: "rust.rustdoc.feature_set_narrower_than_resolved".to_owned(),
                    severity: ProducerDiagnosticSeverity::Warning,
                    location: None,
                    message: format!(
                        "rustdoc ran without the Cargo-resolved features {missing:?}, so items they gate are absent from this surface"
                    ),
                });
                pack.completeness = Completeness::Partial;
            }
        }
        DependencyPackProduction {
            pack: production.pack,
            diagnostics,
            suppressed_diagnostics: production.suppressed_diagnostics,
        }
    }
}

/// The Cargo-resolved features this pack was *not* produced with, if any.
///
/// Discovery records both axes on the dependency: `cargo.feature` is what the
/// host says it passed to rustdoc, and `cargo.metadata_feature` is the set
/// Cargo's own resolve reports for the package. Nothing else compares them and
/// neither reaches the pack, so the comparison has to happen here, while both
/// are still in hand and while the answer can still change the pack's recorded
/// completeness.
///
/// The test is containment, not equality, because the two directions are not
/// symmetric. A pack built with *more* features than the build enables still
/// documents everything the build can see, so an item missing from it is
/// genuinely missing: extra features only add items. A pack built with *fewer*
/// features is missing whatever those features gate, so a miss against it
/// proves nothing about the crate as this workspace compiles it. Only the
/// second case may block an absence claim, and it does so by recording the
/// pack partial -- which is exactly the signal `rust/crate_identity.rs` already
/// reads to refuse a proof (#1625).
fn features_the_pack_never_saw(dependency: &ResolvedDependency) -> Option<Vec<String>> {
    let produced: std::collections::BTreeSet<&str> = dependency
        .provenance
        .iter()
        .filter(|entry| entry.key == "cargo.feature")
        .map(|entry| entry.value.as_str())
        .collect();
    let missing: Vec<String> = dependency
        .provenance
        .iter()
        .filter(|entry| entry.key == "cargo.metadata_feature")
        .map(|entry| entry.value.as_str())
        .filter(|feature| !produced.contains(feature))
        .map(str::to_owned)
        .collect();
    (!missing.is_empty()).then_some(missing)
}

/// Publish the pack under every spelling this workspace writes to reach the
/// crate, and publish its crate root under those spellings only.
///
/// Cargo's `package = "..."` rename gives one crate two names with two
/// different jobs. The renamed spelling is what source can write; the crate's
/// own name is what the pack's own rustdoc-derived paths are spelled with -- a
/// signature naming `widget::Error`, a hierarchy target, a member's owner
/// path. Publishing the renamed spelling as an alias on every fact serves the
/// first job. Leaving the crate's own name on every fact serves the second.
///
/// What must not survive is the crate's own name as a *crate root*: under a
/// rename `widget::Widget` is a path Cargo and rustc both reject, so resolving
/// it is a missed error (#1795). The root module fact is the one fact whose
/// name plays only the first role -- nothing inside a pack refers to the crate
/// by its bare root -- so the rename replaces it there and extends it
/// everywhere else. `rust::crate_identity` reads exactly that distinction.
///
/// The workspace's spellings come from `cargo metadata`'s resolve graph, where
/// `deps[].name` is the dependency's library target name and therefore equals
/// the crate's own name unless the manifest renamed it. Renaming is thus the
/// precise condition "the resolve graph binds this package under names, none
/// of which is its own".
fn apply_cargo_dependency_spellings(
    pack: &mut AuthoredSemanticModelPack,
    dependency: &ResolvedDependency,
) {
    let Some(crate_name) = dependency
        .evidence
        .module
        .as_ref()
        .map(|module| &module.name)
    else {
        return;
    };
    let written = dependency
        .provenance
        .iter()
        .filter(|entry| entry.key == "cargo.dependency_name")
        .map(|entry| entry.value.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let aliases = written
        .iter()
        .copied()
        .filter(|name| *name != crate_name.as_str())
        .collect::<Vec<_>>();
    for shard in &mut pack.shards {
        let AuthoredPayload::DeclarationFacts { types, members, .. } = &mut shard.payload else {
            continue;
        };
        let owner_names = types
            .iter()
            .map(|fact| (fact.id.clone(), fact.name.clone()))
            .collect::<std::collections::HashMap<_, _>>();
        for fact in types {
            for alias in &aliases {
                if let Some(suffix) = fact
                    .name
                    .strip_prefix(crate_name)
                    .filter(|suffix| suffix.is_empty() || suffix.starts_with('.'))
                {
                    let alias = format!("{alias}{suffix}");
                    if !fact.aliases.contains(&alias) {
                        fact.aliases.push(alias);
                    }
                }
            }
        }
        for fact in members {
            for alias in &aliases {
                let Some(owner_name) = owner_names.get(&fact.owner) else {
                    continue;
                };
                let declaration_path = format!("{owner_name}.{}", fact.name);
                if let Some(suffix) = declaration_path
                    .strip_prefix(crate_name)
                    .filter(|suffix| suffix.is_empty() || suffix.starts_with('.'))
                {
                    let alias = format!("{alias}{suffix}");
                    if !fact.aliases.contains(&alias) {
                        fact.aliases.push(alias);
                    }
                }
            }
        }
    }

    // Every remaining spelling is an added one. The crate's own name stays on
    // the facts above, where the pack's own paths need it, but it stops being
    // a crate root the moment the resolve graph binds this package only under
    // other names.
    if written.is_empty() || written.contains(crate_name.as_str()) {
        return;
    }
    let Some(root_spelling) = aliases.first().copied() else {
        return;
    };
    let mut shadowed_roots = Vec::new();
    for shard in &mut pack.shards {
        let AuthoredPayload::DeclarationFacts { types, .. } = &mut shard.payload else {
            continue;
        };
        for fact in types.iter_mut().filter(|fact| fact.name == *crate_name) {
            fact.name = root_spelling.to_owned();
            fact.aliases.retain(|alias| alias != root_spelling);
            shadowed_roots.push(fact.id.clone());
        }
    }
    debug_assert!(
        !shadowed_roots.is_empty(),
        "a rustdoc pack publishes its crate root as a fact named exactly `{crate_name}`, but no shard of {:?} carried one",
        pack.shards
            .iter()
            .map(|shard| shard.id.as_str())
            .collect::<Vec<_>>()
    );
}

fn rust_dependency_production_request(
    dependency: &ResolvedDependency,
) -> ArtifactProductionRequest {
    ArtifactProductionRequest {
        path: PathBuf::new(),
        artifact_kind: ExternalArtifactKind::RustdocJson,
        pack_id: "bifrost.external.rust".to_owned(),
        pack_version: env!("CARGO_PKG_VERSION").to_owned(),
        ecosystem: dependency.evidence.ecosystem.clone(),
        compatibility: Compatibility {
            bifrost: format!("={}", env!("CARGO_PKG_VERSION")),
            toolchains: dependency
                .evidence
                .toolchain
                .as_ref()
                .and_then(|coordinate| {
                    coordinate
                        .version
                        .as_ref()
                        .map(|version| VersionConstraint {
                            name: coordinate.name.clone(),
                            requirement: format!("={version}"),
                        })
                })
                .into_iter()
                .collect(),
        },
        activation: vec![ActivationSelector {
            package: dependency
                .evidence
                .package
                .as_ref()
                .map(exact_name_selector),
            module: dependency.evidence.module.as_ref().map(exact_name_selector),
            toolchain: dependency
                .evidence
                .toolchain
                .as_ref()
                .map(exact_name_selector),
            targets: dependency.evidence.target.clone().into_iter().collect(),
            configurations: dependency
                .evidence
                .configuration
                .clone()
                .into_iter()
                .collect(),
            artifact_sha256: None,
        }],
        provenance: Provenance {
            source: dependency
                .provenance
                .iter()
                .find(|entry| entry.key == "cargo.source")
                .map(|entry| entry.value.clone())
                .unwrap_or_else(|| "exact Cargo dependency".to_owned()),
            revision: dependency
                .provenance
                .iter()
                .find(|entry| entry.key == "cargo.checksum")
                .map(|entry| entry.value.clone()),
        },
        license: "NOASSERTION".to_owned(),
        safety: Safety {
            generated_code_only: false,
            review_required: false,
        },
    }
}

fn exact_name_selector(coordinate: &CatalogCoordinate) -> NameSelector {
    NameSelector {
        name: coordinate.name.clone(),
        version: coordinate
            .version
            .as_ref()
            .map(|version| format!("={version}")),
    }
}

fn failed_production(code: &str, message: &str) -> DependencyPackProduction {
    DependencyPackProduction {
        pack: None,
        diagnostics: vec![ProducerDiagnostic {
            severity: ProducerDiagnosticSeverity::Error,
            code: code.to_owned(),
            location: None,
            message: message.to_owned(),
        }],
        suppressed_diagnostics: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdoc_types::{
        Crate as RustdocCrate, Id, Item, ItemEnum, ItemKind, ItemSummary, Module, Struct,
        StructKind, Target, Visibility as RustVisibility,
    };
    use semver::Version;
    use std::collections::HashMap as StdHashMap;
    use std::fs;

    use crate::analyzer::semantic_model::{
        CatalogCoordinate, CatalogOptions, DependencyPackLimits, DependencyPackPreparationStatus,
        DependencyProvenance, ResolvedDependencyArtifact, SemanticModelActivationRequest,
        SemanticModelOverlay, SemanticModelResolutionOutcome, SemanticPackCatalog,
        prepare_dependency_semantic_packs, resolve_active_semantic_models,
    };
    use crate::analyzer::{Language, Project, ProjectFile, RustAnalyzer, TestProject};

    fn item(id: u32, name: &str, visibility: RustVisibility, inner: ItemEnum) -> Item {
        Item {
            id: Id(id),
            crate_id: 0,
            name: Some(name.to_owned()),
            span: None,
            visibility,
            docs: None,
            links: StdHashMap::new(),
            attrs: Vec::new(),
            deprecation: None,
            stability: None,
            const_stability: None,
            inner,
        }
    }

    fn rustdoc_document(extra_type: bool) -> RustdocCrate {
        let mut root_items = vec![Id(1)];
        if extra_type {
            root_items.push(Id(2));
        }
        let mut index = StdHashMap::from([
            (
                Id(0),
                item(
                    0,
                    "widget",
                    RustVisibility::Default,
                    ItemEnum::Module(Module {
                        is_crate: true,
                        items: root_items,
                        is_stripped: false,
                    }),
                ),
            ),
            (
                Id(1),
                item(
                    1,
                    "Widget",
                    RustVisibility::Public,
                    ItemEnum::Struct(Struct {
                        kind: StructKind::Unit,
                        generics: rustdoc_types::Generics {
                            params: Vec::new(),
                            where_predicates: Vec::new(),
                        },
                        impls: Vec::new(),
                    }),
                ),
            ),
        ]);
        if extra_type {
            index.insert(
                Id(2),
                item(
                    2,
                    "Added",
                    RustVisibility::Public,
                    ItemEnum::Struct(Struct {
                        kind: StructKind::Unit,
                        generics: rustdoc_types::Generics {
                            params: Vec::new(),
                            where_predicates: Vec::new(),
                        },
                        impls: Vec::new(),
                    }),
                ),
            );
        }
        let mut paths = StdHashMap::from([
            (
                Id(0),
                ItemSummary {
                    crate_id: 0,
                    path: vec!["widget".to_owned()],
                    kind: ItemKind::Module,
                },
            ),
            (
                Id(1),
                ItemSummary {
                    crate_id: 0,
                    path: vec!["widget".to_owned(), "Widget".to_owned()],
                    kind: ItemKind::Struct,
                },
            ),
        ]);
        if extra_type {
            paths.insert(
                Id(2),
                ItemSummary {
                    crate_id: 0,
                    path: vec!["widget".to_owned(), "Added".to_owned()],
                    kind: ItemKind::Struct,
                },
            );
        }
        RustdocCrate {
            root: Id(0),
            crate_version: Some("1.2.3".to_owned()),
            includes_private: false,
            index,
            paths,
            external_crates: StdHashMap::new(),
            target: Target {
                triple: "x86_64-unknown-linux-gnu".to_owned(),
                target_features: Vec::new(),
            },
            format_version: rustdoc_types::FORMAT_VERSION,
        }
    }

    fn dependency(path: PathBuf, feature: &str) -> ResolvedDependency {
        let version = Version::parse("1.2.3").unwrap();
        ResolvedDependency {
            id: format!("rust:widget@1.2.3:widget:x86_64-unknown-linux-gnu:{feature}"),
            evidence: crate::analyzer::semantic_model::SemanticModelActivationEvidence {
                language: "rust".to_owned(),
                ecosystem: "cargo".to_owned(),
                package: Some(CatalogCoordinate {
                    name: "widget".to_owned(),
                    version: Some(version.clone()),
                }),
                module: Some(CatalogCoordinate {
                    name: "widget".to_owned(),
                    version: Some(version),
                }),
                toolchain: None,
                target: Some("x86_64-unknown-linux-gnu".to_owned()),
                configuration: Some("default".to_owned()),
                artifact_sha256: None,
            },
            provenance: vec![DependencyProvenance {
                key: "cargo.feature".to_owned(),
                value: feature.to_owned(),
            }],
            artifacts: vec![ResolvedDependencyArtifact::file(
                DependencyArtifactRole::Reference,
                ExternalArtifactKind::RustdocJson,
                path,
            )],
        }
    }

    /// A dependency whose rustdoc run saw `produced` while Cargo resolves
    /// `resolved`.
    fn dependency_with_features(
        path: PathBuf,
        produced: &[&str],
        resolved: &[&str],
    ) -> ResolvedDependency {
        let mut dependency = dependency(path, "derive");
        dependency.provenance = produced
            .iter()
            .map(|feature| DependencyProvenance {
                key: "cargo.feature".to_owned(),
                value: (*feature).to_owned(),
            })
            .chain(resolved.iter().map(|feature| DependencyProvenance {
                key: "cargo.metadata_feature".to_owned(),
                value: (*feature).to_owned(),
            }))
            .collect();
        dependency
    }

    fn prepared_completeness(dependency: &ResolvedDependency) -> (Completeness, Vec<String>) {
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let prepared = prepare_dependency_semantic_packs(
            &catalog,
            &RustDependencyPackAdapter,
            std::slice::from_ref(dependency),
            &DependencyPackLimits::default(),
            None,
        );
        let pack = prepared
            .packs
            .first()
            .expect("one dependency produces one pack");
        (
            pack.completeness,
            prepared
                .diagnostics
                .iter()
                .map(|diagnostic| diagnostic.code.clone())
                .collect(),
        )
    }

    /// A pack produced without a feature Cargo resolves is missing whatever
    /// that feature gates, so it must not be trusted to prove an item absent
    /// (#1625). Recording it partial is how that reaches the diagnostic ladder.
    #[test]
    fn a_pack_built_without_a_resolved_feature_is_recorded_partial() {
        let root = tempfile::tempdir().unwrap();
        let rustdoc_path = root.path().join("widget.json");
        fs::write(
            &rustdoc_path,
            serde_json::to_vec(&rustdoc_document(false)).unwrap(),
        )
        .unwrap();

        let (completeness, codes) = prepared_completeness(&dependency_with_features(
            rustdoc_path.clone(),
            &["derive"],
            &["derive", "serde"],
        ));
        assert_eq!(Completeness::Partial, completeness);
        assert!(
            codes
                .iter()
                .any(|code| code == "rust.rustdoc.feature_set_narrower_than_resolved"),
            "{codes:#?}"
        );
    }

    /// The converse, and the reason the test is containment rather than
    /// equality: a pack built with *more* features than Cargo resolves still
    /// documents everything the build can see, so it keeps its complete
    /// surface and can still prove an item absent.
    #[test]
    fn a_pack_built_with_extra_features_keeps_its_complete_surface() {
        let root = tempfile::tempdir().unwrap();
        let rustdoc_path = root.path().join("widget.json");
        fs::write(
            &rustdoc_path,
            serde_json::to_vec(&rustdoc_document(false)).unwrap(),
        )
        .unwrap();

        let (completeness, codes) = prepared_completeness(&dependency_with_features(
            rustdoc_path.clone(),
            &["derive", "serde"],
            &["derive"],
        ));
        assert_eq!(Completeness::Complete, completeness, "{codes:#?}");
    }

    #[test]
    fn exact_rustdoc_pack_reuses_and_activates_without_adding_project_files() {
        let root = tempfile::tempdir().unwrap();
        let rustdoc_path = root.path().join("widget.json");
        fs::write(
            &rustdoc_path,
            serde_json::to_vec(&rustdoc_document(false)).unwrap(),
        )
        .unwrap();
        ProjectFile::new(root.path(), "src/lib.rs")
            .write("pub fn local() {}\n")
            .unwrap();
        let project = TestProject::new(root.path(), Language::Rust);
        let analyzer = RustAnalyzer::from_project(project.clone());
        let files_before = project.all_files().unwrap();
        let resolved_dependency = dependency(rustdoc_path.clone(), "default");
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let limits = DependencyPackLimits::default();

        let first = prepare_dependency_semantic_packs(
            &catalog,
            &RustDependencyPackAdapter,
            std::slice::from_ref(&resolved_dependency),
            &limits,
            None,
        );
        let second = prepare_dependency_semantic_packs(
            &catalog,
            &RustDependencyPackAdapter,
            std::slice::from_ref(&resolved_dependency),
            &limits,
            None,
        );
        assert!(first.complete, "{:#?}", first.diagnostics);
        assert_eq!(
            first.packs[0].status,
            DependencyPackPreparationStatus::Generated
        );
        assert_eq!(
            second.packs[0].status,
            DependencyPackPreparationStatus::Reused
        );
        assert_eq!(first.packs[0].production, second.packs[0].production);

        let request = second
            .compose_activation_request(SemanticModelActivationRequest {
                bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
                evidence: Vec::new(),
                controls: Vec::new(),
                limits: Default::default(),
            })
            .unwrap();
        let cancellation = CancellationToken::new();
        let active = match resolve_active_semantic_models(&catalog, &request, &cancellation) {
            SemanticModelResolutionOutcome::Ready(active) => active,
            outcome => panic!("expected ready Rust dependency model, got {outcome:#?}"),
        };
        assert!(
            !active.shards().is_empty(),
            "{:#?}",
            active.activation_report()
        );
        assert_eq!(active.types_named("widget.Widget").records.len(), 1);
        let overlay =
            SemanticModelOverlay::build(&analyzer, &active, &cancellation, 64 * 1024 * 1024)
                .unwrap();
        let widget = overlay.symbols_named("widget.Widget");
        assert_eq!(widget.records.len(), 1, "{:#?}", overlay.symbols());
        assert!(
            widget.records[0]
                .location
                .identity()
                .starts_with("bifrost-model://v1/")
        );
        assert_eq!(project.all_files().unwrap(), files_before);

        let changed_feature = dependency(rustdoc_path.clone(), "serde");
        let feature_result = prepare_dependency_semantic_packs(
            &catalog,
            &RustDependencyPackAdapter,
            &[changed_feature],
            &limits,
            None,
        );
        assert_eq!(
            feature_result.packs[0].status,
            DependencyPackPreparationStatus::Generated
        );

        fs::write(
            &rustdoc_path,
            serde_json::to_vec(&rustdoc_document(true)).unwrap(),
        )
        .unwrap();
        let artifact_result = prepare_dependency_semantic_packs(
            &catalog,
            &RustDependencyPackAdapter,
            &[resolved_dependency],
            &limits,
            None,
        );
        assert_eq!(
            artifact_result.packs[0].status,
            DependencyPackPreparationStatus::Generated
        );
        assert_ne!(
            artifact_result.packs[0].production,
            first.packs[0].production
        );
    }

    /// The same crate, reached by a workspace that spells it `spelling`.
    ///
    /// `cargo metadata`'s resolve graph records that spelling as the
    /// dependency edge's name, which discovery pushes here as
    /// `cargo.dependency_name`: the crate's own name where the manifest
    /// declares it plainly, the renamed one where `package = "widget"` renames
    /// it.
    fn dependency_spelled(path: PathBuf, spelling: &str) -> ResolvedDependency {
        let mut dependency = dependency(path, "default");
        dependency.provenance.push(DependencyProvenance {
            key: "cargo.dependency_name".to_owned(),
            value: spelling.to_owned(),
        });
        dependency
    }

    /// A Cargo rename is a fact about one workspace, and the production cache
    /// already keeps it that way (#1795).
    ///
    /// `dependency_input_digest` hashes a dependency's whole provenance list,
    /// and the rename reaches it as `cargo.dependency_name`. So two workspaces
    /// sharing one catalog and reading byte-identical rustdoc JSON still
    /// generate separate productions: neither can be served the other's
    /// crate-root spelling on a cache hit, and neither activates the other's
    /// shards. That is what makes it correct to bake the spelling into the
    /// pack at production time instead of applying it per activation.
    #[test]
    fn a_rename_forks_the_production_so_workspaces_never_share_a_crate_root() {
        let root = tempfile::tempdir().unwrap();
        let plain_path = root.path().join("workspace-plain/widget.json");
        let renamed_path = root.path().join("workspace-renamed/widget.json");
        let artifact = serde_json::to_vec(&rustdoc_document(false)).unwrap();
        for path in [&plain_path, &renamed_path] {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, &artifact).unwrap();
        }
        let project = TestProject::new(root.path(), Language::Rust);
        let analyzer = RustAnalyzer::from_project(project);
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let limits = DependencyPackLimits::default();

        let prepare = |dependency: ResolvedDependency| {
            prepare_dependency_semantic_packs(
                &catalog,
                &RustDependencyPackAdapter,
                &[dependency],
                &limits,
                None,
            )
        };
        let plain = prepare(dependency_spelled(plain_path, "widget"));
        let renamed = prepare(dependency_spelled(renamed_path, "renamed_widget"));

        assert!(plain.complete, "{:#?}", plain.diagnostics);
        assert!(renamed.complete, "{:#?}", renamed.diagnostics);
        assert_eq!(
            plain.packs[0].status,
            DependencyPackPreparationStatus::Generated
        );
        assert_eq!(
            renamed.packs[0].status,
            DependencyPackPreparationStatus::Generated,
            "a rename must not be served the plain workspace's cached production"
        );
        assert_ne!(plain.packs[0].production, renamed.packs[0].production);

        // Each workspace sees its own spelling as the crate root, and only its
        // own. The crate's own inner paths stay published either way, because
        // that is what the pack's recorded rustdoc paths are spelled with.
        let cancellation = CancellationToken::new();
        for (outcome, written, unwritable) in [
            (plain, "widget", "renamed_widget"),
            (renamed, "renamed_widget", "widget"),
        ] {
            let request = outcome
                .compose_activation_request(SemanticModelActivationRequest {
                    bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
                    evidence: Vec::new(),
                    controls: Vec::new(),
                    limits: Default::default(),
                })
                .unwrap();
            let active = match resolve_active_semantic_models(&catalog, &request, &cancellation) {
                SemanticModelResolutionOutcome::Ready(active) => active,
                outcome => panic!("expected ready Rust dependency model, got {outcome:#?}"),
            };
            let overlay =
                SemanticModelOverlay::build(&analyzer, &active, &cancellation, 64 * 1024 * 1024)
                    .unwrap();
            let publishes_crate_root = |spelling: &str| {
                overlay
                    .symbols_named(spelling)
                    .records
                    .iter()
                    .any(|symbol| symbol.qualified_name == spelling)
            };
            assert!(
                publishes_crate_root(written),
                "`{written}` is the spelling this workspace writes: {:#?}",
                overlay.symbols()
            );
            assert!(
                !publishes_crate_root(unwritable),
                "`{unwritable}` is not a crate root this workspace can write: {:#?}",
                overlay.symbols()
            );
            assert_eq!(
                overlay.symbols_named("widget.Widget").records.len(),
                1,
                "the pack's own recorded path stays resolvable: {:#?}",
                overlay.symbols()
            );
        }
    }
}
