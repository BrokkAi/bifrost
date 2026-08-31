use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use semver::Version;
use serde_json::Value;
use tree_sitter::{Node, Parser};

use crate::CancellationToken;
use crate::analyzer::semantic_model::{
    ActivationSelector, ArtifactProducerLimits, ArtifactProduction, ArtifactProductionRequest,
    AuthoredPayload, AuthoredSemanticModelPack, AuthoredShard, BoundedProducerDiagnostics,
    CatalogCoordinate, Compatibility, Completeness, DeclarationGuard, DependencyArtifactRole,
    DependencyDiscoveryOutcome, DependencyDiscoveryProfile, DependencyPackAdapter,
    DependencyPackDiagnostic, DependencyPackDiagnosticSeverity, DependencyPackLimits,
    DependencyPackProduction, DependencyProvenance, ExactArtifact, ExactDependencyArtifact,
    ExternalArtifactKind, ExternalArtifactPackProducer, HierarchyFact, HierarchyKind, Locator,
    MemberFact, MemberIdentity, MemberKind, NameSelector, Parameter, Producer, ProducerDiagnostic,
    ProducerDiagnosticSeverity, Provenance, ResolvedDependency, ResolvedDependencyArtifact, Safety,
    SemanticModelActivationEvidence, Signature, TypeFact, TypeIdentity, TypeKind, TypeRef,
    Visibility, carried_source_paths, member_declaration_id, read_exact_artifact_while,
    type_declaration_id,
};
use crate::analyzer::topology::DependencyScope;
use crate::analyzer::{JsTsDependencyDiscoveryConfig, Project};
use crate::hash::HashMap;
use brokk_bifrost_js_ts::model::node_text;
use brokk_bifrost_js_ts::tsconfig::{
    TypeScriptLibrarySelection, canonical_library_name, effective_library_selection_for_config,
    typescript_library_activation_closure,
};

pub const TYPESCRIPT_STDLIB_PACKAGE: &str = "typescript";
pub const TYPESCRIPT_STDLIB_VERSION: &str = "7.0.2";

/// Built-in TypeScript activation evidence derived from one effective
/// `tsconfig` selection. Every row is exact about the pinned npm package and
/// carries one canonical `typescript-lib:<name>` configuration identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeScriptLibraryActivationOutcome {
    pub selection: TypeScriptLibrarySelection,
    pub evidence: Vec<SemanticModelActivationEvidence>,
    pub diagnostics: Vec<String>,
}

pub fn typescript_library_activation_evidence(
    config_path: &Path,
    canonical_root: &Path,
) -> TypeScriptLibraryActivationOutcome {
    let selection = effective_library_selection_for_config(config_path, canonical_root);
    let evidence = if selection.is_complete() {
        typescript_library_activation_closure(selection.libraries())
            .iter()
            .map(|library| SemanticModelActivationEvidence {
                language: "typescript".to_owned(),
                ecosystem: "npm".to_owned(),
                package: Some(CatalogCoordinate {
                    name: TYPESCRIPT_STDLIB_PACKAGE.to_owned(),
                    version: Some(
                        Version::parse(TYPESCRIPT_STDLIB_VERSION)
                            .expect("pinned TypeScript version is valid"),
                    ),
                }),
                module: None,
                toolchain: None,
                target: None,
                configuration: Some(format!("typescript-lib:{library}")),
                artifact_sha256: None,
            })
            .collect()
    } else {
        Vec::new()
    };
    TypeScriptLibraryActivationOutcome {
        diagnostics: selection.diagnostics().to_vec(),
        selection,
        evidence,
    }
}

#[derive(Debug)]
struct NpmDiagnostic {
    code: &'static str,
    dependency_id: Option<String>,
    location: Option<String>,
    message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DeclarationEntry {
    module: String,
    relative_path: PathBuf,
    route: String,
}

/// Resolve exact locally installed npm declaration entry points without adding dependency files
/// to the project's workspace source set.
pub fn resolve_js_ts_semantic_pack_dependencies(
    config: &JsTsDependencyDiscoveryConfig,
    project: &dyn Project,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> DependencyDiscoveryOutcome {
    if cancelled(cancellation) {
        return cancelled_outcome();
    }

    let root = project.root();
    let lockfiles = lockfile_candidates(config, root);
    let approved_roots = approved_package_roots(config, root);
    let mut dependencies = Vec::new();
    let mut diagnostics = Vec::new();
    let mut metadata_inputs_considered = 0usize;
    let mut installed_packages = Vec::new();

    for lockfile in lockfiles {
        if cancelled(cancellation) {
            return cancelled_outcome();
        }
        if !lockfile.is_file() {
            if config
                .lockfile_paths
                .iter()
                .any(|path| resolve(root, path) == lockfile)
            {
                diagnostics.push(NpmDiagnostic {
                    code: "npm.lockfile.missing",
                    dependency_id: None,
                    location: Some(lockfile.display().to_string()),
                    message: "configured npm lockfile does not exist".to_owned(),
                });
            }
            continue;
        }
        metadata_inputs_considered = metadata_inputs_considered.saturating_add(1);
        let lock = match read_json_bounded(&lockfile, config.max_lockfile_bytes) {
            Ok(lock) => lock,
            Err(message) => {
                diagnostics.push(NpmDiagnostic {
                    code: "npm.lockfile.invalid",
                    dependency_id: None,
                    location: Some(lockfile.display().to_string()),
                    message,
                });
                continue;
            }
        };
        let Some(packages) = lock.get("packages").and_then(Value::as_object) else {
            diagnostics.push(NpmDiagnostic {
                code: "npm.lockfile.unsupported",
                dependency_id: None,
                location: Some(lockfile.display().to_string()),
                message: "npm lockfile does not contain an exact installed packages table"
                    .to_owned(),
            });
            continue;
        };
        installed_packages.extend(
            packages
                .iter()
                .filter(|(path, _)| lock_path_contains_node_modules(path))
                .map(|(path, entry)| (lockfile.clone(), path.clone(), entry.clone())),
        );
    }
    installed_packages
        .sort_unstable_by(|left, right| (&left.0, &left.1).cmp(&(&right.0, &right.1)));

    for (lockfile, lock_path, lock_entry) in installed_packages {
        if cancelled(cancellation) {
            return cancelled_outcome();
        }
        if dependencies.len() >= limits.max_dependencies {
            diagnostics.push(NpmDiagnostic {
                code: "limit.dependencies",
                dependency_id: None,
                location: Some(lockfile.display().to_string()),
                message: format!(
                    "npm dependency discovery exceeded the configured limit {}",
                    limits.max_dependencies
                ),
            });
            break;
        }
        metadata_inputs_considered = metadata_inputs_considered.saturating_add(1);
        match resolve_locked_package(
            &lockfile,
            &lock_path,
            &lock_entry,
            &approved_roots,
            config.max_package_manifest_bytes,
        ) {
            Ok(mut resolved) => dependencies.append(&mut resolved),
            Err(diagnostic) => diagnostics.push(diagnostic),
        }
    }

    dependencies.sort_by(|left, right| left.id.cmp(&right.id));
    dependencies.dedup_by(|left, right| left.id == right.id);
    let mut suppressed_diagnostics = diagnostics.len().saturating_sub(limits.max_diagnostics);
    diagnostics.truncate(limits.max_diagnostics);
    if dependencies.len() > limits.max_dependencies {
        suppressed_diagnostics =
            suppressed_diagnostics.saturating_add(dependencies.len() - limits.max_dependencies);
        dependencies.truncate(limits.max_dependencies);
    }
    let diagnostics: Vec<_> = diagnostics
        .into_iter()
        .map(|diagnostic| DependencyPackDiagnostic {
            severity: DependencyPackDiagnosticSeverity::Error,
            code: diagnostic.code.to_owned(),
            dependency_id: diagnostic.dependency_id,
            location: diagnostic.location,
            message: bounded_message(diagnostic.message, limits.max_diagnostic_message_bytes),
        })
        .collect();
    DependencyDiscoveryOutcome {
        profile: DependencyDiscoveryProfile {
            metadata_inputs_considered,
            dependencies_resolved: dependencies.len(),
        },
        dependencies,
        complete: diagnostics.is_empty() && suppressed_diagnostics == 0,
        diagnostics,
        suppressed_diagnostics,
        cancelled: false,
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TypeScriptDeclarationPackProducer;

#[derive(Debug, Clone, Copy, Default)]
pub struct JsTsDependencyPackAdapter;

impl ExternalArtifactPackProducer for TypeScriptDeclarationPackProducer {
    fn produce_exact_artifact(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
    ) -> ArtifactProduction {
        self.produce(request, limits, None)
    }

    fn produce_exact_artifact_with_cancellation(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
    ) -> ArtifactProduction {
        self.produce(request, limits, cancellation)
    }
}

impl TypeScriptDeclarationPackProducer {
    fn produce(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
    ) -> ArtifactProduction {
        if request.artifact_kind != ExternalArtifactKind::TypeScriptDeclarationFile {
            return failed_production(
                "artifact.kind",
                "TypeScript declaration producer requires a declaration-file artifact",
                limits,
            );
        }
        let artifact =
            match read_exact_artifact_while(&request.path, limits, || cancelled(cancellation)) {
                Ok(artifact) => artifact,
                Err(diagnostic) => return ArtifactProduction::failed(diagnostic, limits),
            };
        self.produce_loaded_artifact(request, limits, cancellation, &artifact)
    }

    pub fn produce_loaded_artifact(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
        artifact: &ExactArtifact,
    ) -> ArtifactProduction {
        if cancelled(cancellation) {
            return failed_loaded_production(
                "artifact.cancelled",
                "TypeScript declaration production was cancelled",
                artifact.sha256(),
                limits,
            );
        }
        let source = match std::str::from_utf8(artifact.bytes()) {
            Ok(source) => source,
            Err(_) => {
                return failed_loaded_production(
                    "typescript.declaration.encoding",
                    "TypeScript declaration artifact is not valid UTF-8",
                    artifact.sha256(),
                    limits,
                );
            }
        };
        let module_name = request
            .activation
            .iter()
            .find_map(|selector| selector.module.as_ref())
            .map(|module| module.name.clone())
            .unwrap_or_else(|| {
                request
                    .path
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
            });
        let locator_path = format!("{}.d.ts", module_name.replace(['/', '\\'], "_"));
        let outcome = parse_and_collect_declarations(
            source,
            &request.path.display().to_string(),
            locator_path,
            module_name,
            limits,
            cancellation,
            BoundedProducerDiagnostics::new(limits),
        );
        if outcome.cancelled {
            return failed_loaded_production(
                "artifact.cancelled",
                "TypeScript declaration production was cancelled",
                artifact.sha256(),
                limits,
            );
        }
        finish_typescript_production(
            request,
            artifact.sha256(),
            outcome.types,
            outcome.members,
            outcome.diagnostics,
        )
    }

    /// Produce one pack from an exact source set of npm declaration files.
    ///
    /// Each entry's importable module name is pinned explicitly by the spec
    /// (there is no on-disk `node_modules` layout to derive it from), and the
    /// package manifest is read only far enough to confirm the pinned tree
    /// actually names an npm package: a real `name` and an exact semantic
    /// `version`. An entry that fails to parse becomes a bounded reject
    /// diagnostic and makes the pack honestly partial, matching the Python
    /// stub source-set producer.
    pub fn produce_loaded_source_set(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
        artifact: &ExactArtifact,
        manifest_path: &str,
        declarations: &[(String, String)],
    ) -> ArtifactProduction {
        if request.artifact_kind != ExternalArtifactKind::NpmPackageManifest {
            return failed_production(
                "artifact.kind",
                "npm package source-set producer requires an npm_package_manifest artifact",
                limits,
            );
        }
        let mut diagnostics = Vec::new();
        let mut suppressed_diagnostics = 0usize;
        let partial = |diagnostics, suppressed_diagnostics| ArtifactProduction {
            artifact_sha256: Some(artifact.sha256().to_owned()),
            pack: None,
            completeness: Completeness::Partial,
            diagnostics,
            suppressed_diagnostics,
        };
        let Some(manifest_entry) = artifact
            .source_entries()
            .iter()
            .find(|entry| entry.relative_path() == manifest_path)
        else {
            diagnostics.push(ProducerDiagnostic {
                severity: ProducerDiagnosticSeverity::Error,
                code: "npm.package.manifest_missing".to_owned(),
                location: Some(manifest_path.to_owned()),
                declaration: None,
                message: "pinned npm source set does not contain its declared manifest".to_owned(),
            });
            return partial(diagnostics, suppressed_diagnostics);
        };
        if let Err(message) = validate_npm_manifest(manifest_entry.bytes()) {
            diagnostics.push(ProducerDiagnostic {
                severity: ProducerDiagnosticSeverity::Error,
                code: "npm.package.identity".to_owned(),
                location: Some(manifest_path.to_owned()),
                declaration: None,
                message,
            });
            return partial(diagnostics, suppressed_diagnostics);
        }

        let mut types = Vec::new();
        let mut members = Vec::new();
        for (module_name, declaration_path) in declarations {
            if cancelled(cancellation) {
                diagnostics.push(ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    code: "artifact.cancelled".to_owned(),
                    location: None,
                    declaration: None,
                    message: "npm package source-set production was cancelled".to_owned(),
                });
                return partial(diagnostics, suppressed_diagnostics);
            }
            let Some(entry) = artifact
                .source_entries()
                .iter()
                .find(|entry| entry.relative_path() == declaration_path)
            else {
                diagnostics.push(ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Warning,
                    code: "npm.declarations.missing".to_owned(),
                    location: Some(declaration_path.clone()),
                    declaration: None,
                    message: "pinned npm source set does not contain its declared declaration file"
                        .to_owned(),
                });
                continue;
            };
            let Ok(source) = std::str::from_utf8(entry.bytes()) else {
                diagnostics.push(ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Warning,
                    code: "typescript.declaration.encoding".to_owned(),
                    location: Some(declaration_path.clone()),
                    declaration: None,
                    message: "TypeScript declaration entry is not valid UTF-8".to_owned(),
                });
                continue;
            };
            let locator_path = format!("{}.d.ts", module_name.replace(['/', '\\'], "_"));
            let outcome = parse_and_collect_declarations(
                source,
                declaration_path,
                locator_path,
                module_name.clone(),
                limits,
                cancellation,
                BoundedProducerDiagnostics::new(limits),
            );
            if outcome.cancelled {
                diagnostics.push(ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    code: "artifact.cancelled".to_owned(),
                    location: Some(declaration_path.clone()),
                    declaration: None,
                    message: "npm package source-set production was cancelled".to_owned(),
                });
                return partial(diagnostics, suppressed_diagnostics);
            }
            let (entry_diagnostics, entry_suppressed) = outcome.diagnostics.finish();
            diagnostics.extend(entry_diagnostics);
            suppressed_diagnostics = suppressed_diagnostics.saturating_add(entry_suppressed);
            types.extend(outcome.types);
            members.extend(outcome.members);
        }
        types.sort_unstable_by(|left, right| (&left.name, &left.id).cmp(&(&right.name, &right.id)));
        members.sort_unstable_by(|left, right| {
            (&left.owner, &left.name, &left.id).cmp(&(&right.owner, &right.name, &right.id))
        });
        members.dedup_by(|left, right| left.id == right.id);
        let has_declarations =
            !members.is_empty() || types.iter().any(|fact| fact.type_kind != TypeKind::Module);
        if !has_declarations {
            diagnostics.push(ProducerDiagnostic {
                severity: ProducerDiagnosticSeverity::Error,
                code: "npm.declarations.no_external_declarations".to_owned(),
                location: None,
                declaration: None,
                message: "pinned npm declaration files contain no exported or ambient declarations"
                    .to_owned(),
            });
        }
        let mut activation = request.activation.clone();
        for selector in &mut activation {
            selector.artifact_sha256 = Some(artifact.sha256().to_owned());
        }
        let completeness = if diagnostics.is_empty() && suppressed_diagnostics == 0 {
            Completeness::Complete
        } else {
            Completeness::Partial
        };
        // Every Source locator in these shards names a declaration module this
        // producer read and parsed, so the pack carries them all.
        let shards = vec![AuthoredShard {
            id: "declarations.typescript.external".to_owned(),
            activation,
            payload: AuthoredPayload::DeclarationFacts {
                types,
                members,
                relations: Vec::new(),
            },
        }];
        ArtifactProduction {
            artifact_sha256: Some(artifact.sha256().to_owned()),
            pack: has_declarations.then(|| AuthoredSemanticModelPack {
                schema_version: crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
                pack_id: request.pack_id.clone(),
                version: request.pack_version.clone(),
                producer: Producer {
                    name: "bifrost-typescript-declaration".to_owned(),
                    version: env!("CARGO_PKG_VERSION").to_owned(),
                },
                language: "typescript".to_owned(),
                ecosystem: request.ecosystem.clone(),
                compatibility: request.compatibility.clone(),
                provenance: request.provenance.clone(),
                license: request.license.clone(),
                completeness,
                safety: request.safety.clone(),
                carried_sources: carried_source_paths(&shards),
                shards,
            }),
            completeness,
            diagnostics,
            suppressed_diagnostics,
        }
    }

    /// Produce one shard per canonical TypeScript built-in library from the
    /// exact `package.json` + `lib/*.d.ts` source set used by the pinned pack.
    ///
    /// Built-in declarations are ambient globals rather than npm modules. Each
    /// file is therefore collected in the global scope, and each shard carries
    /// a `typescript-lib:<canonical>` configuration selector so the workspace
    /// can activate precisely the effective `tsconfig` library set.
    pub fn produce_loaded_library_set(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
        artifact: &ExactArtifact,
        manifest_path: &str,
        libraries: &[(String, String)],
    ) -> ArtifactProduction {
        if request.artifact_kind != ExternalArtifactKind::TypeScriptLibrarySet {
            return failed_loaded_production(
                "artifact.kind",
                "TypeScript library source-set producer requires a typescript_library_set artifact",
                artifact.sha256(),
                limits,
            );
        }
        let mut diagnostics = BoundedProducerDiagnostics::new(limits);
        let mut suppressed_diagnostics = 0usize;
        let Some(manifest) = artifact
            .source_entries()
            .iter()
            .find(|entry| entry.relative_path() == manifest_path)
        else {
            diagnostics.error(
                "typescript.package.manifest_missing",
                Some(manifest_path.to_owned()),
                "pinned TypeScript source set does not contain package.json",
            );
            let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
            return ArtifactProduction {
                artifact_sha256: Some(artifact.sha256().to_owned()),
                pack: None,
                completeness: Completeness::Partial,
                diagnostics,
                suppressed_diagnostics,
            };
        };
        if let Err(message) = validate_typescript_manifest(manifest.bytes()) {
            diagnostics.error(
                "typescript.package.identity",
                Some(manifest_path.to_owned()),
                message,
            );
            let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
            return ArtifactProduction {
                artifact_sha256: Some(artifact.sha256().to_owned()),
                pack: None,
                completeness: Completeness::Partial,
                diagnostics,
                suppressed_diagnostics,
            };
        }

        let mut names = libraries
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        names.sort_unstable();
        if names.windows(2).any(|pair| pair[0] == pair[1]) {
            diagnostics.error(
                "typescript.library.duplicate",
                None,
                "pinned TypeScript source set contains a duplicate canonical library",
            );
        }
        let mut references_by_library = BTreeMap::<String, Vec<String>>::new();
        for (library_name, declaration_path) in libraries {
            let Some(entry) = artifact
                .source_entries()
                .iter()
                .find(|entry| entry.relative_path() == declaration_path)
            else {
                continue;
            };
            let Ok(source) = std::str::from_utf8(entry.bytes()) else {
                continue;
            };
            let mut tree_parser = Parser::new();
            tree_parser
                .set_language(&tree_sitter_typescript::LANGUAGE_TSX.into())
                .expect("tree-sitter TypeScript language must load");
            let Some(tree) = tree_parser.parse(source, None) else {
                continue;
            };
            if tree.root_node().has_error() {
                continue;
            }
            let mut references = Vec::new();
            for reference in triple_slash_library_references(tree.root_node(), source) {
                if let TripleSlashLibraryReference::Known(name) = reference {
                    references.push(name);
                }
            }
            references.sort_unstable();
            references.dedup();
            references_by_library.insert(library_name.clone(), references);
        }
        let mut shards = Vec::new();
        let mut seen_paths = BTreeSet::new();
        let mut remaining_records = limits.max_records;
        for (library_name, declaration_path) in libraries {
            let path_name = Path::new(declaration_path)
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_prefix("lib."))
                .and_then(canonical_library_name);
            if canonical_library_name(library_name) != Some(library_name.clone())
                || path_name.as_deref() != Some(library_name.as_str())
            {
                diagnostics.error(
                    "typescript.library.identity",
                    Some(declaration_path.clone()),
                    format!(
                        "library {library_name} is not a canonical TypeScript 7.0.2 declaration identity"
                    ),
                );
                continue;
            }
            if !seen_paths.insert(declaration_path.clone()) {
                diagnostics.error(
                    "typescript.library.duplicate_path",
                    Some(declaration_path.clone()),
                    "pinned TypeScript source set contains a duplicate declaration path",
                );
                continue;
            }
            if cancelled(cancellation) {
                diagnostics.error(
                    "artifact.cancelled",
                    Some(declaration_path.clone()),
                    "TypeScript library source-set production was cancelled",
                );
                break;
            }
            let Some(entry) = artifact
                .source_entries()
                .iter()
                .find(|entry| entry.relative_path() == declaration_path)
            else {
                diagnostics.error(
                    "typescript.library.missing",
                    Some(declaration_path.clone()),
                    "pinned TypeScript library declaration is missing",
                );
                continue;
            };
            let Ok(source) = std::str::from_utf8(entry.bytes()) else {
                diagnostics.error(
                    "typescript.declaration.encoding",
                    Some(declaration_path.clone()),
                    "TypeScript library declaration is not valid UTF-8",
                );
                continue;
            };
            let mut tree_parser = Parser::new();
            tree_parser
                .set_language(&tree_sitter_typescript::LANGUAGE_TSX.into())
                .expect("tree-sitter TypeScript language must load");
            let Some(tree) = tree_parser.parse(source, None) else {
                diagnostics.error(
                    "typescript.declaration.parse",
                    Some(declaration_path.clone()),
                    "TypeScript library declaration could not be parsed",
                );
                continue;
            };
            if tree.root_node().has_error() && has_unrecoverable_typescript_errors(tree.root_node())
            {
                diagnostics.error(
                    "typescript.declaration.parse",
                    Some(declaration_path.clone()),
                    "TypeScript library declaration contains malformed or unsupported syntax",
                );
                continue;
            }
            let references = triple_slash_library_references(tree.root_node(), source);
            for reference in references {
                match reference {
                    TripleSlashLibraryReference::Known(reference) => {
                        if !libraries.iter().any(|(name, _)| name == &reference) {
                            diagnostics.error(
                                "typescript.library.reference_missing",
                                Some(declaration_path.clone()),
                                format!(
                                    "library {library_name} references unpinned built-in library {reference}"
                                ),
                            );
                        }
                    }
                    TripleSlashLibraryReference::Unknown(reference) => diagnostics.error(
                        "typescript.library.reference_unknown",
                        Some(declaration_path.clone()),
                        format!(
                            "library {library_name} references unknown built-in library {reference}"
                        ),
                    ),
                    TripleSlashLibraryReference::Malformed(message) => diagnostics.error(
                        "typescript.library.reference_malformed",
                        Some(declaration_path.clone()),
                        format!(
                            "library {library_name} has malformed triple-slash reference: {message}"
                        ),
                    ),
                }
            }
            if remaining_records == 0 {
                diagnostics.warning(
                    "limit.records",
                    Some(declaration_path.clone()),
                    format!(
                        "TypeScript library source set exhausted the {} record budget",
                        limits.max_records
                    ),
                );
                break;
            }
            let mut library_limits = *limits;
            library_limits.max_records = remaining_records;
            let mut collector = DeclarationCollector::new(
                source,
                declaration_path.clone(),
                format!("global.{library_name}"),
                &library_limits,
                cancellation,
                BoundedProducerDiagnostics::new(limits),
            );
            collector.collect_global(tree.root_node());
            let DeclarationCollector {
                mut types,
                mut members,
                diagnostics: collector_diagnostics,
                cancelled: collector_cancelled,
                remaining_records: collector_remaining_records,
                ..
            } = collector;
            remaining_records = collector_remaining_records;
            let (collector_diagnostics, collector_suppressed) = collector_diagnostics.finish();
            suppressed_diagnostics = suppressed_diagnostics.saturating_add(collector_suppressed);
            for diagnostic in collector_diagnostics {
                match diagnostic.severity {
                    ProducerDiagnosticSeverity::Warning => diagnostics.warning(
                        diagnostic.code,
                        diagnostic.location,
                        diagnostic.message,
                    ),
                    ProducerDiagnosticSeverity::Error => {
                        diagnostics.error(diagnostic.code, diagnostic.location, diagnostic.message)
                    }
                }
            }
            if collector_cancelled {
                diagnostics.error(
                    "artifact.cancelled",
                    Some(declaration_path.clone()),
                    "TypeScript library source-set production was cancelled",
                );
                break;
            }
            types.sort_unstable_by(|left, right| {
                (&left.name, &left.id).cmp(&(&right.name, &right.id))
            });
            members.sort_unstable_by(|left, right| {
                (&left.owner, &left.name, &left.id).cmp(&(&right.owner, &right.name, &right.id))
            });
            members.dedup_by(|left, right| left.id == right.id);
            let mut activation = request.activation.clone();
            if activation.is_empty() {
                activation.push(ActivationSelector {
                    package: None,
                    module: None,
                    toolchain: None,
                    targets: Vec::new(),
                    configurations: Vec::new(),
                    artifact_sha256: None,
                });
            }
            for selector in &mut activation {
                selector.package = Some(NameSelector {
                    name: TYPESCRIPT_STDLIB_PACKAGE.to_owned(),
                    version: Some(format!("={TYPESCRIPT_STDLIB_VERSION}")),
                });
                selector.configurations = library_activation_configurations(
                    library_name,
                    libraries,
                    &references_by_library,
                );
                // Runtime discovery intentionally emits no local artifact. The
                // installed pinned pack must therefore match package/version
                // and `typescript-lib:<name>` evidence alone.
                selector.artifact_sha256 = None;
            }
            shards.push(AuthoredShard {
                id: format!("declarations.typescript.lib.{library_name}"),
                activation,
                payload: AuthoredPayload::DeclarationFacts {
                    types,
                    members,
                    relations: Vec::new(),
                },
            });
        }
        shards.sort_unstable_by(|left, right| left.id.cmp(&right.id));
        consolidate_library_shards(&mut shards, &mut diagnostics);
        if shards.is_empty() {
            diagnostics.error(
                "typescript.library.no_declarations",
                None,
                "pinned TypeScript library source set produced no declaration shards",
            );
        }
        let (diagnostics, own_suppressed_diagnostics) = diagnostics.finish();
        suppressed_diagnostics = suppressed_diagnostics.saturating_add(own_suppressed_diagnostics);
        let completeness = if diagnostics.is_empty() && suppressed_diagnostics == 0 {
            Completeness::Complete
        } else {
            Completeness::Partial
        };
        ArtifactProduction {
            artifact_sha256: Some(artifact.sha256().to_owned()),
            pack: (!shards.is_empty()).then(|| AuthoredSemanticModelPack {
                schema_version: crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
                pack_id: request.pack_id.clone(),
                version: request.pack_version.clone(),
                producer: Producer {
                    name: "bifrost-typescript-declaration".to_owned(),
                    version: env!("CARGO_PKG_VERSION").to_owned(),
                },
                language: "typescript".to_owned(),
                ecosystem: request.ecosystem.clone(),
                compatibility: request.compatibility.clone(),
                provenance: request.provenance.clone(),
                license: request.license.clone(),
                completeness,
                safety: request.safety.clone(),
                carried_sources: carried_source_paths(&shards),
                shards,
            }),
            completeness,
            diagnostics,
            suppressed_diagnostics,
        }
    }
}

fn consolidate_library_shards(
    shards: &mut [AuthoredShard],
    diagnostics: &mut BoundedProducerDiagnostics,
) {
    let mut canonical = BTreeMap::<String, (usize, TypeFact)>::new();
    let mut configurations = BTreeMap::<String, BTreeSet<String>>::new();
    for (shard_index, shard) in shards.iter().enumerate() {
        let AuthoredPayload::DeclarationFacts { types, .. } = &shard.payload else {
            continue;
        };
        let shard_configurations = shard
            .activation
            .iter()
            .flat_map(|selector| selector.configurations.iter().cloned())
            .collect::<BTreeSet<_>>();
        for incoming in types {
            configurations
                .entry(incoming.name.clone())
                .or_default()
                .extend(shard_configurations.iter().cloned());
            let Some((owner, existing)) = canonical.get_mut(&incoming.name) else {
                canonical.insert(incoming.name.clone(), (shard_index, incoming.clone()));
                continue;
            };
            if existing.type_kind != incoming.type_kind {
                diagnostics.error(
                    "typescript.declaration.incompatible_merge",
                    None,
                    format!(
                        "library shards disagree on the TypeScript declaration kind of {}",
                        incoming.name
                    ),
                );
                continue;
            }
            for relation in &incoming.hierarchy {
                if !existing.hierarchy.contains(relation) {
                    existing.hierarchy.push(relation.clone());
                }
            }
            for alias in &incoming.aliases {
                if !existing.aliases.contains(alias) {
                    existing.aliases.push(alias.clone());
                }
            }
            for surface in &incoming.extension_surfaces {
                if !existing.extension_surfaces.contains(surface) {
                    existing.extension_surfaces.push(surface.clone());
                }
            }
            existing.guard = DeclarationGuard::union(existing.guard.take(), incoming.guard.clone());
            if existing.type_parameters.is_empty() {
                existing.type_parameters = incoming.type_parameters.clone();
            }
            if existing.underlying_type.is_none() {
                existing.underlying_type = incoming.underlying_type.clone();
            }
            *owner = (*owner).min(shard_index);
        }
    }

    let mut seen_members = BTreeSet::new();
    for (shard_index, shard) in shards.iter_mut().enumerate() {
        let AuthoredPayload::DeclarationFacts { types, members, .. } = &mut shard.payload else {
            continue;
        };
        types.retain(|type_fact| {
            canonical
                .get(&type_fact.name)
                .is_some_and(|(owner, _)| *owner == shard_index)
        });
        for type_fact in types.iter_mut() {
            if let Some((_, merged)) = canonical.get(&type_fact.name) {
                *type_fact = merged.clone();
            }
        }
        let shard_configurations = types
            .iter()
            .flat_map(|type_fact| configurations.get(&type_fact.name).into_iter().flatten())
            .cloned()
            .collect::<Vec<_>>();
        if !shard_configurations.is_empty() {
            for selector in &mut shard.activation {
                selector.configurations = shard_configurations.clone();
            }
        }
        members.retain(|member| seen_members.insert(member.id.clone()));
    }
}

/// The result of parsing and collecting declarations from one TypeScript
/// declaration source. `types`/`members` are empty on a parse failure, on a
/// tree with syntax errors, and on cancellation; `diagnostics` names which.
struct DeclarationCollectionOutcome {
    types: Vec<TypeFact>,
    members: Vec<MemberFact>,
    diagnostics: BoundedProducerDiagnostics,
    cancelled: bool,
}

#[allow(clippy::too_many_arguments)]
fn parse_and_collect_declarations(
    source: &str,
    diagnostic_path: &str,
    locator_path: String,
    module_name: String,
    limits: &ArtifactProducerLimits,
    cancellation: Option<&CancellationToken>,
    mut diagnostics: BoundedProducerDiagnostics,
) -> DeclarationCollectionOutcome {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_typescript::LANGUAGE_TSX.into())
        .expect("tree-sitter TypeScript language must load");
    let Some(tree) = parser.parse(source, None) else {
        diagnostics.error(
            "typescript.declaration.parse",
            Some(diagnostic_path.to_owned()),
            "TypeScript declaration artifact could not be parsed",
        );
        return DeclarationCollectionOutcome {
            types: Vec::new(),
            members: Vec::new(),
            diagnostics,
            cancelled: false,
        };
    };
    if tree.root_node().has_error() && has_unrecoverable_typescript_errors(tree.root_node()) {
        diagnostics.error(
            "typescript.declaration.parse",
            Some(diagnostic_path.to_owned()),
            "TypeScript declaration artifact contains malformed or unsupported syntax",
        );
        return DeclarationCollectionOutcome {
            types: Vec::new(),
            members: Vec::new(),
            diagnostics,
            cancelled: false,
        };
    }
    let mut collector = DeclarationCollector::new(
        source,
        locator_path,
        module_name,
        limits,
        cancellation,
        diagnostics,
    );
    collector.collect(tree.root_node());
    let DeclarationCollector {
        mut types,
        mut members,
        diagnostics,
        cancelled,
        ..
    } = collector;
    if cancelled {
        return DeclarationCollectionOutcome {
            types: Vec::new(),
            members: Vec::new(),
            diagnostics,
            cancelled: true,
        };
    }
    types.sort_unstable_by(|left, right| (&left.name, &left.id).cmp(&(&right.name, &right.id)));
    members.sort_unstable_by(|left, right| {
        (&left.owner, &left.name, &left.id).cmp(&(&right.owner, &right.name, &right.id))
    });
    members.dedup_by(|left, right| left.id == right.id);
    DeclarationCollectionOutcome {
        types,
        members,
        diagnostics,
        cancelled: false,
    }
}

/// Validate that pinned npm manifest bytes name a real package: valid JSON
/// with a non-empty `name` and an exact semantic `version`.
fn validate_npm_manifest(bytes: &[u8]) -> Result<(), String> {
    let manifest: Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("manifest is not valid JSON: {error}"))?;
    let name = manifest
        .get("name")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    if name.is_none() {
        return Err("manifest package name is missing".to_owned());
    }
    let version_text = manifest
        .get("version")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "manifest package version is missing".to_owned())?;
    Version::parse(version_text).map_err(|_| {
        format!("manifest version is not an exact semantic version: {version_text}")
    })?;
    Ok(())
}

fn validate_typescript_manifest(bytes: &[u8]) -> Result<(), String> {
    let manifest: Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("manifest is not valid JSON: {error}"))?;
    let name = manifest.get("name").and_then(Value::as_str);
    if name != Some(TYPESCRIPT_STDLIB_PACKAGE) {
        return Err("pinned library manifest must name the typescript package".to_owned());
    }
    let version = manifest.get("version").and_then(Value::as_str);
    if version != Some(TYPESCRIPT_STDLIB_VERSION) {
        return Err("pinned library manifest must be TypeScript version 7.0.2".to_owned());
    }
    if manifest.get("license").and_then(Value::as_str) != Some("Apache-2.0") {
        return Err("pinned library manifest must carry the Apache-2.0 license".to_owned());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TripleSlashLibraryReference {
    Known(String),
    Unknown(String),
    Malformed(String),
}

/// Read triple-slash `lib` references from parsed comment nodes. The small
/// directive parser accepts the whitespace forms TypeScript permits, while
/// keeping ordinary comments and non-`lib` directives out of the result.
fn triple_slash_library_references(
    root: Node<'_>,
    source: &str,
) -> Vec<TripleSlashLibraryReference> {
    let mut references = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "comment" {
            let text = node_text(node, source).trim();
            if let Some(directive) = text.strip_prefix("///")
                && let Some(reference) = parse_triple_slash_library_directive(directive)
            {
                references.push(reference);
            }
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    references
}

fn parse_triple_slash_library_directive(text: &str) -> Option<TripleSlashLibraryReference> {
    let start = text.find("<reference")? + "<reference".len();
    let Some(end) = text[start..].find('>').map(|offset| offset + start) else {
        return Some(TripleSlashLibraryReference::Malformed(
            "reference directive has no closing `>`".to_owned(),
        ));
    };
    let mut content = text[start..end].trim();
    if content.ends_with('/') {
        content = content[..content.len() - 1].trim_end();
    }
    let lib_start = content.find("lib")?;
    let after_name = &content[lib_start + 3..];
    if after_name
        .chars()
        .next()
        .is_some_and(|character| !character.is_ascii_whitespace() && character != '=')
    {
        return Some(TripleSlashLibraryReference::Malformed(
            "malformed lib attribute name".to_owned(),
        ));
    }
    let Some(equals) = after_name.find('=') else {
        return Some(TripleSlashLibraryReference::Malformed(
            "lib attribute has no `=`".to_owned(),
        ));
    };
    let mut value = after_name[equals + 1..].trim_start();
    let Some(quote) = value.as_bytes().first().copied() else {
        return Some(TripleSlashLibraryReference::Malformed(
            "lib attribute has no value".to_owned(),
        ));
    };
    if quote != b'"' && quote != b'\'' {
        return Some(TripleSlashLibraryReference::Malformed(
            "lib attribute must use a quoted value".to_owned(),
        ));
    }
    value = &value[1..];
    let Some(end_quote) = value.find(quote as char) else {
        return Some(TripleSlashLibraryReference::Malformed(
            "lib attribute has no closing quote".to_owned(),
        ));
    };
    let raw = value[..end_quote].trim();
    if raw.is_empty() {
        return Some(TripleSlashLibraryReference::Malformed(
            "lib attribute is empty".to_owned(),
        ));
    }
    match canonical_library_name(raw) {
        Some(name) => Some(TripleSlashLibraryReference::Known(name)),
        None => Some(TripleSlashLibraryReference::Unknown(raw.to_owned())),
    }
}

fn library_activation_configurations(
    library_name: &str,
    libraries: &[(String, String)],
    references_by_library: &BTreeMap<String, Vec<String>>,
) -> Vec<String> {
    let mut configurations = BTreeSet::new();
    for (candidate, _) in libraries {
        let mut stack = vec![candidate.as_str()];
        let mut visited = BTreeSet::new();
        while let Some(current) = stack.pop() {
            if !visited.insert(current) {
                continue;
            }
            if current == library_name {
                configurations.insert(format!("typescript-lib:{candidate}"));
                break;
            }
            if let Some(references) = references_by_library.get(current) {
                stack.extend(references.iter().map(String::as_str));
            }
        }
    }
    if configurations.is_empty() {
        configurations.insert(format!("typescript-lib:{library_name}"));
    }
    configurations.into_iter().collect()
}

impl DependencyPackAdapter for JsTsDependencyPackAdapter {
    fn adapter_name(&self) -> &str {
        "bifrost-js-ts-dependency"
    }

    fn adapter_version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn producer(&self) -> Producer {
        Producer {
            name: "bifrost-typescript-declaration".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    fn can_produce(&self, dependency: &ResolvedDependency) -> bool {
        if dependency.evidence.language == "typescript"
            && dependency.evidence.ecosystem == "npm"
            && dependency.evidence.package.as_ref().is_some_and(|package| {
                package.name == TYPESCRIPT_STDLIB_PACKAGE
                    && package.version.as_ref().is_some_and(|version| {
                        version == &Version::parse(TYPESCRIPT_STDLIB_VERSION).expect("valid pin")
                    })
            })
            && dependency.artifacts.len() == 1
            && dependency.artifacts[0].kind == ExternalArtifactKind::TypeScriptLibrarySet
        {
            return true;
        }
        dependency.evidence.language == "typescript"
            && dependency.evidence.ecosystem == "npm"
            && dependency.artifacts.len() == 2
            && dependency.artifacts.iter().any(|artifact| {
                artifact.role == DependencyArtifactRole::Metadata
                    && artifact.kind == ExternalArtifactKind::NpmPackageManifest
            })
            && dependency.artifacts.iter().any(|artifact| {
                artifact.role == DependencyArtifactRole::Declarations
                    && artifact.kind == ExternalArtifactKind::TypeScriptDeclarationFile
            })
    }

    fn produce(
        &self,
        dependency: &ResolvedDependency,
        artifacts: &[ExactDependencyArtifact],
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
    ) -> DependencyPackProduction {
        if dependency
            .artifacts
            .iter()
            .any(|artifact| artifact.kind == ExternalArtifactKind::TypeScriptLibrarySet)
        {
            if artifacts.len() != 1
                || artifacts[0].kind() != ExternalArtifactKind::TypeScriptLibrarySet
            {
                return dependency_failure(
                    "artifact.count",
                    "TypeScript library production requires exactly one pinned source set",
                );
            }
            let source_set = &artifacts[0];
            let mut libraries = source_set
                .source_entries()
                .iter()
                .filter(|entry| entry.relative_path() != "package.json")
                .filter_map(|entry| {
                    let file_name = Path::new(entry.relative_path())
                        .file_name()
                        .and_then(|name| name.to_str())
                        .and_then(|name| name.strip_prefix("lib."))?;
                    let name = canonical_library_name(file_name)?;
                    // TypeScript ships compatibility aliases such as
                    // lib.es6.d.ts alongside the canonical lib.es2015.d.ts.
                    // Keep one pinned identity and reject aggregate aliases
                    // that would otherwise create duplicate shards.
                    (file_name == format!("{name}.d.ts"))
                        .then(|| (name, entry.relative_path().to_owned()))
                })
                .collect::<Vec<_>>();
            libraries.sort_unstable();
            if libraries.is_empty() {
                return dependency_failure(
                    "typescript.library.empty",
                    "TypeScript library source set contains no lib/*.d.ts declarations",
                );
            }
            let mut request = typescript_library_production_request(dependency);
            request.path = source_set.path().to_owned();
            let production = TypeScriptDeclarationPackProducer.produce_loaded_library_set(
                &request,
                limits,
                cancellation,
                source_set.exact(),
                "package.json",
                &libraries,
            );
            return DependencyPackProduction {
                pack: production.pack,
                diagnostics: production.diagnostics,
                suppressed_diagnostics: production.suppressed_diagnostics,
            };
        }
        let Some(declaration) = artifacts.iter().find(|artifact| {
            artifact.role() == DependencyArtifactRole::Declarations
                && artifact.kind() == ExternalArtifactKind::TypeScriptDeclarationFile
        }) else {
            return dependency_failure(
                "artifact.role",
                "npm dependency production requires one declaration artifact",
            );
        };
        let valid_manifest_count = artifacts
            .iter()
            .filter(|artifact| {
                artifact.role() == DependencyArtifactRole::Metadata
                    && artifact.kind() == ExternalArtifactKind::NpmPackageManifest
            })
            .count();
        if artifacts.len() != 2 || valid_manifest_count != 1 {
            return dependency_failure(
                "artifact.count",
                "npm dependency production requires exactly one package manifest and one declaration artifact",
            );
        }
        let mut request = js_ts_dependency_production_request(dependency);
        request.path = declaration.path().to_owned();
        let mut production = TypeScriptDeclarationPackProducer.produce_loaded_artifact(
            &request,
            limits,
            cancellation,
            declaration.exact(),
        );
        debug_assert_eq!(
            production.artifact_sha256.as_deref(),
            Some(declaration.sha256())
        );
        if let Some(pack) = production.pack.as_mut() {
            pack.producer = self.producer();
        }
        DependencyPackProduction {
            pack: production.pack,
            diagnostics: production.diagnostics,
            suppressed_diagnostics: production.suppressed_diagnostics,
        }
    }
}

struct DeclarationCollector<'source, 'cancel> {
    source: &'source str,
    artifact_path: String,
    root_module_name: String,
    limits: &'source ArtifactProducerLimits,
    cancellation: Option<&'cancel CancellationToken>,
    diagnostics: BoundedProducerDiagnostics,
    types: Vec<TypeFact>,
    members: Vec<MemberFact>,
    type_index_by_name: HashMap<String, usize>,
    export_aliases: HashMap<String, Vec<String>>,
    external_module: bool,
    remaining_records: usize,
    cancelled: bool,
    record_limit_hit: bool,
    global_scope: bool,
}

#[derive(Clone)]
struct PendingDeclaration<'tree> {
    node: Node<'tree>,
    owner_name: String,
    owner_id: String,
    exported: bool,
    ambient: bool,
}

struct MemberDraft {
    name: String,
    member_kind: MemberKind,
    visibility: Visibility,
    is_static: bool,
    signature: Option<Signature>,
}

impl<'source, 'cancel> DeclarationCollector<'source, 'cancel> {
    fn new(
        source: &'source str,
        artifact_path: String,
        root_module_name: String,
        limits: &'source ArtifactProducerLimits,
        cancellation: Option<&'cancel CancellationToken>,
        diagnostics: BoundedProducerDiagnostics,
    ) -> Self {
        Self {
            source,
            artifact_path,
            root_module_name,
            limits,
            cancellation,
            diagnostics,
            types: Vec::new(),
            members: Vec::new(),
            type_index_by_name: HashMap::default(),
            export_aliases: HashMap::default(),
            external_module: false,
            remaining_records: limits.max_records,
            cancelled: false,
            record_limit_hit: false,
            global_scope: false,
        }
    }

    fn collect(&mut self, root: Node<'_>) {
        self.export_aliases = explicit_export_aliases(root, self.source);
        self.external_module = (0..root.named_child_count()).any(|index| {
            root.named_child(index).is_some_and(|child| {
                matches!(child.kind(), "import_statement" | "export_statement")
            })
        });
        let root_name = self.root_module_name.clone();
        let Some(root_id) =
            self.add_type(&root_name, TypeKind::Module, root, Vec::new(), Vec::new())
        else {
            return;
        };
        let mut stack = Vec::new();
        for index in (0..root.named_child_count()).rev() {
            if let Some(child) = root.named_child(index) {
                stack.push(PendingDeclaration {
                    node: child,
                    owner_name: root_name.clone(),
                    owner_id: root_id.clone(),
                    exported: !self.external_module,
                    ambient: false,
                });
            }
        }
        while let Some(pending) = stack.pop() {
            if cancelled(self.cancellation) {
                self.cancelled = true;
                return;
            }
            self.visit(pending, &mut stack);
        }
        self.resolve_local_hierarchy_ids();
        self.apply_export_aliases(&root_id);
        if self.record_limit_hit {
            self.diagnostics.warning(
                "limit.records",
                None,
                format!(
                    "producer stopped after {} declaration records",
                    self.limits.max_records
                ),
            );
        }
    }

    /// Collect a `lib.*.d.ts` file in the ambient global scope.  Built-in
    /// libraries declare names such as `Array` and `Document` directly; they
    /// must not acquire the synthetic source-file module prefix used for npm
    /// modules.  The small synthetic `global` owner remains only to give
    /// top-level members a stable owner identity.
    fn collect_global(&mut self, root: Node<'_>) {
        self.global_scope = true;
        self.collect(root);
    }

    fn visit<'tree>(
        &mut self,
        pending: PendingDeclaration<'tree>,
        stack: &mut Vec<PendingDeclaration<'tree>>,
    ) {
        let PendingDeclaration {
            node,
            owner_name,
            owner_id,
            exported,
            ambient,
        } = pending;
        match node.kind() {
            "export_statement" => {
                if let Some(declaration) = node.child_by_field_name("declaration") {
                    stack.push(PendingDeclaration {
                        node: declaration,
                        owner_name,
                        owner_id,
                        exported: true,
                        ambient,
                    });
                } else if node.child_by_field_name("source").is_some() {
                    self.diagnostics.warning(
                        "typescript.reexport.unresolved",
                        Some(self.artifact_path.clone()),
                        "declaration re-export has no locally resolvable declaration",
                    );
                } else if is_export_assignment(node) {
                    self.diagnostics.warning(
                        "typescript.export_assignment.unsupported",
                        Some(self.artifact_path.clone()),
                        "declaration uses `export =`, which replaces the module's export shape",
                    );
                }
            }
            "ambient_declaration" | "statement_block" => {
                let exported = exported || is_global_ambient_declaration(node);
                for index in (0..node.named_child_count()).rev() {
                    if let Some(declaration) = node.named_child(index) {
                        stack.push(PendingDeclaration {
                            node: declaration,
                            owner_name: owner_name.clone(),
                            owner_id: owner_id.clone(),
                            exported,
                            ambient: true,
                        });
                    }
                }
            }
            "class_declaration"
            | "abstract_class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "type_alias_declaration" => {
                if exported
                    || (owner_name == self.root_module_name
                        && self.node_is_explicitly_exported(node))
                {
                    self.collect_type_declaration(node, &owner_name, stack, ambient);
                }
            }
            "internal_module" => {
                if exported || (ambient && is_global_internal_module(node, self.source)) {
                    self.collect_module(node, &owner_name, stack);
                }
            }
            "function_declaration" | "function_signature" => {
                if exported
                    || (owner_name == self.root_module_name
                        && self.node_is_explicitly_exported(node))
                {
                    self.collect_callable(node, &owner_id, MemberKind::Function, true);
                }
            }
            "lexical_declaration" | "variable_declaration" => {
                self.collect_variables(node, &owner_id, exported);
            }
            _ => {}
        }
    }

    fn collect_type_declaration<'tree>(
        &mut self,
        node: Node<'tree>,
        owner_name: &str,
        stack: &mut Vec<PendingDeclaration<'tree>>,
        ambient: bool,
    ) {
        let Some(short_name) = field_text(node, "name", self.source) else {
            return;
        };
        let name = self.qualified_name(owner_name, &short_name);
        let kind = match node.kind() {
            "interface_declaration" => TypeKind::Interface,
            "enum_declaration" => TypeKind::Enum,
            "type_alias_declaration" => TypeKind::TypeAlias,
            _ => TypeKind::Class,
        };
        let type_parameters = type_parameters(node, self.source);
        let hierarchy = typescript_hierarchy(node, self.source, self.limits.max_signature_depth);
        let Some(type_id) = self.add_type(&name, kind, node, type_parameters, hierarchy) else {
            return;
        };
        let Some(body) = node.child_by_field_name("body") else {
            return;
        };
        for index in (0..body.named_child_count()).rev() {
            let Some(child) = body.named_child(index) else {
                continue;
            };
            match child.kind() {
                "method_definition" | "method_signature" | "abstract_method_signature" => {
                    self.collect_callable(child, &type_id, MemberKind::Method, false);
                }
                "public_field_definition" | "property_signature" | "index_signature" => {
                    self.collect_property(child, &type_id);
                }
                "class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "internal_module" => stack.push(PendingDeclaration {
                    node: child,
                    owner_name: name.clone(),
                    owner_id: type_id.clone(),
                    exported: true,
                    ambient,
                }),
                _ => {}
            }
        }
    }

    fn collect_module<'tree>(
        &mut self,
        node: Node<'tree>,
        owner_name: &str,
        stack: &mut Vec<PendingDeclaration<'tree>>,
    ) {
        let Some(raw_name) = field_text(node, "name", self.source) else {
            return;
        };
        let short_name = raw_name.trim_matches(['\'', '"']);
        let name = if (self.global_scope && owner_name == self.root_module_name)
            || short_name == self.root_module_name
            || short_name.starts_with('@')
        {
            short_name.to_owned()
        } else {
            format!("{owner_name}.{short_name}")
        };
        let Some(module_id) = self.add_type(&name, TypeKind::Module, node, Vec::new(), Vec::new())
        else {
            return;
        };
        let Some(body) = node.child_by_field_name("body") else {
            return;
        };
        let container = body.child_by_field_name("body").unwrap_or(body);
        for index in (0..container.named_child_count()).rev() {
            if let Some(child) = container.named_child(index) {
                stack.push(PendingDeclaration {
                    node: child,
                    owner_name: name.clone(),
                    owner_id: module_id.clone(),
                    exported: true,
                    ambient: true,
                });
            }
        }
    }

    fn qualified_name(&self, owner_name: &str, short_name: &str) -> String {
        if self.global_scope && owner_name == self.root_module_name {
            short_name.to_owned()
        } else {
            format!("{owner_name}.{short_name}")
        }
    }

    fn collect_callable(
        &mut self,
        node: Node<'_>,
        owner_id: &str,
        default_kind: MemberKind,
        is_static: bool,
    ) {
        let Some(name) = field_text(node, "name", self.source) else {
            return;
        };
        let member_kind = if name == "constructor" {
            MemberKind::Constructor
        } else {
            default_kind
        };
        let signature = callable_signature(node, self.source, self.limits.max_signature_depth);
        self.add_member(
            owner_id,
            MemberDraft {
                name,
                member_kind,
                visibility: visibility(node, self.source),
                is_static,
                signature,
            },
            node,
        );
    }

    fn collect_property(&mut self, node: Node<'_>, owner_id: &str) {
        let name = field_text(node, "name", self.source).unwrap_or_else(|| "[]".to_owned());
        let signature = node.child_by_field_name("type").map(|node| Signature {
            type_parameters: Vec::new(),
            parameters: Vec::new(),
            returns: Some(type_ref(node, self.source, self.limits.max_signature_depth)),
        });
        self.add_member(
            owner_id,
            MemberDraft {
                name,
                member_kind: MemberKind::Property,
                visibility: visibility(node, self.source),
                is_static: false,
                signature,
            },
            node,
        );
    }

    fn collect_variables(&mut self, node: Node<'_>, owner_id: &str, exported: bool) {
        let mut stack = vec![node];
        while let Some(candidate) = stack.pop() {
            if candidate.kind() == "variable_declarator" {
                let Some(name) = field_text(candidate, "name", self.source) else {
                    continue;
                };
                if !exported && !self.export_aliases.contains_key(&name) {
                    continue;
                }
                let signature = candidate.child_by_field_name("type").map(|node| Signature {
                    type_parameters: Vec::new(),
                    parameters: Vec::new(),
                    returns: Some(type_ref(node, self.source, self.limits.max_signature_depth)),
                });
                self.add_member(
                    owner_id,
                    MemberDraft {
                        name,
                        member_kind: MemberKind::Constant,
                        visibility: Visibility::Public,
                        is_static: true,
                        signature,
                    },
                    candidate,
                );
                continue;
            }
            for index in (0..candidate.named_child_count()).rev() {
                if let Some(child) = candidate.named_child(index) {
                    stack.push(child);
                }
            }
        }
    }

    fn add_type(
        &mut self,
        name: &str,
        type_kind: TypeKind,
        node: Node<'_>,
        type_parameters: Vec<String>,
        hierarchy: Vec<HierarchyFact>,
    ) -> Option<String> {
        if let Some(&index) = self.type_index_by_name.get(name) {
            let existing = &mut self.types[index];
            let compatible_namespace_merge = matches!(
                (existing.type_kind, type_kind),
                (TypeKind::Class | TypeKind::Enum, TypeKind::Module)
                    | (TypeKind::Module, TypeKind::Class | TypeKind::Enum)
            );
            if existing.type_kind == TypeKind::Module
                && matches!(type_kind, TypeKind::Class | TypeKind::Enum)
            {
                existing.type_kind = type_kind;
                existing.type_parameters = type_parameters;
                existing.locator = source_locator(&self.artifact_path, name, node);
            } else if existing.type_kind != type_kind && !compatible_namespace_merge {
                self.diagnostics.warning(
                    "typescript.declaration.merge",
                    Some(self.artifact_path.clone()),
                    format!("declaration merge for {name} has incompatible kinds"),
                );
            }
            for relation in hierarchy {
                if !existing.hierarchy.contains(&relation) {
                    existing.hierarchy.push(relation);
                }
            }
            return Some(existing.id.clone());
        }
        if !self.take_record() {
            return None;
        }
        let id = type_declaration_id(TypeIdentity {
            ecosystem: "npm",
            name,
        });
        self.type_index_by_name
            .insert(name.to_owned(), self.types.len());
        self.types.push(TypeFact {
            id: id.clone(),
            name: name.to_owned(),
            type_kind,
            visibility: Visibility::Public,
            is_abstract: node.kind() == "abstract_class_declaration",
            is_sealed: false,
            has_explicit_type_terms: false,
            type_parameters,
            type_parameter_constraints: Vec::new(),
            underlying_type: None,
            embedded_types: Vec::new(),
            hierarchy,
            aliases: Vec::new(),
            extension_surfaces: Vec::new(),
            guard: None,
            locator: source_locator(&self.artifact_path, name, node),
        });
        Some(id)
    }

    fn add_member(&mut self, owner_id: &str, draft: MemberDraft, node: Node<'_>) {
        if !self.take_record() {
            return;
        }
        let parameter_types = draft
            .signature
            .as_ref()
            .map(|signature| {
                signature
                    .parameters
                    .iter()
                    .map(|parameter| parameter.r#type.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let id = member_declaration_id(MemberIdentity {
            owner_id,
            kind: draft.member_kind,
            is_static: draft.is_static,
            parameter_arity: parameter_types.len(),
            name: &draft.name,
            generic_arity: draft
                .signature
                .as_ref()
                .map_or(0, |signature| signature.type_parameters.len()),
            parameter_types: &parameter_types,
            parameter_variadics: &[],
            return_type: draft
                .signature
                .as_ref()
                .and_then(|signature| signature.returns.as_ref()),
        });
        self.members.push(MemberFact {
            id,
            owner: owner_id.to_owned(),
            name: draft.name.clone(),
            member_kind: draft.member_kind,
            visibility: draft.visibility,
            is_static: draft.is_static,
            is_abstract: false,
            is_virtual: draft.member_kind == MemberKind::Method && !draft.is_static,
            callable_family_complete: false,
            signature: draft.signature,
            receiver: None,
            extension_receiver: None,
            extension_receiver_constraints: Vec::new(),
            aliases: Vec::new(),
            guard: None,
            locator: source_locator(&self.artifact_path, &draft.name, node),
        });
    }

    fn take_record(&mut self) -> bool {
        if self.remaining_records == 0 {
            self.record_limit_hit = true;
            return false;
        }
        self.remaining_records -= 1;
        true
    }

    fn node_is_explicitly_exported(&self, node: Node<'_>) -> bool {
        field_text(node, "name", self.source)
            .is_some_and(|name| self.export_aliases.contains_key(&name))
    }

    fn resolve_local_hierarchy_ids(&mut self) {
        let mut ids_by_name = HashMap::default();
        let mut ids_by_short_name: HashMap<String, Option<String>> = HashMap::default();
        for fact in &self.types {
            ids_by_name.insert(fact.name.clone(), fact.id.clone());
            let short_name = fact
                .name
                .rsplit('.')
                .next()
                .unwrap_or(&fact.name)
                .to_owned();
            ids_by_short_name
                .entry(short_name)
                .and_modify(|id| *id = None)
                .or_insert_with(|| Some(fact.id.clone()));
        }
        for fact in &mut self.types {
            for hierarchy in &mut fact.hierarchy {
                let TypeRef::Named {
                    name,
                    arguments,
                    nullable,
                } = &hierarchy.target
                else {
                    continue;
                };
                let target_id = ids_by_name
                    .get(name)
                    .cloned()
                    .or_else(|| ids_by_short_name.get(name).and_then(Clone::clone));
                if let Some(id) = target_id {
                    hierarchy.target = TypeRef::Declared {
                        id,
                        arguments: arguments.clone(),
                        nullable: *nullable,
                    };
                }
            }
        }
    }

    fn apply_export_aliases(&mut self, root_id: &str) {
        for (local_name, exported_names) in &self.export_aliases {
            let qualified_local = format!("{}.{}", self.root_module_name, local_name);
            if let Some(&index) = self.type_index_by_name.get(&qualified_local) {
                let aliases = &mut self.types[index].aliases;
                for exported_name in exported_names {
                    aliases.push(exported_name.clone());
                    aliases.push(format!("{}.{}", self.root_module_name, exported_name));
                }
            }
            for member in self.members.iter_mut().filter(|member| {
                member.owner == root_id && member.name.as_str() == local_name.as_str()
            }) {
                for exported_name in exported_names {
                    member.aliases.push(exported_name.clone());
                    member
                        .aliases
                        .push(format!("{}.{}", self.root_module_name, exported_name));
                }
            }
        }
    }
}

fn explicit_export_aliases(root: Node<'_>, source: &str) -> HashMap<String, Vec<String>> {
    let mut aliases = HashMap::default();
    for index in 0..root.named_child_count() {
        let Some(statement) = root.named_child(index) else {
            continue;
        };
        if statement.kind() != "export_statement"
            || statement.child_by_field_name("declaration").is_some()
            || statement.child_by_field_name("source").is_some()
        {
            continue;
        }
        let mut stack = vec![statement];
        while let Some(node) = stack.pop() {
            if node.kind() == "export_specifier" {
                let local = node
                    .child_by_field_name("name")
                    .or_else(|| node.named_child(0))
                    .map(|name| node_text(name, source).trim().to_owned())
                    .filter(|name| !name.is_empty());
                let exported = node
                    .child_by_field_name("alias")
                    .map(|alias| node_text(alias, source).trim().to_owned())
                    .filter(|alias| !alias.is_empty());
                if let Some(local) = local {
                    let exported = exported.unwrap_or_else(|| local.clone());
                    let exported_names = aliases.entry(local).or_insert_with(Vec::new);
                    if !exported_names.contains(&exported) {
                        exported_names.push(exported);
                    }
                }
                continue;
            }
            for child_index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(child_index) {
                    stack.push(child);
                }
            }
        }
    }
    aliases
}

/// Whether an `export_statement` is a TypeScript export assignment (`export = X`).
///
/// An export assignment republishes one declaration as the module's entire
/// export shape, so `import { member } from 'pkg'` reaches `X`'s members rather
/// than the module's. This producer records declarations under their own names
/// and cannot express that re-rooting, so the surface it emits would answer a
/// named import wrongly. Reporting it keeps the pack partial, which stops a
/// consumer from proving a name absent from a shape the pack never had.
///
/// The grammar gives an export assignment no `declaration`, `source` or `value`
/// field; its `=` token is what separates it from a re-export clause.
fn is_export_assignment(node: Node<'_>) -> bool {
    (0..node.child_count())
        .filter_map(|index| node.child(index))
        .any(|child| child.kind() == "=")
}

fn is_global_internal_module(node: Node<'_>, source: &str) -> bool {
    node.kind() == "internal_module"
        && field_text(node, "name", source).is_some_and(|name| name == "global")
}

fn is_global_ambient_declaration(node: Node<'_>) -> bool {
    node.kind() == "ambient_declaration"
        && (0..node.child_count()).any(|index| {
            node.child(index)
                .is_some_and(|child| child.kind() == "global")
        })
}

fn field_text(node: Node<'_>, field: &str, source: &str) -> Option<String> {
    node.child_by_field_name(field)
        .map(|child| node_text(child, source).trim().to_owned())
        .filter(|text| !text.is_empty())
}

fn type_parameters(node: Node<'_>, source: &str) -> Vec<String> {
    let Some(parameters) = node.child_by_field_name("type_parameters") else {
        return Vec::new();
    };
    let mut result = Vec::new();
    let mut cursor = parameters.walk();
    for parameter in parameters.named_children(&mut cursor) {
        if let Some(name) = parameter
            .child_by_field_name("name")
            .or_else(|| parameter.named_child(0))
        {
            let name = node_text(name, source).trim();
            if !name.is_empty() {
                result.push(name.to_owned());
            }
        }
    }
    result
}

fn callable_signature(node: Node<'_>, source: &str, max_depth: usize) -> Option<Signature> {
    let parameters = node.child_by_field_name("parameters")?;
    let mut parsed_parameters = Vec::new();
    let mut cursor = parameters.walk();
    for parameter in parameters.named_children(&mut cursor) {
        let name_node = parameter
            .child_by_field_name("pattern")
            .or_else(|| parameter.child_by_field_name("name"));
        let parameter_name = name_node
            .map(|name| node_text(name, source).trim().to_owned())
            .filter(|name| !name.is_empty());
        let parameter_type = parameter
            .child_by_field_name("type")
            .map(|node| type_ref(node, source, max_depth))
            .unwrap_or_else(|| named_type("unknown".to_owned()));
        let variadic = name_node.is_some_and(|name| name.kind() == "rest_pattern")
            || parameter.kind() == "rest_pattern";
        parsed_parameters.push(Parameter {
            name: parameter_name,
            r#type: parameter_type,
            optional: parameter.kind() == "optional_parameter",
            variadic,
        });
    }
    Some(Signature {
        type_parameters: type_parameters(node, source),
        parameters: parsed_parameters,
        returns: node
            .child_by_field_name("return_type")
            .map(|node| type_ref(node, source, max_depth)),
    })
}

fn typescript_hierarchy(node: Node<'_>, source: &str, max_depth: usize) -> Vec<HierarchyFact> {
    let mut hierarchy = Vec::new();
    let mut stack = vec![node];
    while let Some(candidate) = stack.pop() {
        if matches!(candidate.kind(), "class_body" | "object_type") {
            continue;
        }
        let hierarchy_kind = match candidate.kind() {
            "extends_type_clause" => Some(HierarchyKind::Extends),
            "implements_clause" => Some(HierarchyKind::Implements),
            _ => None,
        };
        if let Some(hierarchy_kind) = hierarchy_kind {
            let mut cursor = candidate.walk();
            for target in candidate.named_children(&mut cursor) {
                hierarchy.push(HierarchyFact {
                    hierarchy_kind,
                    target: type_ref(target, source, max_depth),
                    declaration_ordinal: None,
                });
            }
            continue;
        }
        for index in (0..candidate.named_child_count()).rev() {
            if let Some(child) = candidate.named_child(index) {
                stack.push(child);
            }
        }
    }
    hierarchy
}

fn type_ref(node: Node<'_>, source: &str, remaining_depth: usize) -> TypeRef {
    if remaining_depth == 0 {
        return named_type("unknown".to_owned());
    }
    match node.kind() {
        "type_annotation" | "parenthesized_type" => node
            .named_child(0)
            .map(|child| type_ref(child, source, remaining_depth - 1))
            .unwrap_or_else(|| named_type("unknown".to_owned())),
        "array_type" => node
            .named_child(0)
            .map(|element| TypeRef::Array {
                element: Box::new(type_ref(element, source, remaining_depth - 1)),
            })
            .unwrap_or_else(|| TypeRef::Array {
                element: Box::new(named_type("unknown".to_owned())),
            }),
        "tuple_type" => {
            let mut cursor = node.walk();
            TypeRef::Tuple {
                elements: node
                    .named_children(&mut cursor)
                    .map(|element| type_ref(element, source, remaining_depth - 1))
                    .collect(),
            }
        }
        "function_type" | "constructor_type" => {
            let parameters = callable_signature(node, source, remaining_depth - 1)
                .map(|signature| signature.parameters)
                .unwrap_or_default();
            let result = node
                .child_by_field_name("return_type")
                .map(|result| type_ref(result, source, remaining_depth - 1))
                .unwrap_or_else(|| named_type("unknown".to_owned()));
            TypeRef::Function {
                parameters,
                result: Some(Box::new(result)),
            }
        }
        "generic_type" => {
            let name_node = node
                .child_by_field_name("name")
                .or_else(|| node.named_child(0));
            let name = name_node
                .filter(|name| {
                    matches!(
                        name.kind(),
                        "type_identifier" | "identifier" | "nested_type_identifier"
                    )
                })
                .map(|name| node_text(name, source).trim().to_owned())
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| "unknown".to_owned());
            let arguments = node
                .child_by_field_name("type_arguments")
                .map(|arguments| {
                    let mut cursor = arguments.walk();
                    arguments
                        .named_children(&mut cursor)
                        .map(|argument| type_ref(argument, source, remaining_depth - 1))
                        .collect()
                })
                .unwrap_or_default();
            TypeRef::Named {
                name,
                arguments,
                nullable: false,
            }
        }
        "type_identifier" | "identifier" | "nested_type_identifier" | "predefined_type" => {
            named_type(node_text(node, source).trim().to_owned())
        }
        "literal_type"
        | "object_type"
        | "union_type"
        | "intersection_type"
        | "indexed_access_type"
        | "lookup_type"
        | "type_query" => named_type("unknown".to_owned()),
        _ => named_type("unknown".to_owned()),
    }
}

fn named_type(name: String) -> TypeRef {
    let name = if name.is_empty() || name.chars().any(char::is_whitespace) {
        "unknown".to_owned()
    } else {
        name
    };
    TypeRef::Named {
        name,
        arguments: Vec::new(),
        nullable: false,
    }
}

fn visibility(node: Node<'_>, source: &str) -> Visibility {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "accessibility_modifier" {
            return match node_text(child, source).trim() {
                "private" => Visibility::Private,
                "protected" => Visibility::Protected,
                _ => Visibility::Public,
            };
        }
    }
    Visibility::Public
}

fn source_locator(path: &str, name: &str, node: Node<'_>) -> Locator {
    Locator::Source {
        path: path.to_owned(),
        symbol: Some(format!("{name}@{}:{}", node.start_byte(), node.end_byte())),
    }
}

fn finish_typescript_production(
    request: &ArtifactProductionRequest,
    artifact_sha256: &str,
    types: Vec<TypeFact>,
    members: Vec<MemberFact>,
    mut diagnostics: BoundedProducerDiagnostics,
) -> ArtifactProduction {
    if types.len() == 1 && members.is_empty() {
        diagnostics.error(
            "typescript.declaration.no_external_declarations",
            Some(request.path.display().to_string()),
            "declaration file contains no exported or ambient declarations",
        );
    }
    let mut activation = request.activation.clone();
    for selector in &mut activation {
        selector.artifact_sha256 = Some(artifact_sha256.to_owned());
    }
    let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
    let completeness = if diagnostics.is_empty() && suppressed_diagnostics == 0 {
        Completeness::Complete
    } else {
        Completeness::Partial
    };
    let has_declarations = types.len() > 1 || !members.is_empty();
    // Every Source locator in these shards names a declaration module this
    // producer read and parsed, so the pack carries them all.
    let shards = vec![AuthoredShard {
        id: "declarations.typescript.external".to_owned(),
        activation,
        payload: AuthoredPayload::DeclarationFacts {
            types,
            members,
            relations: Vec::new(),
        },
    }];
    ArtifactProduction {
        artifact_sha256: Some(artifact_sha256.to_owned()),
        pack: has_declarations.then(|| AuthoredSemanticModelPack {
            schema_version: crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
            pack_id: request.pack_id.clone(),
            version: request.pack_version.clone(),
            producer: Producer {
                name: "bifrost-typescript-declaration".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            },
            language: "typescript".to_owned(),
            ecosystem: request.ecosystem.clone(),
            compatibility: request.compatibility.clone(),
            provenance: request.provenance.clone(),
            license: request.license.clone(),
            completeness,
            safety: request.safety.clone(),
            carried_sources: carried_source_paths(&shards),
            shards,
        }),
        completeness,
        diagnostics,
        suppressed_diagnostics,
    }
}

fn js_ts_dependency_production_request(
    dependency: &ResolvedDependency,
) -> ArtifactProductionRequest {
    ArtifactProductionRequest {
        path: PathBuf::new(),
        artifact_kind: ExternalArtifactKind::TypeScriptDeclarationFile,
        pack_id: "bifrost.external.typescript".to_owned(),
        pack_version: env!("CARGO_PKG_VERSION").to_owned(),
        ecosystem: dependency.evidence.ecosystem.clone(),
        compatibility: Compatibility {
            bifrost: format!("={}", env!("CARGO_PKG_VERSION")),
            toolchains: Vec::new(),
        },
        activation: vec![ActivationSelector {
            package: dependency
                .evidence
                .package
                .as_ref()
                .map(|coordinate| NameSelector {
                    name: coordinate.name.clone(),
                    version: coordinate
                        .version
                        .as_ref()
                        .map(|version| format!("={version}")),
                }),
            module: dependency
                .evidence
                .module
                .as_ref()
                .map(|coordinate| NameSelector {
                    name: coordinate.name.clone(),
                    version: coordinate
                        .version
                        .as_ref()
                        .map(|version| format!("={version}")),
                }),
            toolchain: None,
            targets: Vec::new(),
            configurations: Vec::new(),
            artifact_sha256: None,
        }],
        provenance: Provenance {
            source: "exact local npm declaration dependency".to_owned(),
            revision: dependency
                .evidence
                .package
                .as_ref()
                .and_then(|coordinate| coordinate.version.as_ref())
                .map(ToString::to_string),
        },
        license: "NOASSERTION".to_owned(),
        safety: Safety {
            generated_code_only: false,
            review_required: false,
        },
    }
}

fn typescript_library_production_request(
    dependency: &ResolvedDependency,
) -> ArtifactProductionRequest {
    ArtifactProductionRequest {
        path: PathBuf::new(),
        artifact_kind: ExternalArtifactKind::TypeScriptLibrarySet,
        pack_id: "bifrost.typescript-stdlib".to_owned(),
        pack_version: TYPESCRIPT_STDLIB_VERSION.to_owned(),
        ecosystem: "npm".to_owned(),
        compatibility: Compatibility {
            bifrost: format!("={}", env!("CARGO_PKG_VERSION")),
            toolchains: Vec::new(),
        },
        activation: vec![ActivationSelector {
            package: Some(NameSelector {
                name: TYPESCRIPT_STDLIB_PACKAGE.to_owned(),
                version: Some(format!("={TYPESCRIPT_STDLIB_VERSION}")),
            }),
            module: None,
            toolchain: None,
            targets: Vec::new(),
            configurations: dependency
                .evidence
                .configuration
                .clone()
                .into_iter()
                .collect(),
            artifact_sha256: None,
        }],
        provenance: Provenance {
            source: "official TypeScript npm package".to_owned(),
            revision: Some(TYPESCRIPT_STDLIB_VERSION.to_owned()),
        },
        license: "Apache-2.0".to_owned(),
        safety: Safety {
            generated_code_only: false,
            review_required: true,
        },
    }
}

fn failed_production(
    code: &str,
    message: &str,
    limits: &ArtifactProducerLimits,
) -> ArtifactProduction {
    ArtifactProduction::failed(
        ProducerDiagnostic {
            severity: ProducerDiagnosticSeverity::Error,
            code: code.to_owned(),
            location: None,
            declaration: None,
            message: message.to_owned(),
        },
        limits,
    )
}

fn failed_loaded_production(
    code: &str,
    message: &str,
    artifact_sha256: &str,
    limits: &ArtifactProducerLimits,
) -> ArtifactProduction {
    let mut production = failed_production(code, message, limits);
    production.artifact_sha256 = Some(artifact_sha256.to_owned());
    production
}

fn dependency_failure(code: &str, message: &str) -> DependencyPackProduction {
    DependencyPackProduction {
        pack: None,
        diagnostics: vec![ProducerDiagnostic {
            severity: ProducerDiagnosticSeverity::Error,
            code: code.to_owned(),
            location: None,
            declaration: None,
            message: message.to_owned(),
        }],
        suppressed_diagnostics: 0,
    }
}

fn resolve_locked_package(
    lockfile: &Path,
    lock_path: &str,
    lock_entry: &Value,
    approved_roots: &[PathBuf],
    max_manifest_bytes: u64,
) -> Result<Vec<ResolvedDependency>, NpmDiagnostic> {
    let dependency_hint = lock_entry
        .get("name")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let failure = |code, message: String| NpmDiagnostic {
        code,
        dependency_id: dependency_hint.clone(),
        location: Some(lock_path.to_owned()),
        message,
    };
    let Some(relative_package_path) = safe_lock_package_path(lock_path) else {
        return Err(failure(
            "npm.package.path",
            "lockfile package path is not a safe installed node_modules path".to_owned(),
        ));
    };
    let package_path = lockfile
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(relative_package_path);
    let canonical_package = package_path.canonicalize().map_err(|error| {
        failure(
            "npm.package.missing",
            format!("installed package directory is unavailable: {error}"),
        )
    })?;
    if !approved_roots
        .iter()
        .any(|approved| canonical_package.starts_with(approved))
    {
        return Err(failure(
            "npm.package.outside_root",
            "installed package is outside the approved node_modules roots".to_owned(),
        ));
    }

    let manifest_path = canonical_package.join("package.json");
    let manifest = read_json_bounded(&manifest_path, max_manifest_bytes)
        .map_err(|message| failure("npm.package.manifest", message))?;
    let name = manifest
        .get("name")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| failure("npm.package.identity", "package name is missing".to_owned()))?;
    let version_text = manifest
        .get("version")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            failure(
                "npm.package.identity",
                "package version is missing".to_owned(),
            )
        })?;
    let version = Version::parse(version_text).map_err(|_| {
        failure(
            "npm.package.version",
            format!("package version is not exact semantic version evidence: {version_text}"),
        )
    })?;
    let locked_version = lock_entry
        .get("version")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            failure(
                "npm.lockfile.version",
                "lockfile package entry has no exact version".to_owned(),
            )
        })?;
    if locked_version != version_text {
        return Err(failure(
            "npm.package.version_mismatch",
            format!(
                "installed package version {version_text} does not match locked version {locked_version}"
            ),
        ));
    }
    if let Some(locked_name) = lock_entry.get("name").and_then(Value::as_str)
        && locked_name != name
    {
        return Err(failure(
            "npm.package.name_mismatch",
            format!("installed package name {name} does not match locked name {locked_name}"),
        ));
    }

    if name == TYPESCRIPT_STDLIB_PACKAGE && version_text == TYPESCRIPT_STDLIB_VERSION {
        let config_path = lockfile
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("tsconfig.json");
        let activation = typescript_library_activation_evidence(
            &config_path,
            lockfile.parent().unwrap_or_else(|| Path::new(".")),
        );
        if !activation.selection.is_complete() || activation.evidence.is_empty() {
            return Err(failure(
                "typescript.library.activation",
                activation.diagnostics.join("; "),
            ));
        }
        let provenance = vec![
            DependencyProvenance {
                key: "lockfile_format".to_owned(),
                value: "npm-packages-v2".to_owned(),
            },
            DependencyProvenance {
                key: "lockfile_entry".to_owned(),
                value: lock_path.to_owned(),
            },
            DependencyProvenance {
                key: "package".to_owned(),
                value: name.to_owned(),
            },
            DependencyProvenance {
                key: "version".to_owned(),
                value: version_text.to_owned(),
            },
        ];
        let selected_libraries = activation.selection.libraries().to_vec();
        return Ok(selected_libraries
            .into_iter()
            .map(|library| {
                let evidence = SemanticModelActivationEvidence {
                    language: "typescript".to_owned(),
                    ecosystem: "npm".to_owned(),
                    package: Some(CatalogCoordinate {
                        name: TYPESCRIPT_STDLIB_PACKAGE.to_owned(),
                        version: Some(version.clone()),
                    }),
                    module: None,
                    toolchain: None,
                    target: None,
                    configuration: Some(format!("typescript-lib:{library}")),
                    artifact_sha256: None,
                };
                ResolvedDependency {
                    id: format!(
                        "npm:{name}@{version_text}:{}",
                        evidence.configuration.as_deref().unwrap_or("stdlib")
                    ),
                    evidence,
                    provenance: provenance.clone(),
                    artifacts: Vec::new(),
                    scope: DependencyScope::Unknown,
                    declared_by: None,
                }
            })
            .collect());
    }

    let entries = declaration_entries(name, &manifest, &canonical_package)
        .map_err(|message| failure("npm.declarations.incomplete", message))?;
    let integrity = lock_entry.get("integrity").and_then(Value::as_str);
    Ok(entries
        .into_iter()
        .map(|entry| {
            let mut provenance = vec![
                DependencyProvenance {
                    key: "lockfile_format".to_owned(),
                    value: "npm-packages-v2".to_owned(),
                },
                DependencyProvenance {
                    key: "lockfile_entry".to_owned(),
                    value: lock_path.to_owned(),
                },
                DependencyProvenance {
                    key: "package".to_owned(),
                    value: name.to_owned(),
                },
                DependencyProvenance {
                    key: "version".to_owned(),
                    value: version_text.to_owned(),
                },
                DependencyProvenance {
                    key: "declaration_route".to_owned(),
                    value: entry.route.clone(),
                },
                DependencyProvenance {
                    key: "declaration_path".to_owned(),
                    value: slash_path(&entry.relative_path),
                },
            ];
            if let Some(integrity) = integrity {
                provenance.push(DependencyProvenance {
                    key: "integrity".to_owned(),
                    value: integrity.to_owned(),
                });
            }
            ResolvedDependency {
                id: format!("npm:{name}@{version_text}:{}", entry.module),
                evidence: SemanticModelActivationEvidence {
                    language: "typescript".to_owned(),
                    ecosystem: "npm".to_owned(),
                    package: Some(CatalogCoordinate {
                        name: name.to_owned(),
                        version: Some(version.clone()),
                    }),
                    module: Some(CatalogCoordinate {
                        name: entry.module,
                        version: None,
                    }),
                    toolchain: None,
                    target: None,
                    configuration: None,
                    artifact_sha256: None,
                },
                provenance,
                artifacts: vec![
                    ResolvedDependencyArtifact::file(
                        DependencyArtifactRole::Metadata,
                        ExternalArtifactKind::NpmPackageManifest,
                        manifest_path.clone(),
                    ),
                    ResolvedDependencyArtifact::file(
                        DependencyArtifactRole::Declarations,
                        ExternalArtifactKind::TypeScriptDeclarationFile,
                        canonical_package.join(entry.relative_path),
                    ),
                ],
                scope: DependencyScope::Unknown,
                declared_by: None,
            }
        })
        .collect())
}

fn declaration_entries(
    package_name: &str,
    manifest: &Value,
    package_root: &Path,
) -> Result<Vec<DeclarationEntry>, String> {
    let imported_name = declaration_import_name(package_name);
    let mut entries = Vec::new();
    let root_declaration = ["types", "typings"].into_iter().find_map(|field| {
        manifest
            .get(field)
            .and_then(Value::as_str)
            .map(|path| (field, path))
    });
    if let Some((field, path)) = root_declaration {
        entries.push(DeclarationEntry {
            module: imported_name.clone(),
            relative_path: declaration_path(path)?,
            route: field.to_owned(),
        });
    }
    if let Some(exports) = manifest.get("exports") {
        collect_export_entries(
            &imported_name,
            exports,
            root_declaration.is_some(),
            &mut entries,
        )?;
    }
    if entries.is_empty() {
        let conventional = PathBuf::from("index.d.ts");
        if package_root.join(&conventional).is_file() {
            entries.push(DeclarationEntry {
                module: imported_name,
                relative_path: conventional,
                route: "index.d.ts".to_owned(),
            });
        }
    }
    entries.sort();
    entries.dedup_by(|left, right| left.module == right.module);
    if entries.is_empty() {
        return Err("package has no proven declaration entry point".to_owned());
    }
    for entry in &entries {
        let path = package_root.join(&entry.relative_path);
        let canonical = path.canonicalize().map_err(|error| {
            format!(
                "declaration entry {} is unavailable: {error}",
                entry.relative_path.display()
            )
        })?;
        if !canonical.starts_with(package_root) || !canonical.is_file() {
            return Err(format!(
                "declaration entry {} escapes the installed package",
                entry.relative_path.display()
            ));
        }
    }
    Ok(entries)
}

fn collect_export_entries(
    package_name: &str,
    exports: &Value,
    root_already_selected: bool,
    entries: &mut Vec<DeclarationEntry>,
) -> Result<(), String> {
    match exports {
        Value::String(path) if !root_already_selected && is_declaration_path(path) => {
            entries.push(DeclarationEntry {
                module: package_name.to_owned(),
                relative_path: declaration_path(path)?,
                route: "exports:.".to_owned(),
            });
        }
        Value::Object(object) if object.keys().any(|key| key.starts_with('.')) => {
            for (subpath, value) in object {
                if subpath.contains('*') {
                    return Err(format!("wildcard export {subpath} is not exact"));
                }
                if subpath != "." && !subpath.starts_with("./") {
                    return Err(format!("export key {subpath} is not a package subpath"));
                }
                if subpath == "." && root_already_selected {
                    continue;
                }
                if let Some(path) = explicit_types_export(value)? {
                    let module = if subpath == "." {
                        package_name.to_owned()
                    } else {
                        format!("{package_name}/{}", &subpath[2..])
                    };
                    entries.push(DeclarationEntry {
                        module,
                        relative_path: declaration_path(path)?,
                        route: format!("exports:{subpath}"),
                    });
                }
            }
        }
        Value::Object(_) if !root_already_selected => {
            if let Some(path) = explicit_types_export(exports)? {
                entries.push(DeclarationEntry {
                    module: package_name.to_owned(),
                    relative_path: declaration_path(path)?,
                    route: "exports:.".to_owned(),
                });
            }
        }
        Value::Null | Value::String(_) | Value::Object(_) => {}
        _ => return Err("exports declaration routing is not statically supported".to_owned()),
    }
    Ok(())
}

fn explicit_types_export(value: &Value) -> Result<Option<&str>, String> {
    match value {
        Value::String(path) => Ok(is_declaration_path(path).then_some(path.as_str())),
        Value::Object(object) => match object.get("types") {
            Some(Value::String(path)) if is_declaration_path(path) => Ok(Some(path)),
            Some(Value::String(_)) => {
                Err("exports types target is not a declaration file".to_owned())
            }
            Some(_) => Err("exports types condition is ambiguous".to_owned()),
            None => Ok(None),
        },
        Value::Null => Ok(None),
        _ => Err("exports target is not statically supported".to_owned()),
    }
}

fn declaration_path(value: &str) -> Result<PathBuf, String> {
    if !is_declaration_path(value) {
        return Err(format!("declaration target is not a .d.ts file: {value}"));
    }
    let path = Path::new(value.strip_prefix("./").unwrap_or(value));
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "declaration target is not package-relative: {value}"
        ));
    }
    Ok(path.to_path_buf())
}

fn is_declaration_path(value: &str) -> bool {
    value.ends_with(".d.ts") || value.ends_with(".d.mts") || value.ends_with(".d.cts")
}

fn declaration_import_name(package_name: &str) -> String {
    let Some(suffix) = package_name.strip_prefix("@types/") else {
        return package_name.to_owned();
    };
    match suffix.split_once("__") {
        Some((scope, package)) => format!("@{scope}/{package}"),
        None => suffix.to_owned(),
    }
}

fn lockfile_candidates(config: &JsTsDependencyDiscoveryConfig, root: &Path) -> Vec<PathBuf> {
    let mut paths: BTreeSet<_> = config
        .lockfile_paths
        .iter()
        .map(|path| resolve(root, path))
        .collect();
    if config.discover_workspace_lockfiles {
        paths.extend([
            root.join("package-lock.json"),
            root.join("npm-shrinkwrap.json"),
        ]);
    }
    paths.into_iter().collect()
}

fn approved_package_roots(config: &JsTsDependencyDiscoveryConfig, root: &Path) -> Vec<PathBuf> {
    let candidates: Vec<_> = if config.node_modules_roots.is_empty() {
        vec![root.join("node_modules")]
    } else {
        config
            .node_modules_roots
            .iter()
            .map(|path| resolve(root, path))
            .collect()
    };
    candidates
        .into_iter()
        .filter_map(|path| path.canonicalize().ok())
        .collect()
}

fn safe_lock_package_path(value: &str) -> Option<PathBuf> {
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || !path
            .components()
            .any(|component| component.as_os_str() == "node_modules")
    {
        return None;
    }
    Some(path.to_path_buf())
}

fn lock_path_contains_node_modules(value: &str) -> bool {
    Path::new(value)
        .components()
        .any(|component| component.as_os_str() == "node_modules")
}

fn read_json_bounded(path: &Path, max_bytes: u64) -> Result<Value, String> {
    let metadata = path
        .metadata()
        .map_err(|error| format!("could not inspect JSON metadata: {error}"))?;
    if metadata.len() > max_bytes {
        return Err(format!(
            "JSON metadata exceeds configured limit {max_bytes}"
        ));
    }
    let file =
        File::open(path).map_err(|error| format!("could not open JSON metadata: {error}"))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read JSON metadata: {error}"))?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!(
            "JSON metadata exceeds configured limit {max_bytes}"
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("could not parse JSON metadata: {error}"))
}

fn resolve(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

fn slash_path(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn bounded_message(mut message: String, max_bytes: usize) -> String {
    if message.len() <= max_bytes {
        return message;
    }
    let mut end = max_bytes;
    while end > 0 && !message.is_char_boundary(end) {
        end -= 1;
    }
    message.truncate(end);
    message
}

fn cancelled(cancellation: Option<&CancellationToken>) -> bool {
    cancellation.is_some_and(CancellationToken::is_cancelled)
}

/// tree-sitter-typescript 0.23 reports the `in keyof readonly T[]` form used
/// by TypeScript's standard library mapped properties as an ERROR child of a
/// computed property name, although the surrounding declaration tree is
/// complete and structurally traversable. Keep malformed trees error-grade;
/// recover only this known grammar gap.
fn has_unrecoverable_typescript_errors(root: Node<'_>) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if (node.is_error() || node.is_missing())
            && !is_known_typescript_computed_property_error(node)
        {
            return true;
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    false
}

fn is_known_typescript_computed_property_error(node: Node<'_>) -> bool {
    if !node.is_error()
        || node.named_child_count() != 1
        || !node
            .parent()
            .is_some_and(|parent| parent.kind() == "computed_property_name")
    {
        return false;
    }
    let Some(readonly_type) = node.named_child(0) else {
        return false;
    };
    readonly_type.kind() == "readonly_type"
        && readonly_type.named_child_count() == 1
        && readonly_type
            .named_child(0)
            .is_some_and(|child| child.kind() == "array_type")
}

fn cancelled_outcome() -> DependencyDiscoveryOutcome {
    DependencyDiscoveryOutcome {
        dependencies: Vec::new(),
        diagnostics: vec![DependencyPackDiagnostic {
            severity: DependencyPackDiagnosticSeverity::Error,
            code: "discovery.cancelled".to_owned(),
            dependency_id: None,
            location: None,
            message: "npm dependency discovery was cancelled".to_owned(),
        }],
        complete: false,
        suppressed_diagnostics: 0,
        cancelled: true,
        profile: DependencyDiscoveryProfile::default(),
    }
}

#[cfg(test)]
mod producer_tests {
    use super::*;
    use crate::analyzer::semantic_model::compile_pack;
    use crate::analyzer::semantic_model::read_exact_source_set;

    const DECLARATIONS: &str = r#"
export interface Widget<T> extends Base<T> {
  value: T;
  transform(input: T): Promise<T>;
}

export declare class Builder {
  constructor(name: string);
  build(): Widget<string>;
}
export declare namespace Builder {
  function from(value: string): Builder;
}

export declare function create<T>(value: T): Widget<T>;
export declare function create(value: string): Widget<string>;
export type Choice = string | number;
export declare const version: string;
export declare namespace Tools {
  function parse(value: string): Widget<string>;
  interface Widget { nested: true }
}

interface LocalOnly { local: true }
export { LocalOnly as PublicLocal };

export interface Merged { left: string }
export interface Merged { right: number }

declare global {
  interface Window {
    widget: Widget<string>;
  }
}

interface Hidden {}
declare class AmbientHidden {}
declare namespace HiddenSpace { interface Widget { hidden: true } }
"#;

    #[test]
    fn declaration_producer_is_deterministic_and_structural() {
        let first_root = tempfile::tempdir().expect("first temp root");
        let second_root = tempfile::tempdir().expect("second temp root");
        let first = first_root.path().join("index.d.ts");
        let second = second_root.path().join("renamed.d.ts");
        std::fs::write(&first, DECLARATIONS).expect("write first declaration");
        std::fs::write(&second, DECLARATIONS).expect("write second declaration");

        let first_production = TypeScriptDeclarationPackProducer
            .produce_exact_artifact(&request(first), &ArtifactProducerLimits::default());
        let second_production = TypeScriptDeclarationPackProducer
            .produce_exact_artifact(&request(second), &ArtifactProducerLimits::default());

        assert_eq!(first_production.completeness, Completeness::Complete);
        assert!(first_production.diagnostics.is_empty());
        assert_eq!(first_production.pack, second_production.pack);
        let pack = first_production.pack.expect("declaration pack");
        let AuthoredPayload::DeclarationFacts { types, members, .. } = &pack.shards[0].payload
        else {
            panic!("declaration payload expected");
        };
        let type_names = types
            .iter()
            .map(|fact| fact.name.as_str())
            .collect::<Vec<_>>();
        assert!(type_names.contains(&"widget.Widget"));
        assert!(type_names.contains(&"widget.Builder"));
        assert!(type_names.contains(&"widget.Choice"));
        assert!(type_names.contains(&"widget.Window"), "{type_names:?}");
        assert!(type_names.contains(&"widget.Tools.Widget"));
        assert!(type_names.contains(&"widget.Merged"));
        assert!(!type_names.iter().any(|name| name.ends_with("Hidden")));
        assert!(!type_names.iter().any(|name| name.contains("HiddenSpace")));
        let local = types
            .iter()
            .find(|fact| fact.name == "widget.LocalOnly")
            .expect("locally declared re-export");
        assert!(local.aliases.contains(&"PublicLocal".to_owned()));
        assert!(local.aliases.contains(&"widget.PublicLocal".to_owned()));
        assert_eq!(
            members
                .iter()
                .filter(|member| member.name == "create")
                .count(),
            2
        );
        assert!(members.iter().any(|member| {
            member.name == "create"
                && member.signature.as_ref().is_some_and(|signature| {
                    signature.type_parameters == ["T"]
                        && signature.parameters[0].r#type == named_type("T".to_owned())
                })
        }));
        assert!(members.iter().any(|member| {
            member.name == "transform" && member.member_kind == MemberKind::Method
        }));
        assert!(members.iter().any(|member| {
            member.name == "constructor" && member.member_kind == MemberKind::Constructor
        }));
        let builder = types
            .iter()
            .find(|fact| fact.name == "widget.Builder")
            .expect("merged class and namespace");
        assert!(members.iter().any(|member| {
            member.owner == builder.id
                && member.name == "from"
                && member.member_kind == MemberKind::Function
        }));
        let merged = types
            .iter()
            .find(|fact| fact.name == "widget.Merged")
            .expect("merged interface");
        let merged_member_names = members
            .iter()
            .filter(|member| member.owner == merged.id)
            .map(|member| member.name.as_str())
            .collect::<Vec<_>>();
        assert!(merged_member_names.contains(&"left"));
        assert!(merged_member_names.contains(&"right"));
    }

    #[test]
    fn declaration_producer_rejects_unexported_surface() {
        let root = tempfile::tempdir().expect("temp root");
        let path = root.path().join("index.d.ts");
        std::fs::write(&path, "export {};\ninterface Hidden { value: string }\n")
            .expect("write declaration");

        let production = TypeScriptDeclarationPackProducer
            .produce_exact_artifact(&request(path), &ArtifactProducerLimits::default());

        assert_eq!(production.completeness, Completeness::Partial);
        assert!(production.pack.is_none());
        assert_eq!(
            production.diagnostics[0].code,
            "typescript.declaration.no_external_declarations"
        );
    }

    #[test]
    fn typescript_error_recovery_is_limited_to_computed_property_names() {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TSX.into())
            .expect("tree-sitter TypeScript language must load");
        let library_declaration = "interface Symbol { readonly [Symbol.unscopables]: { [K in keyof readonly any[]]?: boolean; }; }";
        let library_tree = parser
            .parse(library_declaration, None)
            .expect("parse standard-library declaration");
        assert!(library_tree.root_node().has_error());
        assert!(!has_unrecoverable_typescript_errors(
            library_tree.root_node()
        ));

        let malformed_tree = parser
            .parse("interface {", None)
            .expect("parse malformed declaration");
        assert!(malformed_tree.root_node().has_error());
        assert!(has_unrecoverable_typescript_errors(
            malformed_tree.root_node()
        ));
    }

    #[test]
    fn library_source_set_emits_global_shards_and_requires_reference_closure() {
        let root = tempfile::tempdir().expect("library source root");
        std::fs::create_dir_all(root.path().join("lib")).unwrap();
        std::fs::write(
            root.path().join("package.json"),
            r#"{"name":"typescript","version":"7.0.2","license":"Apache-2.0"}"#,
        )
        .unwrap();
        std::fs::write(
            root.path().join("lib/lib.es5.d.ts"),
            "/// <reference lib=\"dom\" />\ninterface Array<T> { length: number }\n",
        )
        .unwrap();
        std::fs::write(
            root.path().join("lib/lib.dom.d.ts"),
            "interface Array<T> { length: number }\ninterface Document { title: string }\n",
        )
        .unwrap();
        let artifact = read_exact_source_set(
            root.path(),
            &[
                PathBuf::from("package.json"),
                PathBuf::from("lib/lib.dom.d.ts"),
                PathBuf::from("lib/lib.es5.d.ts"),
            ],
            32,
            16,
            &ArtifactProducerLimits::default(),
        )
        .unwrap();
        let mut request = request(PathBuf::new());
        request.artifact_kind = ExternalArtifactKind::TypeScriptLibrarySet;
        request.activation.clear();
        let production = TypeScriptDeclarationPackProducer.produce_loaded_library_set(
            &request,
            &ArtifactProducerLimits::default(),
            None,
            &artifact,
            "package.json",
            &[
                ("es5".to_owned(), "lib/lib.es5.d.ts".to_owned()),
                ("dom".to_owned(), "lib/lib.dom.d.ts".to_owned()),
            ],
        );
        assert_eq!(
            production.completeness,
            Completeness::Complete,
            "{:#?}",
            production.diagnostics
        );
        let pack = production.pack.expect("built-in library pack");
        compile_pack(&pack, &Default::default()).expect("multi-library augmentation pack");
        assert_eq!(
            pack.carried_sources,
            ["lib/lib.dom.d.ts", "lib/lib.es5.d.ts"]
        );
        assert_eq!(pack.shards.len(), 2);
        let es5 = pack
            .shards
            .iter()
            .find(|shard| shard.id.ends_with(".es5"))
            .expect("es5 shard");
        let AuthoredPayload::DeclarationFacts { types, .. } = &es5.payload else {
            panic!("declaration facts expected");
        };
        assert!(!types.iter().any(|fact| fact.name == "global.Array"));
        assert!(pack.shards.iter().any(|shard| {
            matches!(&shard.payload, AuthoredPayload::DeclarationFacts { types, .. }
                if types.iter().any(|fact| fact.name == "Array"))
        }));
        assert_eq!(es5.activation[0].configurations, ["typescript-lib:es5"]);
        assert_eq!(
            es5.activation[0]
                .package
                .as_ref()
                .unwrap()
                .version
                .as_deref(),
            Some("=7.0.2")
        );
    }

    #[test]
    fn library_source_set_rejects_missing_triple_slash_reference() {
        let root = tempfile::tempdir().expect("library source root");
        std::fs::create_dir_all(root.path().join("lib")).unwrap();
        std::fs::write(
            root.path().join("package.json"),
            r#"{"name":"typescript","version":"7.0.2","license":"Apache-2.0"}"#,
        )
        .unwrap();
        std::fs::write(
            root.path().join("lib/lib.es5.d.ts"),
            "/// <reference lib=\"dom\" />\ninterface Array<T> { length: number }\n",
        )
        .unwrap();
        let artifact = read_exact_source_set(
            root.path(),
            &[
                PathBuf::from("package.json"),
                PathBuf::from("lib/lib.es5.d.ts"),
            ],
            32,
            16,
            &ArtifactProducerLimits::default(),
        )
        .unwrap();
        let mut request = request(PathBuf::new());
        request.artifact_kind = ExternalArtifactKind::TypeScriptLibrarySet;
        let production = TypeScriptDeclarationPackProducer.produce_loaded_library_set(
            &request,
            &ArtifactProducerLimits::default(),
            None,
            &artifact,
            "package.json",
            &[("es5".to_owned(), "lib/lib.es5.d.ts".to_owned())],
        );
        assert_eq!(production.completeness, Completeness::Partial);
        assert!(
            production
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "typescript.library.reference_missing")
        );
    }

    #[test]
    fn library_source_set_diagnoses_unknown_triple_slash_reference() {
        let root = tempfile::tempdir().expect("library source root");
        std::fs::create_dir_all(root.path().join("lib")).unwrap();
        std::fs::write(
            root.path().join("package.json"),
            r#"{"name":"typescript","version":"7.0.2","license":"Apache-2.0"}"#,
        )
        .unwrap();
        std::fs::write(
            root.path().join("lib/lib.es5.d.ts"),
            "/// <reference lib = \"not-a-real-lib\" />\ninterface Array<T> {}\n",
        )
        .unwrap();
        let artifact = read_exact_source_set(
            root.path(),
            &[
                PathBuf::from("package.json"),
                PathBuf::from("lib/lib.es5.d.ts"),
            ],
            32,
            16,
            &ArtifactProducerLimits::default(),
        )
        .unwrap();
        let mut request = request(PathBuf::new());
        request.artifact_kind = ExternalArtifactKind::TypeScriptLibrarySet;
        let production = TypeScriptDeclarationPackProducer.produce_loaded_library_set(
            &request,
            &ArtifactProducerLimits::default(),
            None,
            &artifact,
            "package.json",
            &[("es5".to_owned(), "lib/lib.es5.d.ts".to_owned())],
        );
        assert!(
            production
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "typescript.library.reference_unknown")
        );
    }

    #[test]
    fn aggregate_library_shard_selectors_include_transitive_components() {
        let root = tempfile::tempdir().expect("library source root");
        std::fs::create_dir_all(root.path().join("lib")).unwrap();
        std::fs::write(
            root.path().join("package.json"),
            r#"{"name":"typescript","version":"7.0.2","license":"Apache-2.0"}"#,
        )
        .unwrap();
        std::fs::write(
            root.path().join("lib/lib.es5.d.ts"),
            "interface Array<T> { length: number }\n",
        )
        .unwrap();
        std::fs::write(
            root.path().join("lib/lib.es2015.core.d.ts"),
            "/// <reference lib = \"es5\" />\ninterface PromiseLike<T> {}\n",
        )
        .unwrap();
        std::fs::write(
            root.path().join("lib/lib.es2015.d.ts"),
            "/// <reference lib=\"es5\" />\n/// <reference lib=\"es2015.core\" />\n",
        )
        .unwrap();
        let libraries = [
            ("es5".to_owned(), "lib/lib.es5.d.ts".to_owned()),
            (
                "es2015.core".to_owned(),
                "lib/lib.es2015.core.d.ts".to_owned(),
            ),
            ("es2015".to_owned(), "lib/lib.es2015.d.ts".to_owned()),
        ];
        let artifact = read_exact_source_set(
            root.path(),
            &libraries
                .iter()
                .map(|(_, path)| PathBuf::from(path))
                .chain([PathBuf::from("package.json")])
                .collect::<Vec<_>>(),
            32,
            16,
            &ArtifactProducerLimits::default(),
        )
        .unwrap();
        let mut request = request(PathBuf::new());
        request.artifact_kind = ExternalArtifactKind::TypeScriptLibrarySet;
        request.activation = vec![ActivationSelector {
            package: None,
            module: None,
            toolchain: None,
            targets: Vec::new(),
            configurations: vec!["typescript-lib:es2015".to_owned()],
            artifact_sha256: None,
        }];
        let production = TypeScriptDeclarationPackProducer.produce_loaded_library_set(
            &request,
            &ArtifactProducerLimits::default(),
            None,
            &artifact,
            "package.json",
            &libraries,
        );
        assert_eq!(production.completeness, Completeness::Complete);
        let pack = production.pack.unwrap();
        let es5 = pack
            .shards
            .iter()
            .find(|shard| shard.id.ends_with(".es5"))
            .unwrap();
        assert!(
            es5.activation[0]
                .configurations
                .contains(&"typescript-lib:es2015".to_owned())
        );
    }

    #[test]
    fn library_source_set_uses_one_record_budget() {
        let root = tempfile::tempdir().expect("library source root");
        std::fs::create_dir_all(root.path().join("lib")).unwrap();
        std::fs::write(
            root.path().join("package.json"),
            r#"{"name":"typescript","version":"7.0.2","license":"Apache-2.0"}"#,
        )
        .unwrap();
        std::fs::write(
            root.path().join("lib/lib.es5.d.ts"),
            "interface Array<T> { length: number }\ninterface Object {}\n",
        )
        .unwrap();
        std::fs::write(
            root.path().join("lib/lib.dom.d.ts"),
            "interface Document { title: string }\n",
        )
        .unwrap();
        let artifact = read_exact_source_set(
            root.path(),
            &[
                PathBuf::from("package.json"),
                PathBuf::from("lib/lib.dom.d.ts"),
                PathBuf::from("lib/lib.es5.d.ts"),
            ],
            32,
            16,
            &ArtifactProducerLimits::default(),
        )
        .unwrap();
        let mut request = request(PathBuf::new());
        request.artifact_kind = ExternalArtifactKind::TypeScriptLibrarySet;
        let limits = ArtifactProducerLimits {
            max_records: 2,
            ..ArtifactProducerLimits::default()
        };
        let production = TypeScriptDeclarationPackProducer.produce_loaded_library_set(
            &request,
            &limits,
            None,
            &artifact,
            "package.json",
            &[
                ("es5".to_owned(), "lib/lib.es5.d.ts".to_owned()),
                ("dom".to_owned(), "lib/lib.dom.d.ts".to_owned()),
            ],
        );
        assert_eq!(production.completeness, Completeness::Partial);
        assert!(
            production
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "limit.records")
        );
    }

    #[test]
    fn library_activation_evidence_is_exact_and_narrow() {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("tsconfig.json");
        std::fs::write(&config, r#"{"compilerOptions":{"lib":["ES5","DOM"]}}"#).unwrap();
        let outcome = typescript_library_activation_evidence(&config, root.path());
        assert!(outcome.selection.is_complete(), "{outcome:?}");
        assert_eq!(outcome.selection.libraries(), ["dom", "es5"]);
        assert!(outcome.evidence.len() > 2);
        assert!(outcome.evidence.iter().all(|evidence| {
            evidence.package.as_ref().is_some_and(|package| {
                package.name == TYPESCRIPT_STDLIB_PACKAGE
                    && package.version.as_ref().is_some_and(|version| {
                        version == &Version::parse(TYPESCRIPT_STDLIB_VERSION).unwrap()
                    })
            })
        }));
        assert!(
            outcome
                .evidence
                .iter()
                .any(|evidence| evidence.configuration.as_deref() == Some("typescript-lib:dom"))
        );
        assert!(
            outcome
                .evidence
                .iter()
                .any(|evidence| evidence.configuration.as_deref() == Some("typescript-lib:es2015"))
        );
    }

    #[test]
    fn malformed_library_config_has_no_uncertain_activation() {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("tsconfig.json");
        std::fs::write(
            &config,
            r#"{"compilerOptions":{"lib":["DOM","not-a-library"]}}"#,
        )
        .unwrap();
        let outcome = typescript_library_activation_evidence(&config, root.path());
        assert!(!outcome.selection.is_complete());
        assert!(outcome.selection.libraries().is_empty());
        assert!(outcome.evidence.is_empty());
        assert!(!outcome.diagnostics.is_empty());
    }

    fn request(path: PathBuf) -> ArtifactProductionRequest {
        ArtifactProductionRequest {
            path,
            artifact_kind: ExternalArtifactKind::TypeScriptDeclarationFile,
            pack_id: "bifrost.external.typescript".to_owned(),
            pack_version: "1.0.0".to_owned(),
            ecosystem: "npm".to_owned(),
            compatibility: Compatibility {
                bifrost: "*".to_owned(),
                toolchains: Vec::new(),
            },
            activation: vec![ActivationSelector {
                package: Some(NameSelector {
                    name: "widget".to_owned(),
                    version: Some("=1.2.3".to_owned()),
                }),
                module: Some(NameSelector {
                    name: "widget".to_owned(),
                    version: None,
                }),
                toolchain: None,
                targets: Vec::new(),
                configurations: Vec::new(),
                artifact_sha256: None,
            }],
            provenance: Provenance {
                source: "test".to_owned(),
                revision: Some("1.2.3".to_owned()),
            },
            license: "NOASSERTION".to_owned(),
            safety: Safety {
                generated_code_only: false,
                review_required: false,
            },
        }
    }
}
