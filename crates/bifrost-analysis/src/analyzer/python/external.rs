//! Static discovery of explicitly selected Python API-pack inputs.
//!
//! This module never invokes Python or imports a dependency. It only reads
//! configured directories and distribution metadata, returning exact local
//! files for the shared semantic-pack coordinator to hash and consume later.

use std::fs;
use std::path::{Path, PathBuf};

use semver::Version;

use crate::CancellationToken;
use crate::analyzer::semantic_model::{
    ActivationSelector, ArtifactProducerLimits, ArtifactProduction, ArtifactProductionRequest,
    AuthoredPayload, AuthoredSemanticModelPack, AuthoredShard, BoundedProducerDiagnostics,
    CatalogCoordinate, Compatibility, Completeness, DeclarationGuard, DependencyArtifactRole,
    DependencyDiscoveryOutcome, DependencyDiscoveryProfile, DependencyPackAdapter,
    DependencyPackDiagnostic, DependencyPackDiagnosticSeverity, DependencyPackLimits,
    DependencyPackProduction, DependencyProvenance, ExactArtifact, ExactDependencyArtifact,
    ExternalArtifactKind, ExternalArtifactPackProducer, GuardVersion, HierarchyFact, Locator,
    MemberFact, MemberIdentity, MemberKind, NameSelector, Parameter, ParameterPassingMode,
    Producer, ProducerDiagnostic, ProducerDiagnosticSeverity, Provenance, ResolvedDependency,
    ResolvedDependencyArtifact, Safety, SemanticModelActivationEvidence, Signature,
    SuppressedDiagnostics, TypeFact, TypeIdentity, TypeKind, TypeRef, Visibility,
    member_declaration_id, read_exact_artifact_while, type_declaration_id,
};
use crate::analyzer::topology::DependencyScope;
use crate::analyzer::{Project, PythonAnalyzerConfig, PythonEnvironmentConfig};
use brokk_bifrost_python::syntax::python_plain_string_literal;
use tree_sitter::Node;

#[derive(Debug, Clone, Copy, Default)]
pub struct PythonDependencyPackAdapter;

#[derive(Debug, Clone, Copy, Default)]
pub struct PythonArtifactPackProducer;

impl DependencyPackAdapter for PythonDependencyPackAdapter {
    fn adapter_name(&self) -> &str {
        "bifrost-python-environment"
    }

    fn adapter_version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn producer(&self) -> Producer {
        Producer {
            name: "bifrost-python-stub".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    fn produce(
        &self,
        dependency: &ResolvedDependency,
        artifacts: &[ExactDependencyArtifact],
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
    ) -> DependencyPackProduction {
        let request = python_dependency_production_request(dependency);
        let mut types = Vec::new();
        let mut members = Vec::new();
        let mut diagnostics = Vec::new();
        let mut suppressed_diagnostics = SuppressedDiagnostics::default();
        let mut completeness = Completeness::Complete;
        let stub_modules = artifacts
            .iter()
            .filter(|artifact| artifact.kind() == ExternalArtifactKind::PythonStub)
            .filter_map(|artifact| artifact.module().map(str::to_owned))
            .collect::<std::collections::HashSet<_>>();
        for artifact in artifacts {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                diagnostics.push(ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    source_entry: None,
                    code: "artifact.cancelled".to_owned(),
                    location: None,
                    declaration: None,
                    message: "Python dependency production was cancelled".to_owned(),
                });
                completeness = Completeness::Partial;
                break;
            }
            let Some(module) = artifact.module() else {
                diagnostics.push(ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    source_entry: None,
                    code: "python.artifact_module".to_owned(),
                    location: Some(artifact.path().display().to_string()),
                    declaration: None,
                    message: "Python environment artifact has no import-module identity".to_owned(),
                });
                completeness = Completeness::Partial;
                continue;
            };
            // A stub is the authoritative surface for a module.  Source remains
            // available for modules for which the environment supplied no stub.
            if artifact.kind() == ExternalArtifactKind::PythonSource
                && stub_modules.contains(module)
            {
                continue;
            }
            let mut artifact_request = request.clone();
            artifact_request.path = artifact.path().to_owned();
            artifact_request.artifact_kind = artifact.kind();
            let production = PythonArtifactPackProducer.produce_loaded_artifact(
                &artifact_request,
                limits,
                cancellation,
                artifact.exact(),
                module,
            );
            completeness = combine_completeness(completeness, production.completeness);
            suppressed_diagnostics += production.suppressed_diagnostics;
            diagnostics.extend(production.diagnostics);
            if let Some(pack) = production.pack {
                for shard in pack.shards {
                    let AuthoredPayload::DeclarationFacts {
                        types: produced_types,
                        members: produced_members,
                        ..
                    } = shard.payload
                    else {
                        continue;
                    };
                    types.extend(produced_types);
                    members.extend(produced_members);
                }
            }
        }
        if types.is_empty() {
            return DependencyPackProduction {
                pack: None,
                diagnostics,
                suppressed_diagnostics,
            };
        }
        dedup_declarations(&mut types, &mut members);
        resolve_hierarchy_references(&mut types);
        let mut activation = request.activation.clone();
        for selector in &mut activation {
            selector.artifact_sha256 = None;
        }
        DependencyPackProduction {
            pack: Some(AuthoredSemanticModelPack {
                schema_version: crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
                pack_id: request.pack_id,
                version: request.pack_version,
                producer: self.producer(),
                language: "python".to_owned(),
                ecosystem: request.ecosystem,
                compatibility: request.compatibility,
                provenance: request.provenance,
                license: request.license,
                completeness,
                safety: request.safety,
                carried_sources: Vec::new(),
                cpp_portability: None,
                shards: vec![AuthoredShard {
                    id: "declarations.external".to_owned(),
                    activation,
                    payload: AuthoredPayload::DeclarationFacts {
                        types,
                        members,
                        relations: Vec::new(),
                    },
                }],
            }),
            diagnostics,
            suppressed_diagnostics,
        }
    }
}

impl ExternalArtifactPackProducer for PythonArtifactPackProducer {
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

impl PythonArtifactPackProducer {
    fn produce(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
    ) -> ArtifactProduction {
        if !matches!(
            request.artifact_kind,
            ExternalArtifactKind::PythonStub | ExternalArtifactKind::PythonSource
        ) {
            return ArtifactProduction::failed(
                ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    source_entry: None,
                    code: "artifact.kind".to_owned(),
                    location: None,
                    declaration: None,
                    message: "Python producer requires a .pyi or .py artifact".to_owned(),
                },
                limits,
            );
        }
        let artifact = match read_exact_artifact_while(&request.path, limits, || {
            cancellation.is_some_and(CancellationToken::is_cancelled)
        }) {
            Ok(artifact) => artifact,
            Err(diagnostic) => return ArtifactProduction::failed(diagnostic, limits),
        };
        self.produce_loaded_artifact(
            request,
            limits,
            cancellation,
            &artifact,
            &python_module_name_for_artifact(artifact.path()),
        )
    }

    fn produce_loaded_artifact(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
        artifact: &ExactArtifact,
        module: &str,
    ) -> ArtifactProduction {
        if !matches!(
            request.artifact_kind,
            ExternalArtifactKind::PythonStub | ExternalArtifactKind::PythonSource
        ) {
            return ArtifactProduction::failed(
                ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    source_entry: None,
                    code: "artifact.kind".to_owned(),
                    location: None,
                    declaration: None,
                    message: "Python producer requires a .pyi or .py artifact".to_owned(),
                },
                limits,
            );
        }
        let source = match std::str::from_utf8(artifact.bytes()) {
            Ok(source) => source,
            Err(_) => {
                return ArtifactProduction::failed(
                    ProducerDiagnostic {
                        severity: ProducerDiagnosticSeverity::Error,
                        source_entry: None,
                        code: "python.source.encoding".to_owned(),
                        location: Some(artifact.path().display().to_string()),
                        declaration: None,
                        message: "Python artifact is not UTF-8".to_owned(),
                    },
                    limits,
                );
            }
        };
        let Some(tree) = brokk_bifrost_python::declarations::parse_python_tree(source) else {
            return ArtifactProduction::failed(
                ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    source_entry: None,
                    code: "python.source.parse".to_owned(),
                    location: Some(artifact.path().display().to_string()),
                    declaration: None,
                    message: "Python parser did not produce a syntax tree".to_owned(),
                },
                limits,
            );
        };
        let mut diagnostics = BoundedProducerDiagnostics::new(limits);
        let (mut types, mut members) = {
            let mut collector = PythonApiCollector::new(
                module,
                artifact.path(),
                python_locator_file_name(artifact.path()),
                source,
                limits,
                &mut diagnostics,
            );
            collector.collect(tree.root_node(), cancellation);
            (collector.types, collector.members)
        };
        dedup_declarations(&mut types, &mut members);
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            diagnostics.error(
                "artifact.cancelled",
                None,
                "Python artifact production was cancelled",
            );
        }
        let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
        let completeness = if diagnostics.is_empty() && suppressed_diagnostics.total() == 0 {
            Completeness::Complete
        } else {
            Completeness::Partial
        };
        let mut activation = request.activation.clone();
        for selector in &mut activation {
            selector.artifact_sha256 = Some(artifact.sha256().to_owned());
        }
        ArtifactProduction {
            artifact_sha256: Some(artifact.sha256().to_owned()),
            pack: Some(AuthoredSemanticModelPack {
                schema_version: crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
                pack_id: request.pack_id.clone(),
                version: request.pack_version.clone(),
                producer: Producer {
                    name: "bifrost-python-stub".to_owned(),
                    version: env!("CARGO_PKG_VERSION").to_owned(),
                },
                language: "python".to_owned(),
                ecosystem: request.ecosystem.clone(),
                compatibility: request.compatibility.clone(),
                provenance: request.provenance.clone(),
                license: request.license.clone(),
                completeness,
                safety: request.safety.clone(),
                carried_sources: Vec::new(),
                cpp_portability: None,
                shards: vec![AuthoredShard {
                    id: "declarations.external".to_owned(),
                    activation,
                    payload: AuthoredPayload::DeclarationFacts {
                        types,
                        members,
                        relations: Vec::new(),
                    },
                }],
            }),
            completeness,
            diagnostics,
            suppressed_diagnostics,
        }
    }

    /// Produce one pack from an exact source set of Python stub files.
    ///
    /// Each entry's import-module identity comes from its relative path under
    /// the set root, exactly as an installed package tree derives it. Entries
    /// without a module identity, with invalid encoding, or with source the
    /// pinned parser rejects become bounded reject diagnostics and make the
    /// pack honestly partial.
    pub fn produce_loaded_source_set(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
        artifact: &ExactArtifact,
    ) -> ArtifactProduction {
        if request.artifact_kind != ExternalArtifactKind::PythonStub {
            return ArtifactProduction::failed(
                ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    source_entry: None,
                    code: "artifact.kind".to_owned(),
                    location: None,
                    declaration: None,
                    message: "Python stub source-set producer requires a python_stub artifact"
                        .to_owned(),
                },
                limits,
            );
        }
        let mut diagnostics = BoundedProducerDiagnostics::new(limits);
        let mut types = Vec::new();
        let mut members = Vec::new();
        let mut surfaces = Vec::new();
        for entry in artifact.source_entries() {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                diagnostics.error(
                    "artifact.cancelled",
                    None,
                    "Python stub source-set production was cancelled",
                );
                break;
            }
            let relative = Path::new(entry.relative_path());
            let Some(module) = python_module_name_from_relative(relative) else {
                diagnostics.warning_for_source_entry(
                    "python.artifact_module",
                    Some(entry.relative_path().to_owned()),
                    Some(entry.relative_path().to_owned()),
                    "Python stub entry has no import-module identity",
                );
                continue;
            };
            let Ok(source) = std::str::from_utf8(entry.bytes()) else {
                diagnostics.warning_for_source_entry(
                    "python.source.encoding",
                    Some(entry.relative_path().to_owned()),
                    Some(entry.relative_path().to_owned()),
                    "Python stub entry is not UTF-8",
                );
                continue;
            };
            let Some(tree) = brokk_bifrost_python::declarations::parse_python_tree(source) else {
                diagnostics.warning_for_source_entry(
                    "python.source.parse",
                    Some(entry.relative_path().to_owned()),
                    Some(entry.relative_path().to_owned()),
                    "Python parser did not produce a syntax tree",
                );
                continue;
            };
            let mut collector = PythonApiCollector::new(
                &module,
                relative,
                entry.relative_path().to_owned(),
                source,
                limits,
                &mut diagnostics,
            );
            collector.collect(tree.root_node(), cancellation);
            surfaces.push(collector.module_surface());
            types.extend(collector.types);
            members.extend(collector.members);
        }
        if types.is_empty() {
            diagnostics.error(
                "python.source_set.no_external_declarations",
                None,
                "stub source set contains no externally visible Python declarations",
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
        // Only a whole source set can say what a wildcard re-export binds, so
        // this is the one production stage that sees every module at once.
        expand_wildcard_reexports(
            &mut surfaces,
            &mut types,
            &mut members,
            limits,
            &mut diagnostics,
        );
        dedup_declarations(&mut types, &mut members);
        resolve_hierarchy_references(&mut types);
        let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
        let completeness = if diagnostics.is_empty() && suppressed_diagnostics.total() == 0 {
            Completeness::Complete
        } else {
            Completeness::Partial
        };
        // A source-set digest proves the exact model input, not an installed
        // Python dependency. Keep the caller's activation selector so a
        // typeshed-derived stdlib pack can activate from CPython toolchain
        // evidence without pretending the typeshed archive is present in the
        // analyzed workspace. Single-artifact dependency production retains
        // its exact artifact selector in `produce_loaded_artifact`.
        let activation = request.activation.clone();
        ArtifactProduction {
            artifact_sha256: Some(artifact.sha256().to_owned()),
            pack: Some(AuthoredSemanticModelPack {
                schema_version: crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
                pack_id: request.pack_id.clone(),
                version: request.pack_version.clone(),
                producer: Producer {
                    name: "bifrost-python-stub".to_owned(),
                    version: env!("CARGO_PKG_VERSION").to_owned(),
                },
                language: "python".to_owned(),
                ecosystem: request.ecosystem.clone(),
                compatibility: request.compatibility.clone(),
                provenance: request.provenance.clone(),
                license: request.license.clone(),
                completeness,
                safety: request.safety.clone(),
                carried_sources: Vec::new(),
                cpp_portability: None,
                shards: vec![AuthoredShard {
                    id: "declarations.external".to_owned(),
                    activation,
                    payload: AuthoredPayload::DeclarationFacts {
                        types,
                        members,
                        relations: Vec::new(),
                    },
                }],
            }),
            completeness,
            diagnostics,
            suppressed_diagnostics,
        }
    }
}

fn python_dependency_production_request(
    dependency: &ResolvedDependency,
) -> ArtifactProductionRequest {
    ArtifactProductionRequest {
        path: PathBuf::new(),
        artifact_kind: ExternalArtifactKind::PythonStub,
        pack_id: "bifrost.external.python".to_owned(),
        pack_version: env!("CARGO_PKG_VERSION").to_owned(),
        ecosystem: dependency.evidence.ecosystem.clone(),
        compatibility: Compatibility {
            bifrost: format!("={}", env!("CARGO_PKG_VERSION")),
            toolchains: dependency
                .evidence
                .toolchain
                .as_ref()
                .map(
                    |coordinate| crate::analyzer::semantic_model::VersionConstraint {
                        name: coordinate.name.clone(),
                        requirement: coordinate
                            .version
                            .as_ref()
                            .map(|version| format!("={version}"))
                            .unwrap_or_else(|| "*".to_owned()),
                    },
                )
                .into_iter()
                .collect(),
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
            toolchain: dependency
                .evidence
                .toolchain
                .as_ref()
                .map(|coordinate| NameSelector {
                    name: coordinate.name.clone(),
                    version: coordinate
                        .version
                        .as_ref()
                        .map(|version| format!("={version}")),
                }),
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
            source: "exact local Python environment artifact".to_owned(),
            revision: None,
        },
        license: "NOASSERTION".to_owned(),
        safety: Safety {
            generated_code_only: false,
            review_required: false,
        },
    }
}

fn combine_completeness(left: Completeness, right: Completeness) -> Completeness {
    if left == Completeness::Partial || right == Completeness::Partial {
        Completeness::Partial
    } else {
        Completeness::Complete
    }
}

fn python_module_name_for_artifact(path: &Path) -> String {
    let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
        return "__external__".to_owned();
    };
    if stem == "__init__" {
        return path
            .parent()
            .and_then(|parent| parent.file_name())
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .unwrap_or("__external__")
            .to_owned();
    }
    stem.to_owned()
}

fn python_module_name_from_import_root(import_root: &Path, path: &Path) -> Option<String> {
    python_module_name_from_relative(path.strip_prefix(import_root).ok()?)
}

fn python_module_name_from_relative(relative: &Path) -> Option<String> {
    let mut components = relative
        .components()
        .map(|component| component.as_os_str().to_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()?;
    let file_name = components.pop()?;
    let stem = Path::new(&file_name).file_stem()?.to_str()?;
    if stem != "__init__" {
        components.push(stem.to_owned());
    }
    (!components.is_empty()).then(|| components.join("."))
}

fn python_locator_file_name(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("__external__.pyi")
        .to_owned()
}

fn python_artifact_precedence(
    source_kind: Option<&str>,
    artifact_kind: ExternalArtifactKind,
) -> usize {
    match (source_kind, artifact_kind) {
        (Some("bundled_stub") | Some("stdlib"), ExternalArtifactKind::PythonStub) => 4,
        (Some("stub_only_distribution"), ExternalArtifactKind::PythonStub) => 3,
        (Some("inline_py_typed"), ExternalArtifactKind::PythonSource) => 2,
        (_, ExternalArtifactKind::PythonStub) => 2,
        (_, ExternalArtifactKind::PythonSource) => 1,
        _ => 0,
    }
}

struct PythonApiCollector<'a, 'd> {
    module: &'a str,
    path: &'a Path,
    locator_path: String,
    source: &'a str,
    limits: &'a ArtifactProducerLimits,
    diagnostics: &'d mut BoundedProducerDiagnostics,
    types: Vec<TypeFact>,
    members: Vec<MemberFact>,
    /// Every distinct guard this file's conditional blocks produced. A walk
    /// frame and a declaration name one by index, so an enclosing block's
    /// guard is not cloned once per statement it contains.
    guards: Vec<DeclarationGuard>,
    /// `owner.name` for every binding an import already contributed, mapped to
    /// that member's position, so a conditional import cannot mint one member
    /// identity twice and a second binding can widen the first one's guard.
    imported_names: std::collections::HashMap<String, usize>,
    /// Source-ordered Python bindings that can name a class in a hierarchy
    /// expression. The optional target is `None` when a binding is known but
    /// does not identify one declared type.
    hierarchy_bindings: std::collections::HashMap<String, HierarchyBinding>,
    /// Every `from m import *` this file spells, kept beside the
    /// [`PYTHON_UNENUMERATED_BINDING`] marker it recorded so a production that
    /// also collects `m` can replace the marker with the names the wildcard
    /// really binds (#2958).
    wildcard_imports: Vec<WildcardImport>,
    /// Surfaces that bind names no cross-module pass can enumerate: an import
    /// form that spells no bound name, or a wildcard outside module scope.
    unenumerable_owners: std::collections::HashSet<String>,
    /// What this module's `__all__` statements say it exports.
    exports: ModuleExports,
}

/// One `from m import *` a collected surface carries.
#[derive(Debug, Clone)]
struct WildcardImport {
    /// The absolute module the wildcard reads, or `None` when a relative
    /// spelling resolved to no module.
    target_module: Option<String>,
    /// The condition of the conditional block the wildcard sits in.
    guard: Option<DeclarationGuard>,
}

/// What a module states about the names `from <module> import *` binds.
///
/// Python binds `__all__` when the module defines it and every public name
/// otherwise, so a module that lists `__all__` in a form this producer cannot
/// read leaves its wildcard consumers unenumerable.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ModuleExports {
    /// No `__all__` statement: `import *` binds every public name.
    PublicNames,
    /// Every name the module's literal `__all__` statements list.
    Listed(Vec<String>),
    /// An `__all__` this producer could not read as a list of string literals.
    Unreadable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HierarchyBinding {
    target: Option<String>,
    guard: Option<usize>,
    local_type: bool,
}

/// One hierarchy name resolved to the exact source binding it references.
/// `target` is absent for a known non-type binding such as typeshed's
/// `typing.Protocol: _SpecialForm`; `bound_name` still preserves the exact
/// module-owned identity for the typing-marker decision.
struct ResolvedHierarchyBinding {
    target: Option<String>,
    bound_name: String,
    local_type: bool,
}

/// One pending subtree in the collector's iterative walk.
struct PendingNode<'tree> {
    node: Node<'tree>,
    owner: String,
    class_scope: bool,
    /// Index into [`PythonApiCollector::guards`], or `None` when no enclosing
    /// conditional block guards this subtree.
    guard: Option<usize>,
}

/// How deep a conditional expression this producer reads before it records the
/// condition as uninterpreted.
///
/// A real version or platform guard nests two or three operators. The bound
/// keeps a hostile stub's deeply nested condition from recursing without end.
const MAX_GUARD_CONDITION_DEPTH: usize = 32;

/// The member name a Python surface carries when it binds names this producer
/// cannot enumerate, e.g. `from ._impl import *` in a package's `__init__`.
///
/// `*` is not a Python identifier, so this member can never collide with a
/// real name. Its presence is the module-level fact that the listed members
/// are not the whole surface. A wildcard is a property of the surface, not a
/// fault in producing the pack, so it is recorded rather than reported as a
/// producer diagnostic: a diagnostic would make the production partial and
/// stop the whole environment from activating.
pub(crate) const PYTHON_UNENUMERATED_BINDING: &str = "*";

/// The module-level name whose value states which names `import *` binds.
const PYTHON_MODULE_EXPORTS: &str = "__all__";

/// Read a list or tuple of plain string literals, which is the only `__all__`
/// form whose export set is a fact rather than a guess.
fn python_string_list_literal(node: Node<'_>, source: &str) -> Option<Vec<String>> {
    if !matches!(node.kind(), "list" | "tuple") {
        return None;
    }
    named_children(node)
        .filter(|child| child.kind() != "comment")
        .map(|child| python_plain_string_literal(child, source).map(str::to_owned))
        .collect()
}

impl<'a, 'd> PythonApiCollector<'a, 'd> {
    fn new(
        module: &'a str,
        path: &'a Path,
        locator_path: String,
        source: &'a str,
        limits: &'a ArtifactProducerLimits,
        diagnostics: &'d mut BoundedProducerDiagnostics,
    ) -> Self {
        let mut collector = Self {
            module,
            path,
            locator_path,
            source,
            limits,
            diagnostics,
            types: Vec::new(),
            members: Vec::new(),
            guards: Vec::new(),
            imported_names: std::collections::HashMap::new(),
            hierarchy_bindings: std::collections::HashMap::new(),
            wildcard_imports: Vec::new(),
            unenumerable_owners: std::collections::HashSet::new(),
            exports: ModuleExports::PublicNames,
        };
        collector.push_type(
            module.to_owned(),
            TypeKind::Module,
            Vec::new(),
            Vec::new(),
            None,
        );
        collector
    }

    fn collect(&mut self, root: Node<'_>, cancellation: Option<&CancellationToken>) {
        let mut stack = vec![PendingNode {
            node: root,
            owner: self.module.to_owned(),
            class_scope: false,
            guard: None,
        }];
        while let Some(PendingNode {
            node,
            owner,
            class_scope,
            guard,
        }) = stack.pop()
        {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return;
            }
            match node.kind() {
                "module" | "block" => {
                    self.push_children(&mut stack, node, &owner, class_scope, guard)
                }
                "decorated_definition" => {
                    if let Some(definition) = node.child_by_field_name("definition") {
                        self.visit_definition(
                            &mut stack,
                            definition,
                            Some(node),
                            owner,
                            class_scope,
                            guard,
                        );
                    }
                }
                "class_definition" | "function_definition" => {
                    self.visit_definition(&mut stack, node, None, owner, class_scope, guard);
                }
                "expression_statement" => self.visit_assignment(node, &owner, class_scope, guard),
                "import_statement" | "import_from_statement" => {
                    self.visit_import(node, &owner, guard)
                }
                "type_alias_statement" => self.visit_type_alias(node, &owner, guard),
                // A conditional block does not make its declarations dynamic.
                // The emitted pack stays a static surface and never evaluates
                // a condition; it records the condition on the declarations
                // the block encloses so activation can (#1899).
                "if_statement" => {
                    self.visit_if_statement(&mut stack, node, &owner, class_scope, guard)
                }
                // The declarations an `except` body binds exist only when the
                // matching `try` body raised, which no static reader decides.
                "except_clause" => {
                    let guard = self.intern_guard(
                        self.guard_of(guard)
                            .cloned()
                            .unwrap_or_default()
                            .and(&DeclarationGuard::uninterpreted()),
                    );
                    self.push_children(&mut stack, node, &owner, class_scope, guard);
                }
                "try_statement" | "with_statement" | "for_statement" | "while_statement"
                | "else_clause" | "finally_clause" => {
                    self.push_children(&mut stack, node, &owner, class_scope, guard)
                }
                _ => {}
            }
        }
    }

    fn push_children<'tree>(
        &self,
        stack: &mut Vec<PendingNode<'tree>>,
        node: Node<'tree>,
        owner: &str,
        class_scope: bool,
        guard: Option<usize>,
    ) {
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        for child in children.into_iter().rev() {
            stack.push(PendingNode {
                node: child,
                owner: owner.to_owned(),
                class_scope,
                guard,
            });
        }
    }

    /// Walk one `if`/`elif`/`else` chain, recording on each branch's body the
    /// condition that reaches it: the enclosing guard, this branch's own
    /// condition, and the negation of every condition an earlier branch of the
    /// same chain already claimed.
    fn visit_if_statement<'tree>(
        &mut self,
        stack: &mut Vec<PendingNode<'tree>>,
        node: Node<'tree>,
        owner: &str,
        class_scope: bool,
        guard: Option<usize>,
    ) {
        let mut branches = vec![(
            node.child_by_field_name("condition"),
            node.child_by_field_name("consequence"),
        )];
        let mut cursor = node.walk();
        for alternative in node.children_by_field_name("alternative", &mut cursor) {
            match alternative.kind() {
                "elif_clause" => branches.push((
                    alternative.child_by_field_name("condition"),
                    alternative.child_by_field_name("consequence"),
                )),
                "else_clause" => branches.push((None, alternative.child_by_field_name("body"))),
                _ => {}
            }
        }
        // The guard of the path that reaches the next branch: nothing earlier
        // in the chain was taken.
        let mut untaken = self.guard_of(guard).cloned().unwrap_or_default();
        let mut bodies = Vec::with_capacity(branches.len());
        for (condition, body) in branches {
            let branch = match condition {
                Some(condition) => {
                    let constraint =
                        condition_guard(condition, self.source, MAX_GUARD_CONDITION_DEPTH);
                    let branch = untaken.and(&constraint);
                    untaken = untaken.and(
                        &constraint
                            .negated()
                            .unwrap_or_else(DeclarationGuard::uninterpreted),
                    );
                    branch
                }
                None => untaken.clone(),
            };
            let Some(body) = body else {
                continue;
            };
            bodies.push((body, self.intern_guard(branch)));
        }
        for (body, guard) in bodies.into_iter().rev() {
            stack.push(PendingNode {
                node: body,
                owner: owner.to_owned(),
                class_scope,
                guard,
            });
        }
    }

    fn guard_of(&self, guard: Option<usize>) -> Option<&DeclarationGuard> {
        guard.map(|index| &self.guards[index])
    }

    /// Retain one branch guard and name it by index. A guard that constrains
    /// nothing is not recorded: an unguarded declaration must stay unguarded.
    fn intern_guard(&mut self, guard: DeclarationGuard) -> Option<usize> {
        if guard == DeclarationGuard::default() {
            return None;
        }
        self.guards.push(guard);
        Some(self.guards.len() - 1)
    }

    fn visit_definition<'tree>(
        &mut self,
        stack: &mut Vec<PendingNode<'tree>>,
        definition: Node<'tree>,
        decorated: Option<Node<'tree>>,
        owner: String,
        class_scope: bool,
        guard: Option<usize>,
    ) {
        let Some(name) = node_identifier(definition.child_by_field_name("name"), self.source)
        else {
            self.diagnostics.warning(
                "python.declaration.name",
                Some(self.path.display().to_string()),
                "external Python declaration has no supported name",
            );
            return;
        };
        if definition.kind() == "class_definition" {
            let qualified = format!("{owner}.{name}");
            let hierarchy = definition
                .child_by_field_name("superclasses")
                .map(|bases| {
                    named_children(bases)
                        .filter(|base| !self.is_typing_marker_base(*base, &owner, guard))
                        .map(|base| HierarchyFact {
                            hierarchy_kind: crate::analyzer::semantic_model::HierarchyKind::Extends,
                            target: self.hierarchy_type_ref(base, &owner, guard),
                            declaration_ordinal: None,
                        })
                        .collect()
                })
                .unwrap_or_default();
            let type_parameters = definition
                .child_by_field_name("type_parameters")
                .map(|list| type_parameter_names(list, self.source))
                .unwrap_or_default();
            self.push_type(
                qualified.clone(),
                TypeKind::Class,
                type_parameters,
                hierarchy,
                guard,
            );
            self.record_hierarchy_binding(&owner, &name, Some(qualified.clone()), guard, true);
            if let Some(body) = definition.child_by_field_name("body") {
                stack.push(PendingNode {
                    node: body,
                    owner: qualified,
                    class_scope: true,
                    guard,
                });
            }
            return;
        }
        let decorators = decorated
            .map(|node| decorator_names(node, self.source))
            .unwrap_or_default();
        let member_kind = if decorators.iter().any(|decorator| decorator == "property") {
            MemberKind::Property
        } else if class_scope {
            MemberKind::Method
        } else {
            MemberKind::Function
        };
        let is_static = decorators
            .iter()
            .any(|decorator| decorator == "staticmethod");
        let signature =
            function_signature(definition, self.source, self.limits.max_signature_depth);
        self.record_hierarchy_binding(&owner, &name, None, guard, false);
        self.push_member(owner, name, member_kind, is_static, signature, guard);
    }

    fn visit_assignment(
        &mut self,
        node: Node<'_>,
        owner: &str,
        class_scope: bool,
        guard: Option<usize>,
    ) {
        let Some(assignment) = node.named_child(0) else {
            return;
        };
        if !matches!(assignment.kind(), "assignment" | "augmented_assignment") {
            return;
        }
        let Some(left) = assignment.child_by_field_name("left") else {
            return;
        };
        let Some(name) = node_identifier(Some(left), self.source) else {
            return;
        };
        if name == PYTHON_MODULE_EXPORTS && owner == self.module {
            self.record_module_exports(assignment);
        }
        self.record_hierarchy_binding(owner, &name, None, guard, false);
        if assignment
            .child_by_field_name("type")
            .or_else(|| {
                named_children(assignment)
                    .find(|child| is_type_alias_annotation(*child, self.source))
            })
            .is_some_and(|annotation| is_type_alias_annotation(annotation, self.source))
        {
            self.push_type(
                format!("{owner}.{name}"),
                TypeKind::TypeAlias,
                Vec::new(),
                Vec::new(),
                guard,
            );
            return;
        }
        self.push_member(
            owner.to_owned(),
            name,
            if class_scope {
                MemberKind::Field
            } else {
                MemberKind::Constant
            },
            false,
            None,
            guard,
        );
    }

    /// Read what one `__all__` statement adds to this module's export set.
    ///
    /// Python binds the names `__all__` lists when a module defines it, so the
    /// export set is what a wildcard consumer needs. Only a list or tuple of
    /// plain string literals is readable; every other form leaves the export
    /// set unreadable rather than guessed, which keeps the wildcard marker on
    /// every module that reads this one.
    fn record_module_exports(&mut self, assignment: Node<'_>) {
        if self.exports == ModuleExports::Unreadable {
            return;
        }
        let Some(listed) = assignment
            .child_by_field_name("right")
            .and_then(|right| python_string_list_literal(right, self.source))
        else {
            self.exports = ModuleExports::Unreadable;
            return;
        };
        match &mut self.exports {
            ModuleExports::PublicNames => self.exports = ModuleExports::Listed(listed),
            ModuleExports::Listed(names) => names.extend(listed),
            ModuleExports::Unreadable => {}
        }
    }

    /// An import inside a module or class body binds a name on that surface:
    /// `from .sessions import Session` in `requests/__init__.pyi` is how
    /// `requests.Session` exists at all. One artifact is produced without a
    /// view of the modules it imports, so the binding is recorded by name
    /// alone. That is what an absence proof needs -- "does this surface bind
    /// that name" -- and recording it is what makes a surface marked complete
    /// actually complete.
    ///
    /// A wildcard binds a set one file cannot enumerate, and so does a form
    /// that spells no single bound name. Either one is recorded as the
    /// [`PYTHON_UNENUMERATED_BINDING`] member, which is not a Python
    /// identifier and so can never be confused with a real name. A consumer
    /// that finds it knows this surface binds more than it lists, and that a
    /// name missing from it is therefore not proof of absence.
    ///
    /// A wildcard also keeps the module it reads, so a production that
    /// collects that module can expand the wildcard into the names it really
    /// binds and drop the marker (#2958). A wildcard outside module scope
    /// binds into a surface no module-level export set describes, so it leaves
    /// that owner unenumerable.
    fn visit_import(&mut self, node: Node<'_>, owner: &str, guard: Option<usize>) {
        for import in
            brokk_bifrost_python::imports::python_import_infos_from_node(node, self.source)
        {
            let hierarchy_target = self.import_hierarchy_target(&import);
            let name = match import.local_name().filter(|_| !import.is_wildcard) {
                Some(name) => name,
                None => PYTHON_UNENUMERATED_BINDING,
            };
            if name != PYTHON_UNENUMERATED_BINDING {
                self.record_hierarchy_binding(owner, name, hierarchy_target, guard, false);
            } else if import.is_wildcard && owner == self.module {
                let target_module = self.wildcard_target_module(&import);
                self.wildcard_imports.push(WildcardImport {
                    target_module,
                    guard: self.guard_of(guard).cloned(),
                });
            } else {
                self.unenumerable_owners.insert(owner.to_owned());
            }
            // Two branches of a `try`/`except ImportError` pair bind the same
            // name; recording it twice would mint one identity twice and mark
            // the surface ambiguous. The surviving binding takes the union of
            // the two branches' guards, so a name one branch binds
            // unconditionally is never hidden by the other branch's condition.
            let key = format!("{owner}.{name}", name = name);
            if let Some(&index) = self.imported_names.get(&key) {
                let recorded = self.guard_of(guard).cloned();
                self.members[index].guard =
                    DeclarationGuard::union(self.members[index].guard.take(), recorded);
                continue;
            }
            let index = self.members.len();
            self.push_member(
                owner.to_owned(),
                name.to_owned(),
                MemberKind::Constant,
                false,
                None,
                guard,
            );
            if self.members.len() > index {
                self.imported_names.insert(key, index);
            }
        }
    }

    fn import_hierarchy_target(&self, import: &crate::analyzer::ImportInfo) -> Option<String> {
        use brokk_bifrost_python::imports::{
            PythonImportDetails, python_import_details, python_namespace_binding_module,
            resolve_python_relative_module_from_package,
        };

        match python_import_details(import)? {
            PythonImportDetails::Import { module, alias } => Some(python_namespace_binding_module(
                import,
                alias.as_deref(),
                &module,
            )),
            PythonImportDetails::FromImport {
                module,
                name,
                wildcard: false,
                ..
            } => {
                let module =
                    resolve_python_relative_module_from_package(self.current_package(), &module)?;
                Some(format!("{module}.{name}"))
            }
            PythonImportDetails::FromImport { wildcard: true, .. } => None,
        }
    }

    /// The absolute module a `from m import *` reads, resolved through the
    /// same package identity a named import resolves through.
    fn wildcard_target_module(&self, import: &crate::analyzer::ImportInfo) -> Option<String> {
        use brokk_bifrost_python::imports::{
            PythonImportDetails, python_import_details, resolve_python_relative_module_from_package,
        };

        let PythonImportDetails::FromImport {
            module,
            wildcard: true,
            ..
        } = python_import_details(import)?
        else {
            return None;
        };
        resolve_python_relative_module_from_package(self.current_package(), &module)
    }

    /// The package a relative import in this file resolves against. A package
    /// `__init__` is its own package; any other module resolves against the
    /// package that contains it.
    fn current_package(&self) -> &str {
        if self.path.file_stem().is_some_and(|stem| stem == "__init__") {
            self.module
        } else {
            self.module
                .rsplit_once('.')
                .map_or("", |(package, _)| package)
        }
    }

    fn record_hierarchy_binding(
        &mut self,
        owner: &str,
        name: &str,
        target: Option<String>,
        guard: Option<usize>,
        local_type: bool,
    ) {
        let key = format!("{owner}.{name}");
        let next = HierarchyBinding {
            target,
            guard,
            local_type,
        };
        match self.hierarchy_bindings.get(&key) {
            Some(previous) if guard.is_some() && previous != &next => {
                self.hierarchy_bindings.insert(
                    key,
                    HierarchyBinding {
                        target: None,
                        guard: None,
                        local_type: false,
                    },
                );
            }
            _ => {
                self.hierarchy_bindings.insert(key, next);
            }
        }
    }

    fn hierarchy_type_ref(&self, node: Node<'_>, owner: &str, guard: Option<usize>) -> TypeRef {
        let parsed = type_ref(node, self.source, self.limits.max_signature_depth);
        let Some(binding) = self.resolved_hierarchy_binding(node, owner, guard) else {
            return parsed;
        };
        let Some(target) = binding.target else {
            return parsed;
        };
        let TypeRef::Named {
            arguments,
            nullable,
            ..
        } = parsed
        else {
            return parsed;
        };
        if !binding.local_type {
            return TypeRef::Named {
                name: target,
                arguments,
                nullable,
            };
        }
        TypeRef::Declared {
            id: type_declaration_id(TypeIdentity {
                ecosystem: "python",
                name: &target,
            }),
            arguments,
            nullable,
        }
    }

    /// Resolve the AST name of a hierarchy expression through the bindings
    /// already collected from imports and local type declarations.
    fn resolved_hierarchy_binding(
        &self,
        node: Node<'_>,
        owner: &str,
        guard: Option<usize>,
    ) -> Option<ResolvedHierarchyBinding> {
        let segments = type_name_segments(node, self.source)?;
        let (local, suffix) = segments.split_first()?;
        let mut scope = Some(owner);
        while let Some(current) = scope {
            let key = format!("{current}.{local}");
            if let Some(binding) = self.hierarchy_bindings.get(&key) {
                if binding.guard.is_some() && binding.guard != guard {
                    return None;
                }
                let mut target = binding.target.clone();
                let mut bound_name = key;
                if !suffix.is_empty() {
                    let suffix = suffix.join(".");
                    if let Some(target) = &mut target {
                        target.push('.');
                        target.push_str(&suffix);
                    }
                    bound_name.push('.');
                    bound_name.push_str(&suffix);
                }
                return Some(ResolvedHierarchyBinding {
                    target,
                    bound_name,
                    local_type: binding.local_type,
                });
            }
            scope = current.rsplit_once('.').map(|(parent, _)| parent);
        }
        None
    }

    /// This file's module-level surface, in the form the production's
    /// cross-module wildcard expansion reads.
    ///
    /// Every module-level binding is already recorded for hierarchy
    /// resolution, keyed by `owner.name`; a module-level key is one whose
    /// remainder after this module's own name is a single identifier.
    fn module_surface(&self) -> CollectedModuleSurface {
        let prefix = format!("{}.", self.module);
        let bindings = self
            .hierarchy_bindings
            .iter()
            .filter_map(|(key, binding)| {
                let name = key.strip_prefix(&prefix)?;
                if name.contains('.') {
                    return None;
                }
                Some((
                    name.to_owned(),
                    ModuleBinding {
                        target: binding.target.clone(),
                        guard: self.guard_of(binding.guard).cloned(),
                        expanded: false,
                    },
                ))
            })
            .collect();
        CollectedModuleSurface {
            module: self.module.to_owned(),
            locator_path: self.locator_path.clone(),
            bindings,
            exports: self.exports.clone(),
            wildcards: self.wildcard_imports.clone(),
            opaque: self.unenumerable_owners.contains(self.module),
        }
    }

    /// `Protocol` and `Generic` are typing-only class construction markers,
    /// not runtime inheritance surfaces. Omit them only when the structured
    /// binding graph proves their exact standard typing identity.
    fn is_typing_marker_base(&self, node: Node<'_>, owner: &str, guard: Option<usize>) -> bool {
        self.resolved_hierarchy_binding(node, owner, guard)
            .is_some_and(|binding| {
                !binding.local_type
                    && matches!(
                        binding.target.as_deref().unwrap_or(&binding.bound_name),
                        "typing.Protocol"
                            | "typing.Generic"
                            | "typing_extensions.Protocol"
                            | "typing_extensions.Generic"
                    )
            })
    }

    /// A PEP 695 `type Alias[T] = ...` statement spells its declared name in
    /// the `left` field, not a `name` field, and wraps it in a `type` node.
    /// Reading that wrapper is what makes the alias exist in the pack at all.
    fn visit_type_alias(&mut self, node: Node<'_>, owner: &str, guard: Option<usize>) {
        let Some(left) = node.child_by_field_name("left") else {
            return;
        };
        let Some(name) = type_name(left, self.source) else {
            return;
        };
        // The statement has no `type_parameters` field: an alias spells its
        // list inside its declared name, as `Alias[T]`.
        let type_parameters = named_children(left)
            .find(|child| child.kind() == "generic_type")
            .and_then(|generic| {
                named_children(generic).find(|child| child.kind() == "type_parameter")
            })
            .map(|list| type_parameter_names(list, self.source))
            .unwrap_or_default();
        self.push_type(
            format!("{owner}.{name}"),
            TypeKind::TypeAlias,
            type_parameters,
            Vec::new(),
            guard,
        );
    }

    fn push_type(
        &mut self,
        name: String,
        type_kind: TypeKind,
        type_parameters: Vec<String>,
        hierarchy: Vec<crate::analyzer::semantic_model::HierarchyFact>,
        guard: Option<usize>,
    ) {
        if self.types.len().saturating_add(self.members.len()) >= self.limits.max_records {
            self.diagnostics.error(
                "limit.records",
                Some(self.path.display().to_string()),
                format!(
                    "Python artifact exceeds declaration limit {}",
                    self.limits.max_records
                ),
            );
            return;
        }
        let guard = self.guard_of(guard).cloned();
        self.types.push(TypeFact {
            id: type_declaration_id(TypeIdentity {
                ecosystem: "python",
                name: &name,
            }),
            name: name.clone(),
            type_kind,
            visibility: python_visibility(&name),
            is_abstract: false,
            is_sealed: false,
            has_explicit_type_terms: false,
            type_parameters,
            type_parameter_constraints: Vec::new(),
            underlying_type: None,
            value_semantics: None,
            embedded_types: Vec::new(),
            hierarchy,
            aliases: Vec::new(),
            extension_surfaces: Vec::new(),
            guard,
            locator: Locator::Artifact {
                path: self.locator_path.clone(),
                symbol: name,
            },
        });
    }

    fn push_member(
        &mut self,
        owner: String,
        name: String,
        member_kind: MemberKind,
        is_static: bool,
        signature: Option<Signature>,
        guard: Option<usize>,
    ) {
        if self.types.len().saturating_add(self.members.len()) >= self.limits.max_records {
            self.diagnostics.error(
                "limit.records",
                Some(self.path.display().to_string()),
                format!(
                    "Python artifact exceeds declaration limit {}",
                    self.limits.max_records
                ),
            );
            return;
        }
        let guard = self.guard_of(guard).cloned();
        self.members.push(member_fact(
            &owner,
            &name,
            member_kind,
            is_static,
            signature,
            &self.locator_path,
            guard,
        ));
    }
}

/// One member declaration of a Python surface, with the identity its owner,
/// kind, and signature determine.
fn member_fact(
    owner: &str,
    name: &str,
    member_kind: MemberKind,
    is_static: bool,
    signature: Option<Signature>,
    locator_path: &str,
    guard: Option<DeclarationGuard>,
) -> MemberFact {
    let owner_id = type_declaration_id(TypeIdentity {
        ecosystem: "python",
        name: owner,
    });
    let parameter_types = signature
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
        owner_id: &owner_id,
        kind: member_kind,
        is_static,
        parameter_arity: parameter_types.len(),
        name,
        generic_arity: signature
            .as_ref()
            .map_or(0, |signature| signature.type_parameters.len()),
        parameter_types: &parameter_types,
        parameter_variadics: &[],
        return_type: signature
            .as_ref()
            .and_then(|signature| signature.returns.as_ref()),
    });
    MemberFact {
        id,
        owner: owner_id,
        name: name.to_owned(),
        member_kind,
        visibility: python_visibility(name),
        is_static,
        is_abstract: false,
        is_virtual: false,
        implicit_operation: None,
        callable_family_complete: false,
        signature,
        receiver: None,
        extension_receiver: None,
        extension_receiver_constraints: Vec::new(),
        aliases: Vec::new(),
        guard,
        locator: Locator::Artifact {
            path: locator_path.to_owned(),
            symbol: format!("{owner}.{name}"),
        },
    }
}

/// One collected module's module-level surface, kept beside its declarations
/// so a production can expand the wildcard re-exports its modules read from
/// one another (#2958).
struct CollectedModuleSurface {
    module: String,
    locator_path: String,
    /// Every module-level name this surface binds.
    bindings: std::collections::HashMap<String, ModuleBinding>,
    exports: ModuleExports,
    wildcards: Vec<WildcardImport>,
    /// True when this surface binds names no expansion can enumerate.
    opaque: bool,
}

/// One module-level name a surface binds.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ModuleBinding {
    /// The qualified declaration the name refers to, or `None` when the
    /// binding names no declared type.
    target: Option<String>,
    guard: Option<DeclarationGuard>,
    /// True when a wildcard expansion produced this binding, so the production
    /// still has to publish it.
    expanded: bool,
}

/// Expand every `from m import *` whose `m` this production also collected.
///
/// Python binds the names `m.__all__` lists when `m` defines it, and every
/// public name of `m` otherwise, including the names `m` itself re-exports.
/// Each expanded name is published on the reading module as the binding a
/// named import of it would have produced, and, when it names a type this
/// production declares, as a qualified alias of that type: a wildcard chain
/// such as `collections.abc -> _collections_abc -> typing.MutableSet` then
/// ends at the declaring class, and a hierarchy edge to
/// `collections.abc.MutableSet` resolves.
///
/// Wildcards chain, so names propagate to a fixed point. The
/// [`PYTHON_UNENUMERATED_BINDING`] marker survives only where a surface really
/// binds more than it lists: a wildcard whose module this production does not
/// carry, an `__all__` this producer cannot read, or an `__all__` naming a
/// name the module does not bind.
fn expand_wildcard_reexports(
    surfaces: &mut [CollectedModuleSurface],
    types: &mut [TypeFact],
    members: &mut Vec<MemberFact>,
    limits: &ArtifactProducerLimits,
    diagnostics: &mut BoundedProducerDiagnostics,
) {
    let modules = surfaces
        .iter()
        .enumerate()
        .map(|(index, surface)| (surface.module.clone(), index))
        .collect::<std::collections::HashMap<_, _>>();

    // Names first: a wildcard's source module can itself gain names from a
    // wildcard, so one pass over the surfaces is not enough.
    loop {
        let mut gains = Vec::new();
        for (consumer, surface) in surfaces.iter().enumerate() {
            for wildcard in &surface.wildcards {
                let Some(&source) = wildcard
                    .target_module
                    .as_ref()
                    .and_then(|module| modules.get(module))
                else {
                    continue;
                };
                if source == consumer {
                    continue;
                }
                for (name, binding) in exported_bindings(&surfaces[source]) {
                    let guard = conjoined_guard(wildcard.guard.clone(), binding.guard.clone());
                    let gained = match surface.bindings.get(name) {
                        // An explicit binding on the reading module names the
                        // declaration itself; a wildcard never overrides it.
                        Some(existing) if !existing.expanded => continue,
                        Some(existing) => ModuleBinding {
                            target: (existing.target == binding.target)
                                .then(|| existing.target.clone())
                                .flatten(),
                            guard: DeclarationGuard::union(existing.guard.clone(), guard),
                            expanded: true,
                        },
                        None => ModuleBinding {
                            target: binding.target.clone(),
                            guard,
                            expanded: true,
                        },
                    };
                    if surface.bindings.get(name) != Some(&gained) {
                        gains.push((consumer, name.clone(), gained));
                    }
                }
            }
        }
        if gains.is_empty() {
            break;
        }
        for (consumer, name, binding) in gains {
            surfaces[consumer].bindings.insert(name, binding);
        }
    }

    // Then enumerability, which the expanded name sets decide. A surface earns
    // it only from evidence, so a wildcard cycle stays unenumerable rather
    // than declaring itself complete.
    let mut enumerable = vec![false; surfaces.len()];
    loop {
        let mut changed = false;
        for (index, surface) in surfaces.iter().enumerate() {
            if enumerable[index] || !exports_enumerable(surface, &modules, &enumerable) {
                continue;
            }
            enumerable[index] = true;
            changed = true;
        }
        if !changed {
            break;
        }
    }

    let mut alias_targets = std::collections::HashMap::<&str, Vec<usize>>::new();
    for (index, fact) in types.iter().enumerate() {
        alias_targets
            .entry(fact.name.as_str())
            .or_default()
            .push(index);
    }
    let mut aliases = Vec::new();
    let mut enumerated_owners = std::collections::HashSet::new();
    for surface in surfaces.iter() {
        let mut expanded = surface
            .bindings
            .iter()
            .filter(|(_, binding)| binding.expanded)
            .collect::<Vec<_>>();
        expanded.sort_by_key(|(name, _)| *name);
        if types
            .len()
            .saturating_add(members.len())
            .saturating_add(expanded.len())
            > limits.max_records
        {
            diagnostics.error(
                "limit.records",
                Some(surface.locator_path.clone()),
                format!(
                    "Python wildcard re-export expansion exceeds declaration limit {}",
                    limits.max_records
                ),
            );
            return;
        }
        for (name, binding) in expanded {
            members.push(member_fact(
                &surface.module,
                name,
                MemberKind::Constant,
                false,
                None,
                &surface.locator_path,
                binding.guard.clone(),
            ));
            let alias = format!("{}.{}", surface.module, name);
            if let Some(target) = &binding.target
                && *target != alias
                && let Some(declarations) = alias_targets.get(target.as_str())
            {
                for declaration in declarations {
                    aliases.push((*declaration, alias.clone()));
                }
            }
        }
        // The marker states that a surface binds more than it lists. Once
        // every wildcard of a module is expanded, it lists everything.
        if !surface.wildcards.is_empty() && bindings_complete(surface, &modules, &enumerable) {
            enumerated_owners.insert(type_declaration_id(TypeIdentity {
                ecosystem: "python",
                name: &surface.module,
            }));
        }
    }
    for (declaration, alias) in aliases {
        types[declaration].aliases.push(alias);
    }
    for fact in types.iter_mut() {
        fact.aliases.sort();
        fact.aliases.dedup();
    }
    if !enumerated_owners.is_empty() {
        members.retain(|member| {
            member.name != PYTHON_UNENUMERATED_BINDING || !enumerated_owners.contains(&member.owner)
        });
    }
}

/// The names `from <module> import *` binds, as far as the module states them.
fn exported_bindings(surface: &CollectedModuleSurface) -> Vec<(&String, &ModuleBinding)> {
    match &surface.exports {
        // An unreadable `__all__` states nothing about the export set, so this
        // module publishes no name through a wildcard rather than a guess.
        ModuleExports::Unreadable => Vec::new(),
        ModuleExports::Listed(names) => names
            .iter()
            .filter_map(|name| surface.bindings.get_key_value(name))
            .collect(),
        ModuleExports::PublicNames => surface
            .bindings
            .iter()
            .filter(|(name, _)| !name.starts_with('_'))
            .collect(),
    }
}

/// Whether every name this surface binds is known: nothing else on it binds
/// names out of view, and every wildcard it reads has an enumerable module.
fn bindings_complete(
    surface: &CollectedModuleSurface,
    modules: &std::collections::HashMap<String, usize>,
    enumerable: &[bool],
) -> bool {
    !surface.opaque
        && surface.wildcards.iter().all(|wildcard| {
            wildcard
                .target_module
                .as_ref()
                .and_then(|module| modules.get(module))
                .is_some_and(|source| enumerable[*source])
        })
}

/// Whether the names `from <module> import *` binds are all known.
fn exports_enumerable(
    surface: &CollectedModuleSurface,
    modules: &std::collections::HashMap<String, usize>,
    enumerable: &[bool],
) -> bool {
    bindings_complete(surface, modules, enumerable)
        && match &surface.exports {
            ModuleExports::Unreadable => false,
            ModuleExports::PublicNames => true,
            ModuleExports::Listed(names) => {
                names.iter().all(|name| surface.bindings.contains_key(name))
            }
        }
}

/// The condition that holds where both conditions hold. A name reached through
/// a guarded wildcard exists only where the wildcard is taken and the module
/// it reads declares the name.
fn conjoined_guard(
    left: Option<DeclarationGuard>,
    right: Option<DeclarationGuard>,
) -> Option<DeclarationGuard> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.and(&right)),
        (Some(guard), None) | (None, Some(guard)) => Some(guard),
        (None, None) => None,
    }
}

/// Collapse declarations that share one identity, keeping the guard that is
/// true wherever either record's guard is.
///
/// Two branches of one conditional block can declare the same name with the
/// same shape, which mints one identity twice. Keeping only the first record
/// would keep only that branch's condition and would hide the declaration from
/// every activation the other branch covers (#1899).
fn dedup_declarations(types: &mut Vec<TypeFact>, members: &mut Vec<MemberFact>) {
    types.sort_by(|left, right| left.id.cmp(&right.id));
    types.dedup_by(|later, kept| {
        if later.id != kept.id {
            return false;
        }
        kept.guard = DeclarationGuard::union(kept.guard.take(), later.guard.take());
        true
    });
    members.sort_by(|left, right| left.id.cmp(&right.id));
    members.dedup_by(|later, kept| {
        if later.id != kept.id {
            return false;
        }
        kept.guard = DeclarationGuard::union(kept.guard.take(), later.guard.take());
        true
    });
}

/// Resolve imported hierarchy names only when their declarations are part of
/// this exact source set. An import can name a valid external Python type that
/// is not included in a pinned artifact; keeping that edge named preserves the
/// relationship without emitting a declared ID the pack cannot define.
fn resolve_hierarchy_references(types: &mut [TypeFact]) {
    let declared_names = types
        .iter()
        .map(|fact| fact.name.clone())
        .collect::<std::collections::HashSet<_>>();
    for fact in types.iter_mut() {
        for hierarchy in &mut fact.hierarchy {
            let TypeRef::Named {
                name,
                arguments,
                nullable,
            } = &hierarchy.target
            else {
                continue;
            };
            if !declared_names.contains(name.as_str()) {
                continue;
            }
            hierarchy.target = TypeRef::Declared {
                id: type_declaration_id(TypeIdentity {
                    ecosystem: "python",
                    name,
                }),
                arguments: arguments.clone(),
                nullable: *nullable,
            };
        }
    }
}

/// The condition one conditional block places on the declarations inside it.
///
/// The returned guard is a conjunction of necessary conditions. A condition
/// this reader cannot express returns [`DeclarationGuard::uninterpreted`],
/// which keeps every declaration in the block and states that the pack read
/// less than the whole condition rather than dropping the declarations or
/// claiming they are unconditional.
fn condition_guard(node: Node<'_>, source: &str, depth: usize) -> DeclarationGuard {
    if depth == 0 {
        return DeclarationGuard::uninterpreted();
    }
    match node.kind() {
        "parenthesized_expression" => node
            .named_child(0)
            .map(|inner| condition_guard(inner, source, depth - 1))
            .unwrap_or_else(DeclarationGuard::uninterpreted),
        // `A and B` holds only where both hold, so both sides stay necessary.
        // `A or B` makes neither side necessary, so it records nothing.
        "boolean_operator" => {
            let operator = node.child_by_field_name("operator").map(|node| node.kind());
            let left = node.child_by_field_name("left");
            let right = node.child_by_field_name("right");
            match (operator, left, right) {
                (Some("and"), Some(left), Some(right)) => condition_guard(left, source, depth - 1)
                    .and(&condition_guard(right, source, depth - 1)),
                _ => DeclarationGuard::uninterpreted(),
            }
        }
        "not_operator" => node
            .child_by_field_name("argument")
            .map(|argument| condition_guard(argument, source, depth - 1))
            .and_then(|guard| guard.negated())
            .unwrap_or_else(DeclarationGuard::uninterpreted),
        "comparison_operator" => comparison_guard(node, source),
        _ => DeclarationGuard::uninterpreted(),
    }
}

/// The constraint one comparison spells, for the two interpreter coordinates a
/// stub can branch on: `sys.version_info` and `sys.platform`.
///
/// A chained comparison such as `a < b < c` carries more than one operator and
/// more than two operands; it is not one of the two forms, so it records
/// nothing.
fn comparison_guard(node: Node<'_>, source: &str) -> DeclarationGuard {
    let mut cursor = node.walk();
    let operators = node
        .children_by_field_name("operators", &mut cursor)
        .map(|operator| operator.kind())
        .collect::<Vec<_>>();
    let operands = named_children(node).collect::<Vec<_>>();
    let ([operator], [left, right]) = (operators.as_slice(), operands.as_slice()) else {
        return DeclarationGuard::uninterpreted();
    };
    match type_name(*left, source).as_deref() {
        Some("sys.version_info") => version_info_guard(operator, *right, source),
        Some("sys.platform") => platform_guard(operator, *right, source),
        _ => DeclarationGuard::uninterpreted(),
    }
}

/// The version bound one `sys.version_info` comparison places on a block.
///
/// `sys.version_info` is a five-component tuple, so a comparison against a
/// shorter tuple with an equal prefix always makes the interpreter's own value
/// the greater one: `(3, 14, 0, 'final', 0) > (3, 14)`. `>` therefore admits
/// exactly the versions `>=` admits, and `<=` excludes exactly the versions
/// `<` excludes.
fn version_info_guard(operator: &str, bound: Node<'_>, source: &str) -> DeclarationGuard {
    let Some(bound) = version_tuple(bound, source) else {
        return DeclarationGuard::uninterpreted();
    };
    match operator {
        ">=" | ">" => DeclarationGuard {
            min_toolchain_version: Some(bound),
            ..DeclarationGuard::default()
        },
        "<" | "<=" => DeclarationGuard {
            max_toolchain_version_exclusive: Some(bound),
            ..DeclarationGuard::default()
        },
        _ => DeclarationGuard::uninterpreted(),
    }
}

/// The target constraint one `sys.platform` comparison places on a block.
///
/// A Python environment's activation target is the interpreter's
/// `sys.platform` value, so the literal the condition names is the target name
/// the guard records.
fn platform_guard(operator: &str, value: Node<'_>, source: &str) -> DeclarationGuard {
    let targets = match operator {
        "==" | "!=" => string_literal(value, source).map(|value| vec![value]),
        "in" | "not in" => string_sequence(value, source),
        _ => None,
    };
    let Some(targets) = targets.filter(|targets| !targets.is_empty()) else {
        return DeclarationGuard::uninterpreted();
    };
    match operator {
        "==" | "in" => DeclarationGuard {
            required_targets: targets,
            ..DeclarationGuard::default()
        },
        _ => DeclarationGuard {
            excluded_targets: targets,
            ..DeclarationGuard::default()
        },
    }
}

/// The version a `(3, 14)` literal names, padded to three components.
fn version_tuple(node: Node<'_>, source: &str) -> Option<GuardVersion> {
    if node.kind() != "tuple" {
        return None;
    }
    let components = named_children(node)
        .map(|child| {
            (child.kind() == "integer")
                .then(|| child.utf8_text(source.as_bytes()).ok()?.parse::<u64>().ok())
                .flatten()
        })
        .collect::<Option<Vec<_>>>()?;
    match components.as_slice() {
        [major] => Some(GuardVersion::new(*major, 0, 0)),
        [major, minor] => Some(GuardVersion::new(*major, *minor, 0)),
        [major, minor, patch] => Some(GuardVersion::new(*major, *minor, *patch)),
        _ => None,
    }
}

/// The text one plain string literal spells.
///
/// The grammar puts a literal's text in a `string_content` child between a
/// `string_start` and a `string_end`. A prefixed literal, an interpolation, and
/// an escape all mean the text is not the value, so each one reads as no
/// literal at all.
fn string_literal(node: Node<'_>, source: &str) -> Option<String> {
    python_plain_string_literal(node, source).map(ToOwned::to_owned)
}

/// The texts one literal sequence of plain strings spells.
fn string_sequence(node: Node<'_>, source: &str) -> Option<Vec<String>> {
    if !matches!(node.kind(), "tuple" | "list" | "set") {
        return None;
    }
    named_children(node)
        .map(|child| string_literal(child, source))
        .collect()
}

fn named_children(node: Node<'_>) -> impl Iterator<Item = Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .collect::<Vec<_>>()
        .into_iter()
}

fn node_identifier(node: Option<Node<'_>>, source: &str) -> Option<String> {
    let node = node?;
    match node.kind() {
        "identifier" => node.utf8_text(source.as_bytes()).ok().map(str::to_owned),
        "typed_parameter" | "default_parameter" | "typed_default_parameter" => {
            node_identifier(node.child_by_field_name("name"), source)
        }
        _ => None,
    }
    .filter(|name| !name.is_empty())
}

fn decorator_names(node: Node<'_>, source: &str) -> Vec<String> {
    named_children(node)
        .filter(|child| child.kind() == "decorator")
        .filter_map(|decorator| decorator.named_child(0))
        .filter_map(|expression| match expression.kind() {
            "identifier" => node_identifier(Some(expression), source),
            "attribute" => expression
                .child_by_field_name("attribute")
                .and_then(|attribute| node_identifier(Some(attribute), source)),
            _ => None,
        })
        .collect()
}

fn is_type_alias_annotation(node: Node<'_>, source: &str) -> bool {
    let mut pending = vec![node];
    while let Some(node) = pending.pop() {
        if node.kind() == "identifier"
            && node_identifier(Some(node), source).as_deref() == Some("TypeAlias")
        {
            return true;
        }
        let mut cursor = node.walk();
        pending.extend(node.named_children(&mut cursor));
    }
    false
}

/// Read one function's declared signature.
///
/// The grammar spells a parameter's binding name as a plain child rather than
/// a `name` field on `typed_parameter` and on the two splat patterns, so the
/// binding is read through the shared parameter-label reader that every other
/// Python surface already uses. A parameter that reads its name from a
/// missing field loses it silently, and an annotated parameter that loses its
/// annotation makes two overloads of one name indistinguishable.
fn function_signature(node: Node<'_>, source: &str, max_depth: usize) -> Option<Signature> {
    let parameters = node.child_by_field_name("parameters")?;
    let parameter_nodes = named_children(parameters).collect::<Vec<_>>();
    let positional_separator = parameter_nodes
        .iter()
        .position(|parameter| parameter.kind() == "positional_separator");
    let keyword_boundary = parameter_nodes.iter().position(|parameter| {
        parameter.kind() == "keyword_separator"
            || python_variadic_parameter_mode(*parameter)
                == Some(ParameterPassingMode::PositionalOnly)
    });
    let mut modeled_parameters = Vec::new();
    for (index, parameter) in parameter_nodes.into_iter().enumerate() {
        let variadic_mode = python_variadic_parameter_mode(parameter);
        let (annotation, optional, variadic) = match parameter.kind() {
            "identifier" => (None, false, false),
            "typed_parameter" => (
                parameter.child_by_field_name("type"),
                false,
                variadic_mode.is_some(),
            ),
            "default_parameter" | "typed_default_parameter" => {
                (parameter.child_by_field_name("type"), true, false)
            }
            "list_splat_pattern" | "dictionary_splat_pattern" => (None, false, true),
            "positional_separator" | "keyword_separator" => continue,
            _ => continue,
        };
        let passing_mode = variadic_mode.unwrap_or_else(|| {
            if positional_separator.is_some_and(|separator| index < separator) {
                ParameterPassingMode::PositionalOnly
            } else if keyword_boundary.is_some_and(|separator| index > separator) {
                ParameterPassingMode::NamedOnly
            } else {
                ParameterPassingMode::PositionalOrNamed
            }
        });
        modeled_parameters.push(Parameter {
            name: brokk_bifrost_python::declarations::python_parameter_label_node(parameter)
                .and_then(|label| node_identifier(Some(label), source)),
            r#type: annotation
                .map(|annotation| type_ref(annotation, source, max_depth))
                .unwrap_or_else(any_type),
            optional,
            variadic,
            passing_mode,
        });
    }
    Some(Signature {
        type_parameters: node
            .child_by_field_name("type_parameters")
            .map(|list| type_parameter_names(list, source))
            .unwrap_or_default(),
        parameters: modeled_parameters,
        returns: node
            .child_by_field_name("return_type")
            .map(|annotation| type_ref(annotation, source, max_depth)),
    })
}

fn python_variadic_parameter_mode(parameter: Node<'_>) -> Option<ParameterPassingMode> {
    let kind = if matches!(
        parameter.kind(),
        "list_splat_pattern" | "dictionary_splat_pattern"
    ) {
        Some(parameter.kind())
    } else {
        named_children(parameter)
            .find(|child| {
                matches!(
                    child.kind(),
                    "list_splat_pattern" | "dictionary_splat_pattern"
                )
            })
            .map(|child| child.kind())
    };
    match kind {
        Some("list_splat_pattern") => Some(ParameterPassingMode::PositionalOnly),
        Some("dictionary_splat_pattern") => Some(ParameterPassingMode::NamedOnly),
        _ => None,
    }
}

/// The names a PEP 695 `[T, S]` type-parameter list declares.
///
/// Every entry is a `type` node, so a declared parameter name comes from the
/// same reader as any other annotation.
fn type_parameter_names(list: Node<'_>, source: &str) -> Vec<String> {
    named_children(list)
        .filter_map(|parameter| type_name(parameter, source))
        .collect()
}

/// Read one type reference.
///
/// Two spellings reach this function. A base-class list or an assignment
/// annotation is an ordinary expression, so `os.PathLike` is an `attribute`
/// and `list[int]` is a `subscript`. A parameter, return, or alias
/// annotation is wrapped in a `type` node and uses the grammar's
/// annotation-only kinds instead, so the same two shapes arrive as
/// `member_type` and `generic_type`. Handling only the expression spelling
/// degrades every annotated parameter and return to `Any`, which erases the
/// difference between two overloads of one name.
fn type_ref(node: Node<'_>, source: &str, max_depth: usize) -> TypeRef {
    if max_depth == 0 {
        return any_type();
    }
    match node.kind() {
        // An annotation wraps its shape in one `type` node. A PEP 695 bound
        // and a `*Ts` unpack wrap the constrained or unpacked type the same
        // way, and the shape is the first named child in each case.
        "type" | "constrained_type" | "splat_type" => node
            .named_child(0)
            .map(|inner| type_ref(inner, source, max_depth - 1))
            .unwrap_or_else(any_type),
        "identifier" => TypeRef::Named {
            name: node_identifier(Some(node), source).unwrap_or_else(|| "Any".to_owned()),
            arguments: Vec::new(),
            nullable: false,
        },
        "attribute" | "member_type" => TypeRef::Named {
            name: type_name(node, source).unwrap_or_else(|| "Any".to_owned()),
            arguments: Vec::new(),
            nullable: false,
        },
        "subscript" => {
            let name = node
                .child_by_field_name("value")
                .map(|value| type_ref(value, source, max_depth - 1));
            let arguments = node
                .child_by_field_name("subscript")
                .map(|argument| {
                    if argument.kind() == "tuple" {
                        named_children(argument)
                            .map(|argument| type_ref(argument, source, max_depth - 1))
                            .collect()
                    } else {
                        vec![type_ref(argument, source, max_depth - 1)]
                    }
                })
                .unwrap_or_default();
            match name {
                Some(TypeRef::Named { name, .. }) => TypeRef::Named {
                    name,
                    arguments,
                    nullable: false,
                },
                _ => any_type(),
            }
        }
        // `list[int]` in an annotation: the generic name comes first and the
        // bracketed arguments follow as one `type_parameter` list.
        "generic_type" => {
            let mut children = named_children(node);
            let name = children
                .next()
                .map(|name| type_ref(name, source, max_depth - 1));
            let arguments = children
                .flat_map(named_children)
                .map(|argument| type_ref(argument, source, max_depth - 1))
                .collect();
            match name {
                Some(TypeRef::Named { name, .. }) => TypeRef::Named {
                    name,
                    arguments,
                    nullable: false,
                },
                _ => any_type(),
            }
        }
        "union_type" => TypeRef::Named {
            name: "Union".to_owned(),
            arguments: named_children(node)
                .map(|child| type_ref(child, source, max_depth - 1))
                .collect(),
            nullable: false,
        },
        "none" => TypeRef::Named {
            name: "None".to_owned(),
            arguments: Vec::new(),
            nullable: true,
        },
        _ => any_type(),
    }
}

/// The dotted name a type reference spells, e.g. `int`, `os.PathLike`, or
/// the `list` of `list[int]`.
///
/// The walk is iterative because an annotation nests its qualifier on the
/// left: `a.b.c` is `member_type(member_type(a, b), c)`.
fn type_name(node: Node<'_>, source: &str) -> Option<String> {
    type_name_segments(node, source).map(|segments| segments.join("."))
}

fn type_name_segments(node: Node<'_>, source: &str) -> Option<Vec<String>> {
    let mut segments = Vec::new();
    let mut current = node;
    loop {
        match current.kind() {
            "identifier" => {
                segments.push(node_identifier(Some(current), source)?);
                break;
            }
            // One wrapper around the shape, and the generic name of a
            // subscripted annotation, are both the first named child.
            "type" | "generic_type" | "subscript" => current = current.named_child(0)?,
            "attribute" => {
                segments.push(node_identifier(
                    current.child_by_field_name("attribute"),
                    source,
                )?);
                current = current.child_by_field_name("object")?;
            }
            // `member_type` carries no fields: its children are the
            // qualifying type and the member identifier, in that order.
            "member_type" => {
                let mut children = named_children(current);
                let qualifier = children.next()?;
                segments.push(node_identifier(children.next(), source)?);
                current = qualifier;
            }
            _ => return None,
        }
    }
    segments.reverse();
    Some(segments)
}

fn any_type() -> TypeRef {
    TypeRef::Named {
        name: "Any".to_owned(),
        arguments: Vec::new(),
        nullable: false,
    }
}

fn python_visibility(name: &str) -> Visibility {
    if name
        .rsplit('.')
        .next()
        .is_some_and(|name| name.starts_with('_') && !name.starts_with("__"))
    {
        Visibility::Private
    } else {
        Visibility::Public
    }
}

const PYTHON_VERSION_FILE_NAME: &str = ".python-version";
const PYPROJECT_FILE_NAME: &str = "pyproject.toml";
const CPYTHON_TOOLCHAIN_NAME: &str = "cpython";
const MAX_PYTHON_TOOLCHAIN_DECLARATION_BYTES: u64 = 256 * 1024;

/// Resolve the standard-library dependency a workspace *declares* rather than
/// installs: an exact `cpython` toolchain pin read from `.python-version` or
/// from `pyproject.toml`'s `requires-python` lower bound (#1869).
///
/// The dependency carries no artifacts on purpose. Preparation serves an
/// artifact-less dependency from a compatible installed pack, so this is what
/// selects the released `bifrost.python-stdlib` typeshed pack the same way an
/// evidence-only `JAVA_HOME` selects the released JDK pack and a declared
/// `rust-toolchain.toml` selects the Rust standard-library pack. No
/// interpreter is discovered or consulted; the declaration files are ordinary
/// workspace files.
fn resolve_declared_python_stdlib_dependency(
    project_root: &Path,
    inputs_considered: &mut usize,
) -> Result<Option<ResolvedDependency>, DependencyPackDiagnostic> {
    let version_file = project_root.join(PYTHON_VERSION_FILE_NAME);
    if let Some(source) = read_bounded_declaration_file(&version_file).map_err(|message| {
        declaration_diagnostic("python.toolchain.version_file", &version_file, message)
    })? {
        *inputs_considered += 1;
        let (version, declared) = parse_python_version_file(&source).map_err(|message| {
            declaration_diagnostic("python.toolchain.version_file", &version_file, message)
        })?;
        return Ok(Some(declared_python_stdlib_dependency(
            version,
            PYTHON_VERSION_FILE_NAME,
            &declared,
        )));
    }
    let pyproject = project_root.join(PYPROJECT_FILE_NAME);
    let Some(source) = read_bounded_declaration_file(&pyproject).map_err(|message| {
        declaration_diagnostic("python.toolchain.requires_python", &pyproject, message)
    })?
    else {
        return Ok(None);
    };
    *inputs_considered += 1;
    let Some(requirement) = parse_pyproject_requires_python(&source).map_err(|message| {
        declaration_diagnostic("python.toolchain.requires_python", &pyproject, message)
    })?
    else {
        return Ok(None);
    };
    let version = requires_python_lower_bound(&requirement).map_err(|message| {
        declaration_diagnostic("python.toolchain.requires_python", &pyproject, message)
    })?;
    Ok(Some(declared_python_stdlib_dependency(
        version,
        PYPROJECT_FILE_NAME,
        &requirement,
    )))
}

fn declaration_diagnostic(
    code: &str,
    location: &Path,
    message: String,
) -> DependencyPackDiagnostic {
    DependencyPackDiagnostic {
        severity: DependencyPackDiagnosticSeverity::Warning,
        code: code.to_owned(),
        dependency_id: None,
        location: Some(location.display().to_string()),
        message,
    }
}

/// Read one workspace toolchain-declaration file. Absent means "the workspace
/// declares nothing here" and is not a diagnostic.
fn read_bounded_declaration_file(path: &Path) -> Result<Option<String>, String> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("could not inspect declaration file: {error}")),
    };
    if !metadata.is_file() || metadata.len() > MAX_PYTHON_TOOLCHAIN_DECLARATION_BYTES {
        return Err(format!(
            "declaration file is not a regular file within {MAX_PYTHON_TOOLCHAIN_DECLARATION_BYTES} bytes"
        ));
    }
    fs::read_to_string(path)
        .map(Some)
        .map_err(|error| format!("could not read declaration file: {error}"))
}

/// Parse the first declared line of a `.python-version` file into an exact
/// cpython version. The pyenv/uv convention allows comments and multiple
/// lines; only the first declaration decides, and only a plain numeric
/// `MAJOR.MINOR[.PATCH]` is an interpretable cpython pin. Implementation
/// prefixes (`pypy3.10`), suffixes (`3.13-dev`), and anything else stay an
/// attributable refusal rather than a guessed toolchain.
fn parse_python_version_file(source: &str) -> Result<(Version, String), String> {
    let declared = source
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .ok_or_else(|| "`.python-version` declares no version line".to_owned())?;
    let version = parse_exact_cpython_version(declared).ok_or_else(|| {
        format!(
            "`.python-version` declaration {declared:?} is not an exact cpython version \
             (expected MAJOR.MINOR or MAJOR.MINOR.PATCH)"
        )
    })?;
    Ok((version, declared.to_owned()))
}

/// Parse a plain dotted numeric version with two or three components. A
/// missing patch component means `.0`: declaring `3.12` pins the interpreter
/// line's floor, which is the only version the declaration proves.
fn parse_exact_cpython_version(text: &str) -> Option<Version> {
    let mut components = text.split('.').map(|component| {
        (!component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| component.parse::<u64>().ok())
            .flatten()
    });
    let major = components.next().flatten()?;
    let minor = components.next().flatten()?;
    let patch = match components.next() {
        Some(patch) => patch?,
        None => 0,
    };
    components
        .next()
        .is_none()
        .then(|| Version::new(major, minor, patch))
}

/// Extract `[project] requires-python` from `pyproject.toml` source. An
/// absent table or field is `Ok(None)`: the workspace declares nothing.
fn parse_pyproject_requires_python(source: &str) -> Result<Option<String>, String> {
    #[derive(serde::Deserialize)]
    struct PyProjectDocument {
        project: Option<PyProjectSection>,
    }
    #[derive(serde::Deserialize)]
    struct PyProjectSection {
        #[serde(rename = "requires-python")]
        requires_python: Option<String>,
    }
    let document: PyProjectDocument = toml::from_str(source)
        .map_err(|error| format!("could not decode pyproject.toml: {error}"))?;
    Ok(document.project.and_then(|project| project.requires_python))
}

/// Pin the provable inclusive lower bound of a `requires-python` specifier
/// list. `>=X.Y[.Z]` and `~=X.Y[.Z]` state it directly, and `==X.Y[.Z]` or
/// `==X.Y.*` pin it exactly; upper bounds (`<`, `<=`) and exclusions (`!=`)
/// never lower it and pass through uninterpreted. Any clause this cannot
/// read exactly refuses the whole declaration: a guessed pin would let the
/// pack prove a declaration absent for an interpreter the workspace supports.
fn requires_python_lower_bound(requirement: &str) -> Result<Version, String> {
    let mut lower: Option<Version> = None;
    for clause in requirement.split(',') {
        let clause = clause.trim();
        let bound = if let Some(rest) = clause
            .strip_prefix(">=")
            .or_else(|| clause.strip_prefix("~="))
        {
            Some(parse_exact_cpython_version(rest.trim()).ok_or_else(|| {
                format!("requires-python clause {clause:?} does not state an exact lower bound")
            })?)
        } else if let Some(rest) = clause.strip_prefix("==") {
            let rest = rest.trim();
            let exact = rest.strip_suffix(".*").unwrap_or(rest);
            Some(parse_exact_cpython_version(exact).ok_or_else(|| {
                format!("requires-python clause {clause:?} does not state an exact version")
            })?)
        } else if clause.starts_with("<=") || clause.starts_with('<') || clause.starts_with("!=") {
            None
        } else {
            return Err(format!(
                "requires-python clause {clause:?} is not an interpretable version specifier"
            ));
        };
        if let Some(bound) = bound
            && lower.as_ref().is_none_or(|current| bound > *current)
        {
            lower = Some(bound);
        }
    }
    lower.ok_or_else(|| {
        format!("requires-python {requirement:?} declares no provable inclusive lower bound")
    })
}

fn declared_python_stdlib_dependency(
    version: Version,
    source_file: &str,
    declared: &str,
) -> ResolvedDependency {
    ResolvedDependency {
        id: format!("python:stdlib:declared:cpython:{version}"),
        evidence: SemanticModelActivationEvidence {
            language: "python".to_owned(),
            ecosystem: "python".to_owned(),
            package: None,
            module: None,
            toolchain: Some(CatalogCoordinate {
                name: CPYTHON_TOOLCHAIN_NAME.to_owned(),
                version: Some(version.clone()),
            }),
            // The workspace declares a version, not a platform. Leaving the
            // target unpinned keeps platform-guarded declarations active and
            // read-incomplete instead of provably dropped, per the pack's
            // one-way honesty rule (semantic-packs/python/README.md).
            target: None,
            configuration: None,
            artifact_sha256: None,
        },
        provenance: vec![
            DependencyProvenance {
                key: "python.toolchain_declaration".to_owned(),
                value: source_file.to_owned(),
            },
            DependencyProvenance {
                key: "python.declared_requirement".to_owned(),
                value: declared.to_owned(),
            },
            DependencyProvenance {
                key: "python.pinned_version".to_owned(),
                value: version.to_string(),
            },
        ],
        artifacts: Vec::new(),
        scope: DependencyScope::Unknown,
        declared_by: None,
    }
}

/// The discovery outcome for a workspace with no configured Python
/// environment: the declared-toolchain route alone (#1869). A workspace that
/// declares nothing resolves nothing and stays complete, exactly as before.
fn resolve_declared_python_stdlib_outcome(project: &dyn Project) -> DependencyDiscoveryOutcome {
    let mut outcome = DependencyDiscoveryOutcome::complete(Vec::new());
    match resolve_declared_python_stdlib_dependency(
        project.root(),
        &mut outcome.profile.metadata_inputs_considered,
    ) {
        Ok(Some(dependency)) => {
            outcome.dependencies.push(dependency);
            outcome.profile.dependencies_resolved = 1;
        }
        Ok(None) => {}
        Err(diagnostic) => {
            outcome.diagnostics.push(diagnostic);
            outcome.complete = false;
        }
    }
    outcome
}

/// Resolve configured Python standard-library, bundled-stub, and installed
/// distribution files without using the interpreter, `sys.path`, `.pth`, or a
/// package manager. A disabled Python environment intentionally resolves no
/// environment dependencies; the workspace-declared toolchain route
/// ([`resolve_declared_python_stdlib_dependency`]) still runs so an installed
/// standard-library pack can activate by default. An explicitly configured
/// environment supersedes the declaration: it pins the interpreter exactly
/// and produces the stdlib pack from the interpreter's own stubs.
pub fn resolve_python_semantic_pack_dependencies(
    config: &PythonAnalyzerConfig,
    project: &dyn Project,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> DependencyDiscoveryOutcome {
    let Some(environment) = &config.environment else {
        return resolve_declared_python_stdlib_outcome(project);
    };
    let mut state = DiscoveryState::new(environment, limits);
    if state.cancelled(cancellation) {
        return state.cancelled_outcome();
    }

    let standard_library_root =
        match state.resolve_root(project.root(), &environment.standard_library_root, "stdlib") {
            Some(root) => root,
            None => return state.outcome(Vec::new()),
        };
    let standard_library = state.collect_dependency(
        "python:stdlib",
        None,
        "stdlib",
        &standard_library_root,
        cancellation,
    );

    let mut dependencies = standard_library.into_iter().collect::<Vec<_>>();
    for (index, root) in environment.bundled_stub_roots.iter().enumerate() {
        if state.cancelled(cancellation) {
            return state.cancelled_outcome();
        }
        let Some(root) = state.resolve_root(project.root(), root, "bundled_stub") else {
            continue;
        };
        if let Some(dependency) = state.collect_dependency(
            &format!("python:bundled-stubs:{index}"),
            None,
            "bundled_stub",
            &root,
            cancellation,
        ) {
            dependencies.push(dependency);
        }
    }
    for root in &environment.distribution_roots {
        if state.cancelled(cancellation) {
            return state.cancelled_outcome();
        }
        let Some(root) = state.resolve_root(project.root(), root, "distribution") else {
            continue;
        };
        dependencies.extend(state.collect_distributions(&root, cancellation));
    }
    state.apply_precedence(&mut dependencies);
    dependencies.sort_by(|left, right| left.id.cmp(&right.id));
    dependencies.dedup_by(|left, right| left.id == right.id && left.artifacts == right.artifacts);
    if dependencies.len() > limits.max_dependencies {
        state.error(
            "limit.dependencies",
            None,
            None,
            format!(
                "Python environment discovery exceeded dependency limit {}",
                limits.max_dependencies
            ),
        );
        dependencies.truncate(limits.max_dependencies);
    }
    state.outcome(dependencies)
}

struct DiscoveryState<'a> {
    environment: &'a PythonEnvironmentConfig,
    limits: &'a DependencyPackLimits,
    diagnostics: Vec<DependencyPackDiagnostic>,
    suppressed_diagnostics: SuppressedDiagnostics,
    metadata_inputs_considered: usize,
    directories_considered: usize,
    candidate_bytes: u64,
    incomplete: bool,
}

impl<'a> DiscoveryState<'a> {
    fn new(environment: &'a PythonEnvironmentConfig, limits: &'a DependencyPackLimits) -> Self {
        Self {
            environment,
            limits,
            diagnostics: Vec::new(),
            suppressed_diagnostics: SuppressedDiagnostics::default(),
            metadata_inputs_considered: 0,
            directories_considered: 0,
            candidate_bytes: 0,
            incomplete: false,
        }
    }

    fn cancelled(&self, cancellation: Option<&CancellationToken>) -> bool {
        cancellation.is_some_and(CancellationToken::is_cancelled)
    }

    fn cancelled_outcome(mut self) -> DependencyDiscoveryOutcome {
        self.error(
            "discovery.cancelled",
            None,
            None,
            "Python environment discovery was cancelled".to_owned(),
        );
        DependencyDiscoveryOutcome {
            dependencies: Vec::new(),
            diagnostics: self.diagnostics,
            suppressed_diagnostics: self.suppressed_diagnostics,
            complete: false,
            cancelled: true,
            profile: DependencyDiscoveryProfile {
                metadata_inputs_considered: self.metadata_inputs_considered,
                dependencies_resolved: 0,
            },
        }
    }

    fn outcome(self, dependencies: Vec<ResolvedDependency>) -> DependencyDiscoveryOutcome {
        DependencyDiscoveryOutcome {
            profile: DependencyDiscoveryProfile {
                metadata_inputs_considered: self.metadata_inputs_considered,
                dependencies_resolved: dependencies.len(),
            },
            complete: !self.incomplete && self.suppressed_diagnostics.total() == 0,
            dependencies,
            diagnostics: self.diagnostics,
            suppressed_diagnostics: self.suppressed_diagnostics,
            cancelled: false,
        }
    }

    fn resolve_root(
        &mut self,
        project_root: &Path,
        configured: &Path,
        role: &str,
    ) -> Option<PathBuf> {
        let path = if configured.is_absolute() {
            configured.to_path_buf()
        } else {
            project_root.join(configured)
        };
        let root = match path.canonicalize() {
            Ok(root) if root.is_dir() => root,
            Ok(_) => {
                self.error(
                    "python.environment_root",
                    None,
                    Some(&path),
                    format!("configured {role} root is not a directory"),
                );
                return None;
            }
            Err(error) => {
                self.error(
                    "python.environment_root",
                    None,
                    Some(&path),
                    format!("could not inspect configured {role} root: {error}"),
                );
                return None;
            }
        };
        Some(root)
    }

    fn collect_distributions(
        &mut self,
        root: &Path,
        cancellation: Option<&CancellationToken>,
    ) -> Vec<ResolvedDependency> {
        let entries = match sorted_directory_entries(root) {
            Ok(entries) => entries,
            Err(error) => {
                self.error(
                    "python.distribution_root",
                    None,
                    Some(root),
                    format!("could not list configured distribution root: {error}"),
                );
                return Vec::new();
            }
        };
        let mut dependencies = Vec::new();
        for metadata in entries
            .into_iter()
            .filter(|path| is_distribution_metadata(path))
        {
            if self.cancelled(cancellation) {
                break;
            }
            if dependencies.len() >= self.environment.limits.max_distributions {
                self.error(
                    "limit.distributions",
                    None,
                    Some(root),
                    format!(
                        "Python environment exceeds distribution limit {}",
                        self.environment.limits.max_distributions
                    ),
                );
                break;
            }
            self.metadata_inputs_considered += 1;
            let Some((name, version)) = self.distribution_identity(&metadata) else {
                continue;
            };
            let package_roots = self.distribution_package_roots(root, &metadata, &name);
            if package_roots.is_empty() {
                self.error(
                    "python.distribution_artifacts",
                    Some(&name),
                    Some(&metadata),
                    "distribution metadata did not identify an importable package or module"
                        .to_owned(),
                );
                continue;
            }
            let mut artifacts = Vec::new();
            let typed = package_roots.iter().any(|path| {
                path.file_name().is_some_and(|name| name == "py.typed")
                    || path.join("py.typed").is_file()
            });
            for package_root in package_roots {
                let mut discovered = self.collect_artifacts(&package_root, root, cancellation);
                let remaining = self
                    .environment
                    .limits
                    .max_files_per_distribution
                    .saturating_sub(artifacts.len());
                if discovered.len() > remaining {
                    self.error(
                        "limit.files_per_distribution",
                        Some(&name),
                        Some(&package_root),
                        format!(
                            "Python distribution exceeds file limit {}",
                            self.environment.limits.max_files_per_distribution
                        ),
                    );
                    discovered.truncate(remaining);
                }
                artifacts.extend(discovered);
                if artifacts.len() == self.environment.limits.max_files_per_distribution {
                    break;
                }
            }
            if artifacts.is_empty() {
                self.error(
                    "python.distribution_artifacts",
                    Some(&name),
                    Some(&metadata),
                    "distribution contains no supported .pyi or .py artifacts".to_owned(),
                );
                continue;
            }
            artifacts.sort_by(|left, right| {
                (&left.module, artifact_kind_rank(left.kind), left.path()).cmp(&(
                    &right.module,
                    artifact_kind_rank(right.kind),
                    right.path(),
                ))
            });
            artifacts.dedup();
            let source_kind = if is_stub_only_distribution_name(&name) {
                "stub_only_distribution"
            } else if typed {
                "inline_py_typed"
            } else {
                "implementation_source"
            };
            dependencies.push(self.dependency(
                format!("python:distribution:{name}:{version}"),
                Some((name, version)),
                source_kind,
                artifacts,
            ));
        }
        dependencies
    }

    fn distribution_identity(&mut self, metadata: &Path) -> Option<(String, String)> {
        let metadata_file = metadata.join("METADATA");
        let source = match read_bounded(&metadata_file, self.environment.limits.max_metadata_bytes)
        {
            Ok(source) => source,
            Err(error) => {
                self.error(
                    "python.distribution_metadata",
                    None,
                    Some(&metadata_file),
                    error,
                );
                return None;
            }
        };
        let Some(name) = metadata_header(&source, "Name") else {
            self.error(
                "python.distribution_metadata",
                None,
                Some(&metadata_file),
                "METADATA is missing Name".to_owned(),
            );
            return None;
        };
        let Some(version) = metadata_header(&source, "Version") else {
            self.error(
                "python.distribution_metadata",
                Some(&name),
                Some(&metadata_file),
                "METADATA is missing Version".to_owned(),
            );
            return None;
        };
        Some((normalize_distribution_name(&name), version))
    }

    fn distribution_package_roots(
        &mut self,
        root: &Path,
        metadata: &Path,
        name: &str,
    ) -> Vec<PathBuf> {
        let record = metadata.join("RECORD");
        if record.is_file()
            && let Ok(contents) = read_bounded(&record, self.environment.limits.max_metadata_bytes)
        {
            let mut artifacts = contents
                .lines()
                .filter_map(|line| line.split_once(',').map(|(path, _)| path))
                .map(PathBuf::from)
                .filter(|path| python_artifact_kind(path).is_some() || path.ends_with("py.typed"))
                .map(|path| root.join(path))
                .filter(|path| path.is_file())
                .collect::<Vec<_>>();
            artifacts.sort();
            artifacts.dedup();
            if !artifacts.is_empty() {
                return artifacts;
            }
        }
        let top_level = metadata.join("top_level.txt");
        let names = read_bounded(&top_level, self.environment.limits.max_metadata_bytes)
            .ok()
            .map(|contents| {
                contents
                    .lines()
                    .map(str::trim)
                    .filter(|value| {
                        !value.is_empty()
                            && value
                                .chars()
                                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
                    })
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .filter(|names| !names.is_empty())
            .unwrap_or_else(|| vec![name.replace('-', "_")]);
        let mut roots = Vec::new();
        for name in names {
            let package = root.join(&name);
            let module = root.join(format!("{name}.pyi"));
            let source_module = root.join(format!("{name}.py"));
            if package.is_dir() {
                roots.push(package);
            } else if module.is_file() {
                roots.push(module);
            } else if source_module.is_file() {
                roots.push(source_module);
            }
        }
        roots.sort();
        roots.dedup();
        roots
    }

    fn collect_dependency(
        &mut self,
        id_prefix: &str,
        package: Option<(String, String)>,
        source_kind: &str,
        root: &Path,
        cancellation: Option<&CancellationToken>,
    ) -> Option<ResolvedDependency> {
        let artifacts = self.collect_artifacts(root, root, cancellation);
        (!artifacts.is_empty()).then(|| {
            let id = match &package {
                Some((name, version)) => format!("{id_prefix}:{name}:{version}"),
                None => format!(
                    "{id_prefix}:{}:{}",
                    self.environment.implementation, self.environment.version
                ),
            };
            self.dependency(id, package, source_kind, artifacts)
        })
    }

    fn collect_artifacts(
        &mut self,
        root: &Path,
        import_root: &Path,
        cancellation: Option<&CancellationToken>,
    ) -> Vec<ResolvedDependencyArtifact> {
        let root = match root.canonicalize() {
            Ok(root) => root,
            Err(error) => {
                self.error(
                    "python.artifact_root",
                    None,
                    Some(root),
                    format!("could not canonicalize artifact root: {error}"),
                );
                return Vec::new();
            }
        };
        let import_root = match import_root.canonicalize() {
            Ok(root) => root,
            Err(error) => {
                self.error(
                    "python.import_root",
                    None,
                    Some(import_root),
                    format!("could not canonicalize Python import root: {error}"),
                );
                return Vec::new();
            }
        };
        if root.is_file() {
            let Some(kind) = python_artifact_kind(&root) else {
                return Vec::new();
            };
            let metadata = match root.metadata() {
                Ok(metadata) => metadata,
                Err(error) => {
                    self.error(
                        "python.artifact_metadata",
                        None,
                        Some(&root),
                        format!("could not inspect artifact candidate: {error}"),
                    );
                    return Vec::new();
                }
            };
            self.candidate_bytes = self.candidate_bytes.saturating_add(metadata.len());
            if self.candidate_bytes > self.environment.limits.max_total_candidate_bytes {
                self.error(
                    "limit.candidate_bytes",
                    None,
                    Some(&root),
                    format!(
                        "Python environment candidates exceed byte limit {}",
                        self.environment.limits.max_total_candidate_bytes
                    ),
                );
                return Vec::new();
            }
            let Some(module) = python_module_name_from_import_root(&import_root, &root) else {
                self.error(
                    "python.artifact_module",
                    None,
                    Some(&root),
                    "artifact path cannot be represented as a Python import module".to_owned(),
                );
                return Vec::new();
            };
            return vec![ResolvedDependencyArtifact::module_file(
                artifact_role(kind),
                kind,
                module,
                root,
            )];
        }
        let mut pending = vec![root.clone()];
        let mut artifacts = Vec::new();
        while let Some(directory) = pending.pop() {
            if self.cancelled(cancellation) {
                break;
            }
            self.directories_considered += 1;
            if self.directories_considered > self.environment.limits.max_directories {
                self.error(
                    "limit.directories",
                    None,
                    Some(&root),
                    format!(
                        "Python environment exceeds directory limit {}",
                        self.environment.limits.max_directories
                    ),
                );
                break;
            }
            let entries = match sorted_directory_entries(&directory) {
                Ok(entries) => entries,
                Err(error) => {
                    self.error(
                        "python.artifact_directory",
                        None,
                        Some(&directory),
                        format!("could not list artifact directory: {error}"),
                    );
                    continue;
                }
            };
            for entry in entries {
                if self.cancelled(cancellation) {
                    break;
                }
                let metadata = match fs::symlink_metadata(&entry) {
                    Ok(metadata) => metadata,
                    Err(error) => {
                        self.error(
                            "python.artifact_metadata",
                            None,
                            Some(&entry),
                            format!("could not inspect artifact candidate: {error}"),
                        );
                        continue;
                    }
                };
                if metadata.file_type().is_symlink() {
                    let Ok(target) = entry.canonicalize() else {
                        self.error(
                            "python.artifact_symlink",
                            None,
                            Some(&entry),
                            "could not resolve artifact symlink".to_owned(),
                        );
                        continue;
                    };
                    if !target.starts_with(&root) {
                        self.error(
                            "python.artifact_symlink",
                            None,
                            Some(&entry),
                            "artifact symlink escapes its configured root".to_owned(),
                        );
                    }
                    continue;
                }
                if metadata.is_dir() {
                    pending.push(entry);
                    continue;
                }
                if !metadata.is_file()
                    || artifacts.len() >= self.environment.limits.max_files_per_distribution
                {
                    continue;
                }
                let Some(kind) = python_artifact_kind(&entry) else {
                    continue;
                };
                self.candidate_bytes = self.candidate_bytes.saturating_add(metadata.len());
                if self.candidate_bytes > self.environment.limits.max_total_candidate_bytes {
                    self.error(
                        "limit.candidate_bytes",
                        None,
                        Some(&entry),
                        format!(
                            "Python environment candidates exceed byte limit {}",
                            self.environment.limits.max_total_candidate_bytes
                        ),
                    );
                    return artifacts;
                }
                let Some(module) = python_module_name_from_import_root(&import_root, &entry) else {
                    self.error(
                        "python.artifact_module",
                        None,
                        Some(&entry),
                        "artifact path cannot be represented as a Python import module".to_owned(),
                    );
                    continue;
                };
                artifacts.push(ResolvedDependencyArtifact::module_file(
                    artifact_role(kind),
                    kind,
                    module,
                    entry,
                ));
            }
        }
        artifacts.sort_by(|left, right| {
            (&left.module, artifact_kind_rank(left.kind), left.path()).cmp(&(
                &right.module,
                artifact_kind_rank(right.kind),
                right.path(),
            ))
        });
        artifacts
    }

    fn apply_precedence(&mut self, dependencies: &mut Vec<ResolvedDependency>) {
        use std::collections::{HashMap, HashSet};

        let mut winners = HashMap::<String, (usize, usize, PathBuf)>::new();
        let mut conflicts = HashSet::new();
        for (dependency_index, dependency) in dependencies.iter().enumerate() {
            let source_kind = dependency
                .provenance
                .iter()
                .find(|entry| entry.key == "source_kind")
                .map(|entry| entry.value.as_str());
            for artifact in &dependency.artifacts {
                let Some(module) = artifact.module.as_ref() else {
                    continue;
                };
                let candidate = (
                    python_artifact_precedence(source_kind, artifact.kind),
                    dependency_index,
                    artifact.path().to_owned(),
                );
                let replace = winners.get(module).is_none_or(|winner| {
                    candidate.0 > winner.0
                        || (candidate.0 == winner.0
                            && (candidate.1, &candidate.2) < (winner.1, &winner.2))
                });
                if winners
                    .get(module)
                    .is_some_and(|winner| candidate.0 == winner.0 && candidate.2 != winner.2)
                {
                    conflicts.insert(module.clone());
                }
                if replace {
                    winners.insert(module.clone(), candidate);
                }
            }
        }
        for module in conflicts {
            self.error(
                "python.precedence_conflict",
                None,
                None,
                format!(
                    "multiple equal-precedence Python artifacts provide module {module}; selected a deterministic winner"
                ),
            );
        }
        for (dependency_index, dependency) in dependencies.iter_mut().enumerate() {
            let source_kind = dependency
                .provenance
                .iter()
                .find(|entry| entry.key == "source_kind")
                .map(|entry| entry.value.clone());
            dependency.artifacts.retain(|artifact| {
                let Some(module) = artifact.module.as_ref() else {
                    return false;
                };
                let Some(winner) = winners.get(module) else {
                    return false;
                };
                (
                    python_artifact_precedence(source_kind.as_deref(), artifact.kind),
                    dependency_index,
                    artifact.path(),
                ) == (winner.0, winner.1, &winner.2)
            });
        }
        dependencies.retain(|dependency| !dependency.artifacts.is_empty());
    }

    fn dependency(
        &self,
        id: String,
        package: Option<(String, String)>,
        source_kind: &str,
        artifacts: Vec<ResolvedDependencyArtifact>,
    ) -> ResolvedDependency {
        let package = package.map(|(name, version)| CatalogCoordinate {
            name,
            version: Version::parse(&version).ok(),
        });
        ResolvedDependency {
            id,
            evidence: SemanticModelActivationEvidence {
                language: "python".to_owned(),
                ecosystem: "python".to_owned(),
                package,
                module: None,
                toolchain: Some(CatalogCoordinate {
                    name: self.environment.implementation.clone(),
                    version: Version::parse(&self.environment.version).ok(),
                }),
                target: Some(self.environment.platform.clone()),
                configuration: None,
                artifact_sha256: None,
            },
            provenance: vec![
                DependencyProvenance {
                    key: "python_implementation".to_owned(),
                    value: self.environment.implementation.clone(),
                },
                DependencyProvenance {
                    key: "python_version".to_owned(),
                    value: self.environment.version.clone(),
                },
                DependencyProvenance {
                    key: "platform".to_owned(),
                    value: self.environment.platform.clone(),
                },
                DependencyProvenance {
                    key: "source_kind".to_owned(),
                    value: source_kind.to_owned(),
                },
            ],
            artifacts,
            scope: DependencyScope::Unknown,
            declared_by: None,
        }
    }

    fn error(
        &mut self,
        code: &str,
        dependency_id: Option<&str>,
        location: Option<&Path>,
        message: String,
    ) {
        self.incomplete = true;
        if self.diagnostics.len()
            >= self
                .environment
                .limits
                .max_diagnostics
                .min(self.limits.max_diagnostics)
        {
            self.suppressed_diagnostics.errors =
                self.suppressed_diagnostics.errors.saturating_add(1);
            return;
        }
        self.diagnostics.push(DependencyPackDiagnostic {
            severity: DependencyPackDiagnosticSeverity::Error,
            code: code.to_owned(),
            dependency_id: dependency_id.map(str::to_owned),
            location: location.map(|path| path.display().to_string()),
            message: bounded_message(
                message,
                self.environment
                    .limits
                    .max_diagnostic_message_bytes
                    .min(self.limits.max_diagnostic_message_bytes),
            ),
        });
    }
}

fn sorted_directory_entries(path: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut entries = fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort();
    Ok(entries)
}

fn is_distribution_metadata(path: &Path) -> bool {
    path.is_dir()
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".dist-info") || name.ends_with(".egg-info"))
}

fn python_artifact_kind(path: &Path) -> Option<ExternalArtifactKind> {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("pyi") => Some(ExternalArtifactKind::PythonStub),
        Some("py") => Some(ExternalArtifactKind::PythonSource),
        _ => None,
    }
}

fn artifact_kind_rank(kind: ExternalArtifactKind) -> u8 {
    match kind {
        ExternalArtifactKind::PythonStub => 0,
        ExternalArtifactKind::PythonSource => 1,
        _ => unreachable!("Python discovery only returns Python artifact kinds"),
    }
}

fn artifact_role(kind: ExternalArtifactKind) -> DependencyArtifactRole {
    match kind {
        ExternalArtifactKind::PythonStub => DependencyArtifactRole::Reference,
        ExternalArtifactKind::PythonSource => DependencyArtifactRole::Sources,
        _ => unreachable!("Python discovery only returns Python artifact kinds"),
    }
}

fn metadata_header(metadata: &str, name: &str) -> Option<String> {
    metadata.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.eq_ignore_ascii_case(name) && !value.trim().is_empty())
            .then(|| value.trim().to_owned())
    })
}

fn normalize_distribution_name(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace(['_', '.'], "-")
}

fn is_stub_only_distribution_name(name: &str) -> bool {
    name.starts_with("types-") || name.ends_with("-stubs")
}

fn read_bounded(path: &Path, max_bytes: u64) -> Result<String, String> {
    let metadata = path
        .metadata()
        .map_err(|error| format!("could not inspect metadata: {error}"))?;
    if metadata.len() > max_bytes {
        return Err(format!("metadata exceeds byte limit {max_bytes}"));
    }
    fs::read_to_string(path).map_err(|error| format!("could not read metadata: {error}"))
}

fn bounded_message(mut message: String, limit: usize) -> String {
    if message.len() > limit {
        message.truncate(limit);
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic_model::{CompilerOptions, compile_pack, read_exact_source_set};
    use tempfile::{TempDir, tempdir};

    #[test]
    fn version_file_declarations_pin_exact_cpython_versions() {
        let (version, declared) = parse_python_version_file("3.12.4\n").unwrap();
        assert_eq!(version, Version::new(3, 12, 4));
        assert_eq!(declared, "3.12.4");
        let (version, _) = parse_python_version_file("# team default\n\n3.11\n3.9\n").unwrap();
        assert_eq!(version, Version::new(3, 11, 0), "first declaration decides");
        for refused in ["pypy3.10", "3.13-dev", "cpython-3.12", "3", "3.12.4.1", ""] {
            assert!(
                parse_python_version_file(refused).is_err(),
                "{refused:?} must not pin a cpython version"
            );
        }
    }

    #[test]
    fn requires_python_pins_the_provable_inclusive_lower_bound() {
        assert_eq!(
            requires_python_lower_bound(">=3.10").unwrap(),
            Version::new(3, 10, 0)
        );
        assert_eq!(
            requires_python_lower_bound(">=3.10.2, <3.15").unwrap(),
            Version::new(3, 10, 2)
        );
        assert_eq!(
            requires_python_lower_bound("~=3.11.1").unwrap(),
            Version::new(3, 11, 1)
        );
        assert_eq!(
            requires_python_lower_bound("==3.12.*").unwrap(),
            Version::new(3, 12, 0)
        );
        assert_eq!(
            requires_python_lower_bound(">=3.9, >=3.10, !=3.10.1").unwrap(),
            Version::new(3, 10, 0),
            "the strictest lower bound wins"
        );
        for refused in [">3.9", ">=3.*", "<3.13", ">=3.10rc1", "3.10", ""] {
            assert!(
                requires_python_lower_bound(refused).is_err(),
                "{refused:?} must refuse rather than guess a pin"
            );
        }
    }

    #[test]
    fn declared_toolchain_discovery_reads_version_file_before_pyproject() {
        let root = tempdir().unwrap();
        std::fs::write(
            root.path().join("pyproject.toml"),
            "[project]\nname = \"fixture\"\nrequires-python = \">=3.10\"\n",
        )
        .unwrap();
        let mut inputs = 0;
        let dependency = resolve_declared_python_stdlib_dependency(root.path(), &mut inputs)
            .unwrap()
            .expect("requires-python declares a toolchain");
        assert_eq!(dependency.id, "python:stdlib:declared:cpython:3.10.0");
        let toolchain = dependency.evidence.toolchain.as_ref().unwrap();
        assert_eq!(toolchain.name, "cpython");
        assert_eq!(toolchain.version, Some(Version::new(3, 10, 0)));
        assert_eq!(dependency.evidence.target, None);
        assert!(dependency.artifacts.is_empty());

        std::fs::write(root.path().join(".python-version"), "3.12.1\n").unwrap();
        let mut inputs = 0;
        let dependency = resolve_declared_python_stdlib_dependency(root.path(), &mut inputs)
            .unwrap()
            .expect(".python-version declares a toolchain");
        assert_eq!(
            dependency.id, "python:stdlib:declared:cpython:3.12.1",
            "the exact version file wins over the pyproject range"
        );
    }

    #[test]
    fn undeclared_and_uninterpretable_toolchains_stay_honest() {
        let root = tempdir().unwrap();
        let mut inputs = 0;
        assert_eq!(
            resolve_declared_python_stdlib_dependency(root.path(), &mut inputs).unwrap(),
            None,
            "a workspace declaring nothing resolves nothing"
        );
        std::fs::write(
            root.path().join("pyproject.toml"),
            "[project]\nname = \"fixture\"\n",
        )
        .unwrap();
        let mut inputs = 0;
        assert_eq!(
            resolve_declared_python_stdlib_dependency(root.path(), &mut inputs).unwrap(),
            None,
            "a pyproject without requires-python declares nothing"
        );
        std::fs::write(root.path().join(".python-version"), "pypy3.10\n").unwrap();
        let mut inputs = 0;
        let diagnostic =
            resolve_declared_python_stdlib_dependency(root.path(), &mut inputs).unwrap_err();
        assert_eq!(diagnostic.code, "python.toolchain.version_file");
        assert_eq!(
            diagnostic.severity,
            DependencyPackDiagnosticSeverity::Warning
        );
        assert!(diagnostic.message.contains("pypy3.10"), "{diagnostic:#?}");
    }

    #[test]
    fn source_set_resolves_present_imported_hierarchy_and_keeps_external_named() {
        let fixture = tempdir().unwrap();
        std::fs::write(fixture.path().join("base.pyi"), "class Base: ...\n").unwrap();
        std::fs::write(
            fixture.path().join("derived.pyi"),
            "from base import Base\nfrom absent import Missing\n\nclass Derived(Base): ...\nclass External(Missing): ...\n",
        )
        .unwrap();
        let artifact = read_exact_source_set(
            fixture.path(),
            &["base.pyi".into(), "derived.pyi".into()],
            32,
            16,
            &ArtifactProducerLimits::default(),
        )
        .unwrap();
        let production = PythonArtifactPackProducer.produce_loaded_source_set(
            &ArtifactProductionRequest {
                path: fixture.path().to_owned(),
                artifact_kind: ExternalArtifactKind::PythonStub,
                pack_id: "python-hierarchy-fixture".to_owned(),
                pack_version: "1.0.0".to_owned(),
                ecosystem: "python".to_owned(),
                compatibility: Compatibility {
                    bifrost: format!("={}", env!("CARGO_PKG_VERSION")),
                    toolchains: Vec::new(),
                },
                activation: vec![ActivationSelector {
                    package: None,
                    module: None,
                    toolchain: None,
                    targets: Vec::new(),
                    configurations: Vec::new(),
                    artifact_sha256: None,
                }],
                provenance: Provenance {
                    source: "fixture".to_owned(),
                    revision: None,
                },
                license: "Apache-2.0".to_owned(),
                safety: Safety {
                    generated_code_only: false,
                    review_required: false,
                },
            },
            &ArtifactProducerLimits::default(),
            None,
            &artifact,
        );
        assert!(
            production.diagnostics.is_empty(),
            "{:#?}",
            production.diagnostics
        );
        assert_eq!(
            production
                .pack
                .as_ref()
                .unwrap()
                .shards
                .first()
                .unwrap()
                .activation[0]
                .artifact_sha256,
            None,
            "a source-set digest is provenance, not workspace activation evidence"
        );
        let pack = production.pack.unwrap();
        let derived = pack
            .shards
            .first()
            .and_then(|shard| match &shard.payload {
                AuthoredPayload::DeclarationFacts { types, .. } => {
                    types.iter().find(|fact| fact.name == "derived.Derived")
                }
                _ => None,
            })
            .unwrap();
        assert!(
            matches!(derived.hierarchy[0].target, TypeRef::Declared { .. }),
            "derived hierarchy: {:?}",
            derived.hierarchy
        );
        let external = match &pack.shards[0].payload {
            AuthoredPayload::DeclarationFacts { types, .. } => types
                .iter()
                .find(|fact| fact.name == "derived.External")
                .unwrap(),
            _ => unreachable!(),
        };
        assert!(matches!(
            external.hierarchy[0].target,
            TypeRef::Named { ref name, .. } if name == "absent.Missing"
        ));
        compile_pack(&pack, &CompilerOptions::default()).unwrap();
    }

    fn source_set_rejection_fixture() -> (TempDir, ExactArtifact) {
        let fixture = tempdir().unwrap();
        std::fs::create_dir_all(fixture.path().join("pkg")).unwrap();
        std::fs::write(fixture.path().join("__init__.pyi"), "class RootOnly: ...\n").unwrap();
        std::fs::write(
            fixture.path().join("pkg/__init__.pyi"),
            "class Widget: ...\n",
        )
        .unwrap();
        std::fs::write(fixture.path().join("pkg/bad.pyi"), [0xff, 0xfe, 0x00, 0x01]).unwrap();
        let artifact = read_exact_source_set(
            fixture.path(),
            &[
                "__init__.pyi".into(),
                "pkg/__init__.pyi".into(),
                "pkg/bad.pyi".into(),
            ],
            32,
            16,
            &ArtifactProducerLimits::default(),
        )
        .unwrap();
        (fixture, artifact)
    }

    fn source_set_request(root: &Path) -> ArtifactProductionRequest {
        ArtifactProductionRequest {
            path: root.to_owned(),
            artifact_kind: ExternalArtifactKind::PythonStub,
            pack_id: "python-source-set-rejection-fixture".to_owned(),
            pack_version: "1.0.0".to_owned(),
            ecosystem: "python".to_owned(),
            compatibility: Compatibility {
                bifrost: format!("={}", env!("CARGO_PKG_VERSION")),
                toolchains: Vec::new(),
            },
            activation: vec![ActivationSelector {
                package: None,
                module: None,
                toolchain: None,
                targets: Vec::new(),
                configurations: Vec::new(),
                artifact_sha256: None,
            }],
            provenance: Provenance {
                source: "fixture".to_owned(),
                revision: Some("fixture-v1".to_owned()),
            },
            license: "Apache-2.0".to_owned(),
            safety: Safety {
                generated_code_only: false,
                review_required: false,
            },
        }
    }

    #[test]
    fn source_set_rejects_keep_exact_source_entries_and_artifact_digest() {
        let (fixture, artifact) = source_set_rejection_fixture();
        let expected_digest = artifact.sha256().to_owned();
        let production = PythonArtifactPackProducer.produce_loaded_source_set(
            &source_set_request(fixture.path()),
            &ArtifactProducerLimits::default(),
            None,
            &artifact,
        );

        assert_eq!(
            production.artifact_sha256.as_deref(),
            Some(expected_digest.as_str()),
            "source-set production retains the exact input digest"
        );
        assert_eq!(production.completeness, Completeness::Partial);
        assert_eq!(
            production.suppressed_diagnostics,
            SuppressedDiagnostics::default()
        );
        assert_eq!(production.diagnostics.len(), 2);
        let rejects = [
            ("python.artifact_module", "__init__.pyi"),
            ("python.source.encoding", "pkg/bad.pyi"),
        ];
        for (code, source_entry) in rejects {
            let diagnostic = production
                .diagnostics
                .iter()
                .find(|diagnostic| diagnostic.code == code)
                .unwrap_or_else(|| panic!("missing diagnostic {code}"));
            assert_eq!(diagnostic.severity, ProducerDiagnosticSeverity::Warning);
            assert_eq!(diagnostic.location.as_deref(), Some(source_entry));
            assert_eq!(diagnostic.source_entry.as_deref(), Some(source_entry));
            assert_eq!(diagnostic.declaration, None);
        }
        assert_eq!(
            production
                .diagnostics
                .iter()
                .filter_map(|diagnostic| diagnostic.source_entry.as_deref())
                .count(),
            production.diagnostics.len(),
            "every retained warning has one exact source-entry accounting subject"
        );
        assert!(
            production.pack.as_ref().is_some_and(|pack| {
                pack.shards.iter().any(|shard| match &shard.payload {
                    AuthoredPayload::DeclarationFacts { types, .. } => {
                        types.iter().any(|fact| fact.name == "pkg.Widget")
                    }
                    _ => false,
                })
            }),
            "a warning-only partial source set still retains valid declarations"
        );
    }

    #[test]
    fn source_set_suppressed_and_cancelled_rejects_remain_unaccounted() {
        let (fixture, artifact) = source_set_rejection_fixture();
        let limits = ArtifactProducerLimits {
            max_diagnostics: 1,
            ..ArtifactProducerLimits::default()
        };
        let production = PythonArtifactPackProducer.produce_loaded_source_set(
            &source_set_request(fixture.path()),
            &limits,
            None,
            &artifact,
        );
        assert_eq!(production.completeness, Completeness::Partial);
        assert_eq!(
            production.suppressed_diagnostics,
            SuppressedDiagnostics {
                warnings: 1,
                errors: 0,
            }
        );
        assert_eq!(production.diagnostics.len(), 1);
        assert_eq!(
            production.diagnostics[0].source_entry.as_deref(),
            Some("__init__.pyi")
        );
        assert_eq!(
            production
                .diagnostics
                .iter()
                .filter_map(|diagnostic| diagnostic.source_entry.as_deref())
                .count(),
            1,
            "the suppressed reject has no retained identity to account for"
        );

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let cancelled = PythonArtifactPackProducer.produce_loaded_source_set(
            &source_set_request(fixture.path()),
            &ArtifactProducerLimits::default(),
            Some(&cancellation),
            &artifact,
        );
        assert_eq!(cancelled.completeness, Completeness::Partial);
        assert!(cancelled.pack.is_none());
        assert!(cancelled.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "artifact.cancelled"
                && diagnostic.severity == ProducerDiagnosticSeverity::Error
        }));
        assert!(
            cancelled
                .diagnostics
                .iter()
                .all(|diagnostic| diagnostic.source_entry.is_none()),
            "cancellation is a whole-source-set failure, not an entry accounting subject"
        );
    }

    /// Produce one pack from an inline stub source set, the way the pinned
    /// typeshed selection is produced.
    fn produce_stub_set(files: &[(&str, &str)]) -> ArtifactProduction {
        let fixture = tempdir().unwrap();
        for (relative, source) in files {
            let path = fixture.path().join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, source).unwrap();
        }
        let artifact = read_exact_source_set(
            fixture.path(),
            &files
                .iter()
                .map(|(relative, _)| (*relative).into())
                .collect::<Vec<_>>(),
            32,
            16,
            &ArtifactProducerLimits::default(),
        )
        .unwrap();
        PythonArtifactPackProducer.produce_loaded_source_set(
            &ArtifactProductionRequest {
                path: fixture.path().to_owned(),
                artifact_kind: ExternalArtifactKind::PythonStub,
                pack_id: "python-wildcard-fixture".to_owned(),
                pack_version: "1.0.0".to_owned(),
                ecosystem: "python".to_owned(),
                compatibility: Compatibility {
                    bifrost: format!("={}", env!("CARGO_PKG_VERSION")),
                    toolchains: Vec::new(),
                },
                activation: vec![ActivationSelector {
                    package: None,
                    module: None,
                    toolchain: None,
                    targets: Vec::new(),
                    configurations: Vec::new(),
                    artifact_sha256: None,
                }],
                provenance: Provenance {
                    source: "fixture".to_owned(),
                    revision: None,
                },
                license: "Apache-2.0".to_owned(),
                safety: Safety {
                    generated_code_only: false,
                    review_required: false,
                },
            },
            &ArtifactProducerLimits::default(),
            None,
            &artifact,
        )
    }

    fn declaration_facts(production: &ArtifactProduction) -> (&[TypeFact], &[MemberFact]) {
        match &production.pack.as_ref().unwrap().shards[0].payload {
            AuthoredPayload::DeclarationFacts { types, members, .. } => (types, members),
            payload => panic!("declaration facts: {payload:#?}"),
        }
    }

    /// Every member name one module owns, sorted.
    fn module_members<'a>(members: &'a [MemberFact], module: &str) -> Vec<&'a str> {
        let owner = type_declaration_id(TypeIdentity {
            ecosystem: "python",
            name: module,
        });
        let mut names = members
            .iter()
            .filter(|member| member.owner == owner)
            .map(|member| member.name.as_str())
            .collect::<Vec<_>>();
        names.sort_unstable();
        names
    }

    fn type_aliases<'a>(types: &'a [TypeFact], name: &str) -> &'a [String] {
        &types
            .iter()
            .find(|fact| fact.name == name)
            .unwrap_or_else(|| panic!("`{name}` is declared"))
            .aliases
    }

    const WILDCARD_IMPL: &str =
        "from typing import MutableSet as MutableSet\n\nclass Own: ...\n\n_private: int\n";

    #[test]
    fn a_wildcard_shim_publishes_the_public_names_its_source_module_exports() {
        let production = produce_stub_set(&[
            ("shim.pyi", "from _impl import *\n"),
            ("_impl.pyi", WILDCARD_IMPL),
            ("typing.pyi", "class MutableSet: ...\n"),
        ]);
        assert!(
            production.diagnostics.is_empty(),
            "{:#?}",
            production.diagnostics
        );
        let (types, members) = declaration_facts(&production);
        assert_eq!(
            module_members(members, "shim"),
            vec!["MutableSet", "Own"],
            "a wildcard binds the exported public names and nothing else"
        );
        assert_eq!(
            type_aliases(types, "typing.MutableSet"),
            ["shim.MutableSet"],
            "a re-export chain ends at the declaring class"
        );
        assert_eq!(
            type_aliases(types, "_impl.Own"),
            ["shim.Own"],
            "a re-exported local class is published under the shim's name"
        );
    }

    #[test]
    fn a_literal_dunder_all_decides_what_a_wildcard_binds() {
        let production = produce_stub_set(&[
            ("shim.pyi", "from _impl import *\n"),
            (
                "_impl.pyi",
                &format!("__all__ = [\"Own\"]\n{WILDCARD_IMPL}"),
            ),
            ("typing.pyi", "class MutableSet: ...\n"),
        ]);
        let (types, members) = declaration_facts(&production);
        assert_eq!(
            module_members(members, "shim"),
            vec!["Own"],
            "`__all__` states the whole export set"
        );
        assert!(
            type_aliases(types, "typing.MutableSet").is_empty(),
            "a name `__all__` withholds is not re-exported"
        );
    }

    #[test]
    fn a_wildcard_this_production_cannot_read_keeps_the_unenumerated_marker() {
        let outside = produce_stub_set(&[
            ("shim.pyi", "from outside import *\n"),
            ("_impl.pyi", WILDCARD_IMPL),
            ("typing.pyi", "class MutableSet: ...\n"),
        ]);
        let (_, members) = declaration_facts(&outside);
        assert_eq!(
            module_members(members, "shim"),
            vec![PYTHON_UNENUMERATED_BINDING],
            "a wildcard whose module the production does not carry stays unenumerated"
        );

        let unreadable = produce_stub_set(&[
            ("shim.pyi", "from _impl import *\n"),
            (
                "_impl.pyi",
                &format!("__all__ = list(_names)\n{WILDCARD_IMPL}"),
            ),
            ("typing.pyi", "class MutableSet: ...\n"),
        ]);
        let (_, members) = declaration_facts(&unreadable);
        assert_eq!(
            module_members(members, "shim"),
            vec![PYTHON_UNENUMERATED_BINDING],
            "an `__all__` this producer cannot read states no export set"
        );
    }

    #[test]
    fn wildcards_chain_to_the_same_declaring_targets() {
        let production = produce_stub_set(&[
            ("shim2.pyi", "from shim import *\n"),
            ("shim.pyi", "from _impl import *\n"),
            ("_impl.pyi", WILDCARD_IMPL),
            ("typing.pyi", "class MutableSet: ...\n"),
        ]);
        let (types, members) = declaration_facts(&production);
        assert_eq!(module_members(members, "shim2"), vec!["MutableSet", "Own"]);
        assert_eq!(
            type_aliases(types, "typing.MutableSet"),
            ["shim.MutableSet", "shim2.MutableSet"],
            "every module in the chain names the declaring class"
        );
        assert_eq!(type_aliases(types, "_impl.Own"), ["shim.Own", "shim2.Own"]);
    }

    #[test]
    fn a_guarded_wildcard_carries_its_condition_onto_the_names_it_binds() {
        let production = produce_stub_set(&[
            (
                "shim.pyi",
                "import sys\n\nif sys.platform == \"win32\":\n    from _impl import *\n",
            ),
            ("_impl.pyi", WILDCARD_IMPL),
            ("typing.pyi", "class MutableSet: ...\n"),
        ]);
        let (_, members) = declaration_facts(&production);
        let owner = type_declaration_id(TypeIdentity {
            ecosystem: "python",
            name: "shim",
        });
        let own = members
            .iter()
            .find(|member| member.owner == owner && member.name == "Own")
            .expect("the guarded wildcard still binds `Own`");
        assert_eq!(
            own.guard
                .as_ref()
                .map(|guard| guard.required_targets.clone()),
            Some(vec!["win32".to_owned()]),
            "{own:#?}"
        );
    }

    #[test]
    fn a_hierarchy_edge_through_a_wildcard_shim_names_the_declaring_class() {
        let production = produce_stub_set(&[
            ("shim.pyi", "from _impl import *\n"),
            ("_impl.pyi", WILDCARD_IMPL),
            ("typing.pyi", "class MutableSet: ...\n"),
            (
                "user.pyi",
                "from shim import MutableSet\n\nclass Uses(MutableSet): ...\n",
            ),
        ]);
        let (types, _) = declaration_facts(&production);
        let uses = types
            .iter()
            .find(|fact| fact.name == "user.Uses")
            .expect("`user.Uses` is declared");
        assert!(
            matches!(
                &uses.hierarchy[0].target,
                TypeRef::Named { name, .. } if name == "shim.MutableSet"
            ),
            "{:#?}",
            uses.hierarchy
        );
        assert!(
            type_aliases(types, "typing.MutableSet").contains(&"shim.MutableSet".to_owned()),
            "the overlay resolves that edge through the re-export alias"
        );
        compile_pack(
            production.pack.as_ref().unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap();
    }

    #[test]
    fn stub_overloads_preserve_subprocess_run_formal_names_and_defaults() {
        let source = r#"from typing import Literal, overload

@overload
def run(
    args: object,
    bufsize: int = -1,
    executable: object = None,
    stdin: object = None,
    stdout: object = None,
    stderr: object = None,
    preexec_fn: object = None,
    close_fds: bool = True,
    shell: bool = False,
    cwd: object = None,
    *,
    capture_output: bool = False,
    check: bool = False,
    text: Literal[False] | None = None,
) -> bytes: ...

@overload
def run(
    args: object,
    bufsize: int = -1,
    executable: object = None,
    stdin: object = None,
    stdout: object = None,
    stderr: object = None,
    preexec_fn: object = None,
    close_fds: bool = True,
    shell: bool = False,
    cwd: object = None,
    *,
    capture_output: bool = False,
    check: bool = False,
    text: Literal[True],
) -> str: ...
"#;
        let tree = brokk_bifrost_python::declarations::parse_python_tree(source).unwrap();
        let limits = ArtifactProducerLimits::default();
        let mut diagnostics = BoundedProducerDiagnostics::new(&limits);
        let mut collector = PythonApiCollector::new(
            "subprocess",
            Path::new("subprocess.pyi"),
            "subprocess.pyi".to_owned(),
            source,
            &limits,
            &mut diagnostics,
        );
        collector.collect(tree.root_node(), None);
        let runs = collector
            .members
            .iter()
            .filter(|member| {
                member.owner
                    == type_declaration_id(TypeIdentity {
                        ecosystem: "python",
                        name: "subprocess",
                    })
                    && member.name == "run"
            })
            .collect::<Vec<_>>();
        assert_eq!(runs.len(), 2, "both overload declarations must survive");
        for run in runs {
            let parameters = &run.signature.as_ref().unwrap().parameters;
            assert_eq!(
                parameters
                    .iter()
                    .map(|parameter| parameter.name.as_deref().unwrap())
                    .collect::<Vec<_>>(),
                [
                    "args",
                    "bufsize",
                    "executable",
                    "stdin",
                    "stdout",
                    "stderr",
                    "preexec_fn",
                    "close_fds",
                    "shell",
                    "cwd",
                    "capture_output",
                    "check",
                    "text",
                ]
            );
            assert!(!parameters[0].optional);
            assert!(parameters[8].optional, "shell has an exact default");
            assert!(parameters[10].optional, "capture_output is keyword-only");
            assert!(
                parameters[..10]
                    .iter()
                    .all(|parameter| parameter.passing_mode
                        == ParameterPassingMode::PositionalOrNamed)
            );
            assert!(
                parameters[10..]
                    .iter()
                    .all(|parameter| parameter.passing_mode == ParameterPassingMode::NamedOnly)
            );
            assert!(!parameters.iter().any(|parameter| parameter.variadic));
        }
        drop(collector);
        let (diagnostics, suppressed) = diagnostics.finish();
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert_eq!(suppressed, SuppressedDiagnostics::default());
    }

    #[test]
    fn stub_signature_preserves_python_parameter_passing_regions() {
        let source = "def api(first: int, /, second: int, *values: int, third: int, **rest: int) -> None: ...\n";
        let tree = brokk_bifrost_python::declarations::parse_python_tree(source).unwrap();
        let definition = tree.root_node().named_child(0).expect("function");

        let signature = function_signature(definition, source, 32).expect("signature");

        assert_eq!(
            signature
                .parameters
                .iter()
                .map(|parameter| parameter.passing_mode)
                .collect::<Vec<_>>(),
            [
                ParameterPassingMode::PositionalOnly,
                ParameterPassingMode::PositionalOrNamed,
                ParameterPassingMode::PositionalOnly,
                ParameterPassingMode::NamedOnly,
                ParameterPassingMode::NamedOnly,
            ]
        );
        assert!(signature.parameters[2].variadic, "*values is variadic");
        assert!(signature.parameters[4].variadic, "**rest is variadic");
    }
}
