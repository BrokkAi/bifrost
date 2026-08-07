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
    CatalogCoordinate, Compatibility, Completeness, DependencyArtifactRole,
    DependencyDiscoveryOutcome, DependencyDiscoveryProfile, DependencyPackAdapter,
    DependencyPackDiagnostic, DependencyPackDiagnosticSeverity, DependencyPackLimits,
    DependencyPackProduction, DependencyProvenance, ExactArtifact, ExactDependencyArtifact,
    ExternalArtifactKind, ExternalArtifactPackProducer, HierarchyFact, Locator, MemberFact,
    MemberIdentity, MemberKind, NameSelector, Parameter, Producer, ProducerDiagnostic,
    ProducerDiagnosticSeverity, Provenance, ResolvedDependency, ResolvedDependencyArtifact, Safety,
    SemanticModelActivationEvidence, Signature, TypeFact, TypeIdentity, TypeKind, TypeRef,
    Visibility, member_declaration_id, read_exact_artifact_while, type_declaration_id,
};
use crate::analyzer::{Project, PythonAnalyzerConfig, PythonEnvironmentConfig};
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
        let mut suppressed_diagnostics = 0usize;
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
                    code: "artifact.cancelled".to_owned(),
                    location: None,
                    message: "Python dependency production was cancelled".to_owned(),
                });
                completeness = Completeness::Partial;
                break;
            }
            let Some(module) = artifact.module() else {
                diagnostics.push(ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    code: "python.artifact_module".to_owned(),
                    location: Some(artifact.path().display().to_string()),
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
            suppressed_diagnostics =
                suppressed_diagnostics.saturating_add(production.suppressed_diagnostics);
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
        types.sort_by(|left, right| left.id.cmp(&right.id));
        types.dedup_by(|left, right| left.id == right.id);
        members.sort_by(|left, right| left.id.cmp(&right.id));
        members.dedup_by(|left, right| left.id == right.id);
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
                    code: "artifact.kind".to_owned(),
                    location: None,
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
                    code: "artifact.kind".to_owned(),
                    location: None,
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
                        code: "python.source.encoding".to_owned(),
                        location: Some(artifact.path().display().to_string()),
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
                    code: "python.source.parse".to_owned(),
                    location: Some(artifact.path().display().to_string()),
                    message: "Python parser did not produce a syntax tree".to_owned(),
                },
                limits,
            );
        };
        let mut diagnostics = BoundedProducerDiagnostics::new(limits);
        let (types, members) = {
            let mut collector =
                PythonApiCollector::new(module, artifact.path(), source, limits, &mut diagnostics);
            collector.collect(tree.root_node(), cancellation);
            (collector.types, collector.members)
        };
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            diagnostics.error(
                "artifact.cancelled",
                None,
                "Python artifact production was cancelled",
            );
        }
        let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
        let completeness = if diagnostics.is_empty() && suppressed_diagnostics == 0 {
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
    let relative = path.strip_prefix(import_root).ok()?;
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
    /// `owner.name` for every binding an import already contributed, so a
    /// conditional import cannot mint one member identity twice.
    imported_names: std::collections::HashSet<String>,
}

impl<'a, 'd> PythonApiCollector<'a, 'd> {
    fn new(
        module: &'a str,
        path: &'a Path,
        source: &'a str,
        limits: &'a ArtifactProducerLimits,
        diagnostics: &'d mut BoundedProducerDiagnostics,
    ) -> Self {
        let mut collector = Self {
            module,
            path,
            locator_path: path
                .file_name()
                .and_then(|name| name.to_str())
                .filter(|name| !name.is_empty())
                .unwrap_or("__external__.pyi")
                .to_owned(),
            source,
            limits,
            diagnostics,
            types: Vec::new(),
            members: Vec::new(),
            imported_names: std::collections::HashSet::new(),
        };
        collector.push_type(module.to_owned(), TypeKind::Module, Vec::new(), Vec::new());
        collector
    }

    fn collect(&mut self, root: Node<'_>, cancellation: Option<&CancellationToken>) {
        let mut stack = vec![(root, self.module.to_owned(), false)];
        while let Some((node, owner, class_scope)) = stack.pop() {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return;
            }
            match node.kind() {
                "module" | "block" => self.push_children(&mut stack, node, &owner, class_scope),
                "decorated_definition" => {
                    if let Some(definition) = node.child_by_field_name("definition") {
                        self.visit_definition(
                            &mut stack,
                            definition,
                            Some(node),
                            owner,
                            class_scope,
                        );
                    }
                }
                "class_definition" | "function_definition" => {
                    self.visit_definition(&mut stack, node, None, owner, class_scope);
                }
                "expression_statement" => self.visit_assignment(node, &owner, class_scope),
                "import_statement" | "import_from_statement" => self.visit_import(node, &owner),
                "type_alias_statement" => self.visit_type_alias(node, &owner),
                // Module control blocks do not make declarations dynamic by
                // themselves. The emitted pack remains a static surface and
                // never evaluates a guard.
                "if_statement" | "try_statement" | "with_statement" | "for_statement"
                | "while_statement" | "elif_clause" | "else_clause" | "except_clause"
                | "finally_clause" => self.push_children(&mut stack, node, &owner, class_scope),
                _ => {}
            }
        }
    }

    fn push_children<'tree>(
        &self,
        stack: &mut Vec<(Node<'tree>, String, bool)>,
        node: Node<'tree>,
        owner: &str,
        class_scope: bool,
    ) {
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        for child in children.into_iter().rev() {
            stack.push((child, owner.to_owned(), class_scope));
        }
    }

    fn visit_definition<'tree>(
        &mut self,
        stack: &mut Vec<(Node<'tree>, String, bool)>,
        definition: Node<'tree>,
        decorated: Option<Node<'tree>>,
        owner: String,
        class_scope: bool,
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
                        .map(|base| HierarchyFact {
                            hierarchy_kind: crate::analyzer::semantic_model::HierarchyKind::Extends,
                            target: type_ref(base, self.source, self.limits.max_signature_depth),
                            declaration_ordinal: None,
                        })
                        .collect()
                })
                .unwrap_or_default();
            let type_parameters = definition
                .child_by_field_name("type_parameters")
                .map(|parameters| {
                    named_children(parameters)
                        .filter_map(|node| node_identifier(Some(node), self.source))
                        .collect()
                })
                .unwrap_or_default();
            self.push_type(
                qualified.clone(),
                TypeKind::Class,
                type_parameters,
                hierarchy,
            );
            if let Some(body) = definition.child_by_field_name("body") {
                stack.push((body, qualified, true));
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
        self.push_member(owner, name, member_kind, is_static, signature);
    }

    fn visit_assignment(&mut self, node: Node<'_>, owner: &str, class_scope: bool) {
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
        );
    }

    /// An import inside a module or class body binds a name on that surface:
    /// `from .sessions import Session` in `requests/__init__.pyi` is how
    /// `requests.Session` exists at all. One artifact is produced without a
    /// view of the modules it imports, so the binding is recorded by name
    /// alone. That is what an absence proof needs -- "does this surface bind
    /// that name" -- and recording it is what makes a surface marked complete
    /// actually complete.
    ///
    /// A wildcard binds a set this producer cannot enumerate, so it reports a
    /// diagnostic instead, which makes the pack partial and stops the surface
    /// from proving anything absent.
    fn visit_import(&mut self, node: Node<'_>, owner: &str) {
        for import in
            brokk_bifrost_python::imports::python_import_infos_from_node(node, self.source)
        {
            if import.is_wildcard {
                self.diagnostics.warning(
                    "python.import.wildcard",
                    Some(self.path.display().to_string()),
                    format!(
                        "`{}` binds names this producer cannot enumerate",
                        import.raw_snippet.trim()
                    ),
                );
                continue;
            }
            let Some(name) = import.local_name() else {
                self.diagnostics.warning(
                    "python.import.binding",
                    Some(self.path.display().to_string()),
                    format!("`{}` binds no single name", import.raw_snippet.trim()),
                );
                continue;
            };
            // Two branches of a `try`/`except ImportError` pair bind the same
            // name; recording it twice would mint one identity twice and mark
            // the surface ambiguous.
            if !self
                .imported_names
                .insert(format!("{owner}.{name}", name = name))
            {
                continue;
            }
            self.push_member(
                owner.to_owned(),
                name.to_owned(),
                MemberKind::Constant,
                false,
                None,
            );
        }
    }

    fn visit_type_alias(&mut self, node: Node<'_>, owner: &str) {
        let Some(name) = node_identifier(node.child_by_field_name("name"), self.source) else {
            return;
        };
        self.push_type(
            format!("{owner}.{name}"),
            TypeKind::TypeAlias,
            Vec::new(),
            Vec::new(),
        );
    }

    fn push_type(
        &mut self,
        name: String,
        type_kind: TypeKind,
        type_parameters: Vec<String>,
        hierarchy: Vec<crate::analyzer::semantic_model::HierarchyFact>,
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
            embedded_types: Vec::new(),
            hierarchy,
            aliases: Vec::new(),
            extension_surfaces: Vec::new(),
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
        let owner_id = type_declaration_id(TypeIdentity {
            ecosystem: "python",
            name: &owner,
        });
        let parameters = signature
            .as_ref()
            .map(|signature| signature.parameters.clone())
            .unwrap_or_default();
        let parameter_types = parameters
            .iter()
            .map(|parameter| parameter.r#type.clone())
            .collect::<Vec<_>>();
        let return_type = signature
            .as_ref()
            .and_then(|signature| signature.returns.as_ref());
        let id = member_declaration_id(MemberIdentity {
            owner_id: &owner_id,
            kind: member_kind,
            is_static,
            parameter_arity: parameter_types.len(),
            name: &name,
            generic_arity: signature
                .as_ref()
                .map_or(0, |signature| signature.type_parameters.len()),
            parameter_types: &parameter_types,
            parameter_variadics: &[],
            return_type,
        });
        self.members.push(MemberFact {
            id,
            owner: owner_id,
            name: name.clone(),
            member_kind,
            visibility: python_visibility(&name),
            is_static,
            is_abstract: false,
            is_virtual: false,
            signature,
            receiver: None,
            extension_receiver: None,
            extension_receiver_constraints: Vec::new(),
            aliases: Vec::new(),
            locator: Locator::Artifact {
                path: self.locator_path.clone(),
                symbol: format!("{owner}.{name}"),
            },
        });
    }
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

fn function_signature(node: Node<'_>, source: &str, max_depth: usize) -> Option<Signature> {
    let parameters = node.child_by_field_name("parameters")?;
    let parameters = named_children(parameters)
        .filter_map(|parameter| {
            let (name, annotation, optional, variadic) = match parameter.kind() {
                "identifier" => (node_identifier(Some(parameter), source), None, false, false),
                "typed_parameter" => (
                    node_identifier(parameter.child_by_field_name("name"), source),
                    parameter.child_by_field_name("type"),
                    false,
                    false,
                ),
                "default_parameter" | "typed_default_parameter" => (
                    node_identifier(parameter.child_by_field_name("name"), source),
                    parameter.child_by_field_name("type"),
                    true,
                    false,
                ),
                "list_splat_pattern" | "dictionary_splat_pattern" => (
                    node_identifier(parameter.child_by_field_name("name"), source),
                    parameter.child_by_field_name("type"),
                    false,
                    true,
                ),
                _ => return None,
            };
            Some(Parameter {
                name,
                r#type: annotation
                    .map(|annotation| type_ref(annotation, source, max_depth))
                    .unwrap_or_else(any_type),
                optional,
                variadic,
            })
        })
        .collect();
    Some(Signature {
        type_parameters: node
            .child_by_field_name("type_parameters")
            .map(|parameters| {
                named_children(parameters)
                    .filter_map(|parameter| node_identifier(Some(parameter), source))
                    .collect()
            })
            .unwrap_or_default(),
        parameters,
        returns: node
            .child_by_field_name("return_type")
            .map(|annotation| type_ref(annotation, source, max_depth)),
    })
}

fn type_ref(node: Node<'_>, source: &str, max_depth: usize) -> TypeRef {
    if max_depth == 0 {
        return any_type();
    }
    match node.kind() {
        "identifier" => TypeRef::Named {
            name: node_identifier(Some(node), source).unwrap_or_else(|| "Any".to_owned()),
            arguments: Vec::new(),
            nullable: false,
        },
        "attribute" => TypeRef::Named {
            name: attribute_name(node, source).unwrap_or_else(|| "Any".to_owned()),
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

fn attribute_name(node: Node<'_>, source: &str) -> Option<String> {
    let object = node.child_by_field_name("object")?;
    let attribute = node.child_by_field_name("attribute")?;
    let object = match object.kind() {
        "identifier" => node_identifier(Some(object), source),
        "attribute" => attribute_name(object, source),
        _ => None,
    }?;
    let attribute = node_identifier(Some(attribute), source)?;
    Some(format!("{object}.{attribute}"))
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

/// Resolve configured Python standard-library, bundled-stub, and installed
/// distribution files without using the interpreter, `sys.path`, `.pth`, or a
/// package manager. A disabled Python environment intentionally resolves no
/// dependencies.
pub fn resolve_python_semantic_pack_dependencies(
    config: &PythonAnalyzerConfig,
    project: &dyn Project,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> DependencyDiscoveryOutcome {
    let Some(environment) = &config.environment else {
        return DependencyDiscoveryOutcome::complete(Vec::new());
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
    suppressed_diagnostics: usize,
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
            suppressed_diagnostics: 0,
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
            complete: !self.incomplete && self.suppressed_diagnostics == 0,
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
            self.suppressed_diagnostics = self.suppressed_diagnostics.saturating_add(1);
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
