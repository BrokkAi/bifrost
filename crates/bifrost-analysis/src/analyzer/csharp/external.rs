use super::dependency_discovery::project_assets_files;
use crate::CancellationToken;
use crate::analyzer::semantic_model::{
    ActivationSelector, ArtifactProducerLimits, ArtifactProduction, ArtifactProductionRequest,
    AuthoredPayload, AuthoredSemanticModelPack, AuthoredShard, BoundedProducerDiagnostics,
    CatalogCoordinate, Compatibility, Completeness, DependencyArtifactRole,
    DependencyDiscoveryOutcome, DependencyDiscoveryProfile, DependencyPackAdapter,
    DependencyPackDiagnostic, DependencyPackDiagnosticSeverity, DependencyPackLimits,
    DependencyPackProduction, DependencyProvenance, ExactArtifact, ExactDependencyArtifact,
    ExternalArtifactKind, ExternalArtifactPackProducer, HierarchyFact, HierarchyKind, Locator,
    MemberFact, MemberIdentity, MemberKind, NameSelector, Parameter, Producer, ProducerDiagnostic,
    ProducerDiagnosticSeverity, Provenance, ResolvedDependency, ResolvedDependencyArtifact, Safety,
    SemanticModelActivationEvidence, Signature, TypeFact, TypeIdentity, TypeKind, TypeRef,
    Visibility, member_declaration_id, normalize_artifact_locator_paths, read_exact_artifact_while,
    type_declaration_id,
};
use crate::analyzer::{CSharpAnalyzerConfig, Project};
use crate::hash::{HashMap, HashSet};
use goblin::pe::PE;
use semver::Version;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const MAX_ASSEMBLY_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ASSETS_BYTES: u64 = 8 * 1024 * 1024;
const MAX_METADATA_ROWS: u32 = 100_000;
const MAX_METADATA_TOTAL_ROWS: u32 = 250_000;
const MAX_SIGNATURE_DEPTH: usize = 64;
const MAX_SIGNATURE_PARAMETERS: usize = 4_096;
const MAX_ARRAY_RANK: usize = 64;
const MAX_DECODED_METADATA_BYTES: usize = 64 * 1024 * 1024;
const MAX_PROJECT_OUTPUTS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CSharpExternalTypeKind {
    Class,
    Interface,
    Struct,
    Enum,
    Delegate,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CSharpVisibility {
    Private,
    Internal,
    ProtectedAndInternal,
    Protected,
    ProtectedOrInternal,
    Public,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CSharpExternalMemberKind {
    Constructor,
    Method,
    Field,
    Property,
    Event,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CSharpExternalDeclarationSource {
    Assembly { path: PathBuf, metadata_token: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DecodedType {
    Void,
    Named {
        name: String,
        arguments: Vec<DecodedType>,
    },
    TypeParameter {
        method: bool,
        index: usize,
    },
    Array {
        element: Box<DecodedType>,
        rank: usize,
    },
    Pointer(Box<DecodedType>),
    ByRef(Box<DecodedType>),
}

impl DecodedType {
    fn legacy_name(&self) -> String {
        match self {
            Self::Void => "void".to_owned(),
            Self::Named { name, arguments } => {
                let name = csharp_alias(name);
                if arguments.is_empty() {
                    name.to_owned()
                } else {
                    format!(
                        "{name}<{}>",
                        arguments
                            .iter()
                            .map(Self::legacy_name)
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                }
            }
            Self::TypeParameter { method, index } => {
                format!("{}{index}", if *method { "!!" } else { "!" })
            }
            Self::Array { element, rank } => format!(
                "{}[{}]",
                element.legacy_name(),
                ",".repeat(rank.saturating_sub(1))
            ),
            Self::Pointer(inner) => format!("{}*", inner.legacy_name()),
            Self::ByRef(inner) => format!("{}&", inner.legacy_name()),
        }
    }

    fn type_ref(
        &self,
        owner_type_parameters: &[String],
        member_type_parameters: &[String],
    ) -> Result<TypeRef, &'static str> {
        match self {
            Self::Void => Err("void is not a value type"),
            Self::Named { name, arguments } => Ok(TypeRef::Named {
                name: name.clone(),
                arguments: arguments
                    .iter()
                    .map(|argument| {
                        argument.type_ref(owner_type_parameters, member_type_parameters)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                nullable: false,
            }),
            Self::TypeParameter { method, index } => {
                let parameters = if *method {
                    member_type_parameters
                } else {
                    owner_type_parameters
                };
                parameters
                    .get(*index)
                    .cloned()
                    .map(|name| TypeRef::TypeParameter { name })
                    .ok_or("generic parameter name is unavailable")
            }
            Self::Array { element, rank: 1 } => Ok(TypeRef::Array {
                element: Box::new(element.type_ref(owner_type_parameters, member_type_parameters)?),
            }),
            Self::Array { .. } => Err("multidimensional array types are not representable"),
            Self::Pointer(_) => Err("pointer types are not representable"),
            Self::ByRef(inner) => Ok(TypeRef::ByRef {
                element: Box::new(inner.type_ref(owner_type_parameters, member_type_parameters)?),
            }),
        }
    }
}

fn csharp_alias(name: &str) -> &str {
    match name {
        "System.Void" => "void",
        "System.Boolean" => "bool",
        "System.Char" => "char",
        "System.SByte" => "sbyte",
        "System.Byte" => "byte",
        "System.Int16" => "short",
        "System.UInt16" => "ushort",
        "System.Int32" => "int",
        "System.UInt32" => "uint",
        "System.Int64" => "long",
        "System.UInt64" => "ulong",
        "System.Single" => "float",
        "System.Double" => "double",
        "System.String" => "string",
        "System.Object" => "object",
        other => other,
    }
}

#[derive(Debug, Clone)]
pub struct CSharpExternalMember {
    owner_fqn: String,
    name: String,
    kind: CSharpExternalMemberKind,
    visibility: CSharpVisibility,
    is_static: bool,
    is_abstract: bool,
    is_virtual: bool,
    generic_arity: usize,
    type_parameters: Vec<String>,
    return_type: Option<String>,
    parameter_types: Vec<String>,
    return_type_ref: Option<DecodedType>,
    parameter_type_refs: Vec<DecodedType>,
    source: CSharpExternalDeclarationSource,
}
impl CSharpExternalMember {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn kind(&self) -> CSharpExternalMemberKind {
        self.kind
    }
    pub fn owner_fqn(&self) -> &str {
        &self.owner_fqn
    }
    pub fn return_type(&self) -> Option<&str> {
        self.return_type.as_deref()
    }
    pub fn parameter_types(&self) -> &[String] {
        &self.parameter_types
    }
    pub fn visibility(&self) -> CSharpVisibility {
        self.visibility
    }
    pub fn is_static(&self) -> bool {
        self.is_static
    }
    pub fn is_abstract(&self) -> bool {
        self.is_abstract
    }
    pub fn is_virtual(&self) -> bool {
        self.is_virtual
    }
    pub fn generic_arity(&self) -> usize {
        self.generic_arity
    }
    pub fn source(&self) -> &CSharpExternalDeclarationSource {
        &self.source
    }
    fn externally_visible(&self) -> bool {
        matches!(
            self.visibility,
            CSharpVisibility::Public
                | CSharpVisibility::Protected
                | CSharpVisibility::ProtectedOrInternal
        )
    }
}

#[derive(Debug, Clone)]
pub struct CSharpExternalType {
    fqn: String,
    namespace: String,
    short_name: String,
    kind: CSharpExternalTypeKind,
    visibility: CSharpVisibility,
    is_abstract: bool,
    is_sealed: bool,
    generic_arity: usize,
    type_parameters: Vec<String>,
    base: Option<DecodedType>,
    interfaces: Vec<String>,
    interface_refs: Vec<DecodedType>,
    source: CSharpExternalDeclarationSource,
    members: Vec<CSharpExternalMember>,
    is_effectively_visible: bool,
}
impl CSharpExternalType {
    pub fn fqn(&self) -> &str {
        &self.fqn
    }
    pub fn members(&self) -> &[CSharpExternalMember] {
        &self.members
    }
    pub fn kind(&self) -> CSharpExternalTypeKind {
        self.kind
    }
    pub fn visibility(&self) -> CSharpVisibility {
        self.visibility
    }
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
    pub fn short_name(&self) -> &str {
        &self.short_name
    }
    pub fn generic_arity(&self) -> usize {
        self.generic_arity
    }
    pub fn interfaces(&self) -> &[String] {
        &self.interfaces
    }
    /// The metadata names of this type's immediate supertypes: its base type
    /// and each interface it declares.
    ///
    /// A member-absence claim walks this to the root of the chain, because the
    /// owner's own [`Self::members`] is only part of its surface and an
    /// ancestor the index cannot resolve leaves the rest of that surface
    /// unknown.
    ///
    /// These are the raw decoded identities, which key [`Self::fqn`] and so
    /// key [`CSharpExternalDeclarationIndex::types_named`]. That is what makes
    /// them usable for a chain walk, and what separates them from
    /// [`Self::interfaces`], whose display spelling aliases `System.Int32` to
    /// `int` and writes generics out in source form. Only a
    /// [`DecodedType::Named`] supertype names a type; arrays, pointers and
    /// generic parameters cannot appear in a supertype position, so they
    /// contribute nothing rather than a synthesized string.
    pub fn supertype_names(&self) -> Vec<&str> {
        self.base
            .iter()
            .chain(self.interface_refs.iter())
            .filter_map(|decoded| match decoded {
                DecodedType::Named { name, .. } => Some(name.as_str()),
                _ => None,
            })
            .collect()
    }
    pub fn source(&self) -> &CSharpExternalDeclarationSource {
        &self.source
    }
    fn externally_visible(&self) -> bool {
        self.is_effectively_visible
    }
}

#[derive(Debug, Clone)]
pub struct CSharpExternalDeclarationIndex {
    types: HashMap<String, Vec<CSharpExternalType>>,
    /// Every namespace the indexed assemblies declare an externally visible
    /// type in. A `using` directive naming a namespace absent from here
    /// reached nothing this index reads.
    namespaces: HashSet<String>,
    /// Externally visible static method names, keyed by the namespace of the
    /// type declaring them.
    ///
    /// An extension method is a static method, and the metadata this index
    /// decodes carries no `[Extension]` attribute, so the two are not
    /// distinguishable here. A proof-gated instance-member lookup reads this
    /// to find out whether a namespace the file has in scope could supply an
    /// extension method of that name, which makes the miss unprovable.
    static_methods_by_namespace: HashMap<String, HashSet<String>>,
    /// Whether every dependency input this index was built from was both
    /// discovered and decoded whole.
    complete: bool,
    /// Whether the project declared any dependency input at all: a configured
    /// assembly path, or a `project.assets.json` under the project root.
    ///
    /// Zero inputs is not proof that the compilation references nothing. It is
    /// the absence of evidence, which is why it is kept apart from
    /// [`Self::complete`]: discovery over an empty input set completes
    /// vacuously, and reading that as "the external surface is empty" would
    /// turn every `using System;` in a loose `.cs` file into an error.
    has_dependency_inputs: bool,
    production_diagnostics: Vec<ProducerDiagnostic>,
}

impl Default for CSharpExternalDeclarationIndex {
    fn default() -> Self {
        Self {
            types: HashMap::default(),
            namespaces: HashSet::default(),
            static_methods_by_namespace: HashMap::default(),
            // An index that was handed no inputs read all of them. What stops
            // an empty index proving anything external is
            // `has_dependency_inputs`, not this.
            complete: true,
            has_dependency_inputs: false,
            production_diagnostics: Vec::new(),
        }
    }
}

impl CSharpExternalDeclarationIndex {
    pub fn build_for_project(config: &CSharpAnalyzerConfig, project: &dyn Project) -> Self {
        let discovery = resolve_csharp_semantic_pack_dependencies(
            config,
            project,
            &DependencyPackLimits::default(),
            None,
        );
        let mut paths: Vec<_> = discovery
            .dependencies
            .iter()
            .flat_map(|dependency| dependency.artifacts.iter())
            .map(|artifact| artifact.path().to_owned())
            .collect();
        paths.sort();
        paths.dedup();
        let mut index = Self::default();
        index.complete &= discovery.complete;
        index.has_dependency_inputs = discovery.profile.metadata_inputs_considered > 0;
        for path in paths {
            index.index_assembly(&path);
        }
        index
            .production_diagnostics
            .extend(
                discovery
                    .diagnostics
                    .into_iter()
                    .map(|diagnostic| ProducerDiagnostic {
                        severity: match diagnostic.severity {
                            DependencyPackDiagnosticSeverity::Warning => {
                                ProducerDiagnosticSeverity::Warning
                            }
                            DependencyPackDiagnosticSeverity::Error => {
                                ProducerDiagnosticSeverity::Error
                            }
                        },
                        code: diagnostic.code,
                        location: diagnostic.location,
                        message: diagnostic.message,
                    }),
            );
        index
    }
    pub fn resolve_in_file(
        &self,
        reference: &str,
        namespace: &str,
        usings: &[String],
        aliases: &HashMap<String, String>,
    ) -> Vec<&CSharpExternalType> {
        let mut name = reference.trim().trim_end_matches('?').to_string();
        if let Some((alias, suffix)) = name.split_once("::") {
            name = if alias == "global" {
                suffix.to_string()
            } else {
                aliases
                    .get(alias)
                    .map(|p| {
                        if suffix.is_empty() {
                            p.clone()
                        } else {
                            format!("{p}.{suffix}")
                        }
                    })
                    .unwrap_or(name)
            };
        }
        name = metadata_type_identity(&name);
        let mut keys = Vec::new();
        if name.contains('.') {
            keys.push(name);
        } else {
            if !namespace.is_empty() {
                keys.push(format!("{namespace}.{name}"));
            }
            keys.extend(usings.iter().map(|u| format!("{u}.{name}")));
            keys.push(name);
        }
        keys.into_iter()
            .flat_map(|key| self.types.get(&key).into_iter().flatten())
            .filter(|ty| ty.externally_visible())
            .collect()
    }
    pub fn members_named(&self, owner: &str, name: &str) -> Vec<&CSharpExternalMember> {
        self.types
            .get(owner)
            .into_iter()
            .flatten()
            .filter(|ty| ty.externally_visible())
            .flat_map(|ty| ty.members.iter())
            .filter(|m| m.externally_visible())
            .filter(|m| m.name == name)
            .collect()
    }
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }
    /// Types recorded under the exact metadata identity `fqn`.
    ///
    /// [`Self::resolve_in_file`] answers a *reference as a file spells it*;
    /// this answers an identity the index itself produced, which is what
    /// walking a base-type chain needs.
    pub fn types_named(&self, fqn: &str) -> &[CSharpExternalType] {
        self.types.get(fqn).map_or(&[], Vec::as_slice)
    }
    /// Whether any indexed assembly declares an externally visible type in
    /// `namespace`.
    pub fn declares_namespace(&self, namespace: &str) -> bool {
        self.namespaces.contains(namespace)
    }
    /// Whether an indexed static method named `name` sits in any of
    /// `namespaces`.
    ///
    /// The caller passes the namespaces a file has in scope. A hit means an
    /// instance-member miss could be an extension method, so it is not proof
    /// of absence.
    pub fn declares_static_method_in(&self, namespaces: &[String], name: &str) -> bool {
        namespaces.iter().any(|namespace| {
            self.static_methods_by_namespace
                .get(namespace)
                .is_some_and(|names| names.contains(name))
        })
    }
    /// Whether every dependency input was discovered and decoded whole.
    ///
    /// A partial index holds an unknown remainder, so a miss against it is
    /// never proof of absence.
    pub fn is_complete(&self) -> bool {
        self.complete
    }
    /// Whether the project declared any dependency input for this index to
    /// read. A miss against an index built from no inputs proves nothing about
    /// the compilation's external surface.
    pub fn has_dependency_inputs(&self) -> bool {
        self.has_dependency_inputs
    }
    pub fn production_diagnostics(&self) -> &[ProducerDiagnostic] {
        &self.production_diagnostics
    }
    fn index_assembly(&mut self, path: &Path) {
        let production = CSharpAssemblyPackProducer.produce_exact_artifact(
            &ArtifactProductionRequest {
                path: path.to_path_buf(),
                artifact_kind: ExternalArtifactKind::DotNetAssembly,
                pack_id: "bifrost.external.csharp".to_owned(),
                pack_version: env!("CARGO_PKG_VERSION").to_owned(),
                ecosystem: "nuget".to_owned(),
                compatibility: Compatibility {
                    bifrost: format!("={}", env!("CARGO_PKG_VERSION")),
                    toolchains: Vec::new(),
                },
                activation: vec![ActivationSelector {
                    package: None,
                    module: None,
                    toolchain: Some(NameSelector {
                        name: "dotnet".to_owned(),
                        version: None,
                    }),
                    targets: Vec::new(),
                    configurations: Vec::new(),
                    artifact_sha256: None,
                }],
                provenance: Provenance {
                    source: "local dependency artifact".to_owned(),
                    revision: None,
                },
                license: "NOASSERTION".to_owned(),
                safety: Safety {
                    generated_code_only: false,
                    review_required: false,
                },
            },
            &ArtifactProducerLimits::default(),
        );
        self.production_diagnostics
            .extend(production.diagnostics.iter().cloned());
        self.complete &= production.completeness == Completeness::Complete;
        let Some(pack) = production.pack.as_ref() else {
            return;
        };
        for ty in project_pack_types(path, pack) {
            if ty.externally_visible() {
                self.namespaces.insert(ty.namespace.clone());
                let static_methods = ty
                    .members
                    .iter()
                    .filter(|member| member.is_static)
                    .filter(|member| member.kind == CSharpExternalMemberKind::Method)
                    .filter(|member| member.externally_visible())
                    .map(|member| member.name.clone());
                self.static_methods_by_namespace
                    .entry(ty.namespace.clone())
                    .or_default()
                    .extend(static_methods);
            }
            self.types.entry(ty.fqn.clone()).or_default().push(ty);
        }
    }
}

fn project_pack_types(path: &Path, pack: &AuthoredSemanticModelPack) -> Vec<CSharpExternalType> {
    let mut result = Vec::new();
    let mut type_indexes = HashMap::default();
    for shard in &pack.shards {
        let AuthoredPayload::DeclarationFacts { types, .. } = &shard.payload else {
            continue;
        };
        for fact in types {
            let (namespace, short_name) = fact
                .name
                .rsplit_once('.')
                .map_or(("", fact.name.as_str()), |(namespace, name)| {
                    (namespace, name)
                });
            let base = fact
                .hierarchy
                .iter()
                .find(|relation| relation.hierarchy_kind == HierarchyKind::Extends)
                .and_then(|relation| {
                    decoded_type_from_semantic(&relation.target, &fact.type_parameters, &[])
                });
            let interface_refs = fact
                .hierarchy
                .iter()
                .filter(|relation| relation.hierarchy_kind == HierarchyKind::Implements)
                .filter_map(|relation| {
                    decoded_type_from_semantic(&relation.target, &fact.type_parameters, &[])
                })
                .collect::<Vec<_>>();
            let source = CSharpExternalDeclarationSource::Assembly {
                path: path.to_path_buf(),
                metadata_token: locator_metadata_token(&fact.locator),
            };
            type_indexes.insert(fact.id.clone(), result.len());
            result.push(CSharpExternalType {
                fqn: fact.name.clone(),
                namespace: namespace.to_owned(),
                short_name: short_name.to_owned(),
                kind: external_type_kind(fact.type_kind),
                visibility: external_visibility(fact.visibility),
                is_abstract: fact.is_abstract,
                is_sealed: fact.is_sealed,
                generic_arity: fact.type_parameters.len(),
                type_parameters: fact.type_parameters.clone(),
                base,
                interfaces: interface_refs
                    .iter()
                    .map(DecodedType::legacy_name)
                    .collect(),
                interface_refs,
                source,
                members: Vec::new(),
                is_effectively_visible: true,
            });
        }
    }
    for shard in &pack.shards {
        let AuthoredPayload::DeclarationFacts { members, .. } = &shard.payload else {
            continue;
        };
        for fact in members {
            let Some(owner_index) = type_indexes.get(&fact.owner).copied() else {
                continue;
            };
            let owner = &result[owner_index];
            let signature = fact.signature.as_ref();
            let member_parameters = signature
                .map(|signature| signature.type_parameters.as_slice())
                .unwrap_or_default();
            let parameter_type_refs = signature
                .into_iter()
                .flat_map(|signature| &signature.parameters)
                .filter_map(|parameter| {
                    decoded_type_from_semantic(
                        &parameter.r#type,
                        &owner.type_parameters,
                        member_parameters,
                    )
                })
                .collect::<Vec<_>>();
            let return_type_ref = signature.and_then(|signature| {
                signature.returns.as_ref().and_then(|returns| {
                    decoded_type_from_semantic(returns, &owner.type_parameters, member_parameters)
                })
            });
            let member = CSharpExternalMember {
                name: fact.name.clone(),
                kind: external_member_kind(fact.member_kind),
                owner_fqn: owner.fqn.clone(),
                visibility: external_visibility(fact.visibility),
                is_static: fact.is_static,
                is_abstract: fact.is_abstract,
                is_virtual: fact.is_virtual,
                generic_arity: member_parameters.len(),
                type_parameters: member_parameters.to_vec(),
                return_type: return_type_ref.as_ref().map(DecodedType::legacy_name),
                parameter_types: parameter_type_refs
                    .iter()
                    .map(DecodedType::legacy_name)
                    .collect(),
                return_type_ref,
                parameter_type_refs,
                source: CSharpExternalDeclarationSource::Assembly {
                    path: path.to_path_buf(),
                    metadata_token: locator_metadata_token(&fact.locator),
                },
            };
            result[owner_index].members.push(member);
        }
    }
    result
}

fn locator_metadata_token(locator: &Locator) -> u32 {
    let Locator::Artifact { symbol, .. } = locator else {
        return 0;
    };
    u32::from_str_radix(symbol.strip_prefix("0x").unwrap_or(symbol), 16).unwrap_or(0)
}

fn decoded_type_from_semantic(
    value: &TypeRef,
    owner_parameters: &[String],
    member_parameters: &[String],
) -> Option<DecodedType> {
    match value {
        TypeRef::Named {
            name, arguments, ..
        } => Some(DecodedType::Named {
            name: name.clone(),
            arguments: arguments
                .iter()
                .map(|argument| {
                    decoded_type_from_semantic(argument, owner_parameters, member_parameters)
                })
                .collect::<Option<Vec<_>>>()?,
        }),
        TypeRef::TypeParameter { name } => member_parameters
            .iter()
            .position(|parameter| parameter == name)
            .map(|index| DecodedType::TypeParameter {
                method: true,
                index,
            })
            .or_else(|| {
                owner_parameters
                    .iter()
                    .position(|parameter| parameter == name)
                    .map(|index| DecodedType::TypeParameter {
                        method: false,
                        index,
                    })
            }),
        TypeRef::Array { element } => Some(DecodedType::Array {
            element: Box::new(decoded_type_from_semantic(
                element,
                owner_parameters,
                member_parameters,
            )?),
            rank: 1,
        }),
        TypeRef::ByRef { element } => Some(DecodedType::ByRef(Box::new(
            decoded_type_from_semantic(element, owner_parameters, member_parameters)?,
        ))),
        TypeRef::Declared { .. }
        | TypeRef::Pointer { .. }
        | TypeRef::Slice { .. }
        | TypeRef::FixedArray { .. }
        | TypeRef::Map { .. }
        | TypeRef::Channel { .. }
        | TypeRef::Wildcard { .. }
        | TypeRef::Tuple { .. }
        | TypeRef::Function { .. } => None,
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CSharpAssemblyPackProducer;

#[derive(Debug, Clone, Copy, Default)]
pub struct CSharpDependencyPackAdapter;

pub fn resolve_csharp_semantic_pack_dependencies(
    config: &CSharpAnalyzerConfig,
    project: &dyn Project,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> DependencyDiscoveryOutcome {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return csharp_cancelled_discovery();
    }
    let mut assemblies: Vec<_> = config
        .assembly_paths
        .iter()
        .map(|path| ResolvedCSharpAssembly {
            path: resolve_csharp_path(project.root(), path),
            package_name: None,
            package_version: None,
            target: None,
            configuration: None,
            role: DotNetAssetRole::Explicit,
            project_reference: false,
        })
        .collect();
    let assets_files = project_assets_files(project.root());
    let metadata_inputs_considered = config
        .assembly_paths
        .len()
        .saturating_add(assets_files.len());
    let mut diagnostic_messages = Vec::new();
    for assets in assets_files {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return csharp_cancelled_discovery();
        }
        let resolution = assemblies_from_assets(&assets);
        assemblies.extend(resolution.assemblies);
        diagnostic_messages.extend(resolution.diagnostics);
    }
    assemblies.sort_by(|left, right| {
        (
            &left.path,
            &left.package_name,
            &left.package_version,
            &left.target,
            &left.configuration,
            left.role,
        )
            .cmp(&(
                &right.path,
                &right.package_name,
                &right.package_version,
                &right.target,
                &right.configuration,
                right.role,
            ))
    });
    assemblies.dedup();
    let mut dependencies: Vec<_> = assemblies
        .into_iter()
        .map(resolved_csharp_dependency)
        .collect();
    let mut suppressed_diagnostics = 0;
    if dependencies.len() > limits.max_dependencies {
        suppressed_diagnostics = dependencies.len() - limits.max_dependencies;
        dependencies.truncate(limits.max_dependencies);
        diagnostic_messages.push(format!(
            ".NET dependency discovery exceeded the configured limit {}",
            limits.max_dependencies
        ));
    }
    let mut diagnostics: Vec<_> = diagnostic_messages
        .into_iter()
        .map(|message| DependencyPackDiagnostic {
            severity: DependencyPackDiagnosticSeverity::Error,
            code: "csharp.dependency_unresolved".to_owned(),
            dependency_id: None,
            location: None,
            message,
        })
        .collect();
    if diagnostics.len() > limits.max_diagnostics {
        suppressed_diagnostics =
            suppressed_diagnostics.saturating_add(diagnostics.len() - limits.max_diagnostics);
        diagnostics.truncate(limits.max_diagnostics);
    }
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

fn csharp_cancelled_discovery() -> DependencyDiscoveryOutcome {
    DependencyDiscoveryOutcome {
        dependencies: Vec::new(),
        diagnostics: vec![DependencyPackDiagnostic {
            severity: DependencyPackDiagnosticSeverity::Error,
            code: "discovery.cancelled".to_owned(),
            dependency_id: None,
            location: None,
            message: ".NET dependency discovery was cancelled".to_owned(),
        }],
        suppressed_diagnostics: 0,
        complete: false,
        cancelled: true,
        profile: DependencyDiscoveryProfile::default(),
    }
}

impl DependencyPackAdapter for CSharpDependencyPackAdapter {
    fn adapter_name(&self) -> &str {
        "bifrost-csharp-dependency"
    }

    fn adapter_version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn producer(&self) -> Producer {
        Producer {
            name: "bifrost-csharp-assembly".to_owned(),
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
        let Some(artifact) = artifacts.first().filter(|_| artifacts.len() == 1) else {
            return DependencyPackProduction {
                pack: None,
                diagnostics: vec![ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    code: "artifact.count".to_owned(),
                    location: None,
                    message: ".NET dependency production requires exactly one assembly".to_owned(),
                }],
                suppressed_diagnostics: 0,
            };
        };
        let mut request = csharp_dependency_production_request(dependency);
        request.path = artifact.path().to_owned();
        let mut production = CSharpAssemblyPackProducer.produce_loaded_artifact(
            &request,
            limits,
            cancellation,
            artifact.exact(),
        );
        debug_assert_eq!(
            production.artifact_sha256.as_deref(),
            Some(artifact.sha256())
        );
        if let Some(pack) = production.pack.as_mut() {
            normalize_artifact_locator_paths(
                pack,
                &format!("sha256-{}.artifact", artifact.sha256()),
            );
        }
        DependencyPackProduction {
            pack: production.pack,
            diagnostics: production.diagnostics,
            suppressed_diagnostics: production.suppressed_diagnostics,
        }
    }
}

impl ExternalArtifactPackProducer for CSharpAssemblyPackProducer {
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

impl CSharpAssemblyPackProducer {
    fn produce(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
    ) -> ArtifactProduction {
        if request.artifact_kind != ExternalArtifactKind::DotNetAssembly {
            return ArtifactProduction::failed(
                ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    code: "artifact.kind".to_owned(),
                    location: None,
                    message: "C# producer requires a .NET assembly artifact".to_owned(),
                },
                limits,
            );
        }
        let read_limits = ArtifactProducerLimits {
            max_artifact_bytes: limits.max_artifact_bytes.min(MAX_ASSEMBLY_BYTES),
            ..*limits
        };
        let artifact = match read_exact_artifact_while(&request.path, &read_limits, || {
            cancellation.is_some_and(CancellationToken::is_cancelled)
        }) {
            Ok(artifact) => artifact,
            Err(diagnostic) => return ArtifactProduction::failed(diagnostic, limits),
        };
        self.produce_loaded_artifact(request, limits, cancellation, &artifact)
    }

    pub(crate) fn produce_loaded_artifact(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
        artifact: &ExactArtifact,
    ) -> ArtifactProduction {
        if artifact.bytes().len() as u64 > limits.max_artifact_bytes.min(MAX_ASSEMBLY_BYTES) {
            return ArtifactProduction::failed(
                ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    code: "artifact.size".to_owned(),
                    location: Some(artifact.path().to_string_lossy().into_owned()),
                    message: "exact assembly exceeds the configured byte limit".to_owned(),
                },
                limits,
            );
        }
        let Some((external_types, omitted_signatures)) = parse_assembly_bounded(
            artifact.path(),
            artifact.bytes(),
            limits.max_signature_depth.min(MAX_SIGNATURE_DEPTH),
            cancellation,
        ) else {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return ArtifactProduction::failed(
                    ProducerDiagnostic {
                        severity: ProducerDiagnosticSeverity::Error,
                        code: "artifact.cancelled".to_owned(),
                        location: None,
                        message: ".NET assembly production was cancelled".to_owned(),
                    },
                    limits,
                );
            }
            return ArtifactProduction::failed(
                ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    code: "csharp.metadata.invalid".to_owned(),
                    location: None,
                    message: "artifact does not contain supported bounded CLI metadata".to_owned(),
                },
                limits,
            );
        };
        let Some(locator_path) = artifact
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned)
        else {
            return ArtifactProduction::failed(
                ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    code: "artifact.path_encoding".to_owned(),
                    location: None,
                    message: "artifact filename is not valid UTF-8".to_owned(),
                },
                limits,
            );
        };

        let mut diagnostics = BoundedProducerDiagnostics::new(limits);
        if omitted_signatures > 0 {
            diagnostics.warning(
                "csharp.signature.omitted",
                None,
                format!(
                    "omitted {omitted_signatures} members whose signatures were malformed, unsupported, or exceeded the configured depth"
                ),
            );
        }
        let mut type_ids = HashMap::default();
        for ty in external_types.iter().filter(|ty| ty.externally_visible()) {
            type_ids.insert(
                ty.fqn.clone(),
                type_declaration_id(TypeIdentity {
                    ecosystem: "cli",
                    name: &ty.fqn,
                }),
            );
        }

        let mut types = Vec::new();
        let mut members = Vec::new();
        let mut record_limit_reported = false;
        for ty in external_types.iter().filter(|ty| ty.externally_visible()) {
            if types.len().saturating_add(members.len()) >= limits.max_records {
                if !record_limit_reported {
                    diagnostics.warning(
                        "limit.records",
                        None,
                        format!(
                            "producer stopped after {} declaration records",
                            limits.max_records
                        ),
                    );
                }
                break;
            }
            let type_id = type_ids
                .get(&ty.fqn)
                .expect("visible types receive stable ids")
                .clone();
            let mut hierarchy = Vec::new();
            if let Some(base) = &ty.base {
                let base_name = base.legacy_name();
                if !matches!(
                    base_name.as_str(),
                    "System.Object"
                        | "System.ValueType"
                        | "System.Enum"
                        | "System.MulticastDelegate"
                ) {
                    match base.type_ref(&ty.type_parameters, &[]) {
                        Ok(target) => hierarchy.push(HierarchyFact {
                            hierarchy_kind: HierarchyKind::Extends,
                            target,
                            declaration_ordinal: None,
                        }),
                        Err(message) => diagnostics.warning(
                            "csharp.type.unsupported_base",
                            Some(metadata_location(ty.source())),
                            message,
                        ),
                    }
                }
            }
            for interface in &ty.interface_refs {
                match interface.type_ref(&ty.type_parameters, &[]) {
                    Ok(target) => hierarchy.push(HierarchyFact {
                        hierarchy_kind: HierarchyKind::Implements,
                        target,
                        declaration_ordinal: None,
                    }),
                    Err(message) => diagnostics.warning(
                        "csharp.type.unsupported_interface",
                        Some(metadata_location(ty.source())),
                        message,
                    ),
                }
            }
            types.push(TypeFact {
                id: type_id.clone(),
                name: ty.fqn.clone(),
                type_kind: semantic_type_kind(ty.kind),
                visibility: semantic_visibility(ty.visibility),
                is_abstract: ty.is_abstract,
                is_sealed: ty.is_sealed,
                has_explicit_type_terms: false,
                type_parameters: ty.type_parameters.clone(),
                type_parameter_constraints: Vec::new(),
                underlying_type: None,
                embedded_types: Vec::new(),
                hierarchy,
                aliases: Vec::new(),
                extension_surfaces: Vec::new(),
                locator: Locator::Artifact {
                    path: locator_path.clone(),
                    symbol: metadata_location(ty.source()),
                },
            });

            for member in ty
                .members
                .iter()
                .filter(|member| member.externally_visible())
            {
                if types.len().saturating_add(members.len()) >= limits.max_records {
                    if !record_limit_reported {
                        diagnostics.warning(
                            "limit.records",
                            None,
                            format!(
                                "producer stopped after {} declaration records",
                                limits.max_records
                            ),
                        );
                        record_limit_reported = true;
                    }
                    break;
                }
                let parameter_types = match member
                    .parameter_type_refs
                    .iter()
                    .map(|value| value.type_ref(&ty.type_parameters, &member.type_parameters))
                    .collect::<Result<Vec<_>, _>>()
                {
                    Ok(types) => types,
                    Err(message) => {
                        diagnostics.warning(
                            "csharp.member.unsupported_parameter_type",
                            Some(metadata_location(member.source())),
                            message,
                        );
                        continue;
                    }
                };
                let returns = match member.return_type_ref.as_ref() {
                    None | Some(DecodedType::Void) => None,
                    Some(value) => {
                        match value.type_ref(&ty.type_parameters, &member.type_parameters) {
                            Ok(value) => Some(value),
                            Err(message) => {
                                diagnostics.warning(
                                    "csharp.member.unsupported_return_type",
                                    Some(metadata_location(member.source())),
                                    message,
                                );
                                continue;
                            }
                        }
                    }
                };
                if member.generic_arity != member.type_parameters.len() {
                    diagnostics.warning(
                        "csharp.member.missing_generic_parameter_names",
                        Some(metadata_location(member.source())),
                        format!(
                            "signature declares {} generic parameters but metadata names {}",
                            member.generic_arity,
                            member.type_parameters.len()
                        ),
                    );
                }
                let member_kind = semantic_member_kind(member.kind);
                let id = member_declaration_id(MemberIdentity {
                    owner_id: &type_id,
                    kind: member_kind,
                    is_static: member.is_static,
                    parameter_arity: parameter_types.len(),
                    name: &member.name,
                    generic_arity: member.generic_arity,
                    parameter_types: &parameter_types,
                    parameter_variadics: &[],
                    return_type: returns.as_ref(),
                });
                members.push(MemberFact {
                    id,
                    owner: type_id.clone(),
                    name: member.name.clone(),
                    member_kind,
                    visibility: semantic_visibility(member.visibility),
                    is_static: member.is_static,
                    is_abstract: member.is_abstract,
                    is_virtual: member.is_virtual,
                    signature: Some(Signature {
                        type_parameters: member.type_parameters.clone(),
                        parameters: parameter_types
                            .into_iter()
                            .map(|r#type| Parameter {
                                name: None,
                                r#type,
                                optional: false,
                                variadic: false,
                            })
                            .collect(),
                        returns,
                    }),
                    receiver: None,
                    extension_receiver: None,
                    extension_receiver_constraints: Vec::new(),
                    aliases: Vec::new(),
                    locator: Locator::Artifact {
                        path: locator_path.clone(),
                        symbol: metadata_location(member.source()),
                    },
                });
            }
        }

        if types.is_empty() {
            diagnostics.error(
                "csharp.metadata.no_external_declarations",
                None,
                "assembly contains no externally visible declarations",
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

        let mut activation = request.activation.clone();
        for selector in &mut activation {
            selector.artifact_sha256 = Some(artifact.sha256().to_owned());
        }
        let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
        let completeness = if diagnostics.is_empty() && suppressed_diagnostics == 0 {
            Completeness::Complete
        } else {
            Completeness::Partial
        };
        let pack = AuthoredSemanticModelPack {
            schema_version: super::super::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
            pack_id: request.pack_id.clone(),
            version: request.pack_version.clone(),
            producer: Producer {
                name: "bifrost-csharp-assembly".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            },
            language: "csharp".to_owned(),
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
        };
        ArtifactProduction {
            artifact_sha256: Some(artifact.sha256().to_owned()),
            pack: Some(pack),
            completeness,
            diagnostics,
            suppressed_diagnostics,
        }
    }
}

fn metadata_location(source: &CSharpExternalDeclarationSource) -> String {
    match source {
        CSharpExternalDeclarationSource::Assembly { metadata_token, .. } => {
            format!("0x{metadata_token:08x}")
        }
    }
}

fn semantic_type_kind(kind: CSharpExternalTypeKind) -> TypeKind {
    match kind {
        CSharpExternalTypeKind::Class => TypeKind::Class,
        CSharpExternalTypeKind::Interface => TypeKind::Interface,
        CSharpExternalTypeKind::Struct => TypeKind::Struct,
        CSharpExternalTypeKind::Enum => TypeKind::Enum,
        CSharpExternalTypeKind::Delegate => TypeKind::Delegate,
    }
}

fn semantic_member_kind(kind: CSharpExternalMemberKind) -> MemberKind {
    match kind {
        CSharpExternalMemberKind::Constructor => MemberKind::Constructor,
        CSharpExternalMemberKind::Method => MemberKind::Method,
        CSharpExternalMemberKind::Field => MemberKind::Field,
        CSharpExternalMemberKind::Property => MemberKind::Property,
        CSharpExternalMemberKind::Event => MemberKind::Event,
    }
}

fn semantic_visibility(visibility: CSharpVisibility) -> Visibility {
    match visibility {
        CSharpVisibility::Private => Visibility::Private,
        CSharpVisibility::Internal => Visibility::Internal,
        CSharpVisibility::ProtectedAndInternal => Visibility::Internal,
        CSharpVisibility::Protected => Visibility::Protected,
        CSharpVisibility::ProtectedOrInternal => Visibility::ProtectedInternal,
        CSharpVisibility::Public => Visibility::Public,
    }
}

fn external_type_kind(kind: TypeKind) -> CSharpExternalTypeKind {
    match kind {
        TypeKind::Interface | TypeKind::Trait => CSharpExternalTypeKind::Interface,
        TypeKind::Struct | TypeKind::Union | TypeKind::Record => CSharpExternalTypeKind::Struct,
        TypeKind::Enum => CSharpExternalTypeKind::Enum,
        TypeKind::Delegate => CSharpExternalTypeKind::Delegate,
        TypeKind::Class | TypeKind::Annotation | TypeKind::Module | TypeKind::TypeAlias => {
            CSharpExternalTypeKind::Class
        }
    }
}

fn external_member_kind(kind: MemberKind) -> CSharpExternalMemberKind {
    match kind {
        MemberKind::Constructor => CSharpExternalMemberKind::Constructor,
        MemberKind::Field | MemberKind::Constant | MemberKind::Static => {
            CSharpExternalMemberKind::Field
        }
        MemberKind::Property => CSharpExternalMemberKind::Property,
        MemberKind::Event => CSharpExternalMemberKind::Event,
        MemberKind::Method | MemberKind::Function | MemberKind::Macro => {
            CSharpExternalMemberKind::Method
        }
    }
}

fn external_visibility(visibility: Visibility) -> CSharpVisibility {
    match visibility {
        Visibility::Public => CSharpVisibility::Public,
        Visibility::Protected => CSharpVisibility::Protected,
        Visibility::Internal | Visibility::Package => CSharpVisibility::Internal,
        Visibility::ProtectedInternal => CSharpVisibility::ProtectedOrInternal,
        Visibility::Private => CSharpVisibility::Private,
    }
}

fn metadata_type_identity(reference: &str) -> String {
    let reference = reference.trim().trim_end_matches("[]");
    let Some(open) = reference.find('<') else {
        return reference.to_string();
    };
    let Some(close) = reference.rfind('>') else {
        return reference[..open].trim().to_string();
    };
    if close < open {
        return reference[..open].trim().to_string();
    }
    let mut depth = 0usize;
    let mut arity = 1usize;
    for character in reference[open + 1..close].chars() {
        match character {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => arity += 1,
            _ => {}
        }
    }
    format!("{}`{arity}", reference[..open].trim())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum DotNetAssetRole {
    Reference,
    Compile,
    Runtime,
    ProjectOutput,
    Explicit,
}

impl DotNetAssetRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Reference => "reference",
            Self::Compile => "compile",
            Self::Runtime => "runtime",
            Self::ProjectOutput => "project_output",
            Self::Explicit => "explicit",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedCSharpAssembly {
    path: PathBuf,
    package_name: Option<String>,
    package_version: Option<String>,
    target: Option<String>,
    configuration: Option<String>,
    role: DotNetAssetRole,
    project_reference: bool,
}

fn resolve_csharp_path(project_root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        project_root.join(path)
    }
}

fn resolved_csharp_dependency(assembly: ResolvedCSharpAssembly) -> ResolvedDependency {
    let assembly_name = assembly
        .path
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let id = match (&assembly.package_name, &assembly.package_version) {
        (Some(name), Some(version)) => format!("{name}/{version}:{assembly_name}"),
        _ => format!("explicit:{assembly_name}"),
    };
    let package = assembly
        .package_name
        .as_ref()
        .map(|name| CatalogCoordinate {
            name: name.clone(),
            version: assembly
                .package_version
                .as_deref()
                .and_then(|version| Version::parse(version).ok()),
        });
    let mut provenance = vec![
        DependencyProvenance {
            key: "asset_role".to_owned(),
            value: assembly.role.as_str().to_owned(),
        },
        DependencyProvenance {
            key: "project_reference".to_owned(),
            value: assembly.project_reference.to_string(),
        },
    ];
    for (key, value) in [
        ("package", assembly.package_name.as_ref()),
        ("version", assembly.package_version.as_ref()),
        ("target", assembly.target.as_ref()),
        ("configuration", assembly.configuration.as_ref()),
    ] {
        if let Some(value) = value {
            provenance.push(DependencyProvenance {
                key: key.to_owned(),
                value: value.clone(),
            });
        }
    }
    let artifact_role = match assembly.role {
        DotNetAssetRole::Reference | DotNetAssetRole::Compile => DependencyArtifactRole::Reference,
        DotNetAssetRole::Runtime | DotNetAssetRole::ProjectOutput | DotNetAssetRole::Explicit => {
            DependencyArtifactRole::Runtime
        }
    };
    ResolvedDependency {
        id,
        evidence: SemanticModelActivationEvidence {
            language: "csharp".to_owned(),
            ecosystem: if package.is_some() { "nuget" } else { "dotnet" }.to_owned(),
            package,
            module: Some(CatalogCoordinate {
                name: if assembly.package_name.is_some() {
                    assembly_name
                } else {
                    "local-dotnet-assembly".to_owned()
                },
                version: None,
            }),
            toolchain: None,
            target: assembly.target,
            configuration: assembly.configuration,
            artifact_sha256: None,
        },
        provenance,
        artifacts: vec![ResolvedDependencyArtifact::file(
            artifact_role,
            ExternalArtifactKind::DotNetAssembly,
            assembly.path,
        )],
    }
}

fn csharp_dependency_production_request(
    dependency: &ResolvedDependency,
) -> ArtifactProductionRequest {
    ArtifactProductionRequest {
        path: PathBuf::new(),
        artifact_kind: ExternalArtifactKind::DotNetAssembly,
        pack_id: "bifrost.external.csharp".to_owned(),
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
                    version: None,
                }),
            toolchain: None,
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
            source: "exact local .NET dependency".to_owned(),
            revision: None,
        },
        license: "NOASSERTION".to_owned(),
        safety: Safety {
            generated_code_only: false,
            review_required: false,
        },
    }
}

#[derive(Default)]
struct CSharpAssetsResolution {
    assemblies: Vec<ResolvedCSharpAssembly>,
    diagnostics: Vec<String>,
}

fn assemblies_from_assets(path: &Path) -> CSharpAssetsResolution {
    let Ok(meta) = fs::metadata(path) else {
        return CSharpAssetsResolution {
            diagnostics: vec![format!("could not inspect {}", path.display())],
            ..CSharpAssetsResolution::default()
        };
    };
    if meta.len() > MAX_ASSETS_BYTES {
        return CSharpAssetsResolution {
            diagnostics: vec![format!(
                "{} exceeds the {} byte project.assets.json limit",
                path.display(),
                MAX_ASSETS_BYTES
            )],
            ..CSharpAssetsResolution::default()
        };
    };
    let Ok(text) = fs::read_to_string(path) else {
        return CSharpAssetsResolution {
            diagnostics: vec![format!("could not read {}", path.display())],
            ..CSharpAssetsResolution::default()
        };
    };
    let Ok(root): Result<Value, _> = serde_json::from_str(&text) else {
        return CSharpAssetsResolution {
            diagnostics: vec![format!("could not parse {}", path.display())],
            ..CSharpAssetsResolution::default()
        };
    };
    let workspace_root = path
        .parent()
        .and_then(Path::parent)
        .and_then(|root| root.canonicalize().ok());
    let approved_package_roots = approved_package_roots(workspace_root.as_deref());
    let folders = root
        .get("packageFolders")
        .and_then(Value::as_object)
        .map(|o| {
            o.keys()
                .filter_map(|folder| PathBuf::from(folder).canonicalize().ok())
                .filter(|folder| approved_package_roots.contains(folder))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut out = Vec::new();
    let mut diagnostics = Vec::new();
    for (target_name, target) in root
        .get("targets")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|targets| targets.iter())
        .filter_map(|(name, target)| target.as_object().map(|target| (name, target)))
    {
        for (library, entry) in target {
            let (package_name, package_version) = library
                .rsplit_once('/')
                .map(|(name, version)| (name.to_owned(), version.to_owned()))
                .unwrap_or_else(|| (library.clone(), String::new()));
            let project_path = root
                .get("libraries")
                .and_then(Value::as_object)
                .and_then(|libraries| libraries.get(library))
                .filter(|entry| entry.get("type").and_then(Value::as_str) == Some("project"))
                .and_then(|entry| entry.get("path"))
                .and_then(Value::as_str);
            for (section, role) in [
                ("ref", DotNetAssetRole::Reference),
                ("compile", DotNetAssetRole::Compile),
                ("runtime", DotNetAssetRole::Runtime),
            ] {
                for relative in entry
                    .get(section)
                    .and_then(Value::as_object)
                    .into_iter()
                    .flat_map(|o| o.keys())
                {
                    if !relative.ends_with(".dll") && !relative.ends_with(".exe") {
                        continue;
                    }
                    let Some(relative) = safe_relative_path(relative) else {
                        continue;
                    };
                    let Some(library) = safe_relative_path(library) else {
                        continue;
                    };
                    let out_start = out.len();
                    for folder in &folders {
                        let candidate = folder.join(library).join(relative);
                        if let Ok(candidate) = candidate.canonicalize()
                            && candidate.starts_with(folder)
                            && candidate.is_file()
                        {
                            out.push(ResolvedCSharpAssembly {
                                path: candidate,
                                package_name: Some(package_name.clone()),
                                package_version: (!package_version.is_empty())
                                    .then(|| package_version.clone()),
                                target: Some(target_name.clone()),
                                configuration: None,
                                role,
                                project_reference: false,
                            });
                        }
                    }
                    if let (Some(root), Some(project_path)) =
                        (workspace_root.as_ref(), project_path)
                    {
                        let project_path = path
                            .parent()
                            .and_then(Path::parent)
                            .unwrap_or(root)
                            .join(project_path);
                        if let Ok(project_path) = project_path.canonicalize()
                            && project_path.starts_with(root)
                        {
                            let project_root = if project_path.is_dir() {
                                project_path
                            } else {
                                project_path
                                    .parent()
                                    .map(Path::to_path_buf)
                                    .unwrap_or_default()
                            };
                            out.extend(
                                project_output_candidates(
                                    &project_root,
                                    relative.file_name(),
                                    root,
                                    target_name,
                                )
                                .into_iter()
                                .map(|(path, configuration)| ResolvedCSharpAssembly {
                                    path,
                                    package_name: Some(package_name.clone()),
                                    package_version: (!package_version.is_empty())
                                        .then(|| package_version.clone()),
                                    target: Some(target_name.clone()),
                                    configuration,
                                    role: DotNetAssetRole::ProjectOutput,
                                    project_reference: true,
                                }),
                            );
                        }
                    }
                    if out.len() == out_start {
                        diagnostics.push(format!(
                            "restored assembly {} for {} target {} was not found under an approved root",
                            relative.display(),
                            library.display(),
                            target_name
                        ));
                    }
                }
            }
        }
    }
    out.sort_by(|left, right| {
        (
            &left.target,
            &left.package_name,
            &left.package_version,
            &left.configuration,
            left.path.file_name(),
            left.role,
            &left.path,
        )
            .cmp(&(
                &right.target,
                &right.package_name,
                &right.package_version,
                &right.configuration,
                right.path.file_name(),
                right.role,
                &right.path,
            ))
    });
    let mut seen = crate::hash::HashSet::default();
    out.retain(|assembly| {
        seen.insert((
            assembly.target.clone(),
            assembly.package_name.clone(),
            assembly.package_version.clone(),
            assembly.configuration.clone(),
            assembly.path.file_name().map(std::ffi::OsStr::to_owned),
        ))
    });
    CSharpAssetsResolution {
        assemblies: out,
        diagnostics,
    }
}

fn approved_package_roots(workspace_root: Option<&Path>) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(path) = std::env::var_os("NUGET_PACKAGES").map(PathBuf::from) {
        roots.push(path);
    }
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        roots.push(home.join(".nuget/packages"));
    }
    if let Some(root) = workspace_root {
        roots.push(root.join(".nuget/packages"));
    }
    roots
        .into_iter()
        .filter_map(|root| root.canonicalize().ok())
        .collect()
}

fn project_output_candidates(
    project_root: &Path,
    filename: Option<&std::ffi::OsStr>,
    workspace_root: &Path,
    target: &str,
) -> Vec<(PathBuf, Option<String>)> {
    let Some(filename) = filename else {
        return Vec::new();
    };
    let bin = project_root.join("bin");
    if !bin.is_dir() {
        return Vec::new();
    }
    let Ok(bin) = bin.canonicalize() else {
        return Vec::new();
    };
    let Ok(workspace_root) = workspace_root.canonicalize() else {
        return Vec::new();
    };
    let mut candidates: Vec<_> = WalkDir::new(&bin)
        .follow_links(false)
        .max_depth(5)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file() && entry.file_name() == filename)
        .filter_map(|entry| entry.into_path().canonicalize().ok())
        .filter(|candidate| candidate.starts_with(&workspace_root))
        .filter(|candidate| project_output_matches_target(&bin, candidate, target))
        .map(|candidate| {
            let configuration = candidate
                .strip_prefix(&bin)
                .ok()
                .and_then(|relative| relative.components().next())
                .and_then(|component| match component {
                    std::path::Component::Normal(value) => {
                        Some(value.to_string_lossy().into_owned())
                    }
                    _ => None,
                });
            (candidate, configuration)
        })
        .collect();
    candidates.sort();
    candidates.truncate(MAX_PROJECT_OUTPUTS);
    candidates
}

fn project_output_matches_target(bin: &Path, candidate: &Path, target: &str) -> bool {
    let mut target_parts = target.split('/');
    let framework = target_parts.next().unwrap_or_default();
    let runtime = target_parts.next();
    let mut components = candidate
        .strip_prefix(bin)
        .ok()
        .into_iter()
        .flat_map(Path::components)
        .filter_map(|component| match component {
            std::path::Component::Normal(value) => Some(value.to_string_lossy()),
            _ => None,
        });
    let _configuration = components.next();
    components.next().as_deref() == Some(framework)
        && runtime.is_none_or(|runtime| components.next().as_deref() == Some(runtime))
}

fn safe_relative_path(value: &str) -> Option<&Path> {
    let path = Path::new(value);
    (!path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_))))
    .then_some(path)
}

#[derive(Clone)]
struct TypeRow {
    flags: u32,
    name: String,
    namespace: String,
    extends: u32,
    field_start: u32,
    method_start: u32,
}
#[derive(Clone)]
struct TypeRefRow {
    scope: u32,
    name: String,
    namespace: String,
}
#[derive(Clone)]
struct TypeSpecRow {
    sig: Vec<u8>,
}
#[derive(Clone)]
struct FieldRow {
    flags: u16,
    name: String,
    sig: Vec<u8>,
}
#[derive(Clone)]
struct MethodRow {
    flags: u16,
    name: String,
    sig: Vec<u8>,
}
#[derive(Clone)]
struct PropertyRow {
    flags: u16,
    name: String,
    sig: Vec<u8>,
}
#[derive(Clone)]
struct EventRow {
    flags: u16,
    name: String,
    event_type: u32,
}

#[cfg(test)]
fn parse_assembly(path: &Path, bytes: &[u8]) -> Option<Vec<CSharpExternalType>> {
    parse_assembly_bounded(path, bytes, MAX_SIGNATURE_DEPTH, None).map(|(types, _)| types)
}

fn parse_assembly_bounded(
    path: &Path,
    bytes: &[u8],
    max_signature_depth: usize,
    cancellation: Option<&CancellationToken>,
) -> Option<(Vec<CSharpExternalType>, usize)> {
    let pe = PE::parse(bytes).ok()?;
    let metadata = metadata_bytes(&pe, bytes)?;
    let streams = Streams::parse(metadata)?;
    let tables = streams.tables?;
    let strings = streams.strings.unwrap_or(&[]);
    let blobs = streams.blobs.unwrap_or(&[]);
    let layout = TableLayout::parse(tables)?;
    if layout.rows.iter().any(|rows| *rows > MAX_METADATA_ROWS)
        || layout
            .rows
            .iter()
            .try_fold(0u32, |total, rows| total.checked_add(*rows))?
            > MAX_METADATA_TOTAL_ROWS
        || strings.len() > MAX_ASSETS_BYTES as usize
        || blobs.len() > MAX_ASSETS_BYTES as usize
    {
        return None;
    }
    let mut decode_budget = MetadataDecodeBudget::default();
    let types = collect_metadata_rows(layout.rows(2), cancellation, |i| {
        read_typedef(&layout, i, strings, &mut decode_budget)
    })?;
    let type_refs = collect_metadata_rows(layout.rows(1), cancellation, |i| {
        read_typeref(&layout, i, strings, &mut decode_budget)
    })?;
    let type_specs = collect_metadata_rows(layout.rows(27), cancellation, |i| {
        read_typespec(&layout, i, blobs, &mut decode_budget)
    })?;
    let fields = collect_metadata_rows(layout.rows(4), cancellation, |i| {
        read_field(&layout, i, strings, blobs, &mut decode_budget)
    })?;
    let methods = collect_metadata_rows(layout.rows(6), cancellation, |i| {
        read_method(&layout, i, strings, blobs, &mut decode_budget)
    })?;
    let properties = collect_metadata_rows(layout.rows(23), cancellation, |i| {
        read_property(&layout, i, strings, blobs, &mut decode_budget)
    })?;
    let events = collect_metadata_rows(layout.rows(20), cancellation, |i| {
        read_event(&layout, i, strings, &mut decode_budget)
    })?;
    let nested = nested_map(&layout);
    let property_owners = property_owners(&layout, types.len() as u32, properties.len() as u32);
    let property_accessors = property_accessors(&layout, &methods);
    let event_owners = event_owners(&layout, types.len() as u32, events.len() as u32);
    let event_accessors = association_accessors(&layout, &methods, 0);
    let generic = generic_parameters(&layout, strings, &mut decode_budget);
    let interfaces = interfaces_for(&layout, &types, &type_refs, &type_specs);
    let mut names = Vec::new();
    for (idx, row) in types.iter().enumerate() {
        if !cancellation_checkpoint(cancellation, idx) {
            return None;
        }
        names.push(full_type_name((idx + 1) as u32, row, &types, &nested));
    }
    let mut result = Vec::new();
    let mut omitted_signatures = 0usize;
    for (idx, row) in types.iter().enumerate() {
        if !cancellation_checkpoint(cancellation, idx) {
            return None;
        }
        let token = 0x0200_0000 | ((idx + 1) as u32);
        let fqn = names[idx].clone();
        let end_field = types
            .get(idx + 1)
            .map(|r| r.field_start)
            .unwrap_or(fields.len() as u32 + 1);
        let end_method = types
            .get(idx + 1)
            .map(|r| r.method_start)
            .unwrap_or(methods.len() as u32 + 1);
        let mut members = Vec::new();
        for (field_index, f) in fields
            .iter()
            .enumerate()
            .skip(row.field_start.saturating_sub(1) as usize)
            .take(end_field.saturating_sub(row.field_start) as usize)
        {
            if let Some(member) = member(
                path,
                0x0400_0000 | (field_index as u32 + 1),
                &fqn,
                &f.name,
                CSharpExternalMemberKind::Field,
                f.flags,
                false,
                Vec::new(),
                &f.sig,
                &types,
                &type_refs,
                &type_specs,
                max_signature_depth,
            ) {
                members.push(member);
            } else {
                omitted_signatures = omitted_signatures.saturating_add(1);
            }
        }
        for (method_index, m) in methods
            .iter()
            .enumerate()
            .skip(row.method_start.saturating_sub(1) as usize)
            .take(end_method.saturating_sub(row.method_start) as usize)
        {
            let kind = if m.name == ".ctor" || m.name == ".cctor" {
                CSharpExternalMemberKind::Constructor
            } else {
                CSharpExternalMemberKind::Method
            };
            if let Some(member) = member(
                path,
                0x0600_0000 | (method_index as u32 + 1),
                &fqn,
                &m.name,
                kind,
                m.flags,
                true,
                generic
                    .methods
                    .get(&(method_index as u32 + 1))
                    .cloned()
                    .unwrap_or_default(),
                &m.sig,
                &types,
                &type_refs,
                &type_specs,
                max_signature_depth,
            ) {
                members.push(member);
            } else {
                omitted_signatures = omitted_signatures.saturating_add(1);
            }
        }
        for (pidx, p) in properties
            .iter()
            .enumerate()
            .filter(|(pidx, _)| property_owners.get(&(*pidx as u32 + 1)) == Some(&(idx as u32 + 1)))
        {
            let flags = property_accessors
                .get(&(pidx as u32 + 1))
                .copied()
                .unwrap_or(p.flags);
            if let Some(member) = member(
                path,
                0x1700_0000 | (pidx as u32 + 1),
                &fqn,
                &p.name,
                CSharpExternalMemberKind::Property,
                flags,
                false,
                Vec::new(),
                &p.sig,
                &types,
                &type_refs,
                &type_specs,
                max_signature_depth,
            ) {
                members.push(member);
            } else {
                omitted_signatures = omitted_signatures.saturating_add(1);
            }
        }
        for (event_index, event) in events.iter().enumerate().filter(|(event_index, _)| {
            event_owners.get(&(*event_index as u32 + 1)) == Some(&(idx as u32 + 1))
        }) {
            let flags = event_accessors
                .get(&(event_index as u32 + 1))
                .copied()
                .unwrap_or(event.flags);
            let Some(event_type) = resolve_typedef_or_ref_type_at_depth(
                event.event_type,
                &types,
                &type_refs,
                &type_specs,
                max_signature_depth,
                0,
            ) else {
                omitted_signatures = omitted_signatures.saturating_add(1);
                continue;
            };
            members.push(CSharpExternalMember {
                owner_fqn: fqn.clone(),
                name: event.name.clone(),
                kind: CSharpExternalMemberKind::Event,
                visibility: member_visibility(flags),
                is_static: flags & 0x10 != 0,
                is_abstract: flags & 0x400 != 0,
                is_virtual: flags & 0x40 != 0,
                generic_arity: 0,
                type_parameters: Vec::new(),
                return_type: Some(event_type.legacy_name()),
                parameter_types: Vec::new(),
                return_type_ref: Some(event_type),
                parameter_type_refs: Vec::new(),
                source: CSharpExternalDeclarationSource::Assembly {
                    path: path.to_path_buf(),
                    metadata_token: 0x1400_0000 | (event_index as u32 + 1),
                },
            });
        }
        let namespace = fqn
            .rsplit_once('.')
            .map(|(ns, _)| ns.to_string())
            .unwrap_or_default();
        let short_name = fqn.rsplit('.').next().unwrap_or(&fqn).to_string();
        let base = resolve_typedef_or_ref_type(row.extends, &types, &type_refs, &type_specs);
        let base_name = base
            .as_ref()
            .map(DecodedType::legacy_name)
            .unwrap_or_default();
        let kind = if row.flags & 0x20 != 0 {
            CSharpExternalTypeKind::Interface
        } else if base_name.ends_with("System.Enum") {
            CSharpExternalTypeKind::Enum
        } else if base_name.ends_with("System.ValueType") {
            CSharpExternalTypeKind::Struct
        } else if base_name.ends_with("System.MulticastDelegate") {
            CSharpExternalTypeKind::Delegate
        } else {
            CSharpExternalTypeKind::Class
        };
        result.push(CSharpExternalType {
            fqn,
            namespace,
            short_name,
            kind,
            visibility: type_visibility(row.flags),
            is_abstract: row.flags & 0x80 != 0,
            is_sealed: row.flags & 0x100 != 0,
            generic_arity: generic
                .types
                .get(&((idx + 1) as u32))
                .map(Vec::len)
                .unwrap_or(0),
            type_parameters: generic
                .types
                .get(&((idx + 1) as u32))
                .cloned()
                .unwrap_or_default(),
            base,
            interfaces: interfaces
                .get(&((idx + 1) as u32))
                .into_iter()
                .flatten()
                .map(DecodedType::legacy_name)
                .collect(),
            interface_refs: interfaces
                .get(&((idx + 1) as u32))
                .cloned()
                .unwrap_or_default(),
            source: CSharpExternalDeclarationSource::Assembly {
                path: path.to_path_buf(),
                metadata_token: token,
            },
            members,
            is_effectively_visible: false,
        });
    }
    for index in 0..result.len() {
        result[index].is_effectively_visible =
            effective_type_visibility((index + 1) as u32, &result, &nested);
    }
    Some((result, omitted_signatures))
}

fn collect_metadata_rows<T>(
    count: u32,
    cancellation: Option<&CancellationToken>,
    mut read: impl FnMut(u32) -> Option<T>,
) -> Option<Vec<T>> {
    let mut rows = Vec::with_capacity(count as usize);
    for index in 1..=count {
        if !cancellation_checkpoint(cancellation, index as usize) {
            return None;
        }
        rows.push(read(index)?);
    }
    Some(rows)
}

fn cancellation_checkpoint(cancellation: Option<&CancellationToken>, index: usize) -> bool {
    !index.is_multiple_of(256) || !cancellation.is_some_and(CancellationToken::is_cancelled)
}

fn effective_type_visibility(
    mut index: u32,
    types: &[CSharpExternalType],
    nested: &HashMap<u32, u32>,
) -> bool {
    for _ in 0..types.len() {
        let Some(ty) = types.get(index.saturating_sub(1) as usize) else {
            return false;
        };
        if !matches!(
            ty.visibility,
            CSharpVisibility::Public
                | CSharpVisibility::Protected
                | CSharpVisibility::ProtectedOrInternal
        ) {
            return false;
        }
        let Some(owner) = nested.get(&index).copied() else {
            return true;
        };
        index = owner;
    }
    false
}

fn metadata_bytes<'a>(pe: &PE<'_>, bytes: &'a [u8]) -> Option<&'a [u8]> {
    let clr = pe.clr_data?;
    let rva = clr.cor20_header.metadata.virtual_address;
    let size = clr.cor20_header.metadata.size as usize;
    let section = pe.sections.iter().find(|section| {
        rva >= section.virtual_address
            && rva
                < section
                    .virtual_address
                    .saturating_add(section.virtual_size.max(1))
    })?;
    let offset =
        section.pointer_to_raw_data as usize + rva.checked_sub(section.virtual_address)? as usize;
    bytes.get(offset..offset.checked_add(size)?)
}

#[allow(clippy::too_many_arguments)] // Metadata tables are distinct, borrowed inputs in a hot decode path.
fn member(
    path: &Path,
    token: u32,
    owner: &str,
    name: &str,
    kind: CSharpExternalMemberKind,
    flags: u16,
    method: bool,
    type_parameters: Vec<String>,
    sig: &[u8],
    types: &[TypeRow],
    type_refs: &[TypeRefRow],
    type_specs: &[TypeSpecRow],
    max_signature_depth: usize,
) -> Option<CSharpExternalMember> {
    let (return_type_ref, parameter_type_refs, generic_arity) = decode_signature(
        sig,
        method,
        types,
        type_refs,
        type_specs,
        max_signature_depth,
    )?;
    Some(CSharpExternalMember {
        owner_fqn: owner.to_string(),
        name: name.to_string(),
        kind,
        visibility: member_visibility(flags),
        is_static: flags & 0x10 != 0,
        is_abstract: flags & 0x400 != 0,
        is_virtual: flags & 0x40 != 0,
        generic_arity,
        type_parameters,
        return_type: return_type_ref.as_ref().map(DecodedType::legacy_name),
        parameter_types: parameter_type_refs
            .iter()
            .map(DecodedType::legacy_name)
            .collect(),
        return_type_ref,
        parameter_type_refs,
        source: CSharpExternalDeclarationSource::Assembly {
            path: path.to_path_buf(),
            metadata_token: token,
        },
    })
}

struct Streams<'a> {
    tables: Option<&'a [u8]>,
    strings: Option<&'a [u8]>,
    blobs: Option<&'a [u8]>,
}
impl<'a> Streams<'a> {
    fn parse(bytes: &'a [u8]) -> Option<Self> {
        let mut p = 0;
        take(bytes, &mut p, 4)?;
        take(bytes, &mut p, 2)?;
        take(bytes, &mut p, 2)?;
        take(bytes, &mut p, 4)?;
        let len = u32at(bytes, &mut p)? as usize;
        take(bytes, &mut p, len)?;
        p = (p + 3) & !3;
        take(bytes, &mut p, 2)?;
        let count = u16at(bytes, &mut p)?;
        let mut out = Self {
            tables: None,
            strings: None,
            blobs: None,
        };
        for _ in 0..count {
            let off = u32at(bytes, &mut p)? as usize;
            let size = u32at(bytes, &mut p)? as usize;
            let start = p;
            while *bytes.get(p)? != 0 {
                p += 1;
            }
            let name = std::str::from_utf8(&bytes[start..p]).ok()?;
            p = (p + 4) & !3;
            let Some(end) = off.checked_add(size) else {
                continue;
            };
            let Some(data) = bytes.get(off..end) else {
                continue;
            };
            match name {
                "#~" | "#-" => out.tables = Some(data),
                "#Strings" => out.strings = Some(data),
                "#Blob" => out.blobs = Some(data),
                _ => {}
            }
        }
        Some(out)
    }
}
struct TableLayout<'a> {
    data: &'a [u8],
    rows: [u32; 45],
    starts: [usize; 45],
    heap: u8,
}
impl<'a> TableLayout<'a> {
    fn parse(data: &'a [u8]) -> Option<Self> {
        let mut p = 0;
        take(data, &mut p, 4)?;
        take(data, &mut p, 1)?;
        take(data, &mut p, 1)?;
        let heap = *take(data, &mut p, 1)?.first()?;
        take(data, &mut p, 1)?;
        let valid = u64at(data, &mut p)?;
        take(data, &mut p, 8)?;
        let mut rows = [0; 45];
        for (i, row_count) in rows.iter_mut().enumerate() {
            if valid & (1 << i) != 0 {
                *row_count = u32at(data, &mut p)?;
            }
        }
        let mut starts = [0; 45];
        for i in 0..45 {
            if rows[i] > 0 {
                starts[i] = p;
                p = p.checked_add(rows[i] as usize * row_size(i, &rows, heap)?)?;
                if p > data.len() {
                    return None;
                }
            }
        }
        Some(Self {
            data,
            rows,
            starts,
            heap,
        })
    }
    fn rows(&self, n: usize) -> u32 {
        self.rows[n]
    }
    fn row(&self, t: usize, index: u32) -> Option<&[u8]> {
        let size = row_size(t, &self.rows, self.heap)?;
        let start = self.starts[t].checked_add(index.checked_sub(1)? as usize * size)?;
        self.data.get(start..start + size)
    }
}
fn read_typedef(
    l: &TableLayout<'_>,
    i: u32,
    s: &[u8],
    budget: &mut MetadataDecodeBudget,
) -> Option<TypeRow> {
    let mut p = 0;
    let r = l.row(2, i)?;
    let flags = u32at(r, &mut p)?;
    let name = str_index(r, &mut p, l.heap, s, budget)?;
    let namespace = str_index(r, &mut p, l.heap, s, budget)?;
    let extends = index(r, &mut p, coded_size(&l.rows, &[2, 1, 27], 2))?;
    let field_start = index(r, &mut p, index_size(l.rows(4)))?;
    let method_start = index(r, &mut p, index_size(l.rows(6)))?;
    Some(TypeRow {
        flags,
        name,
        namespace,
        extends,
        field_start,
        method_start,
    })
}
fn read_typeref(
    l: &TableLayout<'_>,
    i: u32,
    s: &[u8],
    budget: &mut MetadataDecodeBudget,
) -> Option<TypeRefRow> {
    let mut p = 0;
    let r = l.row(1, i)?;
    let scope = index(r, &mut p, coded_size(&l.rows, &[0, 26, 35, 1], 2))?;
    let name = str_index(r, &mut p, l.heap, s, budget)?;
    let namespace = str_index(r, &mut p, l.heap, s, budget)?;
    Some(TypeRefRow {
        scope,
        name,
        namespace,
    })
}
fn read_typespec(
    l: &TableLayout<'_>,
    i: u32,
    blobs: &[u8],
    budget: &mut MetadataDecodeBudget,
) -> Option<TypeSpecRow> {
    let mut p = 0;
    let sig = blob_index(l.row(27, i)?, &mut p, l.heap, blobs, budget)?;
    Some(TypeSpecRow { sig })
}
fn read_field(
    l: &TableLayout<'_>,
    i: u32,
    s: &[u8],
    b: &[u8],
    budget: &mut MetadataDecodeBudget,
) -> Option<FieldRow> {
    let mut p = 0;
    let r = l.row(4, i)?;
    let flags = u16at(r, &mut p)?;
    let name = str_index(r, &mut p, l.heap, s, budget)?;
    let sig = blob_index(r, &mut p, l.heap, b, budget)?;
    Some(FieldRow { flags, name, sig })
}
fn read_method(
    l: &TableLayout<'_>,
    i: u32,
    s: &[u8],
    b: &[u8],
    budget: &mut MetadataDecodeBudget,
) -> Option<MethodRow> {
    let mut p = 0;
    let r = l.row(6, i)?;
    take(r, &mut p, 4)?;
    take(r, &mut p, 2)?;
    let flags = u16at(r, &mut p)?;
    let name = str_index(r, &mut p, l.heap, s, budget)?;
    let sig = blob_index(r, &mut p, l.heap, b, budget)?;
    Some(MethodRow { flags, name, sig })
}
fn read_property(
    l: &TableLayout<'_>,
    i: u32,
    s: &[u8],
    b: &[u8],
    budget: &mut MetadataDecodeBudget,
) -> Option<PropertyRow> {
    let mut p = 0;
    let r = l.row(23, i)?;
    let flags = u16at(r, &mut p)?;
    let name = str_index(r, &mut p, l.heap, s, budget)?;
    let sig = blob_index(r, &mut p, l.heap, b, budget)?;
    Some(PropertyRow { flags, name, sig })
}

fn read_event(
    layout: &TableLayout<'_>,
    event_index: u32,
    strings: &[u8],
    budget: &mut MetadataDecodeBudget,
) -> Option<EventRow> {
    let mut cursor = 0;
    let row = layout.row(20, event_index)?;
    let flags = u16at(row, &mut cursor)?;
    let name = str_index(row, &mut cursor, layout.heap, strings, budget)?;
    let event_type = index(row, &mut cursor, coded_size(&layout.rows, &[2, 1, 27], 2))?;
    Some(EventRow {
        flags,
        name,
        event_type,
    })
}

fn nested_map(l: &TableLayout<'_>) -> HashMap<u32, u32> {
    let mut out = HashMap::default();
    for i in 1..=l.rows(41) {
        let Some(r) = l.row(41, i) else { continue };
        let mut p = 0;
        let Some(nested) = index(r, &mut p, index_size(l.rows(2))) else {
            continue;
        };
        let Some(owner) = index(r, &mut p, index_size(l.rows(2))) else {
            continue;
        };
        out.insert(nested, owner);
    }
    out
}
fn property_owners(l: &TableLayout<'_>, type_count: u32, prop_count: u32) -> HashMap<u32, u32> {
    let mut maps = Vec::new();
    for i in 1..=l.rows(21) {
        let Some(r) = l.row(21, i) else { continue };
        let mut p = 0;
        let Some(owner) = index(r, &mut p, index_size(type_count)) else {
            continue;
        };
        let Some(start) = index(r, &mut p, index_size(prop_count)) else {
            continue;
        };
        if owner > 0 && owner <= type_count && start > 0 && start <= prop_count.saturating_add(1) {
            maps.push((owner, start));
        }
    }
    maps.sort();
    let mut out = HashMap::default();
    for (idx, (owner, start)) in maps.iter().enumerate() {
        let end = maps
            .get(idx + 1)
            .map(|(_, start)| *start)
            .unwrap_or(prop_count + 1);
        if end < *start || end > prop_count.saturating_add(1) {
            continue;
        }
        for p in *start..end {
            out.insert(p, *owner);
        }
    }
    out
}
fn event_owners(l: &TableLayout<'_>, type_count: u32, event_count: u32) -> HashMap<u32, u32> {
    let mut maps = Vec::new();
    for i in 1..=l.rows(18) {
        let Some(row) = l.row(18, i) else {
            continue;
        };
        let mut cursor = 0;
        let Some(owner) = index(row, &mut cursor, index_size(type_count)) else {
            continue;
        };
        let Some(start) = index(row, &mut cursor, index_size(event_count)) else {
            continue;
        };
        if owner > 0 && owner <= type_count && start > 0 && start <= event_count.saturating_add(1) {
            maps.push((owner, start));
        }
    }
    maps.sort();
    let mut owners = HashMap::default();
    for (map_index, (owner, start)) in maps.iter().enumerate() {
        let end = maps
            .get(map_index + 1)
            .map(|(_, next_start)| *next_start)
            .unwrap_or(event_count + 1);
        if end < *start || end > event_count.saturating_add(1) {
            continue;
        }
        for event in *start..end {
            owners.insert(event, *owner);
        }
    }
    owners
}
fn property_accessors(l: &TableLayout<'_>, methods: &[MethodRow]) -> HashMap<u32, u16> {
    association_accessors(l, methods, 1)
}
fn association_accessors(
    l: &TableLayout<'_>,
    methods: &[MethodRow],
    association_tag: u32,
) -> HashMap<u32, u16> {
    let mut out = HashMap::default();
    for i in 1..=l.rows(24) {
        let Some(row) = l.row(24, i) else {
            continue;
        };
        let mut p = 0;
        let Some(_) = u16at(row, &mut p) else {
            continue;
        };
        let Some(method) = index(row, &mut p, index_size(methods.len() as u32)) else {
            continue;
        };
        let Some(association) = index(row, &mut p, coded_size(&l.rows, &[20, 23], 1)) else {
            continue;
        };
        if association & 1 != association_tag {
            continue;
        }
        let Some(method) = methods.get(method.saturating_sub(1) as usize) else {
            continue;
        };
        let associated_row = association >> 1;
        out.entry(associated_row)
            .and_modify(|flags| {
                if method.flags & 7 > *flags & 7 {
                    *flags = method.flags;
                }
            })
            .or_insert(method.flags);
    }
    out
}
struct GenericParameters {
    types: HashMap<u32, Vec<String>>,
    methods: HashMap<u32, Vec<String>>,
}

fn generic_parameters(
    l: &TableLayout<'_>,
    strings: &[u8],
    budget: &mut MetadataDecodeBudget,
) -> GenericParameters {
    let mut types: HashMap<u32, Vec<(u16, String)>> = HashMap::default();
    let mut methods: HashMap<u32, Vec<(u16, String)>> = HashMap::default();
    for i in 1..=l.rows(42) {
        let Some(r) = l.row(42, i) else { continue };
        let mut p = 0;
        let Some(number) = u16at(r, &mut p) else {
            continue;
        };
        let _ = u16at(r, &mut p);
        let Some(owner) = index(r, &mut p, coded_size(&l.rows, &[2, 6], 1)) else {
            continue;
        };
        let Some(name) = str_index(r, &mut p, l.heap, strings, budget) else {
            continue;
        };
        if owner == 0 || name.is_empty() {
            continue;
        }
        if owner & 1 == 0 {
            types.entry(owner >> 1).or_default().push((number, name));
        } else {
            methods.entry(owner >> 1).or_default().push((number, name));
        }
    }
    let finish = |mut input: HashMap<u32, Vec<(u16, String)>>| {
        input
            .drain()
            .map(|(owner, mut values)| {
                values.sort_by_key(|(number, _)| *number);
                (owner, values.into_iter().map(|(_, name)| name).collect())
            })
            .collect()
    };
    GenericParameters {
        types: finish(types),
        methods: finish(methods),
    }
}
fn interfaces_for(
    l: &TableLayout<'_>,
    types: &[TypeRow],
    type_refs: &[TypeRefRow],
    type_specs: &[TypeSpecRow],
) -> HashMap<u32, Vec<DecodedType>> {
    let mut out = HashMap::default();
    for i in 1..=l.rows(9) {
        let Some(r) = l.row(9, i) else { continue };
        let mut p = 0;
        let Some(owner) = index(r, &mut p, index_size(types.len() as u32)) else {
            continue;
        };
        let Some(interface) = index(r, &mut p, coded_size(&l.rows, &[2, 1, 27], 2)) else {
            continue;
        };
        if let Some(value) = resolve_typedef_or_ref_type(interface, types, type_refs, type_specs) {
            out.entry(owner).or_insert_with(Vec::new).push(value);
        }
    }
    out
}
fn full_type_name(
    index: u32,
    row: &TypeRow,
    all: &[TypeRow],
    nested: &HashMap<u32, u32>,
) -> String {
    let mut parts = vec![row.name.clone()];
    let mut namespace = row.namespace.clone();
    let mut current = index;
    for _ in 0..64 {
        let Some(owner) = nested.get(&current).copied() else {
            break;
        };
        let Some(owner_row) = all.get(owner.saturating_sub(1) as usize) else {
            return String::new();
        };
        parts.push(owner_row.name.clone());
        namespace = owner_row.namespace.clone();
        current = owner;
    }
    if nested.contains_key(&current) {
        return String::new();
    }
    parts.reverse();
    if namespace.is_empty() {
        parts.join(".")
    } else {
        format!("{}.{}", namespace, parts.join("."))
    }
}
#[cfg(test)]
fn resolve_typedef_or_ref(
    value: u32,
    types: &[TypeRow],
    type_refs: &[TypeRefRow],
    type_specs: &[TypeSpecRow],
) -> String {
    resolve_typedef_or_ref_type_at_depth(
        value,
        types,
        type_refs,
        type_specs,
        MAX_SIGNATURE_DEPTH,
        0,
    )
    .map(|value| value.legacy_name())
    .unwrap_or_default()
}
fn resolve_typedef_or_ref_type(
    value: u32,
    types: &[TypeRow],
    type_refs: &[TypeRefRow],
    type_specs: &[TypeSpecRow],
) -> Option<DecodedType> {
    resolve_typedef_or_ref_type_at_depth(
        value,
        types,
        type_refs,
        type_specs,
        MAX_SIGNATURE_DEPTH,
        0,
    )
}
fn resolve_typedef_or_ref_type_at_depth(
    value: u32,
    types: &[TypeRow],
    type_refs: &[TypeRefRow],
    type_specs: &[TypeSpecRow],
    max_signature_depth: usize,
    depth: usize,
) -> Option<DecodedType> {
    if depth >= max_signature_depth {
        return None;
    }
    let tag = value & 3;
    let index = (value >> 2) as usize;
    match tag {
        0 => types
            .get(index.saturating_sub(1))
            .map(|r| DecodedType::Named {
                name: if r.namespace.is_empty() {
                    r.name.clone()
                } else {
                    format!("{}.{}", r.namespace, r.name)
                },
                arguments: Vec::new(),
            }),
        1 => {
            let name = type_ref_name(index, type_refs);
            (!name.is_empty()).then(|| DecodedType::Named {
                name,
                arguments: Vec::new(),
            })
        }
        2 => {
            let spec = type_specs.get(index.saturating_sub(1))?;
            let mut cursor = 0;
            decode_type_at_depth(
                &spec.sig,
                &mut cursor,
                types,
                type_refs,
                type_specs,
                max_signature_depth,
                depth + 1,
            )
        }
        _ => None,
    }
}
fn type_ref_name(index: usize, type_refs: &[TypeRefRow]) -> String {
    let mut current = index;
    let mut names = Vec::new();
    for _ in 0..type_refs.len() {
        let Some(row) = type_refs.get(current.saturating_sub(1)) else {
            return String::new();
        };
        names.push(row.name.clone());
        if row.scope & 3 != 3 {
            names.reverse();
            return if row.namespace.is_empty() {
                names.join(".")
            } else {
                format!("{}.{}", row.namespace, names.join("."))
            };
        }
        current = (row.scope >> 2) as usize;
    }
    String::new()
}
fn type_visibility(flags: u32) -> CSharpVisibility {
    match flags & 7 {
        1 | 2 => CSharpVisibility::Public,
        3 => CSharpVisibility::Private,
        4 => CSharpVisibility::Protected,
        5 => CSharpVisibility::Internal,
        6 => CSharpVisibility::ProtectedAndInternal,
        7 => CSharpVisibility::ProtectedOrInternal,
        _ => CSharpVisibility::Internal,
    }
}
fn member_visibility(flags: u16) -> CSharpVisibility {
    match flags & 7 {
        1 => CSharpVisibility::Private,
        2 => CSharpVisibility::ProtectedAndInternal,
        3 => CSharpVisibility::Internal,
        4 => CSharpVisibility::Protected,
        5 => CSharpVisibility::ProtectedOrInternal,
        6 => CSharpVisibility::Public,
        _ => CSharpVisibility::Private,
    }
}
fn decode_signature(
    blob: &[u8],
    method: bool,
    types: &[TypeRow],
    type_refs: &[TypeRefRow],
    type_specs: &[TypeSpecRow],
    max_signature_depth: usize,
) -> Option<(Option<DecodedType>, Vec<DecodedType>, usize)> {
    let mut p = 0;
    let header = blob.get(p).copied()?;
    p += 1;
    let generic = if header & 0x10 != 0 {
        compressed(blob, &mut p)? as usize
    } else {
        0
    };
    let count = if method || header & 0x0f == 0x08 {
        compressed(blob, &mut p)? as usize
    } else {
        0
    };
    if count > MAX_SIGNATURE_PARAMETERS || count > blob.len().saturating_sub(p) {
        return None;
    }
    let ret = Some(decode_type(
        blob,
        &mut p,
        types,
        type_refs,
        type_specs,
        max_signature_depth,
    )?);
    let mut params = Vec::new();
    for _ in 0..count {
        params.push(decode_type(
            blob,
            &mut p,
            types,
            type_refs,
            type_specs,
            max_signature_depth,
        )?);
    }
    Some((ret, params, generic))
}
fn decode_type(
    blob: &[u8],
    p: &mut usize,
    types: &[TypeRow],
    type_refs: &[TypeRefRow],
    type_specs: &[TypeSpecRow],
    max_signature_depth: usize,
) -> Option<DecodedType> {
    decode_type_at_depth(
        blob,
        p,
        types,
        type_refs,
        type_specs,
        max_signature_depth,
        0,
    )
}
fn decode_type_at_depth(
    blob: &[u8],
    p: &mut usize,
    types: &[TypeRow],
    type_refs: &[TypeRefRow],
    type_specs: &[TypeSpecRow],
    max_signature_depth: usize,
    depth: usize,
) -> Option<DecodedType> {
    if depth >= max_signature_depth {
        return None;
    }
    let element = *blob.get(*p)?;
    *p += 1;
    let primitive = match element {
        0x01 => return Some(DecodedType::Void),
        0x02 => "System.Boolean",
        0x03 => "System.Char",
        0x04 => "System.SByte",
        0x05 => "System.Byte",
        0x06 => "System.Int16",
        0x07 => "System.UInt16",
        0x08 => "System.Int32",
        0x09 => "System.UInt32",
        0x0a => "System.Int64",
        0x0b => "System.UInt64",
        0x0c => "System.Single",
        0x0d => "System.Double",
        0x0e => "System.String",
        0x18 => "System.IntPtr",
        0x19 => "System.UIntPtr",
        0x1c => "System.Object",
        _ => "",
    };
    if !primitive.is_empty() {
        return Some(DecodedType::Named {
            name: primitive.to_owned(),
            arguments: Vec::new(),
        });
    }
    match element {
        0x0f => decode_type_at_depth(
            blob,
            p,
            types,
            type_refs,
            type_specs,
            max_signature_depth,
            depth + 1,
        )
        .map(Box::new)
        .map(DecodedType::Pointer),
        0x10 => decode_type_at_depth(
            blob,
            p,
            types,
            type_refs,
            type_specs,
            max_signature_depth,
            depth + 1,
        )
        .map(Box::new)
        .map(DecodedType::ByRef),
        0x1d => decode_type_at_depth(
            blob,
            p,
            types,
            type_refs,
            type_specs,
            max_signature_depth,
            depth + 1,
        )
        .map(Box::new)
        .map(|element| DecodedType::Array { element, rank: 1 }),
        0x11 | 0x12 => resolve_typedef_or_ref_type_at_depth(
            compressed(blob, p)?,
            types,
            type_refs,
            type_specs,
            max_signature_depth,
            depth + 1,
        ),
        0x13 => compressed(blob, p).map(|index| DecodedType::TypeParameter {
            method: false,
            index: index as usize,
        }),
        0x1e => compressed(blob, p).map(|index| DecodedType::TypeParameter {
            method: true,
            index: index as usize,
        }),
        0x14 => {
            let inner = decode_type_at_depth(
                blob,
                p,
                types,
                type_refs,
                type_specs,
                max_signature_depth,
                depth + 1,
            )?;
            let rank = compressed(blob, p)?;
            if rank as usize > MAX_ARRAY_RANK {
                return None;
            }
            let sizes = compressed(blob, p)?;
            if sizes as usize > MAX_ARRAY_RANK {
                return None;
            }
            for _ in 0..sizes {
                compressed(blob, p)?;
            }
            let lowers = compressed(blob, p)?;
            if lowers as usize > MAX_ARRAY_RANK {
                return None;
            }
            for _ in 0..lowers {
                compressed(blob, p)?;
            }
            Some(DecodedType::Array {
                element: Box::new(inner),
                rank: rank as usize,
            })
        }
        0x15 => {
            let _ = blob.get(*p)?;
            *p += 1;
            let base = resolve_typedef_or_ref_type_at_depth(
                compressed(blob, p)?,
                types,
                type_refs,
                type_specs,
                max_signature_depth,
                depth + 1,
            )?;
            let count = compressed(blob, p)?;
            let mut arguments = Vec::new();
            for _ in 0..count {
                arguments.push(decode_type_at_depth(
                    blob,
                    p,
                    types,
                    type_refs,
                    type_specs,
                    max_signature_depth,
                    depth + 1,
                )?);
            }
            let DecodedType::Named { name, .. } = base else {
                return None;
            };
            Some(DecodedType::Named { name, arguments })
        }
        0x1f | 0x20 => {
            compressed(blob, p)?;
            decode_type_at_depth(
                blob,
                p,
                types,
                type_refs,
                type_specs,
                max_signature_depth,
                depth + 1,
            )
        }
        _ => None,
    }
}
fn compressed(bytes: &[u8], p: &mut usize) -> Option<u32> {
    let first = *bytes.get(*p)?;
    *p += 1;
    if first & 0x80 == 0 {
        return Some(first as u32);
    }
    if first & 0xc0 == 0x80 {
        let second = *bytes.get(*p)?;
        *p += 1;
        return Some((((first & 0x3f) as u32) << 8) | second as u32);
    }
    if first & 0xe0 == 0xc0 {
        let rest = take(bytes, p, 3)?;
        return Some(
            (((first & 0x1f) as u32) << 24)
                | ((rest[0] as u32) << 16)
                | ((rest[1] as u32) << 8)
                | rest[2] as u32,
        );
    }
    None
}
fn row_size(table: usize, rows: &[u32; 45], heap: u8) -> Option<usize> {
    let s = if heap & 1 != 0 { 4 } else { 2 };
    let g = if heap & 2 != 0 { 4 } else { 2 };
    let b = if heap & 4 != 0 { 4 } else { 2 };
    let ix = |t| index_size(rows[t]);
    let c = |tables: &[usize], bits| coded_size(rows, tables, bits);
    Some(match table {
        0 => 2 + s + g * 3,
        1 => c(&[0, 26, 35, 1], 2) + s * 2,
        2 => 4 + s * 2 + c(&[2, 1, 27], 2) + ix(4) + ix(6),
        3 => ix(4),
        4 => 2 + s + b,
        5 => ix(6),
        6 => 8 + s + b + ix(8),
        7 => ix(8),
        8 => 4 + s,
        9 => ix(2) + c(&[2, 1, 27], 2),
        10 => c(&[2, 1, 26, 6, 27], 3) + s + b,
        11 => 2 + c(&[4, 8, 23], 2) + b,
        12 => {
            c(
                &[
                    6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43,
                ],
                5,
            ) + c(&[6, 10], 3)
                + b
        }
        13 => c(&[4, 8], 1) + b,
        14 => 2 + c(&[2, 6, 32], 2) + b,
        15 => 2 + 4 + ix(2),
        16 => 4 + ix(4),
        17 => b,
        18 => ix(2) + ix(20),
        19 => ix(20),
        20 => 2 + s + c(&[2, 1, 27], 2),
        21 => ix(2) + ix(23),
        22 => ix(23),
        23 => 2 + s + b,
        24 => 2 + ix(6) + c(&[20, 23], 1),
        25 => ix(2) + c(&[6, 10], 1) * 2,
        26 => s,
        27 => b,
        28 => 2 + c(&[4, 6], 1) + s + ix(26),
        29 => 4 + ix(4),
        30 => 8,
        31 => 4,
        32 => 16 + b + s * 2,
        33 => 4,
        34 => 12,
        35 => 12 + b + s * 2 + b,
        36 => 4 + ix(35),
        37 => 12 + ix(35),
        38 => 4 + s + b,
        39 => 8 + s * 2 + c(&[38, 35, 39], 2),
        40 => 8 + s + c(&[38, 35, 39], 2),
        41 => ix(2) * 2,
        42 => 4 + c(&[2, 6], 1) + s,
        43 => c(&[6, 10], 1) + b,
        44 => ix(42) + c(&[2, 1, 27], 2),
        _ => return None,
    })
}
fn index_size(rows: u32) -> usize {
    if rows < 0x10000 { 2 } else { 4 }
}
fn coded_size(rows: &[u32; 45], tables: &[usize], bits: u32) -> usize {
    if tables.iter().any(|&t| rows[t] >= (1 << (16 - bits))) {
        4
    } else {
        2
    }
}
fn take<'a>(bytes: &'a [u8], p: &mut usize, n: usize) -> Option<&'a [u8]> {
    let out = bytes.get(*p..p.checked_add(n)?)?;
    *p += n;
    Some(out)
}
fn u16at(b: &[u8], p: &mut usize) -> Option<u16> {
    Some(u16::from_le_bytes(take(b, p, 2)?.try_into().ok()?))
}
fn u32at(b: &[u8], p: &mut usize) -> Option<u32> {
    Some(u32::from_le_bytes(take(b, p, 4)?.try_into().ok()?))
}
fn u64at(b: &[u8], p: &mut usize) -> Option<u64> {
    Some(u64::from_le_bytes(take(b, p, 8)?.try_into().ok()?))
}
fn index(b: &[u8], p: &mut usize, size: usize) -> Option<u32> {
    if size == 2 {
        u16at(b, p).map(u32::from)
    } else {
        u32at(b, p)
    }
}
struct MetadataDecodeBudget {
    remaining_bytes: usize,
}

impl Default for MetadataDecodeBudget {
    fn default() -> Self {
        Self {
            remaining_bytes: MAX_DECODED_METADATA_BYTES,
        }
    }
}

impl MetadataDecodeBudget {
    fn consume(&mut self, bytes: usize) -> Option<()> {
        self.remaining_bytes = self.remaining_bytes.checked_sub(bytes)?;
        Some(())
    }
}

fn str_index(
    b: &[u8],
    p: &mut usize,
    heap: u8,
    strings: &[u8],
    budget: &mut MetadataDecodeBudget,
) -> Option<String> {
    let idx = index(b, p, if heap & 1 != 0 { 4 } else { 2 })? as usize;
    if idx == 0 {
        return Some(String::new());
    }
    let end = strings.get(idx..)?.iter().position(|v| *v == 0)? + idx;
    budget.consume(end.saturating_sub(idx))?;
    std::str::from_utf8(strings.get(idx..end)?)
        .ok()
        .map(str::to_string)
}
fn blob_index(
    b: &[u8],
    p: &mut usize,
    heap: u8,
    blobs: &[u8],
    budget: &mut MetadataDecodeBudget,
) -> Option<Vec<u8>> {
    let idx = index(b, p, if heap & 4 != 0 { 4 } else { 2 })? as usize;
    if idx == 0 {
        return Some(Vec::new());
    }
    let mut start = idx;
    let len = compressed(blobs, &mut start)? as usize;
    budget.consume(len)?;
    blobs
        .get(start..start.checked_add(len)?)
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic_model::{
        ActivationSelector, Compatibility, CompilerOptions, NameSelector, Provenance, Safety,
        compile_pack,
    };
    use sha2::{Digest, Sha256};

    const DLL: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/csharp-external/ExternalLibrary.dll"
    ));
    const SHA: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/csharp-external/ExternalLibrary.dll.sha256"
    ));

    fn production_request(path: PathBuf) -> ArtifactProductionRequest {
        ArtifactProductionRequest {
            path,
            artifact_kind: ExternalArtifactKind::DotNetAssembly,
            pack_id: "fixture.external-library".to_owned(),
            pack_version: "1.0.0".to_owned(),
            ecosystem: "nuget".to_owned(),
            compatibility: Compatibility {
                bifrost: ">=0.8.0, <1.0.0".to_owned(),
                toolchains: Vec::new(),
            },
            activation: vec![ActivationSelector {
                package: Some(NameSelector {
                    name: "fixture:external-library".to_owned(),
                    version: Some("1.0.0".to_owned()),
                }),
                module: None,
                toolchain: None,
                targets: Vec::new(),
                configurations: Vec::new(),
                artifact_sha256: None,
            }],
            provenance: Provenance {
                source: "checked-in fixture".to_owned(),
                revision: None,
            },
            license: "MIT".to_owned(),
            safety: Safety {
                generated_code_only: false,
                review_required: false,
            },
        }
    }

    fn produce_fixture(limits: &ArtifactProducerLimits) -> ArtifactProduction {
        let temp = tempfile::tempdir().unwrap();
        let assembly = temp.path().join("ExternalLibrary.dll");
        std::fs::write(&assembly, DLL).unwrap();
        CSharpAssemblyPackProducer.produce_exact_artifact(&production_request(assembly), limits)
    }

    #[test]
    fn assembly_producer_emits_deterministic_structured_api_pack() {
        let first = produce_fixture(&ArtifactProducerLimits::default());
        let second = produce_fixture(&ArtifactProducerLimits::default());

        assert_eq!(first, second);
        assert_eq!(first.completeness, Completeness::Complete);
        assert!(first.diagnostics.is_empty(), "{:?}", first.diagnostics);
        assert_eq!(
            first.artifact_sha256.as_deref(),
            SHA.split_whitespace().next()
        );
        let pack = first.pack.as_ref().expect("fixture pack");
        let AuthoredPayload::DeclarationFacts { types, members, .. } = &pack.shards[0].payload
        else {
            panic!("C# producer must emit declaration facts");
        };

        let client = types
            .iter()
            .find(|fact| fact.name == "Fixture.Api.Client`1")
            .expect("generic client type");
        assert_eq!(client.type_parameters, ["T"]);
        assert!(client.hierarchy.iter().any(|fact| {
            fact.hierarchy_kind == HierarchyKind::Implements
                && matches!(&fact.target, TypeRef::Named { name, .. } if name == "Fixture.Api.IClient")
        }));
        assert!(types.iter().any(|fact| fact.name.ends_with(".Nested")));
        assert!(
            types
                .iter()
                .any(|fact| fact.name.ends_with(".ProtectedNested"))
        );
        assert!(
            !types
                .iter()
                .any(|fact| fact.name.ends_with(".PrivateNested"))
        );
        assert!(!types.iter().any(|fact| fact.name.contains("InternalOnly")));

        let convert = members
            .iter()
            .find(|fact| fact.owner == client.id && fact.name == "Convert")
            .expect("generic method");
        let signature = convert.signature.as_ref().expect("method signature");
        assert_eq!(signature.type_parameters, ["U"]);
        assert_eq!(signature.parameters.len(), 1);
        assert!(
            signature
                .parameters
                .iter()
                .all(|parameter| parameter.name.is_none())
        );
        assert!(matches!(
            signature.parameters[0].r#type,
            TypeRef::TypeParameter { ref name } if name == "U"
        ));
        assert!(matches!(
            signature.returns,
            Some(TypeRef::TypeParameter { ref name }) if name == "U"
        ));
        assert!(members.iter().all(|fact| {
            matches!(
                &fact.locator,
                Locator::Artifact { path, symbol }
                    if path == "ExternalLibrary.dll" && symbol.starts_with("0x")
            )
        }));

        let first_compiled = compile_pack(pack, &CompilerOptions::default()).unwrap();
        let second_compiled = compile_pack(
            second.pack.as_ref().expect("second fixture pack"),
            &CompilerOptions::default(),
        )
        .unwrap();
        assert_eq!(first_compiled, second_compiled);
    }

    #[test]
    fn assembly_producer_cancels_during_bounded_metadata_walk() {
        let temp = tempfile::tempdir().unwrap();
        let assembly = temp.path().join("ExternalLibrary.dll");
        std::fs::write(&assembly, DLL).unwrap();
        let cancellation = CancellationToken::cancel_after_checks_for_test(3);

        let production = CSharpAssemblyPackProducer.produce_exact_artifact_with_cancellation(
            &production_request(assembly),
            &ArtifactProducerLimits::default(),
            Some(&cancellation),
        );

        assert!(cancellation.is_cancelled());
        assert!(production.pack.is_none());
        assert!(
            production
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "artifact.cancelled")
        );
    }

    #[test]
    fn assembly_producer_reports_record_limit_as_partial() {
        let production = produce_fixture(&ArtifactProducerLimits {
            max_records: 2,
            ..ArtifactProducerLimits::default()
        });

        assert_eq!(production.completeness, Completeness::Partial);
        assert!(production.pack.is_some());
        assert!(
            production
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "limit.records")
        );
    }

    #[test]
    fn assembly_producer_applies_signature_depth_limit() {
        let production = produce_fixture(&ArtifactProducerLimits {
            max_signature_depth: 0,
            ..ArtifactProducerLimits::default()
        });

        assert_eq!(production.completeness, Completeness::Partial);
        assert!(production.pack.is_some());
        assert!(production.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "csharp.signature.omitted" && diagnostic.message.contains("omitted")
        }));
    }

    #[test]
    fn assembly_producer_rejects_non_cli_input_without_panicking() {
        let temp = tempfile::tempdir().unwrap();
        let assembly = temp.path().join("broken.dll");
        std::fs::write(&assembly, b"not a PE").unwrap();
        let production = CSharpAssemblyPackProducer.produce_exact_artifact(
            &production_request(assembly),
            &ArtifactProducerLimits::default(),
        );

        assert!(production.pack.is_none());
        assert_eq!(production.completeness, Completeness::Partial);
        assert_eq!(production.diagnostics[0].code, "csharp.metadata.invalid");
    }

    #[test]
    fn external_fixture_is_pinned_and_exposes_members() {
        let actual = format!("{:x}", Sha256::digest(DLL));
        let expected = SHA.split_whitespace().next().unwrap();
        assert_eq!(
            actual, expected,
            "C# fixture DLL changed; rebuild it through the fixture verifier"
        );
        let pe = PE::parse(DLL).expect("fixture PE");
        let metadata = metadata_bytes(&pe, DLL).expect("fixture metadata");
        let streams = Streams::parse(metadata).expect("fixture streams");
        assert!(
            TableLayout::parse(streams.tables.expect("fixture tables")).is_some(),
            "fixture table layout"
        );
        let layout = TableLayout::parse(streams.tables.expect("fixture tables")).unwrap();
        let mut decode_budget = MetadataDecodeBudget::default();
        assert!(
            (1..=layout.rows(2)).all(|i| read_typedef(
                &layout,
                i,
                streams.strings.unwrap(),
                &mut decode_budget
            )
            .is_some()),
            "fixture type definitions"
        );
        assert!(
            (1..=layout.rows(4)).all(|i| {
                read_field(
                    &layout,
                    i,
                    streams.strings.unwrap(),
                    streams.blobs.unwrap(),
                    &mut decode_budget,
                )
                .is_some()
            }),
            "fixture fields"
        );
        assert!(
            (1..=layout.rows(6)).all(|i| {
                read_method(
                    &layout,
                    i,
                    streams.strings.unwrap(),
                    streams.blobs.unwrap(),
                    &mut decode_budget,
                )
                .is_some()
            }),
            "fixture methods"
        );
        assert!(
            (1..=layout.rows(23)).all(|i| {
                read_property(
                    &layout,
                    i,
                    streams.strings.unwrap(),
                    streams.blobs.unwrap(),
                    &mut decode_budget,
                )
                .is_some()
            }),
            "fixture properties"
        );
        let types = parse_assembly(Path::new("ExternalLibrary.dll"), DLL)
            .expect("fixture must be a managed assembly");
        let client = types
            .iter()
            .find(|ty| ty.fqn() == "Fixture.Api.Client`1")
            .expect("generic public class");
        assert!(
            client
                .members()
                .iter()
                .any(|member| member.name() == "Send")
        );
        assert!(
            client
                .members()
                .iter()
                .any(|member| member.name() == "Name")
        );
        let name = client
            .members()
            .iter()
            .find(|member| member.name() == "Name")
            .unwrap();
        assert_eq!(name.kind(), CSharpExternalMemberKind::Property);
        assert_eq!(name.visibility(), CSharpVisibility::Public);
        assert_eq!(name.return_type(), Some("string"));
        assert!(matches!(
            name.source(),
            CSharpExternalDeclarationSource::Assembly { metadata_token, .. }
                if *metadata_token & 0xff00_0000 == 0x1700_0000
        ));
        assert!(matches!(
            types.iter().find(|ty| ty.fqn() == "Fixture.Api.Message"),
            Some(ty) if ty.kind() == CSharpExternalTypeKind::Struct
        ));
        assert!(matches!(
            types.iter().find(|ty| ty.fqn() == "Fixture.Api.Status"),
            Some(ty) if ty.kind() == CSharpExternalTypeKind::Enum
        ));
        assert!(matches!(
            types.iter().find(|ty| ty.fqn() == "Fixture.Api.MessageHandler"),
            Some(ty) if ty.kind() == CSharpExternalTypeKind::Delegate
        ));
        let generic_surface = types
            .iter()
            .find(|ty| ty.fqn() == "Fixture.Api.GenericSurface")
            .expect("constructed generic metadata surface");
        assert!(
            generic_surface
                .interfaces()
                .iter()
                .any(|interface| interface.contains("IEnumerable`1<Fixture.Api.Message>"))
        );
        assert!(generic_surface.members().iter().any(|member| {
            member.name() == "Lookup"
                && member
                    .return_type()
                    .is_some_and(|ty| ty.contains("Dictionary`2<string"))
        }));
    }

    #[test]
    fn malformed_input_is_ignored() {
        assert!(parse_assembly(Path::new("bad.dll"), b"not a PE").is_none());
    }

    #[test]
    fn typespec_generic_instances_preserve_base_and_arguments() {
        let refs = vec![TypeRefRow {
            scope: 0,
            name: "List`1".to_string(),
            namespace: "System.Collections.Generic".to_string(),
        }];
        let specs = vec![TypeSpecRow {
            // GENERICINST CLASS TypeRef(1) one argument: string.
            sig: vec![0x15, 0x12, 0x05, 0x01, 0x0e],
        }];
        assert_eq!(
            resolve_typedef_or_ref(0x06, &[], &refs, &specs),
            "System.Collections.Generic.List`1<string>"
        );
    }

    #[test]
    fn cyclic_typespec_is_undecodable_without_recursing_unboundedly() {
        let specs = vec![TypeSpecRow {
            // GENERICINST CLASS TypeSpec(1), with no generic arguments.
            sig: vec![0x15, 0x12, 0x06, 0x00],
        }];
        assert!(resolve_typedef_or_ref(0x06, &[], &[], &specs).is_empty());
    }

    #[test]
    fn explicit_assembly_queries_honor_using_aliases_and_generic_identity() {
        let temp = tempfile::tempdir().unwrap();
        let assembly = temp.path().join("ExternalLibrary.dll");
        std::fs::write(&assembly, DLL).unwrap();
        let source = temp.path().join("Probe.cs");
        std::fs::write(&source, "namespace Consumer; class Probe {}\n").unwrap();
        let project =
            crate::analyzer::TestProject::new(temp.path(), crate::analyzer::Language::CSharp);
        let index = CSharpExternalDeclarationIndex::build_for_project(
            &CSharpAnalyzerConfig {
                assembly_paths: vec![assembly.clone()],
            },
            &project,
        );
        assert!(
            index.production_diagnostics().is_empty(),
            "{:?}",
            index.production_diagnostics()
        );

        let mut aliases = HashMap::default();
        aliases.insert("Api".to_string(), "Fixture.Api".to_string());
        let candidates = index.resolve_in_file("Api::Client<int>", "Consumer", &[], &aliases);
        assert_eq!(candidates.len(), 1);
        let client = candidates[0];
        assert_eq!(client.fqn(), "Fixture.Api.Client`1");
        assert!(matches!(
            client.source(),
            CSharpExternalDeclarationSource::Assembly { path, metadata_token }
                if path == &assembly && *metadata_token == 0x0200_0003
        ));
        assert!(
            index
                .resolve_in_file("InternalOnly", "Fixture.Api", &[], &HashMap::default())
                .is_empty()
        );
        assert_eq!(index.members_named(client.fqn(), "Send").len(), 1);
    }

    #[test]
    fn assets_discovery_retains_candidates_from_multiple_targets() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("Probe.cs"), "class Probe {}\n").unwrap();
        let packages = temp.path().join(".nuget/packages");
        for package in ["fixture-one", "fixture-two"] {
            let assembly = packages
                .join(package)
                .join("1.0.0/ref/net8.0/ExternalLibrary.dll");
            std::fs::create_dir_all(assembly.parent().unwrap()).unwrap();
            std::fs::write(assembly, DLL).unwrap();
        }
        let obj = temp.path().join("obj");
        std::fs::create_dir_all(&obj).unwrap();
        std::fs::write(
            obj.join("project.assets.json"),
            serde_json::json!({
                "packageFolders": { format!("{}/", packages.display()): {} },
                "targets": {
                    "net8.0": {
                        "fixture-one/1.0.0": { "ref": { "ref/net8.0/ExternalLibrary.dll": {} } },
                    },
                    "net9.0": {
                        "fixture-two/1.0.0": { "compile": { "ref/net8.0/ExternalLibrary.dll": {} } },
                    },
                },
            })
            .to_string(),
        )
        .unwrap();
        let project =
            crate::analyzer::TestProject::new(temp.path(), crate::analyzer::Language::CSharp);
        let index = CSharpExternalDeclarationIndex::build_for_project(
            &CSharpAnalyzerConfig::default(),
            &project,
        );
        assert_eq!(
            index
                .resolve_in_file("Fixture.Api.Status", "", &[], &HashMap::default())
                .len(),
            2
        );
        let dependencies = resolve_csharp_semantic_pack_dependencies(
            &CSharpAnalyzerConfig::default(),
            &project,
            &DependencyPackLimits::default(),
            None,
        );
        assert_eq!(dependencies.len(), 2);
        assert_eq!(
            dependencies
                .iter()
                .filter_map(|dependency| dependency.evidence.target.as_deref())
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from(["net8.0", "net9.0"])
        );
    }

    #[test]
    fn malformed_assets_is_actionable_incomplete_discovery() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("obj")).unwrap();
        std::fs::write(root.path().join("obj/project.assets.json"), b"not json").unwrap();
        let project =
            crate::analyzer::TestProject::new(root.path(), crate::analyzer::Language::CSharp);
        let outcome = resolve_csharp_semantic_pack_dependencies(
            &CSharpAnalyzerConfig::default(),
            &project,
            &DependencyPackLimits::default(),
            None,
        );

        assert!(!outcome.complete);
        assert!(outcome.dependencies.is_empty());
        assert_eq!(outcome.diagnostics[0].code, "csharp.dependency_unresolved");
        assert!(outcome.diagnostics[0].message.contains("could not parse"));
    }

    #[test]
    fn project_output_candidates_match_the_assets_target() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("library");
        let net7 = project.join("bin/Debug/net7.0/Library.dll");
        let net8 = project.join("bin/Debug/net8.0/Library.dll");
        std::fs::create_dir_all(net7.parent().unwrap()).unwrap();
        std::fs::create_dir_all(net8.parent().unwrap()).unwrap();
        std::fs::write(&net7, b"net7").unwrap();
        std::fs::write(&net8, b"net8").unwrap();

        let candidates = project_output_candidates(
            &project,
            Some(std::ffi::OsStr::new("Library.dll")),
            root.path(),
            "net8.0",
        );

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].0, net8.canonicalize().unwrap());
        assert_eq!(candidates[0].1.as_deref(), Some("Debug"));
    }

    #[test]
    fn assets_prefer_reference_assembly_and_reuse_exact_pack() {
        use crate::analyzer::semantic_model::{
            CatalogOptions, DependencyPackLimits, DependencyPackPreparationStatus,
            SemanticPackCatalog, prepare_dependency_semantic_packs,
        };

        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("Probe.cs"), "class Probe {}\n").unwrap();
        let packages = temp.path().join(".nuget/packages");
        let reference = packages.join("fixture/1.0.0/ref/net8.0/ExternalLibrary.dll");
        let runtime = packages.join("fixture/1.0.0/lib/net8.0/ExternalLibrary.dll");
        std::fs::create_dir_all(reference.parent().unwrap()).unwrap();
        std::fs::create_dir_all(runtime.parent().unwrap()).unwrap();
        std::fs::write(&reference, DLL).unwrap();
        std::fs::write(&runtime, DLL).unwrap();
        let obj = temp.path().join("obj");
        std::fs::create_dir_all(&obj).unwrap();
        std::fs::write(
            obj.join("project.assets.json"),
            serde_json::json!({
                "packageFolders": { format!("{}/", packages.display()): {} },
                "targets": { "net8.0": { "fixture/1.0.0": {
                    "ref": { "ref/net8.0/ExternalLibrary.dll": {} },
                    "runtime": { "lib/net8.0/ExternalLibrary.dll": {} }
                } } }
            })
            .to_string(),
        )
        .unwrap();
        let project =
            crate::analyzer::TestProject::new(temp.path(), crate::analyzer::Language::CSharp);
        let dependencies = resolve_csharp_semantic_pack_dependencies(
            &CSharpAnalyzerConfig::default(),
            &project,
            &DependencyPackLimits::default(),
            None,
        );

        assert_eq!(dependencies.len(), 1);
        assert_eq!(
            dependencies[0].artifacts[0].path(),
            reference.canonicalize().unwrap()
        );
        assert!(
            dependencies[0]
                .provenance
                .iter()
                .any(|entry| { entry.key == "asset_role" && entry.value == "reference" })
        );
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let first = prepare_dependency_semantic_packs(
            &catalog,
            &CSharpDependencyPackAdapter,
            &dependencies,
            &DependencyPackLimits::default(),
            None,
        );
        let second = prepare_dependency_semantic_packs(
            &catalog,
            &CSharpDependencyPackAdapter,
            &dependencies,
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
    }

    #[test]
    fn renamed_identical_assemblies_reuse_one_path_independent_manifest() {
        use crate::analyzer::semantic_model::{
            CatalogOptions, DependencyPackPreparationStatus, SemanticPackCatalog,
            prepare_dependency_semantic_packs,
        };

        let root = tempfile::tempdir().unwrap();
        let first_path = root.path().join("First.dll");
        let second_path = root.path().join("Renamed.dll");
        std::fs::write(&first_path, DLL).unwrap();
        std::fs::write(&second_path, DLL).unwrap();
        let project =
            crate::analyzer::TestProject::new(root.path(), crate::analyzer::Language::CSharp);
        let limits = DependencyPackLimits::default();
        let resolve = |path| {
            resolve_csharp_semantic_pack_dependencies(
                &CSharpAnalyzerConfig {
                    assembly_paths: vec![path],
                },
                &project,
                &limits,
                None,
            )
        };
        let first_dependencies = resolve(first_path);
        let second_dependencies = resolve(second_path);
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let first = prepare_dependency_semantic_packs(
            &catalog,
            &CSharpDependencyPackAdapter,
            &first_dependencies,
            &limits,
            None,
        );
        let second = prepare_dependency_semantic_packs(
            &catalog,
            &CSharpDependencyPackAdapter,
            &second_dependencies,
            &limits,
            None,
        );

        assert!(
            first.complete && second.complete,
            "first={:#?}\nsecond={:#?}",
            first,
            second
        );
        assert_eq!(
            second.packs[0].status,
            DependencyPackPreparationStatus::Reused
        );
        assert_eq!(first.packs[0].production, second.packs[0].production);
    }

    #[test]
    fn assets_discovery_finds_referenced_project_outputs() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("Probe.cs"), "class Probe {}\n").unwrap();
        let project = temp.path().join("projects/Referenced");
        std::fs::create_dir_all(project.join("bin/Debug/net8.0")).unwrap();
        std::fs::write(project.join("Referenced.csproj"), "<Project />").unwrap();
        std::fs::write(project.join("bin/Debug/net8.0/ExternalLibrary.dll"), DLL).unwrap();
        let obj = temp.path().join("obj");
        std::fs::create_dir_all(&obj).unwrap();
        std::fs::write(
            obj.join("project.assets.json"),
            serde_json::json!({
                "targets": { "net8.0": {
                    "Referenced/1.0.0": { "compile": { "bin/placeholder/ExternalLibrary.dll": {} } }
                } },
                "libraries": { "Referenced/1.0.0": {
                    "type": "project", "path": "projects/Referenced/Referenced.csproj"
                } }
            })
            .to_string(),
        )
        .unwrap();
        let project =
            crate::analyzer::TestProject::new(temp.path(), crate::analyzer::Language::CSharp);
        let index = CSharpExternalDeclarationIndex::build_for_project(
            &CSharpAnalyzerConfig::default(),
            &project,
        );
        assert_eq!(
            index
                .resolve_in_file("Fixture.Api.Status", "", &[], &HashMap::default())
                .len(),
            1
        );
        let dependencies = resolve_csharp_semantic_pack_dependencies(
            &CSharpAnalyzerConfig::default(),
            &project,
            &DependencyPackLimits::default(),
            None,
        );
        assert_eq!(dependencies.len(), 1);
        assert_eq!(dependencies[0].evidence.target.as_deref(), Some("net8.0"));
        assert_eq!(
            dependencies[0].evidence.configuration.as_deref(),
            Some("Debug")
        );
        assert!(
            dependencies[0]
                .provenance
                .iter()
                .any(|entry| { entry.key == "project_reference" && entry.value == "true" })
        );
    }
}
