//! Exact semantic packs from explicit C++ include roots.

use crate::CancellationToken;
use crate::analyzer::ProjectFile;
use crate::analyzer::canonical_hash::{lower_hex_string, sha256_bytes};
use crate::analyzer::cpp::CppAnalyzer;
use crate::analyzer::semantic_model::{
    ActivationSelector, ArtifactProducerLimits, AuthoredPayload, AuthoredSemanticModelPack,
    AuthoredShard, BoundedProducerDiagnostics, CatalogCoordinate, Compatibility, Completeness,
    DependencyArtifactRole, DependencyDiscoveryOutcome, DependencyDiscoveryProfile,
    DependencyPackAdapter, DependencyPackDiagnostic, DependencyPackDiagnosticSeverity,
    DependencyPackLimits, DependencyPackProduction, ExactDependencyArtifact, ExternalArtifactKind,
    HierarchyFact, HierarchyKind, Locator, MemberFact, MemberIdentity, MemberKind, NameSelector,
    Parameter, Producer, Provenance, ReceiverFact, ResolvedDependency, ResolvedDependencyArtifact,
    Safety, SemanticModelActivationEvidence, Signature, TypeFact, TypeIdentity, TypeKind, TypeRef,
    Visibility, WildcardVariance, member_declaration_id, type_declaration_id,
};
use crate::analyzer::semantic_model::{SemanticModelCompleteness, SemanticModelOverlay};
use crate::analyzer::structural::BoundaryStatus;
use crate::analyzer::{Language, Project};
use crate::hash::HashMap;
use brokk_bifrost_core::analyzer::model::{
    StructuredTypeIdentity, StructuredTypeNodeId, StructuredTypeNodeView,
};
use brokk_bifrost_cpp::compile_context::CppCompileContexts;
use brokk_bifrost_cpp::compile_context::CppExternalIncludeResolution;
use brokk_bifrost_cpp::declarations::CppParameterType;
use brokk_bifrost_cpp::external_declarations::{
    CppExternalDeclarationCompleteness, CppExternalDeclarationLimits, CppExternalMemberKind,
    CppExternalVisibility, external_angle_include_paths, external_angle_include_paths_from_root,
    extract_external_declarations,
};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, Default)]
pub struct CppDependencyPackAdapter;

/// Refine one C++ route with explicit include and activated-pack evidence.
pub(crate) fn external_boundary_evidence(
    analyzer: &CppAnalyzer,
    overlay: Option<&SemanticModelOverlay>,
    file: &ProjectFile,
    name: &str,
) -> (BoundaryStatus, Option<String>) {
    let Some(resolved_headers) = directly_reached_external_headers(analyzer, file) else {
        return (BoundaryStatus::ExternalUnknown, None);
    };
    let Some(resolved_headers) = resolved_headers.headers() else {
        return (BoundaryStatus::ExternalUnknown, None);
    };
    if resolved_headers.is_empty() {
        return (BoundaryStatus::ExternalUnknown, None);
    }

    let matches = overlay
        .into_iter()
        .flat_map(|overlay| overlay.symbols_named(name).records)
        .filter(|symbol| symbol.language == "cpp")
        .filter(|symbol| symbol_is_in_headers(symbol, resolved_headers))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [symbol] => (BoundaryStatus::ExternalIndexed, Some(symbol.id.clone())),
        [] => (BoundaryStatus::ExternalDeclaredUnindexed, None),
        _ => (BoundaryStatus::ExternalIndexed, None),
    }
}

/// Whether a direct external include publishes one exact owner/member pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CppExternalMemberResolution {
    Indexed,
    DeclaredUnindexed,
    Absent,
    Unknown,
}

pub(crate) fn external_member_resolution(
    analyzer: &CppAnalyzer,
    overlay: Option<&SemanticModelOverlay>,
    file: &ProjectFile,
    owner_name: &str,
    member_name: &str,
) -> CppExternalMemberResolution {
    let Some(headers) = directly_reached_external_headers(analyzer, file) else {
        return CppExternalMemberResolution::Unknown;
    };
    let Some(headers) = headers.headers() else {
        return CppExternalMemberResolution::Unknown;
    };
    let mut matching_owner = false;
    let mut partial_owner = false;
    if let Some(overlay) = overlay {
        for owner in overlay
            .symbols_named(owner_name)
            .records
            .into_iter()
            .filter(|owner| {
                owner.language == "cpp"
                    && owner.owner_id.is_none()
                    && symbol_is_in_headers(owner, headers)
            })
        {
            matching_owner = true;
            partial_owner |= owner.provenance.completeness == SemanticModelCompleteness::Partial;
            if overlay
                .members_of(&owner.id)
                .records
                .into_iter()
                .any(|member| {
                    member.name == member_name
                        && member.visibility == Visibility::Public
                        && symbol_is_in_headers(member, headers)
                })
            {
                return CppExternalMemberResolution::Indexed;
            }
        }
    }
    if matching_owner && !partial_owner {
        CppExternalMemberResolution::Absent
    } else if headers.is_empty() {
        CppExternalMemberResolution::Unknown
    } else {
        CppExternalMemberResolution::DeclaredUnindexed
    }
}

fn directly_reached_external_headers(
    analyzer: &CppAnalyzer,
    file: &ProjectFile,
) -> Option<Arc<ReachedExternalHeaders>> {
    let cancellation = analyzer.active_query_cancellation();
    let keep_going = || {
        !cancellation
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
    };
    directly_reached_external_headers_while(analyzer, file, &keep_going)
}

fn directly_reached_external_headers_while(
    analyzer: &CppAnalyzer,
    file: &ProjectFile,
    keep_going: &impl Fn() -> bool,
) -> Option<Arc<ReachedExternalHeaders>> {
    let cell = analyzer.external_header_closure_cell(file);
    match cell.get_or_try_build_pool_independent_while(keep_going, || {
        Ok::<_, std::convert::Infallible>(build_directly_reached_external_headers(
            analyzer, file, keep_going,
        ))
    }) {
        Ok(outcome) => outcome,
        Err(never) => match never {},
    }
}

fn build_directly_reached_external_headers(
    analyzer: &CppAnalyzer,
    file: &ProjectFile,
    keep_going: &impl Fn() -> bool,
) -> Option<ReachedExternalHeaders> {
    if !keep_going() {
        return None;
    }
    analyzer.record_external_header_closure_build();
    let Some(syntax) = analyzer.prepared_syntax(file) else {
        return Some(ReachedExternalHeaders::Unavailable);
    };
    const MAX_CLOSURE_HEADERS: usize = 10_000;
    const MAX_CLOSURE_BYTES: usize = 32 * 1024 * 1024;
    let mut resolved_headers = Vec::new();
    let mut pending =
        external_angle_include_paths_from_root(syntax.source(), syntax.tree().root_node());
    let mut visited = crate::hash::HashSet::default();
    let mut bytes_read = 0usize;
    while let Some(include) = pending.pop() {
        if !keep_going() {
            return None;
        }
        match analyzer.resolve_external_angle_include(file, &include) {
            CppExternalIncludeResolution::Declared { root, header } => {
                if !visited.insert(header.clone()) {
                    continue;
                }
                if visited.len() > MAX_CLOSURE_HEADERS {
                    return Some(ReachedExternalHeaders::Unavailable);
                }
                let Ok(relative_path) = header.strip_prefix(&root) else {
                    return Some(ReachedExternalHeaders::Unavailable);
                };
                resolved_headers.push(ReachedExternalHeader {
                    dependency_name: root_dependency_name(&root),
                    relative_path: relative_path.to_path_buf(),
                });
                let Ok(header_source) = read_external_header(&header) else {
                    return Some(ReachedExternalHeaders::Unavailable);
                };
                bytes_read = bytes_read.saturating_add(header_source.len());
                if bytes_read > MAX_CLOSURE_BYTES {
                    return Some(ReachedExternalHeaders::Unavailable);
                }
                analyzer.record_external_header_parse();
                pending.extend(external_angle_include_paths(&header_source));
            }
            CppExternalIncludeResolution::MissingCompileContext
            | CppExternalIncludeResolution::Conflicting => {
                return Some(ReachedExternalHeaders::Unavailable);
            }
            CppExternalIncludeResolution::Undeclared => {}
        }
    }
    resolved_headers.sort();
    resolved_headers.dedup();
    Some(ReachedExternalHeaders::Complete(resolved_headers))
}

#[derive(Debug)]
pub(super) enum ReachedExternalHeaders {
    Complete(Vec<ReachedExternalHeader>),
    Unavailable,
}

impl ReachedExternalHeaders {
    fn headers(&self) -> Option<&[ReachedExternalHeader]> {
        match self {
            Self::Complete(headers) => Some(headers),
            Self::Unavailable => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ReachedExternalHeader {
    dependency_name: String,
    relative_path: PathBuf,
}

fn symbol_is_in_headers(
    symbol: &crate::analyzer::semantic_model::SemanticModelSymbol,
    headers: &[ReachedExternalHeader],
) -> bool {
    let Some(path) = symbol.locator_path.as_deref() else {
        return false;
    };
    let package = symbol
        .provenance
        .activation
        .matched_evidence
        .package
        .as_ref()
        .map(|package| package.name.as_str());
    headers.iter().any(|header| {
        package == Some(header.dependency_name.as_str()) && header.relative_path == Path::new(path)
    })
}

impl DependencyPackAdapter for CppDependencyPackAdapter {
    fn adapter_name(&self) -> &str {
        "bifrost-cpp-headers"
    }

    fn adapter_version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn producer(&self) -> Producer {
        Producer {
            name: self.adapter_name().to_owned(),
            version: self.adapter_version().to_owned(),
        }
    }

    fn can_produce(&self, dependency: &ResolvedDependency) -> bool {
        dependency.evidence.language == "cpp"
            && dependency
                .artifacts
                .iter()
                .any(|artifact| artifact.kind == ExternalArtifactKind::CppHeaderSourceSet)
    }

    fn produce(
        &self,
        dependency: &ResolvedDependency,
        artifacts: &[ExactDependencyArtifact],
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
    ) -> DependencyPackProduction {
        let mut diagnostics = BoundedProducerDiagnostics::new(limits);
        let artifacts = artifacts
            .iter()
            .filter(|artifact| artifact.kind() == ExternalArtifactKind::CppHeaderSourceSet)
            .collect::<Vec<_>>();
        if artifacts.len() != 1 {
            diagnostics.error(
                "cpp.artifact_count",
                None,
                "C++ dependency production requires exactly one header source set",
            );
            let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
            return DependencyPackProduction {
                pack: None,
                diagnostics,
                suppressed_diagnostics,
            };
        }
        let artifact = artifacts[0];
        let mut extracted_types = Vec::new();
        let mut extracted_members = Vec::new();
        let mut partial = false;
        for entry in artifact.source_entries() {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                diagnostics.error(
                    "artifact.cancelled",
                    None,
                    "C++ header production was cancelled",
                );
                let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
                return DependencyPackProduction {
                    pack: None,
                    diagnostics,
                    suppressed_diagnostics,
                };
            }
            let Ok(source) = std::str::from_utf8(entry.bytes()) else {
                partial = true;
                diagnostics.warning(
                    "cpp.header_not_utf8",
                    Some(entry.relative_path().to_owned()),
                    "C++ header is not UTF-8",
                );
                continue;
            };
            let extracted = extract_external_declarations(
                artifact.path(),
                Path::new(entry.relative_path()),
                source,
                CppExternalDeclarationLimits {
                    max_records: limits.max_records.saturating_sub(
                        extracted_types
                            .len()
                            .saturating_add(extracted_members.len()),
                    ),
                },
            );
            partial |= extracted.completeness == CppExternalDeclarationCompleteness::Partial;
            for diagnostic in extracted.diagnostics {
                diagnostics.warning(
                    diagnostic.code,
                    Some(entry.relative_path().to_owned()),
                    diagnostic.message,
                );
            }
            extracted_types.extend(extracted.types);
            extracted_members.extend(extracted.members);
            if extracted_types
                .len()
                .saturating_add(extracted_members.len())
                >= limits.max_records
            {
                partial = true;
                diagnostics.warning(
                    "cpp.external.record_limit",
                    Some(entry.relative_path().to_owned()),
                    format!(
                        "C++ header source set reached the declaration record limit {}",
                        limits.max_records
                    ),
                );
                break;
            }
        }

        let member_owner_sources = extracted_members
            .iter()
            .filter_map(|member| {
                member
                    .owner
                    .as_ref()
                    .map(|owner| (owner.clone(), member.source_path.clone()))
            })
            .collect::<crate::hash::HashSet<_>>();
        extracted_types.sort_by(|left, right| {
            left.name.cmp(&right.name).then_with(|| {
                member_owner_sources
                    .contains(&(right.name.clone(), right.source_path.clone()))
                    .cmp(
                        &member_owner_sources
                            .contains(&(left.name.clone(), left.source_path.clone())),
                    )
            })
        });
        extracted_types.dedup_by(|left, right| left.name == right.name);
        let type_ids = extracted_types
            .iter()
            .map(|record| {
                (
                    record.name.clone(),
                    type_declaration_id(TypeIdentity {
                        ecosystem: "cpp-headers",
                        name: &record.name,
                    }),
                )
            })
            .collect::<HashMap<_, _>>();
        let types = extracted_types
            .into_iter()
            .map(|record| TypeFact {
                id: type_ids[&record.name].clone(),
                name: record.name.clone(),
                type_kind: TypeKind::Class,
                visibility: match record.visibility {
                    CppExternalVisibility::Public => Visibility::Public,
                    CppExternalVisibility::Protected => Visibility::Protected,
                    CppExternalVisibility::Private => Visibility::Private,
                },
                is_abstract: false,
                is_sealed: false,
                has_explicit_type_terms: false,
                type_parameters: Vec::new(),
                type_parameter_constraints: Vec::new(),
                underlying_type: None,
                embedded_types: Vec::new(),
                hierarchy: record
                    .direct_bases
                    .into_iter()
                    .map(|name| HierarchyFact {
                        hierarchy_kind: HierarchyKind::Extends,
                        target: named_type(name),
                        declaration_ordinal: None,
                    })
                    .collect(),
                aliases: (record.source_name != record.name)
                    .then_some(record.source_name)
                    .into_iter()
                    .collect(),
                extension_surfaces: Vec::new(),
                guard: None,
                locator: Locator::Artifact {
                    path: stable_path(&record.source_path),
                    symbol: record.name,
                },
            })
            .collect::<Vec<_>>();

        let mut members = Vec::new();
        for record in extracted_members {
            let Some(owner_name) = record.owner.as_deref() else {
                partial = true;
                diagnostics.warning(
                    "cpp.member_owner_unavailable",
                    Some(stable_path(&record.source_path)),
                    format!(
                        "C++ declaration `{}` has no indexed type owner",
                        record.qualified_name
                    ),
                );
                continue;
            };
            let Some(owner_id) = type_ids.get(owner_name) else {
                partial = true;
                diagnostics.warning(
                    "cpp.member_owner_missing",
                    Some(stable_path(&record.source_path)),
                    format!(
                        "C++ member `{}` has no emitted owner",
                        record.qualified_name
                    ),
                );
                continue;
            };
            let parameters = record
                .parameter_types
                .unwrap_or_default()
                .into_iter()
                .map(|parameter| match parameter {
                    CppParameterType::Structured(identity) => {
                        (pack_type_ref(&identity).unwrap_or_else(unknown_type), false)
                    }
                    CppParameterType::Ellipsis => (unknown_type(), true),
                    CppParameterType::Unstructured => (unknown_type(), false),
                })
                .collect::<Vec<_>>();
            let parameter_types = parameters
                .iter()
                .map(|(r#type, _)| r#type.clone())
                .collect::<Vec<_>>();
            let parameter_variadics = parameters
                .iter()
                .map(|(_, variadic)| *variadic)
                .collect::<Vec<_>>();
            let return_type = record.return_type.as_ref().and_then(pack_type_ref);
            let member_kind = match record.kind {
                CppExternalMemberKind::Function if record.is_constructor => MemberKind::Constructor,
                CppExternalMemberKind::Function => MemberKind::Method,
                CppExternalMemberKind::Field => MemberKind::Field,
                CppExternalMemberKind::Macro => MemberKind::Macro,
            };
            let id = member_declaration_id(MemberIdentity {
                owner_id,
                kind: member_kind,
                is_static: false,
                parameter_arity: parameter_types.len(),
                name: &record.name,
                generic_arity: 0,
                parameter_types: &parameter_types,
                parameter_variadics: &parameter_variadics,
                return_type: return_type.as_ref(),
            });
            let signature = (record.kind == CppExternalMemberKind::Function).then(|| Signature {
                type_parameters: Vec::new(),
                parameters: parameters
                    .into_iter()
                    .map(|(r#type, variadic)| Parameter {
                        name: None,
                        r#type,
                        optional: false,
                        variadic,
                    })
                    .collect(),
                returns: return_type,
            });
            members.push(MemberFact {
                id,
                owner: owner_id.clone(),
                name: record.name,
                member_kind,
                visibility: match record.visibility {
                    CppExternalVisibility::Public => Visibility::Public,
                    CppExternalVisibility::Protected => Visibility::Protected,
                    CppExternalVisibility::Private => Visibility::Private,
                },
                is_static: false,
                is_abstract: false,
                is_virtual: false,
                signature,
                receiver: Some(ReceiverFact { pointer: false }),
                extension_receiver: None,
                extension_receiver_constraints: Vec::new(),
                aliases: Vec::new(),
                guard: None,
                locator: Locator::Artifact {
                    path: stable_path(&record.source_path),
                    symbol: record.qualified_name,
                },
            });
        }
        members.sort_by(|left, right| left.id.cmp(&right.id));
        members.dedup_by(|left, right| left.id == right.id);

        let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
        let completeness = if partial || !diagnostics.is_empty() || suppressed_diagnostics != 0 {
            Completeness::Partial
        } else {
            Completeness::Complete
        };
        let selector = dependency
            .evidence
            .package
            .as_ref()
            .map(|coordinate| NameSelector {
                name: coordinate.name.clone(),
                version: coordinate
                    .version
                    .as_ref()
                    .map(|version| format!("={version}")),
            });
        DependencyPackProduction {
            pack: Some(AuthoredSemanticModelPack {
                schema_version: crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
                pack_id: "bifrost.external.cpp-headers".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                producer: self.producer(),
                language: "cpp".to_owned(),
                ecosystem: "cpp-headers".to_owned(),
                compatibility: Compatibility {
                    bifrost: format!("={}", env!("CARGO_PKG_VERSION")),
                    toolchains: Vec::new(),
                },
                provenance: Provenance {
                    source: format!("exact local C++ headers sha256:{}", artifact.sha256()),
                    revision: None,
                },
                license: "NOASSERTION".to_owned(),
                completeness,
                safety: Safety {
                    generated_code_only: false,
                    review_required: false,
                },
                shards: vec![AuthoredShard {
                    id: "declarations.external".to_owned(),
                    activation: vec![ActivationSelector {
                        package: selector,
                        module: None,
                        toolchain: None,
                        targets: Vec::new(),
                        configurations: Vec::new(),
                        artifact_sha256: Some(artifact.sha256().to_owned()),
                    }],
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

pub fn resolve_cpp_semantic_pack_dependencies(
    project: &dyn Project,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> DependencyDiscoveryOutcome {
    let contexts = CppCompileContexts::load(project);
    let mut dependencies = Vec::new();
    let mut diagnostics = Vec::new();
    let header_sets = match discover_reachable_header_sets(project, &contexts, limits, cancellation)
    {
        Ok(header_sets) => header_sets,
        Err(HeaderDiscoveryError::Cancelled) => {
            return DependencyDiscoveryOutcome {
                dependencies,
                diagnostics,
                suppressed_diagnostics: 0,
                complete: false,
                cancelled: true,
                profile: DependencyDiscoveryProfile::default(),
            };
        }
        Err(HeaderDiscoveryError::Failed(message)) => {
            diagnostics.push(DependencyPackDiagnostic {
                severity: DependencyPackDiagnosticSeverity::Error,
                code: "cpp.header_discovery_failed".to_owned(),
                dependency_id: None,
                location: None,
                message,
            });
            Vec::new()
        }
    };
    let dependency_limit_hit = header_sets.len() > limits.max_dependencies;
    let suppressed_diagnostics = header_sets.len().saturating_sub(limits.max_dependencies);
    for (root, paths) in header_sets.into_iter().take(limits.max_dependencies) {
        let name = root_dependency_name(&root);
        dependencies.push(ResolvedDependency {
            id: name.clone(),
            evidence: SemanticModelActivationEvidence {
                language: "cpp".to_owned(),
                ecosystem: "cpp-headers".to_owned(),
                package: Some(CatalogCoordinate {
                    name,
                    version: None,
                }),
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            },
            provenance: Vec::new(),
            artifacts: vec![ResolvedDependencyArtifact::source_set(
                DependencyArtifactRole::Declarations,
                ExternalArtifactKind::CppHeaderSourceSet,
                root,
                paths,
            )],
        });
    }
    if dependency_limit_hit {
        diagnostics.push(DependencyPackDiagnostic {
            severity: DependencyPackDiagnosticSeverity::Error,
            code: "limit.dependencies".to_owned(),
            dependency_id: None,
            location: None,
            message: format!(
                "C++ header discovery exceeded dependency limit {}",
                limits.max_dependencies
            ),
        });
    }
    DependencyDiscoveryOutcome {
        profile: DependencyDiscoveryProfile {
            metadata_inputs_considered: 1,
            dependencies_resolved: dependencies.len(),
        },
        complete: diagnostics.is_empty(),
        dependencies,
        diagnostics,
        suppressed_diagnostics,
        cancelled: false,
    }
}

fn root_dependency_name(root: &Path) -> String {
    let identity = lower_hex_string(&sha256_bytes(root.to_string_lossy().as_bytes()));
    format!("cpp-include-root-{identity}")
}

fn discover_reachable_header_sets(
    project: &dyn Project,
    contexts: &CppCompileContexts,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> Result<Vec<(PathBuf, Vec<PathBuf>)>, HeaderDiscoveryError> {
    let files = project.analyzable_files(Language::Cpp).map_err(|error| {
        HeaderDiscoveryError::Failed(format!("cannot list C++ source files: {error}"))
    })?;
    let mut pending = Vec::new();
    for file in files {
        let source = file.read_to_string().map_err(|error| {
            HeaderDiscoveryError::Failed(format!(
                "cannot read C++ source {}: {error}",
                file.rel_path().display()
            ))
        })?;
        pending.extend(
            external_angle_include_paths(&source)
                .into_iter()
                .map(|include| (file.clone(), include)),
        );
    }
    let mut paths_by_root: HashMap<PathBuf, crate::hash::HashSet<PathBuf>> = HashMap::default();
    let mut visited = crate::hash::HashSet::default();
    let mut bytes_read = 0u64;
    while let Some((source_file, include)) = pending.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(HeaderDiscoveryError::Cancelled);
        }
        let CppExternalIncludeResolution::Declared { root, header } =
            contexts.resolve_external_angle_include(&source_file, &include)
        else {
            continue;
        };
        if !visited.insert(header.clone()) {
            continue;
        }
        let relative = header
            .strip_prefix(&root)
            .expect("compile-context containment keeps headers below their root")
            .to_path_buf();
        if relative.components().count() > limits.max_source_path_depth {
            return Err(HeaderDiscoveryError::Failed(format!(
                "C++ header source set exceeded path-depth limit {}",
                limits.max_source_path_depth
            )));
        }
        let root_paths = paths_by_root.entry(root).or_default();
        root_paths.insert(relative);
        if root_paths.len() > limits.max_source_files_per_artifact {
            return Err(HeaderDiscoveryError::Failed(format!(
                "C++ header source set exceeded file limit {}",
                limits.max_source_files_per_artifact
            )));
        }
        let source = read_external_header(&header).map_err(|error| {
            HeaderDiscoveryError::Failed(format!(
                "cannot read external C++ header {}: {error}",
                header.display()
            ))
        })?;
        bytes_read = bytes_read.saturating_add(source.len() as u64);
        if bytes_read > limits.max_total_artifact_bytes {
            return Err(HeaderDiscoveryError::Failed(format!(
                "C++ header discovery exceeded byte limit {}",
                limits.max_total_artifact_bytes
            )));
        }
        pending.extend(
            external_angle_include_paths(&source)
                .into_iter()
                .map(|include| (source_file.clone(), include)),
        );
    }
    let mut sets = paths_by_root
        .into_iter()
        .map(|(root, paths)| {
            let mut paths = paths.into_iter().collect::<Vec<_>>();
            paths.sort();
            (root, paths)
        })
        .collect::<Vec<_>>();
    sets.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(sets)
}

fn read_external_header(path: &Path) -> std::io::Result<String> {
    std::fs::read_to_string(path)
}

enum HeaderDiscoveryError {
    Cancelled,
    Failed(String),
}

fn named_type(name: String) -> TypeRef {
    TypeRef::Named {
        name,
        arguments: Vec::new(),
        nullable: false,
    }
}

/// The pack type reference for a type the header extractor could not reduce to
/// a structured identity, and for a `...` pack, which has no type at all.
///
/// An unbounded wildcard is the model's own way to say "some type": it keeps
/// the parameter's position, and therefore the callable's arity and identity,
/// without inventing a type name that no declaration spells.
fn unknown_type() -> TypeRef {
    TypeRef::Wildcard {
        variance: WildcardVariance::Any,
        bound: None,
    }
}

/// Translate a parser-derived structured type into a pack type reference.
///
/// The two models line up node for node except in one place: C++ cv-qualifiers
/// are not part of either model, so `const T&` is published as a reference to
/// `T`, exactly as the rustdoc producer publishes `&mut T` and the C# producer
/// publishes an `in` parameter. A nominal name is published as the path the
/// declaration writes, joined by `.` like every other name in a pack; the
/// structured name's lexical scope is deliberately not folded in, because a
/// pack name asserts an identity and prefixing an enclosing scope onto an
/// unqualified spelling would assert one the header never proved.
fn pack_type_ref(identity: &StructuredTypeIdentity) -> Option<TypeRef> {
    enum Work {
        Visit(StructuredTypeNodeId),
        Pointer,
        ByRef,
        Array,
        Slice,
        Map,
        Generic { argument_count: usize },
    }

    // A structured arena may share one child among several parents, while a
    // pack type reference is a tree. Expanding sharing is bounded work here
    // rather than unbounded materialization: a type past the bound is reported
    // as unknown instead of being expanded.
    const MAX_TRANSLATION_STEPS: usize = 8_192;

    let mut work = vec![Work::Visit(identity.root_id())];
    let mut values: Vec<TypeRef> = Vec::new();
    let mut steps = 0usize;
    while let Some(next) = work.pop() {
        steps += 1;
        if steps > MAX_TRANSLATION_STEPS {
            return None;
        }
        match next {
            Work::Visit(id) => match identity.view(id)? {
                StructuredTypeNodeView::Named(name) => {
                    let name = name.path().join(".");
                    debug_assert!(
                        !name.is_empty() && !name.chars().any(char::is_whitespace),
                        "structured type name components are parser identifiers: {name:?}"
                    );
                    values.push(named_type(name));
                }
                StructuredTypeNodeView::Pointer(inner) => {
                    work.push(Work::Pointer);
                    work.push(Work::Visit(inner));
                }
                StructuredTypeNodeView::Reference(inner) => {
                    work.push(Work::ByRef);
                    work.push(Work::Visit(inner));
                }
                StructuredTypeNodeView::Array(inner) => {
                    work.push(Work::Array);
                    work.push(Work::Visit(inner));
                }
                StructuredTypeNodeView::Slice(inner) => {
                    work.push(Work::Slice);
                    work.push(Work::Visit(inner));
                }
                StructuredTypeNodeView::Map { key, value } => {
                    work.push(Work::Map);
                    work.push(Work::Visit(value));
                    work.push(Work::Visit(key));
                }
                StructuredTypeNodeView::Generic { base, arguments } => {
                    work.push(Work::Generic {
                        argument_count: arguments.len(),
                    });
                    for argument in arguments.iter().rev() {
                        work.push(Work::Visit(*argument));
                    }
                    work.push(Work::Visit(base));
                }
            },
            Work::Pointer => {
                let element = Box::new(values.pop()?);
                values.push(TypeRef::Pointer { element });
            }
            Work::ByRef => {
                let element = Box::new(values.pop()?);
                values.push(TypeRef::ByRef { element });
            }
            Work::Array => {
                let element = Box::new(values.pop()?);
                values.push(TypeRef::Array { element });
            }
            Work::Slice => {
                let element = Box::new(values.pop()?);
                values.push(TypeRef::Slice { element });
            }
            Work::Map => {
                let value = Box::new(values.pop()?);
                let key = Box::new(values.pop()?);
                values.push(TypeRef::Map { key, value });
            }
            Work::Generic { argument_count } => {
                let start = values.len().checked_sub(argument_count)?;
                let arguments = values.split_off(start);
                let TypeRef::Named { name, nullable, .. } = values.pop()? else {
                    // Only a nominal type can carry pack type arguments.
                    return None;
                };
                values.push(TypeRef::Named {
                    name,
                    arguments,
                    nullable,
                });
            }
        }
    }
    (values.len() == 1).then(|| values.pop()).flatten()
}

fn stable_path(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic_model::CompilerOptions;
    use crate::analyzer::semantic_model::{
        AuthoredPayload, CatalogOptions, ResolvedDependencyArtifactInput,
        SemanticModelActivationControl, SemanticModelActivationRequest, SemanticModelControlAction,
        SemanticModelControlScope, SemanticModelPackSelector, SemanticModelRuntimeLimits,
        SemanticModelRuntimeOutcome, SemanticPackCatalog, compile_pack, read_exact_source_set,
    };
    use crate::analyzer::usages::get_definition::DefinitionLookupRequest;
    use crate::analyzer::usages::get_definition::trace::{
        TraceCandidateRef, resolve_definition_batch_with_trace,
    };
    use crate::analyzer::{
        AnalyzerConfig, DependencyPackEcosystem, DependencyPackWorkspaceContext, Language,
        TestProject, WorkspaceAnalyzer,
    };
    use brokk_bifrost_core::analyzer::ProjectFile;
    use std::sync::Arc;

    #[test]
    fn discovers_and_produces_vector_type_and_member_facts() {
        let temp = tempfile::tempdir().expect("temp root");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), "src/main.cpp")
            .write("#include <vector>\n")
            .expect("source");
        ProjectFile::new(root.clone(), "fake/include/vector")
            .write("namespace std { template <typename T> class vector { public: void push_back(const T&); }; }")
            .expect("header");
        ProjectFile::new(root.clone(), "compile_commands.json")
            .write(r#"[{"directory":".","file":"src/main.cpp","arguments":["clang++","-isystem","fake/include","-c","src/main.cpp"]}]"#)
            .expect("database");
        let project = TestProject::new(root, Language::Cpp);
        let discovery = resolve_cpp_semantic_pack_dependencies(
            &project,
            &DependencyPackLimits::default(),
            None,
        );
        assert!(discovery.complete, "{discovery:#?}");
        let [dependency] = discovery.dependencies.as_slice() else {
            panic!("one C++ include-root dependency: {discovery:#?}");
        };
        let ResolvedDependencyArtifactInput::SourceSet {
            root,
            relative_paths,
        } = &dependency.artifacts[0].input
        else {
            panic!("C++ dependency uses a source set");
        };
        let exact = read_exact_source_set(
            root,
            relative_paths,
            DependencyPackLimits::default().max_source_files_per_artifact,
            DependencyPackLimits::default().max_source_path_depth,
            &ArtifactProducerLimits::default(),
        )
        .expect("exact source set");
        let artifact = ExactDependencyArtifact::from_exact(
            DependencyArtifactRole::Declarations,
            ExternalArtifactKind::CppHeaderSourceSet,
            None,
            exact,
        );
        let production = CppDependencyPackAdapter.produce(
            dependency,
            &[artifact],
            &ArtifactProducerLimits::default(),
            None,
        );
        let pack = production.pack.expect("C++ pack");
        let AuthoredPayload::DeclarationFacts { types, members, .. } = &pack.shards[0].payload
        else {
            panic!("declaration facts");
        };
        let vector = types
            .iter()
            .find(|fact| fact.name == "std.vector")
            .expect("vector type");
        assert!(
            members
                .iter()
                .any(|fact| fact.owner == vector.id && fact.name == "push_back")
        );
    }

    /// The pack type model carries a type's identity and shape, never a source
    /// spelling: a parameter written `const T&` must reach the pack as a
    /// reference to `T`, and the pack must validate.
    #[test]
    fn produced_header_pack_publishes_structured_parameter_types() {
        let temp = tempfile::tempdir().expect("temp root");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), "src/main.cpp")
            .write("#include <vector>\n")
            .expect("source");
        ProjectFile::new(root.clone(), "fake/include/vector")
            .write(concat!(
                "namespace ns { class Widget; }\n",
                "namespace std {\n",
                "class string;\n",
                "template <typename T> class vector {\n",
                "public:\n",
                "  void push_back(const T& value);\n",
                "  void assign(const std::string& name, ns::Widget* widget);\n",
                "  void nest(const vector<int>& other);\n",
                "  void insert(int index);\n",
                "  void insert(const T& value);\n",
                "  void log(const char* format, ...);\n",
                "};\n",
                "}\n",
            ))
            .expect("header");
        ProjectFile::new(root.clone(), "compile_commands.json")
            .write(r#"[{"directory":".","file":"src/main.cpp","arguments":["clang++","-isystem","fake/include","-c","src/main.cpp"]}]"#)
            .expect("database");
        let project = TestProject::new(root, Language::Cpp);
        let discovery = resolve_cpp_semantic_pack_dependencies(
            &project,
            &DependencyPackLimits::default(),
            None,
        );
        let [dependency] = discovery.dependencies.as_slice() else {
            panic!("one C++ include-root dependency: {discovery:#?}");
        };
        let ResolvedDependencyArtifactInput::SourceSet {
            root,
            relative_paths,
        } = &dependency.artifacts[0].input
        else {
            panic!("C++ dependency uses a source set");
        };
        let exact = read_exact_source_set(
            root,
            relative_paths,
            DependencyPackLimits::default().max_source_files_per_artifact,
            DependencyPackLimits::default().max_source_path_depth,
            &ArtifactProducerLimits::default(),
        )
        .expect("exact source set");
        let production = CppDependencyPackAdapter.produce(
            dependency,
            &[ExactDependencyArtifact::from_exact(
                DependencyArtifactRole::Declarations,
                ExternalArtifactKind::CppHeaderSourceSet,
                None,
                exact,
            )],
            &ArtifactProducerLimits::default(),
            None,
        );
        let pack = production.pack.expect("C++ pack");
        if let Err(diagnostics) = compile_pack(&pack, &CompilerOptions::default()) {
            panic!("the produced pack must validate: {diagnostics:#?}");
        }
        let AuthoredPayload::DeclarationFacts { types, members, .. } = &pack.shards[0].payload
        else {
            panic!("declaration facts");
        };
        let vector = types
            .iter()
            .find(|fact| fact.name == "std.vector")
            .expect("vector type");
        let parameters = |name: &str, arity: usize| {
            members
                .iter()
                .filter(|fact| fact.owner == vector.id && fact.name == name)
                .filter_map(|fact| fact.signature.as_ref())
                .find(|signature| signature.parameters.len() == arity)
                .unwrap_or_else(|| panic!("`{name}` with {arity} parameters: {members:#?}"))
                .parameters
                .clone()
        };
        let by_reference = |element: TypeRef| Parameter {
            name: None,
            r#type: TypeRef::ByRef {
                element: Box::new(element),
            },
            optional: false,
            variadic: false,
        };

        assert_eq!(
            vec![by_reference(named_type("T".to_owned()))],
            parameters("push_back", 1),
            "a `const T&` parameter is a reference to `T`, not the text `const T&`"
        );
        assert_eq!(
            vec![
                by_reference(named_type("std.string".to_owned())),
                Parameter {
                    name: None,
                    r#type: TypeRef::Pointer {
                        element: Box::new(named_type("ns.Widget".to_owned())),
                    },
                    optional: false,
                    variadic: false,
                },
            ],
            parameters("assign", 2),
            "qualification and pointer shape survive"
        );
        assert_eq!(
            vec![by_reference(TypeRef::Named {
                name: "vector".to_owned(),
                arguments: vec![named_type("int".to_owned())],
                nullable: false,
            })],
            parameters("nest", 1),
            "type arguments survive"
        );
        assert_eq!(
            vec![
                Parameter {
                    name: None,
                    r#type: TypeRef::Pointer {
                        element: Box::new(named_type("char".to_owned())),
                    },
                    optional: false,
                    variadic: false,
                },
                Parameter {
                    name: None,
                    r#type: TypeRef::Wildcard {
                        variance: WildcardVariance::Any,
                        bound: None,
                    },
                    optional: false,
                    variadic: true,
                },
            ],
            parameters("log", 2),
            "a `...` pack keeps its position without inventing a type name"
        );

        let insert_ids = members
            .iter()
            .filter(|fact| fact.owner == vector.id && fact.name == "insert")
            .map(|fact| fact.id.clone())
            .collect::<crate::hash::HashSet<_>>();
        assert_eq!(
            2,
            insert_ids.len(),
            "parameter types discriminate two `insert` overloads: {members:#?}"
        );
    }

    #[test]
    fn dependency_limit_makes_discovery_incomplete() {
        let temp = tempfile::tempdir().expect("temp root");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), "src/main.cpp")
            .write("#include <one.hpp>\n#include <two.hpp>\nint main() {}\n")
            .expect("source");
        ProjectFile::new(root.clone(), "first/include/one.hpp")
            .write("class One {};\n")
            .expect("first header");
        ProjectFile::new(root.clone(), "second/include/two.hpp")
            .write("class Two {};\n")
            .expect("second header");
        ProjectFile::new(root.clone(), "compile_commands.json")
            .write(r#"[{"directory":".","file":"src/main.cpp","arguments":["clang++","-isystem","first/include","-isystem","second/include","-c","src/main.cpp"]}]"#)
            .expect("database");
        let project = TestProject::new(root, Language::Cpp);
        let limits = DependencyPackLimits {
            max_dependencies: 1,
            ..DependencyPackLimits::default()
        };

        let discovery = resolve_cpp_semantic_pack_dependencies(&project, &limits, None);

        assert!(!discovery.complete, "{discovery:#?}");
        assert_eq!(1, discovery.dependencies.len());
        assert_eq!(1, discovery.suppressed_diagnostics);
        assert!(
            discovery
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "limit.dependencies"),
            "{discovery:#?}"
        );
    }

    #[test]
    fn activated_header_pack_indexes_a_direct_external_member_route() {
        let temp = tempfile::tempdir().expect("temp root");
        let root = temp.path().canonicalize().expect("canonical root");
        let source =
            "#include <vector>\nvoid add(std::vector<int>& values) { values.push_back(1); }\n";
        let file = ProjectFile::new(root.clone(), "src/main.cpp");
        file.write(source).expect("source");
        ProjectFile::new(root.clone(), "fake/include/vector")
            .write("#include <bits/vector_impl>\n")
            .expect("entry header");
        ProjectFile::new(root.clone(), "fake/include/bits/vector_impl")
            .write("namespace std { template <typename T> class vector { public: void push_back(const T&); }; }")
            .expect("declaration header");
        ProjectFile::new(root.clone(), "compile_commands.json")
            .write(r#"[{"directory":".","file":"src/main.cpp","arguments":["clang++","-isystem","fake/include","-c","src/main.cpp"]}]"#)
            .expect("database");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Cpp));
        let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
        let cancellation = CancellationToken::new();
        let start = source.find("push_back").expect("member start");
        let request = || DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(start),
            end_byte: Some(start + "push_back".len()),
        };
        let [(_, unindexed_trace)] = resolve_definition_batch_with_trace(
            workspace.analyzer(),
            vec![request()],
            file.clone(),
            Arc::from(source),
            &cancellation,
        )
        .try_into()
        .expect("one unindexed lookup");
        assert!(
            unindexed_trace.candidates.iter().any(|candidate| {
                candidate.boundary == BoundaryStatus::ExternalDeclaredUnindexed
            }),
            "{unindexed_trace:#?}"
        );

        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
            .expect("ephemeral catalog");
        let activation = SemanticModelActivationRequest {
            bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION"))
                .expect("crate version"),
            evidence: Vec::new(),
            controls: vec![SemanticModelActivationControl {
                scope: SemanticModelControlScope::Workspace,
                action: SemanticModelControlAction::Enable,
                selector: SemanticModelPackSelector {
                    pack_id: "bifrost.external.cpp-headers".to_owned(),
                    version: None,
                    manifest_digest: None,
                },
            }],
            limits: SemanticModelRuntimeLimits::default(),
        };
        let outcome = workspace.activate_dependency_packs(
            &AnalyzerConfig::default(),
            &[DependencyPackEcosystem::Cpp],
            DependencyPackWorkspaceContext {
                catalog: &catalog,
                persistence: None,
                activation: &activation,
                limits: DependencyPackLimits::default(),
                cancellation: &cancellation,
            },
        );
        assert!(outcome.complete(), "{outcome:#?}");
        assert!(matches!(
            outcome.runtime,
            Some(SemanticModelRuntimeOutcome::Ready { .. })
        ));
        let overlay = workspace
            .analyzer()
            .semantic_model_overlay()
            .expect("C++ overlay");
        let cpp = crate::analyzer::resolve_analyzer::<CppAnalyzer>(workspace.analyzer())
            .expect("C++ analyzer");
        assert!(
            external_member_resolution(cpp, Some(&overlay), &file, "std::vector", "push_back")
                == CppExternalMemberResolution::Indexed,
            "outcome={outcome:#?}\nsymbols={:#?}",
            overlay.symbols()
        );
        assert_eq!(
            CppExternalMemberResolution::Indexed,
            external_member_resolution(cpp, Some(&overlay), &file, "std.vector", "push_back")
        );
        assert_eq!(
            CppExternalMemberResolution::Absent,
            external_member_resolution(cpp, Some(&overlay), &file, "std.vector", "push_bak")
        );
        assert_eq!(
            crate::analyzer::cpp::ExternalHeaderClosureWorkCounts {
                builds: 1,
                external_header_parses: 2,
            },
            cpp.external_header_closure_work_counts_for_test(),
            "all external member and boundary lookups share one closure"
        );

        let [(lookup, trace)] = resolve_definition_batch_with_trace(
            workspace.analyzer(),
            vec![request()],
            file,
            Arc::from(source),
            &cancellation,
        )
        .try_into()
        .expect("one lookup");
        assert!(
            trace.candidates.iter().any(|candidate| {
                matches!(
                    &candidate.candidate,
                    TraceCandidateRef::ExternalRoute { name } if name == "push_back"
                ) && candidate.boundary == BoundaryStatus::ExternalIndexed
                    && candidate.external_target.is_some()
            }),
            "lookup={lookup:#?}\ntrace={trace:#?}"
        );
        assert_eq!(
            crate::analyzer::cpp::ExternalHeaderClosureWorkCounts {
                builds: 1,
                external_header_parses: 2,
            },
            cpp.external_header_closure_work_counts_for_test(),
            "a later forward batch reuses the published closure"
        );
    }

    #[test]
    fn interrupted_external_header_closure_is_not_published() {
        let temp = tempfile::tempdir().expect("temp root");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(root.clone(), "src/main.cpp");
        file.write("#include <one.hpp>\n").expect("source");
        ProjectFile::new(root.clone(), "fake/include/one.hpp")
            .write("#include <two.hpp>\nclass One {};\n")
            .expect("first header");
        ProjectFile::new(root.clone(), "fake/include/two.hpp")
            .write("class Two {};\n")
            .expect("second header");
        ProjectFile::new(root.clone(), "compile_commands.json")
            .write(r#"[{"directory":".","file":"src/main.cpp","arguments":["clang++","-isystem","fake/include","-c","src/main.cpp"]}]"#)
            .expect("database");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Cpp));
        let analyzer = CppAnalyzer::new(project);
        let checks = std::sync::atomic::AtomicUsize::new(0);
        let interrupted = directly_reached_external_headers_while(&analyzer, &file, &|| {
            checks.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 3
        });
        assert!(interrupted.is_none(), "interrupted work is not an answer");
        let interrupted_counts = analyzer.external_header_closure_work_counts_for_test();
        assert_eq!(1, interrupted_counts.builds);

        let complete = directly_reached_external_headers_while(&analyzer, &file, &|| true)
            .expect("fresh query rebuilds");
        let Some(headers) = complete.headers() else {
            panic!("complete closure");
        };
        assert_eq!(2, headers.len());
        let complete_counts = analyzer.external_header_closure_work_counts_for_test();
        assert_eq!(2, complete_counts.builds);
        assert_eq!(
            interrupted_counts.external_header_parses + 2,
            complete_counts.external_header_parses
        );

        let cached = directly_reached_external_headers_while(&analyzer, &file, &|| true)
            .expect("cached closure");
        assert_eq!(2, cached.headers().expect("complete cached closure").len());
        assert_eq!(
            complete_counts,
            analyzer.external_header_closure_work_counts_for_test(),
            "completed work is published exactly once"
        );
    }

    #[test]
    fn unavailable_compile_context_is_cached_without_claiming_headers() {
        let temp = tempfile::tempdir().expect("temp root");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(root.clone(), "src/main.cpp");
        file.write("#include <missing.hpp>\n").expect("source");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Cpp));
        let analyzer = CppAnalyzer::new(project);

        for _ in 0..2 {
            let outcome = directly_reached_external_headers_while(&analyzer, &file, &|| true)
                .expect("stable unavailable outcome");
            assert!(outcome.headers().is_none());
        }
        assert_eq!(
            crate::analyzer::cpp::ExternalHeaderClosureWorkCounts {
                builds: 1,
                external_header_parses: 0,
            },
            analyzer.external_header_closure_work_counts_for_test()
        );
    }

    #[test]
    fn conflicting_compile_context_is_cached_without_claiming_one_header() {
        let temp = tempfile::tempdir().expect("temp root");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(root.clone(), "src/main.cpp");
        file.write("#include <shared.hpp>\n").expect("source");
        ProjectFile::new(root.clone(), "first/include/shared.hpp")
            .write("class First {};\n")
            .expect("first header");
        ProjectFile::new(root.clone(), "second/include/shared.hpp")
            .write("class Second {};\n")
            .expect("second header");
        ProjectFile::new(root.clone(), "compile_commands.json")
            .write(
                r#"[
                    {"directory":".","file":"src/main.cpp","arguments":["clang++","-isystem","first/include","-c","src/main.cpp"]},
                    {"directory":".","file":"src/main.cpp","arguments":["clang++","-isystem","second/include","-c","src/main.cpp"]}
                ]"#,
            )
            .expect("database");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Cpp));
        let analyzer = CppAnalyzer::new(project);

        for _ in 0..2 {
            let outcome = directly_reached_external_headers_while(&analyzer, &file, &|| true)
                .expect("stable conflicting outcome");
            assert!(outcome.headers().is_none());
        }
        assert_eq!(
            crate::analyzer::cpp::ExternalHeaderClosureWorkCounts {
                builds: 1,
                external_header_parses: 0,
            },
            analyzer.external_header_closure_work_counts_for_test()
        );
    }

    #[test]
    fn analyzer_update_discards_external_header_closure_state() {
        use crate::analyzer::IAnalyzer;
        use std::collections::BTreeSet;

        let temp = tempfile::tempdir().expect("temp root");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(root.clone(), "src/main.cpp");
        file.write("#include <one.hpp>\n").expect("source");
        ProjectFile::new(root.clone(), "fake/include/one.hpp")
            .write("class One {};\n")
            .expect("first header");
        ProjectFile::new(root.clone(), "fake/include/two.hpp")
            .write("class Two {};\n")
            .expect("second header");
        ProjectFile::new(root.clone(), "compile_commands.json")
            .write(r#"[{"directory":".","file":"src/main.cpp","arguments":["clang++","-isystem","fake/include","-c","src/main.cpp"]}]"#)
            .expect("database");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Cpp));
        let analyzer = CppAnalyzer::new(project);
        let first = directly_reached_external_headers_while(&analyzer, &file, &|| true)
            .expect("first closure");
        assert_eq!(1, first.headers().expect("complete first closure").len());

        file.write("#include <one.hpp>\n#include <two.hpp>\n")
            .expect("updated source");
        let updated = analyzer.update(&BTreeSet::from([file.clone()]));
        let second = directly_reached_external_headers_while(&updated, &file, &|| true)
            .expect("updated closure");
        assert_eq!(2, second.headers().expect("complete updated closure").len());
        assert_eq!(
            crate::analyzer::cpp::ExternalHeaderClosureWorkCounts {
                builds: 1,
                external_header_parses: 2,
            },
            updated.external_header_closure_work_counts_for_test()
        );
    }
}
