use super::GO_MODULE_SCOPE_SEGMENT;
use super::declarations::{
    collect_go_import_infos, determine_go_package_name, go_node_text, go_structured_type_identity,
};
use super::dependency_discovery::DiscoveredGoPackage;
use crate::CancellationToken;
use crate::analyzer::semantic_model::{
    ActivationSelector, ArtifactProducerLimits, AuthoredPayload, AuthoredSemanticModelPack,
    AuthoredShard, BoundedProducerDiagnostics, ChannelDirection, Compatibility, Completeness,
    DependencyPackAdapter, DependencyPackProduction, EmbeddedTypeFact, ExactDependencyArtifact,
    ExternalArtifactKind, HierarchyFact, HierarchyKind, Locator, MemberFact, MemberIdentity,
    MemberKind, NameSelector, Parameter, Producer, Provenance, ReceiverFact, ResolvedDependency,
    Safety, Signature, StructuredTypeExpression, TypeFact, TypeIdentity, TypeKind,
    TypeParameterConstraint, TypeRef, VersionConstraint, Visibility, member_declaration_id,
    type_declaration_id,
};
use crate::analyzer::tree_sitter_analyzer::{WalkControl, walk_named_tree_preorder};
use crate::hash::{HashMap, HashSet};
use tree_sitter::{Node, Parser, Tree};

#[derive(Debug, Clone, Copy, Default)]
pub struct GoDependencyPackAdapter;

impl DependencyPackAdapter for GoDependencyPackAdapter {
    fn adapter_name(&self) -> &str {
        "bifrost-go-dependency"
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
        dependency.evidence.language == "go"
            && dependency
                .artifacts
                .iter()
                .any(|artifact| artifact.kind == ExternalArtifactKind::GoSourceSet)
    }

    fn produce(
        &self,
        dependency: &ResolvedDependency,
        artifacts: &[ExactDependencyArtifact],
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
    ) -> DependencyPackProduction {
        let mut diagnostics = BoundedProducerDiagnostics::new(limits);
        let go_artifacts = artifacts
            .iter()
            .filter(|artifact| artifact.kind() == ExternalArtifactKind::GoSourceSet)
            .collect::<Vec<_>>();
        if go_artifacts.len() != 1 {
            diagnostics.error(
                "go.artifact_count",
                None,
                "Go dependency production requires exactly one exact source set",
            );
            let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
            return DependencyPackProduction {
                pack: None,
                diagnostics,
                suppressed_diagnostics,
            };
        }
        let packages = match dependency
            .provenance
            .iter()
            .find(|entry| entry.key == "go.packages")
            .map(|entry| serde_json::from_str::<Vec<DiscoveredGoPackage>>(&entry.value))
        {
            Some(Ok(packages)) if !packages.is_empty() => packages,
            Some(Ok(_)) | None => {
                diagnostics.error(
                    "go.package_metadata_missing",
                    None,
                    "Go dependency has no selected package metadata",
                );
                let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
                return DependencyPackProduction {
                    pack: None,
                    diagnostics,
                    suppressed_diagnostics,
                };
            }
            Some(Err(error)) => {
                diagnostics.error(
                    "go.package_metadata_invalid",
                    None,
                    format!("Go package metadata is invalid: {error}"),
                );
                let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
                return DependencyPackProduction {
                    pack: None,
                    diagnostics,
                    suppressed_diagnostics,
                };
            }
        };
        let artifact = go_artifacts[0];
        let import_names = dependency
            .provenance
            .iter()
            .find(|entry| entry.key == "go.import_names")
            .and_then(|entry| serde_json::from_str::<HashMap<String, String>>(&entry.value).ok())
            .unwrap_or_default();
        let facts = produce_go_facts(
            &packages,
            &import_names,
            artifact
                .source_entries()
                .iter()
                .map(|entry| (entry.relative_path(), entry.bytes())),
            limits,
            cancellation,
            &mut diagnostics,
        );
        let Some((types, members)) = facts else {
            let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
            return DependencyPackProduction {
                pack: None,
                diagnostics,
                suppressed_diagnostics,
            };
        };
        let request = production_request(dependency);
        let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
        let completeness = if diagnostics.is_empty() && suppressed_diagnostics == 0 {
            Completeness::Complete
        } else {
            Completeness::Partial
        };
        DependencyPackProduction {
            pack: Some(AuthoredSemanticModelPack {
                schema_version: crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
                pack_id: request.pack_id,
                version: request.version,
                producer: self.producer(),
                language: "go".to_owned(),
                ecosystem: dependency.evidence.ecosystem.clone(),
                compatibility: request.compatibility,
                provenance: Provenance {
                    source: format!("exact local Go dependency sha256:{}", artifact.sha256()),
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
                    activation: request.activation,
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

struct ProductionRequest {
    pack_id: String,
    version: String,
    compatibility: Compatibility,
    activation: Vec<ActivationSelector>,
}

fn production_request(dependency: &ResolvedDependency) -> ProductionRequest {
    let selector = |coordinate: &crate::analyzer::semantic_model::CatalogCoordinate| NameSelector {
        name: coordinate.name.clone(),
        version: coordinate
            .version
            .as_ref()
            .map(|version| format!("={version}")),
    };
    ProductionRequest {
        pack_id: "bifrost.external.go".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        compatibility: Compatibility {
            bifrost: format!("={}", env!("CARGO_PKG_VERSION")),
            toolchains: dependency
                .evidence
                .toolchain
                .as_ref()
                .map(|coordinate| VersionConstraint {
                    name: coordinate.name.clone(),
                    requirement: coordinate
                        .version
                        .as_ref()
                        .map(|version| format!("={version}"))
                        .unwrap_or_else(|| "*".to_owned()),
                })
                .into_iter()
                .collect(),
        },
        activation: vec![ActivationSelector {
            package: dependency.evidence.package.as_ref().map(selector),
            module: dependency.evidence.module.as_ref().map(selector),
            toolchain: dependency.evidence.toolchain.as_ref().map(selector),
            targets: dependency.evidence.target.clone().into_iter().collect(),
            configurations: dependency
                .evidence
                .configuration
                .clone()
                .into_iter()
                .collect(),
            artifact_sha256: None,
        }],
    }
}

struct ParsedSource {
    import_path: String,
    path: String,
    source: String,
    tree: Tree,
}

fn produce_go_facts<'a>(
    packages: &[DiscoveredGoPackage],
    import_names: &HashMap<String, String>,
    entries: impl IntoIterator<Item = (&'a str, &'a [u8])>,
    limits: &ArtifactProducerLimits,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut BoundedProducerDiagnostics,
) -> Option<(Vec<TypeFact>, Vec<MemberFact>)> {
    let entries = entries.into_iter().collect::<HashMap<_, _>>();
    let mut parsed_sources = Vec::new();
    for package in packages {
        for path in &package.files {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                diagnostics.error(
                    "artifact.cancelled",
                    Some(path.clone()),
                    "Go dependency production was cancelled",
                );
                return None;
            }
            let Some(bytes) = entries.get(path.as_str()) else {
                diagnostics.error(
                    "go.source_missing",
                    Some(path.clone()),
                    "selected Go source was not retained in the exact artifact",
                );
                continue;
            };
            let Ok(source) = std::str::from_utf8(bytes) else {
                diagnostics.error(
                    "go.source_encoding",
                    Some(path.clone()),
                    "selected Go source is not valid UTF-8",
                );
                continue;
            };
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_go::LANGUAGE.into())
                .expect("tree-sitter Go language must load");
            let tree = if let Some(cancellation) = cancellation {
                let mut read = |offset: usize, _| &source.as_bytes()[offset..];
                let mut progress = |_: &tree_sitter::ParseState| cancellation.is_cancelled();
                parser.parse_with_options(
                    &mut read,
                    None,
                    Some(tree_sitter::ParseOptions::new().progress_callback(&mut progress)),
                )
            } else {
                parser.parse(source, None)
            };
            let Some(tree) = tree else {
                if cancellation.is_some_and(CancellationToken::is_cancelled) {
                    diagnostics.error(
                        "artifact.cancelled",
                        Some(path.clone()),
                        "Go dependency production was cancelled",
                    );
                    return None;
                }
                diagnostics.error(
                    "go.source_parse",
                    Some(path.clone()),
                    "selected Go source could not be parsed",
                );
                continue;
            };
            if tree.root_node().has_error() {
                diagnostics.error(
                    "go.source_parse",
                    Some(path.clone()),
                    "selected Go source contains malformed or unsupported syntax",
                );
                continue;
            }
            if has_go_generated_directive(tree.root_node(), source) {
                diagnostics.warning(
                    "go.generated_surface",
                    Some(path.clone()),
                    "selected Go source is generated; exported coverage is retained but explicitly partial",
                );
            }
            let declared_name = determine_go_package_name(tree.root_node(), source);
            if !package.name.is_empty() && declared_name != package.name {
                diagnostics.error(
                    "go.package_name_mismatch",
                    Some(path.clone()),
                    format!(
                        "selected Go package {} declared package {declared_name:?}, expected {:?}",
                        package.import_path, package.name
                    ),
                );
                continue;
            }
            parsed_sources.push(ParsedSource {
                import_path: package.import_path.clone(),
                path: path.clone(),
                source: source.to_owned(),
                tree,
            });
        }
    }
    parsed_sources.sort_by(|left, right| {
        (&left.import_path, &left.path).cmp(&(&right.import_path, &right.path))
    });
    let type_ids = collect_type_ids(&parsed_sources);
    let mut package_names = import_names.clone();
    package_names.extend(
        packages
            .iter()
            .filter(|package| !package.name.is_empty())
            .map(|package| (package.import_path.clone(), package.name.clone())),
    );
    let mut type_drafts = module_type_drafts(packages, &parsed_sources);
    if type_drafts.len() > limits.max_records {
        type_drafts.truncate(limits.max_records);
        diagnostics.warning(
            "limit.records",
            None,
            format!(
                "Go producer retained at most {} type drafts before surface filtering",
                limits.max_records
            ),
        );
    }
    let mut member_drafts = Vec::new();
    for parsed in &parsed_sources {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            diagnostics.error(
                "artifact.cancelled",
                Some(parsed.path.clone()),
                "Go dependency production was cancelled",
            );
            return None;
        }
        collect_source_drafts(
            parsed,
            &package_names,
            &type_ids,
            limits,
            diagnostics,
            &mut type_drafts,
            &mut member_drafts,
        );
    }
    augment_go_api_surface(&mut type_drafts, &mut member_drafts, limits, diagnostics);
    Some(finish_facts(
        type_drafts,
        member_drafts,
        limits,
        diagnostics,
    ))
}

fn has_go_generated_directive(root: Node<'_>, source: &str) -> bool {
    let mut generated = false;
    walk_named_tree_preorder(root, true, |node| {
        if node.kind() == "comment" {
            let comment = go_node_text(node, source).trim();
            if comment.starts_with("// Code generated ") && comment.ends_with(" DO NOT EDIT.") {
                generated = true;
                return WalkControl::Break;
            }
        }
        WalkControl::Continue
    });
    generated
}

fn interface_has_explicit_type_terms(root: Node<'_>) -> bool {
    let mut has_type_terms = false;
    walk_named_tree_preorder(root, true, |node| {
        if matches!(node.kind(), "negated_type" | "union_type") {
            has_type_terms = true;
            return WalkControl::Break;
        }
        WalkControl::Continue
    });
    has_type_terms
}

fn augment_go_api_surface(
    types: &mut [TypeDraft],
    members: &mut Vec<MemberDraft>,
    limits: &ArtifactProducerLimits,
    diagnostics: &mut BoundedProducerDiagnostics,
) {
    let type_index = types
        .iter()
        .enumerate()
        .map(|(index, draft)| (draft.fact.id.clone(), index))
        .collect::<HashMap<_, _>>();
    let direct_members = members.iter().cloned().fold(
        HashMap::<String, Vec<MemberDraft>>::default(),
        |mut by_owner, member| {
            by_owner
                .entry(member.fact.owner.clone())
                .or_default()
                .push(member);
            by_owner
        },
    );

    for draft in types.iter_mut().filter(|draft| draft.exported) {
        if draft.fact.type_kind != TypeKind::Interface {
            continue;
        }
        draft
            .fact
            .hierarchy
            .extend(
                draft
                    .fact
                    .embedded_types
                    .iter()
                    .map(|embedded| HierarchyFact {
                        hierarchy_kind: HierarchyKind::UsesTrait,
                        target: embedded.target.clone(),
                        declaration_ordinal: None,
                    }),
            );
    }

    const MAX_GO_PROMOTION_TRAVERSAL_STEPS: usize = 2_000_000;
    let exported_type_ids = types
        .iter()
        .filter(|draft| draft.exported)
        .map(|draft| draft.fact.id.clone())
        .collect::<Vec<_>>();
    let mut traversal_steps = 0usize;
    'owners: for owner_id in exported_type_ids {
        if members.len() >= limits.max_records {
            diagnostics.warning(
                "limit.records",
                None,
                format!(
                    "Go producer retained at most {} member drafts before surface filtering",
                    limits.max_records
                ),
            );
            break;
        }
        let Some(owner_index) = type_index.get(&owner_id).copied() else {
            continue;
        };
        let direct_names = direct_members
            .get(&owner_id)
            .into_iter()
            .flatten()
            .map(|member| member.fact.name.clone())
            .collect::<HashSet<_>>();
        let mut resolved_names = direct_names;
        let mut current = HashMap::<(String, bool), u8>::default();
        for embedded in &types[owner_index].fact.embedded_types {
            if let Some(target) = declared_type_id(&embedded.target) {
                current
                    .entry((target.to_owned(), embedded.pointer))
                    .and_modify(|count| *count = 2)
                    .or_insert(1);
            }
        }
        let mut seen_depth = HashMap::<(String, bool), usize>::default();
        seen_depth.insert((owner_id.clone(), false), 0);
        let mut depth = 1usize;
        while !current.is_empty() {
            let mut candidates = HashMap::<String, (Option<MemberDraft>, u8)>::default();
            let mut next = HashMap::<(String, bool), u8>::default();
            for ((type_id, pointer_available), multiplicity) in current {
                traversal_steps = traversal_steps.saturating_add(1);
                if traversal_steps > MAX_GO_PROMOTION_TRAVERSAL_STEPS {
                    diagnostics.warning(
                        "go.promotion_relation_limit",
                        None,
                        format!(
                            "Go promotion discovery exceeded {MAX_GO_PROMOTION_TRAVERSAL_STEPS} traversal steps"
                        ),
                    );
                    break 'owners;
                }
                if let Some(type_members) = direct_members.get(&type_id) {
                    for member in type_members.iter().filter(|member| {
                        member.fact.visibility == Visibility::Public
                            && !resolved_names.contains(&member.fact.name)
                    }) {
                        let mut promoted = member.clone();
                        if promoted
                            .fact
                            .receiver
                            .is_some_and(|receiver| receiver.pointer)
                            && pointer_available
                        {
                            promoted.fact.receiver = Some(ReceiverFact { pointer: false });
                        }
                        let entry = candidates
                            .entry(promoted.fact.name.clone())
                            .or_insert((None, 0));
                        entry.1 = entry.1.saturating_add(multiplicity).min(2);
                        if entry.1 == 1 {
                            entry.0 = Some(promoted);
                        } else {
                            entry.0 = None;
                        }
                    }
                }
                if let Some(type_index) = type_index.get(&type_id).copied() {
                    for embedded in &types[type_index].fact.embedded_types {
                        if let Some(target) = declared_type_id(&embedded.target) {
                            let state = (target.to_owned(), pointer_available || embedded.pointer);
                            match seen_depth.get(&state).copied() {
                                Some(previous) if previous < depth + 1 => continue,
                                Some(_) => {}
                                None => {
                                    seen_depth.insert(state.clone(), depth + 1);
                                }
                            }
                            next.entry(state)
                                .and_modify(|count| {
                                    *count = count.saturating_add(multiplicity).min(2)
                                })
                                .or_insert(multiplicity);
                        }
                    }
                }
            }
            let mut names = candidates.into_iter().collect::<Vec<_>>();
            names.sort_by(|left, right| left.0.cmp(&right.0));
            for (name, (promoted, multiplicity)) in names {
                resolved_names.insert(name);
                if multiplicity != 1 {
                    continue;
                }
                let mut promoted = promoted.expect("unique promoted member has a candidate");
                promoted.fact.owner = owner_id.clone();
                promoted.fact.id = member_declaration_id(MemberIdentity {
                    owner_id: &owner_id,
                    kind: promoted.fact.member_kind,
                    is_static: promoted.fact.is_static,
                    parameter_arity: promoted
                        .fact
                        .signature
                        .as_ref()
                        .map_or(0, |signature| signature.parameters.len()),
                    name: &promoted.fact.name,
                    generic_arity: promoted
                        .fact
                        .signature
                        .as_ref()
                        .map_or(0, |signature| signature.type_parameters.len()),
                    parameter_types: &promoted
                        .fact
                        .signature
                        .as_ref()
                        .map(|signature| {
                            signature
                                .parameters
                                .iter()
                                .map(|parameter| parameter.r#type.clone())
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default(),
                    parameter_variadics: &[],
                    return_type: promoted
                        .fact
                        .signature
                        .as_ref()
                        .and_then(|signature| signature.returns.as_ref()),
                });
                members.push(promoted);
                if members.len() >= limits.max_records {
                    break;
                }
            }
            current = next;
            depth += 1;
        }
    }

    add_go_interface_relations(types, members, diagnostics);
}

fn add_go_interface_relations(
    types: &mut [TypeDraft],
    members: &[MemberDraft],
    diagnostics: &mut BoundedProducerDiagnostics,
) {
    const MAX_STRUCTURAL_SATISFACTION_PAIRS: usize = 2_000_000;

    let methods_by_owner = members
        .iter()
        .filter(|member| {
            member.fact.member_kind == MemberKind::Method
                && member.fact.visibility == Visibility::Public
                && member.surface
        })
        .fold(
            HashMap::<String, Vec<&MemberFact>>::default(),
            |mut grouped, member| {
                grouped
                    .entry(member.fact.owner.clone())
                    .or_default()
                    .push(&member.fact);
                grouped
            },
        );
    let interfaces = types
        .iter()
        .enumerate()
        .filter(|(_, draft)| draft.exported && draft.fact.type_kind == TypeKind::Interface)
        .filter_map(|(index, draft)| {
            if draft.fact.has_explicit_type_terms {
                return None;
            }
            let methods = methods_by_owner.get(&draft.fact.id)?;
            (!methods.is_empty()).then_some((index, methods.as_slice()))
        })
        .collect::<Vec<_>>();
    let candidates = types
        .iter()
        .enumerate()
        .filter(|(_, draft)| {
            draft.exported
                && !matches!(draft.fact.type_kind, TypeKind::Module | TypeKind::TypeAlias)
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if interfaces.len().saturating_mul(candidates.len()) > MAX_STRUCTURAL_SATISFACTION_PAIRS {
        diagnostics.warning(
            "go.interface_relation_limit",
            None,
            format!(
                "Go structural interface discovery exceeded {MAX_STRUCTURAL_SATISFACTION_PAIRS} candidate pairs"
            ),
        );
        return;
    }
    let mut relations = Vec::new();
    for candidate_index in candidates {
        let candidate = &types[candidate_index];
        let candidate_methods = methods_by_owner
            .get(&candidate.fact.id)
            .map(Vec::as_slice)
            .unwrap_or_default();
        for (interface_index, required_methods) in &interfaces {
            if candidate_index == *interface_index
                || !required_methods.iter().all(|required| {
                    candidate_methods.iter().any(|candidate| {
                        !candidate.receiver.is_some_and(|receiver| receiver.pointer)
                            && go_method_signatures_match(candidate, required)
                    })
                })
            {
                continue;
            }
            relations.push((candidate_index, types[*interface_index].fact.id.clone()));
        }
    }
    for (candidate_index, interface_id) in relations {
        types[candidate_index].fact.hierarchy.push(HierarchyFact {
            hierarchy_kind: HierarchyKind::Implements,
            target: TypeRef::Declared {
                id: interface_id,
                arguments: Vec::new(),
                nullable: false,
            },
            declaration_ordinal: None,
        });
    }
}

fn go_method_signatures_match(candidate: &MemberFact, required: &MemberFact) -> bool {
    if candidate.name != required.name {
        return false;
    }
    match (&candidate.signature, &required.signature) {
        (Some(candidate), Some(required)) => {
            candidate.type_parameters.len() == required.type_parameters.len()
                && candidate.parameters.len() == required.parameters.len()
                && candidate.parameters.iter().zip(&required.parameters).all(
                    |(candidate, required)| {
                        candidate.r#type == required.r#type
                            && candidate.variadic == required.variadic
                    },
                )
                && candidate.returns == required.returns
        }
        (None, None) => true,
        _ => false,
    }
}

fn declared_type_id(reference: &TypeRef) -> Option<&str> {
    match reference {
        TypeRef::Declared { id, .. } => Some(id),
        TypeRef::Pointer { element } => declared_type_id(element),
        _ => None,
    }
}

fn collect_type_ids(parsed_sources: &[ParsedSource]) -> HashMap<String, String> {
    let mut type_ids = HashMap::default();
    for source in parsed_sources {
        for node in top_level_type_specs(source.tree.root_node()) {
            let Some(name_node) = node.child_by_field_name("name") else {
                continue;
            };
            let name = go_node_text(name_node, &source.source).trim();
            if name.is_empty() {
                continue;
            }
            let fq_name = format!("{}.{}", source.import_path, name);
            type_ids.entry(fq_name.clone()).or_insert_with(|| {
                type_declaration_id(TypeIdentity {
                    ecosystem: "go",
                    name: &fq_name,
                })
            });
        }
    }
    type_ids
}

fn top_level_type_specs(root: Node<'_>) -> Vec<Node<'_>> {
    let mut specs = Vec::new();
    let mut cursor = root.walk();
    for declaration in root.named_children(&mut cursor) {
        if declaration.kind() != "type_declaration" {
            continue;
        }
        walk_named_tree_preorder(declaration, false, |node| {
            if matches!(node.kind(), "type_spec" | "type_alias") {
                specs.push(node);
                WalkControl::SkipChildren
            } else {
                WalkControl::Continue
            }
        });
    }
    specs
}

#[derive(Clone)]
struct TypeDraft {
    fact: TypeFact,
    exported: bool,
    scaffold: bool,
    referenced_type_ids: Vec<String>,
}

#[derive(Clone)]
struct MemberDraft {
    fact: MemberFact,
    surface: bool,
    referenced_type_ids: Vec<String>,
}

fn module_type_drafts(
    packages: &[DiscoveredGoPackage],
    parsed_sources: &[ParsedSource],
) -> Vec<TypeDraft> {
    packages
        .iter()
        .flat_map(|package| {
            let path = parsed_sources
                .iter()
                .find(|source| source.import_path == package.import_path)
                .map(|source| source.path.clone())
                .unwrap_or_else(|| package.directory.clone());
            [
                package.import_path.clone(),
                format!("{}.{}", package.import_path, GO_MODULE_SCOPE_SEGMENT),
            ]
            .into_iter()
            .map(move |name| {
                let aliases = (name == package.import_path && !package.name.is_empty())
                    .then(|| package.name.clone())
                    .into_iter()
                    .collect();
                TypeDraft {
                    fact: TypeFact {
                        id: type_declaration_id(TypeIdentity {
                            ecosystem: "go",
                            name: &name,
                        }),
                        name: name.clone(),
                        type_kind: TypeKind::Module,
                        visibility: Visibility::Package,
                        is_abstract: false,
                        is_sealed: false,
                        has_explicit_type_terms: false,
                        type_parameters: Vec::new(),
                        type_parameter_constraints: Vec::new(),
                        underlying_type: None,
                        embedded_types: Vec::new(),
                        hierarchy: Vec::new(),
                        aliases,
                        extension_surfaces: Vec::new(),
                        locator: artifact_locator(&path, &name),
                    },
                    exported: false,
                    scaffold: true,
                    referenced_type_ids: Vec::new(),
                }
            })
        })
        .collect()
}

fn collect_source_drafts(
    parsed: &ParsedSource,
    package_names: &HashMap<String, String>,
    type_ids: &HashMap<String, String>,
    limits: &ArtifactProducerLimits,
    diagnostics: &mut BoundedProducerDiagnostics,
    types: &mut Vec<TypeDraft>,
    members: &mut Vec<MemberDraft>,
) {
    let imports = import_bindings(parsed.tree.root_node(), &parsed.source, package_names);
    let mut cursor = parsed.tree.root_node().walk();
    for declaration in parsed.tree.root_node().named_children(&mut cursor) {
        match declaration.kind() {
            "type_declaration" => {
                for spec in top_level_specs(declaration) {
                    collect_type_draft(
                        parsed,
                        spec,
                        &imports,
                        type_ids,
                        limits,
                        diagnostics,
                        types,
                        members,
                    );
                }
            }
            "function_declaration" => collect_callable_draft(
                parsed,
                declaration,
                &imports,
                type_ids,
                limits,
                diagnostics,
                None,
                false,
                &[],
                members,
            ),
            "method_declaration" => {
                let Some((receiver_name, pointer, receiver_type_parameters)) =
                    method_receiver(declaration, &parsed.source)
                else {
                    diagnostics.warning(
                        "go.receiver_unsupported",
                        Some(parsed.path.clone()),
                        "Go method receiver could not be resolved to a named type",
                    );
                    continue;
                };
                collect_callable_draft(
                    parsed,
                    declaration,
                    &imports,
                    type_ids,
                    limits,
                    diagnostics,
                    Some(receiver_name),
                    pointer,
                    &receiver_type_parameters,
                    members,
                );
            }
            "var_declaration" => collect_value_drafts(
                parsed,
                declaration,
                MemberKind::Field,
                &imports,
                type_ids,
                limits,
                diagnostics,
                members,
            ),
            "const_declaration" => collect_value_drafts(
                parsed,
                declaration,
                MemberKind::Constant,
                &imports,
                type_ids,
                limits,
                diagnostics,
                members,
            ),
            _ => {}
        }
    }
}

fn import_bindings(
    root: Node<'_>,
    source: &str,
    package_names: &HashMap<String, String>,
) -> HashMap<String, String> {
    collect_go_import_infos(root, source)
        .into_iter()
        .filter_map(|info| {
            let path = info.path.as_ref()?.render_segments("/");
            if path.is_empty() {
                return None;
            }
            let local = info
                .alias
                .or_else(|| package_names.get(&path).cloned())
                .or(info.identifier)?;
            (!matches!(local.as_str(), "_" | ".")).then_some((local, path))
        })
        .collect()
}

fn top_level_specs(declaration: Node<'_>) -> Vec<Node<'_>> {
    let mut specs = Vec::new();
    walk_named_tree_preorder(declaration, false, |node| {
        if matches!(node.kind(), "type_spec" | "type_alias") {
            specs.push(node);
            WalkControl::SkipChildren
        } else {
            WalkControl::Continue
        }
    });
    specs
}

#[allow(clippy::too_many_arguments)]
fn collect_type_draft(
    parsed: &ParsedSource,
    node: Node<'_>,
    imports: &HashMap<String, String>,
    type_ids: &HashMap<String, String>,
    limits: &ArtifactProducerLimits,
    diagnostics: &mut BoundedProducerDiagnostics,
    types: &mut Vec<TypeDraft>,
    members: &mut Vec<MemberDraft>,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let name = go_node_text(name_node, &parsed.source).trim();
    let Some(type_node) = node.child_by_field_name("type") else {
        diagnostics.warning(
            "go.type_unsupported",
            Some(parsed.path.clone()),
            format!("Go type {name} has no structured type node"),
        );
        return;
    };
    let canonical_name = format!("{}.{}", parsed.import_path, name);
    let Some(type_id) = type_ids.get(&canonical_name).cloned() else {
        return;
    };
    let alias_name = format!(
        "{}.{}.{}",
        parsed.import_path, GO_MODULE_SCOPE_SEGMENT, name
    );
    let (type_parameters, type_parameter_constraints) = type_parameters(
        node,
        &parsed.source,
        &parsed.import_path,
        imports,
        type_ids,
        limits,
        diagnostics,
        &parsed.path,
    );
    let type_parameter_names = type_parameters.iter().cloned().collect::<HashSet<_>>();
    let context = TypeContext {
        package: &parsed.import_path,
        imports,
        type_ids,
        type_parameters: &type_parameter_names,
    };
    let underlying_type = structured_expression(
        type_node,
        &parsed.source,
        &context,
        limits,
        diagnostics,
        &parsed.path,
    );
    let embedded_types = super::declarations::go_embedded_type_nodes(type_node)
        .into_iter()
        .filter_map(|embedded| {
            let target = nominal_type_ref(embedded, &parsed.source, &context)?;
            Some(EmbeddedTypeFact {
                target,
                pointer: embedded_type_is_pointer(embedded),
            })
        })
        .collect::<Vec<_>>();
    let mut referenced_type_ids = underlying_type
        .as_ref()
        .map(|expression| declared_type_ids(&expression.referenced_types))
        .unwrap_or_default();
    referenced_type_ids.extend(declared_type_ids(
        &type_parameter_constraints
            .iter()
            .flat_map(|constraint| constraint.constraint.referenced_types.iter().cloned())
            .collect::<Vec<_>>(),
    ));
    referenced_type_ids.extend(declared_type_ids(
        &embedded_types
            .iter()
            .map(|embedded| embedded.target.clone())
            .collect::<Vec<_>>(),
    ));
    referenced_type_ids.sort();
    referenced_type_ids.dedup();
    let type_kind = match (node.kind(), type_node.kind()) {
        ("type_alias", _) => TypeKind::TypeAlias,
        (_, "struct_type") => TypeKind::Struct,
        (_, "interface_type") => TypeKind::Interface,
        _ => TypeKind::Class,
    };
    let exported = go_name_is_exported(name);
    if types.len() >= limits.max_records {
        diagnostics.warning(
            "limit.records",
            Some(parsed.path.clone()),
            format!(
                "Go producer retained at most {} type drafts before surface filtering",
                limits.max_records
            ),
        );
        return;
    }
    types.push(TypeDraft {
        fact: TypeFact {
            id: type_id.clone(),
            name: canonical_name.clone(),
            type_kind,
            visibility: if exported {
                Visibility::Public
            } else {
                Visibility::Private
            },
            is_abstract: type_kind == TypeKind::Interface,
            is_sealed: false,
            has_explicit_type_terms: type_kind == TypeKind::Interface
                && interface_has_explicit_type_terms(type_node),
            type_parameters,
            type_parameter_constraints,
            underlying_type,
            embedded_types,
            hierarchy: Vec::<HierarchyFact>::new(),
            aliases: (type_kind == TypeKind::TypeAlias)
                .then_some(alias_name)
                .into_iter()
                .collect(),
            extension_surfaces: Vec::new(),
            locator: artifact_locator(&parsed.path, &canonical_name),
        },
        exported,
        scaffold: false,
        referenced_type_ids,
    });
    match type_node.kind() {
        "struct_type" => collect_struct_members(
            parsed,
            type_node,
            &canonical_name,
            &type_id,
            &context,
            limits,
            diagnostics,
            members,
        ),
        "interface_type" => collect_interface_members(
            parsed,
            type_node,
            &canonical_name,
            &type_id,
            &context,
            limits,
            diagnostics,
            members,
        ),
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn collect_struct_members(
    parsed: &ParsedSource,
    node: Node<'_>,
    owner_name: &str,
    owner_id: &str,
    context: &TypeContext<'_>,
    limits: &ArtifactProducerLimits,
    diagnostics: &mut BoundedProducerDiagnostics,
    members: &mut Vec<MemberDraft>,
) {
    let mut cursor = node.walk();
    let Some(fields) = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "field_declaration_list")
    else {
        return;
    };
    let mut cursor = fields.walk();
    for field in fields
        .named_children(&mut cursor)
        .filter(|field| field.kind() == "field_declaration")
    {
        let Some(type_node) = field.child_by_field_name("type") else {
            continue;
        };
        let type_ref = type_ref(
            type_node,
            &parsed.source,
            context,
            limits.max_signature_depth,
        )
        .unwrap_or_else(|| rendered_type_ref(type_node, &parsed.source));
        let mut name_cursor = field.walk();
        let names = field
            .named_children(&mut name_cursor)
            .filter(|child| child.kind() == "field_identifier")
            .map(|child| go_node_text(child, &parsed.source).trim().to_owned())
            .collect::<Vec<_>>();
        let names = if names.is_empty() {
            nominal_type_name(type_node, &parsed.source)
                .into_iter()
                .collect()
        } else {
            names
        };
        for name in names {
            let exported = go_name_is_exported(&name);
            push_member(
                owner_id,
                name.clone(),
                MemberKind::Field,
                false,
                false,
                if exported {
                    Visibility::Public
                } else {
                    Visibility::Private
                },
                exported,
                Some(Signature {
                    type_parameters: Vec::new(),
                    parameters: Vec::new(),
                    returns: Some(type_ref.clone()),
                }),
                None,
                artifact_locator(&parsed.path, &format!("{owner_name}.{name}")),
                limits,
                diagnostics,
                members,
            );
        }
        if type_ref_depth(&type_ref) > limits.max_signature_depth {
            diagnostics.warning(
                "limit.signature_depth",
                Some(parsed.path.clone()),
                format!("Go field on {owner_name} exceeded the signature depth limit"),
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn collect_interface_members(
    parsed: &ParsedSource,
    node: Node<'_>,
    owner_name: &str,
    owner_id: &str,
    context: &TypeContext<'_>,
    limits: &ArtifactProducerLimits,
    diagnostics: &mut BoundedProducerDiagnostics,
    members: &mut Vec<MemberDraft>,
) {
    walk_named_tree_preorder(node, false, |candidate| {
        if candidate.kind() != "method_elem" {
            return WalkControl::Continue;
        }
        let Some(name_node) = candidate.child_by_field_name("name") else {
            return WalkControl::SkipChildren;
        };
        let name = go_node_text(name_node, &parsed.source).trim().to_owned();
        let signature = callable_signature(
            candidate,
            &parsed.source,
            context,
            limits,
            diagnostics,
            &parsed.path,
        );
        let exported = go_name_is_exported(&name);
        push_member(
            owner_id,
            name.clone(),
            MemberKind::Method,
            false,
            true,
            if exported {
                Visibility::Public
            } else {
                Visibility::Package
            },
            true,
            Some(signature),
            None,
            artifact_locator(&parsed.path, &format!("{owner_name}.{name}")),
            limits,
            diagnostics,
            members,
        );
        WalkControl::SkipChildren
    });
}

#[allow(clippy::too_many_arguments)]
fn collect_callable_draft(
    parsed: &ParsedSource,
    node: Node<'_>,
    imports: &HashMap<String, String>,
    type_ids: &HashMap<String, String>,
    limits: &ArtifactProducerLimits,
    diagnostics: &mut BoundedProducerDiagnostics,
    receiver_name: Option<String>,
    receiver_pointer: bool,
    receiver_type_parameters: &[String],
    members: &mut Vec<MemberDraft>,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let name = go_node_text(name_node, &parsed.source).trim().to_owned();
    if name.is_empty() {
        return;
    }
    let (owner_name, member_kind, is_static, receiver) = match receiver_name {
        Some(receiver_name) => (
            format!("{}.{}", parsed.import_path, receiver_name),
            MemberKind::Method,
            false,
            Some(ReceiverFact {
                pointer: receiver_pointer,
            }),
        ),
        None => (parsed.import_path.clone(), MemberKind::Function, true, None),
    };
    let owner_id = type_declaration_id(TypeIdentity {
        ecosystem: "go",
        name: &owner_name,
    });
    if member_kind == MemberKind::Method && !type_ids.contains_key(&owner_name) {
        diagnostics.warning(
            "go.receiver_owner_missing",
            Some(parsed.path.clone()),
            format!("Go method {} has no selected receiver type", name),
        );
        return;
    }
    let callable_type_parameters = type_parameter_names(node, &parsed.source);
    let type_parameters = callable_type_parameters
        .iter()
        .chain(receiver_type_parameters)
        .cloned()
        .collect::<HashSet<_>>();
    let context = TypeContext {
        package: &parsed.import_path,
        imports,
        type_ids,
        type_parameters: &type_parameters,
    };
    let signature = callable_signature(
        node,
        &parsed.source,
        &context,
        limits,
        diagnostics,
        &parsed.path,
    );
    let exported = go_name_is_exported(&name);
    push_member(
        &owner_id,
        name.clone(),
        member_kind,
        is_static,
        false,
        if exported {
            Visibility::Public
        } else {
            Visibility::Private
        },
        exported,
        Some(signature),
        receiver,
        artifact_locator(&parsed.path, &format!("{owner_name}.{name}")),
        limits,
        diagnostics,
        members,
    );
}

#[allow(clippy::too_many_arguments)]
fn collect_value_drafts(
    parsed: &ParsedSource,
    declaration: Node<'_>,
    member_kind: MemberKind,
    imports: &HashMap<String, String>,
    type_ids: &HashMap<String, String>,
    limits: &ArtifactProducerLimits,
    diagnostics: &mut BoundedProducerDiagnostics,
    members: &mut Vec<MemberDraft>,
) {
    let spec_kind = if member_kind == MemberKind::Constant {
        "const_spec"
    } else {
        "var_spec"
    };
    let owner_name = format!("{}.{}", parsed.import_path, GO_MODULE_SCOPE_SEGMENT);
    let owner_id = type_declaration_id(TypeIdentity {
        ecosystem: "go",
        name: &owner_name,
    });
    let type_parameters = HashSet::default();
    let context = TypeContext {
        package: &parsed.import_path,
        imports,
        type_ids,
        type_parameters: &type_parameters,
    };
    walk_named_tree_preorder(declaration, false, |spec| {
        if spec.kind() != spec_kind {
            return WalkControl::Continue;
        }
        let signature = spec.child_by_field_name("type").map(|type_node| Signature {
            type_parameters: Vec::new(),
            parameters: Vec::new(),
            returns: Some(
                type_ref(
                    type_node,
                    &parsed.source,
                    &context,
                    limits.max_signature_depth,
                )
                .unwrap_or_else(|| rendered_type_ref(type_node, &parsed.source)),
            ),
        });
        let mut cursor = spec.walk();
        for name_node in spec
            .named_children(&mut cursor)
            .filter(|child| child.kind() == "identifier")
        {
            let name = go_node_text(name_node, &parsed.source).trim().to_owned();
            if name.is_empty() {
                continue;
            }
            let exported = go_name_is_exported(&name);
            push_member(
                &owner_id,
                name.clone(),
                member_kind,
                true,
                false,
                if exported {
                    Visibility::Public
                } else {
                    Visibility::Private
                },
                exported,
                signature.clone(),
                None,
                artifact_locator(&parsed.path, &format!("{owner_name}.{name}")),
                limits,
                diagnostics,
                members,
            );
        }
        WalkControl::SkipChildren
    });
}

#[allow(clippy::too_many_arguments)]
fn push_member(
    owner_id: &str,
    name: String,
    member_kind: MemberKind,
    is_static: bool,
    is_abstract: bool,
    visibility: Visibility,
    surface: bool,
    signature: Option<Signature>,
    receiver: Option<ReceiverFact>,
    locator: Locator,
    limits: &ArtifactProducerLimits,
    diagnostics: &mut BoundedProducerDiagnostics,
    members: &mut Vec<MemberDraft>,
) {
    if members.len() >= limits.max_records {
        diagnostics.warning(
            "limit.records",
            None,
            format!(
                "Go producer retained at most {} member drafts before surface filtering",
                limits.max_records
            ),
        );
        return;
    }
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
    let return_type = signature
        .as_ref()
        .and_then(|signature| signature.returns.as_ref());
    let generic_arity = signature
        .as_ref()
        .map_or(0, |signature| signature.type_parameters.len());
    let id = member_declaration_id(MemberIdentity {
        owner_id,
        kind: member_kind,
        is_static,
        parameter_arity: parameter_types.len(),
        name: &name,
        generic_arity,
        parameter_types: &parameter_types,
        parameter_variadics: &[],
        return_type,
    });
    let referenced_type_ids = signature
        .as_ref()
        .map(|signature| {
            let mut refs = signature
                .parameters
                .iter()
                .map(|parameter| parameter.r#type.clone())
                .collect::<Vec<_>>();
            refs.extend(signature.returns.clone());
            declared_type_ids(&refs)
        })
        .unwrap_or_default();
    members.push(MemberDraft {
        fact: MemberFact {
            id,
            owner: owner_id.to_owned(),
            name,
            member_kind,
            visibility,
            is_static,
            is_abstract,
            is_virtual: is_abstract,
            signature,
            receiver,
            extension_receiver: None,
            extension_receiver_constraints: Vec::new(),
            aliases: Vec::new(),
            locator,
        },
        surface,
        referenced_type_ids,
    });
}

fn callable_signature(
    node: Node<'_>,
    source: &str,
    context: &TypeContext<'_>,
    limits: &ArtifactProducerLimits,
    diagnostics: &mut BoundedProducerDiagnostics,
    path: &str,
) -> Signature {
    let type_parameters = type_parameter_names(node, source);
    let parameters = node
        .child_by_field_name("parameters")
        .map(|parameters| {
            callable_parameters(parameters, source, context, limits, diagnostics, path)
        })
        .unwrap_or_default();
    let returns = node.child_by_field_name("result").and_then(|result| {
        if result.kind() == "parameter_list" {
            let results = callable_parameters(result, source, context, limits, diagnostics, path)
                .into_iter()
                .map(|parameter| parameter.r#type)
                .collect::<Vec<_>>();
            match results.len() {
                0 => None,
                1 => results.into_iter().next(),
                _ => Some(TypeRef::Tuple { elements: results }),
            }
        } else {
            type_ref(result, source, context, limits.max_signature_depth).or_else(|| {
                diagnostics.warning(
                    "go.signature_type_unsupported",
                    Some(path.to_owned()),
                    format!(
                        "unsupported Go result type {}",
                        go_node_text(result, source).trim()
                    ),
                );
                Some(rendered_type_ref(result, source))
            })
        }
    });
    Signature {
        type_parameters,
        parameters,
        returns,
    }
}

fn callable_parameters(
    parameters: Node<'_>,
    source: &str,
    context: &TypeContext<'_>,
    limits: &ArtifactProducerLimits,
    diagnostics: &mut BoundedProducerDiagnostics,
    path: &str,
) -> Vec<Parameter> {
    let mut result = Vec::new();
    let mut cursor = parameters.walk();
    for parameter in parameters.named_children(&mut cursor) {
        if !matches!(
            parameter.kind(),
            "parameter_declaration" | "variadic_parameter_declaration"
        ) {
            continue;
        }
        let variadic = parameter.kind() == "variadic_parameter_declaration";
        let type_node = parameter.child_by_field_name("type").or_else(|| {
            let mut cursor = parameter.walk();
            parameter.named_children(&mut cursor).last()
        });
        let Some(type_node) = type_node else {
            continue;
        };
        let parameter_type = type_ref(type_node, source, context, limits.max_signature_depth)
            .unwrap_or_else(|| {
                diagnostics.warning(
                    "go.signature_type_unsupported",
                    Some(path.to_owned()),
                    format!(
                        "unsupported Go parameter type {}",
                        go_node_text(type_node, source).trim()
                    ),
                );
                rendered_type_ref(type_node, source)
            });
        let mut name_cursor = parameter.walk();
        let names = parameter
            .named_children(&mut name_cursor)
            .filter(|child| child.kind() == "identifier" && child.id() != type_node.id())
            .map(|child| go_node_text(child, source).trim().to_owned())
            .collect::<Vec<_>>();
        if names.is_empty() {
            result.push(Parameter {
                name: None,
                r#type: parameter_type,
                optional: false,
                variadic,
            });
        } else {
            result.extend(names.into_iter().map(|name| Parameter {
                name: Some(name),
                r#type: parameter_type.clone(),
                optional: false,
                variadic,
            }));
        }
    }
    result
}

struct TypeContext<'a> {
    package: &'a str,
    imports: &'a HashMap<String, String>,
    type_ids: &'a HashMap<String, String>,
    type_parameters: &'a HashSet<String>,
}

#[allow(clippy::too_many_arguments)]
fn type_parameters(
    node: Node<'_>,
    source: &str,
    package: &str,
    imports: &HashMap<String, String>,
    type_ids: &HashMap<String, String>,
    limits: &ArtifactProducerLimits,
    diagnostics: &mut BoundedProducerDiagnostics,
    path: &str,
) -> (Vec<String>, Vec<TypeParameterConstraint>) {
    let names = type_parameter_names(node, source);
    let name_set = names.iter().cloned().collect::<HashSet<_>>();
    let context = TypeContext {
        package,
        imports,
        type_ids,
        type_parameters: &name_set,
    };
    let Some(list) = type_parameter_list(node) else {
        return (names, Vec::new());
    };
    let mut constraints = Vec::new();
    let mut cursor = list.walk();
    for declaration in list
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "type_parameter_declaration")
    {
        let Some(constraint_node) = declaration.child_by_field_name("type").or_else(|| {
            let mut cursor = declaration.walk();
            declaration.named_children(&mut cursor).last()
        }) else {
            continue;
        };
        let mut cursor = declaration.walk();
        let parameter_names = declaration
            .named_children(&mut cursor)
            .filter(|child| child.kind() == "identifier" && child.id() != constraint_node.id())
            .map(|child| go_node_text(child, source).trim().to_owned())
            .collect::<Vec<_>>();
        let Some(constraint) =
            structured_expression(constraint_node, source, &context, limits, diagnostics, path)
        else {
            continue;
        };
        constraints.extend(
            parameter_names
                .into_iter()
                .map(|parameter| TypeParameterConstraint {
                    parameter,
                    constraint: constraint.clone(),
                }),
        );
    }
    (names, constraints)
}

fn type_parameter_names(node: Node<'_>, source: &str) -> Vec<String> {
    let Some(list) = type_parameter_list(node) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    let mut cursor = list.walk();
    for declaration in list
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "type_parameter_declaration")
    {
        let constraint = declaration.child_by_field_name("type");
        let mut cursor = declaration.walk();
        names.extend(
            declaration
                .named_children(&mut cursor)
                .filter(|child| {
                    child.kind() == "identifier"
                        && constraint.is_none_or(|constraint| child.id() != constraint.id())
                })
                .map(|child| go_node_text(child, source).trim().to_owned())
                .filter(|name| !name.is_empty()),
        );
    }
    names
}

fn type_parameter_list(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("type_parameters").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .find(|child| child.kind() == "type_parameter_list")
    })
}

fn structured_expression(
    node: Node<'_>,
    source: &str,
    context: &TypeContext<'_>,
    limits: &ArtifactProducerLimits,
    diagnostics: &mut BoundedProducerDiagnostics,
    path: &str,
) -> Option<StructuredTypeExpression> {
    let display = go_node_text(node, source).trim().to_owned();
    if display.is_empty() {
        return None;
    }
    if go_structured_type_identity(node, source).is_none()
        && !matches!(
            node.kind(),
            "struct_type"
                | "interface_type"
                | "function_type"
                | "channel_type"
                | "type_constraint"
                | "type_elem"
                | "union_type"
        )
    {
        diagnostics.warning(
            "go.type_expression_partial",
            Some(path.to_owned()),
            format!("Go type expression {display} is retained only as rendered AST text"),
        );
    }
    let referenced_types = referenced_type_refs(node, source, context, limits.max_signature_depth);
    Some(StructuredTypeExpression {
        display,
        referenced_types,
    })
}

enum TypeFrame<'tree> {
    Visit(Node<'tree>, usize),
    Pointer,
    Slice,
    FixedArray {
        length: String,
    },
    Map,
    Channel {
        direction: ChannelDirection,
    },
    Generic {
        argument_count: usize,
    },
    Function {
        parameters: Vec<(Option<String>, bool)>,
        result_count: usize,
    },
}

fn type_ref(
    node: Node<'_>,
    source: &str,
    context: &TypeContext<'_>,
    max_depth: usize,
) -> Option<TypeRef> {
    let mut frames = vec![TypeFrame::Visit(node, 0)];
    let mut values = Vec::new();
    while let Some(frame) = frames.pop() {
        match frame {
            TypeFrame::Visit(node, depth) => {
                if depth > max_depth {
                    return None;
                }
                match node.kind() {
                    "type_identifier" | "identifier" => {
                        let name = go_node_text(node, source).trim();
                        values.push(resolve_nominal(&[name], context)?);
                    }
                    "qualified_type" => {
                        let package = node.child_by_field_name("package")?;
                        let name = node.child_by_field_name("name")?;
                        values.push(resolve_nominal(
                            &[
                                go_node_text(package, source).trim(),
                                go_node_text(name, source).trim(),
                            ],
                            context,
                        )?);
                    }
                    "pointer_type" => {
                        frames.push(TypeFrame::Pointer);
                        frames.push(TypeFrame::Visit(wrapper_type_child(node)?, depth + 1));
                    }
                    "array_type" | "implicit_length_array_type" => {
                        let length = node
                            .child_by_field_name("length")
                            .map(|length| go_node_text(length, source).trim().to_owned())
                            .filter(|length| !length.is_empty())
                            .unwrap_or_else(|| "...".to_owned());
                        frames.push(TypeFrame::FixedArray { length });
                        frames.push(TypeFrame::Visit(
                            node.child_by_field_name("element")
                                .or_else(|| last_named_child(node))?,
                            depth + 1,
                        ));
                    }
                    "slice_type" => {
                        frames.push(TypeFrame::Slice);
                        frames.push(TypeFrame::Visit(
                            node.child_by_field_name("element")
                                .or_else(|| last_named_child(node))?,
                            depth + 1,
                        ));
                    }
                    "map_type" => {
                        let key = node.child_by_field_name("key")?;
                        let value = node.child_by_field_name("value")?;
                        frames.push(TypeFrame::Map);
                        frames.push(TypeFrame::Visit(value, depth + 1));
                        frames.push(TypeFrame::Visit(key, depth + 1));
                    }
                    "channel_type" => {
                        let element = node
                            .child_by_field_name("value")
                            .or_else(|| node.child_by_field_name("type"))
                            .or_else(|| last_named_child(node))?;
                        frames.push(TypeFrame::Channel {
                            direction: channel_direction(node),
                        });
                        frames.push(TypeFrame::Visit(element, depth + 1));
                    }
                    "generic_type" => {
                        let base = node
                            .child_by_field_name("type")
                            .or_else(|| node.child_by_field_name("name"))
                            .or_else(|| node.named_child(0))?;
                        let arguments =
                            node.child_by_field_name("type_arguments").or_else(|| {
                                let mut cursor = node.walk();
                                node.named_children(&mut cursor)
                                    .find(|child| child.kind() == "type_arguments")
                            })?;
                        let mut cursor = arguments.walk();
                        let arguments = arguments.named_children(&mut cursor).collect::<Vec<_>>();
                        frames.push(TypeFrame::Generic {
                            argument_count: arguments.len(),
                        });
                        for argument in arguments.into_iter().rev() {
                            frames.push(TypeFrame::Visit(argument, depth + 1));
                        }
                        frames.push(TypeFrame::Visit(base, depth + 1));
                    }
                    "function_type" => {
                        let (parameter_nodes, parameters) = function_type_parameters(
                            node.child_by_field_name("parameters"),
                            source,
                        );
                        let result_nodes =
                            function_type_results(node.child_by_field_name("result"), source);
                        frames.push(TypeFrame::Function {
                            parameters,
                            result_count: result_nodes.len(),
                        });
                        for result in result_nodes.into_iter().rev() {
                            frames.push(TypeFrame::Visit(result, depth + 1));
                        }
                        for parameter in parameter_nodes.into_iter().rev() {
                            frames.push(TypeFrame::Visit(parameter, depth + 1));
                        }
                    }
                    "parenthesized_type" => {
                        frames.push(TypeFrame::Visit(wrapper_type_child(node)?, depth + 1));
                    }
                    _ => values.push(rendered_type_ref(node, source)),
                }
            }
            TypeFrame::Pointer => {
                let element = values.pop()?;
                values.push(TypeRef::Pointer {
                    element: Box::new(element),
                });
            }
            TypeFrame::Slice => {
                let element = values.pop()?;
                values.push(TypeRef::Slice {
                    element: Box::new(element),
                });
            }
            TypeFrame::FixedArray { length } => {
                let element = values.pop()?;
                values.push(TypeRef::FixedArray {
                    element: Box::new(element),
                    length,
                });
            }
            TypeFrame::Map => {
                let value = values.pop()?;
                let key = values.pop()?;
                values.push(TypeRef::Map {
                    key: Box::new(key),
                    value: Box::new(value),
                });
            }
            TypeFrame::Channel { direction } => {
                let element = values.pop()?;
                values.push(TypeRef::Channel {
                    element: Box::new(element),
                    direction,
                });
            }
            TypeFrame::Generic { argument_count } => {
                if values.len() < argument_count + 1 {
                    return None;
                }
                let arguments = values.split_off(values.len() - argument_count);
                let base = values.pop()?;
                values.push(match base {
                    TypeRef::Named { name, nullable, .. } => TypeRef::Named {
                        name,
                        arguments,
                        nullable,
                    },
                    TypeRef::Declared { id, nullable, .. } => TypeRef::Declared {
                        id,
                        arguments,
                        nullable,
                    },
                    _ => return None,
                });
            }
            TypeFrame::Function {
                parameters,
                result_count,
            } => {
                if values.len() < parameters.len() + result_count {
                    return None;
                }
                let results = values.split_off(values.len() - result_count);
                let parameter_types = values.split_off(values.len() - parameters.len());
                let parameters = parameters
                    .into_iter()
                    .zip(parameter_types)
                    .map(|((name, variadic), r#type)| Parameter {
                        name,
                        r#type,
                        optional: false,
                        variadic,
                    })
                    .collect();
                let result = match results.len() {
                    0 => None,
                    1 => results.into_iter().next().map(Box::new),
                    _ => Some(Box::new(TypeRef::Tuple { elements: results })),
                };
                values.push(TypeRef::Function { parameters, result });
            }
        }
    }
    (values.len() == 1).then(|| values.pop()).flatten()
}

fn function_type_parameters<'tree>(
    parameters: Option<Node<'tree>>,
    source: &str,
) -> (Vec<Node<'tree>>, Vec<(Option<String>, bool)>) {
    let Some(parameters) = parameters else {
        return (Vec::new(), Vec::new());
    };
    let mut type_nodes = Vec::new();
    let mut metadata = Vec::new();
    let mut cursor = parameters.walk();
    for parameter in parameters.named_children(&mut cursor).filter(|parameter| {
        matches!(
            parameter.kind(),
            "parameter_declaration" | "variadic_parameter_declaration"
        )
    }) {
        let Some(type_node) = parameter.child_by_field_name("type").or_else(|| {
            let mut cursor = parameter.walk();
            parameter.named_children(&mut cursor).last()
        }) else {
            continue;
        };
        let variadic = parameter.kind() == "variadic_parameter_declaration";
        let mut name_cursor = parameter.walk();
        let names = parameter
            .named_children(&mut name_cursor)
            .filter(|child| child.kind() == "identifier" && child.id() != type_node.id())
            .map(|child| go_node_text(child, source).trim().to_owned())
            .collect::<Vec<_>>();
        if names.is_empty() {
            type_nodes.push(type_node);
            metadata.push((None, variadic));
        } else {
            for name in names {
                type_nodes.push(type_node);
                metadata.push((Some(name), variadic));
            }
        }
    }
    (type_nodes, metadata)
}

fn function_type_results<'tree>(result: Option<Node<'tree>>, source: &str) -> Vec<Node<'tree>> {
    let Some(result) = result else {
        return Vec::new();
    };
    if result.kind() != "parameter_list" {
        return vec![result];
    }
    function_type_parameters(Some(result), source).0
}

fn resolve_nominal(path: &[&str], context: &TypeContext<'_>) -> Option<TypeRef> {
    let first = *path.first()?;
    if path.len() == 1 && context.type_parameters.contains(first) {
        return Some(TypeRef::TypeParameter {
            name: first.to_owned(),
        });
    }
    let name = if path.len() == 1 {
        if go_builtin_type(first) {
            first.to_owned()
        } else {
            format!("{}.{}", context.package, first)
        }
    } else {
        let package = context
            .imports
            .get(first)
            .map(String::as_str)
            .unwrap_or(first);
        format!("{package}.{}", path[1..].join("."))
    };
    match context.type_ids.get(&name) {
        Some(id) => Some(TypeRef::Declared {
            id: id.clone(),
            arguments: Vec::new(),
            nullable: false,
        }),
        None if path.len() > 1 => Some(TypeRef::Named {
            name,
            arguments: Vec::new(),
            nullable: false,
        }),
        None => Some(TypeRef::Named {
            name,
            arguments: Vec::new(),
            nullable: false,
        }),
    }
}

fn nominal_type_ref(node: Node<'_>, source: &str, context: &TypeContext<'_>) -> Option<TypeRef> {
    let identity = go_structured_type_identity(node, source)?;
    let path = identity.nominal_name()?.path();
    let path = path.iter().map(String::as_str).collect::<Vec<_>>();
    resolve_nominal(&path, context)
}

fn nominal_type_name(node: Node<'_>, source: &str) -> Option<String> {
    go_structured_type_identity(node, source)?
        .nominal_name()?
        .path()
        .last()
        .cloned()
}

fn referenced_type_refs(
    node: Node<'_>,
    source: &str,
    context: &TypeContext<'_>,
    _max_depth: usize,
) -> Vec<TypeRef> {
    let mut references = Vec::new();
    walk_named_tree_preorder(node, true, |candidate| match candidate.kind() {
        "qualified_type" => {
            if let Some(reference) = nominal_type_ref(candidate, source, context)
                && !references.contains(&reference)
            {
                references.push(reference);
            }
            WalkControl::SkipChildren
        }
        "type_identifier" => {
            if let Some(reference) = nominal_type_ref(candidate, source, context)
                && !references.contains(&reference)
            {
                references.push(reference);
            }
            WalkControl::SkipChildren
        }
        _ => WalkControl::Continue,
    });
    references
}

fn rendered_type_ref(node: Node<'_>, source: &str) -> TypeRef {
    TypeRef::Named {
        name: go_node_text(node, source).trim().to_owned(),
        arguments: Vec::new(),
        nullable: false,
    }
}

fn wrapper_type_child(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("type").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor).next()
    })
}

fn last_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).last()
}

fn channel_direction(node: Node<'_>) -> ChannelDirection {
    let arrow_index = (0..node.child_count())
        .find(|index| node.child(*index).is_some_and(|child| child.kind() == "<-"));
    match arrow_index {
        None => ChannelDirection::Bidirectional,
        Some(0) => ChannelDirection::Receive,
        Some(_) => ChannelDirection::Send,
    }
}

fn go_builtin_type(name: &str) -> bool {
    matches!(
        name,
        "any"
            | "bool"
            | "byte"
            | "comparable"
            | "complex64"
            | "complex128"
            | "error"
            | "float32"
            | "float64"
            | "int"
            | "int8"
            | "int16"
            | "int32"
            | "int64"
            | "rune"
            | "string"
            | "uint"
            | "uint8"
            | "uint16"
            | "uint32"
            | "uint64"
            | "uintptr"
    )
}

fn method_receiver(node: Node<'_>, source: &str) -> Option<(String, bool, Vec<String>)> {
    let receiver = node.child_by_field_name("receiver")?;
    let mut cursor = receiver.walk();
    let parameter = receiver
        .named_children(&mut cursor)
        .find(|child| child.kind() == "parameter_declaration")?;
    let type_node = parameter
        .child_by_field_name("type")
        .or_else(|| last_named_child(parameter))?;
    let identity = go_structured_type_identity(type_node, source)?;
    let name = identity.nominal_name()?.path().last()?.clone();
    let mut type_parameters = Vec::new();
    walk_named_tree_preorder(type_node, true, |candidate| {
        if candidate.kind() != "type_arguments" {
            return WalkControl::Continue;
        }
        walk_named_tree_preorder(candidate, false, |argument| {
            if argument.kind() == "type_identifier" {
                type_parameters.push(go_node_text(argument, source).trim().to_owned());
                WalkControl::SkipChildren
            } else {
                WalkControl::Continue
            }
        });
        WalkControl::SkipChildren
    });
    Some((name, identity.is_pointer(), type_parameters))
}

fn embedded_type_is_pointer(node: Node<'_>) -> bool {
    if node.kind() == "pointer_type" {
        return true;
    }
    node.parent()
        .filter(|parent| parent.kind() == "field_declaration")
        .is_some_and(|field| {
            (0..field.child_count()).any(|index| {
                field
                    .child(index)
                    .is_some_and(|child| !child.is_named() && child.kind() == "*")
            })
        })
}

fn declared_type_ids(types: &[TypeRef]) -> Vec<String> {
    let mut ids = Vec::new();
    let mut pending = types.iter().collect::<Vec<_>>();
    while let Some(reference) = pending.pop() {
        match reference {
            TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } => {
                if let TypeRef::Declared { id, .. } = reference
                    && !ids.contains(id)
                {
                    ids.push(id.clone());
                }
                pending.extend(arguments);
            }
            TypeRef::Array { element }
            | TypeRef::ByRef { element }
            | TypeRef::Pointer { element }
            | TypeRef::Slice { element }
            | TypeRef::FixedArray { element, .. }
            | TypeRef::Channel { element, .. } => pending.push(element),
            TypeRef::Map { key, value } => {
                pending.push(key);
                pending.push(value);
            }
            TypeRef::Wildcard { bound, .. } => pending.extend(bound.as_deref()),
            TypeRef::Tuple { elements } => pending.extend(elements),
            TypeRef::Function { parameters, result } => {
                pending.extend(parameters.iter().map(|parameter| &parameter.r#type));
                pending.extend(result.as_deref());
            }
            TypeRef::TypeParameter { .. } => {}
        }
    }
    ids.sort();
    ids
}

fn type_ref_depth(reference: &TypeRef) -> usize {
    let mut maximum = 0usize;
    let mut pending = vec![(reference, 1usize)];
    while let Some((reference, depth)) = pending.pop() {
        maximum = maximum.max(depth);
        match reference {
            TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } => {
                pending.extend(arguments.iter().map(|argument| (argument, depth + 1)));
            }
            TypeRef::Array { element }
            | TypeRef::ByRef { element }
            | TypeRef::Pointer { element }
            | TypeRef::Slice { element }
            | TypeRef::FixedArray { element, .. }
            | TypeRef::Channel { element, .. } => {
                pending.push((element, depth + 1));
            }
            TypeRef::Map { key, value } => {
                pending.push((key, depth + 1));
                pending.push((value, depth + 1));
            }
            TypeRef::Wildcard { bound, .. } => {
                pending.extend(bound.as_deref().map(|bound| (bound, depth + 1)));
            }
            TypeRef::Tuple { elements } => {
                pending.extend(elements.iter().map(|element| (element, depth + 1)));
            }
            TypeRef::Function { parameters, result } => {
                pending.extend(
                    parameters
                        .iter()
                        .map(|parameter| (&parameter.r#type, depth + 1)),
                );
                pending.extend(result.as_deref().map(|result| (result, depth + 1)));
            }
            TypeRef::TypeParameter { .. } => {}
        }
    }
    maximum
}

fn finish_facts(
    mut type_drafts: Vec<TypeDraft>,
    mut member_drafts: Vec<MemberDraft>,
    limits: &ArtifactProducerLimits,
    diagnostics: &mut BoundedProducerDiagnostics,
) -> (Vec<TypeFact>, Vec<MemberFact>) {
    type_drafts.sort_by(|left, right| {
        left.fact
            .name
            .cmp(&right.fact.name)
            .then_with(|| left.fact.id.cmp(&right.fact.id))
    });
    type_drafts.dedup_by(|left, right| left.fact.id == right.fact.id);
    member_drafts.sort_by(|left, right| {
        (&left.fact.owner, &left.fact.name, &left.fact.id).cmp(&(
            &right.fact.owner,
            &right.fact.name,
            &right.fact.id,
        ))
    });
    member_drafts.dedup_by(|left, right| left.fact.id == right.fact.id);

    let type_index = type_drafts
        .iter()
        .enumerate()
        .map(|(index, draft)| (draft.fact.id.clone(), index))
        .collect::<HashMap<_, _>>();
    let mut retained = type_drafts
        .iter()
        .filter(|draft| draft.exported)
        .map(|draft| draft.fact.id.clone())
        .collect::<HashSet<_>>();
    for member in &member_drafts {
        if !member.surface {
            continue;
        }
        if type_index
            .get(&member.fact.owner)
            .is_some_and(|index| type_drafts[*index].scaffold)
        {
            retained.insert(member.fact.owner.clone());
        }
    }
    let member_references_by_owner = member_drafts.iter().filter(|member| member.surface).fold(
        HashMap::<String, Vec<String>>::default(),
        |mut grouped, member| {
            grouped
                .entry(member.fact.owner.clone())
                .or_default()
                .extend(member.referenced_type_ids.iter().cloned());
            grouped
        },
    );
    let mut pending = retained.iter().cloned().collect::<Vec<_>>();
    while let Some(type_id) = pending.pop() {
        let Some(index) = type_index.get(&type_id) else {
            continue;
        };
        for referenced in &type_drafts[*index].referenced_type_ids {
            if retained.insert(referenced.clone()) {
                pending.push(referenced.clone());
            }
        }
        if let Some(references) = member_references_by_owner.get(&type_id) {
            for referenced in references {
                if retained.insert(referenced.clone()) {
                    pending.push(referenced.clone());
                }
            }
        }
    }
    let mut types = type_drafts
        .into_iter()
        .filter(|draft| retained.contains(&draft.fact.id))
        .map(|draft| draft.fact)
        .collect::<Vec<_>>();
    let retained_owners = types
        .iter()
        .map(|fact| fact.id.clone())
        .collect::<HashSet<_>>();
    let mut members = member_drafts
        .into_iter()
        .filter(|draft| draft.surface && retained_owners.contains(&draft.fact.owner))
        .map(|draft| draft.fact)
        .collect::<Vec<_>>();

    let total = types.len().saturating_add(members.len());
    if total > limits.max_records {
        diagnostics.warning(
            "limit.records",
            None,
            format!(
                "Go producer stopped after {} declaration records",
                limits.max_records
            ),
        );
        if types.len() > limits.max_records {
            types.truncate(limits.max_records);
            members.clear();
        } else {
            members.truncate(limits.max_records - types.len());
        }
    }
    let retained_owners = types
        .iter()
        .map(|fact| fact.id.as_str())
        .collect::<HashSet<_>>();
    members.retain(|member| retained_owners.contains(member.owner.as_str()));
    (types, members)
}

fn artifact_locator(path: &str, symbol: &str) -> Locator {
    Locator::Artifact {
        path: path.to_owned(),
        symbol: symbol.to_owned(),
    }
}

fn go_name_is_exported(name: &str) -> bool {
    name.chars().next().is_some_and(char::is_uppercase)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic_model::{CompilerOptions, ProducerDiagnostic, compile_pack};

    fn package(files: &[&str]) -> DiscoveredGoPackage {
        DiscoveredGoPackage {
            import_path: "example.com/dep/api".to_owned(),
            name: "api".to_owned(),
            directory: "api".to_owned(),
            files: files.iter().map(|file| format!("api/{file}")).collect(),
            ignored_go_files: Vec::new(),
            cgo_files: Vec::new(),
        }
    }

    fn facts(source: &str) -> (Vec<TypeFact>, Vec<MemberFact>, Vec<ProducerDiagnostic>) {
        let packages = vec![package(&["api.go"])];
        let entries = [("api/api.go", source.as_bytes())];
        let limits = ArtifactProducerLimits::default();
        let mut diagnostics = BoundedProducerDiagnostics::new(&limits);
        let facts = produce_go_facts(
            &packages,
            &HashMap::default(),
            entries,
            &limits,
            None,
            &mut diagnostics,
        )
        .unwrap();
        let (diagnostics, suppressed) = diagnostics.finish();
        assert_eq!(suppressed, 0);
        (facts.0, facts.1, diagnostics)
    }

    #[test]
    fn producer_preserves_exported_generics_embedding_and_receivers() {
        let (types, members, diagnostics) = facts(
            r#"
package api

type Constraint interface { ~int | ~string }
type hidden struct{}
func (hidden) Promoted(value string) int { return 0 }

type Box[T Constraint] struct {
    hidden
    Value T
    private int
}

func (Box[T]) Read(value T) T { return value }
func (*Box[T]) Write(value T) {}
func Exported(value Box[int]) Box[string] { return Box[string]{} }
var PublicValue Box[int]
const PublicConstant = 1
var privateValue int
"#,
        );
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        let box_type = types
            .iter()
            .find(|fact| fact.name == "example.com/dep/api.Box")
            .unwrap();
        assert_eq!(box_type.type_parameters, ["T"]);
        assert_eq!(box_type.type_parameter_constraints.len(), 1);
        assert_eq!(box_type.embedded_types.len(), 1);
        assert!(
            types
                .iter()
                .any(|fact| fact.name == "example.com/dep/api.hidden")
        );
        assert!(
            members
                .iter()
                .any(|member| member.name == "Promoted" && member.owner == box_type.id)
        );
        assert!(members.iter().any(|member| {
            member.name == "Write" && member.receiver == Some(ReceiverFact { pointer: true })
        }));
        let read = members.iter().find(|member| member.name == "Read").unwrap();
        assert!(
            matches!(
                read.signature.as_ref().unwrap().parameters[0].r#type,
                TypeRef::TypeParameter { ref name } if name == "T"
            ),
            "{:#?}",
            read.signature
        );
        assert!(!members.iter().any(|member| member.name == "privateValue"));
        assert!(members.iter().any(|member| member.name == "PublicConstant"));
        let pack = AuthoredSemanticModelPack {
            schema_version: crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
            pack_id: "bifrost.test.go".to_owned(),
            version: "1.0.0".to_owned(),
            producer: Producer {
                name: "test".to_owned(),
                version: "1.0.0".to_owned(),
            },
            language: "go".to_owned(),
            ecosystem: "go-module".to_owned(),
            compatibility: Compatibility {
                bifrost: "*".to_owned(),
                toolchains: Vec::new(),
            },
            provenance: Provenance {
                source: "test".to_owned(),
                revision: None,
            },
            license: "NOASSERTION".to_owned(),
            completeness: Completeness::Complete,
            safety: Safety {
                generated_code_only: false,
                review_required: false,
            },
            shards: vec![AuthoredShard {
                id: "go".to_owned(),
                activation: vec![ActivationSelector {
                    package: None,
                    module: Some(NameSelector {
                        name: "example.com/dep".to_owned(),
                        version: Some("=1.0.0".to_owned()),
                    }),
                    toolchain: None,
                    targets: Vec::new(),
                    configurations: Vec::new(),
                    artifact_sha256: None,
                }],
                payload: AuthoredPayload::DeclarationFacts {
                    types,
                    members,
                    relations: Vec::new(),
                },
            }],
        };
        compile_pack(&pack, &CompilerOptions::default()).unwrap();
    }

    #[test]
    fn producer_is_independent_of_file_enumeration() {
        let packages = vec![package(&["a.go", "b.go"])];
        let a = ("api/a.go", b"package api\ntype A struct{}\n".as_slice());
        let b = (
            "api/b.go",
            b"package api\nfunc Exported(value A) A { return value }\n".as_slice(),
        );
        let limits = ArtifactProducerLimits::default();
        let produce = |entries| {
            let mut diagnostics = BoundedProducerDiagnostics::new(&limits);
            let facts = produce_go_facts(
                &packages,
                &HashMap::default(),
                entries,
                &limits,
                None,
                &mut diagnostics,
            )
            .unwrap();
            assert!(diagnostics.finish().0.is_empty());
            facts
        };
        assert_eq!(produce([a, b]), produce([b, a]));
    }

    #[test]
    fn producer_marks_generated_source_as_partial_coverage() {
        let (types, members, diagnostics) = facts(
            "// Code generated by fixture; DO NOT EDIT.\npackage api\ntype Exported struct{}\n",
        );
        assert!(types.iter().any(|fact| fact.name.ends_with(".Exported")));
        assert!(members.is_empty());
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "go.generated_surface"),
            "{diagnostics:#?}"
        );
    }

    #[test]
    fn producer_resolves_imported_declared_package_names() {
        let packages = vec![
            DiscoveredGoPackage {
                import_path: "example.com/dep/presentation".to_owned(),
                name: "views".to_owned(),
                directory: "presentation".to_owned(),
                files: vec!["presentation/view.go".to_owned()],
                ignored_go_files: Vec::new(),
                cgo_files: Vec::new(),
            },
            DiscoveredGoPackage {
                import_path: "example.com/dep/api".to_owned(),
                name: "api".to_owned(),
                directory: "api".to_owned(),
                files: vec!["api/api.go".to_owned()],
                ignored_go_files: Vec::new(),
                cgo_files: Vec::new(),
            },
        ];
        let entries = [
            (
                "presentation/view.go",
                b"package views\ntype Widget struct{}\n".as_slice(),
            ),
            (
                "api/api.go",
                b"package api\nimport \"example.com/dep/presentation\"\nfunc Exported(value views.Widget) views.Widget { return value }\n".as_slice(),
            ),
        ];
        let import_names = HashMap::from_iter([(
            "example.com/dep/presentation".to_owned(),
            "views".to_owned(),
        )]);
        let limits = ArtifactProducerLimits::default();
        let mut diagnostics = BoundedProducerDiagnostics::new(&limits);
        let (types, members) = produce_go_facts(
            &packages,
            &import_names,
            entries,
            &limits,
            None,
            &mut diagnostics,
        )
        .unwrap();
        assert!(diagnostics.finish().0.is_empty());
        let widget = types
            .iter()
            .find(|fact| fact.name == "example.com/dep/presentation.Widget")
            .unwrap();
        let exported = members
            .iter()
            .find(|member| member.name == "Exported")
            .unwrap();
        assert!(matches!(
            exported.signature.as_ref().unwrap().parameters[0].r#type,
            TypeRef::Declared { ref id, .. } if id == &widget.id
        ));
    }

    #[test]
    fn producer_preserves_structured_go_function_and_container_types() {
        let (types, members, diagnostics) = facts(
            r#"
package api

type Box[T any] struct { Value T }
func Use(callback func(input map[string][]*Box[int], rest ...<-chan int) (Box[string], error)) {}
func Notify(callback func()) {}
"#,
        );
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        let box_id = &types
            .iter()
            .find(|fact| fact.name == "example.com/dep/api.Box")
            .unwrap()
            .id;
        let callback = &members
            .iter()
            .find(|member| member.name == "Use")
            .unwrap()
            .signature
            .as_ref()
            .unwrap()
            .parameters[0]
            .r#type;
        let TypeRef::Function { parameters, result } = callback else {
            panic!("expected a structured function type, got {callback:#?}");
        };
        assert_eq!(parameters.len(), 2);
        assert!(matches!(
            parameters[0].r#type,
            TypeRef::Map { ref key, ref value }
                if matches!(**key, TypeRef::Named { ref name, .. } if name == "string")
                    && matches!(
                        **value,
                        TypeRef::Slice { ref element }
                            if matches!(
                                **element,
                                TypeRef::Pointer { ref element }
                                    if matches!(
                                        **element,
                                        TypeRef::Declared { ref id, .. } if id == box_id
                                    )
                            )
                    )
        ));
        assert!(parameters[1].variadic);
        assert!(matches!(
            parameters[1].r#type,
            TypeRef::Channel {
                direction: ChannelDirection::Receive,
                ..
            }
        ));
        assert!(matches!(
            result.as_deref(),
            Some(TypeRef::Tuple { elements }) if elements.len() == 2
        ));
        let notify = &members
            .iter()
            .find(|member| member.name == "Notify")
            .unwrap()
            .signature
            .as_ref()
            .unwrap()
            .parameters[0]
            .r#type;
        assert!(matches!(
            notify,
            TypeRef::Function { parameters, result }
                if parameters.is_empty() && result.is_none()
        ));
    }

    #[test]
    fn producer_reports_and_honors_record_limits() {
        let packages = vec![package(&["api.go"])];
        let entries = [(
            "api/api.go",
            b"package api\ntype A struct{}\ntype B struct{}\nfunc One() {}\nfunc Two() {}\n"
                .as_slice(),
        )];
        let limits = ArtifactProducerLimits {
            max_records: 2,
            ..ArtifactProducerLimits::default()
        };
        let mut diagnostics = BoundedProducerDiagnostics::new(&limits);
        let (types, members) = produce_go_facts(
            &packages,
            &HashMap::default(),
            entries,
            &limits,
            None,
            &mut diagnostics,
        )
        .unwrap();
        let (diagnostics, _) = diagnostics.finish();
        assert!(types.len() + members.len() <= limits.max_records);
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "limit.records"),
            "{diagnostics:#?}"
        );
    }

    #[test]
    fn producer_applies_go_promotion_depth_ambiguity_and_pointer_rules() {
        let (types, members, diagnostics) = facts(
            r#"
package api

type hidden struct{}
func (hidden) Promoted() {}

type A struct { hidden }
type B struct { hidden }
type Root struct { A; B }

type PointerOnly struct{}
func (*PointerOnly) Touch() {}
type PointerBox struct { *PointerOnly }
type ValueBox struct { PointerOnly }
"#,
        );
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        let owner = |name: &str| {
            types
                .iter()
                .find(|fact| fact.name == format!("example.com/dep/api.{name}"))
                .unwrap()
                .id
                .clone()
        };
        assert!(
            !members
                .iter()
                .any(|member| { member.owner == owner("Root") && member.name == "Promoted" })
        );
        assert!(members.iter().any(|member| {
            member.owner == owner("PointerBox")
                && member.name == "Touch"
                && member.receiver == Some(ReceiverFact { pointer: false })
        }));
        assert!(members.iter().any(|member| {
            member.owner == owner("ValueBox")
                && member.name == "Touch"
                && member.receiver == Some(ReceiverFact { pointer: true })
        }));
    }

    #[test]
    fn producer_derives_structural_interface_relations_from_value_method_sets() {
        let (types, _, diagnostics) = facts(
            r#"
package api
type Reader interface { Read() int }
type Constraint interface { ~int | ~string; Read() int }
type Good struct{}
func (Good) Read() int { return 0 }
type PointerOnly struct{}
func (*PointerOnly) Read() int { return 0 }
type WrongResult struct{}
func (WrongResult) Read() string { return "" }
"#,
        );
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        let reader = types
            .iter()
            .find(|fact| fact.name.ends_with(".Reader"))
            .unwrap();
        let implements_reader = |name: &str| {
            types
                .iter()
                .find(|fact| fact.name.ends_with(&format!(".{name}")))
                .unwrap()
                .hierarchy
                .iter()
                .any(|relation| {
                    relation.hierarchy_kind == HierarchyKind::Implements
                        && declared_type_id(&relation.target) == Some(reader.id.as_str())
                })
        };
        assert!(implements_reader("Good"));
        assert!(!implements_reader("PointerOnly"));
        assert!(!implements_reader("WrongResult"));
        let constraint = types
            .iter()
            .find(|fact| fact.name.ends_with(".Constraint"))
            .unwrap();
        assert!(constraint.has_explicit_type_terms);
        assert!(
            !types
                .iter()
                .find(|fact| fact.name.ends_with(".Good"))
                .unwrap()
                .hierarchy
                .iter()
                .any(|relation| {
                    relation.hierarchy_kind == HierarchyKind::Implements
                        && declared_type_id(&relation.target) == Some(constraint.id.as_str())
                })
        );
    }
}
