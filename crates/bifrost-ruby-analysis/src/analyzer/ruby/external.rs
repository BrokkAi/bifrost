use std::path::PathBuf;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_analysis::analyzer::dependency_support::append_producer_diagnostics as append_diagnostics;

use brokk_bifrost_analysis::analyzer::dependency_support::dependency_locator_path as locator_path;

use brokk_bifrost_analysis::analyzer::dependency_support::failed_dependency_pack_production as failed;
#[cfg(test)]
use brokk_bifrost_analysis::analyzer::semantic_model::dependency::SuppressedDiagnostics;

use brokk_bifrost_analysis::analyzer::semantic_model::model::ActivationSelector;

use brokk_bifrost_analysis::analyzer::semantic_model::producer::ArtifactProducerLimits;

use brokk_bifrost_analysis::analyzer::semantic_model::producer::ArtifactProduction;

use brokk_bifrost_analysis::analyzer::semantic_model::producer::ArtifactProductionRequest;

use brokk_bifrost_analysis::analyzer::semantic_model::model::AuthoredPayload;

use brokk_bifrost_analysis::analyzer::semantic_model::model::AuthoredSemanticModelPack;

use brokk_bifrost_analysis::analyzer::semantic_model::model::AuthoredShard;

use brokk_bifrost_analysis::analyzer::semantic_model::producer::BoundedProducerDiagnostics;

use brokk_bifrost_analysis::analyzer::semantic_model::model::Compatibility;

use brokk_bifrost_analysis::analyzer::semantic_model::model::Completeness;

use brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyArtifactRole;

use brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyPackAdapter;

use brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyPackProduction;

use brokk_bifrost_analysis::analyzer::semantic_model::producer::ExactArtifact;

use brokk_bifrost_analysis::analyzer::semantic_model::dependency::ExactDependencyArtifact;

use brokk_bifrost_analysis::analyzer::semantic_model::producer::ExternalArtifactKind;

use brokk_bifrost_analysis::analyzer::semantic_model::model::NameSelector;

use brokk_bifrost_analysis::analyzer::semantic_model::model::Producer;

use brokk_bifrost_analysis::analyzer::semantic_model::producer::ProducerDiagnostic;

use brokk_bifrost_analysis::analyzer::semantic_model::producer::ProducerDiagnosticSeverity;

use brokk_bifrost_analysis::analyzer::semantic_model::model::Provenance;

use brokk_bifrost_analysis::analyzer::semantic_model::dependency::ResolvedDependency;

use brokk_bifrost_analysis::analyzer::semantic_model::model::SEMANTIC_MODEL_SCHEMA_VERSION;

use brokk_bifrost_analysis::analyzer::semantic_model::model::Safety;

use brokk_bifrost_analysis::analyzer::semantic_model::model::TypeFact;

use brokk_bifrost_analysis::analyzer::semantic_model::model::TypeRef;

use brokk_bifrost_analysis::analyzer::semantic_model::producer::read_exact_artifact_while;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::hash::HashSet;

use crate::analyzer::ruby::gem_artifact::RubyGemDeclarationEntry;

use crate::analyzer::ruby::gem_artifact::RubyGemDeclarationKind;

use crate::analyzer::ruby::gem_artifact::read_gem_declaration_entries;

use crate::analyzer::ruby::rbs_artifact::RubyMemberAlias;

use crate::analyzer::ruby::rbs_artifact::project_rbs;

use crate::analyzer::ruby::source_artifact::project_ruby_source;

#[derive(Debug, Clone, Copy, Default)]
pub struct RubyDependencyPackAdapter;

/// One pinned `.gem` archive, read and projected exactly as the dependency
/// adapter projects an installed gem: RBS is authoritative where present,
/// Sorbet RBI and plain Ruby fill the remainder.
#[derive(Debug, Clone, Copy, Default)]
pub struct RubyGemArchivePackProducer;

brokk_bifrost_analysis::analyzer::semantic_model::implement_external_artifact_pack_producer!(
    RubyGemArchivePackProducer,
    produce
);

impl RubyGemArchivePackProducer {
    fn produce(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
    ) -> ArtifactProduction {
        if request.artifact_kind != ExternalArtifactKind::RubyGemArchive {
            return ArtifactProduction::failed(
                ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    source_entry: None,
                    code: "artifact.kind".to_owned(),
                    location: None,
                    declaration: None,
                    message: "Ruby gem producer requires a gem archive artifact".to_owned(),
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
        self.produce_loaded_artifact(request, limits, cancellation, &artifact)
    }

    pub fn produce_loaded_artifact(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
        artifact: &ExactArtifact,
    ) -> ArtifactProduction {
        let archive =
            read_gem_declaration_entries(artifact.sha256(), artifact.bytes(), limits, cancellation);
        let mut diagnostics = BoundedProducerDiagnostics::new(limits);
        append_diagnostics(&mut diagnostics, archive.diagnostics);
        let mut complete = archive.complete && archive.suppressed_diagnostics.total() == 0;
        let (types, members, projection_complete) = merge_entries(
            artifact.sha256(),
            &archive.entries,
            limits,
            &mut diagnostics,
            cancellation,
        );
        complete &= projection_complete;
        if types.is_empty() && members.is_empty() {
            diagnostics.error(
                "ruby.gem.no_declarations",
                None,
                "Ruby gem contains no supported RBS, RBI, or Ruby declarations",
            );
            complete = false;
        }
        let completeness = if complete && diagnostics.is_empty() {
            Completeness::Complete
        } else {
            Completeness::Partial
        };
        let (diagnostics, mut suppressed_diagnostics) = diagnostics.finish();
        suppressed_diagnostics += archive.suppressed_diagnostics;
        let mut activation = request.activation.clone();
        for selector in &mut activation {
            selector.artifact_sha256 = Some(artifact.sha256().to_owned());
        }
        ArtifactProduction {
            artifact_sha256: Some(artifact.sha256().to_owned()),
            pack: (!types.is_empty() || !members.is_empty()).then(|| AuthoredSemanticModelPack {
                extraction: Some(brokk_bifrost_analysis::analyzer::semantic_model::ArtifactExtraction::from_artifact(request.artifact_kind, artifact)),
schema_version: SEMANTIC_MODEL_SCHEMA_VERSION,
                pack_id: request.pack_id.clone(),
                version: request.pack_version.clone(),
                producer: Producer {
                    name: "bifrost-ruby-gem".to_owned(),
                    version: env!("CARGO_PKG_VERSION").to_owned(),
                },
                language: "ruby".to_owned(),
                ecosystem: request.ecosystem.clone(),
                compatibility: request.compatibility.clone(),
                provenance: request.provenance.clone(),
                license: request.license.clone(),
                completeness,
                safety: request.safety.clone(),
                carried_sources: Vec::new(),
                cpp_portability: None,
                python_correspondence: None,
                shards: vec![AuthoredShard {
                    id: "declarations.ruby.external".to_owned(),
                    activation,
                    payload: AuthoredPayload::DeclarationFacts {
assembly_identity: None,
type_forwards: Vec::new(),
                        types,
                        members,
                        relations: Vec::new(),
                    },
                    runtime_values: None,
                    runtime_contracts: None,
                    collection_flows: None,
                    deferred_yields: None,
                    conditional_type_refinements: None,
                    callable_values: None,
                }],
            }),
            completeness,
            diagnostics,
            suppressed_diagnostics,
        }
    }
}

impl DependencyPackAdapter for RubyDependencyPackAdapter {
    fn adapter_name(&self) -> &str {
        "bifrost-ruby-dependency"
    }

    fn producer(&self) -> Producer {
        Producer::for_name("bifrost-ruby-gem")
    }

    fn can_produce(&self, dependency: &ResolvedDependency) -> bool {
        dependency.evidence.language == "ruby" && dependency.evidence.ecosystem == "rubygems"
    }

    fn produce(
        &self,
        dependency: &ResolvedDependency,
        artifacts: &[ExactDependencyArtifact],
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
    ) -> DependencyPackProduction {
        let Some(artifact) = artifacts.first().filter(|_| artifacts.len() == 1) else {
            return failed(
                "artifact.count",
                "Ruby dependency production requires one gem archive",
            );
        };
        if artifact.kind() != ExternalArtifactKind::RubyGemArchive
            || artifact.role() != DependencyArtifactRole::Declarations
        {
            return failed(
                "artifact.kind",
                "Ruby dependency production requires one declaration-role gem archive",
            );
        }
        let source = dependency
            .provenance
            .iter()
            .find(|entry| entry.key == "rubygems.source")
            .map(|entry| entry.value.clone())
            .unwrap_or_else(|| "exact Ruby gem".to_owned());
        let request = ArtifactProductionRequest {
            path: PathBuf::new(),
            artifact_kind: ExternalArtifactKind::RubyGemArchive,
            pack_id: "bifrost.external.ruby".to_owned(),
            pack_version: env!("CARGO_PKG_VERSION").to_owned(),
            ecosystem: "rubygems".to_owned(),
            compatibility: Compatibility {
                bifrost: None,
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
                module: None,
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
                source,
                revision: Some(artifact.sha256().to_owned()),
            },
            license: "NOASSERTION".to_owned(),
            safety: Safety {
                generated_code_only: false,
                review_required: false,
            },
        };
        let production = RubyGemArchivePackProducer.produce_loaded_artifact(
            &request,
            limits,
            cancellation,
            artifact.exact(),
        );
        debug_assert_eq!(
            production.artifact_sha256.as_deref(),
            Some(artifact.sha256())
        );
        DependencyPackProduction {
            pack: production.pack,
            diagnostics: production.diagnostics,
            suppressed_diagnostics: production.suppressed_diagnostics,
        }
    }
}

fn merge_entries(
    archive_sha256: &str,
    entries: &[RubyGemDeclarationEntry],
    limits: &ArtifactProducerLimits,
    diagnostics: &mut BoundedProducerDiagnostics,
    cancellation: Option<&CancellationToken>,
) -> (
    Vec<TypeFact>,
    Vec<brokk_bifrost_analysis::analyzer::semantic_model::model::MemberFact>,
    bool,
) {
    let mut ordered = entries.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        (origin_priority(left.kind), &left.path).cmp(&(origin_priority(right.kind), &right.path))
    });
    let mut types: HashMap<String, TypeFact> = HashMap::default();
    let mut members: HashMap<
        String,
        brokk_bifrost_analysis::analyzer::semantic_model::model::MemberFact,
    > = HashMap::default();
    let mut member_ids_by_lookup: HashMap<String, Vec<String>> = HashMap::default();
    let mut member_id_by_callable_shape: HashMap<String, String> = HashMap::default();
    let mut aliases = Vec::<RubyMemberAlias>::new();
    let mut conflicted_types = HashSet::default();
    let mut conflicted_type_facts: HashMap<String, Vec<TypeFact>> = HashMap::default();
    let mut complete = true;
    for entry in ordered {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            diagnostics.error(
                "ruby.projection.cancelled",
                None,
                "Ruby declaration projection was cancelled",
            );
            complete = false;
            break;
        }
        let (
            projected_types,
            projected_members,
            projected_diagnostics,
            suppressed,
            entry_complete,
            projected_aliases,
        ) = match entry.kind {
            RubyGemDeclarationKind::Rbs => {
                let projection = project_rbs(
                    archive_sha256,
                    &entry.path,
                    &entry.source,
                    limits,
                    cancellation,
                );
                (
                    projection.types,
                    projection.members,
                    projection.diagnostics,
                    projection.suppressed_diagnostics,
                    projection.complete,
                    projection.aliases,
                )
            }
            RubyGemDeclarationKind::Rbi | RubyGemDeclarationKind::Ruby => {
                let projection = project_ruby_source(
                    archive_sha256,
                    &entry.path,
                    &entry.source,
                    limits,
                    entry.kind == RubyGemDeclarationKind::Rbi,
                    cancellation,
                );
                (
                    projection.types,
                    projection.members,
                    projection.diagnostics,
                    projection.suppressed_diagnostics,
                    projection.complete,
                    projection.aliases,
                )
            }
        };
        aliases.extend(projected_aliases);
        complete &= entry_complete && suppressed.total() == 0;
        append_diagnostics(diagnostics, projected_diagnostics);
        for mut incoming in projected_types {
            if types.len().saturating_add(members.len()) >= limits.max_records {
                diagnostics.error(
                    "limit.records",
                    Some(entry.path.clone()),
                    format!(
                        "Ruby declarations exceed the {} record limit",
                        limits.max_records
                    ),
                );
                complete = false;
                break;
            }
            if conflicted_types.contains(&incoming.id) {
                continue;
            }
            match types.get_mut(&incoming.id) {
                None => {
                    types.insert(incoming.id.clone(), incoming);
                }
                Some(primary) if primary.type_kind == incoming.type_kind => {
                    let conflicting_parent = incoming.hierarchy.iter().find(|incoming_fact| {
                        incoming_fact.hierarchy_kind
                            == brokk_bifrost_analysis::analyzer::semantic_model::HierarchyKind::Extends
                            && primary.hierarchy.iter().any(|existing| {
                                existing.hierarchy_kind
                                    == brokk_bifrost_analysis::analyzer::semantic_model::HierarchyKind::Extends
                                    && existing.target != incoming_fact.target
                            })
                    });
                    if conflicting_parent.is_some() {
                        diagnostics.warning(
                            "ruby.declaration.superclass_conflict",
                            Some(locator_path(&incoming.locator).to_owned()),
                            format!(
                                "Ruby type {} declares incompatible superclasses",
                                incoming.name
                            ),
                        );
                        complete = false;
                    }
                    let mut next_ordinal = primary
                        .hierarchy
                        .iter()
                        .filter_map(|fact| fact.declaration_ordinal)
                        .max()
                        .map_or(0, |ordinal| ordinal.saturating_add(1));
                    for mut hierarchy in incoming.hierarchy.drain(..) {
                        if primary.hierarchy.iter().any(|existing| {
                            existing.hierarchy_kind == hierarchy.hierarchy_kind
                                && existing.target == hierarchy.target
                        }) {
                            continue;
                        }
                        if hierarchy.declaration_ordinal.is_some() {
                            hierarchy.declaration_ordinal = Some(next_ordinal);
                            next_ordinal = next_ordinal.saturating_add(1);
                        }
                        primary.hierarchy.push(hierarchy);
                    }
                    for type_parameter in incoming.type_parameters {
                        if !primary.type_parameters.contains(&type_parameter) {
                            primary.type_parameters.push(type_parameter);
                        }
                    }
                }
                Some(primary) => {
                    let conflicted_id = incoming.id.clone();
                    let primary = primary.clone();
                    diagnostics.warning(
                        "ruby.declaration.type_conflict",
                        Some(locator_path(&incoming.locator).to_owned()),
                        format!(
                            "Ruby type {} conflicts with the primary {:?} declaration from {}",
                            incoming.name,
                            primary.type_kind,
                            locator_path(&primary.locator)
                        ),
                    );
                    complete = false;
                    types.remove(&conflicted_id);
                    conflicted_types.insert(conflicted_id.clone());
                    conflicted_type_facts.insert(conflicted_id, vec![primary, incoming]);
                }
            }
        }
        for incoming in projected_members {
            if types.len().saturating_add(members.len()) >= limits.max_records {
                diagnostics.error(
                    "limit.records",
                    Some(entry.path.clone()),
                    format!(
                        "Ruby declarations exceed the {} record limit",
                        limits.max_records
                    ),
                );
                complete = false;
                break;
            }
            if conflicted_types.contains(&incoming.owner) {
                continue;
            }
            let lookup_key = member_lookup_key(&incoming);
            let callable_shape_key = member_callable_shape_key(&incoming);
            if !member_is_untyped(&incoming)
                && let Some(primary) = member_id_by_callable_shape
                    .get(&callable_shape_key)
                    .and_then(|id| members.get(id))
                && !same_signature_semantics(primary, &incoming)
            {
                diagnostics.warning(
                    "ruby.declaration.member_conflict",
                    Some(locator_path(&incoming.locator).to_owned()),
                    format!(
                        "Ruby member {}::{} conflicts with the primary declaration from {}",
                        incoming.owner,
                        incoming.name,
                        locator_path(&primary.locator)
                    ),
                );
                complete = false;
            }
            if entry.kind != RubyGemDeclarationKind::Rbs
                && member_is_untyped(&incoming)
                && member_ids_by_lookup.contains_key(&lookup_key)
            {
                continue;
            }
            match members.get_mut(&incoming.id) {
                None => {
                    member_id_by_callable_shape
                        .entry(callable_shape_key)
                        .or_insert_with(|| incoming.id.clone());
                    member_ids_by_lookup
                        .entry(lookup_key)
                        .or_default()
                        .push(incoming.id.clone());
                    members.insert(incoming.id.clone(), incoming);
                }
                Some(primary) => {
                    for alias in incoming.aliases {
                        if !primary.aliases.contains(&alias) {
                            primary.aliases.push(alias);
                        }
                    }
                }
            }
        }
    }
    members.retain(|_, member| !conflicted_types.contains(&member.owner));
    for (base_id, mut facts) in conflicted_type_facts {
        for mut fact in facts.drain(..) {
            fact.id = format!("{base_id}.conflict.{}", fact.type_kind.stable_label());
            types.insert(fact.id.clone(), fact);
        }
    }
    for alias in aliases {
        let mut matched = false;
        let lookup_key = member_lookup_key_parts(
            &alias.owner,
            &alias.old_name,
            brokk_bifrost_analysis::analyzer::semantic_model::MemberKind::Method,
            alias.is_static,
        );
        let matching_ids = member_ids_by_lookup
            .get(&lookup_key)
            .into_iter()
            .flatten()
            .cloned()
            .collect::<Vec<_>>();
        for id in matching_ids {
            let Some(member) = members.get_mut(&id) else {
                continue;
            };
            matched = true;
            if !member.aliases.contains(&alias.new_name) {
                member.aliases.push(alias.new_name.clone());
            }
        }
        if !matched {
            diagnostics.warning(
                "ruby.declaration.alias_target_missing",
                None,
                format!(
                    "Ruby alias {} could not find target {} on {}",
                    alias.new_name, alias.old_name, alias.owner
                ),
            );
            complete = false;
        }
    }
    let mut types = types.into_values().collect::<Vec<_>>();
    let mut members = members.into_values().collect::<Vec<_>>();
    resolve_local_hierarchy_ids(&mut types);
    types.sort_by(|left, right| left.id.cmp(&right.id));
    members.sort_by(|left, right| left.id.cmp(&right.id));
    (types, members, complete)
}

fn member_lookup_key(
    member: &brokk_bifrost_analysis::analyzer::semantic_model::model::MemberFact,
) -> String {
    member_lookup_key_parts(
        &member.owner,
        &member.name,
        member.member_kind,
        member.is_static,
    )
}

fn member_callable_shape_key(
    member: &brokk_bifrost_analysis::analyzer::semantic_model::model::MemberFact,
) -> String {
    let Some(signature) = &member.signature else {
        return format!("{}\0none", member_lookup_key(member));
    };
    let parameter_types = signature
        .parameters
        .iter()
        .map(|parameter| parameter.r#type.clone())
        .collect::<Vec<_>>();
    let identity =
        brokk_bifrost_analysis::analyzer::semantic_model::identity::member_declaration_id(
            brokk_bifrost_analysis::analyzer::semantic_model::identity::MemberIdentity {
                owner_id: &member.owner,
                kind: member.member_kind,
                is_static: member.is_static,
                parameter_arity: parameter_types.len(),
                name: &member.name,
                generic_arity: signature.type_parameters.len(),
                parameter_types: &parameter_types,
                parameter_variadics: &[],
                return_type: None,
            },
        );
    let modifiers = signature
        .parameters
        .iter()
        .map(|parameter| (parameter.optional, parameter.variadic))
        .collect::<Vec<_>>();
    format!("{identity}\0{modifiers:?}")
}

fn member_lookup_key_parts(
    owner: &str,
    name: &str,
    kind: brokk_bifrost_analysis::analyzer::semantic_model::model::MemberKind,
    is_static: bool,
) -> String {
    format!("{owner}\0{name}\0{kind:?}\0{is_static}")
}

fn same_signature_semantics(
    left: &brokk_bifrost_analysis::analyzer::semantic_model::model::MemberFact,
    right: &brokk_bifrost_analysis::analyzer::semantic_model::model::MemberFact,
) -> bool {
    let (Some(left), Some(right)) = (&left.signature, &right.signature) else {
        return left.signature.is_none() && right.signature.is_none();
    };
    if left.contains_unknown_types() || right.contains_unknown_types() {
        return false;
    }
    left.type_parameters == right.type_parameters
        && left.returns == right.returns
        && left.parameters.len() == right.parameters.len()
        && left
            .parameters
            .iter()
            .zip(&right.parameters)
            .all(|(left, right)| {
                left.r#type == right.r#type
                    && left.optional == right.optional
                    && left.variadic == right.variadic
            })
}

fn resolve_local_hierarchy_ids(types: &mut [TypeFact]) {
    let mut ids_by_name: HashMap<String, Option<String>> = HashMap::default();
    let mut ids_by_short_name: HashMap<String, Option<String>> = HashMap::default();
    for fact in &*types {
        ids_by_name
            .entry(fact.name.clone())
            .and_modify(|id| *id = None)
            .or_insert_with(|| Some(fact.id.clone()));
        let short_name = fact
            .name
            .rsplit("::")
            .next()
            .unwrap_or(&fact.name)
            .to_owned();
        ids_by_short_name
            .entry(short_name)
            .and_modify(|id| *id = None)
            .or_insert_with(|| Some(fact.id.clone()));
    }
    for fact in types {
        let owner_name = fact.name.clone();
        for hierarchy in &mut fact.hierarchy {
            let TypeRef::Named {
                name,
                arguments,
                nullable,
            } = &hierarchy.target
            else {
                continue;
            };
            let normalized = name.trim_start_matches("::");
            let mut target_id = ids_by_name.get(normalized).and_then(Clone::clone);
            if target_id.is_none() && !name.starts_with("::") && !normalized.contains("::") {
                let mut namespace = owner_name.as_str();
                while let Some(boundary) = namespace.rfind("::") {
                    namespace = &namespace[..boundary];
                    let candidate = format!("{namespace}::{normalized}");
                    if let Some(id) = ids_by_name.get(&candidate).and_then(Clone::clone) {
                        target_id = Some(id);
                        break;
                    }
                }
            }
            if target_id.is_none() {
                target_id = ids_by_short_name.get(normalized).and_then(Clone::clone);
            }
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

fn member_is_untyped(
    member: &brokk_bifrost_analysis::analyzer::semantic_model::model::MemberFact,
) -> bool {
    let Some(signature) = &member.signature else {
        return true;
    };
    signature.returns.is_none()
        || signature.returns.as_ref().is_some_and(type_is_untyped)
        || signature
            .parameters
            .iter()
            .any(|parameter| type_is_untyped(&parameter.r#type))
}

fn type_is_untyped(
    type_ref: &brokk_bifrost_analysis::analyzer::semantic_model::model::TypeRef,
) -> bool {
    matches!(
        type_ref,
        brokk_bifrost_analysis::analyzer::semantic_model::TypeRef::Named { name, .. } if name == "untyped"
    )
}

fn origin_priority(kind: RubyGemDeclarationKind) -> u8 {
    match kind {
        RubyGemDeclarationKind::Rbs => 0,
        RubyGemDeclarationKind::Rbi => 1,
        RubyGemDeclarationKind::Ruby => 2,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use brokk_bifrost_analysis::test_support::ruby_gem_archive as gem_archive;

    use crate::analyzer::ruby::external::*;

    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::canonical::sha256_hex;

    use brokk_bifrost_analysis::analyzer::semantic_model::producer::ArtifactProducerLimits;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogOptions;

    use brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyPackLimits;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

    use brokk_bifrost_analysis::analyzer::semantic_model::dependency::prepare_discovered_dependency_semantic_packs;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::project::Project;

    use brokk_bifrost_core::analyzer::config::RubyAnalyzerConfig;

    use brokk_bifrost_core::analyzer::config::RubyDependencyApiEvidence;

    use brokk_bifrost_core::analyzer::config::RubyGemApiArtifact;

    use brokk_bifrost_core::analyzer::project::TestProject;

    fn member_with_signature_types(
        parameter_type: TypeRef,
        return_type: TypeRef,
    ) -> brokk_bifrost_analysis::analyzer::semantic_model::model::MemberFact {
        brokk_bifrost_analysis::analyzer::semantic_model::model::MemberFact {
            id: "member.Widget.call".to_owned(),
            owner: "type.Widget".to_owned(),
            name: "call".to_owned(),
            member_kind: brokk_bifrost_analysis::analyzer::semantic_model::MemberKind::Method,
            visibility: brokk_bifrost_analysis::analyzer::semantic_model::Visibility::Public,
            is_static: false,
            is_abstract: false,
            is_virtual: false,
            implemented_trait: None,
            self_form: None,
            non_overridable: None,
            implicit_operation: None,
            explicit_operation: None,
            ambient_use: None,
            value_type: None,
            proxied_type: None,
            callable_family_complete: false,
            exact_return_classes: Vec::new(),
            signature: Some(brokk_bifrost_analysis::analyzer::semantic_model::model::Signature {
                type_parameters: Vec::new(),
                parameters: vec![brokk_bifrost_analysis::analyzer::semantic_model::model::Parameter {
                    name: Some("value".to_owned()),
                    r#type: parameter_type,
                    optional: false,
                    variadic: false,
                    role: None,
                    passing_mode: brokk_bifrost_analysis::analyzer::semantic_model::ParameterPassingMode::default(),
                }],
                returns: Some(return_type),
            }),
            receiver: None,
            extension_receiver: None,
            extension_receiver_constraints: Vec::new(),
            aliases: Vec::new(),
            guard: None,
            locator: brokk_bifrost_analysis::analyzer::semantic_model::Locator::Source {
                path: "sig/widget.rbs".to_owned(),
                symbol: Some("Widget#call".to_owned()),
            },
        }
    }

    #[test]
    fn unknown_types_never_establish_ruby_signature_equivalence() {
        let concrete_type = TypeRef::Named {
            name: "String".to_owned(),
            arguments: Vec::new(),
            nullable: false,
        };
        let concrete = member_with_signature_types(concrete_type.clone(), concrete_type.clone());
        let unknown_parameter =
            member_with_signature_types(TypeRef::Unknown, concrete_type.clone());
        let unknown_return = member_with_signature_types(concrete_type.clone(), TypeRef::Unknown);
        let nested_unknown = member_with_signature_types(
            TypeRef::Array {
                element: Box::new(TypeRef::Unknown),
            },
            concrete_type,
        );

        assert!(same_signature_semantics(&concrete, &concrete));
        assert!(!same_signature_semantics(
            &unknown_parameter,
            &unknown_parameter
        ));
        assert!(!same_signature_semantics(&unknown_parameter, &concrete));
        assert!(!same_signature_semantics(&unknown_return, &unknown_return));
        assert!(!same_signature_semantics(&nested_unknown, &nested_unknown));
    }

    #[test]
    fn merging_is_origin_order_independent_and_prefers_rbs_locations() {
        let entries = vec![
            RubyGemDeclarationEntry {
                path: "lib/widget.rb".to_owned(),
                kind: RubyGemDeclarationKind::Ruby,
                source: "class Widget; def call(value); end; end".to_owned(),
            },
            RubyGemDeclarationEntry {
                path: "sorbet/rbi/widget.rbi".to_owned(),
                kind: RubyGemDeclarationKind::Rbi,
                source: "class Widget; def call(value); end; end".to_owned(),
            },
            RubyGemDeclarationEntry {
                path: "sig/widget.rbs".to_owned(),
                kind: RubyGemDeclarationKind::Rbs,
                source: "class Widget\n  def call: (String value) -> Integer\nend".to_owned(),
            },
        ];
        let mut reversed = entries.clone();
        reversed.reverse();
        let limits = ArtifactProducerLimits::default();
        let mut first_diagnostics = BoundedProducerDiagnostics::new(&limits);
        let mut second_diagnostics = BoundedProducerDiagnostics::new(&limits);
        let first = merge_entries(
            &"d".repeat(64),
            &entries,
            &limits,
            &mut first_diagnostics,
            None,
        );
        let second = merge_entries(
            &"d".repeat(64),
            &reversed,
            &limits,
            &mut second_diagnostics,
            None,
        );

        assert_eq!(first, second);
        assert!(locator_path(&first.0[0].locator).contains("sig/widget.rbs"));
        assert!(
            first
                .1
                .iter()
                .any(|member| locator_path(&member.locator).contains("sig/widget.rbs"))
        );
    }

    #[test]
    fn contradictory_typed_origins_are_retained_and_diagnosed() {
        let entries = vec![
            RubyGemDeclarationEntry {
                path: "sig/widget.rbs".to_owned(),
                kind: RubyGemDeclarationKind::Rbs,
                source: "class Widget\n  def call: (String value) -> Integer\nend".to_owned(),
            },
            RubyGemDeclarationEntry {
                path: "sorbet/rbi/widget.rbi".to_owned(),
                kind: RubyGemDeclarationKind::Rbi,
                source: "class Widget\n  sig { params(value: String).returns(String) }\n  def call(value); end\nend".to_owned(),
            },
        ];
        let limits = ArtifactProducerLimits::default();
        let mut diagnostics = BoundedProducerDiagnostics::new(&limits);
        let (_, members, complete) =
            merge_entries(&"d".repeat(64), &entries, &limits, &mut diagnostics, None);
        let (diagnostics, suppressed) = diagnostics.finish();

        assert!(!complete);
        assert_eq!(suppressed, SuppressedDiagnostics::default());
        assert_eq!(
            members
                .iter()
                .filter(|member| member.name == "call")
                .count(),
            2
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "ruby.declaration.member_conflict")
        );
    }

    #[test]
    fn hierarchy_resolution_prefers_the_lexical_namespace() {
        let entries = vec![RubyGemDeclarationEntry {
            path: "sig/namespaces.rbs".to_owned(),
            kind: RubyGemDeclarationKind::Rbs,
            source: "class A::Base end\nclass B::Base end\nclass A::Child < Base end\n".to_owned(),
        }];
        let limits = ArtifactProducerLimits::default();
        let mut diagnostics = BoundedProducerDiagnostics::new(&limits);
        let (types, _, complete) =
            merge_entries(&"d".repeat(64), &entries, &limits, &mut diagnostics, None);

        assert!(complete);
        let base = types.iter().find(|fact| fact.name == "A::Base").unwrap();
        let child = types.iter().find(|fact| fact.name == "A::Child").unwrap();
        assert!(matches!(
            &child.hierarchy[0].target,
            TypeRef::Declared { id, .. } if id == &base.id
        ));
    }

    #[test]
    fn conflicting_type_kinds_remain_visible_as_ambiguity_candidates() {
        let entries = vec![
            RubyGemDeclarationEntry {
                path: "sig/widget.rbs".to_owned(),
                kind: RubyGemDeclarationKind::Rbs,
                source: "class Widget end".to_owned(),
            },
            RubyGemDeclarationEntry {
                path: "sorbet/rbi/widget.rbi".to_owned(),
                kind: RubyGemDeclarationKind::Rbi,
                source: "module Widget; end".to_owned(),
            },
        ];
        let limits = ArtifactProducerLimits::default();
        let mut diagnostics = BoundedProducerDiagnostics::new(&limits);
        let (types, _, complete) =
            merge_entries(&"d".repeat(64), &entries, &limits, &mut diagnostics, None);

        assert!(!complete);
        assert_eq!(types.iter().filter(|fact| fact.name == "Widget").count(), 2);
        assert_ne!(types[0].id, types[1].id);
    }

    #[test]
    fn source_aliases_apply_across_reopened_files() {
        let entries = vec![
            RubyGemDeclarationEntry {
                path: "lib/widget.rb".to_owned(),
                kind: RubyGemDeclarationKind::Ruby,
                source: "class Widget\n  def call; end\nend".to_owned(),
            },
            RubyGemDeclarationEntry {
                path: "lib/widget_alias.rb".to_owned(),
                kind: RubyGemDeclarationKind::Ruby,
                source: "class Widget\n  alias invoke call\nend".to_owned(),
            },
        ];
        let limits = ArtifactProducerLimits::default();
        let mut diagnostics = BoundedProducerDiagnostics::new(&limits);
        let (_, members, complete) =
            merge_entries(&"d".repeat(64), &entries, &limits, &mut diagnostics, None);

        assert!(complete);
        assert_eq!(members[0].aliases, ["invoke"]);
    }

    #[test]
    fn exact_gem_discovery_and_adapter_compile_a_reusable_pack() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        let archive_root = temp.path().join("archives");
        fs::create_dir_all(&project_root).unwrap();
        fs::create_dir_all(&archive_root).unwrap();
        let lockfile = b"GEM\n  remote: https://rubygems.org/\n  specs:\n    widget (1.2.3)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  widget\n\nRUBY VERSION\n   ruby 3.4.1p0\n";
        fs::write(project_root.join("Gemfile.lock"), lockfile).unwrap();
        fs::write(project_root.join("main.rb"), "Widget.new.call('x')\n").unwrap();
        let archive = gem_archive(&[
            (
                "sig/widget.rbs",
                b"class Widget\n  def call: (String value) -> Integer\nend",
            ),
            (
                "sorbet/rbi/widget.rbi",
                b"class Widget; def call(value); end; end",
            ),
        ]);
        let archive_path = archive_root.join("widget.gem");
        fs::write(&archive_path, &archive).unwrap();
        let project = TestProject::new(&project_root, Language::Ruby);
        let files_before = project.all_files().unwrap();
        let config = RubyAnalyzerConfig {
            dependency_api_evidence: vec![RubyDependencyApiEvidence {
                lockfile_path: project_root.join("Gemfile.lock"),
                lockfile_sha256: sha256_hex(lockfile),
                ruby_version: "3.4.1".to_owned(),
                platform: "ruby".to_owned(),
                approved_archive_roots: vec![archive_root],
                gems: vec![RubyGemApiArtifact {
                    name: "widget".to_owned(),
                    version: "1.2.3".to_owned(),
                    source: "https://rubygems.org/".to_owned(),
                    checksum: Some(sha256_hex(&archive)),
                    gem_archive_path: archive_path.clone(),
                }],
            }],
        };
        let limits = DependencyPackLimits::default();
        let discovery = crate::analyzer::ruby::resolve_ruby_semantic_pack_dependencies(
            &config, &project, &limits, None,
        );
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let prepared = prepare_discovered_dependency_semantic_packs(
            &catalog,
            &RubyDependencyPackAdapter,
            discovery,
            &limits,
            None,
        );

        assert!(prepared.complete, "{:#?}", prepared.diagnostics);
        assert_eq!(prepared.packs.len(), 1);
        assert_eq!(project.all_files().unwrap(), files_before);
        assert!(
            files_before
                .iter()
                .all(|file| file.abs_path() != archive_path)
        );

        let stale_discovery = crate::analyzer::ruby::resolve_ruby_semantic_pack_dependencies(
            &config, &project, &limits, None,
        );
        fs::write(&archive_path, b"replaced after discovery").unwrap();
        let rejected = prepare_discovered_dependency_semantic_packs(
            &catalog,
            &RubyDependencyPackAdapter,
            stale_discovery,
            &limits,
            None,
        );
        assert!(!rejected.complete);
        assert!(
            rejected
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "artifact.digest_changed")
        );
    }

    #[test]
    fn equivalent_parameter_names_do_not_create_a_conflict() {
        let entries = vec![
            RubyGemDeclarationEntry {
                path: "sig/widget.rbs".to_owned(),
                kind: RubyGemDeclarationKind::Rbs,
                source: "class Widget\n  def call: (String value) -> Integer\nend".to_owned(),
            },
            RubyGemDeclarationEntry {
                path: "sorbet/rbi/widget.rbi".to_owned(),
                kind: RubyGemDeclarationKind::Rbi,
                source: "class Widget\n  sig { params(input: String).returns(Integer) }\n  def call(input); end\nend".to_owned(),
            },
        ];
        let limits = ArtifactProducerLimits::default();
        let mut diagnostics = BoundedProducerDiagnostics::new(&limits);
        let (_, members, complete) =
            merge_entries(&"d".repeat(64), &entries, &limits, &mut diagnostics, None);

        assert!(complete);
        assert_eq!(
            members
                .iter()
                .filter(|member| member.name == "call")
                .count(),
            1
        );
    }
}
