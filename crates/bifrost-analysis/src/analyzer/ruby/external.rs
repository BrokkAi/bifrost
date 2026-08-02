use crate::CancellationToken;
use crate::analyzer::semantic_model::{
    ActivationSelector, ArtifactProducerLimits, AuthoredPayload, AuthoredSemanticModelPack,
    AuthoredShard, BoundedProducerDiagnostics, Compatibility, Completeness, DependencyArtifactRole,
    DependencyPackAdapter, DependencyPackProduction, ExactDependencyArtifact, ExternalArtifactKind,
    NameSelector, Producer, ProducerDiagnostic, ProducerDiagnosticSeverity, Provenance,
    ResolvedDependency, SEMANTIC_MODEL_SCHEMA_VERSION, Safety, TypeFact, TypeRef,
};
use crate::hash::{HashMap, HashSet};

use super::gem_artifact::{
    RubyGemDeclarationEntry, RubyGemDeclarationKind, read_gem_declaration_entries,
};
use super::rbs_artifact::{RbsMemberAlias, project_rbs};
use super::source_artifact::project_ruby_source;

#[derive(Debug, Clone, Copy, Default)]
pub struct RubyDependencyPackAdapter;

impl DependencyPackAdapter for RubyDependencyPackAdapter {
    fn adapter_name(&self) -> &str {
        "bifrost-ruby-dependency"
    }

    fn adapter_version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn producer(&self) -> Producer {
        Producer {
            name: "bifrost-ruby-gem".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
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
        let archive =
            read_gem_declaration_entries(artifact.sha256(), artifact.bytes(), limits, cancellation);
        let mut diagnostics = BoundedProducerDiagnostics::new(limits);
        append_diagnostics(&mut diagnostics, archive.diagnostics);
        let mut complete = archive.complete && archive.suppressed_diagnostics == 0;
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
        suppressed_diagnostics =
            suppressed_diagnostics.saturating_add(archive.suppressed_diagnostics);
        let activation = vec![ActivationSelector {
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
            artifact_sha256: Some(artifact.sha256().to_owned()),
        }];
        let source = dependency
            .provenance
            .iter()
            .find(|entry| entry.key == "rubygems.source")
            .map(|entry| entry.value.clone())
            .unwrap_or_else(|| "exact Ruby gem".to_owned());
        DependencyPackProduction {
            pack: (!types.is_empty() || !members.is_empty()).then(|| AuthoredSemanticModelPack {
                schema_version: SEMANTIC_MODEL_SCHEMA_VERSION,
                pack_id: "bifrost.external.ruby".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                producer: self.producer(),
                language: "ruby".to_owned(),
                ecosystem: "rubygems".to_owned(),
                compatibility: Compatibility {
                    bifrost: format!("={}", env!("CARGO_PKG_VERSION")),
                    toolchains: Vec::new(),
                },
                provenance: Provenance {
                    source,
                    revision: Some(artifact.sha256().to_owned()),
                },
                license: "NOASSERTION".to_owned(),
                completeness,
                safety: Safety {
                    generated_code_only: false,
                    review_required: false,
                },
                shards: vec![AuthoredShard {
                    id: "declarations.ruby.external".to_owned(),
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

fn merge_entries(
    archive_sha256: &str,
    entries: &[RubyGemDeclarationEntry],
    limits: &ArtifactProducerLimits,
    diagnostics: &mut BoundedProducerDiagnostics,
    cancellation: Option<&CancellationToken>,
) -> (
    Vec<TypeFact>,
    Vec<crate::analyzer::semantic_model::MemberFact>,
    bool,
) {
    let mut ordered = entries.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        (origin_priority(left.kind), &left.path).cmp(&(origin_priority(right.kind), &right.path))
    });
    let mut types: HashMap<String, TypeFact> = HashMap::default();
    let mut members: HashMap<String, crate::analyzer::semantic_model::MemberFact> =
        HashMap::default();
    let mut aliases = Vec::<RbsMemberAlias>::new();
    let mut conflicted_types = HashSet::default();
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
                    Vec::new(),
                )
            }
        };
        aliases.extend(projected_aliases);
        complete &= entry_complete && suppressed == 0;
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
                            == crate::analyzer::semantic_model::HierarchyKind::Extends
                            && primary.hierarchy.iter().any(|existing| {
                                existing.hierarchy_kind
                                    == crate::analyzer::semantic_model::HierarchyKind::Extends
                                    && existing.target != incoming_fact.target
                            })
                    });
                    if conflicting_parent.is_some() {
                        diagnostics.warning(
                            "ruby.declaration.superclass_conflict",
                            Some(locator_path(&incoming.locator)),
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
                    diagnostics.warning(
                        "ruby.declaration.type_conflict",
                        Some(locator_path(&incoming.locator)),
                        format!(
                            "Ruby type {} conflicts with the primary {:?} declaration from {}",
                            incoming.name,
                            primary.type_kind,
                            locator_path(&primary.locator)
                        ),
                    );
                    complete = false;
                    types.remove(&conflicted_id);
                    conflicted_types.insert(conflicted_id);
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
            if !member_is_untyped(&incoming)
                && let Some(primary) = members.values().find(|primary| {
                    same_callable_shape(primary, &incoming)
                        && primary.signature != incoming.signature
                })
            {
                diagnostics.warning(
                    "ruby.declaration.member_conflict",
                    Some(locator_path(&incoming.locator)),
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
                && members.values().any(|primary| {
                    primary.owner == incoming.owner
                        && primary.name == incoming.name
                        && primary.member_kind == incoming.member_kind
                        && primary.is_static == incoming.is_static
                })
            {
                continue;
            }
            match members.get_mut(&incoming.id) {
                None => {
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
    for alias in aliases {
        let mut matched = false;
        for member in members.values_mut().filter(|member| {
            member.owner == alias.owner
                && member.name == alias.old_name
                && member.is_static == alias.is_static
        }) {
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

fn same_callable_shape(
    left: &crate::analyzer::semantic_model::MemberFact,
    right: &crate::analyzer::semantic_model::MemberFact,
) -> bool {
    if left.owner != right.owner
        || left.name != right.name
        || left.member_kind != right.member_kind
        || left.is_static != right.is_static
    {
        return false;
    }
    let (Some(left), Some(right)) = (&left.signature, &right.signature) else {
        return false;
    };
    left.type_parameters.len() == right.type_parameters.len()
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

fn member_is_untyped(member: &crate::analyzer::semantic_model::MemberFact) -> bool {
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

fn type_is_untyped(type_ref: &crate::analyzer::semantic_model::TypeRef) -> bool {
    matches!(
        type_ref,
        crate::analyzer::semantic_model::TypeRef::Named { name, .. } if name == "untyped"
    )
}

fn origin_priority(kind: RubyGemDeclarationKind) -> u8 {
    match kind {
        RubyGemDeclarationKind::Rbs => 0,
        RubyGemDeclarationKind::Rbi => 1,
        RubyGemDeclarationKind::Ruby => 2,
    }
}

fn append_diagnostics(
    bounded: &mut BoundedProducerDiagnostics,
    diagnostics: Vec<ProducerDiagnostic>,
) {
    for diagnostic in diagnostics {
        match diagnostic.severity {
            ProducerDiagnosticSeverity::Warning => {
                bounded.warning(diagnostic.code, diagnostic.location, diagnostic.message)
            }
            ProducerDiagnosticSeverity::Error => {
                bounded.error(diagnostic.code, diagnostic.location, diagnostic.message)
            }
        }
    }
}

fn locator_path(locator: &crate::analyzer::semantic_model::Locator) -> String {
    match locator {
        crate::analyzer::semantic_model::Locator::Source { path, .. }
        | crate::analyzer::semantic_model::Locator::Artifact { path, .. } => path.clone(),
    }
}

fn failed(code: &str, message: &str) -> DependencyPackProduction {
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
    use std::fs;

    use flate2::Compression;
    use flate2::write::GzEncoder;

    use super::*;
    use crate::analyzer::canonical_hash::{lower_hex_string, sha256_bytes};
    use crate::analyzer::semantic_model::{
        ArtifactProducerLimits, CatalogOptions, DependencyPackLimits, SemanticPackCatalog,
        prepare_discovered_dependency_semantic_packs,
    };
    use crate::analyzer::{
        Language, Project, RubyAnalyzerConfig, RubyDependencyApiEvidence, RubyGemApiArtifact,
        TestProject,
    };

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
        assert_eq!(suppressed, 0);
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
    fn exact_gem_discovery_and_adapter_compile_a_reusable_pack() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        let archive_root = temp.path().join("archives");
        fs::create_dir_all(&project_root).unwrap();
        fs::create_dir_all(&archive_root).unwrap();
        let lockfile = b"GEM\n  remote: https://rubygems.org/\n  specs:\n    widget (1.2.3)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  widget\n";
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
                lockfile_sha256: digest(lockfile),
                ruby_version: "3.4.1".to_owned(),
                platform: "ruby".to_owned(),
                approved_archive_roots: vec![archive_root],
                gems: vec![RubyGemApiArtifact {
                    name: "widget".to_owned(),
                    version: "1.2.3".to_owned(),
                    source: "https://rubygems.org/".to_owned(),
                    checksum: Some(digest(&archive)),
                    gem_archive_path: archive_path.clone(),
                }],
            }],
        };
        let limits = DependencyPackLimits::default();
        let discovery =
            super::super::resolve_ruby_semantic_pack_dependencies(&config, &project, &limits, None);
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

        let stale_discovery =
            super::super::resolve_ruby_semantic_pack_dependencies(&config, &project, &limits, None);
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

    fn gem_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut compressed = Vec::new();
        {
            let encoder = GzEncoder::new(&mut compressed, Compression::default());
            let mut data = tar::Builder::new(encoder);
            for (path, bytes) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_size(bytes.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                data.append_data(&mut header, path, *bytes).unwrap();
            }
            data.into_inner().unwrap().finish().unwrap();
        }
        let mut gem = Vec::new();
        {
            let mut outer = tar::Builder::new(&mut gem);
            let mut header = tar::Header::new_gnu();
            header.set_size(compressed.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            outer
                .append_data(&mut header, "data.tar.gz", compressed.as_slice())
                .unwrap();
            outer.finish().unwrap();
        }
        gem
    }

    fn digest(bytes: &[u8]) -> String {
        lower_hex_string(&sha256_bytes(bytes))
    }
}
