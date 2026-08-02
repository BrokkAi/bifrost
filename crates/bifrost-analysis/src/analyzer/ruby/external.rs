use crate::CancellationToken;
use crate::analyzer::semantic_model::{
    ActivationSelector, ArtifactProducerLimits, AuthoredPayload, AuthoredSemanticModelPack,
    AuthoredShard, BoundedProducerDiagnostics, Compatibility, Completeness, DependencyArtifactRole,
    DependencyPackAdapter, DependencyPackProduction, ExactDependencyArtifact, ExternalArtifactKind,
    NameSelector, Producer, ProducerDiagnostic, ProducerDiagnosticSeverity, Provenance,
    ResolvedDependency, SEMANTIC_MODEL_SCHEMA_VERSION, Safety, TypeFact,
};
use crate::hash::HashMap;

use super::gem_artifact::{
    RubyGemDeclarationEntry, RubyGemDeclarationKind, read_gem_declaration_entries,
};
use super::rbs_artifact::project_rbs;
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
    let mut members = HashMap::default();
    let mut complete = true;
    for entry in ordered {
        let (projected_types, projected_members, projected_diagnostics, suppressed, entry_complete) =
            match entry.kind {
                RubyGemDeclarationKind::Rbs => {
                    let projection =
                        project_rbs(archive_sha256, &entry.path, &entry.source, limits);
                    (
                        projection.types,
                        projection.members,
                        projection.diagnostics,
                        projection.suppressed_diagnostics,
                        projection.complete,
                    )
                }
                RubyGemDeclarationKind::Rbi | RubyGemDeclarationKind::Ruby => {
                    let projection = project_ruby_source(
                        archive_sha256,
                        &entry.path,
                        &entry.source,
                        limits,
                        entry.kind == RubyGemDeclarationKind::Rbi,
                    );
                    (
                        projection.types,
                        projection.members,
                        projection.diagnostics,
                        projection.suppressed_diagnostics,
                        projection.complete,
                    )
                }
            };
        complete &= entry_complete && suppressed == 0;
        append_diagnostics(diagnostics, projected_diagnostics);
        for mut incoming in projected_types {
            match types.get_mut(&incoming.id) {
                None => {
                    types.insert(incoming.id.clone(), incoming);
                }
                Some(primary) if primary.type_kind == incoming.type_kind => {
                    let mut next_ordinal = primary
                        .hierarchy
                        .iter()
                        .filter_map(|fact| fact.declaration_ordinal)
                        .max()
                        .map_or(0, |ordinal| ordinal.saturating_add(1));
                    for mut hierarchy in incoming.hierarchy.drain(..) {
                        if hierarchy.declaration_ordinal.is_some() {
                            hierarchy.declaration_ordinal = Some(next_ordinal);
                            next_ordinal = next_ordinal.saturating_add(1);
                        }
                        if !primary.hierarchy.contains(&hierarchy) {
                            primary.hierarchy.push(hierarchy);
                        }
                    }
                    for type_parameter in incoming.type_parameters {
                        if !primary.type_parameters.contains(&type_parameter) {
                            primary.type_parameters.push(type_parameter);
                        }
                    }
                }
                Some(primary) => {
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
                }
            }
        }
        for incoming in projected_members {
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
    let mut types = types.into_values().collect::<Vec<_>>();
    let mut members = members.into_values().collect::<Vec<_>>();
    types.sort_by(|left, right| left.id.cmp(&right.id));
    members.sort_by(|left, right| left.id.cmp(&right.id));
    (types, members, complete)
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
        let first = merge_entries(&"d".repeat(64), &entries, &limits, &mut first_diagnostics);
        let second = merge_entries(&"d".repeat(64), &reversed, &limits, &mut second_diagnostics);

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
    fn exact_gem_discovery_and_adapter_compile_a_reusable_pack() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        let archive_root = temp.path().join("archives");
        fs::create_dir_all(&project_root).unwrap();
        fs::create_dir_all(&archive_root).unwrap();
        let lockfile = b"GEM\n";
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
