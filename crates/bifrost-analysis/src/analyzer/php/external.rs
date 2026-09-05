//! The PHP external-pack producers.
//!
//! Two producers live here and share one tree-sitter PHP declaration walk
//! (`super::source_artifact::project_php_source`).
//!
//! [`PhpDependencyPackAdapter`] and [`ComposerPackagePackProducer`] read a
//! Composer package's real sources. Discovery hands the adapter one exact
//! source set per autoload rule; the adapter parses each PHP file and merges
//! the declarations into one pack for the package.
//!
//! [`PhpDeclarationStubPackProducer`] reads a pinned tree of plain PHP
//! declaration stubs describing the PHP runtime itself. Its declarations take
//! the `php` ecosystem rather than the `composer` one, so a builtin class and
//! a vendor class of the same name stay distinct identities.

use crate::CancellationToken;
use crate::analyzer::semantic_model::{
    ActivationSelector, ArtifactProducerLimits, ArtifactProduction, ArtifactProductionRequest,
    AuthoredPayload, AuthoredSemanticModelPack, AuthoredShard, BoundedProducerDiagnostics,
    Compatibility, Completeness, DependencyArtifactRole, DependencyPackAdapter,
    DependencyPackProduction, ExactArtifact, ExactDependencyArtifact, ExternalArtifactKind,
    MemberFact, NameSelector, Producer, ProducerDiagnostic, ProducerDiagnosticSeverity, Provenance,
    ResolvedDependency, SEMANTIC_MODEL_SCHEMA_VERSION, Safety, SuppressedDiagnostics, TypeFact,
};
use crate::hash::HashMap;

use super::source_artifact::{
    COMPOSER_ECOSYSTEM, PhpAutoloadRule, PhpDeclarationMarker, PhpProjectionOrigin, is_php_entry,
    project_php_source,
};

#[derive(Debug, Clone, Copy, Default)]
pub struct PhpDependencyPackAdapter;

impl DependencyPackAdapter for PhpDependencyPackAdapter {
    fn adapter_name(&self) -> &str {
        "bifrost-php-dependency"
    }

    fn adapter_version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn producer(&self) -> Producer {
        Producer {
            name: "bifrost-composer-package".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    fn can_produce(&self, dependency: &ResolvedDependency) -> bool {
        dependency.evidence.language == "php"
            && dependency.evidence.ecosystem == COMPOSER_ECOSYSTEM
            && dependency
                .artifacts
                .iter()
                .any(|artifact| artifact.kind == ExternalArtifactKind::ComposerPackageSourceSet)
    }

    fn produce(
        &self,
        dependency: &ResolvedDependency,
        artifacts: &[ExactDependencyArtifact],
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
    ) -> DependencyPackProduction {
        if artifacts.is_empty() {
            return failed(
                "composer.artifact_count",
                "Composer production requires at least one package source set",
            );
        }
        if artifacts
            .iter()
            .any(|artifact| artifact.kind() != ExternalArtifactKind::ComposerPackageSourceSet)
        {
            return failed(
                "composer.artifact_kind",
                "Composer production requires Composer package source sets",
            );
        }

        let mut diagnostics = BoundedProducerDiagnostics::new(limits);
        let mut types: HashMap<String, TypeFact> = HashMap::default();
        let mut members: HashMap<String, MemberFact> = HashMap::default();
        let mut complete = true;

        for artifact in artifacts {
            // The autoload rule survives as the artifact's own shape: a module
            // identity is the PSR-4 prefix, a runtime role is `files`
            // autoloading, and anything else is a classmap rule.
            let rule = match (artifact.module(), artifact.role()) {
                (Some(prefix), _) => PhpAutoloadRule::Psr4 {
                    namespace_prefix: prefix,
                },
                (None, DependencyArtifactRole::Runtime) => PhpAutoloadRule::Files,
                (None, _) => PhpAutoloadRule::Classmap,
            };
            for entry in artifact.source_entries() {
                if cancellation.is_some_and(CancellationToken::is_cancelled) {
                    diagnostics.error(
                        "composer.projection.cancelled",
                        None,
                        "Composer declaration projection was cancelled",
                    );
                    complete = false;
                    break;
                }
                if !is_php_entry(entry.relative_path()) {
                    continue;
                }
                let Ok(source) = std::str::from_utf8(entry.bytes()) else {
                    diagnostics.error(
                        "composer.source.encoding",
                        Some(entry.relative_path().to_owned()),
                        "PHP source entry is not valid UTF-8",
                    );
                    complete = false;
                    continue;
                };
                let projection = project_php_source(
                    artifact.sha256(),
                    entry.relative_path(),
                    source,
                    rule,
                    PhpProjectionOrigin::composer(),
                    limits,
                    cancellation,
                );
                complete &= projection.complete && projection.suppressed_diagnostics.total() == 0;
                append_diagnostics(&mut diagnostics, projection.diagnostics);
                for fact in projection.types {
                    merge_type(&mut types, fact, &mut diagnostics, &mut complete);
                }
                for fact in projection.members {
                    members.entry(fact.id.clone()).or_insert(fact);
                }
                if types.len().saturating_add(members.len()) >= limits.max_records {
                    diagnostics.error(
                        "limit.records",
                        Some(entry.relative_path().to_owned()),
                        format!(
                            "Composer declarations exceed the {} record limit",
                            limits.max_records
                        ),
                    );
                    complete = false;
                    break;
                }
            }
        }

        if types.is_empty() && members.is_empty() {
            diagnostics.error(
                "composer.package.no_declarations",
                None,
                "Composer package autoloads no projectable PHP declarations",
            );
            complete = false;
        }
        let completeness = if complete && diagnostics.is_empty() {
            Completeness::Complete
        } else {
            Completeness::Partial
        };
        let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
        let mut types = types.into_values().collect::<Vec<_>>();
        let mut members = members.into_values().collect::<Vec<_>>();
        types.sort_by(|left, right| left.id.cmp(&right.id));
        members.sort_by(|left, right| left.id.cmp(&right.id));

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
            targets: Vec::new(),
            configurations: dependency
                .evidence
                .configuration
                .clone()
                .into_iter()
                .collect(),
            artifact_sha256: None,
        }];
        let source = dependency
            .provenance
            .iter()
            .find(|entry| entry.key == "composer.dist_url" || entry.key == "composer.source_url")
            .map(|entry| entry.value.clone())
            .unwrap_or_else(|| "exact Composer package".to_owned());
        let revision = dependency
            .provenance
            .iter()
            .find(|entry| {
                entry.key == "composer.dist_reference" || entry.key == "composer.source_reference"
            })
            .map(|entry| entry.value.clone());

        DependencyPackProduction {
            pack: (!types.is_empty() || !members.is_empty()).then(|| AuthoredSemanticModelPack {
                schema_version: SEMANTIC_MODEL_SCHEMA_VERSION,
                pack_id: "bifrost.external.php".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                producer: self.producer(),
                language: "php".to_owned(),
                ecosystem: COMPOSER_ECOSYSTEM.to_owned(),
                compatibility: Compatibility {
                    bifrost: format!("={}", env!("CARGO_PKG_VERSION")),
                    toolchains: Vec::new(),
                },
                provenance: Provenance { source, revision },
                license: "NOASSERTION".to_owned(),
                completeness,
                safety: Safety {
                    generated_code_only: false,
                    review_required: false,
                },
                carried_sources: Vec::new(),
                cpp_portability: None,
                shards: vec![AuthoredShard {
                    id: "declarations.php.external".to_owned(),
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

/// One Composer autoload rule as a pinned release spec declares it.
///
/// A workspace dependency learns its autoload rules from an installed
/// package's `composer.lock`/`installed.json` autoload block. A pinned spec
/// names the rule and the files it admits explicitly instead, exactly as the
/// pinned Go module names its packages: the structure is spec-authored, not
/// derived from an on-disk vendor tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComposerPinnedAutoloadRule {
    Psr4 {
        namespace_prefix: String,
        files: Vec<String>,
    },
    Classmap {
        files: Vec<String>,
    },
    Files {
        files: Vec<String>,
    },
}

impl ComposerPinnedAutoloadRule {
    fn files(&self) -> &[String] {
        match self {
            Self::Psr4 { files, .. } | Self::Classmap { files } | Self::Files { files } => files,
        }
    }

    fn autoload_rule(&self) -> PhpAutoloadRule<'_> {
        match self {
            Self::Psr4 {
                namespace_prefix, ..
            } => PhpAutoloadRule::Psr4 { namespace_prefix },
            Self::Classmap { .. } => PhpAutoloadRule::Classmap,
            Self::Files { .. } => PhpAutoloadRule::Files,
        }
    }
}

/// Produce one pack from a pinned exact source set of Composer package
/// sources, grouped into autoload rules the spec names explicitly.
#[derive(Debug, Clone, Copy, Default)]
pub struct ComposerPackagePackProducer;

impl ComposerPackagePackProducer {
    pub fn produce_loaded_source_set(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
        artifact: &ExactArtifact,
        rules: &[ComposerPinnedAutoloadRule],
    ) -> ArtifactProduction {
        if request.artifact_kind != ExternalArtifactKind::ComposerPackageSourceSet {
            return ArtifactProduction::failed(
                ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    source_entry: None,
                    code: "artifact.kind".to_owned(),
                    location: None,
                    declaration: None,
                    message: "Composer package producer requires a Composer source-set artifact"
                        .to_owned(),
                },
                limits,
            );
        }
        let mut diagnostics = BoundedProducerDiagnostics::new(limits);
        let mut types: HashMap<String, TypeFact> = HashMap::default();
        let mut members: HashMap<String, MemberFact> = HashMap::default();
        let mut complete = true;

        for rule in rules {
            let autoload_rule = rule.autoload_rule();
            for path in rule.files() {
                if cancellation.is_some_and(CancellationToken::is_cancelled) {
                    diagnostics.error(
                        "composer.projection.cancelled",
                        None,
                        "Composer declaration projection was cancelled",
                    );
                    complete = false;
                    break;
                }
                let Some(entry) = artifact
                    .source_entries()
                    .iter()
                    .find(|entry| entry.relative_path() == path)
                else {
                    diagnostics.error(
                        "composer.declarations.missing",
                        Some(path.clone()),
                        "pinned Composer source set does not contain its declared file",
                    );
                    complete = false;
                    continue;
                };
                if !is_php_entry(entry.relative_path()) {
                    continue;
                }
                let Ok(source) = std::str::from_utf8(entry.bytes()) else {
                    diagnostics.error(
                        "composer.source.encoding",
                        Some(path.clone()),
                        "PHP source entry is not valid UTF-8",
                    );
                    complete = false;
                    continue;
                };
                let projection = project_php_source(
                    artifact.sha256(),
                    entry.relative_path(),
                    source,
                    autoload_rule,
                    PhpProjectionOrigin::composer(),
                    limits,
                    cancellation,
                );
                complete &= projection.complete && projection.suppressed_diagnostics.total() == 0;
                append_diagnostics(&mut diagnostics, projection.diagnostics);
                for fact in projection.types {
                    merge_type(&mut types, fact, &mut diagnostics, &mut complete);
                }
                for fact in projection.members {
                    members.entry(fact.id.clone()).or_insert(fact);
                }
                if types.len().saturating_add(members.len()) >= limits.max_records {
                    diagnostics.error(
                        "limit.records",
                        Some(path.clone()),
                        format!(
                            "Composer declarations exceed the {} record limit",
                            limits.max_records
                        ),
                    );
                    complete = false;
                    break;
                }
            }
        }

        if types.is_empty() && members.is_empty() {
            diagnostics.error(
                "composer.package.no_declarations",
                None,
                "Composer package autoloads no projectable PHP declarations",
            );
            complete = false;
        }
        let completeness = if complete && diagnostics.is_empty() {
            Completeness::Complete
        } else {
            Completeness::Partial
        };
        let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
        let mut types = types.into_values().collect::<Vec<_>>();
        let mut members = members.into_values().collect::<Vec<_>>();
        types.sort_by(|left, right| left.id.cmp(&right.id));
        members.sort_by(|left, right| left.id.cmp(&right.id));

        let mut activation = request.activation.clone();
        for selector in &mut activation {
            selector.artifact_sha256 = Some(artifact.sha256().to_owned());
        }
        ArtifactProduction {
            artifact_sha256: Some(artifact.sha256().to_owned()),
            pack: (!types.is_empty() || !members.is_empty()).then(|| AuthoredSemanticModelPack {
                schema_version: SEMANTIC_MODEL_SCHEMA_VERSION,
                pack_id: request.pack_id.clone(),
                version: request.pack_version.clone(),
                producer: Producer {
                    name: "bifrost-composer-package".to_owned(),
                    version: env!("CARGO_PKG_VERSION").to_owned(),
                },
                language: "php".to_owned(),
                ecosystem: request.ecosystem.clone(),
                compatibility: request.compatibility.clone(),
                provenance: request.provenance.clone(),
                license: request.license.clone(),
                completeness,
                safety: request.safety.clone(),
                carried_sources: Vec::new(),
                cpp_portability: None,
                shards: vec![AuthoredShard {
                    id: "declarations.php.external".to_owned(),
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

/// The prefix `phpstorm-stubs` gives a function whose real name is a PHP
/// reserved word, which no PHP program can call under the stubbed spelling.
const PHP_STUB_RESERVED_PREFIX: &str = "PS_UNRESERVE_PREFIX_";

/// The stub attribute that states a declaration's type depends on the runtime
/// version. This producer publishes the natively written type and reports the
/// declaration as read incompletely.
const PHP_STUB_LANGUAGE_LEVEL_ATTRIBUTE: &str = "LanguageLevelTypeAware";

/// The stub attribute that states a declaration or parameter exists only for
/// some runtime versions. This producer evaluates no such window.
const PHP_STUB_AVAILABILITY_ATTRIBUTE: &str = "PhpStormStubsElementAvailable";

/// Produce one pack from a pinned exact source set of plain PHP declaration
/// stubs: PHP source that states the runtime's classes, interfaces, traits,
/// enums, constants and functions with native signatures and empty bodies.
///
/// This is not the Composer producer with a different input. A Composer
/// package's sources are the code that runs; a stub tree is a description of
/// code that is not in any file the workspace can index, so its declarations
/// take the `php` runtime ecosystem rather than the `composer` one, and the
/// producer must account for everything the stub dialect states that a plain
/// PHP declaration walk cannot model.
#[derive(Debug, Clone, Copy, Default)]
pub struct PhpDeclarationStubPackProducer;

impl PhpDeclarationStubPackProducer {
    pub fn produce_loaded_source_set(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
        artifact: &ExactArtifact,
        stubs: &[String],
    ) -> ArtifactProduction {
        if request.artifact_kind != ExternalArtifactKind::PhpDeclarationStub {
            return ArtifactProduction::failed(
                ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    source_entry: None,
                    code: "artifact.kind".to_owned(),
                    location: None,
                    declaration: None,
                    message:
                        "PHP declaration-stub producer requires a PHP stub source-set artifact"
                            .to_owned(),
                },
                limits,
            );
        }
        let mut diagnostics = BoundedProducerDiagnostics::new(limits);
        let mut types: HashMap<String, TypeFact> = HashMap::default();
        let mut members: HashMap<String, MemberFact> = HashMap::default();
        let mut complete = true;

        for path in stubs {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                diagnostics.error(
                    "php.stub.projection.cancelled",
                    None,
                    "PHP declaration-stub projection was cancelled",
                );
                complete = false;
                break;
            }
            let Some(entry) = artifact
                .source_entries()
                .iter()
                .find(|entry| entry.relative_path() == path)
            else {
                diagnostics.error(
                    "php.stub.declarations.missing",
                    Some(path.clone()),
                    "pinned PHP stub source set does not contain its declared file",
                );
                complete = false;
                continue;
            };
            if !is_php_entry(entry.relative_path()) {
                diagnostics.error(
                    "php.stub.declarations.not_php",
                    Some(path.clone()),
                    "pinned PHP stub source set names a file that is not PHP source",
                );
                complete = false;
                continue;
            }
            let Ok(source) = std::str::from_utf8(entry.bytes()) else {
                diagnostics.error(
                    "php.stub.source.encoding",
                    Some(path.clone()),
                    "PHP stub source entry is not valid UTF-8",
                );
                complete = false;
                continue;
            };
            // A stub tree has no autoload rules: nothing installs it, and its
            // paths carry no PSR-4 promise, so the classmap rule -- "whatever
            // this file declares" -- is the only honest reading.
            let projection = project_php_source(
                artifact.sha256(),
                entry.relative_path(),
                source,
                PhpAutoloadRule::Classmap,
                PhpProjectionOrigin::php_runtime_stub(),
                limits,
                cancellation,
            );
            complete &= projection.complete && projection.suppressed_diagnostics.total() == 0;
            append_diagnostics(&mut diagnostics, projection.diagnostics);
            for fact in projection.types {
                merge_type(&mut types, fact, &mut diagnostics, &mut complete);
            }
            let mut dropped = Vec::new();
            for fact in projection.members {
                // A reserved-word stub names a construct PHP parses as syntax,
                // not a callable any program can name. Publishing it would put
                // a callable in the pack that no reference can ever reach.
                if fact.name.starts_with(PHP_STUB_RESERVED_PREFIX) {
                    // The reject names the declaration it dropped: release
                    // verification admits a partial pack only when every
                    // reject is an individually named warning.
                    diagnostics.warning_for_declaration(
                        "php.stub.reserved_prefix",
                        Some(path.clone()),
                        fact.id.clone(),
                        format!(
                            "PHP stub function {} names a reserved construct and is not published",
                            fact.name
                        ),
                    );
                    complete = false;
                    dropped.push(fact.id.clone());
                    continue;
                }
                members.entry(fact.id.clone()).or_insert(fact);
            }
            for note in projection.notes {
                if dropped.contains(&note.declaration) {
                    continue;
                }
                let (code, message) = match &note.marker {
                    PhpDeclarationMarker::Attribute(name)
                        if terminal_attribute_name(name) == PHP_STUB_LANGUAGE_LEVEL_ATTRIBUTE =>
                    {
                        (
                            "php.stub.language_level_type",
                            "PHP stub declaration states a version-dependent type this producer \
                             publishes as written"
                                .to_owned(),
                        )
                    }
                    PhpDeclarationMarker::Attribute(name)
                        if terminal_attribute_name(name) == PHP_STUB_AVAILABILITY_ATTRIBUTE =>
                    {
                        (
                            "php.stub.element_availability",
                            "PHP stub declaration states an availability window this producer \
                             does not evaluate"
                                .to_owned(),
                        )
                    }
                    // Every other attribute (`Pure`, `Deprecated`, `ArrayShape`,
                    // `TentativeType`) leaves the declaration's identity and
                    // signature exactly as written, so it needs no marker.
                    PhpDeclarationMarker::Attribute(_) => continue,
                    PhpDeclarationMarker::DuplicateParameterName(parameter) => (
                        "php.stub.version_variant_parameter",
                        format!(
                            "PHP stub callable states parameter {parameter} more than once for \
                             different runtime versions; the projection keeps the first spelling"
                        ),
                    ),
                    PhpDeclarationMarker::DocblockOnlyMembers => (
                        "php.stub.docblock_only_member",
                        "PHP stub type states members only in its docblock; the published surface \
                         is not all of it"
                            .to_owned(),
                    ),
                };
                diagnostics.warning_for_declaration(
                    code,
                    Some(path.clone()),
                    note.declaration.clone(),
                    message,
                );
                complete = false;
            }
            if types.len().saturating_add(members.len()) >= limits.max_records {
                diagnostics.error(
                    "limit.records",
                    Some(path.clone()),
                    format!(
                        "PHP stub declarations exceed the {} record limit",
                        limits.max_records
                    ),
                );
                complete = false;
                break;
            }
        }

        if types.is_empty() && members.is_empty() {
            diagnostics.error(
                "php.stub.no_declarations",
                None,
                "pinned PHP stub source set declares nothing projectable",
            );
            complete = false;
        }
        let completeness = if complete && diagnostics.is_empty() {
            Completeness::Complete
        } else {
            Completeness::Partial
        };
        let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
        let mut types = types.into_values().collect::<Vec<_>>();
        let mut members = members.into_values().collect::<Vec<_>>();
        types.sort_by(|left, right| left.id.cmp(&right.id));
        members.sort_by(|left, right| left.id.cmp(&right.id));

        // A source-set digest proves the exact model input, not an installed
        // PHP dependency, so the caller's activation selector is kept as
        // written. Stamping the stub tree's digest here would pin activation
        // to evidence naming that digest, which a workspace never publishes:
        // the runtime dependency a workspace declares is artifact-less. The
        // Composer producer above stamps its digest precisely because there
        // the artifact really is installed in the analyzed workspace.
        let activation = request.activation.clone();
        ArtifactProduction {
            artifact_sha256: Some(artifact.sha256().to_owned()),
            pack: (!types.is_empty() || !members.is_empty()).then(|| AuthoredSemanticModelPack {
                schema_version: SEMANTIC_MODEL_SCHEMA_VERSION,
                pack_id: request.pack_id.clone(),
                version: request.pack_version.clone(),
                producer: Producer {
                    name: "bifrost-php-declaration-stub".to_owned(),
                    version: env!("CARGO_PKG_VERSION").to_owned(),
                },
                language: "php".to_owned(),
                ecosystem: request.ecosystem.clone(),
                compatibility: request.compatibility.clone(),
                provenance: request.provenance.clone(),
                license: request.license.clone(),
                completeness,
                safety: request.safety.clone(),
                carried_sources: Vec::new(),
                cpp_portability: None,
                shards: vec![AuthoredShard {
                    id: "declarations.php.builtin".to_owned(),
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

/// The last segment of a resolved attribute identity.
///
/// The projection resolves an attribute name through the file's `use`
/// bindings and stores it in Bifrost's dotted qualified form, so a plain
/// import and an aliased one both produce
/// `JetBrains.PhpStorm.Internal.PhpStormStubsElementAvailable`. The terminal
/// segment is the attribute's own name, which is what the rules above match.
fn terminal_attribute_name(name: &str) -> &str {
    name.rsplit('.').next().unwrap_or(name)
}

/// Merge one projected type into the package surface.
///
/// A namespace scaffold repeats across every file that declares into it, so it
/// merges silently. Two different declarations of the same class name are a
/// real Composer conflict and must not collapse into one silent winner.
fn merge_type(
    types: &mut HashMap<String, TypeFact>,
    incoming: TypeFact,
    diagnostics: &mut BoundedProducerDiagnostics,
    complete: &mut bool,
) {
    use crate::analyzer::semantic_model::TypeKind;
    match types.get(&incoming.id) {
        None => {
            types.insert(incoming.id.clone(), incoming);
        }
        Some(existing) if existing.type_kind == TypeKind::Module => {}
        Some(existing) => {
            if existing.locator != incoming.locator {
                diagnostics.warning(
                    "composer.declaration.conflict",
                    Some(locator_path(&incoming.locator)),
                    format!(
                        "Composer package declares {} more than once; the first declaration came from {}",
                        incoming.name,
                        locator_path(&existing.locator)
                    ),
                );
                *complete = false;
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

fn failed(code: &str, message: &str) -> DependencyPackProduction {
    DependencyPackProduction {
        pack: None,
        diagnostics: vec![ProducerDiagnostic {
            severity: ProducerDiagnosticSeverity::Error,
            source_entry: None,
            code: code.to_owned(),
            location: None,
            declaration: None,
            message: message.to_owned(),
        }],
        suppressed_diagnostics: SuppressedDiagnostics::default(),
    }
}

#[cfg(test)]
pub(crate) mod fixture {
    use std::fs;
    use std::path::PathBuf;

    use crate::analyzer::canonical_hash::{lower_hex_string, sha256_bytes};
    use crate::analyzer::{Language, PhpAnalyzerConfig, PhpDependencyApiEvidence, TestProject};

    /// One Composer package to install into a fixture vendor tree.
    pub(crate) struct PackageSpec<'a> {
        pub name: &'a str,
        pub version: &'a str,
        pub reference: &'a str,
        pub autoload: &'a str,
        pub files: &'a [(&'a str, &'a str)],
    }

    /// An installed Composer vendor tree with a matching lock and installed.json.
    pub(crate) struct VendorFixture {
        pub _temp: tempfile::TempDir,
        pub root: PathBuf,
        pub project: TestProject,
        pub config: PhpAnalyzerConfig,
    }

    impl VendorFixture {
        pub(crate) fn new(packages: &[PackageSpec<'_>]) -> Self {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("project");
            fs::create_dir_all(root.join("vendor/composer")).unwrap();
            let mut locked = Vec::new();
            let mut installed = Vec::new();
            for package in packages {
                let install_dir = root.join("vendor").join(package.name);
                for (path, source) in package.files {
                    let absolute = install_dir.join(path);
                    fs::create_dir_all(absolute.parent().unwrap()).unwrap();
                    fs::write(absolute, source).unwrap();
                }
                locked.push(format!(
                    r#"{{"name":"{}","version":"{}","type":"library","dist":{{"type":"path","url":"file:///{}","reference":"{}"}},"autoload":{}}}"#,
                    package.name,
                    package.version,
                    package.name,
                    package.reference,
                    package.autoload
                ));
                installed.push(format!(
                    r#"{{"name":"{}","version":"{}","type":"library","install-path":"../{}","autoload":{}}}"#,
                    package.name, package.version, package.name, package.autoload
                ));
            }
            let lockfile = format!(
                r#"{{"content-hash":"fixture","packages":[{}],"packages-dev":[]}}"#,
                locked.join(",")
            );
            let installed_json = format!(r#"{{"packages":[{}],"dev":false}}"#, installed.join(","));
            fs::write(root.join("composer.lock"), &lockfile).unwrap();
            fs::write(root.join("vendor/composer/installed.json"), &installed_json).unwrap();
            fs::write(root.join("main.php"), "<?php\n").unwrap();

            let project = TestProject::new(&root, Language::Php);
            let config = PhpAnalyzerConfig {
                dependency_api_evidence: vec![PhpDependencyApiEvidence {
                    lockfile_path: PathBuf::from("composer.lock"),
                    lockfile_sha256: digest(lockfile.as_bytes()),
                    installed_json_path: Some(PathBuf::from("vendor/composer/installed.json")),
                    installed_json_sha256: Some(digest(installed_json.as_bytes())),
                    php_version: "8.3.0".to_owned(),
                    approved_vendor_roots: vec![PathBuf::from("vendor")],
                    include_dev_packages: false,
                }],
            };
            Self {
                _temp: temp,
                root,
                project,
                config,
            }
        }
    }

    pub(crate) fn digest(bytes: &[u8]) -> String {
        lower_hex_string(&sha256_bytes(bytes))
    }

    pub(crate) const WIDGET_PSR4: &str = r#"<?php
namespace Vendor\Widget;

use Vendor\Widget\Contracts\Renderable;

abstract class Widget implements Renderable {
    public const MODE = 'fast';
    protected string $label;
    public function __construct(string $label) { $this->label = $label; }
    public function render(int $width): string { return $this->label; }
    private function hidden(): void {}
    public static function create(string $label): static { return new static($label); }
}
"#;

    pub(crate) const RENDERABLE_PSR4: &str = r#"<?php
namespace Vendor\Widget\Contracts;

interface Renderable {
    public function render(int $width): string;
}
"#;

    pub(crate) const LEGACY_CLASSMAP: &str = r#"<?php
class Vendor_Widget_Legacy {
    public function legacyCall(): void {}
}
"#;

    pub(crate) const HELPERS_FILES: &str = r#"<?php
namespace Vendor\Widget;

function widget_render(Widget $widget): string { return $widget->render(10); }
"#;

    pub(crate) fn widget_package() -> PackageSpec<'static> {
        PackageSpec {
            name: "vendor/widget",
            version: "1.2.3",
            reference: "ref-widget",
            autoload: r#"{"psr-4":{"Vendor\\Widget\\":"src/"},"classmap":["legacy/"],"files":["helpers.php"]}"#,
            files: &[
                ("src/Widget.php", WIDGET_PSR4),
                ("src/Contracts/Renderable.php", RENDERABLE_PSR4),
                ("helpers.php", HELPERS_FILES),
                ("legacy/Vendor_Widget_Legacy.php", LEGACY_CLASSMAP),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::{PackageSpec, VendorFixture, widget_package};
    use super::*;
    use crate::analyzer::Project;
    use crate::analyzer::php::resolve_php_semantic_pack_dependencies;
    use crate::analyzer::semantic_model::{
        CatalogOptions, DependencyPackLimits, SemanticPackCatalog,
        prepare_discovered_dependency_semantic_packs,
    };

    #[test]
    fn composer_discovery_binds_lockfile_vendor_roots_and_autoload_rules() {
        let fixture = VendorFixture::new(&[widget_package()]);
        let limits = DependencyPackLimits::default();

        let discovery = resolve_php_semantic_pack_dependencies(
            &fixture.config,
            &fixture.project,
            &limits,
            None,
        );

        assert!(discovery.complete, "{:#?}", discovery.diagnostics);
        assert_eq!(discovery.dependencies.len(), 1);
        let dependency = &discovery.dependencies[0];
        assert_eq!(dependency.evidence.language, "php");
        assert_eq!(dependency.evidence.ecosystem, "composer");
        assert_eq!(
            dependency.evidence.package.as_ref().unwrap().name,
            "vendor/widget"
        );
        assert_eq!(dependency.evidence.configuration.as_deref(), Some("8.3.0"));
        // One artifact per autoload rule: PSR-4, then classmap, then files.
        assert_eq!(dependency.artifacts.len(), 3, "{:#?}", dependency.artifacts);
        assert_eq!(
            dependency.artifacts[0].module.as_deref(),
            Some("Vendor.Widget")
        );
        assert_eq!(
            dependency.artifacts[0].role,
            DependencyArtifactRole::Declarations
        );
        assert_eq!(
            dependency.artifacts[2].role,
            DependencyArtifactRole::Runtime
        );
        assert!(
            dependency
                .provenance
                .iter()
                .any(|entry| entry.key == "composer.dist_reference" && entry.value == "ref-widget"),
            "{:#?}",
            dependency.provenance
        );
    }

    #[test]
    fn dependency_files_are_read_through_the_pack_pipeline_not_the_workspace() {
        // The acceptance criterion is that indexing a dependency never grows the
        // ordinary workspace file set: vendor sources reach the analyzer as pack
        // facts, not as ProjectFiles.
        let fixture = VendorFixture::new(&[widget_package()]);
        let limits = DependencyPackLimits::default();
        let files_before = fixture.project.all_files().unwrap();
        let discovery = resolve_php_semantic_pack_dependencies(
            &fixture.config,
            &fixture.project,
            &limits,
            None,
        );
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();

        let prepared = prepare_discovered_dependency_semantic_packs(
            &catalog,
            &PhpDependencyPackAdapter,
            discovery,
            &limits,
            None,
        );

        assert!(prepared.complete, "{:#?}", prepared.diagnostics);
        assert_eq!(fixture.project.all_files().unwrap(), files_before);
    }

    #[test]
    fn exact_composer_package_produces_a_complete_reusable_pack() {
        let fixture = VendorFixture::new(&[widget_package()]);
        let limits = DependencyPackLimits::default();
        let discovery = resolve_php_semantic_pack_dependencies(
            &fixture.config,
            &fixture.project,
            &limits,
            None,
        );
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();

        let prepared = prepare_discovered_dependency_semantic_packs(
            &catalog,
            &PhpDependencyPackAdapter,
            discovery,
            &limits,
            None,
        );

        assert!(prepared.complete, "{:#?}", prepared.diagnostics);
        assert_eq!(prepared.packs.len(), 1);
        assert_eq!(prepared.packs[0].completeness, Completeness::Complete);
    }

    #[test]
    fn a_psr4_path_mismatch_keeps_the_package_surface_partial() {
        // `Vendor\Widget\Widget` must autoload from `src/Widget.php`. Declaring
        // it in `src/Wrong.php` is a real Composer autoload failure, so the
        // package surface must not claim to be complete.
        let package = PackageSpec {
            name: "vendor/widget",
            version: "1.2.3",
            reference: "ref-widget",
            autoload: r#"{"psr-4":{"Vendor\\Widget\\":"src/"}}"#,
            files: &[("src/Wrong.php", super::fixture::WIDGET_PSR4)],
        };
        let fixture = VendorFixture::new(&[package]);
        let limits = DependencyPackLimits::default();
        let discovery = resolve_php_semantic_pack_dependencies(
            &fixture.config,
            &fixture.project,
            &limits,
            None,
        );
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();

        let prepared = prepare_discovered_dependency_semantic_packs(
            &catalog,
            &PhpDependencyPackAdapter,
            discovery,
            &limits,
            None,
        );

        assert!(
            prepared
                .packs
                .iter()
                .all(|pack| pack.completeness == Completeness::Partial)
                || !prepared.complete,
            "{:#?}",
            prepared.diagnostics
        );
    }

    #[test]
    fn a_package_installed_outside_every_approved_root_is_rejected() {
        let mut fixture = VendorFixture::new(&[widget_package()]);
        fixture.config.dependency_api_evidence[0].approved_vendor_roots =
            vec![fixture.root.join("vendor/composer")];
        let limits = DependencyPackLimits::default();

        let discovery = resolve_php_semantic_pack_dependencies(
            &fixture.config,
            &fixture.project,
            &limits,
            None,
        );

        assert!(!discovery.complete);
        assert!(
            discovery
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "composer.package.outside_roots"),
            "{:#?}",
            discovery.diagnostics
        );
    }

    #[test]
    fn a_changed_lockfile_digest_rejects_the_evidence() {
        let mut fixture = VendorFixture::new(&[widget_package()]);
        fixture.config.dependency_api_evidence[0].lockfile_sha256 = "0".repeat(64);
        let limits = DependencyPackLimits::default();

        let discovery = resolve_php_semantic_pack_dependencies(
            &fixture.config,
            &fixture.project,
            &limits,
            None,
        );

        assert!(!discovery.complete);
        assert_eq!(
            discovery.diagnostics[0].code,
            "composer.evidence.lockfile_digest_mismatch"
        );
    }
}

/// Milestone 1 of issue #2374: the PHP declaration-stub producer.
///
/// Every test writes small stub files into a temporary tree, reads them with
/// the shared exact-source-set reader, and asserts on the facts the producer
/// publishes. Nothing here activates a pack; that is Milestone 3's subject.
#[cfg(test)]
mod declaration_stub_tests {
    use super::*;
    use crate::analyzer::semantic_model::{
        AuthoredPayload, Compatibility, MemberKind, Provenance, Safety, TypeIdentity, TypeKind,
        read_exact_source_set, type_declaration_id,
    };
    use std::path::PathBuf;

    struct StubTree {
        _temp: tempfile::TempDir,
        artifact: ExactArtifact,
        stubs: Vec<String>,
    }

    fn stub_tree(files: &[(&str, &str)]) -> StubTree {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("stubs");
        let mut stubs = Vec::new();
        for (path, source) in files {
            let absolute = root.join(path);
            std::fs::create_dir_all(absolute.parent().unwrap()).unwrap();
            std::fs::write(absolute, source).unwrap();
            stubs.push((*path).to_owned());
        }
        let relative = stubs.iter().map(PathBuf::from).collect::<Vec<_>>();
        let artifact = read_exact_source_set(
            &root,
            &relative,
            1_000,
            32,
            &ArtifactProducerLimits::default(),
        )
        .unwrap();
        StubTree {
            _temp: temp,
            artifact,
            stubs,
        }
    }

    fn stub_request() -> ArtifactProductionRequest {
        ArtifactProductionRequest {
            path: PathBuf::from("stubs"),
            artifact_kind: ExternalArtifactKind::PhpDeclarationStub,
            pack_id: "test.php-builtin".to_owned(),
            pack_version: "1.0.0".to_owned(),
            ecosystem: "php".to_owned(),
            compatibility: Compatibility {
                bifrost: "*".to_owned(),
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
                source: "test".to_owned(),
                revision: None,
            },
            license: "Apache-2.0".to_owned(),
            safety: Safety {
                generated_code_only: false,
                review_required: false,
            },
        }
    }

    struct Produced {
        types: Vec<TypeFact>,
        members: Vec<MemberFact>,
        diagnostics: Vec<ProducerDiagnostic>,
        completeness: Completeness,
    }

    impl Produced {
        fn type_named(&self, name: &str) -> &TypeFact {
            self.types
                .iter()
                .find(|fact| fact.name == name)
                .unwrap_or_else(|| panic!("no type named {name} in {:#?}", self.types))
        }

        fn member_named(&self, owner: &str, name: &str) -> &MemberFact {
            let owner_id = &self.type_named(owner).id;
            self.members
                .iter()
                .find(|fact| &fact.owner == owner_id && fact.name == name)
                .unwrap_or_else(|| panic!("no member {owner}::{name} in {:#?}", self.members))
        }

        fn codes(&self) -> Vec<&str> {
            self.diagnostics
                .iter()
                .map(|diagnostic| diagnostic.code.as_str())
                .collect()
        }
    }

    fn produce(files: &[(&str, &str)]) -> Produced {
        let tree = stub_tree(files);
        let production = PhpDeclarationStubPackProducer.produce_loaded_source_set(
            &stub_request(),
            &ArtifactProducerLimits::default(),
            None,
            &tree.artifact,
            &tree.stubs,
        );
        let pack = production
            .pack
            .as_ref()
            .unwrap_or_else(|| panic!("no pack produced: {:#?}", production.diagnostics));
        assert_eq!(pack.language, "php");
        assert_eq!(pack.shards.len(), 1, "{:#?}", pack.shards);
        assert_eq!(pack.shards[0].id, "declarations.php.builtin");
        let AuthoredPayload::DeclarationFacts { types, members, .. } = &pack.shards[0].payload
        else {
            panic!("stub production must publish declaration facts");
        };
        Produced {
            types: types.clone(),
            members: members.clone(),
            diagnostics: production.diagnostics.clone(),
            completeness: production.completeness,
        }
    }

    const PDO_STUB: &str = r#"<?php

namespace {
    class PDO
    {
        public const PARAM_INT = 1;

        public function prepare(string $query, array $options = []): PDOStatement|false {}

        public function beginTransaction(): bool {}
    }
}
"#;

    /// A global class publishes under its bare name, with no namespace prefix,
    /// and its members hang off that identity.
    #[test]
    fn a_global_class_publishes_its_bare_name_with_members_and_constants() {
        let produced = produce(&[("PDO/PDO.php", PDO_STUB)]);

        let pdo = produced.type_named("PDO");
        assert_eq!(pdo.type_kind, TypeKind::Class);
        assert_eq!(
            pdo.id,
            type_declaration_id(TypeIdentity {
                ecosystem: "php",
                name: "PDO",
            }),
            "a builtin identity takes the php runtime ecosystem, not composer"
        );

        let prepare = produced.member_named("PDO", "prepare");
        assert_eq!(prepare.member_kind, MemberKind::Method);
        let signature = prepare
            .signature
            .as_ref()
            .expect("a method has a signature");
        assert_eq!(signature.parameters.len(), 2);
        assert_eq!(signature.parameters[0].name.as_deref(), Some("query"));
        assert!(signature.parameters[1].optional);
        assert!(signature.returns.is_some());

        let constant = produced.member_named("PDO", "PARAM_INT");
        assert_eq!(constant.member_kind, MemberKind::Constant);
        assert!(constant.is_static);
    }

    /// A namespaced stub class publishes dot-joined, and its namespace
    /// publishes as the module scaffold the overlay reads coverage from.
    #[test]
    fn a_namespaced_stub_class_publishes_dot_joined_under_its_namespace() {
        let produced = produce(&[(
            "random/Random.php",
            r#"<?php

namespace Random;

class Randomizer
{
    public function getInt(int $min, int $max): int {}
}
"#,
        )]);

        let randomizer = produced.type_named("Random.Randomizer");
        assert_eq!(randomizer.type_kind, TypeKind::Class);
        assert_eq!(produced.type_named("Random").type_kind, TypeKind::Module);
        assert_eq!(
            produced.member_named("Random.Randomizer", "getInt").owner,
            randomizer.id
        );
    }

    /// A global function is a member of the global-namespace scaffold, which
    /// is the same owner a Composer `files` helper takes, so one owner-scoped
    /// query answers for both.
    #[test]
    fn a_global_function_publishes_on_the_global_namespace_scaffold() {
        let produced = produce(&[(
            "standard/standard_1.php",
            "<?php\nfunction substr(string $string, int $offset, ?int $length = null) {}\n",
        )]);

        let scaffold = produced.type_named(super::super::source_artifact::PHP_GLOBAL_NAMESPACE);
        assert_eq!(scaffold.type_kind, TypeKind::Module);
        let substr = produced.member_named(
            super::super::source_artifact::PHP_GLOBAL_NAMESPACE,
            "substr",
        );
        assert_eq!(substr.member_kind, MemberKind::Function);
        assert_eq!(
            substr.signature.as_ref().unwrap().parameters.len(),
            3,
            "{substr:#?}"
        );
    }

    /// `extends` and `implements` become hierarchy facts in declaration order.
    #[test]
    fn stub_inheritance_publishes_extends_and_implements_in_declaration_order() {
        use crate::analyzer::semantic_model::{HierarchyKind, TypeRef};

        let produced = produce(&[(
            "PDO/PDO.php",
            r#"<?php

namespace {
    class PDOException extends RuntimeException implements Throwable
    {
    }
}
"#,
        )]);

        let exception = produced.type_named("PDOException");
        let targets = exception
            .hierarchy
            .iter()
            .map(|fact| {
                let TypeRef::Named { name, .. } = &fact.target else {
                    panic!("a PHP base is always a named type: {fact:#?}");
                };
                (fact.hierarchy_kind, name.as_str())
            })
            .collect::<Vec<_>>();
        assert_eq!(
            targets,
            vec![
                (HierarchyKind::Extends, "RuntimeException"),
                (HierarchyKind::Implements, "Throwable"),
            ]
        );
    }

    /// Each braced namespace carries its own import table into declaration-pack
    /// projection. The same local alias can therefore name different bases in
    /// sibling namespaces, while a namespace with no import sees neither.
    #[test]
    fn stub_projection_keeps_braced_namespace_aliases_scoped() {
        use crate::analyzer::semantic_model::TypeRef;

        let produced = produce(&[(
            "scoped/Aliases.php",
            r#"<?php

namespace First {
    use Vendor\One\Base as ImportedBase;
    class Child extends ImportedBase {}
}

namespace Second {
    use Vendor\Two\Base as ImportedBase;
    class Child extends ImportedBase {}
}

namespace Third {
    class Child extends ImportedBase {}
}
"#,
        )]);

        let hierarchy_target = |name: &str| {
            let fact = produced.type_named(name);
            assert_eq!(fact.hierarchy.len(), 1, "{fact:#?}");
            let TypeRef::Named { name, .. } = &fact.hierarchy[0].target else {
                panic!("a PHP base is always a named type: {fact:#?}");
            };
            name.as_str()
        };

        assert_eq!(hierarchy_target("First.Child"), "Vendor.One.Base");
        assert_eq!(hierarchy_target("Second.Child"), "Vendor.Two.Base");
        assert_eq!(hierarchy_target("Third.Child"), "Third.ImportedBase");
    }

    /// Everything the stub dialect states that this producer does not model is
    /// reported, and the production is `Partial` because of it. A reserved-word
    /// stub is the one case that is dropped rather than published, because no
    /// PHP program can name it.
    #[test]
    fn stub_features_the_producer_does_not_model_are_reported_as_incompleteness() {
        let produced = produce(&[(
            "stubs/markers.php",
            r#"<?php

namespace {
    use JetBrains\PhpStorm\Internal\LanguageLevelTypeAware;
    use JetBrains\PhpStorm\Internal\PhpStormStubsElementAvailable;

    /**
     * @method string magicCall(int $times)
     */
    class Marked
    {
        #[LanguageLevelTypeAware(['8.1' => 'array|null'], default: '')]
        public $errorInfo;

        public function guarded(
            #[PhpStormStubsElementAvailable(from: '8.0')] int $flags = 0
        ): void {}
    }

    function PS_UNRESERVE_PREFIX_list($var1, ...$_) {}

    function hex2bin(string $string): string|false {}
}
"#,
        )]);

        assert_eq!(produced.completeness, Completeness::Partial);
        let mut codes = produced.codes();
        codes.sort_unstable();
        assert_eq!(
            codes,
            vec![
                "php.stub.docblock_only_member",
                "php.stub.element_availability",
                "php.stub.language_level_type",
                "php.stub.reserved_prefix",
            ],
            "{:#?}",
            produced.diagnostics
        );

        // The three surfaces that are read incompletely are still published;
        // the fictional name is not.
        produced.type_named("Marked");
        produced.member_named("Marked", "errorInfo");
        produced.member_named("Marked", "guarded");
        produced.member_named(
            super::super::source_artifact::PHP_GLOBAL_NAMESPACE,
            "hex2bin",
        );
        assert!(
            !produced
                .members
                .iter()
                .any(|member| member.name.starts_with("PS_UNRESERVE_PREFIX_")),
            "{:#?}",
            produced.members
        );
    }

    /// The producer refuses an artifact of any other kind rather than reading
    /// it with the wrong dialect.
    #[test]
    fn the_stub_producer_refuses_a_non_stub_artifact_kind() {
        let tree = stub_tree(&[("PDO/PDO.php", PDO_STUB)]);
        let mut request = stub_request();
        request.artifact_kind = ExternalArtifactKind::ComposerPackageSourceSet;

        let production = PhpDeclarationStubPackProducer.produce_loaded_source_set(
            &request,
            &ArtifactProducerLimits::default(),
            None,
            &tree.artifact,
            &tree.stubs,
        );

        assert!(production.pack.is_none());
        assert_eq!(
            production
                .diagnostics
                .iter()
                .map(|diagnostic| diagnostic.code.as_str())
                .collect::<Vec<_>>(),
            vec!["artifact.kind"]
        );
    }
}
