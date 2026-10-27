//! JVM realm support shared by the Java, Scala, and Kotlin analyzers.
//!
//! Java, Scala, and Kotlin compile to one classpath, so they share one
//! dependency universe: the same Maven/Gradle artifacts, the same jar-backed
//! declaration index, and the same build-manifest inputs that invalidate it.
//! Everything in this module is language-neutral by construction; per-language
//! behaviour belongs in `crate::analyzer::{java, scala, kotlin}`.

pub(crate) mod dependency_discovery;
#[doc(hidden)]
pub mod external;
pub(crate) mod hierarchy;
pub(crate) mod import_routes;
pub(crate) mod java_artifact;
pub(crate) mod jdk_artifact;
pub(crate) mod jmod_artifact;
pub(crate) mod kotlin_artifact;
#[doc(hidden)]
pub mod native_points;
pub(crate) mod realm_builder;
pub(crate) mod scala_artifact;
pub(crate) mod toolchains_document;
pub(crate) mod topology;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_semantic::analyzer::semantic_model::producer::ArtifactProduction;

use brokk_bifrost_semantic::analyzer::semantic_model::producer::BoundedProducerDiagnostics;

use brokk_bifrost_analysis::analyzer::semantic_model::Completeness;

use brokk_bifrost_analysis::analyzer::semantic_model::TypeFact;

use brokk_bifrost_analysis::analyzer::semantic_model::Visibility;

use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;

use brokk_bifrost_core::hash::HashMap;
use brokk_bifrost_jvm::proof::{
    JvmActiveSemanticModel, JvmModelDisposition, JvmRetainedExternalIndex,
};

use crate::analyzer::jvm::external::JvmExternalDeclarationIndex;
use tree_sitter::{Language, Node, Parser, Tree};

pub(crate) fn take_artifact_record(remaining: &mut usize, record_limit_hit: &mut bool) -> bool {
    if *remaining == 0 {
        *record_limit_hit = true;
        return false;
    }
    *remaining -= 1;
    true
}

pub(crate) fn visibility_from_java_access_flags(
    public: bool,
    protected: bool,
    private: bool,
) -> Visibility {
    if public {
        Visibility::Public
    } else if protected {
        Visibility::Protected
    } else if private {
        Visibility::Private
    } else {
        Visibility::Package
    }
}

/// Count Java array axes from their structural opening-bracket tokens.
///
/// Dimension annotations are children of the `dimensions` node too, so its
/// child count is not a reliable axis count.
pub(crate) fn java_array_dimension_count(dimensions: Node<'_>) -> usize {
    let count = (0..dimensions.child_count())
        .filter_map(|index| dimensions.child(index))
        .filter(|child| child.kind() == "[")
        .count();
    debug_assert!(
        count > 0,
        "Java dimensions node contains an array dimension"
    );
    count
}

pub(crate) fn equivalent_java_type_identity(left: &TypeFact, right: &TypeFact) -> bool {
    left.id == right.id
        && left.name == right.name
        && left.type_kind == right.type_kind
        && left.visibility == right.visibility
        && left.is_abstract == right.is_abstract
        && left.is_sealed == right.is_sealed
        && left.type_parameters == right.type_parameters
}

#[cfg(test)]
pub(crate) fn jdk_artifact_request(
    path: std::path::PathBuf,
    artifact_kind: brokk_bifrost_semantic::analyzer::semantic_model::producer::ExternalArtifactKind,
    version: &str,
    targets: Vec<String>,
) -> brokk_bifrost_semantic::analyzer::semantic_model::producer::ArtifactProductionRequest {
    use brokk_bifrost_analysis::analyzer::semantic_model::ActivationSelector;

    use brokk_bifrost_semantic::analyzer::semantic_model::producer::ArtifactProductionRequest;

    use brokk_bifrost_analysis::analyzer::semantic_model::Compatibility;

    use brokk_bifrost_analysis::analyzer::semantic_model::NameSelector;

    use brokk_bifrost_analysis::analyzer::semantic_model::Provenance;

    use brokk_bifrost_analysis::analyzer::semantic_model::Safety;

    use brokk_bifrost_analysis::analyzer::semantic_model::VersionConstraint;

    ArtifactProductionRequest {
        path,
        artifact_kind,
        pack_id: "jdk-21".to_owned(),
        pack_version: version.to_owned(),
        ecosystem: "jdk".to_owned(),
        compatibility: Compatibility {
            bifrost: None,
            toolchains: vec![VersionConstraint {
                name: "jdk".to_owned(),
                requirement: format!("={version}"),
            }],
        },
        activation: vec![ActivationSelector {
            package: None,
            module: None,
            toolchain: Some(NameSelector {
                name: "jdk".to_owned(),
                version: Some(format!("={version}")),
            }),
            targets,
            configurations: Vec::new(),
            artifact_sha256: None,
        }],
        provenance: Provenance {
            source: "OpenJDK".to_owned(),
            revision: Some(format!("jdk-{version}")),
        },
        license: "GPL-2.0-only WITH Classpath-exception-2.0".to_owned(),
        safety: Safety {
            generated_code_only: false,
            review_required: false,
        },
    }
}

/// Shared bounded source-JAR walk. Both full producers and the offline name
/// generator consume these exact entries; extraction warnings never disappear.
fn source_archive_entries(
    artifact: &brokk_bifrost_semantic::analyzer::semantic_model::producer::ExactArtifact,
    extensions: &[&str],
    diagnostic_prefix: &str,
    max_locator_path_bytes: usize,
    limits: &brokk_bifrost_semantic::analyzer::semantic_model::producer::ArtifactProducerLimits,
    cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    diagnostics: &mut BoundedProducerDiagnostics,
) -> Result<Vec<(String, String)>, Box<ArtifactProduction>> {
    use crate::analyzer::jvm::java_artifact::MAX_ARCHIVE_ENTRIES;

    use crate::analyzer::jvm::java_artifact::MAX_SOURCE_ENTRY_BYTES;

    use crate::analyzer::jvm::java_artifact::MAX_TOTAL_ARCHIVE_BYTES;
    use std::io::{Cursor, Read};
    let mut archive = zip::ZipArchive::new(Cursor::new(artifact.bytes()))
        .map_err(|_| {
            brokk_bifrost_semantic::analyzer::semantic_model::producer::failed_artifact_production(
                &format!("{diagnostic_prefix}.archive.invalid"),
                "artifact is not a readable ZIP/JAR archive",
                limits,
            )
        })
        .map_err(Box::new)?;
    let mut entries = Vec::new();
    let mut total_bytes = 0u64;
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        diagnostics.warning(
            "limit.archive_entries",
            None,
            format!("producer inspected at most {MAX_ARCHIVE_ENTRIES} archive entries"),
        );
    }
    for index in 0..archive.len().min(MAX_ARCHIVE_ENTRIES) {
        if cancellation
            .is_some_and(brokk_bifrost_core::cancellation::CancellationToken::is_cancelled)
        {
            return Err(Box::new(brokk_bifrost_semantic::analyzer::semantic_model::producer::failed_artifact_production(
                "artifact.cancelled",
                "source archive production was cancelled",
                limits,
            )));
        }
        let Ok(mut entry) = archive.by_index(index) else {
            diagnostics.warning(
                format!("{diagnostic_prefix}.archive.entry"),
                None,
                format!("could not read archive entry at index {index}"),
            );
            continue;
        };
        let name = match entry.name() {
            Ok(name) => name.into_owned(),
            Err(error) => {
                diagnostics.warning(
                    format!("{diagnostic_prefix}.archive.entry_name"),
                    None,
                    format!("could not decode archive entry name at index {index}: {error}"),
                );
                continue;
            }
        };
        if !extensions
            .iter()
            .any(|extension| name.ends_with(*extension))
        {
            continue;
        }
        if name.len() > max_locator_path_bytes {
            diagnostics.warning(
                "limit.locator_path",
                None,
                "source entry path exceeded the locator length limit",
            );
            continue;
        }
        let next_total = total_bytes.saturating_add(entry.size());
        if entry.size() > MAX_SOURCE_ENTRY_BYTES || next_total > MAX_TOTAL_ARCHIVE_BYTES {
            diagnostics.warning(
                "limit.archive_bytes",
                Some(name),
                "archive entry exceeded the bounded source extraction budget",
            );
            continue;
        }
        total_bytes = next_total;
        let mut bytes = Vec::with_capacity(entry.size() as usize);
        if entry
            .by_ref()
            .take(MAX_SOURCE_ENTRY_BYTES + 1)
            .read_to_end(&mut bytes)
            .is_err()
            || bytes.len() as u64 > MAX_SOURCE_ENTRY_BYTES
        {
            diagnostics.warning(
                format!("{diagnostic_prefix}.archive.entry_read"),
                Some(name),
                "could not read bounded archive entry bytes",
            );
            continue;
        }
        match String::from_utf8(bytes) {
            Ok(source) => entries.push((name, source)),
            Err(_) => diagnostics.warning(
                format!("{diagnostic_prefix}.source.encoding"),
                Some(name),
                "source entry is not valid UTF-8",
            ),
        }
    }
    entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    Ok(entries)
}

pub(crate) fn parse_source_tree(
    language: Language,
    source: &str,
    language_name: &'static str,
) -> Option<Tree> {
    let mut parser = Parser::new();
    parser.set_language(&language).expect(language_name);
    parser.parse(source, None)
}

pub(crate) fn parent_index(parsed: &ParsedFile) -> HashMap<CodeUnit, CodeUnit> {
    let mut parents = HashMap::default();
    for (parent, children) in &parsed.children {
        for child in children {
            parents.insert(child.clone(), parent.clone());
        }
    }
    parents
}

pub(crate) fn restrict_visibility(declared: Visibility, enclosing: Visibility) -> Visibility {
    match (declared, enclosing) {
        (Visibility::Private, _) | (_, Visibility::Private) => Visibility::Private,
        (Visibility::Package, _) | (_, Visibility::Package) => Visibility::Package,
        (Visibility::Protected, _) | (_, Visibility::Protected) => Visibility::Protected,
        _ => Visibility::Public,
    }
}

pub(crate) fn restrict_effective_visibility(
    declared: Visibility,
    enclosing: impl IntoIterator<Item = Option<Visibility>>,
) -> Option<Visibility> {
    let mut visibility = declared;
    for enclosing in enclosing {
        visibility = restrict_visibility(enclosing?, visibility);
    }
    Some(visibility)
}

pub(crate) fn valid_module_name(name: &str) -> bool {
    let mut segment_start = true;
    for character in name.chars() {
        if character == '.' {
            if segment_start {
                return false;
            }
            segment_start = true;
        } else if segment_start {
            if character != '_' && !character.is_ascii_alphabetic() {
                return false;
            }
            segment_start = false;
        } else if character != '_' && !character.is_ascii_alphanumeric() {
            return false;
        }
    }
    !segment_start
}

pub(crate) fn failed_with_diagnostics(
    artifact_sha256: &str,
    diagnostics: BoundedProducerDiagnostics,
) -> ArtifactProduction {
    let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
    ArtifactProduction {
        artifact_sha256: Some(artifact_sha256.to_owned()),
        pack: None,
        completeness: Completeness::Partial,
        diagnostics,
        suppressed_diagnostics,
    }
}

/// The build inputs every JVM language captures as selected configuration:
/// dependency-discovery build files and the toolchain declaration.
pub(crate) fn is_jvm_configuration_input_path(path: &std::path::Path) -> bool {
    dependency_discovery::is_jvm_dependency_input_path(path)
        || path == std::path::Path::new(".bifrost/jvm-toolchains.json")
}

/// Classify a peeked `OnceLock<JvmExternalDeclarationIndex>` cell for the
/// proof-gated diagnostic ladder (#1619).
///
/// All three JVM analyzers hold that cell and all three must read it the same
/// way, so the mapping lives here rather than three times over. `None` is a
/// cell no resolution and no `warm_query_indexes` has filled yet: a diagnostic
/// may not fill it, because building it reads jars.
pub(crate) fn retained_external_index_state(
    retained: Option<&JvmExternalDeclarationIndex>,
) -> JvmRetainedExternalIndex {
    match retained {
        None => JvmRetainedExternalIndex::Unbuilt,
        Some(external) if external.production_diagnostic_count() > 0 => {
            JvmRetainedExternalIndex::Partial
        }
        Some(_) => JvmRetainedExternalIndex::Complete,
    }
}

/// The active dependency model, as [`JvmActiveSemanticModel`] narrows it for
/// `brokk-bifrost-jvm`.
///
/// The overlay is the *dispatching* analyzer's, so this is built at the
/// analysis-side shim where that analyzer is in hand, not inside a language
/// analyzer that only knows its own generation.
pub(crate) struct JvmOverlayModel {
    overlay: Option<
        std::sync::Arc<
            brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay,
        >,
    >,
    truncated_discovery: bool,
}

impl JvmOverlayModel {
    /// Read the dispatching analyzer's published JVM external surface: the
    /// overlay, and whether the discovery that produced it reached everything
    /// the build declared (#2887).
    ///
    /// Java, Scala and Kotlin compile to one classpath, and the JVM ecosystem
    /// publishes its one discovery evidence under every language it serves, so
    /// the realm's truncation is whatever any of the three keys retained.
    /// Asking all three -- the ecosystem's own language list, not a second
    /// copy of it -- keeps this independent of which keys a publication used.
    pub(crate) fn new(
        analyzer: &dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
    ) -> Self {
        let truncated_discovery =
            brokk_bifrost_analysis::analyzer::workspace::DependencyPackEcosystem::Jvm
                .languages()
                .iter()
                .filter_map(|language| analyzer.dependency_discovery_evidence(*language))
                .any(|evidence| evidence.truncated());
        Self {
            overlay: analyzer.semantic_model_overlay(),
            truncated_discovery,
        }
    }
}

impl JvmActiveSemanticModel for JvmOverlayModel {
    fn is_published(&self) -> bool {
        // Publication means a declaration surface, not merely an overlay: a
        // bare JVM workspace activates generator-rule packs (e.g.
        // `bifrost.scala.case-class`) whose overlay declares no API at all,
        // and proving a name absent against that empty surface produced false
        // unrecognized-symbol errors for JDK types (#2678). Java, Scala and
        // Kotlin compile to one classpath, so a declaration surface published
        // for any of the three realms is the shared external surface.
        self.overlay.as_ref().is_some_and(|overlay| {
            ["java", "scala", "kotlin"]
                .iter()
                .any(|language| overlay.publishes_declaration_surface_for(language))
        })
    }

    fn discovery_truncated(&self) -> bool {
        self.truncated_discovery
    }

    fn qualified_name_disposition(&self, fqn: &str) -> JvmModelDisposition {
        let Some(overlay) = self.overlay.as_ref() else {
            return JvmModelDisposition::Absent;
        };
        // `symbols_named` posts every symbol under its simple name, its
        // qualified name and each alias, so it answers a bare `Widget` with
        // `com.acme.Widget`. A JVM caller has already walked its own import
        // tiers to produce a *qualified* spelling, and accepting the simple-name
        // posting would let any dependency type that happens to share a short
        // name silence a real error. Only the qualified spellings count: the
        // declared one, and the aliases, which are qualified too.
        let declarations = overlay
            .symbols_named(fqn)
            .records
            .iter()
            .filter(|symbol| {
                symbol.qualified_name == fqn || symbol.aliases.iter().any(|alias| alias == fqn)
            })
            .count();
        match declarations {
            0 => JvmModelDisposition::Absent,
            1 => JvmModelDisposition::Unique,
            declarations => JvmModelDisposition::Conflicting { declarations },
        }
    }

    fn extraction_gap(&self, fqn: &str) -> Option<brokk_bifrost_jvm::proof::JvmPackExtractionGap> {
        let gap = self.overlay.as_ref()?.gapped(fqn)?;
        Some(brokk_bifrost_jvm::proof::JvmPackExtractionGap {
            pack_id: gap.pack_id.clone(),
            declaration: gap.declaration.clone(),
        })
    }
}

/// Shared interpretation of a proven JVM receiver-to-owner hierarchy route.
pub(crate) fn native_member_attribution(
    context: &brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::ProjectedNativeMemberContext,
) -> brokk_bifrost_analysis::analyzer::languages::NativeMemberAttribution {
    use brokk_bifrost_core::analyzer::structural::resolution::HierarchyRelation;

    use brokk_bifrost_core::analyzer::structural::resolution::MemberDispatchTier;

    use brokk_bifrost_core::analyzer::structural::resolution::PrecedenceTier;
    let direct = context.owner_path.len() == 1;
    brokk_bifrost_analysis::analyzer::languages::NativeMemberAttribution {
        dispatch_tier: if context.route_kind
            == brokk_bifrost_analysis::analyzer::resolution::fact_resolution::FactMemberRouteKind::TypeQualified
        {
            MemberDispatchTier::StaticOrCompanion
        } else if direct {
            MemberDispatchTier::InherentOrDirect
        } else {
            MemberDispatchTier::InheritedOrPromoted
        },
        relation: HierarchyRelation::Supertype,
        precedence_tier: if direct {
            PrecedenceTier::OwnMember
        } else {
            PrecedenceTier::InheritedMember
        },
    }
}

pub(crate) mod dependency_packs {

    use brokk_bifrost_analysis::analyzer::dependency_support::resolve_dependency_path as resolve_path;

    use crate::analyzer::jvm::external::jdk_home_for_dependency;
    use brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelActivationEvidence;

    use brokk_bifrost_analysis::analyzer::semantic_model::DependencyDiscoveryOutcome;

    use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackAdapter;

    use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackLimits;

    use brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyResolver;

    use brokk_bifrost_analysis::analyzer::semantic_model::DependencyResolverBounds;

    use brokk_bifrost_analysis::analyzer::store::StoreError;

    use brokk_bifrost_analysis::analyzer::workspace::DependencyPackEcosystem;

    use brokk_bifrost_analysis::analyzer::workspace::DependencyPackEcosystemOutcome;

    use brokk_bifrost_analysis::analyzer::workspace::build_tool_dependency_resolver_bounds;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_core::analyzer::project::Project;

    use brokk_bifrost_core::analyzer::config::JvmDependencyDiscoveryMode;

    use crate::analyzer::JvmDependencyPackAdapter;

    use crate::analyzer::resolve_jvm_semantic_pack_dependencies;

    use brokk_bifrost_core::hash::HashMap;
    use std::path::{Path, PathBuf};
    pub(crate) struct JvmDependencyResolver;

    impl DependencyResolver for JvmDependencyResolver {
        fn adapter(&self) -> &'static dyn DependencyPackAdapter {
            &JvmDependencyPackAdapter
        }

        fn dependency_inputs(&self) -> &'static [&'static str] {
            // `is_jvm_dependency_input` is the reader-side predicate for the same
            // inputs; these are its base names.
            &[
                "pom.xml",
                "settings.xml",
                "build.gradle",
                "build.gradle.kts",
                "settings.gradle",
                "settings.gradle.kts",
                "gradle.properties",
                "gradle.lockfile",
                "libs.versions.toml",
                "gradle-wrapper.properties",
            ]
        }

        fn bounds(&self, config: &AnalyzerConfig) -> DependencyResolverBounds {
            let discovery = &config.jvm.dependency_discovery;
            let runs_tools = discovery.mode == JvmDependencyDiscoveryMode::OfflineBuildTools;
            build_tool_dependency_resolver_bounds(
                runs_tools.then_some(discovery.timeout),
                Some(
                    brokk_bifrost_analysis::analyzer::store::maven_xml::MAX_BUILD_METADATA_BYTES
                        as u64,
                ),
            )
        }

        fn resolve(
            &self,
            config: &AnalyzerConfig,
            project: &dyn Project,
            limits: &DependencyPackLimits,
            cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
        ) -> DependencyDiscoveryOutcome {
            resolve_jvm_semantic_pack_dependencies(&config.jvm, project, limits, cancellation)
        }
    }

    /// Correlate a configured source toolchain with the exact pack produced from
    /// that home's artifacts. Discovery IDs are run-local join keys; only the
    /// prepared evidence's artifact digest authorizes later call applicability.
    pub(crate) fn prepared_jdk_artifacts_for_source_bindings(
        config: &AnalyzerConfig,
        project_root: &Path,
        outcomes: &[DependencyPackEcosystemOutcome],
    ) -> Option<HashMap<PathBuf, SemanticModelActivationEvidence>> {
        let jvm = outcomes
            .iter()
            .find(|outcome| outcome.ecosystem == DependencyPackEcosystem::Jvm)?;
        let mut by_home = HashMap::default();
        if let Some(preparation) = &jvm.preparation {
            let prepared = preparation
                .packs
                .iter()
                .map(|pack| (pack.dependency_id.as_str(), &pack.evidence))
                .collect::<HashMap<_, _>>();
            for dependency in &jvm.discovery.dependencies {
                let (Some(home), Some(evidence)) = (
                    jdk_home_for_dependency(dependency),
                    prepared.get(dependency.id.as_str()),
                ) else {
                    continue;
                };
                if evidence.artifact_sha256.is_some() {
                    by_home.insert(home.to_path_buf(), (*evidence).clone());
                }
            }
        }
        let mut selected = HashMap::default();
        for binding in &config.jvm.standard_library_discovery.source_toolchains {
            let candidate = resolve_path(project_root, binding.jdk_home());
            if let Ok(home) = std::fs::canonicalize(candidate)
                && let Some(evidence) = by_home.get(&home)
            {
                selected.insert(binding.jdk_home().to_path_buf(), evidence.clone());
            }
        }
        Some(selected)
    }

    pub(crate) fn configure_dependency_workspace(
        config: &mut AnalyzerConfig,
        project_root: &Path,
    ) -> Result<(), StoreError> {
        for binding in
            crate::analyzer::jvm::toolchains_document::load_source_toolchains(project_root)
                .map_err(StoreError::new)?
        {
            let bindings = &mut config.jvm.standard_library_discovery.source_toolchains;
            if !bindings.contains(&binding) {
                bindings.push(binding);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod intrinsic_inventory_generator;

#[doc(hidden)]
pub mod native_graph;
