//! JVM realm support shared by the Java, Scala, and Kotlin analyzers.
//!
//! Java, Scala, and Kotlin compile to one classpath, so they share one
//! dependency universe: the same Maven/Gradle artifacts, the same jar-backed
//! declaration index, and the same build-manifest inputs that invalidate it.
//! Everything in this module is language-neutral by construction; per-language
//! behaviour belongs in `crate::analyzer::{java, scala, kotlin}`.

pub(crate) mod dependency_discovery;
pub(crate) mod external;
pub(crate) mod import_routes;
pub(crate) mod java_artifact;
pub(crate) mod jdk_artifact;
pub(crate) mod jmod_artifact;
pub(crate) mod kotlin_artifact;
#[cfg(any(test, feature = "test-support"))]
pub(crate) mod native_points;
pub(crate) mod realm_builder;
pub(crate) mod scala_artifact;
pub(crate) mod toolchains_document;
pub(crate) mod topology;

use crate::analyzer::CodeUnit;
use crate::analyzer::semantic_model::{
    ArtifactProduction, BoundedProducerDiagnostics, Completeness, TypeFact, Visibility,
};
use crate::analyzer::tree_sitter_analyzer::ParsedFile;
use crate::hash::HashMap;
use brokk_bifrost_jvm::proof::{
    JvmActiveSemanticModel, JvmModelDisposition, JvmRetainedExternalIndex,
};
use external::JvmExternalDeclarationIndex;
use tree_sitter::{Language, Node, Parser, Tree};

pub(crate) use dependency_discovery::MAX_BUILD_METADATA_BYTES;

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
    artifact_kind: crate::analyzer::semantic_model::ExternalArtifactKind,
    version: &str,
    targets: Vec<String>,
) -> crate::analyzer::semantic_model::ArtifactProductionRequest {
    use crate::analyzer::semantic_model::{
        ActivationSelector, ArtifactProductionRequest, Compatibility, NameSelector, Provenance,
        Safety, VersionConstraint,
    };

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
    overlay: Option<std::sync::Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
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
    pub(crate) fn new(analyzer: &dyn crate::analyzer::IAnalyzer) -> Self {
        let truncated_discovery = crate::analyzer::DependencyPackEcosystem::Jvm
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
    context: &crate::analyzer::store::resolution_operation::ProjectedNativeMemberContext,
) -> crate::analyzer::languages::NativeMemberAttribution {
    use crate::analyzer::structural::{HierarchyRelation, MemberDispatchTier, PrecedenceTier};
    let direct = context.owner_path.len() == 1;
    crate::analyzer::languages::NativeMemberAttribution {
        dispatch_tier: if context.route_kind
            == crate::analyzer::resolution::FactMemberRouteKind::TypeQualified
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
