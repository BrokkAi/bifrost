use crate::analyzer::jvm::dependency_discovery::{discover_build_tools, discover_metadata};
use crate::analyzer::jvm::java_artifact::{
    JavaClassSurfaceOutcome, JavaJarPackProducer, ZipDirectoryStatus, class_surface,
    zip_directory_status,
};
use crate::analyzer::jvm::jdk_artifact::{
    JdkSourceArchivePackProducer, detect_jdk_source_archive_layout,
};
use crate::analyzer::jvm::jmod_artifact::JdkJmodSetPackProducer;
use crate::analyzer::jvm::kotlin_artifact::KotlinSourceJarPackProducer;
use crate::analyzer::jvm::scala_artifact::ScalaSourceJarPackProducer;
use crate::analyzer::semantic::{LengthDelimitedDigest, StableDigest};
use crate::analyzer::semantic_model::{
    ActivationSelector, ArtifactProducerLimits, ArtifactProduction, ArtifactProductionRequest,
    AuthoredPayload, AuthoredSemanticModelPack, CatalogCoordinate, Compatibility, Completeness,
    DependencyArtifactRole, DependencyDiscoveryOutcome, DependencyDiscoveryProfile,
    DependencyPackAdapter, DependencyPackDiagnostic, DependencyPackDiagnosticSeverity,
    DependencyPackLimits, DependencyPackProduction, DependencyProvenance, ExactDependencyArtifact,
    ExternalArtifactKind, ExternalArtifactPackProducer, HierarchyFact, Locator, MemberFact,
    MemberKind, NameSelector, Producer, ProducerDiagnostic, ProducerDiagnosticSeverity, Provenance,
    ResolvedDependency, ResolvedDependencyArtifact, Safety, SemanticModelActivationEvidence,
    TypeFact, TypeKind, TypeRef, Visibility, normalize_artifact_locator_paths,
    read_exact_artifact_while,
};
use crate::analyzer::{
    JvmAnalyzerConfig, JvmDependencyDiscoveryMode, JvmExternalArtifact, JvmExternalArtifactOrigin,
    JvmExternalDependencies, JvmMavenCoordinate, Project, ProjectFile,
};
use crate::hash::HashMap;
use brokk_bifrost_jvm::java::declarations::{
    class_like_body_children_rev, determine_package_name, is_class_like_declaration_kind,
    node_text, parse_tree,
};
use jclassfile::attributes::Attribute;
use jclassfile::constant_pool::ConstantPool;
use semver::Version;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use tree_sitter::Parser;
use zip::ZipArchive;

use crate::CancellationToken;
use crate::analyzer::topology::DependencyScope;

const MAX_ARCHIVE_ENTRIES: usize = 10_000;
const MAX_INDEX_ARTIFACTS: usize = 128;
const MAX_SOURCE_ENTRY_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ANALYZER_SOURCE_ENTRY_BYTES: u64 = 1024 * 1024;
const MAX_CLASS_ENTRY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_ARCHIVE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_TOTAL_INDEX_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ANALYZER_SOURCE_TYPES: usize = 4_096;
const MAX_JDK_JMOD_FILES: usize = 512;
/// The most member declarations one indexed artifact may contribute to the
/// external member surface (#1900).
///
/// The type-level index bounds an artifact by bytes ([`MAX_TOTAL_ARCHIVE_BYTES`]
/// against the shared [`MAX_TOTAL_INDEX_BYTES`] remainder) and by entries
/// ([`MAX_ARCHIVE_ENTRIES`]). Members are a second dimension: one class entry
/// well inside the byte bound can declare thousands of them, so a jar of
/// generated API classes could otherwise multiply the retained index far past
/// what its bytes suggest. Charging members separately keeps the retained
/// surface bounded in the dimension that actually grows.
///
/// Reaching the bound is recorded as a production diagnostic, so the artifact
/// reports as declared-but-not-fully-indexed rather than as a complete surface
/// that happens to declare fewer members.
const MAX_ARTIFACT_MEMBERS: usize = 32_768;
/// The most owner types one member lookup may walk while following an indexed
/// owner's supertypes.
///
/// An indexed hierarchy comes from class files that were compiled separately
/// and may disagree, so a cycle is possible; the visited set already stops one,
/// and this bounds the work of a wide but acyclic hierarchy as well.
const MAX_MEMBER_SURFACE_OWNERS: usize = 64;
const JVM_EXTERNAL_DISPATCH_BEHAVIOR_DOMAIN: &[u8] = b"bifrost-jvm-external-dispatch-behavior/v1";

#[derive(Debug, Clone, Default)]
pub(crate) struct JvmExternalDeclarationIndex {
    types_by_fqn: HashMap<String, JvmExternalType>,
    /// The member surface of every indexed owner whose own artifact entry this
    /// index read to the end, keyed by the owner's fully-qualified name
    /// (#1900).
    ///
    /// An owner with no entry here has no read member surface at all, which is
    /// not the same as an owner that declares no members: see
    /// [`JvmIndexedOwnerSurface`].
    members_by_owner: HashMap<String, JvmIndexedOwnerSurface>,
    production_diagnostics: Vec<ProducerDiagnostic>,
    /// Stable, path-independent identity of the effective declaration surface
    /// this index exposes to type, member, and hierarchy resolution.
    dispatch_behavior_identity: OnceLock<StableDigest>,
}

/// The member surface one indexed artifact type carries (#1900).
///
/// A surface exists only for an owner whose own archive entry passed the byte
/// budget and parsed, which is what makes the absence of a surface mean "not
/// read" rather than "declares nothing". This is the artifact half of the same
/// distinction the pack half draws between a pack that ships an empty `members`
/// array and no activated pack at all: in both halves only a positive
/// declaration is ever added, and a lookup that finds none leaves the caller's
/// status exactly where it was.
#[derive(Debug, Clone, Default)]
struct JvmIndexedOwnerSurface {
    /// One entry per written member name. Overloads are one name and not
    /// ambiguity -- `sort(List)` and `sort(List, Comparator)` are two
    /// declarations a reference spells identically -- so the first declaration
    /// read wins, which is the rule the pack half's `members_of` search already
    /// applies.
    members: HashMap<String, JvmExternalMember>,
    /// The fully-qualified supertypes the owner's own artifact entry named, so
    /// an inherited member is answered where it is declared. This is the
    /// artifact half of the pack half's `SemanticModelOverlay::owner_surface`
    /// closure.
    supertypes: Vec<String>,
}

/// What one Java artifact's declaration-fact production yielded, indexed the
/// way the archive walk consumes it (#1900).
///
/// The producer emits a flat list of member facts that point at their owner by
/// declaration id; the archive walk asks for one owner at a time, by
/// fully-qualified name, as it finishes reading that owner's entry. This does
/// the join once.
struct JavaArtifactFacts {
    types: HashMap<String, TypeFact>,
    members_by_owner: HashMap<String, Vec<MemberFact>>,
}

impl JavaArtifactFacts {
    fn new(types: HashMap<String, TypeFact>, members: Vec<MemberFact>) -> Self {
        let name_by_id = types
            .values()
            .map(|fact| (fact.id.clone(), fact.name.clone()))
            .collect::<HashMap<_, _>>();
        let mut members_by_owner: HashMap<String, Vec<MemberFact>> = HashMap::default();
        for member in members {
            // A member whose owner the production never emitted has no name to
            // hang on, so nothing can spell it.
            let Some(owner) = name_by_id.get(&member.owner) else {
                continue;
            };
            members_by_owner
                .entry(owner.clone())
                .or_default()
                .push(member);
        }
        Self {
            types,
            members_by_owner,
        }
    }

    /// The member surface for one owner whose artifact entry was just read to
    /// the end, charged against this artifact's member budget.
    ///
    /// Taking rather than borrowing keeps one owner's members from being
    /// charged twice when the same class appears under two entries.
    fn take_owner_surface(
        &mut self,
        owner_fqn: &str,
        owner_package: &str,
        budget: &mut MemberBudget,
    ) -> JvmIndexedOwnerSurface {
        let supertypes = self
            .types
            .get(owner_fqn)
            .map(|fact| hierarchy_type_names(&fact.hierarchy))
            .unwrap_or_default();
        let mut members = HashMap::default();
        for fact in self.members_by_owner.remove(owner_fqn).unwrap_or_default() {
            if !budget.take() {
                break;
            }
            let is_static = fact.is_static;
            let is_constant = fact.member_kind == MemberKind::Constant;
            members
                .entry(fact.name.clone())
                .or_insert_with(|| JvmExternalMember {
                    fqn: qualified_name(owner_fqn, &fact.name),
                    declaring_package: owner_package.to_owned(),
                    visibility: semantic_visibility(fact.visibility),
                    returns: fact.signature.and_then(|signature| signature.returns),
                    is_static,
                    is_constant,
                });
        }
        JvmIndexedOwnerSurface {
            members,
            supertypes,
        }
    }
}

/// The per-artifact member-count bound [`MAX_ARTIFACT_MEMBERS`] states,
/// carried across one artifact's whole archive walk.
///
/// Once it is spent the walk keeps indexing types and simply records no further
/// members, and `exhausted` makes the artifact report as not fully read, so a
/// member the bound dropped is unknown rather than absent.
struct MemberBudget {
    remaining: usize,
    exhausted: bool,
}

impl MemberBudget {
    fn new() -> Self {
        Self {
            remaining: MAX_ARTIFACT_MEMBERS,
            exhausted: false,
        }
    }

    fn take(&mut self) -> bool {
        match self.remaining.checked_sub(1) {
            Some(remaining) => {
                self.remaining = remaining;
                true
            }
            None => {
                self.exhausted = true;
                false
            }
        }
    }
}

/// The fully-qualified supertype names one indexed type's hierarchy facts name.
///
/// A hierarchy target the producer could not name -- an erased type variable,
/// an array -- is not a type a member surface can be read from, so it is
/// dropped rather than guessed at.
fn hierarchy_type_names(hierarchy: &[HierarchyFact]) -> Vec<String> {
    hierarchy
        .iter()
        .filter_map(|relation| match &relation.target {
            TypeRef::Named { name, .. } => (!name.is_empty()).then(|| name.clone()),
            _ => None,
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JvmExternalType {
    fqn: String,
    package_name: String,
    short_name: String,
    kind: JvmExternalTypeKind,
    visibility: JvmVisibility,
    source: JvmExternalDeclarationSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JvmExternalTypeKind {
    Class,
    Interface,
    Enum,
    Annotation,
    Record,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JvmVisibility {
    Public,
    Protected,
    PackagePrivate,
    Private,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JvmExternalDeclarationSource {
    SourceJar {
        artifact_path: PathBuf,
        source_path: String,
    },
    ClassFile {
        artifact_path: PathBuf,
        class_entry: String,
    },
    /// A declaration-facts record an activated semantic pack publishes
    /// (#1893). There is no artifact on disk to point at: the pack itself is
    /// the evidence, so the provenance recorded here is the pack that declared
    /// the type and the declaration identity inside it.
    SemanticPack {
        pack_id: String,
        declaration_id: String,
    },
}

#[derive(Debug, Clone)]
struct ResolvedJvmArtifact {
    artifact_path: PathBuf,
    source_artifact_path: Option<PathBuf>,
    coordinate: Option<JvmMavenCoordinate>,
    origin: JvmDependencyOrigin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JvmDependencyOrigin {
    ExplicitPath,
    MavenReport,
    GradleReport,
    MavenRepository,
    GradleCache,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct JvmDependencyPackAdapter;

impl JvmDependencyPackAdapter {
    /// Build the exact JDK source dependency used by the runtime resolver.
    /// Release tooling uses this constructor so its production key includes
    /// the same evidence and provenance as a locally discovered JDK.
    pub fn jdk_source_dependency(version: Version, source_archive: PathBuf) -> ResolvedDependency {
        resolved_jdk_dependency(version, Some(source_archive))
    }
}

pub fn resolve_jvm_semantic_pack_dependencies(
    config: &JvmAnalyzerConfig,
    project: &dyn Project,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> DependencyDiscoveryOutcome {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return cancelled_discovery("JVM dependency discovery was cancelled");
    }
    let mut dependencies = config.external_dependencies.clone();
    // What the build files *declare*, kept beside the coordinates themselves:
    // scope and declaring target are properties of the declaration, and the
    // merged coordinate list has already lost which file each came from.
    let mut declarations = crate::hash::HashMap::default();
    if config.dependency_discovery.mode != JvmDependencyDiscoveryMode::Disabled {
        let discovered = discover_metadata(project);
        declarations.clone_from(&discovered.declarations);
        discovered.merge_into(&mut dependencies);
    }
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return cancelled_discovery("JVM dependency discovery was cancelled");
    }
    if config.dependency_discovery.mode == JvmDependencyDiscoveryMode::OfflineBuildTools {
        discover_build_tools(project, &config.dependency_discovery).merge_into(&mut dependencies);
    }
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return cancelled_discovery("JVM dependency discovery was cancelled");
    }
    let mut metadata_inputs_considered = dependencies
        .artifact_paths
        .len()
        .saturating_add(dependencies.coordinates.len());
    let resolved = resolve_configured_artifacts(&dependencies, project.root());
    let mut resolved_coordinates = crate::hash::HashSet::default();
    for artifact in &resolved {
        if let Some(coordinate) = &artifact.coordinate {
            resolved_coordinates.insert(coordinate.clone());
        }
    }
    let mut diagnostics = Vec::new();
    for coordinate in &dependencies.coordinates {
        if !resolved_coordinates.contains(coordinate) {
            diagnostics.push(DependencyPackDiagnostic {
                severity: DependencyPackDiagnosticSeverity::Error,
                code: "jvm.dependency_unresolved".to_owned(),
                dependency_id: Some(jvm_coordinate_id(coordinate)),
                location: None,
                message: format!(
                    "exact local artifact was not found for {}",
                    jvm_coordinate_id(coordinate)
                ),
            });
        }
    }
    let mut suppressed_diagnostics = resolved.len().saturating_sub(limits.max_dependencies);
    let dependency_limit_hit = suppressed_diagnostics > 0;
    let mut resolved_artifacts = resolved;
    resolved_artifacts.truncate(limits.max_dependencies);
    let mut resolved = Vec::with_capacity(resolved_artifacts.len());
    for artifact in resolved_artifacts {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return cancelled_discovery("JVM dependency discovery was cancelled");
        }
        let declaration = artifact
            .coordinate
            .as_ref()
            .and_then(|coordinate| declarations.get(coordinate).cloned());
        let mut dependency = resolved_semantic_pack_dependency_while(artifact, cancellation);
        // A jar resolved out of a local repository proves the artifact; only a
        // build file proves the scope, so a dependency with no declaration
        // keeps `Unknown` rather than inheriting a neighbour's scope.
        if let Some(declaration) = declaration {
            dependency.scope = declaration.scope;
            dependency.declared_by = declaration.declared_by;
        }
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return cancelled_discovery("JVM dependency discovery was cancelled");
        }
        if dependency
            .provenance
            .iter()
            .any(|entry| entry.key == "kotlin.classification" && entry.value == "incomplete")
        {
            diagnostics.push(DependencyPackDiagnostic {
                severity: DependencyPackDiagnosticSeverity::Warning,
                code: "kotlin.classification_incomplete".to_owned(),
                dependency_id: Some(dependency.id.clone()),
                location: None,
                message: "bounded Kotlin metadata inspection was incomplete; the artifact was not treated as Java and requires a compatible prebuilt Kotlin pack"
                    .to_owned(),
            });
        }
        resolved.push(dependency);
    }
    let jdk_discovery = discover_jdk_semantic_pack_dependencies(
        config,
        project.root(),
        config
            .standard_library_discovery
            .discover_java_home
            .then(|| std::env::var_os("JAVA_HOME"))
            .flatten(),
    );
    metadata_inputs_considered =
        metadata_inputs_considered.saturating_add(jdk_discovery.inputs_considered);
    resolved.extend(jdk_discovery.dependencies);
    diagnostics.extend(jdk_discovery.diagnostics);
    if dependency_limit_hit {
        diagnostics.push(DependencyPackDiagnostic {
            severity: DependencyPackDiagnosticSeverity::Error,
            code: "limit.dependencies".to_owned(),
            dependency_id: None,
            location: None,
            message: format!(
                "JVM dependency discovery exceeded the configured limit {}",
                limits.max_dependencies
            ),
        });
    }
    if resolved.len() > limits.max_dependencies {
        suppressed_diagnostics =
            suppressed_diagnostics.saturating_add(resolved.len() - limits.max_dependencies);
        resolved.truncate(limits.max_dependencies);
        if !dependency_limit_hit {
            diagnostics.push(DependencyPackDiagnostic {
                severity: DependencyPackDiagnosticSeverity::Error,
                code: "limit.dependencies".to_owned(),
                dependency_id: None,
                location: None,
                message: format!(
                    "JVM dependency discovery exceeded the configured limit {}",
                    limits.max_dependencies
                ),
            });
        }
    }
    if diagnostics.len() > limits.max_diagnostics {
        suppressed_diagnostics =
            suppressed_diagnostics.saturating_add(diagnostics.len() - limits.max_diagnostics);
        diagnostics.truncate(limits.max_diagnostics);
    }
    DependencyDiscoveryOutcome {
        profile: DependencyDiscoveryProfile {
            metadata_inputs_considered,
            dependencies_resolved: resolved.len(),
        },
        dependencies: resolved,
        complete: !diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == DependencyPackDiagnosticSeverity::Error)
            && suppressed_diagnostics == 0,
        diagnostics,
        suppressed_diagnostics,
        cancelled: false,
    }
}

fn cancelled_discovery(message: &str) -> DependencyDiscoveryOutcome {
    DependencyDiscoveryOutcome {
        dependencies: Vec::new(),
        diagnostics: vec![DependencyPackDiagnostic {
            severity: DependencyPackDiagnosticSeverity::Error,
            code: "discovery.cancelled".to_owned(),
            dependency_id: None,
            location: None,
            message: message.to_owned(),
        }],
        suppressed_diagnostics: 0,
        complete: false,
        cancelled: true,
        profile: DependencyDiscoveryProfile::default(),
    }
}

fn jvm_coordinate_id(coordinate: &JvmMavenCoordinate) -> String {
    format!(
        "{}:{}:{}",
        coordinate.group_id, coordinate.artifact_id, coordinate.version
    )
}

#[derive(Debug, Default)]
struct JdkDiscovery {
    dependencies: Vec<ResolvedDependency>,
    diagnostics: Vec<DependencyPackDiagnostic>,
    inputs_considered: usize,
}

fn discover_jdk_semantic_pack_dependencies(
    config: &JvmAnalyzerConfig,
    project_root: &Path,
    java_home: Option<OsString>,
) -> JdkDiscovery {
    let mut candidates: Vec<(PathBuf, bool)> = config
        .standard_library_discovery
        .jdk_homes
        .iter()
        .map(|home| (resolve_path(project_root, home), true))
        .collect();
    if let Some(java_home) = java_home.filter(|value| !value.is_empty()) {
        candidates.push((resolve_path(project_root, Path::new(&java_home)), false));
    }

    let mut discovery = JdkDiscovery {
        inputs_considered: candidates.len(),
        ..JdkDiscovery::default()
    };
    let mut seen_homes = crate::hash::HashSet::default();
    let mut dependency_by_version = crate::hash::HashMap::default();
    for (candidate, configured) in candidates {
        let home = fs::canonicalize(&candidate).unwrap_or(candidate);
        if !seen_homes.insert(home.clone()) {
            continue;
        }
        let version = match read_jdk_release_version(&home) {
            Ok(version) => version,
            Err(message) => {
                discovery.diagnostics.push(DependencyPackDiagnostic {
                    severity: if configured {
                        DependencyPackDiagnosticSeverity::Error
                    } else {
                        DependencyPackDiagnosticSeverity::Warning
                    },
                    code: "jdk.home.invalid".to_owned(),
                    dependency_id: None,
                    location: Some(home.to_string_lossy().into_owned()),
                    message,
                });
                continue;
            }
        };
        let source = [home.join("lib").join("src.zip"), home.join("src.zip")]
            .into_iter()
            .find(|path| path.is_file());
        let dependency = if let Some(source) = source {
            resolved_jdk_dependency(version.clone(), Some(source))
        } else if configured {
            match discover_jdk_jmods(&home) {
                Ok(Some(relative_paths)) => {
                    resolved_jdk_jmod_dependency(version.clone(), home, relative_paths)
                }
                Ok(None) => resolved_jdk_dependency(version.clone(), None),
                Err(message) => {
                    discovery.diagnostics.push(DependencyPackDiagnostic {
                        severity: if configured {
                            DependencyPackDiagnosticSeverity::Error
                        } else {
                            DependencyPackDiagnosticSeverity::Warning
                        },
                        code: "jdk.jmods.invalid".to_owned(),
                        dependency_id: Some(format!("jdk:{version}")),
                        location: Some(home.to_string_lossy().into_owned()),
                        message,
                    });
                    resolved_jdk_dependency(version.clone(), None)
                }
            }
        } else {
            // Automatic JAVA_HOME discovery supplies exact toolchain evidence
            // for a released source-derived pack. Parsing a full binary JDK is
            // an explicit local-production opt-in through `jdk_homes`; doing
            // it implicitly would block ordinary Java workspace readiness.
            resolved_jdk_dependency(version.clone(), None)
        };
        match dependency_by_version.entry(version) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(discovery.dependencies.len());
                discovery.dependencies.push(dependency);
            }
            std::collections::hash_map::Entry::Occupied(entry) => {
                let existing = &discovery.dependencies[*entry.get()];
                if jdk_dependency_priority(&dependency) > jdk_dependency_priority(existing) {
                    discovery.dependencies[*entry.get()] = dependency;
                }
            }
        }
    }
    discovery
}

fn jdk_dependency_priority(dependency: &ResolvedDependency) -> u8 {
    if dependency
        .artifacts
        .iter()
        .any(|artifact| artifact.kind == ExternalArtifactKind::JdkSourceZip)
    {
        2
    } else if dependency
        .artifacts
        .iter()
        .any(|artifact| artifact.kind == ExternalArtifactKind::JdkJmodSet)
    {
        1
    } else {
        0
    }
}

fn discover_jdk_jmods(home: &Path) -> Result<Option<Vec<PathBuf>>, String> {
    let jmods = home.join("jmods");
    let metadata = match fs::symlink_metadata(&jmods) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("could not inspect JDK jmods directory: {error}")),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("JDK jmods path is not a real directory".to_owned());
    }
    let mut paths = Vec::new();
    let mut entries_seen = 0usize;
    let entries = fs::read_dir(&jmods)
        .map_err(|error| format!("could not read JDK jmods directory: {error}"))?;
    for entry in entries {
        entries_seen = entries_seen.saturating_add(1);
        if entries_seen > MAX_JDK_JMOD_FILES {
            return Err(format!(
                "JDK jmods directory contains more than {MAX_JDK_JMOD_FILES} bounded entries"
            ));
        }
        let entry = entry.map_err(|error| format!("could not read JDK jmod entry: {error}"))?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.ends_with(".jmod") {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("could not inspect JDK jmod {name}: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            continue;
        }
        paths.push(PathBuf::from("jmods").join(name));
    }
    paths.sort_unstable();
    if paths.len() > MAX_JDK_JMOD_FILES {
        return Err(format!(
            "JDK jmods directory contains more than {MAX_JDK_JMOD_FILES} bounded archives"
        ));
    }
    Ok((!paths.is_empty()).then_some(paths))
}

fn read_jdk_release_version(home: &Path) -> Result<Version, String> {
    const MAX_RELEASE_BYTES: u64 = 64 * 1024;

    let release_path = home.join("release");
    let metadata = fs::metadata(&release_path)
        .map_err(|error| format!("JDK home does not contain a readable release file: {error}"))?;
    if !metadata.is_file() || metadata.len() > MAX_RELEASE_BYTES {
        return Err("JDK release file is not a bounded regular file".to_owned());
    }
    let mut release_bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(&release_path)
        .and_then(|file| {
            file.take(MAX_RELEASE_BYTES.saturating_add(1))
                .read_to_end(&mut release_bytes)
        })
        .map_err(|error| format!("could not read JDK release file: {error}"))?;
    if release_bytes.len() as u64 > MAX_RELEASE_BYTES {
        return Err("JDK release file grew beyond the bounded read limit".to_owned());
    }
    let release = std::str::from_utf8(&release_bytes)
        .map_err(|error| format!("JDK release file is not valid UTF-8 text: {error}"))?;
    let mut values = release.lines().filter_map(|line| {
        let (key, value) = line.split_once('=')?;
        (key == "JAVA_VERSION").then_some(value.trim().trim_matches('"'))
    });
    let raw = values
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "JDK release file does not declare JAVA_VERSION".to_owned())?;
    if values.next().is_some() {
        return Err("JDK release file declares JAVA_VERSION more than once".to_owned());
    }
    Version::parse(raw).map_err(|error| {
        format!("JDK JAVA_VERSION {raw:?} is not an exact semantic version: {error}")
    })
}

fn resolved_jdk_dependency(
    version: Version,
    source_archive: Option<PathBuf>,
) -> ResolvedDependency {
    ResolvedDependency {
        id: format!("jdk:{version}"),
        evidence: SemanticModelActivationEvidence {
            language: "java".to_owned(),
            ecosystem: "jdk".to_owned(),
            package: None,
            module: None,
            toolchain: Some(CatalogCoordinate {
                name: "jdk".to_owned(),
                version: Some(version.clone()),
            }),
            target: Some("jvm".to_owned()),
            configuration: None,
            artifact_sha256: None,
        },
        provenance: vec![DependencyProvenance {
            key: "version".to_owned(),
            value: version.to_string(),
        }],
        artifacts: source_archive
            .map(|path| {
                ResolvedDependencyArtifact::file(
                    DependencyArtifactRole::Sources,
                    ExternalArtifactKind::JdkSourceZip,
                    path,
                )
            })
            .into_iter()
            .collect(),
        scope: DependencyScope::Unknown,
        declared_by: None,
    }
}

fn resolved_jdk_jmod_dependency(
    version: Version,
    home: PathBuf,
    relative_paths: Vec<PathBuf>,
) -> ResolvedDependency {
    let mut dependency = resolved_jdk_dependency(version, None);
    dependency.artifacts = vec![ResolvedDependencyArtifact::source_set(
        DependencyArtifactRole::Binary,
        ExternalArtifactKind::JdkJmodSet,
        home,
        relative_paths,
    )];
    dependency
}

impl DependencyPackAdapter for JvmDependencyPackAdapter {
    fn adapter_name(&self) -> &str {
        "bifrost-jvm-dependency"
    }

    fn adapter_version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn producer(&self) -> Producer {
        Producer {
            name: "bifrost-jvm-dependency".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    fn can_produce(&self, dependency: &ResolvedDependency) -> bool {
        !matches!(dependency.evidence.language.as_str(), "scala" | "kotlin")
            || dependency.artifacts.iter().any(|artifact| {
                artifact.kind
                    == if dependency.evidence.language == "scala" {
                        ExternalArtifactKind::ScalaSourceJar
                    } else {
                        ExternalArtifactKind::KotlinSourceJar
                    }
            })
    }

    fn produce(
        &self,
        dependency: &ResolvedDependency,
        artifacts: &[ExactDependencyArtifact],
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
    ) -> DependencyPackProduction {
        let request = jvm_dependency_production_request(dependency);
        let mut diagnostics = Vec::new();
        let mut suppressed_diagnostics = 0usize;
        let mut source_pack = None;
        let mut binary_pack = None;
        let mut partial = false;
        for artifact in artifacts {
            let mut artifact_request = request.clone();
            artifact_request.path = artifact.path().to_owned();
            artifact_request.artifact_kind = artifact.kind();
            let production = match artifact.kind() {
                ExternalArtifactKind::ScalaSourceJar => ScalaSourceJarPackProducer
                    .produce_loaded_artifact(
                        &artifact_request,
                        limits,
                        cancellation,
                        artifact.exact(),
                    ),
                ExternalArtifactKind::KotlinSourceJar => KotlinSourceJarPackProducer
                    .produce_loaded_artifact(
                        &artifact_request,
                        limits,
                        cancellation,
                        artifact.exact(),
                    ),
                ExternalArtifactKind::JavaSourceJar | ExternalArtifactKind::JavaClassJar => {
                    JavaJarPackProducer.produce_loaded_artifact(
                        &artifact_request,
                        limits,
                        cancellation,
                        artifact.exact(),
                    )
                }
                ExternalArtifactKind::JdkSourceZip => {
                    match detect_jdk_source_archive_layout(artifact.exact()) {
                        Ok(layout) => JdkSourceArchivePackProducer::new(layout)
                            .produce_loaded_artifact(
                                &artifact_request,
                                limits,
                                cancellation,
                                artifact.exact(),
                            ),
                        Err(diagnostic) => ArtifactProduction::failed(diagnostic, limits),
                    }
                }
                ExternalArtifactKind::JdkJmodSet => JdkJmodSetPackProducer.produce_loaded_artifact(
                    &artifact_request,
                    limits,
                    cancellation,
                    artifact.exact(),
                ),
                kind => ArtifactProduction::failed(
                    ProducerDiagnostic {
                        severity: ProducerDiagnosticSeverity::Error,
                        code: "artifact.kind".to_owned(),
                        location: Some(artifact.path().to_string_lossy().into_owned()),
                        declaration: None,
                        message: format!("unsupported JVM dependency artifact kind {kind:?}"),
                    },
                    limits,
                ),
            };
            debug_assert_eq!(
                production.artifact_sha256.as_deref(),
                Some(artifact.sha256())
            );
            partial |= production.completeness == Completeness::Partial;
            diagnostics.extend(production.diagnostics);
            suppressed_diagnostics =
                suppressed_diagnostics.saturating_add(production.suppressed_diagnostics);
            match (artifact.role(), production.pack) {
                (DependencyArtifactRole::Sources, Some(pack)) => source_pack = Some(pack),
                (DependencyArtifactRole::Binary, Some(mut pack)) => {
                    normalize_artifact_locator_paths(
                        &mut pack,
                        &format!("sha256-{}.artifact", artifact.sha256()),
                    );
                    binary_pack = Some(pack);
                }
                (_, Some(_)) => diagnostics.push(ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    code: "artifact.role".to_owned(),
                    location: Some(artifact.path().to_string_lossy().into_owned()),
                    declaration: None,
                    message: "JVM dependency requires binary or sources artifact roles".to_owned(),
                }),
                (_, None) => {}
            }
        }
        let pack = merge_java_dependency_packs(
            source_pack,
            binary_pack,
            &mut diagnostics,
            &mut suppressed_diagnostics,
            limits,
        );
        let mut pack = pack;
        if let Some(pack) = pack.as_mut() {
            pack.producer = self.producer();
            if partial || !diagnostics.is_empty() || suppressed_diagnostics > 0 {
                pack.completeness = Completeness::Partial;
            }
        }
        DependencyPackProduction {
            pack,
            diagnostics,
            suppressed_diagnostics,
        }
    }
}

#[cfg(test)]
fn resolved_semantic_pack_dependency(artifact: ResolvedJvmArtifact) -> ResolvedDependency {
    resolved_semantic_pack_dependency_while(artifact, None)
}

fn resolved_semantic_pack_dependency_while(
    artifact: ResolvedJvmArtifact,
    cancellation: Option<&CancellationToken>,
) -> ResolvedDependency {
    let scala_library = artifact
        .coordinate
        .as_ref()
        .is_some_and(is_scala_library_coordinate);
    let source_path = if is_source_jar(&artifact.artifact_path) {
        Some(artifact.artifact_path.as_path())
    } else {
        artifact.source_artifact_path.as_deref()
    };
    let kotlin_source = source_path
        .map(|path| classify_kotlin_source(path, cancellation))
        .unwrap_or(KotlinArchiveClassification::Absent);
    let kotlin_binary = if kotlin_source == KotlinArchiveClassification::Present
        || is_source_jar(&artifact.artifact_path)
    {
        KotlinArchiveClassification::Absent
    } else {
        classify_kotlin_metadata(&artifact.artifact_path, cancellation)
    };
    let kotlin_stdlib = artifact
        .coordinate
        .as_ref()
        .is_some_and(is_kotlin_stdlib_coordinate);
    let kotlin = kotlin_source != KotlinArchiveClassification::Absent
        || kotlin_binary != KotlinArchiveClassification::Absent
        || kotlin_stdlib;
    let kotlin_classification_incomplete = !kotlin_stdlib
        && kotlin_source != KotlinArchiveClassification::Present
        && kotlin_binary != KotlinArchiveClassification::Present
        && (kotlin_source == KotlinArchiveClassification::Incomplete
            || kotlin_binary == KotlinArchiveClassification::Incomplete);
    let coordinate_id = artifact.coordinate.as_ref().map(|coordinate| {
        format!(
            "{}:{}:{}",
            coordinate.group_id, coordinate.artifact_id, coordinate.version
        )
    });
    let id = coordinate_id.unwrap_or_else(|| {
        format!(
            "explicit:{}",
            artifact
                .artifact_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
        )
    });
    let ecosystem = if scala_library || kotlin_stdlib {
        "maven"
    } else {
        match artifact.origin {
            JvmDependencyOrigin::MavenReport | JvmDependencyOrigin::MavenRepository => "maven",
            JvmDependencyOrigin::GradleReport | JvmDependencyOrigin::GradleCache => "gradle",
            JvmDependencyOrigin::ExplicitPath => "jvm",
        }
    };
    let package = artifact
        .coordinate
        .as_ref()
        .map(|coordinate| CatalogCoordinate {
            name: format!("{}:{}", coordinate.group_id, coordinate.artifact_id),
            version: Version::parse(&coordinate.version).ok(),
        });
    let mut provenance = vec![DependencyProvenance {
        key: "origin".to_owned(),
        value: jvm_dependency_origin_name(artifact.origin).to_owned(),
    }];
    if let Some(coordinate) = &artifact.coordinate {
        provenance.extend([
            DependencyProvenance {
                key: "group".to_owned(),
                value: coordinate.group_id.clone(),
            },
            DependencyProvenance {
                key: "artifact".to_owned(),
                value: coordinate.artifact_id.clone(),
            },
            DependencyProvenance {
                key: "version".to_owned(),
                value: coordinate.version.clone(),
            },
        ]);
    }
    if kotlin_classification_incomplete {
        provenance.push(DependencyProvenance {
            key: "kotlin.classification".to_owned(),
            value: "incomplete".to_owned(),
        });
    }
    let source_kind = if scala_library {
        ExternalArtifactKind::ScalaSourceJar
    } else if kotlin {
        ExternalArtifactKind::KotlinSourceJar
    } else {
        ExternalArtifactKind::JavaSourceJar
    };
    let artifacts = if is_source_jar(&artifact.artifact_path) {
        vec![ResolvedDependencyArtifact::file(
            DependencyArtifactRole::Sources,
            source_kind,
            artifact.artifact_path,
        )]
    } else if (scala_library || kotlin) && artifact.source_artifact_path.is_some() {
        vec![ResolvedDependencyArtifact::file(
            DependencyArtifactRole::Sources,
            source_kind,
            artifact
                .source_artifact_path
                .expect("source path was checked above"),
        )]
    } else {
        let mut artifacts = vec![ResolvedDependencyArtifact::file(
            DependencyArtifactRole::Binary,
            ExternalArtifactKind::JavaClassJar,
            artifact.artifact_path,
        )];
        if let Some(source_artifact_path) = artifact.source_artifact_path {
            artifacts.push(ResolvedDependencyArtifact::file(
                DependencyArtifactRole::Sources,
                source_kind,
                source_artifact_path,
            ));
        }
        artifacts
    };
    ResolvedDependency {
        id,
        evidence: SemanticModelActivationEvidence {
            language: if scala_library {
                "scala"
            } else if kotlin {
                "kotlin"
            } else {
                "java"
            }
            .to_owned(),
            ecosystem: ecosystem.to_owned(),
            package,
            module: (artifact.origin == JvmDependencyOrigin::ExplicitPath).then(|| {
                CatalogCoordinate {
                    name: "local-jvm-artifact".to_owned(),
                    version: None,
                }
            }),
            toolchain: (scala_library || kotlin_stdlib).then(|| CatalogCoordinate {
                name: if scala_library { "scala" } else { "kotlin" }.to_owned(),
                version: artifact
                    .coordinate
                    .as_ref()
                    .and_then(|coordinate| Version::parse(&coordinate.version).ok()),
            }),
            target: Some("jvm".to_owned()),
            configuration: None,
            artifact_sha256: None,
        },
        provenance,
        artifacts,
        scope: DependencyScope::Unknown,
        declared_by: None,
    }
}

fn is_scala_library_coordinate(coordinate: &JvmMavenCoordinate) -> bool {
    coordinate.group_id == "org.scala-lang"
        && matches!(
            coordinate.artifact_id.as_str(),
            "scala-library" | "scala3-library_3"
        )
}

fn is_kotlin_stdlib_coordinate(coordinate: &JvmMavenCoordinate) -> bool {
    coordinate.group_id == "org.jetbrains.kotlin"
        && matches!(
            coordinate.artifact_id.as_str(),
            "kotlin-stdlib" | "kotlin-stdlib-common" | "kotlin-stdlib-jdk7" | "kotlin-stdlib-jdk8"
        )
}

fn jvm_dependency_origin_name(origin: JvmDependencyOrigin) -> &'static str {
    match origin {
        JvmDependencyOrigin::ExplicitPath => "explicit_path",
        JvmDependencyOrigin::MavenReport => "maven_report",
        JvmDependencyOrigin::GradleReport => "gradle_report",
        JvmDependencyOrigin::MavenRepository => "maven_repository",
        JvmDependencyOrigin::GradleCache => "gradle_cache",
    }
}

fn jvm_dependency_production_request(dependency: &ResolvedDependency) -> ArtifactProductionRequest {
    ArtifactProductionRequest {
        path: PathBuf::new(),
        artifact_kind: ExternalArtifactKind::JavaClassJar,
        pack_id: format!("bifrost.external.{}", dependency.evidence.language),
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
            source: "exact local JVM dependency".to_owned(),
            revision: None,
        },
        license: "NOASSERTION".to_owned(),
        safety: Safety {
            generated_code_only: false,
            review_required: false,
        },
    }
}

fn merge_java_dependency_packs(
    source: Option<AuthoredSemanticModelPack>,
    binary: Option<AuthoredSemanticModelPack>,
    diagnostics: &mut Vec<ProducerDiagnostic>,
    suppressed_diagnostics: &mut usize,
    limits: &ArtifactProducerLimits,
) -> Option<AuthoredSemanticModelPack> {
    let (mut pack, secondary) = match (source, binary) {
        (Some(source), binary) => (source, binary),
        (None, Some(binary)) => (binary, None),
        (None, None) => return None,
    };
    let Some(secondary) = secondary else {
        return Some(pack);
    };
    let Some(primary_shard) = pack.shards.first_mut() else {
        return Some(pack);
    };
    let AuthoredPayload::DeclarationFacts {
        types,
        members,
        relations,
    } = &mut primary_shard.payload
    else {
        return Some(pack);
    };
    let mut type_indexes: HashMap<String, usize> = types
        .iter()
        .enumerate()
        .map(|(index, fact)| (fact.id.clone(), index))
        .collect();
    let mut member_indexes: HashMap<String, usize> = members
        .iter()
        .enumerate()
        .map(|(index, fact)| (fact.id.clone(), index))
        .collect();
    let mut relation_ids: crate::hash::HashSet<String> =
        relations.iter().map(|fact| fact.id.clone()).collect();
    for shard in secondary.shards {
        let AuthoredPayload::DeclarationFacts {
            types: secondary_types,
            members: secondary_members,
            relations: secondary_relations,
        } = shard.payload
        else {
            continue;
        };
        for fact in secondary_types {
            if let Some(index) = type_indexes.get(&fact.id).copied() {
                if !equivalent_java_type_fact(&types[index], &fact) {
                    push_java_merge_conflict(diagnostics, suppressed_diagnostics, limits, &fact.id);
                }
            } else {
                type_indexes.insert(fact.id.clone(), types.len());
                types.push(fact);
            }
        }
        for fact in secondary_members {
            if let Some(index) = member_indexes.get(&fact.id).copied() {
                if !equivalent_java_member_fact(&members[index], &fact) {
                    push_java_merge_conflict(diagnostics, suppressed_diagnostics, limits, &fact.id);
                }
            } else {
                member_indexes.insert(fact.id.clone(), members.len());
                members.push(fact);
            }
        }
        for fact in secondary_relations {
            if relation_ids.insert(fact.id.clone()) {
                relations.push(fact);
            }
        }
    }
    Some(pack)
}

fn equivalent_java_type_fact(left: &TypeFact, right: &TypeFact) -> bool {
    left.id == right.id
        && left.name == right.name
        && left.type_kind == right.type_kind
        && left.visibility == right.visibility
        && left.is_abstract == right.is_abstract
        && left.is_sealed == right.is_sealed
        && left.type_parameters == right.type_parameters
        && left.hierarchy == right.hierarchy
        && left.aliases == right.aliases
        && left.extension_surfaces == right.extension_surfaces
}

fn equivalent_java_member_fact(left: &MemberFact, right: &MemberFact) -> bool {
    left.id == right.id
        && left.owner == right.owner
        && left.name == right.name
        && left.member_kind == right.member_kind
        && left.visibility == right.visibility
        && left.is_static == right.is_static
        && left.is_abstract == right.is_abstract
        && left.is_virtual == right.is_virtual
        && left.signature == right.signature
        && left.aliases == right.aliases
}

fn push_java_merge_conflict(
    diagnostics: &mut Vec<ProducerDiagnostic>,
    suppressed_diagnostics: &mut usize,
    limits: &ArtifactProducerLimits,
    declaration_id: &str,
) {
    if diagnostics.len() < limits.max_diagnostics {
        diagnostics.push(ProducerDiagnostic {
            severity: ProducerDiagnosticSeverity::Warning,
            code: "java.source_binary_conflict".to_owned(),
            location: Some(declaration_id.to_owned()),
            declaration: None,
            message: "source and binary facts disagree; deterministic source facts were kept"
                .to_owned(),
        });
    } else {
        *suppressed_diagnostics = (*suppressed_diagnostics).saturating_add(1);
    }
}

impl JvmExternalDeclarationIndex {
    #[cfg(test)]
    pub(crate) fn build(config: &JvmExternalDependencies, project_root: &Path) -> Self {
        let artifacts = resolve_configured_artifacts(config, project_root);
        Self::build_from_artifacts(artifacts)
    }

    pub(crate) fn build_for_project(config: &JvmAnalyzerConfig, project: &dyn Project) -> Self {
        let discovery = resolve_jvm_semantic_pack_dependencies(
            config,
            project,
            &DependencyPackLimits::default(),
            None,
        );
        let artifacts = discovery
            .dependencies
            .iter()
            .filter_map(jvm_artifact_from_dependency)
            .collect();
        let mut index = Self::build_from_artifacts(artifacts);
        index.production_diagnostics.extend(
            discovery
                .diagnostics
                .into_iter()
                .map(discovery_producer_diagnostic),
        );
        index
    }

    fn build_from_artifacts(artifacts: Vec<ResolvedJvmArtifact>) -> Self {
        let mut index = Self::default();
        let mut remaining_index_bytes = MAX_TOTAL_INDEX_BYTES;
        for artifact in artifacts.into_iter().take(MAX_INDEX_ARTIFACTS) {
            if remaining_index_bytes == 0 {
                break;
            }
            if is_source_jar(&artifact.artifact_path) {
                remaining_index_bytes = remaining_index_bytes.saturating_sub(
                    index.index_source_jar(&artifact.artifact_path, remaining_index_bytes),
                );
                continue;
            }
            if let Some(source_artifact_path) = artifact.source_artifact_path.as_deref() {
                remaining_index_bytes = remaining_index_bytes.saturating_sub(
                    index.index_source_jar(source_artifact_path, remaining_index_bytes),
                );
            }
            if remaining_index_bytes == 0 {
                break;
            }
            remaining_index_bytes = remaining_index_bytes.saturating_sub(
                index.index_class_jar(&artifact.artifact_path, remaining_index_bytes),
            );
        }
        index.apply_enclosing_visibility();
        index
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.types_by_fqn.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn production_diagnostics(&self) -> &[ProducerDiagnostic] {
        &self.production_diagnostics
    }

    /// How many diagnostics the artifact producers raised while this index was
    /// built.
    ///
    /// A non-zero count means the build declared JVM artifacts that the index
    /// could not read to the end -- an archive past `MAX_ARCHIVE_ENTRIES`, a
    /// class past `MAX_CLASS_ENTRY_BYTES`, an artifact set past
    /// `MAX_INDEX_ARTIFACTS`. It is the difference between "this name is not
    /// declared anywhere" and "this name may well be declared in a dependency
    /// nothing finished indexing", which is exactly the boundary distinction a
    /// resolution trace must report. The full diagnostics stay test-only; a
    /// count is all a boundary classification needs.
    pub(crate) fn production_diagnostic_count(&self) -> usize {
        self.production_diagnostics.len()
    }

    /// Stable identity of every retained fact that can change external JVM
    /// dispatch behavior.
    ///
    /// Artifact paths and archive entry names are intentionally absent. Once
    /// an artifact has produced this surface, moving identical bytes does not
    /// change any resolver answer and should continue to reuse cached flow
    /// results. A single incomplete marker captures the only diagnostic state
    /// the resolution boundary observes: whether any producer diagnostic made
    /// a negative lookup uncertain.
    pub(crate) fn dispatch_behavior_identity(&self) -> StableDigest {
        *self.dispatch_behavior_identity.get_or_init(|| {
            let mut digest = LengthDelimitedDigest::new(JVM_EXTERNAL_DISPATCH_BEHAVIOR_DOMAIN);
            digest.push(if self.production_diagnostics.is_empty() {
                b"complete"
            } else {
                b"incomplete"
            });

            let mut types = self.types_by_fqn.iter().collect::<Vec<_>>();
            types.sort_unstable_by_key(|(fqn, _)| *fqn);
            digest.push(&(types.len() as u64).to_le_bytes());
            for (lookup_fqn, external_type) in types {
                digest.push(b"type");
                digest.push(lookup_fqn.as_bytes());
                digest.push(external_type.fqn.as_bytes());
                digest.push(external_type.package_name.as_bytes());
                digest.push(external_type.short_name.as_bytes());
                digest.push(match external_type.kind {
                    JvmExternalTypeKind::Class => b"class",
                    JvmExternalTypeKind::Interface => b"interface",
                    JvmExternalTypeKind::Enum => b"enum",
                    JvmExternalTypeKind::Annotation => b"annotation",
                    JvmExternalTypeKind::Record => b"record",
                });
                digest.push(match external_type.visibility {
                    JvmVisibility::Public => b"public",
                    JvmVisibility::Protected => b"protected",
                    JvmVisibility::PackagePrivate => b"package-private",
                    JvmVisibility::Private => b"private",
                });
            }

            let mut owners = self.members_by_owner.iter().collect::<Vec<_>>();
            owners.sort_unstable_by_key(|(owner, _)| *owner);
            digest.push(&(owners.len() as u64).to_le_bytes());
            for (owner_fqn, surface) in owners {
                digest.push(b"owner");
                digest.push(owner_fqn.as_bytes());
                digest.push(&(surface.supertypes.len() as u64).to_le_bytes());
                for supertype in &surface.supertypes {
                    digest.push(b"supertype");
                    digest.push(supertype.as_bytes());
                }

                let mut members = surface.members.iter().collect::<Vec<_>>();
                members.sort_unstable_by_key(|(name, _)| *name);
                digest.push(&(members.len() as u64).to_le_bytes());
                for (lookup_name, member) in members {
                    digest.push(b"member");
                    digest.push(lookup_name.as_bytes());
                    digest.push(member.fqn.as_bytes());
                    digest.push(member.declaring_package.as_bytes());
                    digest.push(match member.visibility {
                        JvmVisibility::Public => b"public",
                        JvmVisibility::Protected => b"protected",
                        JvmVisibility::PackagePrivate => b"package-private",
                        JvmVisibility::Private => b"private",
                    });
                    match member.declared_return_type_fqn() {
                        Some(return_type) => {
                            digest.push(b"named-return");
                            digest.push(return_type.as_bytes());
                        }
                        None => digest.push(b"no-named-return"),
                    }
                    digest.push(if member.is_static {
                        b"static"
                    } else {
                        b"instance"
                    });
                    digest.push(if member.is_constant {
                        b"constant"
                    } else {
                        b"not-constant"
                    });
                }
            }
            digest.finish()
        })
    }

    pub(crate) fn get(&self, fqn: &str) -> Option<&JvmExternalType> {
        self.types_by_fqn.get(fqn)
    }

    /// The member `member_name` names on the indexed owner `owner_fqn`,
    /// searched over the owner's whole read inherited surface (#1900).
    ///
    /// The walk starts at the owner and follows the supertypes its own artifact
    /// entry named, breadth first, because a JVM member is as often inherited
    /// as declared: a static factory sits on the class the reference wrote
    /// while an accessor sits on the base class it extends, and a reference
    /// spells both the same way. The declaration that answers keeps its own
    /// qualified name and its own declaring package, so the reported target
    /// names where the member is declared rather than where it was written,
    /// and package-private accessibility measures against the right package.
    ///
    /// An owner with no read surface, and a supertype whose own class file was
    /// never read, both contribute nothing rather than proving anything: this
    /// returns `None` for "not declared here" and for "never read" alike, and a
    /// caller that finds nothing keeps the status it had.
    fn member(&self, owner_fqn: &str, member_name: &str) -> Option<&JvmExternalMember> {
        let mut visited = crate::hash::HashSet::default();
        let mut queue = std::collections::VecDeque::new();
        visited.insert(owner_fqn.to_owned());
        queue.push_back(owner_fqn.to_owned());
        let mut walked = 0usize;
        while let Some(owner) = queue.pop_front() {
            walked = walked.saturating_add(1);
            if walked > MAX_MEMBER_SURFACE_OWNERS {
                return None;
            }
            let Some(surface) = self.members_by_owner.get(&owner) else {
                continue;
            };
            if let Some(member) = surface.members.get(member_name) {
                return Some(member);
            }
            for supertype in &surface.supertypes {
                if visited.insert(supertype.clone()) {
                    queue.push_back(supertype.clone());
                }
            }
        }
        None
    }

    pub(crate) fn resolve_explicit_import(
        &self,
        import_path: &str,
        access_package: &str,
    ) -> Option<&JvmExternalType> {
        self.get(import_path)
            .filter(|ty| ty.is_accessible_from_package(access_package))
    }

    pub(crate) fn resolve_wildcard_import(
        &self,
        package_name: &str,
        short_name: &str,
        access_package: &str,
    ) -> Option<&JvmExternalType> {
        self.get(&qualified_name(package_name, short_name))
            .filter(|ty| ty.is_accessible_from_package(access_package))
    }

    pub(crate) fn resolve_same_package(
        &self,
        package_name: &str,
        short_name: &str,
    ) -> Option<&JvmExternalType> {
        self.get(&qualified_name(package_name, short_name))
            .filter(|ty| ty.is_accessible_from_package(package_name))
    }

    pub(crate) fn resolve_java_lang(&self, short_name: &str) -> Option<&JvmExternalType> {
        self.get(&qualified_name("java.lang", short_name))
            .filter(|ty| ty.visibility == JvmVisibility::Public)
    }

    pub(crate) fn resolve_qualified_name(
        &self,
        fqn: &str,
        access_package: &str,
    ) -> Option<&JvmExternalType> {
        self.get(fqn)
            .filter(|ty| ty.is_accessible_from_package(access_package))
    }

    fn insert(&mut self, external_type: JvmExternalType) {
        match self.types_by_fqn.get(&external_type.fqn) {
            Some(existing)
                if matches!(
                    existing.source,
                    JvmExternalDeclarationSource::SourceJar { .. }
                ) =>
            {
                return;
            }
            _ => {}
        }
        self.types_by_fqn
            .insert(external_type.fqn.clone(), external_type);
    }

    fn apply_enclosing_visibility(&mut self) {
        let updates: Vec<_> = self
            .types_by_fqn
            .values()
            .filter_map(|external_type| {
                let mut effective_visibility = external_type.visibility;
                for owner_fqn in enclosing_type_fqns(external_type) {
                    let Some(owner) = self.types_by_fqn.get(&owner_fqn) else {
                        continue;
                    };
                    effective_visibility =
                        restrict_visibility(effective_visibility, owner.visibility);
                }
                (effective_visibility != external_type.visibility)
                    .then(|| (external_type.fqn.clone(), effective_visibility))
            })
            .collect();

        for (fqn, visibility) in updates {
            if let Some(external_type) = self.types_by_fqn.get_mut(&fqn) {
                external_type.visibility = visibility;
            }
        }
    }

    fn index_source_jar(&mut self, artifact_path: &Path, index_byte_budget: u64) -> u64 {
        let Some(file) = open_artifact_file(artifact_path) else {
            return 0;
        };
        let Ok(mut archive) = ZipArchive::new(file) else {
            return 0;
        };
        let entry_count = archive.len().min(MAX_ARCHIVE_ENTRIES);
        let mut total_bytes = 0u64;
        let mut java_facts = None;
        let mut scala_indexed = false;
        let mut skipped_entries = archive.len().saturating_sub(entry_count);
        let mut member_budget = MemberBudget::new();
        for index in 0..entry_count {
            let Ok(entry) = archive.by_index(index) else {
                skipped_entries = skipped_entries.saturating_add(1);
                continue;
            };
            let Some(language) = SourceJarLanguage::for_entry(entry.name()) else {
                continue;
            };
            let max_entry_bytes = language.max_entry_bytes();
            if !can_read_entry(
                entry.size(),
                max_entry_bytes,
                MAX_TOTAL_ARCHIVE_BYTES.min(index_byte_budget),
                &mut total_bytes,
            ) {
                skipped_entries = skipped_entries.saturating_add(1);
                continue;
            }
            if matches!(language, SourceJarLanguage::Scala) {
                if !scala_indexed {
                    let mut facts = self
                        .produce_scala_type_facts(artifact_path)
                        .into_values()
                        .collect::<Vec<_>>();
                    facts.sort_unstable_by(|left, right| left.name.cmp(&right.name));
                    for fact in facts.into_iter().take(MAX_ANALYZER_SOURCE_TYPES) {
                        if let Some(external_type) = scala_external_type(artifact_path, fact) {
                            self.insert(external_type);
                        }
                    }
                    scala_indexed = true;
                }
                continue;
            }
            let source_path = entry.name().to_string();
            let mut source = String::new();
            if entry
                .take(max_entry_bytes + 1)
                .read_to_string(&mut source)
                .is_err()
                || source.len() as u64 > max_entry_bytes
            {
                skipped_entries = skipped_entries.saturating_add(1);
                continue;
            }
            let external_types = language.source_types(artifact_path, &source_path, &source);
            if matches!(language, SourceJarLanguage::Java) && java_facts.is_none() {
                java_facts = Some(
                    self.produce_java_facts(artifact_path, ExternalArtifactKind::JavaSourceJar),
                );
            }
            for mut external_type in external_types {
                if let Some(facts) = java_facts.as_mut() {
                    if let Some(fact) = facts.types.get(&external_type.fqn) {
                        apply_java_type_fact(&mut external_type, fact);
                    }
                    // The entry that declares this type was read to the end, so
                    // its member surface may answer.
                    let surface = facts.take_owner_surface(
                        &external_type.fqn,
                        &external_type.package_name,
                        &mut member_budget,
                    );
                    self.attach_member_surface(&external_type.fqn, surface);
                }
                self.insert(external_type);
            }
        }
        self.note_bounded_artifact(artifact_path, skipped_entries, member_budget);
        total_bytes
    }

    fn index_class_jar(&mut self, artifact_path: &Path, index_byte_budget: u64) -> u64 {
        let Some(file) = open_artifact_file(artifact_path) else {
            return 0;
        };
        let Ok(mut archive) = ZipArchive::new(file) else {
            return 0;
        };
        let entry_count = archive.len().min(MAX_ARCHIVE_ENTRIES);
        let mut total_bytes = 0u64;
        let mut skipped_entries = archive.len().saturating_sub(entry_count);
        let mut member_budget = MemberBudget::new();
        let producer_limits = ArtifactProducerLimits::default();
        let mut producer_diagnostics =
            crate::analyzer::semantic_model::BoundedProducerDiagnostics::new(&producer_limits);
        let mut remaining_records = producer_limits.max_records;
        let mut record_limit_hit = false;
        for index in 0..entry_count {
            let Ok(entry) = archive.by_index(index) else {
                skipped_entries = skipped_entries.saturating_add(1);
                continue;
            };
            if !entry.name().ends_with(".class") || entry.name().ends_with("module-info.class") {
                continue;
            }
            if !can_read_entry(
                entry.size(),
                MAX_CLASS_ENTRY_BYTES,
                MAX_TOTAL_ARCHIVE_BYTES.min(index_byte_budget),
                &mut total_bytes,
            ) {
                skipped_entries = skipped_entries.saturating_add(1);
                continue;
            }
            let class_entry = entry.name().to_string();
            let mut bytes = Vec::new();
            if entry
                .take(MAX_CLASS_ENTRY_BYTES + 1)
                .read_to_end(&mut bytes)
                .is_err()
                || bytes.len() as u64 > MAX_CLASS_ENTRY_BYTES
            {
                skipped_entries = skipped_entries.saturating_add(1);
                continue;
            }
            let surface = match class_surface(
                artifact_path.to_string_lossy().as_ref(),
                &class_entry,
                &bytes,
                producer_limits.max_signature_depth,
                &mut remaining_records,
                &mut record_limit_hit,
                &mut producer_diagnostics,
            ) {
                JavaClassSurfaceOutcome::Declared(surface) => surface,
                // A module descriptor and a private class were read
                // completely; the index publishes neither on purpose, and
                // neither leaves anything unread.
                JavaClassSurfaceOutcome::Excluded => continue,
                // The producer could not parse this class file, so it declares
                // no type here and, just as importantly, no member surface that
                // could later answer a member spelling negatively.
                JavaClassSurfaceOutcome::Invalid => {
                    producer_diagnostics.warning(
                        "java.class.invalid",
                        Some(class_entry.clone()),
                        "class entry did not contain supported bounded metadata",
                    );
                    skipped_entries = skipped_entries.saturating_add(1);
                    continue;
                }
                // The bounded producer record limit was spent. It is reported
                // below as `limit.records`; do not misclassify an intentional
                // bound as an unread archive entry.
                JavaClassSurfaceOutcome::Skipped => continue,
            };

            let short_name = surface
                .name
                .strip_prefix(&format!("{}.", surface.package_name))
                .unwrap_or(&surface.name)
                .to_owned();
            let external_type = JvmExternalType {
                fqn: surface.name.clone(),
                package_name: surface.package_name.clone(),
                short_name,
                kind: semantic_type_kind(surface.type_kind),
                visibility: semantic_visibility(surface.visibility),
                source: JvmExternalDeclarationSource::ClassFile {
                    artifact_path: artifact_path.to_path_buf(),
                    class_entry: class_entry.clone(),
                },
            };
            if external_type.visibility == JvmVisibility::Private {
                continue;
            }
            // This entry was read to the end and parsed, so the members the
            // same class file declares are a surface that may answer (#1900).
            let mut members = HashMap::default();
            for member in surface.members {
                if !member_budget.take() {
                    break;
                }
                let is_static = member.is_static;
                let is_constant = member.member_kind == MemberKind::Constant;
                members
                    .entry(member.name.clone())
                    .or_insert_with(|| JvmExternalMember {
                        fqn: qualified_name(&external_type.fqn, &member.name),
                        declaring_package: external_type.package_name.clone(),
                        visibility: semantic_visibility(member.visibility),
                        // The class file's member table is what types a chained
                        // receiver (#2454), so this path carries the declared
                        // return type exactly as `take_owner_surface` does for
                        // the pack-production path. Dropping it here made the
                        // same jar answer `response.getWriter()` on one path and
                        // not on the other, which measurably retired the whole
                        // chained-receiver census on the OWASP corpus.
                        returns: member.returns,
                        // The class file's access flags are what prove a
                        // `static final` field is a compile-time constant
                        // (#2538); dropping them here would make the same
                        // class file answer a `Cipher.ENCRYPT_MODE`-shaped
                        // read on the pack-production path and not on this
                        // one, the same asymmetry #2454's comment above
                        // describes for return types.
                        is_static,
                        is_constant,
                    });
            }
            self.attach_member_surface(
                &external_type.fqn,
                JvmIndexedOwnerSurface {
                    members,
                    supertypes: hierarchy_type_names(&surface.hierarchy),
                },
            );
            self.insert(external_type);
        }
        if record_limit_hit {
            producer_diagnostics.warning(
                "limit.records",
                None,
                format!(
                    "producer stopped after {} declaration records",
                    producer_limits.max_records
                ),
            );
        }
        let (diagnostics, _) = producer_diagnostics.finish();
        self.production_diagnostics.extend(diagnostics);
        self.note_bounded_artifact(artifact_path, skipped_entries, member_budget);
        total_bytes
    }

    /// Record the member surface an owner's own artifact entry declared.
    ///
    /// Only ever called for an owner whose entry was read to the end, which is
    /// what gives the presence of an entry in `members_by_owner` its meaning.
    fn attach_member_surface(&mut self, owner_fqn: &str, surface: JvmIndexedOwnerSurface) {
        match self.members_by_owner.get_mut(owner_fqn) {
            // One owner can be read twice -- a binary jar beside its own
            // source jar, or two artifacts shipping the same class. Merging
            // keeps every positive declaration either read produced, which is
            // the only direction this surface ever moves.
            Some(existing) => {
                for (name, member) in surface.members {
                    existing.members.entry(name).or_insert(member);
                }
                for supertype in surface.supertypes {
                    if !existing.supertypes.contains(&supertype) {
                        existing.supertypes.push(supertype);
                    }
                }
            }
            None => {
                self.members_by_owner.insert(owner_fqn.to_owned(), surface);
            }
        }
    }

    /// Record that one artifact was not read to the end.
    ///
    /// This is the honest-absence link for the member surface: an entry the
    /// byte budget refused, an entry that did not parse, and a member set past
    /// [`MAX_ARTIFACT_MEMBERS`] all leave declarations unread, and every JVM
    /// boundary already reads [`Self::production_diagnostic_count`] to report
    /// `external_declared_unindexed` -- "the build declared this and nothing
    /// finished reading it" -- instead of `external_unknown`. One diagnostic
    /// per artifact keeps the record bounded no matter how many entries an
    /// artifact skipped.
    fn note_bounded_artifact(
        &mut self,
        artifact_path: &Path,
        skipped_entries: usize,
        member_budget: MemberBudget,
    ) {
        if skipped_entries > 0 {
            self.production_diagnostics.push(ProducerDiagnostic {
                severity: ProducerDiagnosticSeverity::Warning,
                code: "jvm.index.unread_entries".to_owned(),
                location: Some(artifact_path.to_string_lossy().into_owned()),
                declaration: None,
                message: format!(
                    "bounded index read skipped {skipped_entries} archive entries, so this artifact declares types and members the index never read"
                ),
            });
        }
        if member_budget.exhausted {
            self.production_diagnostics.push(ProducerDiagnostic {
                severity: ProducerDiagnosticSeverity::Warning,
                code: "limit.artifact_members".to_owned(),
                location: Some(artifact_path.to_string_lossy().into_owned()),
                declaration: None,
                message: format!(
                    "bounded index read stopped after {MAX_ARTIFACT_MEMBERS} member declarations from this artifact"
                ),
            });
        }
    }

    fn produce_java_facts(
        &mut self,
        artifact_path: &Path,
        artifact_kind: ExternalArtifactKind,
    ) -> JavaArtifactFacts {
        let production = JavaJarPackProducer.produce_exact_artifact(
            &ArtifactProductionRequest {
                path: artifact_path.to_path_buf(),
                artifact_kind,
                pack_id: "bifrost.external.java".to_owned(),
                pack_version: env!("CARGO_PKG_VERSION").to_owned(),
                ecosystem: "maven".to_owned(),
                compatibility: Compatibility {
                    bifrost: format!("={}", env!("CARGO_PKG_VERSION")),
                    toolchains: Vec::new(),
                },
                activation: vec![ActivationSelector {
                    package: None,
                    module: None,
                    toolchain: Some(NameSelector {
                        name: "jvm".to_owned(),
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
        let mut types = HashMap::default();
        let mut members = Vec::new();
        for shard in production.pack.into_iter().flat_map(|pack| pack.shards) {
            let AuthoredPayload::DeclarationFacts {
                types: shard_types,
                members: shard_members,
                ..
            } = shard.payload
            else {
                continue;
            };
            types.extend(
                shard_types
                    .into_iter()
                    .map(|fact| (fact.name.clone(), fact)),
            );
            members.extend(shard_members);
        }
        JavaArtifactFacts::new(types, members)
    }

    fn produce_scala_type_facts(&mut self, artifact_path: &Path) -> HashMap<String, TypeFact> {
        let production = ScalaSourceJarPackProducer.produce_exact_artifact(
            &ArtifactProductionRequest {
                path: artifact_path.to_path_buf(),
                artifact_kind: ExternalArtifactKind::ScalaSourceJar,
                pack_id: "bifrost.external.scala".to_owned(),
                pack_version: env!("CARGO_PKG_VERSION").to_owned(),
                ecosystem: "maven".to_owned(),
                compatibility: Compatibility {
                    bifrost: format!("={}", env!("CARGO_PKG_VERSION")),
                    toolchains: Vec::new(),
                },
                activation: vec![ActivationSelector {
                    package: None,
                    module: None,
                    toolchain: Some(NameSelector {
                        name: "jvm".to_owned(),
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
        production
            .pack
            .into_iter()
            .flat_map(|pack| pack.shards)
            .flat_map(|shard| match shard.payload {
                AuthoredPayload::DeclarationFacts { types, .. } => types,
                AuthoredPayload::GeneratorRules { .. }
                | AuthoredPayload::ProcedureSummaries { .. } => Vec::new(),
            })
            .map(|fact| (fact.name.clone(), fact))
            .collect()
    }
}

/// Feeds [`JvmExternalDeclarationIndex::build_from_artifacts`]: raw
/// class-file/`-sources.jar` byte scanning (`index_class_jar`,
/// `index_source_jar`) over an ordinary Maven/Gradle dependency's resolved
/// jar(s).
///
/// A JDK dependency's own artifact is a `src.zip` or JMOD source set
/// (`ExternalArtifactKind::JdkSourceZip`/`JdkJmodSet`, built by
/// [`resolved_jdk_dependency`]
/// from `JAVA_HOME`/`jdk_homes`), and this function excludes it
/// unconditionally. This is deliberate, not an oversight, for two independent
/// reasons:
///
/// 1. Structurally, this index could not read it correctly even if let
///    through: `is_source_jar` only recognizes a `-sources.jar` filename
///    suffix (false for `src.zip`), and `index_class_jar` expects `.class`
///    entries (none exist in a source archive), so the raw-byte path silently
///    produces zero facts for it either way.
/// 2. Architecturally, a JDK source archive already has its own producer,
///    `JdkSourceArchivePackProducer` (dispatched from
///    `JvmDependencyPackAdapter::produce`, above), which turns the same
///    `src.zip` into a proper declaration-fact semantic pack. That pack
///    reaches resolution through the pack-activation pipeline
///    (`prepare_dependency_semantic_packs` / `activate_workspace_packs`, or a
///    caller's own hand-curated `SemanticModelActivationRequest`, as
///    `owasp_benchmark.rs` uses), never through this artifact index. Routing
///    the same `src.zip` through both would double-produce and diverge from
///    that pack's own completeness/gap accounting (#2401).
///
/// Confirmed twice independently: #2538's investigation (see that issue's
/// ExecPlan, `.agents/plans/issue-2538-external-constants.md`, "Surprises &
/// Discoveries") found this exclusion by tracing why `java.util.Locale`/
/// `javax.crypto.Cipher` never resolved through this index, and #2401's own
/// session (this repository, 2026-08-21) re-confirmed it while evaluating
/// whether to lift it. Do not lift this exclusion; if a JDK dependency ever
/// needs to resolve here too, give it a real conversion from the pack's own
/// `TypeFact`/`MemberFact` shards (`apply_java_type_fact` already exists for
/// half of that), not a change to this filter.
fn jvm_artifact_from_dependency(dependency: &ResolvedDependency) -> Option<ResolvedJvmArtifact> {
    if dependency.artifacts.iter().any(|artifact| {
        matches!(
            artifact.kind,
            ExternalArtifactKind::JdkSourceZip | ExternalArtifactKind::JdkJmodSet
        )
    }) {
        return None;
    }
    let binary = dependency
        .artifacts
        .iter()
        .find(|artifact| artifact.role == DependencyArtifactRole::Binary);
    let source = dependency
        .artifacts
        .iter()
        .find(|artifact| artifact.role == DependencyArtifactRole::Sources);
    let primary = binary.or(source)?;
    Some(ResolvedJvmArtifact {
        artifact_path: primary.path().to_owned(),
        source_artifact_path: binary.and(source).map(|source| source.path().to_owned()),
        coordinate: None,
        origin: JvmDependencyOrigin::ExplicitPath,
    })
}

fn discovery_producer_diagnostic(diagnostic: DependencyPackDiagnostic) -> ProducerDiagnostic {
    ProducerDiagnostic {
        severity: match diagnostic.severity {
            DependencyPackDiagnosticSeverity::Warning => ProducerDiagnosticSeverity::Warning,
            DependencyPackDiagnosticSeverity::Error => ProducerDiagnosticSeverity::Error,
        },
        code: diagnostic.code,
        location: diagnostic.location,
        declaration: None,
        message: diagnostic.message,
    }
}

fn apply_java_type_fact(external_type: &mut JvmExternalType, fact: &TypeFact) {
    external_type.kind = semantic_type_kind(fact.type_kind);
    external_type.visibility = semantic_visibility(fact.visibility);
}

fn scala_external_type(artifact_path: &Path, fact: TypeFact) -> Option<JvmExternalType> {
    let source_path = match fact.locator {
        Locator::Source { path, .. } => path,
        Locator::Artifact { .. } => return None,
    };
    let name = fact.name;
    let (package_name, short_name) = name
        .rsplit_once('.')
        .map_or(("", name.as_str()), |(package, short)| (package, short));
    (!short_name.is_empty()).then(|| JvmExternalType {
        fqn: name.clone(),
        package_name: package_name.to_owned(),
        short_name: short_name.to_owned(),
        kind: semantic_type_kind(fact.type_kind),
        visibility: semantic_visibility(fact.visibility),
        source: JvmExternalDeclarationSource::SourceJar {
            artifact_path: artifact_path.to_path_buf(),
            source_path,
        },
    })
}

fn semantic_type_kind(kind: TypeKind) -> JvmExternalTypeKind {
    match kind {
        TypeKind::Interface | TypeKind::Trait => JvmExternalTypeKind::Interface,
        TypeKind::Enum => JvmExternalTypeKind::Enum,
        TypeKind::Annotation => JvmExternalTypeKind::Annotation,
        TypeKind::Record => JvmExternalTypeKind::Record,
        TypeKind::Class
        | TypeKind::Delegate
        | TypeKind::Struct
        | TypeKind::Union
        | TypeKind::Module
        | TypeKind::TypeAlias => JvmExternalTypeKind::Class,
    }
}

fn semantic_visibility(visibility: Visibility) -> JvmVisibility {
    match visibility {
        Visibility::Public => JvmVisibility::Public,
        Visibility::Protected | Visibility::ProtectedInternal => JvmVisibility::Protected,
        Visibility::Package | Visibility::Internal => JvmVisibility::PackagePrivate,
        Visibility::Private => JvmVisibility::Private,
    }
}

/// The manifest languages whose declaration facts answer a JVM name.
///
/// Java, Kotlin and Scala compile to one classpath, so a pack that declares a
/// type for any of them declares it for all three. A pack for any other
/// language never answers here, so activating a Python or npm pack cannot
/// upgrade a JVM reference.
const JVM_PACK_LANGUAGES: [&str; 3] = ["java", "kotlin", "scala"];

/// The external declaration surface one JVM lookup reads: the artifact-derived
/// index first, then the declaration facts the activated semantic packs
/// publish (#1893).
///
/// Both halves answer the same question -- does an external declaration spell
/// this name, and may this package see it -- so they are one lookup with one
/// precedence, not two indexes with two vocabularies. The artifact half wins a
/// tie: an artifact on disk is the classpath the build actually resolved, while
/// a pack is a published claim about one.
///
/// The name may be a type's or a member's. Both halves carry member
/// declarations (#1900): the index reads them out of the member tables of the
/// class files it indexes, and a pack publishes them as declaration facts, so
/// `Collections.sort` is answered by whichever half declared the owner.
///
/// # Why the pack half is read live
///
/// [`JvmExternalDeclarationIndex`] is memoized in an analyzer `OnceLock` that
/// survives across activation transactions: a host activates, invalidates and
/// re-activates packs while one analyzer generation stays alive, and only a
/// changed build manifest drops the cell. Folding pack facts into that cell
/// would therefore answer from a pack set the host has since replaced or
/// withdrawn. This surface instead reads the published overlay on every
/// lookup, so it always reports the currently activated set and cannot go
/// stale. The read is a published `Arc` clone plus one hash lookup, which is
/// the same cost the other seven languages already pay for their overlay-backed
/// boundary evidence.
pub(crate) struct JvmExternalDeclarations<'a> {
    artifacts: &'a JvmExternalDeclarationIndex,
    packs: Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
}

impl<'a> JvmExternalDeclarations<'a> {
    pub(crate) fn new(
        artifacts: &'a JvmExternalDeclarationIndex,
        packs: Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
    ) -> Self {
        Self { artifacts, packs }
    }

    /// Whether no surface can answer anything, so a caller may skip the ladder
    /// altogether.
    pub(crate) fn is_empty(&self) -> bool {
        self.artifacts.is_empty() && self.packs.is_none()
    }

    pub(crate) fn get(&self, fqn: &str) -> Option<JvmExternalType> {
        if let Some(external_type) = self.artifacts.get(fqn) {
            return Some(external_type.clone());
        }
        self.pack_declaration(fqn)
    }

    pub(crate) fn resolve_explicit_import(
        &self,
        import_path: &str,
        access_package: &str,
    ) -> Option<JvmExternalType> {
        self.resolve_qualified_name(import_path, access_package)
    }

    pub(crate) fn resolve_wildcard_import(
        &self,
        package_name: &str,
        short_name: &str,
        access_package: &str,
    ) -> Option<JvmExternalType> {
        self.resolve_qualified_name(&qualified_name(package_name, short_name), access_package)
    }

    pub(crate) fn resolve_same_package(
        &self,
        package_name: &str,
        short_name: &str,
    ) -> Option<JvmExternalType> {
        self.resolve_qualified_name(&qualified_name(package_name, short_name), package_name)
    }

    pub(crate) fn resolve_java_lang(&self, short_name: &str) -> Option<JvmExternalType> {
        self.get(&qualified_name("java.lang", short_name))
            .filter(|external_type| external_type.visibility == JvmVisibility::Public)
    }

    pub(crate) fn resolve_qualified_name(
        &self,
        fqn: &str,
        access_package: &str,
    ) -> Option<JvmExternalType> {
        self.get(fqn)
            .filter(|external_type| external_type.is_accessible_from_package(access_package))
    }

    /// The external member a written `Owner.member` spelling names (#1900).
    ///
    /// A reference-site spelling that crosses a `.` is one written name whose
    /// head is a type and whose last segment is a member: `Collections.sort`
    /// spells the `sort` member of `java.util.Collections`. The head is
    /// resolved by `resolve_owner`, which is the caller's own type ladder --
    /// Java's import tiers, Kotlin's name scope, Scala's import tiers -- so a
    /// member spelling reaches the same owner a type spelling would.
    ///
    /// Only a spelling the type ladder has already failed to answer belongs
    /// here. A nested type is spelled with the same dot, and its declaration is
    /// a type, so it is decided by the type ladder before this runs.
    ///
    /// Both halves answer here, in the same precedence the type half uses: the
    /// artifact-derived member surface first, then the activated packs'. The
    /// owner decides which half can even speak, because an owner is resolved
    /// once and carries where it came from -- an owner the jar index declared
    /// has an artifact member surface and no pack declaration id, and a
    /// pack-declared owner the reverse -- so "artifacts win ties" is settled by
    /// the owner lookup rather than by a second race here.
    ///
    /// A miss is never a proof of absence. The surface reports what it
    /// declares; a caller that finds nothing keeps the status it had, so a type
    /// whose pack declares no members, and a type whose class file the bounded
    /// index never read, both leave every member spelling exactly as unknown as
    /// it was before.
    pub(crate) fn resolve_member_spelling(
        &self,
        spelling: &str,
        access_package: &str,
        resolve_owner: impl FnOnce(&str) -> Option<JvmExternalType>,
    ) -> Option<JvmExternalMember> {
        let (owner_spelling, member_name) = spelling.trim().rsplit_once('.')?;
        if owner_spelling.is_empty() || member_name.is_empty() {
            return None;
        }
        let owner = resolve_owner(owner_spelling)?;
        self.artifact_member(&owner, member_name)
            .or_else(|| self.pack_member(&owner, member_name))
            .filter(|member| member.is_accessible_from_package(access_package))
    }

    /// The member the indexed artifacts declare on `owner` (#1900).
    ///
    /// Only an artifact-declared owner has an artifact member surface, for the
    /// same reason [`Self::pack_member`] refuses a non-pack owner: the surface
    /// is keyed by the identity the half that read it produced. An owner the
    /// jar index never read has no entry at all, which is why a miss here is
    /// silence rather than a negative answer.
    fn artifact_member(
        &self,
        owner: &JvmExternalType,
        member_name: &str,
    ) -> Option<JvmExternalMember> {
        match owner.source {
            JvmExternalDeclarationSource::SourceJar { .. }
            | JvmExternalDeclarationSource::ClassFile { .. } => {
                self.artifacts.member(&owner.fqn, member_name).cloned()
            }
            JvmExternalDeclarationSource::SemanticPack { .. } => None,
        }
    }

    /// The one declaration the activated packs publish for `fqn`, if exactly
    /// one does.
    ///
    /// `symbols_named` also posts every symbol under its simple name, so a bare
    /// `Collections` would otherwise match `java.util.Collections` and let any
    /// dependency type that happens to share a short name answer a JVM name.
    /// The caller has already walked its own import tiers to produce a
    /// qualified spelling, so only the qualified postings count: the declared
    /// name, and the aliases, which are qualified too. This is the same rule
    /// `JvmOverlayModel::qualified_name_disposition` applies on the
    /// proof-gated diagnostic side, so a trace, a definition and a diagnostic
    /// read one activated set the same way.
    fn pack_declaration(&self, fqn: &str) -> Option<JvmExternalType> {
        let overlay = self.packs.as_ref()?;
        let mut declarations = overlay
            .symbols_named(fqn)
            .records
            .into_iter()
            .filter(|symbol| {
                symbol.qualified_name == fqn || symbol.aliases.iter().any(|alias| alias == fqn)
            })
            .filter_map(pack_external_type);
        let declared = declarations.next()?;
        // Two activated packs claiming one qualified name is ambiguity, not a
        // declaration: the name exists but which declaration it denotes is not
        // decided, so no single external type can be reported. Reporting none
        // understates what is known and never overstates it.
        declarations.next().is_none().then_some(declared)
    }

    /// The member an activated pack publishes on `owner`, searched over the
    /// owner's whole inherited surface.
    ///
    /// The surface is the closure `SemanticModelOverlay::owner_surface` builds,
    /// because a JVM member is as often inherited as declared: `sort` sits on
    /// `java.util.Collections` while `toString` sits on `java.lang.Object`, and
    /// a reference spells both the same way. The declaration that answers keeps
    /// its own qualified name, so the reported target names where the member is
    /// declared rather than where it was written.
    ///
    /// More than one hit is the ordinary shape of an override or an overload --
    /// a class and the interface it implements both declare the method, and
    /// `sort(List)` and `sort(List, Comparator)` are two declarations of one
    /// name -- so it is not ambiguity. Only a declaration an indexed pack itself
    /// flagged ambiguous is, which is the same rule PHP's external surface
    /// applies.
    ///
    /// Staticness and arity are deliberately not filtered on. The question this
    /// surface answers is whether an external declaration spells the name, not
    /// whether the written use of it compiles: the workspace member tier does
    /// not refuse a static member written through an instance either, and a
    /// Scala `object` or Kotlin companion member is published without the
    /// static flag a Java static carries.
    fn pack_member(&self, owner: &JvmExternalType, member_name: &str) -> Option<JvmExternalMember> {
        let overlay = self.packs.as_ref()?;
        // Only a pack-declared owner has a pack member surface: an artifact
        // owner carries no declaration identity to look members up by.
        let JvmExternalDeclarationSource::SemanticPack { declaration_id, .. } = &owner.source
        else {
            return None;
        };
        let owner_symbol = overlay
            .symbols_with_id(declaration_id)
            .records
            .first()
            .copied()?;
        let surface = overlay.owner_surface(owner_symbol);
        surface.closure.iter().find_map(|declaring| {
            let member = overlay
                .members_of(&declaring.id)
                .records
                .into_iter()
                .find(|symbol| {
                    symbol.name == member_name
                        && !symbol.provenance.ambiguous
                        && JVM_PACK_LANGUAGES.contains(&symbol.language.as_str())
                })?;
            Some(JvmExternalMember {
                fqn: member.qualified_name.clone(),
                // The package split is the one [`pack_external_type`] makes on
                // a type's declared name, taken from the declaring type rather
                // than from the type the reference wrote.
                declaring_package: declaring
                    .qualified_name
                    .rsplit_once('.')
                    .map_or("", |(package, _)| package)
                    .to_owned(),
                visibility: semantic_visibility(member.visibility),
                returns: member
                    .structured_signature
                    .as_ref()
                    .and_then(|signature| signature.returns.clone()),
                // Carried for parity with the artifact-derived member surface
                // (#2538). The doc comment above already warns that a Scala
                // `object` or Kotlin companion member is published without
                // the static flag a Java `static` carries, so a caller that
                // needs a *proof* of compile-time-constant-ness (not merely
                // "declared const-shaped") must not rely on this half alone
                // for those languages; [`JvmExternalMember::is_compile_time_constant`]
                // requires both flags together and fails closed if either is
                // under-reported.
                is_static: member.is_static,
                is_constant: member.kind
                    == crate::analyzer::semantic_model::SemanticModelSymbolKind::Constant,
            })
        })
    }
}

/// One member an external declaration surface declares on an external type
/// (#1900): the `sort` of `Collections.sort`, not the `Collections`.
///
/// Both halves produce this same shape -- the jar index reads it out of a
/// class file's member table, an activated pack reads it out of a declaration
/// fact -- so one lookup answers a member spelling whichever half declared it.
///
/// A member is not a type, so it is not a [`JvmExternalType`]: nothing may
/// resolve a type name to it, and [`pack_type_kind`] rejects every member kind
/// precisely so that cannot happen. What a member shares with a type is the
/// question a boundary asks -- does an external declaration spell this name,
/// and may this package see it -- so it carries exactly what answers that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JvmExternalMember {
    fqn: String,
    /// The package of the type that *declares* the member, which is what
    /// `protected` and package-private accessibility are measured against. An
    /// inherited member is declared in its own supertype's package, not in the
    /// package of the type the reference wrote.
    declaring_package: String,
    visibility: JvmVisibility,
    /// The type the declaration writes as this member's return type, exactly as
    /// the declaring half recorded it. `None` means the declaration wrote none
    /// -- a field, a constructor, a `void` method, or a member surface whose
    /// signature the producer did not record -- which is not a claim that the
    /// member returns nothing a caller can name.
    ///
    /// Overloads share one entry per written name in the artifact half, so this
    /// is the return type of the *first* declaration read for that name. That is
    /// the same "overloads are one name, not ambiguity" rule
    /// [`JvmIndexedOwnerSurface`] already applies to the member itself.
    returns: Option<TypeRef>,
    /// Whether the declaring half marked this member `static` (#2538).
    is_static: bool,
    /// Whether the declaring half classified this member as a compile-time
    /// constant: for the JVM class-file half, exactly a field whose access
    /// flags carry both `ACC_STATIC` and `ACC_FINAL`
    /// (`MemberKind::Constant`, set by `class_field_member`); for an
    /// activated pack, `SemanticModelSymbolKind::Constant` (#2538).
    ///
    /// This is a separate signal from [`Self::is_static`] rather than the
    /// whole story on its own: a caller that needs "provably a compile-time
    /// constant" should require both, so a producer that ever set one flag
    /// without the other fails closed instead of over-claiming.
    is_constant: bool,
}

impl JvmExternalMember {
    pub(crate) fn fqn(&self) -> &str {
        &self.fqn
    }

    /// The fully-qualified name of the class this member's declaration says it
    /// returns (#2454).
    ///
    /// This is what types a *chained* receiver: `response.getWriter()` has no
    /// written type anywhere in the reading file, but the declaration surface
    /// that declares `getWriter` also writes down that it returns
    /// `java.io.PrintWriter`.
    ///
    /// It fails closed, in the same direction as every other tier of the
    /// receiver ladder. Only a `Named` return type names a class a member
    /// lookup can continue from; a type variable, a wildcard, an array, a
    /// pointer and every other structured form name no single declaration, so
    /// they answer nothing and the call keeps the identity-free boundary it had.
    /// A primitive return spells a `Named` type no external surface declares, so
    /// it fails at the next rung rather than here.
    pub(crate) fn declared_return_type_fqn(&self) -> Option<&str> {
        match self.returns.as_ref()? {
            TypeRef::Named { name, .. } if !name.is_empty() => Some(name),
            _ => None,
        }
    }

    fn is_accessible_from_package(&self, package_name: &str) -> bool {
        is_visible_from_package(self.visibility, &self.declaring_package, package_name)
    }

    /// Whether the declaring half marked this member `static` (#2538).
    pub(crate) fn is_static(&self) -> bool {
        self.is_static
    }

    /// Whether this member is provably a compile-time constant: `static`
    /// *and* classified `MemberKind::Constant`/`SemanticModelSymbolKind::Constant`
    /// by whichever half declared it (#2538).
    ///
    /// A field the class-file half classifies `MemberKind::Constant` is,
    /// by construction, a field whose access flags carry both `ACC_STATIC`
    /// and `ACC_FINAL` -- read straight off the real class file, not
    /// inferred -- so a caller may treat a read of such a field as carrying
    /// no attacker-influenced value flow (Java Language Specification
    /// compile-time-constant semantics for a `static final` field). Requiring
    /// both flags here, rather than trusting `is_constant` alone, means a
    /// producer that only ever set one of the two still fails closed.
    pub(crate) fn is_compile_time_constant(&self) -> bool {
        self.is_static && self.is_constant
    }
}

/// One activated pack symbol as the JVM realm's external declaration, when the
/// symbol is a JVM type at all.
///
/// The package and short name are split out of the declared qualified name
/// exactly as the pack-fact producers in this module already do
/// ([`scala_external_type`]), because a declaration fact carries one dotted
/// name and no separate package field.
fn pack_external_type(
    symbol: &crate::analyzer::semantic_model::SemanticModelSymbol,
) -> Option<JvmExternalType> {
    if !JVM_PACK_LANGUAGES.contains(&symbol.language.as_str()) {
        return None;
    }
    let kind = pack_type_kind(symbol.kind)?;
    let (package_name, short_name) = symbol
        .qualified_name
        .rsplit_once('.')
        .map_or(("", symbol.qualified_name.as_str()), |(package, short)| {
            (package, short)
        });
    (!short_name.is_empty()).then(|| JvmExternalType {
        fqn: symbol.qualified_name.clone(),
        package_name: package_name.to_owned(),
        short_name: short_name.to_owned(),
        kind,
        visibility: semantic_visibility(symbol.visibility),
        source: JvmExternalDeclarationSource::SemanticPack {
            pack_id: symbol.provenance.pack_id.clone(),
            declaration_id: symbol.id.clone(),
        },
    })
}

/// The JVM type shape an overlay symbol kind denotes, or `None` when the
/// symbol is not a type a JVM reference can name.
///
/// The overlay keeps the pack's declared kind, so this is the inverse of the
/// [`semantic_type_kind`] mapping the artifact producers use, narrowed to the
/// kinds that exist on a classpath. Members, macros and namespace scaffolds
/// are not type names; a Kotlin `typealias` is a source-level alias with no
/// class of its own.
fn pack_type_kind(
    kind: crate::analyzer::semantic_model::SemanticModelSymbolKind,
) -> Option<JvmExternalTypeKind> {
    use crate::analyzer::semantic_model::SemanticModelSymbolKind as Kind;

    match kind {
        Kind::Class | Kind::Struct => Some(JvmExternalTypeKind::Class),
        Kind::Interface | Kind::Trait => Some(JvmExternalTypeKind::Interface),
        Kind::Enum => Some(JvmExternalTypeKind::Enum),
        Kind::Annotation => Some(JvmExternalTypeKind::Annotation),
        Kind::Record => Some(JvmExternalTypeKind::Record),
        Kind::Delegate
        | Kind::Union
        | Kind::Module
        | Kind::TypeAlias
        | Kind::Constructor
        | Kind::Method
        | Kind::Function
        | Kind::Field
        | Kind::Property
        | Kind::Constant
        | Kind::Static
        | Kind::Macro
        | Kind::Event => None,
    }
}

/// A source language Bifrost can read out of a published `-sources.jar`.
///
/// All three compile to the same classpath, so one archive walk feeds one
/// index. They differ only in how much budget an entry gets and which parser
/// turns it into declarations.
#[derive(Clone, Copy)]
enum SourceJarLanguage {
    Java,
    Scala,
    Kotlin,
}

impl SourceJarLanguage {
    fn for_entry(entry_name: &str) -> Option<Self> {
        if entry_name.ends_with(".java") {
            Some(Self::Java)
        } else if entry_name.ends_with(".scala") {
            Some(Self::Scala)
        } else if entry_name.ends_with(".kt") {
            Some(Self::Kotlin)
        } else {
            // `.kts` build scripts are packaged into some source jars but
            // declare no library API, so they are deliberately skipped.
            None
        }
    }

    fn max_entry_bytes(self) -> u64 {
        match self {
            Self::Java => MAX_SOURCE_ENTRY_BYTES,
            // Scala and Kotlin entries run the language's whole declaration
            // walk rather than Java's targeted class-like scan, so they get a
            // tighter per-entry budget.
            Self::Scala | Self::Kotlin => MAX_ANALYZER_SOURCE_ENTRY_BYTES,
        }
    }

    fn source_types(
        self,
        artifact_path: &Path,
        source_path: &str,
        source: &str,
    ) -> Vec<JvmExternalType> {
        match self {
            Self::Java => source_types(artifact_path, source_path, source),
            Self::Scala => unreachable!("Scala source JARs are indexed from semantic pack facts"),
            Self::Kotlin => kotlin_source_types(artifact_path, source_path, source),
        }
    }
}

#[allow(dead_code)]
impl JvmExternalType {
    pub(crate) fn package_name(&self) -> &str {
        &self.package_name
    }

    pub(crate) fn short_name(&self) -> &str {
        &self.short_name
    }

    pub(crate) fn kind(&self) -> JvmExternalTypeKind {
        self.kind
    }

    pub(crate) fn visibility(&self) -> JvmVisibility {
        self.visibility
    }

    pub(crate) fn source(&self) -> &JvmExternalDeclarationSource {
        &self.source
    }

    pub(crate) fn fqn(&self) -> &str {
        &self.fqn
    }

    fn is_accessible_from_package(&self, package_name: &str) -> bool {
        is_visible_from_package(self.visibility, &self.package_name, package_name)
    }
}

/// Whether a declaration of `visibility` sitting in `declaring_package` is
/// visible to code compiled in `access_package`.
///
/// One rule for types and members, because the JVM applies one: a `protected`
/// declaration is also visible to a subtype, which this deliberately does not
/// admit, so the answer understates what is reachable and never overstates it.
fn is_visible_from_package(
    visibility: JvmVisibility,
    declaring_package: &str,
    access_package: &str,
) -> bool {
    visibility == JvmVisibility::Public
        || (matches!(
            visibility,
            JvmVisibility::Protected | JvmVisibility::PackagePrivate
        ) && declaring_package == access_package)
}

fn open_artifact_file(path: &Path) -> Option<File> {
    let metadata = path.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > MAX_ARTIFACT_BYTES {
        return None;
    }
    File::open(path).ok()
}

fn can_read_entry(
    entry_size: u64,
    max_entry_bytes: u64,
    max_total_bytes: u64,
    total_bytes: &mut u64,
) -> bool {
    if entry_size > max_entry_bytes {
        return false;
    }
    let Some(next_total) = total_bytes.checked_add(entry_size) else {
        return false;
    };
    if next_total > max_total_bytes {
        return false;
    }
    *total_bytes = next_total;
    true
}

fn resolve_configured_artifacts(
    config: &JvmExternalDependencies,
    project_root: &Path,
) -> Vec<ResolvedJvmArtifact> {
    let mut artifacts = Vec::new();
    for artifact in &config.artifact_paths {
        artifacts.push(resolve_explicit_artifact(artifact, project_root));
    }

    let repository_roots = repository_roots(config);
    let gradle_cache_roots = gradle_cache_roots(config);
    for coordinate in &config.coordinates {
        let mut resolved = false;
        for root in &repository_roots {
            if let Some(artifact) = resolve_coordinate(root, coordinate) {
                artifacts.push(artifact);
                resolved = true;
                break;
            }
        }
        if !resolved {
            for root in &gradle_cache_roots {
                let gradle_artifacts = resolve_gradle_coordinate(root, coordinate);
                if !gradle_artifacts.is_empty() {
                    artifacts.extend(gradle_artifacts);
                    break;
                }
            }
        }
    }

    let mut seen = crate::hash::HashSet::default();
    artifacts.retain(|artifact| {
        seen.insert((
            artifact.artifact_path.clone(),
            artifact.source_artifact_path.clone(),
        ))
    });
    artifacts
}

fn resolve_explicit_artifact(
    artifact: &JvmExternalArtifact,
    project_root: &Path,
) -> ResolvedJvmArtifact {
    ResolvedJvmArtifact {
        artifact_path: resolve_path(project_root, &artifact.artifact_path),
        source_artifact_path: artifact
            .source_artifact_path
            .as_ref()
            .map(|path| resolve_path(project_root, path)),
        coordinate: artifact.coordinate.clone(),
        origin: match artifact.origin {
            JvmExternalArtifactOrigin::Explicit => JvmDependencyOrigin::ExplicitPath,
            JvmExternalArtifactOrigin::MavenReport => JvmDependencyOrigin::MavenReport,
            JvmExternalArtifactOrigin::GradleReport => JvmDependencyOrigin::GradleReport,
        },
    }
}

fn resolve_coordinate(
    repository_root: &Path,
    coordinate: &JvmMavenCoordinate,
) -> Option<ResolvedJvmArtifact> {
    if !is_safe_maven_coordinate(coordinate) {
        return None;
    }

    let repository_root = repository_root.canonicalize().ok()?;
    let mut directory = repository_root.clone();
    for segment in coordinate.group_id.split('.') {
        directory.push(segment);
    }
    directory.push(&coordinate.artifact_id);
    directory.push(&coordinate.version);

    let jar_name = format!("{}-{}.jar", coordinate.artifact_id, coordinate.version);
    let sources_name = format!(
        "{}-{}-sources.jar",
        coordinate.artifact_id, coordinate.version
    );
    let artifact_path = canonical_file_under(&repository_root, &directory.join(jar_name))?;
    if !artifact_path.is_file() {
        return None;
    }
    let source_artifact_path =
        canonical_file_under(&repository_root, &directory.join(sources_name));
    Some(ResolvedJvmArtifact {
        artifact_path,
        source_artifact_path,
        coordinate: Some(coordinate.clone()),
        origin: JvmDependencyOrigin::MavenRepository,
    })
}

fn is_safe_maven_coordinate(coordinate: &JvmMavenCoordinate) -> bool {
    !coordinate.group_id.is_empty()
        && coordinate
            .group_id
            .split('.')
            .all(is_safe_maven_path_segment)
        && is_safe_maven_path_segment(&coordinate.artifact_id)
        && is_safe_maven_path_segment(&coordinate.version)
}

fn is_safe_maven_path_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && !segment.contains('/')
        && !segment.contains('\\')
}

fn canonical_file_under(root: &Path, path: &Path) -> Option<PathBuf> {
    let canonical = path.canonicalize().ok()?;
    canonical.starts_with(root).then_some(canonical)
}

fn is_source_jar(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with("-sources.jar"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KotlinArchiveClassification {
    Present,
    Absent,
    Incomplete,
}

fn classification_archive(
    path: &Path,
    cancellation: Option<&CancellationToken>,
) -> Result<ZipArchive<Cursor<Vec<u8>>>, KotlinArchiveClassification> {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return Err(KotlinArchiveClassification::Incomplete);
    }
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => return Err(KotlinArchiveClassification::Incomplete),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(KotlinArchiveClassification::Absent);
        }
        Err(_) => return Err(KotlinArchiveClassification::Incomplete),
    }
    let limits = ArtifactProducerLimits {
        max_artifact_bytes: MAX_ARTIFACT_BYTES,
        ..ArtifactProducerLimits::default()
    };
    let artifact = read_exact_artifact_while(path, &limits, || {
        cancellation.is_some_and(CancellationToken::is_cancelled)
    })
    .map_err(|_| KotlinArchiveClassification::Incomplete)?;
    match zip_directory_status(artifact.bytes()) {
        ZipDirectoryStatus::Valid => {}
        ZipDirectoryStatus::Invalid | ZipDirectoryStatus::Exceeded => {
            return Err(KotlinArchiveClassification::Incomplete);
        }
    }
    ZipArchive::new(Cursor::new(artifact.into_bytes()))
        .map_err(|_| KotlinArchiveClassification::Incomplete)
}

fn classify_kotlin_source(
    path: &Path,
    cancellation: Option<&CancellationToken>,
) -> KotlinArchiveClassification {
    let mut archive = match classification_archive(path, cancellation) {
        Ok(archive) => archive,
        Err(classification) => return classification,
    };
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return KotlinArchiveClassification::Incomplete;
    }
    for index in 0..archive.len() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return KotlinArchiveClassification::Incomplete;
        }
        let Ok(entry) = archive.by_index(index) else {
            return KotlinArchiveClassification::Incomplete;
        };
        if entry.name().ends_with(".kt") {
            return KotlinArchiveClassification::Present;
        }
    }
    KotlinArchiveClassification::Absent
}

fn classify_kotlin_metadata(
    path: &Path,
    cancellation: Option<&CancellationToken>,
) -> KotlinArchiveClassification {
    const MAX_CLASSIFICATION_CLASSES: usize = 1_024;
    const MAX_CLASSIFICATION_BYTES: u64 = 32 * 1024 * 1024;

    let mut archive = match classification_archive(path, cancellation) {
        Ok(archive) => archive,
        Err(classification) => return classification,
    };
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return KotlinArchiveClassification::Incomplete;
    }
    let mut classes_read = 0usize;
    let mut bytes_read = 0u64;
    let mut incomplete = false;
    for index in 0..archive.len() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return KotlinArchiveClassification::Incomplete;
        }
        let Ok(mut entry) = archive.by_index(index) else {
            incomplete = true;
            continue;
        };
        if !entry.name().ends_with(".class") || entry.name().ends_with("module-info.class") {
            continue;
        }
        if classes_read == MAX_CLASSIFICATION_CLASSES
            || bytes_read.saturating_add(entry.size()) > MAX_CLASSIFICATION_BYTES
        {
            return KotlinArchiveClassification::Incomplete;
        }
        if entry.size() > MAX_CLASS_ENTRY_BYTES {
            incomplete = true;
            continue;
        }
        classes_read += 1;
        bytes_read = bytes_read.saturating_add(entry.size());
        let mut bytes = Vec::with_capacity(entry.size() as usize);
        if entry
            .by_ref()
            .take(MAX_CLASS_ENTRY_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .is_err()
            || bytes.len() as u64 > MAX_CLASS_ENTRY_BYTES
        {
            incomplete = true;
            continue;
        }
        let Ok(class_file) = jclassfile::class_file::parse(&bytes) else {
            incomplete = true;
            continue;
        };
        if class_file.attributes().iter().any(|attribute| {
            let annotations = match attribute {
                Attribute::RuntimeVisibleAnnotations { annotations, .. }
                | Attribute::RuntimeInvisibleAnnotations { annotations } => annotations,
                _ => return false,
            };
            annotations.iter().any(|annotation| {
                matches!(
                    class_file
                        .constant_pool()
                        .get(annotation.type_index() as usize),
                    Some(ConstantPool::Utf8 { value }) if value == "Lkotlin/Metadata;"
                )
            })
        }) {
            return KotlinArchiveClassification::Present;
        }
    }
    if incomplete {
        KotlinArchiveClassification::Incomplete
    } else {
        KotlinArchiveClassification::Absent
    }
}

fn repository_roots(config: &JvmExternalDependencies) -> Vec<PathBuf> {
    if !config.repository_roots.is_empty() {
        return config.repository_roots.clone();
    }

    home_dir()
        .map(|home| vec![home.join(".m2").join("repository")])
        .unwrap_or_default()
}

fn gradle_cache_roots(config: &JvmExternalDependencies) -> Vec<PathBuf> {
    if !config.gradle_cache_roots.is_empty() {
        return config.gradle_cache_roots.clone();
    }

    std::env::var_os("GRADLE_USER_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .map(|root| root.join("caches").join("modules-2").join("files-2.1"))
        .or_else(|| {
            home_dir().map(|home| {
                home.join(".gradle")
                    .join("caches")
                    .join("modules-2")
                    .join("files-2.1")
            })
        })
        .into_iter()
        .collect()
}

fn resolve_gradle_coordinate(
    cache_root: &Path,
    coordinate: &JvmMavenCoordinate,
) -> Vec<ResolvedJvmArtifact> {
    if !is_safe_maven_coordinate(coordinate) {
        return Vec::new();
    }
    let Ok(cache_root) = cache_root.canonicalize() else {
        return Vec::new();
    };
    let coordinate_directory = cache_root
        .join(&coordinate.group_id)
        .join(&coordinate.artifact_id)
        .join(&coordinate.version);
    let Ok(hash_directories) = coordinate_directory.read_dir() else {
        return Vec::new();
    };

    let mut jars = Vec::new();
    for hash_directory in hash_directories.filter_map(Result::ok) {
        let Ok(file_type) = hash_directory.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let Ok(entries) = hash_directory.path().read_dir() else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.extension().is_none_or(|extension| extension != "jar") {
                continue;
            }
            let Some(path) = canonical_file_under(&cache_root, &path) else {
                continue;
            };
            if path.is_file() {
                jars.push(path);
            }
        }
    }
    jars.sort();
    jars.dedup();

    let expected_binary = format!("{}-{}.jar", coordinate.artifact_id, coordinate.version);
    let expected_sources = format!(
        "{}-{}-sources.jar",
        coordinate.artifact_id, coordinate.version
    );
    let sources = jars
        .iter()
        .find(|path| {
            path.file_name()
                .is_some_and(|name| name == expected_sources.as_str())
        })
        .cloned();
    let exact_binaries: Vec<_> = jars
        .iter()
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name == expected_binary.as_str())
        })
        .cloned()
        .collect();
    let binaries = exact_binaries;
    if binaries.is_empty() {
        return sources
            .into_iter()
            .map(|artifact_path| ResolvedJvmArtifact {
                artifact_path,
                source_artifact_path: None,
                coordinate: Some(coordinate.clone()),
                origin: JvmDependencyOrigin::GradleCache,
            })
            .collect();
    }
    binaries
        .into_iter()
        .map(|artifact_path| ResolvedJvmArtifact {
            artifact_path,
            source_artifact_path: sources.clone(),
            coordinate: Some(coordinate.clone()),
            origin: JvmDependencyOrigin::GradleCache,
        })
        .collect()
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
        })
}

fn resolve_path(project_root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        project_root.join(path)
    }
}

fn source_types(artifact_path: &Path, source_path: &str, source: &str) -> Vec<JvmExternalType> {
    let Some(tree) = parse_tree(source) else {
        return Vec::new();
    };
    let root = tree.root_node();
    let package_name = determine_package_name(root, source);
    let mut result = Vec::new();
    let mut stack = Vec::new();
    for index in (0..root.named_child_count()).rev() {
        let Some(child) = root.named_child(index) else {
            continue;
        };
        if is_class_like_declaration_kind(child.kind()) {
            stack.push((
                child,
                None::<String>,
                None::<JvmVisibility>,
                JvmVisibility::PackagePrivate,
            ));
        }
    }

    while let Some((node, parent_short_name, parent_visibility, default_visibility)) = stack.pop() {
        let Some(name_node) = node.child_by_field_name("name") else {
            continue;
        };
        let simple_name = node_text(name_node, source).trim();
        if simple_name.is_empty() {
            continue;
        }

        let short_name = parent_short_name
            .as_deref()
            .map(|parent| format!("{parent}.{simple_name}"))
            .unwrap_or_else(|| simple_name.to_string());
        let declared_visibility = source_visibility(node, source, default_visibility);
        let visibility = parent_visibility
            .map(|parent| restrict_visibility(declared_visibility, parent))
            .unwrap_or(declared_visibility);
        if visibility != JvmVisibility::Private {
            result.push(JvmExternalType {
                fqn: qualified_name(&package_name, &short_name),
                package_name: package_name.clone(),
                short_name: short_name.clone(),
                kind: source_kind(node.kind()),
                visibility,
                source: JvmExternalDeclarationSource::SourceJar {
                    artifact_path: artifact_path.to_path_buf(),
                    source_path: source_path.to_string(),
                },
            });
        }

        let child_default_visibility = if is_interface_like_node(node.kind()) {
            JvmVisibility::Public
        } else {
            JvmVisibility::PackagePrivate
        };
        let Some(body) = node.child_by_field_name("body") else {
            continue;
        };
        for child in class_like_body_children_rev(body) {
            if is_class_like_declaration_kind(child.kind()) {
                stack.push((
                    child,
                    Some(short_name.clone()),
                    Some(visibility),
                    child_default_visibility,
                ));
            }
        }
    }

    result
}

/// Public Kotlin types declared by one `.kt` entry of a source jar.
///
/// Kotlin identities are already source-level (issue #1236): no `FooKt` file
/// facade, no `$` encoding, companions spelled by their declared name. The
/// declaration walk therefore yields exactly the names a consumer would write,
/// and no normalization step is needed the way Scala's `$`-suffixed object
/// identities require one.
///
/// A file whose tree contains a parse error is skipped entirely, matching the
/// Scala path: a source jar is untrusted input, and a partially-recovered tree
/// can name types the library does not actually export, which would make an
/// unknown name look resolvable.
fn kotlin_source_types(
    artifact_path: &Path,
    source_path: &str,
    source: &str,
) -> Vec<JvmExternalType> {
    let mut parser = Parser::new();
    parser
        .set_language(&crate::analyzer::kotlin::language::LANGUAGE.into())
        .expect("tree-sitter Kotlin language must load");
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    if tree.root_node().has_error() {
        return Vec::new();
    }

    let synthetic_file = ProjectFile::new(std::env::temp_dir(), "external.kt");
    let parsed =
        brokk_bifrost_jvm::kotlin::declarations::parse_kotlin_file(&synthetic_file, source, &tree);
    parsed
        .declarations()
        .iter()
        .filter(|declaration| declaration.is_class() && !declaration.is_synthetic())
        .filter_map(|declaration| {
            let node = kotlin_source_declaration_node(&tree, &parsed, declaration)?;
            let visibility = kotlin_external_visibility(node, source)?;
            let kind = kotlin_external_kind(node)?;
            let short_name = declaration.short_name().to_string();
            (!short_name.is_empty()).then(|| JvmExternalType {
                fqn: declaration.fq_name(),
                package_name: declaration.package_name().to_string(),
                short_name,
                kind,
                visibility,
                source: JvmExternalDeclarationSource::SourceJar {
                    artifact_path: artifact_path.to_path_buf(),
                    source_path: source_path.to_string(),
                },
            })
        })
        // Source JARs are untrusted input. The index is deliberately
        // best-effort, so stopping at a bounded number of public Kotlin types
        // is preferable to retaining an arbitrarily large declaration set.
        .take(MAX_ANALYZER_SOURCE_TYPES)
        .collect()
}

fn kotlin_source_declaration_node<'tree>(
    tree: &'tree tree_sitter::Tree,
    parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    declaration: &crate::analyzer::CodeUnit,
) -> Option<tree_sitter::Node<'tree>> {
    let range = parsed.declaration_ranges(declaration).first()?;
    let mut node = tree
        .root_node()
        .descendant_for_byte_range(range.start_byte, range.end_byte)?;
    loop {
        if brokk_bifrost_jvm::kotlin::declarations::KOTLIN_CLASS_LIKE_KINDS.contains(&node.kind()) {
            return Some(node);
        }
        node = node.parent()?;
    }
}

/// The visibility a Kotlin declaration contributes to the shared index, or
/// `None` when it contributes nothing.
///
/// `internal` restricts a declaration to its own compilation module, so from
/// the perspective of code consuming a published artifact it is exactly as
/// invisible as `private` — neither belongs in the index at all.
fn kotlin_external_visibility(node: tree_sitter::Node<'_>, source: &str) -> Option<JvmVisibility> {
    use brokk_bifrost_jvm::kotlin::declarations::KotlinDeclaredVisibility;
    match brokk_bifrost_jvm::kotlin::declarations::kotlin_declared_visibility(node, source) {
        KotlinDeclaredVisibility::Public => Some(JvmVisibility::Public),
        // Kotlin has no package-private tier; `protected` is modelled with the
        // index's nearest same-package-only tier so a consumer in another
        // package cannot resolve it.
        KotlinDeclaredVisibility::Protected => Some(JvmVisibility::Protected),
        KotlinDeclaredVisibility::Internal | KotlinDeclaredVisibility::Private => None,
    }
}

fn kotlin_external_kind(node: tree_sitter::Node<'_>) -> Option<JvmExternalTypeKind> {
    use brokk_bifrost_jvm::kotlin::declarations::KotlinClassLikeKind;
    Some(
        match brokk_bifrost_jvm::kotlin::declarations::kotlin_class_like_kind(node)? {
            KotlinClassLikeKind::Interface => JvmExternalTypeKind::Interface,
            KotlinClassLikeKind::Enum => JvmExternalTypeKind::Enum,
            KotlinClassLikeKind::Annotation => JvmExternalTypeKind::Annotation,
            // An `object` is a class with exactly one instance; the index only
            // answers "does this type name exist", so the distinction between
            // an object and a class carries no information here.
            KotlinClassLikeKind::Class | KotlinClassLikeKind::Object => JvmExternalTypeKind::Class,
        },
    )
}

fn source_visibility(
    node: tree_sitter::Node<'_>,
    source: &str,
    default_visibility: JvmVisibility,
) -> JvmVisibility {
    for index in 0..node.named_child_count() {
        let Some(child) = node.named_child(index) else {
            continue;
        };
        if child.kind() != "modifiers" {
            continue;
        }
        let modifiers = node_text(child, source);
        if modifier_present(modifiers, "public") {
            return JvmVisibility::Public;
        }
        if modifier_present(modifiers, "protected") {
            return JvmVisibility::Protected;
        }
        if modifier_present(modifiers, "private") {
            return JvmVisibility::Private;
        }
    }
    default_visibility
}

fn modifier_present(modifiers: &str, expected: &str) -> bool {
    modifiers
        .split(|ch: char| !ch.is_ascii_alphabetic())
        .any(|token| token == expected)
}

/// One class to assemble into a test class JAR: its binary name, the binary
/// name of its superclass, and the members it declares (#1900).
///
/// Binary names use the `/` separator the class-file format itself uses, for
/// example `com/example/probe/Registry`, because that is what the bytes hold.
#[cfg(test)]
pub(crate) struct TestClassFile<'a> {
    pub(crate) internal_name: &'a str,
    pub(crate) super_internal_name: &'a str,
    pub(crate) methods: &'a [TestClassMethod<'a>],
    /// Emit the `InnerClasses` attribute a compiler writes for a class nested
    /// inside another and declared `private`. Real JARs are full of these, and
    /// the index deliberately publishes none of them, so a fixture needs one to
    /// show that a deliberate exclusion is not a failed read.
    pub(crate) private_nested: bool,
}

/// One public method of a [`TestClassFile`]. `descriptor` is the JVM method
/// descriptor, for example `(Ljava/lang/String;)V` for a method taking one
/// `String` and returning nothing.
#[cfg(test)]
pub(crate) struct TestClassMethod<'a> {
    pub(crate) name: &'a str,
    pub(crate) descriptor: &'a str,
    pub(crate) is_static: bool,
}

/// The bytes of a minimal, valid `.class` file for `class`.
///
/// Bifrost's JVM tests normally compile fixtures with `javac`, and skip
/// themselves when no JDK is installed. A skipped test proves nothing, and the
/// member surface this file indexes is read out of class files, so the #1900
/// acceptance needs a class JAR that exists on every machine. Emitting the
/// bytes directly is the only way to get one without a JDK.
///
/// This writes only what the class-file format requires of a declaration: the
/// magic number, a class-file version, a constant pool holding the two class
/// names and each method's name and descriptor, the access flags, and one
/// method table entry per method with no attributes. There is no bytecode,
/// because nothing here executes; `jclassfile` parses it exactly as it parses a
/// compiled class, which is what the index reads.
#[cfg(test)]
pub(crate) fn test_class_file_bytes(class: &TestClassFile<'_>) -> Vec<u8> {
    const ACC_PUBLIC_CLASS: u16 = 0x0021; // ACC_PUBLIC | ACC_SUPER
    const ACC_PUBLIC_METHOD: u16 = 0x0001;
    const ACC_STATIC_METHOD: u16 = 0x0008;
    const CONSTANT_UTF8: u8 = 1;
    const CONSTANT_CLASS: u8 = 7;
    const CLASS_FILE_MAJOR_VERSION: u16 = 52; // Java 8

    let mut pool = Vec::new();
    let mut next_index = 1u16;
    // The constant pool is indexed by a `u16`, so a class declaring thousands
    // of methods only fits when repeated strings are shared. Interning is also
    // what a compiler emits, so the bytes stay ordinary.
    let mut interned: std::collections::HashMap<String, u16> = std::collections::HashMap::new();
    let mut utf8_index = |pool: &mut Vec<u8>, next_index: &mut u16, value: &str| -> u16 {
        if let Some(index) = interned.get(value) {
            return *index;
        }
        pool.push(CONSTANT_UTF8);
        pool.extend_from_slice(&(value.len() as u16).to_be_bytes());
        pool.extend_from_slice(value.as_bytes());
        let index = *next_index;
        *next_index += 1;
        interned.insert(value.to_owned(), index);
        index
    };
    let this_name_index = utf8_index(&mut pool, &mut next_index, class.internal_name);
    pool.push(CONSTANT_CLASS);
    pool.extend_from_slice(&this_name_index.to_be_bytes());
    let this_class_index = next_index;
    next_index += 1;
    let super_name_index = utf8_index(&mut pool, &mut next_index, class.super_internal_name);
    pool.push(CONSTANT_CLASS);
    pool.extend_from_slice(&super_name_index.to_be_bytes());
    let super_class_index = next_index;
    next_index += 1;
    let mut method_indexes = Vec::with_capacity(class.methods.len());
    for method in class.methods {
        let name_index = utf8_index(&mut pool, &mut next_index, method.name);
        let descriptor_index = utf8_index(&mut pool, &mut next_index, method.descriptor);
        method_indexes.push((name_index, descriptor_index));
    }
    let inner_classes_index = class
        .private_nested
        .then(|| utf8_index(&mut pool, &mut next_index, "InnerClasses"));

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0xCAFE_BABEu32.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&CLASS_FILE_MAJOR_VERSION.to_be_bytes());
    bytes.extend_from_slice(&next_index.to_be_bytes());
    bytes.extend_from_slice(&pool);
    bytes.extend_from_slice(&ACC_PUBLIC_CLASS.to_be_bytes());
    bytes.extend_from_slice(&this_class_index.to_be_bytes());
    bytes.extend_from_slice(&super_class_index.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&(class.methods.len() as u16).to_be_bytes());
    for (method, (name_index, descriptor_index)) in class.methods.iter().zip(method_indexes) {
        let flags = if method.is_static {
            ACC_PUBLIC_METHOD | ACC_STATIC_METHOD
        } else {
            ACC_PUBLIC_METHOD
        };
        bytes.extend_from_slice(&flags.to_be_bytes());
        bytes.extend_from_slice(&name_index.to_be_bytes());
        bytes.extend_from_slice(&descriptor_index.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
    }
    match inner_classes_index {
        // One `InnerClasses` entry naming this very class as a private nested
        // class: inner class, no outer, no simple name, `ACC_PRIVATE`.
        Some(name_index) => {
            const ACC_PRIVATE_NESTED: u16 = 0x0002;

            bytes.extend_from_slice(&1u16.to_be_bytes());
            bytes.extend_from_slice(&name_index.to_be_bytes());
            bytes.extend_from_slice(&10u32.to_be_bytes());
            bytes.extend_from_slice(&1u16.to_be_bytes());
            bytes.extend_from_slice(&this_class_index.to_be_bytes());
            bytes.extend_from_slice(&0u16.to_be_bytes());
            bytes.extend_from_slice(&0u16.to_be_bytes());
            bytes.extend_from_slice(&ACC_PRIVATE_NESTED.to_be_bytes());
        }
        None => bytes.extend_from_slice(&0u16.to_be_bytes()),
    }
    bytes
}

/// Write `classes` into a class JAR at `path`, one entry per class named after
/// its binary name, exactly as `jar cf` would lay them out.
#[cfg(test)]
pub(crate) fn write_test_class_jar(path: &Path, classes: &[TestClassFile<'_>]) {
    use std::io::Write;

    let file = File::create(path).expect("create the fixture class jar");
    let mut jar = zip::ZipWriter::new(file);
    for class in classes {
        jar.start_file(
            format!("{}.class", class.internal_name),
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored),
        )
        .expect("start a fixture class entry");
        jar.write_all(&test_class_file_bytes(class))
            .expect("write a fixture class entry");
    }
    jar.finish().expect("finish the fixture class jar");
}

fn restrict_visibility(declared: JvmVisibility, enclosing: JvmVisibility) -> JvmVisibility {
    match (declared, enclosing) {
        (JvmVisibility::Private, _) | (_, JvmVisibility::Private) => JvmVisibility::Private,
        (JvmVisibility::PackagePrivate, _) | (_, JvmVisibility::PackagePrivate) => {
            JvmVisibility::PackagePrivate
        }
        (JvmVisibility::Protected, _) | (_, JvmVisibility::Protected) => JvmVisibility::Protected,
        _ => JvmVisibility::Public,
    }
}

fn is_interface_like_node(kind: &str) -> bool {
    matches!(
        kind,
        "interface_declaration" | "annotation_type_declaration"
    )
}

fn source_kind(kind: &str) -> JvmExternalTypeKind {
    match kind {
        "interface_declaration" => JvmExternalTypeKind::Interface,
        "enum_declaration" => JvmExternalTypeKind::Enum,
        "annotation_type_declaration" => JvmExternalTypeKind::Annotation,
        "record_declaration" => JvmExternalTypeKind::Record,
        _ => JvmExternalTypeKind::Class,
    }
}

fn qualified_name(package_name: &str, short_name: &str) -> String {
    if package_name.is_empty() {
        short_name.to_string()
    } else {
        format!("{package_name}.{short_name}")
    }
}

fn enclosing_type_fqns(external_type: &JvmExternalType) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = external_type.short_name.as_str();
    while let Some((owner, _)) = current.rsplit_once('.') {
        result.push(qualified_name(&external_type.package_name, owner));
        current = owner;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{
        AnalyzerConfig, AnalyzerDelegate, IAnalyzer, JavaAnalyzer, JvmExternalArtifact,
        JvmExternalDependencies, JvmMavenCoordinate, Language, MultiAnalyzer, Project, ProjectFile,
        PythonAnalyzer, TestProject, resolve_analyzer,
    };
    use crate::analyzer::{AnalyzerQueryScope, QueryScope};
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::io::Write;
    use std::process::Command;
    use std::sync::Arc;
    use zip::write::SimpleFileOptions;

    const GROUP_PATH: &str = "com/example/external-lib/1.2.3";
    const BINARY_JAR: &str = "external-lib-1.2.3.jar";
    const SOURCE_JAR: &str = "external-lib-1.2.3-sources.jar";

    // -----------------------------------------------------------------------
    // The artifact half of the JVM external member surface (#1900).
    // -----------------------------------------------------------------------

    /// A class JAR declaring `com.example.probe.Registry`, which extends
    /// `com.example.probe.BaseRegistry`. `register` is declared on the subclass
    /// and `reset` is inherited from the base, so one fixture covers both
    /// shapes a written `Owner.member` can take.
    ///
    /// The third entry is a private nested class, which every real JAR carries
    /// and this index deliberately publishes for nobody. It is here so the
    /// fixture proves a *deliberate exclusion* does not make the artifact
    /// report as not fully read.
    fn probe_class_jar(path: &Path) {
        write_test_class_jar(
            path,
            &[
                TestClassFile {
                    internal_name: "com/example/probe/Registry",
                    super_internal_name: "com/example/probe/BaseRegistry",
                    methods: &[TestClassMethod {
                        name: "register",
                        descriptor: "(Ljava/lang/String;)V",
                        is_static: true,
                    }],
                    private_nested: false,
                },
                TestClassFile {
                    internal_name: "com/example/probe/BaseRegistry",
                    super_internal_name: "java/lang/Object",
                    methods: &[TestClassMethod {
                        name: "reset",
                        descriptor: "()V",
                        is_static: true,
                    }],
                    private_nested: false,
                },
                TestClassFile {
                    internal_name: "com/example/probe/Registry$Hidden",
                    super_internal_name: "java/lang/Object",
                    methods: &[TestClassMethod {
                        name: "secret",
                        descriptor: "()V",
                        is_static: true,
                    }],
                    private_nested: true,
                },
            ],
        );
    }

    fn probe_index(jar: &Path) -> JvmExternalDeclarationIndex {
        JvmExternalDeclarationIndex::build_from_artifacts(vec![ResolvedJvmArtifact {
            artifact_path: jar.to_path_buf(),
            source_artifact_path: None,
            coordinate: None,
            origin: JvmDependencyOrigin::ExplicitPath,
        }])
    }

    #[test]
    fn a_class_jar_member_answers_a_written_member_spelling() {
        let root = tempfile::tempdir().unwrap();
        let jar = root.path().join("probe.jar");
        probe_class_jar(&jar);
        let index = probe_index(&jar);
        let surface = JvmExternalDeclarations::new(&index, None);

        assert!(
            index.get("com.example.probe.Registry").is_some(),
            "the type half still indexes the owner"
        );
        let owner = |spelling: &str| surface.resolve_qualified_name(spelling, "app");
        let member = surface
            .resolve_member_spelling("com.example.probe.Registry.register", "app", owner)
            .expect("the class jar declares the member");
        assert_eq!(member.fqn(), "com.example.probe.Registry.register");

        // Inherited: `reset` is declared on the base class in the same jar, and
        // a reference spells it through the subclass exactly as it spells a
        // declared member.
        let inherited = surface
            .resolve_member_spelling("com.example.probe.Registry.reset", "app", owner)
            .expect("the base class in the same jar declares the member");
        assert_eq!(inherited.fqn(), "com.example.probe.BaseRegistry.reset");

        // A member no class file declares is not upgraded: the owner is
        // decided, and the spelling stays exactly as unknown as before.
        assert!(
            surface
                .resolve_member_spelling("com.example.probe.Registry.absent", "app", owner)
                .is_none()
        );
        // An owner nothing indexed answers nothing at all.
        assert!(
            surface
                .resolve_member_spelling("com.example.probe.Missing.register", "app", owner)
                .is_none()
        );
        // A class the index deliberately publishes for nobody -- the private
        // nested `Registry$Hidden` -- was read completely and is not a gap.
        // Counting it as unread would make every ordinary JAR report as
        // declared-but-not-indexed, which would turn every honest miss in the
        // whole workspace into "may be there".
        assert!(
            index.get("com.example.probe.Registry.Hidden").is_none(),
            "a private nested class is not published"
        );
        assert_eq!(
            index.production_diagnostic_count(),
            0,
            "the whole fixture jar was read: {:?}",
            index.production_diagnostics()
        );
    }

    #[test]
    fn a_class_entry_the_byte_budget_refused_declares_no_member_surface() {
        // Honest absence for the artifact half: an owner whose class entry the
        // bounded read never finished has no member surface, so its members are
        // unknown rather than absent -- and the index says so, which is what
        // makes every JVM boundary report `external_declared_unindexed` instead
        // of `external_unknown`.
        let root = tempfile::tempdir().unwrap();
        let jar = root.path().join("probe.jar");
        probe_class_jar(&jar);

        let mut index = JvmExternalDeclarationIndex::default();
        // One byte of budget refuses every entry in the archive.
        index.index_class_jar(&jar, 1);
        let surface = JvmExternalDeclarations::new(&index, None);
        assert!(
            index.get("com.example.probe.Registry").is_none(),
            "a refused entry declares no type either"
        );
        assert!(
            index
                .member("com.example.probe.Registry", "register")
                .is_none(),
            "a refused entry declares no member surface"
        );
        assert!(
            surface
                .resolve_member_spelling("com.example.probe.Registry.register", "app", |spelling| {
                    surface.resolve_qualified_name(spelling, "app")
                })
                .is_none()
        );
        let diagnostics = index.production_diagnostics();
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "jvm.index.unread_entries"),
            "a refused read must be recorded, not silently look complete: {diagnostics:?}"
        );
        assert!(index.production_diagnostic_count() > 0);
    }

    /// A class JAR whose first entry alone spends the whole per-artifact member
    /// budget, so `Registry`'s own members are read *after* the charge is gone.
    /// Everything stays well inside the byte and entry bounds, which is the
    /// point: members are a bound of their own.
    fn member_saturated_class_jar(path: &Path) {
        let names: Vec<String> = (0..MAX_ARTIFACT_MEMBERS)
            .map(|ordinal| format!("filler{ordinal}"))
            .collect();
        let filler_methods: Vec<TestClassMethod<'_>> = names
            .iter()
            .map(|name| TestClassMethod {
                name,
                descriptor: "()V",
                is_static: true,
            })
            .collect();
        write_test_class_jar(
            path,
            &[
                TestClassFile {
                    internal_name: "com/example/probe/Filler",
                    super_internal_name: "java/lang/Object",
                    methods: &filler_methods,
                    private_nested: false,
                },
                TestClassFile {
                    internal_name: "com/example/probe/Registry",
                    super_internal_name: "java/lang/Object",
                    methods: &[TestClassMethod {
                        name: "register",
                        descriptor: "(Ljava/lang/String;)V",
                        is_static: true,
                    }],
                    private_nested: false,
                },
            ],
        );
    }

    #[test]
    fn the_per_artifact_member_bound_drops_members_and_says_so() {
        // The second bounded dimension #1900 requires beside
        // `MAX_TOTAL_INDEX_BYTES`: one artifact well inside the byte budget can
        // declare any number of members, so members are charged per artifact.
        // What must not happen is a silent short surface -- the owner type is
        // still indexed, so a member spelling on it would otherwise look
        // decidable -- which is why exhausting the charge is recorded.
        let root = tempfile::tempdir().unwrap();
        let jar = root.path().join("probe.jar");
        member_saturated_class_jar(&jar);
        let index = probe_index(&jar);
        let surface = JvmExternalDeclarations::new(&index, None);

        assert!(
            index.get("com.example.probe.Registry").is_some(),
            "the type half still indexes the owner; only members were bounded"
        );
        assert!(
            surface
                .resolve_member_spelling("com.example.probe.Registry.register", "app", |spelling| {
                    surface.resolve_qualified_name(spelling, "app")
                })
                .is_none(),
            "the member fell past the per-artifact bound"
        );
        let diagnostics = index.production_diagnostics();
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "limit.artifact_members"),
            "a bounded member read must be recorded, not look complete: {diagnostics:?}"
        );
    }

    #[test]
    fn configured_jdk_home_discovers_and_generates_exact_source_pack() {
        use crate::analyzer::JvmStandardLibraryDiscoveryConfig;
        use crate::analyzer::semantic_model::{
            CatalogOptions, DependencyPackPreparationStatus, SemanticPackCatalog,
            prepare_dependency_semantic_packs,
        };

        let root = tempfile::tempdir().unwrap();
        let relative_home = PathBuf::from("toolchains").join("jdk-21");
        let home = root.path().join(&relative_home);
        fs::create_dir_all(home.join("lib")).unwrap();
        fs::write(home.join("release"), "JAVA_VERSION=\"21.0.8\"\n").unwrap();
        let source_archive = home.join("lib").join("src.zip");
        write_zip_entries(
            &source_archive,
            &[
                (
                    "java.base/module-info.java",
                    b"module java.base { exports java.lang; }" as &[u8],
                ),
                (
                    "java.base/java/lang/Object.java",
                    b"package java.lang; public class Object {}",
                ),
            ],
        );
        let project = TestProject::new(root.path(), Language::Java);
        let config = JvmAnalyzerConfig {
            dependency_discovery: crate::analyzer::JvmDependencyDiscoveryConfig {
                mode: JvmDependencyDiscoveryMode::Disabled,
                ..Default::default()
            },
            standard_library_discovery: JvmStandardLibraryDiscoveryConfig {
                jdk_homes: vec![relative_home],
                discover_java_home: false,
            },
            ..JvmAnalyzerConfig::default()
        };
        let limits = DependencyPackLimits::default();

        let discovered = resolve_jvm_semantic_pack_dependencies(&config, &project, &limits, None);

        assert!(discovered.complete, "{:#?}", discovered.diagnostics);
        assert_eq!(discovered.dependencies.len(), 1);
        assert_eq!(discovered.dependencies[0].id, "jdk:21.0.8");
        assert_eq!(discovered.dependencies[0].evidence.ecosystem, "jdk");
        assert_eq!(
            discovered.dependencies[0].artifacts[0].path(),
            fs::canonicalize(source_archive).unwrap()
        );

        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let prepared = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            &discovered.dependencies,
            &limits,
            None,
        );
        assert!(prepared.complete, "{:#?}", prepared.diagnostics);
        assert_eq!(prepared.packs.len(), 1);
        assert_eq!(
            prepared.packs[0].status,
            DependencyPackPreparationStatus::Generated
        );
        assert!(prepared.packs[0].evidence.artifact_sha256.is_some());
    }

    #[test]
    fn jdk_home_prefers_sources_and_falls_back_to_one_exact_jmod_source_set() {
        use crate::analyzer::JvmStandardLibraryDiscoveryConfig;
        use crate::analyzer::semantic_model::{
            CatalogOptions, DependencyPackPreparationStatus, SemanticPackCatalog,
            prepare_dependency_semantic_packs,
        };

        let root = tempfile::tempdir().unwrap();
        let relative_home = PathBuf::from("toolchains").join("jdk-21");
        let home = root.path().join(&relative_home);
        fs::create_dir_all(home.join("jmods")).unwrap();
        fs::write(home.join("release"), "JAVA_VERSION=\"21.0.8\"\n").unwrap();
        let class = test_class_file_bytes(&TestClassFile {
            internal_name: "java/lang/Object",
            super_internal_name: "java/lang/Object",
            methods: &[],
            private_nested: false,
        });
        write_zip_entries(
            &home.join("jmods/java.base.jmod"),
            &[
                (
                    "classes/module-info.class",
                    &crate::analyzer::jvm::jmod_artifact::test_module_info_class_bytes(&[
                        "java/lang",
                    ]),
                ),
                ("classes/java/lang/Object.class", &class),
            ],
        );
        let project = TestProject::new(root.path(), Language::Java);
        let config = JvmAnalyzerConfig {
            dependency_discovery: crate::analyzer::JvmDependencyDiscoveryConfig {
                mode: JvmDependencyDiscoveryMode::Disabled,
                ..Default::default()
            },
            standard_library_discovery: JvmStandardLibraryDiscoveryConfig {
                jdk_homes: vec![relative_home],
                discover_java_home: false,
            },
            ..JvmAnalyzerConfig::default()
        };
        let limits = DependencyPackLimits::default();
        let discovered = resolve_jvm_semantic_pack_dependencies(&config, &project, &limits, None);
        assert!(discovered.complete, "{:#?}", discovered.diagnostics);
        assert_eq!(discovered.dependencies.len(), 1);
        assert_eq!(discovered.dependencies[0].artifacts.len(), 1);
        assert_eq!(
            discovered.dependencies[0].artifacts[0].kind,
            ExternalArtifactKind::JdkJmodSet
        );
        assert_eq!(
            discovered.dependencies[0].artifacts[0].path(),
            fs::canonicalize(&home).unwrap()
        );

        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let prepared = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            &discovered.dependencies,
            &limits,
            None,
        );
        assert!(prepared.complete, "{:#?}", prepared.diagnostics);
        assert_eq!(prepared.packs.len(), 1);
        assert_eq!(
            prepared.packs[0].status,
            DependencyPackPreparationStatus::Generated
        );

        // Adding a source archive must preserve the existing source-first
        // preference even when JMODs are present in the same approved home.
        fs::create_dir_all(home.join("lib")).unwrap();
        write_zip_entries(
            &home.join("lib/src.zip"),
            &[
                (
                    "java.base/module-info.java",
                    b"module java.base { exports java.lang; }",
                ),
                (
                    "java.base/java/lang/Object.java",
                    b"package java.lang; public class Object {}",
                ),
            ],
        );
        let source_discovered = discover_jdk_semantic_pack_dependencies(&config, root.path(), None);
        assert_eq!(
            source_discovered.dependencies[0].artifacts[0].kind,
            ExternalArtifactKind::JdkSourceZip
        );
        assert_eq!(
            source_discovered.dependencies[0].artifacts[0].path(),
            fs::canonicalize(home.join("lib/src.zip")).unwrap()
        );
    }

    #[test]
    fn missing_jmod_after_discovery_is_an_honest_preparation_failure() {
        use crate::analyzer::JvmStandardLibraryDiscoveryConfig;
        use crate::analyzer::semantic_model::{
            CatalogOptions, SemanticPackCatalog, prepare_dependency_semantic_packs,
        };

        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("jdk");
        fs::create_dir_all(home.join("jmods")).unwrap();
        fs::write(home.join("release"), "JAVA_VERSION=\"21.0.8\"\n").unwrap();
        fs::write(home.join("jmods/java.base.jmod"), b"not a jmod").unwrap();
        let config = JvmAnalyzerConfig {
            standard_library_discovery: JvmStandardLibraryDiscoveryConfig {
                jdk_homes: vec![home.clone()],
                discover_java_home: false,
            },
            ..JvmAnalyzerConfig::default()
        };
        let project = TestProject::new(root.path(), Language::Java);
        let limits = DependencyPackLimits::default();
        let discovered = resolve_jvm_semantic_pack_dependencies(&config, &project, &limits, None);
        assert_eq!(discovered.dependencies.len(), 1);
        fs::remove_file(home.join("jmods/java.base.jmod")).unwrap();
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let prepared = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            &discovered.dependencies,
            &limits,
            None,
        );
        assert!(!prepared.complete);
        assert!(prepared.packs.is_empty());
        assert!(
            prepared
                .diagnostics
                .iter()
                .any(|diagnostic| { diagnostic.code == "artifact.metadata" })
        );
    }

    #[test]
    fn automatic_java_home_with_only_jmods_uses_prebuilt_selection() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("portable-jdk-home");
        fs::create_dir_all(home.join("jmods")).unwrap();
        fs::write(home.join("release"), "JAVA_VERSION=\"21.0.8\"\n").unwrap();
        fs::write(home.join("jmods/java.base.jmod"), b"exact binary input").unwrap();
        let config = JvmAnalyzerConfig::default();

        let discovered = discover_jdk_semantic_pack_dependencies(
            &config,
            root.path(),
            Some(home.as_os_str().to_owned()),
        );

        assert!(discovered.diagnostics.is_empty());
        assert_eq!(discovered.dependencies.len(), 1);
        assert!(discovered.dependencies[0].artifacts.is_empty());
        assert_eq!(
            discovered.dependencies[0]
                .evidence
                .toolchain
                .as_ref()
                .and_then(|coordinate| coordinate.version.as_ref()),
            Some(&Version::parse("21.0.8").unwrap())
        );
    }

    #[test]
    fn invalid_environment_jdk_home_is_a_warning_without_guessed_version() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("not-a-jdk");

        let discovered = discover_jdk_semantic_pack_dependencies(
            &JvmAnalyzerConfig::default(),
            root.path(),
            Some(missing.as_os_str().to_owned()),
        );

        assert!(discovered.dependencies.is_empty());
        assert_eq!(discovered.diagnostics.len(), 1);
        assert_eq!(
            discovered.diagnostics[0].severity,
            DependencyPackDiagnosticSeverity::Warning
        );
        assert_eq!(discovered.diagnostics[0].code, "jdk.home.invalid");
    }

    #[test]
    fn java_external_declaration_indexes_coordinate_and_prefers_source_jar() {
        let Some(fixture) = ExternalJarFixture::new(true) else {
            return;
        };
        let config = fixture.coordinate_config();
        let index = JvmExternalDeclarationIndex::build(&config, fixture.project_root());
        assert!(
            index.production_diagnostics().is_empty(),
            "{:?}",
            index.production_diagnostics()
        );

        let service = index.get("com.example.dep.ExternalService").unwrap();
        assert_eq!("com.example.dep", service.package_name());
        assert_eq!("ExternalService", service.short_name());
        assert_eq!(JvmExternalTypeKind::Class, service.kind());
        assert_eq!(JvmVisibility::Public, service.visibility());
        assert!(
            matches!(
                service.source(),
                JvmExternalDeclarationSource::SourceJar { source_path, .. }
                    if source_path == "com/example/dep/ExternalService.java"
            ),
            "{service:#?}"
        );

        assert!(
            index
                .get("com.example.dep.ExternalService.Nested")
                .is_some()
        );
        assert!(
            matches!(
                index
                    .get("com.example.dep.ExternalService.Nested")
                    .map(JvmExternalType::source),
                Some(JvmExternalDeclarationSource::SourceJar { .. })
            ),
            "nested source declarations should retain source-JAR provenance"
        );
        assert_eq!(
            Some(JvmVisibility::Protected),
            index
                .get("com.example.dep.ExternalService.ProtectedNested")
                .map(JvmExternalType::visibility)
        );
        assert!(
            index
                .get("com.example.dep.ExternalService.Hidden")
                .is_none(),
            "private nested classes should not be indexed as externally visible"
        );
        assert!(
            index
                .get("com.example.dep.ExternalService.Hidden.Leaks")
                .is_none(),
            "nested classes under a private parent should not be indexed as externally visible"
        );
        assert_eq!(
            Some(JvmVisibility::PackagePrivate),
            index
                .get("com.example.dep.PackageHelper")
                .map(JvmExternalType::visibility)
        );
        assert_eq!(
            Some(JvmVisibility::PackagePrivate),
            index
                .get("com.example.dep.PackageOuter.Nested")
                .map(JvmExternalType::visibility)
        );
        assert_eq!(
            Some(JvmVisibility::Public),
            index
                .get("com.example.dep.PublicApi.Callback")
                .map(JvmExternalType::visibility)
        );
        assert!(
            index
                .resolve_wildcard_import("com.example.dep", "ExternalService", "app")
                .is_some()
        );
    }

    #[test]
    fn java_dependency_pack_retains_coordinate_and_reuses_merged_artifacts() {
        use crate::analyzer::semantic_model::{
            CatalogOptions, DependencyArtifactRole, DependencyPackLimits,
            DependencyPackPreparationStatus, SemanticPackCatalog,
            prepare_dependency_semantic_packs,
        };

        let Some(fixture) = ExternalJarFixture::new(true) else {
            return;
        };
        let project = TestProject::new(fixture.project_root(), Language::Java);
        let config = JvmAnalyzerConfig {
            external_dependencies: fixture.coordinate_config(),
            dependency_discovery: crate::analyzer::JvmDependencyDiscoveryConfig {
                mode: JvmDependencyDiscoveryMode::Disabled,
                ..crate::analyzer::JvmDependencyDiscoveryConfig::default()
            },
            standard_library_discovery: crate::analyzer::JvmStandardLibraryDiscoveryConfig {
                discover_java_home: false,
                ..Default::default()
            },
        };
        let dependencies = resolve_jvm_semantic_pack_dependencies(
            &config,
            &project,
            &DependencyPackLimits::default(),
            None,
        );

        assert_eq!(dependencies.len(), 1);
        assert_eq!(dependencies[0].id, "com.example:external-lib:1.2.3");
        assert_eq!(
            dependencies[0]
                .evidence
                .package
                .as_ref()
                .map(|coordinate| coordinate.name.as_str()),
            Some("com.example:external-lib")
        );
        assert!(
            dependencies[0]
                .provenance
                .iter()
                .any(|entry| { entry.key == "origin" && entry.value == "maven_repository" })
        );
        assert_eq!(
            dependencies[0]
                .artifacts
                .iter()
                .map(|artifact| artifact.role)
                .collect::<Vec<_>>(),
            vec![
                DependencyArtifactRole::Binary,
                DependencyArtifactRole::Sources
            ]
        );

        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let first = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            &dependencies,
            &DependencyPackLimits::default(),
            None,
        );
        let second = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            &dependencies,
            &DependencyPackLimits::default(),
            None,
        );

        assert_eq!(first.packs.len(), 1, "{:#?}", first.diagnostics);
        assert_eq!(second.packs.len(), 1, "{:#?}", second.diagnostics);
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
    fn scala_library_dependency_uses_source_pack_and_exact_toolchain_evidence() {
        use crate::analyzer::semantic_model::{
            CatalogOptions, DependencyPackLimits, DependencyPackPreparationStatus,
            SemanticPackCatalog, prepare_dependency_semantic_packs,
        };

        let temp = tempfile::tempdir().unwrap();
        let source_jar = temp.path().join("scala-library-2.13.16-sources.jar");
        write_zip_entry(
            &source_jar,
            "scala/example/LibraryApi.scala",
            b"package scala.example\ntrait LibraryApi { def value: String }\n",
        );
        let dependency = resolved_semantic_pack_dependency(ResolvedJvmArtifact {
            artifact_path: temp.path().join("scala-library-2.13.16.jar"),
            source_artifact_path: Some(source_jar),
            coordinate: Some(JvmMavenCoordinate::new(
                "org.scala-lang",
                "scala-library",
                "2.13.16",
            )),
            origin: JvmDependencyOrigin::MavenRepository,
        });

        assert_eq!(dependency.evidence.language, "scala");
        assert_eq!(
            dependency.evidence.toolchain,
            Some(CatalogCoordinate {
                name: "scala".to_owned(),
                version: Some(Version::parse("2.13.16").unwrap()),
            })
        );
        assert_eq!(dependency.artifacts.len(), 1);
        assert_eq!(
            dependency.artifacts[0].kind,
            ExternalArtifactKind::ScalaSourceJar
        );

        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let prepared = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            &[dependency],
            &DependencyPackLimits::default(),
            None,
        );

        assert!(prepared.complete, "{:#?}", prepared.diagnostics);
        assert_eq!(prepared.profile.artifacts_read, 1);
        assert_eq!(prepared.packs.len(), 1);
        assert_eq!(
            prepared.packs[0].status,
            DependencyPackPreparationStatus::Generated
        );
        assert_eq!(prepared.packs[0].evidence.language, "scala");
    }

    #[test]
    fn scala_library_without_sources_waits_for_compatible_prebuilt_pack() {
        use crate::analyzer::semantic_model::{
            CatalogOptions, SemanticPackCatalog, prepare_dependency_semantic_packs,
        };

        let dependency = resolved_semantic_pack_dependency(ResolvedJvmArtifact {
            artifact_path: PathBuf::from("scala-library-2.13.16.jar"),
            source_artifact_path: None,
            coordinate: Some(JvmMavenCoordinate::new(
                "org.scala-lang",
                "scala-library",
                "2.13.16",
            )),
            origin: JvmDependencyOrigin::GradleCache,
        });
        assert_eq!(dependency.evidence.ecosystem, "maven");
        assert!(!JvmDependencyPackAdapter.can_produce(&dependency));
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();

        let prepared = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            &[dependency],
            &DependencyPackLimits::default(),
            None,
        );

        assert!(!prepared.complete);
        assert_eq!(prepared.profile.artifacts_read, 0);
        // The dependency is unaccounted (no pack, no installed pack), so
        // preparation names both the specific reason and the generic
        // catch-all (#2756).
        assert_eq!(prepared.diagnostics.len(), 2, "{:#?}", prepared.diagnostics);
        assert!(
            prepared
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "dependency.pack_unavailable")
        );
        assert!(
            prepared
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "preparation.unaccounted-dependency")
        );
    }

    #[test]
    fn kotlin_library_dependency_uses_source_pack_and_exact_toolchain_evidence() {
        use crate::analyzer::semantic_model::{
            CatalogOptions, DependencyPackLimits, DependencyPackPreparationStatus,
            SemanticPackCatalog, prepare_dependency_semantic_packs,
        };

        let temp = tempfile::tempdir().unwrap();
        let source_jar = temp.path().join("kotlin-stdlib-2.2.0-sources.jar");
        write_zip_entry(
            &source_jar,
            "kotlin/example/LibraryApi.kt",
            b"package kotlin.example\ninterface LibraryApi {\n    fun value(): String\n}\n",
        );
        let dependency = resolved_semantic_pack_dependency(ResolvedJvmArtifact {
            artifact_path: temp.path().join("kotlin-stdlib-2.2.0.jar"),
            source_artifact_path: Some(source_jar),
            coordinate: Some(JvmMavenCoordinate::new(
                "org.jetbrains.kotlin",
                "kotlin-stdlib",
                "2.2.0",
            )),
            origin: JvmDependencyOrigin::MavenRepository,
        });

        assert_eq!(dependency.evidence.language, "kotlin");
        assert_eq!(
            dependency.evidence.toolchain,
            Some(CatalogCoordinate {
                name: "kotlin".to_owned(),
                version: Some(Version::parse("2.2.0").unwrap()),
            })
        );
        assert_eq!(dependency.artifacts.len(), 1);
        assert_eq!(
            dependency.artifacts[0].kind,
            ExternalArtifactKind::KotlinSourceJar
        );

        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let prepared = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            &[dependency],
            &DependencyPackLimits::default(),
            None,
        );

        assert!(prepared.complete, "{:#?}", prepared.diagnostics);
        assert_eq!(prepared.profile.artifacts_read, 1);
        assert_eq!(prepared.packs.len(), 1);
        assert_eq!(
            prepared.packs[0].status,
            DependencyPackPreparationStatus::Generated
        );
        assert_eq!(prepared.packs[0].evidence.language, "kotlin");
    }

    #[test]
    fn kotlin_library_without_sources_waits_for_compatible_prebuilt_pack() {
        use crate::analyzer::semantic_model::{
            CatalogOptions, DependencyPackLimits, SemanticPackCatalog,
            prepare_dependency_semantic_packs,
        };

        let dependency = resolved_semantic_pack_dependency(ResolvedJvmArtifact {
            artifact_path: PathBuf::from("kotlin-stdlib-2.2.0.jar"),
            source_artifact_path: None,
            coordinate: Some(JvmMavenCoordinate::new(
                "org.jetbrains.kotlin",
                "kotlin-stdlib",
                "2.2.0",
            )),
            origin: JvmDependencyOrigin::GradleCache,
        });
        assert_eq!(dependency.evidence.language, "kotlin");
        assert_eq!(dependency.evidence.ecosystem, "maven");
        assert!(!JvmDependencyPackAdapter.can_produce(&dependency));
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();

        let prepared = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            &[dependency],
            &DependencyPackLimits::default(),
            None,
        );

        assert!(!prepared.complete);
        assert_eq!(prepared.profile.artifacts_read, 0);
        // The dependency is unaccounted (no pack, no installed pack), so
        // preparation names both the specific reason and the generic
        // catch-all (#2756).
        assert_eq!(prepared.diagnostics.len(), 2, "{:#?}", prepared.diagnostics);
        assert!(
            prepared
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "dependency.pack_unavailable")
        );
        assert!(
            prepared
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "preparation.unaccounted-dependency")
        );
    }

    #[test]
    fn incomplete_kotlin_classification_never_falls_through_to_java() {
        let temp = tempfile::tempdir().unwrap();
        let source_jar = temp.path().join("unknown-sources.jar");
        File::create(&source_jar)
            .unwrap()
            .set_len(MAX_ARTIFACT_BYTES + 1)
            .unwrap();
        let invalid_jar = temp.path().join("invalid-sources.jar");
        fs::write(&invalid_jar, b"not a ZIP archive").unwrap();
        for path in [source_jar, invalid_jar] {
            let dependency = resolved_semantic_pack_dependency(ResolvedJvmArtifact {
                artifact_path: temp.path().join("unknown.jar"),
                source_artifact_path: Some(path),
                coordinate: Some(JvmMavenCoordinate::new("example", "unknown", "1.0.0")),
                origin: JvmDependencyOrigin::ExplicitPath,
            });

            assert_eq!(dependency.evidence.language, "kotlin");
            assert_eq!(
                dependency.artifacts[0].kind,
                ExternalArtifactKind::KotlinSourceJar
            );
            assert!(dependency.provenance.iter().any(|entry| {
                entry.key == "kotlin.classification" && entry.value == "incomplete"
            }));
        }
    }

    #[test]
    fn unresolved_jvm_coordinate_is_actionable_incomplete_discovery() {
        use crate::analyzer::semantic_model::{
            DependencyPackLimits, prepare_discovered_dependency_semantic_packs,
        };

        let root = tempfile::tempdir().unwrap();
        let project = TestProject::new(root.path(), Language::Java);
        let config = JvmAnalyzerConfig {
            external_dependencies: JvmExternalDependencies {
                coordinates: vec![JvmMavenCoordinate {
                    group_id: "com.example".to_owned(),
                    artifact_id: "missing".to_owned(),
                    version: "1.0.0".to_owned(),
                }],
                repository_roots: vec![root.path().join("repository")],
                ..JvmExternalDependencies::default()
            },
            dependency_discovery: crate::analyzer::JvmDependencyDiscoveryConfig {
                mode: JvmDependencyDiscoveryMode::Disabled,
                ..crate::analyzer::JvmDependencyDiscoveryConfig::default()
            },
            standard_library_discovery: crate::analyzer::JvmStandardLibraryDiscoveryConfig {
                discover_java_home: false,
                ..Default::default()
            },
        };
        let limits = DependencyPackLimits::default();
        let discovery = resolve_jvm_semantic_pack_dependencies(&config, &project, &limits, None);

        assert!(!discovery.complete);
        assert!(discovery.dependencies.is_empty());
        assert_eq!(discovery.diagnostics[0].code, "jvm.dependency_unresolved");
        let catalog = crate::analyzer::semantic_model::SemanticPackCatalog::open_ephemeral(
            Default::default(),
        )
        .unwrap();
        let prepared = prepare_discovered_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            discovery,
            &limits,
            None,
        );
        assert!(!prepared.complete);
        assert!(
            prepared
                .compose_activation_request(
                    crate::analyzer::semantic_model::SemanticModelActivationRequest {
                        bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
                        evidence: Vec::new(),
                        controls: Vec::new(),
                        limits: Default::default(),
                    }
                )
                .is_none()
        );
    }

    #[test]
    fn renamed_identical_jars_reuse_one_path_independent_manifest() {
        use crate::analyzer::semantic_model::{
            CatalogOptions, DependencyPackLimits, DependencyPackPreparationStatus,
            SemanticPackCatalog, prepare_dependency_semantic_packs,
        };

        let Some(fixture) = ExternalJarFixture::new(true) else {
            return;
        };
        let copies = tempfile::tempdir().unwrap();
        let first_binary = copies.path().join("first.jar");
        let second_binary = copies.path().join("renamed.jar");
        fs::copy(fixture.binary_jar_path(), &first_binary).unwrap();
        fs::copy(fixture.binary_jar_path(), &second_binary).unwrap();
        let project = TestProject::new(copies.path(), Language::Java);
        let config = |binary| JvmAnalyzerConfig {
            external_dependencies: JvmExternalDependencies {
                artifact_paths: vec![JvmExternalArtifact {
                    artifact_path: binary,
                    source_artifact_path: None,
                    ..JvmExternalArtifact::default()
                }],
                ..JvmExternalDependencies::default()
            },
            dependency_discovery: crate::analyzer::JvmDependencyDiscoveryConfig {
                mode: JvmDependencyDiscoveryMode::Disabled,
                ..Default::default()
            },
            standard_library_discovery: crate::analyzer::JvmStandardLibraryDiscoveryConfig {
                discover_java_home: false,
                ..Default::default()
            },
        };
        let limits = DependencyPackLimits::default();
        let first_dependencies =
            resolve_jvm_semantic_pack_dependencies(&config(first_binary), &project, &limits, None);
        let second_dependencies =
            resolve_jvm_semantic_pack_dependencies(&config(second_binary), &project, &limits, None);
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let first = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
            &first_dependencies,
            &limits,
            None,
        );
        let second = prepare_dependency_semantic_packs(
            &catalog,
            &JvmDependencyPackAdapter,
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
    fn java_external_declaration_uses_classfile_when_source_jar_is_missing() {
        let Some(fixture) = ExternalJarFixture::new(false) else {
            return;
        };
        let config = fixture.coordinate_config();
        let index = JvmExternalDeclarationIndex::build(&config, fixture.project_root());

        let service = index.get("com.example.dep.ExternalService").unwrap();
        assert!(
            matches!(
                service.source(),
                JvmExternalDeclarationSource::ClassFile { class_entry, .. }
                    if class_entry == "com/example/dep/ExternalService.class"
            ),
            "{service:#?}"
        );
        assert_eq!(
            Some(JvmVisibility::Protected),
            index
                .get("com.example.dep.ExternalService.ProtectedNested")
                .map(JvmExternalType::visibility)
        );
        assert_eq!(
            Some(JvmVisibility::PackagePrivate),
            index
                .get("com.example.dep.PackageHelper")
                .map(JvmExternalType::visibility)
        );
        let package_nested = index
            .get("com.example.dep.ExternalService.PackageNested")
            .unwrap();
        assert_eq!("com.example.dep", package_nested.package_name());
        assert_eq!("ExternalService.PackageNested", package_nested.short_name());
        assert_eq!(JvmVisibility::PackagePrivate, package_nested.visibility());
        assert_eq!(
            Some(JvmVisibility::PackagePrivate),
            index
                .get("com.example.dep.PackageOuter.Nested")
                .map(JvmExternalType::visibility)
        );
        assert!(
            index
                .get("com.example.dep.ExternalService.Hidden")
                .is_none(),
            "classfile fallback should respect InnerClasses private visibility"
        );
    }

    #[test]
    fn java_dependency_discovery_indexes_exact_maven_pom_coordinate() {
        let Some(fixture) = ExternalJarFixture::new(true) else {
            return;
        };
        let app = ProjectFile::new(fixture.project_root().to_path_buf(), "src/App.java");
        app.write(
            "package app; import com.example.dep.ExternalService; class App { ExternalService service; }",
        )
        .unwrap();
        ProjectFile::new(fixture.project_root().to_path_buf(), "pom.xml")
            .write(
                "<project><groupId>app</groupId><artifactId>app</artifactId><version>1</version><dependencies><dependency><groupId>com.example</groupId><artifactId>external-lib</artifactId><version>1.2.3</version></dependency></dependencies></project>",
            )
            .unwrap();
        let config = AnalyzerConfig {
            jvm: JvmAnalyzerConfig {
                external_dependencies: JvmExternalDependencies {
                    repository_roots: vec![fixture.maven_repository_root()],
                    ..JvmExternalDependencies::default()
                },
                ..JvmAnalyzerConfig::default()
            },
            ..AnalyzerConfig::default()
        };
        let analyzer = JavaAnalyzer::from_project_with_config(
            TestProject::new(fixture.project_root().to_path_buf(), Language::Java),
            config,
        );
        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        assert!(analyzer.is_known_type_name_in_file(token, None, &app, "ExternalService"));
    }

    #[test]
    fn java_dependency_discovery_indexes_only_locked_gradle_coordinate_directory() {
        let Some(fixture) = ExternalJarFixture::new(true) else {
            return;
        };
        let gradle_cache = fixture.root.join("gradle-cache");
        let locked_dir = gradle_cache.join("com.example/external-lib/1.2.3/binary-hash");
        let source_dir = gradle_cache.join("com.example/external-lib/1.2.3/source-hash");
        let unrelated_dir = gradle_cache.join("unrelated/example/9.9.9/hash");
        fs::create_dir_all(&locked_dir).unwrap();
        fs::create_dir_all(&source_dir).unwrap();
        fs::create_dir_all(&unrelated_dir).unwrap();
        fs::copy(fixture.binary_jar_path(), locked_dir.join(BINARY_JAR)).unwrap();
        fs::copy(fixture.source_jar_path(), source_dir.join(SOURCE_JAR)).unwrap();
        fs::copy(
            fixture.binary_jar_path(),
            unrelated_dir.join("example-9.9.9.jar"),
        )
        .unwrap();

        let app = ProjectFile::new(fixture.project_root().to_path_buf(), "src/App.java");
        app.write(
            "package app; import com.example.dep.ExternalService; class App { ExternalService service; }",
        )
        .unwrap();
        ProjectFile::new(fixture.project_root().to_path_buf(), "gradle.lockfile")
            .write("com.example:external-lib:1.2.3=compileClasspath\n")
            .unwrap();
        let config = AnalyzerConfig {
            jvm: JvmAnalyzerConfig {
                external_dependencies: JvmExternalDependencies {
                    repository_roots: vec![fixture.root.join("empty-maven")],
                    gradle_cache_roots: vec![gradle_cache],
                    ..JvmExternalDependencies::default()
                },
                ..JvmAnalyzerConfig::default()
            },
            ..AnalyzerConfig::default()
        };
        let analyzer = JavaAnalyzer::from_project_with_config(
            TestProject::new(fixture.project_root().to_path_buf(), Language::Java),
            config,
        );
        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        let resolution = analyzer
            .resolve_type_name_with_external(token, None, &app, "ExternalService")
            .unwrap();
        let crate::analyzer::java::imports::JavaTypeResolution::External(external) = resolution
        else {
            panic!("dependency should resolve externally");
        };
        assert!(matches!(
            external.source(),
            JvmExternalDeclarationSource::SourceJar { .. }
        ));
    }

    #[test]
    fn java_dependency_discovery_skips_classifier_only_gradle_cache_entries() {
        let Some(fixture) = ExternalJarFixture::new(false) else {
            return;
        };
        let gradle_cache = fixture.root.join("gradle-cache");
        let classifier_dir = gradle_cache.join("com.example/external-lib/1.2.3/classifier-hash");
        fs::create_dir_all(&classifier_dir).unwrap();
        fs::copy(
            fixture.binary_jar_path(),
            classifier_dir.join("external-lib-1.2.3-tests.jar"),
        )
        .unwrap();

        let config = JvmExternalDependencies {
            coordinates: vec![JvmMavenCoordinate::new(
                "com.example",
                "external-lib",
                "1.2.3",
            )],
            gradle_cache_roots: vec![gradle_cache],
            ..JvmExternalDependencies::default()
        };
        let index = JvmExternalDeclarationIndex::build(&config, fixture.project_root());
        assert!(index.is_empty());
    }

    #[test]
    fn java_dependency_discovery_disabled_keeps_metadata_out_of_index() {
        let Some(fixture) = ExternalJarFixture::new(false) else {
            return;
        };
        let app = ProjectFile::new(fixture.project_root().to_path_buf(), "src/App.java");
        app.write(
            "package app; import com.example.dep.ExternalService; class App { ExternalService service; }",
        )
        .unwrap();
        ProjectFile::new(fixture.project_root().to_path_buf(), "pom.xml")
            .write(
                "<project><dependencies><dependency><groupId>com.example</groupId><artifactId>external-lib</artifactId><version>1.2.3</version></dependency></dependencies></project>",
            )
            .unwrap();
        let config = AnalyzerConfig {
            jvm: JvmAnalyzerConfig {
                external_dependencies: JvmExternalDependencies {
                    repository_roots: vec![fixture.maven_repository_root()],
                    ..JvmExternalDependencies::default()
                },
                dependency_discovery: crate::analyzer::JvmDependencyDiscoveryConfig {
                    mode: crate::analyzer::JvmDependencyDiscoveryMode::Disabled,
                    ..crate::analyzer::JvmDependencyDiscoveryConfig::default()
                },
                standard_library_discovery: crate::analyzer::JvmStandardLibraryDiscoveryConfig {
                    discover_java_home: false,
                    ..Default::default()
                },
            },
            ..AnalyzerConfig::default()
        };
        let analyzer = JavaAnalyzer::from_project_with_config(
            TestProject::new(fixture.project_root().to_path_buf(), Language::Java),
            config,
        );
        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        assert!(!analyzer.is_known_type_name_in_file(token, None, &app, "ExternalService"));
    }

    #[test]
    fn java_dependency_discovery_invalidates_only_for_build_inputs() {
        let Some(fixture) = ExternalJarFixture::new(false) else {
            return;
        };
        let app = ProjectFile::new(fixture.project_root().to_path_buf(), "src/App.java");
        app.write(
            "package app; import com.example.dep.ExternalService; class App { ExternalService service; }",
        )
        .unwrap();
        let pom = ProjectFile::new(fixture.project_root().to_path_buf(), "pom.xml");
        pom.write("<project><dependencies><dependency><groupId>com.example</groupId><artifactId>external-lib</artifactId></dependency></dependencies></project>")
            .unwrap();
        let config = AnalyzerConfig {
            jvm: JvmAnalyzerConfig {
                external_dependencies: JvmExternalDependencies {
                    repository_roots: vec![fixture.maven_repository_root()],
                    ..JvmExternalDependencies::default()
                },
                ..JvmAnalyzerConfig::default()
            },
            ..AnalyzerConfig::default()
        };
        let analyzer = JavaAnalyzer::from_project_with_config(
            TestProject::new(fixture.project_root().to_path_buf(), Language::Java),
            config,
        );
        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        assert!(!analyzer.is_known_type_name_in_file(token, None, &app, "ExternalService"));
        let initial_index = analyzer.external_index.clone();

        pom.write("<project><dependencies><dependency><groupId>com.example</groupId><artifactId>external-lib</artifactId><version>1.2.3</version></dependency></dependencies></project>")
            .unwrap();
        let updated = analyzer.update(&BTreeSet::from([pom.clone()]));
        assert!(!Arc::ptr_eq(&initial_index, &updated.external_index));
        assert!(updated.is_known_type_name_in_file(token, None, &app, "ExternalService"));

        app.write(
            "package app; import com.example.dep.ExternalService; class App { ExternalService changed; }",
        )
        .unwrap();
        let java_only = updated.update(&BTreeSet::from([app]));
        assert!(Arc::ptr_eq(
            &updated.external_index,
            &java_only.external_index
        ));
        let refreshed = java_only.update_all();
        assert!(!Arc::ptr_eq(
            &java_only.external_index,
            &refreshed.external_index
        ));
    }

    #[test]
    fn java_dependency_discovery_routes_manifest_changes_through_multi_analyzer() {
        let Some(fixture) = ExternalJarFixture::new(false) else {
            return;
        };
        let app = ProjectFile::new(fixture.project_root().to_path_buf(), "src/App.java");
        app.write(
            "package app; import com.example.dep.ExternalService; class App { ExternalService service; }",
        )
        .unwrap();
        ProjectFile::new(fixture.project_root().to_path_buf(), "tool.py")
            .write("def tool():\n    pass\n")
            .unwrap();
        let pom = ProjectFile::new(fixture.project_root().to_path_buf(), "pom.xml");
        pom.write("<project/>").unwrap();
        let project = TestProject::with_languages(
            fixture.project_root().to_path_buf(),
            BTreeSet::from([Language::Java, Language::Python]),
        );
        let config = AnalyzerConfig {
            jvm: JvmAnalyzerConfig {
                external_dependencies: JvmExternalDependencies {
                    repository_roots: vec![fixture.maven_repository_root()],
                    ..JvmExternalDependencies::default()
                },
                ..JvmAnalyzerConfig::default()
            },
            ..AnalyzerConfig::default()
        };
        let multi = MultiAnalyzer::new(BTreeMap::from([
            (
                Language::Java,
                AnalyzerDelegate::Java(JavaAnalyzer::from_project_with_config(
                    project.clone(),
                    config,
                )),
            ),
            (
                Language::Python,
                AnalyzerDelegate::Python(PythonAnalyzer::from_project(project)),
            ),
        ]));
        let java = resolve_analyzer::<JavaAnalyzer>(&multi).unwrap();
        let scope = AnalyzerQueryScope::new(&multi);
        let token = scope.token();
        assert!(!java.is_known_type_name_in_file(token, None, &app, "ExternalService"));

        pom.write("<project><dependencies><dependency><groupId>com.example</groupId><artifactId>external-lib</artifactId><version>1.2.3</version></dependency></dependencies></project>")
            .unwrap();
        let updated = multi.update(&BTreeSet::from([pom]));
        let java = resolve_analyzer::<JavaAnalyzer>(&updated).unwrap();
        assert!(java.is_known_type_name_in_file(token, None, &app, "ExternalService"));
    }

    #[test]
    fn java_external_declaration_indexes_explicit_source_artifact_path() {
        let Some(fixture) = ExternalJarFixture::new(true) else {
            return;
        };
        let config = JvmExternalDependencies {
            artifact_paths: vec![JvmExternalArtifact {
                artifact_path: fixture.source_jar_path(),
                source_artifact_path: None,
                ..JvmExternalArtifact::default()
            }],
            ..JvmExternalDependencies::default()
        };
        let index = JvmExternalDeclarationIndex::build(&config, fixture.project_root());

        let service = index.get("com.example.dep.ExternalService").unwrap();
        assert!(
            matches!(
                service.source(),
                JvmExternalDeclarationSource::SourceJar { source_path, .. }
                    if source_path == "com/example/dep/ExternalService.java"
            ),
            "{service:#?}"
        );
    }

    #[test]
    fn jvm_external_declaration_indexes_scala_source_jar() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let source_jar = root.join("scala-library-sources.jar");
        write_zip_entry(
            &source_jar,
            "scala/example/Dependency.scala",
            b"package scala.example\nclass Dependency\ntrait Contract\nobject Defaults\nprivate class Hidden\n",
        );

        let index = JvmExternalDeclarationIndex::build(
            &JvmExternalDependencies {
                artifact_paths: vec![JvmExternalArtifact {
                    artifact_path: source_jar,
                    source_artifact_path: None,
                    ..JvmExternalArtifact::default()
                }],
                ..JvmExternalDependencies::default()
            },
            &root,
        );

        for name in [
            "scala.example.Dependency",
            "scala.example.Contract",
            "scala.example.Defaults",
        ] {
            assert!(matches!(
                index.get(name).map(JvmExternalType::source),
                Some(JvmExternalDeclarationSource::SourceJar { source_path, .. })
                    if source_path == "scala/example/Dependency.scala"
            ));
        }
        assert!(index.get("scala.example.Hidden").is_none());
    }

    const KOTLIN_DEPENDENCY_SOURCE: &str = "package kotlin.example\n\
         \n\
         class Dependency {\n\
             class Nested\n\
             private class Hidden\n\
             companion object Factory\n\
         }\n\
         \n\
         interface Contract\n\
         \n\
         object Defaults\n\
         \n\
         enum class Mode { FAST, SLOW }\n\
         \n\
         annotation class Marked\n\
         \n\
         internal class ModulePrivate\n\
         \n\
         private class FilePrivate\n\
         \n\
         fun topLevelHelper(): Int = 1\n";

    fn kotlin_source_jar_index(root: &Path) -> JvmExternalDeclarationIndex {
        let source_jar = root.join("kotlin-library-sources.jar");
        write_zip_entry(
            &source_jar,
            "kotlin/example/Dependency.kt",
            KOTLIN_DEPENDENCY_SOURCE.as_bytes(),
        );
        JvmExternalDeclarationIndex::build(
            &JvmExternalDependencies {
                artifact_paths: vec![JvmExternalArtifact {
                    artifact_path: source_jar,
                    source_artifact_path: None,
                    ..JvmExternalArtifact::default()
                }],
                ..JvmExternalDependencies::default()
            },
            root,
        )
    }

    #[test]
    fn jvm_external_declaration_indexes_kotlin_source_jar() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let index = kotlin_source_jar_index(&root);

        for name in [
            "kotlin.example.Dependency",
            "kotlin.example.Dependency.Nested",
            "kotlin.example.Dependency.Factory",
            "kotlin.example.Contract",
            "kotlin.example.Defaults",
            "kotlin.example.Mode",
            "kotlin.example.Marked",
        ] {
            assert!(
                matches!(
                    index.get(name).map(JvmExternalType::source),
                    Some(JvmExternalDeclarationSource::SourceJar { source_path, .. })
                        if source_path == "kotlin/example/Dependency.kt"
                ),
                "expected {name} to be indexed from the Kotlin source jar"
            );
        }

        assert_eq!(
            Some(JvmExternalTypeKind::Interface),
            index
                .get("kotlin.example.Contract")
                .map(JvmExternalType::kind)
        );
        assert_eq!(
            Some(JvmExternalTypeKind::Enum),
            index.get("kotlin.example.Mode").map(JvmExternalType::kind)
        );
        assert_eq!(
            Some(JvmExternalTypeKind::Annotation),
            index
                .get("kotlin.example.Marked")
                .map(JvmExternalType::kind)
        );
    }

    #[test]
    fn jvm_external_declaration_omits_kotlin_types_a_consumer_cannot_name() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let index = kotlin_source_jar_index(&root);

        // `internal` is module-scoped and `private` is file-scoped, so neither
        // is nameable from a different artifact.
        assert!(index.get("kotlin.example.ModulePrivate").is_none());
        assert!(index.get("kotlin.example.FilePrivate").is_none());
        assert!(index.get("kotlin.example.Dependency.Hidden").is_none());

        // The index answers "does this *type* exist"; top-level callables are
        // not types, and the JVM facade Kotlin generates for them
        // (`DependencyKt`) is a compiler artifact that never appears in a
        // Kotlin identity.
        assert!(index.get("kotlin.example.topLevelHelper").is_none());
        assert!(index.get("kotlin.example.DependencyKt").is_none());
    }

    #[test]
    fn kotlin_analyzer_shares_the_jvm_dependency_realm() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let workspace_root = root.join("workspace");
        fs::create_dir_all(&workspace_root).unwrap();
        let source_jar = root.join("kotlin-library-sources.jar");
        write_zip_entry(
            &source_jar,
            "kotlin/example/Dependency.kt",
            KOTLIN_DEPENDENCY_SOURCE.as_bytes(),
        );

        ProjectFile::new(workspace_root.clone(), "src/App.kt")
            .write("package app\n\nimport kotlin.example.Dependency\n\nclass App\n")
            .unwrap();

        let config = AnalyzerConfig {
            jvm: JvmAnalyzerConfig {
                external_dependencies: JvmExternalDependencies {
                    artifact_paths: vec![JvmExternalArtifact {
                        artifact_path: source_jar,
                        source_artifact_path: None,
                        ..JvmExternalArtifact::default()
                    }],
                    ..JvmExternalDependencies::default()
                },
                ..JvmAnalyzerConfig::default()
            },
            ..AnalyzerConfig::default()
        };
        let analyzer = crate::analyzer::KotlinAnalyzer::new_with_config(
            Arc::new(TestProject::new(workspace_root, Language::Kotlin)),
            config,
        );

        let index = analyzer.external_declaration_index();
        assert!(
            index
                .resolve_explicit_import("kotlin.example.Dependency", "app")
                .is_some(),
            "the Kotlin analyzer must read the same jar-backed index Java and Scala use"
        );
        assert!(
            index
                .resolve_explicit_import("kotlin.example.ModulePrivate", "app")
                .is_none()
        );
    }

    #[test]
    fn java_external_declaration_ignores_missing_and_malformed_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let malformed = root.join("bad.jar");
        fs::write(&malformed, b"not a zip").unwrap();

        let config = JvmExternalDependencies {
            artifact_paths: vec![
                JvmExternalArtifact {
                    artifact_path: malformed,
                    source_artifact_path: None,
                    ..JvmExternalArtifact::default()
                },
                JvmExternalArtifact {
                    artifact_path: root.join("missing.jar"),
                    source_artifact_path: None,
                    ..JvmExternalArtifact::default()
                },
            ],
            ..JvmExternalDependencies::default()
        };

        let index = JvmExternalDeclarationIndex::build(&config, &root);
        assert!(index.is_empty());
    }

    #[test]
    fn java_external_declaration_rejects_unsafe_coordinates() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let unsafe_coordinates = [
            JvmMavenCoordinate::new("..", "external-lib", "1.2.3"),
            JvmMavenCoordinate::new("com.example", "../external-lib", "1.2.3"),
            JvmMavenCoordinate::new("com.example", "external-lib", "../1.2.3"),
            JvmMavenCoordinate::new("com..example", "external-lib", "1.2.3"),
        ];

        for coordinate in unsafe_coordinates {
            assert!(
                resolve_coordinate(&root, &coordinate).is_none(),
                "unsafe coordinate should not resolve: {coordinate:?}"
            );
        }
    }

    #[test]
    fn java_external_declaration_skips_oversized_source_entries() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let oversized_source_jar = root.join("oversized-sources.jar");
        write_zip_entry(
            &oversized_source_jar,
            "com/example/dep/Oversized.java",
            &vec![b' '; MAX_SOURCE_ENTRY_BYTES as usize + 1],
        );
        let config = JvmExternalDependencies {
            artifact_paths: vec![JvmExternalArtifact {
                artifact_path: oversized_source_jar,
                source_artifact_path: None,
                ..JvmExternalArtifact::default()
            }],
            ..JvmExternalDependencies::default()
        };

        let index = JvmExternalDeclarationIndex::build(&config, &root);
        assert!(index.is_empty());
    }

    #[test]
    fn java_external_declaration_skips_oversized_artifacts_before_zip_parse() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let oversized_jar = root.join("oversized.jar");
        File::create(&oversized_jar)
            .unwrap()
            .set_len(MAX_ARTIFACT_BYTES + 1)
            .unwrap();
        let config = JvmExternalDependencies {
            artifact_paths: vec![JvmExternalArtifact {
                artifact_path: oversized_jar,
                source_artifact_path: None,
                ..JvmExternalArtifact::default()
            }],
            ..JvmExternalDependencies::default()
        };

        let index = JvmExternalDeclarationIndex::build(&config, &root);
        assert!(index.is_empty());
    }

    #[test]
    fn java_external_declaration_resolver_distinguishes_source_and_external_types() {
        let Some(fixture) = ExternalJarFixture::new(true) else {
            return;
        };
        let config = AnalyzerConfig {
            jvm: crate::analyzer::JvmAnalyzerConfig {
                external_dependencies: fixture.coordinate_config(),
                ..crate::analyzer::JvmAnalyzerConfig::default()
            },
            ..AnalyzerConfig::default()
        };

        let app = ProjectFile::new(fixture.project_root().to_path_buf(), "src/App.java");
        app.write(
            "package app;\n\
             import com.example.dep.ExternalService;\n\
             import com.example.dep.ExternalHelper;\n\
             import com.example.dep.PublicApi;\n\
             import com.example.dep.*;\n\
             import com.example.other.*;\n\
             public class App { ExternalService one; ExternalService.Nested two; ExternalHelper helper; ExternalService.ProtectedNested blocked; PublicApi.Callback callback; Foo ambiguous; PackageOuter.Nested hidden; }\n",
        )
        .unwrap();
        ProjectFile::new(fixture.project_root().to_path_buf(), "src/LocalType.java")
            .write("package app; public class LocalType {}")
            .unwrap();
        let same_package_app = ProjectFile::new(
            fixture.project_root().to_path_buf(),
            "src/com/example/dep/App.java",
        );
        same_package_app
            .write("package com.example.dep; public class App { PackageHelper helper; }\n")
            .unwrap();

        let project = TestProject::new(fixture.project_root().to_path_buf(), Language::Java);
        let analyzer = JavaAnalyzer::from_project_with_config(project.clone(), config);

        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        assert!(matches!(
            analyzer.resolve_type_name_with_external(token, None, &app, "LocalType"),
            Some(crate::analyzer::java::imports::JavaTypeResolution::Source(
                _
            ))
        ));
        assert!(matches!(
            analyzer.resolve_type_name_with_external(token, None, &app, "ExternalService"),
            Some(crate::analyzer::java::imports::JavaTypeResolution::External(_))
        ));
        assert!(matches!(
            analyzer.resolve_type_name_with_external(token, None, &app, "ExternalService.Nested"),
            Some(crate::analyzer::java::imports::JavaTypeResolution::External(_))
        ));
        assert!(
            analyzer
                .resolve_type_name_with_external(
                    token,
                    None,
                    &app,
                    "ExternalService.ProtectedNested"
                )
                .is_none(),
            "protected nested dependency types should not resolve from unrelated packages"
        );
        assert!(matches!(
            analyzer.resolve_type_name_with_external(token, None, &app, "PublicApi.Callback"),
            Some(crate::analyzer::java::imports::JavaTypeResolution::External(_))
        ));
        assert!(
            analyzer
                .resolve_type_name_with_external(token, None, &app, "Foo")
                .is_none(),
            "ambiguous wildcard external types should not resolve arbitrarily"
        );
        assert!(
            analyzer
                .resolve_type_name_with_external(token, None, &app, "PackageOuter.Nested")
                .is_none(),
            "public nested types under package-private outers should not resolve from other packages"
        );
        assert!(matches!(
            analyzer.resolve_type_name_with_external(
                token,
                None,
                &same_package_app,
                "PackageHelper"
            ),
            Some(crate::analyzer::java::imports::JavaTypeResolution::External(_))
        ));
        assert!(matches!(
            analyzer.resolve_type_name_with_external(
                token,
                None,
                &same_package_app,
                "ExternalService.PackageNested"
            ),
            Some(crate::analyzer::java::imports::JavaTypeResolution::External(_))
        ));
        assert!(
            analyzer
                .resolve_type_name_in_file(token, &app, "ExternalService")
                .is_none(),
            "source-only resolution should not fabricate CodeUnits for dependency types"
        );
        assert!(
            project
                .all_files()
                .unwrap()
                .iter()
                .all(|file| !file.rel_path().to_string_lossy().contains(".jar"))
        );
    }

    struct ExternalJarFixture {
        _temp: tempfile::TempDir,
        root: PathBuf,
        workspace_root: PathBuf,
    }

    impl ExternalJarFixture {
        fn new(include_sources: bool) -> Option<Self> {
            if !jdk_tool_available("javac") || !jdk_tool_available("jar") {
                eprintln!(
                    "skipping Java external declaration fixture test: `javac` and `jar` are required"
                );
                return None;
            }

            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().canonicalize().unwrap();
            let workspace_root = root.join("workspace");
            let repo_dir = root.join("m2").join(GROUP_PATH);
            let source_dir = root.join("dep-src");
            let package_dir = source_dir.join("com/example/dep");
            let other_package_dir = source_dir.join("com/example/other");
            let classes_dir = root.join("dep-classes");
            fs::create_dir_all(&workspace_root).unwrap();
            fs::create_dir_all(&repo_dir).unwrap();
            fs::create_dir_all(&package_dir).unwrap();
            fs::create_dir_all(&other_package_dir).unwrap();
            fs::create_dir_all(&classes_dir).unwrap();

            fs::write(
                package_dir.join("ExternalService.java"),
                "package com.example.dep;\n\
                 public class ExternalService {\n\
                   public static class Nested {}\n\
                   protected static class ProtectedNested {}\n\
                   static class PackageNested {}\n\
                   private static class Hidden { public static class Leaks {} }\n\
                 }\n",
            )
            .unwrap();
            fs::write(
                package_dir.join("ExternalInterface.java"),
                "package com.example.dep; public interface ExternalInterface {}\n",
            )
            .unwrap();
            fs::write(
                package_dir.join("ExternalHelper.java"),
                "package com.example.dep; public class ExternalHelper {}\n",
            )
            .unwrap();
            fs::write(
                package_dir.join("PackageHelper.java"),
                "package com.example.dep; class PackageHelper {}\n",
            )
            .unwrap();
            fs::write(
                package_dir.join("PackageOuter.java"),
                "package com.example.dep; class PackageOuter { public static class Nested {} }\n",
            )
            .unwrap();
            fs::write(
                package_dir.join("PublicApi.java"),
                "package com.example.dep; public interface PublicApi { interface Callback {} }\n",
            )
            .unwrap();
            fs::write(
                package_dir.join("Foo.java"),
                "package com.example.dep; public class Foo {}\n",
            )
            .unwrap();
            fs::write(
                other_package_dir.join("Foo.java"),
                "package com.example.other; public class Foo {}\n",
            )
            .unwrap();

            run(Command::new("javac")
                .arg("-d")
                .arg(&classes_dir)
                .arg(package_dir.join("ExternalService.java"))
                .arg(package_dir.join("ExternalInterface.java"))
                .arg(package_dir.join("ExternalHelper.java"))
                .arg(package_dir.join("PackageHelper.java"))
                .arg(package_dir.join("PackageOuter.java"))
                .arg(package_dir.join("PublicApi.java"))
                .arg(package_dir.join("Foo.java"))
                .arg(other_package_dir.join("Foo.java")));
            run(Command::new("jar")
                .current_dir(&classes_dir)
                .arg("cf")
                .arg(repo_dir.join(BINARY_JAR))
                .arg("."));
            if include_sources {
                run(Command::new("jar")
                    .current_dir(&source_dir)
                    .arg("cf")
                    .arg(repo_dir.join(SOURCE_JAR))
                    .arg("."));
            }

            Some(Self {
                _temp: temp,
                root,
                workspace_root,
            })
        }

        fn project_root(&self) -> &Path {
            &self.workspace_root
        }

        fn source_jar_path(&self) -> PathBuf {
            self.root.join("m2").join(GROUP_PATH).join(SOURCE_JAR)
        }

        fn binary_jar_path(&self) -> PathBuf {
            self.root.join("m2").join(GROUP_PATH).join(BINARY_JAR)
        }

        fn maven_repository_root(&self) -> PathBuf {
            self.root.join("m2")
        }

        fn coordinate_config(&self) -> JvmExternalDependencies {
            JvmExternalDependencies {
                coordinates: vec![JvmMavenCoordinate::new(
                    "com.example",
                    "external-lib",
                    "1.2.3",
                )],
                repository_roots: vec![self.root.join("m2")],
                ..JvmExternalDependencies::default()
            }
        }
    }

    fn jdk_tool_available(tool: &str) -> bool {
        Command::new(tool)
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
    }

    fn run(command: &mut Command) {
        let output = command
            .output()
            .unwrap_or_else(|err| panic!("failed to run JDK fixture command {command:?}: {err}"));
        assert!(
            output.status.success(),
            "JDK fixture command failed: {command:?}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn write_zip_entry(path: &Path, entry_name: &str, bytes: &[u8]) {
        let file = File::create(path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file(
            entry_name,
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
        )
        .unwrap();
        zip.write_all(bytes).unwrap();
        zip.finish().unwrap();
    }

    fn write_zip_entries(path: &Path, entries: &[(&str, &[u8])]) {
        let file = File::create(path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        for (entry_name, bytes) in entries {
            zip.start_file(
                *entry_name,
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
            )
            .unwrap();
            zip.write_all(bytes).unwrap();
        }
        zip.finish().unwrap();
    }
}
