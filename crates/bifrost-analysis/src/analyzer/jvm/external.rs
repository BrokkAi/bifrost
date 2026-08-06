use crate::analyzer::jvm::dependency_discovery::{discover_build_tools, discover_metadata};
use crate::analyzer::jvm::java_artifact::{
    JavaJarPackProducer, ZipDirectoryStatus, zip_directory_status,
};
use crate::analyzer::jvm::jdk_artifact::{
    JdkSourceArchivePackProducer, detect_jdk_source_archive_layout,
};
use crate::analyzer::jvm::kotlin_artifact::KotlinSourceJarPackProducer;
use crate::analyzer::jvm::scala_artifact::ScalaSourceJarPackProducer;
use crate::analyzer::semantic_model::{
    ActivationSelector, ArtifactProducerLimits, ArtifactProduction, ArtifactProductionRequest,
    AuthoredPayload, AuthoredSemanticModelPack, CatalogCoordinate, Compatibility, Completeness,
    DependencyArtifactRole, DependencyDiscoveryOutcome, DependencyDiscoveryProfile,
    DependencyPackAdapter, DependencyPackDiagnostic, DependencyPackDiagnosticSeverity,
    DependencyPackLimits, DependencyPackProduction, DependencyProvenance, ExactDependencyArtifact,
    ExternalArtifactKind, ExternalArtifactPackProducer, Locator, MemberFact, NameSelector,
    Producer, ProducerDiagnostic, ProducerDiagnosticSeverity, Provenance, ResolvedDependency,
    ResolvedDependencyArtifact, Safety, SemanticModelActivationEvidence, TypeFact, TypeKind,
    Visibility, normalize_artifact_locator_paths, read_exact_artifact_while,
};
use crate::analyzer::{
    JvmAnalyzerConfig, JvmDependencyDiscoveryMode, JvmExternalArtifact, JvmExternalArtifactOrigin,
    JvmExternalDependencies, JvmMavenCoordinate, Project, ProjectFile,
};
use crate::hash::HashMap;
use brokk_bifrost_jvm::java::declarations::{
    class_like_body_children_rev, determine_package_name, is_class_like_declaration_kind,
    node_text, normalize_java_full_name, parse_tree,
};
use jclassfile::attributes::{Attribute, NestedClassFlags};
use jclassfile::class_file::{ClassFile, ClassFlags};
use jclassfile::constant_pool::ConstantPool;
use semver::Version;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use tree_sitter::Parser;
use zip::ZipArchive;

use crate::CancellationToken;

const MAX_ARCHIVE_ENTRIES: usize = 10_000;
const MAX_INDEX_ARTIFACTS: usize = 128;
const MAX_SOURCE_ENTRY_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ANALYZER_SOURCE_ENTRY_BYTES: u64 = 1024 * 1024;
const MAX_CLASS_ENTRY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_ARCHIVE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_TOTAL_INDEX_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ANALYZER_SOURCE_TYPES: usize = 4_096;

#[derive(Debug, Clone, Default)]
pub(crate) struct JvmExternalDeclarationIndex {
    types_by_fqn: HashMap<String, JvmExternalType>,
    production_diagnostics: Vec<ProducerDiagnostic>,
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
    if config.dependency_discovery.mode != JvmDependencyDiscoveryMode::Disabled {
        discover_metadata(project).merge_into(&mut dependencies);
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
        let dependency = resolved_semantic_pack_dependency_while(artifact, cancellation);
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
        let dependency = resolved_jdk_dependency(version.clone(), source);
        match dependency_by_version.entry(version) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(discovery.dependencies.len());
                discovery.dependencies.push(dependency);
            }
            std::collections::hash_map::Entry::Occupied(entry)
                if discovery.dependencies[*entry.get()].artifacts.is_empty()
                    && !dependency.artifacts.is_empty() =>
            {
                discovery.dependencies[*entry.get()] = dependency;
            }
            std::collections::hash_map::Entry::Occupied(_) => {}
        }
    }
    discovery
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
    }
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
                kind => ArtifactProduction::failed(
                    ProducerDiagnostic {
                        severity: ProducerDiagnosticSeverity::Error,
                        code: "artifact.kind".to_owned(),
                        location: Some(artifact.path().to_string_lossy().into_owned()),
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

    pub(crate) fn get(&self, fqn: &str) -> Option<&JvmExternalType> {
        self.types_by_fqn.get(fqn)
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
        for index in 0..entry_count {
            let Ok(entry) = archive.by_index(index) else {
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
                continue;
            }
            let external_types = language.source_types(artifact_path, &source_path, &source);
            if matches!(language, SourceJarLanguage::Java) && java_facts.is_none() {
                java_facts =
                    Some(self.produce_java_type_facts(
                        artifact_path,
                        ExternalArtifactKind::JavaSourceJar,
                    ));
            }
            for mut external_type in external_types {
                if let Some(fact) = java_facts
                    .as_ref()
                    .and_then(|facts| facts.get(&external_type.fqn))
                {
                    apply_java_type_fact(&mut external_type, fact);
                }
                self.insert(external_type);
            }
        }
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
        let java_facts =
            self.produce_java_type_facts(artifact_path, ExternalArtifactKind::JavaClassJar);
        for index in 0..entry_count {
            let Ok(entry) = archive.by_index(index) else {
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
                continue;
            }
            if let Some(mut external_type) = class_type(artifact_path, &class_entry, &bytes) {
                if let Some(fact) = java_facts.get(&external_type.fqn) {
                    apply_java_type_fact(&mut external_type, fact);
                }
                self.insert(external_type);
            }
        }
        total_bytes
    }

    fn produce_java_type_facts(
        &mut self,
        artifact_path: &Path,
        artifact_kind: ExternalArtifactKind,
    ) -> HashMap<String, TypeFact> {
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

fn jvm_artifact_from_dependency(dependency: &ResolvedDependency) -> Option<ResolvedJvmArtifact> {
    if dependency
        .artifacts
        .iter()
        .any(|artifact| artifact.kind == ExternalArtifactKind::JdkSourceZip)
    {
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
        self.visibility == JvmVisibility::Public
            || (matches!(
                self.visibility,
                JvmVisibility::Protected | JvmVisibility::PackagePrivate
            ) && self.package_name == package_name)
    }
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
        crate::analyzer::kotlin::declarations::parse_kotlin_file(&synthetic_file, source, &tree);
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
        if crate::analyzer::kotlin::declarations::KOTLIN_CLASS_LIKE_KINDS.contains(&node.kind()) {
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
    use crate::analyzer::kotlin::declarations::KotlinDeclaredVisibility;
    match crate::analyzer::kotlin::declarations::kotlin_declared_visibility(node, source) {
        KotlinDeclaredVisibility::Public => Some(JvmVisibility::Public),
        // Kotlin has no package-private tier; `protected` is modelled with the
        // index's nearest same-package-only tier so a consumer in another
        // package cannot resolve it.
        KotlinDeclaredVisibility::Protected => Some(JvmVisibility::Protected),
        KotlinDeclaredVisibility::Internal | KotlinDeclaredVisibility::Private => None,
    }
}

fn kotlin_external_kind(node: tree_sitter::Node<'_>) -> Option<JvmExternalTypeKind> {
    use crate::analyzer::kotlin::declarations::KotlinClassLikeKind;
    Some(
        match crate::analyzer::kotlin::declarations::kotlin_class_like_kind(node)? {
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

fn class_type(artifact_path: &Path, class_entry: &str, bytes: &[u8]) -> Option<JvmExternalType> {
    let class_file = jclassfile::class_file::parse(bytes).ok()?;
    let flags = class_file.access_flags();
    if flags.contains(ClassFlags::ACC_MODULE) {
        return None;
    }
    let internal_name = class_internal_name(&class_file)?;
    let (package_name, short_name) = split_internal_class_name(&internal_name);
    if short_name.is_empty() {
        return None;
    }
    let fqn = qualified_name(&package_name, &short_name);
    let visibility = class_visibility(&class_file, &internal_name);
    if visibility == JvmVisibility::Private {
        return None;
    }
    Some(JvmExternalType {
        fqn,
        package_name,
        short_name,
        kind: class_kind(flags),
        visibility,
        source: JvmExternalDeclarationSource::ClassFile {
            artifact_path: artifact_path.to_path_buf(),
            class_entry: class_entry.to_string(),
        },
    })
}

fn class_internal_name(class_file: &ClassFile) -> Option<String> {
    let class_index = class_file.this_class() as usize;
    class_name_at_class_index(class_file, class_index)
}

fn class_name_at_class_index(class_file: &ClassFile, class_index: usize) -> Option<String> {
    let constant_pool = class_file.constant_pool();
    let ConstantPool::Class { name_index } = constant_pool.get(class_index)? else {
        return None;
    };
    let ConstantPool::Utf8 { value } = constant_pool.get(*name_index as usize)? else {
        return None;
    };
    Some(value.clone())
}

fn class_visibility(class_file: &ClassFile, internal_name: &str) -> JvmVisibility {
    let mut own_visibility = None;
    for attribute in class_file.attributes() {
        let Attribute::InnerClasses { classes } = attribute else {
            continue;
        };
        for class in classes {
            let Some(inner_name) =
                class_name_at_class_index(class_file, class.inner_class_info_index() as usize)
            else {
                continue;
            };
            if internal_name.starts_with(&format!("{inner_name}$"))
                && nested_class_visibility(class.inner_class_access_flags())
                    == JvmVisibility::Private
            {
                return JvmVisibility::Private;
            }
            if inner_name == internal_name {
                own_visibility = Some(nested_class_visibility(class.inner_class_access_flags()));
            }
        }
    }
    if let Some(visibility) = own_visibility {
        return visibility;
    }

    if class_file.access_flags().contains(ClassFlags::ACC_PUBLIC) {
        JvmVisibility::Public
    } else {
        JvmVisibility::PackagePrivate
    }
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

fn nested_class_visibility(flags: &NestedClassFlags) -> JvmVisibility {
    if flags.contains(NestedClassFlags::ACC_PUBLIC) {
        JvmVisibility::Public
    } else if flags.contains(NestedClassFlags::ACC_PROTECTED) {
        JvmVisibility::Protected
    } else if flags.contains(NestedClassFlags::ACC_PRIVATE) {
        JvmVisibility::Private
    } else {
        JvmVisibility::PackagePrivate
    }
}

fn class_kind(flags: &ClassFlags) -> JvmExternalTypeKind {
    if flags.contains(ClassFlags::ACC_ANNOTATION) {
        JvmExternalTypeKind::Annotation
    } else if flags.contains(ClassFlags::ACC_ENUM) {
        JvmExternalTypeKind::Enum
    } else if flags.contains(ClassFlags::ACC_INTERFACE) {
        JvmExternalTypeKind::Interface
    } else {
        JvmExternalTypeKind::Class
    }
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

fn split_internal_class_name(internal_name: &str) -> (String, String) {
    let (package_path, class_name) = internal_name
        .rsplit_once('/')
        .unwrap_or(("", internal_name));
    (
        package_path.replace('/', "."),
        normalize_java_full_name(&class_name.replace('$', ".")),
    )
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
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::io::Write;
    use std::process::Command;
    use std::sync::Arc;
    use zip::write::SimpleFileOptions;

    const GROUP_PATH: &str = "com/example/external-lib/1.2.3";
    const BINARY_JAR: &str = "external-lib-1.2.3.jar";
    const SOURCE_JAR: &str = "external-lib-1.2.3-sources.jar";

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
    fn java_home_without_sources_produces_exact_evidence_for_prebuilt_selection() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("portable-jdk-home");
        fs::create_dir_all(&home).unwrap();
        fs::write(home.join("release"), "JAVA_VERSION=\"21.0.8\"\n").unwrap();
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
        assert_eq!(prepared.diagnostics.len(), 1);
        assert_eq!(prepared.diagnostics[0].code, "dependency.pack_unavailable");
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
        assert_eq!(prepared.diagnostics.len(), 1);
        assert_eq!(prepared.diagnostics[0].code, "dependency.pack_unavailable");
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
        assert!(analyzer.is_known_type_name_in_file(&app, "ExternalService"));
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
        let resolution = analyzer
            .resolve_type_name_with_external(&app, "ExternalService")
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
        assert!(!analyzer.is_known_type_name_in_file(&app, "ExternalService"));
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
        assert!(!analyzer.is_known_type_name_in_file(&app, "ExternalService"));
        let initial_index = analyzer.external_index.clone();

        pom.write("<project><dependencies><dependency><groupId>com.example</groupId><artifactId>external-lib</artifactId><version>1.2.3</version></dependency></dependencies></project>")
            .unwrap();
        let updated = analyzer.update(&BTreeSet::from([pom.clone()]));
        assert!(!Arc::ptr_eq(&initial_index, &updated.external_index));
        assert!(updated.is_known_type_name_in_file(&app, "ExternalService"));

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
        assert!(!java.is_known_type_name_in_file(&app, "ExternalService"));

        pom.write("<project><dependencies><dependency><groupId>com.example</groupId><artifactId>external-lib</artifactId><version>1.2.3</version></dependency></dependencies></project>")
            .unwrap();
        let updated = multi.update(&BTreeSet::from([pom]));
        let java = resolve_analyzer::<JavaAnalyzer>(&updated).unwrap();
        assert!(java.is_known_type_name_in_file(&app, "ExternalService"));
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

        assert!(matches!(
            analyzer.resolve_type_name_with_external(&app, "LocalType"),
            Some(crate::analyzer::java::imports::JavaTypeResolution::Source(
                _
            ))
        ));
        assert!(matches!(
            analyzer.resolve_type_name_with_external(&app, "ExternalService"),
            Some(crate::analyzer::java::imports::JavaTypeResolution::External(_))
        ));
        assert!(matches!(
            analyzer.resolve_type_name_with_external(&app, "ExternalService.Nested"),
            Some(crate::analyzer::java::imports::JavaTypeResolution::External(_))
        ));
        assert!(
            analyzer
                .resolve_type_name_with_external(&app, "ExternalService.ProtectedNested")
                .is_none(),
            "protected nested dependency types should not resolve from unrelated packages"
        );
        assert!(matches!(
            analyzer.resolve_type_name_with_external(&app, "PublicApi.Callback"),
            Some(crate::analyzer::java::imports::JavaTypeResolution::External(_))
        ));
        assert!(
            analyzer
                .resolve_type_name_with_external(&app, "Foo")
                .is_none(),
            "ambiguous wildcard external types should not resolve arbitrarily"
        );
        assert!(
            analyzer
                .resolve_type_name_with_external(&app, "PackageOuter.Nested")
                .is_none(),
            "public nested types under package-private outers should not resolve from other packages"
        );
        assert!(matches!(
            analyzer.resolve_type_name_with_external(&same_package_app, "PackageHelper"),
            Some(crate::analyzer::java::imports::JavaTypeResolution::External(_))
        ));
        assert!(matches!(
            analyzer.resolve_type_name_with_external(
                &same_package_app,
                "ExternalService.PackageNested"
            ),
            Some(crate::analyzer::java::imports::JavaTypeResolution::External(_))
        ));
        assert!(
            analyzer
                .resolve_type_name_in_file(&app, "ExternalService")
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
