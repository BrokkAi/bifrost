//! The JVM build model as project topology (#2448 slice 1, #9325).
//!
//! Reads checked-in build definitions only: the reactor's `pom.xml` files,
//! Gradle Kotlin DSL settings and build scripts, and `build.sbt`. No build
//! tool runs here, unlike `JvmDependencyDiscoveryMode::OfflineBuildTools` in
//! `super::dependency_discovery`, and nothing is inferred from a path that a
//! build file does not justify.
//!
//! What the readers emit, and what justifies it:
//!
//! - One `BuildProject` and one `Target` per project: a pom's coordinate
//!   declaration, a Gradle project the settings file includes (or a lone
//!   build script), or an sbt `project` definition. The parent pom's
//!   `<modules>` entry, the Gradle `include` and the sbt build file are
//!   recorded as the module list.
//! - `main` and `test` `SourceSet`s per target, justified by the build file
//!   that selects the build model's default layout: Maven's default
//!   lifecycle, a Gradle JVM plugin (`java`, `java-library`, `application`,
//!   Kotlin JVM, `scala`, `groovy`), or sbt's default project layout. The
//!   build file is the evidence; the two path segments alone would not be.
//! - One edge per declared dependency on another target of this same
//!   workspace: a Maven coordinate, a Gradle `project(":x")` or an sbt
//!   `dependsOn`, with the scope as its kind.
//!
//! Gradle's Groovy DSL has no grammar here, so a Groovy build or settings
//! file leaves the topology incomplete rather than read by string scanning.
//! Source visibility domains below are separate path and package evidence.

use brokk_bifrost_analysis::analyzer::store::maven_xml::MAX_BUILD_METADATA_BYTES;
use std::path::{Path, PathBuf};

use crate::analyzer::jvm::build_scripts::{
    GradleTarget, read_gradle_build, read_gradle_settings, read_sbt_build,
};

use brokk_bifrost_core::analyzer::common::language_for_file;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::project::Project;

use brokk_bifrost_analysis::analyzer::IAnalyzer;

use brokk_bifrost_analysis::analyzer::languages::BuildModelProvider;

use brokk_bifrost_analysis::analyzer::topology::DependencyScope;

use brokk_bifrost_analysis::analyzer::topology::FileOwnership;

use brokk_bifrost_analysis::analyzer::topology::FileOwnershipState;

use brokk_bifrost_analysis::analyzer::topology::TopologyAxis;

use brokk_bifrost_analysis::analyzer::topology::TopologyCompleteness;

use brokk_bifrost_analysis::analyzer::topology::TopologyEdge;

use brokk_bifrost_analysis::analyzer::topology::TopologyEntity;

use brokk_bifrost_analysis::analyzer::topology::TopologyEntityKind;

use brokk_bifrost_analysis::analyzer::topology::TopologyProvenance;

use brokk_bifrost_analysis::analyzer::topology::TopologyProvenanceKind;

use brokk_bifrost_analysis::analyzer::topology::TopologySupport;

use brokk_bifrost_analysis::analyzer::topology::WorkspaceTopology;

use brokk_bifrost_core::hash::HashMap;

/// The axes the readers answer. `Configurations` stays unsupported: scope is
/// published as the edge kind, and Gradle's and sbt's named configurations
/// are not enumerated.
static JVM_TOPOLOGY_SUPPORT: TopologySupport = TopologySupport::NONE
    .supported(TopologyAxis::BuildProjects)
    .supported(TopologyAxis::Targets)
    .supported(TopologyAxis::SourceSets)
    .supported(TopologyAxis::TargetDependencies)
    .supported(TopologyAxis::FileOwnership);

pub(crate) struct JvmBuildModel;

pub(crate) static JVM_BUILD_MODEL: JvmBuildModel = JvmBuildModel;

impl BuildModelProvider for JvmBuildModel {
    fn support(&self) -> &'static TopologySupport {
        &JVM_TOPOLOGY_SUPPORT
    }

    fn topology(&self, analyzer: &dyn IAnalyzer) -> Option<WorkspaceTopology> {
        jvm_topology(analyzer.project())
    }
}

/// The build systems whose files define projects, by file name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BuildSystem {
    Maven,
    Gradle,
    Sbt,
}

const GRADLE_SETTINGS: [&str; 2] = ["settings.gradle.kts", "settings.gradle"];
const GRADLE_BUILDS: [&str; 2] = ["build.gradle.kts", "build.gradle"];
/// Gradle plugins that select the JVM `src/main` and `src/test` layout.
const GRADLE_JVM_PLUGINS: [&str; 7] = [
    "java",
    "java-library",
    "application",
    "org.jetbrains.kotlin.jvm",
    "scala",
    "groovy",
    "war",
];

/// Whether `path` is a file that defines JVM build projects.
pub(crate) fn build_definition_system(path: &Path) -> Option<BuildSystem> {
    let name = path.file_name()?.to_str()?;
    match name {
        "pom.xml" => Some(BuildSystem::Maven),
        "build.sbt" => Some(BuildSystem::Sbt),
        _ if GRADLE_SETTINGS.contains(&name) || GRADLE_BUILDS.contains(&name) => {
            Some(BuildSystem::Gradle)
        }
        _ => None,
    }
}

/// One build project of any build system, before assembly.
struct BuildUnit {
    system: BuildSystem,
    /// The build file that declares the project.
    declaration: PathBuf,
    /// Workspace-relative directory the project governs.
    directory: PathBuf,
    name: String,
    /// The project that lists this one, and the file that lists it.
    parent: Option<(String, PathBuf)>,
    /// Names of workspace targets this project depends on, with scope.
    dependencies: Vec<(String, DependencyScope)>,
    /// Default-layout roles, empty when no build model fixes the layout.
    source_roots: Vec<(&'static str, PathBuf)>,
}

impl BuildUnit {
    fn default_layout(directory: &Path) -> Vec<(&'static str, PathBuf)> {
        MAVEN_SOURCE_SETS
            .iter()
            .map(|(role, relative)| (*role, directory.join(relative)))
            .collect()
    }
}

/// `None` when the workspace holds no build file and no JVM source: the JVM
/// build model then has nothing to own.
fn jvm_topology(project: &dyn Project) -> Option<WorkspaceTopology> {
    let Ok(files) = project.all_files() else {
        let mut topology = WorkspaceTopology::incomplete(JVM_TOPOLOGY_SUPPORT.clone());
        topology.mark_provider_failed();
        return Some(topology);
    };
    if !files.iter().any(|file| {
        build_definition_system(file.rel_path()).is_some()
            || matches!(
                language_for_file(file),
                Language::Java | Language::Kotlin | Language::Scala
            )
    }) {
        return None;
    }
    let configurations: Vec<_> = files
        .iter()
        .filter(|file| build_definition_system(file.rel_path()).is_some())
        .map(|file| {
            (
                file.rel_path(),
                brokk_bifrost_analysis::analyzer::common::read_bounded_source(
                    project,
                    file,
                    MAX_BUILD_METADATA_BYTES,
                ),
            )
        })
        .collect();
    Some(jvm_topology_from_inputs(
        files.iter().map(|file| file.rel_path()),
        configurations
            .iter()
            .map(|(path, source)| (*path, source.as_ref().map(|source| source.as_bytes()))),
    ))
}

/// Interpret one selected inventory without reading current project files.
///
/// `files` must enumerate the selected workspace paths, and `configurations`
/// must include every selected build definition file, with `None` for
/// unavailable bytes. Omission means absence, not a request to load a
/// current file. Both inputs belong to the same selection; the result is
/// owned by this topology query only. Configuration identities and
/// external/JDK inventories remain the caller's authority. Only each build
/// model's default source layout is modelled.
pub(crate) fn jvm_topology_from_inputs<'a>(
    files: impl IntoIterator<Item = &'a Path> + Clone,
    configurations: impl IntoIterator<Item = (&'a Path, Option<&'a [u8]>)>,
) -> WorkspaceTopology {
    let mut complete = TopologyCompleteness::Complete;
    let mut provider_failed = false;
    let mut sources = Vec::new();
    for (path, source) in configurations {
        let Some(system) = build_definition_system(path) else {
            continue;
        };
        provider_failed |= source.is_none_or(|source| source.len() > MAX_BUILD_METADATA_BYTES);
        let text = source
            .filter(|source| source.len() <= MAX_BUILD_METADATA_BYTES)
            .and_then(|source| std::str::from_utf8(source).ok());
        match text {
            Some(text) => sources.push((system, path, text)),
            None => complete = TopologyCompleteness::Incomplete,
        }
    }
    let mut units = Vec::new();
    if !maven_units(&sources, &mut units) {
        complete = TopologyCompleteness::Incomplete;
    }
    if !gradle_units(&sources, &mut units) {
        complete = TopologyCompleteness::Incomplete;
    }
    if !sbt_units(&sources, &mut units) {
        complete = TopologyCompleteness::Incomplete;
    }
    if units.is_empty() {
        let mut topology = WorkspaceTopology::incomplete(JVM_TOPOLOGY_SUPPORT.clone());
        if provider_failed {
            topology.mark_provider_failed();
        }
        return topology;
    }

    let mut entities = Vec::new();
    let roots: Vec<&BuildUnit> = units.iter().filter(|unit| unit.parent.is_none()).collect();
    match roots.as_slice() {
        [root] => entities.push(TopologyEntity {
            kind: TopologyEntityKind::Workspace,
            name: root.name.clone(),
            owner: None,
            root: Some(root.directory.clone()),
            provenance: vec![TopologyProvenance::new(
                root.declaration.clone(),
                TopologyProvenanceKind::ProjectDeclaration,
            )],
            completeness: complete,
        }),
        // Several unrelated builds, or none: no single build invocation root
        // is declared, so this reader does not name one.
        _ => complete = TopologyCompleteness::Incomplete,
    }

    let mut ownership = Vec::new();
    for unit in &units {
        let mut provenance = vec![TopologyProvenance::new(
            unit.declaration.clone(),
            TopologyProvenanceKind::ProjectDeclaration,
        )];
        if let Some((_, listing)) = &unit.parent
            && *listing != unit.declaration
        {
            provenance.push(TopologyProvenance::new(
                listing.clone(),
                TopologyProvenanceKind::ModuleList,
            ));
        }
        entities.push(TopologyEntity {
            kind: TopologyEntityKind::BuildProject,
            name: unit.name.clone(),
            owner: unit.parent.as_ref().map(|(parent, _)| parent.clone()),
            root: Some(unit.directory.clone()),
            provenance: provenance.clone(),
            completeness: TopologyCompleteness::Complete,
        });
        entities.push(TopologyEntity {
            kind: TopologyEntityKind::Target,
            name: unit.name.clone(),
            owner: Some(unit.name.clone()),
            root: Some(unit.directory.clone()),
            provenance,
            completeness: TopologyCompleteness::Complete,
        });

        for (role, root) in &unit.source_roots {
            let owned: Vec<PathBuf> = files
                .clone()
                .into_iter()
                .map(Path::to_path_buf)
                .filter(|path| path.starts_with(root))
                .collect();
            if owned.is_empty() {
                continue;
            }
            let name = source_set_name(&unit.name, role);
            entities.push(TopologyEntity {
                kind: TopologyEntityKind::SourceSet,
                name: name.clone(),
                owner: Some(unit.name.clone()),
                root: Some(root.clone()),
                provenance: vec![TopologyProvenance::new(
                    unit.declaration.clone(),
                    TopologyProvenanceKind::BuildModelLayout,
                )],
                completeness: TopologyCompleteness::Complete,
            });
            for path in owned {
                ownership.push(FileOwnership {
                    file: path,
                    source_set: Some(name.clone()),
                    target: Some(unit.name.clone()),
                    state: FileOwnershipState::Owned,
                });
            }
        }
    }
    collapse_ambiguous_ownership(&mut ownership);

    let mut edges = Vec::new();
    for unit in &units {
        for (target, kind) in &unit.dependencies {
            // Only targets of this workspace are related; an external
            // coordinate's evidence is a dependency row, not an edge.
            if !units
                .iter()
                .any(|candidate| candidate.system == unit.system && candidate.name == *target)
            {
                continue;
            }
            edges.push(TopologyEdge {
                from: unit.name.clone(),
                to: target.clone(),
                kind: *kind,
                provenance: vec![TopologyProvenance::new(
                    unit.declaration.clone(),
                    TopologyProvenanceKind::DependencyDeclaration,
                )],
                completeness: TopologyCompleteness::Complete,
            });
        }
    }

    entities.sort_by(|left, right| {
        (left.kind, &left.name, &left.owner).cmp(&(right.kind, &right.name, &right.owner))
    });
    entities.dedup();
    edges.sort_by(|left, right| {
        (&left.from, &left.to, left.kind, &left.provenance).cmp(&(
            &right.from,
            &right.to,
            right.kind,
            &right.provenance,
        ))
    });
    edges.dedup();
    ownership.sort_by(|left, right| left.file.cmp(&right.file));

    let mut topology = WorkspaceTopology::new(
        entities,
        edges,
        ownership,
        JVM_TOPOLOGY_SUPPORT.clone(),
        complete,
    );
    if provider_failed {
        topology.mark_provider_failed();
    }
    topology
}

/// The BuildProject each build definition declares, with its identity, for
/// readers that name an owner in `declared_by`.
pub(crate) struct DeclaredBuildProject {
    pub(crate) system: BuildSystem,
    pub(crate) declaration: PathBuf,
    pub(crate) directory: PathBuf,
    pub(crate) id: String,
}

pub(crate) fn declared_build_projects<'a>(
    configurations: impl IntoIterator<Item = (&'a Path, &'a str)>,
) -> Vec<DeclaredBuildProject> {
    let sources = configurations
        .into_iter()
        .filter_map(|(path, text)| Some((build_definition_system(path)?, path, text)))
        .collect::<Vec<_>>();
    let mut units = Vec::new();
    maven_units(&sources, &mut units);
    gradle_units(&sources, &mut units);
    sbt_units(&sources, &mut units);
    units
        .into_iter()
        .map(|unit| DeclaredBuildProject {
            system: unit.system,
            id: TopologyEntity {
                kind: TopologyEntityKind::BuildProject,
                name: unit.name.clone(),
                owner: unit.parent.as_ref().map(|(parent, _)| parent.clone()),
                root: Some(unit.directory.clone()),
                provenance: Vec::new(),
                completeness: TopologyCompleteness::Complete,
            }
            .id(),
            declaration: unit.declaration,
            directory: unit.directory,
        })
        .collect()
}

/// Maven projects of the selected poms. Returns whether every pom parsed and
/// every listed module's pom is present.
fn maven_units(sources: &[(BuildSystem, &Path, &str)], units: &mut Vec<BuildUnit>) -> bool {
    let mut complete = true;
    let mut projects = Vec::new();
    for (system, path, text) in sources {
        if *system != BuildSystem::Maven {
            continue;
        }
        match read_maven_project(path, text) {
            Some(parsed) => projects.push(parsed),
            None => complete = false,
        }
    }
    let parent_of: HashMap<&Path, &MavenProject> = projects
        .iter()
        .flat_map(|parent| {
            parent
                .modules
                .iter()
                .map(move |module| (module.as_path(), parent))
        })
        .collect();
    // A listed module with no pom in the workspace is a reactor this reader
    // cannot see the whole of.
    if projects
        .iter()
        .flat_map(|parsed| &parsed.modules)
        .any(|module| !projects.iter().any(|parsed| parsed.pom == *module))
    {
        complete = false;
    }
    for parsed in &projects {
        let dependencies = parsed
            .dependencies
            .iter()
            .filter_map(|dependency| {
                let target = projects.iter().find(|candidate| {
                    candidate.group_id == dependency.group_id
                        && candidate.artifact_id == dependency.artifact_id
                })?;
                Some((target.artifact_id.clone(), dependency.kind))
            })
            .collect();
        units.push(BuildUnit {
            system: BuildSystem::Maven,
            declaration: parsed.pom.clone(),
            directory: parsed.directory.clone(),
            name: parsed.artifact_id.clone(),
            parent: parent_of
                .get(parsed.pom.as_path())
                .map(|parent| (parent.artifact_id.clone(), parent.pom.clone())),
            dependencies,
            source_roots: parsed.source_roots.to_vec(),
        });
    }
    complete
}

/// Gradle projects: each settings file's root and includes, and each build
/// script outside every settings file as a single-project build. Returns
/// whether every file was read.
fn gradle_units(sources: &[(BuildSystem, &Path, &str)], units: &mut Vec<BuildUnit>) -> bool {
    let mut complete = true;
    let gradle = sources
        .iter()
        .filter(|(system, _, _)| *system == BuildSystem::Gradle)
        .collect::<Vec<_>>();
    let named = |directory: &Path, names: &[&str]| {
        names.iter().find_map(|name| {
            gradle
                .iter()
                .find(|(_, path, _)| *path == directory.join(name))
                .map(|(_, path, text)| (*path, *text))
        })
    };
    let settings_directories = gradle
        .iter()
        .filter(|(_, path, _)| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| GRADLE_SETTINGS.contains(&name))
        })
        .map(|(_, path, _)| path.parent().unwrap_or(Path::new("")))
        .collect::<Vec<_>>();
    // (directory, name, parent name and listing settings file) per project.
    type GradleProject = (PathBuf, String, Option<(String, PathBuf)>);
    let mut projects: Vec<GradleProject> = Vec::new();
    for directory in &settings_directories {
        let (settings_path, settings_text) =
            named(directory, &GRADLE_SETTINGS).expect("a settings directory has settings");
        let settings = if settings_path.extension().is_some_and(|ext| ext == "kts") {
            read_gradle_settings(settings_text)
        } else {
            None
        };
        let Some(settings) = settings else {
            complete = false;
            continue;
        };
        complete &= settings.unread.is_empty();
        let root_name = settings.root_name.clone().unwrap_or_else(|| {
            directory
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| ":".to_owned())
        });
        projects.push((directory.to_path_buf(), root_name.clone(), None));
        for (include, _) in &settings.includes {
            // `include("a:b")` also creates `:a`; each project's parent is
            // the one path segment above it, the root for a top-level one.
            let segments = include
                .trim_start_matches(':')
                .split(':')
                .filter(|segment| !segment.is_empty())
                .collect::<Vec<_>>();
            for depth in 1..=segments.len() {
                let parent = if depth == 1 {
                    root_name.clone()
                } else {
                    format!(":{}", segments[..depth - 1].join(":"))
                };
                projects.push((
                    directory.join(segments[..depth].iter().collect::<PathBuf>()),
                    format!(":{}", segments[..depth].join(":")),
                    Some((parent, settings_path.to_path_buf())),
                ));
            }
        }
    }
    // A build script under no settings file is a single-project build.
    for (_, path, _) in &gradle {
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !GRADLE_BUILDS.contains(&name) {
            continue;
        }
        let directory = path.parent().unwrap_or(Path::new(""));
        if settings_directories
            .iter()
            .any(|settings| directory.starts_with(settings))
        {
            continue;
        }
        // A Groovy script declares a project this reader cannot see into,
        // so it names none.
        if path.extension().is_none_or(|ext| ext != "kts") {
            complete = false;
            continue;
        }
        let name = directory
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| ":".to_owned());
        projects.push((directory.to_path_buf(), name, None));
    }
    projects.sort();
    projects.dedup();
    for (directory, name, parent) in &projects {
        let listing = parent.as_ref().map(|(_, listing)| listing.clone());
        let build = named(directory, &GRADLE_BUILDS);
        let declaration = build
            .map(|(path, _)| path.to_path_buf())
            .or_else(|| listing.clone())
            .unwrap_or_else(|| {
                named(directory, &GRADLE_SETTINGS)
                    .expect("a root project has settings or a build script")
                    .0
                    .to_path_buf()
            });
        let read = build.and_then(|(path, text)| {
            path.extension()
                .is_some_and(|ext| ext == "kts")
                .then(|| read_gradle_build(text))
                .flatten()
        });
        if build.is_some() && read.is_none() {
            complete = false;
        }
        let (source_roots, dependencies) = match &read {
            Some(script) => {
                complete &= script.unread.is_empty();
                let roots = if script
                    .plugins
                    .iter()
                    .any(|plugin| GRADLE_JVM_PLUGINS.contains(&plugin.as_str()))
                {
                    BuildUnit::default_layout(directory)
                } else {
                    Vec::new()
                };
                let dependencies = script
                    .declarations
                    .iter()
                    .filter_map(|declaration| match &declaration.target {
                        GradleTarget::Project(path) => Some((
                            format!(":{}", path.trim_start_matches(':')),
                            gradle_configuration_scope(&declaration.configuration),
                        )),
                        _ => None,
                    })
                    .collect();
                (roots, dependencies)
            }
            None => (Vec::new(), Vec::new()),
        };
        units.push(BuildUnit {
            system: BuildSystem::Gradle,
            declaration,
            directory: directory.clone(),
            name: name.clone(),
            parent: parent.clone(),
            dependencies,
            source_roots,
        });
    }
    complete
}

/// The scope a Gradle configuration name implies.
pub(crate) fn gradle_configuration_scope(configuration: &str) -> DependencyScope {
    match configuration {
        "implementation" | "api" | "compile" => DependencyScope::Compile,
        "compileOnly" | "compileOnlyApi" | "annotationProcessor" | "kapt" | "ksp" => {
            DependencyScope::Provided
        }
        "runtimeOnly" | "runtime" => DependencyScope::Runtime,
        name if name.starts_with("test") => DependencyScope::Test,
        _ => DependencyScope::Unknown,
    }
}

/// sbt projects of each outermost `build.sbt`: its `project` definitions,
/// and the root project sbt synthesizes at the build directory when none is
/// defined there. Returns whether every build file was read.
fn sbt_units(sources: &[(BuildSystem, &Path, &str)], units: &mut Vec<BuildUnit>) -> bool {
    let mut complete = true;
    let builds = sources
        .iter()
        .filter(|(system, _, _)| *system == BuildSystem::Sbt)
        .collect::<Vec<_>>();
    for (_, path, text) in &builds {
        let directory = path.parent().unwrap_or(Path::new(""));
        // A nested build.sbt adds settings to the project based there.
        if builds.iter().any(|(_, other, _)| {
            let other = other.parent().unwrap_or(Path::new(""));
            other != directory && directory.starts_with(other)
        }) {
            continue;
        }
        let Some(build) = read_sbt_build(text) else {
            complete = false;
            continue;
        };
        complete &= build.unread.is_empty();
        let base = |relative: &str| {
            normalize_relative_path_from(directory, Path::new(relative))
                .unwrap_or_else(|| directory.to_path_buf())
        };
        let root = build
            .projects
            .iter()
            .find(|project| base(&project.directory) == directory)
            .map_or_else(|| "root".to_owned(), |project| project.id.clone());
        if !build
            .projects
            .iter()
            .any(|project| base(&project.directory) == directory)
        {
            units.push(BuildUnit {
                system: BuildSystem::Sbt,
                declaration: path.to_path_buf(),
                directory: directory.to_path_buf(),
                name: root.clone(),
                parent: None,
                dependencies: Vec::new(),
                source_roots: BuildUnit::default_layout(directory),
            });
        }
        for project in &build.projects {
            let project_directory = base(&project.directory);
            units.push(BuildUnit {
                system: BuildSystem::Sbt,
                declaration: path.to_path_buf(),
                directory: project_directory.clone(),
                name: project.id.clone(),
                parent: (project.id != root).then(|| (root.clone(), path.to_path_buf())),
                dependencies: project.depends_on.clone(),
                source_roots: BuildUnit::default_layout(&project_directory),
            });
        }
    }
    complete
}

use brokk_bifrost_core::path_utils::normalize_relative_path_from;

/// One pom, read.
struct MavenProject {
    /// Workspace-relative path of the pom itself.
    pom: PathBuf,
    /// Workspace-relative directory the pom governs.
    directory: PathBuf,
    group_id: String,
    artifact_id: String,
    /// Workspace-relative pom paths of the modules this pom lists.
    modules: Vec<PathBuf>,
    dependencies: Vec<MavenDependency>,
    source_roots: [(&'static str, PathBuf); 2],
}

struct MavenDependency {
    group_id: String,
    artifact_id: String,
    kind: DependencyScope,
}

fn source_set_name(artifact_id: &str, role: &str) -> String {
    format!("{artifact_id}:{role}")
}

/// A file two declared source sets both claim is ambiguous, not owned by
/// whichever the walk reached first.
fn collapse_ambiguous_ownership(ownership: &mut Vec<FileOwnership>) {
    ownership.sort_by(|left, right| {
        (&left.file, &left.source_set).cmp(&(&right.file, &right.source_set))
    });
    let mut collapsed: Vec<FileOwnership> = Vec::with_capacity(ownership.len());
    for entry in ownership.drain(..) {
        match collapsed.last_mut() {
            Some(previous) if previous.file == entry.file => {
                if previous.source_set != entry.source_set {
                    previous.source_set = None;
                    previous.target = None;
                    previous.state = FileOwnershipState::Ambiguous;
                }
            }
            _ => collapsed.push(entry),
        }
    }
    *ownership = collapsed;
}

fn read_maven_project(path: &Path, source: &str) -> Option<MavenProject> {
    let facts = maven_configuration_from_bytes(path, source.as_bytes())?;
    let source_roots = facts.default_source_roots();
    let modules = facts
        .modules
        .into_iter()
        .filter_map(|module| {
            let MavenValue::Resolved(module) = module else {
                return None;
            };
            Some(facts.directory.join(module).join("pom.xml"))
        })
        .collect();
    let dependencies = facts
        .dependencies
        .into_iter()
        .filter_map(|dependency| {
            let MavenValue::Resolved(group_id) = dependency.group_id else {
                return None;
            };
            let MavenValue::Resolved(artifact_id) = dependency.artifact_id else {
                return None;
            };
            Some(MavenDependency {
                group_id,
                artifact_id,
                kind: dependency.topology_kind,
            })
        })
        .collect();
    Some(MavenProject {
        pom: path.to_path_buf(),
        directory: facts.directory,
        group_id: facts.group_id,
        artifact_id: facts.artifact_id,
        modules,
        dependencies,
        source_roots,
    })
}

// Preserve the engine paths while store consumers use the lower owner.
#[allow(unused_imports)]
pub use brokk_bifrost_analysis::analyzer::store::maven::{
    JvmSourceDomain, MAVEN_SOURCE_SETS, MavenConfigurationFacts, MavenDependencyFacts,
    MavenModelLimitation, MavenValue, maven_configuration_from_bytes, maven_scope_edge_kind,
    maven_value, read_maven_configuration, source_set, source_set_sees,
};

#[cfg(test)]
mod tests {

    use crate::analyzer::jvm::topology::*;

    use brokk_bifrost_analysis::analyzer::topology::AxisSupport;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::project::TestProject;

    /// The analysis crate cannot reach the `test-support` inline harness --
    /// that harness depends on this crate -- so this mirrors the sibling
    /// `dependency_discovery` tests' setup.
    fn topology_of(files: &[(&str, &str)]) -> WorkspaceTopology {
        let root = tempfile::tempdir().unwrap().keep();
        for (path, source) in files {
            let path = root.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, source).unwrap();
        }
        let project = TestProject::new(root, Language::Java);
        jvm_topology(&project).expect("a fixture with a pom applies the Maven model")
    }

    #[test]
    fn maven_configuration_preserves_direct_dependency_values_and_limits() {
        let source = br#"<project>
            <parent><groupId>parent</groupId><artifactId>base</artifactId><version>1</version></parent>
            <groupId>example</groupId><artifactId>app</artifactId><version>${revision}</version>
            <properties><revision>21</revision><optionalFlag>true</optionalFlag></properties>
            <modules><module>child</module><module>${missingModule}</module></modules>
            <dependencies>
                <dependency><groupId>example</groupId><artifactId>lib</artifactId>
                    <scope>test</scope><optional>${optionalFlag}</optional><type>test-jar</type><classifier>tests</classifier>
                </dependency>
                <dependency><groupId>${missingGroup}</groupId><version>${managedVersion}</version></dependency>
            </dependencies>
            <profiles/><dependencyManagement/>
            <build><sourceDirectory>custom</sourceDirectory><plugins/></build>
        </project>"#;
        let facts = maven_configuration_from_bytes(Path::new("module/pom.xml"), source).unwrap();
        assert_eq!(facts.group_id, "example");
        assert_eq!(facts.artifact_id, "app");
        assert_eq!(facts.version, MavenValue::Resolved("21".to_owned()));
        assert_eq!(
            facts.modules,
            vec![
                MavenValue::Resolved("child".to_owned()),
                MavenValue::Unresolved
            ]
        );
        assert_eq!(facts.dependencies.len(), 2);
        let dependency = &facts.dependencies[0];
        assert_eq!(dependency.ordinal, 0);
        assert_eq!(
            dependency.group_id,
            MavenValue::Resolved("example".to_owned())
        );
        assert_eq!(
            dependency.artifact_id,
            MavenValue::Resolved("lib".to_owned())
        );
        assert_eq!(dependency.version, MavenValue::Missing);
        assert_eq!(dependency.scope, MavenValue::Resolved("test".to_owned()));
        assert_eq!(dependency.optional, MavenValue::Resolved("true".to_owned()));
        assert_eq!(
            dependency.artifact_type,
            MavenValue::Resolved("test-jar".to_owned())
        );
        assert_eq!(
            dependency.classifier,
            MavenValue::Resolved("tests".to_owned())
        );
        // Current display topology treats only literal true as optional.
        assert_eq!(dependency.topology_kind, DependencyScope::Test);
        let unresolved = &facts.dependencies[1];
        assert_eq!(unresolved.ordinal, 1);
        assert_eq!(unresolved.group_id, MavenValue::Unresolved);
        assert_eq!(unresolved.artifact_id, MavenValue::Missing);
        assert_eq!(unresolved.version, MavenValue::Unresolved);
        assert_eq!(
            facts.limitations,
            vec![
                MavenModelLimitation::ParentModel,
                MavenModelLimitation::Profiles,
                MavenModelLimitation::DependencyManagement,
                MavenModelLimitation::CustomSourceRoots,
                MavenModelLimitation::BuildPlugins
            ]
        );
        assert_eq!(
            facts.default_source_roots(),
            [
                ("main", PathBuf::from("module/src/main")),
                ("test", PathBuf::from("module/src/test"))
            ]
        );
    }

    #[test]
    fn equal_maven_display_names_retain_distinct_configuration_directories() {
        let source =
            br#"<project><groupId>example</groupId><artifactId>same</artifactId></project>"#;
        let first = maven_configuration_from_bytes(Path::new("first/pom.xml"), source).unwrap();
        let second = maven_configuration_from_bytes(Path::new("second/pom.xml"), source).unwrap();
        assert_eq!(first.artifact_id, second.artifact_id);
        assert_ne!(first.directory, second.directory);
        assert_ne!(first.default_source_roots(), second.default_source_roots());
        assert_eq!(first.version, MavenValue::Missing);
        assert!(first.limitations.is_empty());
    }

    #[test]
    fn selected_bytes_and_paths_control_topology_without_project_reads() {
        let domain = domain_pom("");
        let paths = [Path::new("domain/src/main/java/Order.java")];
        let configurations = [
            (Path::new("pom.xml"), Some(ROOT_POM.as_bytes())),
            (Path::new("domain/pom.xml"), Some(domain.as_bytes())),
            (
                Path::new("persistence/pom.xml"),
                Some(PERSISTENCE_POM.as_bytes()),
            ),
        ];
        let before = jvm_topology_from_inputs(paths, configurations);
        assert_eq!(before.completeness(), TopologyCompleteness::Complete);
        assert_eq!(
            before.ownership_of(paths[0]).target.as_deref(),
            Some("domain")
        );

        let replacement = domain.replace(
            "<artifactId>domain</artifactId>",
            "<artifactId>renamed</artifactId>",
        );
        let after = jvm_topology_from_inputs(
            paths,
            [
                configurations[0],
                (Path::new("domain/pom.xml"), Some(replacement.as_bytes())),
                configurations[2],
            ],
        );
        assert_eq!(
            after.ownership_of(paths[0]).target.as_deref(),
            Some("renamed")
        );
        assert!(after.entity(TopologyEntityKind::Target, "domain").is_none());
        assert_eq!(
            before.ownership_of(paths[0]).target.as_deref(),
            Some("domain")
        );

        let removed = jvm_topology_from_inputs(paths, [configurations[0], configurations[2]]);
        assert_eq!(removed.completeness(), TopologyCompleteness::Incomplete);
        assert_eq!(
            removed.ownership_of(paths[0]).state,
            FileOwnershipState::Unknown
        );
        let no_sources = jvm_topology_from_inputs([], configurations);
        assert_eq!(
            no_sources
                .entities_of_kind(TopologyEntityKind::SourceSet)
                .count(),
            0
        );
    }

    #[test]
    fn selected_unavailable_invalid_and_oversized_poms_keep_topology_open() {
        let mut oversized = domain_pom("").into_bytes();
        oversized.resize(MAX_BUILD_METADATA_BYTES + 1, b' ');
        for source in [
            None,
            Some(&b"<invalid/>"[..]),
            Some(&b"\xff"[..]),
            Some(oversized.as_slice()),
        ] {
            let topology = jvm_topology_from_inputs(
                [],
                [
                    (Path::new("pom.xml"), Some(ROOT_POM.as_bytes())),
                    (Path::new("domain/pom.xml"), source),
                    (
                        Path::new("persistence/pom.xml"),
                        Some(PERSISTENCE_POM.as_bytes()),
                    ),
                ],
            );
            assert_eq!(topology.completeness(), TopologyCompleteness::Incomplete);
            assert!(
                topology
                    .entity(TopologyEntityKind::Target, "domain")
                    .is_none()
            );
        }
        let gradle = jvm_topology_from_inputs(
            [Path::new("src/main/java/App.java")],
            [(
                Path::new("build.gradle"),
                Some(&b"plugins { id 'java' }"[..]),
            )],
        );
        assert_eq!(gradle.completeness(), TopologyCompleteness::Incomplete);
        assert_eq!(
            gradle
                .ownership_of(Path::new("src/main/java/App.java"))
                .state,
            FileOwnershipState::Unknown
        );
    }

    const ROOT_POM: &str = r#"<project>
          <groupId>com.example</groupId>
          <artifactId>app</artifactId>
          <version>1.0</version>
          <modules><module>domain</module><module>persistence</module></modules>
        </project>"#;

    const PERSISTENCE_POM: &str = r#"<project>
          <parent><groupId>com.example</groupId><artifactId>app</artifactId><version>1.0</version></parent>
          <artifactId>persistence</artifactId>
        </project>"#;

    fn domain_pom(dependency: &str) -> String {
        format!(
            r#"<project>
              <parent><groupId>com.example</groupId><artifactId>app</artifactId><version>1.0</version></parent>
              <artifactId>domain</artifactId>
              <dependencies>{dependency}</dependencies>
            </project>"#
        )
    }

    /// The reader names the reactor's projects, targets, and source sets, and
    /// every one of them carries the build file that justifies it.
    #[test]
    fn maven_reactor_becomes_targets_and_source_sets_with_build_file_provenance() {
        let domain = domain_pom("");
        let topology = topology_of(&[
            ("pom.xml", ROOT_POM),
            ("domain/pom.xml", &domain),
            ("domain/src/main/java/Order.java", "class Order {}"),
            ("domain/src/test/java/OrderTest.java", "class OrderTest {}"),
            ("persistence/pom.xml", PERSISTENCE_POM),
            ("persistence/src/main/java/Rows.java", "class Rows {}"),
        ]);

        assert_eq!(topology.completeness(), TopologyCompleteness::Complete);
        assert_eq!(
            topology
                .entities_of_kind(TopologyEntityKind::Target)
                .map(|entity| entity.name.as_str())
                .collect::<Vec<_>>(),
            vec!["app", "domain", "persistence"]
        );
        let domain_target = topology
            .entity(TopologyEntityKind::Target, "domain")
            .expect("the reactor declares a domain target");
        assert_eq!(domain_target.owner.as_deref(), Some("domain"));
        assert_eq!(
            domain_target
                .provenance
                .iter()
                .map(|entry| (entry.build_file.clone(), entry.kind))
                .collect::<Vec<_>>(),
            vec![
                (
                    PathBuf::from("domain/pom.xml"),
                    TopologyProvenanceKind::ProjectDeclaration
                ),
                (PathBuf::from("pom.xml"), TopologyProvenanceKind::ModuleList),
            ]
        );

        assert_eq!(
            topology
                .entities_of_kind(TopologyEntityKind::SourceSet)
                .map(|entity| entity.name.as_str())
                .collect::<Vec<_>>(),
            vec!["domain:main", "domain:test", "persistence:main"]
        );
        let ownership = topology.ownership_of(Path::new("domain/src/test/java/OrderTest.java"));
        assert_eq!(ownership.state, FileOwnershipState::Owned);
        assert_eq!(ownership.source_set.as_deref(), Some("domain:test"));
        assert_eq!(ownership.target.as_deref(), Some("domain"));
    }

    /// A file no declared source set claims is explicitly unknown. The reader
    /// has the same `src/main` segments available for it and still refuses to
    /// guess, because no pom declares that directory.
    #[test]
    fn a_file_outside_every_declared_source_set_is_unknown_not_guessed() {
        let domain = domain_pom("");
        let topology = topology_of(&[
            ("pom.xml", ROOT_POM),
            ("domain/pom.xml", &domain),
            ("domain/src/main/java/Order.java", "class Order {}"),
            ("persistence/pom.xml", PERSISTENCE_POM),
            ("scratch/src/main/java/Loose.java", "class Loose {}"),
        ]);
        let ownership = topology.ownership_of(Path::new("scratch/src/main/java/Loose.java"));
        assert_eq!(ownership.state, FileOwnershipState::Unknown);
        assert_eq!(ownership.source_set, None);
        assert_eq!(ownership.target, None);
    }

    /// A declared dependency between two targets of the reactor becomes an
    /// edge carrying the Maven scope and the pom that declares it. An external
    /// coordinate does not.
    #[test]
    fn declared_module_dependencies_become_scoped_edges_anchored_on_their_pom() {
        let domain = domain_pom(
            r#"<dependency><groupId>com.example</groupId><artifactId>persistence</artifactId><version>1.0</version></dependency>
               <dependency><groupId>org.external</groupId><artifactId>library</artifactId><version>2.0</version></dependency>"#,
        );
        let topology = topology_of(&[
            ("pom.xml", ROOT_POM),
            ("domain/pom.xml", &domain),
            ("domain/src/main/java/Order.java", "class Order {}"),
            ("persistence/pom.xml", PERSISTENCE_POM),
            ("persistence/src/main/java/Rows.java", "class Rows {}"),
        ]);

        assert_eq!(topology.edges().len(), 1);
        let edge = &topology.edges()[0];
        assert_eq!(edge.from, "domain");
        assert_eq!(edge.to, "persistence");
        assert_eq!(edge.kind, DependencyScope::Compile);
        assert_eq!(edge.anchor(), Some(Path::new("domain/pom.xml")));
        assert_eq!(
            topology.declares_dependency("domain", "persistence"),
            (true, TopologyCompleteness::Complete)
        );
        assert_eq!(
            topology.declares_dependency("persistence", "domain"),
            (false, TopologyCompleteness::Complete)
        );
    }

    /// A test-scoped dependency is a different edge from a compile-scoped one,
    /// so an architecture rule can forbid one and permit the other.
    #[test]
    fn maven_scopes_reach_the_edge_kind() {
        let domain = domain_pom(
            r#"<dependency><groupId>com.example</groupId><artifactId>persistence</artifactId><version>1.0</version><scope>test</scope></dependency>"#,
        );
        let topology = topology_of(&[
            ("pom.xml", ROOT_POM),
            ("domain/pom.xml", &domain),
            ("domain/src/main/java/Order.java", "class Order {}"),
            ("persistence/pom.xml", PERSISTENCE_POM),
            ("persistence/src/main/java/Rows.java", "class Rows {}"),
        ]);
        assert_eq!(topology.edges().len(), 1);
        assert_eq!(topology.edges()[0].kind, DependencyScope::Test);
        assert_eq!(
            maven_scope_edge_kind(Some("import")),
            DependencyScope::Unknown
        );
    }

    /// A workspace whose build files this reader cannot see is incomplete, not
    /// clean: the missing-evidence answer a policy must not read as "no
    /// dependency declared".
    #[test]
    fn a_workspace_without_maven_metadata_is_incomplete() {
        let topology = topology_of(&[
            ("build.gradle", "plugins { id 'java' }"),
            ("domain/src/main/java/Order.java", "class Order {}"),
        ]);
        assert_eq!(topology.completeness(), TopologyCompleteness::Incomplete);
        assert!(topology.entities().is_empty());
        assert_eq!(
            topology.declares_dependency("domain", "persistence"),
            (false, TopologyCompleteness::Incomplete)
        );
        assert_eq!(
            topology.support().support(TopologyAxis::Configurations),
            AxisSupport::Unsupported
        );
    }

    /// A reactor that lists a module whose pom is missing produces the rows it
    /// could read, and reports the whole topology incomplete.
    #[test]
    fn a_module_whose_pom_is_missing_makes_the_topology_incomplete() {
        let topology = topology_of(&[
            ("pom.xml", ROOT_POM),
            ("domain/pom.xml", &domain_pom("")),
            ("domain/src/main/java/Order.java", "class Order {}"),
        ]);
        assert_eq!(topology.completeness(), TopologyCompleteness::Incomplete);
        assert!(
            topology
                .entity(TopologyEntityKind::Target, "domain")
                .is_some()
        );
        assert!(
            topology
                .entity(TopologyEntityKind::Target, "persistence")
                .is_none()
        );
    }
}
