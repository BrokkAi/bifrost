//! The JVM build model as project topology (#2448 slice 1).
//!
//! Reads the checked-in Maven metadata only: the reactor's `pom.xml` files,
//! their module lists, and the dependencies they declare. No build tool runs
//! here, unlike `JvmDependencyDiscoveryMode::OfflineBuildTools` in
//! `super::dependency_discovery`, and nothing is inferred from a path that a
//! pom does not justify.
//!
//! What the reader emits, and what justifies it:
//!
//! - One `BuildProject` and one `Target` per pom, justified by that pom's own
//!   coordinate declaration, plus the parent pom's `<modules>` entry when the
//!   reactor lists it.
//! - `main` and `test` `SourceSet`s per target, justified by the pom that
//!   selects Maven's default lifecycle. Maven compiles `src/main/java` and
//!   tests `src/test/java` by build-model definition, so the pom is the
//!   evidence; the two path segments alone would not be.
//! - One edge per declared dependency whose coordinate is another target of
//!   this same workspace, carrying the Maven scope as its kind.
//!
//! Gradle is deliberately absent. A Gradle module list lives in a Groovy or
//! Kotlin build script, and reading it means either running Gradle or
//! string-scanning a program; both are excluded here, so a Gradle-only
//! workspace gets an incomplete topology that says so rather than an empty one
//! that reads as clean.

use std::path::{Path, PathBuf};

use super::dependency_discovery::{
    MAX_BUILD_METADATA_BYTES, expand_maven_value, is_maven_pom, maven_project_properties,
    parse_xml, read_bounded_source,
};
use crate::analyzer::Project;
use crate::analyzer::topology::{
    BuildModelProvider, DependencyScope, FileOwnership, FileOwnershipState, TopologyAxis,
    TopologyCompleteness, TopologyEdge, TopologyEntity, TopologyEntityKind, TopologyProvenance,
    TopologyProvenanceKind, TopologySupport, WorkspaceTopology,
};
use crate::hash::HashMap;

/// The axes the Maven reader answers. `Configurations` stays unsupported:
/// Maven expresses scope on the dependency, which this reader publishes as the
/// edge kind, and it has no named resolution scopes of its own to enumerate.
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

    fn topology(&self, project: &dyn Project) -> WorkspaceTopology {
        maven_topology(project)
    }
}

/// The `src/main` and `src/test` roles Maven's default lifecycle fixes.
const MAVEN_SOURCE_SETS: [(&str, &str); 2] = [("main", "src/main"), ("test", "src/test")];

/// A declared value retains failed interpolation separately from absence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MavenValue {
    Missing,
    Unresolved,
    Resolved(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MavenModelLimitation {
    ParentModel,
    Profiles,
    DependencyManagement,
    CustomSourceRoots,
    BuildPlugins,
}

/// Direct declarations in one selected pom, not an effective Maven model.
/// The caller retains the selected configuration file-version/content identity.
#[derive(Debug)]
pub(crate) struct MavenConfigurationFacts {
    pub(crate) directory: PathBuf,
    pub(crate) group_id: String,
    pub(crate) artifact_id: String,
    pub(crate) version: MavenValue,
    pub(crate) modules: Vec<MavenValue>,
    pub(crate) dependencies: Vec<MavenDependencyFacts>,
    pub(crate) limitations: Vec<MavenModelLimitation>,
}

impl MavenConfigurationFacts {
    pub(crate) fn default_source_roots(&self) -> [(&'static str, PathBuf); 2] {
        MAVEN_SOURCE_SETS.map(|(role, relative)| (role, self.directory.join(relative)))
    }
}

#[derive(Debug)]
pub(crate) struct MavenDependencyFacts {
    pub(crate) ordinal: u32,
    pub(crate) group_id: MavenValue,
    pub(crate) artifact_id: MavenValue,
    pub(crate) version: MavenValue,
    pub(crate) artifact_type: MavenValue,
    pub(crate) classifier: MavenValue,
    pub(crate) scope: MavenValue,
    pub(crate) optional: MavenValue,
    // Keep the established display topology's literal optional interpretation.
    topology_kind: DependencyScope,
}

/// Parse one exact configuration without consulting other files or the host.
/// Absence, malformed XML, invalid UTF-8, an oversized input or an unresolved
/// required project coordinate cannot supply a named Maven project.
pub(crate) fn maven_configuration_from_bytes(
    pom_path: &Path,
    source: &[u8],
) -> Option<MavenConfigurationFacts> {
    if source.len() > MAX_BUILD_METADATA_BYTES {
        return None;
    }
    read_maven_configuration(pom_path, std::str::from_utf8(source).ok()?)
}

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

fn maven_topology(project: &dyn Project) -> WorkspaceTopology {
    let Ok(files) = project.all_files() else {
        return WorkspaceTopology::incomplete(JVM_TOPOLOGY_SUPPORT.clone());
    };
    let configurations: Vec<_> = files
        .iter()
        .filter(|file| is_maven_pom(file))
        .map(|file| (file.rel_path(), read_bounded_source(project, file)))
        .collect();
    maven_topology_from_inputs(
        files.iter().map(|file| file.rel_path()),
        configurations
            .iter()
            .map(|(path, source)| (*path, source.as_ref().map(|source| source.as_bytes()))),
    )
}

/// Interpret one selected inventory without reading current project files.
///
/// `files` must enumerate the selected workspace paths, and `configurations`
/// must include every selected pom, with `None` for unavailable bytes. Omission
/// means absence, not a request to load a current file. Both inputs belong to
/// the same selection; the result is owned by this topology query only.
/// Configuration identities and external/JDK inventories remain the caller's
/// authority. This reader models only Maven's default source layout.
pub(crate) fn maven_topology_from_inputs<'a>(
    files: impl IntoIterator<Item = &'a Path> + Clone,
    configurations: impl IntoIterator<Item = (&'a Path, Option<&'a [u8]>)>,
) -> WorkspaceTopology {
    let mut complete = TopologyCompleteness::Complete;
    let mut projects = Vec::new();
    for (path, source) in configurations {
        if path.file_name().is_none_or(|name| name != "pom.xml") {
            continue;
        }
        let parsed = source
            .filter(|source| source.len() <= MAX_BUILD_METADATA_BYTES)
            .and_then(|source| std::str::from_utf8(source).ok())
            .and_then(|source| read_maven_project(path, source));
        match parsed {
            Some(parsed) => projects.push(parsed),
            None => complete = TopologyCompleteness::Incomplete,
        }
    }
    if projects.is_empty() {
        return WorkspaceTopology::incomplete(JVM_TOPOLOGY_SUPPORT.clone());
    }

    let listed_modules: Vec<&PathBuf> = projects
        .iter()
        .flat_map(|parsed| parsed.modules.iter())
        .collect();
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
    if listed_modules
        .iter()
        .any(|module| !projects.iter().any(|parsed| parsed.pom == **module))
    {
        complete = TopologyCompleteness::Incomplete;
    }

    let mut entities = Vec::new();
    let roots: Vec<&MavenProject> = projects
        .iter()
        .filter(|parsed| !parent_of.contains_key(parsed.pom.as_path()))
        .collect();
    match roots.as_slice() {
        [root] => entities.push(TopologyEntity {
            kind: TopologyEntityKind::Workspace,
            name: root.artifact_id.clone(),
            owner: None,
            root: Some(root.directory.clone()),
            provenance: vec![TopologyProvenance::new(
                root.pom.clone(),
                TopologyProvenanceKind::ProjectDeclaration,
            )],
            completeness: complete,
        }),
        // Several unrelated reactors, or none: no single build invocation root
        // is declared, so this reader does not name one.
        _ => complete = TopologyCompleteness::Incomplete,
    }

    let mut ownership = Vec::new();
    for parsed in &projects {
        let mut provenance = vec![TopologyProvenance::new(
            parsed.pom.clone(),
            TopologyProvenanceKind::ProjectDeclaration,
        )];
        let owner = parent_of
            .get(parsed.pom.as_path())
            .map(|parent| parent.artifact_id.clone());
        if let Some(parent) = parent_of.get(parsed.pom.as_path()) {
            provenance.push(TopologyProvenance::new(
                parent.pom.clone(),
                TopologyProvenanceKind::ModuleList,
            ));
        }
        entities.push(TopologyEntity {
            kind: TopologyEntityKind::BuildProject,
            name: parsed.artifact_id.clone(),
            owner: owner.clone(),
            root: Some(parsed.directory.clone()),
            provenance: provenance.clone(),
            completeness: TopologyCompleteness::Complete,
        });
        entities.push(TopologyEntity {
            kind: TopologyEntityKind::Target,
            name: parsed.artifact_id.clone(),
            owner: Some(parsed.artifact_id.clone()),
            root: Some(parsed.directory.clone()),
            provenance,
            completeness: TopologyCompleteness::Complete,
        });

        for (role, root) in &parsed.source_roots {
            let owned: Vec<PathBuf> = files
                .clone()
                .into_iter()
                .map(Path::to_path_buf)
                .filter(|path| path.starts_with(root))
                .collect();
            if owned.is_empty() {
                continue;
            }
            let name = source_set_name(&parsed.artifact_id, role);
            entities.push(TopologyEntity {
                kind: TopologyEntityKind::SourceSet,
                name: name.clone(),
                owner: Some(parsed.artifact_id.clone()),
                root: Some(root.clone()),
                provenance: vec![TopologyProvenance::new(
                    parsed.pom.clone(),
                    TopologyProvenanceKind::BuildModelLayout,
                )],
                completeness: TopologyCompleteness::Complete,
            });
            for path in owned {
                ownership.push(FileOwnership {
                    file: path,
                    source_set: Some(name.clone()),
                    target: Some(parsed.artifact_id.clone()),
                    state: FileOwnershipState::Owned,
                });
            }
        }
    }
    collapse_ambiguous_ownership(&mut ownership);

    let mut edges = Vec::new();
    for parsed in &projects {
        for dependency in &parsed.dependencies {
            let Some(target) = projects.iter().find(|candidate| {
                candidate.group_id == dependency.group_id
                    && candidate.artifact_id == dependency.artifact_id
            }) else {
                // An external coordinate. Its evidence is `ResolvedDependency`,
                // not a topology edge; internal topology only relates targets
                // of this workspace.
                continue;
            };
            edges.push(TopologyEdge {
                from: parsed.artifact_id.clone(),
                to: target.artifact_id.clone(),
                kind: dependency.kind,
                provenance: vec![TopologyProvenance::new(
                    parsed.pom.clone(),
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

    WorkspaceTopology::new(
        entities,
        edges,
        ownership,
        JVM_TOPOLOGY_SUPPORT.clone(),
        complete,
    )
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

fn maven_value(value: Option<&str>, properties: &HashMap<String, String>) -> MavenValue {
    match value {
        None => MavenValue::Missing,
        Some(value) => expand_maven_value(value, properties)
            .map(MavenValue::Resolved)
            .unwrap_or(MavenValue::Unresolved),
    }
}

fn read_maven_configuration(path: &Path, source: &str) -> Option<MavenConfigurationFacts> {
    let node = parse_xml(source)?;
    if node.name != "project" {
        return None;
    }
    let properties = maven_project_properties(&node);
    let parent = node.child("parent");
    let MavenValue::Resolved(group_id) = maven_value(
        node.child_text("groupId")
            .or_else(|| parent.and_then(|parent| parent.child_text("groupId"))),
        &properties,
    ) else {
        return None;
    };
    let MavenValue::Resolved(artifact_id) = maven_value(node.child_text("artifactId"), &properties)
    else {
        return None;
    };
    if group_id.is_empty() || artifact_id.is_empty() {
        return None;
    }
    let version = maven_value(
        node.child_text("version")
            .or_else(|| parent.and_then(|parent| parent.child_text("version"))),
        &properties,
    );
    let directory = path.parent().map(Path::to_path_buf).unwrap_or_default();
    let modules = node
        .child("modules")
        .map(|modules| {
            modules
                .children_named("module")
                .map(|module| maven_value(Some(module.text.trim()), &properties))
                .collect()
        })
        .unwrap_or_default();
    let dependencies = node
        .child("dependencies")
        .map(|dependencies| {
            dependencies
                .children_named("dependency")
                .enumerate()
                .map(|(ordinal, dependency)| {
                    let scope = maven_value(dependency.child_text("scope"), &properties);
                    let optional_literal = dependency
                        .child_text("optional")
                        .is_some_and(|value| value.eq_ignore_ascii_case("true"));
                    let topology_kind = if optional_literal {
                        DependencyScope::Optional
                    } else {
                        maven_scope_edge_kind(match &scope {
                            MavenValue::Resolved(value) => Some(value),
                            _ => None,
                        })
                    };
                    MavenDependencyFacts {
                        ordinal: u32::try_from(ordinal)
                            .expect("bounded XML node inventory fits u32"),
                        group_id: maven_value(dependency.child_text("groupId"), &properties),
                        artifact_id: maven_value(dependency.child_text("artifactId"), &properties),
                        version: maven_value(dependency.child_text("version"), &properties),
                        artifact_type: maven_value(dependency.child_text("type"), &properties),
                        classifier: maven_value(dependency.child_text("classifier"), &properties),
                        scope,
                        optional: maven_value(dependency.child_text("optional"), &properties),
                        topology_kind,
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    let mut limitations = Vec::new();
    if parent.is_some() {
        limitations.push(MavenModelLimitation::ParentModel);
    }
    if node.child("profiles").is_some() {
        limitations.push(MavenModelLimitation::Profiles);
    }
    if node.child("dependencyManagement").is_some() {
        limitations.push(MavenModelLimitation::DependencyManagement);
    }
    if let Some(build) = node.child("build") {
        if build.child("sourceDirectory").is_some() || build.child("testSourceDirectory").is_some()
        {
            limitations.push(MavenModelLimitation::CustomSourceRoots);
        }
        if build.child("plugins").is_some()
            || build.child("pluginManagement").is_some()
            || build.child("extensions").is_some()
        {
            limitations.push(MavenModelLimitation::BuildPlugins);
        }
    }
    Some(MavenConfigurationFacts {
        directory,
        group_id,
        artifact_id,
        version,
        modules,
        dependencies,
        limitations,
    })
}

/// The Maven scope vocabulary as topology edge kinds. An absent scope is
/// `compile` by Maven's own default; a scope this reader does not model stays
/// [`DependencyScope::Unknown`] rather than being folded into the nearest
/// match.
pub(crate) fn maven_scope_edge_kind(scope: Option<&str>) -> DependencyScope {
    match scope.map(str::trim) {
        None | Some("") | Some("compile") => DependencyScope::Compile,
        Some("runtime") => DependencyScope::Runtime,
        Some("test") => DependencyScope::Test,
        Some("provided") => DependencyScope::Provided,
        Some(_) => DependencyScope::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::topology::AxisSupport;
    use crate::analyzer::{Language, TestProject};

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
        JVM_BUILD_MODEL.topology(&project)
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
        let before = maven_topology_from_inputs(paths, configurations);
        assert_eq!(before.completeness(), TopologyCompleteness::Complete);
        assert_eq!(
            before.ownership_of(paths[0]).target.as_deref(),
            Some("domain")
        );

        let replacement = domain.replace(
            "<artifactId>domain</artifactId>",
            "<artifactId>renamed</artifactId>",
        );
        let after = maven_topology_from_inputs(
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

        let removed = maven_topology_from_inputs(paths, [configurations[0], configurations[2]]);
        assert_eq!(removed.completeness(), TopologyCompleteness::Incomplete);
        assert_eq!(
            removed.ownership_of(paths[0]).state,
            FileOwnershipState::Unknown
        );
        let no_sources = maven_topology_from_inputs([], configurations);
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
            let topology = maven_topology_from_inputs(
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
        let gradle = maven_topology_from_inputs(
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
