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
    XmlNode, expand_maven_value, is_maven_pom, maven_project_properties, parse_xml,
    read_bounded_source,
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
    let mut complete = TopologyCompleteness::Complete;
    let mut projects = Vec::new();
    for file in &files {
        if !is_maven_pom(file) {
            continue;
        }
        match read_maven_project(project, file) {
            Some(parsed) => projects.push(parsed),
            // A pom the workspace has but this reader could not read or could
            // not name: the topology it produces is missing whatever that pom
            // declares, and must say so.
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

        for (role, relative) in MAVEN_SOURCE_SETS {
            let root = parsed.directory.join(relative);
            let owned: Vec<PathBuf> = files
                .iter()
                .map(|file| file.rel_path().to_path_buf())
                .filter(|path| path.starts_with(&root))
                .collect();
            if owned.is_empty() {
                continue;
            }
            let name = source_set_name(&parsed.artifact_id, role);
            entities.push(TopologyEntity {
                kind: TopologyEntityKind::SourceSet,
                name: name.clone(),
                owner: Some(parsed.artifact_id.clone()),
                root: Some(root),
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

fn read_maven_project(
    project: &dyn Project,
    file: &crate::analyzer::ProjectFile,
) -> Option<MavenProject> {
    let source = read_bounded_source(project, file)?;
    let node = parse_xml(&source)?;
    if node.name != "project" {
        return None;
    }
    let properties = maven_project_properties(&node);
    let parent = node.child("parent");
    let group_id = node
        .child_text("groupId")
        .or_else(|| parent.and_then(|parent| parent.child_text("groupId")))
        .and_then(|value| expand_maven_value(value, &properties))?;
    let artifact_id = node
        .child_text("artifactId")
        .and_then(|value| expand_maven_value(value, &properties))?;
    if group_id.is_empty() || artifact_id.is_empty() {
        return None;
    }
    let pom = file.rel_path().to_path_buf();
    let directory = pom.parent().map(Path::to_path_buf).unwrap_or_default();

    let modules = node
        .child("modules")
        .map(|modules| {
            modules
                .children_named("module")
                .filter_map(|module| expand_maven_value(module.text.trim(), &properties))
                .map(|module| directory.join(module).join("pom.xml"))
                .collect()
        })
        .unwrap_or_default();

    let dependencies = node
        .child("dependencies")
        .map(|dependencies| maven_dependencies(dependencies, &properties))
        .unwrap_or_default();

    Some(MavenProject {
        pom,
        directory,
        group_id,
        artifact_id,
        modules,
        dependencies,
    })
}

fn maven_dependencies(
    dependencies: &XmlNode,
    properties: &HashMap<String, String>,
) -> Vec<MavenDependency> {
    dependencies
        .children_named("dependency")
        .filter_map(|dependency| {
            let group_id = dependency
                .child_text("groupId")
                .and_then(|value| expand_maven_value(value, properties))?;
            let artifact_id = dependency
                .child_text("artifactId")
                .and_then(|value| expand_maven_value(value, properties))?;
            let optional = dependency
                .child_text("optional")
                .is_some_and(|value| value.eq_ignore_ascii_case("true"));
            let scope = dependency
                .child_text("scope")
                .and_then(|value| expand_maven_value(value, properties));
            let kind = if optional {
                DependencyScope::Optional
            } else {
                maven_scope_edge_kind(scope.as_deref())
            };
            Some(MavenDependency {
                group_id,
                artifact_id,
                kind,
            })
        })
        .collect()
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
