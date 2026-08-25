//! Internal project topology (#2448): the build structure a workspace's own
//! build files declare.
//!
//! Bifrost had no model of a workspace's internal structure at all. Ownership
//! was a path prefix and a "source set" was a string window over `src/main`
//! and `src/test` path segments (`brokk_bifrost_core::analyzer::test_paths`).
//! Those heuristics remain, and they remain what they are: ranking inputs. A
//! topology row is different in kind. It is a statement about what the build
//! declares, so every entity and every edge here names the build files that
//! justify it, and a file whose owner no build file names is an explicit
//! [`FileOwnershipState::Unknown`] row rather than a guess from its path.
//!
//! Three things live here:
//!
//! - The vocabulary: [`TopologyEntity`], [`TopologyEdge`], [`FileOwnership`],
//!   and the provenance and completeness markers all three carry.
//! - The declared-support table ([`TopologySupport`]), which is the
//!   `X_Support`-sized-by-`Axis::COUNT` pattern from
//!   `brokk_bifrost_core::analyzer::structural::materialization`: an axis a
//!   provider does not name is explicitly unsupported, and an unsupported axis
//!   produces an incomplete topology rather than an empty one.
//! - The [`BuildModelProvider`] seam one build ecosystem implements. The
//!   providers themselves live with their ecosystem (the Maven reader is
//!   `crate::analyzer::jvm::topology`), and the registry that names them is
//!   assembly, in `crate::analyzer::languages`.

use std::path::{Path, PathBuf};

use crate::analyzer::Project;
use crate::analyzer::canonical_hash::{CanonicalHasher, lower_hex_string};

const TOPOLOGY_ENTITY_DOMAIN: &[u8] = b"bifrost.topology.entity.v1";
const TOPOLOGY_EDGE_DOMAIN: &[u8] = b"bifrost.topology.edge.v1";

/// What kind of build-model object one topology entity is.
///
/// The vocabulary is the union the supported ecosystems need, not one
/// ecosystem's spelling: a Maven reactor project and a Gradle subproject are
/// both [`TopologyEntityKind::BuildProject`], and the artifact each produces is
/// a [`TopologyEntityKind::Target`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TopologyEntityKind {
    /// The whole workspace: the root the build system is invoked at.
    Workspace,
    /// One project the build system evaluates (a Maven reactor project, a
    /// Gradle subproject).
    BuildProject,
    /// One artifact a build project produces, and the unit an architecture
    /// policy names.
    Target,
    /// A grouping a build system exposes above targets and below the
    /// workspace, where it has one.
    Module,
    /// One compilation input set of a target (Maven's `src/main` and
    /// `src/test`, a Gradle source set).
    SourceSet,
    /// One named resolution scope of a build project (a Gradle configuration).
    Configuration,
}

impl TopologyEntityKind {
    /// The published value domain of the `kind` row field (#2515).
    pub const LABELS: &'static [&'static str] = &[
        "workspace",
        "build_project",
        "target",
        "module",
        "source_set",
        "configuration",
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Workspace => "workspace",
            Self::BuildProject => "build_project",
            Self::Target => "target",
            Self::Module => "module",
            Self::SourceSet => "source_set",
            Self::Configuration => "configuration",
        }
    }
}

/// Why one build file justifies an entity or an edge.
///
/// Every variant names a statement a build file actually makes. There is no
/// variant for "the path looked like it": a producer that cannot attribute a
/// fact to a build file must not record the fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TopologyProvenanceKind {
    /// The build file exists and declares this project's own coordinate.
    ProjectDeclaration,
    /// The build file lists this project as one of its children.
    ModuleList,
    /// The build file declares this dependency.
    DependencyDeclaration,
    /// The build model this build file selects fixes this directory's role.
    /// Maven's default lifecycle compiles `src/main/java` and tests
    /// `src/test/java`; recording the pom that selects that lifecycle is what
    /// separates this from reading the same two segments off an arbitrary
    /// path.
    BuildModelLayout,
}

impl TopologyProvenanceKind {
    pub const LABELS: &'static [&'static str] = &[
        "project_declaration",
        "module_list",
        "dependency_declaration",
        "build_model_layout",
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::ProjectDeclaration => "project_declaration",
            Self::ModuleList => "module_list",
            Self::DependencyDeclaration => "dependency_declaration",
            Self::BuildModelLayout => "build_model_layout",
        }
    }
}

/// One build file, and the statement it makes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TopologyProvenance {
    /// Workspace-relative path of the build file.
    pub build_file: PathBuf,
    pub kind: TopologyProvenanceKind,
}

impl TopologyProvenance {
    pub fn new(build_file: impl Into<PathBuf>, kind: TopologyProvenanceKind) -> Self {
        let build_file = build_file.into();
        debug_assert!(
            build_file.is_relative(),
            "topology provenance must name a workspace-relative build file: {}",
            build_file.display()
        );
        Self { build_file, kind }
    }
}

/// Whether the build evidence behind a row was read in full.
///
/// `Incomplete` is the honest answer whenever a producer could not read a build
/// file it knows exists, an axis is unsupported for the workspace's ecosystem,
/// or no build file was found at all. A policy that concludes from the absence
/// of an edge must consult this, which is the whole reason it travels on the
/// row instead of on the run.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TopologyCompleteness {
    Complete,
    #[default]
    Incomplete,
}

impl TopologyCompleteness {
    pub const LABELS: &'static [&'static str] = &["complete", "incomplete"];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Incomplete => "incomplete",
        }
    }

    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }

    /// The meet of two completeness markers: incomplete wins.
    pub const fn meet(self, other: Self) -> Self {
        match (self, other) {
            (Self::Complete, Self::Complete) => Self::Complete,
            _ => Self::Incomplete,
        }
    }
}

/// One object the build declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyEntity {
    pub kind: TopologyEntityKind,
    /// The name the build declares, unique within its kind: a Maven
    /// `artifactId`, a Gradle project path, a source set qualified by the
    /// target that owns it.
    pub name: String,
    /// The entity that owns this one, where the build model gives it one: the
    /// target a source set compiles into, the build project a target belongs
    /// to.
    pub owner: Option<String>,
    /// Workspace-relative root directory, where the build model gives the
    /// entity one.
    pub root: Option<PathBuf>,
    pub provenance: Vec<TopologyProvenance>,
    pub completeness: TopologyCompleteness,
}

impl TopologyEntity {
    /// The stable identity of this entity: a digest over the coordinates that
    /// define it, never over its provenance, so re-reading the same build with
    /// one extra justifying file does not rename it.
    pub fn id(&self) -> String {
        let mut hasher = CanonicalHasher::new(TOPOLOGY_ENTITY_DOMAIN);
        hasher.field("kind", self.kind.label().as_bytes());
        hasher.field("name", self.name.as_bytes());
        hasher.field("owner", self.owner.as_deref().unwrap_or("").as_bytes());
        lower_hex_string(&hasher.finish())
    }
}

/// The build-declared scope of one dependency.
///
/// This is the shared envelope of #2442 and #2448: the same seven labels
/// describe an edge between two targets of this workspace
/// ([`TopologyEdge::kind`]) and an external package a resolver found
/// (`ResolvedDependency::scope`). One vocabulary is the point -- an
/// architecture rule that forbids a compile-scoped dependency means the same
/// thing on both sides -- and every build model this repository reads
/// expresses scope in these terms.
///
/// [`DependencyScope::Unknown`] is the default and is a real answer: a
/// resolver that cannot attribute a dependency to a scope writes it rather
/// than guessing the nearest match, and a policy concluding from scope must
/// treat it as unproven.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DependencyScope {
    Compile,
    Runtime,
    Test,
    Provided,
    Optional,
    FeatureGated,
    #[default]
    Unknown,
}

impl DependencyScope {
    pub const LABELS: &'static [&'static str] = &[
        "compile",
        "runtime",
        "test",
        "provided",
        "optional",
        "feature_gated",
        "unknown",
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Compile => "compile",
            Self::Runtime => "runtime",
            Self::Test => "test",
            Self::Provided => "provided",
            Self::Optional => "optional",
            Self::FeatureGated => "feature_gated",
            Self::Unknown => "unknown",
        }
    }
}

/// One declared dependency between two entities of the same workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyEdge {
    /// Name of the depending entity.
    pub from: String,
    /// Name of the depended-on entity.
    pub to: String,
    pub kind: DependencyScope,
    pub provenance: Vec<TopologyProvenance>,
    pub completeness: TopologyCompleteness,
}

impl TopologyEdge {
    /// The stable identity of this edge, including the build file that
    /// declares it: two build files declaring the same dependency are two
    /// pieces of evidence, and a finding anchors on one of them.
    pub fn id(&self) -> String {
        let mut hasher = CanonicalHasher::new(TOPOLOGY_EDGE_DOMAIN);
        hasher.field("from", self.from.as_bytes());
        hasher.field("to", self.to.as_bytes());
        hasher.field("kind", self.kind.label().as_bytes());
        hasher.sequence("provenance", &self.provenance, |hasher, entry| {
            hasher.field("build_file", entry.build_file.to_string_lossy().as_bytes());
            hasher.field("kind", entry.kind.label().as_bytes());
        });
        lower_hex_string(&hasher.finish())
    }

    /// The build file a finding on this edge anchors to.
    pub fn anchor(&self) -> Option<&Path> {
        self.provenance
            .first()
            .map(|entry| entry.build_file.as_path())
    }
}

/// What the build says about which source set and target one file belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FileOwnershipState {
    /// Exactly one source set of one target claims the file.
    Owned,
    /// More than one declared source set claims the file, and the build model
    /// does not say which compiles it.
    Ambiguous,
    /// No build file this producer read claims the file. This is a statement
    /// about the evidence, never a fallback derived from the path.
    Unknown,
}

impl FileOwnershipState {
    pub const LABELS: &'static [&'static str] = &["owned", "ambiguous", "unknown"];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Owned => "owned",
            Self::Ambiguous => "ambiguous",
            Self::Unknown => "unknown",
        }
    }
}

/// The `file -> source set -> target` relation for one workspace file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileOwnership {
    /// Workspace-relative path.
    pub file: PathBuf,
    pub source_set: Option<String>,
    pub target: Option<String>,
    pub state: FileOwnershipState,
}

impl FileOwnership {
    /// The row for a file no build file claims. Its own state says so; there is
    /// no path-shaped guess behind it.
    pub fn unknown(file: impl Into<PathBuf>) -> Self {
        Self {
            file: file.into(),
            source_set: None,
            target: None,
            state: FileOwnershipState::Unknown,
        }
    }
}

macro_rules! topology_axes {
    ($($variant:ident => $label:literal: $description:literal),+ $(,)?) => {
        /// One axis of the build model a provider either answers from build
        /// evidence or declares unsupported.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum TopologyAxis {
            $($variant,)+
        }

        pub const ALL_TOPOLOGY_AXES: &[TopologyAxis] = &[$(TopologyAxis::$variant,)+];

        impl TopologyAxis {
            pub const COUNT: usize = ALL_TOPOLOGY_AXES.len();

            pub const LABELS: &'static [&'static str] = &[$($label,)+];

            pub const fn index(self) -> usize {
                self as usize
            }

            pub const fn label(self) -> &'static str {
                match self {
                    $(TopologyAxis::$variant => $label,)+
                }
            }

            pub const fn description(self) -> &'static str {
                match self {
                    $(TopologyAxis::$variant => $description,)+
                }
            }
        }
    };
}

topology_axes! {
    BuildProjects => "build_projects":
        "The projects the build evaluates, each justified by its own build file.",
    Targets => "targets":
        "The artifacts the build projects produce.",
    SourceSets => "source_sets":
        "The compilation input sets of each target.",
    TargetDependencies => "target_dependencies":
        "The declared dependencies between targets of this workspace, with their scope.",
    FileOwnership => "file_ownership":
        "Which source set, and so which target, compiles each workspace file.",
    Configurations => "configurations":
        "The named resolution scopes of each build project.",
}

/// Whether a provider answers one topology axis from build evidence.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AxisSupport {
    Supported,
    #[default]
    Unsupported,
}

impl AxisSupport {
    pub const fn is_supported(self) -> bool {
        matches!(self, Self::Supported)
    }
}

/// A total topology-axis support table. Every axis a provider does not name
/// explicitly is explicitly unsupported, so a new axis cannot silently inherit
/// "supported" from a provider that has never seen it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologySupport {
    support: [AxisSupport; TopologyAxis::COUNT],
}

impl Default for TopologySupport {
    fn default() -> Self {
        Self::NONE
    }
}

impl TopologySupport {
    /// The all-unsupported table. Providers build their own by chaining
    /// [`TopologySupport::supported`] off this in a `const` initializer.
    pub const NONE: Self = Self {
        support: [AxisSupport::Unsupported; TopologyAxis::COUNT],
    };

    pub const fn supported(mut self, axis: TopologyAxis) -> Self {
        self.support[axis.index()] = AxisSupport::Supported;
        self
    }

    pub const fn support(&self, axis: TopologyAxis) -> AxisSupport {
        self.support[axis.index()]
    }

    pub const fn is_supported(&self, axis: TopologyAxis) -> bool {
        self.support(axis).is_supported()
    }

    /// Iterate in the stable order declared by [`ALL_TOPOLOGY_AXES`].
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (TopologyAxis, AxisSupport)> + '_ {
        ALL_TOPOLOGY_AXES
            .iter()
            .map(|&axis| (axis, self.support(axis)))
    }
}

/// The build structure of one workspace, as one build ecosystem's build files
/// declare it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceTopology {
    entities: Vec<TopologyEntity>,
    edges: Vec<TopologyEdge>,
    ownership: Vec<FileOwnership>,
    support: TopologySupport,
    completeness: TopologyCompleteness,
}

impl WorkspaceTopology {
    pub fn new(
        entities: Vec<TopologyEntity>,
        edges: Vec<TopologyEdge>,
        ownership: Vec<FileOwnership>,
        support: TopologySupport,
        completeness: TopologyCompleteness,
    ) -> Self {
        Self {
            entities,
            edges,
            ownership,
            support,
            completeness,
        }
    }

    /// The answer for a workspace this provider has no build evidence for: no
    /// rows, and incomplete. An empty topology is never clean, because "no
    /// declared dependency" and "no build file read" are different answers and
    /// only one of them lets a policy conclude from absence.
    pub fn incomplete(support: TopologySupport) -> Self {
        Self {
            entities: Vec::new(),
            edges: Vec::new(),
            ownership: Vec::new(),
            support,
            completeness: TopologyCompleteness::Incomplete,
        }
    }

    pub fn entities(&self) -> &[TopologyEntity] {
        &self.entities
    }

    pub fn edges(&self) -> &[TopologyEdge] {
        &self.edges
    }

    pub fn ownership(&self) -> &[FileOwnership] {
        &self.ownership
    }

    pub fn support(&self) -> &TopologySupport {
        &self.support
    }

    pub fn completeness(&self) -> TopologyCompleteness {
        self.completeness
    }

    pub fn entities_of_kind(
        &self,
        kind: TopologyEntityKind,
    ) -> impl Iterator<Item = &TopologyEntity> {
        self.entities
            .iter()
            .filter(move |entity| entity.kind == kind)
    }

    pub fn entity(&self, kind: TopologyEntityKind, name: &str) -> Option<&TopologyEntity> {
        self.entities
            .iter()
            .find(|entity| entity.kind == kind && entity.name == name)
    }

    /// What the build says about `file`. A file no read build file claims gets
    /// an explicit [`FileOwnershipState::Unknown`] row rather than no row, so a
    /// caller cannot mistake "unclaimed" for "not asked".
    pub fn ownership_of(&self, file: &Path) -> FileOwnership {
        self.ownership
            .iter()
            .find(|entry| entry.file == file)
            .cloned()
            .unwrap_or_else(|| FileOwnership::unknown(file))
    }

    /// Whether this workspace declares any edge from `from` to `to`, and the
    /// completeness of the evidence that answer rests on.
    pub fn declares_dependency(&self, from: &str, to: &str) -> (bool, TopologyCompleteness) {
        let matched: Vec<_> = self
            .edges
            .iter()
            .filter(|edge| edge.from == from && edge.to == to)
            .collect();
        let completeness = matched
            .iter()
            .fold(self.completeness, |completeness, edge| {
                completeness.meet(edge.completeness)
            });
        (!matched.is_empty(), completeness)
    }
}

/// One build ecosystem's reader of its own build files.
///
/// A provider is the only code that knows what its build files mean, so it
/// alone decides which axes it answers and what justifies each row. The
/// registry that names the providers is assembly
/// (`crate::analyzer::languages::build_model_providers`); nothing else
/// dispatches over ecosystems.
pub(crate) trait BuildModelProvider: Send + Sync {
    /// The axes this provider answers from build evidence.
    fn support(&self) -> &'static TopologySupport;

    /// Read this workspace's build files. Must not run a build tool or open a
    /// network connection: a topology row is derived from checked-in build
    /// metadata alone.
    fn topology(&self, project: &dyn Project) -> WorkspaceTopology;
}

/// The topology of `project` as every registered build model declares it.
///
/// Providers are folded rather than selected: a polyglot workspace can carry
/// two build models, and the union of what they declare is the workspace's
/// structure. Completeness is the meet, so one provider that found no build
/// file it understands leaves the whole answer incomplete -- which is the
/// point, because the missing model is exactly the evidence a policy would
/// have concluded from.
pub fn workspace_topology(project: &dyn Project) -> WorkspaceTopology {
    let mut entities = Vec::new();
    let mut edges = Vec::new();
    let mut ownership = Vec::new();
    let mut support = TopologySupport::NONE;
    let mut completeness = TopologyCompleteness::Complete;
    for provider in crate::analyzer::languages::build_model_providers() {
        let topology = provider.topology(project);
        completeness = completeness.meet(topology.completeness);
        for (axis, axis_support) in provider.support().iter() {
            if axis_support.is_supported() {
                support = support.supported(axis);
            }
        }
        entities.extend(topology.entities);
        edges.extend(topology.edges);
        ownership.extend(topology.ownership);
    }
    WorkspaceTopology {
        entities,
        edges,
        ownership,
        support,
        completeness,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The support table is total: an axis nobody named is unsupported, and
    /// naming one does not disturb its neighbours.
    #[test]
    fn topology_support_defaults_every_unnamed_axis_to_unsupported() {
        const TABLE: TopologySupport = TopologySupport::NONE
            .supported(TopologyAxis::Targets)
            .supported(TopologyAxis::FileOwnership);
        assert!(TABLE.is_supported(TopologyAxis::Targets));
        assert!(TABLE.is_supported(TopologyAxis::FileOwnership));
        assert!(!TABLE.is_supported(TopologyAxis::Configurations));
        assert!(!TABLE.is_supported(TopologyAxis::TargetDependencies));
        assert_eq!(TABLE.iter().count(), TopologyAxis::COUNT);
        assert_eq!(TopologyAxis::LABELS.len(), TopologyAxis::COUNT);
    }

    /// A workspace with no build evidence answers incomplete, and a file it
    /// was never told about gets an explicit unknown-ownership row rather than
    /// nothing.
    #[test]
    fn a_topology_without_build_evidence_is_incomplete_not_clean() {
        let topology = WorkspaceTopology::incomplete(TopologySupport::NONE);
        assert_eq!(topology.completeness(), TopologyCompleteness::Incomplete);
        assert!(topology.edges().is_empty());
        let ownership = topology.ownership_of(Path::new("domain/src/main/java/App.java"));
        assert_eq!(ownership.state, FileOwnershipState::Unknown);
        assert_eq!(ownership.target, None);
        let (declared, completeness) = topology.declares_dependency("domain", "persistence");
        assert!(!declared);
        assert_eq!(completeness, TopologyCompleteness::Incomplete);
    }

    /// Entity identity is a function of the entity's coordinates only, so the
    /// same target keeps its id when a second build file starts justifying it,
    /// while an edge's identity includes the build file that declares it.
    #[test]
    fn entity_identity_ignores_provenance_and_edge_identity_does_not() {
        let entity = TopologyEntity {
            kind: TopologyEntityKind::Target,
            name: "domain".to_owned(),
            owner: None,
            root: Some(PathBuf::from("domain")),
            provenance: vec![TopologyProvenance::new(
                PathBuf::from("domain/pom.xml"),
                TopologyProvenanceKind::ProjectDeclaration,
            )],
            completeness: TopologyCompleteness::Complete,
        };
        let mut restated = entity.clone();
        restated.provenance.push(TopologyProvenance::new(
            PathBuf::from("pom.xml"),
            TopologyProvenanceKind::ModuleList,
        ));
        assert_eq!(entity.id(), restated.id());

        let edge = TopologyEdge {
            from: "domain".to_owned(),
            to: "persistence".to_owned(),
            kind: DependencyScope::Compile,
            provenance: vec![TopologyProvenance::new(
                PathBuf::from("domain/pom.xml"),
                TopologyProvenanceKind::DependencyDeclaration,
            )],
            completeness: TopologyCompleteness::Complete,
        };
        let mut elsewhere = edge.clone();
        elsewhere.provenance = vec![TopologyProvenance::new(
            PathBuf::from("other/pom.xml"),
            TopologyProvenanceKind::DependencyDeclaration,
        )];
        assert_ne!(edge.id(), elsewhere.id());
        assert_eq!(edge.anchor(), Some(Path::new("domain/pom.xml")));
    }
}
