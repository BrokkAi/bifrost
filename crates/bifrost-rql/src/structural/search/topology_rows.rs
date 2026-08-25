//! The execution adapter between the query engine and the project-topology
//! model (#2448 slice 2: the row surface of the vocabulary slice 1 froze).
//!
//! Three row families live here, and all three are statements a build file
//! makes:
//!
//! * `build_target` -- one artifact the build declares, reached from a file
//!   through `target_of`.
//! * `source_set` -- one compilation input set, reached from a file through
//!   `source_set_of`.
//! * `topology_edge` -- one declared dependency between two targets of this
//!   workspace, reached from a target through `topology_edges_of`.
//!
//! Nothing here reads a path. `crate::analyzer::topology` is the single source
//! of truth for what the build declares, and the ownership relation this module
//! projects is the one its providers derived from build files. The path
//! heuristics in `brokk_bifrost_core::analyzer::test_paths` stay what they are
//! -- ranking inputs -- and are deliberately not a fallback here.
//!
//! Three honesty properties the rows are built to keep:
//!
//! * An empty answer is never silently a complete one. A workspace whose build
//!   model no provider could read reports
//!   [`CodeQueryDiagnosticCode::TopologyDerivationIncomplete`], so the response
//!   is incomplete and a policy cannot read "no declared dependency" off a
//!   build nobody could see.
//! * A file two declared source sets both claim produces no owner row and an
//!   explicit ambiguity diagnostic, rather than the first source set the walk
//!   reached.
//! * A file no build file claims, in a workspace whose build model *was* read
//!   in full, produces no row and no diagnostic. That is a proven absence and
//!   the only case in which one is publishable.
//!
//! Deliberately not stored: like the flow-state, rewrite-path and
//! control-relation families, these rows are derived on demand from the build
//! files already in the workspace and memoised per request. Nothing enters the
//! semantic IR, so no adapter version moves.

use super::results::{
    CodeQueryBuildTarget, CodeQueryDiagnostic, CodeQueryDiagnosticCode, CodeQueryDiagnosticImpact,
    CodeQueryResultRef, CodeQuerySourceSet, CodeQueryTopologyEdge, DetailedCodeQueryKey,
};
use crate::analyzer::topology::{
    FileOwnership, FileOwnershipState, TopologyAxis, TopologyCompleteness, TopologyEntity,
    TopologyEntityKind, WorkspaceTopology, workspace_topology,
};
use crate::analyzer::{IAnalyzer, Language, ProjectFile};
use crate::hash::HashSet;
use crate::path_utils::rel_path_string;
use std::sync::Arc;

/// Per-request memo of the workspace's declared topology plus the diagnostics
/// already reported, so the build files are read once per query and one reason
/// is reported once.
///
/// The topology is a property of the workspace rather than of any one seed, so
/// unlike the per-procedure and per-file caches beside it this holds exactly
/// one derivation.
#[derive(Default)]
pub(super) struct TopologyTraversalCache {
    topology: Option<Arc<WorkspaceTopology>>,
    reported: HashSet<(String, &'static str)>,
}

impl TopologyTraversalCache {
    /// Read (or replay) the workspace's declared topology.
    pub(super) fn workspace(&mut self, analyzer: &dyn IAnalyzer) -> Arc<WorkspaceTopology> {
        if let Some(cached) = &self.topology {
            return Arc::clone(cached);
        }
        let derived = Arc::new(workspace_topology(analyzer.project()));
        self.topology = Some(Arc::clone(&derived));
        derived
    }

    /// Report the workspace-level incompleteness one topology axis carries.
    ///
    /// Reported before any row is emitted, so a step that returns nothing still
    /// leaves the reason on the response. Two distinct reasons: the providers
    /// could not read the build model in full, and no registered provider
    /// answers this axis at all. Both make an absence claim unpublishable, and
    /// naming them apart is what tells "the build says nothing here" from
    /// "Bifrost has no reader for this build system".
    fn report_axis(
        &mut self,
        topology: &WorkspaceTopology,
        axis: TopologyAxis,
        diagnostics: &mut Vec<CodeQueryDiagnostic>,
    ) {
        if !topology.support().is_supported(axis) {
            self.report(
                "workspace",
                CodeQueryDiagnosticCode::TopologyDerivationIncomplete,
                "no registered build-model provider answers this topology axis",
                format!(
                    "no build model in this workspace declares the `{}` topology axis ({}), so \
                     the absence of a row is not evidence of an absent declaration",
                    axis.label(),
                    axis.description()
                ),
                diagnostics,
            );
            return;
        }
        if !topology.completeness().is_complete() {
            self.report(
                "workspace",
                CodeQueryDiagnosticCode::TopologyDerivationIncomplete,
                "the workspace's build model could not be read in full",
                format!(
                    "the declared project topology is incomplete, so the `{}` rows are not the \
                     whole set the build declares",
                    axis.label()
                ),
                diagnostics,
            );
        }
    }

    /// Report that the build model does not say which source set compiles one
    /// file.
    fn report_ambiguous_ownership(
        &mut self,
        file: &ProjectFile,
        diagnostics: &mut Vec<CodeQueryDiagnostic>,
    ) {
        let path = rel_path_string(file);
        self.report(
            &path,
            CodeQueryDiagnosticCode::TopologyOwnershipAmbiguous,
            "more than one declared source set claims this file",
            format!(
                "more than one declared source set claims {path}, and the build model does not \
                 say which one compiles it, so no owner row is published for it"
            ),
            diagnostics,
        );
    }

    fn report(
        &mut self,
        subject: &str,
        code: CodeQueryDiagnosticCode,
        detail: &'static str,
        message: String,
        diagnostics: &mut Vec<CodeQueryDiagnostic>,
    ) {
        if !self.reported.insert((subject.to_string(), detail)) {
            return;
        }
        diagnostics.push(CodeQueryDiagnostic {
            code,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            // A build file belongs to no analyzed language, and the topology is
            // a property of the workspace rather than of one language's
            // sources.
            language: Language::None.config_label(),
            message,
        });
    }
}

/// One topology entity row travelling through the pipeline.
///
/// The whole topology is held by `Arc` rather than the single entity: one query
/// commonly asks for the owner of every file in a module, and every row shares
/// it. `build_file` is the workspace file the entity's own provenance names,
/// resolved once here so the row's evidence anchor and its `build_file` column
/// cannot disagree.
#[derive(Debug, Clone)]
pub(super) struct TopologyEntityValue {
    pub(super) topology: Arc<WorkspaceTopology>,
    pub(super) entity: usize,
    pub(super) build_file: ProjectFile,
}

impl TopologyEntityValue {
    pub(super) fn row(&self) -> &TopologyEntity {
        &self.topology.entities()[self.entity]
    }

    pub(super) fn file(&self) -> &ProjectFile {
        &self.build_file
    }

    /// The row's own completeness: the entity's, met with the whole
    /// derivation's. A complete entity read out of an incomplete topology is
    /// still evidence about a build nobody saw all of.
    fn completeness(&self) -> TopologyCompleteness {
        self.row().completeness.meet(self.topology.completeness())
    }

    pub(super) fn key(&self) -> TopologyEntityKey {
        TopologyEntityKey {
            id: self.row().id(),
        }
    }
}

/// One declared dependency row travelling through the pipeline.
#[derive(Debug, Clone)]
pub(super) struct TopologyEdgeValue {
    pub(super) topology: Arc<WorkspaceTopology>,
    pub(super) edge: usize,
    /// The seed target's row identity, so `from_id` is the id of the very row
    /// this edge was expanded from rather than a second lookup that could
    /// disagree with it.
    pub(super) from_id: String,
    pub(super) build_file: ProjectFile,
}

impl TopologyEdgeValue {
    fn row(&self) -> &crate::analyzer::topology::TopologyEdge {
        &self.topology.edges()[self.edge]
    }

    pub(super) fn file(&self) -> &ProjectFile {
        &self.build_file
    }

    fn completeness(&self) -> TopologyCompleteness {
        self.row().completeness.meet(self.topology.completeness())
    }

    pub(super) fn key(&self) -> TopologyEdgeKey {
        TopologyEdgeKey {
            id: self.row().id(),
        }
    }
}

/// Dedup identity of a topology entity row: the entity's own stable id, so the
/// hundred files of one module expand to one target row rather than a hundred.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct TopologyEntityKey {
    pub(super) id: String,
}

/// Dedup identity of a topology edge row: the edge's own stable id, which
/// includes the build file that declares it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct TopologyEdgeKey {
    pub(super) id: String,
}

/// The build file one entity or edge is anchored to: the first build file its
/// own provenance names.
///
/// `None` means the producer recorded no justifying build file at all. That row
/// is not published: the topology module's own contract is that a fact no build
/// file justifies must not be recorded, and a row with no anchor could not be
/// published as a finding location anyway.
fn anchor_file(seed: &ProjectFile, build_file: Option<&std::path::Path>) -> Option<ProjectFile> {
    build_file.map(|path| seed.with_rel_path(path))
}

/// The `build_target` rows of one file: the target the build says compiles it.
///
/// At most one row, because the ownership relation names at most one target. A
/// file the build model does not resolve produces no row and, when the reason
/// is ambiguity or unread build evidence, a diagnostic that says which.
pub(super) fn build_targets_of_file(
    cache: &mut TopologyTraversalCache,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<TopologyEntityValue> {
    let topology = cache.workspace(analyzer);
    cache.report_axis(&topology, TopologyAxis::Targets, diagnostics);
    let ownership = topology.ownership_of(file.rel_path());
    let Some(name) = owner_name(cache, file, &ownership, |owner| owner.target, diagnostics) else {
        return Vec::new();
    };
    entity_rows(&topology, TopologyEntityKind::Target, name, file)
}

/// The `source_set` rows of one file: the compilation input set the build says
/// it belongs to.
pub(super) fn source_sets_of_file(
    cache: &mut TopologyTraversalCache,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<TopologyEntityValue> {
    let topology = cache.workspace(analyzer);
    cache.report_axis(&topology, TopologyAxis::SourceSets, diagnostics);
    let ownership = topology.ownership_of(file.rel_path());
    let Some(name) = owner_name(
        cache,
        file,
        &ownership,
        |owner| owner.source_set,
        diagnostics,
    ) else {
        return Vec::new();
    };
    entity_rows(&topology, TopologyEntityKind::SourceSet, name, file)
}

/// The declared name of one file's owner on one axis, or nothing plus the
/// reason.
///
/// `Ambiguous` is the case worth naming: it is a build model that declares two
/// claimants and does not resolve them, which is different in kind from a file
/// nothing claims.
fn owner_name(
    cache: &mut TopologyTraversalCache,
    file: &ProjectFile,
    ownership: &FileOwnership,
    axis: impl FnOnce(FileOwnership) -> Option<String>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Option<String> {
    if ownership.state == FileOwnershipState::Ambiguous {
        cache.report_ambiguous_ownership(file, diagnostics);
        return None;
    }
    axis(ownership.clone())
}

fn entity_rows(
    topology: &Arc<WorkspaceTopology>,
    kind: TopologyEntityKind,
    name: String,
    seed: &ProjectFile,
) -> Vec<TopologyEntityValue> {
    topology
        .entities()
        .iter()
        .enumerate()
        .filter(|(_, entity)| entity.kind == kind && entity.name == name)
        .filter_map(|(index, entity)| {
            Some(TopologyEntityValue {
                topology: Arc::clone(topology),
                entity: index,
                build_file: anchor_file(
                    seed,
                    entity
                        .provenance
                        .first()
                        .map(|entry| entry.build_file.as_path()),
                )?,
            })
        })
        .collect()
}

/// The `topology_edge` rows one target declares: every dependency whose
/// depending end is this target.
pub(super) fn topology_edges_of_target(
    cache: &mut TopologyTraversalCache,
    target: &TopologyEntityValue,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<TopologyEdgeValue> {
    cache.report_axis(
        &target.topology,
        TopologyAxis::TargetDependencies,
        diagnostics,
    );
    let from = target.row().name.clone();
    let from_id = target.row().id();
    target
        .topology
        .edges()
        .iter()
        .enumerate()
        .filter(|(_, edge)| edge.from == from)
        .filter_map(|(index, edge)| {
            Some(TopologyEdgeValue {
                topology: Arc::clone(&target.topology),
                edge: index,
                from_id: from_id.clone(),
                build_file: anchor_file(target.file(), edge.anchor())?,
            })
        })
        .collect()
}

/// The public projection of one `source_set` row.
pub(super) fn public_source_set(value: &TopologyEntityValue) -> CodeQuerySourceSet {
    let entity = value.row();
    debug_assert_eq!(
        entity.kind,
        TopologyEntityKind::SourceSet,
        "a source_set row projects a source-set entity"
    );
    CodeQuerySourceSet {
        id: entity.id(),
        name: entity.name.clone(),
        target_id: owner_entity_id(&value.topology, TopologyEntityKind::Target, entity),
        build_file: rel_path_string(value.file()),
        completeness: value.completeness().label(),
    }
}

/// The public projection of one `build_target` row.
pub(super) fn public_build_target(value: &TopologyEntityValue) -> CodeQueryBuildTarget {
    let entity = value.row();
    debug_assert_eq!(
        entity.kind,
        TopologyEntityKind::Target,
        "a build_target row projects a target entity"
    );
    CodeQueryBuildTarget {
        id: entity.id(),
        name: entity.name.clone(),
        build_project_id: owner_entity_id(
            &value.topology,
            TopologyEntityKind::BuildProject,
            entity,
        ),
        build_file: rel_path_string(value.file()),
        completeness: value.completeness().label(),
    }
}

/// The public projection of one `topology_edge` row.
pub(super) fn public_topology_edge(value: &TopologyEdgeValue) -> CodeQueryTopologyEdge {
    let edge = value.row();
    CodeQueryTopologyEdge {
        id: edge.id(),
        from_id: value.from_id.clone(),
        // The depended-on end is resolved through the entity table rather than
        // assumed: a build model may declare a dependency on a coordinate it
        // does not also declare as a target of this workspace, and an id that
        // joins to no row would be worse than an absent one.
        to_id: value
            .topology
            .entity(TopologyEntityKind::Target, &edge.to)
            .map(TopologyEntity::id),
        from_name: edge.from.clone(),
        to_name: edge.to.clone(),
        scope: edge.kind.label(),
        build_file: rel_path_string(value.file()),
        completeness: value.completeness().label(),
    }
}

/// The identity of the entity that owns `entity` on one kind axis, where the
/// build model declares one and the topology also carries that entity.
fn owner_entity_id(
    topology: &WorkspaceTopology,
    kind: TopologyEntityKind,
    entity: &TopologyEntity,
) -> Option<String> {
    let owner = entity.owner.as_deref()?;
    topology.entity(kind, owner).map(TopologyEntity::id)
}

pub(super) fn source_set_key(value: &TopologyEntityValue) -> DetailedCodeQueryKey {
    let entity = value.row();
    DetailedCodeQueryKey::SourceSet {
        id: entity.id(),
        name: entity.name.clone(),
    }
}

pub(super) fn build_target_key(value: &TopologyEntityValue) -> DetailedCodeQueryKey {
    let entity = value.row();
    DetailedCodeQueryKey::BuildTarget {
        id: entity.id(),
        name: entity.name.clone(),
    }
}

pub(super) fn topology_edge_key(value: &TopologyEdgeValue) -> DetailedCodeQueryKey {
    let edge = value.row();
    DetailedCodeQueryKey::TopologyEdge {
        id: edge.id(),
        from_name: edge.from.clone(),
        to_name: edge.to.clone(),
        scope: edge.kind.label().to_string(),
    }
}

pub(super) fn source_set_ref(value: &TopologyEntityValue) -> CodeQueryResultRef {
    let public = public_source_set(value);
    CodeQueryResultRef::SourceSet {
        id: public.id,
        path: public.build_file,
        name: public.name,
    }
}

pub(super) fn build_target_ref(value: &TopologyEntityValue) -> CodeQueryResultRef {
    let public = public_build_target(value);
    CodeQueryResultRef::BuildTarget {
        id: public.id,
        path: public.build_file,
        name: public.name,
    }
}

pub(super) fn topology_edge_ref(value: &TopologyEdgeValue) -> CodeQueryResultRef {
    let public = public_topology_edge(value);
    CodeQueryResultRef::TopologyEdge {
        id: public.id,
        path: public.build_file,
        from_name: public.from_name,
        to_name: public.to_name,
        scope: public.scope,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::topology::{
        DependencyScope, TopologyEdge, TopologyProvenance, TopologyProvenanceKind, TopologySupport,
    };
    use std::path::PathBuf;

    fn target(
        name: &str,
        owner: Option<&str>,
        completeness: TopologyCompleteness,
    ) -> TopologyEntity {
        TopologyEntity {
            kind: TopologyEntityKind::Target,
            name: name.to_owned(),
            owner: owner.map(str::to_owned),
            root: Some(PathBuf::from(name)),
            provenance: vec![TopologyProvenance::new(
                PathBuf::from(name).join("pom.xml"),
                TopologyProvenanceKind::ProjectDeclaration,
            )],
            completeness,
        }
    }

    fn seed_file() -> ProjectFile {
        let root = if cfg!(windows) {
            PathBuf::from("C:\\workspace")
        } else {
            PathBuf::from("/workspace")
        };
        ProjectFile::new(root, PathBuf::from("domain/src/main/java/Order.java"))
    }

    /// A complete entity read out of an incomplete topology is still evidence
    /// about a build nobody saw all of, so the row says `incomplete`.
    #[test]
    fn a_rows_completeness_meets_the_whole_derivations() {
        let topology = Arc::new(WorkspaceTopology::new(
            vec![target("domain", None, TopologyCompleteness::Complete)],
            Vec::new(),
            Vec::new(),
            TopologySupport::NONE.supported(TopologyAxis::Targets),
            TopologyCompleteness::Incomplete,
        ));
        let value = TopologyEntityValue {
            topology,
            entity: 0,
            build_file: seed_file().with_rel_path("domain/pom.xml"),
        };
        assert_eq!(public_build_target(&value).completeness, "incomplete");
    }

    /// The depended-on end joins to a target row when the workspace declares
    /// one, and is absent -- rather than a dangling id -- when it does not.
    #[test]
    fn an_edge_names_its_depended_on_target_only_when_the_workspace_declares_it() {
        let domain = target("domain", Some("domain"), TopologyCompleteness::Complete);
        let persistence = target(
            "persistence",
            Some("persistence"),
            TopologyCompleteness::Complete,
        );
        let edges = vec![
            TopologyEdge {
                from: "domain".to_owned(),
                to: "persistence".to_owned(),
                kind: DependencyScope::Compile,
                provenance: vec![TopologyProvenance::new(
                    PathBuf::from("domain").join("pom.xml"),
                    TopologyProvenanceKind::DependencyDeclaration,
                )],
                completeness: TopologyCompleteness::Complete,
            },
            TopologyEdge {
                from: "domain".to_owned(),
                to: "not-a-declared-target".to_owned(),
                kind: DependencyScope::Test,
                provenance: vec![TopologyProvenance::new(
                    PathBuf::from("domain").join("pom.xml"),
                    TopologyProvenanceKind::DependencyDeclaration,
                )],
                completeness: TopologyCompleteness::Complete,
            },
        ];
        let topology = Arc::new(WorkspaceTopology::new(
            vec![domain.clone(), persistence.clone()],
            edges,
            Vec::new(),
            TopologySupport::NONE.supported(TopologyAxis::TargetDependencies),
            TopologyCompleteness::Complete,
        ));
        let seed = seed_file();
        let declared = TopologyEdgeValue {
            topology: Arc::clone(&topology),
            edge: 0,
            from_id: domain.id(),
            build_file: seed.with_rel_path("domain/pom.xml"),
        };
        let undeclared = TopologyEdgeValue {
            topology,
            edge: 1,
            from_id: domain.id(),
            build_file: seed.with_rel_path("domain/pom.xml"),
        };
        let declared = public_topology_edge(&declared);
        assert_eq!(declared.from_id, domain.id());
        assert_eq!(declared.to_id, Some(persistence.id()));
        assert_eq!(declared.scope, "compile");
        assert_eq!(public_topology_edge(&undeclared).to_id, None);
    }

    /// A file two source sets claim publishes no owner row and one diagnostic
    /// that says why. The first claimant is never the answer.
    #[test]
    fn an_ambiguous_file_publishes_a_diagnostic_and_no_owner() {
        let mut cache = TopologyTraversalCache::default();
        let file = seed_file();
        let ownership = FileOwnership {
            file: file.rel_path().to_path_buf(),
            source_set: None,
            target: None,
            state: FileOwnershipState::Ambiguous,
        };
        let mut diagnostics = Vec::new();
        assert_eq!(
            owner_name(
                &mut cache,
                &file,
                &ownership,
                |owner| owner.target,
                &mut diagnostics
            ),
            None
        );
        assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
        assert_eq!(
            diagnostics[0].code,
            CodeQueryDiagnosticCode::TopologyOwnershipAmbiguous
        );
        // One reason is reported once per subject.
        owner_name(
            &mut cache,
            &file,
            &ownership,
            |owner| owner.target,
            &mut diagnostics,
        );
        assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
    }

    /// An axis no provider answers and a build model nobody could read fully
    /// are different reasons, and both make the response incomplete.
    #[test]
    fn an_unsupported_axis_and_an_unread_build_are_reported_apart() {
        let mut cache = TopologyTraversalCache::default();
        let unsupported = WorkspaceTopology::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            TopologySupport::NONE,
            TopologyCompleteness::Complete,
        );
        let mut diagnostics = Vec::new();
        cache.report_axis(&unsupported, TopologyAxis::Targets, &mut diagnostics);
        assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
        assert!(
            diagnostics[0].message.contains("no build model"),
            "{:?}",
            diagnostics[0]
        );

        let unread =
            WorkspaceTopology::incomplete(TopologySupport::NONE.supported(TopologyAxis::Targets));
        cache.report_axis(&unread, TopologyAxis::Targets, &mut diagnostics);
        assert_eq!(diagnostics.len(), 2, "{diagnostics:?}");
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.impact == CodeQueryDiagnosticImpact::Incomplete),
            "{diagnostics:?}"
        );

        // A complete, supported axis says nothing at all: that is the one case
        // in which an empty row set is a proven absence.
        let complete = WorkspaceTopology::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            TopologySupport::NONE.supported(TopologyAxis::Targets),
            TopologyCompleteness::Complete,
        );
        cache.report_axis(&complete, TopologyAxis::Targets, &mut diagnostics);
        assert_eq!(diagnostics.len(), 2, "{diagnostics:?}");
    }
}
