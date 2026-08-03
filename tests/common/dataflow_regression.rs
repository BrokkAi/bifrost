//! Small deterministic language-neutral ICFGs shared by data-flow gates.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use brokk_bifrost::Language;
use brokk_bifrost::analyzer::semantic::*;

const SOURCE: SourceMappingId = SourceMappingId::new(0);
const EVIDENCE: EvidenceId = EvidenceId::new(0);
const BLOCK: BlockId = BlockId::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RegressionScenario {
    StraightLine,
    DiamondJoin,
    Loop,
    NestedCall,
    MatchedReturn,
    RecursiveScc,
    ExceptionalReturn,
    Cleanup,
}

impl RegressionScenario {
    pub const ALL: [Self; 8] = [
        Self::StraightLine,
        Self::DiamondJoin,
        Self::Loop,
        Self::NestedCall,
        Self::MatchedReturn,
        Self::RecursiveScc,
        Self::ExceptionalReturn,
        Self::Cleanup,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::StraightLine => "straight_line",
            Self::DiamondJoin => "diamond_join",
            Self::Loop => "loop",
            Self::NestedCall => "nested_call",
            Self::MatchedReturn => "matched_return",
            Self::RecursiveScc => "recursive_scc",
            Self::ExceptionalReturn => "exceptional_return",
            Self::Cleanup => "cleanup",
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RegressionMutation {
    pub reverse_edges: bool,
    pub reverse_provider_rows: bool,
}

#[derive(Debug, Clone)]
struct CallSpec {
    point: u32,
    target_procedure: u32,
    normal_continuation: u32,
    exceptional_continuation: u32,
}

#[derive(Debug, Clone)]
struct ProcedureSpec {
    name: &'static str,
    point_count: u32,
    normal_exit: u32,
    exceptional_exit: u32,
    edges: Vec<(u32, u32, ControlEdgeKind)>,
    calls: Vec<CallSpec>,
}

impl ProcedureSpec {
    fn line(name: &'static str) -> Self {
        Self {
            name,
            point_count: 4,
            normal_exit: 2,
            exceptional_exit: 3,
            edges: vec![
                (0, 1, ControlEdgeKind::Normal),
                (1, 2, ControlEdgeKind::Normal),
            ],
            calls: Vec::new(),
        }
    }

    fn caller(name: &'static str, target_procedure: u32) -> Self {
        Self {
            name,
            point_count: 5,
            normal_exit: 3,
            exceptional_exit: 4,
            edges: vec![
                (0, 1, ControlEdgeKind::Normal),
                (1, 2, ControlEdgeKind::Normal),
                (1, 4, ControlEdgeKind::Exceptional),
                (2, 3, ControlEdgeKind::Normal),
            ],
            calls: vec![CallSpec {
                point: 1,
                target_procedure,
                normal_continuation: 2,
                exceptional_continuation: 4,
            }],
        }
    }
}

fn scenario_specs(scenario: RegressionScenario) -> Vec<ProcedureSpec> {
    match scenario {
        RegressionScenario::StraightLine => vec![ProcedureSpec::line("root")],
        RegressionScenario::DiamondJoin => vec![ProcedureSpec {
            name: "root",
            point_count: 7,
            normal_exit: 5,
            exceptional_exit: 6,
            edges: vec![
                (0, 1, ControlEdgeKind::Normal),
                (1, 2, ControlEdgeKind::ConditionalTrue),
                (1, 3, ControlEdgeKind::ConditionalFalse),
                (2, 4, ControlEdgeKind::Normal),
                (3, 4, ControlEdgeKind::Normal),
                (4, 5, ControlEdgeKind::Normal),
            ],
            calls: Vec::new(),
        }],
        RegressionScenario::Loop => vec![ProcedureSpec {
            name: "root",
            point_count: 5,
            normal_exit: 3,
            exceptional_exit: 4,
            edges: vec![
                (0, 1, ControlEdgeKind::Normal),
                (1, 2, ControlEdgeKind::ConditionalTrue),
                (1, 3, ControlEdgeKind::ConditionalFalse),
                (2, 1, ControlEdgeKind::LoopBack),
            ],
            calls: Vec::new(),
        }],
        RegressionScenario::NestedCall => vec![
            ProcedureSpec::caller("root", 1),
            ProcedureSpec::caller("helper", 2),
            ProcedureSpec::line("leaf"),
        ],
        RegressionScenario::MatchedReturn => {
            let mut root = ProcedureSpec {
                name: "root",
                point_count: 7,
                normal_exit: 5,
                exceptional_exit: 6,
                edges: vec![
                    (0, 1, ControlEdgeKind::Normal),
                    (1, 2, ControlEdgeKind::Normal),
                    (1, 6, ControlEdgeKind::Exceptional),
                    (2, 3, ControlEdgeKind::Normal),
                    (3, 4, ControlEdgeKind::Normal),
                    (3, 6, ControlEdgeKind::Exceptional),
                    (4, 5, ControlEdgeKind::Normal),
                ],
                calls: vec![
                    CallSpec {
                        point: 1,
                        target_procedure: 1,
                        normal_continuation: 2,
                        exceptional_continuation: 6,
                    },
                    CallSpec {
                        point: 3,
                        target_procedure: 1,
                        normal_continuation: 4,
                        exceptional_continuation: 6,
                    },
                ],
            };
            root.calls.shrink_to_fit();
            vec![root, ProcedureSpec::line("leaf")]
        }
        RegressionScenario::RecursiveScc => {
            let recursive = |name, target_procedure| ProcedureSpec {
                name,
                point_count: 6,
                normal_exit: 4,
                exceptional_exit: 5,
                edges: vec![
                    (0, 1, ControlEdgeKind::Normal),
                    (1, 4, ControlEdgeKind::ConditionalTrue),
                    (1, 2, ControlEdgeKind::ConditionalFalse),
                    (2, 3, ControlEdgeKind::Normal),
                    (2, 5, ControlEdgeKind::Exceptional),
                    (3, 4, ControlEdgeKind::Normal),
                ],
                calls: vec![CallSpec {
                    point: 2,
                    target_procedure,
                    normal_continuation: 3,
                    exceptional_continuation: 5,
                }],
            };
            vec![recursive("even", 1), recursive("odd", 0)]
        }
        RegressionScenario::ExceptionalReturn => {
            let mut leaf = ProcedureSpec::line("leaf");
            leaf.edges.push((1, 3, ControlEdgeKind::Exceptional));
            vec![ProcedureSpec::caller("root", 1), leaf]
        }
        RegressionScenario::Cleanup => vec![ProcedureSpec {
            name: "root",
            point_count: 5,
            normal_exit: 3,
            exceptional_exit: 4,
            edges: vec![
                (0, 1, ControlEdgeKind::Normal),
                (1, 2, ControlEdgeKind::Cleanup),
                (2, 3, ControlEdgeKind::Normal),
            ],
            calls: Vec::new(),
        }],
    }
}

fn position(offset: u32) -> SourcePosition {
    SourcePosition::new(offset, 0, offset)
}

fn anchor(offset: u32) -> SourceAnchor {
    SourceAnchor::new(
        SourceSpan::new(position(offset), position(offset.saturating_add(1)))
            .expect("ordered synthetic span"),
        0,
    )
}

fn artifact_key(scenario: RegressionScenario) -> SemanticArtifactKey {
    let path = WorkspaceRelativePath::new(format!("synthetic/{}.icfg", scenario.name()))
        .expect("synthetic path is workspace-relative");
    SemanticArtifactKey::new(
        WorkspaceMountId::hash_bytes(b"dataflow-regression-mount"),
        path,
        // The semantic artifact contract requires an analyzable identity even
        // though this topology is constructed directly and never lowered from
        // source syntax.
        SemanticLanguage::Standard(Language::Rust),
        SourceRevision::Disk {
            content: ContentIdentity::hash_bytes(scenario.name().as_bytes()),
        },
        AdapterSemanticsVersion::hash_bytes("dataflow-regression", b"v1")
            .expect("adapter name is non-empty"),
        SemanticIrVersion::hash_bytes(b"dataflow-regression-ir-v1"),
        ConfigurationFingerprint::hash_bytes(b"dataflow-regression-config"),
        DependencyFingerprint::hash_bytes(b"dataflow-regression-dependencies"),
    )
}

fn locator(key: &SemanticArtifactKey, name: &str, offset: u32) -> SemanticLocator {
    let declaration = DeclarationLocator::new(vec![
        DeclarationSegment::named(DeclarationSegmentKind::File, "synthetic.icfg", anchor(0), 0)
            .expect("file segment"),
        DeclarationSegment::named(DeclarationSegmentKind::Function, name, anchor(offset), 0)
            .expect("procedure segment"),
    ])
    .expect("non-empty declaration");
    SemanticLocator::new(
        key.mount(),
        key.path().clone(),
        key.language(),
        declaration,
        SemanticRole::Procedure,
        anchor(offset),
    )
}

fn event(effect: SemanticEffect) -> SemanticEvent {
    SemanticEvent::new(effect, SOURCE, EVIDENCE)
}

fn capabilities() -> SemanticCapabilities {
    SemanticCapabilities::builder()
        .complete(SemanticCapability::Procedures)
        .complete(SemanticCapability::EntryBoundary)
        .complete(SemanticCapability::NormalExitBoundary)
        .complete(SemanticCapability::ExceptionalExitBoundary)
        .complete(SemanticCapability::BasicBlocks)
        .complete(SemanticCapability::ProgramPoints)
        .complete(SemanticCapability::Values)
        .complete(SemanticCapability::CallableReferences)
        .complete(SemanticCapability::NormalControlFlow)
        .complete(SemanticCapability::ExceptionalControlFlow)
        .complete(SemanticCapability::CleanupControlFlow)
        .complete(SemanticCapability::Calls)
        .complete(SemanticCapability::NormalCallContinuation)
        .complete(SemanticCapability::ExceptionalCallContinuation)
        .complete(SemanticCapability::ReturnFlow)
        .build()
}

fn build_artifact(
    scenario: RegressionScenario,
    specs: &[ProcedureSpec],
    reverse_edges: bool,
) -> Arc<SemanticArtifact> {
    let key = artifact_key(scenario);
    let mut procedures = Vec::with_capacity(specs.len());
    for (procedure_index, spec) in specs.iter().enumerate() {
        let procedure_id = ProcedureId::new(u32::try_from(procedure_index).expect("small family"));
        let offset = u32::try_from(procedure_index.saturating_mul(100)).expect("small family") + 1;
        let procedure_locator = locator(&key, spec.name, offset);
        let mut parts = ProcedureSemanticsParts::new(
            procedure_id,
            procedure_locator.clone(),
            ProcedureKind::Function,
            SOURCE,
            EVIDENCE,
        );
        parts.source_mappings.push(SourceMapping {
            id: SOURCE,
            locator: procedure_locator,
            kind: SourceMappingKind::Synthetic,
        });
        parts.evidence_rows.push(Evidence {
            id: EVIDENCE,
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Complete,
            sources: Box::new([SOURCE]),
        });
        let point_ids = (0..spec.point_count)
            .map(ProgramPointId::new)
            .collect::<Vec<_>>();
        parts.blocks.push(BasicBlock {
            id: BLOCK,
            points: point_ids.clone().into_boxed_slice(),
            source: SOURCE,
            evidence: EVIDENCE,
        });
        let mut point_events = vec![Vec::<SemanticEvent>::new(); spec.point_count as usize];
        point_events[0].push(event(SemanticEffect::Entry));
        point_events[spec.normal_exit as usize].push(event(SemanticEffect::NormalExit));
        point_events[spec.exceptional_exit as usize].push(event(SemanticEffect::ExceptionalExit));

        for (call_index, call) in spec.calls.iter().enumerate() {
            let call_id = CallSiteId::new(u32::try_from(call_index).expect("small call family"));
            let value_id = ValueId::new(u32::try_from(call_index).expect("small call family"));
            parts.values.push(SemanticValue {
                id: value_id,
                kind: SemanticValueKind::Callable,
                source: SOURCE,
                evidence: EVIDENCE,
            });
            parts.call_sites.push(SemanticCallSite {
                id: call_id,
                point: ProgramPointId::new(call.point),
                callee: value_id,
                receiver: None,
                arguments: Box::new([]),
                result: None,
                thrown: None,
                declared_targets: CallableTargetResolution::Proven(CallableTarget::Local(
                    ProcedureId::new(call.target_procedure),
                )),
                target_evidence: EVIDENCE,
                normal_continuation: ControlContinuation::Target(ProgramPointId::new(
                    call.normal_continuation,
                )),
                exceptional_continuation: ControlContinuation::Target(ProgramPointId::new(
                    call.exceptional_continuation,
                )),
                source: SOURCE,
                evidence: EVIDENCE,
            });
            point_events[call.point as usize]
                .push(event(SemanticEffect::Invoke { call_site: call_id }));
            point_events[call.normal_continuation as usize].push(event(
                SemanticEffect::CallContinuation {
                    call_site: call_id,
                    kind: CallContinuationKind::Normal,
                },
            ));
            point_events[call.exceptional_continuation as usize].push(event(
                SemanticEffect::CallContinuation {
                    call_site: call_id,
                    kind: CallContinuationKind::Exceptional,
                },
            ));
        }
        parts
            .points
            .extend(point_ids.into_iter().map(|id| ProgramPoint {
                id,
                block: BLOCK,
                events: std::mem::take(&mut point_events[id.index()]).into_boxed_slice(),
                source: SOURCE,
                evidence: EVIDENCE,
            }));
        let edge_iter: Box<dyn Iterator<Item = &(u32, u32, ControlEdgeKind)>> = if reverse_edges {
            Box::new(spec.edges.iter().rev())
        } else {
            Box::new(spec.edges.iter())
        };
        parts
            .control_edges
            .extend(edge_iter.map(|(source, target, kind)| ControlEdge {
                source_point: ProgramPointId::new(*source),
                target_point: ProgramPointId::new(*target),
                kind: *kind,
                source: SOURCE,
                evidence: EVIDENCE,
            }));
        procedures.push(parts);
    }
    Arc::new(
        SemanticArtifact::try_new(key, capabilities(), procedures)
            .expect("synthetic data-flow artifact satisfies semantic contracts"),
    )
}

pub struct RegressionIcfg {
    scenario: RegressionScenario,
    specs: Vec<ProcedureSpec>,
    artifact: Arc<SemanticArtifact>,
    snapshot: IcfgSnapshot,
    node_labels: HashMap<IcfgNodeId, Box<str>>,
    point_labels: HashMap<ProgramPointHandle, Box<str>>,
    reverse_provider_rows: bool,
}

impl RegressionIcfg {
    pub fn new(scenario: RegressionScenario, mutation: RegressionMutation) -> Self {
        let specs = scenario_specs(scenario);
        let artifact = build_artifact(scenario, &specs, mutation.reverse_edges);
        let built = build_snapshot(&artifact, &specs, mutation.reverse_edges);
        Self {
            scenario,
            specs,
            artifact,
            snapshot: built.snapshot,
            node_labels: built.node_labels,
            point_labels: built.point_labels,
            reverse_provider_rows: mutation.reverse_provider_rows,
        }
    }

    pub const fn scenario(&self) -> RegressionScenario {
        self.scenario
    }

    pub fn root(&self) -> ProcedureHandle {
        self.procedure(0)
    }

    pub fn procedure(&self, index: u32) -> ProcedureHandle {
        self.artifact
            .procedure_handle(ProcedureId::new(index))
            .expect("scenario root exists")
    }

    pub const fn snapshot(&self) -> &IcfgSnapshot {
        &self.snapshot
    }

    pub fn snapshot_outcome(&self) -> SemanticOutcome<IcfgSnapshot> {
        SemanticOutcome::Complete {
            value: self.snapshot.clone(),
            work: SemanticWork::default(),
        }
    }

    pub fn node_label(&self, node: IcfgNodeId) -> &str {
        self.node_labels
            .get(&node)
            .unwrap_or_else(|| panic!("missing node label for {node}"))
    }

    pub fn point_label(&self, point: &ProgramPointHandle) -> &str {
        self.point_labels
            .get(point)
            .unwrap_or_else(|| panic!("missing point label for {point:?}"))
    }

    pub fn root_entry_node(&self) -> IcfgNodeId {
        self.snapshot
            .nodes()
            .iter()
            .position(|node| {
                node.point().procedure() == &self.root()
                    && node.point().id() == self.root().semantics().entry_point()
            })
            .and_then(|index| u32::try_from(index).ok())
            .map(IcfgNodeId::new)
            .expect("root entry node exists")
    }

    pub fn alternate_seed_node(&self) -> IcfgNodeId {
        self.snapshot
            .node_ids()
            .find(|node| *node != self.root_entry_node())
            .expect("every scenario has a second node")
    }
}

struct BuiltSnapshot {
    snapshot: IcfgSnapshot,
    node_labels: HashMap<IcfgNodeId, Box<str>>,
    point_labels: HashMap<ProgramPointHandle, Box<str>>,
}

fn build_snapshot(
    artifact: &Arc<SemanticArtifact>,
    specs: &[ProcedureSpec],
    reverse_edges: bool,
) -> BuiltSnapshot {
    let mut nodes = Vec::new();
    let mut node_ids = HashMap::new();
    let mut node_labels = HashMap::new();
    let mut point_labels = HashMap::new();
    for (procedure_index, spec) in specs.iter().enumerate() {
        let procedure = artifact
            .procedure_handle(ProcedureId::new(
                u32::try_from(procedure_index).expect("small family"),
            ))
            .expect("scenario procedure exists");
        for point_index in 0..spec.point_count {
            let point = procedure
                .point_handle(ProgramPointId::new(point_index))
                .expect("scenario point exists");
            let node = IcfgNodeId::new(u32::try_from(nodes.len()).expect("small family"));
            let label = format!("{}:p{point_index}", spec.name).into_boxed_str();
            node_ids.insert((procedure_index as u32, point_index), node);
            node_labels.insert(node, label.clone());
            point_labels.insert(point.clone(), label);
            nodes.push(IcfgNodeKey::new(point, Vec::new()));
        }
    }

    let mut edges = Vec::new();
    for (procedure_index, spec) in specs.iter().enumerate() {
        let procedure = artifact
            .procedure_handle(ProcedureId::new(procedure_index as u32))
            .expect("scenario procedure exists");
        for &(source, target, kind) in &spec.edges {
            let scaffolding = spec.calls.iter().any(|call| {
                call.point == source
                    && (call.normal_continuation == target
                        || call.exceptional_continuation == target)
            });
            if scaffolding {
                continue;
            }
            edges.push(IcfgEdge {
                source: node_ids[&(procedure_index as u32, source)],
                target: node_ids[&(procedure_index as u32, target)],
                kind: IcfgEdgeKind::Intraprocedural(kind),
                origin: None,
                proof: ProofStatus::Proven,
                completeness: EvidenceCompleteness::Complete,
                boundary: None,
            });
        }
        for (call_index, call) in spec.calls.iter().enumerate() {
            let origin = procedure
                .call_site_handle(CallSiteId::new(call_index as u32))
                .expect("scenario call exists");
            let target_spec = &specs[call.target_procedure as usize];
            edges.push(IcfgEdge {
                source: node_ids[&(procedure_index as u32, call.point)],
                target: node_ids[&(call.target_procedure, 0)],
                kind: IcfgEdgeKind::Call,
                origin: Some(origin.clone()),
                proof: ProofStatus::Proven,
                completeness: EvidenceCompleteness::Complete,
                boundary: None,
            });
            edges.push(IcfgEdge {
                source: node_ids[&(call.target_procedure, target_spec.normal_exit)],
                target: node_ids[&(procedure_index as u32, call.normal_continuation)],
                kind: IcfgEdgeKind::NormalReturn,
                origin: Some(origin.clone()),
                proof: ProofStatus::Proven,
                completeness: EvidenceCompleteness::Complete,
                boundary: None,
            });
            edges.push(IcfgEdge {
                source: node_ids[&(call.target_procedure, target_spec.exceptional_exit)],
                target: node_ids[&(procedure_index as u32, call.exceptional_continuation)],
                kind: IcfgEdgeKind::ExceptionalReturn,
                origin: Some(origin),
                proof: ProofStatus::Proven,
                completeness: EvidenceCompleteness::Complete,
                boundary: None,
            });
        }
    }
    if reverse_edges {
        edges.reverse();
    }
    let snapshot = IcfgSnapshot::try_from_parts(nodes, edges, Vec::new())
        .expect("synthetic ICFG parts are valid");
    BuiltSnapshot {
        snapshot,
        node_labels,
        point_labels,
    }
}

impl DispatchOracle for RegressionIcfg {
    fn resolve_call(
        &self,
        _call: &CallSiteHandle,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
        Ok(SemanticOutcome::Unknown {
            partial: None,
            work: SemanticWork::default(),
        })
    }
}

impl IcfgProvider for RegressionIcfg {
    fn call_transfers(
        &self,
        caller: &ProcedureHandle,
        call: CallSiteId,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<CallTransferSet>, SemanticProviderError> {
        let procedure_index = caller.id().index();
        let spec = self
            .specs
            .get(procedure_index)
            .ok_or_else(|| SemanticProviderError::internal("unknown regression procedure"))?;
        let call_spec = spec
            .calls
            .get(call.index())
            .ok_or_else(|| SemanticProviderError::internal("unknown regression call"))?;
        let origin = caller
            .call_site_handle(call)
            .ok_or_else(|| SemanticProviderError::internal("regression call is not scoped"))?;
        let callee = self
            .artifact
            .procedure_handle(ProcedureId::new(call_spec.target_procedure))
            .ok_or_else(|| SemanticProviderError::internal("regression callee is missing"))?;
        let callee_entry = callee
            .point_handle(callee.semantics().entry_point())
            .ok_or_else(|| SemanticProviderError::internal("regression callee entry is missing"))?;
        let mut transfers = vec![CallTransfer {
            origin,
            callee,
            callee_entry,
            normal_continuation: ControlContinuation::Target(ProgramPointId::new(
                call_spec.normal_continuation,
            )),
            exceptional_continuation: ControlContinuation::Target(ProgramPointId::new(
                call_spec.exceptional_continuation,
            )),
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Complete,
        }];
        if self.reverse_provider_rows {
            transfers.reverse();
        }
        Ok(SemanticOutcome::Complete {
            value: CallTransferSet {
                transfers: transfers.into_boxed_slice(),
                boundaries: Box::new([]),
            },
            work: SemanticWork::default(),
        })
    }

    fn snapshot(
        &self,
        _root: &ProcedureHandle,
        _limits: IcfgSnapshotLimits,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<IcfgSnapshot>, SemanticProviderError> {
        Ok(self.snapshot_outcome())
    }
}
