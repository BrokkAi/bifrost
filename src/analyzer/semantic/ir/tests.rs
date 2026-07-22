use super::*;
use crate::analyzer::Language;

use super::super::ids::{
    AdapterSemanticsVersion, ConfigurationFingerprint, ContentIdentity, DeclarationLocator,
    DeclarationSegment, DeclarationSegmentKind, DependencyFingerprint, SemanticIrVersion,
    SemanticLanguage, SourceAnchor, SourcePosition, SourceRevision, SourceSpan, WorkspaceMountId,
    WorkspaceRelativePath,
};

fn key_with_language(language: SemanticLanguage) -> SemanticArtifactKey {
    SemanticArtifactKey::new(
        WorkspaceMountId::hash_bytes(b"test mount"),
        WorkspaceRelativePath::new("src/Test.java").expect("valid fixture path"),
        language,
        SourceRevision::Disk {
            content: ContentIdentity::hash_bytes(b"class Test {}"),
        },
        AdapterSemanticsVersion::hash_bytes("test-java", b"adapter").expect("non-empty adapter"),
        SemanticIrVersion::hash_bytes(b"semantic-ir-test"),
        ConfigurationFingerprint::hash_bytes(b"configuration"),
        DependencyFingerprint::hash_bytes(b"dependencies"),
    )
}

fn key() -> SemanticArtifactKey {
    key_with_language(SemanticLanguage::Standard(Language::Java))
}

#[test]
fn semantic_gap_impacts_are_compact_total_and_deterministic() {
    let impacts = SemanticGapImpacts::NONE
        .with(SemanticGapImpact::Aliasing)
        .with(SemanticGapImpact::DispatchCoverage)
        .with(SemanticGapImpact::HeapRead)
        .with(SemanticGapImpact::HeapRead);

    assert_eq!(
        impacts.iter().collect::<Vec<_>>(),
        vec![
            SemanticGapImpact::DispatchCoverage,
            SemanticGapImpact::HeapRead,
            SemanticGapImpact::Aliasing,
        ]
    );
    assert!(impacts.contains(SemanticGapImpact::HeapRead));
    assert!(!impacts.contains(SemanticGapImpact::ValueFlow));
    assert_eq!(SemanticGapImpacts::default(), SemanticGapImpacts::NONE);

    assert_eq!(
        SemanticGapImpacts::for_gap(
            SemanticCapability::DynamicDispatch,
            SemanticGapSubject::Point,
        ),
        SemanticGapImpacts::single(SemanticGapImpact::DispatchCoverage),
    );
    assert_eq!(
        SemanticGapImpacts::for_gap(
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapSubject::Point,
        ),
        SemanticGapImpacts::CONTROL_FLOW,
    );
    let call_impacts = SemanticGapImpacts::for_gap(
        SemanticCapability::Calls,
        SemanticGapSubject::CallSite(CallSiteId::new(0)),
    );
    assert_eq!(call_impacts, SemanticGapImpacts::VALUE);
    assert!(!call_impacts.contains(SemanticGapImpact::DispatchCoverage));
    assert!(!call_impacts.contains(SemanticGapImpact::CallEvaluation));
    assert_eq!(
        SemanticGapImpacts::for_gap(SemanticCapability::Calls, SemanticGapSubject::Procedure,),
        SemanticGapImpacts::NONE,
    );
    let callable_impacts = SemanticGapImpacts::for_gap(
        SemanticCapability::CallableReferences,
        SemanticGapSubject::CallSite(CallSiteId::new(0)),
    );
    assert_eq!(callable_impacts, SemanticGapImpacts::NONE);
    let deferred_impacts = SemanticGapImpacts::for_gap(
        SemanticCapability::DeferredExecution,
        SemanticGapSubject::CallSite(CallSiteId::new(0)),
    );
    assert_eq!(deferred_impacts, SemanticGapImpacts::DEFERRED_EFFECTS);
    assert!(!deferred_impacts.contains(SemanticGapImpact::DispatchCoverage));
    assert!(!deferred_impacts.contains(SemanticGapImpact::CallEvaluation));
    for impact in [
        SemanticGapImpact::ReturnTransfer,
        SemanticGapImpact::ValueFlow,
        SemanticGapImpact::HeapRead,
        SemanticGapImpact::HeapWrite,
        SemanticGapImpact::Aliasing,
    ] {
        assert!(SemanticGapImpacts::DEFERRED_EFFECTS.contains(impact));
        assert!(SemanticGapImpacts::CALL_EVALUATION.contains(impact));
    }
    assert!(!SemanticGapImpacts::DEFERRED_EFFECTS.contains(SemanticGapImpact::CallEvaluation));
    assert!(SemanticGapImpacts::CALL_EVALUATION.contains(SemanticGapImpact::CallEvaluation));
    assert!(!SemanticGapImpacts::CALL_EVALUATION.contains(SemanticGapImpact::DispatchCoverage));
    assert_eq!(
        SemanticGapImpacts::for_gap(
            SemanticCapability::ConcurrentSpawn,
            SemanticGapSubject::CallSite(CallSiteId::new(0)),
        ),
        SemanticGapImpacts::CALL_EVALUATION,
    );
    let assignment =
        SemanticGapImpacts::for_gap(SemanticCapability::Assignments, SemanticGapSubject::Point);
    assert!(assignment.contains(SemanticGapImpact::ValueFlow));
    assert!(assignment.contains(SemanticGapImpact::Aliasing));

    let capture = SemanticGapImpacts::for_gap(
        SemanticCapability::Captures,
        SemanticGapSubject::MemoryLocation(MemoryLocationId::new(0)),
    );
    for impact in [
        SemanticGapImpact::ValueFlow,
        SemanticGapImpact::HeapRead,
        SemanticGapImpact::HeapWrite,
        SemanticGapImpact::Aliasing,
    ] {
        assert!(capture.contains(impact), "missing {impact:?}");
    }
}

fn capabilities(features: &[SemanticCapability]) -> SemanticCapabilities {
    let mut builder = SemanticCapabilities::builder();
    for capability in [
        SemanticCapability::Procedures,
        SemanticCapability::EntryBoundary,
        SemanticCapability::NormalExitBoundary,
        SemanticCapability::ExceptionalExitBoundary,
        SemanticCapability::BasicBlocks,
        SemanticCapability::ProgramPoints,
        SemanticCapability::NormalControlFlow,
        SemanticCapability::ExceptionalControlFlow,
    ]
    .into_iter()
    .chain(features.iter().copied())
    {
        builder = builder.complete(capability);
    }
    builder.build()
}

fn anchor(offset: u32, occurrence: u32) -> SourceAnchor {
    let start = SourcePosition::new(offset, 0, offset);
    let end = SourcePosition::new(offset + 1, 0, offset + 1);
    SourceAnchor::new(
        SourceSpan::new(start, end).expect("ordered fixture span"),
        occurrence,
    )
}

fn procedure_locator(key: &SemanticArtifactKey, name: &str, offset: u32) -> SemanticLocator {
    let file_anchor = anchor(0, 0);
    let procedure_anchor = anchor(offset, 0);
    let declaration = DeclarationLocator::new(vec![
        DeclarationSegment::named(DeclarationSegmentKind::File, "Test.java", file_anchor, 0)
            .expect("named file segment"),
        DeclarationSegment::named(DeclarationSegmentKind::Function, name, procedure_anchor, 0)
            .expect("named procedure segment"),
    ])
    .expect("non-empty declaration path");
    SemanticLocator::new(
        key.mount(),
        key.path().clone(),
        key.language(),
        declaration,
        SemanticRole::Procedure,
        procedure_anchor,
    )
}

fn direct_child_locator(
    key: &SemanticArtifactKey,
    parent: &SemanticLocator,
    kind: DeclarationSegmentKind,
    name: &str,
    offset: u32,
) -> SemanticLocator {
    let child_anchor = anchor(offset, 0);
    let mut segments = parent.declaration().segments().to_vec();
    segments.push(
        DeclarationSegment::named(kind, name, child_anchor, 0)
            .expect("named child procedure segment"),
    );
    SemanticLocator::new(
        key.mount(),
        key.path().clone(),
        key.language(),
        DeclarationLocator::new(segments).expect("non-empty child declaration path"),
        SemanticRole::Procedure,
        child_anchor,
    )
}

fn minimal_procedure(
    key: &SemanticArtifactKey,
    id: ProcedureId,
    name: &str,
    offset: u32,
) -> ProcedureSemanticsParts {
    let locator = procedure_locator(key, name, offset);
    let source = SourceMappingId::new(0);
    let evidence = EvidenceId::new(0);
    let mut parts = ProcedureSemanticsParts::new(
        id,
        locator.clone(),
        ProcedureKind::Function,
        source,
        evidence,
    );
    parts.source_mappings.push(SourceMapping {
        id: source,
        locator,
        kind: SourceMappingKind::Exact,
    });
    parts.evidence_rows.push(Evidence {
        id: evidence,
        proof: ProofStatus::Proven,
        completeness: EvidenceCompleteness::Complete,
        sources: vec![source].into_boxed_slice(),
    });

    let entry = ProgramPointId::new(0);
    let normal_exit = ProgramPointId::new(1);
    let exceptional_exit = ProgramPointId::new(2);
    parts.blocks.push(BasicBlock {
        id: BlockId::new(0),
        points: vec![entry, normal_exit, exceptional_exit].into_boxed_slice(),
        source,
        evidence,
    });
    parts.points.extend([
        ProgramPoint {
            id: entry,
            block: BlockId::new(0),
            events: vec![SemanticEvent::new(SemanticEffect::Entry, source, evidence)]
                .into_boxed_slice(),
            source,
            evidence,
        },
        ProgramPoint {
            id: normal_exit,
            block: BlockId::new(0),
            events: vec![SemanticEvent::new(
                SemanticEffect::NormalExit,
                source,
                evidence,
            )]
            .into_boxed_slice(),
            source,
            evidence,
        },
        ProgramPoint {
            id: exceptional_exit,
            block: BlockId::new(0),
            events: vec![SemanticEvent::new(
                SemanticEffect::ExceptionalExit,
                source,
                evidence,
            )]
            .into_boxed_slice(),
            source,
            evidence,
        },
    ]);
    parts.control_edges.extend([
        ControlEdge {
            source_point: entry,
            target_point: normal_exit,
            kind: ControlEdgeKind::Normal,
            source,
            evidence,
        },
        ControlEdge {
            source_point: entry,
            target_point: exceptional_exit,
            kind: ControlEdgeKind::Exceptional,
            source,
            evidence,
        },
    ]);
    parts
}

#[test]
fn minimal_valid_artifact_exposes_scoped_handles() {
    let key = key();
    let artifact = SemanticArtifact::try_new(
        key.clone(),
        capabilities(&[]),
        vec![minimal_procedure(&key, ProcedureId::new(0), "main", 1)],
    )
    .expect("minimal procedure is valid");
    assert_eq!(artifact.key(), &key);
    assert_eq!(artifact.procedures().len(), 1);
    let procedure = &artifact.procedures()[0];
    assert_eq!(procedure.entry_point(), ProgramPointId::new(0));
    assert_eq!(procedure.normal_exit_point(), ProgramPointId::new(1));
    assert_eq!(procedure.exceptional_exit_point(), ProgramPointId::new(2));

    let artifact = Arc::new(artifact);
    let handle = artifact
        .procedure_handle(ProcedureId::new(0))
        .expect("in-bounds procedure handle");
    assert!(handle.point_handle(ProgramPointId::new(2)).is_some());
    assert!(handle.point_handle(ProgramPointId::new(3)).is_none());
    assert!(handle.control_edge_handle(ControlEdgeId::new(1)).is_some());
    assert!(handle.control_edge_handle(ControlEdgeId::new(2)).is_none());
    assert!(handle.value_handle(ValueId::new(0)).is_none());
}

#[test]
fn cfg_freeze_assigns_canonical_edge_ids_and_bidirectional_rows() {
    let key = key();
    let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
    parts.control_edges.reverse();

    let artifact = SemanticArtifact::try_new(key, capabilities(&[]), vec![parts])
        .expect("valid edges should freeze into indexed topology");
    let procedure = &artifact.procedures()[0];

    // Six locator segments, one evidence source, three block members,
    // eight row offsets, and two incoming edge IDs are retained.
    assert_eq!(artifact.work().nested_entries, 20);
    assert_eq!(procedure.control_edges(), procedure.cfg().edges());
    assert_eq!(procedure.control_edges().len(), 2);
    assert_eq!(
        procedure.control_edge(ControlEdgeId::new(0)).unwrap().kind,
        ControlEdgeKind::Exceptional
    );
    assert_eq!(
        procedure.control_edge(ControlEdgeId::new(1)).unwrap().kind,
        ControlEdgeKind::Normal
    );
    assert!(procedure.control_edge(ControlEdgeId::new(2)).is_none());

    let successors = procedure
        .successor_edges(ProgramPointId::new(0))
        .map(|(id, edge)| (id, edge.target_point, edge.kind))
        .collect::<Vec<_>>();
    assert_eq!(
        successors,
        vec![
            (
                ControlEdgeId::new(0),
                ProgramPointId::new(2),
                ControlEdgeKind::Exceptional,
            ),
            (
                ControlEdgeId::new(1),
                ProgramPointId::new(1),
                ControlEdgeKind::Normal,
            ),
        ]
    );
    assert_eq!(
        procedure
            .predecessor_edges(ProgramPointId::new(1))
            .map(|(id, _)| id)
            .collect::<Vec<_>>(),
        vec![ControlEdgeId::new(1)]
    );
    assert_eq!(
        procedure
            .predecessor_edges(ProgramPointId::new(2))
            .map(|(id, _)| id)
            .collect::<Vec<_>>(),
        vec![ControlEdgeId::new(0)]
    );
    assert_eq!(procedure.predecessor_edges(ProgramPointId::new(0)).len(), 0);
    assert_eq!(procedure.successor_edges(ProgramPointId::new(1)).len(), 0);

    let invalid = ProgramPointId::new(u32::MAX);
    assert!(std::panic::catch_unwind(|| procedure.cfg().successor_edges(invalid).count()).is_err());
    assert!(
        std::panic::catch_unwind(|| procedure.cfg().predecessor_edges(invalid).count()).is_err()
    );
    assert!(std::panic::catch_unwind(|| procedure.successor_edges(invalid).count()).is_err());
    assert!(std::panic::catch_unwind(|| procedure.predecessor_edges(invalid).count()).is_err());
}

#[test]
fn exact_rich_edges_are_rejected_but_distinct_provenance_is_preserved() {
    let key = key();
    let mut duplicate = minimal_procedure(&key, ProcedureId::new(0), "duplicate", 1);
    duplicate
        .control_edges
        .push(duplicate.control_edges[0].clone());
    let error = SemanticArtifact::try_new(key.clone(), capabilities(&[]), vec![duplicate])
        .expect_err("an exact rich-edge duplicate must fail");
    assert_eq!(error.kind(), SemanticIrErrorKind::DuplicateEdge);

    let mut parallel = minimal_procedure(&key, ProcedureId::new(0), "parallel", 1);
    let second_source = SourceMappingId::new(1);
    let second_evidence = EvidenceId::new(1);
    parallel.source_mappings.push(SourceMapping {
        id: second_source,
        locator: parallel.locator.clone(),
        kind: SourceMappingKind::Exact,
    });
    parallel.evidence_rows.push(Evidence {
        id: second_evidence,
        proof: ProofStatus::Proven,
        completeness: EvidenceCompleteness::Complete,
        sources: Box::new([second_source]),
    });
    let mut second = parallel.control_edges[0].clone();
    second.source = second_source;
    second.evidence = second_evidence;
    parallel.control_edges.push(second);

    let artifact = SemanticArtifact::try_new(key, capabilities(&[]), vec![parallel])
        .expect("parallel rich edges with distinct provenance are valid");
    let procedure = &artifact.procedures()[0];
    let parallel_edges = procedure
        .predecessor_edges(ProgramPointId::new(1))
        .map(|(_, edge)| (edge.source, edge.evidence))
        .collect::<Vec<_>>();
    assert_eq!(
        parallel_edges,
        vec![
            (SourceMappingId::new(0), EvidenceId::new(0)),
            (second_source, second_evidence),
        ]
    );
}

fn raw_cfg_parts() -> (Vec<ControlEdge>, Vec<u32>, Vec<u32>, Vec<ControlEdgeId>) {
    let source = SourceMappingId::new(0);
    let evidence = EvidenceId::new(0);
    (
        vec![
            ControlEdge {
                source_point: ProgramPointId::new(0),
                target_point: ProgramPointId::new(2),
                kind: ControlEdgeKind::Exceptional,
                source,
                evidence,
            },
            ControlEdge {
                source_point: ProgramPointId::new(0),
                target_point: ProgramPointId::new(1),
                kind: ControlEdgeKind::Normal,
                source,
                evidence,
            },
        ],
        vec![0, 2, 2, 2],
        vec![0, 0, 1, 2],
        vec![ControlEdgeId::new(1), ControlEdgeId::new(0)],
    )
}

#[test]
fn checked_cfg_parts_reject_corrupt_adjacency() {
    let procedure = ProcedureId::new(0);
    let (edges, outgoing, incoming_offsets, incoming_ids) = raw_cfg_parts();
    ControlFlowGraph::try_from_parts(
        procedure,
        3,
        edges,
        outgoing,
        incoming_offsets,
        incoming_ids,
    )
    .expect("valid raw adjacency should pass defensive validation");

    let (edges, _, incoming_offsets, incoming_ids) = raw_cfg_parts();
    let error = ControlFlowGraph::try_from_parts(
        procedure,
        3,
        edges,
        vec![0, 1, 2, 2],
        incoming_offsets,
        incoming_ids,
    )
    .expect_err("an edge in the wrong outgoing row must fail");
    assert_eq!(error.kind(), SemanticIrErrorKind::ControlFlowContract);

    let (edges, outgoing, incoming_offsets, _) = raw_cfg_parts();
    let error = ControlFlowGraph::try_from_parts(
        procedure,
        3,
        edges,
        outgoing,
        incoming_offsets,
        vec![ControlEdgeId::new(1), ControlEdgeId::new(9)],
    )
    .expect_err("an out-of-range incoming edge id must fail");
    assert_eq!(error.kind(), SemanticIrErrorKind::ControlFlowContract);

    let (edges, outgoing, incoming_offsets, _) = raw_cfg_parts();
    let error = ControlFlowGraph::try_from_parts(
        procedure,
        3,
        edges,
        outgoing,
        incoming_offsets,
        vec![ControlEdgeId::new(0), ControlEdgeId::new(1)],
    )
    .expect_err("an edge in the wrong incoming row must fail");
    assert_eq!(error.kind(), SemanticIrErrorKind::ControlFlowContract);

    let (edges, outgoing, incoming_offsets, _) = raw_cfg_parts();
    let error = ControlFlowGraph::try_from_parts(
        procedure,
        3,
        edges,
        outgoing,
        incoming_offsets,
        vec![ControlEdgeId::new(1), ControlEdgeId::new(1)],
    )
    .expect_err("duplicate and missing incoming membership must fail");
    assert_eq!(error.kind(), SemanticIrErrorKind::ControlFlowContract);

    let source = SourceMappingId::new(0);
    let evidence = EvidenceId::new(0);
    let (mut edges, _, _, _) = raw_cfg_parts();
    edges.push(ControlEdge {
        source_point: ProgramPointId::new(1),
        target_point: ProgramPointId::new(2),
        kind: ControlEdgeKind::Normal,
        source,
        evidence,
    });
    let error = ControlFlowGraph::try_from_parts(
        procedure,
        3,
        edges,
        vec![0, 2, 3, 3],
        vec![0, 0, 1, 3],
        vec![
            ControlEdgeId::new(1),
            ControlEdgeId::new(2),
            ControlEdgeId::new(0),
        ],
    )
    .expect_err("incoming rows must retain canonical control-edge order");
    assert_eq!(error.kind(), SemanticIrErrorKind::ControlFlowContract);
}

#[test]
fn rejects_non_dense_and_out_of_bounds_local_ids() {
    let key = key();
    let mut non_dense = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
    non_dense.points[1].id = ProgramPointId::new(99);
    let error = SemanticArtifact::try_new(key.clone(), capabilities(&[]), vec![non_dense])
        .expect_err("non-dense point id must fail");
    assert_eq!(error.kind(), SemanticIrErrorKind::DenseId);

    let mut out_of_bounds = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
    let mut entry_events = out_of_bounds.points[0].events.to_vec();
    entry_events.push(SemanticEvent::new(
        SemanticEffect::Assignment {
            target: ValueId::new(0),
            value: ValueId::new(0),
        },
        SourceMappingId::new(0),
        EvidenceId::new(0),
    ));
    out_of_bounds.points[0].events = entry_events.into_boxed_slice();
    let error = SemanticArtifact::try_new(key, capabilities(&[]), vec![out_of_bounds])
        .expect_err("bare value id outside this procedure must fail");
    assert_eq!(error.kind(), SemanticIrErrorKind::OutOfBounds);
}

#[test]
fn rejects_lexical_parent_cycle_iteratively() {
    let key = key();
    let mut outer = minimal_procedure(&key, ProcedureId::new(0), "outer", 1);
    let mut inner = minimal_procedure(&key, ProcedureId::new(1), "inner", 3);
    outer.lexical_parent = Some(ProcedureId::new(1));
    inner.lexical_parent = Some(ProcedureId::new(0));

    let error = SemanticArtifact::try_new(key, capabilities(&[]), vec![outer, inner])
        .expect_err("lexical cycle must fail");
    assert_eq!(error.kind(), SemanticIrErrorKind::ParentCycle);
}

#[test]
fn rejects_non_analyzable_artifact_language() {
    let key = key_with_language(SemanticLanguage::Standard(Language::None));
    let error = SemanticArtifact::try_new(key, SemanticCapabilities::default(), Vec::new())
        .expect_err("Language::None is not a semantic adapter language");
    assert_eq!(error.kind(), SemanticIrErrorKind::ArtifactIdentity);
}

#[test]
fn rejects_exact_ir_for_unsupported_capabilities() {
    let key = key();
    let parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
    let error = SemanticArtifact::try_new(key, SemanticCapabilities::default(), vec![parts])
        .expect_err("exact procedure rows contradict unsupported capabilities");
    assert_eq!(error.kind(), SemanticIrErrorKind::CapabilityContract);
}

#[test]
fn rejects_source_mapping_outside_artifact_scope() {
    let key = key();
    let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
    let local = &parts.source_mappings[0].locator;
    parts.source_mappings[0].locator = SemanticLocator::new(
        WorkspaceMountId::hash_bytes(b"different mount"),
        local.path().clone(),
        local.language(),
        local.declaration().clone(),
        local.role(),
        local.anchor(),
    );

    let error = SemanticArtifact::try_new(key, capabilities(&[]), vec![parts])
        .expect_err("source mappings cannot cross mounted artifact scope");
    assert_eq!(error.kind(), SemanticIrErrorKind::SourceScope);
}

#[test]
fn rejects_creator_local_capture_destination() {
    let key = key();
    let mut outer = minimal_procedure(&key, ProcedureId::new(0), "outer", 1);
    let mut child = minimal_procedure(&key, ProcedureId::new(1), "child", 3);
    child.lexical_parent = Some(ProcedureId::new(0));
    outer.values.extend([
        SemanticValue {
            id: ValueId::new(0),
            kind: SemanticValueKind::Callable,
            source: SourceMappingId::new(0),
            evidence: EvidenceId::new(0),
        },
        SemanticValue {
            id: ValueId::new(1),
            kind: SemanticValueKind::Local,
            source: SourceMappingId::new(0),
            evidence: EvidenceId::new(0),
        },
    ]);
    outer.allocations.push(AllocationSite {
        id: AllocationId::new(0),
        point: ProgramPointId::new(0),
        result: ValueId::new(0),
        kind: AllocationKind::ClosureEnvironment,
        source: SourceMappingId::new(0),
        evidence: EvidenceId::new(0),
    });
    // This location exists only in the creator.  Destination IDs are
    // scoped by `target`, so using raw id 0 cannot make it a child slot.
    outer.memory_locations.push(MemoryLocation {
        id: MemoryLocationId::new(0),
        kind: MemoryLocationKind::LexicalCell {
            binding: ValueId::new(1),
        },
        source: SourceMappingId::new(0),
        evidence: EvidenceId::new(0),
    });
    outer.captures.push(CaptureBinding {
        id: CaptureId::new(0),
        point: ProgramPointId::new(0),
        callable: ValueId::new(0),
        target: ProcedureId::new(1),
        environment: AllocationId::new(0),
        captured: CaptureSource::Value(ValueId::new(1)),
        destination: MemoryLocationId::new(0),
        mode: CaptureMode::Value,
        source: SourceMappingId::new(0),
        evidence: EvidenceId::new(0),
    });

    let error = SemanticArtifact::try_new(
        key,
        capabilities(&[
            SemanticCapability::Values,
            SemanticCapability::Allocations,
            SemanticCapability::LocalFlow,
            SemanticCapability::Captures,
        ]),
        vec![outer, child],
    )
    .expect_err("capture destination must exist in the target child");
    assert_eq!(error.kind(), SemanticIrErrorKind::CaptureContract);
    assert!(error.detail().contains("target procedure"));
}

#[test]
fn capture_slot_requires_a_subject_specific_binding_gap() {
    let key = key();
    let outer = minimal_procedure(&key, ProcedureId::new(0), "outer", 1);
    let mut child = minimal_procedure(&key, ProcedureId::new(1), "child", 3);
    child.lexical_parent = Some(ProcedureId::new(0));
    child.memory_locations.push(MemoryLocation {
        id: MemoryLocationId::new(0),
        kind: MemoryLocationKind::Capture {
            lexical_parent: ProcedureId::new(0),
        },
        source: SourceMappingId::new(0),
        evidence: EvidenceId::new(0),
    });
    child.gaps.push(SemanticGap {
        id: SemanticGapId::new(0),
        point: ProgramPointId::new(0),
        subject: SemanticGapSubject::Point,
        capability: SemanticCapability::Captures,
        impacts: SemanticGapImpacts::for_gap(
            SemanticCapability::Captures,
            SemanticGapSubject::Point,
        ),
        kind: SemanticGapKind::Unknown,
        budget: None,
        detail: "unrelated capture uncertainty".into(),
        source: SourceMappingId::new(0),
        evidence: EvidenceId::new(0),
    });
    let mut events = child.points[0].events.to_vec();
    events.push(SemanticEvent::new(
        SemanticEffect::Gap {
            gap: SemanticGapId::new(0),
        },
        SourceMappingId::new(0),
        EvidenceId::new(0),
    ));
    child.points[0].events = events.into_boxed_slice();

    let error = SemanticArtifact::try_new(
        key.clone(),
        capabilities(&[SemanticCapability::Captures]),
        vec![outer.clone(), child.clone()],
    )
    .expect_err("a broad point gap cannot legitimize an unbound capture slot");
    assert_eq!(error.kind(), SemanticIrErrorKind::CaptureContract);

    child.gaps[0].subject = SemanticGapSubject::MemoryLocation(MemoryLocationId::new(0));
    SemanticArtifact::try_new(
        key,
        capabilities(&[SemanticCapability::Captures]),
        vec![outer, child],
    )
    .expect("a slot-specific gap explicitly preserves the missing binding");
}

#[test]
fn receiver_capture_requires_a_receiver_value() {
    let key = key();
    let mut outer = minimal_procedure(&key, ProcedureId::new(0), "outer", 1);
    let mut child = minimal_procedure(&key, ProcedureId::new(1), "child", 3);
    child.lexical_parent = Some(ProcedureId::new(0));
    child.memory_locations.push(MemoryLocation {
        id: MemoryLocationId::new(0),
        kind: MemoryLocationKind::Capture {
            lexical_parent: ProcedureId::new(0),
        },
        source: SourceMappingId::new(0),
        evidence: EvidenceId::new(0),
    });
    outer.values.extend([
        SemanticValue {
            id: ValueId::new(0),
            kind: SemanticValueKind::Callable,
            source: SourceMappingId::new(0),
            evidence: EvidenceId::new(0),
        },
        SemanticValue {
            id: ValueId::new(1),
            kind: SemanticValueKind::Local,
            source: SourceMappingId::new(0),
            evidence: EvidenceId::new(0),
        },
    ]);
    outer.allocations.push(AllocationSite {
        id: AllocationId::new(0),
        point: ProgramPointId::new(0),
        result: ValueId::new(0),
        kind: AllocationKind::ClosureEnvironment,
        source: SourceMappingId::new(0),
        evidence: EvidenceId::new(0),
    });
    outer.captures.push(CaptureBinding {
        id: CaptureId::new(0),
        point: ProgramPointId::new(0),
        callable: ValueId::new(0),
        target: ProcedureId::new(1),
        environment: AllocationId::new(0),
        captured: CaptureSource::Value(ValueId::new(1)),
        destination: MemoryLocationId::new(0),
        mode: CaptureMode::Receiver,
        source: SourceMappingId::new(0),
        evidence: EvidenceId::new(0),
    });

    let error = SemanticArtifact::try_new(
        key.clone(),
        capabilities(&[
            SemanticCapability::Values,
            SemanticCapability::Allocations,
            SemanticCapability::Captures,
        ]),
        vec![outer.clone(), child.clone()],
    )
    .expect_err("receiver capture cannot relabel a local value");
    assert_eq!(error.kind(), SemanticIrErrorKind::CaptureContract);

    outer.captures[0].mode = CaptureMode::Unknown;
    let error = SemanticArtifact::try_new(
        key,
        capabilities(&[
            SemanticCapability::Values,
            SemanticCapability::Allocations,
            SemanticCapability::Captures,
        ]),
        vec![outer, child],
    )
    .expect_err("unknown capture mode requires a subject-specific gap");
    assert_eq!(error.kind(), SemanticIrErrorKind::GapContract);
}

#[test]
fn known_capture_mode_rejects_a_contradictory_unknown_gap() {
    let key = key();
    let source = SourceMappingId::new(0);
    let evidence = EvidenceId::new(0);
    let mut outer = minimal_procedure(&key, ProcedureId::new(0), "outer", 1);
    let mut child = minimal_procedure(&key, ProcedureId::new(1), "child", 3);
    child.lexical_parent = Some(ProcedureId::new(0));
    child.memory_locations.push(MemoryLocation {
        id: MemoryLocationId::new(0),
        kind: MemoryLocationKind::Capture {
            lexical_parent: ProcedureId::new(0),
        },
        source,
        evidence,
    });
    outer.values.extend([
        SemanticValue {
            id: ValueId::new(0),
            kind: SemanticValueKind::Callable,
            source,
            evidence,
        },
        SemanticValue {
            id: ValueId::new(1),
            kind: SemanticValueKind::Local,
            source,
            evidence,
        },
    ]);
    outer.allocations.push(AllocationSite {
        id: AllocationId::new(0),
        point: ProgramPointId::new(0),
        result: ValueId::new(0),
        kind: AllocationKind::ClosureEnvironment,
        source,
        evidence,
    });
    outer.captures.push(CaptureBinding {
        id: CaptureId::new(0),
        point: ProgramPointId::new(0),
        callable: ValueId::new(0),
        target: ProcedureId::new(1),
        environment: AllocationId::new(0),
        captured: CaptureSource::Value(ValueId::new(1)),
        destination: MemoryLocationId::new(0),
        mode: CaptureMode::Value,
        source,
        evidence,
    });
    let mut events = outer.points[0].events.to_vec();
    events.extend([
        SemanticEvent::new(
            SemanticEffect::Allocation {
                allocation: AllocationId::new(0),
            },
            source,
            evidence,
        ),
        SemanticEvent::new(
            SemanticEffect::CallableCreation {
                result: ValueId::new(0),
                callable: CallableValue {
                    kind: CallableReferenceKind::Lambda,
                    targets: CallableTargetResolution::Proven(CallableTarget::Local(
                        ProcedureId::new(1),
                    )),
                    target_evidence: evidence,
                    bound_receiver: None,
                    environment: Some(AllocationId::new(0)),
                },
            },
            source,
            evidence,
        ),
        SemanticEvent::new(
            SemanticEffect::CaptureBind {
                capture: CaptureId::new(0),
            },
            source,
            evidence,
        ),
    ]);
    outer.points[0].events = events.into_boxed_slice();
    let semantic_capabilities = capabilities(&[
        SemanticCapability::Values,
        SemanticCapability::Allocations,
        SemanticCapability::Captures,
        SemanticCapability::CallableReferences,
    ]);

    SemanticArtifact::try_new(
        key.clone(),
        semantic_capabilities.clone(),
        vec![outer.clone(), child.clone()],
    )
    .expect("the known value capture fixture is valid before adding a gap");

    outer.gaps.push(SemanticGap {
        id: SemanticGapId::new(0),
        point: ProgramPointId::new(0),
        subject: SemanticGapSubject::Capture(CaptureId::new(0)),
        capability: SemanticCapability::Captures,
        impacts: SemanticGapImpacts::for_gap(
            SemanticCapability::Captures,
            SemanticGapSubject::Capture(CaptureId::new(0)),
        ),
        kind: SemanticGapKind::Unknown,
        budget: None,
        detail: "capture mode is allegedly unknown".into(),
        source,
        evidence,
    });
    let mut events = outer.points[0].events.to_vec();
    events.push(SemanticEvent::new(
        SemanticEffect::Gap {
            gap: SemanticGapId::new(0),
        },
        source,
        evidence,
    ));
    outer.points[0].events = events.into_boxed_slice();

    let error = SemanticArtifact::try_new(key, semantic_capabilities, vec![outer, child])
        .expect_err("a known capture mode cannot also carry an unknown gap");
    assert_eq!(error.kind(), SemanticIrErrorKind::GapContract);
}

#[test]
fn rejects_same_artifact_external_callable_target() {
    let key = key();
    let external_in_name_only = procedure_locator(&key, "other", 3);
    let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
    parts.values.push(SemanticValue {
        id: ValueId::new(0),
        kind: SemanticValueKind::Callable,
        source: SourceMappingId::new(0),
        evidence: EvidenceId::new(0),
    });
    let mut events = parts.points[0].events.to_vec();
    events.push(SemanticEvent::new(
        SemanticEffect::CallableReference {
            result: ValueId::new(0),
            callable: CallableValue {
                kind: CallableReferenceKind::Function,
                targets: CallableTargetResolution::Proven(CallableTarget::External(
                    external_in_name_only,
                )),
                target_evidence: EvidenceId::new(0),
                bound_receiver: None,
                environment: None,
            },
        },
        SourceMappingId::new(0),
        EvidenceId::new(0),
    ));
    parts.points[0].events = events.into_boxed_slice();

    let error = SemanticArtifact::try_new(
        key,
        capabilities(&[
            SemanticCapability::Values,
            SemanticCapability::CallableReferences,
        ]),
        vec![parts],
    )
    .expect_err("same-artifact targets must use artifact-local ProcedureId");
    assert_eq!(error.kind(), SemanticIrErrorKind::CallableContract);
}

#[test]
fn rejects_unsupported_gap_for_complete_capability() {
    let key = key();
    let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
    parts.gaps.push(SemanticGap {
        id: SemanticGapId::new(0),
        point: ProgramPointId::new(0),
        subject: SemanticGapSubject::Point,
        capability: SemanticCapability::Calls,
        impacts: SemanticGapImpacts::for_gap(SemanticCapability::Calls, SemanticGapSubject::Point),
        kind: SemanticGapKind::Unsupported,
        budget: None,
        detail: "calls are unsupported here".into(),
        source: SourceMappingId::new(0),
        evidence: EvidenceId::new(0),
    });
    let mut events = parts.points[0].events.to_vec();
    events.push(SemanticEvent::new(
        SemanticEffect::Gap {
            gap: SemanticGapId::new(0),
        },
        SourceMappingId::new(0),
        EvidenceId::new(0),
    ));
    parts.points[0].events = events.into_boxed_slice();

    let error =
        SemanticArtifact::try_new(key, capabilities(&[SemanticCapability::Calls]), vec![parts])
            .expect_err("unsupported gap contradicts complete support");
    assert_eq!(error.kind(), SemanticIrErrorKind::CapabilityContract);
}

#[test]
fn mandatory_gap_impacts_are_enforced_while_specific_extras_are_allowed() {
    let key = key();
    let procedure_with_gap = |capability, subject, impacts| {
        let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
        parts.gaps.push(SemanticGap {
            id: SemanticGapId::new(0),
            point: ProgramPointId::new(0),
            subject,
            capability,
            impacts,
            kind: SemanticGapKind::Unknown,
            budget: None,
            detail: "fixture semantic gap".into(),
            source: SourceMappingId::new(0),
            evidence: EvidenceId::new(0),
        });
        let mut events = parts.points[0].events.to_vec();
        events.push(SemanticEvent::new(
            SemanticEffect::Gap {
                gap: SemanticGapId::new(0),
            },
            SourceMappingId::new(0),
            EvidenceId::new(0),
        ));
        parts.points[0].events = events.into_boxed_slice();
        parts
    };

    for (capability, missing) in [
        (
            SemanticCapability::DynamicDispatch,
            SemanticGapImpact::DispatchCoverage,
        ),
        (
            SemanticCapability::CleanupControlFlow,
            SemanticGapImpact::ReturnTransfer,
        ),
        (
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapImpact::ReturnTransfer,
        ),
        (
            SemanticCapability::NonLocalControl,
            SemanticGapImpact::ReturnTransfer,
        ),
        (
            SemanticCapability::Assignments,
            SemanticGapImpact::ValueFlow,
        ),
        (SemanticCapability::Captures, SemanticGapImpact::ValueFlow),
        (
            SemanticCapability::NormalCallContinuation,
            SemanticGapImpact::CallEvaluation,
        ),
    ] {
        let error = SemanticArtifact::try_new(
            key.clone(),
            capabilities(&[capability]),
            vec![procedure_with_gap(
                capability,
                SemanticGapSubject::Point,
                SemanticGapImpacts::NONE,
            )],
        )
        .expect_err("a consumer-affecting gap cannot omit its mandatory impact");
        assert_eq!(error.kind(), SemanticIrErrorKind::GapContract);
        assert!(error.detail().contains(missing.label()));
    }

    let incomplete_capture = SemanticGapImpacts::single(SemanticGapImpact::ValueFlow);
    let error = SemanticArtifact::try_new(
        key.clone(),
        capabilities(&[SemanticCapability::Captures]),
        vec![procedure_with_gap(
            SemanticCapability::Captures,
            SemanticGapSubject::Point,
            incomplete_capture,
        )],
    )
    .expect_err("a capture gap cannot hide missing heap and alias impacts");
    assert_eq!(error.kind(), SemanticIrErrorKind::GapContract);
    assert!(error.detail().contains(SemanticGapImpact::HeapRead.label()));

    let impacts = SemanticGapImpacts::single(SemanticGapImpact::DispatchCoverage)
        .with(SemanticGapImpact::CallEvaluation);
    let procedure = procedure_with_gap(
        SemanticCapability::DynamicDispatch,
        SemanticGapSubject::Point,
        impacts,
    );
    SemanticArtifact::try_new(
        key,
        capabilities(&[SemanticCapability::DynamicDispatch]),
        vec![procedure],
    )
    .expect("adapter-specific impacts may extend the mandatory baseline");
}

#[test]
fn method_references_cannot_be_callable_creation_events() {
    let key = key();
    let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
    parts.values.push(SemanticValue {
        id: ValueId::new(0),
        kind: SemanticValueKind::Callable,
        source: SourceMappingId::new(0),
        evidence: EvidenceId::new(0),
    });
    let mut events = parts.points[0].events.to_vec();
    events.push(SemanticEvent::new(
        SemanticEffect::CallableCreation {
            result: ValueId::new(0),
            callable: CallableValue {
                kind: CallableReferenceKind::StaticMethod,
                targets: CallableTargetResolution::Proven(CallableTarget::Local(ProcedureId::new(
                    0,
                ))),
                target_evidence: EvidenceId::new(0),
                bound_receiver: None,
                environment: None,
            },
        },
        SourceMappingId::new(0),
        EvidenceId::new(0),
    ));
    parts.points[0].events = events.into_boxed_slice();

    let error = SemanticArtifact::try_new(
        key,
        capabilities(&[
            SemanticCapability::Values,
            SemanticCapability::CallableReferences,
        ]),
        vec![parts],
    )
    .expect_err("method references are values, not body creation");
    assert_eq!(error.kind(), SemanticIrErrorKind::CallableContract);
}

#[test]
fn out_of_bounds_callable_creation_target_returns_an_error() {
    let key = key();
    let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
    parts.values.push(SemanticValue {
        id: ValueId::new(0),
        kind: SemanticValueKind::Callable,
        source: SourceMappingId::new(0),
        evidence: EvidenceId::new(0),
    });
    let mut events = parts.points[0].events.to_vec();
    events.push(SemanticEvent::new(
        SemanticEffect::CallableCreation {
            result: ValueId::new(0),
            callable: CallableValue {
                kind: CallableReferenceKind::Lambda,
                targets: CallableTargetResolution::Proven(CallableTarget::Local(ProcedureId::new(
                    u32::MAX,
                ))),
                target_evidence: EvidenceId::new(0),
                bound_receiver: None,
                environment: None,
            },
        },
        SourceMappingId::new(0),
        EvidenceId::new(0),
    ));
    parts.points[0].events = events.into_boxed_slice();

    let error = SemanticArtifact::try_new(
        key,
        capabilities(&[
            SemanticCapability::Values,
            SemanticCapability::CallableReferences,
        ]),
        vec![parts],
    )
    .expect_err("invalid local target must be rejected without indexing it");
    assert_eq!(error.kind(), SemanticIrErrorKind::OutOfBounds);
}

#[test]
fn callable_creation_preserves_target_uncertainty_without_a_locator() {
    let key = key();
    let mut budget = SemanticBudget::uniform(1).unwrap();
    budget
        .charge(SemanticWork {
            procedures: 1,
            ..SemanticWork::default()
        })
        .unwrap();
    let exceeded = budget
        .charge(SemanticWork {
            procedures: 1,
            ..SemanticWork::default()
        })
        .unwrap_err();
    let cases = [
        (
            CallableTargetResolution::Unknown,
            SemanticGapKind::Unknown,
            None,
        ),
        (
            CallableTargetResolution::Unsupported,
            SemanticGapKind::Unsupported,
            None,
        ),
        (
            CallableTargetResolution::ExceededBudget(Box::new([])),
            SemanticGapKind::ExceededBudget,
            Some(exceeded),
        ),
    ];

    let mut capability_builder = SemanticCapabilities::builder();
    for capability in [
        SemanticCapability::Procedures,
        SemanticCapability::EntryBoundary,
        SemanticCapability::NormalExitBoundary,
        SemanticCapability::ExceptionalExitBoundary,
        SemanticCapability::BasicBlocks,
        SemanticCapability::ProgramPoints,
        SemanticCapability::NormalControlFlow,
        SemanticCapability::ExceptionalControlFlow,
        SemanticCapability::Values,
    ] {
        capability_builder = capability_builder.complete(capability);
    }
    let semantic_capabilities = capability_builder
        .partial(SemanticCapability::CallableReferences)
        .build();

    for (targets, gap_kind, budget) in cases {
        let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
        let source = SourceMappingId::new(0);
        let evidence = EvidenceId::new(0);
        parts.values.push(SemanticValue {
            id: ValueId::new(0),
            kind: SemanticValueKind::Callable,
            source,
            evidence,
        });
        parts.gaps.push(SemanticGap {
            id: SemanticGapId::new(0),
            point: ProgramPointId::new(0),
            subject: SemanticGapSubject::Value(ValueId::new(0)),
            capability: SemanticCapability::CallableReferences,
            impacts: SemanticGapImpacts::for_gap(
                SemanticCapability::CallableReferences,
                SemanticGapSubject::Value(ValueId::new(0)),
            ),
            kind: gap_kind,
            budget,
            detail: "nested body target is unavailable".into(),
            source,
            evidence,
        });
        let mut events = parts.points[0].events.to_vec();
        events.extend([
            SemanticEvent::new(
                SemanticEffect::CallableCreation {
                    result: ValueId::new(0),
                    callable: CallableValue {
                        kind: CallableReferenceKind::Lambda,
                        targets,
                        target_evidence: evidence,
                        bound_receiver: None,
                        environment: None,
                    },
                },
                source,
                evidence,
            ),
            SemanticEvent::new(
                SemanticEffect::Gap {
                    gap: SemanticGapId::new(0),
                },
                source,
                evidence,
            ),
        ]);
        parts.points[0].events = events.into_boxed_slice();

        SemanticArtifact::try_new(key.clone(), semantic_capabilities.clone(), vec![parts])
            .expect("a known creation event may retain typed target uncertainty");
    }
}

#[test]
fn budget_limited_same_artifact_target_remains_explicitly_unmaterialized() {
    let key = key();
    let omitted = procedure_locator(&key, "omitted", 7);
    let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
    parts.values.push(SemanticValue {
        id: ValueId::new(0),
        kind: SemanticValueKind::Callable,
        source: SourceMappingId::new(0),
        evidence: EvidenceId::new(0),
    });
    let mut budget = SemanticBudget::uniform(1).unwrap();
    budget
        .charge(SemanticWork {
            procedures: 1,
            ..SemanticWork::default()
        })
        .unwrap();
    let exceeded = budget
        .charge(SemanticWork {
            procedures: 1,
            ..SemanticWork::default()
        })
        .unwrap_err();
    parts.gaps.push(SemanticGap {
        id: SemanticGapId::new(0),
        point: ProgramPointId::new(0),
        subject: SemanticGapSubject::Value(ValueId::new(0)),
        capability: SemanticCapability::CallableReferences,
        impacts: SemanticGapImpacts::for_gap(
            SemanticCapability::CallableReferences,
            SemanticGapSubject::Value(ValueId::new(0)),
        ),
        kind: SemanticGapKind::ExceededBudget,
        budget: Some(exceeded),
        detail: "nested body was recognized but not materialized".into(),
        source: SourceMappingId::new(0),
        evidence: EvidenceId::new(0),
    });
    let targets =
        CallableTargetResolution::ExceededBudget(Box::new([CallableTarget::Unmaterialized(
            omitted,
        )]));
    let mut events = parts.points[0].events.to_vec();
    events.extend([
        SemanticEvent::new(
            SemanticEffect::CallableReference {
                result: ValueId::new(0),
                callable: CallableValue {
                    kind: CallableReferenceKind::Function,
                    targets,
                    target_evidence: EvidenceId::new(0),
                    bound_receiver: None,
                    environment: None,
                },
            },
            SourceMappingId::new(0),
            EvidenceId::new(0),
        ),
        SemanticEvent::new(
            SemanticEffect::Gap {
                gap: SemanticGapId::new(0),
            },
            SourceMappingId::new(0),
            EvidenceId::new(0),
        ),
    ]);
    parts.points[0].events = events.into_boxed_slice();

    SemanticArtifact::try_new(
        key,
        capabilities(&[
            SemanticCapability::Values,
            SemanticCapability::CallableReferences,
        ]),
        vec![parts],
    )
    .expect("same-artifact locator is legal only as an incomplete target");
}

#[test]
fn unmaterialized_creation_requires_an_unpublished_direct_lexical_child() {
    let key = key();
    let mut outer = minimal_procedure(&key, ProcedureId::new(0), "outer", 1);
    outer.values.push(SemanticValue {
        id: ValueId::new(0),
        kind: SemanticValueKind::Callable,
        source: SourceMappingId::new(0),
        evidence: EvidenceId::new(0),
    });
    let mut budget = SemanticBudget::uniform(1).unwrap();
    budget
        .charge(SemanticWork {
            procedures: 1,
            ..SemanticWork::default()
        })
        .unwrap();
    let exceeded = budget
        .charge(SemanticWork {
            procedures: 1,
            ..SemanticWork::default()
        })
        .unwrap_err();
    outer.gaps.push(SemanticGap {
        id: SemanticGapId::new(0),
        point: ProgramPointId::new(0),
        subject: SemanticGapSubject::Value(ValueId::new(0)),
        capability: SemanticCapability::CallableReferences,
        impacts: SemanticGapImpacts::for_gap(
            SemanticCapability::CallableReferences,
            SemanticGapSubject::Value(ValueId::new(0)),
        ),
        kind: SemanticGapKind::ExceededBudget,
        budget: Some(exceeded),
        detail: "nested body was recognized but not materialized".into(),
        source: SourceMappingId::new(0),
        evidence: EvidenceId::new(0),
    });
    let top_level = procedure_locator(&key, "not_nested", 7);
    let mut events = outer.points[0].events.to_vec();
    events.extend([
        SemanticEvent::new(
            SemanticEffect::CallableCreation {
                result: ValueId::new(0),
                callable: CallableValue {
                    kind: CallableReferenceKind::Lambda,
                    targets: CallableTargetResolution::ExceededBudget(Box::new([
                        CallableTarget::Unmaterialized(top_level),
                    ])),
                    target_evidence: EvidenceId::new(0),
                    bound_receiver: None,
                    environment: None,
                },
            },
            SourceMappingId::new(0),
            EvidenceId::new(0),
        ),
        SemanticEvent::new(
            SemanticEffect::Gap {
                gap: SemanticGapId::new(0),
            },
            SourceMappingId::new(0),
            EvidenceId::new(0),
        ),
    ]);
    outer.points[0].events = events.into_boxed_slice();
    let semantic_capabilities = capabilities(&[
        SemanticCapability::Values,
        SemanticCapability::CallableReferences,
    ]);

    let error = SemanticArtifact::try_new(
        key.clone(),
        semantic_capabilities.clone(),
        vec![outer.clone()],
    )
    .expect_err("callable creation cannot name a top-level unmaterialized procedure");
    assert_eq!(error.kind(), SemanticIrErrorKind::CallableContract);

    let direct_child = direct_child_locator(
        &key,
        &outer.locator,
        DeclarationSegmentKind::Lambda,
        "lambda",
        9,
    );
    let SemanticEffect::CallableCreation { callable, .. } = &mut outer.points[0].events[1].effect
    else {
        panic!("fixture callable creation event moved");
    };
    callable.targets =
        CallableTargetResolution::ExceededBudget(Box::new([CallableTarget::Unmaterialized(
            direct_child.clone(),
        )]));

    SemanticArtifact::try_new(
        key.clone(),
        semantic_capabilities.clone(),
        vec![outer.clone()],
    )
    .expect("an omitted direct lexical child remains a valid incomplete creation target");

    let mut child = minimal_procedure(&key, ProcedureId::new(1), "placeholder", 11);
    child.locator = direct_child.clone();
    child.source_mappings[0].locator = direct_child;
    child.lexical_parent = Some(ProcedureId::new(0));
    let error = SemanticArtifact::try_new(key, semantic_capabilities, vec![outer, child])
        .expect_err("a published procedure must be named by its local ProcedureId");
    assert_eq!(error.kind(), SemanticIrErrorKind::CallableContract);
}

#[test]
fn artifact_construction_charges_retained_work_atomically() {
    let key = key();
    let parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
    let mut budget = SemanticBudget::uniform(1).unwrap();
    let before = budget.used();

    let error =
        SemanticArtifact::try_new_with_budget(key, capabilities(&[]), vec![parts], &mut budget)
            .expect_err("three points exceed a one-point artifact budget");

    let exceeded = error.budget_exceeded().unwrap();
    assert_eq!(
        exceeded.dimension(),
        super::super::provider::SemanticBudgetDimension::ProgramPoints
    );
    assert_eq!(budget.used(), before);
}

#[test]
fn handles_from_different_materializations_do_not_compare_equal() {
    let key = key();
    let first = Arc::new(
        SemanticArtifact::try_new(
            key.clone(),
            capabilities(&[]),
            vec![minimal_procedure(&key, ProcedureId::new(0), "main", 1)],
        )
        .unwrap(),
    );
    let second = Arc::new(
        SemanticArtifact::try_new(
            key.clone(),
            capabilities(&[]),
            vec![minimal_procedure(&key, ProcedureId::new(0), "main", 1)],
        )
        .unwrap(),
    );
    let first = first.procedure_handle(ProcedureId::new(0)).unwrap();
    let second = second.procedure_handle(ProcedureId::new(0)).unwrap();

    assert_ne!(first, second);
    let mut handles = HashSet::default();
    handles.insert(first);
    handles.insert(second);
    assert_eq!(handles.len(), 2);
}

#[test]
fn callable_environment_allocation_is_at_creation_point() {
    let key = key();
    let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
    let mut child = minimal_procedure(&key, ProcedureId::new(1), "lambda", 3);
    child.lexical_parent = Some(ProcedureId::new(0));
    parts.values.push(SemanticValue {
        id: ValueId::new(0),
        kind: SemanticValueKind::Callable,
        source: SourceMappingId::new(0),
        evidence: EvidenceId::new(0),
    });
    parts.allocations.push(AllocationSite {
        id: AllocationId::new(0),
        point: ProgramPointId::new(1),
        result: ValueId::new(0),
        kind: AllocationKind::ClosureEnvironment,
        source: SourceMappingId::new(0),
        evidence: EvidenceId::new(0),
    });
    let mut entry_events = parts.points[0].events.to_vec();
    entry_events.push(SemanticEvent::new(
        SemanticEffect::CallableCreation {
            result: ValueId::new(0),
            callable: CallableValue {
                kind: CallableReferenceKind::Lambda,
                targets: CallableTargetResolution::Proven(CallableTarget::Local(ProcedureId::new(
                    1,
                ))),
                target_evidence: EvidenceId::new(0),
                bound_receiver: None,
                environment: Some(AllocationId::new(0)),
            },
        },
        SourceMappingId::new(0),
        EvidenceId::new(0),
    ));
    parts.points[0].events = entry_events.into_boxed_slice();
    let mut exit_events = parts.points[1].events.to_vec();
    exit_events.push(SemanticEvent::new(
        SemanticEffect::Allocation {
            allocation: AllocationId::new(0),
        },
        SourceMappingId::new(0),
        EvidenceId::new(0),
    ));
    parts.points[1].events = exit_events.into_boxed_slice();

    let error = SemanticArtifact::try_new(
        key,
        capabilities(&[
            SemanticCapability::Values,
            SemanticCapability::Allocations,
            SemanticCapability::CallableReferences,
        ]),
        vec![parts, child],
    )
    .expect_err("capture environment must be allocated at callable creation");
    assert_eq!(error.kind(), SemanticIrErrorKind::CallableContract);
}

#[test]
fn call_site_callee_must_be_a_callable_value() {
    let key = key();
    let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
    parts.values.push(SemanticValue {
        id: ValueId::new(0),
        kind: SemanticValueKind::Temporary,
        source: SourceMappingId::new(0),
        evidence: EvidenceId::new(0),
    });
    parts.call_sites.push(SemanticCallSite {
        id: CallSiteId::new(0),
        point: ProgramPointId::new(0),
        callee: ValueId::new(0),
        receiver: None,
        arguments: Box::new([]),
        result: None,
        thrown: None,
        declared_targets: CallableTargetResolution::Proven(CallableTarget::Local(
            ProcedureId::new(0),
        )),
        target_evidence: EvidenceId::new(0),
        normal_continuation: ControlContinuation::Target(ProgramPointId::new(1)),
        exceptional_continuation: ControlContinuation::Target(ProgramPointId::new(2)),
        source: SourceMappingId::new(0),
        evidence: EvidenceId::new(0),
    });

    let error = SemanticArtifact::try_new(
        key,
        capabilities(&[
            SemanticCapability::Values,
            SemanticCapability::Calls,
            SemanticCapability::NormalCallContinuation,
            SemanticCapability::ExceptionalCallContinuation,
        ]),
        vec![parts],
    )
    .expect_err("call site must classify its callee as callable");
    assert_eq!(error.kind(), SemanticIrErrorKind::CallableContract);
}

#[test]
fn valid_call_has_matched_normal_and_exceptional_continuations() {
    let key = key();
    let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
    let source = SourceMappingId::new(0);
    let evidence = EvidenceId::new(0);
    parts.values.push(SemanticValue {
        id: ValueId::new(0),
        kind: SemanticValueKind::Callable,
        source,
        evidence,
    });
    let target = CallableTargetResolution::Proven(CallableTarget::Local(ProcedureId::new(0)));
    parts.call_sites.push(SemanticCallSite {
        id: CallSiteId::new(0),
        point: ProgramPointId::new(0),
        callee: ValueId::new(0),
        receiver: None,
        arguments: Box::new([]),
        result: None,
        thrown: None,
        declared_targets: target.clone(),
        target_evidence: evidence,
        normal_continuation: ControlContinuation::Target(ProgramPointId::new(1)),
        exceptional_continuation: ControlContinuation::Target(ProgramPointId::new(2)),
        source,
        evidence,
    });
    let mut entry_events = parts.points[0].events.to_vec();
    entry_events.extend([
        SemanticEvent::new(
            SemanticEffect::CallableReference {
                result: ValueId::new(0),
                callable: CallableValue {
                    kind: CallableReferenceKind::Function,
                    targets: target,
                    target_evidence: evidence,
                    bound_receiver: None,
                    environment: None,
                },
            },
            source,
            evidence,
        ),
        SemanticEvent::new(
            SemanticEffect::Invoke {
                call_site: CallSiteId::new(0),
            },
            source,
            evidence,
        ),
    ]);
    parts.points[0].events = entry_events.into_boxed_slice();
    let mut normal_events = parts.points[1].events.to_vec();
    normal_events.push(SemanticEvent::new(
        SemanticEffect::CallContinuation {
            call_site: CallSiteId::new(0),
            kind: CallContinuationKind::Normal,
        },
        source,
        evidence,
    ));
    parts.points[1].events = normal_events.into_boxed_slice();
    let mut exceptional_events = parts.points[2].events.to_vec();
    exceptional_events.push(SemanticEvent::new(
        SemanticEffect::CallContinuation {
            call_site: CallSiteId::new(0),
            kind: CallContinuationKind::Exceptional,
        },
        source,
        evidence,
    ));
    parts.points[2].events = exceptional_events.into_boxed_slice();

    let semantic_capabilities = capabilities(&[
        SemanticCapability::Values,
        SemanticCapability::CallableReferences,
        SemanticCapability::Calls,
        SemanticCapability::NormalCallContinuation,
        SemanticCapability::ExceptionalCallContinuation,
    ]);
    let mut extra_edge = parts.clone();
    extra_edge.control_edges.push(ControlEdge {
        source_point: ProgramPointId::new(0),
        target_point: ProgramPointId::new(2),
        kind: ControlEdgeKind::Normal,
        source,
        evidence,
    });
    let error =
        SemanticArtifact::try_new(key.clone(), semantic_capabilities.clone(), vec![extra_edge])
            .expect_err("a target continuation must own exactly one matching edge");
    assert_eq!(error.kind(), SemanticIrErrorKind::ControlFlowContract);

    let mut unrelated_edge_kind = parts.clone();
    unrelated_edge_kind.control_edges.push(ControlEdge {
        source_point: ProgramPointId::new(0),
        target_point: ProgramPointId::new(1),
        kind: ControlEdgeKind::ConditionalTrue,
        source,
        evidence,
    });
    let error = SemanticArtifact::try_new(
        key.clone(),
        semantic_capabilities.clone(),
        vec![unrelated_edge_kind],
    )
    .expect_err("an invoke point cannot carry an unrelated outgoing edge kind");
    assert_eq!(error.kind(), SemanticIrErrorKind::ControlFlowContract);

    let mut contradictory_gap = parts.clone();
    contradictory_gap.gaps.push(SemanticGap {
        id: SemanticGapId::new(0),
        point: ProgramPointId::new(0),
        subject: SemanticGapSubject::CallContinuation {
            call_site: CallSiteId::new(0),
            kind: CallContinuationKind::Normal,
        },
        capability: SemanticCapability::NormalCallContinuation,
        impacts: SemanticGapImpacts::for_gap(
            SemanticCapability::NormalCallContinuation,
            SemanticGapSubject::CallContinuation {
                call_site: CallSiteId::new(0),
                kind: CallContinuationKind::Normal,
            },
        ),
        kind: SemanticGapKind::Unknown,
        budget: None,
        detail: "normal continuation is allegedly unknown".into(),
        source,
        evidence,
    });
    let mut events = contradictory_gap.points[0].events.to_vec();
    events.push(SemanticEvent::new(
        SemanticEffect::Gap {
            gap: SemanticGapId::new(0),
        },
        source,
        evidence,
    ));
    contradictory_gap.points[0].events = events.into_boxed_slice();
    let error = SemanticArtifact::try_new(
        key.clone(),
        semantic_capabilities.clone(),
        vec![contradictory_gap],
    )
    .expect_err("an exact continuation cannot also carry an unknown gap");
    assert_eq!(error.kind(), SemanticIrErrorKind::GapContract);

    let mut contradictory_targets = parts.clone();
    contradictory_targets.gaps.push(SemanticGap {
        id: SemanticGapId::new(0),
        point: ProgramPointId::new(0),
        subject: SemanticGapSubject::CallSite(CallSiteId::new(0)),
        capability: SemanticCapability::Calls,
        impacts: SemanticGapImpacts::for_gap(
            SemanticCapability::Calls,
            SemanticGapSubject::CallSite(CallSiteId::new(0)),
        ),
        kind: SemanticGapKind::Unknown,
        budget: None,
        detail: "declared targets are allegedly unknown".into(),
        source,
        evidence,
    });
    let mut events = contradictory_targets.points[0].events.to_vec();
    events.push(SemanticEvent::new(
        SemanticEffect::Gap {
            gap: SemanticGapId::new(0),
        },
        source,
        evidence,
    ));
    contradictory_targets.points[0].events = events.into_boxed_slice();
    let error = SemanticArtifact::try_new(
        key.clone(),
        semantic_capabilities.clone(),
        vec![contradictory_targets],
    )
    .expect_err("proven declared targets cannot also carry an unknown gap");
    assert_eq!(error.kind(), SemanticIrErrorKind::GapContract);

    let mut converged = parts.clone();
    converged.call_sites[0].exceptional_continuation =
        ControlContinuation::Target(ProgramPointId::new(1));
    let exceptional_event = converged.points[2]
        .events
        .iter()
        .find(|event| {
            matches!(
                event.effect,
                SemanticEffect::CallContinuation {
                    kind: CallContinuationKind::Exceptional,
                    ..
                }
            )
        })
        .cloned()
        .expect("fixture has an exceptional continuation event");
    converged.points[2].events = converged.points[2]
        .events
        .iter()
        .filter(|event| {
            !matches!(
                event.effect,
                SemanticEffect::CallContinuation {
                    kind: CallContinuationKind::Exceptional,
                    ..
                }
            )
        })
        .cloned()
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let mut joined_events = converged.points[1].events.to_vec();
    joined_events.push(exceptional_event);
    converged.points[1].events = joined_events.into_boxed_slice();
    converged
        .control_edges
        .iter_mut()
        .filter(|edge| {
            edge.source_point == ProgramPointId::new(0) && edge.kind == ControlEdgeKind::Exceptional
        })
        .for_each(|edge| edge.target_point = ProgramPointId::new(1));
    SemanticArtifact::try_new(key.clone(), semantic_capabilities.clone(), vec![converged])
        .expect("normal and exceptional call arms may converge on one typed join point");

    let mut parallel_provenance = parts.clone();
    let second_source = SourceMappingId::new(1);
    let second_evidence = EvidenceId::new(1);
    parallel_provenance.source_mappings.push(SourceMapping {
        id: second_source,
        locator: parallel_provenance.locator.clone(),
        kind: SourceMappingKind::Exact,
    });
    parallel_provenance.evidence_rows.push(Evidence {
        id: second_evidence,
        proof: ProofStatus::Proven,
        completeness: EvidenceCompleteness::Complete,
        sources: Box::new([second_source]),
    });
    let mut parallel_normal_edge = parallel_provenance
        .control_edges
        .iter()
        .find(|edge| edge.kind == ControlEdgeKind::Normal)
        .cloned()
        .expect("fixture has a normal continuation edge");
    parallel_normal_edge.source = second_source;
    parallel_normal_edge.evidence = second_evidence;
    parallel_provenance.control_edges.push(parallel_normal_edge);
    SemanticArtifact::try_new(
        key.clone(),
        semantic_capabilities.clone(),
        vec![parallel_provenance],
    )
    .expect("parallel provenance must not multiply call-continuation topology");

    let artifact = SemanticArtifact::try_new(key, semantic_capabilities, vec![parts])
        .expect("matched call continuations are valid");

    assert_eq!(artifact.procedures()[0].call_sites().len(), 1);
}

#[test]
fn unsupported_call_arm_requires_a_gap_and_no_fabricated_edge() {
    let key = key();
    let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
    let source = SourceMappingId::new(0);
    let evidence = EvidenceId::new(0);
    parts.values.push(SemanticValue {
        id: ValueId::new(0),
        kind: SemanticValueKind::Callable,
        source,
        evidence,
    });
    let target = CallableTargetResolution::Proven(CallableTarget::Local(ProcedureId::new(0)));
    parts.call_sites.push(SemanticCallSite {
        id: CallSiteId::new(0),
        point: ProgramPointId::new(0),
        callee: ValueId::new(0),
        receiver: None,
        arguments: Box::new([]),
        result: None,
        thrown: None,
        declared_targets: target.clone(),
        target_evidence: evidence,
        normal_continuation: ControlContinuation::Target(ProgramPointId::new(1)),
        exceptional_continuation: ControlContinuation::Unsupported,
        source,
        evidence,
    });
    parts.gaps.push(SemanticGap {
        id: SemanticGapId::new(0),
        point: ProgramPointId::new(0),
        subject: SemanticGapSubject::CallContinuation {
            call_site: CallSiteId::new(0),
            kind: CallContinuationKind::Exceptional,
        },
        capability: SemanticCapability::ExceptionalCallContinuation,
        impacts: SemanticGapImpacts::for_gap(
            SemanticCapability::ExceptionalCallContinuation,
            SemanticGapSubject::CallContinuation {
                call_site: CallSiteId::new(0),
                kind: CallContinuationKind::Exceptional,
            },
        ),
        kind: SemanticGapKind::Unsupported,
        budget: None,
        detail: "adapter does not model exceptional call continuation".into(),
        source,
        evidence,
    });
    let mut entry_events = parts.points[0].events.to_vec();
    entry_events.extend([
        SemanticEvent::new(
            SemanticEffect::CallableReference {
                result: ValueId::new(0),
                callable: CallableValue {
                    kind: CallableReferenceKind::Function,
                    targets: target,
                    target_evidence: evidence,
                    bound_receiver: None,
                    environment: None,
                },
            },
            source,
            evidence,
        ),
        SemanticEvent::new(
            SemanticEffect::Invoke {
                call_site: CallSiteId::new(0),
            },
            source,
            evidence,
        ),
        SemanticEvent::new(
            SemanticEffect::Gap {
                gap: SemanticGapId::new(0),
            },
            source,
            evidence,
        ),
    ]);
    parts.points[0].events = entry_events.into_boxed_slice();
    let mut normal_events = parts.points[1].events.to_vec();
    normal_events.push(SemanticEvent::new(
        SemanticEffect::CallContinuation {
            call_site: CallSiteId::new(0),
            kind: CallContinuationKind::Normal,
        },
        source,
        evidence,
    ));
    parts.points[1].events = normal_events.into_boxed_slice();
    parts.control_edges.retain(|edge| {
        !(edge.source_point == ProgramPointId::new(0)
            && edge.target_point == ProgramPointId::new(2))
    });

    let semantic_capabilities = capabilities(&[
        SemanticCapability::Values,
        SemanticCapability::CallableReferences,
        SemanticCapability::Calls,
        SemanticCapability::NormalCallContinuation,
    ]);
    let mut fabricated_edge = parts.clone();
    fabricated_edge.control_edges.push(ControlEdge {
        source_point: ProgramPointId::new(0),
        target_point: ProgramPointId::new(2),
        kind: ControlEdgeKind::Exceptional,
        source,
        evidence,
    });
    let error = SemanticArtifact::try_new(
        key.clone(),
        semantic_capabilities.clone(),
        vec![fabricated_edge],
    )
    .expect_err("an unsupported continuation cannot retain a fabricated edge");
    assert_eq!(error.kind(), SemanticIrErrorKind::ControlFlowContract);

    let artifact = SemanticArtifact::try_new(key, semantic_capabilities, vec![parts])
        .expect("an unsupported arm is valid only as a scoped gap");

    assert!(
        artifact.procedures()[0]
            .control_edges()
            .iter()
            .all(|edge| edge.kind != ControlEdgeKind::Exceptional)
    );
}

#[test]
fn valid_async_suspend_has_matched_resume_arms() {
    let key = key();
    let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
    parts.properties.is_async = true;
    let source = SourceMappingId::new(0);
    let evidence = EvidenceId::new(0);

    let mut entry_events = parts.points[0].events.to_vec();
    entry_events.push(SemanticEvent::new(
        SemanticEffect::AsyncSuspend {
            awaited: None,
            normal_resume: ControlContinuation::Target(ProgramPointId::new(1)),
            exceptional_resume: ControlContinuation::Target(ProgramPointId::new(2)),
        },
        source,
        evidence,
    ));
    parts.points[0].events = entry_events.into_boxed_slice();
    let mut normal_events = parts.points[1].events.to_vec();
    normal_events.push(SemanticEvent::new(
        SemanticEffect::AsyncResume {
            suspend: ProgramPointId::new(0),
            kind: AsyncResumeKind::Normal,
            result: None,
        },
        source,
        evidence,
    ));
    parts.points[1].events = normal_events.into_boxed_slice();
    let mut exceptional_events = parts.points[2].events.to_vec();
    exceptional_events.push(SemanticEvent::new(
        SemanticEffect::AsyncResume {
            suspend: ProgramPointId::new(0),
            kind: AsyncResumeKind::Exceptional,
            result: None,
        },
        source,
        evidence,
    ));
    parts.points[2].events = exceptional_events.into_boxed_slice();
    parts
        .control_edges
        .retain(|edge| edge.source_point != ProgramPointId::new(0));
    parts.control_edges.extend([
        ControlEdge {
            source_point: ProgramPointId::new(0),
            target_point: ProgramPointId::new(1),
            kind: ControlEdgeKind::AsyncNormal,
            source,
            evidence,
        },
        ControlEdge {
            source_point: ProgramPointId::new(0),
            target_point: ProgramPointId::new(2),
            kind: ControlEdgeKind::AsyncExceptional,
            source,
            evidence,
        },
    ]);

    let mut extra_edge = parts.clone();
    extra_edge.control_edges.push(ControlEdge {
        source_point: ProgramPointId::new(0),
        target_point: ProgramPointId::new(2),
        kind: ControlEdgeKind::AsyncNormal,
        source,
        evidence,
    });
    let error = SemanticArtifact::try_new(
        key.clone(),
        capabilities(&[SemanticCapability::AsyncSuspendResume]),
        vec![extra_edge],
    )
    .expect_err("an async target arm must own exactly one matching edge");
    assert_eq!(error.kind(), SemanticIrErrorKind::ControlFlowContract);

    let mut unrelated_edge_kind = parts.clone();
    unrelated_edge_kind.control_edges.push(ControlEdge {
        source_point: ProgramPointId::new(0),
        target_point: ProgramPointId::new(1),
        kind: ControlEdgeKind::Normal,
        source,
        evidence,
    });
    let error = SemanticArtifact::try_new(
        key.clone(),
        capabilities(&[SemanticCapability::AsyncSuspendResume]),
        vec![unrelated_edge_kind],
    )
    .expect_err("an async-suspend point cannot carry an unrelated outgoing edge kind");
    assert_eq!(error.kind(), SemanticIrErrorKind::ControlFlowContract);

    let mut converged = parts.clone();
    let SemanticEffect::AsyncSuspend {
        exceptional_resume, ..
    } = &mut converged.points[0].events[1].effect
    else {
        panic!("fixture async suspend event moved");
    };
    *exceptional_resume = ControlContinuation::Target(ProgramPointId::new(1));
    let exceptional_event = converged.points[2]
        .events
        .iter()
        .find(|event| {
            matches!(
                event.effect,
                SemanticEffect::AsyncResume {
                    kind: AsyncResumeKind::Exceptional,
                    ..
                }
            )
        })
        .cloned()
        .expect("fixture has an exceptional resume event");
    converged.points[2].events = converged.points[2]
        .events
        .iter()
        .filter(|event| {
            !matches!(
                event.effect,
                SemanticEffect::AsyncResume {
                    kind: AsyncResumeKind::Exceptional,
                    ..
                }
            )
        })
        .cloned()
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let mut joined_events = converged.points[1].events.to_vec();
    joined_events.push(exceptional_event);
    converged.points[1].events = joined_events.into_boxed_slice();
    converged
        .control_edges
        .iter_mut()
        .filter(|edge| {
            edge.source_point == ProgramPointId::new(0)
                && edge.kind == ControlEdgeKind::AsyncExceptional
        })
        .for_each(|edge| edge.target_point = ProgramPointId::new(1));
    SemanticArtifact::try_new(
        key.clone(),
        capabilities(&[SemanticCapability::AsyncSuspendResume]),
        vec![converged],
    )
    .expect("normal and exceptional async arms may converge on one typed join point");

    SemanticArtifact::try_new(
        key,
        capabilities(&[SemanticCapability::AsyncSuspendResume]),
        vec![parts],
    )
    .expect("matched async resume arms are valid");
}

#[test]
fn async_continuation_gap_requires_a_real_matching_suspend_arm() {
    let key = key();
    let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
    let source = SourceMappingId::new(0);
    let evidence = EvidenceId::new(0);
    parts.gaps.push(SemanticGap {
        id: SemanticGapId::new(0),
        point: ProgramPointId::new(0),
        subject: SemanticGapSubject::AsyncContinuation {
            suspend: ProgramPointId::new(0),
            kind: AsyncResumeKind::Normal,
        },
        capability: SemanticCapability::AsyncSuspendResume,
        impacts: SemanticGapImpacts::for_gap(
            SemanticCapability::AsyncSuspendResume,
            SemanticGapSubject::AsyncContinuation {
                suspend: ProgramPointId::new(0),
                kind: AsyncResumeKind::Normal,
            },
        ),
        kind: SemanticGapKind::Unknown,
        budget: None,
        detail: "normal resume is allegedly unknown".into(),
        source,
        evidence,
    });
    let mut events = parts.points[0].events.to_vec();
    events.push(SemanticEvent::new(
        SemanticEffect::Gap {
            gap: SemanticGapId::new(0),
        },
        source,
        evidence,
    ));
    parts.points[0].events = events.into_boxed_slice();

    let error = SemanticArtifact::try_new(
        key,
        capabilities(&[SemanticCapability::AsyncSuspendResume]),
        vec![parts],
    )
    .expect_err("an async-continuation gap must name an actual suspend event");
    assert_eq!(error.kind(), SemanticIrErrorKind::GapContract);
}

#[test]
fn multiple_control_splits_at_one_point_are_rejected() {
    let key = key();
    let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
    let mut events = parts.points[0].events.to_vec();
    events.extend([
        SemanticEvent::new(
            SemanticEffect::ProcedureReturn { value: None },
            SourceMappingId::new(0),
            EvidenceId::new(0),
        ),
        SemanticEvent::new(
            SemanticEffect::Throw { value: None },
            SourceMappingId::new(0),
            EvidenceId::new(0),
        ),
    ]);
    parts.points[0].events = events.into_boxed_slice();

    let error = SemanticArtifact::try_new(
        key,
        capabilities(&[SemanticCapability::ReturnFlow]),
        vec![parts],
    )
    .expect_err("one point cannot contain two control splits");
    assert_eq!(error.kind(), SemanticIrErrorKind::ControlFlowContract);
}

#[test]
fn async_events_require_async_procedure_property() {
    let key = key();
    let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
    let source = SourceMappingId::new(0);
    let evidence = EvidenceId::new(0);

    let mut entry_events = parts.points[0].events.to_vec();
    entry_events.push(SemanticEvent::new(
        SemanticEffect::AsyncSuspend {
            awaited: None,
            normal_resume: ControlContinuation::Target(ProgramPointId::new(1)),
            exceptional_resume: ControlContinuation::Target(ProgramPointId::new(2)),
        },
        source,
        evidence,
    ));
    parts.points[0].events = entry_events.into_boxed_slice();

    let mut normal_events = parts.points[1].events.to_vec();
    normal_events.push(SemanticEvent::new(
        SemanticEffect::AsyncResume {
            suspend: ProgramPointId::new(0),
            kind: AsyncResumeKind::Normal,
            result: None,
        },
        source,
        evidence,
    ));
    parts.points[1].events = normal_events.into_boxed_slice();

    let mut exceptional_events = parts.points[2].events.to_vec();
    exceptional_events.push(SemanticEvent::new(
        SemanticEffect::AsyncResume {
            suspend: ProgramPointId::new(0),
            kind: AsyncResumeKind::Exceptional,
            result: None,
        },
        source,
        evidence,
    ));
    parts.points[2].events = exceptional_events.into_boxed_slice();
    parts
        .control_edges
        .retain(|edge| edge.source_point != ProgramPointId::new(0));
    parts.control_edges.extend([
        ControlEdge {
            source_point: ProgramPointId::new(0),
            target_point: ProgramPointId::new(1),
            kind: ControlEdgeKind::AsyncNormal,
            source,
            evidence,
        },
        ControlEdge {
            source_point: ProgramPointId::new(0),
            target_point: ProgramPointId::new(2),
            kind: ControlEdgeKind::AsyncExceptional,
            source,
            evidence,
        },
    ]);

    let error = SemanticArtifact::try_new(
        key,
        capabilities(&[SemanticCapability::AsyncSuspendResume]),
        vec![parts],
    )
    .expect_err("async events in a non-async procedure must fail");
    assert_eq!(error.kind(), SemanticIrErrorKind::AsyncContract);
}
