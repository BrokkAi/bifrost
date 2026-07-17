mod common;

use brokk_bifrost::analyzer::semantic::*;
use brokk_bifrost::{Language, ProjectFile};

use common::InlineTestProject;

const SOURCE: SourceMappingId = SourceMappingId::new(0);
const ALTERNATE_SOURCE: SourceMappingId = SourceMappingId::new(1);
const EVIDENCE: EvidenceId = EvidenceId::new(0);
const ALTERNATE_EVIDENCE: EvidenceId = EvidenceId::new(1);
const BLOCK: BlockId = BlockId::new(0);

const ENTRY: ProgramPointId = ProgramPointId::new(0);
const STRAIGHT_LINE: ProgramPointId = ProgramPointId::new(1);
const BRANCH: ProgramPointId = ProgramPointId::new(2);
const TRUE_ARM: ProgramPointId = ProgramPointId::new(3);
const FALSE_ARM: ProgramPointId = ProgramPointId::new(4);
const MERGE: ProgramPointId = ProgramPointId::new(5);
const LOOP_BODY: ProgramPointId = ProgramPointId::new(6);
const NORMAL_EXIT: ProgramPointId = ProgramPointId::new(7);
const EXCEPTIONAL_EXIT: ProgramPointId = ProgramPointId::new(8);
const DISCONNECTED: ProgramPointId = ProgramPointId::new(9);

struct FixtureSource {
    key: SemanticArtifactKey,
    locator: SemanticLocator,
}

impl FixtureSource {
    fn from_file(file: &ProjectFile) -> Self {
        let contents = file
            .read_to_string()
            .expect("inline CFG fixture should be readable");
        let mount = WorkspaceMountId::hash_bytes(b"semantic-cfg-contract-mount");
        let path = WorkspaceRelativePath::try_from_path(file.rel_path())
            .expect("inline CFG fixture path should be workspace-relative");
        let language = SemanticLanguage::Standard(Language::TypeScript);
        let declaration_anchor = anchor(0, 1);
        let declaration = DeclarationLocator::new(vec![
            DeclarationSegment::named(
                DeclarationSegmentKind::Function,
                "topology",
                declaration_anchor,
                0,
            )
            .expect("fixture function name should be non-empty"),
        ])
        .expect("fixture declaration should be non-empty");
        let locator = SemanticLocator::new(
            mount,
            path.clone(),
            language,
            declaration,
            SemanticRole::Procedure,
            declaration_anchor,
        );
        let key = SemanticArtifactKey::new(
            mount,
            path,
            language,
            SourceRevision::Disk {
                content: ContentIdentity::hash_bytes(contents.as_bytes()),
            },
            AdapterSemanticsVersion::hash_bytes("semantic-cfg-contract", b"cfg-v1")
                .expect("fixture adapter name should be non-empty"),
            SemanticIrVersion::current(),
            ConfigurationFingerprint::hash_bytes(b"cfg-contract-configuration"),
            DependencyFingerprint::hash_bytes(b"cfg-contract-dependencies"),
        );
        Self { key, locator }
    }

    fn point_locator(&self, offset: u32) -> SemanticLocator {
        SemanticLocator::new(
            self.key.mount(),
            self.key.path().clone(),
            self.key.language(),
            self.locator.declaration().clone(),
            SemanticRole::ProgramPoint,
            anchor(offset, 1),
        )
    }
}

fn anchor(offset: u32, width: u32) -> SourceAnchor {
    let start = SourcePosition::new(offset, 0, offset);
    let end_offset = offset + width;
    let end = SourcePosition::new(end_offset, 0, end_offset);
    SourceAnchor::new(
        SourceSpan::new(start, end).expect("fixture source span should be ordered"),
        0,
    )
}

fn event(effect: SemanticEffect) -> SemanticEvent {
    SemanticEvent::new(effect, SOURCE, EVIDENCE)
}

fn edge(
    source_point: ProgramPointId,
    target_point: ProgramPointId,
    kind: ControlEdgeKind,
    source: SourceMappingId,
    evidence: EvidenceId,
) -> ControlEdge {
    ControlEdge {
        source_point,
        target_point,
        kind,
        source,
        evidence,
    }
}

fn fixture_edges() -> Vec<ControlEdge> {
    vec![
        edge(
            ENTRY,
            STRAIGHT_LINE,
            ControlEdgeKind::Normal,
            SOURCE,
            EVIDENCE,
        ),
        edge(
            STRAIGHT_LINE,
            BRANCH,
            ControlEdgeKind::Normal,
            SOURCE,
            EVIDENCE,
        ),
        edge(
            BRANCH,
            TRUE_ARM,
            ControlEdgeKind::ConditionalTrue,
            SOURCE,
            EVIDENCE,
        ),
        // These parallel edges prove that kind and provenance are payload,
        // rather than being collapsed into a bare source-target pair.
        edge(
            BRANCH,
            TRUE_ARM,
            ControlEdgeKind::SwitchCase,
            ALTERNATE_SOURCE,
            EVIDENCE,
        ),
        edge(
            BRANCH,
            TRUE_ARM,
            ControlEdgeKind::ConditionalTrue,
            ALTERNATE_SOURCE,
            ALTERNATE_EVIDENCE,
        ),
        edge(
            BRANCH,
            FALSE_ARM,
            ControlEdgeKind::ConditionalFalse,
            SOURCE,
            EVIDENCE,
        ),
        edge(TRUE_ARM, MERGE, ControlEdgeKind::Normal, SOURCE, EVIDENCE),
        edge(FALSE_ARM, MERGE, ControlEdgeKind::Normal, SOURCE, EVIDENCE),
        edge(MERGE, LOOP_BODY, ControlEdgeKind::Normal, SOURCE, EVIDENCE),
        edge(
            LOOP_BODY,
            MERGE,
            ControlEdgeKind::LoopBack,
            SOURCE,
            EVIDENCE,
        ),
        edge(
            LOOP_BODY,
            NORMAL_EXIT,
            ControlEdgeKind::ConditionalFalse,
            SOURCE,
            EVIDENCE,
        ),
    ]
}

fn build_artifact(source: &FixtureSource, control_edges: Vec<ControlEdge>) -> SemanticArtifact {
    let mut parts = ProcedureSemanticsParts::new(
        ProcedureId::new(0),
        source.locator.clone(),
        ProcedureKind::Function,
        SOURCE,
        EVIDENCE,
    );
    parts.source_mappings.extend([
        SourceMapping {
            id: SOURCE,
            locator: source.locator.clone(),
            kind: SourceMappingKind::Exact,
        },
        SourceMapping {
            id: ALTERNATE_SOURCE,
            locator: source.point_locator(16),
            kind: SourceMappingKind::Exact,
        },
    ]);
    parts.evidence_rows.extend([
        Evidence {
            id: EVIDENCE,
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Complete,
            sources: Box::new([SOURCE]),
        },
        Evidence {
            id: ALTERNATE_EVIDENCE,
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Complete,
            sources: Box::new([ALTERNATE_SOURCE]),
        },
    ]);

    let point_ids = [
        ENTRY,
        STRAIGHT_LINE,
        BRANCH,
        TRUE_ARM,
        FALSE_ARM,
        MERGE,
        LOOP_BODY,
        NORMAL_EXIT,
        EXCEPTIONAL_EXIT,
        DISCONNECTED,
    ];
    parts.blocks.push(BasicBlock {
        id: BLOCK,
        points: point_ids.into(),
        source: SOURCE,
        evidence: EVIDENCE,
    });
    parts.points = point_ids
        .into_iter()
        .map(|id| {
            let events = match id {
                ENTRY => vec![event(SemanticEffect::Entry)],
                NORMAL_EXIT => vec![event(SemanticEffect::NormalExit)],
                EXCEPTIONAL_EXIT => vec![event(SemanticEffect::ExceptionalExit)],
                _ => Vec::new(),
            }
            .into_boxed_slice();
            ProgramPoint {
                id,
                block: BLOCK,
                events,
                source: SOURCE,
                evidence: EVIDENCE,
            }
        })
        .collect();
    parts.control_edges = control_edges;

    let capabilities = SemanticCapabilities::builder()
        .complete(SemanticCapability::Procedures)
        .complete(SemanticCapability::EntryBoundary)
        .complete(SemanticCapability::NormalExitBoundary)
        .complete(SemanticCapability::ExceptionalExitBoundary)
        .complete(SemanticCapability::BasicBlocks)
        .complete(SemanticCapability::ProgramPoints)
        .complete(SemanticCapability::NormalControlFlow)
        .build();
    SemanticArtifact::try_new(source.key.clone(), capabilities, vec![parts])
        .expect("manual CFG fixture should satisfy the semantic IR contract")
}

fn matching_edge_id(procedure: &ProcedureSemantics, expected: &ControlEdge) -> ControlEdgeId {
    procedure
        .cfg()
        .edges()
        .iter()
        .position(|actual| actual == expected)
        .and_then(|index| ControlEdgeId::try_from_index(index).ok())
        .expect("expected rich edge should be present in the canonical CFG")
}

fn observed_edges<'a>(
    edges: impl Iterator<Item = (ControlEdgeId, &'a ControlEdge)>,
) -> Vec<(ControlEdgeId, ControlEdge)> {
    edges.map(|(id, edge)| (id, edge.clone())).collect()
}

fn expected_edges(
    procedure: &ProcedureSemantics,
    edges: impl IntoIterator<Item = ControlEdge>,
) -> Vec<(ControlEdgeId, ControlEdge)> {
    let mut expected = edges
        .into_iter()
        .map(|edge| (matching_edge_id(procedure, &edge), edge))
        .collect::<Vec<_>>();
    expected.sort_unstable_by_key(|(id, _)| *id);
    expected
}

#[test]
fn cfg_exposes_exact_symmetric_successor_and_predecessor_rows() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/topology.ts",
            r#"
export function topology(flag: boolean) {
    const straight = 1;
    if (flag) {
        const truthy = 2;
    } else {
        const falsy = 3;
    }
    let loopValue = 0;
    while (flag) {
        loopValue++;
    }
    return loopValue;
    const disconnected = 4;
}
"#,
        )
        .build();
    let source = FixtureSource::from_file(&project.file("src/topology.ts"));
    let artifact = build_artifact(&source, fixture_edges());
    let procedure = artifact
        .procedure(ProcedureId::new(0))
        .expect("fixture procedure should exist");

    assert_eq!(procedure.cfg().edges(), procedure.control_edges());
    assert_eq!(
        observed_edges(procedure.cfg().successor_edges(BRANCH)),
        observed_edges(procedure.successor_edges(BRANCH))
    );
    assert_eq!(
        observed_edges(procedure.cfg().predecessor_edges(MERGE)),
        observed_edges(procedure.predecessor_edges(MERGE))
    );
    assert_eq!(
        observed_edges(procedure.successor_edges(STRAIGHT_LINE)),
        expected_edges(
            procedure,
            [edge(
                STRAIGHT_LINE,
                BRANCH,
                ControlEdgeKind::Normal,
                SOURCE,
                EVIDENCE,
            )],
        )
    );
    assert_eq!(
        observed_edges(procedure.successor_edges(BRANCH)),
        expected_edges(
            procedure,
            [
                edge(
                    BRANCH,
                    TRUE_ARM,
                    ControlEdgeKind::ConditionalTrue,
                    SOURCE,
                    EVIDENCE,
                ),
                edge(
                    BRANCH,
                    TRUE_ARM,
                    ControlEdgeKind::SwitchCase,
                    ALTERNATE_SOURCE,
                    EVIDENCE,
                ),
                edge(
                    BRANCH,
                    TRUE_ARM,
                    ControlEdgeKind::ConditionalTrue,
                    ALTERNATE_SOURCE,
                    ALTERNATE_EVIDENCE,
                ),
                edge(
                    BRANCH,
                    FALSE_ARM,
                    ControlEdgeKind::ConditionalFalse,
                    SOURCE,
                    EVIDENCE,
                ),
            ],
        )
    );
    assert_eq!(
        observed_edges(procedure.predecessor_edges(MERGE)),
        expected_edges(
            procedure,
            [
                edge(TRUE_ARM, MERGE, ControlEdgeKind::Normal, SOURCE, EVIDENCE),
                edge(FALSE_ARM, MERGE, ControlEdgeKind::Normal, SOURCE, EVIDENCE),
                edge(
                    LOOP_BODY,
                    MERGE,
                    ControlEdgeKind::LoopBack,
                    SOURCE,
                    EVIDENCE,
                ),
            ],
        )
    );
    assert_eq!(
        observed_edges(procedure.successor_edges(LOOP_BODY)),
        expected_edges(
            procedure,
            [
                edge(
                    LOOP_BODY,
                    MERGE,
                    ControlEdgeKind::LoopBack,
                    SOURCE,
                    EVIDENCE,
                ),
                edge(
                    LOOP_BODY,
                    NORMAL_EXIT,
                    ControlEdgeKind::ConditionalFalse,
                    SOURCE,
                    EVIDENCE,
                ),
            ],
        )
    );

    assert_eq!(procedure.predecessor_edges(ENTRY).len(), 0);
    assert_eq!(procedure.successor_edges(NORMAL_EXIT).len(), 0);
    assert_eq!(procedure.predecessor_edges(EXCEPTIONAL_EXIT).len(), 0);
    assert_eq!(procedure.successor_edges(EXCEPTIONAL_EXIT).len(), 0);
    assert_eq!(procedure.predecessor_edges(DISCONNECTED).len(), 0);
    assert_eq!(procedure.successor_edges(DISCONNECTED).len(), 0);

    for point in procedure.points() {
        for (edge_id, edge) in procedure.successor_edges(point.id) {
            assert_eq!(procedure.control_edge(edge_id), Some(edge));
            assert_eq!(procedure.cfg().edge(edge_id), Some(edge));
            assert!(
                procedure
                    .predecessor_edges(edge.target_point)
                    .any(|(candidate_id, candidate)| candidate_id == edge_id && candidate == edge),
                "successor edge {edge_id} must occur in the target's predecessor row"
            );
        }
        for (edge_id, edge) in procedure.predecessor_edges(point.id) {
            assert_eq!(procedure.control_edge(edge_id), Some(edge));
            assert!(
                procedure
                    .successor_edges(edge.source_point)
                    .any(|(candidate_id, candidate)| candidate_id == edge_id && candidate == edge),
                "predecessor edge {edge_id} must occur in the source's successor row"
            );
        }
    }
}

#[test]
fn canonical_edge_ids_do_not_depend_on_construction_order() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/permuted.ts",
            r#"
export function topology(flag: boolean) {
    const straight = 1;
    if (flag) {
        const truthy = 2;
    } else {
        const falsy = 3;
    }
    while (flag) {}
    return straight;
    const disconnected = 4;
}
"#,
        )
        .build();
    let source = FixtureSource::from_file(&project.file("src/permuted.ts"));
    let edges = fixture_edges();
    let mut permuted = edges.clone();
    permuted.rotate_left(4);
    permuted.reverse();

    let first = build_artifact(&source, edges);
    let second = build_artifact(&source, permuted);
    let first = first
        .procedure(ProcedureId::new(0))
        .expect("first fixture procedure should exist");
    let second = second
        .procedure(ProcedureId::new(0))
        .expect("second fixture procedure should exist");

    assert_eq!(first.cfg().edges(), second.cfg().edges());
    assert_eq!(first.control_edges(), second.control_edges());
    for index in 0..first.cfg().edges().len() {
        let id = ControlEdgeId::try_from_index(index).expect("fixture edge count should fit u32");
        assert_eq!(first.control_edge(id), second.control_edge(id));
    }
    for point in first.points() {
        assert_eq!(
            observed_edges(first.successor_edges(point.id)),
            observed_edges(second.successor_edges(point.id))
        );
        assert_eq!(
            observed_edges(first.predecessor_edges(point.id)),
            observed_edges(second.predecessor_edges(point.id))
        );
    }
}
