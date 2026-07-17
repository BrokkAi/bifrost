mod common;

use brokk_bifrost::analyzer::semantic::*;
use brokk_bifrost::{AnalyzerConfig, Language, ProjectFile};

use common::{
    InlineTestProject,
    semantic_graph::{PointSelector, SemanticGraph, TopologyRenderLimits, edge as expected_edge},
};

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

#[test]
fn typescript_cfg_aliases_assert_exact_predecessors_successors_and_reachability() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/branch.ts",
            r#"
                function choose(flag: boolean): void {
                    if (flag) positive();
                    else negative();
                    done();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/branch.ts");

    graph
        .bind(
            "branch",
            PointSelector::new("flag")
                .occurrence(1)
                .procedure("choose")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "positive_statement",
            PointSelector::new("positive();").procedure("choose"),
        )
        .bind(
            "negative_statement",
            PointSelector::new("negative();").procedure("choose"),
        )
        .bind(
            "done_statement",
            PointSelector::new("done();").procedure("choose"),
        );

    graph.assert_successors(
        "branch",
        &[
            expected_edge("positive_statement", ControlEdgeKind::ConditionalTrue),
            expected_edge("negative_statement", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_predecessors(
        "positive_statement",
        &[expected_edge("branch", ControlEdgeKind::ConditionalTrue)],
    );
    graph.assert_predecessors(
        "negative_statement",
        &[expected_edge("branch", ControlEdgeKind::ConditionalFalse)],
    );
    graph.assert_reachable("branch", "done_statement");
    graph.assert_unreachable("positive_statement", "negative_statement");
    graph.assert_adjacency_symmetric();

    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(rendered.contains("aliases=branch"));
    assert!(!rendered.contains("ProgramPointId"));
}

#[test]
fn typescript_cfg_retains_post_return_syntax_as_disconnected_points() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/dead.ts",
            r#"
                function stop(): void {
                    return;
                    never();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/dead.ts");

    graph
        .bind(
            "entry",
            PointSelector::new("function stop")
                .procedure("stop")
                .effect("entry"),
        )
        .bind(
            "return",
            PointSelector::new("return;")
                .procedure("stop")
                .effect("procedure_return"),
        )
        .bind(
            "normal_exit",
            PointSelector::new("function stop")
                .procedure("stop")
                .effect("normal_exit"),
        )
        .bind(
            "exceptional_exit",
            PointSelector::new("function stop")
                .procedure("stop")
                .effect("exceptional_exit"),
        )
        .bind(
            "dead_statement",
            PointSelector::new("never();")
                .procedure("stop")
                .outgoing_kind(ControlEdgeKind::Normal),
        );

    graph.assert_successors(
        "return",
        &[expected_edge("normal_exit", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("entry", "return");
    graph.assert_unreachable("entry", "dead_statement");
    graph.assert_unreachable("return", "dead_statement");
    graph.assert_unreachable("dead_statement", "normal_exit");
    graph.assert_unreachable("dead_statement", "exceptional_exit");
    graph.assert_adjacency_symmetric();
}

#[test]
fn point_selectors_distinguish_text_and_anchor_occurrences_and_nested_callables() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/selectors.ts",
            r#"
                function outer(flag: boolean): void {
                    touch();
                    try {
                        if (flag) return;
                    } finally {
                        cleanup();
                    }
                    const nested = () => {
                        touch();
                    };
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/selectors.ts");

    let nested_as_outer = graph
        .try_bind(
            "wrong_scope",
            PointSelector::new("touch()")
                .occurrence(1)
                .procedure("outer")
                .effect("invoke"),
        )
        .expect_err("an outer callable qualifier must not match its nested lambda");
    assert!(nested_as_outer.to_string().contains("matched no semantic"));
    graph
        .bind(
            "nested_touch",
            PointSelector::new("touch()")
                .occurrence(1)
                .procedure("nested")
                .effect("invoke"),
        )
        .bind(
            "first_cleanup",
            PointSelector::new("cleanup()")
                .procedure("outer")
                .effect("invoke")
                .anchor_occurrence(0),
        );

    let ambiguous_cleanup = graph
        .try_bind(
            "ambiguous_cleanup",
            PointSelector::new("cleanup()")
                .procedure("outer")
                .effect("invoke"),
        )
        .expect_err("finally specialization should retain distinct anchor occurrences");
    let diagnostic = ambiguous_cleanup.to_string();
    assert!(diagnostic.contains("anchor="));
    assert!(diagnostic.contains('#'));
    assert!(diagnostic.contains("bounded topology context:"));
}

#[test]
fn typescript_loop_completions_include_labels_and_infinite_for_has_no_exit() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/loops.ts",
            r#"
                function labeled(flag: boolean): void {
                    outer: while (flag) {
                        for (;;) {
                            if (flag) continue outer;
                            break;
                        }
                        break outer;
                    }
                    after();
                }

                function endless(): void {
                    for (;;) {
                        spin();
                    }
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/loops.ts");

    graph
        .bind(
            "while_test",
            PointSelector::new("flag")
                .occurrence(1)
                .procedure("labeled")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "labeled_while_entry",
            PointSelector::new(
                r#"outer: while (flag) {
                        for (;;) {
                            if (flag) continue outer;
                            break;
                        }
                        break outer;
                    }"#,
            )
            .procedure("labeled")
            .anchor_occurrence(0),
        )
        .bind(
            "continue_outer",
            PointSelector::new("continue outer;").procedure("labeled"),
        )
        .bind(
            "inner_break",
            PointSelector::new("break;").procedure("labeled"),
        )
        .bind(
            "break_outer",
            PointSelector::new("break outer;").procedure("labeled"),
        )
        .bind(
            "after",
            PointSelector::new("after()")
                .procedure("labeled")
                .effect("invoke"),
        )
        .bind(
            "endless_entry",
            PointSelector::new("function endless")
                .procedure("endless")
                .effect("entry"),
        )
        .bind(
            "endless_test",
            PointSelector::new("for (;;)")
                .occurrence(1)
                .procedure("endless")
                .anchor_occurrence(1),
        )
        .bind(
            "endless_body",
            PointSelector::new("{\n                        spin();\n                    }")
                .procedure("endless"),
        )
        .bind(
            "spin",
            PointSelector::new("spin()")
                .procedure("endless")
                .effect("invoke"),
        )
        .bind(
            "endless_normal_exit",
            PointSelector::new("function endless")
                .procedure("endless")
                .effect("normal_exit"),
        );

    graph.assert_successors(
        "continue_outer",
        &[expected_edge(
            "labeled_while_entry",
            ControlEdgeKind::LoopBack,
        )],
    );
    graph.assert_reachable("labeled_while_entry", "while_test");
    graph.assert_reachable("inner_break", "break_outer");
    graph.assert_reachable("break_outer", "after");
    graph.assert_successors(
        "endless_test",
        &[expected_edge("endless_body", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("endless_entry", "spin");
    graph.assert_unreachable("spin", "endless_normal_exit");
    graph.assert_adjacency_symmetric();
}

#[test]
fn typescript_nested_calls_have_matched_normal_and_exceptional_continuations() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/calls.ts",
            r#"
                declare function inner(): number;
                declare function outer(value: number): number;
                declare function after(): void;

                function exercise(): void {
                    outer(inner());
                    after();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/calls.ts");

    graph
        .bind(
            "inner_invoke",
            PointSelector::new("inner()")
                .procedure("exercise")
                .effect("invoke"),
        )
        .bind(
            "inner_normal",
            PointSelector::new("inner()")
                .procedure("exercise")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "inner_exceptional",
            PointSelector::new("inner()")
                .procedure("exercise")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "outer_invoke",
            PointSelector::new("outer(inner())")
                .procedure("exercise")
                .effect("invoke"),
        )
        .bind(
            "outer_normal",
            PointSelector::new("outer(inner())")
                .procedure("exercise")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "outer_exceptional",
            PointSelector::new("outer(inner())")
                .procedure("exercise")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "after_invoke",
            PointSelector::new("after()")
                .procedure("exercise")
                .effect("invoke"),
        )
        .bind(
            "exceptional_exit",
            PointSelector::new("function exercise")
                .procedure("exercise")
                .effect("exceptional_exit"),
        );

    graph.assert_successors(
        "inner_invoke",
        &[
            expected_edge("inner_normal", ControlEdgeKind::Normal),
            expected_edge("inner_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_successors(
        "outer_invoke",
        &[
            expected_edge("outer_normal", ControlEdgeKind::Normal),
            expected_edge("outer_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_reachable("inner_normal", "outer_invoke");
    graph.assert_reachable("outer_normal", "after_invoke");
    graph.assert_reachable("inner_exceptional", "exceptional_exit");
    graph.assert_reachable("outer_exceptional", "exceptional_exit");
    graph.assert_adjacency_symmetric();
}

#[test]
fn typescript_throw_catch_and_finally_override_completion() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/cleanup.ts",
            r#"
                declare function make(): Error;
                declare function handled(): void;
                declare function cleanup(): void;

                function caught(): void {
                    try {
                        throw make();
                    } catch (error) {
                        handled();
                    } finally {
                        cleanup();
                    }
                }

                function returnOverridesThrow(): number {
                    try {
                        throw make();
                    } finally {
                        return 7;
                    }
                }

                function throwOverridesReturn(): number {
                    try {
                        return 1;
                    } finally {
                        throw make();
                    }
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/cleanup.ts");

    graph
        .bind(
            "caught_throw",
            PointSelector::new("throw make();")
                .occurrence(0)
                .procedure("caught")
                .effect("throw"),
        )
        .bind(
            "handled",
            PointSelector::new("handled()")
                .procedure("caught")
                .effect("invoke"),
        )
        .bind(
            "caught_cleanup",
            PointSelector::new("cleanup()")
                .procedure("caught")
                .effect("invoke")
                .anchor_occurrence(0),
        )
        .bind(
            "override_throw",
            PointSelector::new("throw make();")
                .occurrence(1)
                .procedure("returnOverridesThrow")
                .effect("throw"),
        )
        .bind(
            "finally_return",
            PointSelector::new("return 7;")
                .procedure("returnOverridesThrow")
                .effect("procedure_return")
                .anchor_occurrence(1),
        )
        .bind(
            "return_override_normal",
            PointSelector::new("function returnOverridesThrow")
                .procedure("returnOverridesThrow")
                .effect("normal_exit"),
        )
        .bind(
            "return_override_exceptional",
            PointSelector::new("function returnOverridesThrow")
                .procedure("returnOverridesThrow")
                .effect("exceptional_exit"),
        )
        .bind(
            "overridden_return",
            PointSelector::new("return 1;")
                .procedure("throwOverridesReturn")
                .effect("procedure_return"),
        )
        .bind(
            "finally_throw",
            PointSelector::new("throw make();")
                .occurrence(2)
                .procedure("throwOverridesReturn")
                .effect("throw")
                .anchor_occurrence(1),
        )
        .bind(
            "throw_override_normal",
            PointSelector::new("function throwOverridesReturn")
                .procedure("throwOverridesReturn")
                .effect("normal_exit"),
        )
        .bind(
            "throw_override_exceptional",
            PointSelector::new("function throwOverridesReturn")
                .procedure("throwOverridesReturn")
                .effect("exceptional_exit"),
        );

    graph.assert_reachable("caught_throw", "handled");
    graph.assert_reachable("handled", "caught_cleanup");
    graph.assert_reachable("override_throw", "finally_return");
    graph.assert_reachable("finally_return", "return_override_normal");
    graph.assert_unreachable("finally_return", "return_override_exceptional");
    graph.assert_reachable("overridden_return", "finally_throw");
    graph.assert_reachable("finally_throw", "throw_override_exceptional");
    graph.assert_unreachable("finally_throw", "throw_override_normal");
    graph.assert_adjacency_symmetric();
}

#[test]
fn typescript_short_circuit_optional_call_and_switch_predicate_keep_branches() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/expressions.ts",
            r#"
                declare function left(): boolean;
                declare function right(): boolean;
                declare function predicate(): number;
                declare function after(): void;

                function expressions(callback?: () => void, value: number = 0): void {
                    left() && right();
                    callback?.();
                    switch (value) {
                        case predicate():
                            after();
                            break;
                        default:
                            break;
                    }
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/expressions.ts");

    graph
        .bind(
            "left_decision",
            PointSelector::new("left()")
                .procedure("expressions")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "right_invoke",
            PointSelector::new("right()")
                .procedure("expressions")
                .effect("invoke"),
        )
        .bind(
            "right_entry",
            PointSelector::new("right()")
                .procedure("expressions")
                .anchor_occurrence(0),
        )
        .bind(
            "optional_statement",
            PointSelector::new("callback?.();")
                .procedure("expressions")
                .anchor_occurrence(0),
        )
        .bind(
            "optional_decision",
            PointSelector::new("callback?.()")
                .procedure("expressions")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "optional_invoke",
            PointSelector::new("callback?.()")
                .procedure("expressions")
                .effect("invoke"),
        )
        .bind(
            "predicate_invoke",
            PointSelector::new("predicate()")
                .procedure("expressions")
                .effect("invoke"),
        )
        .bind(
            "predicate_normal",
            PointSelector::new("predicate()")
                .procedure("expressions")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "switch_entry",
            PointSelector::new(
                r#"switch (value) {
                        case predicate():
                            after();
                            break;
                        default:
                            break;
                    }"#,
            )
            .procedure("expressions")
            .anchor_occurrence(0),
        )
        .bind(
            "case_decision",
            PointSelector::new("case predicate()")
                .procedure("expressions")
                .outgoing_kind(ControlEdgeKind::SwitchCase),
        )
        .bind(
            "after_invoke",
            PointSelector::new("after()")
                .procedure("expressions")
                .effect("invoke"),
        );

    graph.assert_successors(
        "left_decision",
        &[
            expected_edge("right_entry", ControlEdgeKind::ConditionalTrue),
            expected_edge("optional_statement", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_successors(
        "optional_decision",
        &[
            expected_edge("optional_invoke", ControlEdgeKind::ConditionalTrue),
            expected_edge("switch_entry", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_reachable("right_entry", "right_invoke");
    graph.assert_unreachable("optional_statement", "right_invoke");
    graph.assert_unreachable("switch_entry", "optional_invoke");
    graph.assert_reachable("predicate_invoke", "after_invoke");
    graph.assert_reachable("predicate_normal", "case_decision");
    graph.assert_adjacency_symmetric();
}

#[test]
fn typescript_and_tsx_enumerate_methods_constructors_lambdas_and_stable_topology() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/component.tsx",
            r#"
                declare function consume(value: unknown): void;

                class Widget {
                    constructor(private value: number) {}

                    render(): void {
                        const local = () => this.value;
                        consume(local());
                    }
                }

                function build(): Widget {
                    const widget = new Widget(2);
                    widget.render();
                    return widget;
                }

                export const Component = () => consume(<Widget value={1} />);
            "#,
        )
        .build();
    let first_analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let second_analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut first = SemanticGraph::materialize(&project, &first_analyzer, "src/component.tsx");
    let mut second = SemanticGraph::materialize(&project, &second_analyzer, "src/component.tsx");
    for graph in [&mut first, &mut second] {
        graph
            .bind(
                "component_entry",
                PointSelector::new("() => consume(<Widget value={1} />)")
                    .procedure("Component")
                    .effect("entry"),
            )
            .bind(
                "component_consume",
                PointSelector::new("consume(<Widget value={1} />)")
                    .procedure("Component")
                    .effect("invoke"),
            )
            .bind(
                "constructor_invoke",
                PointSelector::new("new Widget(2)")
                    .procedure("build")
                    .effect("invoke"),
            )
            .bind(
                "constructor_normal",
                PointSelector::new("new Widget(2)")
                    .procedure("build")
                    .effect("call_continuation")
                    .outgoing_kind(ControlEdgeKind::Normal),
            )
            .bind(
                "method_invoke",
                PointSelector::new("widget.render()")
                    .procedure("build")
                    .effect("invoke"),
            );
        graph.assert_reachable("component_entry", "component_consume");
        graph.assert_reachable("constructor_normal", "method_invoke");
        graph.assert_adjacency_symmetric();
    }

    let artifact = first.artifact();
    assert!(
        artifact
            .procedures()
            .iter()
            .any(|procedure| procedure.kind() == ProcedureKind::Constructor)
    );
    assert!(
        artifact
            .procedures()
            .iter()
            .any(|procedure| procedure.kind() == ProcedureKind::Method)
    );
    assert!(
        artifact
            .procedures()
            .iter()
            .filter(|procedure| procedure.kind() == ProcedureKind::Lambda)
            .count()
            >= 2
    );
    assert_eq!(first.render_topology(), second.render_topology());
}

#[test]
fn bare_calls_shadowed_by_parameters_are_not_claimed_as_proven_targets() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/shadow.ts",
            r#"
                function target(): void {}

                function shadowed(target: () => void): void {
                    target();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "src/shadow.ts");
    let shadowed = graph
        .artifact()
        .procedures()
        .iter()
        .find(|procedure| {
            procedure
                .locator()
                .declaration()
                .segments()
                .last()
                .and_then(|segment| segment.name())
                == Some("shadowed")
        })
        .expect("shadowed procedure should be materialized");
    assert_eq!(shadowed.call_sites().len(), 1);
    assert!(!matches!(
        shadowed.call_sites()[0].declared_targets,
        CallableTargetResolution::Proven(_)
    ));
}

#[test]
fn qualified_new_expression_remains_a_constructor_reference() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/qualified_new.ts",
            r#"
                declare const namespace: { Widget: new () => object };
                function build(): object {
                    return new namespace.Widget();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "src/qualified_new.ts");
    let build = graph
        .artifact()
        .procedures()
        .iter()
        .find(|procedure| {
            procedure
                .locator()
                .declaration()
                .segments()
                .last()
                .and_then(|segment| segment.name())
                == Some("build")
        })
        .expect("build procedure should exist");
    assert!(
        build
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .any(|event| matches!(
                &event.effect,
                SemanticEffect::CallableReference { callable, .. }
                    if callable.kind == CallableReferenceKind::Constructor
                        && callable.bound_receiver.is_none()
            ))
    );
}

#[test]
fn topology_renderer_is_golden_deterministic_bounded_and_diagnostic() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/golden.ts",
            r#"function halt(): void { return; }
"#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/golden.ts");
    graph
        .bind(
            "entry",
            PointSelector::new("function halt")
                .procedure("halt")
                .effect("entry"),
        )
        .bind(
            "return",
            PointSelector::new("return;")
                .procedure("halt")
                .effect("procedure_return"),
        );

    graph.assert_topology(
        r#"
procedure src/golden.ts::function:halt kind=function
  entry@L1:1-L1:34#0 aliases=entry `function halt(): void { return; }`
    -> normal point@L1:23-L1:34#0 source=L1:1-L1:34
  exceptional_exit@L1:1-L1:34#0 `function halt(): void { return; }`
  normal_exit@L1:1-L1:34#0 `function halt(): void { return; }`
  point@L1:23-L1:34#0 `{ return; }`
    -> normal procedure_return@L1:25-L1:32#0 source=L1:23-L1:34
  procedure_return@L1:25-L1:32#0 aliases=return `return;`
    -> normal normal_exit@L1:1-L1:34#0 source=L1:25-L1:32
"#,
    );

    let bounded = graph.render_topology_with_limits(TopologyRenderLimits {
        max_procedures: 1,
        max_points: 1,
        max_edges: 1,
        max_output_bytes: 4_096,
    });
    assert!(bounded.contains("truncated: point limit reached"));
    assert!(!bounded.contains("ProgramPointId"));

    let missing = graph
        .try_bind("missing", PointSelector::new("function halt"))
        .expect_err("a source match without a selectable point should produce a diagnostic");
    let diagnostic = missing.to_string();
    assert!(diagnostic.contains("bounded topology context:"));
    assert!(diagnostic.len() < 64 * 1024);
}

#[test]
fn typescript_class_static_blocks_are_deferred_initializer_procedures() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/static.ts",
            r#"
                declare function initialize(): void;
                class Registry {
                    static {
                        initialize();
                    }
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/static.ts");
    graph
        .bind(
            "static_entry",
            PointSelector::new(
                r#"static {
                        initialize();
                    }"#,
            )
            .effect("entry"),
        )
        .bind(
            "static_invoke",
            PointSelector::new("initialize()")
                .occurrence(1)
                .effect("invoke"),
        );

    let initializer = graph
        .artifact()
        .procedures()
        .iter()
        .find(|procedure| procedure.kind() == ProcedureKind::Initializer)
        .expect("class static block should materialize as an initializer procedure");
    assert!(initializer.properties().is_static);
    assert!(initializer.gaps().iter().any(|gap| {
        gap.subject == SemanticGapSubject::Procedure
            && gap.capability == SemanticCapability::DeferredExecution
            && gap.kind == SemanticGapKind::Unsupported
            && gap.detail.contains("class static block scheduling")
    }));
    graph.assert_reachable("static_entry", "static_invoke");
    graph.assert_adjacency_symmetric();
}

#[test]
fn typescript_compound_abrupt_tails_and_dead_control_stay_disconnected() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/dead_compound.ts",
            r#"
                declare function never(): void;
                declare function after(): void;

                function compound(flag: boolean): void {
                    if (flag) {
                        return;
                    } else {
                        throw flag;
                    }
                    never();
                }

                function tryDead(): void {
                    try {
                        return;
                    } finally {
                    }
                    never();
                }

                function deadControl(flag: boolean): void {
                    while (flag) {
                        return;
                        continue;
                    }
                    while (flag) {
                        throw flag;
                        break;
                    }
                    after();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/dead_compound.ts");
    graph
        .bind(
            "compound_entry",
            PointSelector::new("function compound")
                .procedure("compound")
                .effect("entry"),
        )
        .bind(
            "compound_if",
            PointSelector::new("if (flag)")
                .procedure("compound")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "never_invoke",
            PointSelector::new("never()")
                .occurrence(1)
                .procedure("compound")
                .effect("invoke"),
        )
        .bind(
            "first_loop_test",
            PointSelector::new("flag")
                .occurrence(4)
                .procedure("deadControl")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "try_dead_entry",
            PointSelector::new("function tryDead")
                .procedure("tryDead")
                .effect("entry"),
        )
        .bind(
            "try_dead_invoke",
            PointSelector::new("never()")
                .occurrence(2)
                .procedure("tryDead")
                .effect("invoke"),
        )
        .bind(
            "try_dead_normal",
            PointSelector::new("function tryDead")
                .procedure("tryDead")
                .effect("normal_exit"),
        )
        .bind(
            "try_dead_exceptional",
            PointSelector::new("function tryDead")
                .procedure("tryDead")
                .effect("exceptional_exit"),
        )
        .bind(
            "dead_continue",
            PointSelector::new("continue;")
                .procedure("deadControl")
                .anchor_occurrence(0),
        )
        .bind(
            "dead_break",
            PointSelector::new("break;")
                .procedure("deadControl")
                .anchor_occurrence(0),
        )
        .bind(
            "after_invoke",
            PointSelector::new("after()")
                .occurrence(1)
                .procedure("deadControl")
                .effect("invoke"),
        );

    graph.assert_reachable("compound_entry", "compound_if");
    graph.assert_unreachable("compound_entry", "never_invoke");
    graph.assert_unreachable("try_dead_entry", "try_dead_invoke");
    graph.assert_unreachable("try_dead_invoke", "try_dead_normal");
    graph.assert_unreachable("try_dead_invoke", "try_dead_exceptional");
    graph.assert_unreachable("dead_continue", "first_loop_test");
    graph.assert_unreachable("dead_break", "after_invoke");
    graph.assert_adjacency_symmetric();
}

#[test]
fn typescript_unreachable_seal_isolates_switch_and_loop_dead_tails() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/dead_constructs.ts",
            r#"
                declare function neverSwitch(): void;
                declare function neverFor(): void;
                declare function neverDo(): void;
                declare function spin(): void;

                function switchDead(value: number): void {
                    switch (value) {
                        case 0:
                            return;
                        default:
                            throw value;
                    }
                    neverSwitch();
                }

                function forDead(): void {
                    for (;;) {
                        spin();
                    }
                    neverFor();
                }

                function doDead(flag: boolean): void {
                    do {
                        return;
                    } while (flag);
                    neverDo();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/dead_constructs.ts");

    for (prefix, procedure, call) in [
        ("switch", "switchDead", "neverSwitch()"),
        ("for", "forDead", "neverFor()"),
        ("do", "doDead", "neverDo()"),
    ] {
        graph
            .bind(
                format!("{prefix}_entry"),
                PointSelector::new(format!("function {procedure}"))
                    .procedure(procedure)
                    .effect("entry"),
            )
            .bind(
                format!("{prefix}_dead"),
                PointSelector::new(call)
                    .occurrence(1)
                    .procedure(procedure)
                    .effect("invoke"),
            )
            .bind(
                format!("{prefix}_normal"),
                PointSelector::new(format!("function {procedure}"))
                    .procedure(procedure)
                    .effect("normal_exit"),
            )
            .bind(
                format!("{prefix}_exceptional"),
                PointSelector::new(format!("function {procedure}"))
                    .procedure(procedure)
                    .effect("exceptional_exit"),
            );
        graph.assert_unreachable(&format!("{prefix}_entry"), &format!("{prefix}_dead"));
        graph.assert_unreachable(&format!("{prefix}_dead"), &format!("{prefix}_normal"));
        graph.assert_unreachable(&format!("{prefix}_dead"), &format!("{prefix}_exceptional"));
    }
    graph.assert_adjacency_symmetric();
}

#[test]
fn typescript_optional_chains_skip_continuous_suffixes_but_not_parenthesized_suffixes() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/optional.ts",
            r#"
                declare function key(): string;
                declare function argument(): number;
                declare function tail(): number;
                declare function afterStandalone(): void;
                declare function afterNested(): void;

                function optional(obj?: any): void {
                    obj?.[key()];
                    afterStandalone();
                    obj?.method(argument()).other(tail());
                    afterNested();
                    (obj?.method()).other();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/optional.ts");
    graph
        .bind(
            "standalone_decision",
            PointSelector::new("obj?.[key()]")
                .procedure("optional")
                .outgoing_kind(ControlEdgeKind::ConditionalFalse),
        )
        .bind(
            "key_entry",
            PointSelector::new("key()")
                .occurrence(1)
                .procedure("optional")
                .anchor_occurrence(0),
        )
        .bind(
            "key_invoke",
            PointSelector::new("key()")
                .occurrence(1)
                .procedure("optional")
                .effect("invoke"),
        )
        .bind(
            "after_standalone_statement",
            PointSelector::new("afterStandalone();")
                .procedure("optional")
                .anchor_occurrence(0),
        )
        .bind(
            "after_standalone",
            PointSelector::new("afterStandalone()")
                .occurrence(1)
                .procedure("optional")
                .effect("invoke"),
        )
        .bind(
            "nested_decision",
            PointSelector::new("obj?.method")
                .occurrence(0)
                .procedure("optional")
                .outgoing_kind(ControlEdgeKind::ConditionalFalse),
        )
        .bind(
            "nested_access",
            PointSelector::new("obj?.method")
                .occurrence(0)
                .procedure("optional")
                .effect("gap"),
        )
        .bind(
            "argument_invoke",
            PointSelector::new("argument()")
                .occurrence(1)
                .procedure("optional")
                .effect("invoke"),
        )
        .bind(
            "tail_invoke",
            PointSelector::new("tail()")
                .occurrence(1)
                .procedure("optional")
                .effect("invoke"),
        )
        .bind(
            "after_nested_statement",
            PointSelector::new("afterNested();")
                .procedure("optional")
                .anchor_occurrence(0),
        )
        .bind(
            "after_nested",
            PointSelector::new("afterNested()")
                .occurrence(1)
                .procedure("optional")
                .effect("invoke"),
        )
        .bind(
            "parenthesized_decision",
            PointSelector::new("obj?.method")
                .occurrence(1)
                .procedure("optional")
                .outgoing_kind(ControlEdgeKind::ConditionalFalse),
        )
        .bind(
            "parenthesized_inner_access",
            PointSelector::new("obj?.method")
                .occurrence(1)
                .procedure("optional")
                .effect("gap"),
        )
        .bind(
            "parenthesized_access",
            PointSelector::new("(obj?.method()).other")
                .procedure("optional")
                .effect("gap"),
        )
        .bind(
            "parenthesized_outer_invoke",
            PointSelector::new("(obj?.method()).other()")
                .procedure("optional")
                .effect("invoke"),
        );

    graph.assert_successors(
        "standalone_decision",
        &[
            expected_edge("key_entry", ControlEdgeKind::ConditionalTrue),
            expected_edge(
                "after_standalone_statement",
                ControlEdgeKind::ConditionalFalse,
            ),
        ],
    );
    graph.assert_successors(
        "nested_decision",
        &[
            expected_edge("nested_access", ControlEdgeKind::ConditionalTrue),
            expected_edge("after_nested_statement", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_reachable("nested_decision", "tail_invoke");
    graph.assert_successors(
        "parenthesized_decision",
        &[
            expected_edge(
                "parenthesized_inner_access",
                ControlEdgeKind::ConditionalTrue,
            ),
            expected_edge("parenthesized_access", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_reachable("parenthesized_access", "parenthesized_outer_invoke");
    graph.assert_adjacency_symmetric();
}

#[test]
fn typescript_for_of_evaluates_rhs_once_and_left_target_per_iteration() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/for_of.ts",
            r#"
                declare function source(): number[];
                declare function key(): string;
                declare function body(): void;
                declare function after(): void;

                function iterate(target: any): void {
                    for (target[key()] of source()) {
                        body();
                    }
                    after();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/for_of.ts");
    graph
        .bind(
            "source_invoke",
            PointSelector::new("source()")
                .occurrence(1)
                .procedure("iterate")
                .effect("invoke"),
        )
        .bind(
            "source_normal",
            PointSelector::new("source()")
                .occurrence(1)
                .procedure("iterate")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "loop_test",
            PointSelector::new("for (target[key()] of source())")
                .procedure("iterate")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "key_invoke",
            PointSelector::new("key()")
                .occurrence(1)
                .procedure("iterate")
                .effect("invoke"),
        )
        .bind(
            "body_invoke",
            PointSelector::new("body()")
                .occurrence(1)
                .procedure("iterate")
                .effect("invoke"),
        )
        .bind(
            "after_invoke",
            PointSelector::new("after()")
                .occurrence(1)
                .procedure("iterate")
                .effect("invoke"),
        );

    graph.assert_reachable("source_invoke", "loop_test");
    graph.assert_reachable("loop_test", "key_invoke");
    graph.assert_reachable("key_invoke", "body_invoke");
    graph.assert_reachable("body_invoke", "loop_test");
    graph.assert_unreachable("body_invoke", "source_invoke");
    graph.assert_reachable("loop_test", "after_invoke");
    graph.assert_adjacency_symmetric();
}

#[test]
fn typescript_for_in_initializer_and_destructuring_gaps_are_point_scoped() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/for_gaps.ts",
            r#"
                declare function initial(): string;
                declare function source(): any;
                declare function fallback(): number;
                declare function use(value: number): void;

                function legacy(): void {
                    for (var key = initial() in source()) {
                        use(0);
                    }
                }

                function pattern(): void {
                    for (const { value = fallback() } of source()) {
                        use(value);
                    }
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/for_gaps.ts");
    graph
        .bind(
            "legacy_gap",
            PointSelector::new("for (var key = initial() in source())")
                .procedure("legacy")
                .effect("gap"),
        )
        .bind(
            "pattern_gap",
            PointSelector::new("{ value = fallback() }")
                .procedure("pattern")
                .effect("gap"),
        )
        .bind(
            "pattern_body",
            PointSelector::new("use(value)")
                .procedure("pattern")
                .effect("invoke"),
        );

    graph.assert_successors("legacy_gap", &[]);
    graph.assert_successors("pattern_gap", &[]);
    graph.assert_unreachable("pattern_gap", "pattern_body");
    assert!(graph.artifact().procedures().iter().any(|procedure| {
        procedure.gaps().iter().any(|gap| {
            gap.capability == SemanticCapability::NormalControlFlow
                && gap.kind == SemanticGapKind::Unsupported
                && gap.detail.contains("legacy for-in binding initializers")
        })
    }));
    graph.assert_adjacency_symmetric();
}

#[test]
fn typescript_for_await_yield_and_unknown_control_stop_at_typed_boundaries() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/boundaries.ts",
            r#"
                declare function source(): AsyncIterable<number>;
                declare function use(value: number): void;
                declare function after(): void;
                declare function produce(): number;

                async function iterate(): Promise<void> {
                    for await (const value of source()) {
                        use(value);
                    }
                    after();
                }

                function* values(): Generator<number> {
                    yield produce();
                    after();
                }

                function unknownControl(): void {
                    class Local {}
                    after();
                }

                function logical(value: boolean): void {
                    value &&= produce() > 0;
                    after();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/boundaries.ts");
    graph
        .bind(
            "for_await_gap",
            PointSelector::new("for await (const value of source())")
                .procedure("iterate")
                .effect("gap")
                .anchor_occurrence(1),
        )
        .bind(
            "for_await_use",
            PointSelector::new("use(value)")
                .procedure("iterate")
                .effect("invoke"),
        )
        .bind(
            "iterate_after",
            PointSelector::new("after()")
                .occurrence(1)
                .procedure("iterate")
                .effect("invoke"),
        )
        .bind(
            "yield_gap",
            PointSelector::new("yield produce()")
                .procedure("values")
                .effect("gap"),
        )
        .bind(
            "values_after",
            PointSelector::new("after()")
                .occurrence(2)
                .procedure("values")
                .effect("invoke"),
        )
        .bind(
            "unknown_gap",
            PointSelector::new("class Local {}")
                .procedure("unknownControl")
                .effect("gap"),
        )
        .bind(
            "unknown_after",
            PointSelector::new("after()")
                .occurrence(3)
                .procedure("unknownControl")
                .effect("invoke"),
        )
        .bind(
            "logical_gap",
            PointSelector::new("value &&= produce() > 0;")
                .procedure("logical")
                .effect("gap"),
        )
        .bind(
            "logical_after",
            PointSelector::new("after()")
                .occurrence(4)
                .procedure("logical")
                .effect("invoke"),
        );

    for terminal in ["for_await_gap", "yield_gap", "unknown_gap", "logical_gap"] {
        graph.assert_successors(terminal, &[]);
    }
    graph.assert_unreachable("for_await_gap", "for_await_use");
    graph.assert_unreachable("for_await_gap", "iterate_after");
    graph.assert_unreachable("yield_gap", "values_after");
    graph.assert_unreachable("unknown_gap", "unknown_after");
    graph.assert_unreachable("logical_gap", "logical_after");

    let capabilities = [
        SemanticCapability::AsyncSuspendResume,
        SemanticCapability::GeneratorSuspension,
        SemanticCapability::NormalControlFlow,
    ];
    for capability in capabilities {
        assert!(graph.artifact().procedures().iter().any(|procedure| {
            procedure
                .gaps()
                .iter()
                .any(|gap| gap.capability == capability && gap.kind == SemanticGapKind::Unsupported)
        }));
    }
    graph.assert_adjacency_symmetric();
}

#[test]
fn typescript_implicit_throw_operations_emit_exact_exception_gaps() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/implicit_throw.ts",
            r#"
                declare function after(): void;
                function access(value: any): void {
                    value.property;
                    after();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/implicit_throw.ts");
    graph
        .bind(
            "access_gap",
            PointSelector::new("value.property")
                .procedure("access")
                .effect("gap"),
        )
        .bind(
            "after_invoke",
            PointSelector::new("after()")
                .occurrence(1)
                .procedure("access")
                .effect("invoke"),
        );

    let procedure = graph
        .artifact()
        .procedures()
        .iter()
        .find(|procedure| {
            procedure
                .locator()
                .declaration()
                .segments()
                .last()
                .and_then(|segment| segment.name())
                == Some("access")
        })
        .expect("access procedure should exist");
    assert!(procedure.gaps().iter().any(|gap| {
        gap.capability == SemanticCapability::ExceptionalControlFlow
            && gap.kind == SemanticGapKind::Unsupported
            && gap.detail.contains("property access")
    }));
    graph.assert_reachable("access_gap", "after_invoke");
    graph.assert_adjacency_symmetric();
}

#[test]
fn typescript_using_initializers_run_before_terminal_cleanup_gaps() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/resources.ts",
            r#"
                declare function acquire(): Disposable;
                declare function acquireAsync(): AsyncDisposable;
                declare function after(): void;

                function resource(): void {
                    using handle = acquire();
                    after();
                }

                async function asyncResource(): Promise<void> {
                    await using handle = acquireAsync();
                    after();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/resources.ts");
    graph
        .bind(
            "resource_entry",
            PointSelector::new("function resource")
                .procedure("resource")
                .effect("entry"),
        )
        .bind(
            "acquire_invoke",
            PointSelector::new("acquire()")
                .occurrence(1)
                .procedure("resource")
                .effect("invoke"),
        )
        .bind(
            "using_gap",
            PointSelector::new("using handle = acquire()")
                .occurrence(0)
                .procedure("resource")
                .effect("gap"),
        )
        .bind(
            "resource_after",
            PointSelector::new("after()")
                .occurrence(1)
                .procedure("resource")
                .effect("invoke"),
        )
        .bind(
            "async_acquire_invoke",
            PointSelector::new("acquireAsync()")
                .occurrence(1)
                .procedure("asyncResource")
                .effect("invoke"),
        )
        .bind(
            "await_using_gap",
            PointSelector::new("using handle = acquireAsync()")
                .procedure("asyncResource")
                .effect("gap"),
        )
        .bind(
            "async_after",
            PointSelector::new("after()")
                .occurrence(2)
                .procedure("asyncResource")
                .effect("invoke"),
        );

    graph.assert_reachable("resource_entry", "acquire_invoke");
    graph.assert_reachable("acquire_invoke", "using_gap");
    graph.assert_successors("using_gap", &[]);
    graph.assert_unreachable("using_gap", "resource_after");
    graph.assert_reachable("async_acquire_invoke", "await_using_gap");
    graph.assert_successors("await_using_gap", &[]);
    graph.assert_unreachable("await_using_gap", "async_after");

    let async_resource = graph
        .artifact()
        .procedures()
        .iter()
        .find(|procedure| {
            procedure
                .locator()
                .declaration()
                .segments()
                .last()
                .and_then(|segment| segment.name())
                == Some("asyncResource")
        })
        .expect("async resource procedure should exist");
    assert!(async_resource.gaps().iter().any(|gap| {
        gap.capability == SemanticCapability::ResourceManagement
            && gap.detail.contains("using declaration disposal")
    }));
    assert!(async_resource.gaps().iter().any(|gap| {
        gap.capability == SemanticCapability::AsyncSuspendResume
            && gap.detail.contains("await-using asynchronous disposal")
    }));
    graph.assert_adjacency_symmetric();
}

#[test]
fn typescript_matching_labeled_break_completes_normally() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/labeled_block.ts",
            r#"
                declare function after(): void;
                function labeledBlock(): void {
                    outer: {
                        break outer;
                    }
                    after();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/labeled_block.ts");
    graph
        .bind(
            "break_outer",
            PointSelector::new("break outer;").procedure("labeledBlock"),
        )
        .bind(
            "after_statement",
            PointSelector::new("after();")
                .procedure("labeledBlock")
                .anchor_occurrence(0),
        )
        .bind(
            "after_invoke",
            PointSelector::new("after()")
                .occurrence(1)
                .procedure("labeledBlock")
                .effect("invoke"),
        )
        .bind(
            "normal_exit",
            PointSelector::new("function labeledBlock")
                .procedure("labeledBlock")
                .effect("normal_exit"),
        );

    graph.assert_successors(
        "break_outer",
        &[expected_edge("after_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("break_outer", "after_invoke");
    graph.assert_reachable("after_invoke", "normal_exit");
    graph.assert_adjacency_symmetric();
}

#[test]
fn typescript_enumeration_preflights_cumulative_and_deep_identity_budgets() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/budget.ts",
            r#"
                namespace Outer {
                    namespace Inner {
                        export function first(): void {}
                        export function second(): void {}
                    }
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let file = project.file("src/budget.ts");
    let cancellation = CancellationToken::default();

    let mut procedure_limits = SemanticBudget::default().limits();
    procedure_limits.procedures = 1;
    let mut procedure_budget = SemanticBudget::new(procedure_limits).expect("positive limits");
    let outcome = analyzer
        .materialize_program_semantics(
            &file,
            &mut SemanticRequest::new(&mut procedure_budget, &cancellation),
        )
        .expect("procedure budget exhaustion is a semantic outcome");
    assert!(matches!(
        outcome,
        SemanticOutcome::ExceededBudget { exceeded, work, .. }
            if exceeded.dimension() == SemanticBudgetDimension::Procedures
                && work.procedures >= 2
    ));

    let mut nested_limits = SemanticBudget::default().limits();
    nested_limits.nested_entries = 8;
    let mut nested_budget = SemanticBudget::new(nested_limits).expect("positive limits");
    let outcome = analyzer
        .materialize_program_semantics(
            &file,
            &mut SemanticRequest::new(&mut nested_budget, &cancellation),
        )
        .expect("nested identity budget exhaustion is a semantic outcome");
    assert!(matches!(
        outcome,
        SemanticOutcome::ExceededBudget { exceeded, work, .. }
            if exceeded.dimension() == SemanticBudgetDimension::NestedEntries
                && work.nested_entries > 8
    ));
}

#[test]
fn typescript_adapter_lowers_deep_control_iteratively() {
    const DEPTH: usize = 1_024;
    let mut source = String::from(
        r#"
            declare function leaf(): void;
            function deep(flag: boolean): void {
        "#,
    );
    for _ in 0..DEPTH {
        source.push_str("if (flag) {");
    }
    source.push_str("leaf();");
    for _ in 0..DEPTH {
        source.push('}');
    }
    source.push('}');

    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("src/deep.ts", source)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/deep.ts");
    graph
        .bind(
            "deep_entry",
            PointSelector::new("function deep")
                .procedure("deep")
                .effect("entry"),
        )
        .bind(
            "leaf_invoke",
            PointSelector::new("leaf()")
                .occurrence(1)
                .procedure("deep")
                .effect("invoke"),
        );
    graph.assert_reachable("deep_entry", "leaf_invoke");
    graph.assert_adjacency_symmetric();
    assert!(
        graph.artifact().procedures()[0].points().len() > DEPTH,
        "real adapter fixture should retain every nested control point"
    );
}
