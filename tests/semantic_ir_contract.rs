mod common;

use brokk_bifrost::analyzer::semantic::*;
use brokk_bifrost::{Language, ProjectFile};

use common::InlineTestProject;

const SOURCE: SourceMappingId = SourceMappingId::new(0);
const EVIDENCE: EvidenceId = EvidenceId::new(0);
const BLOCK: BlockId = BlockId::new(0);
const ENTRY: ProgramPointId = ProgramPointId::new(0);
const BODY: ProgramPointId = ProgramPointId::new(1);
const NORMAL_EXIT: ProgramPointId = ProgramPointId::new(2);
const EXCEPTIONAL_EXIT: ProgramPointId = ProgramPointId::new(3);
const SECOND_CREATION: ProgramPointId = ProgramPointId::new(4);

struct FixtureSource {
    key: SemanticArtifactKey,
    mount: WorkspaceMountId,
    path: WorkspaceRelativePath,
    language: SemanticLanguage,
}

impl FixtureSource {
    fn from_file(file: &ProjectFile, language: SemanticLanguage) -> Self {
        let contents = file
            .read_to_string()
            .expect("fixture source should be readable");
        let mount = WorkspaceMountId::hash_bytes(b"semantic-ir-contract-mount");
        let path = WorkspaceRelativePath::try_from_path(file.rel_path())
            .expect("inline fixture path should be workspace-relative");
        let adapter_fingerprint = StableDigest::sha256(language.stable_label().as_bytes());
        let key = SemanticArtifactKey::new(
            mount,
            path.clone(),
            language,
            SourceRevision::Disk {
                content: ContentIdentity::hash_bytes(contents.as_bytes()),
            },
            AdapterSemanticsVersion::new("semantic-ir-contract", adapter_fingerprint)
                .expect("adapter name is non-empty"),
            SemanticIrVersion::hash_bytes(b"semantic-ir-v1"),
            ConfigurationFingerprint::hash_bytes(b"contract-test-configuration"),
            DependencyFingerprint::hash_bytes(b"contract-test-dependencies"),
        );
        Self {
            key,
            mount,
            path,
            language,
        }
    }

    fn procedure_locator(
        &self,
        segments: Vec<DeclarationSegment>,
        anchor: SourceAnchor,
    ) -> SemanticLocator {
        SemanticLocator::new(
            self.mount,
            self.path.clone(),
            self.language,
            DeclarationLocator::new(segments).expect("fixture locator should be non-empty"),
            SemanticRole::Procedure,
            anchor,
        )
    }
}

fn anchor(byte: u32, occurrence: u32) -> SourceAnchor {
    let position = SourcePosition::new(byte, 0, byte);
    SourceAnchor::new(
        SourceSpan::new(position, position).expect("zero-width source span should be valid"),
        occurrence,
    )
}

fn named_segment(kind: DeclarationSegmentKind, name: &str, byte: u32) -> DeclarationSegment {
    DeclarationSegment::named(kind, name, anchor(byte, 0), 0)
        .expect("fixture declaration name should be non-empty")
}

fn event(effect: SemanticEffect) -> SemanticEvent {
    SemanticEvent::new(effect, SOURCE, EVIDENCE)
}

fn base_procedure(
    id: ProcedureId,
    locator: SemanticLocator,
    kind: ProcedureKind,
    body_events: Vec<SemanticEvent>,
    connect_body_to_normal_exit: bool,
) -> ProcedureSemanticsParts {
    let mut parts = ProcedureSemanticsParts::new(id, locator.clone(), kind, SOURCE, EVIDENCE);
    parts.source_mappings.push(SourceMapping {
        id: SOURCE,
        locator,
        kind: SourceMappingKind::Exact,
    });
    parts.evidence_rows.push(Evidence {
        id: EVIDENCE,
        proof: ProofStatus::Proven,
        completeness: EvidenceCompleteness::Complete,
        sources: Box::new([SOURCE]),
    });
    parts.blocks.push(BasicBlock {
        id: BLOCK,
        points: Box::new([ENTRY, BODY, NORMAL_EXIT, EXCEPTIONAL_EXIT]),
        source: SOURCE,
        evidence: EVIDENCE,
    });
    parts.points.extend([
        ProgramPoint {
            id: ENTRY,
            block: BLOCK,
            events: Box::new([event(SemanticEffect::Entry)]),
            source: SOURCE,
            evidence: EVIDENCE,
        },
        ProgramPoint {
            id: BODY,
            block: BLOCK,
            events: body_events.into_boxed_slice(),
            source: SOURCE,
            evidence: EVIDENCE,
        },
        ProgramPoint {
            id: NORMAL_EXIT,
            block: BLOCK,
            events: Box::new([event(SemanticEffect::NormalExit)]),
            source: SOURCE,
            evidence: EVIDENCE,
        },
        ProgramPoint {
            id: EXCEPTIONAL_EXIT,
            block: BLOCK,
            events: Box::new([event(SemanticEffect::ExceptionalExit)]),
            source: SOURCE,
            evidence: EVIDENCE,
        },
    ]);
    parts.control_edges.push(ControlEdge {
        source_point: ENTRY,
        target_point: BODY,
        kind: ControlEdgeKind::Normal,
        source: SOURCE,
        evidence: EVIDENCE,
    });
    if connect_body_to_normal_exit {
        parts.control_edges.push(ControlEdge {
            source_point: BODY,
            target_point: NORMAL_EXIT,
            kind: ControlEdgeKind::Normal,
            source: SOURCE,
            evidence: EVIDENCE,
        });
    }
    parts
}

fn capabilities() -> SemanticCapabilities {
    SemanticCapabilities::builder()
        .complete(SemanticCapability::Procedures)
        .complete(SemanticCapability::EntryBoundary)
        .complete(SemanticCapability::NormalExitBoundary)
        .complete(SemanticCapability::ExceptionalExitBoundary)
        .complete(SemanticCapability::BasicBlocks)
        .complete(SemanticCapability::ProgramPoints)
        .complete(SemanticCapability::NormalControlFlow)
        .complete(SemanticCapability::Assignments)
        .complete(SemanticCapability::Values)
        .complete(SemanticCapability::ReturnFlow)
        .complete(SemanticCapability::Allocations)
        .complete(SemanticCapability::LocalFlow)
        .complete(SemanticCapability::Captures)
        .complete(SemanticCapability::CallableReferences)
        .partial(SemanticCapability::Calls)
        .build()
}

fn build_artifact(
    source: &FixtureSource,
    procedures: Vec<ProcedureSemanticsParts>,
) -> SemanticArtifact {
    SemanticArtifact::try_new(source.key.clone(), capabilities(), procedures)
        .expect("manually constructed semantic artifact should satisfy the contract")
}

fn assignment_artifact(source: &FixtureSource, procedure_name: &str) -> SemanticArtifact {
    let locator = source.procedure_locator(
        vec![named_segment(
            DeclarationSegmentKind::Function,
            procedure_name,
            0,
        )],
        anchor(0, 0),
    );
    let mut procedure = base_procedure(
        ProcedureId::new(0),
        locator,
        ProcedureKind::Function,
        vec![
            event(SemanticEffect::Assignment {
                target: ValueId::new(1),
                value: ValueId::new(0),
            }),
            event(SemanticEffect::ProcedureReturn {
                value: Some(ValueId::new(1)),
            }),
        ],
        true,
    );
    procedure.values.extend([
        SemanticValue {
            id: ValueId::new(0),
            kind: SemanticValueKind::Parameter { ordinal: 0 },
            source: SOURCE,
            evidence: EVIDENCE,
        },
        SemanticValue {
            id: ValueId::new(1),
            kind: SemanticValueKind::Local,
            source: SOURCE,
            evidence: EVIDENCE,
        },
    ]);
    build_artifact(source, vec![procedure])
}

#[test]
fn typescript_and_java_share_the_same_neutral_effects() {
    let project = InlineTestProject::new()
        .file(
            "src/copy.ts",
            "export function copy(input: number) { const output = input; return output; }",
        )
        .file(
            "src/Copy.java",
            "class Copy { static int copy(int input) { int output = input; return output; } }",
        )
        .build();
    let typescript_source = FixtureSource::from_file(
        &project.file("src/copy.ts"),
        SemanticLanguage::Standard(Language::TypeScript),
    );
    let java_source = FixtureSource::from_file(
        &project.file("src/Copy.java"),
        SemanticLanguage::Standard(Language::Java),
    );
    let typescript = assignment_artifact(&typescript_source, "copy");
    let java = assignment_artifact(&java_source, "copy");

    let typescript_procedure = typescript.procedure(ProcedureId::new(0)).unwrap();
    let java_procedure = java.procedure(ProcedureId::new(0)).unwrap();
    let neutral_effects = |procedure: &ProcedureSemantics| {
        procedure
            .points()
            .iter()
            .flat_map(|point| point.events.iter())
            .map(|event| event.effect.clone())
            .collect::<Vec<_>>()
    };
    let neutral_edges = |procedure: &ProcedureSemantics| {
        procedure
            .control_edges()
            .iter()
            .map(|edge| (edge.source_point, edge.target_point, edge.kind))
            .collect::<Vec<_>>()
    };
    let neutral_values = |procedure: &ProcedureSemantics| {
        procedure
            .values()
            .iter()
            .map(|value| value.kind.clone())
            .collect::<Vec<_>>()
    };

    assert_ne!(typescript.key(), java.key());
    assert_eq!(
        neutral_effects(typescript_procedure),
        neutral_effects(java_procedure)
    );
    assert_eq!(
        neutral_edges(typescript_procedure),
        neutral_edges(java_procedure)
    );
    assert_eq!(
        neutral_values(typescript_procedure),
        neutral_values(java_procedure)
    );
    assert_eq!(
        typescript.key().mount(),
        typescript_procedure.locator().mount()
    );
    assert_eq!(
        typescript.procedure_id(typescript_procedure.locator()),
        Some(ProcedureId::new(0))
    );
}

#[test]
fn nested_lambda_is_a_separate_procedure_with_explicit_capture_binding() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/nested.ts",
            "export function outer(value: number) { return () => value; }",
        )
        .build();
    let source = FixtureSource::from_file(
        &project.file("src/nested.ts"),
        SemanticLanguage::Standard(Language::TypeScript),
    );
    let outer_segment = named_segment(DeclarationSegmentKind::Function, "outer", 0);
    let outer_locator = source.procedure_locator(vec![outer_segment.clone()], anchor(0, 0));
    let lambda_locator = source.procedure_locator(
        vec![
            outer_segment,
            DeclarationSegment::anonymous(DeclarationSegmentKind::Lambda, anchor(47, 0), 0),
        ],
        anchor(47, 0),
    );

    let callable = CallableValue {
        kind: CallableReferenceKind::Lambda,
        targets: CallableTargetResolution::Proven(CallableTarget::Local(ProcedureId::new(1))),
        target_evidence: EVIDENCE,
        bound_receiver: None,
        environment: Some(AllocationId::new(0)),
    };
    let mut outer = base_procedure(
        ProcedureId::new(0),
        outer_locator,
        ProcedureKind::Function,
        vec![
            event(SemanticEffect::Allocation {
                allocation: AllocationId::new(0),
            }),
            event(SemanticEffect::CallableCreation {
                result: ValueId::new(1),
                callable,
            }),
            event(SemanticEffect::CaptureBind {
                capture: CaptureId::new(0),
            }),
            event(SemanticEffect::CaptureBind {
                capture: CaptureId::new(1),
            }),
        ],
        false,
    );
    outer.values.extend([
        SemanticValue {
            id: ValueId::new(0),
            kind: SemanticValueKind::Parameter { ordinal: 0 },
            source: SOURCE,
            evidence: EVIDENCE,
        },
        SemanticValue {
            id: ValueId::new(1),
            kind: SemanticValueKind::Callable,
            source: SOURCE,
            evidence: EVIDENCE,
        },
        SemanticValue {
            id: ValueId::new(2),
            kind: SemanticValueKind::Temporary,
            source: SOURCE,
            evidence: EVIDENCE,
        },
        SemanticValue {
            id: ValueId::new(3),
            kind: SemanticValueKind::Callable,
            source: SOURCE,
            evidence: EVIDENCE,
        },
        SemanticValue {
            id: ValueId::new(4),
            kind: SemanticValueKind::Temporary,
            source: SOURCE,
            evidence: EVIDENCE,
        },
    ]);
    outer.allocations.extend([
        AllocationSite {
            id: AllocationId::new(0),
            point: BODY,
            result: ValueId::new(2),
            kind: AllocationKind::ClosureEnvironment,
            source: SOURCE,
            evidence: EVIDENCE,
        },
        AllocationSite {
            id: AllocationId::new(1),
            point: SECOND_CREATION,
            result: ValueId::new(4),
            kind: AllocationKind::ClosureEnvironment,
            source: SOURCE,
            evidence: EVIDENCE,
        },
    ]);
    outer.memory_locations.push(MemoryLocation {
        id: MemoryLocationId::new(0),
        kind: MemoryLocationKind::LexicalCell {
            binding: ValueId::new(0),
        },
        source: SOURCE,
        evidence: EVIDENCE,
    });
    outer.captures.extend([
        CaptureBinding {
            id: CaptureId::new(0),
            point: BODY,
            callable: ValueId::new(1),
            target: ProcedureId::new(1),
            environment: AllocationId::new(0),
            captured: CaptureSource::Value(ValueId::new(0)),
            destination: MemoryLocationId::new(0),
            mode: CaptureMode::Value,
            source: SOURCE,
            evidence: EVIDENCE,
        },
        CaptureBinding {
            id: CaptureId::new(1),
            point: BODY,
            callable: ValueId::new(1),
            target: ProcedureId::new(1),
            environment: AllocationId::new(0),
            captured: CaptureSource::Location(MemoryLocationId::new(0)),
            destination: MemoryLocationId::new(1),
            mode: CaptureMode::MutableCell,
            source: SOURCE,
            evidence: EVIDENCE,
        },
        CaptureBinding {
            id: CaptureId::new(2),
            point: SECOND_CREATION,
            callable: ValueId::new(3),
            target: ProcedureId::new(1),
            environment: AllocationId::new(1),
            captured: CaptureSource::Value(ValueId::new(0)),
            destination: MemoryLocationId::new(0),
            mode: CaptureMode::Value,
            source: SOURCE,
            evidence: EVIDENCE,
        },
    ]);
    outer.blocks[0].points =
        Box::new([ENTRY, BODY, NORMAL_EXIT, EXCEPTIONAL_EXIT, SECOND_CREATION]);
    outer.points.push(ProgramPoint {
        id: SECOND_CREATION,
        block: BLOCK,
        events: Box::new([
            event(SemanticEffect::Allocation {
                allocation: AllocationId::new(1),
            }),
            event(SemanticEffect::CallableCreation {
                result: ValueId::new(3),
                callable: CallableValue {
                    kind: CallableReferenceKind::Lambda,
                    targets: CallableTargetResolution::Proven(CallableTarget::Local(
                        ProcedureId::new(1),
                    )),
                    target_evidence: EVIDENCE,
                    bound_receiver: None,
                    environment: Some(AllocationId::new(1)),
                },
            }),
            event(SemanticEffect::CaptureBind {
                capture: CaptureId::new(2),
            }),
            event(SemanticEffect::ProcedureReturn {
                value: Some(ValueId::new(3)),
            }),
        ]),
        source: SOURCE,
        evidence: EVIDENCE,
    });
    outer.control_edges.extend([
        ControlEdge {
            source_point: BODY,
            target_point: SECOND_CREATION,
            kind: ControlEdgeKind::Normal,
            source: SOURCE,
            evidence: EVIDENCE,
        },
        ControlEdge {
            source_point: SECOND_CREATION,
            target_point: NORMAL_EXIT,
            kind: ControlEdgeKind::Normal,
            source: SOURCE,
            evidence: EVIDENCE,
        },
    ]);

    let mut lambda = base_procedure(
        ProcedureId::new(1),
        lambda_locator,
        ProcedureKind::Lambda,
        vec![event(SemanticEffect::ProcedureReturn { value: None })],
        true,
    );
    lambda.lexical_parent = Some(ProcedureId::new(0));
    lambda.memory_locations.extend([
        MemoryLocation {
            id: MemoryLocationId::new(0),
            kind: MemoryLocationKind::Capture {
                lexical_parent: ProcedureId::new(0),
            },
            source: SOURCE,
            evidence: EVIDENCE,
        },
        MemoryLocation {
            id: MemoryLocationId::new(1),
            kind: MemoryLocationKind::Capture {
                lexical_parent: ProcedureId::new(0),
            },
            source: SOURCE,
            evidence: EVIDENCE,
        },
    ]);

    let artifact = build_artifact(&source, vec![outer, lambda]);
    let outer = artifact.procedure(ProcedureId::new(0)).unwrap();
    let lambda = artifact.procedure(ProcedureId::new(1)).unwrap();

    assert_eq!(lambda.kind(), ProcedureKind::Lambda);
    assert_eq!(lambda.lexical_parent(), Some(ProcedureId::new(0)));
    assert_eq!(outer.captures().len(), 3);
    assert_eq!(outer.captures()[0].target, ProcedureId::new(1));
    assert_eq!(
        outer.captures()[1].captured,
        CaptureSource::Location(MemoryLocationId::new(0))
    );
    assert_eq!(outer.captures()[1].mode, CaptureMode::MutableCell);
    assert_ne!(outer.allocations()[0].result, outer.captures()[0].callable);
    assert_eq!(
        outer
            .captures()
            .iter()
            .filter(|capture| capture.destination == MemoryLocationId::new(0))
            .count(),
        2
    );
    assert_eq!(
        lambda.memory_locations()[0].kind,
        MemoryLocationKind::Capture {
            lexical_parent: ProcedureId::new(0),
        }
    );
    assert!(outer.call_sites().is_empty());
    assert!(
        outer
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .all(|event| { !matches!(event.effect, SemanticEffect::Invoke { .. }) })
    );
    assert!(outer.control_edges().iter().all(|edge| {
        outer.point(edge.source_point).is_some() && outer.point(edge.target_point).is_some()
    }));
}

#[test]
fn bound_and_unbound_method_references_are_not_invocations() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/References.java",
            "class References { java.util.function.Consumer<String> make() { return this::consume; } void consume(String value) {} }",
        )
        .build();
    let source = FixtureSource::from_file(
        &project.file("src/References.java"),
        SemanticLanguage::Standard(Language::Java),
    );
    let locator = source.procedure_locator(
        vec![named_segment(DeclarationSegmentKind::Method, "make", 0)],
        anchor(0, 0),
    );
    let target_locator = source.procedure_locator(
        vec![named_segment(DeclarationSegmentKind::Method, "consume", 91)],
        anchor(91, 0),
    );
    let local_target = CallableTargetResolution::Proven(CallableTarget::Local(ProcedureId::new(1)));
    let mut procedure = base_procedure(
        ProcedureId::new(0),
        locator,
        ProcedureKind::Method,
        vec![
            event(SemanticEffect::CallableReference {
                result: ValueId::new(1),
                callable: CallableValue {
                    kind: CallableReferenceKind::BoundMethod,
                    targets: local_target.clone(),
                    target_evidence: EVIDENCE,
                    bound_receiver: Some(ValueId::new(0)),
                    environment: None,
                },
            }),
            event(SemanticEffect::CallableReference {
                result: ValueId::new(2),
                callable: CallableValue {
                    kind: CallableReferenceKind::UnboundMethod,
                    targets: local_target,
                    target_evidence: EVIDENCE,
                    bound_receiver: None,
                    environment: None,
                },
            }),
            event(SemanticEffect::ProcedureReturn {
                value: Some(ValueId::new(1)),
            }),
        ],
        true,
    );
    procedure.values.extend([
        SemanticValue {
            id: ValueId::new(0),
            kind: SemanticValueKind::Receiver,
            source: SOURCE,
            evidence: EVIDENCE,
        },
        SemanticValue {
            id: ValueId::new(1),
            kind: SemanticValueKind::Callable,
            source: SOURCE,
            evidence: EVIDENCE,
        },
        SemanticValue {
            id: ValueId::new(2),
            kind: SemanticValueKind::Callable,
            source: SOURCE,
            evidence: EVIDENCE,
        },
    ]);
    let target_procedure = base_procedure(
        ProcedureId::new(1),
        target_locator,
        ProcedureKind::Method,
        vec![event(SemanticEffect::ProcedureReturn { value: None })],
        true,
    );

    let artifact = build_artifact(&source, vec![procedure, target_procedure]);
    let procedure = artifact.procedure(ProcedureId::new(0)).unwrap();

    assert!(procedure.call_sites().is_empty());
    assert!(
        procedure
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .any(|event| {
                matches!(
                    event.effect,
                    SemanticEffect::CallableReference {
                        callable: CallableValue {
                            kind: CallableReferenceKind::BoundMethod,
                            ..
                        },
                        ..
                    }
                )
            })
    );
    assert!(
        procedure
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .any(|event| {
                matches!(
                    event.effect,
                    SemanticEffect::CallableReference {
                        callable: CallableValue {
                            kind: CallableReferenceKind::UnboundMethod,
                            bound_receiver: None,
                            ..
                        },
                        ..
                    }
                )
            })
    );
    assert!(
        procedure
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .all(|event| { !matches!(event.effect, SemanticEffect::Invoke { .. }) })
    );
}

#[test]
fn ambiguous_callable_reference_keeps_candidates_and_an_explicit_gap() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/ambiguous.ts",
            "export function choose(flag: boolean) { return flag ? first : second; }",
        )
        .build();
    let source = FixtureSource::from_file(
        &project.file("src/ambiguous.ts"),
        SemanticLanguage::Standard(Language::TypeScript),
    );
    let locator = |name: &str, byte: u32| {
        source.procedure_locator(
            vec![named_segment(DeclarationSegmentKind::Function, name, byte)],
            anchor(byte, 0),
        )
    };
    let mut chooser = base_procedure(
        ProcedureId::new(0),
        locator("choose", 0),
        ProcedureKind::Function,
        vec![
            event(SemanticEffect::CallableReference {
                result: ValueId::new(0),
                callable: CallableValue {
                    kind: CallableReferenceKind::Function,
                    targets: CallableTargetResolution::Ambiguous(Box::new([
                        CallableTarget::Local(ProcedureId::new(1)),
                        CallableTarget::Local(ProcedureId::new(2)),
                    ])),
                    target_evidence: EVIDENCE,
                    bound_receiver: None,
                    environment: None,
                },
            }),
            event(SemanticEffect::Gap {
                gap: SemanticGapId::new(0),
            }),
            event(SemanticEffect::ProcedureReturn {
                value: Some(ValueId::new(0)),
            }),
        ],
        true,
    );
    chooser.values.push(SemanticValue {
        id: ValueId::new(0),
        kind: SemanticValueKind::Callable,
        source: SOURCE,
        evidence: EVIDENCE,
    });
    chooser.gaps.push(SemanticGap {
        id: SemanticGapId::new(0),
        point: BODY,
        subject: SemanticGapSubject::Value(ValueId::new(0)),
        capability: SemanticCapability::CallableReferences,
        kind: SemanticGapKind::Ambiguous,
        budget: None,
        detail: "both declarations remain viable".into(),
        source: SOURCE,
        evidence: EVIDENCE,
    });
    let first = base_procedure(
        ProcedureId::new(1),
        locator("first", 42),
        ProcedureKind::Function,
        vec![event(SemanticEffect::ProcedureReturn { value: None })],
        true,
    );
    let second = base_procedure(
        ProcedureId::new(2),
        locator("second", 50),
        ProcedureKind::Function,
        vec![event(SemanticEffect::ProcedureReturn { value: None })],
        true,
    );

    let artifact = build_artifact(&source, vec![chooser, first, second]);
    let chooser = artifact.procedure(ProcedureId::new(0)).unwrap();

    assert_eq!(chooser.gaps()[0].kind, SemanticGapKind::Ambiguous);
    let callable = chooser.points()[BODY.index()]
        .events
        .iter()
        .find_map(|event| match &event.effect {
            SemanticEffect::CallableReference { callable, .. } => Some(callable),
            _ => None,
        })
        .unwrap();
    assert_eq!(callable.targets.candidates().len(), 2);
    assert!(chooser.call_sites().is_empty());
}

#[test]
fn explicit_gap_does_not_fabricate_a_call_or_control_edge() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/unresolved.ts",
            "export function unresolved(candidate: unknown) { /* adapter cannot prove a call */ }",
        )
        .build();
    let source = FixtureSource::from_file(
        &project.file("src/unresolved.ts"),
        SemanticLanguage::Standard(Language::TypeScript),
    );
    let locator = source.procedure_locator(
        vec![named_segment(
            DeclarationSegmentKind::Function,
            "unresolved",
            0,
        )],
        anchor(0, 0),
    );
    let mut procedure = base_procedure(
        ProcedureId::new(0),
        locator,
        ProcedureKind::Function,
        vec![
            event(SemanticEffect::Gap {
                gap: SemanticGapId::new(0),
            }),
            event(SemanticEffect::Gap {
                gap: SemanticGapId::new(1),
            }),
            event(SemanticEffect::Gap {
                gap: SemanticGapId::new(2),
            }),
        ],
        false,
    );
    procedure.gaps.extend([
        SemanticGap {
            id: SemanticGapId::new(0),
            point: BODY,
            subject: SemanticGapSubject::Point,
            capability: SemanticCapability::Calls,
            kind: SemanticGapKind::Unknown,
            budget: None,
            detail: "call target cannot be established".into(),
            source: SOURCE,
            evidence: EVIDENCE,
        },
        SemanticGap {
            id: SemanticGapId::new(1),
            point: BODY,
            subject: SemanticGapSubject::Point,
            capability: SemanticCapability::ExceptionalControlFlow,
            kind: SemanticGapKind::Unsupported,
            budget: None,
            detail: "adapter does not expose exceptional flow".into(),
            source: SOURCE,
            evidence: EVIDENCE,
        },
        SemanticGap {
            id: SemanticGapId::new(2),
            point: BODY,
            subject: SemanticGapSubject::Point,
            capability: SemanticCapability::AsyncSuspendResume,
            kind: SemanticGapKind::Unsupported,
            budget: None,
            detail: "adapter does not expose async suspension".into(),
            source: SOURCE,
            evidence: EVIDENCE,
        },
    ]);

    let artifact = build_artifact(&source, vec![procedure]);
    let procedure = artifact.procedure(ProcedureId::new(0)).unwrap();

    assert_eq!(procedure.gaps().len(), 3);
    assert_eq!(
        procedure.points()[BODY.index()].events[0].effect,
        SemanticEffect::Gap {
            gap: SemanticGapId::new(0),
        }
    );
    assert!(procedure.call_sites().is_empty());
    assert!(
        procedure
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .all(|event| !matches!(event.effect, SemanticEffect::AsyncSuspend { .. }))
    );
    assert_eq!(
        procedure
            .control_edges()
            .iter()
            .map(|edge| (edge.source_point, edge.target_point, edge.kind))
            .collect::<Vec<_>>(),
        vec![(ENTRY, BODY, ControlEdgeKind::Normal)]
    );
}

#[test]
fn semantic_ir_rendering_is_deterministic_and_bounded() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/render.ts",
            "export function render(input: number) { const output = input; return output; }",
        )
        .build();
    let source = FixtureSource::from_file(
        &project.file("src/render.ts"),
        SemanticLanguage::Standard(Language::TypeScript),
    );
    let artifact = assignment_artifact(&source, "render");

    let rendered = render_semantic_ir(
        &artifact,
        SemanticIrSelection::Artifact,
        SemanticIrLimits::default(),
    )
    .unwrap();
    let rendered_again = render_semantic_ir(
        &artifact,
        SemanticIrSelection::Artifact,
        SemanticIrLimits::default(),
    )
    .unwrap();
    assert_eq!(rendered, rendered_again);
    assert!(!rendered.truncated);

    let limits = SemanticIrLimits {
        max_rows: 8,
        max_output_bytes: 2_048,
        ..SemanticIrLimits::default()
    };
    let bounded = render_semantic_ir(&artifact, SemanticIrSelection::Artifact, limits).unwrap();
    let bounded_again =
        render_semantic_ir(&artifact, SemanticIrSelection::Artifact, limits).unwrap();
    assert_eq!(bounded, bounded_again);
    assert!(bounded.truncated);
    assert!(bounded.semantic_ir.len() <= limits.max_output_bytes);
    assert!(bounded.semantic_ir.contains("(truncated :reason"));
}
