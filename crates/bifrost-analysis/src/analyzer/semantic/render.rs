//! Deterministic, bounded rendering for semantic artifacts.
//!
//! The renderer is intentionally a view over validated semantic IR. It does
//! not parse source, resolve targets, or infer missing semantics.

pub use brokk_bifrost_semantic::analyzer::semantic::render::*;

#[cfg(test)]
pub(crate) mod tests {

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::AllocationKind;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::AllocationSite;

    use brokk_bifrost_core::bounded_output::BalancedWriter;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::CallableTarget;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::CallableTargetResolution;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::CallableValue;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::CaptureBinding;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::CaptureSource;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::ControlEdge;

    use brokk_bifrost_analysis::analyzer::semantic::ids::ControlEdgeId;

    use brokk_bifrost_analysis::analyzer::semantic::render::MIN_OUTPUT_BYTES;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::MemoryLocation;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::MemoryLocationKind;

    use brokk_bifrost_analysis::analyzer::semantic::ids::ProcedureId;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::ProgramPoint;

    use brokk_bifrost_analysis::analyzer::semantic::render::RenderState;

    use brokk_bifrost_analysis::analyzer::semantic::ir::artifact::SemanticArtifact;

    use brokk_bifrost_analysis::analyzer::semantic::ids::SemanticArtifactKey;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticEffect;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticGap;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticGapSubject;

    use brokk_bifrost_analysis::analyzer::semantic::render::SemanticIrLimits;

    use brokk_bifrost_analysis::analyzer::semantic::render::SemanticIrSelection;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticValue;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticValueKind;

    use brokk_bifrost_analysis::analyzer::semantic::render::TRUNCATION_RESERVE;

    use brokk_bifrost_core::bounded_output::TruncationStyle;

    use brokk_bifrost_core::bounded_output::quoted;

    use brokk_bifrost_analysis::analyzer::semantic::render::render_point;

    use brokk_bifrost_analysis::analyzer::semantic::render::render_semantic_ir;

    use brokk_bifrost_analysis::analyzer::semantic::render::write_control_edge;

    use brokk_bifrost_analysis::analyzer::semantic::render::write_id_list;

    use brokk_bifrost_analysis::analyzer::semantic::render::write_source_mapping;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::BasicBlock;

    use brokk_bifrost_analysis::analyzer::semantic::ids::BlockId;

    use crate::analyzer::semantic::ContentIdentity;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::ControlEdgeKind;

    use brokk_bifrost_analysis::analyzer::semantic::ids::DeclarationLocator;

    use brokk_bifrost_analysis::analyzer::semantic::ids::DeclarationSegment;

    use brokk_bifrost_analysis::analyzer::semantic::ids::DeclarationSegmentKind;

    use brokk_bifrost_analysis::analyzer::semantic::ids::EvidenceId;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::ProcedureKind;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::ProcedureSemanticsParts;

    use brokk_bifrost_analysis::analyzer::semantic::ids::ProgramPointId;

    use brokk_bifrost_analysis::analyzer::semantic::capabilities::SemanticCapabilities;

    use brokk_bifrost_analysis::analyzer::semantic::capabilities::SemanticCapability;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticEvent;

    use brokk_bifrost_analysis::analyzer::semantic::ids::SemanticGapId;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticGapImpacts;

    use brokk_bifrost_core::analyzer::model::LanguageDialect as SemanticLanguage;

    use brokk_bifrost_analysis::analyzer::semantic::ids::SemanticLocator;

    use brokk_bifrost_analysis::analyzer::semantic::ids::SemanticRole;

    use brokk_bifrost_analysis::analyzer::semantic::ids::SourceAnchor;

    use brokk_bifrost_analysis::analyzer::semantic::ids::SourceMappingId;

    use brokk_bifrost_analysis::analyzer::semantic::ids::SourcePosition;

    use brokk_bifrost_analysis::analyzer::semantic::ids::SourceRevision;

    use brokk_bifrost_analysis::analyzer::semantic::ids::SourceSpan;

    use brokk_bifrost_analysis::analyzer::semantic::ids::StructuralNodeIdentity;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    fn bounded_writer_escapes_strings_and_balances_truncation() {
        let mut writer = BalancedWriter::new(
            MIN_OUTPUT_BYTES,
            TRUNCATION_RESERVE,
            TruncationStyle::ReasonAttribute,
        );
        assert!(writer.open(0, "(semantic-ir"));
        assert!(writer.open(1, "(procedure :id 0"));
        assert!(writer.line(2, &format!("(label {})", quoted("a\\\"b\n(c)"))));
        writer.truncate("row limit reached");
        let (output, truncated) = writer.finish();

        assert!(truncated);
        assert!(output.contains("a\\\\\\\"b\\n(c)"), "{output:?}");
        assert!(output.contains("(truncated :reason \"row limit reached\")"));
        assert!(output.len() <= MIN_OUTPUT_BYTES);
        assert_balanced(&output);
    }

    #[test]
    fn streamed_quoting_preserves_json_string_escaping() {
        let mut value: String = ('\0'..='\u{1f}').collect();
        value.push_str("quoted \" slash \\ unicode é \u{2028}");

        assert_eq!(
            quoted(&value).to_string(),
            serde_json::to_string(&value).unwrap()
        );
    }

    #[test]
    fn artifact_rendering_is_deterministic_scoped_and_source_backed() {
        let artifact = fixture_artifact(2);
        let first = render_semantic_ir(
            &artifact,
            SemanticIrSelection::Artifact,
            SemanticIrLimits::default(),
        )
        .unwrap();
        let second = render_semantic_ir(
            &artifact,
            SemanticIrSelection::Artifact,
            SemanticIrLimits::default(),
        )
        .unwrap();

        assert_eq!(first, second);
        assert!(!first.truncated);
        assert!(first.semantic_ir.contains(":path \"src/render.ts\""));
        assert!(first.semantic_ir.contains("procedure\\\"0\\nline"));
        assert!(first.semantic_ir.contains("(capability :name \"captures\""));
        let scope = first.semantic_ir.find("(artifact :fingerprint").unwrap();
        let local_id = first.semantic_ir.find("(procedure :id 0").unwrap();
        assert!(scope < local_id, "{}", first.semantic_ir);
        assert!(!first.semantic_ir.contains("/Users/"));
        assert_balanced(&first.semantic_ir);
    }

    #[test]
    #[hardwon("#2816: decorated parameter identity must remain content-scoped in semantic output")]
    fn source_mapping_renders_exact_structural_identity() {
        let key = fixture_key();
        let mut mapping = fixture_procedure(&key, 0).source_mappings.remove(0);
        mapping.ast_identity = Some(StructuralNodeIdentity::new(key.revision().content(), 17));
        let mut rendered = String::new();

        write_source_mapping(&mut rendered, &mapping).expect("source mapping renders");

        assert!(rendered.contains(&format!(
            ":ast-identity (structural-node :content {} :node-id 17)",
            key.revision().content()
        )));
        assert_balanced(&rendered);
    }

    #[test]
    fn control_edge_ids_and_point_adjacency_are_rendered_deterministically() {
        let artifact = fixture_artifact(1);
        let procedure = &artifact.procedures()[0];
        let first = render_semantic_ir(
            &artifact,
            SemanticIrSelection::Artifact,
            SemanticIrLimits::default(),
        )
        .unwrap();
        let second = render_semantic_ir(
            &artifact,
            SemanticIrSelection::Artifact,
            SemanticIrLimits::default(),
        )
        .unwrap();

        assert_eq!(first, second);
        assert!(!first.truncated);
        assert_eq!(
            first.semantic_ir.matches("(control-edge :id ").count(),
            procedure.cfg().edges().len()
        );
        assert!(first.semantic_ir.contains(
            "(control-edge :id 0 :source-point 0 :target-point 2 :kind \"exceptional\" :source 0 :evidence 0)"
        ));
        assert!(first.semantic_ir.contains(
            "(program-point :id 0 :block 0 :source 0 :evidence 0 :predecessor-edges () :successor-edges (0 1)"
        ));

        for point in procedure.points() {
            let mut predecessors = String::new();
            write_id_list(
                &mut predecessors,
                procedure
                    .predecessor_edges(point.id)
                    .map(|(edge_id, _)| edge_id),
            )
            .unwrap();
            let mut successors = String::new();
            write_id_list(
                &mut successors,
                procedure
                    .successor_edges(point.id)
                    .map(|(edge_id, _)| edge_id),
            )
            .unwrap();
            let expected = format!(
                "(program-point :id {} :block {} :source {} :evidence {} :predecessor-edges {} :successor-edges {}",
                point.id, point.block, point.source, point.evidence, predecessors, successors,
            );
            assert!(first.semantic_ir.contains(&expected), "{expected:?}");
        }

        for (index, edge) in procedure.cfg().edges().iter().enumerate() {
            let edge_id = ControlEdgeId::try_from_index(index).unwrap();
            let mut expected = String::new();
            write_control_edge(&mut expected, edge_id, edge).unwrap();
            assert!(first.semantic_ir.contains(&expected), "{expected:?}");
        }
        assert_balanced(&first.semantic_ir);
    }

    #[test]
    fn high_degree_adjacency_rows_truncate_transactionally_and_stay_balanced() {
        const DEGREE: usize = 4_096;
        let artifact = fixture_high_degree_artifact(DEGREE);
        let procedure = &artifact.procedures()[0];
        assert!(procedure.successor_edges(ProgramPointId::new(0)).len() > DEGREE);
        assert!(procedure.predecessor_edges(ProgramPointId::new(1)).len() > DEGREE);

        for point_id in [ProgramPointId::new(0), ProgramPointId::new(1)] {
            let limits = SemanticIrLimits {
                max_output_bytes: 512,
                ..SemanticIrLimits::default()
            };
            let mut state = RenderState::new(limits);
            assert!(state.writer.open(0, "(semantic-ir"));
            assert!(state.writer.open(1, "(program-points"));
            let point = procedure.point(point_id).unwrap();

            assert!(!render_point(&mut state, procedure, point));
            let (output, truncated) = state.writer.finish();

            assert!(truncated);
            assert!(output.contains("output byte limit reached"), "{output:?}");
            assert!(!output.contains(&format!("(program-point :id {point_id} ")));
            assert!(output.len() <= limits.max_output_bytes);
            assert_balanced(&output);
        }
    }

    #[test]
    fn artifact_renderer_marks_every_budget_and_stays_balanced() {
        let artifact = fixture_artifact(3);
        let limits = [
            SemanticIrLimits {
                max_procedures: 1,
                ..SemanticIrLimits::default()
            },
            SemanticIrLimits {
                max_rows: 10,
                ..SemanticIrLimits::default()
            },
            SemanticIrLimits {
                max_source_entries: 1,
                ..SemanticIrLimits::default()
            },
            SemanticIrLimits {
                max_output_bytes: MIN_OUTPUT_BYTES,
                ..SemanticIrLimits::default()
            },
        ];

        for limits in limits {
            let rendered =
                render_semantic_ir(&artifact, SemanticIrSelection::Artifact, limits).unwrap();
            assert!(rendered.truncated, "limits: {limits:?}");
            assert!(rendered.semantic_ir.contains("(truncated :reason"));
            assert!(rendered.semantic_ir.len() <= limits.max_output_bytes);
            assert_balanced(&rendered.semantic_ir);
        }
    }
    #[test]
    fn multi_megabyte_gap_detail_is_rejected_without_retaining_a_partial_row() {
        const DETAIL_BYTES: usize = 4 * 1024 * 1024;
        let artifact =
            fixture_feature_artifact_with_gap_detail("x".repeat(DETAIL_BYTES).into_boxed_str());
        let limits = SemanticIrLimits {
            max_output_bytes: 64 * 1024,
            ..SemanticIrLimits::default()
        };

        let rendered =
            render_semantic_ir(&artifact, SemanticIrSelection::Artifact, limits).unwrap();

        assert!(rendered.truncated);
        assert!(rendered.semantic_ir.len() <= limits.max_output_bytes);
        assert!(rendered.semantic_ir.contains("output byte limit reached"));
        assert!(
            !rendered.semantic_ir.contains(&"x".repeat(1_024)),
            "the rejected gap row must be rolled back instead of retained partially"
        );
        assert_balanced(&rendered.semantic_ir);
    }

    #[test]
    fn deeply_nested_procedure_selection_is_stack_safe() {
        const DEPTH: usize = 4_096;
        let artifact = fixture_artifact(DEPTH);
        let selected = ProcedureId::try_from_index(DEPTH - 1).unwrap();
        let rendered = render_semantic_ir(
            &artifact,
            SemanticIrSelection::Procedure(selected),
            SemanticIrLimits::default(),
        )
        .unwrap();

        assert!(!rendered.truncated);
        assert!(rendered.semantic_ir.contains(&format!(
            "(procedure :id {} :kind \"lambda\" :parent {}",
            DEPTH - 1,
            DEPTH - 2
        )));
        assert_balanced(&rendered.semantic_ir);
    }

    fn fixture_artifact(procedure_count: usize) -> SemanticArtifact {
        let key = fixture_key();
        let capabilities = SemanticCapabilities::builder()
            .complete(SemanticCapability::Procedures)
            .complete(SemanticCapability::EntryBoundary)
            .complete(SemanticCapability::NormalExitBoundary)
            .complete(SemanticCapability::ExceptionalExitBoundary)
            .complete(SemanticCapability::BasicBlocks)
            .complete(SemanticCapability::ProgramPoints)
            .complete(SemanticCapability::NormalControlFlow)
            .complete(SemanticCapability::ExceptionalControlFlow)
            .partial(SemanticCapability::Captures)
            .build();
        let procedures = (0..procedure_count)
            .map(|index| fixture_procedure(&key, index))
            .collect();
        SemanticArtifact::try_new(key, capabilities, procedures).unwrap()
    }

    fn fixture_high_degree_artifact(degree: usize) -> SemanticArtifact {
        let key = fixture_key();
        let source = SourceMappingId::new(0);
        let evidence = EvidenceId::new(0);
        let mut procedure = fixture_procedure(&key, 0);
        for _ in 0..degree {
            let point_id = ProgramPointId::try_from_index(procedure.points.len()).unwrap();
            procedure.points.push(ProgramPoint {
                id: point_id,
                block: BlockId::new(0),
                events: Vec::new().into_boxed_slice(),
                source,
                evidence,
            });
            procedure.control_edges.push(ControlEdge {
                source_point: ProgramPointId::new(0),
                target_point: point_id,
                kind: ControlEdgeKind::SwitchCase,
                source,
                evidence,
            });
            procedure.control_edges.push(ControlEdge {
                source_point: point_id,
                target_point: ProgramPointId::new(1),
                kind: ControlEdgeKind::Normal,
                source,
                evidence,
            });
        }
        procedure.blocks[0].points = procedure
            .points
            .iter()
            .map(|point| point.id)
            .collect::<Vec<_>>()
            .into_boxed_slice();

        let capabilities = SemanticCapabilities::builder()
            .complete(SemanticCapability::Procedures)
            .complete(SemanticCapability::EntryBoundary)
            .complete(SemanticCapability::NormalExitBoundary)
            .complete(SemanticCapability::ExceptionalExitBoundary)
            .complete(SemanticCapability::BasicBlocks)
            .complete(SemanticCapability::ProgramPoints)
            .complete(SemanticCapability::NormalControlFlow)
            .complete(SemanticCapability::ExceptionalControlFlow)
            .build();
        SemanticArtifact::try_new(key, capabilities, vec![procedure]).unwrap()
    }

    fn fixture_feature_artifact_with_gap_detail(detail: Box<str>) -> SemanticArtifact {
        let key = fixture_key();
        let source = SourceMappingId::new(0);
        let evidence = EvidenceId::new(0);
        let mut outer = fixture_procedure(&key, 0);
        let mut child = fixture_procedure(&key, 1);

        outer.values = vec![
            SemanticValue {
                id: brokk_bifrost_analysis::analyzer::semantic::ids::ValueId::new(0),
                kind: SemanticValueKind::Callable,
                source,
                evidence,
            },
            SemanticValue {
                id: brokk_bifrost_analysis::analyzer::semantic::ids::ValueId::new(1),
                kind: SemanticValueKind::Receiver { dispatch: true },
                source,
                evidence,
            },
            SemanticValue {
                id: brokk_bifrost_analysis::analyzer::semantic::ids::ValueId::new(2),
                kind: SemanticValueKind::Local,
                source,
                evidence,
            },
            SemanticValue {
                id: brokk_bifrost_analysis::analyzer::semantic::ids::ValueId::new(3),
                kind: SemanticValueKind::Callable,
                source,
                evidence,
            },
            SemanticValue {
                id: brokk_bifrost_analysis::analyzer::semantic::ids::ValueId::new(4),
                kind: SemanticValueKind::Temporary,
                source,
                evidence,
            },
        ];
        outer.allocations = vec![AllocationSite {
            id: brokk_bifrost_analysis::analyzer::semantic::ids::AllocationId::new(0),
            point: ProgramPointId::new(1),
            result: brokk_bifrost_analysis::analyzer::semantic::ids::ValueId::new(4),
            kind: AllocationKind::ClosureEnvironment,
            source,
            evidence,
        }];
        outer.memory_locations = vec![MemoryLocation {
            id: brokk_bifrost_analysis::analyzer::semantic::ids::MemoryLocationId::new(0),
            kind: MemoryLocationKind::LexicalCell {
                binding: brokk_bifrost_analysis::analyzer::semantic::ids::ValueId::new(2),
            },
            value_copy: brokk_bifrost_analysis::analyzer::semantic::ir::MemoryValueCopy::Unknown,
            source,
            evidence,
        }];
        child.memory_locations = vec![MemoryLocation {
            id: brokk_bifrost_analysis::analyzer::semantic::ids::MemoryLocationId::new(0),
            kind: MemoryLocationKind::Capture {
                lexical_parent: ProcedureId::new(0),
                binding: None,
            },
            value_copy: brokk_bifrost_analysis::analyzer::semantic::ir::MemoryValueCopy::Unknown,
            source,
            evidence,
        }];
        outer.captures = vec![CaptureBinding {
            id: brokk_bifrost_analysis::analyzer::semantic::ids::CaptureId::new(0),
            point: ProgramPointId::new(1),
            callable: brokk_bifrost_analysis::analyzer::semantic::ids::ValueId::new(0),
            target: ProcedureId::new(1),
            environment: brokk_bifrost_analysis::analyzer::semantic::ids::AllocationId::new(0),
            captured: CaptureSource::Location(
                brokk_bifrost_analysis::analyzer::semantic::ids::MemoryLocationId::new(0),
            ),
            destination: brokk_bifrost_analysis::analyzer::semantic::ids::MemoryLocationId::new(0),
            mode: brokk_bifrost_analysis::analyzer::semantic::ir::CaptureMode::MutableCell,
            source,
            evidence,
        }];
        outer.gaps = vec![SemanticGap {
            id: SemanticGapId::new(0),
            point: ProgramPointId::new(2),
            subject: SemanticGapSubject::Point,
            capability: SemanticCapability::ExceptionalControlFlow,
            impacts: SemanticGapImpacts::for_gap(
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapSubject::Point,
            ),
            kind: brokk_bifrost_analysis::analyzer::semantic::ir::SemanticGapKind::Unsupported,
            budget: None,
            discharge: brokk_bifrost_analysis::analyzer::semantic::ir::SemanticGapDischarge::None,
            detail,
            source,
            evidence,
        }];
        outer.blocks = vec![BasicBlock {
            id: BlockId::new(0),
            points: (0_u32..5).map(ProgramPointId::new).collect(),
            source,
            evidence,
        }];
        outer.points = vec![
            fixture_point(0, vec![SemanticEffect::Entry], source, evidence),
            fixture_point(
                1,
                vec![
                    SemanticEffect::Allocation {
                        allocation: brokk_bifrost_analysis::analyzer::semantic::ids::AllocationId::new(0),
                    },
                    SemanticEffect::MemoryStore {
                        kind: brokk_bifrost_analysis::analyzer::semantic::ir::MemoryAccessKind::LexicalCell,
                        location: brokk_bifrost_analysis::analyzer::semantic::ids::MemoryLocationId::new(0),
                        value: brokk_bifrost_analysis::analyzer::semantic::ids::ValueId::new(2),
                    },
                    SemanticEffect::CallableCreation {
                        result: brokk_bifrost_analysis::analyzer::semantic::ids::ValueId::new(0),
                        callable: CallableValue {
                            kind: brokk_bifrost_analysis::analyzer::semantic::ir::CallableReferenceKind::Lambda,
                            targets: CallableTargetResolution::Proven(CallableTarget::Local(
                                ProcedureId::new(1),
                            )),
                            target_evidence: evidence,
                            bound_receiver: None,
                            environment: Some(brokk_bifrost_analysis::analyzer::semantic::ids::AllocationId::new(0)),
                        },
                    },
                    SemanticEffect::CaptureBind {
                        capture: brokk_bifrost_analysis::analyzer::semantic::ids::CaptureId::new(0),
                    },
                ],
                source,
                evidence,
            ),
            fixture_point(
                2,
                vec![
                    SemanticEffect::CallableReference {
                        result: brokk_bifrost_analysis::analyzer::semantic::ids::ValueId::new(3),
                        callable: CallableValue {
                            kind: brokk_bifrost_analysis::analyzer::semantic::ir::CallableReferenceKind::BoundMethod,
                            targets: CallableTargetResolution::Proven(CallableTarget::Local(
                                ProcedureId::new(1),
                            )),
                            target_evidence: evidence,
                            bound_receiver: Some(brokk_bifrost_analysis::analyzer::semantic::ids::ValueId::new(1)),
                            environment: None,
                        },
                    },
                    SemanticEffect::Gap {
                        gap: SemanticGapId::new(0),
                    },
                ],
                source,
                evidence,
            ),
            fixture_point(3, vec![SemanticEffect::NormalExit], source, evidence),
            fixture_point(4, vec![SemanticEffect::ExceptionalExit], source, evidence),
        ];
        outer.control_edges = vec![
            fixture_edge(0, 1, ControlEdgeKind::Normal, source, evidence),
            fixture_edge(1, 2, ControlEdgeKind::Normal, source, evidence),
            fixture_edge(2, 3, ControlEdgeKind::Normal, source, evidence),
            fixture_edge(2, 4, ControlEdgeKind::Exceptional, source, evidence),
        ];

        let capabilities = SemanticCapabilities::builder()
            .complete(SemanticCapability::Procedures)
            .complete(SemanticCapability::EntryBoundary)
            .complete(SemanticCapability::NormalExitBoundary)
            .complete(SemanticCapability::ExceptionalExitBoundary)
            .complete(SemanticCapability::BasicBlocks)
            .complete(SemanticCapability::ProgramPoints)
            .complete(SemanticCapability::NormalControlFlow)
            .partial(SemanticCapability::ExceptionalControlFlow)
            .complete(SemanticCapability::Values)
            .complete(SemanticCapability::Allocations)
            .complete(SemanticCapability::LocalFlow)
            .complete(SemanticCapability::CallableReferences)
            .complete(SemanticCapability::Captures)
            .build();
        SemanticArtifact::try_new(key, capabilities, vec![outer, child]).unwrap()
    }

    fn fixture_point(
        id: u32,
        effects: Vec<SemanticEffect>,
        source: SourceMappingId,
        evidence: EvidenceId,
    ) -> ProgramPoint {
        ProgramPoint {
            id: ProgramPointId::new(id),
            block: BlockId::new(0),
            events: effects
                .into_iter()
                .map(|effect| SemanticEvent::new(effect, source, evidence))
                .collect(),
            source,
            evidence,
        }
    }

    fn fixture_edge(
        source_point: u32,
        target_point: u32,
        kind: ControlEdgeKind,
        source: SourceMappingId,
        evidence: EvidenceId,
    ) -> ControlEdge {
        ControlEdge {
            source_point: ProgramPointId::new(source_point),
            target_point: ProgramPointId::new(target_point),
            kind,
            source,
            evidence,
        }
    }

    fn fixture_key() -> SemanticArtifactKey {
        brokk_bifrost_analysis::test_support::semantic_artifact_key_fixture(
            "mount",
            "src/render.ts",
            SemanticLanguage::Standard(Language::TypeScript),
            SourceRevision::Disk {
                content: ContentIdentity::hash_bytes("content"),
            },
            "typescript",
            "adapter",
            "semantic-ir",
            "configuration",
            "dependencies",
        )
    }

    fn fixture_procedure(key: &SemanticArtifactKey, index: usize) -> ProcedureSemanticsParts {
        let id = ProcedureId::try_from_index(index).unwrap();
        let offset = u32::try_from(index).unwrap();
        let start = SourcePosition::new(offset, offset, 0);
        let end = SourcePosition::new(offset + 1, offset, 1);
        let span = SourceSpan::new(start, end).unwrap();
        let anchor = SourceAnchor::new(span, offset);
        let name = format!("procedure\"{index}\nline");
        let declaration = DeclarationLocator::new(vec![
            DeclarationSegment::named(DeclarationSegmentKind::Lambda, name, anchor, offset)
                .unwrap(),
        ])
        .unwrap();
        let locator = SemanticLocator::new(
            key.mount(),
            key.path().clone(),
            key.language(),
            declaration,
            SemanticRole::Procedure,
            anchor,
        );
        let mut parts = brokk_bifrost_analysis::test_support::minimal_semantic_procedure(
            id,
            locator,
            if index == 0 {
                ProcedureKind::Function
            } else {
                ProcedureKind::Lambda
            },
        );
        parts.lexical_parent = index
            .checked_sub(1)
            .map(|parent| ProcedureId::try_from_index(parent).unwrap());
        parts
    }

    fn assert_balanced(value: &str) {
        let mut depth = 0usize;
        let mut quoted = false;
        let mut escaped = false;
        for byte in value.bytes() {
            if quoted {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    quoted = false;
                }
                continue;
            }
            match byte {
                b'"' => quoted = true,
                b'(' => depth += 1,
                b')' => {
                    depth = depth
                        .checked_sub(1)
                        .expect("unexpected closing parenthesis")
                }
                _ => {}
            }
        }
        assert!(!quoted, "unterminated string in {value:?}");
        assert_eq!(depth, 0, "unclosed form in {value:?}");
    }
}
