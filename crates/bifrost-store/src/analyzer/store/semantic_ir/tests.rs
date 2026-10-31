//! Round-trip differential: lower real Rust files, store the rows, read them
//! back, and require the rebuilt artifact to be the lowered one.

use brokk_bifrost_core::cache_gc::PlannerStatisticsState;

use crate::analyzer::store::AnalyzerStore;
use crate::analyzer::store::planner_statistics::pinned_plans::{explain_pin, pinned};

/// The head lookup seeks the blob by its identity and the head and the epoch
/// by their keys, with and without representative statistics.
#[test]
fn semantic_ir_publication_lookup_seeks_keys() {
    for state in PlannerStatisticsState::BOTH {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().unwrap();
        state.install(&conn);
        let plan = explain_pin(&conn, &pinned("semantic_ir_publication"));
        for (table, access) in [
            ("blobs", "sqlite_autoindex_blobs_1"),
            ("publications", "PRIMARY KEY"),
            ("epochs", "PRIMARY KEY"),
        ] {
            assert!(
                plan.iter().any(|detail| {
                    detail.starts_with(&format!("SEARCH {table} ")) && detail.contains(access)
                }),
                "{state}: {table} is not searched by {access}: {plan:#?}"
            );
        }
        for forbidden in ["SCAN", "AUTOMATIC", "TEMP B-TREE", "CO-ROUTINE"] {
            assert!(
                plan.iter().all(|detail| !detail.contains(forbidden)),
                "{state}: the plan uses {forbidden}: {plan:#?}"
            );
        }
    }
}

/// Every table and every row variant of the semantic IR rows: a fixture of
/// five procedures that the encoder writes, the schema checks, and the decoder
/// rebuilds. The parse-time lowerers that write these rows live in other
/// crates and each produces only some variants, so this fixture is built by
/// hand. The ids it names need not form a valid artifact: the rows store them
/// as plain integers and neither side validates references.
mod row_fixture {
    use std::path::Path;

    use git2::Oid;
    use rusqlite::params;

    use super::super::{PreparedSemanticIr, SemanticIrLoweringOutcome, SemanticIrMountScope};
    use crate::CancellationToken;
    use crate::analyzer::model::{Language, LanguageDialect};
    use crate::analyzer::semantic::partial_flow::fixpoint::{
        PartialFlow, PartialFlowOutcome, ProcedurePartialFlows,
    };
    use crate::analyzer::semantic::partial_flow::ports::{HeapSelector, PartialFlowPort, PortId};
    use crate::analyzer::semantic::{
        AccessPathTail, AllocationId, AllocationKind, AllocationSite, ArgumentDomain,
        ArtifactCallableTarget, AsyncResumeKind, BackingStoreOffset, BasicBlock, BlockId,
        CallArgumentExpansion, CallContinuationKind, CallInvocationMode, CallReceiverTypeFact,
        CallSiteId, CallableReferenceKind, CallableTarget, CallableTargetResolution, CallableValue,
        CaptureBinding, CaptureId, CaptureMode, CaptureSource, ConstructionReturn, ContentIdentity,
        ControlContinuation, ControlEdge, ControlEdgeKind, DeclarationLocator, DeclarationSegment,
        DeclarationSegmentKind, DeferredMemberSelection, DispatchExtensibility, DropBehavior,
        DropFact, Evidence, EvidenceCompleteness, EvidenceId, ExecutionTiming, FormalMultiplicity,
        FormalParameterPassingMode, GoPredeclaredBuiltin, GuardArm, GuardConditionDigest,
        GuardFactParts, GuardId, GuardPredicate, IndexedLocationIdentity, IntegerComparison,
        LifecycleIncompleteReason, LoopSite, MemoryAccessKind, MemoryLocation, MemoryLocationId,
        MemoryLocationKind, MemoryValueCopy, MoveInvalidation, MoveOutFact, MoveOutState,
        PointerAccess, PointerAccessKind, PointerAccessWidth, PointerAlias, PointerByteOffset,
        PointerIncompleteReason, PointerInvalidation, PointerInvalidationCause,
        PointerInvalidationTarget, PointerOrigin, PointerOriginId, PointerOriginKind,
        PointerRelationStrength, ProcedureCallBoundary, ProcedureId, ProcedureInvocationKind,
        ProcedureKind, ProcedureProperties, ProcedureReceiverBinding, ProcedureSemanticsParts,
        ProgramPoint, ProgramPointId, ProofStatus, ScopeEndAt, ScopeEndFact,
        SemanticBudgetDimension, SemanticBudgetExceeded, SemanticCallArgument, SemanticCallSite,
        SemanticCapability, SemanticEffect, SemanticEvent, SemanticGap, SemanticGapDischarge,
        SemanticGapId, SemanticGapImpact, SemanticGapImpacts, SemanticGapKind, SemanticGapSubject,
        SemanticIncompleteFact, SemanticIncompleteReason, SemanticIncompleteSubject,
        SemanticLocator, SemanticPlace, SemanticRole, SemanticValue, SemanticValueKind,
        SignedIntegerMagnitude, SourceAnchor, SourceMapping, SourceMappingId, SourceMappingKind,
        SourcePosition, SourceSpan, StableDigest, StatementEntrySite, StructuralNodeIdentity,
        SwitchCaseFactParts, SwitchEdgeParts, SwitchFactId, SwitchFactKind, SwitchFactParts,
        SwitchSelectorDomain, SynchronizationOperation, SynchronizationPayload,
        SynchronizationPayloadCopy, TransferKind, TransferOperation, ValueFlowKind, ValueId,
        ValuePreservation, ValueTransfer, ValueUseKind, WorkspaceMountId, WorkspaceRelativePath,
    };
    use crate::analyzer::semantic_model::{
        AnonymousCallableIdentity, SourceAnchor as ModelSourceAnchor, SourceByteRange,
        SourceCallableShape, SourceDeclarationKind, SourceParameterShape, SourceTypeNode,
    };
    use crate::analyzer::store::AnalyzerStore;

    pub(super) const LANG: &str = "rust";
    pub(super) const EPOCH: &str = "semantic-ir-row-fixture";
    pub(super) const SOURCE_BYTES: usize = 4096;

    pub(super) struct Fixture {
        pub(super) scope: SemanticIrMountScope,
        pub(super) parts: Vec<ProcedureSemanticsParts>,
        pub(super) flows: Vec<ProcedurePartialFlows>,
    }

    fn v(id: u32) -> ValueId {
        ValueId::new(id)
    }

    fn pt(id: u32) -> ProgramPointId {
        ProgramPointId::new(id)
    }

    fn sm(id: u32) -> SourceMappingId {
        SourceMappingId::new(id)
    }

    fn ev(id: u32) -> EvidenceId {
        EvidenceId::new(id)
    }

    fn mem(id: u32) -> MemoryLocationId {
        MemoryLocationId::new(id)
    }

    fn call(id: u32) -> CallSiteId {
        CallSiteId::new(id)
    }

    fn alloc(id: u32) -> AllocationId {
        AllocationId::new(id)
    }

    /// A single-line span.
    fn anchor(start: u32, end: u32, occurrence: u32) -> SourceAnchor {
        let span = SourceSpan::new(
            SourcePosition::new(start, 0, start),
            SourcePosition::new(end, 0, end),
        )
        .unwrap();
        SourceAnchor::new(span, occurrence)
    }

    fn event(effect: SemanticEffect) -> SemanticEvent {
        SemanticEvent::new(effect, sm(1), ev(2))
    }

    fn flow(kind: ValueFlowKind, source: u32, target: u32) -> SemanticEvent {
        event(SemanticEffect::ValueFlow {
            kind,
            source: v(source),
            target: v(target),
        })
    }

    fn transfer(kind: TransferKind, operation: TransferOperation) -> ValueFlowKind {
        ValueFlowKind::Transfer(ValueTransfer { kind, operation })
    }

    fn callable(
        kind: CallableReferenceKind,
        targets: CallableTargetResolution,
        bound_receiver: Option<ValueId>,
        environment: Option<AllocationId>,
    ) -> CallableValue {
        CallableValue {
            kind,
            targets,
            target_evidence: ev(1),
            bound_receiver,
            environment,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn call_site(
        id: u32,
        timing: ExecutionTiming,
        mode: CallInvocationMode,
        declared_targets: CallableTargetResolution,
        normal: ControlContinuation,
        exceptional: ControlContinuation,
        arguments: Vec<SemanticCallArgument>,
        normal_results: Vec<ValueId>,
    ) -> SemanticCallSite {
        SemanticCallSite {
            id: call(id),
            point: pt(3),
            invocation_mode: mode,
            execution_timing: timing,
            callee: v(16),
            receiver: None,
            member_selection: None,
            arguments: arguments.into(),
            normal_results: normal_results.into(),
            result: None,
            thrown: None,
            declared_targets,
            target_evidence: ev(id % 3),
            normal_continuation: normal,
            exceptional_continuation: exceptional,
            source: sm(1),
            evidence: ev(2),
        }
    }

    fn argument(
        value: u32,
        expansion: CallArgumentExpansion,
        keyword: Option<&str>,
    ) -> SemanticCallArgument {
        SemanticCallArgument {
            value: v(value),
            expansion,
            keyword: keyword.map(Into::into),
        }
    }

    fn guard(
        id: u32,
        subject: Option<ValueId>,
        predicate: GuardPredicate,
        true_arm: Option<GuardArm>,
        false_arm: Option<GuardArm>,
    ) -> GuardFactParts {
        GuardFactParts {
            id: GuardId::new(id),
            point: pt(1),
            subject,
            predicate,
            true_arm,
            false_arm,
            source: sm(1),
            evidence: ev(2),
        }
    }

    fn arm(target: u32, kind: ControlEdgeKind) -> GuardArm {
        GuardArm {
            target_point: pt(target),
            kind,
        }
    }

    fn gap(
        id: u32,
        subject: SemanticGapSubject,
        capability: SemanticCapability,
        impacts: SemanticGapImpacts,
        kind: SemanticGapKind,
        budget: Option<SemanticBudgetExceeded>,
        discharge: SemanticGapDischarge,
    ) -> SemanticGap {
        SemanticGap {
            id: SemanticGapId::new(id),
            point: pt(id % 5),
            subject,
            capability,
            impacts,
            kind,
            budget,
            discharge,
            detail: format!("gap detail {id}").into(),
            source: sm(1),
            evidence: ev(2),
        }
    }

    fn artifact_target() -> CallableTarget {
        let file = "src/lib.rs".to_owned();
        let range = |start, end| SourceByteRange { start, end };
        CallableTarget::Artifact(ArtifactCallableTarget::from_bound_identity(
            AnonymousCallableIdentity {
                id: "anonymous-callable-1".to_owned(),
                artifact_sha256: "ab".repeat(32),
                package_identity: "example.com/fixture".to_owned(),
                anchor: ModelSourceAnchor {
                    file: file.clone(),
                    byte_range: range(50, 90),
                    kind: SourceDeclarationKind::FunctionLiteral,
                },
                lexical_owner_chain: vec![ModelSourceAnchor {
                    file: file.clone(),
                    byte_range: range(0, 400),
                    kind: SourceDeclarationKind::Function,
                }],
                signature: SourceCallableShape {
                    function_type: SourceTypeNode {
                        file: file.clone(),
                        byte_range: range(52, 60),
                    },
                    parameters: vec![SourceParameterShape {
                        type_node: SourceTypeNode {
                            file,
                            byte_range: range(53, 56),
                        },
                        variadic: true,
                        arity: 2,
                    }],
                    results: Vec::new(),
                    declaration_chain: Vec::new(),
                },
            },
        ))
    }

    /// The five procedures and their partial flows. Procedure 0 carries every
    /// variant of every row; procedure 1 reuses the event, target-group,
    /// side-table and port keys of procedure 0 under its own procedure id;
    /// procedures 2 to 4 have no child rows except their partial-flow heads.
    pub(super) fn fixture() -> Fixture {
        let mount = WorkspaceMountId::from_root(Path::new("/semantic-ir-row-fixture"));
        let path = WorkspaceRelativePath::new("src/lib.rs").unwrap();
        let other_path = WorkspaceRelativePath::new("src/other.rs").unwrap();
        let language = LanguageDialect::Standard(Language::Rust);
        let content = ContentIdentity::hash_bytes("semantic IR row fixture");
        let scope = SemanticIrMountScope::new(mount, path.clone(), language, content);

        // A span over several lines, so line and column columns differ from
        // the byte columns.
        let multiline = SourceAnchor::new(
            SourceSpan::new(
                SourcePosition::new(12, 1, 2),
                SourcePosition::new(140, 9, 1),
            )
            .unwrap(),
            3,
        );
        let file_segment =
            DeclarationSegment::named(DeclarationSegmentKind::File, "lib.rs", anchor(0, 400, 0), 0)
                .unwrap();
        let outer_segment =
            DeclarationSegment::named(DeclarationSegmentKind::Function, "outer", multiline, 4)
                .unwrap();
        let outer =
            DeclarationLocator::new(vec![file_segment.clone(), outer_segment.clone()]).unwrap();
        let closure = DeclarationLocator::new(vec![
            file_segment,
            outer_segment,
            DeclarationSegment::anonymous(DeclarationSegmentKind::Closure, anchor(50, 90, 1), 2),
        ])
        .unwrap();
        let holder = DeclarationLocator::new(vec![
            DeclarationSegment::named(
                DeclarationSegmentKind::Type,
                "Holder\u{e9}",
                anchor(0, 30, 0),
                0,
            )
            .unwrap(),
        ])
        .unwrap();
        let locator = |path: &WorkspaceRelativePath,
                       declaration: &DeclarationLocator,
                       role: SemanticRole,
                       anchor: SourceAnchor| {
            SemanticLocator::new(
                mount,
                path.clone(),
                language,
                declaration.clone(),
                role,
                anchor,
            )
        };
        let outer_procedure = locator(&path, &outer, SemanticRole::Procedure, multiline);
        let closure_procedure =
            locator(&path, &closure, SemanticRole::Procedure, anchor(50, 90, 1));
        // A locator in another file of the same mount, as the Rust lowerer's
        // field members are.
        let field = locator(
            &other_path,
            &holder,
            SemanticRole::MemoryLocation,
            anchor(4, 8, 0),
        );
        let binding = locator(&path, &outer, SemanticRole::Value, anchor(20, 21, 0));
        let external = locator(
            &other_path,
            &holder,
            SemanticRole::Procedure,
            anchor(10, 30, 2),
        );
        let mapping = locator(
            &path,
            &outer,
            SemanticRole::SourceMapping,
            anchor(30, 34, 0),
        );

        let mut p0 = ProcedureSemanticsParts::new(
            ProcedureId::new(0),
            outer_procedure.clone(),
            ProcedureKind::Function,
            sm(0),
            ev(1),
        );
        p0.properties = ProcedureProperties {
            is_async: true,
            is_generator: false,
            is_static: false,
            is_synthetic: true,
            invocation: ProcedureInvocationKind::Deferred,
            dispatch_extensibility: DispatchExtensibility::Closed,
            call_boundary: ProcedureCallBoundary::Unknown,
            receiver_binding: ProcedureReceiverBinding::Class,
            construction_return: ConstructionReturn::PreservesAllocation,
        };
        let value_kinds = vec![
            SemanticValueKind::Local,
            SemanticValueKind::Parameter {
                ordinal: 0,
                multiplicity: FormalMultiplicity::One,
                name: Some("self\u{e9}".into()),
                passing_mode: FormalParameterPassingMode::PositionalOnly,
            },
            SemanticValueKind::Parameter {
                ordinal: 1,
                multiplicity: FormalMultiplicity::Rest(ArgumentDomain::LanguageDefined(
                    "splat".into(),
                )),
                name: None,
                passing_mode: FormalParameterPassingMode::NamedOnly,
            },
            SemanticValueKind::DefaultArgument { ordinal: 2 },
            SemanticValueKind::Receiver { dispatch: true },
            SemanticValueKind::Return,
            SemanticValueKind::Temporary,
            SemanticValueKind::Address,
            SemanticValueKind::Null,
            SemanticValueKind::Boolean(false),
            SemanticValueKind::UnsignedInteger(u128::MAX),
            SemanticValueKind::SignedInteger(i128::MIN),
            // The sign bit is set, so the stored INTEGER is negative.
            SemanticValueKind::FloatingPoint {
                bits: (-0.5_f64).to_bits(),
            },
            SemanticValueKind::Constant,
            // The same text as the rest domain above: one interned text row.
            SemanticValueKind::ConstantString("splat".into()),
            SemanticValueKind::Exception,
            SemanticValueKind::Callable,
            SemanticValueKind::AwaitResult,
            SemanticValueKind::LanguageDefined("symbol".into()),
            SemanticValueKind::Parameter {
                ordinal: 3,
                multiplicity: FormalMultiplicity::Rest(ArgumentDomain::Keyword),
                name: Some("kwargs".into()),
                passing_mode: FormalParameterPassingMode::PositionalOrNamed,
            },
            SemanticValueKind::Receiver { dispatch: false },
            SemanticValueKind::ConstantString("  padded \t".into()),
            SemanticValueKind::ConstantString("   ".into()),
        ];
        p0.values = value_kinds
            .into_iter()
            .enumerate()
            .map(|(index, kind)| SemanticValue {
                id: v(u32::try_from(index).unwrap()),
                kind,
                source: sm(u32::try_from(index).unwrap() % 3),
                evidence: ev(2),
            })
            .collect();
        p0.allocations = [
            AllocationKind::Object,
            AllocationKind::Array,
            AllocationKind::Slice,
            AllocationKind::Callable,
            AllocationKind::ClosureEnvironment,
            AllocationKind::SharedCell,
            AllocationKind::LanguageDefined("arena".into()),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, kind)| {
            let index = u32::try_from(index).unwrap();
            AllocationSite {
                id: alloc(index),
                point: pt(1),
                result: v(6 + index),
                kind,
                source: sm(1),
                evidence: ev(2),
            }
        })
        .collect();
        p0.memory_locations = [
            (
                MemoryLocationKind::Field {
                    base: v(0),
                    member: field.clone(),
                },
                MemoryValueCopy::Unknown,
            ),
            (
                MemoryLocationKind::Property {
                    base: v(4),
                    key: "key".to_owned(),
                },
                MemoryValueCopy::Value,
            ),
            (
                MemoryLocationKind::Static {
                    member: field.clone(),
                },
                MemoryValueCopy::Reference,
            ),
            (
                MemoryLocationKind::Index {
                    base: v(0),
                    index: Some(v(10)),
                    constant_index: Some(u128::MAX),
                    identity: IndexedLocationIdentity::Element,
                },
                MemoryValueCopy::BackingStore {
                    identity: IndexedLocationIdentity::Aggregate,
                },
            ),
            (
                MemoryLocationKind::Index {
                    base: v(4),
                    index: None,
                    constant_index: None,
                    identity: IndexedLocationIdentity::Aggregate,
                },
                MemoryValueCopy::BackingStore {
                    identity: IndexedLocationIdentity::Element,
                },
            ),
            (
                MemoryLocationKind::Dereference { address: v(7) },
                MemoryValueCopy::Unknown,
            ),
            (
                MemoryLocationKind::LexicalCell { binding: v(0) },
                MemoryValueCopy::Unknown,
            ),
            (
                MemoryLocationKind::Capture {
                    lexical_parent: ProcedureId::new(2),
                    binding: Some(v(1)),
                },
                MemoryValueCopy::Unknown,
            ),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, (kind, value_copy))| MemoryLocation {
            id: mem(u32::try_from(index).unwrap()),
            kind,
            value_copy,
            source: sm(1),
            evidence: ev(2),
        })
        .collect();
        p0.captures = [
            (CaptureSource::Value(v(0)), CaptureMode::Value),
            (CaptureSource::Location(mem(6)), CaptureMode::Move),
            (CaptureSource::Value(v(1)), CaptureMode::SharedCell),
            (CaptureSource::Location(mem(5)), CaptureMode::MutableCell),
            (CaptureSource::Value(v(4)), CaptureMode::Receiver),
            (
                CaptureSource::Value(v(0)),
                CaptureMode::LanguageDefined("borrow".into()),
            ),
            (CaptureSource::Value(v(0)), CaptureMode::Unknown),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, (captured, mode))| {
            let index = u32::try_from(index).unwrap();
            CaptureBinding {
                id: CaptureId::new(index),
                point: pt(3),
                callable: v(16),
                target: ProcedureId::new(1),
                environment: alloc(4),
                captured,
                destination: mem(7 - index % 2),
                mode,
                source: sm(1),
                evidence: ev(2),
            }
        })
        .collect();
        let mut first_call = call_site(
            0,
            ExecutionTiming::SameEvaluation,
            CallInvocationMode::Ordinary,
            CallableTargetResolution::Proven(CallableTarget::Local(ProcedureId::new(1))),
            ControlContinuation::Target(pt(4)),
            ControlContinuation::Absent,
            vec![
                argument(0, CallArgumentExpansion::Unclassified, None),
                argument(
                    1,
                    CallArgumentExpansion::Direct(ArgumentDomain::Positional),
                    None,
                ),
                argument(
                    2,
                    CallArgumentExpansion::Direct(ArgumentDomain::Keyword),
                    Some("named"),
                ),
                argument(
                    3,
                    CallArgumentExpansion::Spread(ArgumentDomain::PositionalOrKeyword),
                    None,
                ),
                argument(
                    18,
                    CallArgumentExpansion::Spread(ArgumentDomain::LanguageDefined("splat".into())),
                    Some("rest"),
                ),
            ],
            vec![v(5)],
        );
        first_call.receiver = Some(v(4));
        first_call.result = Some(v(6));
        first_call.thrown = Some(v(15));
        p0.call_sites = vec![
            first_call,
            call_site(
                1,
                ExecutionTiming::DifferentThread,
                CallInvocationMode::Detached,
                CallableTargetResolution::Ambiguous(
                    vec![
                        CallableTarget::Unmaterialized(closure_procedure.clone()),
                        CallableTarget::External(external.clone()),
                        artifact_target(),
                    ]
                    .into(),
                ),
                ControlContinuation::Unknown,
                ControlContinuation::Unsupported,
                vec![argument(
                    0,
                    CallArgumentExpansion::Direct(ArgumentDomain::PositionalOrKeyword),
                    None,
                )],
                vec![v(5), v(6)],
            ),
            call_site(
                2,
                ExecutionTiming::Unknown,
                CallInvocationMode::Ordinary,
                CallableTargetResolution::Unknown,
                ControlContinuation::Unproven,
                ControlContinuation::ExceededBudget,
                Vec::new(),
                Vec::new(),
            ),
            call_site(
                3,
                ExecutionTiming::GeneratorResume,
                CallInvocationMode::Ordinary,
                CallableTargetResolution::Unsupported,
                ControlContinuation::Absent,
                ControlContinuation::Target(pt(2)),
                Vec::new(),
                Vec::new(),
            ),
            call_site(
                4,
                ExecutionTiming::LaterSameTurn,
                CallInvocationMode::Detached,
                CallableTargetResolution::Unproven(
                    vec![CallableTarget::Local(ProcedureId::new(0))].into(),
                ),
                ControlContinuation::Target(pt(4)),
                ControlContinuation::Target(pt(2)),
                Vec::new(),
                Vec::new(),
            ),
            call_site(
                5,
                ExecutionTiming::CancellationCleanup,
                CallInvocationMode::Ordinary,
                CallableTargetResolution::ExceededBudget(
                    vec![CallableTarget::External(external.clone())].into(),
                ),
                ControlContinuation::ExceededBudget,
                ControlContinuation::Unknown,
                Vec::new(),
                Vec::new(),
            ),
        ];
        for (index, place, depth) in [
            (
                0,
                Some(SemanticPlace::LocalBinding(binding.clone())),
                Some(0),
            ),
            (1, Some(SemanticPlace::MemoryLocation(mem(0))), Some(1)),
            (2, None, Some(0)),
            (3, None, None),
        ] {
            p0.call_sites[index].receiver = Some(v(4));
            p0.call_sites[index].member_selection = Some(Box::new(DeferredMemberSelection {
                member: "selected_member".into(),
                receiver_place: place,
                receiver_pointer_depth: depth,
            }));
        }
        p0.source_mappings = vec![
            SourceMapping {
                id: sm(0),
                locator: outer_procedure.clone(),
                kind: SourceMappingKind::Exact,
                ast_identity: Some(StructuralNodeIdentity::new(content, 7)),
            },
            SourceMapping {
                id: sm(1),
                locator: mapping,
                kind: SourceMappingKind::Enclosing,
                ast_identity: None,
            },
            SourceMapping {
                id: sm(2),
                locator: binding.clone(),
                kind: SourceMappingKind::Synthetic,
                ast_identity: Some(StructuralNodeIdentity::new(content, u32::MAX)),
            },
        ];
        p0.statement_entries = vec![
            StatementEntrySite {
                source: sm(1),
                evidence: ev(2),
                point: pt(0),
            },
            StatementEntrySite {
                source: sm(2),
                evidence: ev(0),
                point: pt(3),
            },
        ];
        p0.loop_sites = vec![LoopSite {
            source: sm(1),
            evidence: ev(2),
            header: pt(2),
            body: pt(3),
        }];
        p0.evidence_rows = vec![
            Evidence {
                id: ev(0),
                proof: ProofStatus::Proven,
                completeness: EvidenceCompleteness::Complete,
                sources: Box::new([]),
            },
            Evidence {
                id: ev(1),
                proof: ProofStatus::Unproven("unproven reason".into()),
                completeness: EvidenceCompleteness::Partial("partial reason".into()),
                sources: vec![sm(0), sm(2)].into(),
            },
            Evidence {
                id: ev(2),
                proof: ProofStatus::Proven,
                completeness: EvidenceCompleteness::Partial("partial reason".into()),
                sources: vec![sm(1)].into(),
            },
        ];
        let every_impact = SemanticGapImpact::ALL
            .into_iter()
            .fold(SemanticGapImpacts::NONE, SemanticGapImpacts::with);
        let some_impacts = SemanticGapImpacts::single(SemanticGapImpact::ValueFlow)
            .with(SemanticGapImpact::HeapWrite);
        p0.gaps = vec![
            gap(
                0,
                SemanticGapSubject::Procedure,
                SemanticCapability::Procedures,
                SemanticGapImpacts::NONE,
                SemanticGapKind::Ambiguous,
                None,
                SemanticGapDischarge::None,
            ),
            gap(
                1,
                SemanticGapSubject::Point,
                SemanticCapability::SwitchFacts,
                every_impact,
                SemanticGapKind::ExceededBudget,
                Some(SemanticBudgetExceeded::new(
                    SemanticBudgetDimension::OwnedTextBytes,
                    7,
                    usize::try_from(i64::MAX).unwrap(),
                )),
                SemanticGapDischarge::ResidualConversion,
            ),
            gap(
                2,
                SemanticGapSubject::Value(v(1)),
                SemanticCapability::Values,
                some_impacts,
                SemanticGapKind::Unknown,
                None,
                SemanticGapDischarge::CallResolution,
            ),
            gap(
                3,
                SemanticGapSubject::MemoryLocation(mem(3)),
                SemanticCapability::IndexMemory,
                some_impacts,
                SemanticGapKind::Unsupported,
                None,
                SemanticGapDischarge::CanonicalIndexIdentity,
            ),
            gap(
                4,
                SemanticGapSubject::Capture(CaptureId::new(2)),
                SemanticCapability::Captures,
                every_impact,
                SemanticGapKind::Unproven,
                None,
                SemanticGapDischarge::InertDropGlue,
            ),
            gap(
                5,
                SemanticGapSubject::CallSite(call(1)),
                SemanticCapability::Calls,
                some_impacts,
                SemanticGapKind::Ambiguous,
                None,
                SemanticGapDischarge::None,
            ),
            gap(
                6,
                SemanticGapSubject::CallContinuation {
                    call_site: call(0),
                    kind: CallContinuationKind::Exceptional,
                },
                SemanticCapability::ExceptionalCallContinuation,
                some_impacts,
                SemanticGapKind::Unknown,
                None,
                SemanticGapDischarge::None,
            ),
            gap(
                7,
                SemanticGapSubject::AsyncContinuation {
                    suspend: pt(3),
                    kind: AsyncResumeKind::Exceptional,
                },
                SemanticCapability::AsyncSuspendResume,
                some_impacts,
                SemanticGapKind::Unknown,
                None,
                SemanticGapDischarge::None,
            ),
        ];
        p0.blocks = vec![
            BasicBlock {
                id: BlockId::new(0),
                points: vec![pt(0), pt(1)].into(),
                source: sm(1),
                evidence: ev(2),
            },
            BasicBlock {
                id: BlockId::new(1),
                points: vec![pt(2), pt(3), pt(4)].into(),
                source: sm(2),
                evidence: ev(0),
            },
            BasicBlock {
                id: BlockId::new(2),
                points: Box::new([]),
                source: sm(1),
                evidence: ev(2),
            },
        ];
        let digest_a = StableDigest::sha256("conversion");
        let digest_b = StableDigest::sha256("adaptation");
        let point_0 = vec![
            event(SemanticEffect::Entry),
            event(SemanticEffect::Assignment {
                target: v(0),
                value: v(1),
            }),
            event(SemanticEffect::AggregateInitializer {
                aggregate: v(0),
                selector: field.clone(),
                value: v(1),
            }),
            flow(transfer(TransferKind::Copy, TransferOperation::None), 1, 0),
            flow(
                transfer(
                    TransferKind::AggregateCopy,
                    TransferOperation::CallSite(call(1)),
                ),
                2,
                0,
            ),
            flow(
                transfer(
                    TransferKind::Move {
                        invalidation: MoveInvalidation::Invalidated,
                    },
                    TransferOperation::CallArgumentConversion(digest_a),
                ),
                3,
                0,
            ),
            flow(
                transfer(
                    TransferKind::Move {
                        invalidation: MoveInvalidation::Unknown,
                    },
                    TransferOperation::ValueCarrierAdaptation(digest_b),
                ),
                4,
                0,
            ),
            flow(
                transfer(
                    TransferKind::Conversion {
                        preservation: ValuePreservation::Identity,
                    },
                    TransferOperation::Unknown,
                ),
                5,
                0,
            ),
            flow(
                transfer(
                    TransferKind::Conversion {
                        preservation: ValuePreservation::Preserving,
                    },
                    TransferOperation::None,
                ),
                6,
                0,
            ),
            flow(
                transfer(
                    TransferKind::Conversion {
                        preservation: ValuePreservation::Changing,
                    },
                    TransferOperation::None,
                ),
                7,
                0,
            ),
            flow(
                transfer(TransferKind::Boxing, TransferOperation::None),
                8,
                0,
            ),
            flow(
                transfer(TransferKind::Unboxing, TransferOperation::None),
                9,
                0,
            ),
            flow(
                ValueFlowKind::BackingStore {
                    offset: BackingStoreOffset::Zero,
                },
                10,
                0,
            ),
            flow(
                ValueFlowKind::BackingStore {
                    offset: BackingStoreOffset::Constant(u128::MAX),
                },
                11,
                0,
            ),
            flow(
                ValueFlowKind::BackingStore {
                    offset: BackingStoreOffset::Value(v(10)),
                },
                12,
                0,
            ),
            flow(
                ValueFlowKind::IntegerOffset {
                    offset: SignedIntegerMagnitude::new(true, 5),
                },
                13,
                0,
            ),
            flow(
                ValueFlowKind::IntegerOffset {
                    offset: SignedIntegerMagnitude::new(false, u128::MAX),
                },
                14,
                0,
            ),
            flow(
                ValueFlowKind::BackingStoreAlternative {
                    offset: BackingStoreOffset::Constant(3),
                    allocation: alloc(1),
                },
                15,
                0,
            ),
            flow(
                ValueFlowKind::BackingStoreAlternative {
                    offset: BackingStoreOffset::Value(v(11)),
                    allocation: alloc(2),
                },
                16,
                0,
            ),
            flow(ValueFlowKind::IndexedReturn { ordinal: 2 }, 17, 5),
            flow(ValueFlowKind::Local, 0, 6),
            flow(ValueFlowKind::Parameter, 1, 6),
            flow(ValueFlowKind::Receiver, 4, 6),
            flow(ValueFlowKind::Return, 6, 5),
            flow(ValueFlowKind::ReferenceBoxing, 6, 7),
            flow(ValueFlowKind::ReferenceUnboxing, 7, 6),
            flow(ValueFlowKind::LanguageDefined, 18, 6),
        ];
        let point_1 = vec![
            event(SemanticEffect::ValueUse {
                kind: ValueUseKind::Dereference,
                value: v(7),
            }),
            event(SemanticEffect::ValueUse {
                kind: ValueUseKind::Unbind,
                value: v(0),
            }),
            event(SemanticEffect::Allocation {
                allocation: alloc(0),
            }),
            event(SemanticEffect::MemoryLoad {
                kind: MemoryAccessKind::Field,
                location: mem(0),
                result: v(6),
            }),
            event(SemanticEffect::MemoryStore {
                kind: MemoryAccessKind::Property,
                location: mem(1),
                value: v(1),
            }),
            event(SemanticEffect::MemoryLoad {
                kind: MemoryAccessKind::Static,
                location: mem(2),
                result: v(6),
            }),
            event(SemanticEffect::MemoryStore {
                kind: MemoryAccessKind::Index,
                location: mem(3),
                value: v(2),
            }),
            event(SemanticEffect::MemoryLoad {
                kind: MemoryAccessKind::Dereference,
                location: mem(5),
                result: v(6),
            }),
            event(SemanticEffect::MemoryStore {
                kind: MemoryAccessKind::LexicalCell,
                location: mem(6),
                value: v(3),
            }),
            event(SemanticEffect::MemoryLoad {
                kind: MemoryAccessKind::Capture,
                location: mem(7),
                result: v(6),
            }),
            event(SemanticEffect::Synchronization {
                operation: SynchronizationOperation::ChannelSend,
                subject: v(16),
                payload: Some(SynchronizationPayload::Send {
                    value: v(1),
                    copy: SynchronizationPayloadCopy::Unknown,
                }),
            }),
            event(SemanticEffect::Synchronization {
                operation: SynchronizationOperation::ChannelSend,
                subject: v(16),
                payload: Some(SynchronizationPayload::Send {
                    value: v(2),
                    copy: SynchronizationPayloadCopy::Reference,
                }),
            }),
            event(SemanticEffect::Synchronization {
                operation: SynchronizationOperation::ChannelSend,
                subject: v(16),
                payload: Some(SynchronizationPayload::Send {
                    value: v(3),
                    copy: SynchronizationPayloadCopy::BackingStore {
                        identity: IndexedLocationIdentity::Element,
                    },
                }),
            }),
            event(SemanticEffect::Synchronization {
                operation: SynchronizationOperation::ChannelReceive,
                subject: v(16),
                payload: Some(SynchronizationPayload::Receive { result: v(6) }),
            }),
            event(SemanticEffect::Synchronization {
                operation: SynchronizationOperation::ChannelClose,
                subject: v(16),
                payload: None,
            }),
        ];
        let point_2 = vec![
            event(SemanticEffect::CallableCreation {
                result: v(16),
                callable: callable(
                    CallableReferenceKind::Lambda,
                    CallableTargetResolution::Proven(CallableTarget::Local(ProcedureId::new(1))),
                    None,
                    Some(alloc(4)),
                ),
            }),
            event(SemanticEffect::CallableReference {
                result: v(16),
                callable: callable(
                    CallableReferenceKind::Function,
                    CallableTargetResolution::Unknown,
                    None,
                    None,
                ),
            }),
            event(SemanticEffect::CallableReference {
                result: v(16),
                callable: callable(
                    CallableReferenceKind::BoundMethod,
                    CallableTargetResolution::Ambiguous(
                        vec![
                            CallableTarget::External(external.clone()),
                            artifact_target(),
                        ]
                        .into(),
                    ),
                    Some(v(4)),
                    None,
                ),
            }),
            event(SemanticEffect::CallableReference {
                result: v(16),
                callable: callable(
                    CallableReferenceKind::UnboundMethod,
                    CallableTargetResolution::Unsupported,
                    None,
                    None,
                ),
            }),
            event(SemanticEffect::CallableReference {
                result: v(16),
                callable: callable(
                    CallableReferenceKind::ModuleQualified { qualifier: v(13) },
                    CallableTargetResolution::Unproven(
                        vec![CallableTarget::Unmaterialized(closure_procedure.clone())].into(),
                    ),
                    None,
                    None,
                ),
            }),
            event(SemanticEffect::CallableReference {
                result: v(16),
                callable: callable(
                    CallableReferenceKind::TypeQualifiedMethod { qualifier: v(14) },
                    CallableTargetResolution::ExceededBudget(
                        vec![CallableTarget::Local(ProcedureId::new(0))].into(),
                    ),
                    Some(v(0)),
                    Some(alloc(5)),
                ),
            }),
            event(SemanticEffect::CallableCreation {
                result: v(16),
                callable: callable(
                    CallableReferenceKind::StaticMethod,
                    CallableTargetResolution::Unknown,
                    None,
                    None,
                ),
            }),
            event(SemanticEffect::CallableCreation {
                result: v(16),
                callable: callable(
                    CallableReferenceKind::Constructor,
                    CallableTargetResolution::Unknown,
                    None,
                    None,
                ),
            }),
        ];
        let point_3 = vec![
            event(SemanticEffect::CaptureBind {
                capture: CaptureId::new(0),
            }),
            event(SemanticEffect::Invoke { call_site: call(0) }),
            event(SemanticEffect::CallContinuation {
                call_site: call(0),
                kind: CallContinuationKind::Normal,
            }),
            event(SemanticEffect::CallContinuation {
                call_site: call(1),
                kind: CallContinuationKind::Exceptional,
            }),
            event(SemanticEffect::AsyncSuspend {
                awaited: Some(v(17)),
                normal_resume: ControlContinuation::Target(pt(4)),
                exceptional_resume: ControlContinuation::Absent,
            }),
            event(SemanticEffect::AsyncSuspend {
                awaited: None,
                normal_resume: ControlContinuation::Unknown,
                exceptional_resume: ControlContinuation::Unsupported,
            }),
            event(SemanticEffect::AsyncSuspend {
                awaited: None,
                normal_resume: ControlContinuation::Unproven,
                exceptional_resume: ControlContinuation::ExceededBudget,
            }),
            event(SemanticEffect::AsyncResume {
                suspend: pt(3),
                kind: AsyncResumeKind::Normal,
                result: Some(v(17)),
            }),
            event(SemanticEffect::AsyncResume {
                suspend: pt(2),
                kind: AsyncResumeKind::Exceptional,
                result: None,
            }),
            event(SemanticEffect::Gap {
                gap: SemanticGapId::new(3),
            }),
            event(SemanticEffect::ProcedureReturn { value: Some(v(5)) }),
            event(SemanticEffect::ProcedureReturn { value: None }),
            event(SemanticEffect::Throw { value: Some(v(15)) }),
            event(SemanticEffect::Throw { value: None }),
            event(SemanticEffect::NormalExit),
            event(SemanticEffect::ExceptionalExit),
        ];
        p0.points = [point_0, point_1, point_2, point_3, Vec::new()]
            .into_iter()
            .enumerate()
            .map(|(index, events)| {
                let index = u32::try_from(index).unwrap();
                ProgramPoint {
                    id: pt(index),
                    block: BlockId::new(u32::from(index >= 2)),
                    events: events.into(),
                    source: sm(index % 3),
                    evidence: ev(2),
                }
            })
            .collect();
        p0.control_edges = [
            (0, 1, ControlEdgeKind::Normal),
            (1, 2, ControlEdgeKind::ConditionalTrue),
            (1, 3, ControlEdgeKind::ConditionalFalse),
            (1, 4, ControlEdgeKind::SwitchCase),
            (3, 2, ControlEdgeKind::LoopBack),
            (3, 4, ControlEdgeKind::Exceptional),
            (3, 4, ControlEdgeKind::Cleanup),
            (2, 3, ControlEdgeKind::AsyncNormal),
            (2, 4, ControlEdgeKind::AsyncExceptional),
        ]
        .into_iter()
        .map(|(source, target, kind)| ControlEdge {
            source_point: pt(source),
            target_point: pt(target),
            kind,
            source: sm(1),
            evidence: ev(2),
        })
        .collect();
        p0.guard_facts = vec![
            guard(
                0,
                Some(v(0)),
                GuardPredicate::ConstantBoolean { value: true },
                Some(arm(2, ControlEdgeKind::ConditionalTrue)),
                Some(arm(3, ControlEdgeKind::ConditionalFalse)),
            ),
            guard(
                1,
                None,
                GuardPredicate::NullComparison {
                    null_on_true: false,
                },
                None,
                None,
            ),
            guard(
                2,
                Some(v(0)),
                GuardPredicate::ConstantEquality {
                    negated: true,
                    constant: v(8),
                },
                Some(arm(2, ControlEdgeKind::ConditionalTrue)),
                None,
            ),
            guard(
                3,
                Some(v(10)),
                GuardPredicate::OrderedIntegerComparison {
                    relation: IntegerComparison::GreaterThanOrEqual,
                    constant: v(10),
                },
                None,
                Some(arm(3, ControlEdgeKind::ConditionalFalse)),
            ),
            guard(
                4,
                Some(v(12)),
                GuardPredicate::OrderedFloatComparison {
                    relation: IntegerComparison::LessThan,
                    constant: v(12),
                },
                None,
                None,
            ),
            guard(
                5,
                Some(v(12)),
                GuardPredicate::NanComparison { nan_on_true: true },
                None,
                None,
            ),
            guard(
                6,
                Some(v(0)),
                GuardPredicate::InstanceOf {
                    value: v(0),
                    classes: v(13),
                },
                None,
                None,
            ),
            guard(
                7,
                Some(v(0)),
                GuardPredicate::ExactClass {
                    value: v(0),
                    classes: v(13),
                    exact_on_true: false,
                },
                None,
                None,
            ),
            guard(
                8,
                Some(v(0)),
                GuardPredicate::HasMember {
                    value: v(0),
                    member: v(14),
                },
                None,
                None,
            ),
            guard(
                9,
                Some(v(9)),
                GuardPredicate::Truthy { value: v(9) },
                None,
                None,
            ),
            // The high bit is set, so the stored INTEGER is negative.
            guard(
                10,
                None,
                GuardPredicate::Opaque {
                    digest: GuardConditionDigest::from_bits(u64::MAX - 1),
                },
                None,
                None,
            ),
        ];
        let switch_edge = |source: u32, target: u32, kind| SwitchEdgeParts {
            source_point: pt(source),
            arm: arm(target, kind),
        };
        p0.switch_facts = vec![
            SwitchFactParts {
                id: SwitchFactId::new(0),
                kind: SwitchFactKind::Expression,
                point: pt(1),
                selector: Some(v(0)),
                selector_domain: SwitchSelectorDomain::Open,
                cases: vec![
                    SwitchCaseFactParts {
                        value: v(10),
                        edge: switch_edge(1, 2, ControlEdgeKind::SwitchCase),
                    },
                    SwitchCaseFactParts {
                        value: v(11),
                        edge: switch_edge(1, 3, ControlEdgeKind::SwitchCase),
                    },
                ],
                default_edge: Some(switch_edge(1, 4, ControlEdgeKind::Normal)),
                default_present: true,
                source: sm(1),
                evidence: ev(2),
            },
            SwitchFactParts {
                id: SwitchFactId::new(1),
                kind: SwitchFactKind::Expressionless,
                point: pt(2),
                selector: None,
                selector_domain: SwitchSelectorDomain::Boolean,
                cases: Vec::new(),
                default_edge: None,
                default_present: false,
                source: sm(1),
                evidence: ev(2),
            },
            SwitchFactParts {
                id: SwitchFactId::new(2),
                kind: SwitchFactKind::Type,
                point: pt(3),
                selector: Some(v(4)),
                selector_domain: SwitchSelectorDomain::Open,
                cases: vec![SwitchCaseFactParts {
                    value: v(13),
                    edge: switch_edge(3, 4, ControlEdgeKind::SwitchCase),
                }],
                default_edge: None,
                default_present: true,
                source: sm(2),
                evidence: ev(0),
            },
        ];
        let local = SemanticPlace::LocalBinding(binding.clone());
        p0.drops = vec![
            DropFact {
                place: local.clone(),
                point: pt(4),
                behavior: DropBehavior::Trivial,
                source: sm(1),
                evidence: ev(2),
            },
            DropFact {
                place: SemanticPlace::MemoryLocation(mem(0)),
                point: pt(4),
                behavior: DropBehavior::Destructor(CallableTargetResolution::Proven(
                    CallableTarget::Local(ProcedureId::new(1)),
                )),
                source: sm(1),
                evidence: ev(2),
            },
            DropFact {
                place: SemanticPlace::MemoryLocation(mem(1)),
                point: pt(3),
                behavior: DropBehavior::Destructor(CallableTargetResolution::Unknown),
                source: sm(1),
                evidence: ev(2),
            },
            DropFact {
                place: local.clone(),
                point: pt(4),
                behavior: DropBehavior::Destructor(CallableTargetResolution::Ambiguous(
                    vec![
                        CallableTarget::External(external.clone()),
                        CallableTarget::Local(ProcedureId::new(0)),
                    ]
                    .into(),
                )),
                source: sm(1),
                evidence: ev(2),
            },
        ];
        p0.move_outs = [
            (local.clone(), MoveOutState::Uninitialized),
            (
                SemanticPlace::MemoryLocation(mem(2)),
                MoveOutState::PartiallyInitialized,
            ),
            (local.clone(), MoveOutState::Unknown),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, (place, state_after))| {
            let index = u32::try_from(index).unwrap();
            MoveOutFact {
                place,
                point: pt(index + 1),
                source_value: v(index),
                target_value: v(index + 5),
                state_after,
                source: sm(1),
                evidence: ev(2),
            }
        })
        .collect();
        p0.scope_ends = vec![
            ScopeEndFact {
                place: local.clone(),
                at: ScopeEndAt::Point(pt(4)),
                source: sm(1),
                evidence: ev(2),
            },
            ScopeEndFact {
                place: SemanticPlace::MemoryLocation(mem(6)),
                at: ScopeEndAt::Edge {
                    source_point: pt(3),
                    target_point: pt(4),
                    kind: ControlEdgeKind::Cleanup,
                },
                source: sm(2),
                evidence: ev(0),
            },
        ];
        p0.pointer_origins = vec![
            PointerOrigin {
                id: PointerOriginId::new(0),
                point: pt(1),
                kind: PointerOriginKind::StackPlace {
                    place: local.clone(),
                },
                byte_extent: Some(u128::MAX),
                source: sm(1),
                evidence: ev(2),
            },
            PointerOrigin {
                id: PointerOriginId::new(1),
                point: pt(1),
                kind: PointerOriginKind::StackPlace {
                    place: SemanticPlace::MemoryLocation(mem(3)),
                },
                byte_extent: None,
                source: sm(1),
                evidence: ev(2),
            },
            PointerOrigin {
                id: PointerOriginId::new(2),
                point: pt(2),
                kind: PointerOriginKind::Allocation {
                    allocation: alloc(0),
                },
                byte_extent: Some(16),
                source: sm(1),
                evidence: ev(2),
            },
        ];
        p0.pointer_aliases = [
            (
                0,
                PointerByteOffset::Exact(i128::MIN),
                PointerRelationStrength::Must,
            ),
            (
                1,
                PointerByteOffset::Value(v(10)),
                PointerRelationStrength::May,
            ),
            (
                2,
                PointerByteOffset::Range {
                    minimum: -5,
                    maximum: i128::MAX,
                },
                PointerRelationStrength::Must,
            ),
            (0, PointerByteOffset::Unknown, PointerRelationStrength::May),
        ]
        .into_iter()
        .map(|(origin, byte_offset, strength)| PointerAlias {
            point: pt(2),
            pointer: v(7),
            origin: PointerOriginId::new(origin),
            byte_offset,
            strength,
            source: sm(1),
            evidence: ev(2),
        })
        .collect();
        p0.pointer_accesses = [
            (
                PointerAccessKind::Read,
                PointerAccessWidth::Exact(u128::MAX),
            ),
            (
                PointerAccessKind::Write,
                PointerAccessWidth::ValueTimes {
                    value: v(10),
                    multiplier: 8,
                },
            ),
            (PointerAccessKind::ReadWrite, PointerAccessWidth::Unknown),
        ]
        .into_iter()
        .map(|(kind, width)| PointerAccess {
            point: pt(2),
            pointer: v(7),
            kind,
            width,
            source: sm(1),
            evidence: ev(2),
        })
        .collect();
        p0.pointer_invalidations = [
            (
                PointerInvalidationTarget::Pointer(v(7)),
                PointerInvalidationCause::Deallocated,
                PointerRelationStrength::Must,
            ),
            (
                PointerInvalidationTarget::Origin(PointerOriginId::new(1)),
                PointerInvalidationCause::OwnerDropped,
                PointerRelationStrength::May,
            ),
            (
                PointerInvalidationTarget::Origin(PointerOriginId::new(2)),
                PointerInvalidationCause::OwnershipTransferred,
                PointerRelationStrength::Must,
            ),
            (
                PointerInvalidationTarget::Pointer(v(8)),
                PointerInvalidationCause::PossibleReallocation,
                PointerRelationStrength::May,
            ),
        ]
        .into_iter()
        .map(|(target, cause, strength)| PointerInvalidation {
            point: pt(3),
            target,
            cause,
            strength,
            source: sm(1),
            evidence: ev(2),
        })
        .collect();
        p0.incomplete_facts = [
            (
                SemanticIncompleteSubject::Procedure,
                SemanticIncompleteReason::Lifecycle(
                    LifecycleIncompleteReason::UnsupportedMacroExpansion,
                ),
            ),
            (
                SemanticIncompleteSubject::Place(local.clone()),
                SemanticIncompleteReason::Lifecycle(
                    LifecycleIncompleteReason::AsyncCancellationState,
                ),
            ),
            (
                SemanticIncompleteSubject::Place(SemanticPlace::MemoryLocation(mem(5))),
                SemanticIncompleteReason::Pointer(PointerIncompleteReason::RawPointerType),
            ),
            (
                SemanticIncompleteSubject::Value(v(7)),
                SemanticIncompleteReason::Pointer(PointerIncompleteReason::OffsetOverflow),
            ),
            (
                SemanticIncompleteSubject::PointerOrigin(PointerOriginId::new(2)),
                SemanticIncompleteReason::Pointer(PointerIncompleteReason::AmbiguousAlias),
            ),
        ]
        .into_iter()
        .map(|(subject, reason)| SemanticIncompleteFact {
            point: pt(2),
            subject,
            reason,
            source: sm(1),
            evidence: ev(2),
        })
        .collect();
        p0.receiver_type_facts = vec![
            CallReceiverTypeFact {
                call_site: call(0),
                receiver_type: vec!["std".into(), "vec".into(), "Vec".into()].into(),
                member: "push".into(),
            },
            CallReceiverTypeFact {
                call_site: call(1),
                receiver_type: Box::new([]),
                member: "len".into(),
            },
        ];
        p0.go_predeclared_builtin_assumptions = vec![
            GoPredeclaredBuiltin::Len,
            GoPredeclaredBuiltin::Append,
            GoPredeclaredBuiltin::Len,
        ];

        // The closure reuses procedure 0's keys: target group 0, event
        // (point 0, ordinal 3) with a transfer side row, and value ids.
        let mut p1 = ProcedureSemanticsParts::new(
            ProcedureId::new(1),
            closure_procedure.clone(),
            ProcedureKind::Closure,
            sm(0),
            ev(0),
        );
        p1.lexical_parent = Some(ProcedureId::new(0));
        p1.properties = ProcedureProperties {
            is_async: false,
            is_generator: true,
            is_static: false,
            is_synthetic: true,
            ..ProcedureProperties::default()
        };
        p1.values = vec![
            SemanticValue {
                id: v(0),
                kind: SemanticValueKind::Local,
                source: sm(0),
                evidence: ev(0),
            },
            SemanticValue {
                id: v(1),
                kind: SemanticValueKind::Temporary,
                source: sm(0),
                evidence: ev(0),
            },
        ];
        p1.memory_locations = vec![
            MemoryLocation {
                id: mem(0),
                kind: MemoryLocationKind::Capture {
                    lexical_parent: ProcedureId::new(0),
                    binding: Some(v(0)),
                },
                value_copy: MemoryValueCopy::Value,
                source: sm(0),
                evidence: ev(0),
            },
            MemoryLocation {
                id: mem(1),
                kind: MemoryLocationKind::Capture {
                    lexical_parent: ProcedureId::new(0),
                    binding: None,
                },
                value_copy: MemoryValueCopy::Unknown,
                source: sm(0),
                evidence: ev(0),
            },
        ];
        p1.call_sites = vec![SemanticCallSite {
            id: call(0),
            point: pt(0),
            invocation_mode: CallInvocationMode::Ordinary,
            execution_timing: ExecutionTiming::SameInvocation,
            callee: v(1),
            receiver: None,
            member_selection: None,
            arguments: vec![argument(
                0,
                CallArgumentExpansion::Direct(ArgumentDomain::Positional),
                None,
            )]
            .into(),
            normal_results: Box::new([]),
            result: Some(v(1)),
            thrown: None,
            declared_targets: CallableTargetResolution::Proven(CallableTarget::External(
                external.clone(),
            )),
            target_evidence: ev(0),
            normal_continuation: ControlContinuation::Target(pt(0)),
            exceptional_continuation: ControlContinuation::Absent,
            source: sm(0),
            evidence: ev(0),
        }];
        p1.source_mappings = vec![SourceMapping {
            id: sm(0),
            locator: closure_procedure.clone(),
            kind: SourceMappingKind::Exact,
            ast_identity: None,
        }];
        p1.evidence_rows = vec![Evidence {
            id: ev(0),
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Complete,
            sources: vec![sm(0)].into(),
        }];
        p1.blocks = vec![BasicBlock {
            id: BlockId::new(0),
            points: vec![pt(0)].into(),
            source: sm(0),
            evidence: ev(0),
        }];
        p1.points = vec![ProgramPoint {
            id: pt(0),
            block: BlockId::new(0),
            events: vec![
                SemanticEvent::new(SemanticEffect::Entry, sm(0), ev(0)),
                SemanticEvent::new(SemanticEffect::Invoke { call_site: call(0) }, sm(0), ev(0)),
                SemanticEvent::new(
                    SemanticEffect::CallableCreation {
                        result: v(1),
                        callable: callable(
                            CallableReferenceKind::Lambda,
                            CallableTargetResolution::Unproven(
                                vec![CallableTarget::Local(ProcedureId::new(0))].into(),
                            ),
                            None,
                            None,
                        ),
                    },
                    sm(0),
                    ev(0),
                ),
                SemanticEvent::new(
                    SemanticEffect::ValueFlow {
                        kind: transfer(TransferKind::Boxing, TransferOperation::CallSite(call(0))),
                        source: v(1),
                        target: v(0),
                    },
                    sm(0),
                    ev(0),
                ),
                SemanticEvent::new(SemanticEffect::NormalExit, sm(0), ev(0)),
            ]
            .into(),
            source: sm(0),
            evidence: ev(0),
        }];
        p1.go_predeclared_builtin_assumptions = vec![GoPredeclaredBuiltin::Cap];

        let mut p2 = ProcedureSemanticsParts::new(
            ProcedureId::new(2),
            locator(&path, &outer, SemanticRole::Procedure, anchor(300, 310, 0)),
            ProcedureKind::Operator,
            sm(3),
            ev(4),
        );
        p2.properties = ProcedureProperties {
            is_static: true,
            invocation: ProcedureInvocationKind::Deferred,
            ..ProcedureProperties::default()
        };
        let mut p3 = ProcedureSemanticsParts::new(
            ProcedureId::new(3),
            locator(
                &path,
                &closure,
                SemanticRole::Procedure,
                anchor(320, 330, 1),
            ),
            ProcedureKind::Accessor,
            sm(0),
            ev(0),
        );
        p3.lexical_parent = Some(ProcedureId::new(2));
        let p4 = ProcedureSemanticsParts::new(
            ProcedureId::new(4),
            locator(&path, &outer, SemanticRole::Procedure, anchor(340, 350, 0)),
            ProcedureKind::Method,
            sm(0),
            ev(0),
        );

        let receiver = PartialFlowPort::Receiver;
        let parameter = PartialFlowPort::Parameter { ordinal: 0 };
        let flows_0 = ProcedurePartialFlows {
            outcome: PartialFlowOutcome::Complete,
            detail: Some("unknown".to_owned()),
            ports: vec![
                receiver.clone(),
                parameter.clone(),
                PartialFlowPort::NormalReturn,
                PartialFlowPort::IndexedNormalReturn { ordinal: 1 },
                PartialFlowPort::ExceptionalReturn,
                PartialFlowPort::CallReceiver { call: call(0) },
                PartialFlowPort::CallArgument {
                    call: call(0),
                    ordinal: 2,
                },
                PartialFlowPort::CallResult {
                    call: call(0),
                    ordinal: None,
                },
                PartialFlowPort::CallResult {
                    call: call(1),
                    ordinal: Some(1),
                },
                PartialFlowPort::CallThrown { call: call(0) },
                PartialFlowPort::Capture { slot: mem(7) },
                PartialFlowPort::Heap {
                    root: Box::new(receiver),
                    selectors: vec![
                        HeapSelector::Field(field),
                        HeapSelector::Property("key".into()),
                        HeapSelector::ConstantIndex("3".into()),
                        HeapSelector::ExactIndex(v(10)),
                        HeapSelector::AnyIndex,
                    ]
                    .into(),
                    tail: AccessPathTail::Summary,
                },
                PartialFlowPort::Heap {
                    root: Box::new(parameter),
                    selectors: Box::new([]),
                    tail: AccessPathTail::Exact,
                },
                PartialFlowPort::CaptureOut {
                    target: ProcedureId::new(1),
                    destination: mem(0),
                },
            ],
            flows: vec![
                PartialFlow {
                    from: PortId::new(0),
                    to: PortId::new(2),
                    uncertain: false,
                    crossed: vec![Box::<[CallSiteId]>::default()].into(),
                },
                PartialFlow {
                    from: PortId::new(11),
                    to: PortId::new(7),
                    uncertain: true,
                    crossed: vec![
                        vec![call(0)].into_boxed_slice(),
                        vec![call(1), call(2)].into_boxed_slice(),
                    ]
                    .into(),
                },
                PartialFlow {
                    from: PortId::new(12),
                    to: PortId::new(13),
                    uncertain: false,
                    crossed: vec![vec![call(0)].into_boxed_slice()].into(),
                },
            ],
            open: true,
            relations_complete: true,
            discharged_gaps: vec![SemanticGapId::new(1), SemanticGapId::new(3)],
        };
        // A second procedure with ports, so a read of one procedure's ports
        // or flows that also took another's would be seen.
        let flows_1 = ProcedurePartialFlows {
            outcome: PartialFlowOutcome::Complete,
            detail: None,
            ports: vec![
                PartialFlowPort::Parameter { ordinal: 0 },
                PartialFlowPort::CallArgument {
                    call: call(0),
                    ordinal: 0,
                },
            ],
            flows: vec![PartialFlow {
                from: PortId::new(0),
                to: PortId::new(1),
                uncertain: false,
                crossed: vec![Box::<[CallSiteId]>::default()].into(),
            }],
            open: false,
            relations_complete: true,
            discharged_gaps: Vec::new(),
        };
        let empty_flows = |outcome, detail: Option<&str>| ProcedurePartialFlows {
            outcome,
            detail: detail.map(str::to_owned),
            ports: Vec::new(),
            flows: Vec::new(),
            open: false,
            relations_complete: false,
            discharged_gaps: Vec::new(),
        };
        Fixture {
            scope,
            parts: vec![p0, p1, p2, p3, p4],
            flows: vec![
                flows_0,
                flows_1,
                empty_flows(PartialFlowOutcome::Error, Some("projection failed")),
                empty_flows(PartialFlowOutcome::Truncated, None),
                empty_flows(PartialFlowOutcome::ExceededBudget, None),
            ],
        }
    }

    /// The fixture's parts as the decoder must return them: every Go builtin
    /// assumption of the blob, sorted and without duplicates, on procedure 0.
    pub(super) fn expected_decoded_parts(fixture: &Fixture) -> Vec<ProcedureSemanticsParts> {
        let mut parts = fixture.parts.clone();
        for procedure in &mut parts {
            procedure.go_predeclared_builtin_assumptions.clear();
        }
        parts[0].go_predeclared_builtin_assumptions = vec![
            GoPredeclaredBuiltin::Append,
            GoPredeclaredBuiltin::Cap,
            GoPredeclaredBuiltin::Len,
        ];
        parts
    }

    pub(super) fn prepare(fixture: &Fixture) -> PreparedSemanticIr {
        PreparedSemanticIr::prepare(
            SemanticIrLoweringOutcome::Complete {
                parts: fixture.parts.clone(),
            },
            Some(&fixture.flows),
            EPOCH,
            fixture.scope.content,
            SOURCE_BYTES,
        )
    }

    /// Insert one blob named by `seed` and its rows the way the blob writer
    /// does, under the active epoch.
    pub(super) fn insert(
        store: &AnalyzerStore,
        seed: &str,
        prepared: &PreparedSemanticIr,
    ) -> (Oid, i64) {
        store
            .ensure_semantic_ir_producer_epoch(LANG, EPOCH)
            .unwrap();
        let oid = Oid::hash_object(git2::ObjectType::Blob, seed.as_bytes()).unwrap();
        let mut conn = store.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, ?2, 1)",
            params![oid.to_string(), LANG],
        )
        .unwrap();
        let blob_id = conn.last_insert_rowid();
        let tx = conn.transaction().unwrap();
        assert!(
            super::super::insert_semantic_ir_tx(
                &tx,
                blob_id,
                LANG,
                prepared,
                &CancellationToken::default()
            )
            .unwrap()
        );
        tx.commit().unwrap();
        (oid, blob_id)
    }
}

/// The rows of every table and every variant read back as the procedures and
/// partial flows that were written, through the schema's CHECKs and JSONB
/// columns. The expected value is the input itself, except that the blob's Go
/// builtin assumptions come back sorted and deduplicated on procedure 0.
#[test]
fn semantic_ir_rows_round_trip_every_table_and_variant() {
    use super::{SemanticIrPublication, SemanticIrPublicationOutcome};
    use crate::analyzer::semantic::ProcedureId;
    use row_fixture::{SOURCE_BYTES, expected_decoded_parts, fixture, insert, prepare};

    let fixture = fixture();
    let prepared = prepare(&fixture);
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let (oid, blob_id) = insert(&store, "round trip", &prepared);

    assert_eq!(
        store
            .semantic_ir_publication(&brokk_bifrost_core::gitblob::BlobKey::unvaried(
                oid,
                row_fixture::LANG
            ))
            .unwrap(),
        Some(SemanticIrPublication {
            blob_id,
            content: fixture.scope.content,
            source_bytes: SOURCE_BYTES,
            outcome: SemanticIrPublicationOutcome::Complete,
        })
    );

    // The census the head's logical_rows is computed from matches what SQL
    // holds, and the fixture writes at least one row to every table.
    {
        let conn = store.conn.lock().unwrap();
        let mut child_rows = 0;
        for (table, rows, _) in prepared.table_census() {
            let stored: i64 = conn
                .query_row(
                    &format!("SELECT count(*) FROM {table} WHERE blob_id = ?1"),
                    [blob_id],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(usize::try_from(stored).unwrap(), rows, "{table}");
            assert!(rows > 0, "the fixture writes no {table} row");
            child_rows += rows;
        }
        let logical_rows: i64 = conn
            .query_row(
                "SELECT logical_rows FROM semantic_ir_publications WHERE blob_id = ?1",
                [blob_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(usize::try_from(logical_rows).unwrap(), 1 + child_rows);
        for statement in [
            "UPDATE semantic_ir_call_sites SET receiver_place_locator = 999 WHERE blob_id = ?1 AND procedure = 0 AND call_site = 0",
            "UPDATE semantic_ir_call_sites SET receiver_place_location = 999 WHERE blob_id = ?1 AND procedure = 0 AND call_site = 1",
        ] {
            assert!(
                conn.execute(statement, [blob_id]).is_err(),
                "receiver places must name stored parents: {statement}"
            );
        }
        assert_eq!(
            conn.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            0
        );
    }

    let decoded = store.read_semantic_ir(blob_id, &fixture.scope).unwrap();
    let expected = expected_decoded_parts(&fixture);
    assert_eq!(decoded.len(), expected.len());
    for (index, (decoded, expected)) in decoded.iter().zip(&expected).enumerate() {
        assert_eq!(
            format!("{decoded:#?}"),
            format!("{expected:#?}"),
            "procedure {index}"
        );
    }

    for (index, flows) in fixture.flows.iter().enumerate() {
        let procedure = ProcedureId::new(u32::try_from(index).unwrap());
        assert_eq!(
            store
                .read_partial_flows(blob_id, procedure, &fixture.scope)
                .unwrap()
                .as_ref(),
            Some(flows),
            "procedure {index}"
        );
    }
    assert_eq!(
        store
            .read_partial_flows(blob_id, ProcedureId::new(5), &fixture.scope)
            .unwrap(),
        None
    );

    let missing = store
        .read_semantic_ir(blob_id + 1, &fixture.scope)
        .unwrap_err();
    assert!(
        missing.to_string().contains(&format!(
            "semantic IR rows of blob {} are no longer published",
            blob_id + 1
        )),
        "{missing}"
    );
}

/// A head without child rows carries its outcome in its own columns: the
/// budget triple, the capability label, or the message.
#[test]
fn semantic_ir_publication_round_trips_every_head_only_outcome() {
    use super::{PreparedSemanticIr, SemanticIrLoweringOutcome, SemanticIrPublicationOutcome};
    use crate::analyzer::semantic::{
        ContentIdentity, SemanticBudgetDimension, SemanticBudgetExceeded, SemanticCapability,
    };

    let budget = SemanticBudgetExceeded::new(SemanticBudgetDimension::ControlEdges, 7, 9);
    let cases = [
        (
            SemanticIrLoweringOutcome::ExceededBudget(budget),
            SemanticIrPublicationOutcome::ExceededBudget(budget),
        ),
        (
            SemanticIrLoweringOutcome::Unsupported(SemanticCapability::SwitchFacts),
            SemanticIrPublicationOutcome::Unsupported(SemanticCapability::SwitchFacts),
        ),
        (
            SemanticIrLoweringOutcome::Incomplete { label: "ambiguous" },
            SemanticIrPublicationOutcome::Incomplete("ambiguous".to_owned()),
        ),
        (
            SemanticIrLoweringOutcome::Error("lowering failed: caf\u{e9}".to_owned()),
            SemanticIrPublicationOutcome::Error("lowering failed: caf\u{e9}".to_owned()),
        ),
        (
            SemanticIrLoweringOutcome::Panicked("index out of bounds".to_owned()),
            SemanticIrPublicationOutcome::Panicked("index out of bounds".to_owned()),
        ),
    ];
    let store = AnalyzerStore::open_ephemeral().unwrap();
    for (index, (outcome, expected)) in cases.into_iter().enumerate() {
        let content = ContentIdentity::hash_bytes(format!("head-only outcome {index}"));
        let prepared =
            PreparedSemanticIr::prepare(outcome, None, row_fixture::EPOCH, content, 10 + index);
        assert_eq!(prepared.logical_rows(), 1, "{expected:?}");
        let (oid, blob_id) = row_fixture::insert(&store, &format!("outcome {index}"), &prepared);
        let publication = store
            .semantic_ir_publication(&brokk_bifrost_core::gitblob::BlobKey::unvaried(
                oid,
                row_fixture::LANG,
            ))
            .unwrap()
            .unwrap();
        assert_eq!(publication.blob_id, blob_id);
        assert_eq!(publication.content, content);
        assert_eq!(publication.source_bytes, 10 + index);
        assert_eq!(publication.outcome, expected);
    }
}

/// Which reader a corruption case runs.
#[derive(Debug, Clone, Copy)]
enum CorruptedRead {
    Ir,
    PartialFlows(u32),
}

/// Rows that the schema admits but the encoder never writes do not decode to
/// wrong procedures: the decoder panics and names the table, the blob, the
/// row's key and the column or the broken invariant. `{blob}` in a statement
/// and in an expected message stands for the blob id.
#[test]
fn semantic_ir_decoder_rejects_corrupted_rows_by_naming_the_row() {
    use crate::analyzer::semantic::ProcedureId;
    use row_fixture::{fixture, insert, prepare};

    let cases: &[(&str, CorruptedRead, &str, &[&str])] = &[
        (
            "a value id that skips one",
            CorruptedRead::Ir,
            "DELETE FROM semantic_ir_values WHERE blob_id = {blob} AND procedure = 0 AND value = 3",
            &[
                "semantic_ir_values row of blob {blob} with key [0, 4] does not decode: column value is 4; expected the dense id 3",
            ],
        ),
        (
            "a locator table that lost a row",
            CorruptedRead::Ir,
            "DELETE FROM semantic_ir_locators WHERE blob_id = {blob} AND locator = 1",
            &[
                "semantic_ir_locators row of blob {blob} with key [2] does not decode: column locator is 2; expected the dense id 1",
            ],
        ),
        (
            "a value whose kind lost its payload",
            CorruptedRead::Ir,
            "UPDATE semantic_ir_values SET kind = 9 WHERE blob_id = {blob} AND procedure = 0 AND value = 9",
            &[
                "semantic_ir_values row of blob {blob} with key [0, 9] does not decode: column magnitude is NULL but the row's variant requires it",
            ],
        ),
        (
            "a malformed decimal magnitude",
            CorruptedRead::Ir,
            "UPDATE semantic_ir_values SET magnitude = '12x' WHERE blob_id = {blob} AND procedure = 0 AND value = 10",
            &[
                "semantic_ir_values row of blob {blob} with key [0, 10] does not decode: column magnitude is not a u128 magnitude",
            ],
        ),
        (
            "an id beyond u32",
            CorruptedRead::Ir,
            "UPDATE semantic_ir_allocations SET point = 4294967296 WHERE blob_id = {blob} AND procedure = 0 AND allocation = 0",
            &[
                "semantic_ir_allocations row of blob {blob} with key [0, 0] does not decode: column point is not a u32",
            ],
        ),
        (
            "a missing text",
            CorruptedRead::Ir,
            "UPDATE semantic_ir_values SET text = 999 WHERE blob_id = {blob} AND procedure = 0 AND value = 18",
            &[
                "semantic_ir_values row of blob {blob} with key [0, 18] does not decode: names missing text 999",
            ],
        ),
        (
            "a member selection whose name text is missing",
            CorruptedRead::Ir,
            "UPDATE semantic_ir_call_sites SET member = 999 WHERE blob_id = {blob} AND procedure = 0 AND call_site = 0",
            &[
                "semantic_ir_call_sites row of blob {blob} with key [0, 0] does not decode: names missing text 999",
            ],
        ),
        (
            "a missing locator",
            CorruptedRead::Ir,
            "UPDATE semantic_ir_procedures SET locator = 999 WHERE blob_id = {blob} AND procedure = 1",
            &[
                "semantic_ir_procedures row of blob {blob} with key [1] does not decode: names missing locator 999",
            ],
        ),
        (
            "a row of a missing procedure",
            CorruptedRead::Ir,
            "UPDATE semantic_ir_values SET procedure = 7 WHERE blob_id = {blob} AND procedure = 1 AND value = 1",
            &[
                "semantic_ir_values row of blob {blob} with key [7, 1] does not decode: names procedure 7 of 5",
            ],
        ),
        (
            "a target group claimed twice",
            CorruptedRead::Ir,
            "UPDATE semantic_ir_call_sites SET targets = 0 WHERE blob_id = {blob} AND procedure = 0 AND call_site = 4",
            &[
                "semantic_ir_call_sites row of blob {blob} with key [0, 4] does not decode: takes target group 0 a second time",
            ],
        ),
        (
            "a target group nobody claims",
            CorruptedRead::Ir,
            "UPDATE semantic_ir_call_sites SET target_resolution = 2, targets = NULL WHERE blob_id = {blob} AND procedure = 0 AND call_site = 5",
            &["semantic IR blob {blob} procedure 0 has unclaimed target groups"],
        ),
        (
            "a proven resolution with three candidates",
            CorruptedRead::Ir,
            "UPDATE semantic_ir_call_sites SET target_resolution = 0 WHERE blob_id = {blob} AND procedure = 0 AND call_site = 1",
            &[
                "semantic_ir_call_sites row of blob {blob} with key [0, 1] does not decode: proves 3 targets",
            ],
        ),
        (
            "a side row for no event",
            CorruptedRead::Ir,
            "INSERT INTO semantic_ir_event_transfers(blob_id, procedure, point, ordinal, transfer_kind, operation) VALUES({blob}, 0, 4, 0, 0, 0)",
            &[
                "semantic IR blob {blob}: semantic_ir_event_transfers has rows for no matching event",
            ],
        ),
        (
            "an event whose side row is gone",
            CorruptedRead::Ir,
            "DELETE FROM semantic_ir_event_offsets WHERE blob_id = {blob} AND negative = 1",
            &[
                "semantic_ir_events row of blob {blob} with key [0, 0, ",
                "] does not decode: has no offset row",
            ],
        ),
        (
            "half of a guard arm",
            CorruptedRead::Ir,
            "UPDATE semantic_ir_guard_facts SET true_kind = NULL WHERE blob_id = {blob} AND procedure = 0 AND guard = 0",
            &[
                "semantic_ir_guard_facts row of blob {blob} with key [0, 0] does not decode: column true_target holds half of a guard arm",
            ],
        ),
        (
            "a code outside its enumeration in a column without a CHECK",
            CorruptedRead::Ir,
            "UPDATE semantic_ir_guard_facts SET false_kind = 99 WHERE blob_id = {blob} AND procedure = 0 AND guard = 0",
            &[
                "semantic_ir_guard_facts row of blob {blob} with key [0, 0] does not decode: column false_kind holds 99, not a ",
            ],
        ),
        (
            "a partial gap budget",
            CorruptedRead::Ir,
            "UPDATE semantic_ir_gaps SET budget_limit = NULL WHERE blob_id = {blob} AND procedure = 0 AND gap = 1",
            &[
                "semantic_ir_gaps row of blob {blob} with key [0, 1] does not decode: column budget_dimension holds a partial budget",
            ],
        ),
        (
            "a head that counts another number of procedures",
            CorruptedRead::Ir,
            "UPDATE semantic_ir_publications SET procedure_count = 6 WHERE blob_id = {blob}",
            &["semantic IR blob {blob} head counts 6 procedures"],
        ),
        (
            "a head of other content",
            CorruptedRead::Ir,
            "UPDATE semantic_ir_publications SET content_digest = zeroblob(32) WHERE blob_id = {blob}",
            &["semantic IR rows of blob {blob} are read for another content"],
        ),
        (
            "a head still building",
            CorruptedRead::Ir,
            "UPDATE semantic_ir_publications SET publication_state = 'building' WHERE blob_id = {blob}",
            &[
                "semantic IR rows of blob {blob} are read but the head has outcome 0 in state building",
            ],
        ),
        (
            "an unknown Go builtin",
            CorruptedRead::Ir,
            "UPDATE semantic_ir_publications SET go_predeclared_builtins = jsonb('[\"append\",\"nope\"]') WHERE blob_id = {blob}",
            &["semantic IR blob {blob} stores unknown Go builtin \"nope\""],
        ),
        (
            "a heap port rooted at itself",
            CorruptedRead::PartialFlows(0),
            "UPDATE semantic_ir_ports SET root = 11 WHERE blob_id = {blob} AND procedure = 0 AND port = 11",
            &[
                "semantic_ir_ports row of blob {blob} with key [0, 11] does not decode: is a heap port whose root is not an earlier port",
            ],
        ),
        (
            "a heap selector token of the wrong shape",
            CorruptedRead::PartialFlows(0),
            "UPDATE semantic_ir_ports SET selectors = jsonb('[[4,1]]') WHERE blob_id = {blob} AND procedure = 0 AND port = 11",
            &[
                "semantic_ir_ports row of blob {blob} with key [0, 11] does not decode: has the selector token (4, Some(1))",
            ],
        ),
        (
            "a partial-flow head that counts another number of ports",
            CorruptedRead::PartialFlows(0),
            "UPDATE semantic_ir_partial_flow_heads SET port_count = 2 WHERE blob_id = {blob} AND procedure = 0",
            &["semantic IR partial-flow head of blob {blob} procedure 0 counts ports"],
        ),
        (
            "an error head without its message",
            CorruptedRead::PartialFlows(2),
            "UPDATE semantic_ir_partial_flow_heads SET detail = NULL WHERE blob_id = {blob} AND procedure = 2",
            &[
                "semantic IR partial-flow head of blob {blob} procedure 2 is an error without a message",
            ],
        ),
        (
            "a truncated head with text",
            CorruptedRead::PartialFlows(3),
            "UPDATE semantic_ir_partial_flow_heads SET detail = 0 WHERE blob_id = {blob} AND procedure = 3",
            &[
                "semantic IR partial-flow head of blob {blob} procedure 3 carries text it cannot have",
            ],
        ),
    ];

    let fixture = fixture();
    let prepared = prepare(&fixture);
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let mut accepted = Vec::new();
    for (index, (name, read, statement, expected)) in cases.iter().enumerate() {
        let (_, blob_id) = insert(&store, &format!("corruption {index}"), &prepared);
        let blob = blob_id.to_string();
        let changed = store
            .conn
            .lock()
            .unwrap()
            .execute(&statement.replace("{blob}", &blob), [])
            .unwrap();
        assert_eq!(changed, 1, "{name}: the corruption must change one row");
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match read {
            CorruptedRead::Ir => {
                store.read_semantic_ir(blob_id, &fixture.scope).unwrap();
            }
            CorruptedRead::PartialFlows(procedure) => {
                store
                    .read_partial_flows(blob_id, ProcedureId::new(*procedure), &fixture.scope)
                    .unwrap();
            }
        }));
        let Err(payload) = outcome else {
            accepted.push(*name);
            continue;
        };
        let message = payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| {
                payload
                    .downcast_ref::<&str>()
                    .map(|text| (*text).to_owned())
            })
            .expect("panic payload is text");
        for fragment in *expected {
            let fragment = fragment.replace("{blob}", &blob);
            assert!(
                message.contains(&fragment),
                "{name}: the panic {message:?} does not contain {fragment:?}"
            );
        }
    }
    assert!(
        accepted.is_empty(),
        "the decoder accepted corrupted rows: {accepted:?}"
    );
}
