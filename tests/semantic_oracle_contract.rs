use std::sync::Arc;

use brokk_bifrost::Language;
use brokk_bifrost::analyzer::semantic::*;

const SOURCE: SourceMappingId = SourceMappingId::new(0);
const EVIDENCE: EvidenceId = EvidenceId::new(0);
const UNPROVEN_EVIDENCE: EvidenceId = EvidenceId::new(1);
const PARTIAL_EVIDENCE: EvidenceId = EvidenceId::new(2);
const BLOCK: BlockId = BlockId::new(0);
const ENTRY: ProgramPointId = ProgramPointId::new(0);
const NORMAL_EXIT: ProgramPointId = ProgramPointId::new(1);
const EXCEPTIONAL_EXIT: ProgramPointId = ProgramPointId::new(2);

fn oracle_candidate<T>(
    value: T,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
    provenance: impl IntoIterator<Item = OracleRelationHandle>,
) -> OracleCandidate<T> {
    OracleCandidate::new(
        value,
        proof,
        completeness,
        provenance,
        OracleLimits::default(),
    )
    .expect("fixture candidate fits the default oracle limits")
}

fn proven_candidate<T>(
    value: T,
    provenance: impl IntoIterator<Item = OracleRelationHandle>,
) -> OracleCandidate<T> {
    OracleCandidate::proven(value, provenance, OracleLimits::default())
        .expect("fixture candidate fits the default oracle limits")
}

fn dispatch_candidate_draft(
    target: ProcedureHandle,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
    provenance: impl IntoIterator<Item = OracleRelationHandle>,
) -> DispatchCandidate {
    DispatchCandidate::new(
        target,
        proof,
        completeness,
        provenance,
        OracleLimits::default(),
    )
    .expect("fixture dispatch candidate fits the default oracle limits")
}

fn call_bindings(
    call: CallSiteHandle,
    candidate: &DispatchCandidate,
    context: OracleCallContext,
    bindings: impl IntoIterator<Item = CallBinding>,
    coverage: CandidateCoverage,
) -> Result<CallBindings, OracleContractError> {
    CallBindings::new(
        call,
        candidate,
        context,
        bindings,
        coverage,
        OracleLimits::default(),
    )
}

fn anchor(offset: u32) -> SourceAnchor {
    let start = SourcePosition::new(offset, 0, offset);
    let end = SourcePosition::new(offset + 1, 0, offset + 1);
    SourceAnchor::new(SourceSpan::new(start, end).expect("ordered span"), 0)
}

fn artifact_key() -> SemanticArtifactKey {
    SemanticArtifactKey::new(
        WorkspaceMountId::hash_bytes(b"semantic-oracle-contract-mount"),
        WorkspaceRelativePath::new("src/Oracle.java").expect("valid fixture path"),
        SemanticLanguage::Standard(Language::Java),
        SourceRevision::Disk {
            content: ContentIdentity::hash_bytes(b"synthetic semantic oracle fixture"),
        },
        AdapterSemanticsVersion::hash_bytes("semantic-oracle-contract", b"adapter-v1")
            .expect("non-empty adapter name"),
        SemanticIrVersion::hash_bytes(b"semantic-oracle-contract-ir"),
        ConfigurationFingerprint::hash_bytes(b"semantic-oracle-contract-configuration"),
        DependencyFingerprint::hash_bytes(b"semantic-oracle-contract-dependencies"),
    )
}

fn procedure_locator(key: &SemanticArtifactKey, name: &str, offset: u32) -> SemanticLocator {
    let declaration = DeclarationLocator::new(vec![
        DeclarationSegment::named(DeclarationSegmentKind::File, "Oracle.java", anchor(0), 0)
            .expect("named file segment"),
        DeclarationSegment::named(DeclarationSegmentKind::Function, name, anchor(offset), 0)
            .expect("named function segment"),
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

fn memory_locator(key: &SemanticArtifactKey, name: &str, offset: u32) -> SemanticLocator {
    let declaration = DeclarationLocator::new(vec![
        DeclarationSegment::named(DeclarationSegmentKind::File, "Oracle.java", anchor(0), 0)
            .expect("named file segment"),
        DeclarationSegment::named(DeclarationSegmentKind::Function, name, anchor(offset), 0)
            .expect("named memory segment"),
    ])
    .expect("non-empty declaration");
    SemanticLocator::new(
        key.mount(),
        key.path().clone(),
        key.language(),
        declaration,
        SemanticRole::MemoryLocation,
        anchor(offset),
    )
}

fn event(effect: SemanticEffect) -> SemanticEvent {
    SemanticEvent::new(effect, SOURCE, EVIDENCE)
}

fn minimal_procedure(
    key: &SemanticArtifactKey,
    id: ProcedureId,
    name: &str,
    offset: u32,
) -> ProcedureSemanticsParts {
    let locator = procedure_locator(key, name, offset);
    let mut parts = ProcedureSemanticsParts::new(
        id,
        locator.clone(),
        ProcedureKind::Function,
        SOURCE,
        EVIDENCE,
    );
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
    parts.evidence_rows.extend([
        Evidence {
            id: UNPROVEN_EVIDENCE,
            proof: ProofStatus::Unproven("synthetic evidence is not proven".into()),
            completeness: EvidenceCompleteness::Complete,
            sources: Box::new([SOURCE]),
        },
        Evidence {
            id: PARTIAL_EVIDENCE,
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Partial(
                "synthetic evidence covers only part of the site".into(),
            ),
            sources: Box::new([SOURCE]),
        },
    ]);
    parts.blocks.push(BasicBlock {
        id: BLOCK,
        points: Box::new([ENTRY, NORMAL_EXIT, EXCEPTIONAL_EXIT]),
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
    parts.control_edges.extend([
        ControlEdge {
            source_point: ENTRY,
            target_point: NORMAL_EXIT,
            kind: ControlEdgeKind::Normal,
            source: SOURCE,
            evidence: EVIDENCE,
        },
        ControlEdge {
            source_point: ENTRY,
            target_point: EXCEPTIONAL_EXIT,
            kind: ControlEdgeKind::Exceptional,
            source: SOURCE,
            evidence: EVIDENCE,
        },
    ]);
    parts
}

fn capabilities() -> SemanticCapabilities {
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
        SemanticCapability::Values,
        SemanticCapability::LocalFlow,
        SemanticCapability::FieldMemory,
        SemanticCapability::IndexMemory,
        SemanticCapability::CallableReferences,
        SemanticCapability::Calls,
        SemanticCapability::NormalCallContinuation,
        SemanticCapability::ExceptionalCallContinuation,
    ] {
        builder = builder.complete(capability);
    }
    builder.build()
}

fn build_artifact() -> Arc<SemanticArtifact> {
    let key = artifact_key();
    let field = memory_locator(&key, "field", 4);
    let mut caller = minimal_procedure(&key, ProcedureId::new(0), "caller", 1);
    let mut callee = minimal_procedure(&key, ProcedureId::new(1), "callee", 2);
    let mut other_callee = minimal_procedure(&key, ProcedureId::new(2), "other", 3);

    caller.values.extend([
        SemanticValue {
            id: ValueId::new(0),
            kind: SemanticValueKind::Callable,
            source: SOURCE,
            evidence: EVIDENCE,
        },
        SemanticValue {
            id: ValueId::new(1),
            kind: SemanticValueKind::Parameter {
                ordinal: 0,
                multiplicity: FormalMultiplicity::One,
            },
            source: SOURCE,
            evidence: EVIDENCE,
        },
        SemanticValue {
            id: ValueId::new(2),
            kind: SemanticValueKind::Local,
            source: SOURCE,
            evidence: EVIDENCE,
        },
        SemanticValue {
            id: ValueId::new(3),
            kind: SemanticValueKind::Receiver,
            source: SOURCE,
            evidence: EVIDENCE,
        },
    ]);
    caller.memory_locations.extend([
        MemoryLocation {
            id: MemoryLocationId::new(0),
            kind: MemoryLocationKind::LexicalCell {
                binding: ValueId::new(1),
            },
            source: SOURCE,
            evidence: EVIDENCE,
        },
        MemoryLocation {
            id: MemoryLocationId::new(1),
            kind: MemoryLocationKind::Index {
                base: ValueId::new(1),
                index: None,
            },
            source: SOURCE,
            evidence: EVIDENCE,
        },
        MemoryLocation {
            id: MemoryLocationId::new(2),
            kind: MemoryLocationKind::Field {
                base: ValueId::new(1),
                member: field,
            },
            source: SOURCE,
            evidence: EVIDENCE,
        },
    ]);

    callee.values.push(SemanticValue {
        id: ValueId::new(0),
        kind: SemanticValueKind::Parameter {
            ordinal: 0,
            multiplicity: FormalMultiplicity::One,
        },
        source: SOURCE,
        evidence: EVIDENCE,
    });
    other_callee.values.push(SemanticValue {
        id: ValueId::new(0),
        kind: SemanticValueKind::Parameter {
            ordinal: 0,
            multiplicity: FormalMultiplicity::One,
        },
        source: SOURCE,
        evidence: EVIDENCE,
    });

    let target = CallableTargetResolution::Proven(CallableTarget::Local(ProcedureId::new(1)));
    caller.call_sites.push(SemanticCallSite {
        id: CallSiteId::new(0),
        point: ENTRY,
        callee: ValueId::new(0),
        receiver: None,
        arguments: Box::new([SemanticCallArgument::direct(ValueId::new(1))]),
        result: Some(ValueId::new(2)),
        thrown: None,
        declared_targets: target.clone(),
        target_evidence: EVIDENCE,
        normal_continuation: ControlContinuation::Target(NORMAL_EXIT),
        exceptional_continuation: ControlContinuation::Target(EXCEPTIONAL_EXIT),
        source: SOURCE,
        evidence: EVIDENCE,
    });
    caller.points[ENTRY.index()].events = vec![
        event(SemanticEffect::Entry),
        event(SemanticEffect::MemoryStore {
            kind: MemoryAccessKind::LexicalCell,
            location: MemoryLocationId::new(0),
            value: ValueId::new(1),
        }),
        event(SemanticEffect::MemoryStore {
            kind: MemoryAccessKind::Index,
            location: MemoryLocationId::new(1),
            value: ValueId::new(1),
        }),
        event(SemanticEffect::MemoryStore {
            kind: MemoryAccessKind::Field,
            location: MemoryLocationId::new(2),
            value: ValueId::new(1),
        }),
        event(SemanticEffect::CallableReference {
            result: ValueId::new(0),
            callable: CallableValue {
                kind: CallableReferenceKind::Function,
                targets: target,
                target_evidence: EVIDENCE,
                bound_receiver: None,
                environment: None,
            },
        }),
        event(SemanticEffect::Invoke {
            call_site: CallSiteId::new(0),
        }),
    ]
    .into_boxed_slice();
    let mut normal_events = caller.points[NORMAL_EXIT.index()].events.to_vec();
    normal_events.push(event(SemanticEffect::CallContinuation {
        call_site: CallSiteId::new(0),
        kind: CallContinuationKind::Normal,
    }));
    caller.points[NORMAL_EXIT.index()].events = normal_events.into_boxed_slice();
    let mut exceptional_events = caller.points[EXCEPTIONAL_EXIT.index()].events.to_vec();
    exceptional_events.push(event(SemanticEffect::CallContinuation {
        call_site: CallSiteId::new(0),
        kind: CallContinuationKind::Exceptional,
    }));
    caller.points[EXCEPTIONAL_EXIT.index()].events = exceptional_events.into_boxed_slice();

    Arc::new(
        SemanticArtifact::try_new(key, capabilities(), vec![caller, callee, other_callee])
            .expect("synthetic oracle artifact should satisfy the semantic IR contract"),
    )
}

struct Fixture {
    artifact: Arc<SemanticArtifact>,
    caller: ProcedureHandle,
    callee: ProcedureHandle,
    other_callee: ProcedureHandle,
    call: CallSiteHandle,
    point: ProgramPointHandle,
    value: ValueHandle,
    result: ValueHandle,
    lexical_location: MemoryLocationHandle,
}

impl Fixture {
    fn new() -> Self {
        let artifact = build_artifact();
        let caller = artifact.procedure_handle(ProcedureId::new(0)).unwrap();
        let callee = artifact.procedure_handle(ProcedureId::new(1)).unwrap();
        let other_callee = artifact.procedure_handle(ProcedureId::new(2)).unwrap();
        Self {
            artifact,
            call: caller.call_site_handle(CallSiteId::new(0)).unwrap(),
            point: caller.point_handle(ENTRY).unwrap(),
            value: caller.value_handle(ValueId::new(1)).unwrap(),
            result: caller.value_handle(ValueId::new(2)).unwrap(),
            lexical_location: caller
                .memory_location_handle(MemoryLocationId::new(0))
                .unwrap(),
            caller,
            callee,
            other_callee,
        }
    }

    fn evidence(&self) -> EvidenceHandle {
        self.caller.evidence_handle(EVIDENCE).unwrap()
    }

    fn evidence_with_quality(&self, id: EvidenceId) -> EvidenceHandle {
        self.caller.evidence_handle(id).unwrap()
    }

    fn context(&self) -> OracleCallContext {
        OracleCallContext::bounded(vec![self.call.clone()], OracleLimits::default())
    }

    fn value_in_context(&self, value: ValueHandle, context: OracleCallContext) -> ValueAtPoint {
        ValueAtPoint::new(
            value,
            self.point.clone(),
            ObservationPhase::BeforeEffects,
            context,
        )
        .unwrap()
    }

    fn value_at_point(&self) -> ValueAtPoint {
        self.value_in_context(self.value.clone(), OracleCallContext::empty())
    }

    fn scoped_field(&self) -> ScopedSemanticLocator {
        let location = self
            .caller
            .semantics()
            .memory_location(MemoryLocationId::new(2))
            .unwrap();
        let MemoryLocationKind::Field { member, .. } = &location.kind else {
            panic!("fixture field location changed kind");
        };
        ScopedSemanticLocator::new(self.artifact.clone(), member.clone()).unwrap()
    }

    fn lexical_path(&self, tail: AccessPathTail) -> AccessPath {
        AccessPath::bounded(
            AccessPathRoot::LexicalCell(self.lexical_location.clone()),
            Vec::new(),
            tail,
            OracleLimits::default(),
        )
        .unwrap()
    }

    fn lexical_store(&self, tail: AccessPathTail) -> StoreAtPoint {
        let path = self.lexical_path(tail);
        let target = AccessPathAtPoint::new(
            path,
            self.point.clone(),
            ObservationPhase::BeforeEffects,
            OracleCallContext::empty(),
        )
        .unwrap();
        StoreAtPoint::new(
            MemoryStoreHandle::new(self.point.clone(), 1).unwrap(),
            target,
            self.value_at_point(),
            None,
        )
        .unwrap()
    }

    fn lexical_object(&self, cardinality: ObjectCardinality) -> AbstractObject {
        AbstractObject::new(
            AbstractObjectIdentity::LexicalCell(self.lexical_location.clone()),
            cardinality,
        )
        .unwrap()
    }

    fn wildcard_store(&self) -> (StoreAtPoint, AbstractObject, AbstractLocation) {
        let port = ProcedurePortHandle::parameter(self.caller.clone(), 0).unwrap();
        let path = AccessPath::exact(
            AccessPathRoot::ProcedurePort(port.clone()),
            vec![AccessSelector::Index(IndexSelector::Any)],
            OracleLimits::default(),
        )
        .unwrap();
        let target = AccessPathAtPoint::new(
            path.clone(),
            self.point.clone(),
            ObservationPhase::BeforeEffects,
            OracleCallContext::empty(),
        )
        .unwrap();
        let store = StoreAtPoint::new(
            MemoryStoreHandle::new(self.point.clone(), 2).unwrap(),
            target,
            self.value_at_point(),
            Some(self.value_at_point()),
        )
        .unwrap();
        let object = AbstractObject::new(
            AbstractObjectIdentity::ProcedurePort(port),
            ObjectCardinality::Singleton,
        )
        .unwrap();
        let location = AbstractLocation::new(object.clone(), path).unwrap();
        (store, object, location)
    }
}

fn binding_argument_group(
    fixture: &BindingFixture,
    arena: &Arc<OracleRelationArena>,
    closure_id: u32,
    sources: impl IntoIterator<Item = u32>,
    mappings: impl IntoIterator<Item = (u32, CallArgumentMember, u32, u32)>,
    coverage: CandidateCoverage,
) -> CallBinding {
    let mappings = mappings
        .into_iter()
        .map(|(source_index, member, formal_ordinal, relation_id)| {
            let mapping = CallArgumentMapping::new(
                source_index,
                member,
                CallArgumentEndpoint::Value(fixture.arguments[source_index as usize].clone()),
                ProcedurePortHandle::parameter(fixture.callee.clone(), formal_ordinal).unwrap(),
                CallPassingMode::Value,
            );
            proven_candidate(
                mapping,
                [arena.handle(OracleRelationId::new(relation_id)).unwrap()],
            )
        })
        .collect::<Vec<_>>();
    CallBinding::ArgumentGroup(
        CallArgumentGroup::new(
            &fixture.call,
            arena.handle(OracleRelationId::new(closure_id)).unwrap(),
            sources,
            mappings,
            coverage,
            OracleLimits::default(),
        )
        .unwrap(),
    )
}

struct BindingFixture {
    caller: ProcedureHandle,
    callee: ProcedureHandle,
    call: CallSiteHandle,
    arguments: Vec<ValueHandle>,
    result: ValueHandle,
}

impl BindingFixture {
    fn new(
        expansions: Vec<CallArgumentExpansion>,
        multiplicities: Vec<FormalMultiplicity>,
    ) -> Self {
        let argument_count = expansions.len();
        let key = artifact_key();
        let mut caller = minimal_procedure(&key, ProcedureId::new(0), "binding_caller", 10);
        let mut callee = minimal_procedure(&key, ProcedureId::new(1), "binding_callee", 20);
        caller.values.push(SemanticValue {
            id: ValueId::new(0),
            kind: SemanticValueKind::Callable,
            source: SOURCE,
            evidence: EVIDENCE,
        });
        for (index, _) in expansions.iter().enumerate() {
            caller.values.push(SemanticValue {
                id: ValueId::new((index + 1) as u32),
                kind: SemanticValueKind::Local,
                source: SOURCE,
                evidence: EVIDENCE,
            });
        }
        let result_id = ValueId::new((expansions.len() + 1) as u32);
        caller.values.push(SemanticValue {
            id: result_id,
            kind: SemanticValueKind::Local,
            source: SOURCE,
            evidence: EVIDENCE,
        });
        for (ordinal, multiplicity) in multiplicities.into_iter().enumerate() {
            callee.values.push(SemanticValue {
                id: ValueId::new(ordinal as u32),
                kind: SemanticValueKind::Parameter {
                    ordinal: ordinal as u32,
                    multiplicity,
                },
                source: SOURCE,
                evidence: EVIDENCE,
            });
        }

        let target = CallableTargetResolution::Proven(CallableTarget::Local(ProcedureId::new(1)));
        let arguments = expansions
            .into_iter()
            .enumerate()
            .map(|(index, expansion)| SemanticCallArgument {
                value: ValueId::new((index + 1) as u32),
                expansion,
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        caller.call_sites.push(SemanticCallSite {
            id: CallSiteId::new(0),
            point: ENTRY,
            callee: ValueId::new(0),
            receiver: None,
            arguments,
            result: Some(result_id),
            thrown: None,
            declared_targets: target.clone(),
            target_evidence: EVIDENCE,
            normal_continuation: ControlContinuation::Target(NORMAL_EXIT),
            exceptional_continuation: ControlContinuation::Target(EXCEPTIONAL_EXIT),
            source: SOURCE,
            evidence: EVIDENCE,
        });
        caller.points[ENTRY.index()].events = vec![
            event(SemanticEffect::Entry),
            event(SemanticEffect::CallableReference {
                result: ValueId::new(0),
                callable: CallableValue {
                    kind: CallableReferenceKind::Function,
                    targets: target,
                    target_evidence: EVIDENCE,
                    bound_receiver: None,
                    environment: None,
                },
            }),
            event(SemanticEffect::Invoke {
                call_site: CallSiteId::new(0),
            }),
        ]
        .into_boxed_slice();
        let mut normal_events = caller.points[NORMAL_EXIT.index()].events.to_vec();
        normal_events.push(event(SemanticEffect::CallContinuation {
            call_site: CallSiteId::new(0),
            kind: CallContinuationKind::Normal,
        }));
        caller.points[NORMAL_EXIT.index()].events = normal_events.into_boxed_slice();
        let mut exceptional_events = caller.points[EXCEPTIONAL_EXIT.index()].events.to_vec();
        exceptional_events.push(event(SemanticEffect::CallContinuation {
            call_site: CallSiteId::new(0),
            kind: CallContinuationKind::Exceptional,
        }));
        caller.points[EXCEPTIONAL_EXIT.index()].events = exceptional_events.into_boxed_slice();

        let artifact = Arc::new(
            SemanticArtifact::try_new(key, capabilities(), vec![caller, callee])
                .expect("binding fixture should satisfy the semantic IR contract"),
        );
        let caller = artifact.procedure_handle(ProcedureId::new(0)).unwrap();
        let callee = artifact.procedure_handle(ProcedureId::new(1)).unwrap();
        let arguments = (0..argument_count)
            .map(|index| {
                caller
                    .value_handle(ValueId::new((index + 1) as u32))
                    .unwrap()
            })
            .collect();
        Self {
            call: caller.call_site_handle(CallSiteId::new(0)).unwrap(),
            result: caller.value_handle(result_id).unwrap(),
            caller,
            callee,
            arguments,
        }
    }

    fn evidence(&self) -> EvidenceHandle {
        self.caller.evidence_handle(EVIDENCE).unwrap()
    }

    fn evidence_with_quality(&self, id: EvidenceId) -> EvidenceHandle {
        self.caller.evidence_handle(id).unwrap()
    }

    fn candidate(&self) -> DispatchCandidate {
        let arena =
            dispatch_relation_arena(&self.call, [self.callee.clone()], [], &self.evidence());
        DispatchResult::new(
            &self.call,
            vec![dispatch_candidate_draft(
                self.callee.clone(),
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
                [arena.handle(OracleRelationId::new(0)).unwrap()],
            )],
            Vec::new(),
            CandidateCoverage::Exhaustive,
            OracleLimits::default(),
        )
        .unwrap()
        .candidates()[0]
            .clone()
    }

    fn binding_arena(
        &self,
        context: &OracleCallContext,
        records: usize,
    ) -> Arc<OracleRelationArena> {
        relation_arena(
            OracleRelationOwner::CallBinding {
                call: self.call.clone(),
                callee: self.callee.clone(),
                context: context.clone(),
            },
            std::iter::repeat_n(OracleRelationKind::CallBinding, records),
            &self.evidence(),
        )
    }

    fn return_binding(&self, relation: OracleRelationHandle) -> CallBinding {
        CallBinding::NormalReturn {
            relation,
            formal: ProcedurePortHandle::normal_return(self.callee.clone()),
            result: self.result.clone(),
        }
    }
}

fn relation_arena(
    owner: OracleRelationOwner,
    kinds: impl IntoIterator<Item = OracleRelationKind>,
    evidence: &EvidenceHandle,
) -> Arc<OracleRelationArena> {
    OracleRelationArena::new(
        owner,
        kinds
            .into_iter()
            .map(|kind| {
                OracleRelationRecord::new(kind, [evidence.clone()], OracleLimits::default())
                    .unwrap()
            })
            .collect(),
        OracleLimits::default(),
    )
    .unwrap()
}

fn dispatch_relation_arena(
    call: &CallSiteHandle,
    targets: impl IntoIterator<Item = ProcedureHandle>,
    boundaries: impl IntoIterator<Item = DispatchBoundaryKind>,
    evidence: &EvidenceHandle,
) -> Arc<OracleRelationArena> {
    let mut records = targets
        .into_iter()
        .map(|target| {
            OracleRelationRecord::dispatch_candidate(
                target,
                [evidence.clone()],
                OracleLimits::default(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    records.extend(boundaries.into_iter().map(|boundary| {
        OracleRelationRecord::dispatch_boundary(
            boundary,
            [evidence.clone()],
            OracleLimits::default(),
        )
        .unwrap()
    }));
    OracleRelationArena::new(
        OracleRelationOwner::Dispatch(call.clone()),
        records,
        OracleLimits::default(),
    )
    .unwrap()
}

fn call_binding_arena(
    fixture: &Fixture,
    context: &OracleCallContext,
    records: usize,
) -> Arc<OracleRelationArena> {
    relation_arena(
        OracleRelationOwner::CallBinding {
            call: fixture.call.clone(),
            callee: fixture.callee.clone(),
            context: context.clone(),
        },
        std::iter::repeat_n(OracleRelationKind::CallBinding, records),
        &fixture.evidence(),
    )
}

fn dispatch_candidates(
    fixture: &Fixture,
    targets: impl IntoIterator<Item = ProcedureHandle>,
) -> Vec<DispatchCandidate> {
    let targets = targets.into_iter().collect::<Vec<_>>();
    let arena = dispatch_relation_arena(
        &fixture.call,
        targets.iter().cloned(),
        [],
        &fixture.evidence(),
    );
    let drafts = targets
        .into_iter()
        .enumerate()
        .map(|(index, target)| {
            dispatch_candidate_draft(
                target,
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
                [arena
                    .handle(OracleRelationId::new(index as u32))
                    .expect("candidate relation")],
            )
        })
        .collect();
    DispatchResult::new(
        &fixture.call,
        drafts,
        Vec::new(),
        CandidateCoverage::Exhaustive,
        OracleLimits::default(),
    )
    .expect("valid dispatch candidates")
    .candidates()
    .to_vec()
}

fn dispatch_candidate(fixture: &Fixture) -> DispatchCandidate {
    dispatch_candidates(fixture, [fixture.callee.clone()])
        .into_iter()
        .next()
        .expect("one dispatch candidate")
}

fn argument_binding(
    fixture: &Fixture,
    closure_relation: OracleRelationHandle,
    mapping_relation: OracleRelationHandle,
    formal: ProcedureHandle,
) -> CallBinding {
    argument_binding_with_endpoint(
        fixture,
        closure_relation,
        mapping_relation,
        formal,
        CallArgumentEndpoint::Value(fixture.value.clone()),
        CallPassingMode::Value,
    )
}

fn argument_binding_with_endpoint(
    fixture: &Fixture,
    closure_relation: OracleRelationHandle,
    mapping_relation: OracleRelationHandle,
    formal: ProcedureHandle,
    actual: CallArgumentEndpoint,
    mode: CallPassingMode,
) -> CallBinding {
    let mapping = CallArgumentMapping::new(
        0,
        CallArgumentMember::Whole,
        actual,
        ProcedurePortHandle::parameter(formal, 0).unwrap(),
        mode,
    );
    CallBinding::ArgumentGroup(
        CallArgumentGroup::new(
            &fixture.call,
            closure_relation,
            [0],
            [proven_candidate(mapping, [mapping_relation])],
            CandidateCoverage::Exhaustive,
            OracleLimits::default(),
        )
        .unwrap(),
    )
}

fn return_binding(fixture: &Fixture, relation: OracleRelationHandle) -> CallBinding {
    CallBinding::NormalReturn {
        relation,
        formal: ProcedurePortHandle::normal_return(fixture.callee.clone()),
        result: fixture.result.clone(),
    }
}

fn strong_evidence(
    fixture: &Fixture,
    store: &StoreAtPoint,
    object: &AbstractObject,
    location: &AbstractLocation,
) -> StrongUpdateEvidence {
    strong_evidence_with_backing(store, object, location, fixture.evidence())
}

fn strong_evidence_with_backing(
    store: &StoreAtPoint,
    object: &AbstractObject,
    location: &AbstractLocation,
    backing: EvidenceHandle,
) -> StrongUpdateEvidence {
    let arena = relation_arena(
        OracleRelationOwner::StrongUpdate(Box::new(store.clone())),
        [
            OracleRelationKind::Location,
            OracleRelationKind::PointsTo,
            OracleRelationKind::Alias,
            OracleRelationKind::Escape,
        ],
        &backing,
    );
    StrongUpdateEvidence::new(
        location_set(
            [proven_candidate(
                location.clone(),
                [arena.handle(OracleRelationId::new(0)).unwrap()],
            )],
            CandidateCoverage::Exhaustive,
        ),
        object_set(
            [proven_candidate(
                object.clone(),
                [arena.handle(OracleRelationId::new(1)).unwrap()],
            )],
            CandidateCoverage::Exhaustive,
        ),
        proven_candidate(
            AliasExclusivityWitness::new(
                store.clone(),
                location.clone(),
                AliasExclusivity::Exclusive,
            )
            .unwrap(),
            [arena.handle(OracleRelationId::new(2)).unwrap()],
        ),
        proven_candidate(
            EscapeWitness::new(store.clone(), object.clone(), EscapeStatus::DoesNotEscape).unwrap(),
            [arena.handle(OracleRelationId::new(3)).unwrap()],
        ),
        OracleLimits::default(),
    )
    .expect("fixture strong-update evidence fits the default oracle limits")
}

fn location_set(
    candidates: impl IntoIterator<Item = OracleCandidate<AbstractLocation>>,
    coverage: CandidateCoverage,
) -> OracleSet<AbstractLocation> {
    OracleSet::bounded_locations(candidates, coverage, OracleLimits::default())
}

fn object_set(
    candidates: impl IntoIterator<Item = OracleCandidate<AbstractObject>>,
    coverage: CandidateCoverage,
) -> OracleSet<AbstractObject> {
    OracleSet::bounded_objects(candidates, coverage, OracleLimits::default())
}

fn rebuild_strong_evidence(
    evidence: &StrongUpdateEvidence,
    locations: Option<OracleSet<AbstractLocation>>,
    objects: Option<OracleSet<AbstractObject>>,
    alias_exclusivity: Option<EvidenceBacked<AliasExclusivityWitness>>,
    escape: Option<EvidenceBacked<EscapeWitness>>,
) -> StrongUpdateEvidence {
    StrongUpdateEvidence::new(
        locations.unwrap_or_else(|| evidence.locations().clone()),
        objects.unwrap_or_else(|| evidence.objects().clone()),
        alias_exclusivity.unwrap_or_else(|| evidence.alias_exclusivity().clone()),
        escape.unwrap_or_else(|| evidence.escape().clone()),
        OracleLimits::default(),
    )
    .expect("rebuilt fixture evidence fits the default oracle limits")
}

fn candidate_with_value<T: Clone>(candidate: &OracleCandidate<T>, value: T) -> OracleCandidate<T> {
    oracle_candidate(
        value,
        candidate.proof().clone(),
        candidate.completeness().clone(),
        candidate.provenance().iter().cloned(),
    )
}

fn candidate_with_quality<T: Clone>(
    candidate: &OracleCandidate<T>,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
) -> OracleCandidate<T> {
    oracle_candidate(
        candidate.value().clone(),
        proof,
        completeness,
        candidate.provenance().iter().cloned(),
    )
}

fn candidate_with_provenance<T: Clone>(
    candidate: &OracleCandidate<T>,
    provenance: impl IntoIterator<Item = OracleRelationHandle>,
) -> OracleCandidate<T> {
    oracle_candidate(
        candidate.value().clone(),
        candidate.proof().clone(),
        candidate.completeness().clone(),
        provenance,
    )
}

fn assert_weak(eligibility: UpdateEligibility, expected: WeakUpdateReason) {
    let UpdateEligibility::Weak(reasons) = eligibility else {
        panic!("expected weak update because of {expected:?}");
    };
    assert!(
        reasons.contains(&expected),
        "missing {expected:?} in {reasons:?}"
    );
}

#[test]
fn every_oracle_limit_dimension_rejects_zero() {
    type LimitSetter = fn(&mut OracleLimitValues);
    let dimensions: [(&str, LimitSetter); 12] = [
        ("dispatch_targets", |limits| limits.dispatch_targets = 0),
        ("objects_per_value", |limits| limits.objects_per_value = 0),
        ("interned_roots", |limits| limits.interned_roots = 0),
        ("interned_selectors", |limits| limits.interned_selectors = 0),
        ("interned_paths", |limits| limits.interned_paths = 0),
        ("access_path_length", |limits| limits.access_path_length = 0),
        ("alias_breadth", |limits| limits.alias_breadth = 0),
        ("call_context_depth", |limits| limits.call_context_depth = 0),
        ("summary_depth", |limits| limits.summary_depth = 0),
        ("call_binding_entries", |limits| {
            limits.call_binding_entries = 0
        }),
        ("provenance_records", |limits| limits.provenance_records = 0),
        ("evidence_handles", |limits| limits.evidence_handles = 0),
    ];
    for (expected, set_zero) in dimensions {
        let mut values = OracleLimitValues::uniform(1);
        set_zero(&mut values);
        assert_eq!(OracleLimits::new(values).unwrap_err().dimension(), expected);
    }
}

#[test]
fn candidate_proof_set_coverage_and_object_cardinality_are_independent() {
    let fixture = Fixture::new();
    let singleton = fixture.lexical_object(ObjectCardinality::Singleton);
    let summary = fixture.lexical_object(ObjectCardinality::Summary);

    let open_singleton = object_set(
        [oracle_candidate(
            singleton.clone(),
            ProofStatus::Proven,
            EvidenceCompleteness::Complete,
            std::iter::empty(),
        )],
        CandidateCoverage::Open,
    );
    assert!(!open_singleton.is_closed());
    assert!(matches!(
        open_singleton.candidates()[0].proof(),
        ProofStatus::Proven
    ));
    assert_eq!(
        open_singleton.candidates()[0].value().cardinality(),
        ObjectCardinality::Singleton
    );

    let exhaustive = object_set(
        [
            oracle_candidate(
                summary,
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
                std::iter::empty(),
            ),
            oracle_candidate(
                singleton,
                ProofStatus::Unproven("candidate remains possible".into()),
                EvidenceCompleteness::Partial("candidate proof is incomplete".into()),
                std::iter::empty(),
            ),
        ],
        CandidateCoverage::Exhaustive,
    );
    assert!(exhaustive.is_closed());
    assert_eq!(exhaustive.coverage(), CandidateCoverage::Exhaustive);
    assert_eq!(exhaustive.candidates().len(), 2);
    assert_eq!(
        exhaustive.candidates()[0].value().cardinality(),
        ObjectCardinality::Summary
    );
    assert!(matches!(
        exhaustive.candidates()[0].proof(),
        ProofStatus::Proven
    ));
    assert_eq!(
        exhaustive.candidates()[1].value().cardinality(),
        ObjectCardinality::Singleton
    );
    assert!(matches!(
        exhaustive.candidates()[1].proof(),
        ProofStatus::Unproven(_)
    ));
}

#[test]
fn bounded_oracle_sets_truncate_at_each_public_breadth_limit() {
    let fixture = Fixture::new();
    let limits = OracleLimits::new(OracleLimitValues {
        objects_per_value: 1,
        alias_breadth: 2,
        ..OracleLimitValues::uniform(3)
    })
    .unwrap();
    let object = fixture.lexical_object(ObjectCardinality::Singleton);
    let location =
        AbstractLocation::new(object.clone(), fixture.lexical_path(AccessPathTail::Exact)).unwrap();

    let objects = OracleSet::bounded_objects(
        [
            proven_candidate(object.clone(), std::iter::empty()),
            proven_candidate(object.clone(), std::iter::empty()),
            proven_candidate(object, std::iter::empty()),
        ],
        CandidateCoverage::Exhaustive,
        limits,
    );
    assert_eq!(objects.candidates().len(), 1);
    assert_eq!(objects.coverage(), CandidateCoverage::Truncated);

    let aliases = OracleSet::bounded_locations(
        [
            proven_candidate(location.clone(), std::iter::empty()),
            proven_candidate(location.clone(), std::iter::empty()),
            proven_candidate(location, std::iter::empty()),
        ],
        CandidateCoverage::Exhaustive,
        limits,
    );
    assert_eq!(aliases.candidates().len(), 2);
    assert_eq!(aliases.coverage(), CandidateCoverage::Truncated);
}

#[test]
fn bounded_contexts_and_paths_retain_explicit_truncation() {
    let fixture = Fixture::new();
    let limits = OracleLimits::uniform(1).unwrap();
    let context =
        OracleCallContext::bounded(vec![fixture.call.clone(), fixture.call.clone()], limits);
    assert_eq!(context.calls(), std::slice::from_ref(&fixture.call));
    assert!(context.was_truncated());

    let field = fixture.scoped_field();
    let path = AccessPath::exact(
        AccessPathRoot::ProcedurePort(
            ProcedurePortHandle::parameter(fixture.caller.clone(), 0).unwrap(),
        ),
        vec![
            AccessSelector::Field(field.clone()),
            AccessSelector::Field(field),
        ],
        limits,
    )
    .unwrap();
    assert_eq!(path.selectors().len(), 1);
    assert_eq!(path.tail(), AccessPathTail::Summary);
    assert!(!path.is_exact());
}

#[test]
fn field_selectors_require_memory_location_locators() {
    let fixture = Fixture::new();
    let procedure_locator = ScopedSemanticLocator::new(
        fixture.artifact.clone(),
        fixture.caller.semantics().locator().clone(),
    )
    .unwrap();
    assert!(matches!(
        AccessPath::exact(
            AccessPathRoot::Value(fixture.value.clone()),
            vec![AccessSelector::Field(procedure_locator)],
            OracleLimits::default(),
        ),
        Err(OracleContractError::InvalidAccessSelector(_))
    ));
}

#[test]
fn relation_handles_are_interned_within_and_scoped_between_arenas() {
    let fixture = Fixture::new();
    let context = OracleCallContext::empty();
    let owner = OracleRelationOwner::ProcedureValueFlow {
        procedure: fixture.caller.clone(),
        context: context.clone(),
    };
    let first = relation_arena(
        owner.clone(),
        [OracleRelationKind::ValueFlow],
        &fixture.evidence(),
    );
    let second = relation_arena(owner, [OracleRelationKind::ValueFlow], &fixture.evidence());
    let first_handle = first.handle(OracleRelationId::new(0)).unwrap();
    assert_eq!(
        first_handle,
        first.handle(OracleRelationId::new(0)).unwrap()
    );
    let second_handle = second.handle(OracleRelationId::new(0)).unwrap();
    assert_eq!(first_handle.id(), second_handle.id());
    assert_ne!(first_handle, second_handle);
    let mut client_facts = std::collections::HashSet::new();
    assert!(client_facts.insert(first_handle.clone()));
    assert!(!client_facts.insert(first_handle));
    assert!(client_facts.insert(second_handle));

    let foreign_evidence = fixture.callee.evidence_handle(EVIDENCE).unwrap();
    assert!(matches!(
        OracleRelationArena::new(
            OracleRelationOwner::ProcedureValueFlow {
                procedure: fixture.caller.clone(),
                context: context.clone(),
            },
            vec![
                OracleRelationRecord::new(
                    OracleRelationKind::ValueFlow,
                    [foreign_evidence],
                    OracleLimits::default(),
                )
                .unwrap()
            ],
            OracleLimits::default(),
        ),
        Err(OracleContractError::CrossProcedure)
    ));

    let one_record = OracleLimits::new(OracleLimitValues {
        provenance_records: 1,
        ..OracleLimitValues::uniform(2)
    })
    .unwrap();
    assert!(matches!(
        OracleRelationArena::new(
            OracleRelationOwner::ProcedureValueFlow {
                procedure: fixture.caller.clone(),
                context,
            },
            vec![
                OracleRelationRecord::new(
                    OracleRelationKind::ValueFlow,
                    [fixture.evidence()],
                    one_record,
                )
                .unwrap(),
                OracleRelationRecord::new(
                    OracleRelationKind::ValueFlow,
                    [fixture.evidence()],
                    one_record,
                )
                .unwrap(),
            ],
            one_record,
        ),
        Err(OracleContractError::LimitExceeded {
            dimension: "provenance_records",
            limit: 1,
            attempted: 2,
        })
    ));

    let one_evidence = OracleLimits::new(OracleLimitValues {
        evidence_handles: 1,
        ..OracleLimitValues::uniform(2)
    })
    .unwrap();
    assert!(matches!(
        OracleRelationRecord::new(
            OracleRelationKind::ValueFlow,
            [fixture.evidence(), fixture.evidence()],
            one_evidence,
        ),
        Err(OracleContractError::LimitExceeded {
            dimension: "evidence_handles",
            limit: 1,
            attempted: 2,
        })
    ));
    let records = vec![
        OracleRelationRecord::new(
            OracleRelationKind::ValueFlow,
            [fixture.evidence()],
            one_evidence,
        )
        .unwrap(),
        OracleRelationRecord::new(
            OracleRelationKind::ValueFlow,
            [fixture.evidence()],
            one_evidence,
        )
        .unwrap(),
    ];
    assert!(matches!(
        OracleRelationArena::new(
            OracleRelationOwner::ProcedureValueFlow {
                procedure: fixture.caller.clone(),
                context: OracleCallContext::empty(),
            },
            records,
            one_evidence,
        ),
        Err(OracleContractError::LimitExceeded {
            dimension: "evidence_handles",
            limit: 1,
            attempted: 2,
        })
    ));
}

#[test]
fn relation_record_stops_consuming_evidence_after_bounded_lookahead() {
    let fixture = Fixture::new();
    let limits = OracleLimits::new(OracleLimitValues {
        evidence_handles: 1,
        ..OracleLimitValues::uniform(2)
    })
    .unwrap();
    let consumed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = Arc::clone(&consumed);
    let evidence = fixture.evidence();
    let unbounded = std::iter::from_fn(move || {
        observed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Some(evidence.clone())
    });

    assert_eq!(
        OracleRelationRecord::new(OracleRelationKind::ValueFlow, unbounded, limits),
        Err(OracleContractError::LimitExceeded {
            dimension: "evidence_handles",
            limit: 1,
            attempted: 2,
        })
    );
    assert_eq!(
        consumed.load(std::sync::atomic::Ordering::Relaxed),
        2,
        "bounded construction must inspect only the limit plus one item"
    );
}

#[test]
fn value_flow_snapshots_retain_context_and_reject_multiple_arenas() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let owner = OracleRelationOwner::ProcedureValueFlow {
        procedure: fixture.caller.clone(),
        context: context.clone(),
    };
    let first = relation_arena(
        owner.clone(),
        [OracleRelationKind::ValueFlow, OracleRelationKind::ValueFlow],
        &fixture.evidence(),
    );
    let second = relation_arena(owner, [OracleRelationKind::ValueFlow], &fixture.evidence());
    let relation = |id| ValueFlowRelation {
        id,
        kind: ValueFlowRelationKind::Assignment,
        source: ValueFlowEndpoint::Value(fixture.value.clone()),
        target: ValueFlowEndpoint::Value(fixture.result.clone()),
        proof: ProofStatus::Proven,
        completeness: EvidenceCompleteness::Complete,
    };
    let first_relation = relation(first.handle(OracleRelationId::new(0)).unwrap());
    let same_arena_relation = relation(first.handle(OracleRelationId::new(1)).unwrap());
    let snapshot = ValueFlowSnapshot::new(
        fixture.caller.clone(),
        context.clone(),
        vec![first_relation.clone(), same_arena_relation],
        CandidateCoverage::Exhaustive,
        OracleLimits::default(),
    )
    .expect("one value-flow arena should retain its exact context");
    assert_eq!(snapshot.context(), &context);
    assert_eq!(snapshot.relations().len(), 2);

    let other_arena_relation = relation(second.handle(OracleRelationId::new(0)).unwrap());
    assert_eq!(
        ValueFlowSnapshot::new(
            fixture.caller.clone(),
            context,
            vec![first_relation, other_arena_relation],
            CandidateCoverage::Exhaustive,
            OracleLimits::default(),
        ),
        Err(OracleContractError::InvalidRelationIdentity)
    );
}

#[test]
fn oracle_quality_claims_cannot_inflate_proof_or_completeness_independently() {
    let fixture = Fixture::new();
    let query = fixture.value_at_point();
    let object = fixture.lexical_object(ObjectCardinality::Singleton);

    for (evidence_id, proof, completeness) in [
        (
            UNPROVEN_EVIDENCE,
            ProofStatus::Proven,
            EvidenceCompleteness::Partial("candidate set remains partial".into()),
        ),
        (
            PARTIAL_EVIDENCE,
            ProofStatus::Unproven("candidate existence remains unproven".into()),
            EvidenceCompleteness::Complete,
        ),
    ] {
        let arena = relation_arena(
            OracleRelationOwner::PointsTo(Box::new(query.clone())),
            [OracleRelationKind::PointsTo],
            &fixture.evidence_with_quality(evidence_id),
        );
        assert_eq!(
            PointsToResult::new(
                query.clone(),
                [oracle_candidate(
                    object.clone(),
                    proof,
                    completeness,
                    [arena.handle(OracleRelationId::new(0)).unwrap()],
                )],
                CandidateCoverage::Open,
                OracleLimits::default(),
            ),
            Err(OracleContractError::InvalidRelationQuality)
        );
    }

    let context = OracleCallContext::empty();
    for (evidence_id, proof, completeness) in [
        (
            UNPROVEN_EVIDENCE,
            ProofStatus::Proven,
            EvidenceCompleteness::Partial("flow closure remains partial".into()),
        ),
        (
            PARTIAL_EVIDENCE,
            ProofStatus::Unproven("flow relation remains unproven".into()),
            EvidenceCompleteness::Complete,
        ),
    ] {
        let arena = relation_arena(
            OracleRelationOwner::ProcedureValueFlow {
                procedure: fixture.caller.clone(),
                context: context.clone(),
            },
            [OracleRelationKind::ValueFlow],
            &fixture.evidence_with_quality(evidence_id),
        );
        let relation = ValueFlowRelation {
            id: arena.handle(OracleRelationId::new(0)).unwrap(),
            kind: ValueFlowRelationKind::Assignment,
            source: ValueFlowEndpoint::Value(fixture.value.clone()),
            target: ValueFlowEndpoint::Value(fixture.result.clone()),
            proof,
            completeness,
        };
        assert_eq!(
            ValueFlowSnapshot::new(
                fixture.caller.clone(),
                context.clone(),
                vec![relation],
                CandidateCoverage::Open,
                OracleLimits::default(),
            ),
            Err(OracleContractError::InvalidRelationQuality)
        );
    }

    let candidate_arena = dispatch_relation_arena(
        &fixture.call,
        [fixture.callee.clone()],
        [],
        &fixture.evidence_with_quality(UNPROVEN_EVIDENCE),
    );
    assert_eq!(
        DispatchResult::new(
            &fixture.call,
            vec![dispatch_candidate_draft(
                fixture.callee.clone(),
                ProofStatus::Proven,
                EvidenceCompleteness::Partial("dispatch set remains partial".into()),
                [candidate_arena.handle(OracleRelationId::new(0)).unwrap()],
            )],
            Vec::new(),
            CandidateCoverage::Open,
            OracleLimits::default(),
        ),
        Err(OracleContractError::InvalidRelationQuality)
    );

    let boundary_arena = dispatch_relation_arena(
        &fixture.call,
        [],
        [DispatchBoundaryKind::External(None)],
        &fixture.evidence_with_quality(PARTIAL_EVIDENCE),
    );
    assert_eq!(
        DispatchResult::new(
            &fixture.call,
            Vec::new(),
            vec![DispatchBoundary {
                kind: DispatchBoundaryKind::External(None),
                proof: ProofStatus::Unproven("external target remains unproven".into()),
                completeness: EvidenceCompleteness::Complete,
                provenance: Box::new([boundary_arena.handle(OracleRelationId::new(0)).unwrap()]),
            }],
            CandidateCoverage::Open,
            OracleLimits::default(),
        ),
        Err(OracleContractError::InvalidRelationQuality)
    );
}

#[test]
fn dispatch_answers_require_one_call_scoped_provenance_arena() {
    let fixture = Fixture::new();
    let arena = dispatch_relation_arena(
        &fixture.call,
        [fixture.callee.clone()],
        [DispatchBoundaryKind::Unresolved],
        &fixture.evidence(),
    );
    let candidate_relation = arena.handle(OracleRelationId::new(0)).unwrap();
    assert_eq!(
        candidate_relation,
        arena.handle(OracleRelationId::new(0)).unwrap()
    );
    let boundary_relation = arena.handle(OracleRelationId::new(1)).unwrap();
    let result = DispatchResult::new(
        &fixture.call,
        vec![dispatch_candidate_draft(
            fixture.callee.clone(),
            ProofStatus::Proven,
            EvidenceCompleteness::Complete,
            [candidate_relation.clone()],
        )],
        vec![DispatchBoundary {
            kind: DispatchBoundaryKind::Unresolved,
            proof: ProofStatus::Unproven("unresolved dispatch arm".into()),
            completeness: EvidenceCompleteness::Partial("open dispatch".into()),
            provenance: Box::new([boundary_relation.clone()]),
        }],
        CandidateCoverage::Open,
        OracleLimits::default(),
    )
    .expect("candidate and boundary provenance share one dispatch arena");
    assert_eq!(result.candidates().len(), 1);
    assert_eq!(result.boundaries().len(), 1);

    assert_eq!(
        DispatchResult::new(
            &fixture.call,
            vec![dispatch_candidate_draft(
                fixture.callee.clone(),
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
                [boundary_relation],
            )],
            Vec::new(),
            CandidateCoverage::Open,
            OracleLimits::default(),
        ),
        Err(OracleContractError::InvalidRelationIdentity)
    );

    let second_arena = dispatch_relation_arena(
        &fixture.call,
        [],
        [DispatchBoundaryKind::Unresolved],
        &fixture.evidence(),
    );
    assert_eq!(
        DispatchResult::new(
            &fixture.call,
            vec![dispatch_candidate_draft(
                fixture.callee.clone(),
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
                [candidate_relation],
            )],
            vec![DispatchBoundary {
                kind: DispatchBoundaryKind::Unresolved,
                proof: ProofStatus::Unproven("unresolved dispatch arm".into()),
                completeness: EvidenceCompleteness::Partial("open dispatch".into()),
                provenance: Box::new([second_arena.handle(OracleRelationId::new(0)).unwrap(),]),
            }],
            CandidateCoverage::Open,
            OracleLimits::default(),
        ),
        Err(OracleContractError::InvalidRelationIdentity)
    );
}

#[test]
fn dispatch_result_cannot_seal_a_relation_for_a_different_target() {
    let fixture = Fixture::new();
    let arena = dispatch_relation_arena(
        &fixture.call,
        [fixture.callee.clone()],
        [],
        &fixture.evidence(),
    );
    let forged = dispatch_candidate_draft(
        fixture.other_callee.clone(),
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
        [arena.handle(OracleRelationId::new(0)).unwrap()],
    );

    assert_eq!(
        DispatchResult::new(
            &fixture.call,
            vec![forged],
            Vec::new(),
            CandidateCoverage::Exhaustive,
            OracleLimits::default(),
        ),
        Err(OracleContractError::InvalidRelationIdentity)
    );
}

#[test]
fn dispatch_boundaries_require_their_exact_structured_relation_identity() {
    let fixture = Fixture::new();
    assert_eq!(
        OracleRelationRecord::new(
            OracleRelationKind::DispatchBoundary,
            [fixture.evidence()],
            OracleLimits::default(),
        ),
        Err(OracleContractError::InvalidRelationIdentity)
    );

    let locator = fixture.callee.semantics().locator().clone();
    let mismatches = [
        (
            DispatchBoundaryKind::External(None),
            DispatchBoundaryKind::Unresolved,
        ),
        (
            DispatchBoundaryKind::Unmaterialized(locator.clone()),
            DispatchBoundaryKind::External(Some(locator.clone())),
        ),
        (
            DispatchBoundaryKind::Deferred {
                target: locator.clone(),
                kind: DeferredInvocationKind::Async,
            },
            DispatchBoundaryKind::Deferred {
                target: locator,
                kind: DeferredInvocationKind::Generator,
            },
        ),
    ];
    for (relation_subject, boundary_kind) in mismatches {
        let arena =
            dispatch_relation_arena(&fixture.call, [], [relation_subject], &fixture.evidence());
        assert_eq!(
            DispatchResult::new(
                &fixture.call,
                Vec::new(),
                vec![DispatchBoundary {
                    kind: boundary_kind,
                    proof: ProofStatus::Proven,
                    completeness: EvidenceCompleteness::Complete,
                    provenance: Box::new([arena.handle(OracleRelationId::new(0)).unwrap()]),
                }],
                CandidateCoverage::Open,
                OracleLimits::default(),
            ),
            Err(OracleContractError::InvalidRelationIdentity)
        );
    }
}

#[test]
fn dispatch_result_rejects_duplicate_targets_with_distinct_valid_provenance() {
    let fixture = Fixture::new();
    let arena = dispatch_relation_arena(
        &fixture.call,
        [fixture.callee.clone(), fixture.callee.clone()],
        [],
        &fixture.evidence(),
    );
    let candidates = (0..2)
        .map(|index| {
            dispatch_candidate_draft(
                fixture.callee.clone(),
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
                [arena.handle(OracleRelationId::new(index)).unwrap()],
            )
        })
        .collect();

    assert_eq!(
        DispatchResult::new(
            &fixture.call,
            candidates,
            Vec::new(),
            CandidateCoverage::Exhaustive,
            OracleLimits::default(),
        ),
        Err(OracleContractError::DuplicateDispatchTarget)
    );
}

#[test]
fn dispatch_result_revalidates_the_retained_arena_against_query_limits() {
    let fixture = Fixture::new();
    let record_arena = dispatch_relation_arena(
        &fixture.call,
        [fixture.callee.clone()],
        [DispatchBoundaryKind::Unresolved],
        &fixture.evidence(),
    );
    let record_limits = OracleLimits::new(OracleLimitValues {
        provenance_records: 1,
        ..OracleLimitValues::uniform(2)
    })
    .unwrap();
    assert!(matches!(
        DispatchResult::new(
            &fixture.call,
            vec![dispatch_candidate_draft(
                fixture.callee.clone(),
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
                [record_arena.handle(OracleRelationId::new(0)).unwrap()],
            )],
            vec![DispatchBoundary {
                kind: DispatchBoundaryKind::Unresolved,
                proof: ProofStatus::Unproven("unresolved dispatch arm".into()),
                completeness: EvidenceCompleteness::Partial("open dispatch".into()),
                provenance: Box::new([record_arena.handle(OracleRelationId::new(1)).unwrap()]),
            }],
            CandidateCoverage::Open,
            record_limits,
        ),
        Err(OracleContractError::LimitExceeded {
            dimension: "provenance_records",
            limit: 1,
            attempted: 2,
        })
    ));

    let evidence_record = OracleRelationRecord::dispatch_candidate(
        fixture.callee.clone(),
        [fixture.evidence(), fixture.evidence()],
        OracleLimits::default(),
    )
    .unwrap();
    let evidence_arena = OracleRelationArena::new(
        OracleRelationOwner::Dispatch(fixture.call.clone()),
        vec![evidence_record],
        OracleLimits::default(),
    )
    .unwrap();
    let evidence_limits = OracleLimits::new(OracleLimitValues {
        evidence_handles: 1,
        ..OracleLimitValues::uniform(2)
    })
    .unwrap();
    assert!(matches!(
        DispatchResult::new(
            &fixture.call,
            vec![dispatch_candidate_draft(
                fixture.callee.clone(),
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
                [evidence_arena.handle(OracleRelationId::new(0)).unwrap()],
            )],
            Vec::new(),
            CandidateCoverage::Exhaustive,
            evidence_limits,
        ),
        Err(OracleContractError::LimitExceeded {
            dimension: "evidence_handles",
            limit: 1,
            attempted: 2,
        })
    ));
}

#[test]
fn dispatch_boundaries_constrain_candidate_set_coverage() {
    let fixture = Fixture::new();
    let arena = dispatch_relation_arena(
        &fixture.call,
        [],
        [
            DispatchBoundaryKind::Unresolved,
            DispatchBoundaryKind::Truncated,
        ],
        &fixture.evidence(),
    );
    let unresolved = DispatchBoundary {
        kind: DispatchBoundaryKind::Unresolved,
        proof: ProofStatus::Unproven("unresolved dispatch arm".into()),
        completeness: EvidenceCompleteness::Partial("target set remains open".into()),
        provenance: Box::new([arena.handle(OracleRelationId::new(0)).unwrap()]),
    };
    assert_eq!(
        DispatchResult::new(
            &fixture.call,
            Vec::new(),
            vec![unresolved],
            CandidateCoverage::Exhaustive,
            OracleLimits::default(),
        ),
        Err(OracleContractError::InconsistentCoverage)
    );

    let truncated = DispatchBoundary {
        kind: DispatchBoundaryKind::Truncated,
        proof: ProofStatus::Unproven("dispatch limit reached".into()),
        completeness: EvidenceCompleteness::Partial("targets were omitted".into()),
        provenance: Box::new([arena.handle(OracleRelationId::new(1)).unwrap()]),
    };
    assert_eq!(
        DispatchResult::new(
            &fixture.call,
            Vec::new(),
            vec![truncated],
            CandidateCoverage::Open,
            OracleLimits::default(),
        ),
        Err(OracleContractError::InconsistentCoverage)
    );
}

#[test]
fn dispatch_result_rejects_more_targets_than_its_query_limit() {
    let fixture = Fixture::new();
    let arena = dispatch_relation_arena(
        &fixture.call,
        [fixture.callee.clone(), fixture.other_callee.clone()],
        [],
        &fixture.evidence(),
    );
    let candidates = [fixture.callee.clone(), fixture.other_callee.clone()]
        .into_iter()
        .enumerate()
        .map(|(index, target)| {
            dispatch_candidate_draft(
                target,
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
                [arena.handle(OracleRelationId::new(index as u32)).unwrap()],
            )
        })
        .collect();
    let limits = OracleLimits::new(OracleLimitValues {
        dispatch_targets: 1,
        ..OracleLimitValues::uniform(2)
    })
    .unwrap();
    assert!(matches!(
        DispatchResult::new(
            &fixture.call,
            candidates,
            Vec::new(),
            CandidateCoverage::Exhaustive,
            limits,
        ),
        Err(OracleContractError::LimitExceeded {
            dimension: "dispatch_targets",
            limit: 1,
            attempted: 2,
        })
    ));
}

#[test]
fn procedure_ports_and_scoped_locators_validate_live_semantics() {
    let fixture = Fixture::new();
    assert!(ProcedurePortHandle::receiver(fixture.caller.clone()).is_ok());
    assert_eq!(
        ProcedurePortHandle::receiver(fixture.callee.clone()),
        Err(OracleContractError::InvalidReceiverPort)
    );
    assert!(ProcedurePortHandle::parameter(fixture.callee.clone(), 0).is_ok());
    assert_eq!(
        ProcedurePortHandle::parameter(fixture.callee.clone(), 1),
        Err(OracleContractError::InvalidParameterOrdinal { ordinal: 1 })
    );
    assert_eq!(
        ProcedurePortHandle::capture(fixture.caller.clone(), MemoryLocationId::new(0)),
        Err(OracleContractError::InvalidCaptureSlot {
            slot: MemoryLocationId::new(0),
        })
    );

    let foreign_artifact = build_artifact();
    let foreign_caller = foreign_artifact
        .procedure_handle(ProcedureId::new(0))
        .unwrap();
    let scoped = ScopedSemanticLocator::new(
        fixture.artifact.clone(),
        fixture.caller.semantics().locator().clone(),
    )
    .unwrap();
    assert!(matches!(
        AbstractObject::new(
            AbstractObjectIdentity::TypeSummary(scoped.clone()),
            ObjectCardinality::Singleton,
        ),
        Err(OracleContractError::InvalidObjectCardinality(_))
    ));
    let path = AccessPath::exact(
        AccessPathRoot::Static(fixture.scoped_field()),
        Vec::new(),
        OracleLimits::default(),
    )
    .unwrap();
    assert_eq!(
        AccessPathAtPoint::new(
            path,
            foreign_caller.point_handle(ENTRY).unwrap(),
            ObservationPhase::BeforeEffects,
            OracleCallContext::empty(),
        ),
        Err(OracleContractError::InvalidSemanticScope)
    );

    let parameter_path = AccessPath::exact(
        AccessPathRoot::ProcedurePort(
            ProcedurePortHandle::parameter(fixture.caller.clone(), 0).unwrap(),
        ),
        Vec::new(),
        OracleLimits::default(),
    )
    .unwrap();
    assert_eq!(
        AbstractLocation::new(
            fixture.lexical_object(ObjectCardinality::Singleton),
            parameter_path,
        ),
        Err(OracleContractError::ObjectPathMismatch)
    );
}

#[test]
fn alias_queries_require_one_point_phase_and_context() {
    let fixture = Fixture::new();
    let observe = |point, phase, context| {
        AccessPathAtPoint::new(
            fixture.lexical_path(AccessPathTail::Exact),
            point,
            phase,
            context,
        )
        .unwrap()
    };
    let left = observe(
        fixture.point.clone(),
        ObservationPhase::BeforeEffects,
        OracleCallContext::empty(),
    );
    let query = AliasQuery::new(left.clone(), left.clone()).unwrap();
    assert_eq!(query.left(), &left);
    assert_eq!(query.right(), &left);

    let other_point = observe(
        fixture.caller.point_handle(NORMAL_EXIT).unwrap(),
        ObservationPhase::BeforeEffects,
        OracleCallContext::empty(),
    );
    assert_eq!(
        AliasQuery::new(left.clone(), other_point),
        Err(OracleContractError::MismatchedObservation)
    );

    let other_phase = observe(
        fixture.point.clone(),
        ObservationPhase::AfterEffects,
        OracleCallContext::empty(),
    );
    assert_eq!(
        AliasQuery::new(left.clone(), other_phase),
        Err(OracleContractError::MismatchedObservation)
    );

    let other_context = observe(
        fixture.point.clone(),
        ObservationPhase::BeforeEffects,
        fixture.context(),
    );
    assert_eq!(
        AliasQuery::new(left, other_context),
        Err(OracleContractError::MismatchedObservation)
    );
}

#[test]
fn heap_results_bind_provenance_to_the_exact_query_subject_and_context() {
    let fixture = Fixture::new();
    let value_query = fixture.value_at_point();
    let object = fixture.lexical_object(ObjectCardinality::Singleton);
    let points_to = relation_arena(
        OracleRelationOwner::PointsTo(Box::new(value_query.clone())),
        [OracleRelationKind::PointsTo],
        &fixture.evidence(),
    );
    let result = PointsToResult::new(
        value_query.clone(),
        [proven_candidate(
            object.clone(),
            [points_to.handle(OracleRelationId::new(0)).unwrap()],
        )],
        CandidateCoverage::Exhaustive,
        OracleLimits::default(),
    )
    .expect("points-to provenance should match its exact value observation");
    assert_eq!(result.query(), &value_query);
    assert_eq!(result.objects().candidates().len(), 1);

    let other_value = fixture.value_in_context(fixture.result.clone(), OracleCallContext::empty());
    let other_subject = relation_arena(
        OracleRelationOwner::PointsTo(Box::new(other_value)),
        [OracleRelationKind::PointsTo],
        &fixture.evidence(),
    );
    assert_eq!(
        PointsToResult::new(
            value_query.clone(),
            [proven_candidate(
                object.clone(),
                [other_subject.handle(OracleRelationId::new(0)).unwrap()],
            )],
            CandidateCoverage::Exhaustive,
            OracleLimits::default(),
        ),
        Err(OracleContractError::InvalidRelationIdentity)
    );

    let other_context_value = fixture.value_in_context(fixture.value.clone(), fixture.context());
    let other_context = relation_arena(
        OracleRelationOwner::PointsTo(Box::new(other_context_value)),
        [OracleRelationKind::PointsTo],
        &fixture.evidence(),
    );
    assert_eq!(
        PointsToResult::new(
            value_query,
            [proven_candidate(
                object.clone(),
                [other_context.handle(OracleRelationId::new(0)).unwrap()],
            )],
            CandidateCoverage::Exhaustive,
            OracleLimits::default(),
        ),
        Err(OracleContractError::InvalidRelationIdentity)
    );

    let access_query = AccessPathAtPoint::new(
        fixture.lexical_path(AccessPathTail::Exact),
        fixture.point.clone(),
        ObservationPhase::BeforeEffects,
        OracleCallContext::empty(),
    )
    .unwrap();
    let location =
        AbstractLocation::new(object.clone(), fixture.lexical_path(AccessPathTail::Exact)).unwrap();
    let locations = relation_arena(
        OracleRelationOwner::Locations(Box::new(access_query.clone())),
        [OracleRelationKind::Location],
        &fixture.evidence(),
    );
    let result = LocationResult::new(
        access_query.clone(),
        [proven_candidate(
            location.clone(),
            [locations.handle(OracleRelationId::new(0)).unwrap()],
        )],
        CandidateCoverage::Exhaustive,
        OracleLimits::default(),
    )
    .expect("location provenance should match its exact access-path observation");
    assert_eq!(result.query(), &access_query);
    assert_eq!(result.locations().candidates().len(), 1);

    let other_access = AccessPathAtPoint::new(
        AccessPath::exact(
            AccessPathRoot::Value(fixture.value.clone()),
            Vec::new(),
            OracleLimits::default(),
        )
        .unwrap(),
        fixture.point.clone(),
        ObservationPhase::BeforeEffects,
        OracleCallContext::empty(),
    )
    .unwrap();
    let other_subject = relation_arena(
        OracleRelationOwner::Locations(Box::new(other_access)),
        [OracleRelationKind::Location],
        &fixture.evidence(),
    );
    assert_eq!(
        LocationResult::new(
            access_query.clone(),
            [proven_candidate(
                location.clone(),
                [other_subject.handle(OracleRelationId::new(0)).unwrap()],
            )],
            CandidateCoverage::Exhaustive,
            OracleLimits::default(),
        ),
        Err(OracleContractError::InvalidRelationIdentity)
    );

    let other_context_access = AccessPathAtPoint::new(
        fixture.lexical_path(AccessPathTail::Exact),
        fixture.point.clone(),
        ObservationPhase::BeforeEffects,
        fixture.context(),
    )
    .unwrap();
    let other_context = relation_arena(
        OracleRelationOwner::Locations(Box::new(other_context_access)),
        [OracleRelationKind::Location],
        &fixture.evidence(),
    );
    assert_eq!(
        LocationResult::new(
            access_query,
            [proven_candidate(
                location,
                [other_context.handle(OracleRelationId::new(0)).unwrap()],
            )],
            CandidateCoverage::Exhaustive,
            OracleLimits::default(),
        ),
        Err(OracleContractError::InvalidRelationIdentity)
    );
}

#[test]
fn call_bindings_require_complete_unique_candidate_specific_relations() {
    let fixture = Fixture::new();
    let candidate = dispatch_candidate(&fixture);
    let context = OracleCallContext::empty();
    let arena = call_binding_arena(&fixture, &context, 10);
    let argument = argument_binding(
        &fixture,
        arena.handle(OracleRelationId::new(0)).unwrap(),
        arena.handle(OracleRelationId::new(1)).unwrap(),
        fixture.callee.clone(),
    );
    let normal_return = return_binding(&fixture, arena.handle(OracleRelationId::new(2)).unwrap());
    let bindings = call_bindings(
        fixture.call.clone(),
        &candidate,
        context.clone(),
        vec![argument.clone(), normal_return.clone()],
        CandidateCoverage::Exhaustive,
    )
    .expect("all real actual, formal, and return slots are bound");
    assert_eq!(bindings.bindings().len(), 2);

    assert!(matches!(
        call_bindings(
            fixture.call.clone(),
            &candidate,
            context.clone(),
            vec![argument.clone()],
            CandidateCoverage::Exhaustive,
        ),
        Err(OracleContractError::InvalidCallBinding(_))
    ));

    let duplicate_actual = argument_binding(
        &fixture,
        arena.handle(OracleRelationId::new(3)).unwrap(),
        arena.handle(OracleRelationId::new(4)).unwrap(),
        fixture.callee.clone(),
    );
    assert!(matches!(
        call_bindings(
            fixture.call.clone(),
            &candidate,
            context.clone(),
            vec![argument.clone(), duplicate_actual],
            CandidateCoverage::Open,
        ),
        Err(OracleContractError::InvalidCallBinding(_))
    ));

    let duplicate_relation_return =
        return_binding(&fixture, arena.handle(OracleRelationId::new(0)).unwrap());
    assert_eq!(
        call_bindings(
            fixture.call.clone(),
            &candidate,
            context.clone(),
            vec![argument.clone(), duplicate_relation_return],
            CandidateCoverage::Open,
        ),
        Err(OracleContractError::InvalidRelationIdentity)
    );

    let cross_callee = argument_binding(
        &fixture,
        arena.handle(OracleRelationId::new(5)).unwrap(),
        arena.handle(OracleRelationId::new(6)).unwrap(),
        fixture.other_callee.clone(),
    );
    assert_eq!(
        call_bindings(
            fixture.call.clone(),
            &candidate,
            context.clone(),
            vec![cross_callee],
            CandidateCoverage::Open,
        ),
        Err(OracleContractError::CrossProcedure)
    );

    let reference_location = AccessPathAtPoint::new(
        fixture.lexical_path(AccessPathTail::Exact),
        fixture.point.clone(),
        ObservationPhase::BeforeEffects,
        OracleCallContext::empty(),
    )
    .unwrap();
    for mode in [
        CallPassingMode::InputOutputReference,
        CallPassingMode::OutputReference,
    ] {
        let by_reference = argument_binding_with_endpoint(
            &fixture,
            arena.handle(OracleRelationId::new(7)).unwrap(),
            arena.handle(OracleRelationId::new(8)).unwrap(),
            fixture.callee.clone(),
            CallArgumentEndpoint::Location {
                value: fixture.value.clone(),
                location: reference_location.clone(),
            },
            mode,
        );
        call_bindings(
            fixture.call.clone(),
            &candidate,
            context.clone(),
            vec![by_reference],
            CandidateCoverage::Open,
        )
        .expect("a caller location supports ref/in-out and out passing modes");
    }

    let invalid_by_value = argument_binding_with_endpoint(
        &fixture,
        arena.handle(OracleRelationId::new(7)).unwrap(),
        arena.handle(OracleRelationId::new(8)).unwrap(),
        fixture.callee.clone(),
        CallArgumentEndpoint::Location {
            value: fixture.value.clone(),
            location: reference_location,
        },
        CallPassingMode::Value,
    );
    assert!(matches!(
        call_bindings(
            fixture.call.clone(),
            &candidate,
            context,
            vec![invalid_by_value],
            CandidateCoverage::Open,
        ),
        Err(OracleContractError::InvalidCallBinding(_))
    ));
}

#[test]
fn call_bindings_retain_context_and_reject_cross_arena_or_cross_context_inputs() {
    let fixture = Fixture::new();
    let candidate = dispatch_candidate(&fixture);
    let context = fixture.context();
    let first = call_binding_arena(&fixture, &context, 3);
    let second = call_binding_arena(&fixture, &context, 1);
    let argument = argument_binding(
        &fixture,
        first.handle(OracleRelationId::new(0)).unwrap(),
        first.handle(OracleRelationId::new(1)).unwrap(),
        fixture.callee.clone(),
    );
    let normal_return = return_binding(&fixture, first.handle(OracleRelationId::new(2)).unwrap());
    let bindings = call_bindings(
        fixture.call.clone(),
        &candidate,
        context.clone(),
        vec![argument.clone(), normal_return],
        CandidateCoverage::Exhaustive,
    )
    .expect("one call-binding arena should retain its exact context");
    assert_eq!(bindings.context(), &context);

    let cross_arena_return =
        return_binding(&fixture, second.handle(OracleRelationId::new(0)).unwrap());
    assert_eq!(
        call_bindings(
            fixture.call.clone(),
            &candidate,
            context.clone(),
            vec![argument, cross_arena_return],
            CandidateCoverage::Exhaustive,
        ),
        Err(OracleContractError::InvalidRelationIdentity)
    );

    let wrong_context_location = AccessPathAtPoint::new(
        fixture.lexical_path(AccessPathTail::Exact),
        fixture.point.clone(),
        ObservationPhase::BeforeEffects,
        OracleCallContext::empty(),
    )
    .unwrap();
    let reference_argument = argument_binding_with_endpoint(
        &fixture,
        first.handle(OracleRelationId::new(0)).unwrap(),
        first.handle(OracleRelationId::new(1)).unwrap(),
        fixture.callee.clone(),
        CallArgumentEndpoint::Location {
            value: fixture.value.clone(),
            location: wrong_context_location,
        },
        CallPassingMode::SharedReference,
    );
    assert!(matches!(
        call_bindings(
            fixture.call.clone(),
            &candidate,
            context,
            vec![reference_argument],
            CandidateCoverage::Open,
        ),
        Err(OracleContractError::InvalidCallBinding(_))
    ));
}

#[test]
fn call_bindings_require_the_exact_validated_dispatch_candidate() {
    let fixture = Fixture::new();
    let context = OracleCallContext::empty();
    let candidates = dispatch_candidates(
        &fixture,
        [fixture.callee.clone(), fixture.other_callee.clone()],
    );
    let arena = call_binding_arena(&fixture, &context, 2);
    let argument = argument_binding(
        &fixture,
        arena.handle(OracleRelationId::new(0)).unwrap(),
        arena.handle(OracleRelationId::new(1)).unwrap(),
        fixture.callee.clone(),
    );
    assert_eq!(
        call_bindings(
            fixture.call.clone(),
            &candidates[1],
            context.clone(),
            vec![argument.clone()],
            CandidateCoverage::Open,
        ),
        Err(OracleContractError::InvalidRelationIdentity)
    );

    let draft = dispatch_candidate_draft(
        fixture.callee.clone(),
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
        candidates[0].provenance().iter().cloned(),
    );
    assert_eq!(
        call_bindings(
            fixture.call.clone(),
            &draft,
            context,
            vec![argument],
            CandidateCoverage::Open,
        ),
        Err(OracleContractError::InvalidRelationIdentity)
    );
}

#[test]
fn call_argument_groups_distinguish_rest_formals_from_single_formals() {
    let context = OracleCallContext::empty();
    let rest = BindingFixture::new(
        vec![
            CallArgumentExpansion::Direct(ArgumentDomain::Positional),
            CallArgumentExpansion::Direct(ArgumentDomain::Positional),
        ],
        vec![FormalMultiplicity::Rest(ArgumentDomain::Positional)],
    );
    let rest_candidate = rest.candidate();
    let rest_arena = rest.binding_arena(&context, 4);
    let rest_group = binding_argument_group(
        &rest,
        &rest_arena,
        0,
        [0, 1],
        [
            (0, CallArgumentMember::Whole, 0, 1),
            (1, CallArgumentMember::Whole, 0, 2),
        ],
        CandidateCoverage::Exhaustive,
    );
    let CallBinding::ArgumentGroup(group) = &rest_group else {
        unreachable!()
    };
    assert_eq!(group.cardinality(), ArgumentCardinality::Exact(2));
    call_bindings(
        rest.call.clone(),
        &rest_candidate,
        context.clone(),
        vec![
            rest_group,
            rest.return_binding(rest_arena.handle(OracleRelationId::new(3)).unwrap()),
        ],
        CandidateCoverage::Exhaustive,
    )
    .expect("two direct actuals may map to one IR-declared rest formal");

    let single = BindingFixture::new(
        vec![
            CallArgumentExpansion::Direct(ArgumentDomain::Positional),
            CallArgumentExpansion::Direct(ArgumentDomain::Positional),
        ],
        vec![FormalMultiplicity::One],
    );
    let single_candidate = single.candidate();
    let single_arena = single.binding_arena(&context, 3);
    let duplicate_single = binding_argument_group(
        &single,
        &single_arena,
        0,
        [0, 1],
        [
            (0, CallArgumentMember::Whole, 0, 1),
            (1, CallArgumentMember::Whole, 0, 2),
        ],
        CandidateCoverage::Exhaustive,
    );
    assert!(matches!(
        call_bindings(
            single.call.clone(),
            &single_candidate,
            context,
            vec![duplicate_single],
            CandidateCoverage::Open,
        ),
        Err(OracleContractError::InvalidCallBinding(_))
    ));
}

#[test]
fn exact_spread_groups_map_structured_members_and_derive_exact_cardinality() {
    let fixture = BindingFixture::new(
        vec![CallArgumentExpansion::Spread(ArgumentDomain::Positional)],
        vec![FormalMultiplicity::One, FormalMultiplicity::One],
    );
    let context = OracleCallContext::empty();
    let candidate = fixture.candidate();
    let arena = fixture.binding_arena(&context, 4);
    let argument_group = binding_argument_group(
        &fixture,
        &arena,
        0,
        [0],
        [
            (0, CallArgumentMember::Positional(0), 0, 1),
            (0, CallArgumentMember::Positional(1), 1, 2),
        ],
        CandidateCoverage::Exhaustive,
    );
    let CallBinding::ArgumentGroup(group) = &argument_group else {
        unreachable!()
    };
    assert_eq!(group.cardinality(), ArgumentCardinality::Exact(2));
    call_bindings(
        fixture.call.clone(),
        &candidate,
        context,
        vec![
            argument_group,
            fixture.return_binding(arena.handle(OracleRelationId::new(3)).unwrap()),
        ],
        CandidateCoverage::Exhaustive,
    )
    .expect("an exact spread may map distinct structured members to fixed formals");
}

#[test]
fn argument_cardinality_counts_only_proven_mappings_across_coverage() {
    let fixture = BindingFixture::new(
        vec![CallArgumentExpansion::Spread(ArgumentDomain::Positional)],
        vec![FormalMultiplicity::Rest(ArgumentDomain::Positional)],
    );
    let context = OracleCallContext::empty();
    let candidate = fixture.candidate();
    let limits = OracleLimits::default();
    let arena = OracleRelationArena::new(
        OracleRelationOwner::CallBinding {
            call: fixture.call.clone(),
            callee: fixture.callee.clone(),
            context: context.clone(),
        },
        vec![
            OracleRelationRecord::new(
                OracleRelationKind::CallBinding,
                [fixture.evidence()],
                limits,
            )
            .unwrap(),
            OracleRelationRecord::new(
                OracleRelationKind::CallBinding,
                [fixture.evidence()],
                limits,
            )
            .unwrap(),
            OracleRelationRecord::new(
                OracleRelationKind::CallBinding,
                [fixture.evidence_with_quality(UNPROVEN_EVIDENCE)],
                limits,
            )
            .unwrap(),
            OracleRelationRecord::new(
                OracleRelationKind::CallBinding,
                [fixture.evidence()],
                limits,
            )
            .unwrap(),
        ],
        limits,
    )
    .unwrap();
    let argument_group = |coverage| {
        let mapping = |member, proof, relation_id| {
            oracle_candidate(
                CallArgumentMapping::new(
                    0,
                    member,
                    CallArgumentEndpoint::Value(fixture.arguments[0].clone()),
                    ProcedurePortHandle::parameter(fixture.callee.clone(), 0).unwrap(),
                    CallPassingMode::Value,
                ),
                proof,
                EvidenceCompleteness::Complete,
                [arena.handle(OracleRelationId::new(relation_id)).unwrap()],
            )
        };
        CallBinding::ArgumentGroup(
            CallArgumentGroup::new(
                &fixture.call,
                arena.handle(OracleRelationId::new(0)).unwrap(),
                [0],
                [
                    mapping(CallArgumentMember::Positional(0), ProofStatus::Proven, 1),
                    mapping(
                        CallArgumentMember::Positional(1),
                        ProofStatus::Unproven("second spread member remains possible".into()),
                        2,
                    ),
                ],
                coverage,
                OracleLimits::default(),
            )
            .unwrap(),
        )
    };

    let exhaustive = argument_group(CandidateCoverage::Exhaustive);
    let CallBinding::ArgumentGroup(group) = &exhaustive else {
        unreachable!()
    };
    assert_eq!(
        group.cardinality(),
        ArgumentCardinality::Between {
            minimum: 1,
            maximum: 2,
        }
    );
    call_bindings(
        fixture.call.clone(),
        &candidate,
        context.clone(),
        vec![
            exhaustive,
            fixture.return_binding(arena.handle(OracleRelationId::new(3)).unwrap()),
        ],
        CandidateCoverage::Exhaustive,
    )
    .expect("closed bindings retain an upper bound for unproven mapping candidates");

    let open = argument_group(CandidateCoverage::Open);
    let CallBinding::ArgumentGroup(group) = &open else {
        unreachable!()
    };
    assert_eq!(group.cardinality(), ArgumentCardinality::AtLeast(1));
    call_bindings(
        fixture.call.clone(),
        &candidate,
        context,
        vec![
            open,
            fixture.return_binding(arena.handle(OracleRelationId::new(3)).unwrap()),
        ],
        CandidateCoverage::Open,
    )
    .expect("open bindings expose only the proven mapping lower bound");
}

#[test]
fn open_and_truncated_spreads_bound_cardinality_and_top_level_coverage() {
    let context = OracleCallContext::empty();
    let open = BindingFixture::new(
        vec![CallArgumentExpansion::Spread(ArgumentDomain::Positional)],
        Vec::new(),
    );
    let open_candidate = open.candidate();
    let open_arena = open.binding_arena(&context, 2);
    let open_group = binding_argument_group(
        &open,
        &open_arena,
        0,
        [0],
        std::iter::empty(),
        CandidateCoverage::Open,
    );
    let CallBinding::ArgumentGroup(group) = &open_group else {
        unreachable!()
    };
    assert_eq!(group.cardinality(), ArgumentCardinality::AtLeast(0));
    let open_return = open.return_binding(open_arena.handle(OracleRelationId::new(1)).unwrap());
    call_bindings(
        open.call.clone(),
        &open_candidate,
        context.clone(),
        vec![open_group.clone(), open_return.clone()],
        CandidateCoverage::Open,
    )
    .expect("an unknown empty spread remains explicitly open");
    assert!(matches!(
        call_bindings(
            open.call.clone(),
            &open_candidate,
            context.clone(),
            vec![open_group, open_return],
            CandidateCoverage::Exhaustive,
        ),
        Err(OracleContractError::InvalidCallBinding(_))
    ));

    let truncated = BindingFixture::new(
        vec![CallArgumentExpansion::Spread(ArgumentDomain::Positional)],
        vec![FormalMultiplicity::Rest(ArgumentDomain::Positional)],
    );
    let truncated_candidate = truncated.candidate();
    let truncated_arena = truncated.binding_arena(&context, 3);
    let truncated_group = binding_argument_group(
        &truncated,
        &truncated_arena,
        0,
        [0],
        [(0, CallArgumentMember::Positional(0), 0, 1)],
        CandidateCoverage::Truncated,
    );
    let CallBinding::ArgumentGroup(group) = &truncated_group else {
        unreachable!()
    };
    assert_eq!(group.cardinality(), ArgumentCardinality::AtLeast(1));
    let truncated_return =
        truncated.return_binding(truncated_arena.handle(OracleRelationId::new(2)).unwrap());
    call_bindings(
        truncated.call.clone(),
        &truncated_candidate,
        context.clone(),
        vec![truncated_group.clone(), truncated_return.clone()],
        CandidateCoverage::Truncated,
    )
    .expect("a retained spread prefix remains explicitly truncated");
    assert!(matches!(
        call_bindings(
            truncated.call.clone(),
            &truncated_candidate,
            context,
            vec![truncated_group, truncated_return],
            CandidateCoverage::Open,
        ),
        Err(OracleContractError::InvalidCallBinding(_))
    ));
}

#[test]
fn exact_empty_spread_requires_a_proven_complete_closure_witness() {
    let fixture = BindingFixture::new(
        vec![CallArgumentExpansion::Spread(ArgumentDomain::Positional)],
        Vec::new(),
    );
    let context = OracleCallContext::empty();
    let candidate = fixture.candidate();
    let owner = OracleRelationOwner::CallBinding {
        call: fixture.call.clone(),
        callee: fixture.callee.clone(),
        context: context.clone(),
    };
    let limits = OracleLimits::default();
    let arena = OracleRelationArena::new(
        owner,
        vec![
            OracleRelationRecord::new(
                OracleRelationKind::CallBinding,
                [fixture.evidence_with_quality(UNPROVEN_EVIDENCE)],
                limits,
            )
            .unwrap(),
            OracleRelationRecord::new(
                OracleRelationKind::CallBinding,
                [fixture.evidence()],
                limits,
            )
            .unwrap(),
        ],
        limits,
    )
    .unwrap();
    let group = binding_argument_group(
        &fixture,
        &arena,
        0,
        [0],
        std::iter::empty(),
        CandidateCoverage::Exhaustive,
    );
    assert!(matches!(
        call_bindings(
            fixture.call.clone(),
            &candidate,
            context,
            vec![
                group,
                fixture.return_binding(arena.handle(OracleRelationId::new(1)).unwrap()),
            ],
            CandidateCoverage::Exhaustive,
        ),
        Err(OracleContractError::InvalidRelationQuality)
    ));

    let proven_arena = fixture.binding_arena(&OracleCallContext::empty(), 2);
    let exact_empty = binding_argument_group(
        &fixture,
        &proven_arena,
        0,
        [0],
        std::iter::empty(),
        CandidateCoverage::Exhaustive,
    );
    let CallBinding::ArgumentGroup(group) = &exact_empty else {
        unreachable!()
    };
    assert_eq!(group.cardinality(), ArgumentCardinality::Exact(0));
    call_bindings(
        fixture.call.clone(),
        &candidate,
        OracleCallContext::empty(),
        vec![
            exact_empty,
            fixture.return_binding(proven_arena.handle(OracleRelationId::new(1)).unwrap()),
        ],
        CandidateCoverage::Exhaustive,
    )
    .expect("a proven closure witness can establish an exact empty spread");
}

#[test]
fn spread_groups_reject_domain_mismatches_and_duplicate_members() {
    let fixture = BindingFixture::new(
        vec![CallArgumentExpansion::Spread(ArgumentDomain::Positional)],
        vec![FormalMultiplicity::Rest(ArgumentDomain::Keyword)],
    );
    let context = OracleCallContext::empty();
    let candidate = fixture.candidate();
    let arena = fixture.binding_arena(&context, 3);
    let mismatched = binding_argument_group(
        &fixture,
        &arena,
        0,
        [0],
        [(0, CallArgumentMember::Positional(0), 0, 1)],
        CandidateCoverage::Exhaustive,
    );
    assert!(matches!(
        call_bindings(
            fixture.call.clone(),
            &candidate,
            context,
            vec![mismatched],
            CandidateCoverage::Open,
        ),
        Err(OracleContractError::InvalidCallBinding(_))
    ));

    let mapping = || {
        CallArgumentMapping::new(
            0,
            CallArgumentMember::Positional(0),
            CallArgumentEndpoint::Value(fixture.arguments[0].clone()),
            ProcedurePortHandle::parameter(fixture.callee.clone(), 0).unwrap(),
            CallPassingMode::Value,
        )
    };
    assert!(matches!(
        CallArgumentGroup::new(
            &fixture.call,
            arena.handle(OracleRelationId::new(0)).unwrap(),
            [0],
            [
                proven_candidate(mapping(), [arena.handle(OracleRelationId::new(1)).unwrap()],),
                proven_candidate(mapping(), [arena.handle(OracleRelationId::new(2)).unwrap()],),
            ],
            CandidateCoverage::Open,
            OracleLimits::default(),
        ),
        Err(OracleContractError::InvalidCallBinding(_))
    ));
}

#[test]
fn memory_store_handles_name_only_real_store_events() {
    let fixture = Fixture::new();
    assert_eq!(
        MemoryStoreHandle::new(fixture.point.clone(), 0),
        Err(OracleContractError::InvalidStoreEvent)
    );
    let store = MemoryStoreHandle::new(fixture.point.clone(), 1).unwrap();
    assert_eq!(store.event_index(), 1);
    assert_eq!(store.location(), &fixture.lexical_location);
    assert_eq!(store.value(), &fixture.value);
}

#[test]
fn field_and_index_store_observations_require_the_exact_base_value() {
    let fixture = Fixture::new();
    let stored = fixture.value_at_point();
    let correct_base = fixture.value_at_point();
    let wrong_base = fixture.value_in_context(fixture.result.clone(), OracleCallContext::empty());

    let field_path = AccessPath::exact(
        AccessPathRoot::Value(fixture.value.clone()),
        vec![AccessSelector::Field(fixture.scoped_field())],
        OracleLimits::default(),
    )
    .unwrap();
    let field_target = AccessPathAtPoint::new(
        field_path,
        fixture.point.clone(),
        ObservationPhase::BeforeEffects,
        OracleCallContext::empty(),
    )
    .unwrap();
    let field_store = MemoryStoreHandle::new(fixture.point.clone(), 3).unwrap();
    let exact_field = StoreAtPoint::new(
        field_store.clone(),
        field_target.clone(),
        stored.clone(),
        Some(correct_base.clone()),
    )
    .expect("field store should accept its exact IR base");
    assert_eq!(exact_field.base().unwrap().value(), &fixture.value);
    assert_eq!(
        StoreAtPoint::new(
            field_store.clone(),
            field_target.clone(),
            stored.clone(),
            None,
        ),
        Err(OracleContractError::StoreLocationMismatch)
    );
    assert_eq!(
        StoreAtPoint::new(
            field_store,
            field_target,
            stored.clone(),
            Some(wrong_base.clone()),
        ),
        Err(OracleContractError::StoreLocationMismatch)
    );
    let wrong_field_root = AccessPathAtPoint::new(
        AccessPath::exact(
            AccessPathRoot::Value(fixture.result.clone()),
            vec![AccessSelector::Field(fixture.scoped_field())],
            OracleLimits::default(),
        )
        .unwrap(),
        fixture.point.clone(),
        ObservationPhase::BeforeEffects,
        OracleCallContext::empty(),
    )
    .unwrap();
    assert_eq!(
        StoreAtPoint::new(
            MemoryStoreHandle::new(fixture.point.clone(), 3).unwrap(),
            wrong_field_root,
            stored.clone(),
            Some(correct_base.clone()),
        ),
        Err(OracleContractError::StoreLocationMismatch)
    );

    let index_path = AccessPath::exact(
        AccessPathRoot::Value(fixture.value.clone()),
        vec![AccessSelector::Index(IndexSelector::Any)],
        OracleLimits::default(),
    )
    .unwrap();
    let index_target = AccessPathAtPoint::new(
        index_path,
        fixture.point.clone(),
        ObservationPhase::BeforeEffects,
        OracleCallContext::empty(),
    )
    .unwrap();
    let index_store = MemoryStoreHandle::new(fixture.point.clone(), 2).unwrap();
    StoreAtPoint::new(
        index_store.clone(),
        index_target.clone(),
        stored.clone(),
        Some(correct_base.clone()),
    )
    .expect("indexed store should accept its exact IR base");
    assert_eq!(
        StoreAtPoint::new(
            index_store.clone(),
            index_target.clone(),
            stored.clone(),
            None,
        ),
        Err(OracleContractError::StoreLocationMismatch)
    );
    assert_eq!(
        StoreAtPoint::new(index_store, index_target, stored, Some(wrong_base),),
        Err(OracleContractError::StoreLocationMismatch)
    );
    let wrong_index_root = AccessPathAtPoint::new(
        AccessPath::exact(
            AccessPathRoot::Value(fixture.result.clone()),
            vec![AccessSelector::Index(IndexSelector::Any)],
            OracleLimits::default(),
        )
        .unwrap(),
        fixture.point.clone(),
        ObservationPhase::BeforeEffects,
        OracleCallContext::empty(),
    )
    .unwrap();
    assert_eq!(
        StoreAtPoint::new(
            MemoryStoreHandle::new(fixture.point.clone(), 2).unwrap(),
            wrong_index_root,
            fixture.value_at_point(),
            Some(correct_base),
        ),
        Err(OracleContractError::StoreLocationMismatch)
    );
}

#[test]
fn strong_update_certificate_is_bound_to_one_actual_store_event() {
    let fixture = Fixture::new();
    let store = fixture.lexical_store(AccessPathTail::Exact);
    let object = fixture.lexical_object(ObjectCardinality::Singleton);
    let location =
        AbstractLocation::new(object.clone(), fixture.lexical_path(AccessPathTail::Exact)).unwrap();
    let eligibility = UpdateEligibility::evaluate(
        store.clone(),
        strong_evidence(&fixture, &store, &object, &location),
    );
    let UpdateEligibility::Strong(certificate) = eligibility else {
        panic!("complete singleton evidence should justify a strong update");
    };
    assert_eq!(certificate.store().store().event_index(), 1);
    assert_eq!(
        certificate.store().store().location(),
        &fixture.lexical_location
    );
    assert_eq!(certificate.location(), &location);
    assert_eq!(certificate.provenance().len(), 4);
}

#[test]
fn strong_update_rejects_relations_backed_by_unproven_or_partial_ir_evidence() {
    let fixture = Fixture::new();
    let store = fixture.lexical_store(AccessPathTail::Exact);
    let object = fixture.lexical_object(ObjectCardinality::Singleton);
    let location =
        AbstractLocation::new(object.clone(), fixture.lexical_path(AccessPathTail::Exact)).unwrap();

    for evidence_id in [UNPROVEN_EVIDENCE, PARTIAL_EVIDENCE] {
        let evidence = strong_evidence_with_backing(
            &store,
            &object,
            &location,
            fixture.evidence_with_quality(evidence_id),
        );
        assert_weak(
            UpdateEligibility::evaluate(store.clone(), evidence),
            WeakUpdateReason::UnprovenEvidence,
        );
    }
}

#[test]
fn strong_update_rejects_non_singleton_or_non_exact_domains() {
    let fixture = Fixture::new();
    let exact_store = fixture.lexical_store(AccessPathTail::Exact);
    let singleton = fixture.lexical_object(ObjectCardinality::Singleton);
    let exact_location = AbstractLocation::new(
        singleton.clone(),
        fixture.lexical_path(AccessPathTail::Exact),
    )
    .unwrap();

    let base = strong_evidence(&fixture, &exact_store, &singleton, &exact_location);
    let open = rebuild_strong_evidence(
        &base,
        Some(location_set(
            base.locations().candidates().iter().cloned(),
            CandidateCoverage::Open,
        )),
        None,
        None,
        None,
    );
    assert_weak(
        UpdateEligibility::evaluate(exact_store.clone(), open),
        WeakUpdateReason::NonExhaustiveLocations,
    );

    let base = strong_evidence(&fixture, &exact_store, &singleton, &exact_location);
    let truncated = rebuild_strong_evidence(
        &base,
        None,
        Some(object_set(
            base.objects().candidates().iter().cloned(),
            CandidateCoverage::Truncated,
        )),
        None,
        None,
    );
    assert_weak(
        UpdateEligibility::evaluate(exact_store.clone(), truncated),
        WeakUpdateReason::TruncatedObjects,
    );

    let base = strong_evidence(&fixture, &exact_store, &singleton, &exact_location);
    let location_candidate = base.locations().candidates()[0].clone();
    let multiple = rebuild_strong_evidence(
        &base,
        Some(location_set(
            [location_candidate.clone(), location_candidate],
            CandidateCoverage::Exhaustive,
        )),
        None,
        None,
        None,
    );
    assert_weak(
        UpdateEligibility::evaluate(exact_store.clone(), multiple),
        WeakUpdateReason::MultipleLocations,
    );

    let summary_object = fixture.lexical_object(ObjectCardinality::Summary);
    let summary_location = AbstractLocation::new(
        summary_object.clone(),
        fixture.lexical_path(AccessPathTail::Exact),
    )
    .unwrap();
    assert_weak(
        UpdateEligibility::evaluate(
            exact_store.clone(),
            strong_evidence(&fixture, &exact_store, &summary_object, &summary_location),
        ),
        WeakUpdateReason::SummaryObject,
    );

    let unknown_object = fixture.lexical_object(ObjectCardinality::Unknown);
    let unknown_location = AbstractLocation::new(
        unknown_object.clone(),
        fixture.lexical_path(AccessPathTail::Exact),
    )
    .unwrap();
    assert_weak(
        UpdateEligibility::evaluate(
            exact_store.clone(),
            strong_evidence(&fixture, &exact_store, &unknown_object, &unknown_location),
        ),
        WeakUpdateReason::UnknownObjectCardinality,
    );

    let summary_store = fixture.lexical_store(AccessPathTail::Summary);
    let summary_path_location = AbstractLocation::new(
        singleton.clone(),
        fixture.lexical_path(AccessPathTail::Summary),
    )
    .unwrap();
    assert_weak(
        UpdateEligibility::evaluate(
            summary_store.clone(),
            strong_evidence(&fixture, &summary_store, &singleton, &summary_path_location),
        ),
        WeakUpdateReason::SummaryPath,
    );

    let (wildcard_store, wildcard_object, wildcard_location) = fixture.wildcard_store();
    assert!(!wildcard_store.target().path().is_exact());
    assert_weak(
        UpdateEligibility::evaluate(
            wildcard_store.clone(),
            strong_evidence(
                &fixture,
                &wildcard_store,
                &wildcard_object,
                &wildcard_location,
            ),
        ),
        WeakUpdateReason::SummaryPath,
    );
}

#[test]
fn strong_update_rejects_subject_and_provenance_mismatches() {
    let fixture = Fixture::new();
    let store = fixture.lexical_store(AccessPathTail::Exact);
    let object = fixture.lexical_object(ObjectCardinality::Singleton);
    let location =
        AbstractLocation::new(object.clone(), fixture.lexical_path(AccessPathTail::Exact)).unwrap();
    let (other_store, other_object, other_location) = fixture.wildcard_store();

    let base = strong_evidence(&fixture, &store, &object, &location);
    let alias_subject = rebuild_strong_evidence(
        &base,
        None,
        None,
        Some(candidate_with_value(
            base.alias_exclusivity(),
            AliasExclusivityWitness::new(
                other_store.clone(),
                other_location.clone(),
                AliasExclusivity::Exclusive,
            )
            .unwrap(),
        )),
        None,
    );
    assert_weak(
        UpdateEligibility::evaluate(store.clone(), alias_subject),
        WeakUpdateReason::AliasSubjectMismatch,
    );

    let base = strong_evidence(&fixture, &store, &object, &location);
    let escape_subject = rebuild_strong_evidence(
        &base,
        None,
        None,
        None,
        Some(candidate_with_value(
            base.escape(),
            EscapeWitness::new(other_store, other_object, EscapeStatus::DoesNotEscape).unwrap(),
        )),
    );
    assert_weak(
        UpdateEligibility::evaluate(store.clone(), escape_subject),
        WeakUpdateReason::EscapeSubjectMismatch,
    );

    let base = strong_evidence(&fixture, &store, &object, &location);
    let wrong_owner = relation_arena(
        OracleRelationOwner::Locations(Box::new(store.target().clone())),
        [OracleRelationKind::Location],
        &fixture.evidence(),
    );
    let owner_mismatch = rebuild_strong_evidence(
        &base,
        Some(location_set(
            [candidate_with_provenance(
                &base.locations().candidates()[0],
                [wrong_owner.handle(OracleRelationId::new(0)).unwrap()],
            )],
            CandidateCoverage::Exhaustive,
        )),
        None,
        None,
        None,
    );
    assert_weak(
        UpdateEligibility::evaluate(store.clone(), owner_mismatch),
        WeakUpdateReason::MismatchedProvenance,
    );

    let base = strong_evidence(&fixture, &store, &object, &location);
    let kind_mismatch = rebuild_strong_evidence(
        &base,
        Some(location_set(
            [candidate_with_provenance(
                &base.locations().candidates()[0],
                base.objects().candidates()[0].provenance().iter().cloned(),
            )],
            CandidateCoverage::Exhaustive,
        )),
        None,
        None,
        None,
    );
    assert_weak(
        UpdateEligibility::evaluate(store.clone(), kind_mismatch),
        WeakUpdateReason::MismatchedProvenance,
    );

    let base = strong_evidence(&fixture, &store, &object, &location);
    let second_arena = relation_arena(
        OracleRelationOwner::StrongUpdate(Box::new(store.clone())),
        [OracleRelationKind::Location],
        &fixture.evidence(),
    );
    let arena_mismatch = rebuild_strong_evidence(
        &base,
        Some(location_set(
            [candidate_with_provenance(
                &base.locations().candidates()[0],
                [second_arena.handle(OracleRelationId::new(0)).unwrap()],
            )],
            CandidateCoverage::Exhaustive,
        )),
        None,
        None,
        None,
    );
    assert_weak(
        UpdateEligibility::evaluate(store, arena_mismatch),
        WeakUpdateReason::MismatchedProvenance,
    );
}

#[test]
fn strong_update_rejects_incomplete_alias_and_escape_proofs() {
    let fixture = Fixture::new();
    let store = fixture.lexical_store(AccessPathTail::Exact);
    let object = fixture.lexical_object(ObjectCardinality::Singleton);
    let location =
        AbstractLocation::new(object.clone(), fixture.lexical_path(AccessPathTail::Exact)).unwrap();

    let base = strong_evidence(&fixture, &store, &object, &location);
    let incomplete_alias = rebuild_strong_evidence(
        &base,
        None,
        None,
        Some(candidate_with_quality(
            base.alias_exclusivity(),
            ProofStatus::Proven,
            EvidenceCompleteness::Partial("alias search is incomplete".into()),
        )),
        None,
    );
    assert_weak(
        UpdateEligibility::evaluate(store.clone(), incomplete_alias),
        WeakUpdateReason::IncompleteAliasEvidence,
    );

    let base = strong_evidence(&fixture, &store, &object, &location);
    let incomplete_escape = rebuild_strong_evidence(
        &base,
        None,
        None,
        None,
        Some(candidate_with_quality(
            base.escape(),
            ProofStatus::Proven,
            EvidenceCompleteness::Partial("escape search is incomplete".into()),
        )),
    );
    assert_weak(
        UpdateEligibility::evaluate(store.clone(), incomplete_escape),
        WeakUpdateReason::IncompleteEscapeEvidence,
    );

    let base = strong_evidence(&fixture, &store, &object, &location);
    let potential_alias = rebuild_strong_evidence(
        &base,
        None,
        None,
        Some(candidate_with_value(
            base.alias_exclusivity(),
            AliasExclusivityWitness::new(
                store.clone(),
                location.clone(),
                AliasExclusivity::PotentialAliases,
            )
            .unwrap(),
        )),
        None,
    );
    assert_weak(
        UpdateEligibility::evaluate(store.clone(), potential_alias),
        WeakUpdateReason::PotentialAliases,
    );

    let base = strong_evidence(&fixture, &store, &object, &location);
    let escaping = rebuild_strong_evidence(
        &base,
        None,
        None,
        None,
        Some(candidate_with_value(
            base.escape(),
            EscapeWitness::new(store.clone(), object.clone(), EscapeStatus::MayEscape).unwrap(),
        )),
    );
    assert_weak(
        UpdateEligibility::evaluate(store.clone(), escaping),
        WeakUpdateReason::EscapingObject,
    );

    let base = strong_evidence(&fixture, &store, &object, &location);
    let unproven = rebuild_strong_evidence(
        &base,
        None,
        None,
        Some(candidate_with_quality(
            base.alias_exclusivity(),
            ProofStatus::Unproven("alias result was not proved".into()),
            EvidenceCompleteness::Complete,
        )),
        None,
    );
    assert_weak(
        UpdateEligibility::evaluate(store.clone(), unproven),
        WeakUpdateReason::UnprovenEvidence,
    );

    let base = strong_evidence(&fixture, &store, &object, &location);
    let missing_provenance = rebuild_strong_evidence(
        &base,
        None,
        None,
        None,
        Some(candidate_with_provenance(base.escape(), std::iter::empty())),
    );
    assert_weak(
        UpdateEligibility::evaluate(store, missing_provenance),
        WeakUpdateReason::MissingProvenance,
    );
}

fn assert_limit_exceeded<T: std::fmt::Debug>(
    result: Result<T, OracleContractError>,
    expected_dimension: &'static str,
    expected_limit: usize,
    expected_attempted: usize,
) {
    match result {
        Err(OracleContractError::LimitExceeded {
            dimension,
            limit,
            attempted,
        }) => {
            assert_eq!(dimension, expected_dimension);
            assert_eq!(limit, expected_limit);
            assert_eq!(attempted, expected_attempted);
        }
        other => panic!("expected {expected_dimension} limit failure, got {other:?}"),
    }
}

#[test]
fn candidate_provenance_is_bounded_before_collection_and_rejects_duplicates() {
    let fixture = Fixture::new();
    let query = fixture.value_at_point();
    let arena = relation_arena(
        OracleRelationOwner::PointsTo(Box::new(query)),
        [OracleRelationKind::PointsTo],
        &fixture.evidence(),
    );
    let relation = arena.handle(OracleRelationId::new(0)).unwrap();
    let limits = OracleLimits::new(OracleLimitValues {
        provenance_records: 1,
        ..OracleLimitValues::uniform(4)
    })
    .unwrap();

    let generic_pulls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed_pulls = Arc::clone(&generic_pulls);
    let repeated_relation = relation.clone();
    let unbounded = std::iter::from_fn(move || {
        observed_pulls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Some(repeated_relation.clone())
    });
    assert_limit_exceeded(
        OracleCandidate::new(
            (),
            ProofStatus::Proven,
            EvidenceCompleteness::Complete,
            unbounded,
            limits,
        ),
        "provenance_records",
        1,
        2,
    );
    assert_eq!(generic_pulls.load(std::sync::atomic::Ordering::Relaxed), 2);

    let duplicate_limits = OracleLimits::uniform(2).unwrap();
    assert_eq!(
        OracleCandidate::proven((), [relation.clone(), relation.clone()], duplicate_limits,),
        Err(OracleContractError::InvalidRelationIdentity)
    );

    let dispatch_pulls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed_pulls = Arc::clone(&dispatch_pulls);
    let repeated_relation = relation.clone();
    let unbounded = std::iter::from_fn(move || {
        observed_pulls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Some(repeated_relation.clone())
    });
    assert_limit_exceeded(
        DispatchCandidate::new(
            fixture.callee.clone(),
            ProofStatus::Proven,
            EvidenceCompleteness::Complete,
            unbounded,
            limits,
        ),
        "provenance_records",
        1,
        2,
    );
    assert_eq!(dispatch_pulls.load(std::sync::atomic::Ordering::Relaxed), 2);
    assert_eq!(
        DispatchCandidate::new(
            fixture.callee,
            ProofStatus::Proven,
            EvidenceCompleteness::Complete,
            [relation.clone(), relation],
            duplicate_limits,
        ),
        Err(OracleContractError::InvalidRelationIdentity)
    );
}

#[test]
fn argument_groups_bound_exact_sources_and_mappings_before_collection() {
    let fixture = BindingFixture::new(
        vec![CallArgumentExpansion::Direct(ArgumentDomain::Positional)],
        vec![FormalMultiplicity::One],
    );
    let context = OracleCallContext::empty();
    let arena = fixture.binding_arena(&context, 2);
    let closure = arena.handle(OracleRelationId::new(0)).unwrap();

    let source_pulls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed_pulls = Arc::clone(&source_pulls);
    let unbounded_sources = std::iter::from_fn(move || {
        observed_pulls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Some(0)
    });
    assert!(matches!(
        CallArgumentGroup::new(
            &fixture.call,
            closure.clone(),
            unbounded_sources,
            std::iter::empty(),
            CandidateCoverage::Open,
            OracleLimits::uniform(8).unwrap(),
        ),
        Err(OracleContractError::InvalidCallBinding(_))
    ));
    assert_eq!(source_pulls.load(std::sync::atomic::Ordering::Relaxed), 2);

    let mapping = proven_candidate(
        CallArgumentMapping::new(
            0,
            CallArgumentMember::Whole,
            CallArgumentEndpoint::Value(fixture.arguments[0].clone()),
            ProcedurePortHandle::parameter(fixture.callee.clone(), 0).unwrap(),
            CallPassingMode::Value,
        ),
        [arena.handle(OracleRelationId::new(1)).unwrap()],
    );
    let mapping_pulls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed_pulls = Arc::clone(&mapping_pulls);
    let unbounded_mappings = std::iter::from_fn(move || {
        observed_pulls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Some(mapping.clone())
    });
    let limits = OracleLimits::new(OracleLimitValues {
        call_binding_entries: 2,
        ..OracleLimitValues::uniform(8)
    })
    .unwrap();
    assert_limit_exceeded(
        CallArgumentGroup::new(
            &fixture.call,
            closure,
            [0],
            unbounded_mappings,
            CandidateCoverage::Open,
            limits,
        ),
        "call_binding_entries",
        2,
        3,
    );
    assert_eq!(mapping_pulls.load(std::sync::atomic::Ordering::Relaxed), 2);
}

#[test]
fn call_bindings_enforce_the_aggregate_group_entry_budget() {
    let fixture = BindingFixture::new(
        vec![CallArgumentExpansion::Direct(ArgumentDomain::Positional)],
        vec![FormalMultiplicity::One],
    );
    let context = OracleCallContext::empty();
    let candidate = fixture.candidate();
    let arena = fixture.binding_arena(&context, 2);
    let group = binding_argument_group(
        &fixture,
        &arena,
        0,
        [0],
        [(0, CallArgumentMember::Whole, 0, 1)],
        CandidateCoverage::Open,
    );
    let limits = OracleLimits::new(OracleLimitValues {
        call_binding_entries: 2,
        ..OracleLimitValues::uniform(8)
    })
    .unwrap();

    assert_limit_exceeded(
        CallBindings::new(
            fixture.call,
            &candidate,
            context,
            [group],
            CandidateCoverage::Open,
            limits,
        ),
        "call_binding_entries",
        2,
        3,
    );
}

#[test]
fn strong_update_evidence_revalidates_typed_location_and_object_breadth() {
    let fixture = Fixture::new();
    let store = fixture.lexical_store(AccessPathTail::Exact);
    let object = fixture.lexical_object(ObjectCardinality::Singleton);
    let location =
        AbstractLocation::new(object.clone(), fixture.lexical_path(AccessPathTail::Exact)).unwrap();
    let base = strong_evidence(&fixture, &store, &object, &location);

    let location_candidate = base.locations().candidates()[0].clone();
    let broad_locations = OracleSet::bounded_locations(
        [location_candidate.clone(), location_candidate],
        CandidateCoverage::Exhaustive,
        OracleLimits::default(),
    );
    let location_limits = OracleLimits::new(OracleLimitValues {
        alias_breadth: 1,
        ..OracleLimitValues::uniform(8)
    })
    .unwrap();
    assert_limit_exceeded(
        StrongUpdateEvidence::new(
            broad_locations,
            base.objects().clone(),
            base.alias_exclusivity().clone(),
            base.escape().clone(),
            location_limits,
        ),
        "alias_breadth",
        1,
        2,
    );

    let object_candidate = base.objects().candidates()[0].clone();
    let broad_objects = OracleSet::bounded_objects(
        [object_candidate.clone(), object_candidate],
        CandidateCoverage::Exhaustive,
        OracleLimits::default(),
    );
    let object_limits = OracleLimits::new(OracleLimitValues {
        objects_per_value: 1,
        ..OracleLimitValues::uniform(8)
    })
    .unwrap();
    assert_limit_exceeded(
        StrongUpdateEvidence::new(
            base.locations().clone(),
            broad_objects,
            base.alias_exclusivity().clone(),
            base.escape().clone(),
            object_limits,
        ),
        "objects_per_value",
        1,
        2,
    );
}

#[test]
fn every_non_dispatch_result_revalidates_whole_retained_arenas() {
    let fixture = Fixture::new();
    let limits = OracleLimits::new(OracleLimitValues {
        provenance_records: 1,
        ..OracleLimitValues::uniform(8)
    })
    .unwrap();

    let value_query = fixture.value_at_point();
    let object = fixture.lexical_object(ObjectCardinality::Singleton);
    let points_to_arena = relation_arena(
        OracleRelationOwner::PointsTo(Box::new(value_query.clone())),
        [OracleRelationKind::PointsTo, OracleRelationKind::PointsTo],
        &fixture.evidence(),
    );
    assert_limit_exceeded(
        PointsToResult::new(
            value_query,
            [proven_candidate(
                object.clone(),
                [points_to_arena.handle(OracleRelationId::new(0)).unwrap()],
            )],
            CandidateCoverage::Exhaustive,
            limits,
        ),
        "provenance_records",
        1,
        2,
    );

    let access_query = AccessPathAtPoint::new(
        fixture.lexical_path(AccessPathTail::Exact),
        fixture.point.clone(),
        ObservationPhase::BeforeEffects,
        OracleCallContext::empty(),
    )
    .unwrap();
    let location =
        AbstractLocation::new(object.clone(), fixture.lexical_path(AccessPathTail::Exact)).unwrap();
    let location_arena = relation_arena(
        OracleRelationOwner::Locations(Box::new(access_query.clone())),
        [OracleRelationKind::Location, OracleRelationKind::Location],
        &fixture.evidence(),
    );
    assert_limit_exceeded(
        LocationResult::new(
            access_query.clone(),
            [proven_candidate(
                location.clone(),
                [location_arena.handle(OracleRelationId::new(0)).unwrap()],
            )],
            CandidateCoverage::Exhaustive,
            limits,
        ),
        "provenance_records",
        1,
        2,
    );

    let context = OracleCallContext::empty();
    let value_flow_arena = relation_arena(
        OracleRelationOwner::ProcedureValueFlow {
            procedure: fixture.caller.clone(),
            context: context.clone(),
        },
        [OracleRelationKind::ValueFlow, OracleRelationKind::ValueFlow],
        &fixture.evidence(),
    );
    let relation = ValueFlowRelation {
        id: value_flow_arena.handle(OracleRelationId::new(0)).unwrap(),
        kind: ValueFlowRelationKind::Assignment,
        source: ValueFlowEndpoint::Value(fixture.value.clone()),
        target: ValueFlowEndpoint::Value(fixture.result.clone()),
        proof: ProofStatus::Proven,
        completeness: EvidenceCompleteness::Complete,
    };
    assert_limit_exceeded(
        ValueFlowSnapshot::new(
            fixture.caller.clone(),
            context.clone(),
            vec![relation],
            CandidateCoverage::Exhaustive,
            limits,
        ),
        "provenance_records",
        1,
        2,
    );

    let alias_query = AliasQuery::new(access_query.clone(), access_query).unwrap();
    let alias_arena = relation_arena(
        OracleRelationOwner::Alias(Box::new(alias_query.clone())),
        [OracleRelationKind::Alias, OracleRelationKind::Alias],
        &fixture.evidence(),
    );
    assert_limit_exceeded(
        AliasResult::new(
            alias_query,
            proven_candidate(
                AliasRelation::MustAlias,
                [alias_arena.handle(OracleRelationId::new(0)).unwrap()],
            ),
            limits,
        ),
        "provenance_records",
        1,
        2,
    );

    let candidate = dispatch_candidate(&fixture);
    let binding_arena = call_binding_arena(&fixture, &context, 1);
    assert_limit_exceeded(
        CallBindings::new(
            fixture.call.clone(),
            &candidate,
            context,
            [return_binding(
                &fixture,
                binding_arena.handle(OracleRelationId::new(0)).unwrap(),
            )],
            CandidateCoverage::Open,
            limits,
        ),
        "provenance_records",
        1,
        2,
    );

    let store = fixture.lexical_store(AccessPathTail::Exact);
    let strong = strong_evidence(&fixture, &store, &object, &location);
    assert_limit_exceeded(
        StrongUpdateEvidence::new(
            strong.locations().clone(),
            strong.objects().clone(),
            strong.alias_exclusivity().clone(),
            strong.escape().clone(),
            limits,
        ),
        "provenance_records",
        1,
        4,
    );
}

#[test]
fn every_non_dispatch_result_revalidates_aggregate_retained_evidence() {
    let fixture = Fixture::new();
    let limits = OracleLimits::new(OracleLimitValues {
        evidence_handles: 1,
        ..OracleLimitValues::uniform(8)
    })
    .unwrap();
    let evidence = fixture.evidence();
    let arena_with_two_evidence = |owner, kind| {
        OracleRelationArena::new(
            owner,
            vec![
                OracleRelationRecord::new(
                    kind,
                    [evidence.clone(), evidence.clone()],
                    OracleLimits::default(),
                )
                .unwrap(),
            ],
            OracleLimits::default(),
        )
        .unwrap()
    };

    let value_query = fixture.value_at_point();
    let object = fixture.lexical_object(ObjectCardinality::Singleton);
    let points_to_arena = arena_with_two_evidence(
        OracleRelationOwner::PointsTo(Box::new(value_query.clone())),
        OracleRelationKind::PointsTo,
    );
    assert_limit_exceeded(
        PointsToResult::new(
            value_query,
            [proven_candidate(
                object.clone(),
                [points_to_arena.handle(OracleRelationId::new(0)).unwrap()],
            )],
            CandidateCoverage::Exhaustive,
            limits,
        ),
        "evidence_handles",
        1,
        2,
    );

    let access_query = AccessPathAtPoint::new(
        fixture.lexical_path(AccessPathTail::Exact),
        fixture.point.clone(),
        ObservationPhase::BeforeEffects,
        OracleCallContext::empty(),
    )
    .unwrap();
    let location =
        AbstractLocation::new(object.clone(), fixture.lexical_path(AccessPathTail::Exact)).unwrap();
    let location_arena = arena_with_two_evidence(
        OracleRelationOwner::Locations(Box::new(access_query.clone())),
        OracleRelationKind::Location,
    );
    assert_limit_exceeded(
        LocationResult::new(
            access_query.clone(),
            [proven_candidate(
                location.clone(),
                [location_arena.handle(OracleRelationId::new(0)).unwrap()],
            )],
            CandidateCoverage::Exhaustive,
            limits,
        ),
        "evidence_handles",
        1,
        2,
    );

    let context = OracleCallContext::empty();
    let value_flow_arena = arena_with_two_evidence(
        OracleRelationOwner::ProcedureValueFlow {
            procedure: fixture.caller.clone(),
            context: context.clone(),
        },
        OracleRelationKind::ValueFlow,
    );
    let relation = ValueFlowRelation {
        id: value_flow_arena.handle(OracleRelationId::new(0)).unwrap(),
        kind: ValueFlowRelationKind::Assignment,
        source: ValueFlowEndpoint::Value(fixture.value.clone()),
        target: ValueFlowEndpoint::Value(fixture.result.clone()),
        proof: ProofStatus::Proven,
        completeness: EvidenceCompleteness::Complete,
    };
    assert_limit_exceeded(
        ValueFlowSnapshot::new(
            fixture.caller.clone(),
            context.clone(),
            vec![relation],
            CandidateCoverage::Exhaustive,
            limits,
        ),
        "evidence_handles",
        1,
        2,
    );

    let alias_query = AliasQuery::new(access_query.clone(), access_query).unwrap();
    let alias_arena = arena_with_two_evidence(
        OracleRelationOwner::Alias(Box::new(alias_query.clone())),
        OracleRelationKind::Alias,
    );
    assert_limit_exceeded(
        AliasResult::new(
            alias_query,
            proven_candidate(
                AliasRelation::MustAlias,
                [alias_arena.handle(OracleRelationId::new(0)).unwrap()],
            ),
            limits,
        ),
        "evidence_handles",
        1,
        2,
    );

    let candidate = dispatch_candidate(&fixture);
    let binding_arena = call_binding_arena(&fixture, &context, 1);
    assert_limit_exceeded(
        CallBindings::new(
            fixture.call.clone(),
            &candidate,
            context,
            [return_binding(
                &fixture,
                binding_arena.handle(OracleRelationId::new(0)).unwrap(),
            )],
            CandidateCoverage::Open,
            limits,
        ),
        "evidence_handles",
        1,
        2,
    );

    let store = fixture.lexical_store(AccessPathTail::Exact);
    let strong = strong_evidence(&fixture, &store, &object, &location);
    assert_limit_exceeded(
        StrongUpdateEvidence::new(
            strong.locations().clone(),
            strong.objects().clone(),
            strong.alias_exclusivity().clone(),
            strong.escape().clone(),
            limits,
        ),
        "evidence_handles",
        1,
        4,
    );
}
