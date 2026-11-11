//! SQL-readable identities for composed output products.

use serde::{Deserialize, Serialize};

use super::{TaintAnalysisPlan, TaintFindingReport};
use crate::analyzer::semantic::{
    AdapterSemanticsVersion, CallSiteId, ConfigurationFingerprint, ContentIdentity,
    DeclarationLocator, DeclarationSegment, DeclarationSegmentKind, DependencyFingerprint,
    EvidenceCompleteness, OverlaySnapshotId, ProcedureId, ProofStatus, SemanticArtifactKey,
    SemanticIrVersion, SemanticLanguage, SemanticLocator, SemanticRole, SourceAnchor,
    SourcePosition, SourceRevision, SourceSpan, StableDigest, ValueTypeBarrierDecision,
    ValueTypeBarrierReason, ValueTypePredicate, WorkspaceMountId, WorkspaceRelativePath,
};
use crate::dataflow::{
    PathQuality, PathQualityFrontier, SummaryWitnessStepKind, WitnessStepRow, WitnessStepState,
};
use crate::value_flow::{
    ValueFlowCarrierKey, ValueFlowEventKey, ValueFlowEventKind, ValueFlowPortKey,
    ValueFlowScopedRootKind, ValueFlowSelectorKey, ValueFlowSinkId,
};

/// A bound event's stable site and per-site ordinal. A run-local sink ID is
/// reconstructed from the current plan rather than stored.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OutputEventRow {
    pub site: OutputLocatorRow,
    pub ordinal: u32,
    pub kind: String,
}

impl OutputEventRow {
    pub fn remount_workspace(
        &mut self,
        from: StableDigest,
        to: StableDigest,
    ) -> Result<(), OutputProductError> {
        self.validate()?;
        if self.site.mount != from {
            return Err(OutputProductError::Corrupt);
        }
        let mut value = serde_json::to_value(&*self).map_err(|_| OutputProductError::Corrupt)?;
        remount_workspace_json(&mut value, from, to)?;
        *self = serde_json::from_value(value).map_err(|_| OutputProductError::Corrupt)?;
        self.validate()
    }
    pub fn decode_key(&self) -> Result<ValueFlowEventKey, OutputProductError> {
        let kind = match self.kind.as_str() {
            "source" => ValueFlowEventKind::Source,
            "sink" => ValueFlowEventKind::Sink,
            "sanitizer" => ValueFlowEventKind::Sanitizer,
            "transform" => ValueFlowEventKind::Transform,
            _ => return Err(OutputProductError::Corrupt),
        };
        Ok(ValueFlowEventKey::from_stable_site(
            self.site.clone().decode()?,
            self.ordinal,
            kind,
        ))
    }

    pub fn encode(key: &ValueFlowEventKey) -> Self {
        Self {
            site: OutputLocatorRow::encode(key.site()),
            ordinal: key.ordinal(),
            kind: match key.kind() {
                ValueFlowEventKind::Source => "source",
                ValueFlowEventKind::Sink => "sink",
                ValueFlowEventKind::Sanitizer => "sanitizer",
                ValueFlowEventKind::Transform => "transform",
            }
            .to_owned(),
        }
    }

    pub fn validate(&self) -> Result<(), OutputProductError> {
        self.site.clone().decode()?;
        if !matches!(
            self.kind.as_str(),
            "source" | "sink" | "sanitizer" | "transform"
        ) {
            return Err(OutputProductError::Corrupt);
        }
        Ok(())
    }

    pub fn matches(&self, key: &ValueFlowEventKey) -> bool {
        self.ordinal == key.ordinal()
            && self.kind
                == match key.kind() {
                    ValueFlowEventKind::Source => "source",
                    ValueFlowEventKind::Sink => "sink",
                    ValueFlowEventKind::Sanitizer => "sanitizer",
                    ValueFlowEventKind::Transform => "transform",
                }
            && self.site == OutputLocatorRow::encode(key.site())
    }

    pub fn sink_in(
        &self,
        plan: &super::TaintAnalysisPlan,
    ) -> Result<ValueFlowSinkId, OutputProductError> {
        if self.kind != "sink" {
            return Err(OutputProductError::Corrupt);
        }
        plan.sinks()
            .iter()
            .map(|binding| binding.sink())
            .find(|&sink| {
                plan.value_flow()
                    .sink(sink)
                    .is_some_and(|bound| self.matches(bound.key()))
            })
            .ok_or(OutputProductError::Corrupt)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct PositionRow {
    byte_offset: u32,
    line: u32,
    byte_column: u32,
}

impl From<SourcePosition> for PositionRow {
    fn from(value: SourcePosition) -> Self {
        Self {
            byte_offset: value.byte_offset(),
            line: value.line(),
            byte_column: value.byte_column(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct AnchorRow {
    start: PositionRow,
    end: PositionRow,
    occurrence: u32,
}

impl From<SourceAnchor> for AnchorRow {
    fn from(value: SourceAnchor) -> Self {
        Self {
            start: value.span().start().into(),
            end: value.span().end().into(),
            occurrence: value.occurrence(),
        }
    }
}

impl AnchorRow {
    fn decode(self) -> Result<SourceAnchor, OutputProductError> {
        let point =
            |row: PositionRow| SourcePosition::new(row.byte_offset, row.line, row.byte_column);
        let span = SourceSpan::new(point(self.start), point(self.end))
            .map_err(|_| OutputProductError::Corrupt)?;
        Ok(SourceAnchor::new(span, self.occurrence))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct SegmentRow {
    kind: String,
    name: Option<String>,
    anchor: AnchorRow,
    sibling_ordinal: u32,
}

/// A stable semantic site, independent of artifact-local indices and handles.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OutputLocatorRow {
    mount: StableDigest,
    path: String,
    language: String,
    declaration: Vec<SegmentRow>,
    role: String,
    anchor: AnchorRow,
}

impl OutputLocatorRow {
    pub const fn mount_digest(&self) -> StableDigest {
        self.mount
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputWitnessStepRow {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary_fingerprint: Option<String>,
    pub typed: OutputWitnessStepState,
    pub source: OutputLocatorRow,
    pub source_point: usize,
    pub target: Option<OutputLocatorRow>,
    pub target_point: Option<usize>,
    pub origin: Option<OutputLocatorRow>,
    pub boundary: Option<String>,
    pub proof: OutputProofRow,
    pub completeness: OutputCompletenessRow,
    pub input_fact: usize,
    pub output_fact: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputWitnessStepState {
    None,
    ModeledReceiver { operand: OutputLocatorRow },
}

impl OutputWitnessStepRow {
    pub fn modeled_receiver_operand(&self) -> Option<&OutputLocatorRow> {
        match &self.typed {
            OutputWitnessStepState::ModeledReceiver { operand } => Some(operand),
            OutputWitnessStepState::None => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputProofRow {
    Proven,
    Unproven(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputCompletenessRow {
    Complete,
    Partial(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputWitnessRow {
    pub proven: bool,
    pub complete: bool,
    pub steps: Vec<OutputWitnessStepRow>,
    pub truncation_cause: Option<String>,
    pub omitted_steps_lower_bound: usize,
    pub alternatives_truncated: bool,
    pub retained_bytes: usize,
    pub evidence_expansions: usize,
}

impl OutputWitnessRow {
    pub fn quality(&self) -> PathQuality {
        match (self.proven, self.complete) {
            (true, true) => PathQuality::PROVEN_COMPLETE,
            (true, false) => PathQuality::PROVEN_PARTIAL,
            (false, true) => PathQuality::UNPROVEN_COMPLETE,
            (false, false) => PathQuality::UNPROVEN_PARTIAL,
        }
    }

    pub fn retention_truncated(&self) -> bool {
        self.truncation_cause.as_deref() == Some("retention_exhausted")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputOriginRow {
    pub event: OutputEventRow,
    pub classes: Vec<String>,
    pub reached_classes: Vec<String>,
    pub witness_paths: Vec<usize>,
    pub certain_path: bool,
    pub authored_arm_closures: Vec<OutputAuthoredClosureRow>,
    pub frontier_source: Option<OutputFrontierSourceRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputFrontierSourceRow {
    pub phase: String,
    pub carrier: OutputCarrierRow,
}

impl OutputFrontierSourceRow {
    pub fn observation_phase(
        &self,
    ) -> Result<crate::value_flow::ValueFlowObservationPhase, OutputProductError> {
        match self.phase.as_str() {
            "before_effects" => Ok(crate::value_flow::ValueFlowObservationPhase::BeforeEffects),
            "after_effects" => Ok(crate::value_flow::ValueFlowObservationPhase::AfterEffects),
            _ => Err(OutputProductError::Corrupt),
        }
    }

    fn encode(
        phase: crate::value_flow::ValueFlowObservationPhase,
        carrier: &crate::value_flow::ValueFlowCarrier,
    ) -> Result<Self, OutputProductError> {
        Ok(Self {
            phase: match phase {
                crate::value_flow::ValueFlowObservationPhase::BeforeEffects => "before_effects",
                crate::value_flow::ValueFlowObservationPhase::AfterEffects => "after_effects",
            }
            .to_owned(),
            carrier: OutputCarrierRow::encode(
                &carrier
                    .stable_key()
                    .map_err(|_| OutputProductError::Corrupt)?,
            ),
        })
    }

    fn validate(&self) -> Result<(), OutputProductError> {
        if !matches!(self.phase.as_str(), "before_effects" | "after_effects") {
            return Err(OutputProductError::Corrupt);
        }
        self.carrier.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OutputCarrierRow {
    Value {
        locator: OutputLocatorRow,
        role: String,
        ordinal: Option<u32>,
    },
    Port {
        procedure: OutputLocatorRow,
        port: OutputPortRow,
    },
    Allocation {
        locator: OutputLocatorRow,
    },
    CallResult {
        call: OutputLocatorRow,
        result: Box<Self>,
        callee: OutputLocatorRow,
    },
    ScopedRoot {
        scope: String,
        locator: OutputLocatorRow,
    },
    RuntimeObject {
        runtime_profile_digest: String,
        realm: String,
        exposure_id: String,
        container_member: String,
        state_boundary: String,
        refinement_identity: StableDigest,
        active_model_set_hash: String,
        manifest_digest: String,
        shard_id: String,
        behavior_id: String,
        activation_source: String,
    },
    LexicalCell {
        locator: OutputLocatorRow,
        binding: OutputValueIdentityRow,
    },
    Location {
        root: Box<Self>,
        selectors: Vec<OutputSelectorRow>,
        exact: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputValueIdentityRow {
    pub locator: OutputLocatorRow,
    pub role: String,
    pub ordinal: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OutputPortRow {
    Receiver,
    Parameter { ordinal: u32 },
    NormalReturn,
    IndexedNormalReturn { ordinal: u32 },
    ExceptionalReturn,
    Capture { slot: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OutputSelectorRow {
    Field { locator: OutputLocatorRow },
    Property { name: String },
    ExactIndex { carrier: Box<OutputCarrierRow> },
    ConstantIndex { index: u128 },
    AnyIndex,
}

impl OutputCarrierRow {
    pub fn encode(key: &ValueFlowCarrierKey) -> Self {
        enum Task<'a> {
            Visit(&'a ValueFlowCarrierKey),
            CallResult(&'a SemanticLocator, &'a SemanticLocator),
            Location(&'a [ValueFlowSelectorKey], bool),
        }
        let mut pending = vec![Task::Visit(key)];
        let mut built = Vec::<Self>::new();
        while let Some(task) = pending.pop() {
            match task {
                Task::Visit(ValueFlowCarrierKey::CallResult {
                    call,
                    result,
                    callee,
                }) => {
                    pending.push(Task::CallResult(call, callee));
                    pending.push(Task::Visit(result));
                }
                Task::Visit(ValueFlowCarrierKey::Location {
                    root,
                    selectors,
                    exact,
                }) => {
                    pending.push(Task::Location(selectors, *exact));
                    for selector in selectors.iter().rev() {
                        if let ValueFlowSelectorKey::ExactIndex(carrier) = selector {
                            pending.push(Task::Visit(carrier));
                        }
                    }
                    pending.push(Task::Visit(root));
                }
                Task::Visit(key) => built.push(Self::encode_leaf(key)),
                Task::CallResult(call, callee) => {
                    let result = built.pop().expect("call result has one carrier");
                    built.push(Self::CallResult {
                        call: OutputLocatorRow::encode(call),
                        result: Box::new(result),
                        callee: OutputLocatorRow::encode(callee),
                    });
                }
                Task::Location(selectors, exact) => {
                    let count = selectors
                        .iter()
                        .filter(|selector| matches!(selector, ValueFlowSelectorKey::ExactIndex(_)))
                        .count();
                    let mut indexes = (0..count)
                        .map(|_| built.pop().expect("exact index has one carrier"))
                        .collect::<Vec<_>>();
                    indexes.reverse();
                    let mut indexes = indexes.into_iter();
                    let root = built.pop().expect("location has one root");
                    let selectors = selectors
                        .iter()
                        .map(|selector| match selector {
                            ValueFlowSelectorKey::Field(locator) => OutputSelectorRow::Field {
                                locator: OutputLocatorRow::encode(locator),
                            },
                            ValueFlowSelectorKey::Property(name) => {
                                OutputSelectorRow::Property { name: name.clone() }
                            }
                            ValueFlowSelectorKey::ExactIndex(_) => OutputSelectorRow::ExactIndex {
                                carrier: Box::new(
                                    indexes.next().expect("exact index carrier built"),
                                ),
                            },
                            ValueFlowSelectorKey::ConstantIndex(index) => {
                                OutputSelectorRow::ConstantIndex { index: *index }
                            }
                            ValueFlowSelectorKey::AnyIndex => OutputSelectorRow::AnyIndex,
                        })
                        .collect();
                    built.push(Self::Location {
                        root: Box::new(root),
                        selectors,
                        exact,
                    });
                }
            }
        }
        assert_eq!(built.len(), 1, "one carrier key encodes one row");
        built.pop().expect("one carrier row remains")
    }

    fn encode_leaf(key: &ValueFlowCarrierKey) -> Self {
        match key {
            ValueFlowCarrierKey::Value {
                locator,
                role,
                ordinal,
            } => Self::Value {
                locator: OutputLocatorRow::encode(locator),
                role: role.to_string(),
                ordinal: *ordinal,
            },
            ValueFlowCarrierKey::Port { procedure, kind } => Self::Port {
                procedure: OutputLocatorRow::encode(procedure),
                port: match kind {
                    ValueFlowPortKey::Receiver => OutputPortRow::Receiver,
                    ValueFlowPortKey::Parameter { ordinal } => {
                        OutputPortRow::Parameter { ordinal: *ordinal }
                    }
                    ValueFlowPortKey::NormalReturn => OutputPortRow::NormalReturn,
                    ValueFlowPortKey::IndexedNormalReturn { ordinal } => {
                        OutputPortRow::IndexedNormalReturn { ordinal: *ordinal }
                    }
                    ValueFlowPortKey::ExceptionalReturn => OutputPortRow::ExceptionalReturn,
                    ValueFlowPortKey::Capture { slot } => OutputPortRow::Capture { slot: *slot },
                },
            },
            ValueFlowCarrierKey::Allocation { locator } => Self::Allocation {
                locator: OutputLocatorRow::encode(locator),
            },
            ValueFlowCarrierKey::CallResult { .. } | ValueFlowCarrierKey::Location { .. } => {
                unreachable!("nested carrier keys are built by the iterative driver")
            }
            ValueFlowCarrierKey::ScopedRoot { kind, locator } => Self::ScopedRoot {
                scope: match kind {
                    ValueFlowScopedRootKind::Static => "static",
                    ValueFlowScopedRootKind::TypeSummary => "type_summary",
                    ValueFlowScopedRootKind::ModuleObject => "module_object",
                    ValueFlowScopedRootKind::External => "external",
                }
                .to_owned(),
                locator: OutputLocatorRow::encode(locator),
            },
            ValueFlowCarrierKey::RuntimeObject {
                runtime_profile_digest,
                realm,
                exposure_id,
                container_member,
                state_boundary,
                refinement_identity,
                active_model_set_hash,
                manifest_digest,
                shard_id,
                behavior_id,
                activation_source,
            } => Self::RuntimeObject {
                runtime_profile_digest: runtime_profile_digest.clone(),
                realm: realm.clone(),
                exposure_id: exposure_id.clone(),
                container_member: container_member.clone(),
                state_boundary: state_boundary.clone(),
                refinement_identity: *refinement_identity,
                active_model_set_hash: active_model_set_hash.clone(),
                manifest_digest: manifest_digest.clone(),
                shard_id: shard_id.clone(),
                behavior_id: behavior_id.clone(),
                activation_source: activation_source.clone(),
            },
            ValueFlowCarrierKey::LexicalCell { locator, binding } => Self::LexicalCell {
                locator: OutputLocatorRow::encode(locator),
                binding: OutputValueIdentityRow {
                    locator: OutputLocatorRow::encode(&binding.locator),
                    role: binding.role.to_string(),
                    ordinal: binding.ordinal,
                },
            },
        }
    }

    /// Recover the stable key used by the public projector without loading an
    /// artifact or constructing a live carrier.
    pub fn decode_key(&self) -> Result<ValueFlowCarrierKey, OutputProductError> {
        enum Task<'a> {
            Visit(&'a OutputCarrierRow),
            CallResult(&'a OutputLocatorRow, &'a OutputLocatorRow),
            Location(&'a [OutputSelectorRow], bool),
        }
        let mut pending = vec![Task::Visit(self)];
        let mut built = Vec::<ValueFlowCarrierKey>::new();
        while let Some(task) = pending.pop() {
            match task {
                Task::Visit(Self::CallResult {
                    call,
                    result,
                    callee,
                }) => {
                    pending.push(Task::CallResult(call, callee));
                    pending.push(Task::Visit(result));
                }
                Task::Visit(Self::Location {
                    root,
                    selectors,
                    exact,
                }) => {
                    pending.push(Task::Location(selectors, *exact));
                    for selector in selectors.iter().rev() {
                        if let OutputSelectorRow::ExactIndex { carrier } = selector {
                            pending.push(Task::Visit(carrier));
                        }
                    }
                    pending.push(Task::Visit(root));
                }
                Task::Visit(row) => built.push(row.decode_leaf()?),
                Task::CallResult(call, callee) => {
                    let result = built.pop().ok_or(OutputProductError::Corrupt)?;
                    built.push(ValueFlowCarrierKey::CallResult {
                        call: call.clone().decode()?,
                        result: Box::new(result),
                        callee: callee.clone().decode()?,
                    });
                }
                Task::Location(selectors, exact) => {
                    let count = selectors
                        .iter()
                        .filter(|selector| matches!(selector, OutputSelectorRow::ExactIndex { .. }))
                        .count();
                    let mut indexes = (0..count)
                        .map(|_| built.pop().ok_or(OutputProductError::Corrupt))
                        .collect::<Result<Vec<_>, _>>()?;
                    indexes.reverse();
                    let mut indexes = indexes.into_iter();
                    let root = built.pop().ok_or(OutputProductError::Corrupt)?;
                    let selectors = selectors
                        .iter()
                        .map(|selector| {
                            Ok(match selector {
                                OutputSelectorRow::Field { locator } => {
                                    ValueFlowSelectorKey::Field(locator.clone().decode()?)
                                }
                                OutputSelectorRow::Property { name } => {
                                    ValueFlowSelectorKey::Property(name.clone())
                                }
                                OutputSelectorRow::ExactIndex { .. } => {
                                    ValueFlowSelectorKey::ExactIndex(Box::new(
                                        indexes.next().ok_or(OutputProductError::Corrupt)?,
                                    ))
                                }
                                OutputSelectorRow::ConstantIndex { index } => {
                                    ValueFlowSelectorKey::ConstantIndex(*index)
                                }
                                OutputSelectorRow::AnyIndex => ValueFlowSelectorKey::AnyIndex,
                            })
                        })
                        .collect::<Result<Vec<_>, OutputProductError>>()?;
                    built.push(ValueFlowCarrierKey::Location {
                        root: Box::new(root),
                        selectors: selectors.into_boxed_slice(),
                        exact,
                    });
                }
            }
        }
        if built.len() != 1 {
            return Err(OutputProductError::Corrupt);
        }
        built.pop().ok_or(OutputProductError::Corrupt)
    }

    fn decode_leaf(&self) -> Result<ValueFlowCarrierKey, OutputProductError> {
        Ok(match self {
            Self::Value {
                locator,
                role,
                ordinal,
            } => ValueFlowCarrierKey::Value {
                locator: locator.clone().decode()?,
                role: role.clone().into(),
                ordinal: *ordinal,
            },
            Self::Port { procedure, port } => ValueFlowCarrierKey::Port {
                procedure: procedure.clone().decode()?,
                kind: match port {
                    OutputPortRow::Receiver => ValueFlowPortKey::Receiver,
                    OutputPortRow::Parameter { ordinal } => {
                        ValueFlowPortKey::Parameter { ordinal: *ordinal }
                    }
                    OutputPortRow::NormalReturn => ValueFlowPortKey::NormalReturn,
                    OutputPortRow::IndexedNormalReturn { ordinal } => {
                        ValueFlowPortKey::IndexedNormalReturn { ordinal: *ordinal }
                    }
                    OutputPortRow::ExceptionalReturn => ValueFlowPortKey::ExceptionalReturn,
                    OutputPortRow::Capture { slot } => ValueFlowPortKey::Capture { slot: *slot },
                },
            },
            Self::Allocation { locator } => ValueFlowCarrierKey::Allocation {
                locator: locator.clone().decode()?,
            },
            Self::ScopedRoot { scope, locator } => ValueFlowCarrierKey::ScopedRoot {
                kind: match scope.as_str() {
                    "static" => ValueFlowScopedRootKind::Static,
                    "type_summary" => ValueFlowScopedRootKind::TypeSummary,
                    "module_object" => ValueFlowScopedRootKind::ModuleObject,
                    "external" => ValueFlowScopedRootKind::External,
                    _ => return Err(OutputProductError::Corrupt),
                },
                locator: locator.clone().decode()?,
            },
            Self::RuntimeObject {
                runtime_profile_digest,
                realm,
                exposure_id,
                container_member,
                state_boundary,
                refinement_identity,
                active_model_set_hash,
                manifest_digest,
                shard_id,
                behavior_id,
                activation_source,
            } => ValueFlowCarrierKey::RuntimeObject {
                runtime_profile_digest: runtime_profile_digest.clone(),
                realm: realm.clone(),
                exposure_id: exposure_id.clone(),
                container_member: container_member.clone(),
                state_boundary: state_boundary.clone(),
                refinement_identity: *refinement_identity,
                active_model_set_hash: active_model_set_hash.clone(),
                manifest_digest: manifest_digest.clone(),
                shard_id: shard_id.clone(),
                behavior_id: behavior_id.clone(),
                activation_source: activation_source.clone(),
            },
            Self::LexicalCell { locator, binding } => ValueFlowCarrierKey::LexicalCell {
                locator: locator.clone().decode()?,
                binding: crate::analyzer::semantic::DurableValueIdentity {
                    locator: binding.locator.clone().decode()?,
                    role: binding.role.clone().into(),
                    ordinal: binding.ordinal,
                },
            },
            Self::CallResult { .. } | Self::Location { .. } => {
                return Err(OutputProductError::Corrupt);
            }
        })
    }

    fn validate(&self) -> Result<(), OutputProductError> {
        let mut pending = vec![self];
        while let Some(row) = pending.pop() {
            match row {
                Self::Value { locator, role, .. } => {
                    locator.clone().decode()?;
                    if role.is_empty() {
                        return Err(OutputProductError::Corrupt);
                    }
                }
                Self::Port { procedure, .. } | Self::Allocation { locator: procedure } => {
                    procedure.clone().decode()?;
                }
                Self::CallResult {
                    call,
                    result,
                    callee,
                } => {
                    call.clone().decode()?;
                    callee.clone().decode()?;
                    pending.push(result);
                }
                Self::ScopedRoot { scope, locator } => {
                    locator.clone().decode()?;
                    if !matches!(
                        scope.as_str(),
                        "static" | "type_summary" | "module_object" | "external"
                    ) {
                        return Err(OutputProductError::Corrupt);
                    }
                }
                Self::RuntimeObject {
                    runtime_profile_digest,
                    realm,
                    exposure_id,
                    container_member,
                    state_boundary,
                    active_model_set_hash,
                    manifest_digest,
                    shard_id,
                    behavior_id,
                    activation_source,
                    ..
                } => {
                    if [
                        runtime_profile_digest,
                        realm,
                        exposure_id,
                        container_member,
                        state_boundary,
                        active_model_set_hash,
                        manifest_digest,
                        shard_id,
                        behavior_id,
                        activation_source,
                    ]
                    .iter()
                    .any(|field| field.is_empty())
                    {
                        return Err(OutputProductError::Corrupt);
                    }
                }
                Self::LexicalCell { locator, binding } => {
                    locator.clone().decode()?;
                    binding.locator.clone().decode()?;
                    if binding.role.is_empty() {
                        return Err(OutputProductError::Corrupt);
                    }
                }
                Self::Location {
                    root, selectors, ..
                } => {
                    pending.push(root);
                    for selector in selectors {
                        match selector {
                            OutputSelectorRow::Field { locator } => {
                                locator.clone().decode()?;
                            }
                            OutputSelectorRow::Property { name } if name.is_empty() => {
                                return Err(OutputProductError::Corrupt);
                            }
                            OutputSelectorRow::ExactIndex { carrier } => pending.push(carrier),
                            OutputSelectorRow::Property { .. }
                            | OutputSelectorRow::ConstantIndex { .. }
                            | OutputSelectorRow::AnyIndex => {}
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// An authored external claim that discharged a call arm. The call context
/// and target are locators, so the row does not retain materialization IDs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputAuthoredClosureRow {
    pub call: OutputLocatorRow,
    pub context: Vec<OutputLocatorRow>,
    pub context_truncated: bool,
    pub target: OutputLocatorRow,
    pub model: String,
    pub content: StableDigest,
    pub contract_version: u32,
    pub covers_overrides: bool,
}

impl OutputAuthoredClosureRow {
    fn encode(value: &crate::value_flow::AuthoredArmClosure) -> Result<Self, OutputProductError> {
        let call = value.call().locator().ok_or(OutputProductError::Corrupt)?;
        let context = value
            .call_context()
            .calls()
            .iter()
            .map(|call| {
                call.locator()
                    .map(OutputLocatorRow::encode)
                    .ok_or(OutputProductError::Corrupt)
            })
            .collect::<Result<_, _>>()?;
        let origin = value.origin();
        Ok(Self {
            call: OutputLocatorRow::encode(call),
            context,
            context_truncated: value.call_context().was_truncated(),
            target: OutputLocatorRow::encode(value.target()),
            model: origin.model().as_str().to_owned(),
            content: origin.content().digest(),
            contract_version: origin.contract_version(),
            covers_overrides: origin.covers_overrides(),
        })
    }

    fn validate(&self) -> Result<(), OutputProductError> {
        self.call.clone().decode()?;
        self.target.clone().decode()?;
        for call in &self.context {
            call.clone().decode()?;
        }
        crate::dataflow::ExternalSummaryModelId::new(self.model.clone())
            .map_err(|_| OutputProductError::Corrupt)?;
        if self.contract_version == 0 {
            return Err(OutputProductError::Corrupt);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputFindingRow {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_receipt: Option<crate::model_attribution::ModelReceipt>,
    pub sink: OutputEventRow,
    pub entry: OutputLocatorRow,
    pub classes: Vec<String>,
    pub origins: Vec<OutputOriginRow>,
    pub path_qualities: Vec<OutputPathQualityRow>,
    pub proven: bool,
    pub complete: bool,
    pub origin_truncated: bool,
    pub witness_truncated: bool,
    pub witness_truncation_cause: Option<String>,
    pub witness_unavailable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputPathQualityRow {
    proven: bool,
    complete: bool,
}

/// The exact immutable artifact whose procedure-local IDs a store boundary
/// names. Every constituent is a SQL-readable scalar, not an encoded key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputArtifactKeyRow {
    mount: StableDigest,
    path: String,
    language: String,
    content: StableDigest,
    overlay_snapshot: Option<StableDigest>,
    adapter_name: String,
    adapter_fingerprint: StableDigest,
    ir_version: StableDigest,
    configuration: StableDigest,
    dependencies: StableDigest,
}

impl OutputArtifactKeyRow {
    fn encode(key: &SemanticArtifactKey) -> Self {
        Self {
            mount: key.mount().digest(),
            path: key.path().as_str().to_owned(),
            language: key.language().stable_label().to_owned(),
            content: key.revision().content().digest(),
            overlay_snapshot: key
                .revision()
                .overlay_snapshot()
                .map(OverlaySnapshotId::digest),
            adapter_name: key.adapter().name().to_owned(),
            adapter_fingerprint: key.adapter().fingerprint(),
            ir_version: key.ir_version().digest(),
            configuration: key.configuration().digest(),
            dependencies: key.dependencies().digest(),
        }
    }

    fn decode(&self) -> Result<SemanticArtifactKey, OutputProductError> {
        let path =
            WorkspaceRelativePath::new(&self.path).map_err(|_| OutputProductError::Corrupt)?;
        let language = SemanticLanguage::ALL
            .into_iter()
            .find(|language| language.stable_label() == self.language)
            .ok_or(OutputProductError::Corrupt)?;
        let content = ContentIdentity::from_digest(self.content);
        let revision = match self.overlay_snapshot {
            Some(snapshot) => SourceRevision::Overlay {
                content,
                snapshot: OverlaySnapshotId::from_digest(snapshot),
            },
            None => SourceRevision::Disk { content },
        };
        let adapter =
            AdapterSemanticsVersion::new(self.adapter_name.clone(), self.adapter_fingerprint)
                .map_err(|_| OutputProductError::Corrupt)?;
        Ok(SemanticArtifactKey::new(
            WorkspaceMountId::from_digest(self.mount),
            path,
            language,
            revision,
            adapter,
            SemanticIrVersion::from_digest(self.ir_version),
            ConfigurationFingerprint::from_digest(self.configuration),
            DependencyFingerprint::from_digest(self.dependencies),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputCallRow {
    pub artifact: OutputArtifactKeyRow,
    pub procedure: u32,
    pub call: u32,
}

impl OutputCallRow {
    pub fn encode(key: &crate::value_flow::DurableCallSiteKey) -> Self {
        Self {
            artifact: OutputArtifactKeyRow::encode(&key.0.0),
            procedure: key.0.1.get(),
            call: key.1.get(),
        }
    }

    pub fn decode(&self) -> Result<crate::value_flow::DurableCallSiteKey, OutputProductError> {
        Ok((
            (self.artifact.decode()?, ProcedureId::new(self.procedure)),
            CallSiteId::new(self.call),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputStoreCrossingRow {
    pub source: OutputEventRow,
    pub original_source: OutputEventRow,
    pub sink: OutputEventRow,
    pub witness_path: usize,
    pub write_call: OutputCallRow,
    pub read_call: OutputCallRow,
    pub write_site: OutputLocatorRow,
    pub read_site: OutputLocatorRow,
    pub policy: Vec<OutputStorePolicyRow>,
    pub prefix_steps: usize,
}

/// Policy-owned endpoint identities and resolved channel dimensions for the
/// declared-store witness steps. Endpoint values retain their authored JSON
/// form so SQL can inspect them without loading a policy artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputStorePolicyRow {
    pub policy_id: String,
    pub source_endpoint: serde_json::Value,
    pub write_endpoint: serde_json::Value,
    pub read_endpoint: serde_json::Value,
    pub write_channel: OutputStoreChannelRow,
    pub read_channel: OutputStoreChannelRow,
    pub source_to_write: Option<OutputWitnessRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputStoreChannelRow {
    pub store: String,
    pub instance: OutputStoreDimensionRow,
    pub key: OutputStoreDimensionRow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "identities", rename_all = "snake_case")]
pub enum OutputStoreDimensionRow {
    Undeclared,
    Unproven,
    Proven(Vec<StableDigest>),
}

/// Source locations retained for a seeded store read after the writer inventory
/// has been evaluated. They are projected without opening the writer artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputStoreSeedEvidenceRow {
    pub read: OutputEventRow,
    pub write_sites: Vec<OutputLocatorRow>,
    pub origin_sites: Vec<OutputLocatorRow>,
}

/// A selected sanitizer decision that a retained path traverses.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OutputSanitizerDeclineRow {
    pub point: OutputLocatorRow,
    pub point_id: usize,
    pub target_id: Option<usize>,
    pub location: OutputLocatorRow,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "reason", rename_all = "snake_case")]
pub enum OutputBarrierDecisionRow {
    ProvenMatch,
    ProvenNonMatch,
    Undecided(ValueTypeBarrierReason),
}

impl From<ValueTypeBarrierDecision> for OutputBarrierDecisionRow {
    fn from(value: ValueTypeBarrierDecision) -> Self {
        match value {
            ValueTypeBarrierDecision::ProvenMatch => Self::ProvenMatch,
            ValueTypeBarrierDecision::ProvenNonMatch => Self::ProvenNonMatch,
            ValueTypeBarrierDecision::Undecided(reason) => Self::Undecided(reason),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputBarrierCheckRow {
    pub id: String,
    pub point: OutputLocatorRow,
    pub value: OutputValueIdentityRow,
    pub value_location: OutputLocatorRow,
    pub mapping_kind: String,
    pub procedure: String,
    pub value_id: u32,
    pub name: Option<String>,
    pub phase: String,
    pub predicate: ValueTypePredicate,
    pub decision: OutputBarrierDecisionRow,
}

impl OutputBarrierCheckRow {
    fn encode(
        check: &crate::taint::compose::ValueTypeBarrierCheck,
    ) -> Result<Self, OutputProductError> {
        let observation = &check.observation;
        let value = observation
            .point()
            .procedure()
            .value_handle(observation.value())
            .ok_or(OutputProductError::Corrupt)?;
        let identity = crate::analyzer::semantic::DurableValueIdentity::of(&value)
            .map_err(|_| OutputProductError::Corrupt)?;
        let procedure = observation.point().procedure();
        let semantics = procedure.semantics();
        let semantic_value = semantics
            .value(observation.value())
            .ok_or(OutputProductError::Corrupt)?;
        let mapping = semantics
            .source_mapping(semantic_value.source)
            .ok_or(OutputProductError::Corrupt)?;
        let span = semantics
            .source_mapping(semantics.source())
            .ok_or(OutputProductError::Corrupt)?
            .locator
            .anchor()
            .span();
        Ok(Self {
            id: check.id.to_string(),
            point: OutputLocatorRow::encode(
                observation
                    .point()
                    .locator()
                    .ok_or(OutputProductError::Corrupt)?,
            ),
            value: OutputValueIdentityRow {
                locator: OutputLocatorRow::encode(&identity.locator),
                role: identity.role.to_string(),
                ordinal: identity.ordinal,
            },
            value_location: OutputLocatorRow::encode(&mapping.locator),
            mapping_kind: mapping.kind.label().to_owned(),
            procedure: format!(
                "{:?} [{}..{}]",
                procedure.id(),
                span.start_byte(),
                span.end_byte()
            ),
            value_id: semantic_value.id.get(),
            name: match &semantic_value.kind {
                crate::analyzer::semantic::SemanticValueKind::Parameter {
                    name: Some(name),
                    ..
                } if name.len() <= 256 => Some(name.to_string()),
                _ => None,
            },
            phase: match observation.phase() {
                crate::analyzer::semantic::ObservationPhase::BeforeEffects => "before_effects",
                crate::analyzer::semantic::ObservationPhase::AfterEffects => "after_effects",
            }
            .to_owned(),
            predicate: check.predicate,
            decision: check.decision.into(),
        })
    }

    fn validate(&self) -> Result<(), OutputProductError> {
        self.point.clone().decode()?;
        self.value.locator.clone().decode()?;
        self.value_location.clone().decode()?;
        if self.id.is_empty()
            || self.value.role.is_empty()
            || !matches!(
                self.mapping_kind.as_str(),
                "exact" | "enclosing" | "synthetic"
            )
            || self.procedure.is_empty()
            || self.procedure.len() > 256
            || self.name.as_ref().is_some_and(|name| name.len() > 256)
            || !matches!(self.phase.as_str(), "before_effects" | "after_effects")
        {
            return Err(OutputProductError::Corrupt);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputBarrierNoteRow {
    pub source: OutputEventRow,
    pub sink: OutputEventRow,
    pub checks: Vec<OutputBarrierCheckRow>,
    pub omitted_lower_bound: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputBarrierPairRow {
    pub lenient: Box<OutputReportRow>,
    pub strict: Option<Box<OutputReportRow>>,
}

impl OutputPathQualityRow {
    fn quality(self) -> PathQuality {
        match (self.proven, self.complete) {
            (true, true) => PathQuality::PROVEN_COMPLETE,
            (true, false) => PathQuality::PROVEN_PARTIAL,
            (false, true) => PathQuality::UNPROVEN_COMPLETE,
            (false, false) => PathQuality::UNPROVEN_PARTIAL,
        }
    }
}

/// One anchor's report content before policy projection. Witness paths are
/// shared by index so a store crossing can name the same retained path.
// Version 2 is burned; version 3 requires the typed modeled-receiver operand.
// G10 #9937: V4 retains selected procedure-summary provenance on composed
// witness steps. M2a #9947: V5 fences products without replayable composition
// diagnostics. Close-match 1b: V6 adds finding model receipts. #10399: V7 also
// records the cause of each provider refusal beside its row in the Output
// product, which decides whether an Output carrying it may be published. The
// DTO is compared for equality, so versions 1-7 are rejected; absent selected
// summaries keep an absent provenance field.
// #10687 B: V8 renders finding diagnostics for partial findings in any run state with
// residual causes appended, and the final preparation strip exempts composition payloads.
const OUTPUT_REPORT_VERSION: u32 = 8;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputReportRow {
    version: u32,
    pub anchor: OutputLocatorRow,
    pub findings: Vec<OutputFindingRow>,
    pub witnesses: Vec<OutputWitnessRow>,
    pub store_crossings: Vec<OutputStoreCrossingRow>,
    pub store_seed_evidence: Vec<OutputStoreSeedEvidenceRow>,
    pub sanitizer_declines: Vec<OutputSanitizerDeclineRow>,
    pub barrier_notes: Vec<OutputBarrierNoteRow>,
    pub barrier_pairs: Vec<OutputBarrierPairRow>,
    pub authored_arm_closures: Vec<OutputAuthoredClosureRow>,
    pub fixed_point: bool,
    pub complete: bool,
    pub proven_by_authored_summaries: bool,
    pub omitted_findings_lower_bound: usize,
    pub retained_witnesses: usize,
    pub retained_witness_steps: usize,
    pub witness_expansions: usize,
    pub retained_witness_bytes: usize,
    pub attribution_attempts: usize,
    pub attribution_steps: usize,
    pub attribution_expansions: usize,
    pub attribution_candidate_exhaustions: usize,
    pub attribution_run_exhausted: bool,
}

impl OutputReportRow {
    /// The row of an anchor whose composition was stopped by a budget before it
    /// produced anything: no findings, nothing proven, and incomplete. It is
    /// never stored; the unit that holds it is refused.
    pub fn stopped(anchor: &SemanticLocator) -> Self {
        Self {
            version: OUTPUT_REPORT_VERSION,
            anchor: OutputLocatorRow::encode(anchor),
            findings: Vec::new(),
            witnesses: Vec::new(),
            store_crossings: Vec::new(),
            store_seed_evidence: Vec::new(),
            sanitizer_declines: Vec::new(),
            barrier_notes: Vec::new(),
            barrier_pairs: Vec::new(),
            authored_arm_closures: Vec::new(),
            fixed_point: false,
            complete: false,
            proven_by_authored_summaries: false,
            omitted_findings_lower_bound: 0,
            retained_witnesses: 0,
            retained_witness_steps: 0,
            witness_expansions: 0,
            retained_witness_bytes: 0,
            attribution_attempts: 0,
            attribution_steps: 0,
            attribution_expansions: 0,
            attribution_candidate_exhaustions: 0,
            attribution_run_exhausted: false,
        }
    }

    /// Whether a retained finding has this origin event. Store-seed evidence
    /// is kept only for such a read.
    pub fn retains_origin_event(&self, event: &OutputEventRow) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.origins.iter().any(|origin| origin.event == *event))
    }

    /// Whether a retained witness still contains the declined sanitizer step.
    pub fn retains_sanitizer_step(
        &self,
        point: &OutputLocatorRow,
        point_id: usize,
        target_id: Option<usize>,
    ) -> bool {
        self.witnesses
            .iter()
            .flat_map(|witness| &witness.steps)
            .any(|step| {
                step.source == *point
                    && step.source_point == point_id
                    && target_id.is_none_or(|target| step.target_point == Some(target))
            })
    }

    /// Extract one anchor from a freshly composed multi-sink batch and pass
    /// it through the same validated JSON representation as a reused unit.
    pub fn encode_site_from_batch(
        plan: &TaintAnalysisPlan,
        anchor: &SemanticLocator,
        report: &TaintFindingReport,
    ) -> Result<Self, OutputProductError> {
        Self::encode_site_with_composition(plan, anchor, report, &[], &[], &[])
    }

    /// Restrict every evidence channel of a freshly composed batch to one
    /// reported site before it enters the durable row projector.
    pub fn encode_site_with_composition(
        plan: &TaintAnalysisPlan,
        anchor: &SemanticLocator,
        report: &TaintFindingReport,
        crossings: &[crate::taint::compose::ComposedStoreCrossing],
        barrier_notes: &[crate::taint::compose::ValueTypeBarrierFindingNotes],
        barrier_pairs: &[crate::taint::compose::ValueTypeBarrierPairEvidence],
    ) -> Result<Self, OutputProductError> {
        let site_report = report.composed_site(anchor);
        let crossings = crossings
            .iter()
            .filter(|crossing| crossing.sink.site() == anchor)
            .cloned()
            .collect::<Vec<_>>();
        let barrier_notes = barrier_notes
            .iter()
            .filter(|note| note.sink.site() == anchor)
            .cloned()
            .collect::<Vec<_>>();
        let barrier_pairs = barrier_pairs
            .iter()
            .filter(|pair| {
                pair.lenient
                    .findings()
                    .iter()
                    .any(|finding| finding.key().sink().site() == anchor)
            })
            .map(|pair| crate::taint::compose::ValueTypeBarrierPairEvidence {
                lenient: pair.lenient.composed_site(anchor),
                strict: pair
                    .strict
                    .as_ref()
                    .map(|report| report.composed_site(anchor)),
            })
            .collect::<Vec<_>>();
        Self::decode_for_plan(
            plan,
            Self::encode_with_composition(
                plan,
                anchor,
                &site_report,
                &crossings,
                &barrier_notes,
                &barrier_pairs,
            )?,
        )
    }

    pub fn encode(
        plan: &TaintAnalysisPlan,
        anchor: &SemanticLocator,
        report: &TaintFindingReport,
    ) -> Result<serde_json::Value, OutputProductError> {
        Self::encode_with_crossings(plan, anchor, report, &[])
    }

    pub fn encode_with_crossings(
        plan: &TaintAnalysisPlan,
        anchor: &SemanticLocator,
        report: &TaintFindingReport,
        crossings: &[crate::taint::compose::ComposedStoreCrossing],
    ) -> Result<serde_json::Value, OutputProductError> {
        Self::encode_with_composition(plan, anchor, report, crossings, &[], &[])
    }

    pub fn encode_with_composition(
        plan: &TaintAnalysisPlan,
        anchor: &SemanticLocator,
        report: &TaintFindingReport,
        crossings: &[crate::taint::compose::ComposedStoreCrossing],
        barrier_notes: &[crate::taint::compose::ValueTypeBarrierFindingNotes],
        barrier_pairs: &[crate::taint::compose::ValueTypeBarrierPairEvidence],
    ) -> Result<serde_json::Value, OutputProductError> {
        let labels = |classes| {
            plan.universe()
                .stable_classes(classes)
                .map(|classes| {
                    classes
                        .into_iter()
                        .map(|class| class.as_str().to_owned())
                        .collect()
                })
                .map_err(|_| OutputProductError::Corrupt)
        };
        let mut witnesses = Vec::new();
        let mut findings = Vec::new();
        for finding in report.findings() {
            if finding.key().sink().site() != anchor {
                return Err(OutputProductError::Corrupt);
            }
            let mut origins = Vec::new();
            for origin in finding.origins().evidence() {
                let mut witness_paths = Vec::new();
                for witness in origin.witnesses() {
                    let mut steps = Vec::new();
                    for step in witness.steps() {
                        let row = WitnessStepRow::encode(step, |fact| Some(fact.index()))
                            .map_err(|_| OutputProductError::Corrupt)?;
                        steps.push(OutputWitnessStepRow {
                            summary_fingerprint: step.summary().map(|summary| summary.fingerprint().to_string()),
                            kind: match row.kind {
                                SummaryWitnessStepKind::Seed => "seed".to_owned(),
                                SummaryWitnessStepKind::ModeledReceiver => "edge:modeled_receiver".to_owned(),
                                SummaryWitnessStepKind::Edge(kind) => format!("edge:{}", kind.label()),
                                SummaryWitnessStepKind::EndSummaryGap(kind) => format!("end_summary_gap:{}", match kind {
                                    crate::analyzer::semantic::ReturnTransferKind::Normal => "normal",
                                    crate::analyzer::semantic::ReturnTransferKind::Exceptional => "exceptional",
                                }),
                            },
                            typed: match row.typed {
                                WitnessStepState::None => OutputWitnessStepState::None,
                                WitnessStepState::ModeledReceiver { operand } => OutputWitnessStepState::ModeledReceiver {
                                    operand: OutputLocatorRow::encode(&operand),
                                },
                            },
                            source: OutputLocatorRow::encode(&row.source.locator),
                            source_point: row.source.ordinal,
                            target: row.target.as_ref().map(|point| OutputLocatorRow::encode(&point.locator)),
                            target_point: row.target.as_ref().map(|point| point.ordinal),
                            origin: row.origin.as_ref().map(OutputLocatorRow::encode),
                            boundary: row.boundary.as_ref().map(|value| value.label().to_owned()),
                            proof: match row.proof {
                                ProofStatus::Proven => OutputProofRow::Proven,
                                ProofStatus::Unproven(reason) => OutputProofRow::Unproven(reason.to_string()),
                            },
                            completeness: match row.completeness {
                                EvidenceCompleteness::Complete => OutputCompletenessRow::Complete,
                                EvidenceCompleteness::Partial(reason) => OutputCompletenessRow::Partial(reason.to_string()),
                            },
                            input_fact: row.input_fact,
                            output_fact: row.output_fact,
                        });
                    }
                    witness_paths.push(witnesses.len());
                    witnesses.push(OutputWitnessRow {
                        proven: witness.quality().is_proven(),
                        complete: witness.quality().is_complete(),
                        steps,
                        truncation_cause: witness
                            .truncation_cause()
                            .map(|cause| cause.stable_label().to_owned()),
                        omitted_steps_lower_bound: witness.omitted_steps_lower_bound(),
                        alternatives_truncated: witness.alternatives_truncated(),
                        retained_bytes: witness.retained_bytes(),
                        evidence_expansions: witness.work().evidence_expansions(),
                    });
                }
                origins.push(OutputOriginRow {
                    event: OutputEventRow::encode(origin.origin().value_flow_key()),
                    classes: labels(origin.classes())?,
                    reached_classes: labels(origin.reached_classes())?,
                    witness_paths,
                    certain_path: origin.has_certain_path(),
                    authored_arm_closures: origin
                        .authored_arm_closures()
                        .iter()
                        .map(OutputAuthoredClosureRow::encode)
                        .collect::<Result<_, _>>()?,
                    frontier_source: origin
                        .frontier_source()
                        .map(|(phase, carrier)| OutputFrontierSourceRow::encode(phase, carrier))
                        .transpose()?,
                });
            }
            findings.push(OutputFindingRow {
                model_receipt: (!finding.model_receipt().is_empty())
                    .then(|| finding.model_receipt().clone()),
                sink: OutputEventRow::encode(finding.key().sink()),
                entry: OutputLocatorRow::encode(
                    finding
                        .entry()
                        .point()
                        .locator()
                        .ok_or(OutputProductError::Corrupt)?,
                ),
                classes: labels(finding.classes())?,
                origins,
                path_qualities: finding
                    .path_qualities()
                    .iter()
                    .map(|quality| OutputPathQualityRow {
                        proven: quality.is_proven(),
                        complete: quality.is_complete(),
                    })
                    .collect(),
                proven: finding.is_proven(),
                complete: finding.is_complete(),
                origin_truncated: finding.origins().origin_truncated(),
                witness_truncated: finding.origins().witness_truncated(),
                witness_truncation_cause: finding
                    .origins()
                    .witness_truncation_cause()
                    .map(|cause| cause.stable_label().to_owned()),
                witness_unavailable: finding.origins().witness_unavailable(),
            });
        }
        let work = report.attribution_work();
        let store_crossings = crossings
            .iter()
            .map(|crossing| {
                let witness_path = report
                    .findings()
                    .iter()
                    .flat_map(|finding| finding.origins().evidence())
                    .flat_map(|origin| origin.witnesses())
                    .position(|witness| std::sync::Arc::ptr_eq(witness, &crossing.witness))
                    .ok_or(OutputProductError::Corrupt)?;
                Ok(OutputStoreCrossingRow {
                    source: OutputEventRow::encode(crossing.source.value_flow_key()),
                    original_source: OutputEventRow::encode(
                        crossing.original_source.value_flow_key(),
                    ),
                    sink: OutputEventRow::encode(&crossing.sink),
                    witness_path,
                    write_call: OutputCallRow::encode(&crossing.write_call),
                    read_call: OutputCallRow::encode(&crossing.read_call),
                    write_site: OutputLocatorRow::encode(&crossing.write_site),
                    read_site: OutputLocatorRow::encode(&crossing.read_site),
                    policy: Vec::new(),
                    prefix_steps: crossing.prefix_steps,
                })
            })
            .collect::<Result<Vec<_>, OutputProductError>>()?;
        let barrier_notes = barrier_notes
            .iter()
            .map(|note| {
                Ok(OutputBarrierNoteRow {
                    source: OutputEventRow::encode(note.source.value_flow_key()),
                    sink: OutputEventRow::encode(&note.sink),
                    checks: note
                        .checks
                        .iter()
                        .map(OutputBarrierCheckRow::encode)
                        .collect::<Result<_, _>>()?,
                    omitted_lower_bound: note.omitted_lower_bound,
                })
            })
            .collect::<Result<Vec<_>, OutputProductError>>()?;
        let barrier_pairs = barrier_pairs
            .iter()
            .map(|pair| {
                let lenient = Self::encode(plan, anchor, &pair.lenient)?;
                let strict = pair
                    .strict
                    .as_ref()
                    .map(|strict| Self::encode(plan, anchor, strict))
                    .transpose()?;
                Ok(OutputBarrierPairRow {
                    lenient: Box::new(Self::decode(lenient)?),
                    strict: strict.map(Self::decode).transpose()?.map(Box::new),
                })
            })
            .collect::<Result<Vec<_>, OutputProductError>>()?;
        let row = Self {
            version: OUTPUT_REPORT_VERSION,
            anchor: OutputLocatorRow::encode(anchor),
            findings,
            witnesses,
            store_crossings,
            store_seed_evidence: Vec::new(),
            sanitizer_declines: Vec::new(),
            barrier_notes,
            barrier_pairs,
            authored_arm_closures: report
                .authored_arm_closures()
                .iter()
                .map(OutputAuthoredClosureRow::encode)
                .collect::<Result<_, _>>()?,
            fixed_point: report.result().termination().is_fixed_point(),
            complete: report.is_complete(),
            proven_by_authored_summaries: report.is_proven_by_authored_summaries(),
            omitted_findings_lower_bound: report.omitted_findings_lower_bound(),
            retained_witnesses: report.retained_witnesses(),
            retained_witness_steps: report.retained_witness_steps(),
            witness_expansions: report.witness_expansions(),
            retained_witness_bytes: report.retained_witness_bytes(),
            attribution_attempts: work.attempts,
            attribution_steps: work.steps,
            attribution_expansions: work.expansions,
            attribution_candidate_exhaustions: work.candidate_exhaustions,
            attribution_run_exhausted: work.run_exhausted,
        };
        row.validate()?;
        serde_json::to_value(row).map_err(|_| OutputProductError::Corrupt)
    }

    pub fn decode(value: serde_json::Value) -> Result<Self, OutputProductError> {
        let row: Self = serde_json::from_value(value).map_err(|_| OutputProductError::Corrupt)?;
        row.validate()?;
        Ok(row)
    }

    /// A stored row must still name bound sinks and classes of this compile.
    pub fn decode_for_plan(
        plan: &TaintAnalysisPlan,
        value: serde_json::Value,
    ) -> Result<Self, OutputProductError> {
        let mut row = Self::decode(value)?;
        // A diff-base scan can bind the same sink in a temporary workspace.
        // The unit key identifies the source site and blob, while a semantic
        // locator's mount identifies the absolute root of this run. Remap only
        // that environmental mount after validating the stored row, then
        // require exact membership in the current compiled plan below.
        let bound_mount = plan
            .sinks()
            .iter()
            .filter_map(|binding| plan.value_flow().sink(binding.sink()))
            .map(|sink| sink.key().site())
            .find(|site| {
                let mut candidate = OutputLocatorRow::encode(site);
                candidate.mount = row.anchor.mount;
                candidate == row.anchor
            })
            .map(|site| site.mount().digest())
            .ok_or(OutputProductError::Corrupt)?;
        if row.anchor.mount != bound_mount {
            let mut remapped =
                serde_json::to_value(&row).map_err(|_| OutputProductError::Corrupt)?;
            remount_workspace_json(&mut remapped, row.anchor.mount, bound_mount)?;
            row = Self::decode(remapped)?;
        }
        let validate_classes = |names: &[String]| {
            let classes = names
                .iter()
                .map(|name| super::SourceClassId::new(name.clone()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| OutputProductError::Corrupt)?;
            plan.universe()
                .class_set(classes.iter())
                .map_err(|_| OutputProductError::Corrupt)?;
            Ok::<_, OutputProductError>(())
        };
        for finding in &row.findings {
            finding.sink.sink_in(plan)?;
            validate_classes(&finding.classes)?;
            for origin in &finding.origins {
                validate_classes(&origin.classes)?;
                validate_classes(&origin.reached_classes)?;
            }
        }
        Ok(row)
    }

    /// The report-side completeness needed for publication. The policy
    /// prefix must also check store seeding, diagnostics and execution work.
    pub fn report_evidence_complete(&self) -> bool {
        (self.complete || self.proven_by_authored_summaries)
            && !self.attribution_run_exhausted
            && self.omitted_findings_lower_bound == 0
            && self.barrier_notes.iter().all(|note| {
                note.omitted_lower_bound == 0
                    && note.checks.iter().all(|check| {
                        !matches!(check.decision, OutputBarrierDecisionRow::Undecided(_))
                    })
            })
            && self.findings.iter().all(|finding| {
                finding.complete
                    && !finding.origin_truncated
                    && !finding.witness_truncated
                    && !finding.witness_unavailable
            })
            && self.witnesses.iter().all(|witness| {
                witness.truncation_cause.is_none() && !witness.alternatives_truncated
            })
    }

    pub fn validate(&self) -> Result<(), OutputProductError> {
        let valid_classes = |classes: &[String]| {
            classes.windows(2).all(|pair| pair[0] < pair[1])
                && classes
                    .iter()
                    .all(|name| super::SourceClassId::new(name.clone()).is_ok())
        };
        if self.version != OUTPUT_REPORT_VERSION
            || (self.complete && !self.fixed_point)
            || (self.complete && self.proven_by_authored_summaries)
        {
            return Err(OutputProductError::Corrupt);
        }
        if self.retained_witnesses != self.witnesses.len()
            || self.retained_witness_steps
                != self
                    .witnesses
                    .iter()
                    .map(|witness| witness.steps.len())
                    .sum::<usize>()
            || (self.complete && self.omitted_findings_lower_bound != 0)
            || (!self.proven_by_authored_summaries && !self.authored_arm_closures.is_empty())
        {
            return Err(OutputProductError::Corrupt);
        }
        for closure in &self.authored_arm_closures {
            closure.validate()?;
        }
        for crossing in &self.store_crossings {
            crossing.source.validate()?;
            crossing.original_source.validate()?;
            crossing.sink.validate()?;
            crossing.write_call.decode()?;
            crossing.read_call.decode()?;
            crossing.write_site.clone().decode()?;
            crossing.read_site.clone().decode()?;
            for policy in &crossing.policy {
                if policy.policy_id.is_empty()
                    || !policy.source_endpoint.is_object()
                    || !policy.write_endpoint.is_object()
                    || !policy.read_endpoint.is_object()
                    || policy.write_channel.store.is_empty()
                    || policy.read_channel.store.is_empty()
                {
                    return Err(OutputProductError::Corrupt);
                }
                for dimension in [
                    &policy.write_channel.instance,
                    &policy.write_channel.key,
                    &policy.read_channel.instance,
                    &policy.read_channel.key,
                ] {
                    if let OutputStoreDimensionRow::Proven(digests) = dimension
                        && (digests.is_empty() || digests.windows(2).any(|pair| pair[0] >= pair[1]))
                    {
                        return Err(OutputProductError::Corrupt);
                    }
                }
            }
            if crossing.source.kind != "source"
                || crossing.original_source.kind != "source"
                || crossing.sink.kind != "sink"
                || crossing.sink.site != self.anchor
                || crossing.witness_path >= self.witnesses.len()
                || crossing.prefix_steps > self.witnesses[crossing.witness_path].steps.len()
            {
                return Err(OutputProductError::Corrupt);
            }
        }
        for evidence in &self.store_seed_evidence {
            evidence.read.validate()?;
            if evidence.read.kind != "source"
                || !self.retains_origin_event(&evidence.read)
                || evidence
                    .write_sites
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
                || evidence
                    .origin_sites
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
            {
                return Err(OutputProductError::Corrupt);
            }
            for site in evidence.write_sites.iter().chain(&evidence.origin_sites) {
                site.clone().decode()?;
            }
        }
        for decline in &self.sanitizer_declines {
            decline.point.clone().decode()?;
            decline.location.clone().decode()?;
            if decline.label.is_empty()
                || !self.retains_sanitizer_step(&decline.point, decline.point_id, decline.target_id)
            {
                return Err(OutputProductError::Corrupt);
            }
        }
        if self
            .sanitizer_declines
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(OutputProductError::Corrupt);
        }
        for note in &self.barrier_notes {
            note.source.validate()?;
            note.sink.validate()?;
            if note.source.kind != "source"
                || note.sink.kind != "sink"
                || note.sink.site != self.anchor
            {
                return Err(OutputProductError::Corrupt);
            }
            for check in &note.checks {
                check.validate()?;
            }
        }
        for pair in &self.barrier_pairs {
            pair.lenient.validate()?;
            if pair.lenient.anchor != self.anchor {
                return Err(OutputProductError::Corrupt);
            }
            if let Some(strict) = &pair.strict {
                strict.validate()?;
                if strict.anchor != self.anchor {
                    return Err(OutputProductError::Corrupt);
                }
            }
        }
        self.anchor.clone().decode()?;
        let mut referenced_witnesses = vec![false; self.witnesses.len()];
        for witness in &self.witnesses {
            if witness.truncation_cause.is_some() != (witness.omitted_steps_lower_bound > 0) {
                return Err(OutputProductError::Corrupt);
            }
            if witness.truncation_cause.as_ref().is_some_and(|cause| {
                !matches!(
                    cause.as_str(),
                    "reconstruction_step_limit"
                        | "reconstruction_expansion_limit"
                        | "reusable_summary_omitted"
                        | "retention_exhausted"
                )
            }) {
                return Err(OutputProductError::Corrupt);
            }
            for step in &witness.steps {
                step.source.clone().decode()?;
                if let Some(target) = &step.target {
                    target.clone().decode()?;
                }
                if let Some(origin) = &step.origin {
                    origin.clone().decode()?;
                }
                match (&step.kind[..], &step.typed) {
                    (
                        "edge:modeled_receiver",
                        OutputWitnessStepState::ModeledReceiver { operand },
                    ) => {
                        operand.clone().decode()?;
                        let call = step.origin.as_ref().ok_or(OutputProductError::Corrupt)?;
                        if operand.mount != call.mount
                            || operand.path != call.path
                            || operand.language != call.language
                            || operand.anchor.start.byte_offset < call.anchor.start.byte_offset
                            || operand.anchor.end.byte_offset > call.anchor.end.byte_offset
                            || operand.anchor.start.byte_offset >= operand.anchor.end.byte_offset
                        {
                            return Err(OutputProductError::Corrupt);
                        }
                    }
                    ("edge:modeled_receiver", _)
                    | (_, OutputWitnessStepState::ModeledReceiver { .. }) => {
                        return Err(OutputProductError::Corrupt);
                    }
                    _ => {}
                }
                if !matches!(
                    step.kind.as_str(),
                    "seed"
                        | "edge:modeled_receiver"
                        | "edge:normal"
                        | "edge:conditional_true"
                        | "edge:conditional_false"
                        | "edge:switch_case"
                        | "edge:loop_back"
                        | "edge:exceptional"
                        | "edge:cleanup"
                        | "edge:async_normal"
                        | "edge:async_exceptional"
                        | "edge:call_to_entry"
                        | "edge:normal_return"
                        | "edge:exceptional_return"
                        | "edge:call_to_normal_continuation"
                        | "edge:call_to_exceptional_continuation"
                        | "end_summary_gap:normal"
                        | "end_summary_gap:exceptional"
                ) {
                    return Err(OutputProductError::Corrupt);
                }
                if step.input_fact != 0 || step.output_fact != 0 {
                    return Err(OutputProductError::Corrupt);
                }
            }
        }
        for finding in &self.findings {
            if finding.model_receipt.as_ref().is_some_and(|receipt| {
                !crate::model_attribution::model_receipt_valid(receipt) || receipt.is_empty()
            }) {
                return Err(OutputProductError::Corrupt);
            }
            finding.sink.validate()?;
            if finding.sink.kind != "sink" || finding.sink.site != self.anchor {
                return Err(OutputProductError::Corrupt);
            }
            if finding.witness_truncated != finding.witness_truncation_cause.is_some() {
                return Err(OutputProductError::Corrupt);
            }
            if finding
                .witness_truncation_cause
                .as_ref()
                .is_some_and(|cause| {
                    !matches!(
                        cause.as_str(),
                        "collection_budget"
                            | "quality_not_retained"
                            | "reconstruction_step_limit"
                            | "reconstruction_expansion_limit"
                            | "reusable_summary_omitted"
                            | "retention_exhausted"
                    )
                })
            {
                return Err(OutputProductError::Corrupt);
            }
            if !valid_classes(&finding.classes) {
                return Err(OutputProductError::Corrupt);
            }
            let mut frontier = PathQualityFrontier::default();
            for row in &finding.path_qualities {
                frontier.insert(row.quality());
            }
            let canonical = frontier
                .iter()
                .map(|quality| OutputPathQualityRow {
                    proven: quality.is_proven(),
                    complete: quality.is_complete(),
                })
                .collect::<Vec<_>>();
            if finding.path_qualities.is_empty() || finding.path_qualities != canonical {
                return Err(OutputProductError::Corrupt);
            }
            finding.entry.clone().decode()?;
            if finding
                .origins
                .windows(2)
                .any(|pair| pair[0].event >= pair[1].event)
            {
                return Err(OutputProductError::Corrupt);
            }
            for origin in &finding.origins {
                origin.event.validate()?;
                for closure in &origin.authored_arm_closures {
                    closure.validate()?;
                }
                if let Some(frontier) = &origin.frontier_source {
                    frontier.validate()?;
                }
                if origin.event.kind != "source"
                    || origin
                        .witness_paths
                        .iter()
                        .any(|&index| index >= self.witnesses.len())
                    || origin
                        .witness_paths
                        .windows(2)
                        .any(|pair| pair[0] >= pair[1])
                    || !valid_classes(&origin.classes)
                    || !valid_classes(&origin.reached_classes)
                {
                    return Err(OutputProductError::Corrupt);
                }
                for &index in &origin.witness_paths {
                    if referenced_witnesses[index] {
                        return Err(OutputProductError::Corrupt);
                    }
                    referenced_witnesses[index] = true;
                }
            }
        }
        if referenced_witnesses.contains(&false) {
            return Err(OutputProductError::Corrupt);
        }
        for crossing in &self.store_crossings {
            if !self.findings.iter().any(|finding| {
                finding.sink == crossing.sink
                    && finding.origins.iter().any(|origin| {
                        origin.event == crossing.source
                            && origin.witness_paths.contains(&crossing.witness_path)
                    })
            }) {
                return Err(OutputProductError::Corrupt);
            }
        }
        Ok(())
    }
}

fn remount_workspace_json(
    value: &mut serde_json::Value,
    from: StableDigest,
    to: StableDigest,
) -> Result<(), OutputProductError> {
    let stored = serde_json::to_value(from).map_err(|_| OutputProductError::Corrupt)?;
    let current = serde_json::to_value(to).map_err(|_| OutputProductError::Corrupt)?;
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            serde_json::Value::Object(fields) => {
                if let Some(mount) = fields.get_mut("mount")
                    && *mount == stored
                {
                    *mount = current.clone();
                }
                pending.extend(fields.values_mut());
            }
            serde_json::Value::Array(values) => pending.extend(values.iter_mut()),
            _ => {}
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputProductError {
    Corrupt,
}

impl OutputLocatorRow {
    pub fn encode(locator: &SemanticLocator) -> Self {
        Self {
            mount: locator.mount().digest(),
            path: locator.path().as_str().to_owned(),
            language: locator.language().stable_label().to_owned(),
            declaration: locator
                .declaration()
                .segments()
                .iter()
                .map(|segment| SegmentRow {
                    kind: segment.kind().stable_label().to_owned(),
                    name: segment.name().map(str::to_owned),
                    anchor: segment.anchor().into(),
                    sibling_ordinal: segment.sibling_ordinal(),
                })
                .collect(),
            role: locator.role().stable_label().to_owned(),
            anchor: locator.anchor().into(),
        }
    }

    pub fn decode(self) -> Result<SemanticLocator, OutputProductError> {
        let path =
            WorkspaceRelativePath::new(&self.path).map_err(|_| OutputProductError::Corrupt)?;
        let language = SemanticLanguage::ALL
            .into_iter()
            .find(|language| language.stable_label() == self.language)
            .ok_or(OutputProductError::Corrupt)?;
        let kinds = [
            DeclarationSegmentKind::File,
            DeclarationSegmentKind::Namespace,
            DeclarationSegmentKind::Type,
            DeclarationSegmentKind::Function,
            DeclarationSegmentKind::Method,
            DeclarationSegmentKind::Constructor,
            DeclarationSegmentKind::Initializer,
            DeclarationSegmentKind::LocalFunction,
            DeclarationSegmentKind::Lambda,
            DeclarationSegmentKind::Closure,
            DeclarationSegmentKind::AnonymousCallable,
        ];
        let mut segments = Vec::with_capacity(self.declaration.len());
        for row in self.declaration {
            let kind = kinds
                .into_iter()
                .find(|kind| kind.stable_label() == row.kind)
                .ok_or(OutputProductError::Corrupt)?;
            let anchor = row.anchor.decode()?;
            segments.push(match row.name {
                Some(name) => DeclarationSegment::named(kind, name, anchor, row.sibling_ordinal)
                    .map_err(|_| OutputProductError::Corrupt)?,
                None => DeclarationSegment::anonymous(kind, anchor, row.sibling_ordinal),
            });
        }
        let declaration =
            DeclarationLocator::new(segments).map_err(|_| OutputProductError::Corrupt)?;
        let roles = [
            SemanticRole::Artifact,
            SemanticRole::Procedure,
            SemanticRole::Block,
            SemanticRole::ProgramPoint,
            SemanticRole::Value,
            SemanticRole::Allocation,
            SemanticRole::CallSite,
            SemanticRole::MemoryLocation,
            SemanticRole::Capture,
            SemanticRole::SourceMapping,
            SemanticRole::Evidence,
            SemanticRole::Gap,
        ];
        let role = roles
            .into_iter()
            .find(|role| role.stable_label() == self.role)
            .ok_or(OutputProductError::Corrupt)?;
        Ok(SemanticLocator::new(
            WorkspaceMountId::from_digest(self.mount),
            path,
            language,
            declaration,
            role,
            self.anchor.decode()?,
        ))
    }
}
