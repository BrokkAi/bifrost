use super::{
    ExtensionCompatibility, ExtensionLimitValues, ExtensionLimits, SourceSpan, StableDigest,
    WorkspaceGeneration,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    io::{BufRead, Write},
};

const SCHEMA: &str = "1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticRelationKind {
    ControlFlow,
    Call,
    Return,
    ControlDependence,
    ValueDependence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticDirection {
    Outgoing,
    Incoming,
    Both,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SemanticRelationScope {
    Procedure,
    File,
    BoundedCalls { max_call_depth: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SemanticSeed {
    Source { span: SourceSpan },
    StableNode { id: StableDigest },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticRelationLimits {
    pub max_seed_matches: u32,
    pub max_call_depth: u16,
    pub max_nodes: u32,
    pub max_edges: u32,
    pub max_boundaries: u32,
    pub max_diagnostics: u32,
    pub max_output_bytes: u64,
    pub max_materialized_files: u32,
    pub max_traversal_steps: u64,
    pub max_source_bytes: u64,
    pub max_value_definitions: u32,
    pub max_value_uses: u32,
    pub max_value_dependence_edges: u32,
}
impl SemanticRelationLimits {
    pub fn validate(self) -> Result<(), RelationCodecError> {
        if self.max_seed_matches == 0
            || self.max_call_depth == 0
            || self.max_nodes == 0
            || self.max_edges == 0
            || self.max_boundaries == 0
            || self.max_diagnostics == 0
            || self.max_output_bytes == 0
            || self.max_materialized_files == 0
            || self.max_traversal_steps == 0
            || self.max_source_bytes == 0
            || self.max_value_definitions == 0
            || self.max_value_uses == 0
            || self.max_value_dependence_edges == 0
        {
            return Err(RelationCodecError::new(
                "every semantic relation limit must be positive",
            ));
        }
        Ok(())
    }
}
impl From<ExtensionLimitValues> for SemanticRelationLimits {
    fn from(v: ExtensionLimitValues) -> Self {
        Self {
            max_seed_matches: v.result_items,
            max_call_depth: v.call_depth,
            max_nodes: v.semantic_nodes,
            max_edges: v.semantic_edges,
            max_boundaries: v.diagnostics,
            max_diagnostics: v.diagnostics,
            max_output_bytes: v.result_bytes,
            max_materialized_files: v.semantic_files,
            max_traversal_steps: v.traversal_steps,
            max_source_bytes: v.source_bytes,
            max_value_definitions: v.semantic_nodes,
            max_value_uses: v.semantic_nodes,
            max_value_dependence_edges: v.semantic_edges,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticRelationRequest {
    pub schema_version: Box<str>,
    pub compatibility: ExtensionCompatibility,
    pub expected_generation: WorkspaceGeneration,
    pub seeds: Box<[SemanticSeed]>,
    pub scope: SemanticRelationScope,
    pub relations: Box<[SemanticRelationKind]>,
    pub direction: SemanticDirection,
    pub limits: SemanticRelationLimits,
}
impl SemanticRelationRequest {
    pub fn new(
        expected_generation: WorkspaceGeneration,
        seeds: Vec<SemanticSeed>,
        scope: SemanticRelationScope,
        relations: Vec<SemanticRelationKind>,
        direction: SemanticDirection,
        limits: SemanticRelationLimits,
    ) -> Result<Self, RelationCodecError> {
        let request = Self {
            schema_version: SCHEMA.into(),
            compatibility: ExtensionCompatibility::default(),
            expected_generation,
            seeds: seeds.into_boxed_slice(),
            scope,
            relations: relations.into_boxed_slice(),
            direction,
            limits,
        };
        request.validate()?;
        Ok(request)
    }
    pub fn from_source(
        expected_generation: WorkspaceGeneration,
        span: SourceSpan,
        limits: ExtensionLimits,
    ) -> Result<Self, RelationCodecError> {
        Self::new(
            expected_generation,
            vec![SemanticSeed::Source { span }],
            SemanticRelationScope::Procedure,
            vec![SemanticRelationKind::ControlFlow],
            SemanticDirection::Outgoing,
            limits.values().into(),
        )
    }
    pub fn validate(&self) -> Result<(), RelationCodecError> {
        if self.schema_version.as_ref() != SCHEMA {
            return Err(RelationCodecError::new(
                "unsupported semantic relation schema version",
            ));
        }
        if self.seeds.is_empty() || self.relations.is_empty() {
            return Err(RelationCodecError::new(
                "seeds and relations must be nonempty",
            ));
        }
        self.limits.validate()?;
        if matches!(
            self.scope,
            SemanticRelationScope::BoundedCalls { max_call_depth: 0 }
        ) {
            return Err(RelationCodecError::new(
                "bounded call depth must be positive",
            ));
        }
        for seed in &self.seeds {
            if let SemanticSeed::Source { span } = seed {
                span.validate().map_err(RelationCodecError::new)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SemanticProof {
    Proven,
    Unproven { reason: Box<str> },
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SemanticRelationCompleteness {
    Complete,
    Partial { reason: Box<str> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticEvidence {
    pub kind: Box<str>,
    pub mappings: Box<[SourceSpan]>,
    pub proof: SemanticProof,
    pub completeness: SemanticRelationCompleteness,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticNodeOccurrence {
    /// Response-local dense index. Valid only inside this snapshot; never
    /// persist it and never join on it across responses.
    pub local_id: u32,
    /// Persistable identity of the node, anchored (like a policy finding id)
    /// on the workspace-relative path, the enclosing declaration's stable
    /// name, the hash of the exact source bytes the node denotes, and the
    /// node's occurrence ordinal among byte-identical siblings under the same
    /// owner. No workspace generation, no absolute byte offsets and no
    /// absolute path participate, so an edit elsewhere in the file, an edit to
    /// an unrelated file, or a relocated checkout leave the id unchanged.
    ///
    /// Editing the denoted bytes, renaming the enclosing declaration, or
    /// moving the file *does* change the id: an id that still matches is
    /// evidence the node still denotes the same text, never a silent alias for
    /// changed source. Ids are therefore safe to persist and join across
    /// revisions, but a disappeared id means "changed or gone", not "gone".
    pub stable_id: StableDigest,
    pub call_context: Box<[StableDigest]>,
    pub span: SourceSpan,
    pub role: Box<str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueOccurrenceRole {
    Definition,
    Use,
    Observation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueObservationPhase {
    BeforeEffects,
    AfterEffects,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StableValueCarrier {
    pub digest: StableDigest,
    pub projection: Box<str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValueOccurrence {
    pub node: u32,
    pub carrier: StableValueCarrier,
    pub role: ValueOccurrenceRole,
    pub phase: ValueObservationPhase,
    pub event_ordinal: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueDependenceSubtype {
    Assignment,
    Parameter,
    Receiver,
    NormalReturn,
    ExceptionalReturn,
    Allocation,
    FieldStore,
    FieldLoad,
    IndexStore,
    IndexLoad,
    StaticStore,
    StaticLoad,
    Capture,
    CallArgument,
    CallReceiver,
    CallResult,
    SummaryTransfer,
    Merge,
    LanguageDefined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueDependenceMayStatus {
    Proven,
    Unproven,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SemanticRelationDetail {
    Generic,
    ValueDependence {
        subtypes: Box<[ValueDependenceSubtype]>,
        source: ValueOccurrence,
        target: ValueOccurrence,
        may: ValueDependenceMayStatus,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticRelationEdge {
    pub source: u32,
    pub target: u32,
    pub kind: SemanticRelationKind,
    pub subtype: Option<Box<str>>,
    pub detail: SemanticRelationDetail,
    pub proof: SemanticProof,
    pub completeness: SemanticRelationCompleteness,
    pub evidence: Box<[SemanticEvidence]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticRelationBoundaryKind {
    DispatchGap,
    MissingSemantics,
    UnsupportedRelation,
    AmbiguousSeed,
    Cancelled,
    CallDepthLimit,
    NodeLimit,
    EdgeLimit,
    BoundaryLimit,
    DiagnosticLimit,
    OutputByteLimit,
    SemanticWorkLimit,
    MaterializedFileLimit,
    TraversalStepLimit,
    UnavailableContinuation,
    NonExitingRegion,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticRelationBoundary {
    pub kind: SemanticRelationBoundaryKind,
    pub at: Option<u32>,
    pub relations: Box<[SemanticRelationKind]>,
    pub message: Box<str>,
    pub evidence: Box<[SemanticEvidence]>,
}

impl SemanticRelationBoundaryKind {
    /// Whether this boundary exists because a caller-supplied budget stopped
    /// the derivation, as opposed to analysis reaching a genuine edge of what
    /// it can know.
    ///
    /// The distinction is the whole of issue #2412: a budget boundary is an
    /// invitation to ask again with a larger limit, while a frontier boundary
    /// is the same answer at every budget. Callers that only want to know
    /// "would more budget help?" read this rather than matching every kind.
    pub const fn is_budget(self) -> bool {
        match self {
            Self::CallDepthLimit
            | Self::NodeLimit
            | Self::EdgeLimit
            | Self::BoundaryLimit
            | Self::DiagnosticLimit
            | Self::OutputByteLimit
            | Self::SemanticWorkLimit
            | Self::MaterializedFileLimit
            | Self::TraversalStepLimit => true,
            Self::DispatchGap
            | Self::MissingSemantics
            | Self::UnsupportedRelation
            | Self::AmbiguousSeed
            | Self::Cancelled
            | Self::UnavailableContinuation
            | Self::NonExitingRegion => false,
        }
    }
}

/// How far the derivation got, and — when it stopped short — *why* (#2412).
///
/// Frontier-bounded and budget-bounded are deliberately distinct states rather
/// than one `Partial`: conflating them made every procedure that reaches any
/// analysis frontier report as budget-truncated, so raising every budget
/// thirtyfold produced byte-identical output with the same truncation flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticRelationStatus {
    /// Every requested relation was derived, and no boundary of either kind
    /// was reached. The only status from which an empty edge set is an
    /// authoritative absence claim.
    Complete,
    /// Analysis reached a genuine edge of what it can know (a region with no
    /// path to a procedure exit, a dispatch gap, non-exhaustive value-flow
    /// candidate coverage, ...) while every caller budget still had room.
    /// Raising the budgets returns exactly this answer again.
    FrontierBounded,
    /// A caller-supplied budget stopped the derivation. The snapshot's
    /// boundaries name every exhausted dimension; asking again with a larger
    /// limit can return more.
    ///
    /// Takes precedence over [`Self::FrontierBounded`] when both occurred,
    /// because it is the actionable one — the frontier boundaries stay
    /// enumerable in `boundaries` either way.
    BudgetBounded,
    Unsupported,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticRelationSnapshot {
    pub schema_version: Box<str>,
    pub generation: WorkspaceGeneration,
    pub request_digest: StableDigest,
    pub status: SemanticRelationStatus,
    pub nodes: Box<[SemanticNodeOccurrence]>,
    pub edges: Box<[SemanticRelationEdge]>,
    pub boundaries: Box<[SemanticRelationBoundary]>,
    pub snapshot_digest: StableDigest,
}
impl SemanticRelationSnapshot {
    pub fn try_new(
        generation: WorkspaceGeneration,
        request_digest: StableDigest,
        status: SemanticRelationStatus,
        mut nodes: Vec<SemanticNodeOccurrence>,
        mut edges: Vec<SemanticRelationEdge>,
        mut boundaries: Vec<SemanticRelationBoundary>,
    ) -> Result<Self, RelationCodecError> {
        let old_ids = nodes
            .iter()
            .map(|node| (node.local_id, node.stable_id.clone()))
            .collect::<std::collections::BTreeMap<_, _>>();
        if old_ids.len() != nodes.len() {
            return Err(RelationCodecError::new("duplicate input node local ID"));
        }
        nodes.sort_by(|a, b| {
            (&a.stable_id, &a.call_context, a.span.start_utf8_byte).cmp(&(
                &b.stable_id,
                &b.call_context,
                b.span.start_utf8_byte,
            ))
        });
        for (index, node) in nodes.iter_mut().enumerate() {
            node.local_id =
                u32::try_from(index).map_err(|_| RelationCodecError::new("too many nodes"))?;
        }
        let canonical_ids = nodes
            .iter()
            .map(|node| node.stable_id.clone())
            .enumerate()
            .map(|(index, stable_id)| (stable_id, index as u32))
            .collect::<std::collections::BTreeMap<_, _>>();
        for edge in &mut edges {
            edge.source = old_ids
                .get(&edge.source)
                .and_then(|id| canonical_ids.get(id))
                .copied()
                .ok_or_else(|| RelationCodecError::new("dangling input edge source"))?;
            edge.target = old_ids
                .get(&edge.target)
                .and_then(|id| canonical_ids.get(id))
                .copied()
                .ok_or_else(|| RelationCodecError::new("dangling input edge target"))?;
            if let SemanticRelationDetail::ValueDependence { source, target, .. } = &mut edge.detail
            {
                source.node = edge.source;
                target.node = edge.target;
            }
        }
        edges.sort_by(|a, b| {
            (a.kind, &a.subtype, a.source, a.target).cmp(&(b.kind, &b.subtype, b.source, b.target))
        });
        boundaries.sort_by_key(|b| (b.kind, b.at));
        let zero = StableDigest::parse("0".repeat(64)).expect("valid digest");
        let mut snapshot = Self {
            schema_version: SCHEMA.into(),
            generation,
            request_digest,
            status,
            nodes: nodes.into_boxed_slice(),
            edges: edges.into_boxed_slice(),
            boundaries: boundaries.into_boxed_slice(),
            snapshot_digest: zero,
        };
        snapshot.validate()?;
        snapshot.snapshot_digest = snapshot_digest(&snapshot)?;
        Ok(snapshot)
    }
    pub fn validate(&self) -> Result<(), RelationCodecError> {
        if self.schema_version.as_ref() != SCHEMA {
            return Err(RelationCodecError::new(
                "unsupported semantic relation schema version",
            ));
        }
        for (index, node) in self.nodes.iter().enumerate() {
            if node.local_id as usize != index {
                return Err(RelationCodecError::new("local IDs must be contiguous"));
            }
            node.span.validate().map_err(RelationCodecError::new)?;
        }
        for edge in &self.edges {
            if edge.source as usize >= self.nodes.len() || edge.target as usize >= self.nodes.len()
            {
                return Err(RelationCodecError::new("dangling edge endpoint"));
            }
            if edge.evidence.is_empty() {
                return Err(RelationCodecError::new("edge evidence must be nonempty"));
            }
            if let SemanticRelationDetail::ValueDependence {
                subtypes,
                source,
                target,
                ..
            } = &edge.detail
            {
                if edge.kind != SemanticRelationKind::ValueDependence || subtypes.is_empty() {
                    return Err(RelationCodecError::new(
                        "value dependence requires a nonempty subtype chain",
                    ));
                }
                if source.node != edge.source || target.node != edge.target {
                    return Err(RelationCodecError::new(
                        "value occurrence aliases must match edge endpoints",
                    ));
                }
                for carrier in [&source.carrier, &target.carrier] {
                    if carrier.digest != value_carrier_digest(&carrier.projection)? {
                        return Err(RelationCodecError::new("value carrier digest mismatch"));
                    }
                }
            } else if edge.kind == SemanticRelationKind::ValueDependence {
                return Err(RelationCodecError::new(
                    "value dependence edge requires value detail",
                ));
            }
        }
        let budget_boundaries = self
            .boundaries
            .iter()
            .filter(|boundary| boundary.kind.is_budget())
            .count();
        match self.status {
            SemanticRelationStatus::Complete if !self.boundaries.is_empty() => {
                return Err(RelationCodecError::new(
                    "complete snapshots cannot contain boundaries",
                ));
            }
            // The two bounded states are claims about *why* the derivation
            // stopped, so each must be able to point at the boundary that says
            // so. A frontier-bounded snapshot carrying a budget boundary would
            // be the #2412 conflation in the other direction.
            SemanticRelationStatus::BudgetBounded if budget_boundaries == 0 => {
                return Err(RelationCodecError::new(
                    "budget-bounded snapshots must name the exhausted dimension",
                ));
            }
            SemanticRelationStatus::FrontierBounded
                if budget_boundaries > 0 || self.boundaries.is_empty() =>
            {
                return Err(RelationCodecError::new(
                    "frontier-bounded snapshots must carry only analysis boundaries",
                ));
            }
            _ => {}
        }
        Ok(())
    }
    /// Whether an empty edge set is a claim that no such edge exists.
    ///
    /// Only [`SemanticRelationStatus::Complete`] qualifies: a snapshot that
    /// stopped at a frontier or ran out of budget has not looked everywhere,
    /// and neither bounded state may be read as proof of absence.
    pub fn authoritative_absence(&self) -> bool {
        self.status == SemanticRelationStatus::Complete && self.edges.is_empty()
    }
}

pub(crate) fn value_carrier_digest(projection: &str) -> Result<StableDigest, RelationCodecError> {
    let mut hasher = Sha256::new();
    hasher.update(b"brokk-bifrost-extension-value-carrier-v1\0");
    hasher.update(projection.as_bytes());
    StableDigest::parse(format!("{:x}", hasher.finalize())).map_err(RelationCodecError::new)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationCodecError(Box<str>);
impl RelationCodecError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into().into_boxed_str())
    }
}
impl fmt::Display for RelationCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for RelationCodecError {}

pub fn encode_relation_request_json(
    value: &SemanticRelationRequest,
) -> Result<Vec<u8>, RelationCodecError> {
    value.validate()?;
    canonical_bytes(value)
}
pub fn decode_relation_request_json(
    bytes: &[u8],
) -> Result<SemanticRelationRequest, RelationCodecError> {
    let value: SemanticRelationRequest = decode(bytes)?;
    value.validate()?;
    Ok(value)
}
pub fn encode_relation_snapshot_json(
    value: &SemanticRelationSnapshot,
) -> Result<Vec<u8>, RelationCodecError> {
    value.validate()?;
    canonical_bytes(value)
}
pub fn decode_relation_snapshot_json(
    bytes: &[u8],
) -> Result<SemanticRelationSnapshot, RelationCodecError> {
    let value: SemanticRelationSnapshot = decode(bytes)?;
    value.validate()?;
    if snapshot_digest(&value)? != value.snapshot_digest {
        return Err(RelationCodecError::new("snapshot digest mismatch"));
    }
    Ok(value)
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "record", rename_all = "snake_case")]
enum Record {
    Header {
        schema_version: Box<str>,
        generation: WorkspaceGeneration,
        request_digest: StableDigest,
        status: SemanticRelationStatus,
    },
    Node {
        node: SemanticNodeOccurrence,
    },
    Edge {
        edge: SemanticRelationEdge,
    },
    Boundary {
        boundary: SemanticRelationBoundary,
    },
    Summary {
        nodes: u64,
        edges: u64,
        boundaries: u64,
        snapshot_digest: StableDigest,
    },
}
pub fn write_relation_snapshot_jsonl(
    value: &SemanticRelationSnapshot,
    mut writer: impl Write,
) -> Result<(), RelationCodecError> {
    value.validate()?;
    let mut records = vec![Record::Header {
        schema_version: value.schema_version.clone(),
        generation: value.generation.clone(),
        request_digest: value.request_digest.clone(),
        status: value.status,
    }];
    records.extend(
        value
            .nodes
            .iter()
            .cloned()
            .map(|node| Record::Node { node }),
    );
    records.extend(
        value
            .edges
            .iter()
            .cloned()
            .map(|edge| Record::Edge { edge }),
    );
    records.extend(
        value
            .boundaries
            .iter()
            .cloned()
            .map(|boundary| Record::Boundary { boundary }),
    );
    records.push(Record::Summary {
        nodes: value.nodes.len() as u64,
        edges: value.edges.len() as u64,
        boundaries: value.boundaries.len() as u64,
        snapshot_digest: value.snapshot_digest.clone(),
    });
    for record in records {
        writer
            .write_all(&canonical_bytes(&record)?)
            .map_err(|e| RelationCodecError::new(e.to_string()))?;
    }
    Ok(())
}
pub fn read_relation_snapshot_jsonl(
    reader: impl BufRead,
) -> Result<SemanticRelationSnapshot, RelationCodecError> {
    let mut header = None;
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut boundaries = Vec::new();
    let mut summary = None;
    for line in reader.lines() {
        match decode::<Record>(
            line.map_err(|e| RelationCodecError::new(e.to_string()))?
                .as_bytes(),
        )? {
            Record::Header {
                schema_version,
                generation,
                request_digest,
                status,
            } if header.is_none() => {
                header = Some((schema_version, generation, request_digest, status))
            }
            Record::Node { node } => nodes.push(node),
            Record::Edge { edge } => edges.push(edge),
            Record::Boundary { boundary } => boundaries.push(boundary),
            Record::Summary {
                nodes,
                edges,
                boundaries,
                snapshot_digest,
            } => summary = Some((nodes, edges, boundaries, snapshot_digest)),
            _ => return Err(RelationCodecError::new("invalid JSONL record order")),
        }
    }
    let (schema_version, generation, request_digest, status) =
        header.ok_or_else(|| RelationCodecError::new("missing JSONL header"))?;
    let (nc, ec, bc, snapshot_digest) =
        summary.ok_or_else(|| RelationCodecError::new("missing JSONL summary"))?;
    if (nc, ec, bc)
        != (
            nodes.len() as u64,
            edges.len() as u64,
            boundaries.len() as u64,
        )
    {
        return Err(RelationCodecError::new("JSONL count mismatch"));
    }
    let value = SemanticRelationSnapshot {
        schema_version,
        generation,
        request_digest,
        status,
        nodes: nodes.into_boxed_slice(),
        edges: edges.into_boxed_slice(),
        boundaries: boundaries.into_boxed_slice(),
        snapshot_digest,
    };
    decode_relation_snapshot_json(&encode_relation_snapshot_json(&value)?)
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, RelationCodecError> {
    serde_json::from_slice(bytes).map_err(|e| RelationCodecError::new(e.to_string()))
}
fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>, RelationCodecError> {
    let value = serde_json::to_value(value).map_err(|e| RelationCodecError::new(e.to_string()))?;
    let mut bytes = serde_json::to_vec(&canonical(value))
        .map_err(|e| RelationCodecError::new(e.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}
fn canonical(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries = map.into_iter().collect::<Vec<_>>();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(k, v)| (k, canonical(v)))
                    .collect::<Map<_, _>>(),
            )
        }
        Value::Array(values) => Value::Array(values.into_iter().map(canonical).collect()),
        other => other,
    }
}
fn snapshot_digest(value: &SemanticRelationSnapshot) -> Result<StableDigest, RelationCodecError> {
    let mut json =
        serde_json::to_value(value).map_err(|e| RelationCodecError::new(e.to_string()))?;
    json.as_object_mut()
        .expect("object")
        .remove("snapshot_digest");
    StableDigest::parse(format!("{:x}", Sha256::digest(canonical_bytes(&json)?)))
        .map_err(RelationCodecError::new)
}
pub(crate) fn request_digest(
    value: &SemanticRelationRequest,
) -> Result<StableDigest, RelationCodecError> {
    StableDigest::parse(format!(
        "{:x}",
        Sha256::digest(encode_relation_request_json(value)?)
    ))
    .map_err(RelationCodecError::new)
}
