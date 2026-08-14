use super::*;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    io::{BufRead, Write},
};

const SCHEMA: &str = "1.0";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ObservationScalar {
    String(Box<str>),
    Signed(i64),
    Unsigned(u64),
    Boolean(bool),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationIdentity {
    pub namespace: Box<str>,
    pub id: Box<str>,
    pub category: Box<str>,
    pub outcome: Box<str>,
    pub attributes: BTreeMap<Box<str>, ObservationScalar>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationRepository {
    pub kind: Box<str>,
    pub identity: Box<str>,
    pub revision: Box<str>,
    pub mount: Box<str>,
    pub dirty_overlay: Option<StableDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationProducer {
    pub format_name: Box<str>,
    pub format_version: Box<str>,
    pub tool_name: Box<str>,
    pub tool_version: Box<str>,
    pub adapter_name: Box<str>,
    pub adapter_version: Box<str>,
    pub input_content_sha256: StableDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationSourceIdentity {
    pub mount: Box<str>,
    pub span: SourceSpan,
    pub content_sha256: StableDigest,
    pub language: Option<Box<str>>,
    pub generated_provenance: Option<StableDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ObservationRecordKind {
    Range,
    Branch {
        branch_key: Box<str>,
        destination: Option<ObservationSourceIdentity>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationRecord {
    pub record_id: Box<str>,
    pub source: ObservationSourceIdentity,
    pub kind: ObservationRecordKind,
    pub category: Box<str>,
    pub outcome: Box<str>,
    pub attributes: BTreeMap<Box<str>, ObservationScalar>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationMappingLimits {
    pub max_records: u32,
    pub max_source_bytes: u64,
    pub max_candidate_nodes: u32,
    pub max_mapped_nodes_per_record: u32,
    pub max_total_mapped_nodes: u32,
    pub max_diagnostics: u32,
    pub max_output_bytes: u64,
    pub max_materialized_files: u32,
    pub max_traversal_steps: u64,
}
impl ObservationMappingLimits {
    fn validate(self) -> Result<(), ObservationCodecError> {
        if [
            self.max_records,
            self.max_candidate_nodes,
            self.max_mapped_nodes_per_record,
            self.max_total_mapped_nodes,
            self.max_diagnostics,
            self.max_materialized_files,
        ]
        .contains(&0)
            || [
                self.max_source_bytes,
                self.max_output_bytes,
                self.max_traversal_steps,
            ]
            .contains(&0)
        {
            return Err(ObservationCodecError::new(
                "every observation limit must be positive",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationDocument {
    pub schema_version: Box<str>,
    pub compatibility: ExtensionCompatibility,
    pub expected_generation: WorkspaceGeneration,
    pub repository: ObservationRepository,
    pub subject: ObservationIdentity,
    pub run: ObservationIdentity,
    pub producer: ObservationProducer,
    pub configuration_hash: StableDigest,
    pub limits: ObservationMappingLimits,
    pub include_synthetic: bool,
    pub include_generated: bool,
    pub records: Box<[ObservationRecord]>,
}
impl ObservationDocument {
    pub fn validate(&self) -> Result<(), ObservationCodecError> {
        if self.schema_version.as_ref() != SCHEMA {
            return Err(ObservationCodecError::new(
                "unsupported observation schema version",
            ));
        }
        self.limits.validate()?;
        if self.records.is_empty() || self.records.len() > self.limits.max_records as usize {
            return Err(ObservationCodecError::new(
                "record count is empty or exceeds max_records",
            ));
        }
        for value in [
            &self.repository.kind,
            &self.repository.identity,
            &self.repository.revision,
            &self.repository.mount,
            &self.subject.namespace,
            &self.subject.id,
            &self.run.namespace,
            &self.run.id,
            &self.producer.format_name,
            &self.producer.format_version,
            &self.producer.tool_name,
            &self.producer.tool_version,
            &self.producer.adapter_name,
            &self.producer.adapter_version,
        ] {
            if value.is_empty() {
                return Err(ObservationCodecError::new(
                    "identity and provenance strings must be nonempty",
                ));
            }
        }
        let mut ids = BTreeSet::new();
        for record in &self.records {
            if record.record_id.is_empty() || !ids.insert(record.record_id.as_ref()) {
                return Err(ObservationCodecError::new(
                    "record IDs must be nonempty and unique",
                ));
            }
            record
                .source
                .span
                .validate()
                .map_err(ObservationCodecError::new)?;
            if record.source.span.start_utf8_byte == record.source.span.end_utf8_byte {
                return Err(ObservationCodecError::new(
                    "observation ranges must be nonempty",
                ));
            }
            if record.source.mount != self.repository.mount {
                return Err(ObservationCodecError::new(
                    "record mount differs from repository mount",
                ));
            }
            if record.source.generated_provenance.is_some() && !self.include_generated {
                return Err(ObservationCodecError::new(
                    "generated source requires include_generated",
                ));
            }
            if let ObservationRecordKind::Branch {
                branch_key,
                destination,
            } = &record.kind
            {
                if branch_key.is_empty() {
                    return Err(ObservationCodecError::new("branch key must be nonempty"));
                }
                if let Some(destination) = destination {
                    destination
                        .span
                        .validate()
                        .map_err(ObservationCodecError::new)?;
                }
            }
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<StableDigest, ObservationCodecError> {
        digest(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MappedObservationNode {
    pub stable_id: StableDigest,
    pub call_context: Box<[StableDigest]>,
    pub span: SourceSpan,
    pub role: Box<str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ObservationMappingOutcome {
    Exact {
        record_id: Box<str>,
        generation: WorkspaceGeneration,
        source: ObservationSourceIdentity,
        nodes: Box<[MappedObservationNode]>,
    },
    Ambiguous {
        record_id: Box<str>,
        source: ObservationSourceIdentity,
        candidates: Box<[MappedObservationNode]>,
        discriminator: Box<str>,
    },
    Unmapped {
        record_id: Box<str>,
        source: ObservationSourceIdentity,
        reason: Box<str>,
    },
    Stale {
        record_id: Box<str>,
        source: ObservationSourceIdentity,
        reason: Box<str>,
    },
    Unsupported {
        record_id: Box<str>,
        source: ObservationSourceIdentity,
        capability: Box<str>,
    },
    Truncated {
        record_id: Box<str>,
        source: ObservationSourceIdentity,
        boundary: Box<str>,
        partial: Box<[MappedObservationNode]>,
    },
}
impl ObservationMappingOutcome {
    pub fn record_id(&self) -> &str {
        match self {
            Self::Exact { record_id, .. }
            | Self::Ambiguous { record_id, .. }
            | Self::Unmapped { record_id, .. }
            | Self::Stale { record_id, .. }
            | Self::Unsupported { record_id, .. }
            | Self::Truncated { record_id, .. } => record_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationMappingResult {
    pub schema_version: Box<str>,
    pub generation: WorkspaceGeneration,
    pub input_digest: StableDigest,
    pub complete: bool,
    pub outcomes: Box<[ObservationMappingOutcome]>,
    pub result_digest: StableDigest,
}

impl ExtensionWorkspace {
    pub fn map_observations(
        &self,
        document: &ObservationDocument,
        cancellation: &ExtensionCancellation,
    ) -> Result<ObservationMappingResult, ExtensionError> {
        document
            .validate()
            .map_err(|e| ExtensionError::InvalidRequest(e.to_string().into()))?;
        if document.expected_generation != *self.generation() {
            return Err(ExtensionError::StaleGeneration {
                expected: document.expected_generation.clone(),
                actual: self.generation().clone(),
            });
        }
        let mut outcomes = Vec::with_capacity(document.records.len());
        let mut total = 0usize;
        let sources = document
            .records
            .iter()
            .map(|record| &record.source.span.path)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|path| {
                (
                    path.clone(),
                    read_observation_source(self.project_root(), path),
                )
            })
            .collect::<BTreeMap<_, _>>();
        for record in &document.records {
            if cancellation.is_cancelled() {
                outcomes.push(ObservationMappingOutcome::Truncated {
                    record_id: record.record_id.clone(),
                    source: record.source.clone(),
                    boundary: "cancelled".into(),
                    partial: Box::new([]),
                });
                continue;
            }
            let bytes = match sources
                .get(&record.source.span.path)
                .and_then(Option::as_deref)
            {
                Some(bytes) => bytes,
                None => {
                    outcomes.push(ObservationMappingOutcome::Stale {
                        record_id: record.record_id.clone(),
                        source: record.source.clone(),
                        reason: "path_not_present".into(),
                    });
                    continue;
                }
            };
            if bytes.len() as u64 > document.limits.max_source_bytes {
                outcomes.push(ObservationMappingOutcome::Truncated {
                    record_id: record.record_id.clone(),
                    source: record.source.clone(),
                    boundary: "source_byte_limit".into(),
                    partial: Box::new([]),
                });
                continue;
            }
            let actual =
                StableDigest::parse(format!("{:x}", Sha256::digest(bytes))).expect("sha256");
            if actual != record.source.content_sha256 {
                outcomes.push(ObservationMappingOutcome::Stale {
                    record_id: record.record_id.clone(),
                    source: record.source.clone(),
                    reason: "content_hash_mismatch".into(),
                });
                continue;
            }
            let end = record.source.span.end_utf8_byte as usize;
            let source_text = std::str::from_utf8(bytes)
                .map_err(|_| ExtensionError::InvalidRequest("source is not UTF-8".into()))?;
            if end > bytes.len()
                || !source_text.is_char_boundary(record.source.span.start_utf8_byte as usize)
                || !source_text.is_char_boundary(end)
            {
                return Err(ExtensionError::InvalidRequest(
                    "range is outside source or not UTF-8 aligned".into(),
                ));
            }
            if record.source.generated_provenance.is_some() && !document.include_generated {
                outcomes.push(ObservationMappingOutcome::Unsupported {
                    record_id: record.record_id.clone(),
                    source: record.source.clone(),
                    capability: "generated_source_mapping".into(),
                });
                continue;
            }
            let relation_limits = SemanticRelationLimits {
                max_seed_matches: document.limits.max_candidate_nodes,
                max_call_depth: 1,
                max_nodes: document.limits.max_candidate_nodes,
                max_edges: 1,
                max_boundaries: document.limits.max_diagnostics,
                max_diagnostics: document.limits.max_diagnostics,
                max_output_bytes: document.limits.max_output_bytes,
                max_materialized_files: document.limits.max_materialized_files,
                max_traversal_steps: document.limits.max_traversal_steps,
                max_source_bytes: document.limits.max_source_bytes,
                max_value_definitions: document.limits.max_candidate_nodes,
                max_value_uses: document.limits.max_candidate_nodes,
                max_value_dependence_edges: 1,
            };
            let request = SemanticRelationRequest::new(
                self.generation().clone(),
                vec![SemanticSeed::Source {
                    span: record.source.span.clone(),
                }],
                SemanticRelationScope::Procedure,
                vec![SemanticRelationKind::ControlFlow],
                SemanticDirection::Outgoing,
                relation_limits,
            )
            .map_err(|e| ExtensionError::InvalidRequest(e.to_string().into()))?;
            let mapped = self.semantic_relations(request, cancellation)?;
            let Some(snapshot) = mapped.value else {
                outcomes.push(ObservationMappingOutcome::Unsupported {
                    record_id: record.record_id.clone(),
                    source: record.source.clone(),
                    capability: "semantic_source_mapping".into(),
                });
                continue;
            };
            let mut nodes = snapshot
                .nodes
                .iter()
                .filter(|node| intersects(&node.span, &record.source.span))
                .map(|node| {
                    let mapped = MappedObservationNode {
                        stable_id: node.stable_id.clone(),
                        call_context: node.call_context.clone(),
                        span: node.span.clone(),
                        role: node.role.clone(),
                    };
                    (
                        (
                            mapped.stable_id.clone(),
                            mapped.call_context.clone(),
                            mapped.span.start_utf8_byte,
                            mapped.span.end_utf8_byte,
                            mapped.role.clone(),
                        ),
                        mapped,
                    )
                })
                .collect::<BTreeMap<_, _>>()
                .into_values()
                .collect::<Vec<_>>();
            if nodes.len() > document.limits.max_mapped_nodes_per_record as usize
                || total + nodes.len() > document.limits.max_total_mapped_nodes as usize
            {
                nodes.truncate(document.limits.max_mapped_nodes_per_record as usize);
                outcomes.push(ObservationMappingOutcome::Truncated {
                    record_id: record.record_id.clone(),
                    source: record.source.clone(),
                    boundary: "mapped_node_limit".into(),
                    partial: nodes.into_boxed_slice(),
                });
                continue;
            }
            total += nodes.len();
            if nodes.is_empty() {
                let text = &source_text[record.source.span.start_utf8_byte as usize..end];
                outcomes.push(ObservationMappingOutcome::Unmapped {
                    record_id: record.record_id.clone(),
                    source: record.source.clone(),
                    reason: if text.trim().is_empty() {
                        "blank_source"
                    } else if text.trim_start().starts_with("//")
                        || text.trim_start().starts_with('#')
                    {
                        "comment"
                    } else {
                        "no_retained_semantic_mapping"
                    }
                    .into(),
                });
            } else {
                outcomes.push(ObservationMappingOutcome::Exact {
                    record_id: record.record_id.clone(),
                    generation: self.generation().clone(),
                    source: record.source.clone(),
                    nodes: nodes.into_boxed_slice(),
                });
            }
        }
        let input_digest = document
            .digest()
            .map_err(|e| ExtensionError::InvalidRequest(e.to_string().into()))?;
        let complete = outcomes.iter().all(|o| {
            matches!(
                o,
                ObservationMappingOutcome::Exact { .. }
                    | ObservationMappingOutcome::Unmapped { .. }
            )
        });
        let zero = StableDigest::parse("0".repeat(64)).unwrap();
        let mut result = ObservationMappingResult {
            schema_version: SCHEMA.into(),
            generation: self.generation().clone(),
            input_digest,
            complete,
            outcomes: outcomes.into_boxed_slice(),
            result_digest: zero,
        };
        result.result_digest =
            result_digest(&result).map_err(|e| ExtensionError::Execution(e.to_string().into()))?;
        Ok(result)
    }
}

fn intersects(a: &SourceSpan, b: &SourceSpan) -> bool {
    a.path == b.path && a.start_utf8_byte < b.end_utf8_byte && b.start_utf8_byte < a.end_utf8_byte
}

fn read_observation_source(
    root: &std::path::Path,
    path: &NormalizedRelativePath,
) -> Option<Vec<u8>> {
    fs::read(root.join(path.as_str())).ok()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservationJoinError {
    GenerationMismatch,
    StableIdSchemaMismatch,
}
impl fmt::Display for ObservationJoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ObservationJoinError {}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationSnapshotJoin {
    pub record_id: Box<str>,
    pub matches: Box<[(u32, StableDigest)]>,
    pub not_present_in_snapshot: Box<[StableDigest]>,
}
pub fn join_exact_observation(
    mapping: &ObservationMappingOutcome,
    snapshot: &SemanticRelationSnapshot,
    exact_context: Option<&[StableDigest]>,
) -> Result<ObservationSnapshotJoin, ObservationJoinError> {
    let ObservationMappingOutcome::Exact {
        record_id,
        generation,
        nodes,
        ..
    } = mapping
    else {
        return Err(ObservationJoinError::StableIdSchemaMismatch);
    };
    if generation != &snapshot.generation {
        return Err(ObservationJoinError::GenerationMismatch);
    }
    let mut matches = Vec::new();
    let mut absent = Vec::new();
    for mapped in nodes {
        let found = snapshot
            .nodes
            .iter()
            .filter(|n| {
                n.stable_id == mapped.stable_id
                    && exact_context.is_none_or(|c| n.call_context.as_ref() == c)
            })
            .collect::<Vec<_>>();
        if found.is_empty() {
            absent.push(mapped.stable_id.clone());
        } else {
            matches.extend(found.into_iter().map(|n| (n.local_id, n.stable_id.clone())));
        }
    }
    Ok(ObservationSnapshotJoin {
        record_id: record_id.clone(),
        matches: matches.into_boxed_slice(),
        not_present_in_snapshot: absent.into_boxed_slice(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationCodecError(Box<str>);
impl ObservationCodecError {
    fn new(v: impl Into<String>) -> Self {
        Self(v.into().into_boxed_str())
    }
}
impl fmt::Display for ObservationCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ObservationCodecError {}
pub fn encode_observation_document_json(
    v: &ObservationDocument,
) -> Result<Vec<u8>, ObservationCodecError> {
    v.validate()?;
    canonical_bytes(v)
}
pub fn decode_observation_document_json(
    b: &[u8],
) -> Result<ObservationDocument, ObservationCodecError> {
    let v: ObservationDocument = decode(b)?;
    v.validate()?;
    Ok(v)
}
pub fn encode_observation_result_json(
    v: &ObservationMappingResult,
) -> Result<Vec<u8>, ObservationCodecError> {
    canonical_bytes(v)
}
pub fn decode_observation_result_json(
    b: &[u8],
) -> Result<ObservationMappingResult, ObservationCodecError> {
    let v: ObservationMappingResult = decode(b)?;
    if result_digest(&v)? != v.result_digest {
        return Err(ObservationCodecError::new("result digest mismatch"));
    }
    Ok(v)
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "record", rename_all = "snake_case")]
enum JsonlRecord {
    Header {
        schema_version: Box<str>,
        generation: WorkspaceGeneration,
        input_digest: StableDigest,
        complete: bool,
    },
    Outcome {
        outcome: ObservationMappingOutcome,
    },
    Summary {
        outcomes: u64,
        result_digest: StableDigest,
    },
}
pub fn write_observation_mapping_jsonl(
    v: &ObservationMappingResult,
    mut w: impl Write,
) -> Result<(), ObservationCodecError> {
    w.write_all(&canonical_bytes(&JsonlRecord::Header {
        schema_version: v.schema_version.clone(),
        generation: v.generation.clone(),
        input_digest: v.input_digest.clone(),
        complete: v.complete,
    })?)
    .map_err(|e| ObservationCodecError::new(e.to_string()))?;
    for outcome in &v.outcomes {
        w.write_all(&canonical_bytes(&JsonlRecord::Outcome {
            outcome: outcome.clone(),
        })?)
        .map_err(|e| ObservationCodecError::new(e.to_string()))?;
    }
    w.write_all(&canonical_bytes(&JsonlRecord::Summary {
        outcomes: v.outcomes.len() as u64,
        result_digest: v.result_digest.clone(),
    })?)
    .map_err(|e| ObservationCodecError::new(e.to_string()))?;
    Ok(())
}
pub fn read_observation_mapping_jsonl(
    r: impl BufRead,
) -> Result<ObservationMappingResult, ObservationCodecError> {
    let mut header = None;
    let mut outcomes = Vec::new();
    let mut summary = None;
    for line in r.lines() {
        match decode::<JsonlRecord>(
            line.map_err(|e| ObservationCodecError::new(e.to_string()))?
                .as_bytes(),
        )? {
            JsonlRecord::Header {
                schema_version,
                generation,
                input_digest,
                complete,
            } if header.is_none() && outcomes.is_empty() => {
                header = Some((schema_version, generation, input_digest, complete))
            }
            JsonlRecord::Outcome { outcome } if header.is_some() && summary.is_none() => {
                outcomes.push(outcome)
            }
            JsonlRecord::Summary {
                outcomes,
                result_digest,
            } if summary.is_none() => summary = Some((outcomes, result_digest)),
            _ => return Err(ObservationCodecError::new("invalid JSONL record order")),
        }
    }
    let (schema_version, generation, input_digest, complete) =
        header.ok_or_else(|| ObservationCodecError::new("missing JSONL header"))?;
    let (count, result_digest) =
        summary.ok_or_else(|| ObservationCodecError::new("missing JSONL summary"))?;
    if count != outcomes.len() as u64 {
        return Err(ObservationCodecError::new("JSONL count mismatch"));
    }
    decode_observation_result_json(&encode_observation_result_json(
        &ObservationMappingResult {
            schema_version,
            generation,
            input_digest,
            complete,
            outcomes: outcomes.into_boxed_slice(),
            result_digest,
        },
    )?)
}
fn decode<T: DeserializeOwned>(b: &[u8]) -> Result<T, ObservationCodecError> {
    serde_json::from_slice(b).map_err(|e| ObservationCodecError::new(e.to_string()))
}
fn canonical_bytes(v: &impl Serialize) -> Result<Vec<u8>, ObservationCodecError> {
    let v = serde_json::to_value(v).map_err(|e| ObservationCodecError::new(e.to_string()))?;
    let mut b =
        serde_json::to_vec(&canonical(v)).map_err(|e| ObservationCodecError::new(e.to_string()))?;
    b.push(b'\n');
    Ok(b)
}
fn canonical(v: Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut e = m.into_iter().collect::<Vec<_>>();
            e.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(
                e.into_iter()
                    .map(|(k, v)| (k, canonical(v)))
                    .collect::<Map<_, _>>(),
            )
        }
        Value::Array(a) => Value::Array(a.into_iter().map(canonical).collect()),
        x => x,
    }
}
fn digest(v: &impl Serialize) -> Result<StableDigest, ObservationCodecError> {
    StableDigest::parse(format!("{:x}", Sha256::digest(canonical_bytes(v)?)))
        .map_err(ObservationCodecError::new)
}
fn result_digest(v: &ObservationMappingResult) -> Result<StableDigest, ObservationCodecError> {
    let mut json =
        serde_json::to_value(v).map_err(|e| ObservationCodecError::new(e.to_string()))?;
    json.as_object_mut().unwrap().remove("result_digest");
    digest(&json)
}
