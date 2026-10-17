use super::{
    ExtensionCancellation, ExtensionWorkspace, ObservationDocument, ObservationMappingResult,
    SemanticRelationRequest, SemanticRelationSnapshot, StructuralRequest, StructuralResult,
    TypestateRequest, TypestateSnapshot,
};
use crate::extension::ExtensionOutcome;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", content = "request", rename_all = "snake_case")]
pub enum ExtensionRequest {
    Structural(StructuralRequest),
    SemanticRelations(SemanticRelationRequest),
    Typestate(Box<TypestateRequest>),
    Observations(Box<ObservationDocument>),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", content = "response", rename_all = "snake_case")]
pub enum ExtensionResponse {
    Structural(ExtensionOutcome<StructuralResult>),
    SemanticRelations(ExtensionOutcome<SemanticRelationSnapshot>),
    Typestate(ExtensionOutcome<TypestateSnapshot>),
    Observations(ObservationMappingResult),
}

#[derive(Debug)]
pub struct ExtensionDecodeError(pub Box<str>);
#[derive(Debug)]
pub struct ExtensionEncodeError(pub Box<str>);
impl fmt::Display for ExtensionDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        super::fmt_text(&self.0, f)
    }
}
impl fmt::Display for ExtensionEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        super::fmt_text(&self.0, f)
    }
}
impl std::error::Error for ExtensionDecodeError {}
impl std::error::Error for ExtensionEncodeError {}

pub fn decode_request_json(bytes: &[u8]) -> Result<ExtensionRequest, ExtensionDecodeError> {
    serde_json::from_slice(bytes)
        .map_err(|error| ExtensionDecodeError(error.to_string().into_boxed_str()))
}
pub fn encode_request_json(request: &ExtensionRequest) -> Result<Vec<u8>, ExtensionEncodeError> {
    encode_json(request)
}
pub fn encode_response_json(response: &ExtensionResponse) -> Result<Vec<u8>, ExtensionEncodeError> {
    encode_json(response)
}

fn encode_json(value: &impl Serialize) -> Result<Vec<u8>, ExtensionEncodeError> {
    serde_json::to_vec(value)
        .map_err(|error| ExtensionEncodeError(error.to_string().into_boxed_str()))
}

pub(super) fn canonical_json_bytes(value: &impl Serialize) -> Result<Vec<u8>, serde_json::Error> {
    let value = serde_json::to_value(value)?;
    let mut bytes = serde_json::to_vec(&canonical_json_value(value))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn canonical_json_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries = map.into_iter().collect::<Vec<_>>();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| (key, canonical_json_value(value)))
                    .collect::<Map<_, _>>(),
            )
        }
        Value::Array(values) => {
            Value::Array(values.into_iter().map(canonical_json_value).collect())
        }
        other => other,
    }
}

impl ExtensionWorkspace {
    pub fn execute(
        &self,
        request: ExtensionRequest,
        cancellation: &ExtensionCancellation,
    ) -> Result<ExtensionResponse, super::ExtensionError> {
        match request {
            ExtensionRequest::Structural(request) => self
                .structural_query(request, cancellation)
                .map(ExtensionResponse::Structural),
            ExtensionRequest::SemanticRelations(request) => self
                .semantic_relations(request, cancellation)
                .map(ExtensionResponse::SemanticRelations),
            ExtensionRequest::Typestate(request) => self
                .typestate_check(*request, cancellation)
                .map(ExtensionResponse::Typestate),
            ExtensionRequest::Observations(request) => self
                .map_observations(&request, cancellation)
                .map(ExtensionResponse::Observations),
        }
    }
}
