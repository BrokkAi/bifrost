use super::{
    ExtensionCancellation, ExtensionWorkspace, ObservationDocument, ObservationMappingResult,
    SemanticRelationRequest, SemanticRelationSnapshot, StructuralRequest, StructuralResult,
    TypestateRequest, TypestateSnapshot,
};
use crate::extension::ExtensionOutcome;
use serde::{Deserialize, Serialize};
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
        f.write_str(&self.0)
    }
}
impl fmt::Display for ExtensionEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ExtensionDecodeError {}
impl std::error::Error for ExtensionEncodeError {}

pub fn decode_request_json(bytes: &[u8]) -> Result<ExtensionRequest, ExtensionDecodeError> {
    serde_json::from_slice(bytes)
        .map_err(|error| ExtensionDecodeError(error.to_string().into_boxed_str()))
}
pub fn encode_request_json(request: &ExtensionRequest) -> Result<Vec<u8>, ExtensionEncodeError> {
    serde_json::to_vec(request)
        .map_err(|error| ExtensionEncodeError(error.to_string().into_boxed_str()))
}
pub fn encode_response_json(response: &ExtensionResponse) -> Result<Vec<u8>, ExtensionEncodeError> {
    serde_json::to_vec(response)
        .map_err(|error| ExtensionEncodeError(error.to_string().into_boxed_str()))
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
