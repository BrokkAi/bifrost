//! Deterministic JSON encoding for CSMI documents.
//!
//! CSMI uses JSON Canonicalization Scheme (RFC 8785) as its serialization
//! baseline.  This module supplies the no-whitespace, lexicographically keyed
//! JSON core and applies the v0.1 set-normalization rules before encoding.
//! Vocabulary payloads remain JSON values and are canonicalized recursively;
//! their vocabulary-specific schemas still belong to the vocabulary owner.

use super::model::{CsmiPackManifest, CsmiSemanticDocument};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Debug)]
pub enum CsmiCanonicalError {
    Json(serde_json::Error),
}

impl fmt::Display for CsmiCanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "JSON canonicalization failed: {error}"),
        }
    }
}

impl std::error::Error for CsmiCanonicalError {}

impl From<serde_json::Error> for CsmiCanonicalError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

/// Set-valued core arrays from section 2.5 of the CSMI v0.1 specification.
/// Ordered arrays (descriptors, parameters, results, type arguments, and
/// projection steps) are deliberately absent from this list.
const SET_ARRAY_FIELDS: &[&str] = &[
    "semanticModels",
    "artifactSelectors",
    "digests",
    "provenanceRecords",
    "inputs",
    "compatibilityConstraints",
    "vocabularyUses",
    "affects",
    "consumerResolvedDependencies",
    "symbols",
    "declarations",
    "relationships",
    "procedureSummaries",
    "transfers",
    "extensionFacts",
    "completenessStatements",
    "limitations",
    "provenance",
    "externalIdentities",
    "extensions",
    "resources",
    "derivedFrom",
];

/// Canonicalize a serializable Rust value to deterministic compact JSON.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, CsmiCanonicalError> {
    let value = serde_json::to_value(value)?;
    canonical_json_value(&value)
}

/// Canonicalize a JSON byte string.  Parsing first ensures trailing bytes and
/// malformed values cannot accidentally participate in a content digest.
pub fn canonical_json_bytes(bytes: &[u8]) -> Result<Vec<u8>, CsmiCanonicalError> {
    let value: Value = serde_json::from_slice(bytes)?;
    canonical_json_value(&value)
}

/// Canonicalize a JSON value using CSMI's set-valued-array normalization.
pub fn canonical_json_value(value: &Value) -> Result<Vec<u8>, CsmiCanonicalError> {
    let normalized = normalize_sets(value.clone(), None)?;
    Ok(serde_json_canonicalizer::to_vec(&normalized)?)
}

pub fn canonical_semantic_document(
    document: &CsmiSemanticDocument,
) -> Result<Vec<u8>, CsmiCanonicalError> {
    canonical_json(document)
}

pub fn canonical_pack_manifest(manifest: &CsmiPackManifest) -> Result<Vec<u8>, CsmiCanonicalError> {
    canonical_json(manifest)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use fmt::Write as _;
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

pub fn canonical_digest<T: Serialize>(value: &T) -> Result<String, CsmiCanonicalError> {
    Ok(sha256_hex(&canonical_json(value)?))
}

fn normalize_sets(value: Value, parent_field: Option<&str>) -> Result<Value, CsmiCanonicalError> {
    match value {
        Value::Array(values) => {
            let values = values
                .into_iter()
                .map(|value| normalize_sets(value, None))
                .collect::<Result<Vec<_>, _>>()?;
            if parent_field.is_some_and(|field| SET_ARRAY_FIELDS.contains(&field)) {
                let mut keyed = values
                    .into_iter()
                    .map(|value| {
                        let key = serde_json_canonicalizer::to_vec(&value)
                            .expect("a serde_json value is JCS serializable");
                        (key, value)
                    })
                    .collect::<Vec<_>>();
                keyed.sort_by(|left, right| left.0.cmp(&right.0));
                keyed.dedup_by(|left, right| left.0 == right.0);
                return Ok(Value::Array(
                    keyed.into_iter().map(|(_, value)| value).collect(),
                ));
            }
            Ok(Value::Array(values))
        }
        Value::Object(object) => Ok(Value::Object(
            object
                .into_iter()
                .map(|(key, value)| {
                    let value = normalize_sets(value, Some(&key))?;
                    Ok((key, value))
                })
                .collect::<Result<_, CsmiCanonicalError>>()?,
        )),
        scalar => Ok(scalar),
    }
}
