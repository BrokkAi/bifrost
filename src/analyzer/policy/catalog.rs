//! Explicit, content-addressed taint catalog registration.
//!
//! Catalogs are machine registration inputs. They never trigger ambient
//! discovery, network access, or solver work. Registration validates the full
//! schema-v1 model, normalizes every semantic set, hashes canonical typed JSON,
//! and then updates the bounded registry transactionally.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::classification::{TextValidationError, validate_required_text};
use super::definition::{
    CatalogRef, EndpointObservationPhase, MAX_POLICY_DISPLAY_TEXT_BYTES, MAX_POLICY_SET_ITEMS,
    POLICY_DOCUMENT_SCHEMA_VERSION, PolicyCategoryId, PolicyEndpointBinding, PolicyId, PolicyPort,
    PolicySelector, TaintCatalogHash, TaintEntryId, TaintExternalModelSpec, TaintImpact,
    TaintLabel, TaintSanitizerSpec, TaintSinkSpec, TaintSourceEvidence, TaintSourceSpec,
    TaintSystemEntry, TaintTag, TaintTransferEffect, TaintTransferSpec, TaintTransformSpec,
    TaintTrustBoundary, TypestateCallBinding, TypestateSeedBinding,
};
use crate::analyzer::semantic::{WorkspaceRelativePath, WorkspaceRelativePathError};
use crate::analyzer::structural::{
    CodeQuery, CodeQueryResultDetail, DEFAULT_LIMIT, SCHEMA_VERSION as RQL_SCHEMA_VERSION,
};
use crate::schema_version::SchemaVersionOrigin;
use crate::workspace_document::{WorkspaceRoot, read_workspace_document};

pub const MAX_CATALOG_JSON_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_CATALOG_JSON_DEPTH: usize = 128;
pub const MAX_CATALOG_ENTRIES_PER_KIND: usize = 4_096;
pub const MAX_CATALOG_IDENTITIES: usize = 1_024;
pub const MAX_CATALOG_ENTRIES: usize = 65_536;
pub const MAX_CATALOG_RETAINED_CANONICAL_BYTES: usize = 64 * 1024 * 1024;
const MAX_EXTERNAL_MODEL_TRANSFERS: usize = 256;

#[derive(Debug, Clone)]
pub struct TaintCatalogDefinition {
    pub schema_version: u32,
    pub name: PolicyId,
    pub version: u32,
    pub sources: Vec<TaintSourceSpec>,
    pub sinks: Vec<TaintSinkSpec>,
    pub sanitizers: Vec<TaintSanitizerSpec>,
    pub transforms: Vec<TaintTransformSpec>,
    pub external_models: Vec<TaintExternalModelSpec>,
}

impl TaintCatalogDefinition {
    pub fn entry_count(&self) -> usize {
        self.sources.len()
            + self.sinks.len()
            + self.sanitizers.len()
            + self.transforms.len()
            + self.external_models.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaintCatalogIdentity {
    pub name: PolicyId,
    pub version: u32,
}

impl TaintCatalogIdentity {
    pub fn from_definition(definition: &TaintCatalogDefinition) -> Self {
        Self {
            name: definition.name.clone(),
            version: definition.version,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogSourceIdentity(Box<str>);

impl CatalogSourceIdentity {
    pub fn new(label: impl AsRef<str>) -> Result<Self, CatalogSourceIdentityError> {
        let label = label.as_ref();
        if label.is_empty() {
            return Err(CatalogSourceIdentityError::Empty);
        }
        if label.len() > 1_024 {
            return Err(CatalogSourceIdentityError::TooLong);
        }
        if label.chars().any(char::is_control) {
            return Err(CatalogSourceIdentityError::ControlCharacter);
        }
        Ok(Self(label.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogSourceIdentityError {
    Empty,
    TooLong,
    ControlCharacter,
}

impl fmt::Display for CatalogSourceIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "catalog source identity must not be empty",
            Self::TooLong => "catalog source identity must be at most 1024 bytes",
            Self::ControlCharacter => "catalog source identity must not contain control characters",
        })
    }
}

impl std::error::Error for CatalogSourceIdentityError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatalogRegistryLimits {
    max_identities: usize,
    max_entries: usize,
    max_retained_canonical_bytes: usize,
}

impl Default for CatalogRegistryLimits {
    fn default() -> Self {
        Self {
            max_identities: MAX_CATALOG_IDENTITIES,
            max_entries: MAX_CATALOG_ENTRIES,
            max_retained_canonical_bytes: MAX_CATALOG_RETAINED_CANONICAL_BYTES,
        }
    }
}

impl CatalogRegistryLimits {
    pub fn max_identities(self) -> usize {
        self.max_identities
    }

    pub fn max_entries(self) -> usize {
        self.max_entries
    }

    pub fn max_retained_canonical_bytes(self) -> usize {
        self.max_retained_canonical_bytes
    }

    pub fn with_max_identities(mut self, value: usize) -> Result<Self, CatalogRegistryLimitError> {
        validate_lowered_limit("max_identities", value, MAX_CATALOG_IDENTITIES)?;
        self.max_identities = value;
        Ok(self)
    }

    pub fn with_max_entries(mut self, value: usize) -> Result<Self, CatalogRegistryLimitError> {
        validate_lowered_limit("max_entries", value, MAX_CATALOG_ENTRIES)?;
        self.max_entries = value;
        Ok(self)
    }

    pub fn with_max_retained_canonical_bytes(
        mut self,
        value: usize,
    ) -> Result<Self, CatalogRegistryLimitError> {
        validate_lowered_limit(
            "max_retained_canonical_bytes",
            value,
            MAX_CATALOG_RETAINED_CANONICAL_BYTES,
        )?;
        self.max_retained_canonical_bytes = value;
        Ok(self)
    }
}

fn validate_lowered_limit(
    field: &'static str,
    value: usize,
    hard_maximum: usize,
) -> Result<(), CatalogRegistryLimitError> {
    if value == 0 || value > hard_maximum {
        return Err(CatalogRegistryLimitError {
            field,
            value,
            hard_maximum,
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatalogRegistryLimitError {
    pub field: &'static str,
    pub value: usize,
    pub hard_maximum: usize,
}

impl fmt::Display for CatalogRegistryLimitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} must be from 1 through {}, found {}",
            self.field, self.hard_maximum, self.value
        )
    }
}

impl std::error::Error for CatalogRegistryLimitError {}

#[derive(Debug, Clone)]
pub struct RegisteredTaintCatalog {
    identity: TaintCatalogIdentity,
    semantic_hash: TaintCatalogHash,
    definition: TaintCatalogDefinition,
    canonical_json: Box<[u8]>,
    source: Option<CatalogSourceIdentity>,
}

impl RegisteredTaintCatalog {
    pub fn identity(&self) -> &TaintCatalogIdentity {
        &self.identity
    }

    pub fn semantic_hash(&self) -> TaintCatalogHash {
        self.semantic_hash
    }

    pub fn definition(&self) -> &TaintCatalogDefinition {
        &self.definition
    }

    pub fn canonical_json(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn source(&self) -> Option<&CatalogSourceIdentity> {
        self.source.as_ref()
    }
}

#[derive(Debug)]
pub struct TaintCatalogRegistry {
    limits: CatalogRegistryLimits,
    catalogs: HashMap<TaintCatalogIdentity, RegisteredTaintCatalog>,
    retained_entries: usize,
    retained_canonical_bytes: usize,
    workspace_root: Option<WorkspaceRoot>,
}

impl TaintCatalogRegistry {
    pub fn new_without_workspace(limits: CatalogRegistryLimits) -> Self {
        Self {
            limits,
            catalogs: HashMap::new(),
            retained_entries: 0,
            retained_canonical_bytes: 0,
            workspace_root: None,
        }
    }

    /// Construct a registry retaining exactly one opened workspace capability.
    pub fn new_for_workspace(
        workspace_root: PathBuf,
        limits: CatalogRegistryLimits,
    ) -> Result<Self, CatalogRegistryError> {
        if !workspace_root.is_absolute() {
            return Err(CatalogRegistryError::WorkspaceRootMustBeAbsolute);
        }
        let workspace_root = WorkspaceRoot::open(&workspace_root).map_err(|error| {
            CatalogRegistryError::WorkspaceAccess {
                message: error.to_string(),
            }
        })?;
        Ok(Self {
            limits,
            catalogs: HashMap::new(),
            retained_entries: 0,
            retained_canonical_bytes: 0,
            workspace_root: Some(workspace_root),
        })
    }

    pub fn register(
        &mut self,
        catalog: TaintCatalogDefinition,
    ) -> Result<TaintCatalogHash, CatalogRegistryError> {
        self.register_with_source(catalog, None)
    }

    pub fn register_json_bytes(
        &mut self,
        source: CatalogSourceIdentity,
        bytes: &[u8],
    ) -> Result<TaintCatalogHash, CatalogRegistryError> {
        if bytes.len() > MAX_CATALOG_JSON_BYTES {
            return Err(CatalogRegistryError::JsonTooLarge {
                bytes: bytes.len(),
                maximum: MAX_CATALOG_JSON_BYTES,
            });
        }
        validate_catalog_json_shape(&source, bytes)?;
        let wire: CatalogWire =
            serde_json::from_slice(bytes).map_err(|error| CatalogRegistryError::InvalidJson {
                source: source.clone(),
                message: error.to_string(),
            })?;
        let catalog = TaintCatalogDefinition::try_from(wire)?;
        self.register_with_source(catalog, Some(source))
    }

    pub fn register_json_path(
        &mut self,
        relative_path: impl AsRef<Path>,
    ) -> Result<TaintCatalogHash, CatalogRegistryError> {
        let root = self
            .workspace_root
            .as_ref()
            .ok_or(CatalogRegistryError::WorkspaceAccessUnavailable)?;
        let document = read_workspace_document(
            root,
            relative_path.as_ref(),
            &["json"],
            MAX_CATALOG_JSON_BYTES as u64,
        )
        .map_err(|error| CatalogRegistryError::WorkspaceAccess {
            message: error.to_string(),
        })?;
        let source = catalog_source_identity_from_path(document.relative_path())?;
        self.register_json_bytes(source, document.source().as_bytes())
    }

    pub fn resolve(
        &self,
        reference: &CatalogRef,
    ) -> Result<&RegisteredTaintCatalog, CatalogRegistryError> {
        let identity = TaintCatalogIdentity {
            name: reference.name.clone(),
            version: reference.version,
        };
        let catalog = self
            .catalogs
            .get(&identity)
            .ok_or(CatalogRegistryError::UnknownCatalog { identity })?;
        if let Some(expected) = reference.sha256
            && expected != catalog.semantic_hash
        {
            return Err(CatalogRegistryError::HashPinMismatch {
                identity: catalog.identity.clone(),
                expected,
                actual: catalog.semantic_hash,
            });
        }
        Ok(catalog)
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &RegisteredTaintCatalog> {
        let mut catalogs: Vec<_> = self.catalogs.values().collect();
        catalogs.sort_by(|left, right| left.identity.cmp(&right.identity));
        catalogs.into_iter()
    }

    pub fn len(&self) -> usize {
        self.catalogs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.catalogs.is_empty()
    }

    fn register_with_source(
        &mut self,
        catalog: TaintCatalogDefinition,
        source: Option<CatalogSourceIdentity>,
    ) -> Result<TaintCatalogHash, CatalogRegistryError> {
        let catalog = normalize_and_validate_catalog(catalog)?;
        let identity = TaintCatalogIdentity::from_definition(&catalog);
        let wire = CatalogWire::from(&catalog);
        let canonical_value = serde_json::to_value(&wire)
            .map_err(|error| CatalogRegistryError::CanonicalSerialization(error.to_string()))?;
        let canonical_json = serde_json::to_vec(&canonical_value)
            .map_err(|error| CatalogRegistryError::CanonicalSerialization(error.to_string()))?;
        let semantic_hash = TaintCatalogHash::from_canonical_catalog_value(&canonical_value);

        if let Some(existing) = self.catalogs.get(&identity) {
            if existing.semantic_hash != semantic_hash {
                return Err(CatalogRegistryError::IdentityCollision {
                    identity,
                    existing: existing.semantic_hash,
                    incoming: semantic_hash,
                });
            }
            if existing.canonical_json.as_ref() != canonical_json.as_slice() {
                return Err(CatalogRegistryError::SemanticHashCollision {
                    identity,
                    hash: semantic_hash,
                });
            }
            return Ok(existing.semantic_hash);
        }

        let next_identities = self.catalogs.len().saturating_add(1);
        if next_identities > self.limits.max_identities {
            return Err(CatalogRegistryError::RegistryIdentityLimit {
                attempted: next_identities,
                maximum: self.limits.max_identities,
            });
        }
        let next_entries = self.retained_entries.saturating_add(catalog.entry_count());
        if next_entries > self.limits.max_entries {
            return Err(CatalogRegistryError::RegistryEntryLimit {
                attempted: next_entries,
                maximum: self.limits.max_entries,
            });
        }
        let next_bytes = self
            .retained_canonical_bytes
            .saturating_add(canonical_json.len());
        if next_bytes > self.limits.max_retained_canonical_bytes {
            return Err(CatalogRegistryError::RegistryCanonicalByteLimit {
                attempted: next_bytes,
                maximum: self.limits.max_retained_canonical_bytes,
            });
        }

        self.catalogs.insert(
            identity.clone(),
            RegisteredTaintCatalog {
                identity,
                semantic_hash,
                definition: catalog,
                canonical_json: canonical_json.into_boxed_slice(),
                source,
            },
        );
        self.retained_entries = next_entries;
        self.retained_canonical_bytes = next_bytes;
        Ok(semantic_hash)
    }
}

/// Reject duplicate object keys before Serde lowers nested query objects to
/// `serde_json::Value`, where duplicate spellings would otherwise be replaced
/// by the last value. The explicit depth check mirrors the catalog JSON hard
/// bound and keeps this recursive visitor stack-safe by construction.
fn validate_catalog_json_shape(
    source: &CatalogSourceIdentity,
    bytes: &[u8],
) -> Result<(), CatalogRegistryError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    StrictJsonSeed { depth: 0 }
        .deserialize(&mut deserializer)
        .and_then(|()| deserializer.end())
        .map_err(|error| CatalogRegistryError::InvalidJson {
            source: source.clone(),
            message: error.to_string(),
        })
}

#[derive(Debug, Clone, Copy)]
struct StrictJsonSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictJsonSeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor { depth: self.depth })
    }
}

struct StrictJsonVisitor {
    depth: usize,
}

impl StrictJsonVisitor {
    fn child_depth<E: de::Error>(&self) -> Result<usize, E> {
        if self.depth >= MAX_CATALOG_JSON_DEPTH {
            return Err(E::custom(format!(
                "catalog JSON nesting exceeds depth {MAX_CATALOG_JSON_DEPTH}"
            )));
        }
        Ok(self.depth + 1)
    }
}

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let depth = self.child_depth()?;
        while sequence
            .next_element_seed(StrictJsonSeed { depth })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let depth = self.child_depth()?;
        let mut keys = HashSet::new();
        while let Some(key) = object.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(format!(
                    "duplicate JSON object key `{key}`"
                )));
            }
            object.next_value_seed(StrictJsonSeed { depth })?;
        }
        Ok(())
    }
}

fn catalog_source_identity_from_path(
    path: &Path,
) -> Result<CatalogSourceIdentity, CatalogRegistryError> {
    let workspace_path = WorkspaceRelativePath::try_from_path(path).map_err(|source| {
        CatalogRegistryError::InvalidWorkspacePath {
            path: path.to_path_buf(),
            source,
        }
    })?;
    CatalogSourceIdentity::new(workspace_path.as_str())
        .map_err(|error| CatalogRegistryError::InvalidModel(error.to_string()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogRegistryError {
    WorkspaceRootMustBeAbsolute,
    WorkspaceAccessUnavailable,
    WorkspaceAccess {
        message: String,
    },
    InvalidWorkspacePath {
        path: PathBuf,
        source: WorkspaceRelativePathError,
    },
    JsonTooLarge {
        bytes: usize,
        maximum: usize,
    },
    InvalidJson {
        source: CatalogSourceIdentity,
        message: String,
    },
    UnsupportedSchemaVersion {
        found: u32,
    },
    ZeroVersion,
    EmptyCatalog,
    TooManyEntries {
        found: usize,
        maximum: usize,
    },
    TooManyEntriesOfKind {
        kind: CatalogEntryKind,
        found: usize,
        maximum: usize,
    },
    DuplicateEntryId {
        id: TaintEntryId,
    },
    InvalidEntry {
        kind: CatalogEntryKind,
        id: TaintEntryId,
        message: String,
    },
    InvalidSelector {
        id: TaintEntryId,
        message: String,
    },
    InvalidModel(String),
    CanonicalSerialization(String),
    IdentityCollision {
        identity: TaintCatalogIdentity,
        existing: TaintCatalogHash,
        incoming: TaintCatalogHash,
    },
    SemanticHashCollision {
        identity: TaintCatalogIdentity,
        hash: TaintCatalogHash,
    },
    RegistryIdentityLimit {
        attempted: usize,
        maximum: usize,
    },
    RegistryEntryLimit {
        attempted: usize,
        maximum: usize,
    },
    RegistryCanonicalByteLimit {
        attempted: usize,
        maximum: usize,
    },
    UnknownCatalog {
        identity: TaintCatalogIdentity,
    },
    HashPinMismatch {
        identity: TaintCatalogIdentity,
        expected: TaintCatalogHash,
        actual: TaintCatalogHash,
    },
}

impl fmt::Display for CatalogRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkspaceRootMustBeAbsolute => {
                formatter.write_str("catalog workspace root must be absolute")
            }
            Self::WorkspaceAccessUnavailable => {
                formatter.write_str("catalog registry has no workspace capability")
            }
            Self::WorkspaceAccess { message } => {
                write!(formatter, "catalog workspace access failed: {message}")
            }
            Self::InvalidWorkspacePath { path, source } => write!(
                formatter,
                "catalog path `{}` is not a portable workspace path: {source}",
                path.display()
            ),
            Self::JsonTooLarge { bytes, maximum } => write!(
                formatter,
                "catalog JSON is too large: {bytes} bytes exceeds {maximum}"
            ),
            Self::InvalidJson { source, message } => {
                write!(
                    formatter,
                    "invalid catalog JSON from {}: {message}",
                    source.as_str()
                )
            }
            Self::UnsupportedSchemaVersion { found } => write!(
                formatter,
                "unsupported catalog schema version {found}; expected {POLICY_DOCUMENT_SCHEMA_VERSION}"
            ),
            Self::ZeroVersion => formatter.write_str("catalog version must be at least 1"),
            Self::EmptyCatalog => formatter.write_str("catalog must contain at least one entry"),
            Self::TooManyEntries { found, maximum } => write!(
                formatter,
                "catalog contains {found} entries; at most {maximum} are allowed"
            ),
            Self::TooManyEntriesOfKind {
                kind,
                found,
                maximum,
            } => write!(
                formatter,
                "catalog contains {found} {kind} entries; at most {maximum} are allowed"
            ),
            Self::DuplicateEntryId { id } => write!(formatter, "duplicate catalog entry ID {id}"),
            Self::InvalidEntry { kind, id, message } => {
                write!(formatter, "invalid {kind} catalog entry {id}: {message}")
            }
            Self::InvalidSelector { id, message } => {
                write!(formatter, "invalid catalog selector for {id}: {message}")
            }
            Self::InvalidModel(message) => write!(formatter, "invalid catalog model: {message}"),
            Self::CanonicalSerialization(message) => {
                write!(
                    formatter,
                    "catalog canonical serialization failed: {message}"
                )
            }
            Self::IdentityCollision {
                identity,
                existing,
                incoming,
            } => write!(
                formatter,
                "catalog {} version {} is already registered with hash {existing}, not {incoming}",
                identity.name, identity.version
            ),
            Self::SemanticHashCollision { identity, hash } => write!(
                formatter,
                "catalog {} version {} produced hash collision {hash}",
                identity.name, identity.version
            ),
            Self::RegistryIdentityLimit { attempted, maximum } => write!(
                formatter,
                "catalog registry would contain {attempted} identities; limit is {maximum}"
            ),
            Self::RegistryEntryLimit { attempted, maximum } => write!(
                formatter,
                "catalog registry would retain {attempted} entries; limit is {maximum}"
            ),
            Self::RegistryCanonicalByteLimit { attempted, maximum } => write!(
                formatter,
                "catalog registry would retain {attempted} canonical bytes; limit is {maximum}"
            ),
            Self::UnknownCatalog { identity } => write!(
                formatter,
                "catalog {} version {} is not registered",
                identity.name, identity.version
            ),
            Self::HashPinMismatch {
                identity,
                expected,
                actual,
            } => write!(
                formatter,
                "catalog {} version {} hash pin {expected} does not match {actual}",
                identity.name, identity.version
            ),
        }
    }
}

impl std::error::Error for CatalogRegistryError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogEntryKind {
    Source,
    Sink,
    Sanitizer,
    Transform,
    ExternalModel,
}

impl fmt::Display for CatalogEntryKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Source => "source",
            Self::Sink => "sink",
            Self::Sanitizer => "sanitizer",
            Self::Transform => "transform",
            Self::ExternalModel => "external-model",
        })
    }
}

fn normalize_and_validate_catalog(
    mut catalog: TaintCatalogDefinition,
) -> Result<TaintCatalogDefinition, CatalogRegistryError> {
    if catalog.schema_version != POLICY_DOCUMENT_SCHEMA_VERSION {
        return Err(CatalogRegistryError::UnsupportedSchemaVersion {
            found: catalog.schema_version,
        });
    }
    if catalog.version == 0 {
        return Err(CatalogRegistryError::ZeroVersion);
    }
    let entry_count = catalog.entry_count();
    if entry_count == 0 {
        return Err(CatalogRegistryError::EmptyCatalog);
    }
    if entry_count > MAX_CATALOG_ENTRIES {
        return Err(CatalogRegistryError::TooManyEntries {
            found: entry_count,
            maximum: MAX_CATALOG_ENTRIES,
        });
    }
    for (kind, count) in [
        (CatalogEntryKind::Source, catalog.sources.len()),
        (CatalogEntryKind::Sink, catalog.sinks.len()),
        (CatalogEntryKind::Sanitizer, catalog.sanitizers.len()),
        (CatalogEntryKind::Transform, catalog.transforms.len()),
        (
            CatalogEntryKind::ExternalModel,
            catalog.external_models.len(),
        ),
    ] {
        if count > MAX_CATALOG_ENTRIES_PER_KIND {
            return Err(CatalogRegistryError::TooManyEntriesOfKind {
                kind,
                found: count,
                maximum: MAX_CATALOG_ENTRIES_PER_KIND,
            });
        }
    }

    let mut ids = HashSet::with_capacity(entry_count);
    for (kind, id) in catalog_entry_ids(&catalog) {
        if !ids.insert(id.clone()) {
            return Err(CatalogRegistryError::DuplicateEntryId { id: id.clone() });
        }
        let _ = kind;
    }

    for source in &mut catalog.sources {
        normalize_source(source)?;
    }
    for sink in &mut catalog.sinks {
        normalize_sink(sink)?;
    }
    for sanitizer in &mut catalog.sanitizers {
        normalize_sanitizer(sanitizer)?;
    }
    for transform in &mut catalog.transforms {
        normalize_transform(transform)?;
    }
    for model in &mut catalog.external_models {
        normalize_external_model(model)?;
    }

    catalog
        .sources
        .sort_by(|left, right| left.id.cmp(&right.id));
    catalog.sinks.sort_by(|left, right| left.id.cmp(&right.id));
    catalog
        .sanitizers
        .sort_by(|left, right| left.id.cmp(&right.id));
    catalog
        .transforms
        .sort_by(|left, right| left.id.cmp(&right.id));
    catalog
        .external_models
        .sort_by(|left, right| left.id.cmp(&right.id));
    Ok(catalog)
}

fn catalog_entry_ids(
    catalog: &TaintCatalogDefinition,
) -> impl Iterator<Item = (CatalogEntryKind, &TaintEntryId)> {
    catalog
        .sources
        .iter()
        .map(|entry| (CatalogEntryKind::Source, &entry.id))
        .chain(
            catalog
                .sinks
                .iter()
                .map(|entry| (CatalogEntryKind::Sink, &entry.id)),
        )
        .chain(
            catalog
                .sanitizers
                .iter()
                .map(|entry| (CatalogEntryKind::Sanitizer, &entry.id)),
        )
        .chain(
            catalog
                .transforms
                .iter()
                .map(|entry| (CatalogEntryKind::Transform, &entry.id)),
        )
        .chain(
            catalog
                .external_models
                .iter()
                .map(|entry| (CatalogEntryKind::ExternalModel, &entry.id)),
        )
}

fn normalize_source(source: &mut TaintSourceSpec) -> Result<(), CatalogRegistryError> {
    validate_selector(&source.id, &source.selector)?;
    validate_display_name(CatalogEntryKind::Source, &source.id, &source.display_name)?;
    normalize_nonempty_set(
        CatalogEntryKind::Source,
        &source.id,
        "categories",
        &mut source.categories,
    )?;
    validate_port(CatalogEntryKind::Source, &source.id, "bind", &source.bind)?;
    normalize_nonempty_set(
        CatalogEntryKind::Source,
        &source.id,
        "labels",
        &mut source.labels,
    )?;
    if let Some(evidence) = &source.evidence
        && evidence.trust_boundary.is_none()
        && evidence.system_entry.is_none()
    {
        return invalid_entry(
            CatalogEntryKind::Source,
            &source.id,
            "source evidence must set trust_boundary or system_entry",
        );
    }
    Ok(())
}

fn normalize_sink(sink: &mut TaintSinkSpec) -> Result<(), CatalogRegistryError> {
    validate_selector(&sink.id, &sink.selector)?;
    validate_display_name(CatalogEntryKind::Sink, &sink.id, &sink.display_name)?;
    normalize_nonempty_set(
        CatalogEntryKind::Sink,
        &sink.id,
        "categories",
        &mut sink.categories,
    )?;
    validate_port(
        CatalogEntryKind::Sink,
        &sink.id,
        "dangerous_operand",
        &sink.dangerous_operand,
    )?;
    normalize_nonempty_set(
        CatalogEntryKind::Sink,
        &sink.id,
        "accepts",
        &mut sink.accepts,
    )?;
    normalize_set(CatalogEntryKind::Sink, &sink.id, "tags", &mut sink.tags)?;
    normalize_set(
        CatalogEntryKind::Sink,
        &sink.id,
        "impacts",
        &mut sink.impacts,
    )?;
    Ok(())
}

fn normalize_sanitizer(sanitizer: &mut TaintSanitizerSpec) -> Result<(), CatalogRegistryError> {
    validate_selector(&sanitizer.id, &sanitizer.selector)?;
    validate_port(
        CatalogEntryKind::Sanitizer,
        &sanitizer.id,
        "input",
        &sanitizer.input,
    )?;
    validate_port(
        CatalogEntryKind::Sanitizer,
        &sanitizer.id,
        "output",
        &sanitizer.output,
    )?;
    normalize_nonempty_set(
        CatalogEntryKind::Sanitizer,
        &sanitizer.id,
        "removes",
        &mut sanitizer.removes,
    )
}

fn normalize_transform(transform: &mut TaintTransformSpec) -> Result<(), CatalogRegistryError> {
    validate_selector(&transform.id, &transform.selector)?;
    validate_port(
        CatalogEntryKind::Transform,
        &transform.id,
        "input",
        &transform.input,
    )?;
    validate_port(
        CatalogEntryKind::Transform,
        &transform.id,
        "output",
        &transform.output,
    )?;
    normalize_set(
        CatalogEntryKind::Transform,
        &transform.id,
        "removes",
        &mut transform.removes,
    )?;
    normalize_set(
        CatalogEntryKind::Transform,
        &transform.id,
        "adds",
        &mut transform.adds,
    )?;
    if transform.removes.is_empty() && transform.adds.is_empty() {
        return invalid_entry(
            CatalogEntryKind::Transform,
            &transform.id,
            "transform must remove or add at least one label",
        );
    }
    Ok(())
}

fn normalize_external_model(
    model: &mut TaintExternalModelSpec,
) -> Result<(), CatalogRegistryError> {
    validate_selector(&model.id, &model.selector)?;
    if model.transfers.is_empty() {
        return invalid_entry(
            CatalogEntryKind::ExternalModel,
            &model.id,
            "external model must contain at least one transfer",
        );
    }
    if model.transfers.len() > MAX_EXTERNAL_MODEL_TRANSFERS {
        return invalid_entry(
            CatalogEntryKind::ExternalModel,
            &model.id,
            format!(
                "external model has {} transfers; at most {MAX_EXTERNAL_MODEL_TRANSFERS} are allowed",
                model.transfers.len()
            ),
        );
    }
    for transfer in &mut model.transfers {
        validate_port(
            CatalogEntryKind::ExternalModel,
            &model.id,
            "transfer from",
            &transfer.from,
        )?;
        validate_port(
            CatalogEntryKind::ExternalModel,
            &model.id,
            "transfer to",
            &transfer.to,
        )?;
        if matches!(transfer.from, PolicyPort::MatchedValue)
            || matches!(transfer.to, PolicyPort::MatchedValue)
        {
            return invalid_entry(
                CatalogEntryKind::ExternalModel,
                &model.id,
                "external-model transfers cannot use matched_value",
            );
        }
        normalize_nonempty_set(
            CatalogEntryKind::ExternalModel,
            &model.id,
            "transfer labels",
            &mut transfer.labels,
        )?;
        match &mut transfer.effect {
            TaintTransferEffect::Propagate => {}
            TaintTransferEffect::Sanitize { removes } => normalize_nonempty_set(
                CatalogEntryKind::ExternalModel,
                &model.id,
                "transfer removes",
                removes,
            )?,
            TaintTransferEffect::Transform { removes, adds } => {
                normalize_set(
                    CatalogEntryKind::ExternalModel,
                    &model.id,
                    "transfer removes",
                    removes,
                )?;
                normalize_set(
                    CatalogEntryKind::ExternalModel,
                    &model.id,
                    "transfer adds",
                    adds,
                )?;
                if removes.is_empty() && adds.is_empty() {
                    return invalid_entry(
                        CatalogEntryKind::ExternalModel,
                        &model.id,
                        "transform transfer must remove or add at least one label",
                    );
                }
            }
        }
    }
    for index in 0..model.transfers.len() {
        if model.transfers[..index].contains(&model.transfers[index]) {
            return invalid_entry(
                CatalogEntryKind::ExternalModel,
                &model.id,
                "duplicate transfer",
            );
        }
    }
    model.transfers.sort_by_key(canonical_transfer_sort_key);
    Ok(())
}

fn canonical_transfer_sort_key(transfer: &TaintTransferSpec) -> Vec<u8> {
    serde_json::to_vec(&TransferWire::from(transfer))
        .expect("catalog transfer canonical JSON is infallible")
}

fn validate_selector(
    id: &TaintEntryId,
    selector: &PolicySelector,
) -> Result<(), CatalogRegistryError> {
    let PolicySelector::Inline { schema, query } = selector else {
        return Err(CatalogRegistryError::InvalidSelector {
            id: id.clone(),
            message: "catalog selectors must be inline".to_string(),
        });
    };
    if schema.version != RQL_SCHEMA_VERSION as u32
        || schema.origin != SchemaVersionOrigin::Explicit
        || query.schema_version != RQL_SCHEMA_VERSION
    {
        return Err(CatalogRegistryError::InvalidSelector {
            id: id.clone(),
            message: format!("catalog selector must use RQL schema version {RQL_SCHEMA_VERSION}"),
        });
    }
    if query.limit != DEFAULT_LIMIT || query.result_detail != CodeQueryResultDetail::Compact {
        return Err(CatalogRegistryError::InvalidSelector {
            id: id.clone(),
            message: "catalog selectors cannot carry query output controls".to_string(),
        });
    }
    query
        .validate_steps()
        .map_err(|error| CatalogRegistryError::InvalidSelector {
            id: id.clone(),
            message: error.to_string(),
        })?;
    Ok(())
}

fn validate_port(
    kind: CatalogEntryKind,
    id: &TaintEntryId,
    field: &str,
    port: &PolicyPort,
) -> Result<(), CatalogRegistryError> {
    let PolicyPort::ArgumentName { name } = port else {
        return Ok(());
    };
    validate_catalog_author_text(kind, id, &format!("{field} argument name"), name)
}

fn validate_display_name(
    kind: CatalogEntryKind,
    id: &TaintEntryId,
    value: &str,
) -> Result<(), CatalogRegistryError> {
    validate_catalog_author_text(kind, id, "display_name", value)
}

fn validate_catalog_author_text(
    kind: CatalogEntryKind,
    id: &TaintEntryId,
    field: &str,
    value: &str,
) -> Result<(), CatalogRegistryError> {
    validate_required_text(value, MAX_POLICY_DISPLAY_TEXT_BYTES).map_err(|error| {
        CatalogRegistryError::InvalidEntry {
            kind,
            id: id.clone(),
            message: match error {
                TextValidationError::Empty => format!("{field} must not be empty"),
                TextValidationError::TooLong { max_bytes } => {
                    format!("{field} must be at most {max_bytes} bytes")
                }
                TextValidationError::UnsafeCharacter => {
                    format!("{field} must not contain control or bidirectional-control characters")
                }
                TextValidationError::InvalidIdentifier => {
                    unreachable!("author-text validation cannot return {error}")
                }
            },
        }
    })
}

fn normalize_nonempty_set<T: Ord>(
    kind: CatalogEntryKind,
    id: &TaintEntryId,
    field: &str,
    values: &mut [T],
) -> Result<(), CatalogRegistryError> {
    if values.is_empty() {
        return invalid_entry(kind, id, format!("{field} must not be empty"));
    }
    normalize_set(kind, id, field, values)
}

fn normalize_set<T: Ord>(
    kind: CatalogEntryKind,
    id: &TaintEntryId,
    field: &str,
    values: &mut [T],
) -> Result<(), CatalogRegistryError> {
    if values.len() > MAX_POLICY_SET_ITEMS {
        return invalid_entry(
            kind,
            id,
            format!(
                "{field} contains {} values; at most {MAX_POLICY_SET_ITEMS} are allowed",
                values.len()
            ),
        );
    }
    values.sort();
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return invalid_entry(kind, id, format!("{field} contains a duplicate value"));
    }
    Ok(())
}

fn invalid_entry<T>(
    kind: CatalogEntryKind,
    id: &TaintEntryId,
    message: impl Into<String>,
) -> Result<T, CatalogRegistryError> {
    Err(CatalogRegistryError::InvalidEntry {
        kind,
        id: id.clone(),
        message: message.into(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogWire {
    schema_version: u32,
    name: String,
    version: u32,
    sources: Vec<SourceWire>,
    sinks: Vec<SinkWire>,
    sanitizers: Vec<SanitizerWire>,
    transforms: Vec<TransformWire>,
    external_models: Vec<ExternalModelWire>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectorWire {
    #[serde(rename = "type")]
    kind: String,
    schema_version: u32,
    query: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceWire {
    id: String,
    display_name: String,
    categories: Vec<String>,
    selector: SelectorWire,
    bind: PortWire,
    labels: Vec<String>,
    evidence: Option<SourceEvidenceWire>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SinkWire {
    id: String,
    display_name: String,
    categories: Vec<String>,
    selector: SelectorWire,
    dangerous_operand: PortWire,
    accepts: Vec<String>,
    tags: Vec<String>,
    impacts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SanitizerWire {
    id: String,
    selector: SelectorWire,
    input: PortWire,
    output: PortWire,
    removes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransformWire {
    id: String,
    selector: SelectorWire,
    input: PortWire,
    output: PortWire,
    removes: Vec<String>,
    adds: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalModelWire {
    id: String,
    selector: SelectorWire,
    transfers: Vec<TransferWire>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferWire {
    from: PortWire,
    to: PortWire,
    labels: Vec<String>,
    effect: TransferEffectWire,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum TransferEffectWire {
    Propagate,
    Sanitize {
        removes: Vec<String>,
    },
    Transform {
        removes: Vec<String>,
        adds: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum PortWire {
    MatchedValue,
    Receiver,
    ReturnValue,
    ArgumentIndex { index: u32 },
    ArgumentName { name: String },
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TransferEffectKindWire {
    Propagate,
    Sanitize,
    Transform,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TaggedTransferEffectWire {
    #[serde(rename = "type")]
    kind: TransferEffectKindWire,
    #[serde(default)]
    removes: OptionalWireField<Vec<String>>,
    #[serde(default)]
    adds: OptionalWireField<Vec<String>>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PortKindWire {
    MatchedValue,
    Receiver,
    ReturnValue,
    ArgumentIndex,
    ArgumentName,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TaggedPortWire {
    #[serde(rename = "type")]
    kind: PortKindWire,
    #[serde(default)]
    index: OptionalWireField<u32>,
    #[serde(default)]
    name: OptionalWireField<String>,
}

#[derive(Debug, Clone, Default)]
enum OptionalWireField<T> {
    #[default]
    Missing,
    Present(T),
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for OptionalWireField<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        T::deserialize(deserializer).map(Self::Present)
    }
}

impl<'de> Deserialize<'de> for PortWire {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        let tagged = TaggedPortWire::deserialize(deserializer)?;
        let invalid_shape = || D::Error::custom("port fields do not match its type");
        match (tagged.kind, tagged.index, tagged.name) {
            (
                PortKindWire::MatchedValue,
                OptionalWireField::Missing,
                OptionalWireField::Missing,
            ) => Ok(Self::MatchedValue),
            (PortKindWire::Receiver, OptionalWireField::Missing, OptionalWireField::Missing) => {
                Ok(Self::Receiver)
            }
            (PortKindWire::ReturnValue, OptionalWireField::Missing, OptionalWireField::Missing) => {
                Ok(Self::ReturnValue)
            }
            (
                PortKindWire::ArgumentIndex,
                OptionalWireField::Present(index),
                OptionalWireField::Missing,
            ) => Ok(Self::ArgumentIndex { index }),
            (
                PortKindWire::ArgumentName,
                OptionalWireField::Missing,
                OptionalWireField::Present(name),
            ) => Ok(Self::ArgumentName { name }),
            _ => Err(invalid_shape()),
        }
    }
}

impl<'de> Deserialize<'de> for TransferEffectWire {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        let tagged = TaggedTransferEffectWire::deserialize(deserializer)?;
        let invalid_shape = || D::Error::custom("transfer-effect fields do not match its type");
        match (tagged.kind, tagged.removes, tagged.adds) {
            (
                TransferEffectKindWire::Propagate,
                OptionalWireField::Missing,
                OptionalWireField::Missing,
            ) => Ok(Self::Propagate),
            (
                TransferEffectKindWire::Sanitize,
                OptionalWireField::Present(removes),
                OptionalWireField::Missing,
            ) => Ok(Self::Sanitize { removes }),
            (
                TransferEffectKindWire::Transform,
                OptionalWireField::Present(removes),
                OptionalWireField::Present(adds),
            ) => Ok(Self::Transform { removes, adds }),
            _ => Err(invalid_shape()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceEvidenceWire {
    trust_boundary: Option<TrustBoundaryWire>,
    system_entry: Option<SystemEntryWire>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TrustBoundaryWire {
    External,
    Internal,
    SameTrustZone,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SystemEntryWire {
    VulnerableSystemNetworkStack,
    DownloadedArtifact,
    LocalInput,
    AdjacentNetwork,
    Physical,
}

impl TryFrom<CatalogWire> for TaintCatalogDefinition {
    type Error = CatalogRegistryError;

    fn try_from(wire: CatalogWire) -> Result<Self, Self::Error> {
        Ok(Self {
            schema_version: wire.schema_version,
            name: PolicyId::new(wire.name).map_err(invalid_wire_identifier("catalog name"))?,
            version: wire.version,
            sources: wire
                .sources
                .into_iter()
                .map(TaintSourceSpec::try_from)
                .collect::<Result<_, _>>()?,
            sinks: wire
                .sinks
                .into_iter()
                .map(TaintSinkSpec::try_from)
                .collect::<Result<_, _>>()?,
            sanitizers: wire
                .sanitizers
                .into_iter()
                .map(TaintSanitizerSpec::try_from)
                .collect::<Result<_, _>>()?,
            transforms: wire
                .transforms
                .into_iter()
                .map(TaintTransformSpec::try_from)
                .collect::<Result<_, _>>()?,
            external_models: wire
                .external_models
                .into_iter()
                .map(TaintExternalModelSpec::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}

fn invalid_wire_identifier(
    field: &'static str,
) -> impl FnOnce(super::definition::PolicyIdentifierError) -> CatalogRegistryError {
    move |error| CatalogRegistryError::InvalidModel(format!("invalid {field}: {error}"))
}

impl From<&TaintCatalogDefinition> for CatalogWire {
    fn from(definition: &TaintCatalogDefinition) -> Self {
        Self {
            schema_version: definition.schema_version,
            name: definition.name.as_str().to_string(),
            version: definition.version,
            sources: definition.sources.iter().map(SourceWire::from).collect(),
            sinks: definition.sinks.iter().map(SinkWire::from).collect(),
            sanitizers: definition
                .sanitizers
                .iter()
                .map(SanitizerWire::from)
                .collect(),
            transforms: definition
                .transforms
                .iter()
                .map(TransformWire::from)
                .collect(),
            external_models: definition
                .external_models
                .iter()
                .map(ExternalModelWire::from)
                .collect(),
        }
    }
}

fn decode_selector(
    id: &TaintEntryId,
    wire: SelectorWire,
) -> Result<PolicySelector, CatalogRegistryError> {
    if wire.kind != "inline" {
        return Err(CatalogRegistryError::InvalidSelector {
            id: id.clone(),
            message: "selector type must be inline".to_string(),
        });
    }
    if wire.schema_version != RQL_SCHEMA_VERSION as u32 {
        return Err(CatalogRegistryError::InvalidSelector {
            id: id.clone(),
            message: format!("selector schema_version must be {RQL_SCHEMA_VERSION}"),
        });
    }
    let query_object =
        wire.query
            .as_object()
            .ok_or_else(|| CatalogRegistryError::InvalidSelector {
                id: id.clone(),
                message: "selector query must be an object".to_string(),
            })?;
    if query_object.get("schema_version").and_then(Value::as_u64)
        != Some(u64::from(wire.schema_version))
    {
        return Err(CatalogRegistryError::InvalidSelector {
            id: id.clone(),
            message: "selector query must repeat the exact schema_version pin".to_string(),
        });
    }
    if query_object.contains_key("limit") || query_object.contains_key("result_detail") {
        return Err(CatalogRegistryError::InvalidSelector {
            id: id.clone(),
            message: "selector query cannot contain limit or result_detail".to_string(),
        });
    }
    let query = CodeQuery::from_json(&wire.query).map_err(|error| {
        CatalogRegistryError::InvalidSelector {
            id: id.clone(),
            message: error.to_string(),
        }
    })?;
    Ok(PolicySelector::Inline {
        schema: crate::schema_version::SchemaVersionResolution {
            version: wire.schema_version,
            origin: crate::schema_version::SchemaVersionOrigin::Explicit,
        },
        query,
    })
}

fn encode_selector(selector: &PolicySelector) -> SelectorWire {
    let PolicySelector::Inline { schema, query } = selector else {
        unreachable!("catalog validation rejects file selectors")
    };
    SelectorWire {
        kind: "inline".to_string(),
        schema_version: schema.version,
        query: query.to_canonical_query_plan_json(),
    }
}

impl TryFrom<SourceWire> for TaintSourceSpec {
    type Error = CatalogRegistryError;

    fn try_from(wire: SourceWire) -> Result<Self, Self::Error> {
        let id = TaintEntryId::new(wire.id).map_err(invalid_wire_identifier("source ID"))?;
        Ok(Self {
            selector: decode_selector(&id, wire.selector)?,
            id,
            display_name: wire.display_name,
            categories: parse_ids(wire.categories, PolicyCategoryId::new, "source category")?,
            bind: wire.bind.into(),
            labels: parse_ids(wire.labels, TaintLabel::new, "source label")?,
            evidence: wire.evidence.map(Into::into),
        })
    }
}

impl From<&TaintSourceSpec> for SourceWire {
    fn from(spec: &TaintSourceSpec) -> Self {
        Self {
            id: spec.id.as_str().to_string(),
            display_name: spec.display_name.clone(),
            categories: display_ids(&spec.categories),
            selector: encode_selector(&spec.selector),
            bind: PortWire::from(&spec.bind),
            labels: display_ids(&spec.labels),
            evidence: spec.evidence.as_ref().map(SourceEvidenceWire::from),
        }
    }
}

impl TryFrom<SinkWire> for TaintSinkSpec {
    type Error = CatalogRegistryError;

    fn try_from(wire: SinkWire) -> Result<Self, Self::Error> {
        let id = TaintEntryId::new(wire.id).map_err(invalid_wire_identifier("sink ID"))?;
        Ok(Self {
            selector: decode_selector(&id, wire.selector)?,
            id,
            display_name: wire.display_name,
            categories: parse_ids(wire.categories, PolicyCategoryId::new, "sink category")?,
            dangerous_operand: wire.dangerous_operand.into(),
            accepts: parse_ids(wire.accepts, TaintLabel::new, "sink accepted label")?,
            tags: parse_ids(wire.tags, TaintTag::new, "sink tag")?,
            impacts: parse_ids(wire.impacts, TaintImpact::new, "sink impact")?,
        })
    }
}

impl From<&TaintSinkSpec> for SinkWire {
    fn from(spec: &TaintSinkSpec) -> Self {
        Self {
            id: spec.id.as_str().to_string(),
            display_name: spec.display_name.clone(),
            categories: display_ids(&spec.categories),
            selector: encode_selector(&spec.selector),
            dangerous_operand: PortWire::from(&spec.dangerous_operand),
            accepts: display_ids(&spec.accepts),
            tags: display_ids(&spec.tags),
            impacts: display_ids(&spec.impacts),
        }
    }
}

impl TryFrom<SanitizerWire> for TaintSanitizerSpec {
    type Error = CatalogRegistryError;

    fn try_from(wire: SanitizerWire) -> Result<Self, Self::Error> {
        let id = TaintEntryId::new(wire.id).map_err(invalid_wire_identifier("sanitizer ID"))?;
        Ok(Self {
            selector: decode_selector(&id, wire.selector)?,
            id,
            input: wire.input.into(),
            output: wire.output.into(),
            removes: parse_ids(wire.removes, TaintLabel::new, "sanitizer label")?,
        })
    }
}

impl From<&TaintSanitizerSpec> for SanitizerWire {
    fn from(spec: &TaintSanitizerSpec) -> Self {
        Self {
            id: spec.id.as_str().to_string(),
            selector: encode_selector(&spec.selector),
            input: PortWire::from(&spec.input),
            output: PortWire::from(&spec.output),
            removes: display_ids(&spec.removes),
        }
    }
}

impl TryFrom<TransformWire> for TaintTransformSpec {
    type Error = CatalogRegistryError;

    fn try_from(wire: TransformWire) -> Result<Self, Self::Error> {
        let id = TaintEntryId::new(wire.id).map_err(invalid_wire_identifier("transform ID"))?;
        Ok(Self {
            selector: decode_selector(&id, wire.selector)?,
            id,
            input: wire.input.into(),
            output: wire.output.into(),
            removes: parse_ids(wire.removes, TaintLabel::new, "transform removed label")?,
            adds: parse_ids(wire.adds, TaintLabel::new, "transform added label")?,
        })
    }
}

impl From<&TaintTransformSpec> for TransformWire {
    fn from(spec: &TaintTransformSpec) -> Self {
        Self {
            id: spec.id.as_str().to_string(),
            selector: encode_selector(&spec.selector),
            input: PortWire::from(&spec.input),
            output: PortWire::from(&spec.output),
            removes: display_ids(&spec.removes),
            adds: display_ids(&spec.adds),
        }
    }
}

impl TryFrom<ExternalModelWire> for TaintExternalModelSpec {
    type Error = CatalogRegistryError;

    fn try_from(wire: ExternalModelWire) -> Result<Self, Self::Error> {
        let id =
            TaintEntryId::new(wire.id).map_err(invalid_wire_identifier("external-model ID"))?;
        Ok(Self {
            selector: decode_selector(&id, wire.selector)?,
            id,
            transfers: wire
                .transfers
                .into_iter()
                .map(TaintTransferSpec::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}

impl From<&TaintExternalModelSpec> for ExternalModelWire {
    fn from(spec: &TaintExternalModelSpec) -> Self {
        Self {
            id: spec.id.as_str().to_string(),
            selector: encode_selector(&spec.selector),
            transfers: spec.transfers.iter().map(TransferWire::from).collect(),
        }
    }
}

impl TryFrom<TransferWire> for TaintTransferSpec {
    type Error = CatalogRegistryError;

    fn try_from(wire: TransferWire) -> Result<Self, Self::Error> {
        Ok(Self {
            from: wire.from.into(),
            to: wire.to.into(),
            labels: parse_ids(wire.labels, TaintLabel::new, "transfer label")?,
            effect: TaintTransferEffect::try_from(wire.effect)?,
        })
    }
}

impl From<&TaintTransferSpec> for TransferWire {
    fn from(spec: &TaintTransferSpec) -> Self {
        Self {
            from: PortWire::from(&spec.from),
            to: PortWire::from(&spec.to),
            labels: display_ids(&spec.labels),
            effect: TransferEffectWire::from(&spec.effect),
        }
    }
}

impl TryFrom<TransferEffectWire> for TaintTransferEffect {
    type Error = CatalogRegistryError;

    fn try_from(wire: TransferEffectWire) -> Result<Self, Self::Error> {
        Ok(match wire {
            TransferEffectWire::Propagate => Self::Propagate,
            TransferEffectWire::Sanitize { removes } => Self::Sanitize {
                removes: parse_ids(removes, TaintLabel::new, "transfer removed label")?,
            },
            TransferEffectWire::Transform { removes, adds } => Self::Transform {
                removes: parse_ids(removes, TaintLabel::new, "transfer removed label")?,
                adds: parse_ids(adds, TaintLabel::new, "transfer added label")?,
            },
        })
    }
}

impl From<&TaintTransferEffect> for TransferEffectWire {
    fn from(effect: &TaintTransferEffect) -> Self {
        match effect {
            TaintTransferEffect::Propagate => Self::Propagate,
            TaintTransferEffect::Sanitize { removes } => Self::Sanitize {
                removes: display_ids(removes),
            },
            TaintTransferEffect::Transform { removes, adds } => Self::Transform {
                removes: display_ids(removes),
                adds: display_ids(adds),
            },
        }
    }
}

impl From<PortWire> for PolicyPort {
    fn from(port: PortWire) -> Self {
        match port {
            PortWire::MatchedValue => Self::MatchedValue,
            PortWire::Receiver => Self::Receiver,
            PortWire::ReturnValue => Self::ReturnValue,
            PortWire::ArgumentIndex { index } => Self::ArgumentIndex { index },
            PortWire::ArgumentName { name } => Self::ArgumentName { name },
        }
    }
}

impl From<&PolicyPort> for PortWire {
    fn from(port: &PolicyPort) -> Self {
        match port {
            PolicyPort::MatchedValue => Self::MatchedValue,
            PolicyPort::Receiver => Self::Receiver,
            PolicyPort::ReturnValue => Self::ReturnValue,
            PolicyPort::ArgumentIndex { index } => Self::ArgumentIndex { index: *index },
            PolicyPort::ArgumentName { name } => Self::ArgumentName { name: name.clone() },
        }
    }
}

impl From<SourceEvidenceWire> for TaintSourceEvidence {
    fn from(evidence: SourceEvidenceWire) -> Self {
        Self {
            trust_boundary: evidence.trust_boundary.map(Into::into),
            system_entry: evidence.system_entry.map(Into::into),
        }
    }
}

impl From<&TaintSourceEvidence> for SourceEvidenceWire {
    fn from(evidence: &TaintSourceEvidence) -> Self {
        Self {
            trust_boundary: evidence.trust_boundary.map(Into::into),
            system_entry: evidence.system_entry.map(Into::into),
        }
    }
}

impl From<TrustBoundaryWire> for TaintTrustBoundary {
    fn from(value: TrustBoundaryWire) -> Self {
        match value {
            TrustBoundaryWire::External => Self::External,
            TrustBoundaryWire::Internal => Self::Internal,
            TrustBoundaryWire::SameTrustZone => Self::SameTrustZone,
        }
    }
}

impl From<TaintTrustBoundary> for TrustBoundaryWire {
    fn from(value: TaintTrustBoundary) -> Self {
        match value {
            TaintTrustBoundary::External => Self::External,
            TaintTrustBoundary::Internal => Self::Internal,
            TaintTrustBoundary::SameTrustZone => Self::SameTrustZone,
        }
    }
}

impl From<SystemEntryWire> for TaintSystemEntry {
    fn from(value: SystemEntryWire) -> Self {
        match value {
            SystemEntryWire::VulnerableSystemNetworkStack => Self::VulnerableSystemNetworkStack,
            SystemEntryWire::DownloadedArtifact => Self::DownloadedArtifact,
            SystemEntryWire::LocalInput => Self::LocalInput,
            SystemEntryWire::AdjacentNetwork => Self::AdjacentNetwork,
            SystemEntryWire::Physical => Self::Physical,
        }
    }
}

impl From<TaintSystemEntry> for SystemEntryWire {
    fn from(value: TaintSystemEntry) -> Self {
        match value {
            TaintSystemEntry::VulnerableSystemNetworkStack => Self::VulnerableSystemNetworkStack,
            TaintSystemEntry::DownloadedArtifact => Self::DownloadedArtifact,
            TaintSystemEntry::LocalInput => Self::LocalInput,
            TaintSystemEntry::AdjacentNetwork => Self::AdjacentNetwork,
            TaintSystemEntry::Physical => Self::Physical,
        }
    }
}

fn parse_ids<T, E>(
    values: Vec<String>,
    parse: impl Fn(String) -> Result<T, E>,
    field: &'static str,
) -> Result<Vec<T>, CatalogRegistryError>
where
    E: fmt::Display,
{
    values
        .into_iter()
        .map(|value| {
            parse(value).map_err(|error| {
                CatalogRegistryError::InvalidModel(format!("invalid {field}: {error}"))
            })
        })
        .collect()
}

fn display_ids<T: AsRef<str>>(values: &[T]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.as_ref().to_string())
        .collect()
}

// Keep these conversions local so catalog registration can validate forged
// binding values without widening definition.rs's authoring-only surface.
pub(crate) fn endpoint_binding_to_port(binding: &PolicyEndpointBinding) -> PolicyPort {
    match binding {
        PolicyEndpointBinding::MatchedValue => PolicyPort::MatchedValue,
        PolicyEndpointBinding::Receiver => PolicyPort::Receiver,
        PolicyEndpointBinding::ReturnValue => PolicyPort::ReturnValue,
        PolicyEndpointBinding::ArgumentIndex { index } => {
            PolicyPort::ArgumentIndex { index: *index }
        }
        PolicyEndpointBinding::ArgumentName { name } => {
            PolicyPort::ArgumentName { name: name.clone() }
        }
    }
}

pub(crate) fn typestate_seed_binding_to_port(binding: &TypestateSeedBinding) -> PolicyPort {
    match binding {
        TypestateSeedBinding::MatchedValue => PolicyPort::MatchedValue,
        TypestateSeedBinding::Receiver => PolicyPort::Receiver,
        TypestateSeedBinding::ReturnValue => PolicyPort::ReturnValue,
        TypestateSeedBinding::ArgumentIndex { index } => {
            PolicyPort::ArgumentIndex { index: *index }
        }
        TypestateSeedBinding::ArgumentName { name } => {
            PolicyPort::ArgumentName { name: name.clone() }
        }
    }
}

pub(crate) fn typestate_call_binding_to_port(binding: &TypestateCallBinding) -> PolicyPort {
    match binding {
        TypestateCallBinding::Receiver => PolicyPort::Receiver,
        TypestateCallBinding::ReturnValue => PolicyPort::ReturnValue,
        TypestateCallBinding::ArgumentIndex { index } => {
            PolicyPort::ArgumentIndex { index: *index }
        }
        TypestateCallBinding::ArgumentName { name } => {
            PolicyPort::ArgumentName { name: name.clone() }
        }
    }
}

pub(crate) fn phase_accepts_port(phase: EndpointObservationPhase, port: &PolicyPort) -> bool {
    match port {
        PolicyPort::MatchedValue => phase == EndpointObservationPhase::AtMatch,
        PolicyPort::ReturnValue => phase == EndpointObservationPhase::AfterNormalReturn,
        PolicyPort::Receiver
        | PolicyPort::ArgumentIndex { .. }
        | PolicyPort::ArgumentName { .. } => {
            matches!(
                phase,
                EndpointObservationPhase::BeforeCall
                    | EndpointObservationPhase::AfterNormalReturn
                    | EndpointObservationPhase::AfterExceptionalReturn
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::structural::CodeQuery;
    use crate::schema_version::{SchemaVersionOrigin, SchemaVersionResolution};

    fn selector(name: &str) -> PolicySelector {
        PolicySelector::Inline {
            schema: SchemaVersionResolution {
                version: 2,
                origin: SchemaVersionOrigin::Explicit,
            },
            query: CodeQuery::from_sexp(&format!(r#"(call :callee (name "{name}"))"#)).unwrap(),
        }
    }

    fn source(id: &str, name: &str) -> TaintSourceSpec {
        TaintSourceSpec {
            id: TaintEntryId::new(id).unwrap(),
            display_name: name.to_string(),
            categories: vec![PolicyCategoryId::new("input.user").unwrap()],
            selector: selector(name),
            bind: PolicyPort::ReturnValue,
            labels: vec![TaintLabel::new("attacker-controlled").unwrap()],
            evidence: None,
        }
    }

    fn catalog(name: &str, source_id: &str, display: &str) -> TaintCatalogDefinition {
        TaintCatalogDefinition {
            schema_version: 1,
            name: PolicyId::new(name).unwrap(),
            version: 1,
            sources: vec![source(source_id, display)],
            sinks: vec![],
            sanitizers: vec![],
            transforms: vec![],
            external_models: vec![],
        }
    }

    #[test]
    fn typed_registration_is_canonical_idempotent_and_pin_checked() {
        let mut registry = TaintCatalogRegistry::new_without_workspace(Default::default());
        let hash = registry
            .register(catalog("bifrost.sources", "request", "request"))
            .unwrap();
        let repeated = registry
            .register(catalog("bifrost.sources", "request", "request"))
            .unwrap();
        assert_eq!(hash, repeated);
        assert_eq!(registry.len(), 1);

        let resolved = registry
            .resolve(
                &CatalogRef::new(PolicyId::new("bifrost.sources").unwrap(), 1, Some(hash)).unwrap(),
            )
            .unwrap();
        assert_eq!(resolved.semantic_hash(), hash);

        let wrong = TaintCatalogHash::from_bytes([7; 32]);
        let error = registry
            .resolve(
                &CatalogRef::new(PolicyId::new("bifrost.sources").unwrap(), 1, Some(wrong))
                    .unwrap(),
            )
            .unwrap_err();
        assert!(matches!(
            error,
            CatalogRegistryError::HashPinMismatch { .. }
        ));
    }

    #[test]
    fn registration_rejects_identity_collision_transactionally() {
        let mut registry = TaintCatalogRegistry::new_without_workspace(Default::default());
        let original = registry
            .register(catalog("bifrost.sources", "request", "request"))
            .unwrap();
        let error = registry
            .register(catalog("bifrost.sources", "request", "changed"))
            .unwrap_err();
        assert!(matches!(
            error,
            CatalogRegistryError::IdentityCollision { .. }
        ));
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.iter().next().unwrap().semantic_hash(), original);
    }

    #[test]
    fn typed_registration_rejects_bidi_controls_in_catalog_author_text() {
        for character in ['\u{202e}', '\u{2066}'] {
            let mut definition = catalog("bifrost.sources", "request", "request");
            definition.sources[0].display_name = format!("request{character}name");
            let error = TaintCatalogRegistry::new_without_workspace(Default::default())
                .register(definition)
                .unwrap_err();
            assert!(matches!(
                error,
                CatalogRegistryError::InvalidEntry { message, .. }
                    if message == "display_name must not contain control or bidirectional-control characters"
            ));

            let mut definition = catalog("bifrost.sources", "request", "request");
            definition.sources[0].bind = PolicyPort::ArgumentName {
                name: format!("value{character}name"),
            };
            let error = TaintCatalogRegistry::new_without_workspace(Default::default())
                .register(definition)
                .unwrap_err();
            assert!(matches!(
                error,
                CatalogRegistryError::InvalidEntry { message, .. }
                    if message == "bind argument name must not contain control or bidirectional-control characters"
            ));
        }
    }

    #[test]
    fn json_registration_hashes_typed_canonical_content_not_layout() {
        let definition =
            normalize_and_validate_catalog(catalog("bifrost.sources", "request", "request"))
                .unwrap();
        let compact = serde_json::to_vec(&CatalogWire::from(&definition)).unwrap();
        let pretty = serde_json::to_vec_pretty(&CatalogWire::from(&definition)).unwrap();
        let source = CatalogSourceIdentity::new("test").unwrap();

        let mut left = TaintCatalogRegistry::new_without_workspace(Default::default());
        let mut right = TaintCatalogRegistry::new_without_workspace(Default::default());
        let left_hash = left.register_json_bytes(source.clone(), &compact).unwrap();
        let right_hash = right.register_json_bytes(source, &pretty).unwrap();
        assert_eq!(left_hash, right_hash);
    }

    #[test]
    fn json_registration_rejects_bidi_controls_in_catalog_author_text() {
        let definition =
            normalize_and_validate_catalog(catalog("bifrost.sources", "request", "request"))
                .unwrap();

        for character in ['\u{202e}', '\u{2066}'] {
            let mut value = serde_json::to_value(CatalogWire::from(&definition)).unwrap();
            value["sources"][0]["display_name"] = Value::String(format!("request{character}name"));
            let bytes = serde_json::to_vec(&value).unwrap();
            let error = TaintCatalogRegistry::new_without_workspace(Default::default())
                .register_json_bytes(CatalogSourceIdentity::new("test").unwrap(), &bytes)
                .unwrap_err();
            assert!(matches!(
                error,
                CatalogRegistryError::InvalidEntry { message, .. }
                    if message == "display_name must not contain control or bidirectional-control characters"
            ));

            let mut value = serde_json::to_value(CatalogWire::from(&definition)).unwrap();
            value["sources"][0]["bind"] = serde_json::json!({
                "type": "argument_name",
                "name": format!("value{character}name"),
            });
            let bytes = serde_json::to_vec(&value).unwrap();
            let error = TaintCatalogRegistry::new_without_workspace(Default::default())
                .register_json_bytes(CatalogSourceIdentity::new("test").unwrap(), &bytes)
                .unwrap_err();
            assert!(matches!(
                error,
                CatalogRegistryError::InvalidEntry { message, .. }
                    if message == "bind argument name must not contain control or bidirectional-control characters"
            ));
        }
    }

    #[test]
    fn forged_catalog_validation_rejects_cross_role_duplicate_ids_and_limits() {
        let mut forged = catalog("bifrost.sources", "same", "request");
        forged.sinks.push(TaintSinkSpec {
            id: TaintEntryId::new("same").unwrap(),
            display_name: "sink".to_string(),
            categories: vec![PolicyCategoryId::new("sink.data").unwrap()],
            selector: selector("sink"),
            dangerous_operand: PolicyPort::ArgumentIndex { index: 0 },
            accepts: vec![TaintLabel::new("attacker-controlled").unwrap()],
            tags: vec![],
            impacts: vec![],
        });
        let mut registry = TaintCatalogRegistry::new_without_workspace(Default::default());
        assert!(matches!(
            registry.register(forged),
            Err(CatalogRegistryError::DuplicateEntryId { .. })
        ));

        let limits = CatalogRegistryLimits::default()
            .with_max_identities(1)
            .unwrap();
        let mut registry = TaintCatalogRegistry::new_without_workspace(limits);
        registry
            .register(catalog("bifrost.one", "one", "one"))
            .unwrap();
        assert!(matches!(
            registry.register(catalog("bifrost.two", "two", "two")),
            Err(CatalogRegistryError::RegistryIdentityLimit { .. })
        ));
    }

    #[test]
    fn workspace_free_registry_refuses_path_loading() {
        let mut registry = TaintCatalogRegistry::new_without_workspace(Default::default());
        assert_eq!(
            registry.register_json_path("catalogs/default.json"),
            Err(CatalogRegistryError::WorkspaceAccessUnavailable)
        );
    }

    #[test]
    fn workspace_registry_reads_only_explicit_json_paths_through_its_capability() {
        let root = tempfile::tempdir().unwrap();
        let definition =
            normalize_and_validate_catalog(catalog("bifrost.sources", "request", "request"))
                .unwrap();
        let bytes = serde_json::to_vec(&CatalogWire::from(&definition)).unwrap();
        std::fs::write(root.path().join("catalog.json"), bytes).unwrap();
        std::fs::write(root.path().join("catalog.txt"), b"{}").unwrap();

        let mut registry =
            TaintCatalogRegistry::new_for_workspace(root.path().to_path_buf(), Default::default())
                .unwrap();
        registry.register_json_path("catalog.json").unwrap();
        assert_eq!(registry.len(), 1);
        assert!(matches!(
            registry.register_json_path("catalog.txt"),
            Err(CatalogRegistryError::WorkspaceAccess { .. })
        ));
        assert!(matches!(
            registry.register_json_path("../catalog.json"),
            Err(CatalogRegistryError::WorkspaceAccess { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn workspace_catalog_paths_must_have_portable_lossless_identities() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let relative = PathBuf::from(OsString::from_vec(b"catalog-\x80.json".to_vec()));
        assert!(matches!(
            catalog_source_identity_from_path(&relative),
            Err(CatalogRegistryError::InvalidWorkspacePath {
                source: WorkspaceRelativePathError::NonUtf8,
                ..
            })
        ));
    }

    #[test]
    fn json_registration_rejects_unknown_tagged_fields() {
        let definition =
            normalize_and_validate_catalog(catalog("bifrost.sources", "request", "request"))
                .unwrap();
        let mut value = serde_json::to_value(CatalogWire::from(&definition)).unwrap();
        value["sources"][0]["bind"]["unexpected"] = Value::Bool(true);
        let bytes = serde_json::to_vec(&value).unwrap();
        let mut registry = TaintCatalogRegistry::new_without_workspace(Default::default());
        assert!(matches!(
            registry.register_json_bytes(CatalogSourceIdentity::new("test").unwrap(), &bytes),
            Err(CatalogRegistryError::InvalidJson { .. })
        ));
    }

    #[test]
    fn json_registration_rejects_duplicate_keys_inside_nested_query_objects() {
        let definition =
            normalize_and_validate_catalog(catalog("bifrost.sources", "request", "request"))
                .unwrap();
        let compact = serde_json::to_string(&CatalogWire::from(&definition)).unwrap();
        let duplicate = compact.replacen(r#""query":{"#, r#""query":{"schema_version":2,"#, 1);
        assert_ne!(duplicate, compact, "fixture must contain a query object");

        let mut registry = TaintCatalogRegistry::new_without_workspace(Default::default());
        let error = registry
            .register_json_bytes(
                CatalogSourceIdentity::new("duplicate-query-key").unwrap(),
                duplicate.as_bytes(),
            )
            .unwrap_err();
        let CatalogRegistryError::InvalidJson { message, .. } = error else {
            panic!("expected strict JSON rejection, got {error:?}");
        };
        assert!(
            message.contains("duplicate JSON object key `schema_version`"),
            "{message}"
        );
    }
}
