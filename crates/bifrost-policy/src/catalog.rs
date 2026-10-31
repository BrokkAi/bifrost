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
    TaintLabel, TaintSanitizerCondition, TaintSanitizerKind, TaintSanitizerOperand,
    TaintSanitizerRequirement, TaintSanitizerResult, TaintSanitizerSpec, TaintSanitizerWhen,
    TaintSinkSpec, TaintSourceEvidence, TaintSourceSpec, TaintSystemEntry, TaintTag,
    TaintThreatModel, TaintTransferEffect, TaintTransferSpec, TaintTransformSpec,
    TaintTrustBoundary, TypestateCallBinding, TypestateSeedBinding, validate_sanitizer_arity,
};
use brokk_bifrost_analysis::analyzer::semantic::{
    WorkspaceRelativePath, WorkspaceRelativePathError,
};
use brokk_bifrost_analysis::schema_version::SchemaVersionOrigin;
use brokk_bifrost_analysis::workspace_document::{WorkspaceRoot, read_workspace_document};
use brokk_bifrost_rql::structural::{
    CodeQuery, CodeQueryExecutionMode, CodeQueryResultDetail, DEFAULT_LIMIT,
    SCHEMA_VERSION as RQL_SCHEMA_VERSION,
};

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
    pub categories: Vec<PolicyCategoryId>,
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
    pub fn with_max_identities(mut self, value: usize) -> Result<Self, CatalogRegistryLimitError> {
        validate_lowered_limit("max_identities", value, MAX_CATALOG_IDENTITIES)?;
        self.max_identities = value;
        Ok(self)
    }
}

fn validate_lowered_limit(
    field: &'static str,
    value: usize,
    hard_maximum: usize,
) -> Result<(), CatalogRegistryLimitError> {
    if !crate::within_policy_limit(value, hard_maximum) {
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
        crate::fmt_limit_error(formatter, &self.field, &self.hard_maximum, &self.value)
    }
}

impl std::error::Error for CatalogRegistryLimitError {}

#[derive(Debug, Clone)]
pub struct RegisteredTaintCatalog {
    identity: TaintCatalogIdentity,
    semantic_hash: TaintCatalogHash,
    definition: TaintCatalogDefinition,
    canonical_json: Box<[u8]>,
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
        self.register_normalized(catalog)
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
        self.register_normalized(catalog)
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
        let CatalogRef::Named {
            name,
            version,
            sha256,
        } = reference
        else {
            return Err(CatalogRegistryError::InvalidModel(
                "a wildcard cannot name an exact catalog endpoint".into(),
            ));
        };
        let identity = TaintCatalogIdentity {
            name: name.clone(),
            version: *version,
        };
        let catalog = self
            .catalogs
            .get(&identity)
            .ok_or(CatalogRegistryError::UnknownCatalog { identity })?;
        if let Some(expected) = *sha256
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

    /// Resolve catalog selection against this run's bounded registry.
    pub fn select(
        &self,
        reference: &CatalogRef,
    ) -> Result<Vec<&RegisteredTaintCatalog>, CatalogRegistryError> {
        match reference {
            CatalogRef::Named { .. } => Ok(vec![self.resolve(reference)?]),
            CatalogRef::AnyRegistered { predicate } => {
                if self.is_empty() {
                    return Ok(Vec::new());
                }
                let categories = match predicate {
                    super::definition::CategoryPredicate::Any { categories }
                    | super::definition::CategoryPredicate::All { categories } => categories,
                };
                for category in categories {
                    if !self
                        .catalogs
                        .values()
                        .any(|catalog| catalog.definition.categories.contains(category))
                    {
                        return Err(CatalogRegistryError::InvalidModel(format!(
                            "unknown catalog category `{category}`"
                        )));
                    }
                }
                Ok(self.iter().collect())
            }
        }
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

    fn register_normalized(
        &mut self,
        catalog: TaintCatalogDefinition,
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
    if catalog.categories.len() > MAX_POLICY_SET_ITEMS {
        return Err(CatalogRegistryError::InvalidModel(
            "catalog category vocabulary exceeds set limit".into(),
        ));
    }
    catalog.categories.sort();
    catalog.categories.dedup();
    for categories in catalog
        .sources
        .iter()
        .map(|entry| &entry.categories)
        .chain(catalog.sinks.iter().map(|entry| &entry.categories))
        .chain(catalog.sanitizers.iter().map(|entry| &entry.categories))
        .chain(catalog.transforms.iter().map(|entry| &entry.categories))
        .chain(
            catalog
                .external_models
                .iter()
                .map(|entry| &entry.categories),
        )
    {
        for category in categories {
            if !catalog.categories.contains(category) {
                return Err(CatalogRegistryError::InvalidModel(format!(
                    "catalog `{}` entry uses undeclared category `{category}`",
                    catalog.name
                )));
            }
        }
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

/// Field ports are external-model write destinations only; every other port
/// position refuses them so a catalog cannot smuggle one into an endpoint.
fn reject_field_port(
    kind: CatalogEntryKind,
    id: &TaintEntryId,
    port: &PolicyPort,
) -> Result<(), CatalogRegistryError> {
    if matches!(port, PolicyPort::FieldOf { .. }) {
        return invalid_entry(
            kind,
            id,
            "a field port is only valid as an external-model transfer write destination",
        );
    }
    Ok(())
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
    reject_field_port(CatalogEntryKind::Source, &source.id, &source.bind)?;
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
    reject_field_port(CatalogEntryKind::Sink, &sink.id, &sink.dangerous_operand)?;
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
    normalize_set(
        CatalogEntryKind::Sanitizer,
        &sanitizer.id,
        "categories",
        &mut sanitizer.categories,
    )?;
    validate_selector(&sanitizer.id, &sanitizer.selector)?;
    match &mut sanitizer.kind {
        TaintSanitizerKind::Transfer { input, output } => {
            reject_field_port(CatalogEntryKind::Sanitizer, &sanitizer.id, input)?;
            reject_field_port(CatalogEntryKind::Sanitizer, &sanitizer.id, output)?;
            validate_port(CatalogEntryKind::Sanitizer, &sanitizer.id, "input", input)?;
            validate_port(CatalogEntryKind::Sanitizer, &sanitizer.id, "output", output)?;
        }
        TaintSanitizerKind::Conditional { requires, .. } => {
            if requires.len() > 64 {
                return Err(CatalogRegistryError::InvalidModel(
                    "too many sanitizer requirements".into(),
                ));
            }
            let mut keys = HashSet::new();
            for item in requires.iter() {
                if let TaintSanitizerCondition::ResultOf(selector) = &item.condition {
                    validate_selector(&sanitizer.id, selector)?;
                }
                if let TaintSanitizerCondition::Equals(literal) = &item.condition
                    && !matches!(
                        literal,
                        Value::String(_) | Value::Number(_) | Value::Bool(_)
                    )
                {
                    return Err(CatalogRegistryError::InvalidModel(
                        "sanitizer equals requires a string, number or Boolean literal".into(),
                    ));
                }
                let key = serde_json_canonicalizer::to_vec(
                    &crate::canonical::sanitizer_requirement_to_json(item),
                )
                .expect("sanitizer requirement encodes as JSON");
                if !keys.insert(key) {
                    return Err(CatalogRegistryError::InvalidModel(
                        "duplicate sanitizer requirement".into(),
                    ));
                }
            }
            requires.sort_by_cached_key(|item| {
                serde_json_canonicalizer::to_vec(&crate::canonical::sanitizer_requirement_to_json(
                    item,
                ))
                .expect("sanitizer requirement encodes as JSON")
            });
        }
    }
    validate_sanitizer_arity(&sanitizer.selector, &sanitizer.kind)
        .map_err(CatalogRegistryError::InvalidModel)?;
    normalize_nonempty_set(
        CatalogEntryKind::Sanitizer,
        &sanitizer.id,
        "removes",
        &mut sanitizer.removes,
    )
}

fn normalize_transform(transform: &mut TaintTransformSpec) -> Result<(), CatalogRegistryError> {
    normalize_set(
        CatalogEntryKind::Transform,
        &transform.id,
        "categories",
        &mut transform.categories,
    )?;
    validate_selector(&transform.id, &transform.selector)?;
    reject_field_port(CatalogEntryKind::Transform, &transform.id, &transform.input)?;
    reject_field_port(
        CatalogEntryKind::Transform,
        &transform.id,
        &transform.output,
    )?;
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
    normalize_set(
        CatalogEntryKind::ExternalModel,
        &model.id,
        "categories",
        &mut model.categories,
    )?;
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
        // A field port is a write destination: only `to` accepts it, and its
        // base names the written object (an argument or the receiver), never
        // another field or a call output.
        if matches!(transfer.from, PolicyPort::FieldOf { .. }) {
            return invalid_entry(
                CatalogEntryKind::ExternalModel,
                &model.id,
                "a field port is only valid as a transfer write destination",
            );
        }
        if let PolicyPort::FieldOf { base, .. } = &transfer.to
            && !matches!(
                base.as_ref(),
                PolicyPort::Receiver
                    | PolicyPort::ArgumentIndex { .. }
                    | PolicyPort::ArgumentName { .. }
            )
        {
            return invalid_entry(
                CatalogEntryKind::ExternalModel,
                &model.id,
                "a field base must be an argument or the receiver",
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
    let PolicySelector::Inline { schema, query, .. } = selector else {
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
    if query.limit != DEFAULT_LIMIT
        || query.result_detail != CodeQueryResultDetail::Compact
        || query.execution_mode != CodeQueryExecutionMode::Results
    {
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
    match port {
        PolicyPort::ArgumentName { name } => {
            validate_catalog_author_text(kind, id, &format!("{field} argument name"), name)
        }
        PolicyPort::FieldOf { base, name } => {
            validate_catalog_author_text(kind, id, &format!("{field} field name"), name)?;
            validate_port(kind, id, field, base)
        }
        _ => Ok(()),
    }
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
    categories: Vec<String>,
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
    #[serde(default)]
    threat_model: Option<String>,
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

fn deserialize_sanitizer_optional<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SanitizerWire {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    categories: Vec<String>,
    id: String,
    selector: SelectorWire,
    #[serde(
        default,
        deserialize_with = "deserialize_sanitizer_optional",
        skip_serializing_if = "Option::is_none"
    )]
    input: Option<PortWire>,
    #[serde(
        default,
        deserialize_with = "deserialize_sanitizer_optional",
        skip_serializing_if = "Option::is_none"
    )]
    output: Option<PortWire>,
    #[serde(
        default,
        deserialize_with = "deserialize_sanitizer_optional",
        skip_serializing_if = "Option::is_none"
    )]
    when: Option<SanitizerWhenWire>,
    #[serde(
        default,
        deserialize_with = "deserialize_sanitizer_optional",
        skip_serializing_if = "Option::is_none"
    )]
    sanitizes: Option<SanitizerOperandWire>,
    #[serde(
        default,
        deserialize_with = "deserialize_sanitizer_optional",
        skip_serializing_if = "Option::is_none"
    )]
    requires: Option<Vec<SanitizerRequirementWire>>,
    removes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SanitizerWhenWire {
    result: SanitizerResultWire,
    #[serde(
        default,
        deserialize_with = "deserialize_sanitizer_optional",
        skip_serializing_if = "Option::is_none"
    )]
    index: Option<u32>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum SanitizerResultWire {
    True,
    False,
    Nil,
    NonNil,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum SanitizerOperandWire {
    Receiver {},
    Argument { index: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SanitizerRequirementWire {
    operand: SanitizerOperandWire,
    #[serde(
        default,
        deserialize_with = "deserialize_sanitizer_optional",
        skip_serializing_if = "Option::is_none"
    )]
    constant: Option<bool>,
    #[serde(
        default,
        deserialize_with = "deserialize_sanitizer_optional",
        skip_serializing_if = "Option::is_none"
    )]
    equals: Option<SanitizerLiteralWire>,
    #[serde(
        default,
        deserialize_with = "deserialize_sanitizer_optional",
        skip_serializing_if = "Option::is_none"
    )]
    result_of: Option<SelectorWire>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum SanitizerLiteralWire {
    String(String),
    Number(serde_json::Number),
    Boolean(bool),
}

impl From<SanitizerOperandWire> for TaintSanitizerOperand {
    fn from(value: SanitizerOperandWire) -> Self {
        match value {
            SanitizerOperandWire::Receiver {} => Self::Receiver,
            SanitizerOperandWire::Argument { index } => Self::Argument { index },
        }
    }
}
impl From<TaintSanitizerOperand> for SanitizerOperandWire {
    fn from(value: TaintSanitizerOperand) -> Self {
        match value {
            TaintSanitizerOperand::Receiver => Self::Receiver {},
            TaintSanitizerOperand::Argument { index } => Self::Argument { index },
        }
    }
}
impl From<SanitizerWhenWire> for TaintSanitizerWhen {
    fn from(value: SanitizerWhenWire) -> Self {
        Self {
            index: value.index,
            result: match value.result {
                SanitizerResultWire::True => TaintSanitizerResult::True,
                SanitizerResultWire::False => TaintSanitizerResult::False,
                SanitizerResultWire::Nil => TaintSanitizerResult::Nil,
                SanitizerResultWire::NonNil => TaintSanitizerResult::NonNil,
            },
        }
    }
}
impl From<TaintSanitizerWhen> for SanitizerWhenWire {
    fn from(value: TaintSanitizerWhen) -> Self {
        Self {
            index: value.index,
            result: match value.result {
                TaintSanitizerResult::True => SanitizerResultWire::True,
                TaintSanitizerResult::False => SanitizerResultWire::False,
                TaintSanitizerResult::Nil => SanitizerResultWire::Nil,
                TaintSanitizerResult::NonNil => SanitizerResultWire::NonNil,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransformWire {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    categories: Vec<String>,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    categories: Vec<String>,
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
    ResultIndex { index: u32 },
    ArgumentIndex { index: u32 },
    ArgumentName { name: String },
    Field { name: String, of: Box<PortWire> },
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
    ResultIndex,
    ArgumentIndex,
    ArgumentName,
    Field,
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
    #[serde(default)]
    of: OptionalWireField<PortWire>,
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
        match (tagged.kind, tagged.index, tagged.name, tagged.of) {
            (
                PortKindWire::MatchedValue,
                OptionalWireField::Missing,
                OptionalWireField::Missing,
                OptionalWireField::Missing,
            ) => Ok(Self::MatchedValue),
            (
                PortKindWire::Receiver,
                OptionalWireField::Missing,
                OptionalWireField::Missing,
                OptionalWireField::Missing,
            ) => Ok(Self::Receiver),
            (
                PortKindWire::ReturnValue,
                OptionalWireField::Missing,
                OptionalWireField::Missing,
                OptionalWireField::Missing,
            ) => Ok(Self::ReturnValue),
            (
                PortKindWire::ResultIndex,
                OptionalWireField::Present(index),
                OptionalWireField::Missing,
                OptionalWireField::Missing,
            ) => Ok(Self::ResultIndex { index }),
            (
                PortKindWire::ArgumentIndex,
                OptionalWireField::Present(index),
                OptionalWireField::Missing,
                OptionalWireField::Missing,
            ) => Ok(Self::ArgumentIndex { index }),
            (
                PortKindWire::ArgumentName,
                OptionalWireField::Missing,
                OptionalWireField::Present(name),
                OptionalWireField::Missing,
            ) => Ok(Self::ArgumentName { name }),
            (
                PortKindWire::Field,
                OptionalWireField::Missing,
                OptionalWireField::Present(name),
                OptionalWireField::Present(of),
            ) => Ok(Self::Field {
                name,
                of: Box::new(of),
            }),
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
            categories: wire
                .categories
                .into_iter()
                .map(PolicyCategoryId::new)
                .collect::<Result<_, _>>()
                .map_err(invalid_wire_identifier("catalog category"))?,
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

fn decode_threat_model_label(label: String) -> Result<TaintThreatModel, CatalogRegistryError> {
    match label.as_str() {
        "remote" => Ok(TaintThreatModel::Remote),
        "commandargs" => Ok(TaintThreatModel::CommandArgs),
        "environment" => Ok(TaintThreatModel::Environment),
        "stdin" => Ok(TaintThreatModel::Stdin),
        "file" => Ok(TaintThreatModel::File),
        "database" => Ok(TaintThreatModel::Database),
        _ => Err(CatalogRegistryError::InvalidModel(format!(
            "unknown source threat model `{label}`"
        ))),
    }
}

impl From<&TaintCatalogDefinition> for CatalogWire {
    fn from(definition: &TaintCatalogDefinition) -> Self {
        Self {
            schema_version: definition.schema_version,
            name: definition.name.as_str().to_string(),
            version: definition.version,
            categories: definition
                .categories
                .iter()
                .map(ToString::to_string)
                .collect(),
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
    if query_object.contains_key("limit")
        || query_object.contains_key("result_detail")
        || query_object.contains_key("execution_mode")
    {
        return Err(CatalogRegistryError::InvalidSelector {
            id: id.clone(),
            message: "selector query cannot contain limit, result_detail, or execution_mode"
                .to_string(),
        });
    }
    let query = CodeQuery::from_json(&wire.query).map_err(|error| {
        CatalogRegistryError::InvalidSelector {
            id: id.clone(),
            message: error.to_string(),
        }
    })?;
    Ok(PolicySelector::Inline {
        schema: brokk_bifrost_analysis::schema_version::SchemaVersionResolution {
            version: wire.schema_version,
            origin: brokk_bifrost_analysis::schema_version::SchemaVersionOrigin::Explicit,
        },
        query,
        resolved_locators: Vec::new(),
    })
}

fn encode_selector(selector: &PolicySelector) -> SelectorWire {
    let (schema_version, query) = super::canonical::inline_selector_fields(selector);
    SelectorWire {
        kind: "inline".to_string(),
        schema_version,
        query,
    }
}

fn catalog_entry_wire_fields(
    id: &TaintEntryId,
    display_name: &str,
    categories: &[PolicyCategoryId],
    selector: &PolicySelector,
) -> (String, String, Vec<String>, SelectorWire) {
    (
        id.as_str().to_string(),
        display_name.to_string(),
        display_ids(categories),
        encode_selector(selector),
    )
}

fn taint_port_transform_wire_fields(
    id: &TaintEntryId,
    selector: &PolicySelector,
    input: &PolicyPort,
    output: &PolicyPort,
    removes: &[TaintLabel],
) -> (String, SelectorWire, PortWire, PortWire, Vec<String>) {
    (
        id.as_str().to_string(),
        encode_selector(selector),
        PortWire::from(input),
        PortWire::from(output),
        display_ids(removes),
    )
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
            threat_model: wire
                .threat_model
                .map(decode_threat_model_label)
                .transpose()?,
            evidence: wire.evidence.map(Into::into),
        })
    }
}

impl From<&TaintSourceSpec> for SourceWire {
    fn from(spec: &TaintSourceSpec) -> Self {
        let (id, display_name, categories, selector) = catalog_entry_wire_fields(
            &spec.id,
            &spec.display_name,
            &spec.categories,
            &spec.selector,
        );
        Self {
            id,
            display_name,
            categories,
            selector,
            bind: PortWire::from(&spec.bind),
            labels: display_ids(&spec.labels),
            threat_model: spec.threat_model.map(|model| model.label().to_owned()),
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
        let (id, display_name, categories, selector) = catalog_entry_wire_fields(
            &spec.id,
            &spec.display_name,
            &spec.categories,
            &spec.selector,
        );
        Self {
            id,
            display_name,
            categories,
            selector,
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
        let kind = match (wire.input, wire.output, wire.when, wire.sanitizes, wire.requires) {
            (Some(input), Some(output), None, None, None) => TaintSanitizerKind::Transfer { input: input.into(), output: output.into() },
            (None, None, Some(when), Some(sanitizes), requires) => {
                if requires.as_ref().is_some_and(Vec::is_empty) {
                    return Err(CatalogRegistryError::InvalidModel("sanitizer requires must not be empty".into()));
                }
                let requires = requires.unwrap_or_default().into_iter().map(|item| {
                    let condition = match (item.constant, item.equals, item.result_of) {
                        (Some(true), None, None) => TaintSanitizerCondition::Constant,
                        (None, Some(literal), None) => TaintSanitizerCondition::Equals(match literal {
                            SanitizerLiteralWire::String(value) => Value::String(value),
                            SanitizerLiteralWire::Number(value) => Value::Number(value),
                            SanitizerLiteralWire::Boolean(value) => Value::Bool(value),
                        }),
                        (None, None, Some(selector)) => TaintSanitizerCondition::ResultOf(decode_selector(&id, selector)?),
                        _ => return Err(CatalogRegistryError::InvalidModel("sanitizer requirement needs exactly one of constant:true, equals or result_of".into())),
                    };
                    Ok(TaintSanitizerRequirement { operand: item.operand.into(), condition })
                }).collect::<Result<Vec<_>, CatalogRegistryError>>()?;
                TaintSanitizerKind::Conditional { when: when.into(), sanitizes: sanitizes.into(), requires }
            }
            _ => return Err(CatalogRegistryError::InvalidModel("use exactly one sanitizer shape: input/output or when/sanitizes with optional requires".into())),
        };
        Ok(Self {
            categories: parse_ids(wire.categories, PolicyCategoryId::new, "category")?,
            selector: decode_selector(&id, wire.selector)?,
            id,
            kind,
            removes: parse_ids(wire.removes, TaintLabel::new, "sanitizer label")?,
        })
    }
}

impl From<&TaintSanitizerSpec> for SanitizerWire {
    fn from(spec: &TaintSanitizerSpec) -> Self {
        let mut wire = Self {
            categories: display_ids(&spec.categories),
            id: spec.id.as_str().to_owned(),
            selector: encode_selector(&spec.selector),
            input: None,
            output: None,
            when: None,
            sanitizes: None,
            requires: None,
            removes: display_ids(&spec.removes),
        };
        match &spec.kind {
            TaintSanitizerKind::Transfer { input, output } => {
                wire.input = Some(PortWire::from(input));
                wire.output = Some(PortWire::from(output));
            }
            TaintSanitizerKind::Conditional {
                when,
                sanitizes,
                requires,
            } => {
                wire.when = Some((*when).into());
                wire.sanitizes = Some((*sanitizes).into());
                if !requires.is_empty() {
                    wire.requires = Some(requires.iter().map(|requirement| {
                        let mut item = SanitizerRequirementWire { operand: requirement.operand.into(), constant: None, equals: None, result_of: None };
                        match &requirement.condition {
                            TaintSanitizerCondition::Constant => item.constant = Some(true),
                            TaintSanitizerCondition::Equals(literal) => item.equals = Some(match literal {
                                Value::String(value) => SanitizerLiteralWire::String(value.clone()),
                                Value::Number(value) => SanitizerLiteralWire::Number(value.clone()),
                                Value::Bool(value) => SanitizerLiteralWire::Boolean(*value),
                                _ => unreachable!("sanitizer equals literals are string, number or Boolean"),
                            }),
                            TaintSanitizerCondition::ResultOf(selector) => item.result_of = Some(encode_selector(selector)),
                        }
                        item
                    }).collect());
                }
            }
        }
        wire
    }
}

impl TryFrom<TransformWire> for TaintTransformSpec {
    type Error = CatalogRegistryError;

    fn try_from(wire: TransformWire) -> Result<Self, Self::Error> {
        let id = TaintEntryId::new(wire.id).map_err(invalid_wire_identifier("transform ID"))?;
        Ok(Self {
            categories: parse_ids(wire.categories, PolicyCategoryId::new, "category")?,
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
        let (id, selector, input, output, removes) = taint_port_transform_wire_fields(
            &spec.id,
            &spec.selector,
            &spec.input,
            &spec.output,
            &spec.removes,
        );
        Self {
            categories: display_ids(&spec.categories),
            id,
            selector,
            input,
            output,
            removes,
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
            categories: parse_ids(wire.categories, PolicyCategoryId::new, "category")?,
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
            categories: display_ids(&spec.categories),
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
            PortWire::ResultIndex { index } => Self::ResultIndex { index },
            PortWire::ArgumentIndex { index } => Self::ArgumentIndex { index },
            PortWire::ArgumentName { name } => Self::ArgumentName { name },
            PortWire::Field { name, of } => Self::FieldOf {
                base: Box::new(Self::from(*of)),
                name,
            },
        }
    }
}

impl From<&PolicyPort> for PortWire {
    fn from(port: &PolicyPort) -> Self {
        match port {
            PolicyPort::MatchedValue => Self::MatchedValue,
            PolicyPort::Receiver => Self::Receiver,
            PolicyPort::ReturnValue => Self::ReturnValue,
            PolicyPort::ResultIndex { index } => Self::ResultIndex { index: *index },
            PolicyPort::ArgumentIndex { index } => Self::ArgumentIndex { index: *index },
            PolicyPort::ArgumentName { name } => Self::ArgumentName { name: name.clone() },
            PolicyPort::FieldOf { base, name } => Self::Field {
                name: name.clone(),
                of: Box::new(Self::from(base.as_ref())),
            },
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
        PolicyEndpointBinding::ResultIndex { index } => PolicyPort::ResultIndex { index: *index },
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
        TypestateSeedBinding::ResultIndex { index } => PolicyPort::ResultIndex { index: *index },
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
        TypestateCallBinding::ResultIndex { index } => PolicyPort::ResultIndex { index: *index },
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
        PolicyPort::ResultIndex { .. } => phase == EndpointObservationPhase::AfterNormalReturn,
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
        // Field ports exist only as external-model transfer destinations,
        // which never carry an endpoint observation phase.
        PolicyPort::FieldOf { .. } => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::inline_match_selector as selector;
    fn source(id: &str, name: &str) -> TaintSourceSpec {
        crate::test_support::taint_source_spec(id, name, name, "attacker-controlled")
    }

    fn catalog(name: &str, source_id: &str, display: &str) -> TaintCatalogDefinition {
        TaintCatalogDefinition {
            categories: vec![
                PolicyCategoryId::new("input.user").unwrap(),
                PolicyCategoryId::new("sink.data").unwrap(),
            ],
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
    fn conditional_sanitizer_catalog_round_trip_enforces_the_wire_contract() {
        let source = r#"(policy :id test.guard :name "Guard" :message "M" :severity warning
          :analysis (analysis :type taint :mode may :sources (endpoint-set) :sinks (endpoint-set)
            :sanitizers (endpoint-set :entries [(sanitizer :id guard :selector (rql :schema-version 1 (call (arity 2)))
              :when (result false :index 1) :sanitizes (argument :index 0)
              :requires [(receiver :result-of (rql :schema-version 1 (call))) (argument :index 1 :equals "..")
                         (argument :index 0 :constant true)] :removes [secret])])) )"#;
        let parsed =
            crate::parse_rqlp_source(source, crate::PolicySourceIdentity::new("test")).unwrap();
        let crate::RqlpDocument::Policy { definition } = parsed.document() else {
            panic!("expected policy")
        };
        let crate::PolicyAnalysis::Taint { spec } = &definition.analysis else {
            panic!("expected taint")
        };
        let mut definition = catalog("test.guard", "request", "request");
        definition.sanitizers = spec.sanitizers.entries.clone();
        let mut typed = TaintCatalogRegistry::new_without_workspace(Default::default());
        let hash = typed.register(definition).unwrap();
        let bytes = typed.iter().next().unwrap().canonical_json();
        let mut wire = TaintCatalogRegistry::new_without_workspace(Default::default());
        assert_eq!(
            wire.register_json_bytes(CatalogSourceIdentity::new("test").unwrap(), bytes)
                .unwrap(),
            hash
        );
        assert_eq!(wire.iter().next().unwrap().canonical_json(), bytes);
        let value: Value = serde_json::from_slice(bytes).unwrap();
        for (field, payload) in [
            ("input", serde_json::json!({"type":"receiver"})),
            ("output", serde_json::json!({"type":"return_value"})),
            ("input", Value::Null),
            ("requires", serde_json::json!([])),
            (
                "requires",
                serde_json::json!([{"operand":{"type":"receiver"},"constant":true},{"operand":{"type":"receiver"},"constant":true}]),
            ),
            (
                "requires",
                serde_json::json!([{"operand":{"type":"argument","index":2},"constant":true}]),
            ),
            (
                "requires",
                serde_json::json!([{"operand":{"type":"receiver"},"constant":false}]),
            ),
            (
                "requires",
                serde_json::json!([{"operand":{"type":"receiver"},"constant":true,"equals":null}]),
            ),
            ("when", serde_json::json!({"result":"true","unknown":1})),
            (
                "sanitizes",
                serde_json::json!({"type":"receiver","index":0}),
            ),
            ("unknown", serde_json::json!(true)),
        ] {
            let mut invalid = value.clone();
            invalid["sanitizers"][0][field] = payload;
            let result = TaintCatalogRegistry::new_without_workspace(Default::default())
                .register_json_bytes(
                    CatalogSourceIdentity::new("test").unwrap(),
                    &serde_json::to_vec(&invalid).unwrap(),
                );
            assert!(result.is_err(), "accepted invalid wire: {invalid}");
        }
    }

    #[test]
    fn transfer_sanitizer_catalog_identity_is_unchanged() {
        let mut definition = catalog("test.sanitizers", "request", "request");
        definition.sanitizers.push(TaintSanitizerSpec {
            categories: vec![],
            id: TaintEntryId::new("scrub").unwrap(),
            selector: crate::test_support::inline_match_selector("clean"),
            kind: crate::definition::TaintSanitizerKind::Transfer {
                input: PolicyPort::ArgumentIndex { index: 0 },
                output: PolicyPort::ReturnValue,
            },
            removes: vec![TaintLabel::new("secret").unwrap()],
        });
        let mut registry = TaintCatalogRegistry::new_without_workspace(Default::default());
        let hash = registry.register(definition).unwrap();
        let resolved = registry.iter().next().unwrap();
        assert_eq!(resolved.canonical_json.len(), 711);
        assert_eq!(
            hash.to_string(),
            "5c5d6f4fcaf8e316cb9bdd46468c2a84e86d0f4906c73c3c763b583d0b54bffc"
        );
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
        let duplicate_prefix = format!(r#""query":{{"schema_version":{RQL_SCHEMA_VERSION},"#);
        let duplicate = compact.replacen(r#""query":{"#, &duplicate_prefix, 1);
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

    #[test]
    fn typed_and_json_registration_reject_execution_mode_controls() {
        let mut typed = catalog("bifrost.sources", "request", "request");
        let PolicySelector::Inline { query, .. } = &mut typed.sources[0].selector else {
            panic!("catalog test selector is inline");
        };
        query.execution_mode = CodeQueryExecutionMode::Profile;
        let mut registry = TaintCatalogRegistry::new_without_workspace(Default::default());
        let error = registry.register(typed).unwrap_err();
        assert!(matches!(
            error,
            CatalogRegistryError::InvalidSelector { ref message, .. }
                if message.contains("output controls")
        ));

        let definition =
            normalize_and_validate_catalog(catalog("bifrost.sources", "request", "request"))
                .unwrap();
        let mut value = serde_json::to_value(CatalogWire::from(&definition)).unwrap();
        value["sources"][0]["selector"]["query"]["execution_mode"] =
            Value::String("profile".to_string());
        let bytes = serde_json::to_vec(&value).unwrap();
        let error = registry
            .register_json_bytes(
                CatalogSourceIdentity::new("execution-mode").unwrap(),
                &bytes,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            CatalogRegistryError::InvalidSelector { ref message, .. }
                if message.contains("execution_mode")
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
}

#[cfg(test)]
mod category_contract_tests {
    use super::*;
    use crate::definition::CategoryPredicate;

    #[test]
    fn catalog_wire_validates_vocabulary_and_auxiliary_category_selection() {
        let category = |name| PolicyCategoryId::new(name).unwrap();
        let mut definition = TaintCatalogDefinition {
            schema_version: 1,
            name: PolicyId::new("test.auxiliary").unwrap(),
            version: 1,
            categories: vec![category("sql-injection"), category("path-injection")],
            sources: Vec::new(),
            sinks: Vec::new(),
            transforms: Vec::new(),
            external_models: Vec::new(),
            sanitizers: [Some("sql-injection"), Some("path-injection"), None]
                .into_iter()
                .enumerate()
                .map(|(index, name)| TaintSanitizerSpec {
                    id: TaintEntryId::new(format!("clean-{index}")).unwrap(),
                    categories: name.map(category).into_iter().collect(),
                    selector: crate::test_support::inline_match_selector("clean"),
                    kind: crate::definition::TaintSanitizerKind::Transfer {
                        input: PolicyPort::ArgumentIndex { index: 0 },
                        output: PolicyPort::ReturnValue,
                    },
                    removes: vec![TaintLabel::new("untrusted").unwrap()],
                })
                .collect(),
        };
        let mut registry = TaintCatalogRegistry::new_without_workspace(Default::default());
        let bytes = serde_json::to_vec(&CatalogWire::from(&definition)).unwrap();
        registry
            .register_json_bytes(
                CatalogSourceIdentity::new("test-only auxiliary fixture").unwrap(),
                &bytes,
            )
            .unwrap();
        let named = CatalogRef::new(definition.name.clone(), 1, None).unwrap();
        let wildcard = CatalogRef::AnyRegistered {
            predicate: CategoryPredicate::Any {
                categories: vec![category("sql-injection")],
            },
        };
        let entries = &registry.select(&wildcard).unwrap()[0]
            .definition()
            .sanitizers;
        let selected = entries
            .iter()
            .filter(|entry| wildcard.includes_categories(&entry.categories))
            .map(|entry| entry.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(selected, ["clean-0"]);
        assert_eq!(
            entries
                .iter()
                .filter(|entry| named.includes_categories(&entry.categories))
                .count(),
            3
        );
        definition.sanitizers[0].categories = vec![category("sql-injectoin")];
        let mut registry = TaintCatalogRegistry::new_without_workspace(Default::default());
        let bytes = serde_json::to_vec(&CatalogWire::from(&definition)).unwrap();
        let error = registry
            .register_json_bytes(CatalogSourceIdentity::new("typo").unwrap(), &bytes)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("undeclared category `sql-injectoin`"),
            "{error}"
        );
        assert!(
            registry.is_empty(),
            "failed registration must be transactional"
        );
    }
}
