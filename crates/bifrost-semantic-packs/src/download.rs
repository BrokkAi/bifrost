//! Acquire and verify public open pack releases before catalog activation.
//!
//! This module is called by the `bifrost` executable during bootstrap. It
//! selects release metadata and caches verified artifacts, but it does not
//! open or mutate an analyzer catalog. The existing bundle and policy readers
//! remain responsible for validating content when they activate it.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use flate2::read::GzDecoder;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tar::{Archive, EntryType};
use tempfile::{Builder as TempDirBuilder, NamedTempFile};
use zip::ZipArchive;

// Keep the request-scoped semantic artifact downloader from the engine. The
// open policy and native release selector below is a separate binary-owned
// acquisition path; it does not replace catalog-driven semantic production.
#[path = "semantic_download.rs"]
mod semantic_download;
pub use semantic_download::acquire_semantic_pack;

const REPOSITORY_URL: &str = "https://github.com/BrokkAi/bifrost-packs";
const API_ROOT: &str = "https://api.github.com/repos/BrokkAi/bifrost-packs";
const RULES_PACK_ID: &str = "bifrost.public.rules";
const SEMANTIC_PACK_ID: &str = "bifrost.public.packs";
const INVENTORY_SCHEMA_VERSION: u32 = 2;
const MANIFEST_CACHE_TTL: Duration = Duration::from_secs(60 * 60);
const MAX_REDIRECTS: u32 = 5;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_MANIFEST_BYTES: u64 = 2 * 1024 * 1024;
const MAX_API_PAGE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_UNPACKED_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 100_000;
const MAX_PAX_BYTES: usize = 1024 * 1024;
const CACHE_DIRECTORY: &str = "open-pack-releases";
// Windows intentionally caches under LOCALAPPDATA/Bifrost/AgentPlugin rather
// than a "bifrost-agent" directory, matching the launcher's historic layout;
// only the macOS and other-Unix arms of `platform_cache_base` use this name.
#[cfg(not(target_os = "windows"))]
const CACHE_AGENT_DIRECTORY: &str = "bifrost-agent";
const CACHE_CATALOG_DIRECTORY: &str = "semantic-pack-catalog-v1";

/// A versioned, caller-supplied pack acquisition request.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackRequest {
    pub request_schema_version: u32,
    pub pack_id: String,
    pub repository: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inventory: Option<PackInventoryPin>,
    pub selection: PackSelection,
    #[serde(default)]
    pub dependencies: Vec<PackDependencyPin>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackInventoryPin {
    pub url: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
pub enum PackSelection {
    Strict {
        release_version: String,
        manifest_sha256: String,
    },
    Preferred {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        preferred_version: Option<String>,
        #[serde(default = "any_version_requirement")]
        allowed_versions: String,
        #[serde(default)]
        channel: PackChannel,
    },
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum PackChannel {
    #[default]
    Stable,
    Prerelease,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackDependencyPin {
    pub pack_id: String,
    pub repository: String,
    /// Omitted only by legacy `PACK_SOURCE`, which predates dependency-version
    /// pins and supplies the dependency manifest digest instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_version: Option<String>,
    pub manifest_sha256: String,
}

fn any_version_requirement() -> String {
    "*".to_owned()
}

/// The verified inventory this run selected from; the receipt keeps the
/// snapshot of the run that first produced the selection.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PackInventorySnapshot {
    pub index_sha256: String,
    pub fetched_at: String,
    pub fetched_online: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailureClass {
    pub name: &'static str,
    pub retryable: bool,
}

/// The result of selecting and verifying a root policy pack and its
/// depth-one dependencies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPackSelection {
    pub selection_id: String,
    pub selection_reason: String,
    pub rejections: Vec<Value>,
    pub inventory: PackInventorySnapshot,
    pub semantic_bundle_root: Option<PathBuf>,
    pub policy_pack_root: PathBuf,
    pub semantic_cache_root: PathBuf,
    pub receipt_path: PathBuf,
    pub cache_reused: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenPackFallbackKind {
    Disabled,
    NoCompatibleRelease,
    Pending,
    Unsupported,
    NetworkUnavailable,
    OfflineCacheMiss,
}

impl Display for OpenPackFallbackKind {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Disabled => "disabled",
            Self::NoCompatibleRelease => "no-compatible-release",
            Self::Pending => "pending",
            Self::Unsupported => "unsupported",
            Self::NetworkUnavailable => "unavailable",
            Self::OfflineCacheMiss => "offline-cache-miss",
        };
        formatter.write_str(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenPackRuntimeOutcome {
    Selected(Box<OpenPackSelection>),
    EmbeddedFallback {
        kind: OpenPackFallbackKind,
        message: String,
    },
}

/// Acquisition errors distinguish an authenticated fresh absence from every
/// failure that must stop the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenPackError {
    Unavailable(String),
    Network(String),
    Authentication(String),
    MissingRelease(String),
    InvalidSource(String),
    IncompatibleSelection(String),
    Unqualified(String),
    Pending(String),
    OfflineCacheMiss(String),
    NoCompatibleRelease {
        message: String,
        receipt: Value,
    },
    /// A cached inventory found no candidate; only an online inventory can
    /// prove absence, so the caller should retry when the network is available.
    UnverifiedAbsence(String),
    InvalidProfile(String),
    InvalidManifest(String),
    Integrity(String),
    Configuration(String),
    /// A selection failure with the candidate rejections and the inventory
    /// snapshot that produced them, so the caller can record which index
    /// denied the request.
    SelectionRejected {
        error: Box<OpenPackError>,
        rejections: Vec<Value>,
        inventory: Value,
    },
}

impl OpenPackError {
    pub fn is_unavailable(&self) -> bool {
        matches!(self, Self::Unavailable(_))
    }

    pub fn is_no_compatible_release(&self) -> bool {
        match self {
            Self::NoCompatibleRelease { .. } => true,
            Self::SelectionRejected { error, .. } => error.is_no_compatible_release(),
            _ => false,
        }
    }

    pub fn failure_class(&self) -> FailureClass {
        match self {
            Self::Configuration(_) => FailureClass {
                name: "invalid-configuration",
                retryable: false,
            },
            Self::InvalidSource(_) => FailureClass {
                name: "invalid-source",
                retryable: false,
            },
            Self::InvalidProfile(_) => FailureClass {
                name: "invalid-profile",
                retryable: false,
            },
            Self::InvalidManifest(_) => FailureClass {
                name: "invalid-manifest",
                retryable: false,
            },
            Self::MissingRelease(_) => FailureClass {
                name: "missing-strict-selection",
                retryable: false,
            },
            Self::IncompatibleSelection(_) => FailureClass {
                name: "incompatible-strict-selection",
                retryable: false,
            },
            Self::NoCompatibleRelease { .. } => FailureClass {
                name: "no-compatible-release",
                retryable: false,
            },
            Self::Integrity(_) => FailureClass {
                name: "integrity",
                retryable: false,
            },
            Self::Authentication(_) => FailureClass {
                name: "access-denied",
                retryable: false,
            },
            Self::Network(_) => FailureClass {
                name: "unavailable",
                retryable: true,
            },
            Self::Unavailable(_) => FailureClass {
                name: "unavailable",
                retryable: false,
            },
            Self::UnverifiedAbsence(_) => FailureClass {
                name: "unavailable",
                retryable: true,
            },
            Self::OfflineCacheMiss(_) => FailureClass {
                name: "offline-cache-miss",
                retryable: false,
            },
            Self::Pending(_) => FailureClass {
                name: "pending",
                retryable: false,
            },
            Self::Unqualified(_) => FailureClass {
                name: "unqualified",
                retryable: false,
            },
            Self::SelectionRejected { error, .. } => error.failure_class(),
        }
    }

    fn unavailable(message: impl Into<String>) -> Self {
        Self::Unavailable(message.into())
    }

    fn manifest(message: impl Into<String>) -> Self {
        Self::InvalidManifest(message.into())
    }

    fn integrity(message: impl Into<String>) -> Self {
        Self::Integrity(message.into())
    }

    fn no_compatible(message: impl Into<String>, receipt: Value) -> Self {
        Self::NoCompatibleRelease {
            message: message.into(),
            receipt,
        }
    }
}

impl Display for OpenPackError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(message)
            | Self::Network(message)
            | Self::Authentication(message)
            | Self::MissingRelease(message)
            | Self::InvalidSource(message)
            | Self::IncompatibleSelection(message)
            | Self::Unqualified(message)
            | Self::Pending(message)
            | Self::OfflineCacheMiss(message)
            | Self::UnverifiedAbsence(message)
            | Self::InvalidProfile(message)
            | Self::InvalidManifest(message)
            | Self::Integrity(message)
            | Self::Configuration(message) => formatter.write_str(message),
            Self::NoCompatibleRelease { message, .. } => formatter.write_str(message),
            Self::SelectionRejected { error, .. } => Display::fmt(error, formatter),
        }
    }
}

impl Error for OpenPackError {}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LegacyPackSource {
    repository: String,
    rules_version: String,
    manifest_sha256: String,
    semantic_manifest_sha256: String,
    #[serde(default)]
    inventory_url: Option<String>,
    #[serde(default)]
    inventory_sha256: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PackSource {
    repository: String,
    #[serde(default)]
    inventory_url: Option<String>,
    #[serde(default)]
    inventory_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SafeHttpsUrl {
    origin: String,
    path: String,
}

fn safe_https_url(value: &str) -> Result<SafeHttpsUrl, OpenPackError> {
    let uri = value
        .parse::<ureq::http::Uri>()
        .map_err(|_| OpenPackError::InvalidSource("invalid trusted HTTPS URL".to_owned()))?;
    let authority = uri
        .authority()
        .ok_or_else(|| OpenPackError::InvalidSource("HTTPS URL has no host".to_owned()))?;
    let path_and_query = uri.path_and_query();
    if uri.scheme_str() != Some("https")
        || authority.as_str().contains('@')
        || authority.port_u16().is_some()
        || authority.as_str() != authority.host()
        || path_and_query.is_some_and(|value| value.query().is_some())
        || value.contains('#')
    {
        return Err(OpenPackError::InvalidSource(
            "trusted URLs require HTTPS without credentials, ports, queries, or fragments"
                .to_owned(),
        ));
    }
    let host = authority.host().to_ascii_lowercase();
    if host.is_empty() {
        return Err(OpenPackError::InvalidSource(
            "HTTPS URL has an empty host".to_owned(),
        ));
    }
    Ok(SafeHttpsUrl {
        origin: format!("https://{host}"),
        path: path_and_query.map_or_else(|| "/".to_owned(), |value| value.path().to_owned()),
    })
}

fn validate_repository_url(value: &str) -> Result<(), OpenPackError> {
    let repository = safe_https_url(value)?;
    let mut components = repository.path.split('/').filter(|part| !part.is_empty());
    let owner = components.next().unwrap_or_default();
    let name = components.next().unwrap_or_default();
    if repository.origin != "https://github.com"
        || components.next().is_some()
        || owner.is_empty()
        || name.is_empty()
        || !owner
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || repository.path != format!("/{owner}/{name}")
    {
        return Err(OpenPackError::InvalidSource(
            "repository must be a GitHub owner/name URL without query, fragment, credentials, or port".to_owned(),
        ));
    }
    Ok(())
}

fn validate_pack_request(request: PackRequest) -> Result<PackRequest, OpenPackError> {
    if request.request_schema_version != 1 {
        return Err(OpenPackError::Configuration(
            "unsupported pack request schema version".to_owned(),
        ));
    }
    if !valid_pack_id(&request.pack_id) {
        return Err(OpenPackError::Configuration(
            "pack request pack_id must be a nonempty identifier".to_owned(),
        ));
    }
    validate_repository_url(&request.repository)?;
    if let Some(inventory) = &request.inventory {
        safe_https_url(&inventory.url)?;
        if !is_sha256(&inventory.sha256) {
            return Err(OpenPackError::InvalidSource(
                "inventory requires an exact SHA-256 pin".to_owned(),
            ));
        }
    }
    match &request.selection {
        PackSelection::Strict {
            release_version,
            manifest_sha256,
        } => {
            if Version::parse(release_version).is_err() {
                return Err(OpenPackError::InvalidSource(
                    "strict selection requires a valid SemVer release version".to_owned(),
                ));
            }
            if !is_sha256(manifest_sha256) {
                return Err(OpenPackError::InvalidSource(
                    "strict selection requires a manifest SHA-256 pin".to_owned(),
                ));
            }
        }
        PackSelection::Preferred {
            preferred_version,
            allowed_versions,
            ..
        } => {
            if preferred_version
                .as_deref()
                .is_some_and(|version| Version::parse(version).is_err())
            {
                return Err(OpenPackError::InvalidSource(
                    "preferred_version must be a valid SemVer release version".to_owned(),
                ));
            }
            semver::VersionReq::parse(allowed_versions).map_err(|_| {
                OpenPackError::InvalidSource(
                    "allowed_versions is not a valid SemVer requirement".to_owned(),
                )
            })?;
        }
    }
    let mut dependency_ids = BTreeSet::new();
    for dependency in &request.dependencies {
        if !valid_pack_id(&dependency.pack_id) {
            return Err(OpenPackError::Configuration(
                "dependency pack_id must be a nonempty identifier".to_owned(),
            ));
        }
        validate_repository_url(&dependency.repository)?;
        if dependency.repository != request.repository
            || dependency
                .release_version
                .as_deref()
                .is_some_and(|version| parse_semver(version).is_err())
            || !is_sha256(&dependency.manifest_sha256)
            || !dependency_ids.insert(dependency.pack_id.as_str())
        {
            return Err(OpenPackError::InvalidSource(
                "dependency pins must be unique, exact, and in the root repository".to_owned(),
            ));
        }
    }
    Ok(request)
}

fn valid_pack_id(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// Parse and validate a pack request without accessing the filesystem or network.
pub fn parse_pack_request(bytes: &[u8]) -> Result<PackRequest, OpenPackError> {
    let request = serde_json::from_slice::<PackRequest>(bytes).map_err(|_| {
        OpenPackError::Configuration(
            "pack request JSON is invalid or contains unknown fields".to_owned(),
        )
    })?;
    validate_pack_request(request)
}

/// Resolve `PACK_SOURCE` to its strict request, or return the public default.
pub fn default_pack_request() -> Result<PackRequest, OpenPackError> {
    let Ok(raw) = std::env::var("PACK_SOURCE") else {
        return Ok(default_preferred_request());
    };
    if raw.is_empty() {
        return Ok(default_preferred_request());
    }
    let source = parse_legacy_pack_source(&raw)?;
    validate_pack_request(PackRequest {
        request_schema_version: 1,
        pack_id: RULES_PACK_ID.to_owned(),
        repository: source.repository.clone(),
        inventory: source
            .inventory_url
            .zip(source.inventory_sha256)
            .map(|(url, sha256)| PackInventoryPin { url, sha256 }),
        selection: PackSelection::Strict {
            release_version: source.rules_version,
            manifest_sha256: source.manifest_sha256,
        },
        dependencies: vec![PackDependencyPin {
            pack_id: SEMANTIC_PACK_ID.to_owned(),
            repository: source.repository,
            release_version: None,
            manifest_sha256: source.semantic_manifest_sha256,
        }],
    })
}

fn default_preferred_request() -> PackRequest {
    PackRequest {
        request_schema_version: 1,
        pack_id: RULES_PACK_ID.to_owned(),
        repository: REPOSITORY_URL.to_owned(),
        inventory: None,
        selection: PackSelection::Preferred {
            preferred_version: None,
            allowed_versions: any_version_requirement(),
            channel: PackChannel::Stable,
        },
        dependencies: Vec::new(),
    }
}

fn parse_legacy_pack_source(raw: &str) -> Result<LegacyPackSource, OpenPackError> {
    let source = serde_json::from_str::<LegacyPackSource>(raw).map_err(|_| {
        OpenPackError::InvalidSource(
            "invalid explicit PACK_SOURCE; no default source fallback is permitted".to_owned(),
        )
    })?;
    validate_repository_url(&source.repository)?;
    if !is_sha256(&source.manifest_sha256)
        || !is_sha256(&source.semantic_manifest_sha256)
        || parse_semver(&source.rules_version).is_err()
    {
        return Err(OpenPackError::InvalidSource(
            "PACK_SOURCE requires an exact rules version and both descriptor SHA-256 pins"
                .to_owned(),
        ));
    }
    match (&source.inventory_url, &source.inventory_sha256) {
        (Some(url), Some(digest)) => {
            safe_https_url(url)?;
            if !is_sha256(digest) {
                return Err(OpenPackError::InvalidSource(
                    "HTTPS inventory requires its exact SHA-256".to_owned(),
                ));
            }
        }
        (None, None) => {}
        _ => {
            return Err(OpenPackError::InvalidSource(
                "inventory URL and digest must be supplied together".to_owned(),
            ));
        }
    }
    Ok(source)
}

fn request_source(request: &PackRequest) -> PackSource {
    PackSource {
        repository: request.repository.clone(),
        inventory_url: request
            .inventory
            .as_ref()
            .map(|inventory| inventory.url.clone()),
        inventory_sha256: request
            .inventory
            .as_ref()
            .map(|inventory| inventory.sha256.clone()),
    }
}

fn source_from_environment() -> Result<Option<LegacyPackSource>, OpenPackError> {
    let Ok(raw) = std::env::var("PACK_SOURCE") else {
        return Ok(None);
    };
    if raw.is_empty() {
        return Ok(None);
    }
    parse_legacy_pack_source(&raw).map(Some)
}

#[cfg(test)]
fn parse_pack_source(raw: &str) -> Result<LegacyPackSource, OpenPackError> {
    parse_legacy_pack_source(raw)
}

fn source_identity(request: &PackRequest) -> Result<String, OpenPackError> {
    let value = json!({
        "pack_id": request.pack_id,
        "repository": request.repository,
        "inventory": request.inventory,
    });
    canonical_json_bytes(&value).map(|bytes| sha256(&bytes))
}

/// Returns a copy of `value` with object keys sorted at every level. Identity
/// digests (source identity, selection id, cache paths derived from them) and
/// golden comparisons must not depend on `serde_json`'s `preserve_order`
/// feature, which any crate in a unified build can enable.
fn sorted_json_value(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(sorted_json_value).collect()),
        Value::Object(entries) => {
            let mut ordered: Vec<(&String, &Value)> = entries.iter().collect();
            ordered.sort_unstable_by_key(|(key, _)| *key);
            let mut sorted = serde_json::Map::new();
            for (key, value) in ordered {
                sorted.insert(key.clone(), sorted_json_value(value));
            }
            Value::Object(sorted)
        }
        scalar => scalar.clone(),
    }
}

fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, OpenPackError> {
    serde_json::to_vec(&sorted_json_value(value))
        .map_err(|error| OpenPackError::integrity(format!("serialize canonical JSON: {error}")))
}

fn request_cache_root(base: &Path, request: &PackRequest) -> Result<PathBuf, OpenPackError> {
    if request.repository == REPOSITORY_URL && request.inventory.is_none() {
        Ok(base.to_path_buf())
    } else {
        Ok(base.join("sources").join(source_identity(request)?))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct EngineProfile {
    build_identity: String,
    capabilities: Vec<String>,
    capability_contract_version: u32,
    engine_version: String,
    model_set_sha256: String,
    schemas: SchemaSet,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SchemaSet {
    policy_document: Vec<u32>,
    rql: Vec<u32>,
    builtin_catalog: Vec<u32>,
    policy_bundle: Vec<u32>,
    semantic_model_read: Vec<u32>,
    semantic_model_write: Vec<u32>,
    semantic_spec: Vec<u32>,
    release_index: Vec<u32>,
    runtime: Vec<u32>,
}

impl SchemaSet {
    fn axes(&self) -> [(&'static str, &[u32]); 9] {
        [
            ("policy_document", &self.policy_document),
            ("rql", &self.rql),
            ("builtin_catalog", &self.builtin_catalog),
            ("policy_bundle", &self.policy_bundle),
            ("semantic_model_read", &self.semantic_model_read),
            ("semantic_model_write", &self.semantic_model_write),
            ("semantic_spec", &self.semantic_spec),
            ("release_index", &self.release_index),
            ("runtime", &self.runtime),
        ]
    }

    fn validate(&self, label: &str) -> Result<(), OpenPackError> {
        for (axis, versions) in self.axes() {
            ensure_unique(versions, &format!("{label}.{axis}"))?;
            if versions.contains(&0) {
                return Err(OpenPackError::manifest(format!(
                    "{label}.{axis} contains schema version zero"
                )));
            }
        }
        Ok(())
    }

    fn supports(&self, required: &Self) -> bool {
        self.axes().into_iter().all(|(axis, supported)| {
            let required = required
                .axes()
                .into_iter()
                .find_map(|(name, values)| (name == axis).then_some(values))
                .expect("schema axes have identical names");
            required.iter().all(|version| supported.contains(version))
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Capabilities {
    contract_version: u32,
    required: Vec<String>,
    provided: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PackIdentity {
    id: String,
    repository: String,
    visibility: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReleaseSource {
    repository: String,
    commit: String,
    dirty: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ContentOrigin {
    repository: String,
    commit: String,
    #[serde(default)]
    lock_sha256: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReleaseContent {
    kind: ContentKind,
    identity: String,
    path: String,
    sha256: String,
    languages: Vec<String>,
    dependencies: Vec<String>,
    schemas: SchemaSet,
    required_capabilities: Vec<String>,
    #[serde(default)]
    license: Option<String>,
    #[serde(default)]
    authored_hash: Option<String>,
    #[serde(default)]
    resolved_semantic_hash: Option<String>,
    #[serde(default)]
    case_ids: Option<Vec<String>>,
    #[serde(default)]
    content_version: Option<String>,
    #[serde(default)]
    completeness: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum ContentKind {
    PolicyPack,
    Policy,
    SemanticModel,
    SemanticSpec,
    PolicyBundle,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReleaseArtifact {
    name: String,
    sha256: String,
    size_bytes: u64,
    format: String,
    role: ArtifactRole,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum ArtifactRole {
    Source,
    Native,
    Policy,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReleaseDependency {
    pack_id: String,
    release_version: String,
    repository: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct EngineRange {
    min_inclusive: String,
    max_exclusive: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompatibilityV1 {
    engine: EngineRange,
    schemas: SchemaSet,
    capabilities: Capabilities,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompatibilityV2 {
    schemas: SchemaSet,
    capabilities: Capabilities,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct QualificationV1 {
    status: String,
    evidence: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct QualificationStateV2 {
    status: String,
    evidence: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct QualificationV2 {
    integrity: QualificationStateV2,
    behavior: QualificationStateV2,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackReleaseV1 {
    manifest_schema_version: u8,
    pack: PackIdentity,
    release_version: String,
    source: ReleaseSource,
    #[serde(default)]
    content_origin: Option<ContentOrigin>,
    compatibility: CompatibilityV1,
    contents: Vec<ReleaseContent>,
    artifacts: Vec<ReleaseArtifact>,
    qualification: QualificationV1,
    #[serde(default)]
    release_dependencies: Vec<ReleaseDependency>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct EngineProvenance {
    #[serde(default)]
    engine_version: Option<String>,
    #[serde(default)]
    build_identity: Option<String>,
    #[serde(default)]
    source_commit: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Provenance {
    #[serde(default)]
    engine_version: Option<String>,
    #[serde(default)]
    build_identity: Option<String>,
    #[serde(default)]
    source_commit: Option<String>,
    #[serde(default)]
    testing: Option<Vec<EngineProvenance>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackReleaseV2 {
    manifest_schema_version: u8,
    pack: PackIdentity,
    release_version: String,
    source: ReleaseSource,
    #[serde(default)]
    content_origin: Option<ContentOrigin>,
    compatibility: CompatibilityV2,
    contents: Vec<ReleaseContent>,
    artifacts: Vec<ReleaseArtifact>,
    qualification: QualificationV2,
    release_dependencies: Vec<ReleaseDependency>,
    #[serde(default)]
    provenance: Option<Provenance>,
}

#[derive(Debug, Clone)]
struct PackRelease {
    schema_version: u8,
    pack: PackIdentity,
    release_version: String,
    source: ReleaseSource,
    content_origin: Option<ContentOrigin>,
    compatibility_schemas: SchemaSet,
    capabilities: Capabilities,
    engine_range: Option<EngineRange>,
    contents: Vec<ReleaseContent>,
    artifacts: Vec<ReleaseArtifact>,
    qualification: Value,
    qualification_v1: Option<QualificationV1>,
    qualification_v2: Option<QualificationV2>,
    release_dependencies: Vec<ReleaseDependency>,
    provenance: Option<Provenance>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AssetRecord {
    url: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CachedReleaseRecord {
    tag: String,
    tag_commit: String,
    prerelease: bool,
    manifest_sha256: String,
    #[serde(default)]
    manifest_url: Option<String>,
    assets: BTreeMap<String, AssetRecord>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManifestIndex {
    schema_version: u32,
    fetched_at: String,
    #[serde(default)]
    source: Option<PackSource>,
    releases: Vec<CachedReleaseRecord>,
}

#[derive(Debug, Clone)]
struct ReleaseRecord {
    cached: CachedReleaseRecord,
    manifest: PackRelease,
    raw_manifest: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ExtractedFile {
    path: String,
    size_bytes: u64,
    sha256: String,
}

#[derive(Debug, Clone)]
struct CachedArtifact {
    release_index: usize,
    artifact: ReleaseArtifact,
    path: PathBuf,
}

struct SelectionContext<'a> {
    profile: &'a EngineProfile,
    request: &'a PackRequest,
    inventory: &'a Inventory,
    root_index: usize,
    dependency_indices: &'a [usize],
    selection_id: &'a str,
    selection_reason: &'a str,
    rejections: &'a [Value],
    cached_artifacts: &'a [CachedArtifact],
    extracted_files: &'a BTreeMap<String, Vec<ExtractedFile>>,
}

trait HttpTransport {
    fn fetch(&self, url: &str, max_bytes: u64) -> Result<Vec<u8>, TransportError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportErrorKind {
    Network,
    Http,
    Redirect,
    TooLarge,
}

#[derive(Debug, Clone)]
struct TransportError {
    status: Option<u16>,
    kind: TransportErrorKind,
    rate_limited: bool,
    message: String,
}

impl TransportError {
    fn unavailable(message: impl Into<String>) -> Self {
        Self {
            status: None,
            kind: TransportErrorKind::Network,
            rate_limited: false,
            message: message.into(),
        }
    }

    fn http_status(
        status: u16,
        authenticated_request: bool,
        headers: &ureq::http::HeaderMap,
    ) -> Self {
        let rate_limited = status == 429
            || (status == 403
                && (!authenticated_request
                    || headers
                        .get("x-ratelimit-remaining")
                        .and_then(|value| value.to_str().ok())
                        .is_some_and(|remaining| remaining.trim() == "0")
                    || headers.contains_key("retry-after")));
        Self {
            status: Some(status),
            kind: TransportErrorKind::Http,
            rate_limited,
            message: format!("HTTP {status}"),
        }
    }

    fn redirect() -> Self {
        Self {
            status: None,
            kind: TransportErrorKind::Redirect,
            rate_limited: false,
            message: "pack source redirect crossed the trusted source boundary".to_owned(),
        }
    }
}

struct UreqTransport {
    agent: ureq::Agent,
    source: Option<PackSource>,
    token: Option<String>,
}

impl UreqTransport {
    fn new(source: Option<PackSource>, token: Option<String>) -> Self {
        let config = ureq::Agent::config_builder()
            .https_only(true)
            .http_status_as_error(false)
            .max_redirects(0)
            .max_redirects_will_error(false)
            .timeout_global(Some(REQUEST_TIMEOUT))
            .user_agent(concat!(
                "Bifrost-Open-Pack-Acquisition/",
                env!("CARGO_PKG_VERSION")
            ))
            .build();
        Self {
            agent: ureq::Agent::new_with_config(config),
            source,
            token,
        }
    }

    fn authorized_api_url(&self, url: &str) -> bool {
        let Some(source) = &self.source else {
            return false;
        };
        if source.inventory_url.is_some() {
            return false;
        }
        let Ok(repository) = safe_https_url(&source.repository) else {
            return false;
        };
        url.starts_with(&format!("https://api.github.com/repos{}/", repository.path))
    }

    fn authorization_header_for_url(&self, url: &str) -> Option<String> {
        self.authorized_api_url(url)
            .then_some(self.token.as_ref())
            .flatten()
            .map(|token| format!("Bearer {token}"))
    }
}

impl HttpTransport for UreqTransport {
    fn fetch(&self, url: &str, max_bytes: u64) -> Result<Vec<u8>, TransportError> {
        let mut current = url.to_owned();
        for redirect_count in 0..=MAX_REDIRECTS {
            let mut request = self.agent.get(&current);
            let api_asset = current.starts_with("https://api.github.com/repos")
                && current.contains("/releases/assets/");
            request = request
                .header(
                    "Accept",
                    if api_asset {
                        "application/octet-stream"
                    } else {
                        "application/vnd.github+json"
                    },
                )
                .header("X-GitHub-Api-Version", "2022-11-28");
            let authorization = self.authorization_header_for_url(&current);
            let authenticated_request = authorization.is_some();
            if let Some(authorization) = authorization {
                request = request.header("Authorization", &authorization);
            }
            let mut response = request
                .call()
                .map_err(|_| TransportError::unavailable("pack source network request failed"))?;
            let status = response.status().as_u16();
            if matches!(status, 301 | 302 | 303 | 307 | 308) {
                if redirect_count == 5 {
                    return Err(TransportError::redirect());
                }
                let location = response
                    .headers()
                    .get("location")
                    .and_then(|value| value.to_str().ok())
                    .ok_or_else(TransportError::redirect)?;
                let next =
                    resolve_redirect(&current, location).ok_or_else(TransportError::redirect)?;
                if !trusted_redirect(url, &current, &next, self.source.as_ref()) {
                    return Err(TransportError::redirect());
                }
                current = next;
                continue;
            }
            if !(200..300).contains(&status) {
                return Err(TransportError::http_status(
                    status,
                    authenticated_request,
                    response.headers(),
                ));
            }
            let mut bytes = response
                .body_mut()
                .with_config()
                .limit(max_bytes)
                .read_to_vec()
                .map_err(|_| {
                    TransportError::unavailable("pack source response could not be read")
                })?;
            if bytes.len() as u64 > max_bytes {
                return Err(TransportError {
                    status: None,
                    kind: TransportErrorKind::TooLarge,
                    rate_limited: false,
                    message: "pack source response exceeded its size limit".to_owned(),
                });
            }
            return Ok(std::mem::take(&mut bytes));
        }
        Err(TransportError::redirect())
    }
}

fn resolve_redirect(current: &str, location: &str) -> Option<String> {
    if location.contains('#') {
        return None;
    }
    if location.starts_with("https://") {
        return Some(location.to_owned());
    }
    let base = current.strip_prefix("https://")?;
    let (authority, path) = base.split_once('/')?;
    if location.starts_with("//") {
        return Some(format!("https:{location}"));
    }
    if location.starts_with('/') {
        return Some(format!("https://{authority}{location}"));
    }
    let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
    Some(format!("https://{authority}/{parent}/{location}"))
}

fn trusted_redirect(initial: &str, current: &str, next: &str, source: Option<&PackSource>) -> bool {
    let Some((origin, _path, has_query)) = https_parts(next) else {
        return false;
    };
    if let Some(source) = source
        && let Some(inventory_url) = &source.inventory_url
    {
        let Ok(trusted) = safe_https_url(inventory_url) else {
            return false;
        };
        return origin == trusted.origin && !has_query;
    }
    let repository_path = source
        .and_then(|source| safe_https_url(&source.repository).ok())
        .map_or_else(
            || "/BrokkAi/bifrost-packs".to_owned(),
            |repository| repository.path,
        );
    let release_download = https_parts(initial).is_some_and(|(initial_origin, initial_path, _)| {
        initial_origin == "https://github.com"
            && initial_path.starts_with(&format!("{repository_path}/releases/download/"))
    });
    let github_asset = matches!(
        origin.as_str(),
        "https://release-assets.githubusercontent.com" | "https://objects.githubusercontent.com"
    );
    let api_asset = https_parts(current).is_some_and(|(origin, path, _)| {
        origin == "https://api.github.com" && path.contains("/releases/assets/")
    });
    (release_download || api_asset) && github_asset
}

fn https_parts(value: &str) -> Option<(String, String, bool)> {
    let uri = value.parse::<ureq::http::Uri>().ok()?;
    let authority = uri.authority()?;
    if uri.scheme_str() != Some("https")
        || authority.as_str().contains('@')
        || authority.port_u16().is_some()
        || authority.as_str() != authority.host()
    {
        return None;
    }
    let path_and_query = uri.path_and_query();
    Some((
        format!("https://{}", authority.host().to_ascii_lowercase()),
        path_and_query.map_or_else(|| "/".to_owned(), |value| value.path().to_owned()),
        path_and_query.is_some_and(|value| value.query().is_some()),
    ))
}

/// Select and verify open packs using the engine profile created in-process.
/// The binary sets the returned paths for the existing activation code.
pub fn prepare_open_packs(engine_profile: &Value) -> Result<OpenPackSelection, OpenPackError> {
    prepare_open_packs_at(engine_profile, None)
}

/// Select and verify open packs beneath an explicit cache root. CI uses the
/// same binary entry point with a job-owned cache directory.
pub fn prepare_open_packs_at(
    engine_profile: &Value,
    cache_root: Option<&Path>,
) -> Result<OpenPackSelection, OpenPackError> {
    let request = default_pack_request()?;
    prepare_pack_request_at(engine_profile, &request, cache_root)
}

/// Select and verify exactly the request supplied by a caller.
pub fn prepare_pack_request_at(
    engine_profile: &Value,
    request: &PackRequest,
    cache_root: Option<&Path>,
) -> Result<OpenPackSelection, OpenPackError> {
    if env_flag("BIFROST_OPEN_PACKS_DISABLE") {
        return Err(OpenPackError::Configuration(
            "open-pack acquisition is disabled by BIFROST_OPEN_PACKS_DISABLE".to_owned(),
        ));
    }
    let request = validate_pack_request(request.clone())?;
    let profile = parse_engine_profile(engine_profile)?;
    let offline = open_packs_offline_from_environment();
    let refresh = env_flag("BIFROST_OPEN_PACKS_REFRESH");
    if offline && refresh {
        return Err(OpenPackError::Configuration(
            "BIFROST_OPEN_PACKS_OFFLINE and BIFROST_OPEN_PACKS_REFRESH cannot both be enabled"
                .to_owned(),
        ));
    }
    let token = std::env::var("PACK_TOKEN")
        .ok()
        .filter(|token| !token.is_empty());
    validate_token(token.as_deref())?;
    if token.is_some() && request.inventory.is_some() {
        return Err(OpenPackError::InvalidSource(
            "PACK_TOKEN cannot be used with a trusted HTTPS inventory mirror".to_owned(),
        ));
    }
    let source = request_source(&request);
    let transport = UreqTransport::new(Some(source.clone()), token);
    let root = cache_root
        .map(Path::to_path_buf)
        .map_or_else(default_cache_root, Ok)?;
    prepare_with_request(
        &root,
        &profile,
        &request,
        offline,
        refresh,
        Some(&source),
        &transport,
    )
}

/// Select verified open packs for scan and server bootstrap. Public discovery
/// may use stale verified inventory when the network is unavailable; soft
/// selection outcomes leave activation on the embedded packs. Explicit-source
/// errors remain hard failures.
pub fn prepare_open_packs_for_runtime(
    engine_profile: &Value,
) -> Result<OpenPackRuntimeOutcome, OpenPackError> {
    if env_flag("BIFROST_OPEN_PACKS_DISABLE") {
        return Ok(OpenPackRuntimeOutcome::EmbeddedFallback {
            kind: OpenPackFallbackKind::Disabled,
            message: "open-pack acquisition is disabled".to_owned(),
        });
    }
    let profile = parse_engine_profile(engine_profile)?;
    let legacy_source = source_from_environment()?;
    let request = default_pack_request()?;
    let source = request_source(&request);
    let token = std::env::var("PACK_TOKEN")
        .ok()
        .filter(|token| !token.is_empty());
    validate_token(token.as_deref())?;
    if token.is_some() && (legacy_source.is_none() || request.inventory.is_some()) {
        return Err(OpenPackError::InvalidSource(
            "PACK_TOKEN requires an explicit GitHub repository source".to_owned(),
        ));
    }
    let transport = UreqTransport::new(Some(source.clone()), token);
    let offline = open_packs_offline_from_environment();
    let refresh = env_flag("BIFROST_OPEN_PACKS_REFRESH");
    if offline && refresh {
        return Err(OpenPackError::Configuration(
            "BIFROST_OPEN_PACKS_OFFLINE and BIFROST_OPEN_PACKS_REFRESH cannot both be enabled"
                .to_owned(),
        ));
    }
    let root = default_cache_root()?;
    prepare_runtime_with_request(
        &root,
        &profile,
        &request,
        offline,
        refresh,
        Some(&source),
        &transport,
        legacy_source.as_ref(),
    )
}

fn validate_token(token: Option<&str>) -> Result<(), OpenPackError> {
    if token.is_some_and(|token| token.bytes().any(|byte| byte.is_ascii_control())) {
        return Err(OpenPackError::InvalidSource(
            "PACK_TOKEN contains unsupported characters".to_owned(),
        ));
    }
    Ok(())
}

fn open_packs_offline_from_environment() -> bool {
    env_flag("BIFROST_OPEN_PACKS_OFFLINE")
        || std::env::var("BIFROST_LAUNCHER_AUTO_INSTALL").as_deref() == Ok("0")
}

/// Return the profile and source identity used to isolate a caller's cache.
/// This does not read PACK_TOKEN or perform network access.
pub fn open_packs_cache_identity(
    engine_profile: &Value,
    cache_root: &Path,
) -> Result<Value, OpenPackError> {
    parse_engine_profile(engine_profile)?;
    let request = default_pack_request()?;
    Ok(json!({
        "identity": source_identity(&request)?,
        "cache_dir": resolve_absolute(cache_root.to_path_buf())?,
    }))
}

fn parse_engine_profile(value: &Value) -> Result<EngineProfile, OpenPackError> {
    let profile = serde_json::from_value::<EngineProfile>(value.clone()).map_err(|error| {
        OpenPackError::InvalidProfile(format!("engine pack profile has an invalid shape: {error}"))
    })?;
    Version::parse(&profile.engine_version).map_err(|error| {
        OpenPackError::InvalidProfile(format!("engine version is not valid SemVer: {error}"))
    })?;
    if profile.build_identity.is_empty()
        || !is_sha256(&profile.model_set_sha256)
        || profile.capability_contract_version == 0
    {
        return Err(OpenPackError::InvalidProfile(
            "engine build, model, or capability contract identity is invalid".to_owned(),
        ));
    }
    profile
        .schemas
        .validate("engine_profile.schemas")
        .map_err(|error| OpenPackError::InvalidProfile(error.to_string()))?;
    validate_string_set(&profile.capabilities, "engine_profile.capabilities")
        .map_err(|error| OpenPackError::InvalidProfile(error.to_string()))?;
    Ok(profile)
}

fn env_flag(name: &str) -> bool {
    matches!(std::env::var(name).as_deref(), Ok("1" | "true"))
}

fn default_cache_root() -> Result<PathBuf, OpenPackError> {
    let base = match std::env::var_os("BIFROST_LAUNCHER_CACHE_DIR") {
        Some(value) if !value.to_string_lossy().trim().is_empty() => {
            resolve_absolute(PathBuf::from(value))?
        }
        _ => platform_cache_base()?,
    };
    Ok(base.join(CACHE_DIRECTORY))
}

fn platform_cache_base() -> Result<PathBuf, OpenPackError> {
    #[cfg(target_os = "macos")]
    let value = std::env::var_os("HOME").map(PathBuf::from).map(|home| {
        home.join("Library")
            .join("Caches")
            .join(CACHE_AGENT_DIRECTORY)
    });
    #[cfg(target_os = "windows")]
    let value = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| PathBuf::from(home).join("AppData").join("Local"))
        })
        .map(|root| root.join("Bifrost").join("AgentPlugin"));
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let value = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .map(|root| root.join(CACHE_AGENT_DIRECTORY));
    value
        .map(resolve_absolute)
        .transpose()?
        .ok_or_else(|| OpenPackError::Configuration("cannot determine a cache directory".into()))
}

fn resolve_absolute(path: PathBuf) -> Result<PathBuf, OpenPackError> {
    if path.is_absolute() {
        Ok(path)
    } else {
        std::env::current_dir()
            .map(|current| current.join(path))
            .map_err(|error| {
                OpenPackError::Configuration(format!("resolve cache directory: {error}"))
            })
    }
}

#[derive(Clone)]
struct Inventory {
    fetched_at: String,
    fetched_at_ms: i64,
    fetched_online: bool,
    inventory_sha256: String,
    releases: Vec<ReleaseRecord>,
}

#[cfg(test)]
fn prepare_with_transport(
    cache_root: &Path,
    profile: &EngineProfile,
    offline: bool,
    refresh: bool,
    transport: &dyn HttpTransport,
) -> Result<OpenPackSelection, OpenPackError> {
    let request = default_preferred_request();
    let source = request_source(&request);
    prepare_with_request(
        cache_root,
        profile,
        &request,
        offline,
        refresh,
        Some(&source),
        transport,
    )
}

#[cfg(test)]
fn prepare_with_source(
    cache_root: &Path,
    profile: &EngineProfile,
    source: Option<&LegacyPackSource>,
    offline: bool,
    refresh: bool,
    transport: &dyn HttpTransport,
) -> Result<OpenPackSelection, OpenPackError> {
    let request = source.map_or_else(default_preferred_request, legacy_source_request);
    let source_config = request_source(&request);
    prepare_with_request(
        cache_root,
        profile,
        &request,
        offline,
        refresh,
        Some(&source_config),
        transport,
    )
}

#[cfg(test)]
fn legacy_source_request(source: &LegacyPackSource) -> PackRequest {
    PackRequest {
        request_schema_version: 1,
        pack_id: RULES_PACK_ID.to_owned(),
        repository: source.repository.clone(),
        inventory: source
            .inventory_url
            .clone()
            .zip(source.inventory_sha256.clone())
            .map(|(url, sha256)| PackInventoryPin { url, sha256 }),
        selection: PackSelection::Strict {
            release_version: source.rules_version.clone(),
            manifest_sha256: source.manifest_sha256.clone(),
        },
        dependencies: vec![PackDependencyPin {
            pack_id: SEMANTIC_PACK_ID.to_owned(),
            repository: source.repository.clone(),
            release_version: None,
            manifest_sha256: source.semantic_manifest_sha256.clone(),
        }],
    }
}

fn prepare_with_request(
    cache_root: &Path,
    profile: &EngineProfile,
    request: &PackRequest,
    offline: bool,
    refresh: bool,
    source: Option<&PackSource>,
    transport: &dyn HttpTransport,
) -> Result<OpenPackSelection, OpenPackError> {
    if offline && refresh {
        return Err(OpenPackError::Configuration(
            "offline and refresh cannot both be enabled".to_owned(),
        ));
    }
    let base = resolve_absolute(cache_root.to_path_buf())?;
    let root = request_cache_root(&base, request)?;
    fs::create_dir_all(&root).map_err(|error| {
        OpenPackError::Integrity(format!("create open-pack cache directory: {error}"))
    })?;
    let inventory = load_or_discover_inventory(&root, source, transport, offline, refresh)?;
    let selected = select_pack_request(&inventory, profile, request)?;
    prepare_selected_set(
        &root, inventory, profile, request, source, offline, transport, selected,
    )
}

#[cfg(test)]
fn prepare_runtime_with_transport(
    cache_root: &Path,
    profile: &EngineProfile,
    offline: bool,
    refresh: bool,
    transport: &dyn HttpTransport,
) -> Result<OpenPackRuntimeOutcome, OpenPackError> {
    let request = default_preferred_request();
    let source = request_source(&request);
    prepare_runtime_with_request(
        cache_root,
        profile,
        &request,
        offline,
        refresh,
        Some(&source),
        transport,
        None,
    )
}

#[cfg(test)]
fn prepare_runtime_with_source(
    cache_root: &Path,
    profile: &EngineProfile,
    source: Option<&LegacyPackSource>,
    offline: bool,
    refresh: bool,
    transport: &dyn HttpTransport,
) -> Result<OpenPackRuntimeOutcome, OpenPackError> {
    let request = source.map_or_else(default_preferred_request, legacy_source_request);
    let source_config = request_source(&request);
    prepare_runtime_with_request(
        cache_root,
        profile,
        &request,
        offline,
        refresh,
        Some(&source_config),
        transport,
        source,
    )
}

#[allow(clippy::too_many_arguments)]
fn prepare_runtime_with_request(
    cache_root: &Path,
    profile: &EngineProfile,
    request: &PackRequest,
    offline: bool,
    refresh: bool,
    source: Option<&PackSource>,
    transport: &dyn HttpTransport,
    explicit_source: Option<&LegacyPackSource>,
) -> Result<OpenPackRuntimeOutcome, OpenPackError> {
    if offline && refresh {
        return Err(OpenPackError::Configuration(
            "offline and refresh cannot both be enabled".to_owned(),
        ));
    }
    let base = resolve_absolute(cache_root.to_path_buf())?;
    let root = request_cache_root(&base, request)?;
    fs::create_dir_all(&root).map_err(|error| {
        OpenPackError::Integrity(format!("create open-pack cache directory: {error}"))
    })?;

    let result = (|| {
        let allow_stale_public_inventory = explicit_source.is_none()
            && request.repository == REPOSITORY_URL
            && request.inventory.is_none();
        let inventory = load_or_discover_inventory_for_runtime(
            &root,
            source,
            transport,
            offline,
            refresh,
            allow_stale_public_inventory,
        )?;
        let selected = select_pack_request(&inventory, profile, request)?;
        prepare_selected_set(
            &root, inventory, profile, request, source, offline, transport, selected,
        )
    })();

    match result {
        Ok(selection) => Ok(OpenPackRuntimeOutcome::Selected(Box::new(selection))),
        Err(error) => runtime_fallback(error, explicit_source),
    }
}

fn runtime_fallback(
    error: OpenPackError,
    source: Option<&LegacyPackSource>,
) -> Result<OpenPackRuntimeOutcome, OpenPackError> {
    if source.is_some() {
        return Err(error);
    }
    let error = match error {
        OpenPackError::SelectionRejected { error, .. } => *error,
        error => error,
    };
    let (kind, message) = match error {
        OpenPackError::NoCompatibleRelease { message, .. } => {
            (OpenPackFallbackKind::NoCompatibleRelease, message)
        }
        OpenPackError::Pending(message) => (OpenPackFallbackKind::Pending, message),
        OpenPackError::IncompatibleSelection(message) => {
            (OpenPackFallbackKind::Unsupported, message)
        }
        OpenPackError::Network(message) => (OpenPackFallbackKind::NetworkUnavailable, message),
        OpenPackError::OfflineCacheMiss(message) => {
            (OpenPackFallbackKind::OfflineCacheMiss, message)
        }
        OpenPackError::Unavailable(message) | OpenPackError::UnverifiedAbsence(message) => {
            (OpenPackFallbackKind::NoCompatibleRelease, message)
        }
        error => return Err(error),
    };
    Ok(OpenPackRuntimeOutcome::EmbeddedFallback { kind, message })
}

#[allow(clippy::too_many_arguments)]
fn prepare_selected_set(
    root: &Path,
    inventory: Inventory,
    profile: &EngineProfile,
    request: &PackRequest,
    source: Option<&PackSource>,
    offline: bool,
    transport: &dyn HttpTransport,
    selected: SelectedSet,
) -> Result<OpenPackSelection, OpenPackError> {
    let root_index = selected.root_index;
    let mut release_indices = Vec::with_capacity(selected.dependency_indices.len() + 1);
    release_indices.push(root_index);
    release_indices.extend(selected.dependency_indices.iter().copied());
    let root_release = &inventory.releases[root_index];
    validate_rules_source_contents(&root_release.manifest)?;
    let content_artifacts = release_indices
        .iter()
        .map(|index| {
            let release = &inventory.releases[*index];
            Ok((
                *index,
                content_artifact(&release.manifest, *index == root_index)?.clone(),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, OpenPackError>>()?;
    let mut cached_artifacts = Vec::new();
    for release_index in release_indices.iter().copied() {
        let release = &inventory.releases[release_index];
        for artifact in &release.manifest.artifacts {
            let asset = release.cached.assets.get(&artifact.name).ok_or_else(|| {
                OpenPackError::integrity(format!(
                    "release {} is missing declared asset {}",
                    release.cached.tag, artifact.name
                ))
            })?;
            let artifact_path = cache_artifact(root, artifact, asset, source, offline, transport)?;
            cached_artifacts.push(CachedArtifact {
                release_index,
                artifact: artifact.clone(),
                path: artifact_path,
            });
        }
    }
    let selection_id = selection_id(profile, request, &inventory, &release_indices)?;
    let selections_root = root.join("selections");
    fs::create_dir_all(&selections_root).map_err(|error| {
        OpenPackError::integrity(format!(
            "create open-pack selections directory {}: {error}",
            selections_root.display()
        ))
    })?;
    let final_root = selections_root.join(&selection_id);
    let receipt_path = final_root.join("receipt.json");
    let mut extracted_files = BTreeMap::<String, Vec<ExtractedFile>>::new();
    for release_index in &release_indices {
        let release = &inventory.releases[*release_index];
        let label = if *release_index == root_index {
            "root".to_owned()
        } else {
            format!("dependency-{}", release.manifest.pack.id)
        };
        let archive = cached_artifact_for(
            &cached_artifacts,
            *release_index,
            &content_artifacts[release_index],
        )?;
        extracted_files.insert(
            label,
            inspect_archive_format(&archive.path, &archive.artifact.format, None)?,
        );
    }
    let context = SelectionContext {
        profile,
        request,
        inventory: &inventory,
        root_index,
        dependency_indices: &selected.dependency_indices,
        selection_id: &selection_id,
        selection_reason: selected.selection_reason,
        rejections: &selected.rejections,
        cached_artifacts: &cached_artifacts,
        extracted_files: &extracted_files,
    };
    if path_exists(&final_root)? {
        let selection = context;
        verify_existing_selection(&final_root, &receipt_path, &selection)?;
        return Ok(selection_result(
            root,
            final_root,
            receipt_path,
            &selection_id,
            true,
            &selected,
            &inventory,
        ));
    }

    let stage = TempDirBuilder::new()
        .prefix(&format!(".stage-{selection_id}-"))
        .tempdir_in(&selections_root)
        .map_err(|error| {
            OpenPackError::integrity(format!("create open-pack staging directory: {error}"))
        })?;
    let mut staged_files = BTreeMap::<String, Vec<ExtractedFile>>::new();
    for release_index in &release_indices {
        let release = &inventory.releases[*release_index];
        let label = if *release_index == root_index {
            "root".to_owned()
        } else {
            format!("dependency-{}", release.manifest.pack.id)
        };
        let archive = cached_artifact_for(
            &cached_artifacts,
            *release_index,
            &content_artifacts[release_index],
        )?;
        let destination = stage.path().join(&label);
        fs::create_dir(&destination).map_err(|error| {
            OpenPackError::integrity(format!("create extraction root {label}: {error}"))
        })?;
        let files =
            inspect_archive_format(&archive.path, &archive.artifact.format, Some(&destination))?;
        verify_manifest_contents(&release.manifest, &destination)?;
        if *release_index == root_index {
            if files.iter().any(|file| !file.path.starts_with("rules/")) {
                return Err(OpenPackError::integrity(
                    "root policy archive contains files outside rules/",
                ));
            }
            require_real_directory(&destination.join("rules"), "policy pack root")?;
        } else if has_native_artifact(&release.manifest) {
            require_regular_file(
                &destination
                    .join("bifrost-semantic-packs")
                    .join("index.json"),
                "native semantic bundle index",
            )?;
        }
        staged_files.insert(label, files);
    }

    let staged_receipt_path = stage.path().join("receipt.json");
    let selection = SelectionContext {
        profile,
        request,
        inventory: &inventory,
        root_index,
        dependency_indices: &selected.dependency_indices,
        selection_id: &selection_id,
        selection_reason: selected.selection_reason,
        rejections: &selected.rejections,
        cached_artifacts: &cached_artifacts,
        extracted_files: &staged_files,
    };
    let receipt = build_receipt(&selection)?;
    write_atomic_replace(
        &staged_receipt_path,
        &serde_json::to_vec_pretty(&receipt).map_err(|error| {
            OpenPackError::integrity(format!("serialize open-pack receipt: {error}"))
        })?,
    )?;

    let staged_path = stage.keep();
    match fs::rename(&staged_path, &final_root) {
        Ok(()) => {}
        Err(error) if path_exists(&final_root)? => {
            fs::remove_dir_all(&staged_path).map_err(|cleanup| {
                OpenPackError::integrity(format!(
                    "remove losing open-pack staging directory {} after publish race ({error}): {cleanup}",
                    staged_path.display()
                ))
            })?;
            verify_existing_selection(&final_root, &receipt_path, &selection)?;
        }
        Err(error) => {
            let message = match fs::remove_dir_all(&staged_path) {
                Ok(()) => format!(
                    "publish verified open-pack selection {}: {error}",
                    final_root.display()
                ),
                Err(cleanup) => format!(
                    "publish verified open-pack selection {}: {error}; remove staging directory {}: {cleanup}",
                    final_root.display(),
                    staged_path.display()
                ),
            };
            return Err(OpenPackError::integrity(message));
        }
    }
    Ok(selection_result(
        root,
        final_root,
        receipt_path,
        &selection_id,
        false,
        &selected,
        &inventory,
    ))
}

fn content_artifact(manifest: &PackRelease, root: bool) -> Result<&ReleaseArtifact, OpenPackError> {
    let role = if root {
        if manifest.artifacts.iter().any(|artifact| {
            artifact.role == ArtifactRole::Policy && is_archive_format(&artifact.format)
        }) {
            ArtifactRole::Policy
        } else {
            ArtifactRole::Source
        }
    } else {
        ArtifactRole::Native
    };
    let mut matches = manifest
        .artifacts
        .iter()
        .filter(|artifact| artifact.role == role && is_archive_format(&artifact.format));
    let first = matches.next().ok_or_else(|| {
        OpenPackError::manifest(format!(
            "release {}@{} has no archive artifact for role {role:?}",
            manifest.pack.id, manifest.release_version
        ))
    })?;
    if matches.next().is_some() {
        return Err(OpenPackError::manifest(format!(
            "release {}@{} has multiple archive artifacts for role {role:?}",
            manifest.pack.id, manifest.release_version
        )));
    }
    Ok(first)
}

fn selection_result(
    root: &Path,
    selection_root: PathBuf,
    receipt_path: PathBuf,
    selection_id: &str,
    cache_reused: bool,
    selected: &SelectedSet,
    inventory: &Inventory,
) -> OpenPackSelection {
    let native_dependency = selected
        .dependency_indices
        .iter()
        .find(|index| has_native_artifact(&inventory.releases[**index].manifest))
        .map(|index| inventory.releases[*index].manifest.pack.id.as_str());
    OpenPackSelection {
        selection_id: selection_id.to_owned(),
        selection_reason: selected.selection_reason.to_owned(),
        rejections: selected.rejections.clone(),
        inventory: PackInventorySnapshot {
            index_sha256: inventory.inventory_sha256.clone(),
            fetched_at: inventory.fetched_at.clone(),
            fetched_online: inventory.fetched_online,
        },
        semantic_bundle_root: native_dependency.map(|pack_id| {
            selection_root.join(format!("dependency-{pack_id}/bifrost-semantic-packs"))
        }),
        policy_pack_root: selection_root.join("root/rules"),
        semantic_cache_root: root.join(CACHE_CATALOG_DIRECTORY),
        receipt_path,
        cache_reused,
    }
}

fn load_or_discover_inventory(
    root: &Path,
    source: Option<&PackSource>,
    transport: &dyn HttpTransport,
    offline: bool,
    refresh: bool,
) -> Result<Inventory, OpenPackError> {
    let index_path = root.join("manifest-index.json");
    let cached = if refresh {
        None
    } else {
        read_cached_inventory(root, &index_path, source)?
    };
    if let Some(inventory) = cached {
        let age = unix_millis().saturating_sub(inventory.fetched_at_ms);
        let fresh = age >= 0 && age < MANIFEST_CACHE_TTL.as_millis() as i64;
        if offline || fresh {
            let mut inventory = inventory;
            inventory.fetched_online = false;
            return Ok(inventory);
        }
    }
    if offline {
        return Err(OpenPackError::OfflineCacheMiss(
            "no verified open-pack manifest cache is available for offline selection".to_owned(),
        ));
    }

    discover_inventory(root, &index_path, source, transport)
}

fn load_or_discover_inventory_for_runtime(
    root: &Path,
    source: Option<&PackSource>,
    transport: &dyn HttpTransport,
    offline: bool,
    refresh: bool,
    allow_stale_public_inventory: bool,
) -> Result<Inventory, OpenPackError> {
    let index_path = root.join("manifest-index.json");
    let cached = if refresh {
        None
    } else {
        read_cached_inventory(root, &index_path, source)?
    };
    if let Some(inventory) = cached.as_ref() {
        let age = unix_millis().saturating_sub(inventory.fetched_at_ms);
        let fresh = age >= 0 && age < MANIFEST_CACHE_TTL.as_millis() as i64;
        if offline || fresh {
            return Ok(inventory.clone());
        }
    }
    if offline {
        return Err(OpenPackError::OfflineCacheMiss(
            "no verified open-pack manifest cache is available for offline selection".to_owned(),
        ));
    }

    match discover_inventory(root, &index_path, source, transport) {
        Ok(inventory) => Ok(inventory),
        Err(error)
            if allow_stale_public_inventory
                && !refresh
                && cached.is_some()
                && matches!(
                    &error,
                    OpenPackError::Network(_) | OpenPackError::Unavailable(_)
                ) =>
        {
            Ok(cached.expect("the guard requires a cached inventory"))
        }
        Err(error) => Err(error),
    }
}

fn read_cached_inventory(
    root: &Path,
    index_path: &Path,
    source: Option<&PackSource>,
) -> Result<Option<Inventory>, OpenPackError> {
    let bytes = match read_regular_file(index_path, MAX_API_PAGE_BYTES) {
        Ok(bytes) => bytes,
        Err(OpenPackError::Unavailable(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    let index = serde_json::from_slice::<ManifestIndex>(&bytes).map_err(|error| {
        OpenPackError::integrity(format!(
            "cached open-pack manifest index is corrupt: {error}"
        ))
    })?;
    if index.schema_version != INVENTORY_SCHEMA_VERSION || index.source.as_ref() != source {
        // A previous binary or a different configured source can leave a valid index
        // that does not apply to this request. Let the caller rediscover it.
        return Ok(None);
    }
    let fetched_at_ms = parse_iso_utc_millis(&index.fetched_at).ok_or_else(|| {
        OpenPackError::integrity("cached open-pack manifest index has an invalid timestamp")
    })?;
    let inventory_sha256 = inventory_snapshot_sha256(&index)?;
    let mut releases = Vec::with_capacity(index.releases.len());
    let mut tags = BTreeSet::new();
    for cached in index.releases {
        validate_cached_record(&cached, source)?;
        if !tags.insert(cached.tag.clone()) {
            return Err(OpenPackError::integrity(format!(
                "cached manifest index repeats release tag {}",
                cached.tag
            )));
        }
        let manifest_path = root
            .join("manifests")
            .join(format!("{}.json", cached.manifest_sha256));
        let manifest_bytes =
            read_regular_file(&manifest_path, MAX_MANIFEST_BYTES).map_err(|_| {
                OpenPackError::integrity(format!(
                    "cached release manifest is missing or unsafe for {}",
                    cached.tag
                ))
            })?;
        if sha256(&manifest_bytes) != cached.manifest_sha256 {
            return Err(OpenPackError::integrity(format!(
                "cached release manifest hash mismatch for {}",
                cached.tag
            )));
        }
        let (manifest, raw_manifest) =
            parse_release_manifest_for_source(&manifest_bytes, source)
                .map_err(|error| OpenPackError::integrity(error.to_string()))?;
        validate_release_binding(&cached, &manifest, source)
            .map_err(|error| OpenPackError::integrity(error.to_string()))?;
        releases.push(ReleaseRecord {
            cached,
            manifest,
            raw_manifest,
        });
    }
    assert_no_ambiguous_versions(&releases)?;
    Ok(Some(Inventory {
        fetched_at: index.fetched_at,
        fetched_at_ms,
        fetched_online: false,
        inventory_sha256,
        releases,
    }))
}

fn inventory_snapshot_sha256(index: &ManifestIndex) -> Result<String, OpenPackError> {
    let mut snapshot = index.clone();
    // The observation time changes on refresh; release records define the snapshot content.
    snapshot.fetched_at.clear();
    serde_json::to_vec(&snapshot)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| {
            OpenPackError::integrity(format!("serialize open-pack inventory snapshot: {error}"))
        })
}

fn discover_inventory(
    root: &Path,
    index_path: &Path,
    source: Option<&PackSource>,
    transport: &dyn HttpTransport,
) -> Result<Inventory, OpenPackError> {
    if source.is_some_and(|source| source.inventory_url.is_some()) {
        return discover_https_inventory(
            root,
            index_path,
            source.expect("source is present"),
            transport,
        );
    }
    let mut releases = Vec::new();
    let mut tags = BTreeSet::new();
    let api_releases = fetch_all_release_pages(transport, source)?;
    for api_release in &api_releases {
        let object = api_release.as_object().ok_or_else(|| {
            OpenPackError::manifest("GitHub release listing contains an invalid release record")
        })?;
        let tag = object
            .get("tag_name")
            .and_then(Value::as_str)
            .ok_or_else(|| OpenPackError::manifest("GitHub release is missing tag_name"))?;
        if object.get("draft").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let has_manifest_asset =
            object
                .get("assets")
                .and_then(Value::as_array)
                .is_some_and(|assets| {
                    assets.iter().any(|asset| {
                        asset.get("name").and_then(Value::as_str) == Some("pack-release.json")
                    })
                });
        if !has_manifest_asset {
            continue;
        }
        if !tags.insert(tag.to_owned()) {
            return Err(OpenPackError::integrity(format!(
                "GitHub release listing repeats tag {tag}"
            )));
        }
        let prerelease = object
            .get("prerelease")
            .and_then(Value::as_bool)
            .ok_or_else(|| {
                OpenPackError::manifest(format!("GitHub release {tag} has no prerelease flag"))
            })?;
        let api_assets = object
            .get("assets")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                OpenPackError::manifest(format!("GitHub release {tag} has no valid asset list"))
            })?;
        let mut assets = BTreeMap::new();
        for item in api_assets {
            let item = item.as_object().ok_or_else(|| {
                OpenPackError::manifest(format!("GitHub release {tag} has an invalid asset entry"))
            })?;
            let name = item
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty())
                .ok_or_else(|| {
                    OpenPackError::manifest(format!("GitHub release {tag} has an unnamed asset"))
                })?;
            let url = item
                .get("browser_download_url")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    OpenPackError::manifest(format!(
                        "GitHub release {tag} has an invalid asset URL"
                    ))
                })?;
            validate_asset_url(url, name, false, source)?;
            let cached_url = if let Some(source) = source {
                let id = item
                    .get("id")
                    .and_then(Value::as_u64)
                    .filter(|id| *id > 0)
                    .ok_or_else(|| {
                        OpenPackError::manifest(
                            "GitHub source release asset has no numeric asset ID",
                        )
                    })?;
                let repository = safe_https_url(&source.repository)?;
                format!(
                    "https://api.github.com/repos{}/releases/assets/{id}",
                    repository.path
                )
            } else {
                url.to_owned()
            };
            if assets
                .insert(name.to_owned(), AssetRecord { url: cached_url })
                .is_some()
            {
                return Err(OpenPackError::manifest(format!(
                    "GitHub release {tag} repeats asset {name}"
                )));
            }
        }
        let manifest_asset = assets.get("pack-release.json").ok_or_else(|| {
            OpenPackError::manifest(format!("GitHub release {tag} is missing pack-release.json"))
        })?;
        let manifest_bytes = fetch_bytes(transport, &manifest_asset.url, MAX_MANIFEST_BYTES)?;
        let (manifest, raw_manifest) = parse_release_manifest_for_source(&manifest_bytes, source)?;
        let expected_repository =
            source.map_or(REPOSITORY_URL, |source| source.repository.as_str());
        if manifest.pack.repository != expected_repository {
            return Err(OpenPackError::manifest(format!(
                "release {tag} has the wrong pack identity or repository"
            )));
        }
        let expected_tag = release_tag(&manifest.pack.id, &manifest.release_version);
        if tag != expected_tag {
            return Err(OpenPackError::integrity(format!(
                "release tag {tag} does not bind manifest version {}",
                manifest.release_version
            )));
        }
        let is_prerelease = !parse_semver(&manifest.release_version)?.pre.is_empty();
        if prerelease != is_prerelease {
            return Err(OpenPackError::integrity(format!(
                "GitHub prerelease flag does not match {tag}"
            )));
        }
        let tag_commit = resolve_tag_commit(tag, source, transport)?;
        let manifest_sha256 = sha256(&manifest_bytes);
        let cached = CachedReleaseRecord {
            tag: tag.to_owned(),
            tag_commit,
            prerelease,
            manifest_sha256,
            manifest_url: None,
            assets,
        };
        validate_release_binding(&cached, &manifest, source)?;
        let manifest_path = root
            .join("manifests")
            .join(format!("{}.json", cached.manifest_sha256));
        write_atomic_noclobber(&manifest_path, &manifest_bytes)?;
        releases.push(ReleaseRecord {
            cached,
            manifest,
            raw_manifest,
        });
    }
    // The listing order is not part of the snapshot: sort by tag so the index
    // digest identifies the release set, not the order GitHub returned it in.
    releases.sort_by(|left, right| left.cached.tag.cmp(&right.cached.tag));
    assert_no_ambiguous_versions(&releases)?;
    let fetched_at = format_iso_utc(SystemTime::now())?;
    let index = ManifestIndex {
        schema_version: INVENTORY_SCHEMA_VERSION,
        fetched_at: fetched_at.clone(),
        source: source.cloned(),
        releases: releases
            .iter()
            .map(|release| release.cached.clone())
            .collect(),
    };
    let index_bytes = serde_json::to_vec_pretty(&index).map_err(|error| {
        OpenPackError::integrity(format!("serialize open-pack manifest index: {error}"))
    })?;
    write_atomic_replace(index_path, &index_bytes)?;
    let inventory_sha256 = inventory_snapshot_sha256(&index)?;
    let fetched_at_ms =
        parse_iso_utc_millis(&fetched_at).expect("the generated UTC timestamp is valid");
    Ok(Inventory {
        fetched_at,
        fetched_at_ms,
        fetched_online: true,
        inventory_sha256,
        releases,
    })
}

fn discover_https_inventory(
    root: &Path,
    index_path: &Path,
    source: &PackSource,
    transport: &dyn HttpTransport,
) -> Result<Inventory, OpenPackError> {
    let inventory_url = source
        .inventory_url
        .as_deref()
        .expect("HTTPS inventory source has an inventory URL");
    let bytes = fetch_bytes(transport, inventory_url, MAX_API_PAGE_BYTES)?;
    let inventory_pin = sha256(&bytes);
    if Some(inventory_pin.as_str()) != source.inventory_sha256.as_deref() {
        return Err(OpenPackError::integrity(
            "HTTPS source inventory SHA-256 does not match its trusted pin",
        ));
    }
    let value = parse_json_value(&bytes)
        .map_err(|_| OpenPackError::manifest("HTTPS source inventory is invalid JSON"))?;
    let releases_value = value
        .get("releases")
        .and_then(Value::as_array)
        .filter(|_| value.get("schema_version").and_then(Value::as_u64) == Some(1))
        .ok_or_else(|| {
            OpenPackError::manifest("HTTPS source must serve a schema-1 manifest inventory")
        })?;
    let mut releases = Vec::with_capacity(releases_value.len());
    let mut tags = BTreeSet::new();
    for value in releases_value {
        let cached =
            serde_json::from_value::<CachedReleaseRecord>(value.clone()).map_err(|_| {
                OpenPackError::manifest("HTTPS source inventory has an invalid release record")
            })?;
        if !tags.insert(cached.tag.clone()) {
            return Err(OpenPackError::manifest(
                "HTTPS source inventory repeats a release tag",
            ));
        }
        validate_cached_record(&cached, Some(source))
            .map_err(|error| OpenPackError::manifest(error.to_string()))?;
        let manifest_url = cached.manifest_url.as_deref().ok_or_else(|| {
            OpenPackError::manifest("HTTPS source inventory is missing a descriptor URL")
        })?;
        let manifest_bytes = fetch_bytes(transport, manifest_url, MAX_MANIFEST_BYTES)?;
        if sha256(&manifest_bytes) != cached.manifest_sha256 {
            return Err(OpenPackError::integrity(
                "HTTPS release descriptor SHA-256 does not match its inventory pin",
            ));
        }
        let (manifest, raw_manifest) =
            parse_release_manifest_for_source(&manifest_bytes, Some(source))?;
        validate_release_binding(&cached, &manifest, Some(source))?;
        let manifest_path = root
            .join("manifests")
            .join(format!("{}.json", cached.manifest_sha256));
        write_atomic_noclobber(&manifest_path, &manifest_bytes)?;
        releases.push(ReleaseRecord {
            cached,
            manifest,
            raw_manifest,
        });
    }
    // The listing order is not part of the snapshot: sort by tag so the index
    // digest identifies the release set, not the order GitHub returned it in.
    releases.sort_by(|left, right| left.cached.tag.cmp(&right.cached.tag));
    assert_no_ambiguous_versions(&releases)?;
    let fetched_at = format_iso_utc(SystemTime::now())?;
    let index = ManifestIndex {
        schema_version: INVENTORY_SCHEMA_VERSION,
        fetched_at: fetched_at.clone(),
        source: Some(source.clone()),
        releases: releases
            .iter()
            .map(|release| release.cached.clone())
            .collect(),
    };
    let index_bytes = serde_json::to_vec_pretty(&index).map_err(|_| {
        OpenPackError::integrity("could not encode verified HTTPS source inventory")
    })?;
    write_atomic_replace(index_path, &index_bytes)?;
    let inventory_sha256 = inventory_snapshot_sha256(&index)?;
    Ok(Inventory {
        fetched_at,
        fetched_at_ms: unix_millis(),
        fetched_online: true,
        inventory_sha256,
        releases,
    })
}

fn fetch_bytes(
    transport: &dyn HttpTransport,
    url: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, OpenPackError> {
    let bytes = transport
        .fetch(url, max_bytes)
        .map_err(|error| match error.kind {
            TransportErrorKind::Network => OpenPackError::Network(error.message),
            TransportErrorKind::Redirect => OpenPackError::InvalidSource(error.message),
            TransportErrorKind::TooLarge => OpenPackError::manifest(error.message),
            TransportErrorKind::Http => match error.status {
                Some(401) => {
                    OpenPackError::Authentication("pack source authentication failed".to_owned())
                }
                Some(403) if error.rate_limited => {
                    OpenPackError::Network("pack source rate limit reached".to_owned())
                }
                Some(403) => {
                    OpenPackError::Authentication("pack source authentication failed".to_owned())
                }
                Some(404) => OpenPackError::MissingRelease(
                    "selected pack source release or asset was not found".to_owned(),
                ),
                Some(429) => OpenPackError::Network("pack source rate limit reached".to_owned()),
                Some(500..=599) => OpenPackError::Network(
                    "pack source request was temporarily unavailable".to_owned(),
                ),
                Some(_) => OpenPackError::manifest("pack source rejected a request"),
                None => OpenPackError::Network("pack source request failed".to_owned()),
            },
        })?;
    if bytes.len() as u64 > max_bytes {
        return Err(OpenPackError::manifest(format!(
            "pack source response exceeded the {max_bytes}-byte limit"
        )));
    }
    Ok(bytes)
}

fn fetch_all_release_pages(
    transport: &dyn HttpTransport,
    source: Option<&PackSource>,
) -> Result<Vec<Value>, OpenPackError> {
    let mut releases = Vec::new();
    for page in 1..=100 {
        let url = format!("{}/releases?per_page=100&page={page}", api_root(source));
        let bytes = match fetch_bytes(transport, &url, MAX_API_PAGE_BYTES) {
            Err(OpenPackError::MissingRelease(_))
                if source.is_some_and(|source| source.repository != REPOSITORY_URL) =>
            {
                return Err(OpenPackError::Authentication(
                    "pack repository listing is inaccessible".to_owned(),
                ));
            }
            result => result?,
        };
        let values = parse_json_value(&bytes).map_err(|error| {
            OpenPackError::manifest(format!("GitHub returned invalid release JSON: {error}"))
        })?;
        let page_records = values.as_array().ok_or_else(|| {
            OpenPackError::manifest(format!(
                "GitHub release page {page} is not an array of releases"
            ))
        })?;
        if page_records.len() > 100 {
            return Err(OpenPackError::manifest(format!(
                "GitHub release page {page} contains more than 100 releases"
            )));
        }
        releases.extend(page_records.iter().cloned());
        if page_records.len() < 100 {
            return Ok(releases);
        }
    }
    Err(OpenPackError::unavailable(
        "GitHub release pagination exceeded the supported 100-page limit",
    ))
}

fn api_root(source: Option<&PackSource>) -> String {
    source
        .and_then(|source| safe_https_url(&source.repository).ok())
        .map_or_else(
            || API_ROOT.to_owned(),
            |repository| format!("https://api.github.com/repos{}", repository.path),
        )
}

fn resolve_tag_commit(
    tag: &str,
    source: Option<&PackSource>,
    transport: &dyn HttpTransport,
) -> Result<String, OpenPackError> {
    let escaped = tag
        .split('/')
        .map(percent_encode_path_segment)
        .collect::<Vec<_>>()
        .join("/");
    let mut url = format!("{}/git/ref/tags/{escaped}", api_root(source));
    let mut seen = BTreeSet::new();
    for _ in 0..10 {
        let bytes = fetch_bytes(transport, &url, 1024 * 1024)?;
        let reference = parse_json_value(&bytes).map_err(|error| {
            OpenPackError::manifest(format!(
                "GitHub returned invalid tag JSON for {tag}: {error}"
            ))
        })?;
        let object = reference
            .get("object")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                OpenPackError::integrity(format!(
                    "GitHub tag API returned invalid object for {tag}"
                ))
            })?;
        let sha = object
            .get("sha")
            .and_then(Value::as_str)
            .filter(|sha| is_git_sha(sha))
            .ok_or_else(|| {
                OpenPackError::integrity(format!(
                    "GitHub tag API returned invalid object for {tag}"
                ))
            })?;
        match object.get("type").and_then(Value::as_str) {
            Some("commit") => return Ok(sha.to_owned()),
            Some("tag") if seen.insert(sha.to_owned()) => {
                url = format!("{}/git/tags/{sha}", api_root(source));
            }
            _ => {
                return Err(OpenPackError::integrity(format!(
                    "GitHub tag {tag} is not a valid commit or annotated-tag chain"
                )));
            }
        }
    }
    Err(OpenPackError::integrity(format!(
        "GitHub tag {tag} has an excessively deep annotated-tag chain"
    )))
}

fn percent_encode_path_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(encoded, "%{byte:02X}").expect("write to String cannot fail");
        }
    }
    encoded
}

#[cfg(test)]
fn parse_release_manifest(bytes: &[u8]) -> Result<(PackRelease, Value), OpenPackError> {
    parse_release_manifest_for_source(bytes, None)
}

fn parse_release_manifest_for_source(
    bytes: &[u8],
    source: Option<&PackSource>,
) -> Result<(PackRelease, Value), OpenPackError> {
    #[derive(Deserialize)]
    struct VersionProbe {
        manifest_schema_version: u8,
    }

    let probe = serde_json::from_slice::<VersionProbe>(bytes).map_err(|error| {
        OpenPackError::manifest(format!("invalid release manifest JSON: {error}"))
    })?;
    let raw = parse_json_value(bytes).map_err(|error| {
        OpenPackError::manifest(format!("invalid release manifest JSON: {error}"))
    })?;
    let manifest = match probe.manifest_schema_version {
        1 => {
            let value = serde_json::from_slice::<PackReleaseV1>(bytes).map_err(|error| {
                OpenPackError::manifest(format!("invalid schema 1 release manifest: {error}"))
            })?;
            if value.manifest_schema_version != 1 {
                return Err(OpenPackError::manifest(
                    "release schema version does not match schema 1",
                ));
            }
            let qualification = serde_json::to_value(&value.qualification)
                .expect("qualification serialization cannot fail");
            PackRelease {
                schema_version: 1,
                pack: value.pack,
                release_version: value.release_version,
                source: value.source,
                content_origin: value.content_origin,
                compatibility_schemas: value.compatibility.schemas,
                capabilities: value.compatibility.capabilities,
                engine_range: Some(value.compatibility.engine),
                contents: value.contents,
                artifacts: value.artifacts,
                qualification,
                qualification_v1: Some(value.qualification),
                qualification_v2: None,
                release_dependencies: value.release_dependencies,
                provenance: None,
            }
        }
        2 => {
            let value = serde_json::from_slice::<PackReleaseV2>(bytes).map_err(|error| {
                OpenPackError::manifest(format!("invalid schema 2 release manifest: {error}"))
            })?;
            if value.manifest_schema_version != 2 {
                return Err(OpenPackError::manifest(
                    "release schema version does not match schema 2",
                ));
            }
            let qualification = serde_json::to_value(&value.qualification)
                .expect("qualification serialization cannot fail");
            PackRelease {
                schema_version: 2,
                pack: value.pack,
                release_version: value.release_version,
                source: value.source,
                content_origin: value.content_origin,
                compatibility_schemas: value.compatibility.schemas,
                capabilities: value.compatibility.capabilities,
                engine_range: None,
                contents: value.contents,
                artifacts: value.artifacts,
                qualification,
                qualification_v1: None,
                qualification_v2: Some(value.qualification),
                release_dependencies: value.release_dependencies,
                provenance: value.provenance,
            }
        }
        version => {
            return Err(OpenPackError::manifest(format!(
                "unsupported release manifest schema {version}"
            )));
        }
    };
    validate_release_manifest(&manifest, source)?;
    Ok((manifest, raw))
}

fn parse_json_value(bytes: &[u8]) -> Result<Value, serde_json::Error> {
    // serde_json's default recursion limit is 128, matching the launcher
    // reader's strict JSON limit.
    serde_json::from_slice(bytes)
}

fn validate_release_manifest(
    manifest: &PackRelease,
    source: Option<&PackSource>,
) -> Result<(), OpenPackError> {
    parse_semver(&manifest.release_version)?;
    let expected_repository = source.map_or(REPOSITORY_URL, |source| source.repository.as_str());
    if !valid_pack_id(&manifest.pack.id)
        || !["public", "private"].contains(&manifest.pack.visibility.as_str())
        || manifest.pack.repository != expected_repository
        || (manifest.pack.repository == REPOSITORY_URL && manifest.pack.visibility != "public")
        || manifest.source.repository != manifest.pack.repository
        || manifest.source.dirty
        || !is_git_sha(&manifest.source.commit)
    {
        return Err(OpenPackError::manifest(
            "release must name its clean source commit and trusted repository",
        ));
    }
    manifest
        .compatibility_schemas
        .validate("compatibility.schemas")?;
    validate_capabilities(&manifest.capabilities, "compatibility.capabilities")?;
    if let Some(range) = &manifest.engine_range {
        let minimum = parse_semver(&range.min_inclusive)?;
        let maximum = parse_semver(&range.max_exclusive)?;
        if minimum >= maximum {
            return Err(OpenPackError::manifest(
                "release engine compatibility range is empty",
            ));
        }
    }
    let required_capabilities = manifest
        .capabilities
        .required
        .iter()
        .collect::<BTreeSet<_>>();
    let mut content_keys = BTreeSet::new();
    for content in &manifest.contents {
        validate_safe_relative_path(&content.path, "content path")?;
        if content.identity.is_empty() || !is_sha256(&content.sha256) {
            return Err(OpenPackError::manifest(format!(
                "content {} has an invalid identity or SHA-256",
                content.path
            )));
        }
        let key = (
            content.kind as u8,
            content.identity.as_str(),
            content.path.as_str(),
        );
        if !content_keys.insert(key) {
            return Err(OpenPackError::manifest(
                "release manifest repeats a content identity and path",
            ));
        }
        validate_string_set(&content.languages, "content.languages")?;
        validate_string_set(&content.dependencies, "content.dependencies")?;
        validate_string_set(
            &content.required_capabilities,
            "content.required_capabilities",
        )?;
        for capability in &content.required_capabilities {
            if !required_capabilities.contains(capability) {
                return Err(OpenPackError::manifest(format!(
                    "content {} requires a capability absent from the release declaration",
                    content.identity
                )));
            }
        }
        content.schemas.validate("content.schemas")?;
        if !manifest.compatibility_schemas.supports(&content.schemas) {
            return Err(OpenPackError::manifest(format!(
                "content {} requires a schema absent from the release declaration",
                content.identity
            )));
        }
        if content.license.as_ref().is_some_and(String::is_empty)
            || content.completeness.as_ref().is_some_and(String::is_empty)
        {
            return Err(OpenPackError::manifest(format!(
                "content {} has an empty optional string field",
                content.identity
            )));
        }
        if let Some(hash) = &content.authored_hash
            && !is_sha256(hash)
        {
            return Err(OpenPackError::manifest(format!(
                "content {} has an invalid authored hash",
                content.identity
            )));
        }
        if let Some(hash) = &content.resolved_semantic_hash
            && !is_sha256(hash)
        {
            return Err(OpenPackError::manifest(format!(
                "content {} has an invalid resolved semantic hash",
                content.identity
            )));
        }
        if let Some(case_ids) = &content.case_ids {
            validate_string_set(case_ids, "content.case_ids")?;
        }
        if let Some(version) = &content.content_version {
            parse_semver(version)?;
        }
    }
    if manifest.artifacts.is_empty() {
        return Err(OpenPackError::manifest(
            "release manifest must declare at least one artifact",
        ));
    }
    let mut artifact_names = BTreeSet::new();
    for artifact in &manifest.artifacts {
        let parts = validate_safe_relative_path(&artifact.name, "artifact name")?;
        if parts.len() != 1 || !artifact_names.insert(&artifact.name) {
            return Err(OpenPackError::manifest(
                "release artifact names must be unique filenames",
            ));
        }
        if artifact.size_bytes > MAX_ARTIFACT_BYTES || !is_sha256(&artifact.sha256) {
            return Err(OpenPackError::manifest(format!(
                "artifact {} exceeds the supported size or has an invalid SHA-256",
                artifact.name
            )));
        }
        if artifact.format.is_empty() {
            return Err(OpenPackError::manifest(format!(
                "artifact {} has an empty format",
                artifact.name
            )));
        }
    }
    match (
        manifest.schema_version,
        &manifest.qualification_v1,
        &manifest.qualification_v2,
    ) {
        (1, Some(qualification), None) => {
            if !["pending", "unqualified", "qualified"].contains(&qualification.status.as_str()) {
                return Err(OpenPackError::manifest(
                    "schema 1 release has an unsupported qualification status",
                ));
            }
            if qualification.status == "qualified"
                && (qualification.evidence.is_empty()
                    || !manifest.artifacts.iter().any(|artifact| {
                        matches!(artifact.role, ArtifactRole::Policy | ArtifactRole::Native)
                    }))
            {
                return Err(OpenPackError::manifest(
                    "qualified schema 1 releases require evidence and a policy or native artifact",
                ));
            }
        }
        (2, None, Some(qualification)) => {
            let integrity_status = qualification.integrity.status.as_str();
            let behavior_status = qualification.behavior.status.as_str();
            if !["pending", "verified", "failed"].contains(&integrity_status)
                || !["pending", "limited", "qualified", "failed"].contains(&behavior_status)
            {
                return Err(OpenPackError::manifest(
                    "schema 2 release has an unsupported qualification status",
                ));
            }
            for (axis, state) in [
                ("integrity", &qualification.integrity),
                ("behavior", &qualification.behavior),
            ] {
                if state.status != "pending"
                    && !state.evidence.iter().any(|entry| !entry.trim().is_empty())
                {
                    return Err(OpenPackError::manifest(format!(
                        "schema 2 {axis} qualification status {} requires nonblank evidence",
                        state.status
                    )));
                }
            }
        }
        _ => {
            return Err(OpenPackError::manifest(
                "release qualification does not match its manifest schema",
            ));
        }
    }
    let mut dependency_keys = BTreeSet::new();
    let mut dependency_versions = BTreeMap::new();
    for dependency in &manifest.release_dependencies {
        if !valid_pack_id(&dependency.pack_id) {
            return Err(OpenPackError::manifest(
                "release dependency has an empty pack id",
            ));
        }
        parse_semver(&dependency.release_version)?;
        validate_https_uri(&dependency.repository, "release dependency repository")?;
        let exact_key = (
            dependency.pack_id.as_str(),
            dependency.release_version.as_str(),
            dependency.repository.as_str(),
        );
        if !dependency_keys.insert(exact_key) {
            return Err(OpenPackError::manifest(
                "release manifest repeats an exact dependency",
            ));
        }
        if manifest.schema_version == 2 {
            let key = (dependency.pack_id.as_str(), dependency.repository.as_str());
            if dependency_versions
                .insert(key, dependency.release_version.as_str())
                .is_some_and(|previous| previous != dependency.release_version)
            {
                return Err(OpenPackError::manifest(format!(
                    "conflicting exact release dependencies for {} from {}",
                    dependency.pack_id, dependency.repository
                )));
            }
        }
    }
    if let Some(origin) = &manifest.content_origin {
        validate_https_uri(&origin.repository, "content origin repository")?;
        if !is_git_sha(&origin.commit)
            || origin
                .lock_sha256
                .as_ref()
                .is_some_and(|hash| !is_sha256(hash))
        {
            return Err(OpenPackError::manifest(
                "content origin identity is invalid",
            ));
        }
    }
    if let Some(provenance) = &manifest.provenance {
        if let Some(version) = &provenance.engine_version {
            parse_semver(version)?;
        }
        if provenance
            .build_identity
            .as_ref()
            .is_some_and(String::is_empty)
            || provenance
                .source_commit
                .as_ref()
                .is_some_and(|sha| !is_git_sha(sha))
            || provenance.testing.as_ref().is_some_and(|items| {
                items.iter().any(|item| {
                    item.engine_version
                        .as_ref()
                        .is_some_and(|version| Version::parse(version).is_err())
                        || item.build_identity.as_ref().is_some_and(String::is_empty)
                        || item
                            .source_commit
                            .as_ref()
                            .is_some_and(|sha| !is_git_sha(sha))
                })
            })
        {
            return Err(OpenPackError::manifest("release provenance is invalid"));
        }
    }
    Ok(())
}

fn validate_capabilities(capabilities: &Capabilities, label: &str) -> Result<(), OpenPackError> {
    if capabilities.contract_version == 0 {
        return Err(OpenPackError::manifest(format!(
            "{label}.contract_version must be positive"
        )));
    }
    validate_string_set(&capabilities.required, &format!("{label}.required"))?;
    validate_string_set(&capabilities.provided, &format!("{label}.provided"))
}

fn validate_string_set(values: &[String], label: &str) -> Result<(), OpenPackError> {
    ensure_unique(values, label)?;
    if values.iter().any(String::is_empty) {
        return Err(OpenPackError::manifest(format!(
            "{label} contains an empty string"
        )));
    }
    Ok(())
}

fn ensure_unique<T: Ord>(values: &[T], label: &str) -> Result<(), OpenPackError> {
    let mut seen = BTreeSet::new();
    if values.iter().any(|value| !seen.insert(value)) {
        return Err(OpenPackError::manifest(format!(
            "{label} contains duplicate values"
        )));
    }
    Ok(())
}

fn validate_safe_relative_path<'a>(
    value: &'a str,
    label: &str,
) -> Result<Vec<&'a str>, OpenPackError> {
    if value.is_empty()
        || value.starts_with('/')
        || value.contains('\\')
        || value.contains('\0')
        || value.as_bytes().get(1) == Some(&b':')
    {
        return Err(OpenPackError::manifest(format!(
            "{label} is not a safe relative POSIX path"
        )));
    }
    let components = value.split('/').collect::<Vec<_>>();
    for component in &components {
        let lower = component.to_ascii_lowercase();
        let base = lower.split('.').next().unwrap_or_default();
        if component.is_empty()
            || *component == "."
            || *component == ".."
            || component.ends_with('.')
            || component.ends_with(' ')
            || component
                .chars()
                .any(|character| character.is_control() || "<>:\"|?*".contains(character))
            || matches!(base, "con" | "prn" | "aux" | "nul")
            || ["com", "lpt"].iter().any(|prefix| {
                base.strip_prefix(prefix).is_some_and(|suffix| {
                    matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
                })
            })
        {
            return Err(OpenPackError::manifest(format!(
                "{label} contains an unsafe path component"
            )));
        }
    }
    Ok(components)
}

fn validate_https_uri(value: &str, label: &str) -> Result<(), OpenPackError> {
    let Some(authority_and_path) = value.strip_prefix("https://") else {
        return Err(OpenPackError::manifest(format!(
            "{label} must be an absolute HTTPS URI"
        )));
    };
    let authority = authority_and_path.split('/').next().unwrap_or_default();
    if authority.is_empty()
        || authority.contains('@')
        || value.chars().any(char::is_whitespace)
        || value.contains('#')
    {
        return Err(OpenPackError::manifest(format!(
            "{label} must be an absolute HTTPS URI"
        )));
    }
    Ok(())
}

fn parse_semver(value: &str) -> Result<Version, OpenPackError> {
    Version::parse(value).map_err(|error| {
        OpenPackError::manifest(format!("invalid SemVer value {value:?}: {error}"))
    })
}

fn is_git_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_asset_url(
    value: &str,
    name: &str,
    cached: bool,
    source: Option<&PackSource>,
) -> Result<(), OpenPackError> {
    let parsed = safe_https_url(value).ok();
    let allowed = parsed.as_ref().is_some_and(|url| {
        if let Some(source) = source
            && let Some(inventory_url) = &source.inventory_url
        {
            return safe_https_url(inventory_url)
                .is_ok_and(|inventory| url.origin == inventory.origin);
        }
        let repository_path = source
            .and_then(|source| safe_https_url(&source.repository).ok())
            .map_or_else(
                || "/BrokkAi/bifrost-packs".to_owned(),
                |repository| repository.path,
            );
        let public_download = url.origin == "https://github.com"
            && url
                .path
                .starts_with(&format!("{repository_path}/releases/download/"));
        let api_asset = source.is_some()
            && url.origin == "https://api.github.com"
            && url
                .path
                .strip_prefix(&format!("/repos{repository_path}/releases/assets/"))
                .is_some_and(|id| !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit()));
        public_download || api_asset
    });
    if !allowed {
        let message = format!("release asset {name} crossed the trusted source boundary");
        return Err(if cached {
            OpenPackError::integrity(message)
        } else {
            OpenPackError::manifest(message)
        });
    }
    Ok(())
}

fn validate_cached_record(
    record: &CachedReleaseRecord,
    source: Option<&PackSource>,
) -> Result<(), OpenPackError> {
    if record.tag.is_empty()
        || record.tag.bytes().any(|byte| byte.is_ascii_control())
        || !is_git_sha(&record.tag_commit)
        || !is_sha256(&record.manifest_sha256)
    {
        return Err(OpenPackError::integrity(
            "cached release record has an invalid shape",
        ));
    }
    if let Some(url) = &record.manifest_url {
        validate_asset_url(url, "descriptor", true, source)?;
    }
    for (name, asset) in &record.assets {
        if name.is_empty() {
            return Err(OpenPackError::integrity(
                "cached release contains an unnamed asset",
            ));
        }
        validate_asset_url(&asset.url, name, true, source)?;
    }
    Ok(())
}

fn validate_release_binding(
    record: &CachedReleaseRecord,
    manifest: &PackRelease,
    source: Option<&PackSource>,
) -> Result<(), OpenPackError> {
    let semver = parse_semver(&manifest.release_version)?;
    if record.tag != release_tag(&manifest.pack.id, &manifest.release_version)
        || record.prerelease != !semver.pre.is_empty()
        || record.tag_commit != manifest.source.commit
        || manifest.pack.repository
            != source.map_or(REPOSITORY_URL, |source| source.repository.as_str())
        || (manifest.pack.repository == REPOSITORY_URL && manifest.pack.visibility != "public")
    {
        return Err(OpenPackError::integrity(format!(
            "release {} no longer matches its manifest and source binding",
            record.tag
        )));
    }
    Ok(())
}

fn release_tag(pack_id: &str, release_version: &str) -> String {
    match pack_id {
        RULES_PACK_ID => format!("rules/v{release_version}"),
        SEMANTIC_PACK_ID => format!("packs/v{release_version}"),
        _ => format!("v{release_version}"),
    }
}

fn assert_no_ambiguous_versions(releases: &[ReleaseRecord]) -> Result<(), OpenPackError> {
    let mut precedence: BTreeMap<(&str, Version), &str> = BTreeMap::new();
    for release in releases {
        let version = parse_semver(&release.manifest.release_version)?;
        let mut key_version = version.clone();
        key_version.build = Default::default();
        if let Some(previous) = precedence.insert(
            (release.manifest.pack.id.as_str(), key_version),
            release.cached.manifest_sha256.as_str(),
        ) && previous != release.cached.manifest_sha256
        {
            return Err(OpenPackError::manifest(format!(
                "ambiguous release manifests share SemVer precedence for {}",
                release.manifest.pack.id
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
fn release_compatible(manifest: &PackRelease, profile: &EngineProfile) -> bool {
    incompatibility_detail(manifest, profile).is_none()
}

fn incompatibility_detail(manifest: &PackRelease, profile: &EngineProfile) -> Option<String> {
    let mut missing_capabilities = BTreeSet::new();
    let mut unsupported_schema_axes = Vec::<(String, Vec<u32>, Vec<u32>)>::new();
    let mut engine_range_mismatch = false;
    if let Some(range) = &manifest.engine_range {
        let Ok(minimum) = Version::parse(&range.min_inclusive) else {
            return Some("manifest engine range cannot be parsed".to_owned());
        };
        let Ok(maximum) = Version::parse(&range.max_exclusive) else {
            return Some("manifest engine range cannot be parsed".to_owned());
        };
        let Ok(engine) = Version::parse(&profile.engine_version) else {
            return Some("engine profile version cannot be parsed".to_owned());
        };
        if engine < minimum || engine >= maximum {
            engine_range_mismatch = true;
        }
    }
    let contract_mismatch =
        manifest.capabilities.contract_version != profile.capability_contract_version;
    for capability in &manifest.capabilities.required {
        if !profile.capabilities.contains(capability) {
            missing_capabilities.insert(capability.as_str());
        }
    }
    collect_unsupported_schema_axes(
        "release",
        &manifest.compatibility_schemas,
        &profile.schemas,
        &mut unsupported_schema_axes,
    );
    for content in &manifest.contents {
        for capability in &content.required_capabilities {
            if !profile.capabilities.contains(capability) {
                missing_capabilities.insert(capability.as_str());
            }
        }
        collect_unsupported_schema_axes(
            &format!("content:{}", content.path),
            &content.schemas,
            &profile.schemas,
            &mut unsupported_schema_axes,
        );
    }
    if missing_capabilities.is_empty()
        && unsupported_schema_axes.is_empty()
        && !contract_mismatch
        && !engine_range_mismatch
    {
        None
    } else {
        Some(format!(
            "missing capabilities {missing_capabilities:?}; unsupported schema axes {unsupported_schema_axes:?}; capability contract mismatch {contract_mismatch}; engine range mismatch {engine_range_mismatch}"
        ))
    }
}

fn collect_unsupported_schema_axes(
    label: &str,
    required: &SchemaSet,
    supported: &SchemaSet,
    failures: &mut Vec<(String, Vec<u32>, Vec<u32>)>,
) {
    for (axis, required_versions) in required.axes() {
        let supported_versions = supported
            .axes()
            .into_iter()
            .find_map(|(name, versions)| (axis == name).then_some(versions))
            .expect("schema axes have identical names");
        let missing = required_versions
            .iter()
            .copied()
            .filter(|version| !supported_versions.contains(version))
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            failures.push((
                format!("{label}.{axis}"),
                missing,
                supported_versions.to_vec(),
            ));
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum QualificationEligibility {
    Eligible,
    Pending,
    IntegrityFailed,
    BehaviorFailed,
}

fn qualification_eligibility(manifest: &PackRelease) -> QualificationEligibility {
    if let Some(qualification) = &manifest.qualification_v1 {
        return if qualification.status == "qualified" {
            QualificationEligibility::Eligible
        } else {
            QualificationEligibility::Pending
        };
    }
    let qualification = manifest
        .qualification_v2
        .as_ref()
        .expect("validated schema 2 release has schema 2 qualification");
    if qualification.integrity.status == "failed" {
        QualificationEligibility::IntegrityFailed
    } else if qualification.behavior.status == "failed" {
        QualificationEligibility::BehaviorFailed
    } else if qualification.integrity.status == "pending"
        || qualification.behavior.status == "pending"
    {
        QualificationEligibility::Pending
    } else {
        QualificationEligibility::Eligible
    }
}

#[derive(Debug)]
struct SelectedSet {
    root_index: usize,
    dependency_indices: Vec<usize>,
    selection_reason: &'static str,
    rejections: Vec<Value>,
}

fn select_pack_request(
    inventory: &Inventory,
    profile: &EngineProfile,
    request: &PackRequest,
) -> Result<SelectedSet, OpenPackError> {
    let mut candidates = inventory
        .releases
        .iter()
        .enumerate()
        .filter(|(_, release)| {
            release.manifest.pack.id == request.pack_id
                && release.manifest.pack.repository == request.repository
        })
        .map(|(index, release)| Ok((index, parse_semver(&release.manifest.release_version)?)))
        .collect::<Result<Vec<_>, OpenPackError>>()?;
    candidates.sort_by(|left, right| right.1.cmp(&left.1));
    let mut rejections = Vec::new();
    if let PackSelection::Strict {
        release_version,
        manifest_sha256,
    } = &request.selection
    {
        let Some((root_index, _)) = candidates.iter().find(|(index, _)| {
            inventory.releases[*index].manifest.release_version == *release_version
        }) else {
            return Err(OpenPackError::MissingRelease(
                "strictly selected pack release is absent from the trusted inventory".to_owned(),
            ));
        };
        let root_index = *root_index;
        let release = &inventory.releases[root_index];
        if &release.cached.manifest_sha256 != manifest_sha256 {
            return Err(OpenPackError::integrity(
                "strictly selected manifest SHA-256 does not match its trusted pin",
            ));
        }
        match inspect_candidate(inventory, profile, request, root_index) {
            Ok(dependency_indices) => {
                let selected = std::iter::once(&release.manifest)
                    .chain(
                        dependency_indices
                            .iter()
                            .map(|index| &inventory.releases[*index].manifest),
                    )
                    .map(qualification_eligibility)
                    .collect::<Vec<_>>();
                let qualification_failure = if selected
                    .contains(&QualificationEligibility::IntegrityFailed)
                {
                    Some((
                        "qualification-integrity-failed",
                        "strict selection includes a release with failed integrity qualification",
                    ))
                } else if selected.contains(&QualificationEligibility::BehaviorFailed) {
                    Some((
                        "qualification-behavior-failed",
                        "strict selection includes a release with failed behavior qualification",
                    ))
                } else if selected.contains(&QualificationEligibility::Pending) {
                    Some((
                        "qualification-pending",
                        "strict selection includes a release with pending qualification",
                    ))
                } else {
                    None
                };
                if let Some((reason, detail)) = qualification_failure {
                    push_rejection(&mut rejections, release, reason, detail.to_owned());
                    return Err(OpenPackError::SelectionRejected {
                        error: Box::new(OpenPackError::IncompatibleSelection(
                            "strictly selected release fails qualification".to_owned(),
                        )),
                        rejections,
                        inventory: inventory_snapshot_value(inventory),
                    });
                }
                return Ok(SelectedSet {
                    root_index,
                    dependency_indices,
                    selection_reason: "strict-lock",
                    rejections,
                });
            }
            Err((reason, detail, error)) => {
                push_rejection(&mut rejections, release, reason, detail);
                return Err(OpenPackError::SelectionRejected {
                    error: error.unwrap_or_else(|| {
                        Box::new(OpenPackError::IncompatibleSelection(
                            "strictly selected release is incompatible with the request or engine"
                                .to_owned(),
                        ))
                    }),
                    rejections,
                    inventory: inventory_snapshot_value(inventory),
                });
            }
        }
    }

    let PackSelection::Preferred {
        preferred_version,
        allowed_versions,
        channel,
    } = &request.selection
    else {
        unreachable!("strict requests returned above")
    };
    let requirement = semver::VersionReq::parse(allowed_versions)
        .expect("validated pack request has a valid version requirement");
    let preferred = preferred_version.as_deref();
    let mut eligible = Vec::new();
    let mut latest_pending = None;
    let mut latest_integrity = None;
    let mut latest_behavior = None;
    for (root_index, version) in candidates {
        let release = &inventory.releases[root_index];
        let reason: Option<(&str, String)> = if *channel == PackChannel::Stable
            && (release.cached.prerelease || !version.pre.is_empty())
        {
            Some((
                "channel",
                "release is a prerelease under the stable channel".to_owned(),
            ))
        } else if !requirement.matches(&Version::new(version.major, version.minor, version.patch)) {
            Some((
                "version-range",
                format!("version {version} is outside {allowed_versions}"),
            ))
        } else {
            None
        };
        if let Some((reason, detail)) = reason {
            push_rejection(&mut rejections, release, reason, detail);
            continue;
        }
        match inspect_candidate(inventory, profile, request, root_index) {
            Ok(dependency_indices) => {
                let qualification = std::iter::once(&release.manifest)
                    .chain(
                        dependency_indices
                            .iter()
                            .map(|index| &inventory.releases[*index].manifest),
                    )
                    .map(qualification_eligibility)
                    .collect::<Vec<_>>();
                if qualification.contains(&QualificationEligibility::IntegrityFailed) {
                    latest_integrity
                        .get_or_insert_with(|| release.manifest.release_version.clone());
                    push_rejection(
                        &mut rejections,
                        release,
                        "qualification-integrity-failed",
                        "a selected release declares failed integrity qualification".to_owned(),
                    );
                } else if qualification.contains(&QualificationEligibility::BehaviorFailed) {
                    latest_behavior.get_or_insert_with(|| release.manifest.release_version.clone());
                    push_rejection(
                        &mut rejections,
                        release,
                        "qualification-behavior-failed",
                        "a selected release declares failed behavior qualification".to_owned(),
                    );
                } else if qualification.contains(&QualificationEligibility::Pending) {
                    latest_pending.get_or_insert_with(|| release.manifest.release_version.clone());
                    push_rejection(
                        &mut rejections,
                        release,
                        "qualification-pending",
                        "a selected release has pending qualification".to_owned(),
                    );
                } else {
                    eligible.push((root_index, dependency_indices, version));
                }
            }
            Err((_reason, _detail, Some(error))) => return Err(*error),
            Err((reason, detail, None)) => push_rejection(&mut rejections, release, reason, detail),
        }
    }
    if let Some(preferred) = preferred
        && let Some((root_index, dependency_indices, _)) = eligible
            .iter()
            .find(|(index, _, _)| inventory.releases[*index].manifest.release_version == preferred)
    {
        return Ok(SelectedSet {
            root_index: *root_index,
            dependency_indices: dependency_indices.clone(),
            selection_reason: "preferred-version",
            rejections: rejections.into_iter().take(32).collect(),
        });
    }
    if let Some((root_index, dependency_indices, _)) = eligible.into_iter().next() {
        return Ok(SelectedSet {
            root_index,
            dependency_indices,
            selection_reason: "highest-eligible",
            rejections: rejections.into_iter().take(32).collect(),
        });
    }
    let (class, message) = if let Some(version) = latest_pending {
        (
            "pending",
            format!("newest otherwise-complete candidate {version} has pending qualification"),
        )
    } else if let Some(version) = latest_integrity {
        (
            "integrity",
            format!("newest otherwise-complete candidate {version} failed integrity qualification"),
        )
    } else if let Some(version) = latest_behavior {
        (
            "unqualified",
            format!("newest otherwise-complete candidate {version} failed behavior qualification"),
        )
    } else {
        (
            "no-compatible-release",
            "no candidate satisfies the pack request and engine contract".to_owned(),
        )
    };
    let error = match class {
        "pending" => OpenPackError::Pending(message),
        "integrity" => OpenPackError::integrity(message),
        "unqualified" => OpenPackError::Unqualified(message),
        _ if inventory.fetched_online => {
            let profile_bytes = serde_json::to_vec(profile).map_err(|error| {
                OpenPackError::integrity(format!("serialize engine profile: {error}"))
            })?;
            OpenPackError::no_compatible(
                message,
                json!({
                    "status": "not-evaluated",
                    "reason": "no-compatible-release",
                    "engine_profile_sha256": sha256(&profile_bytes),
                    "inventory_fetched_at": inventory.fetched_at,
                    "inventory_sha256": inventory.inventory_sha256,
                    "rejections": rejections.iter().take(32).cloned().collect::<Vec<_>>(),
                }),
            )
        }
        _ => OpenPackError::UnverifiedAbsence(
            "cached inventory does not prove a fresh no-compatible-release outcome".to_owned(),
        ),
    };
    Err(OpenPackError::SelectionRejected {
        error: Box::new(error),
        rejections: rejections.into_iter().take(32).collect(),
        inventory: inventory_snapshot_value(inventory),
    })
}

fn inventory_snapshot_value(inventory: &Inventory) -> Value {
    json!({
        "index_sha256": inventory.inventory_sha256,
        "fetched_at": inventory.fetched_at,
        "fetched_online": inventory.fetched_online,
    })
}

/// Reason name, detail text, and an optional hard error. A hard error aborts
/// selection; without one the candidate is recorded as a rejection.
type CandidateRejection = (&'static str, String, Option<Box<OpenPackError>>);

fn inspect_candidate(
    inventory: &Inventory,
    profile: &EngineProfile,
    request: &PackRequest,
    root_index: usize,
) -> Result<Vec<usize>, CandidateRejection> {
    let root = &inventory.releases[root_index];
    if let Some(detail) = incompatibility_detail(&root.manifest, profile) {
        return Err(("engine-contract", detail, None));
    }
    let mut dependency_indices = Vec::new();
    for dependency in &root.manifest.release_dependencies {
        if dependency.repository != request.repository {
            return Err((
                "dependency-repository",
                format!(
                    "dependency {} names a different repository",
                    dependency.pack_id
                ),
                None,
            ));
        }
        let found = inventory.releases.iter().position(|release| {
            release.manifest.pack.id == dependency.pack_id
                && release.manifest.release_version == dependency.release_version
                && release.manifest.pack.repository == request.repository
        });
        let Some(index) = found else {
            return Err((
                "dependency-missing",
                format!(
                    "dependency {}@{} is absent",
                    dependency.pack_id, dependency.release_version
                ),
                None,
            ));
        };
        let selected_dependency = &inventory.releases[index];
        if !selected_dependency.manifest.release_dependencies.is_empty() {
            return Err((
                "dependency-transitive",
                format!(
                    "dependency {} declares further dependencies",
                    dependency.pack_id
                ),
                None,
            ));
        }
        if let Some(detail) = incompatibility_detail(&selected_dependency.manifest, profile) {
            return Err(("dependency-engine-contract", detail, None));
        }
        if let Some(pin) = request
            .dependencies
            .iter()
            .find(|pin| pin.pack_id == dependency.pack_id)
        {
            let digest_mismatch = pin.manifest_sha256 != selected_dependency.cached.manifest_sha256;
            let identity_mismatch = pin.repository != dependency.repository
                || pin
                    .release_version
                    .as_deref()
                    .is_some_and(|version| version != dependency.release_version);
            if digest_mismatch && matches!(request.selection, PackSelection::Strict { .. }) {
                return Err((
                    "dependency-pin-mismatch",
                    format!(
                        "strict dependency digest does not match {}",
                        dependency.pack_id
                    ),
                    Some(Box::new(OpenPackError::integrity(
                        "strict dependency manifest SHA-256 does not match its trusted pin",
                    ))),
                ));
            }
            if identity_mismatch || digest_mismatch {
                return Err((
                    "dependency-pin-mismatch",
                    format!(
                        "dependency pin for {} does not match the declared manifest identity and digest",
                        dependency.pack_id
                    ),
                    None,
                ));
            }
        } else if matches!(request.selection, PackSelection::Strict { .. }) {
            return Err((
                "dependency-pin-mismatch",
                format!(
                    "strict request omits dependency pin for {}",
                    dependency.pack_id
                ),
                None,
            ));
        }
        dependency_indices.push(index);
    }
    for pin in &request.dependencies {
        if !root
            .manifest
            .release_dependencies
            .iter()
            .any(|dependency| dependency.pack_id == pin.pack_id)
        {
            return Err((
                "dependency-pin-mismatch",
                format!("request pins undeclared dependency {}", pin.pack_id),
                None,
            ));
        }
    }
    if matches!(request.selection, PackSelection::Strict { .. })
        && request.dependencies.len() != root.manifest.release_dependencies.len()
    {
        return Err((
            "dependency-pin-mismatch",
            "strict request does not pin every declared dependency".to_owned(),
            None,
        ));
    }
    if dependency_indices
        .iter()
        .filter(|index| has_native_artifact(&inventory.releases[**index].manifest))
        .count()
        > 1
    {
        return Err((
            "dependency-contract",
            "selection has more than one native dependency".to_owned(),
            Some(Box::new(OpenPackError::manifest(
                "a selection cannot export more than one native semantic bundle",
            ))),
        ));
    }
    Ok(dependency_indices)
}

fn has_native_artifact(manifest: &PackRelease) -> bool {
    manifest.artifacts.iter().any(|artifact| {
        artifact.role == ArtifactRole::Native && is_archive_format(&artifact.format)
    })
}

fn is_archive_format(format: &str) -> bool {
    matches!(format, "tar.gz" | "zip")
}

fn push_rejection(
    rejections: &mut Vec<Value>,
    release: &ReleaseRecord,
    reason: &str,
    detail: String,
) {
    if rejections.len() < 32 {
        rejections.push(json!({
            "pack_id": release.manifest.pack.id,
            "release_version": release.manifest.release_version,
            "tag": release.cached.tag,
            "reason": reason,
            "detail": truncate_message(&detail),
        }));
    }
}

fn validate_rules_source_contents(manifest: &PackRelease) -> Result<(), OpenPackError> {
    if manifest.contents.is_empty()
        || manifest
            .contents
            .iter()
            .any(|content| !content.path.starts_with("rules/"))
    {
        return Err(OpenPackError::manifest(
            "root pack content must be nonempty and lie beneath rules/",
        ));
    }
    Ok(())
}

fn cache_artifact(
    root: &Path,
    artifact: &ReleaseArtifact,
    asset: &AssetRecord,
    source: Option<&PackSource>,
    offline: bool,
    transport: &dyn HttpTransport,
) -> Result<PathBuf, OpenPackError> {
    validate_asset_url(&asset.url, &artifact.name, true, source)?;
    let artifact_path = root.join("artifacts").join(&artifact.sha256);
    if path_exists(&artifact_path)? {
        let metadata = fs::symlink_metadata(&artifact_path).map_err(|error| {
            OpenPackError::integrity(format!(
                "inspect cached artifact {}: {error}",
                artifact.name
            ))
        })?;
        if !metadata.file_type().is_file() {
            return Err(OpenPackError::integrity(format!(
                "cached artifact {} is not a regular file",
                artifact.name
            )));
        }
        if metadata.len() != artifact.size_bytes {
            return Err(OpenPackError::integrity(format!(
                "cached artifact {} has the wrong declared size",
                artifact.name
            )));
        }
        if hash_file(&artifact_path)? != artifact.sha256 {
            return Err(OpenPackError::integrity(format!(
                "cached artifact {} failed its declared SHA-256 check",
                artifact.name
            )));
        }
        return Ok(artifact_path);
    }
    if offline {
        return Err(OpenPackError::OfflineCacheMiss(format!(
            "verified artifact {} is not cached for offline use",
            artifact.name
        )));
    }
    let bytes = fetch_bytes(transport, &asset.url, MAX_ARTIFACT_BYTES)?;
    if bytes.len() as u64 != artifact.size_bytes || sha256(&bytes) != artifact.sha256 {
        return Err(OpenPackError::integrity(format!(
            "downloaded artifact {} failed its declared size or SHA-256 check",
            artifact.name
        )));
    }
    write_atomic_noclobber(&artifact_path, &bytes)?;
    if hash_file(&artifact_path)? != artifact.sha256 {
        return Err(OpenPackError::integrity(format!(
            "published artifact {} failed its declared SHA-256 check",
            artifact.name
        )));
    }
    Ok(artifact_path)
}

fn cached_artifact_for<'a>(
    artifacts: &'a [CachedArtifact],
    release_index: usize,
    artifact: &ReleaseArtifact,
) -> Result<&'a CachedArtifact, OpenPackError> {
    artifacts
        .iter()
        .find(|cached| cached.release_index == release_index && cached.artifact == *artifact)
        .ok_or_else(|| {
            OpenPackError::integrity(format!(
                "verified artifact cache record is missing for {}",
                artifact.name
            ))
        })
}

fn selection_id(
    profile: &EngineProfile,
    request: &PackRequest,
    inventory: &Inventory,
    selected: &[usize],
) -> Result<String, OpenPackError> {
    let profile = serde_json::to_value(profile)
        .map_err(|error| OpenPackError::integrity(format!("serialize engine profile: {error}")))?;
    let releases = selected
        .iter()
        .map(|index| {
            let release = &inventory.releases[*index];
            json!({
                "pack_id": release.manifest.pack.id,
                "release_version": release.manifest.release_version,
                "source_commit": release.manifest.source.commit,
                "tag": release.cached.tag,
                "manifest_sha256": release.cached.manifest_sha256,
            })
        })
        .collect::<Vec<_>>();
    let bytes = canonical_json_bytes(&json!({
        "engine_profile": profile,
        "source_identity": {
            "pack_id": request.pack_id,
            "repository": request.repository,
            "inventory": request.inventory,
        },
        "releases": releases,
    }))?;
    Ok(sha256(&bytes))
}

fn build_receipt(selection: &SelectionContext<'_>) -> Result<Value, OpenPackError> {
    let SelectionContext {
        profile,
        request,
        inventory,
        root_index,
        dependency_indices,
        selection_id,
        selection_reason,
        rejections,
        cached_artifacts,
        extracted_files,
    } = selection;
    let mut selected = Vec::with_capacity(dependency_indices.len() + 1);
    selected.push(*root_index);
    selected.extend(dependency_indices.iter().copied());
    let fully_qualified = selected.iter().all(|index| {
        let manifest = &inventory.releases[*index].manifest;
        match &manifest.qualification_v1 {
            Some(qualification) => qualification.status == "qualified",
            None => manifest
                .qualification_v2
                .as_ref()
                .is_some_and(|qualification| {
                    qualification.integrity.status == "verified"
                        && qualification.behavior.status == "qualified"
                }),
        }
    });
    let profile_value = serde_json::to_value(profile)
        .map_err(|error| OpenPackError::integrity(format!("serialize engine profile: {error}")))?;
    let releases = selected
        .iter()
        .enumerate()
        .map(|(position, index)| {
            let release = &inventory.releases[*index];
            let role = if position == 0 { "root" } else { "dependency" };
            let artifacts = release
                .manifest
                .artifacts
                .iter()
                .map(|artifact| {
                    json!({
                        "name": artifact.name,
                        "role": artifact.role,
                        "size_bytes": artifact.size_bytes,
                        "sha256": artifact.sha256,
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "role": role,
                "pack_id": release.manifest.pack.id,
                "release_version": release.manifest.release_version,
                "visibility": release.manifest.pack.visibility,
                "source_commit": release.manifest.source.commit,
                "tag": release.cached.tag,
                "tag_commit": release.cached.tag_commit,
                "manifest_schema_version": release.manifest.schema_version,
                "manifest_sha256": release.cached.manifest_sha256,
                "qualification": release.manifest.qualification,
                "provenance": release.raw_manifest.get("provenance").cloned().unwrap_or(Value::Null),
                "artifacts": artifacts,
                "contents": release.manifest.contents.iter()
                    .map(|content| json!({ "path": content.path, "sha256": content.sha256 }))
                    .collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    let artifacts = cached_artifacts
        .iter()
        .map(|cached| {
            let release = &inventory.releases[cached.release_index];
            json!({
                "pack_id": release.manifest.pack.id,
                "release_version": release.manifest.release_version,
                "name": cached.artifact.name,
                "role": cached.artifact.role,
                "size_bytes": cached.artifact.size_bytes,
                "sha256": cached.artifact.sha256,
                "cache_path": cached.path,
            })
        })
        .collect::<Vec<_>>();
    let root = &inventory.releases[*root_index];
    let dependencies = dependency_indices
        .iter()
        .map(|index| {
            let release = &inventory.releases[*index];
            PackDependencyPin {
                pack_id: release.manifest.pack.id.clone(),
                repository: release.manifest.pack.repository.clone(),
                release_version: Some(release.manifest.release_version.clone()),
                manifest_sha256: release.cached.manifest_sha256.clone(),
            }
        })
        .collect::<Vec<_>>();
    let replay = PackRequest {
        request_schema_version: 1,
        pack_id: root.manifest.pack.id.clone(),
        repository: root.manifest.pack.repository.clone(),
        inventory: request.inventory.clone(),
        selection: PackSelection::Strict {
            release_version: root.manifest.release_version.clone(),
            manifest_sha256: root.cached.manifest_sha256.clone(),
        },
        dependencies,
    };
    let source_value = json!({
        "repository": request.repository,
        "inventory_url": request.inventory.as_ref().map(|inventory| &inventory.url),
        "inventory_sha256_pin": request.inventory.as_ref().map(|inventory| &inventory.sha256),
        "index_sha256": inventory.inventory_sha256,
        "fetched_at": inventory.fetched_at,
        "fetched_online": inventory.fetched_online,
    });
    let receipt = json!({
        "receipt_schema_version": 3,
        "status": if fully_qualified { "qualified" } else { "compatible" },
        "selection_id": selection_id,
        "selection_reason": selection_reason,
        "request": request,
        "engine": {
            "version": profile.engine_version,
            "build_identity": profile.build_identity,
            "profile": profile_value,
        },
        "source": source_value,
        "releases": releases,
        "rejections": rejections.iter().take(32).collect::<Vec<_>>(),
        "extracted_files": extracted_files,
        "artifacts": artifacts,
        "replay": replay,
        "created_at": format_iso_utc(SystemTime::now())?,
    });
    Ok(receipt)
}

fn verify_existing_selection(
    final_root: &Path,
    receipt_path: &Path,
    selection: &SelectionContext<'_>,
) -> Result<(), OpenPackError> {
    require_real_directory(final_root, "cached open-pack selection")?;
    let actual_bytes = read_regular_file(receipt_path, MAX_MANIFEST_BYTES)?;
    let actual: Value = parse_json_value(&actual_bytes).map_err(|error| {
        OpenPackError::integrity(format!(
            "cached open-pack selection receipt is corrupt: {error}"
        ))
    })?;
    let expected = build_receipt(selection)?;
    if !valid_receipt_shape(&actual) || receipt_identity(&actual) != receipt_identity(&expected) {
        return Err(OpenPackError::integrity(
            "cached open-pack selection receipt does not match the selected releases",
        ));
    }
    let mut selected = Vec::with_capacity(selection.dependency_indices.len() + 1);
    selected.push(selection.root_index);
    selected.extend(selection.dependency_indices.iter().copied());
    for (position, index) in selected.iter().enumerate() {
        let release = &selection.inventory.releases[*index];
        let label = if position == 0 {
            "root".to_owned()
        } else {
            format!("dependency-{}", release.manifest.pack.id)
        };
        let extracted_root = final_root.join(&label);
        verify_extracted_tree(&extracted_root, &selection.extracted_files[&label])?;
        verify_manifest_contents(&release.manifest, &extracted_root)?;
        if position == 0 {
            require_real_directory(&extracted_root.join("rules"), "cached policy pack root")?;
        } else if has_native_artifact(&release.manifest) {
            require_regular_file(
                &extracted_root
                    .join("bifrost-semantic-packs")
                    .join("index.json"),
                "cached native semantic bundle index",
            )?;
        }
    }
    Ok(())
}

fn valid_receipt_shape(receipt: &Value) -> bool {
    let Some(object) = receipt.as_object() else {
        return false;
    };
    let expected = [
        "receipt_schema_version",
        "status",
        "selection_id",
        "selection_reason",
        "request",
        "engine",
        "source",
        "releases",
        "rejections",
        "extracted_files",
        "artifacts",
        "replay",
        "created_at",
    ];
    object.len() == expected.len()
        && expected.iter().all(|field| object.contains_key(*field))
        && receipt
            .get("receipt_schema_version")
            .and_then(Value::as_u64)
            == Some(3)
        && receipt
            .get("created_at")
            .and_then(Value::as_str)
            .and_then(parse_iso_utc_millis)
            .is_some()
}

fn receipt_identity(receipt: &Value) -> Value {
    let Some(object) = receipt.as_object() else {
        return Value::Null;
    };
    let mut identity = object.clone();
    identity.remove("created_at");
    identity.remove("request");
    identity.remove("selection_reason");
    identity.remove("rejections");
    if let Some(source) = identity.get_mut("source").and_then(Value::as_object_mut) {
        source.remove("fetched_at");
        source.remove("fetched_online");
        source.remove("index_sha256");
    }
    Value::Object(identity)
}

/// Build the stable machine-readable result for a single acquisition attempt.
pub fn acquisition_outcome(
    engine_profile: &Value,
    request: Option<&PackRequest>,
    result: Result<OpenPackSelection, OpenPackError>,
) -> Value {
    let engine = json!({
        "version": engine_profile.get("engine_version").cloned().unwrap_or(Value::Null),
        "build_identity": engine_profile.get("build_identity").cloned().unwrap_or(Value::Null),
    });
    let created_at =
        format_iso_utc(SystemTime::now()).unwrap_or_else(|_| "1970-01-01T00:00:00.000Z".to_owned());
    match result {
        Ok(selection) => {
            let receipt = read_regular_file(&selection.receipt_path, MAX_MANIFEST_BYTES)
                .map_err(|_| OpenPackError::integrity("selected pack receipt could not be read"))
                .and_then(|bytes| {
                    parse_json_value(&bytes).map_err(|_| {
                        OpenPackError::integrity("selected pack receipt is invalid JSON")
                    })
                })
                .and_then(|receipt| {
                    if valid_receipt_shape(&receipt) {
                        Ok(receipt)
                    } else {
                        Err(OpenPackError::integrity(
                            "selected pack receipt has an invalid shape",
                        ))
                    }
                });
            match receipt {
                Ok(receipt) => json!({
                    "outcome_schema_version": 1,
                    "status": "selected",
                    "engine": engine,
                    "request": request,
                    "failure": Value::Null,
                    "rejections": selection.rejections,
                    "inventory": selection.inventory,
                    "selection": {
                        "selection_id": selection.selection_id,
                        "selection_reason": selection.selection_reason,
                        "cache_reused": selection.cache_reused,
                        "receipt_path": selection.receipt_path,
                        "policy_pack_root": selection.policy_pack_root,
                        "semantic_bundle_root": selection.semantic_bundle_root,
                        "receipt": receipt,
                    },
                    "created_at": created_at,
                }),
                Err(error) => failed_outcome(engine, request, error, created_at),
            }
        }
        Err(error) => failed_outcome(engine, request, error, created_at),
    }
}

fn failed_outcome(
    engine: Value,
    request: Option<&PackRequest>,
    error: OpenPackError,
    created_at: String,
) -> Value {
    let class = error.failure_class();
    let message = sanitize_message(&error.to_string());
    let (rejections, inventory) = error_rejections_and_inventory(&error);
    json!({
        "outcome_schema_version": 1,
        "status": "failed",
        "engine": engine,
        "request": request,
        "failure": {
            "class": class.name,
            "retryable": class.retryable,
            "message": truncate_message(&message),
        },
        "rejections": rejections,
        "inventory": inventory,
        "selection": Value::Null,
        "created_at": created_at,
    })
}

fn error_rejections_and_inventory(error: &OpenPackError) -> (Value, Value) {
    match error {
        OpenPackError::SelectionRejected {
            rejections,
            inventory,
            ..
        } => (
            json!(rejections.iter().take(32).collect::<Vec<_>>()),
            inventory.clone(),
        ),
        OpenPackError::NoCompatibleRelease { receipt, .. } => (
            receipt
                .get("rejections")
                .cloned()
                .unwrap_or_else(|| json!([])),
            json!({
                "index_sha256": receipt.get("inventory_sha256"),
                "fetched_at": receipt.get("inventory_fetched_at"),
                "fetched_online": true,
            }),
        ),
        _ => (json!([]), Value::Null),
    }
}

fn sanitize_message(message: &str) -> String {
    match std::env::var("PACK_TOKEN") {
        Ok(token) if !token.is_empty() => message.replace(&token, "[redacted]"),
        _ => message.to_owned(),
    }
}

fn truncate_message(message: &str) -> String {
    if message.len() <= 1024 {
        return message.to_owned();
    }
    let end = message
        .char_indices()
        .map(|(index, _)| index)
        .take_while(|index| *index <= 1021)
        .last()
        .unwrap_or(0);
    format!("{}...", &message[..end])
}

#[cfg(test)]
fn inspect_archive(
    archive_path: &Path,
    destination: Option<&Path>,
) -> Result<Vec<ExtractedFile>, OpenPackError> {
    inspect_archive_format(archive_path, "tar.gz", destination)
}

fn inspect_archive_format(
    archive_path: &Path,
    format: &str,
    destination: Option<&Path>,
) -> Result<Vec<ExtractedFile>, OpenPackError> {
    match format {
        "tar.gz" => inspect_tar_gz_archive(archive_path, destination),
        "zip" => inspect_zip_archive(archive_path, destination),
        _ => Err(OpenPackError::manifest(format!(
            "unsupported content archive format {format}"
        ))),
    }
}

fn inspect_tar_gz_archive(
    archive_path: &Path,
    destination: Option<&Path>,
) -> Result<Vec<ExtractedFile>, OpenPackError> {
    let file = File::open(archive_path).map_err(|error| {
        OpenPackError::integrity(format!(
            "open verified pack artifact {}: {error}",
            archive_path.display()
        ))
    })?;
    let decoder = GzDecoder::new(file);
    let limited = CountingReader::new(decoder).take(MAX_UNPACKED_BYTES + 1);
    let mut archive = Archive::new(limited);
    let entries = archive
        .entries()
        .map_err(|error| OpenPackError::integrity(format!("read pack archive entries: {error}")))?;
    let mut seen = HashSet::new();
    let mut files = HashSet::new();
    let mut directories = HashSet::new();
    let mut descendants = HashSet::new();
    let mut records = Vec::new();
    let mut entry_count = 0_usize;
    let mut extracted_bytes = 0_u64;
    for item in entries {
        entry_count += 1;
        if entry_count > MAX_ARCHIVE_ENTRIES {
            return Err(OpenPackError::integrity(
                "pack archive exceeds the entry count limit",
            ));
        }
        let mut entry = item.map_err(|error| {
            OpenPackError::integrity(format!("read pack archive entry: {error}"))
        })?;
        let mut entry_pax_bytes = 0_usize;
        let entry_size = entry.size();
        if let Some(extensions) = entry.pax_extensions().map_err(|error| {
            OpenPackError::integrity(format!("read pack archive PAX metadata: {error}"))
        })? {
            let mut pax_keys = BTreeSet::new();
            for extension in extensions {
                let extension = extension.map_err(|error| {
                    OpenPackError::integrity(format!("read pack archive PAX field: {error}"))
                })?;
                let key = extension.key().map_err(|error| {
                    OpenPackError::integrity(format!("decode pack archive PAX key: {error}"))
                })?;
                let value = extension.value().map_err(|error| {
                    OpenPackError::integrity(format!("decode pack archive PAX value: {error}"))
                })?;
                if !["path", "size", "mtime", "uid", "gid", "uname", "gname"].contains(&key)
                    || !pax_keys.insert(key)
                {
                    return Err(OpenPackError::integrity(format!(
                        "pack archive PAX field {key} is duplicate or unsupported"
                    )));
                }
                entry_pax_bytes = entry_pax_bytes
                    .checked_add(key.len() + value.len() + 32)
                    .ok_or_else(|| OpenPackError::integrity("pack archive PAX size overflow"))?;
                if entry_pax_bytes > MAX_PAX_BYTES {
                    return Err(OpenPackError::integrity(
                        "pack archive PAX metadata exceeds the byte limit",
                    ));
                }
                if key == "size" && value.parse::<u64>().ok() != Some(entry_size) {
                    return Err(OpenPackError::integrity(
                        "pack archive PAX size disagrees with entry data",
                    ));
                }
            }
        }
        let entry_type = entry.header().entry_type();
        let is_directory = entry_type == EntryType::Directory;
        if !is_directory && entry_type != EntryType::Regular {
            return Err(OpenPackError::integrity(format!(
                "pack archive entry uses forbidden link or special type {}",
                entry_type.as_byte()
            )));
        }
        let raw_path = entry
            .path()
            .map_err(|error| OpenPackError::integrity(format!("read pack archive path: {error}")))?
            .to_string_lossy()
            .into_owned();
        let normalized = if is_directory {
            raw_path.strip_suffix('/').unwrap_or(&raw_path)
        } else {
            &raw_path
        };
        let parts = validate_archive_path(normalized)?;
        let path = parts.join("/");
        if !seen.insert(path.clone()) {
            return Err(OpenPackError::integrity(format!(
                "pack archive contains duplicate path {path}"
            )));
        }
        for index in 1..parts.len() {
            let ancestor = parts[..index].join("/");
            if files.contains(&ancestor) {
                return Err(OpenPackError::integrity(format!(
                    "pack archive path {path} descends through a file"
                )));
            }
            descendants.insert(ancestor);
        }
        let output_path = destination.map(|root| {
            parts
                .iter()
                .fold(root.to_path_buf(), |path, part| path.join(part))
        });
        if is_directory {
            if entry.size() != 0 {
                return Err(OpenPackError::integrity(format!(
                    "pack archive directory {path} has data"
                )));
            }
            directories.insert(path);
            if let Some(output_path) = output_path {
                fs::create_dir_all(output_path).map_err(|error| {
                    OpenPackError::integrity(format!("create extracted directory: {error}"))
                })?;
            }
            continue;
        }
        if directories.contains(&path) || descendants.contains(&path) {
            return Err(OpenPackError::integrity(format!(
                "pack archive file {path} conflicts with a directory or child path"
            )));
        }
        let size = entry_size;
        extracted_bytes = extracted_bytes
            .checked_add(size)
            .ok_or_else(|| OpenPackError::integrity("pack archive extracted size overflow"))?;
        if extracted_bytes > MAX_UNPACKED_BYTES {
            return Err(OpenPackError::integrity(
                "pack archive exceeds the unpacked byte limit",
            ));
        }
        let mut output = output_path
            .map(|path| {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).map_err(|error| {
                        OpenPackError::integrity(format!(
                            "create extracted parent directory: {error}"
                        ))
                    })?;
                }
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)
                    .map_err(|error| {
                        OpenPackError::integrity(format!(
                            "create extracted file {}: {error}",
                            path.display()
                        ))
                    })
            })
            .transpose()?;
        let (written, digest) = hash_copy(&mut entry, output.as_mut())?;
        if written != size {
            return Err(OpenPackError::integrity(format!(
                "pack archive file {path} declared {size} bytes but contained {written}"
            )));
        }
        records.push(ExtractedFile {
            path,
            size_bytes: written,
            sha256: digest,
        });
        files.insert(parts.join("/"));
    }
    let mut reader = archive.into_inner();
    let mut trailing = [0_u8; 8192];
    while reader.read(&mut trailing).map_err(|error| {
        OpenPackError::integrity(format!("finish reading pack archive: {error}"))
    })? != 0
    {}
    let counted = reader.into_inner();
    if counted.bytes_read > MAX_UNPACKED_BYTES {
        return Err(OpenPackError::integrity(
            "pack archive exceeds the unpacked byte limit",
        ));
    }
    records.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(records)
}

fn inspect_zip_archive(
    archive_path: &Path,
    destination: Option<&Path>,
) -> Result<Vec<ExtractedFile>, OpenPackError> {
    let file = File::open(archive_path).map_err(|error| {
        OpenPackError::integrity(format!(
            "open verified pack artifact {}: {error}",
            archive_path.display()
        ))
    })?;
    let mut archive = ZipArchive::new(file)
        .map_err(|_| OpenPackError::integrity("pack ZIP central directory is invalid"))?;
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(OpenPackError::integrity(
            "pack archive exceeds the entry count limit",
        ));
    }
    let mut seen = HashSet::new();
    let mut files = HashSet::new();
    let mut directories = HashSet::new();
    let mut descendants = HashSet::new();
    let mut records = Vec::new();
    let mut extracted_bytes = 0_u64;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|_| OpenPackError::integrity("read pack ZIP entry"))?;
        if entry.encrypted() {
            return Err(OpenPackError::integrity(
                "pack ZIP contains an encrypted entry",
            ));
        }
        let is_directory = entry.is_dir();
        if let Some(mode) = entry.unix_mode() {
            let file_type = mode & 0o170000;
            if !matches!(file_type, 0 | 0o100000 | 0o040000)
                || (is_directory && file_type == 0o100000)
                || (!is_directory && file_type == 0o040000)
            {
                return Err(OpenPackError::integrity(
                    "pack ZIP contains a symbolic link or special file",
                ));
            }
        }
        let raw_path = entry.name();
        let normalized = if is_directory {
            raw_path.strip_suffix('/').unwrap_or(raw_path)
        } else {
            raw_path
        };
        let parts = validate_archive_path(normalized)?;
        let path = parts.join("/");
        if !seen.insert(path.clone()) {
            return Err(OpenPackError::integrity(format!(
                "pack archive contains duplicate path {path}"
            )));
        }
        for ancestor_index in 1..parts.len() {
            let ancestor = parts[..ancestor_index].join("/");
            if files.contains(&ancestor) {
                return Err(OpenPackError::integrity(format!(
                    "pack archive path {path} descends through a file"
                )));
            }
            descendants.insert(ancestor);
        }
        let output_path = destination.map(|root| {
            parts
                .iter()
                .fold(root.to_path_buf(), |path, part| path.join(part))
        });
        let size = entry.size();
        if is_directory {
            if size != 0 {
                return Err(OpenPackError::integrity(format!(
                    "pack ZIP directory {path} has data"
                )));
            }
            directories.insert(path);
            if let Some(output_path) = output_path {
                fs::create_dir_all(output_path).map_err(|error| {
                    OpenPackError::integrity(format!("create extracted directory: {error}"))
                })?;
            }
            continue;
        }
        if directories.contains(&path) || descendants.contains(&path) {
            return Err(OpenPackError::integrity(format!(
                "pack ZIP file {path} conflicts with a directory or child path"
            )));
        }
        extracted_bytes = extracted_bytes
            .checked_add(size)
            .ok_or_else(|| OpenPackError::integrity("pack ZIP extracted size overflow"))?;
        if extracted_bytes > MAX_UNPACKED_BYTES {
            return Err(OpenPackError::integrity(
                "pack archive exceeds the unpacked byte limit",
            ));
        }
        let mut output = output_path
            .map(|path| {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).map_err(|error| {
                        OpenPackError::integrity(format!(
                            "create extracted parent directory: {error}"
                        ))
                    })?;
                }
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)
                    .map_err(|error| {
                        OpenPackError::integrity(format!(
                            "create extracted file {}: {error}",
                            path.display()
                        ))
                    })
            })
            .transpose()?;
        let (written, digest) = hash_copy(&mut entry, output.as_mut())?;
        if written != size {
            return Err(OpenPackError::integrity(format!(
                "pack ZIP file {path} declared {size} bytes but contained {written}"
            )));
        }
        records.push(ExtractedFile {
            path: path.clone(),
            size_bytes: written,
            sha256: digest,
        });
        files.insert(path);
    }
    records.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(records)
}

struct CountingReader<R> {
    inner: R,
    bytes_read: u64,
}

impl<R> CountingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            bytes_read: 0,
        }
    }
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(bytes)?;
        self.bytes_read = self.bytes_read.saturating_add(read as u64);
        Ok(read)
    }
}

fn validate_archive_path(path: &str) -> Result<Vec<&str>, OpenPackError> {
    validate_safe_relative_path(path, "archive entry path")
        .map_err(|error| OpenPackError::integrity(error.to_string()))
}

fn hash_copy(
    input: &mut impl Read,
    mut output: Option<&mut File>,
) -> Result<(u64, String), OpenPackError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = input.read(&mut buffer).map_err(|error| {
            OpenPackError::integrity(format!("read extracted pack file: {error}"))
        })?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| OpenPackError::integrity("extracted file size overflow"))?;
        hasher.update(&buffer[..read]);
        if let Some(output) = output.as_deref_mut() {
            output.write_all(&buffer[..read]).map_err(|error| {
                OpenPackError::integrity(format!("write extracted pack file: {error}"))
            })?;
        }
    }
    Ok((total, format!("{:x}", hasher.finalize())))
}

fn verify_manifest_contents(manifest: &PackRelease, root: &Path) -> Result<(), OpenPackError> {
    for content in &manifest.contents {
        let components = validate_safe_relative_path(&content.path, "manifest content path")
            .map_err(|error| OpenPackError::integrity(error.to_string()))?;
        let mut current = root.to_path_buf();
        for (index, component) in components.iter().enumerate() {
            current.push(component);
            let metadata = fs::symlink_metadata(&current).map_err(|error| {
                OpenPackError::integrity(format!(
                    "manifest content {} is missing: {error}",
                    content.path
                ))
            })?;
            if metadata.file_type().is_symlink()
                || (index + 1 < components.len() && !metadata.is_dir())
                || (index + 1 == components.len() && !metadata.is_file())
            {
                return Err(OpenPackError::integrity(format!(
                    "manifest content {} has an unsafe filesystem type",
                    content.path
                )));
            }
        }
        if hash_file(&current)? != content.sha256 {
            return Err(OpenPackError::integrity(format!(
                "manifest content {} failed its SHA-256 check",
                content.path
            )));
        }
    }
    Ok(())
}

fn verify_extracted_tree(root: &Path, expected: &[ExtractedFile]) -> Result<(), OpenPackError> {
    require_real_directory(root, "cached pack extraction root")?;
    let mut found = Vec::new();
    let mut pending = vec![(root.to_path_buf(), String::new())];
    while let Some((absolute, prefix)) = pending.pop() {
        for item in fs::read_dir(&absolute).map_err(|error| {
            OpenPackError::integrity(format!(
                "read cached extraction {}: {error}",
                absolute.display()
            ))
        })? {
            let item = item.map_err(|error| {
                OpenPackError::integrity(format!("read cached extraction entry: {error}"))
            })?;
            let path = item.path();
            let name = item.file_name().to_string_lossy().into_owned();
            let relative = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                OpenPackError::integrity(format!("inspect cached extraction entry: {error}"))
            })?;
            if metadata.file_type().is_symlink() {
                return Err(OpenPackError::integrity(format!(
                    "cached extraction contains a symbolic link at {relative}"
                )));
            }
            if metadata.is_dir() {
                pending.push((path, relative));
            } else if metadata.is_file() {
                found.push(ExtractedFile {
                    path: relative,
                    size_bytes: metadata.len(),
                    sha256: hash_file(&path)?,
                });
            } else {
                return Err(OpenPackError::integrity(format!(
                    "cached extraction contains a special file at {relative}"
                )));
            }
        }
    }
    found.sort_by(|left, right| left.path.cmp(&right.path));
    if found != expected {
        return Err(OpenPackError::integrity(
            "cached pack extraction differs from the verified artifact contents",
        ));
    }
    Ok(())
}

fn require_real_directory(path: &Path, label: &str) -> Result<(), OpenPackError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| OpenPackError::integrity(format!("{label} is missing: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(OpenPackError::integrity(format!(
            "{label} must be a real directory"
        )));
    }
    Ok(())
}

fn require_regular_file(path: &Path, label: &str) -> Result<(), OpenPackError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| OpenPackError::integrity(format!("{label} is missing: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(OpenPackError::integrity(format!(
            "{label} must be a regular file"
        )));
    }
    Ok(())
}

fn path_exists(path: &Path) -> Result<bool, OpenPackError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(OpenPackError::integrity(format!(
            "inspect path {}: {error}",
            path.display()
        ))),
    }
}

fn read_regular_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, OpenPackError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            OpenPackError::unavailable(format!("file {} is not cached", path.display()))
        } else {
            OpenPackError::integrity(format!("read file metadata {}: {error}", path.display()))
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(OpenPackError::integrity(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > max_bytes {
        return Err(OpenPackError::integrity(format!(
            "{} exceeds the {max_bytes}-byte limit",
            path.display()
        )));
    }
    fs::read(path)
        .map_err(|error| OpenPackError::integrity(format!("read file {}: {error}", path.display())))
}

fn hash_file(path: &Path) -> Result<String, OpenPackError> {
    let mut file = File::open(path).map_err(|error| {
        OpenPackError::integrity(format!("open file {} for hashing: {error}", path.display()))
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            OpenPackError::integrity(format!("hash file {}: {error}", path.display()))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn write_atomic_noclobber(path: &Path, bytes: &[u8]) -> Result<(), OpenPackError> {
    let parent = path.parent().ok_or_else(|| {
        OpenPackError::integrity(format!("cache path has no parent: {}", path.display()))
    })?;
    fs::create_dir_all(parent).map_err(|error| {
        OpenPackError::integrity(format!(
            "create cache directory {}: {error}",
            parent.display()
        ))
    })?;
    let mut temporary = NamedTempFile::new_in(parent).map_err(|error| {
        OpenPackError::integrity(format!("create temporary cache file: {error}"))
    })?;
    temporary.write_all(bytes).map_err(|error| {
        OpenPackError::integrity(format!("write temporary cache file: {error}"))
    })?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| OpenPackError::integrity(format!("sync temporary cache file: {error}")))?;
    match temporary.persist_noclobber(path) {
        Ok(_) => Ok(()),
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
            let existing = read_regular_file(path, bytes.len() as u64)?;
            if existing == bytes {
                Ok(())
            } else {
                Err(OpenPackError::integrity(format!(
                    "refusing to replace conflicting cached file {}",
                    path.display()
                )))
            }
        }
        Err(error) => Err(OpenPackError::integrity(format!(
            "publish cached file {}: {}",
            path.display(),
            error.error
        ))),
    }
}

fn write_atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), OpenPackError> {
    let parent = path.parent().ok_or_else(|| {
        OpenPackError::integrity(format!("cache path has no parent: {}", path.display()))
    })?;
    fs::create_dir_all(parent).map_err(|error| {
        OpenPackError::integrity(format!(
            "create cache directory {}: {error}",
            parent.display()
        ))
    })?;
    let mut temporary = NamedTempFile::new_in(parent).map_err(|error| {
        OpenPackError::integrity(format!("create temporary cache file: {error}"))
    })?;
    temporary.write_all(bytes).map_err(|error| {
        OpenPackError::integrity(format!("write temporary cache file: {error}"))
    })?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| OpenPackError::integrity(format!("sync temporary cache file: {error}")))?;
    temporary.persist(path).map_err(|error| {
        OpenPackError::integrity(format!(
            "atomically publish cached file {}: {}",
            path.display(),
            error.error
        ))
    })?;
    Ok(())
}

fn unix_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

fn format_iso_utc(time: SystemTime) -> Result<String, OpenPackError> {
    let duration = time.duration_since(UNIX_EPOCH).map_err(|error| {
        OpenPackError::Configuration(format!("system clock is before the Unix epoch: {error}"))
    })?;
    let total_millis = duration.as_millis().min(i64::MAX as u128) as i64;
    let seconds = total_millis.div_euclid(1000);
    let millis = total_millis.rem_euclid(1000);
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    if !(0..=9999).contains(&year) {
        return Err(OpenPackError::Configuration(
            "system clock year is outside the supported range".to_owned(),
        ));
    }
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        seconds_of_day / 3600,
        (seconds_of_day % 3600) / 60,
        seconds_of_day % 60
    ))
}

fn parse_iso_utc_millis(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    if bytes.len() != 24
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'.'
        || bytes[23] != b'Z'
    {
        return None;
    }
    let digits = |range: std::ops::Range<usize>| -> Option<i64> {
        let text = std::str::from_utf8(&bytes[range]).ok()?;
        if !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        text.parse().ok()
    };
    let year = i32::try_from(digits(0..4)?).ok()?;
    let month = u32::try_from(digits(5..7)?).ok()?;
    let day = u32::try_from(digits(8..10)?).ok()?;
    let hour = digits(11..13)?;
    let minute = digits(14..16)?;
    let second = digits(17..19)?;
    let millis = digits(20..23)?;
    if !(1..=12).contains(&month)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=59).contains(&second)
        || !(0..=999).contains(&millis)
    {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    if civil_from_days(days) != (year, month, day) {
        return None;
    }
    days.checked_mul(86_400_000)?
        .checked_add(hour * 3_600_000)?
        .checked_add(minute * 60_000)?
        .checked_add(second * 1_000)?
        .checked_add(millis)
}

fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    if !(1..=31).contains(&day) {
        return None;
    }
    let year = year - i32::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let adjusted_month = month as i32 + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day as i32 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some(i64::from(era) * 146_097 + i64::from(day_of_era) - 719_468)
}

fn civil_from_days(days_since_epoch: i64) -> (i32, u32, u32) {
    let days = days_since_epoch + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year as i32, month as u32, day as u32)
}

#[cfg(test)]
mod request_tests;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tar::Builder;
    use tempfile::tempdir;

    use super::test_support::*;

    #[test]
    #[hardwon(
        "#4437: public pack network and offline cache misses must keep runtime on embedded packs"
    )]
    fn runtime_bootstrap_falls_back_for_public_network_and_offline_misses() {
        let cold_cache = tempdir().expect("temporary cold cache");
        let network = FakeTransport::new(BTreeMap::new());
        let cold = prepare_runtime_with_transport(
            cold_cache.path(),
            &engine_profile("9.9.0"),
            false,
            false,
            &network,
        )
        .expect("public network unavailability falls back");
        assert!(matches!(
            cold,
            OpenPackRuntimeOutcome::EmbeddedFallback {
                kind: OpenPackFallbackKind::NetworkUnavailable,
                ..
            }
        ));
        assert_eq!(network.call_count(), 1);

        let offline_cache = tempdir().expect("temporary offline cache");
        let offline_transport = FakeTransport::new(BTreeMap::new());
        let offline = prepare_runtime_with_transport(
            offline_cache.path(),
            &engine_profile("9.9.0"),
            true,
            false,
            &offline_transport,
        )
        .expect("offline cache miss falls back");
        assert!(matches!(
            offline,
            OpenPackRuntimeOutcome::EmbeddedFallback {
                kind: OpenPackFallbackKind::OfflineCacheMiss,
                ..
            }
        ));
        assert_eq!(offline_transport.call_count(), 0);
    }

    #[test]
    #[hardwon("#4906: stale-schema and foreign-source indexes must be cache misses at startup")]
    fn runtime_bootstrap_rediscovers_inapplicable_cached_indexes() {
        let profile = engine_profile("9.9.0");
        for (field, value) in [
            ("schema_version", json!(INVENTORY_SCHEMA_VERSION - 1)),
            (
                "source",
                json!({
                    "repository": "https://github.com/example/previous-packs",
                    "inventory_url": null,
                    "inventory_sha256": null,
                }),
            ),
        ] {
            let cache = tempdir().expect("temporary inapplicable cache");
            write_empty_cached_inventory(cache.path(), SystemTime::now());
            let index_path = cache.path().join("manifest-index.json");
            let mut index: Value =
                serde_json::from_slice(&fs::read(&index_path).expect("read cached index"))
                    .expect("decode cached index");
            index[field] = value;
            let bytes = serde_json::to_vec(&index).expect("encode inapplicable index");
            fs::write(&index_path, &bytes).expect("write inapplicable index");

            let transport = FakeTransport::new(BTreeMap::from([(
                release_listing_url(REPOSITORY_URL),
                b"[]".to_vec(),
            )]));
            let offline =
                prepare_runtime_with_transport(cache.path(), &profile, true, false, &transport)
                    .expect("inapplicable offline index must not fail startup");
            assert!(matches!(
                offline,
                OpenPackRuntimeOutcome::EmbeddedFallback {
                    kind: OpenPackFallbackKind::OfflineCacheMiss,
                    ..
                }
            ));
            assert_eq!(transport.call_count(), 0);
            assert_eq!(fs::read(&index_path).expect("read offline index"), bytes);

            let online =
                prepare_runtime_with_transport(cache.path(), &profile, false, false, &transport)
                    .expect("inapplicable online index must rediscover");
            assert!(matches!(
                online,
                OpenPackRuntimeOutcome::EmbeddedFallback {
                    kind: OpenPackFallbackKind::NoCompatibleRelease,
                    ..
                }
            ));
            assert_eq!(
                transport.called_urls(),
                vec![release_listing_url(REPOSITORY_URL)]
            );
            let refreshed: ManifestIndex =
                serde_json::from_slice(&fs::read(&index_path).expect("read refreshed index"))
                    .expect("decode refreshed index");
            assert_eq!(refreshed.schema_version, INVENTORY_SCHEMA_VERSION);
            assert_eq!(
                refreshed
                    .source
                    .as_ref()
                    .expect("refreshed source")
                    .repository,
                REPOSITORY_URL
            );
        }
    }

    #[test]
    #[hardwon("#4437: verified cached absence must be reused without network in runtime bootstrap")]
    fn runtime_bootstrap_reuses_fresh_and_offline_cached_absence_without_network() {
        let profile = engine_profile("9.9.0");
        let fresh_cache = tempdir().expect("temporary fresh cache");
        write_empty_cached_inventory(fresh_cache.path(), SystemTime::now());
        let fresh_transport = FakeTransport::new(BTreeMap::new());
        let fresh = prepare_runtime_with_transport(
            fresh_cache.path(),
            &profile,
            false,
            false,
            &fresh_transport,
        )
        .expect("fresh cached absence falls back");
        assert!(matches!(
            fresh,
            OpenPackRuntimeOutcome::EmbeddedFallback {
                kind: OpenPackFallbackKind::NoCompatibleRelease,
                ..
            }
        ));
        assert_eq!(fresh_transport.call_count(), 0);

        let offline_cache = tempdir().expect("temporary stale offline cache");
        write_empty_cached_inventory(
            offline_cache.path(),
            SystemTime::now() - MANIFEST_CACHE_TTL - Duration::from_secs(1),
        );
        let offline_transport = FakeTransport::new(BTreeMap::new());
        let offline = prepare_runtime_with_transport(
            offline_cache.path(),
            &profile,
            true,
            false,
            &offline_transport,
        )
        .expect("offline cached absence falls back at any age");
        assert!(matches!(
            offline,
            OpenPackRuntimeOutcome::EmbeddedFallback {
                kind: OpenPackFallbackKind::NoCompatibleRelease,
                ..
            }
        ));
        assert_eq!(offline_transport.call_count(), 0);
    }

    #[test]
    #[hardwon("#4437: public discovery outage must evaluate a stale verified inventory")]
    fn runtime_bootstrap_uses_stale_inventory_after_public_network_failure() {
        let cache = tempdir().expect("temporary stale cache");
        write_empty_cached_inventory(
            cache.path(),
            SystemTime::now() - MANIFEST_CACHE_TTL - Duration::from_secs(1),
        );
        let transport = FakeTransport::new(BTreeMap::new());
        let outcome = prepare_runtime_with_transport(
            cache.path(),
            &engine_profile("9.9.0"),
            false,
            false,
            &transport,
        )
        .expect("stale inventory is used after discovery outage");
        assert!(matches!(
            outcome,
            OpenPackRuntimeOutcome::EmbeddedFallback {
                kind: OpenPackFallbackKind::NoCompatibleRelease,
                ..
            }
        ));
        assert_eq!(transport.call_count(), 1);
    }

    #[test]
    #[hardwon(
        "#4437: pending and unsupported public releases must degrade only during runtime bootstrap"
    )]
    fn runtime_pending_and_unsupported_outcomes_fall_back_only_for_public_selection() {
        let source = LegacyPackSource {
            repository: "https://github.com/example/private-packs".to_owned(),
            rules_version: "1.4.0".to_owned(),
            manifest_sha256: "a".repeat(64),
            semantic_manifest_sha256: "b".repeat(64),
            inventory_url: None,
            inventory_sha256: None,
        };
        for (error, expected) in [
            (
                OpenPackError::Pending("qualification is pending".to_owned()),
                OpenPackFallbackKind::Pending,
            ),
            (
                OpenPackError::IncompatibleSelection("release is unsupported".to_owned()),
                OpenPackFallbackKind::Unsupported,
            ),
        ] {
            let fallback = runtime_fallback(error.clone(), None)
                .expect("default runtime selection falls back");
            assert!(matches!(
                fallback,
                OpenPackRuntimeOutcome::EmbeddedFallback { kind, .. } if kind == expected
            ));
            let explicit = runtime_fallback(error.clone(), Some(&source))
                .expect_err("explicit source errors must remain hard");
            assert_eq!(explicit, error);
        }
        assert!(matches!(
            runtime_fallback(
                OpenPackError::Unqualified("failed behavior".to_owned()),
                None
            ),
            Err(OpenPackError::Unqualified(_))
        ));
    }

    #[test]
    #[hardwon("#4437: corrupt caches and explicit-source network failures must remain hard errors")]
    fn runtime_bootstrap_keeps_corrupt_cache_and_explicit_network_failures_hard() {
        let profile = engine_profile("9.9.0");
        let corrupt_cache = tempdir().expect("temporary corrupt cache");
        fs::create_dir_all(corrupt_cache.path()).expect("create corrupt cache");
        fs::write(
            corrupt_cache.path().join("manifest-index.json"),
            b"not json",
        )
        .expect("write corrupt index");
        let corrupt_transport = FakeTransport::new(BTreeMap::new());
        let corrupt = prepare_runtime_with_transport(
            corrupt_cache.path(),
            &profile,
            false,
            false,
            &corrupt_transport,
        )
        .expect_err("corrupt cache remains fatal");
        assert!(matches!(corrupt, OpenPackError::Integrity(_)));
        assert_eq!(corrupt_transport.call_count(), 0);

        let source = LegacyPackSource {
            repository: "https://github.com/example/private-packs".to_owned(),
            rules_version: "1.4.0".to_owned(),
            manifest_sha256: "a".repeat(64),
            semantic_manifest_sha256: "b".repeat(64),
            inventory_url: None,
            inventory_sha256: None,
        };
        let explicit_cache = tempdir().expect("temporary explicit-source cache");
        let explicit_transport = FakeTransport::new(BTreeMap::new());
        let explicit = prepare_runtime_with_source(
            explicit_cache.path(),
            &profile,
            Some(&source),
            false,
            false,
            &explicit_transport,
        )
        .expect_err("explicit-source network failure remains fatal");
        assert!(matches!(explicit, OpenPackError::Network(_)));
        assert_eq!(explicit_transport.call_count(), 1);
        let requests = explicit_transport.calls.lock().expect("fake call lock");
        assert!(requests[0].contains("/repos/example/private-packs/"));
        assert!(!requests[0].contains("BrokkAi/bifrost-packs"));
    }

    #[test]
    #[hardwon(
        "#4437: runtime bootstrap must reuse verified stale packs after discovery becomes unavailable"
    )]
    fn schema_two_selection_pins_exact_dependency_and_reuses_warm_cache_offline() {
        let fixture = tempdir().expect("temporary cache");
        let rules_manifest_bytes = b"{\"schema_version\":1}";
        let policy_bytes = b"{\"id\":\"fixture-policy\"}";
        let rules_archive = test_archive(&[
            ("rules/fixture/manifest.json", rules_manifest_bytes),
            ("rules/fixture/policy.json", policy_bytes),
        ]);
        let semantic_index = b"{\"schema_version\":1,\"packs\":[]}";
        let semantic_archive =
            test_archive(&[("bifrost-semantic-packs/index.json", semantic_index)]);
        let mut releases = Vec::new();
        let mut responses = BTreeMap::new();
        add_release(
            &mut releases,
            &mut responses,
            ReleaseFixture {
                pack_id: RULES_PACK_ID,
                version: "1.4.0",
                schema_version: 2,
                artifact_role: "source",
                archive: &rules_archive,
                contents: vec![
                    content_entry(
                        "policy-pack",
                        "fixture-pack",
                        "rules/fixture/manifest.json",
                        rules_manifest_bytes,
                    ),
                    content_entry(
                        "policy",
                        "fixture-policy",
                        "rules/fixture/policy.json",
                        policy_bytes,
                    ),
                ],
                dependencies: vec![json!({
                "pack_id": SEMANTIC_PACK_ID,
                "release_version": "1.2.0",
                "repository": REPOSITORY_URL,
                })],
            },
        );
        add_release(
            &mut releases,
            &mut responses,
            ReleaseFixture {
                pack_id: RULES_PACK_ID,
                version: "1.3.0",
                schema_version: 2,
                artifact_role: "source",
                archive: &rules_archive,
                contents: vec![
                    content_entry(
                        "policy-pack",
                        "fixture-pack",
                        "rules/fixture/manifest.json",
                        rules_manifest_bytes,
                    ),
                    content_entry(
                        "policy",
                        "fixture-policy",
                        "rules/fixture/policy.json",
                        policy_bytes,
                    ),
                ],
                dependencies: vec![json!({
                "pack_id": SEMANTIC_PACK_ID,
                "release_version": "1.1.0",
                "repository": REPOSITORY_URL,
                })],
            },
        );
        add_release(
            &mut releases,
            &mut responses,
            ReleaseFixture {
                pack_id: SEMANTIC_PACK_ID,
                version: "1.1.0",
                schema_version: 2,
                artifact_role: "native",
                archive: &semantic_archive,
                contents: Vec::new(),
                dependencies: Vec::new(),
            },
        );
        add_release(
            &mut releases,
            &mut responses,
            ReleaseFixture {
                pack_id: SEMANTIC_PACK_ID,
                version: "1.2.0",
                schema_version: 2,
                artifact_role: "native",
                archive: &semantic_archive,
                contents: Vec::new(),
                dependencies: Vec::new(),
            },
        );
        // A newer unrelated semantic release must not replace the exact pin.
        add_release(
            &mut releases,
            &mut responses,
            ReleaseFixture {
                pack_id: SEMANTIC_PACK_ID,
                version: "9.9.0",
                schema_version: 2,
                artifact_role: "native",
                archive: &semantic_archive,
                contents: Vec::new(),
                dependencies: Vec::new(),
            },
        );
        responses.insert(
            format!("{API_ROOT}/releases?per_page=100&page=1"),
            serde_json::to_vec(&releases).expect("serialize fixture releases"),
        );
        let transport = FakeTransport::new(responses);
        let profile = engine_profile("9.9.0");
        let first = prepare_with_transport(fixture.path(), &profile, false, false, &transport)
            .expect("download and verify compatible selection");
        assert!(!first.cache_reused);
        assert!(
            first
                .semantic_bundle_root
                .as_ref()
                .expect("native dependency is selected")
                .join("index.json")
                .is_file()
        );
        assert!(
            first
                .policy_pack_root
                .join("fixture/manifest.json")
                .is_file()
        );
        let receipt = serde_json::from_slice::<Value>(
            &fs::read(&first.receipt_path).expect("read selection receipt"),
        )
        .expect("valid selection receipt");
        let selected_versions = receipt["releases"]
            .as_array()
            .expect("receipt releases")
            .iter()
            .map(|release| release["release_version"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(selected_versions, BTreeSet::from(["1.4.0", "1.2.0"]));
        assert!(transport.call_count() > 0);

        let offline_transport = FakeTransport::new(BTreeMap::new());
        let second =
            prepare_with_transport(fixture.path(), &profile, true, false, &offline_transport)
                .expect("verified cache must work offline");
        assert!(second.cache_reused);
        assert_eq!(offline_transport.call_count(), 0);

        let cached_index_path = fixture.path().join("manifest-index.json");
        let mut stale_index = serde_json::from_slice::<Value>(
            &fs::read(&cached_index_path).expect("read cached index for runtime stale-cache check"),
        )
        .expect("parse cached index for runtime stale-cache check");
        stale_index["fetched_at"] = json!("2000-01-01T00:00:00.000Z");
        fs::write(
            &cached_index_path,
            serde_json::to_vec(&stale_index).expect("serialize stale cached index"),
        )
        .expect("age runtime cache");
        let stale_runtime_transport = FakeTransport::new(BTreeMap::new());
        let stale_runtime = prepare_runtime_with_transport(
            fixture.path(),
            &profile,
            false,
            false,
            &stale_runtime_transport,
        )
        .expect("runtime keeps using verified stale content during an outage");
        let OpenPackRuntimeOutcome::Selected(stale_selection) = stale_runtime else {
            panic!("verified stale compatible content must remain selected");
        };
        assert!(stale_selection.cache_reused);
        assert_eq!(stale_runtime_transport.call_count(), 1);

        let policy_manifest_path = first.policy_pack_root.join("fixture/manifest.json");
        let policy_manifest_bytes = fs::read(&policy_manifest_path).expect("read extracted policy");
        fs::write(&policy_manifest_path, b"tampered extracted bytes")
            .expect("tamper extracted policy");
        let tampered_extraction =
            prepare_with_transport(fixture.path(), &profile, true, false, &offline_transport)
                .expect_err("restored extracted files are reverified");
        assert!(matches!(tampered_extraction, OpenPackError::Integrity(_)));
        fs::write(&policy_manifest_path, &policy_manifest_bytes).expect("restore extracted policy");

        let manifest_sha = receipt["releases"][0]["manifest_sha256"]
            .as_str()
            .expect("selected descriptor digest");
        let cached_descriptor = fixture
            .path()
            .join("manifests")
            .join(format!("{manifest_sha}.json"));
        let descriptor_bytes = fs::read(&cached_descriptor).expect("read cached descriptor");
        fs::write(&cached_descriptor, b"tampered descriptor").expect("tamper cached descriptor");
        let tampered_descriptor =
            prepare_with_transport(fixture.path(), &profile, true, false, &offline_transport)
                .expect_err("restored descriptors are reverified");
        assert!(matches!(tampered_descriptor, OpenPackError::Integrity(_)));
        fs::write(&cached_descriptor, &descriptor_bytes).expect("restore cached descriptor");

        let index_path = fixture.path().join("manifest-index.json");
        let mut cached_index =
            serde_json::from_slice::<Value>(&fs::read(&index_path).expect("read cached index"))
                .expect("parse cached index");
        cached_index["fetched_at"] = json!("2000-01-01T00:00:00.000Z");
        fs::write(
            &index_path,
            serde_json::to_vec(&cached_index).expect("serialize stale index"),
        )
        .expect("age cached index");
        let stale_transport = FakeTransport::new(BTreeMap::new());
        let stale =
            prepare_with_transport(fixture.path(), &profile, false, false, &stale_transport)
                .expect_err("network failure cannot degrade to a stale cached selection");
        assert!(matches!(stale, OpenPackError::Network(_)));
        assert_eq!(stale_transport.call_count(), 1);
        let refresh_failure =
            prepare_with_transport(fixture.path(), &profile, false, true, &stale_transport)
                .expect_err("refresh must not reuse stale inventory");
        assert!(matches!(refresh_failure, OpenPackError::Network(_)));
        assert_eq!(stale_transport.call_count(), 2);

        let cached_artifact = fs::read_dir(fixture.path().join("artifacts"))
            .expect("artifact cache")
            .next()
            .expect("cached artifact")
            .expect("read cached artifact entry")
            .path();
        fs::write(&cached_artifact, b"tampered").expect("corrupt cached artifact");
        let corrupted =
            prepare_with_transport(fixture.path(), &profile, true, false, &offline_transport)
                .expect_err("corrupt cache content is fatal");
        assert!(matches!(corrupted, OpenPackError::Integrity(_)));
        assert_eq!(offline_transport.call_count(), 0);
    }

    #[test]
    fn explicit_github_source_honors_descriptor_pins_and_warm_cache() {
        let fixture = tempdir().expect("temporary explicit-source cache");
        let repository = "https://github.com/example/bifrost-packs";
        let policy_manifest = b"{}";
        let policy_source = b"{\"id\":\"fixture-policy\"}";
        let rules_archive = test_archive(&[
            ("rules/fixture/manifest.json", policy_manifest),
            ("rules/fixture/policy.json", policy_source),
        ]);
        let semantic_archive =
            test_archive(&[("bifrost-semantic-packs/index.json", b"{\"packs\":[]}")]);
        let mut releases = Vec::new();
        let mut responses = BTreeMap::new();
        let rules_digest = add_release_for(
            &mut releases,
            &mut responses,
            ReleaseFixture {
                pack_id: RULES_PACK_ID,
                version: "1.4.0",
                schema_version: 2,
                artifact_role: "source",
                archive: &rules_archive,
                contents: vec![
                    content_entry(
                        "policy-pack",
                        "fixture-pack",
                        "rules/fixture/manifest.json",
                        policy_manifest,
                    ),
                    content_entry(
                        "policy",
                        "fixture-policy",
                        "rules/fixture/policy.json",
                        policy_source,
                    ),
                ],
                dependencies: vec![json!({
                    "pack_id": SEMANTIC_PACK_ID,
                    "release_version": "1.2.0",
                    "repository": repository,
                })],
            },
            repository,
        );
        let semantic_digest = add_release_for(
            &mut releases,
            &mut responses,
            ReleaseFixture {
                pack_id: SEMANTIC_PACK_ID,
                version: "1.2.0",
                schema_version: 2,
                artifact_role: "native",
                archive: &semantic_archive,
                contents: Vec::new(),
                dependencies: Vec::new(),
            },
            repository,
        );
        let transport = FakeTransport::new(responses);
        let source = LegacyPackSource {
            repository: repository.to_owned(),
            rules_version: "1.4.0".to_owned(),
            manifest_sha256: rules_digest,
            semantic_manifest_sha256: semantic_digest,
            inventory_url: None,
            inventory_sha256: None,
        };
        let request = legacy_source_request(&source);
        validate_pack_request(request.clone()).expect("valid pinned request");
        let profile = engine_profile("9.9.0");
        let cold = prepare_with_source(
            fixture.path(),
            &profile,
            Some(&source),
            false,
            false,
            &transport,
        )
        .expect("pinned source downloads and verifies");
        assert!(!cold.cache_reused);
        assert!(transport.call_count() > 0);
        let identity = source_identity(&request).expect("source identity");
        let root = fixture.path().join("sources").join(identity);
        let offline = FakeTransport::new(BTreeMap::new());
        let warm = prepare_with_source(
            fixture.path(),
            &profile,
            Some(&source),
            true,
            false,
            &offline,
        )
        .expect("pinned cache reuses offline after re-verification");
        assert!(warm.cache_reused);
        assert_eq!(offline.call_count(), 0);
        assert!(root.join("manifest-index.json").is_file());

        let mut changed_version = request.clone();
        let PackSelection::Strict {
            release_version, ..
        } = &mut changed_version.selection
        else {
            panic!("legacy source produces a strict request");
        };
        *release_version = "1.5.0".to_owned();
        let mut changed_digest = request.clone();
        let PackSelection::Strict {
            manifest_sha256, ..
        } = &mut changed_digest.selection
        else {
            panic!("legacy source produces a strict request");
        };
        *manifest_sha256 = "a".repeat(64);
        let mut changed_profile = profile.clone();
        changed_profile.engine_version = "10.0.0".to_owned();
        let baseline = source_identity(&request).expect("source identity");
        assert_eq!(baseline, source_identity(&changed_version).unwrap());
        assert_eq!(baseline, source_identity(&changed_digest).unwrap());
        assert_ne!(profile.engine_version, changed_profile.engine_version);
    }

    #[test]
    fn invalid_explicit_source_never_enters_default_discovery() {
        let error = parse_pack_source("{\"repository\":\"https://github.com/example/packs\"}")
            .expect_err("incomplete explicit source is invalid");
        assert!(matches!(error, OpenPackError::InvalidSource(_)));
        let malformed =
            parse_pack_source("not json").expect_err("malformed explicit source is invalid");
        assert!(matches!(malformed, OpenPackError::InvalidSource(_)));
    }

    #[test]
    fn only_a_fresh_verified_inventory_can_issue_no_compatible_receipt() {
        let bytes = manifest_bytes(ReleaseFixture {
            pack_id: RULES_PACK_ID,
            version: "1.2.0",
            schema_version: 2,
            artifact_role: "source",
            archive: b"fixture archive",
            contents: Vec::new(),
            dependencies: Vec::new(),
        });
        let mut manifest_value: Value = serde_json::from_slice(&bytes).unwrap();
        manifest_value["compatibility"]["capabilities"]["required"] =
            json!(["capability.absent-from-engine"]);
        let manifest_bytes = serde_json::to_vec(&manifest_value).unwrap();
        let (manifest, raw_manifest) = parse_release_manifest(&manifest_bytes)
            .expect("well-formed but incompatible descriptor");
        let release = ReleaseRecord {
            cached: CachedReleaseRecord {
                tag: "rules/v1.2.0".to_owned(),
                tag_commit: TEST_COMMIT.to_owned(),
                prerelease: false,
                manifest_sha256: sha256(&manifest_bytes),
                manifest_url: None,
                assets: BTreeMap::new(),
            },
            manifest,
            raw_manifest,
        };
        let mut inventory = Inventory {
            fetched_at: "2026-10-07T12:00:00.000Z".to_owned(),
            fetched_at_ms: 0,
            fetched_online: true,
            inventory_sha256: "d".repeat(64),
            releases: vec![release],
        };
        let request = default_preferred_request();
        let receipt = select_pack_request(&inventory, &engine_profile("9.9.0"), &request)
            .expect_err("fresh compatible absence is typed");
        let OpenPackError::SelectionRejected { error, .. } = receipt else {
            panic!("expected selection rejections");
        };
        let OpenPackError::NoCompatibleRelease { receipt, .. } = *error else {
            panic!("expected typed no-compatible result");
        };
        assert_eq!(receipt["status"], "not-evaluated");
        assert_eq!(receipt["reason"], "no-compatible-release");
        assert_eq!(receipt["rejections"][0]["reason"], "engine-contract");

        inventory.fetched_online = false;
        let cached = select_pack_request(&inventory, &engine_profile("9.9.0"), &request)
            .expect_err("cached absence is not fresh evidence");
        assert_eq!(cached.failure_class().name, "unavailable");
    }

    #[test]
    fn private_transport_failures_are_typed_and_token_stays_out_of_public_identities() {
        let secret = "do-not-leak-this-token";
        let source = LegacyPackSource {
            repository: "https://github.com/example/private-packs".to_owned(),
            rules_version: "1.4.0".to_owned(),
            manifest_sha256: "a".repeat(64),
            semantic_manifest_sha256: "b".repeat(64),
            inventory_url: None,
            inventory_sha256: None,
        };
        let api_url =
            "https://api.github.com/repos/example/private-packs/releases/tags/rules%2Fv1.4.0";
        for (status, expected) in [(401, "authentication"), (404, "missing")] {
            let transport = FakeTransport::with_failures(BTreeMap::from([(
                api_url.to_owned(),
                TransportError::http_status(status, true, &ureq::http::HeaderMap::new()),
            )]));
            let error = fetch_bytes(&transport, api_url, MAX_API_PAGE_BYTES)
                .expect_err("HTTP error remains a hard failure");
            assert!(!error.to_string().contains(secret));
            assert!(!format!("{error:?}").contains(secret));
            match (expected, error) {
                ("authentication", OpenPackError::Authentication(message)) => {
                    assert!(!message.contains("token"));
                }
                ("missing", OpenPackError::MissingRelease(message)) => {
                    assert!(!message.contains("token"));
                }
                (expected, error) => panic!("expected {expected} failure, got {error:?}"),
            }
            assert_eq!(transport.call_count(), 1);
        }

        let request = legacy_source_request(&source);
        let transport = UreqTransport::new(Some(request_source(&request)), Some(secret.to_owned()));
        assert_eq!(
            transport.authorization_header_for_url(api_url).as_deref(),
            Some("Bearer do-not-leak-this-token")
        );
        assert_eq!(
            transport.authorization_header_for_url("https://github.com/example/private-packs/releases/download/rules/v1.4.0/file.tar.gz"),
            None
        );
        assert_eq!(
            transport.authorization_header_for_url(
                "https://api.github.com/repos/example/other/releases/assets/2"
            ),
            None
        );
        let identity = source_identity(&request).expect("source identity");
        let serialized_source = serde_json::to_string(&source).unwrap();
        assert!(!identity.contains(secret));
        assert!(!serialized_source.contains(secret));
    }

    #[test]
    #[hardwon("#4437: public GitHub rate limits must preserve embedded-pack runtime fallback")]
    fn public_rate_limited_403_falls_back_and_strict_preparation_stays_network_failure() {
        let secret = "do-not-leak-this-token";
        let url = format!("{API_ROOT}/releases?per_page=100&page=1");
        let cache = tempdir().expect("temporary public cache");
        let runtime_transport = FakeTransport::with_failures(BTreeMap::from([(
            url.clone(),
            TransportError::http_status(403, false, &ureq::http::HeaderMap::new()),
        )]));
        let runtime = prepare_runtime_with_transport(
            cache.path(),
            &engine_profile("9.9.0"),
            false,
            false,
            &runtime_transport,
        )
        .expect("public 403 rate limiting falls back to embedded packs");
        let OpenPackRuntimeOutcome::EmbeddedFallback { kind, message } = runtime else {
            panic!("expected embedded fallback, got {runtime:?}");
        };
        assert_eq!(kind, OpenPackFallbackKind::NetworkUnavailable);
        assert!(message.contains("rate limit"));
        assert!(!message.contains(secret));
        assert_eq!(runtime_transport.call_count(), 1);

        let strict_cache = tempdir().expect("temporary strict cache");
        let strict_transport = FakeTransport::with_failures(BTreeMap::from([(
            url,
            TransportError::http_status(403, false, &ureq::http::HeaderMap::new()),
        )]));
        let strict = prepare_with_transport(
            strict_cache.path(),
            &engine_profile("9.9.0"),
            false,
            false,
            &strict_transport,
        )
        .expect_err("strict receipt preparation must retain the network failure");
        assert!(matches!(
            &strict,
            OpenPackError::Network(message) if message.contains("rate limit")
        ));
        assert!(!strict.to_string().contains(secret));
        assert!(!format!("{strict:?}").contains(secret));
        assert_eq!(strict_transport.call_count(), 1);
    }

    #[test]
    #[hardwon("#4437: distinguish authenticated rate-limited 403s from authorization failures")]
    fn authenticated_403_rate_limits_and_authentication_failures_are_secret_safe() {
        let secret = "do-not-leak-this-token";
        let api_url =
            "https://api.github.com/repos/example/private-packs/releases/tags/rules%2Fv1.4.0";
        let mut rate_limit_headers = ureq::http::HeaderMap::new();
        rate_limit_headers.insert(
            "x-ratelimit-remaining",
            ureq::http::HeaderValue::from_static("0"),
        );
        let mut retry_after_headers = ureq::http::HeaderMap::new();
        retry_after_headers.insert("retry-after", ureq::http::HeaderValue::from_static("60"));

        let rate_limited = fetch_bytes(
            &FakeTransport::with_failures(BTreeMap::from([(
                api_url.to_owned(),
                TransportError::http_status(403, true, &rate_limit_headers),
            )])),
            api_url,
            MAX_API_PAGE_BYTES,
        )
        .expect_err("authenticated rate-limited 403 remains unavailable");
        assert!(matches!(
            &rate_limited,
            OpenPackError::Network(message) if message == "pack source rate limit reached"
        ));

        let retry_after = fetch_bytes(
            &FakeTransport::with_failures(BTreeMap::from([(
                api_url.to_owned(),
                TransportError::http_status(403, true, &retry_after_headers),
            )])),
            api_url,
            MAX_API_PAGE_BYTES,
        )
        .expect_err("retry-after marks the response as rate limited");
        assert!(matches!(retry_after, OpenPackError::Network(_)));

        let unauthorized = fetch_bytes(
            &FakeTransport::with_failures(BTreeMap::from([(
                api_url.to_owned(),
                TransportError::http_status(403, true, &ureq::http::HeaderMap::new()),
            )])),
            api_url,
            MAX_API_PAGE_BYTES,
        )
        .expect_err("authenticated 403 without rate-limit headers is an auth failure");
        assert!(matches!(unauthorized, OpenPackError::Authentication(_)));

        let source = LegacyPackSource {
            repository: "https://github.com/example/private-packs".to_owned(),
            rules_version: "1.4.0".to_owned(),
            manifest_sha256: "a".repeat(64),
            semantic_manifest_sha256: "b".repeat(64),
            inventory_url: None,
            inventory_sha256: None,
        };
        let explicit_cache = tempdir().expect("temporary explicit cache");
        let listing_url =
            "https://api.github.com/repos/example/private-packs/releases?per_page=100&page=1";
        let explicit_transport = FakeTransport::with_failures(BTreeMap::from([(
            listing_url.to_owned(),
            TransportError::http_status(403, true, &ureq::http::HeaderMap::new()),
        )]));
        let explicit = prepare_runtime_with_source(
            explicit_cache.path(),
            &engine_profile("9.9.0"),
            Some(&source),
            false,
            false,
            &explicit_transport,
        )
        .expect_err("authenticated explicit-source 403 must remain a hard failure");
        assert!(matches!(explicit, OpenPackError::Authentication(_)));

        let unauthorized_401 = fetch_bytes(
            &FakeTransport::with_failures(BTreeMap::from([(
                api_url.to_owned(),
                TransportError::http_status(401, true, &ureq::http::HeaderMap::new()),
            )])),
            api_url,
            MAX_API_PAGE_BYTES,
        )
        .expect_err("401 remains an auth failure");
        assert!(matches!(unauthorized_401, OpenPackError::Authentication(_)));

        let too_many_requests = fetch_bytes(
            &FakeTransport::with_failures(BTreeMap::from([(
                api_url.to_owned(),
                TransportError::http_status(429, true, &ureq::http::HeaderMap::new()),
            )])),
            api_url,
            MAX_API_PAGE_BYTES,
        )
        .expect_err("429 remains a rate-limit network failure");
        assert!(matches!(too_many_requests, OpenPackError::Network(_)));

        for error in [
            rate_limited,
            retry_after,
            unauthorized,
            explicit,
            unauthorized_401,
            too_many_requests,
        ] {
            assert!(!error.to_string().contains(secret));
            assert!(!format!("{error:?}").contains(secret));
        }
    }

    #[test]
    fn https_inventory_digest_and_redirects_are_bound_to_trusted_origins() {
        let source = PackSource {
            repository: REPOSITORY_URL.to_owned(),
            inventory_url: Some("https://mirror.example/releases/index.json".to_owned()),
            inventory_sha256: Some("c".repeat(64)),
        };
        validate_repository_url(&source.repository).expect("valid repository");
        assert!(trusted_redirect(
            "https://mirror.example/releases/index.json",
            "https://mirror.example/releases/index.json",
            "https://mirror.example/releases/next.json",
            Some(&source),
        ));
        assert!(!trusted_redirect(
            "https://mirror.example/releases/index.json",
            "https://mirror.example/releases/index.json",
            "https://attacker.example/releases/next.json",
            Some(&source),
        ));
        assert!(!trusted_redirect(
            "https://github.com/BrokkAi/bifrost-packs/releases/download/rules/v1.4.0/file.tar.gz",
            "https://github.com/BrokkAi/bifrost-packs/releases/download/rules/v1.4.0/file.tar.gz",
            "https://attacker.example/file.tar.gz",
            None,
        ));
    }

    #[test]
    fn schema_one_uses_engine_bounds_while_schema_two_ignores_provenance_version() {
        let historical = v1_manifest("1.0.0", "3.0.0");
        assert!(release_compatible(&historical, &engine_profile("2.8.0")));
        assert!(!release_compatible(&historical, &engine_profile("3.0.0")));

        let bytes = manifest_bytes(ReleaseFixture {
            pack_id: SEMANTIC_PACK_ID,
            version: "2.0.0",
            schema_version: 2,
            artifact_role: "native",
            archive: b"x",
            contents: Vec::new(),
            dependencies: Vec::new(),
        });
        let current = parse_release_manifest(&bytes)
            .expect("valid schema 2 manifest with old provenance")
            .0;
        assert!(release_compatible(&current, &engine_profile("99.0.0")));
    }

    #[test]
    fn missing_offline_inventory_and_invalid_profile_have_distinct_failures() {
        let fixture = tempdir().expect("temporary cache");
        let transport = FakeTransport::new(BTreeMap::new());
        let unavailable = prepare_with_transport(
            fixture.path(),
            &engine_profile("1.0.0"),
            true,
            false,
            &transport,
        )
        .expect_err("empty offline cache is unavailable");
        assert!(matches!(unavailable, OpenPackError::OfflineCacheMiss(_)));
        assert_eq!(transport.call_count(), 0);

        let conflicting_controls = prepare_with_transport(
            fixture.path(),
            &engine_profile("1.0.0"),
            true,
            true,
            &transport,
        )
        .expect_err("offline and refresh cannot be combined");
        assert!(matches!(
            conflicting_controls,
            OpenPackError::Configuration(_)
        ));
        assert_eq!(transport.call_count(), 0);

        let invalid = parse_engine_profile(&json!({ "engine_version": "invalid" }))
            .expect_err("invalid profile is fatal");
        assert!(matches!(invalid, OpenPackError::InvalidProfile(_)));
    }

    #[test]
    fn safe_archive_paths_reject_traversal_and_platform_aliases() {
        for path in [
            "../outside",
            "a/../../outside",
            "C:/outside",
            "rules/CON.txt",
        ] {
            assert!(matches!(
                validate_archive_path(path),
                Err(OpenPackError::Integrity(_))
            ));
        }
        assert_eq!(
            validate_archive_path("rules/fixture/policy.json").expect("safe path"),
            vec!["rules", "fixture", "policy.json"]
        );
    }

    #[test]
    fn archive_extraction_rejects_symbolic_links() {
        let fixture = tempdir().expect("temporary archive");
        let archive_path = fixture.path().join("link.tar.gz");
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut archive = Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(EntryType::Symlink);
        header.set_size(0);
        header.set_path("rules/escape").expect("set symlink path");
        header
            .set_link_name("../../outside")
            .expect("set symlink target");
        header.set_cksum();
        archive
            .append(&header, io::empty())
            .expect("append symlink entry");
        let bytes = archive
            .into_inner()
            .expect("finish symlink tar")
            .finish()
            .expect("finish symlink gzip");
        fs::write(&archive_path, bytes).expect("write symlink archive");
        assert!(matches!(
            inspect_archive(&archive_path, None),
            Err(OpenPackError::Integrity(_))
        ));
    }
}
