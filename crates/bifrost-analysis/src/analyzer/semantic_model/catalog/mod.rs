mod db;
mod storage;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use tempfile::TempDir;
use uuid::Uuid;

use super::validate::is_canonical_relative_path;
use super::{
    ActivationSelector, ArtifactEncoding, CompiledPackManifest, CompiledSemanticModelPack,
    CompiledShard, CompiledShardDescriptor, Completeness, DecodeLimits, NameSelector, PayloadKind,
    decode_manifest, decode_validated_shard_for_manifest, validate_manifest_inventory,
};
use crate::analyzer::canonical_hash::{CanonicalHasher, is_lower_sha256, lower_hex_string};
use crate::analyzer::store::{
    AnalyzerStore, SemanticPackActivationSourceKind, SemanticPackActiveReference,
    SemanticPackActiveSet,
};

/// SQLite schema version used to isolate the generated default catalog from
/// older binaries that cannot open a newer catalog.
pub const CATALOG_SCHEMA_VERSION: i64 = db::CURRENT_CATALOG_VERSION;

/// Cache-compatibility version for locally generated semantic packs.
///
/// Increment this whenever producer or compiler behavior can change the bytes
/// or meaning of a generated pack without changing its other exact inputs.
///
/// 9: the Python stub producer expands wildcard re-exports across a source set,
/// publishing the names a shim module binds and dropping its `*` marker (#2958).
/// 10: exact Java binary tables certify scoped callable-family completeness,
/// and source/JMOD production retains both formal names and that proof (#3006).
/// 11: Python source-set rejects retain their exact source-entry identity for
/// release extraction accounting (#3027).
/// 14: the Python stub producer no longer records `@name.setter` and
/// `@name.deleter` as members of their own. A property with a write half
/// published two competing records for one name, and competing records cannot
/// prove the member present on its owner.
/// 15: the Python stub producer records the implicit `builtins.object` base a
/// stub omits when a class names no other. Without it 196 of the stdlib pack's
/// 560 classes, `int`, `float` and `types.NoneType` among them, had no
/// ancestry, so no consumer could resolve their surface or exclude them from
/// an `isinstance` guard.
/// 17: the Python stub producer resolves imported return annotations and
/// canonicalizes the exact `typing_extensions` aliases for `NoReturn` and
/// `Never`. Warm generated packs carry only the unqualified local spelling.
/// 18: the Rust rustdoc producer emits keyed `std::collections::HashMap`
/// collection-flow facts. Warm generated packs predate those contracts.
/// 19: native compilation preserves and validates deferred-yield contracts.
/// 20: schema version three, and the Scala source-JAR producer classifies every
/// declaration it emits with an `ambient_use` role. Warm generated packs carry
/// no such role, and absence there means "unreviewed", so a stale pack would
/// silently withhold every Scala unused-import proof.
/// 22: C++ header production withholds unproven brace pairings in damaged
/// syntax, including the recovered exported-class partitioning used to emit
/// dependency declarations. Warm generated packs may retain the old shape.
/// 23: the Go source producer parses Go 1.26 new(expr) through the same
/// structured repair as workspace analysis. Warm packs can retain declarations
/// and signatures lost to the old grammar recovery (#3325).
/// 24: the C++ header producer publishes namespace owners and the exact
/// explicit value operations of std::basic_string. Warm generated packs
/// predate those owner and operation facts.
/// 25: producers write native schema four, which admits the portable runtime
/// contract companion. Rebuild generated packs under the new wire contract.
/// 26: Java source and binary producers mark formals as positional-only and
/// publish reviewed stable identities and formal names for selected JDK
/// security endpoints. Warm generated JDK packs predate those facts.
/// 27: the Rust declaration producer unwraps grammar-owned attributes in
/// impl bodies so attributed methods, associated constants, and associated
/// types are retained. Warm generated packs may omit those declarations.
/// 28: the Python stub producer projects the `__call__` signature of a
/// module-level value's class onto the value's name, so `builtins.exit` and
/// `builtins.quit` carry the `_sitebuiltins.Quitter.__call__` contract
/// (#3135). Warm generated packs publish those names as signature-less
/// constants.
pub const GENERATED_PRODUCTION_CACHE_VERSION: u32 = 28;
pub const SEMANTIC_PACK_CACHE_ROOT_ENV: &str = "BIFROST_SEMANTIC_PACK_CACHE_ROOT";

/// Resolve the generated catalog used when no explicit catalog is configured.
/// By default this shares the analyzer cache's repository and linked-worktree
/// scope. The semantic-pack-only override deliberately permits a host to share
/// content-addressed productions without sharing analyzer databases.
pub fn default_semantic_pack_catalog_root(workspace_root: &Path) -> PathBuf {
    default_semantic_pack_catalog_root_with_override(
        workspace_root,
        std::env::var_os(SEMANTIC_PACK_CACHE_ROOT_ENV).filter(|value| !value.is_empty()),
    )
}

fn default_semantic_pack_catalog_root_with_override(
    workspace_root: &Path,
    cache_root: Option<std::ffi::OsString>,
) -> PathBuf {
    cache_root
        .map(PathBuf::from)
        .unwrap_or_else(|| crate::gitblob::cache_dir_path(workspace_root))
        .join(format!("semantic-pack-catalog.v{CATALOG_SCHEMA_VERSION}"))
}

/// Open the generated default catalog after applying the shared cache
/// directory's creation and Git-ignore contract.
pub fn open_default_semantic_pack_catalog(
    workspace_root: &Path,
    options: CatalogOptions,
) -> Result<SemanticPackCatalog, CatalogError> {
    let catalog_root = default_semantic_pack_catalog_root(workspace_root);
    let cache_dir = crate::cache_db::prepare_cache_dir(
        catalog_root
            .parent()
            .expect("the default semantic-pack catalog has a cache parent"),
    )
    .map_err(CatalogError::Integrity)?;
    let directory_name = catalog_root
        .file_name()
        .expect("the default semantic-pack catalog has a directory name");
    SemanticPackCatalog::open(
        &cache_dir.join(directory_name),
        CatalogOpenMode::ReadWrite,
        options,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogOpenMode {
    ReadWrite,
    ReadOnly,
}

#[derive(Debug, Clone, Default)]
pub struct CatalogOptions {
    pub decode_limits: DecodeLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurablePackSourceKind {
    Installed,
    Generated,
    PreShipped,
    WorkspaceProduced,
}

impl DurablePackSourceKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Installed => "installed",
            Self::Generated => "generated",
            Self::PreShipped => "pre_shipped",
            Self::WorkspaceProduced => "workspace_produced",
        }
    }

    fn parse(value: &str) -> Result<Self, CatalogError> {
        match value {
            "installed" => Ok(Self::Installed),
            "generated" => Ok(Self::Generated),
            "pre_shipped" => Ok(Self::PreShipped),
            "workspace_produced" => Ok(Self::WorkspaceProduced),
            _ => Err(CatalogError::Integrity(format!(
                "unknown catalog source kind {value:?}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurablePackSource {
    pub kind: DurablePackSourceKind,
    pub source_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionPackSourceKind {
    Embedded,
    EphemeralWorkspace,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPackSource {
    pub kind: SessionPackSourceKind,
    pub source_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogPackSourceKind {
    Installed,
    Generated,
    PreShipped,
    WorkspaceProduced,
    Embedded,
    EphemeralWorkspace,
}

impl CatalogPackSourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Installed => "installed",
            Self::Generated => "generated",
            Self::PreShipped => "pre_shipped",
            Self::WorkspaceProduced => "workspace_produced",
            Self::Embedded => "embedded",
            Self::EphemeralWorkspace => "ephemeral_workspace",
        }
    }

    fn parse(value: &str) -> Result<Self, CatalogError> {
        match value {
            "installed" => Ok(Self::Installed),
            "generated" => Ok(Self::Generated),
            "pre_shipped" => Ok(Self::PreShipped),
            "workspace_produced" => Ok(Self::WorkspaceProduced),
            "embedded" => Ok(Self::Embedded),
            "ephemeral_workspace" => Ok(Self::EphemeralWorkspace),
            _ => Err(CatalogError::Integrity(format!(
                "unknown catalog source kind {value:?}"
            ))),
        }
    }
}

impl From<DurablePackSourceKind> for CatalogPackSourceKind {
    fn from(value: DurablePackSourceKind) -> Self {
        match value {
            DurablePackSourceKind::Installed => Self::Installed,
            DurablePackSourceKind::Generated => Self::Generated,
            DurablePackSourceKind::PreShipped => Self::PreShipped,
            DurablePackSourceKind::WorkspaceProduced => Self::WorkspaceProduced,
        }
    }
}

impl From<SessionPackSourceKind> for CatalogPackSourceKind {
    fn from(value: SessionPackSourceKind) -> Self {
        match value {
            SessionPackSourceKind::Embedded => Self::Embedded,
            SessionPackSourceKind::EphemeralWorkspace => Self::EphemeralWorkspace,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CatalogCoordinate {
    pub name: String,
    pub version: Option<Version>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticPackSelectorQuery {
    pub language: String,
    pub ecosystem: String,
    pub package: Option<CatalogCoordinate>,
    pub module: Option<CatalogCoordinate>,
    pub toolchain: Option<CatalogCoordinate>,
    pub target: Option<String>,
    pub configuration: Option<String>,
    pub artifact_sha256: Option<String>,
    pub bifrost_version: Version,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogCandidate {
    manifest_digest: String,
    shard_id: String,
    descriptor: CompiledShardDescriptor,
    completeness: Completeness,
    source_kind: CatalogPackSourceKind,
    source_id: String,
    location: CatalogCandidateLocation,
}

impl CatalogCandidate {
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    pub fn shard_id(&self) -> &str {
        &self.shard_id
    }

    pub fn descriptor(&self) -> &CompiledShardDescriptor {
        &self.descriptor
    }

    pub fn completeness(&self) -> Completeness {
        self.completeness
    }

    pub fn source_kind(&self) -> CatalogPackSourceKind {
        self.source_kind
    }

    pub fn source_id(&self) -> &str {
        &self.source_id
    }
}

#[derive(Debug)]
pub struct LoadedCatalogShard {
    /// Shared with the catalog's decoded-manifest memo and with every other
    /// shard of the same pack (#3101).
    pub manifest: Arc<CompiledPackManifest>,
    pub shard: CompiledShard,
    pub source_kind: CatalogPackSourceKind,
    pub source_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallOutcome {
    pub manifest_digest: String,
    pub inserted_manifest: bool,
    pub inserted_objects: usize,
}

/// One declaration that a pack producer could not extract.
///
/// `declaration` is the producer's canonical fully-qualified type name. A
/// member-specific reject may use `Owner.member`; owner-wide checks also
/// consult the owning type. `reason` is stable diagnostic context for humans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackExtractionGap {
    pub declaration: String,
    pub reason: String,
}

/// One artifact-relative source entry that a pack producer could not parse.
///
/// A source entry provides accountability for a file-level reject. Unlike
/// [`PackExtractionGap`], it is not a declaration and must not participate in
/// declaration-gap lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackExtractionSourceEntry {
    pub source_entry: String,
    pub reason: String,
}

/// Complete reject accounting installed from a verified release bundle.
///
/// Ordinary authored and workspace-generated packs have no row of this kind.
/// That distinction is intentional: a partial pack may activate only when its
/// release bundle accounts for every reject as an individually named warning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackExtractionAccounting {
    pub reject_count: u64,
    pub suppressed_reject_count: u64,
    pub error_reject_count: u64,
    pub gaps: Vec<PackExtractionGap>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_entries: Vec<PackExtractionSourceEntry>,
}

impl PackExtractionAccounting {
    pub fn warning_only_and_fully_accounted(&self) -> bool {
        self.suppressed_reject_count == 0
            && self.error_reject_count == 0
            && (self.gaps.len() + self.source_entries.len()) as u64 == self.reject_count
    }
}

/// The single release-verification and activation-readiness definition.
pub fn pack_is_activation_ready(
    completeness: Completeness,
    extraction: Option<&PackExtractionAccounting>,
) -> bool {
    completeness == Completeness::Complete
        || extraction.is_some_and(PackExtractionAccounting::warning_only_and_fully_accounted)
}

pub fn pack_rejects_are_warning_only(extraction: &PackExtractionAccounting) -> bool {
    extraction.error_reject_count == 0
}

const GENERATED_PRODUCTION_DOMAIN: &[u8] = b"bifrost.semantic-pack.generated-production.v1";
const ACQUISITION_REQUEST_DOMAIN: &[u8] = b"bifrost.semantic-pack.acquisition-request.v1";
const ACQUISITION_RELEASE_DOMAIN: &[u8] = b"bifrost.semantic-pack.acquisition-release.v1";
const ACQUISITION_SOURCE_STATE_DOMAIN: &[u8] = b"bifrost.semantic-pack.acquisition-sources.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcquisitionReceiptRequest {
    GeneratedProduction(GeneratedProductionKey),
    DeclaredPack(Box<SemanticPackSelectorQuery>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquisitionReceiptRelease {
    pub repository: String,
    pub tag: String,
    pub archive_name: String,
    pub archive_digest: String,
    pub bundle_schema_version: u32,
    pub bundle_generator_name: String,
    pub bundle_generator_version: String,
    pub semantic_schema_version: u32,
    pub generated_cache_version: u32,
    pub client_epoch: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquisitionReceiptSource {
    release_digest: String,
    manifest_digest: String,
    source: DurablePackSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquisitionReceiptLookup {
    Satisfied,
    KnownVerifiedAbsence,
    ReceiptMiss,
}

impl AcquisitionReceiptRequest {
    pub fn generated(key: &GeneratedProductionKey) -> Self {
        Self::GeneratedProduction(key.clone())
    }

    pub fn declared(query: &SemanticPackSelectorQuery) -> Self {
        Self::DeclaredPack(Box::new(query.clone()))
    }

    pub fn digest(&self) -> String {
        let mut hasher = CanonicalHasher::new(ACQUISITION_REQUEST_DOMAIN);
        match self {
            Self::GeneratedProduction(key) => {
                hasher.field("kind", b"generated_production");
                hasher.field("production_digest", key.production_digest().as_bytes());
                hasher.field("input_digest", key.input_digest().as_bytes());
                hasher.field("producer_name", key.producer_name().as_bytes());
                hasher.field("producer_version", key.producer_version().as_bytes());
                hasher.field("schema_version", &key.schema_version().to_be_bytes());
                hasher.field(
                    "generated_cache_version",
                    &GENERATED_PRODUCTION_CACHE_VERSION.to_be_bytes(),
                );
            }
            Self::DeclaredPack(query) => {
                hasher.field("kind", b"declared_pack");
                hasher.field("language", query.language.as_bytes());
                hasher.field("ecosystem", query.ecosystem.as_bytes());
                hash_coordinate(&mut hasher, "package", query.package.as_ref());
                hash_coordinate(&mut hasher, "module", query.module.as_ref());
                hash_coordinate(&mut hasher, "toolchain", query.toolchain.as_ref());
                hash_optional(&mut hasher, "target", query.target.as_deref());
                hash_optional(&mut hasher, "configuration", query.configuration.as_deref());
                hash_optional(
                    &mut hasher,
                    "artifact_sha256",
                    query.artifact_sha256.as_deref(),
                );
                hasher.field(
                    "bifrost_version",
                    query.bifrost_version.to_string().as_bytes(),
                );
            }
        }
        lower_hex_string(&hasher.finish())
    }
}

impl AcquisitionReceiptRelease {
    pub fn digest(&self) -> Result<String, CatalogError> {
        if self.repository.is_empty()
            || self.tag.is_empty()
            || self.archive_name.is_empty()
            || !is_lower_sha256(&self.archive_digest)
            || self.bundle_schema_version == 0
            || self.bundle_generator_name.is_empty()
            || self.bundle_generator_version.is_empty()
            || self.semantic_schema_version == 0
            || self.generated_cache_version == 0
            || self.client_epoch == 0
        {
            return Err(CatalogError::Integrity(
                "acquisition release identity must be complete".to_owned(),
            ));
        }
        let mut hasher = CanonicalHasher::new(ACQUISITION_RELEASE_DOMAIN);
        hasher.field("repository", self.repository.as_bytes());
        hasher.field("tag", self.tag.as_bytes());
        hasher.field("archive_name", self.archive_name.as_bytes());
        hasher.field("archive_digest", self.archive_digest.as_bytes());
        hasher.field(
            "bundle_schema_version",
            &self.bundle_schema_version.to_be_bytes(),
        );
        hasher.field(
            "bundle_generator_name",
            self.bundle_generator_name.as_bytes(),
        );
        hasher.field(
            "bundle_generator_version",
            self.bundle_generator_version.as_bytes(),
        );
        hasher.field(
            "semantic_schema_version",
            &self.semantic_schema_version.to_be_bytes(),
        );
        hasher.field(
            "generated_cache_version",
            &self.generated_cache_version.to_be_bytes(),
        );
        hasher.field("client_epoch", &self.client_epoch.to_be_bytes());
        hasher.field(
            "catalog_schema_version",
            &CATALOG_SCHEMA_VERSION.to_be_bytes(),
        );
        Ok(lower_hex_string(&hasher.finish()))
    }
}

fn hash_optional(hasher: &mut CanonicalHasher, name: &str, value: Option<&str>) {
    hasher.field(name, value.unwrap_or_default().as_bytes());
    hasher.field(&format!("{name}_present"), &[u8::from(value.is_some())]);
}

fn hash_coordinate(
    hasher: &mut CanonicalHasher,
    name: &str,
    coordinate: Option<&CatalogCoordinate>,
) {
    hash_optional(
        hasher,
        &format!("{name}_name"),
        coordinate.map(|coordinate| coordinate.name.as_str()),
    );
    let version = coordinate
        .and_then(|coordinate| coordinate.version.as_ref())
        .map(ToString::to_string);
    hash_optional(hasher, &format!("{name}_version"), version.as_deref());
}

/// Exact semantic inputs that identify one generated semantic-pack production.
///
/// `input_digest` is computed by the ecosystem adapter over its normalized
/// activation evidence and ordered artifact kinds and byte digests. Paths and
/// mtimes must not participate so identical artifacts can be reused by another
/// workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedProductionKey {
    production_digest: String,
    input_digest: String,
    producer_name: String,
    producer_version: String,
    schema_version: u32,
}

impl GeneratedProductionKey {
    pub fn new(
        input_digest: impl Into<String>,
        producer_name: impl Into<String>,
        producer_version: impl Into<String>,
        schema_version: u32,
    ) -> Result<Self, CatalogError> {
        let input_digest = input_digest.into();
        let producer_name = producer_name.into();
        let producer_version = producer_version.into();
        if !is_lower_sha256(&input_digest) {
            return Err(CatalogError::Integrity(
                "generated-production input digest must be lowercase SHA-256".to_owned(),
            ));
        }
        if producer_name.is_empty() || producer_version.is_empty() || schema_version == 0 {
            return Err(CatalogError::Integrity(
                "generated-production producer identity and schema version must be non-empty"
                    .to_owned(),
            ));
        }
        let production_digest = generated_production_digest(
            &input_digest,
            &producer_name,
            &producer_version,
            schema_version,
        );
        Ok(Self {
            production_digest,
            input_digest,
            producer_name,
            producer_version,
            schema_version,
        })
    }

    pub fn production_digest(&self) -> &str {
        &self.production_digest
    }

    pub fn input_digest(&self) -> &str {
        &self.input_digest
    }

    pub fn producer_name(&self) -> &str {
        &self.producer_name
    }

    pub fn producer_version(&self) -> &str {
        &self.producer_version
    }

    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn source_id(&self) -> String {
        format!("production:{}", self.production_digest)
    }
}

/// Verify a release-recorded generated-production digest with its recorded
/// cache epoch. This checks the immutable identity without constructing a key
/// under the current cache epoch.
pub fn verify_recorded_generated_production_digest(
    production_digest: &str,
    input_digest: &str,
    producer_name: &str,
    producer_version: &str,
    schema_version: u32,
    cache_version: u32,
) -> Result<bool, CatalogError> {
    if !is_lower_sha256(production_digest) || !is_lower_sha256(input_digest) {
        return Err(CatalogError::Integrity(
            "generated-production digests must be lowercase SHA-256".to_owned(),
        ));
    }
    if producer_name.is_empty()
        || producer_version.is_empty()
        || schema_version == 0
        || cache_version == 0
    {
        return Err(CatalogError::Integrity(
            "generated-production producer identity, schema version, and cache version must be non-empty"
                .to_owned(),
        ));
    }
    Ok(production_digest
        == generated_production_digest_for_cache_version(
            input_digest,
            producer_name,
            producer_version,
            schema_version,
            cache_version,
        ))
}

/// An acquired operating-system lock for one exact generated production.
/// Dropping the file releases the lock, including after process termination.
pub(crate) struct GeneratedProductionLock {
    file: File,
}

impl GeneratedProductionLock {
    pub(crate) fn try_acquire(&self) -> Result<bool, CatalogError> {
        match self.file.try_lock() {
            Ok(()) => Ok(true),
            Err(std::fs::TryLockError::WouldBlock) => Ok(false),
            Err(std::fs::TryLockError::Error(error)) => {
                Err(CatalogError::io("acquire generated-production lock", error))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedProduction {
    pub key: GeneratedProductionKey,
    pub manifest_digest: String,
    pub completeness: Completeness,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedInstallOutcome {
    pub production: GeneratedProduction,
    pub install: InstallOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogAccounting {
    pub installed_stored_bytes: u64,
    pub active_stored_bytes: u64,
    pub object_count: u64,
    pub logical_shard_count: u64,
    pub active_shard_count: u64,
    pub source_count: u64,
    pub lookup_hits: u64,
    pub lookup_misses: u64,
    pub quarantined_pack_count: u64,
    pub activations: Vec<ActivationSourceCount>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogPackInventorySource {
    pub source_kind: String,
    pub source_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogPackInventoryActivation {
    pub scope_id: String,
    pub active_set_digest: String,
    pub source_kind: String,
    pub source_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogPackInventory {
    pub manifest_content_sha256: String,
    pub manifest_semantic_sha256: String,
    pub state: String,
    pub pack_id: String,
    pub pack_version: String,
    pub producer: super::Producer,
    pub language: String,
    pub ecosystem: String,
    pub provenance: super::Provenance,
    pub completeness: Completeness,
    pub extraction: Option<PackExtractionAccounting>,
    pub sources: Vec<CatalogPackInventorySource>,
    pub catalog_activations: Vec<CatalogPackInventoryActivation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogInventory {
    pub complete: bool,
    pub packs: Vec<CatalogPackInventory>,
}

fn inventory_pack(manifest: &CompiledPackManifest, state: String) -> CatalogPackInventory {
    CatalogPackInventory {
        manifest_content_sha256: manifest.content_sha256.clone(),
        manifest_semantic_sha256: manifest.semantic_sha256.clone(),
        state,
        pack_id: manifest.pack_id.clone(),
        pack_version: manifest.version.clone(),
        producer: manifest.producer.clone(),
        language: manifest.language.clone(),
        ecosystem: manifest.ecosystem.clone(),
        provenance: manifest.provenance.clone(),
        completeness: manifest.completeness,
        extraction: None,
        sources: Vec::new(),
        catalog_activations: Vec::new(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationSourceCount {
    pub source_kind: CatalogPackSourceKind,
    pub source_id: String,
    pub pack_count: u64,
}

#[derive(Debug, Clone)]
pub struct CatalogGcOptions {
    pub minimum_age: Duration,
    pub max_packs: usize,
    pub max_objects: usize,
}

impl Default for CatalogGcOptions {
    fn default() -> Self {
        Self {
            minimum_age: Duration::from_secs(7 * 24 * 60 * 60),
            max_packs: 1_000,
            max_objects: 4_096,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogGcOutcome {
    pub pruned_packs: usize,
    pub pruned_objects: usize,
    pub reclaimed_bytes: u64,
    pub pruned_expired_leases: usize,
}

pub struct CatalogLease<'a> {
    catalog: &'a SemanticPackCatalog,
    lease_id: String,
    released: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogMiss {
    NotFound,
    Quarantined { reason: String },
    Incompatible { reason: String },
}

/// One pack that names a queried coordinate but rejects its exact version.
///
/// `required` is the exact requirement the pack declares for `coordinate`;
/// `installed` is the version the query carried, absent when discovery found
/// the coordinate without an exact version (#1884).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SemanticPackVersionNearMiss {
    pub pack_id: String,
    pub pack_version: String,
    pub manifest_digest: String,
    /// The rejecting coordinate, for example `toolchain jdk` or
    /// `package com.acme:widget`.
    pub coordinate: String,
    pub installed: Option<String>,
    pub required: String,
}

impl SemanticPackVersionNearMiss {
    /// The one-line statement of this rejection, naming both versions.
    pub fn describe(&self) -> String {
        match &self.installed {
            Some(installed) => format!(
                "semantic pack {}@{} requires {} {}, but the workspace {} is {}",
                self.pack_id,
                self.pack_version,
                self.coordinate,
                self.required,
                self.coordinate,
                installed
            ),
            None => format!(
                "semantic pack {}@{} requires {} {}, but discovery found no exact {} version",
                self.pack_id, self.pack_version, self.coordinate, self.required, self.coordinate
            ),
        }
    }
}

/// One raw `catalog_selectors` join row, before compatibility filtering.
struct DurableSelectorRow {
    manifest_digest: String,
    shard_id: String,
    descriptor_json: Vec<u8>,
    selector_json: Vec<u8>,
    source_kind: String,
    source_id: String,
}

#[derive(Debug)]
pub enum CatalogError {
    Io {
        operation: &'static str,
        source: std::io::Error,
    },
    Sqlite {
        operation: &'static str,
        source: rusqlite::Error,
    },
    Artifact(String),
    Integrity(String),
    ReadOnly,
    CatalogTooNew {
        found: i64,
        supported: i64,
    },
    ReadOnlySchema {
        found: i64,
        required: i64,
    },
    Unavailable,
}

impl CatalogError {
    fn io(operation: &'static str, source: std::io::Error) -> Self {
        Self::Io { operation, source }
    }

    fn sqlite(operation: &'static str, source: rusqlite::Error) -> Self {
        Self::Sqlite { operation, source }
    }
}

impl fmt::Display for CatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, source } => write!(formatter, "{operation}: {source}"),
            Self::Sqlite { operation, source } => write!(formatter, "{operation}: {source}"),
            Self::Artifact(message) | Self::Integrity(message) => formatter.write_str(message),
            Self::ReadOnly => formatter.write_str("semantic-pack catalog is read-only"),
            Self::CatalogTooNew { found, supported } => write!(
                formatter,
                "semantic-pack catalog schema {found} is newer than supported version {supported}"
            ),
            Self::ReadOnlySchema { found, required } => write!(
                formatter,
                "read-only semantic-pack catalog schema is {found}, expected {required}"
            ),
            Self::Unavailable => formatter.write_str("catalog candidate is unavailable"),
        }
    }
}

impl std::error::Error for CatalogError {}

pub struct SemanticPackCatalog {
    // Field order is deliberate: all SQLite/session state must drop before an
    // owned ephemeral root is deleted, including on Windows.
    root: PathBuf,
    mode: CatalogOpenMode,
    options: CatalogOptions,
    // Session packs and SQLite data-version counters belong to one opened
    // catalog. Equal counters in another catalog do not identify its content.
    instance_identity: u64,
    connection: Mutex<Connection>,
    session_packs: Mutex<Vec<SessionPack>>,
    session_activations: Mutex<HashMap<String, SessionActivation>>,
    rejected_manifests: Mutex<HashSet<String>>,
    decoded_manifests: Mutex<DecodedManifestMemo>,
    verified_manifest_inventories: Mutex<HashSet<String>>,
    manifest_decodes: AtomicU64,
    manifest_inventory_validations: AtomicU64,
    lookup_hits: AtomicU64,
    lookup_misses: AtomicU64,
    sql_statements: AtomicU64,
    object_reads: AtomicU64,
    mutation_generation: AtomicU64,
    _ephemeral_root: Option<TempDir>,
}

/// Decoded manifests of one catalog, keyed by their content digest.
///
/// Candidate selection visits one row per (shard, selector) and shard loading
/// visits one row per shard. Both used to deserialize the same stored manifest
/// once per row: one fresh policy process decoded the same two JDK manifests
/// 259 times, 18.8 of its 31 activation seconds (#3101). The key is the
/// manifest's own `content_sha256`, and `decode_manifest` proves that the value
/// it returns hashes to that key, so a hit is the value the miss would return.
/// Catalog mutations cannot make an entry stale: a manifest digest names its
/// exact bytes, and readers keep checking each pack's stored state themselves.
struct DecodedManifestMemo {
    entries: HashMap<String, Arc<CompiledPackManifest>>,
    bytes: usize,
}

/// Canonical manifest bytes the memo retains before it starts over.
///
/// Manifests of one pack are adjacent in every ordered reader, so a restart
/// costs one decode per distinct manifest, never one per row. The bound keeps a
/// catalog that serves many packs from retaining unbounded decoded state.
const DECODED_MANIFEST_MEMO_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SemanticPackCatalogCacheIdentity {
    pub(crate) instance_identity: u64,
    pub(crate) mutation_generation: u64,
    pub(crate) sqlite_data_version: u64,
}

#[derive(Clone)]
struct ValidatedShard {
    descriptor: CompiledShardDescriptor,
    bytes: Vec<u8>,
    selectors: Vec<ActivationSelector>,
}

struct ValidatedPack {
    manifest: CompiledPackManifest,
    shards: Vec<ValidatedShard>,
}

struct SessionPack {
    manifest: Arc<CompiledPackManifest>,
    shards: Vec<ValidatedShard>,
    source: SessionPackSource,
}

struct SessionActivation {
    active_set: SemanticPackActiveSet,
    owner: Weak<()>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CatalogCandidateLocation {
    Durable,
    Session {
        pack_ordinal: usize,
        shard_ordinal: usize,
    },
}

impl CatalogLease<'_> {
    pub fn renew(&mut self, ttl: Duration) -> Result<(), CatalogError> {
        let expires_at = lease_expiry(ttl)?;
        let connection = self
            .catalog
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let updated = connection
            .execute(
                "UPDATE catalog_leases SET expires_at = ?2 WHERE lease_id = ?1",
                params![&self.lease_id, expires_at],
            )
            .map_err(|error| CatalogError::sqlite("renew semantic-pack lease", error))?;
        if updated == 0 {
            return Err(CatalogError::Unavailable);
        }
        Ok(())
    }

    pub fn release(mut self) -> Result<(), CatalogError> {
        self.release_inner()
    }

    fn release_inner(&mut self) -> Result<(), CatalogError> {
        if self.released {
            return Ok(());
        }
        let connection = self
            .catalog
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        self.catalog.sql_statements.fetch_add(1, Ordering::Relaxed);
        connection
            .execute(
                "DELETE FROM catalog_leases WHERE lease_id = ?1",
                [&self.lease_id],
            )
            .map_err(|error| CatalogError::sqlite("release semantic-pack lease", error))?;
        self.released = true;
        Ok(())
    }
}

impl Drop for CatalogLease<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.release_inner() {
            eprintln!(
                "failed to release semantic-pack lease {}: {error}",
                self.lease_id
            );
        }
    }
}

impl SemanticPackCatalog {
    pub fn open(
        root: &Path,
        mode: CatalogOpenMode,
        options: CatalogOptions,
    ) -> Result<Self, CatalogError> {
        if mode == CatalogOpenMode::ReadOnly && !root.exists() {
            return Err(CatalogError::Integrity(
                "read-only semantic-pack catalog root does not exist".to_owned(),
            ));
        }
        let root = {
            let _scope = crate::profiling::scope("semantic_pack.catalog.prepare_root");
            match mode {
                CatalogOpenMode::ReadWrite => storage::prepare_root(root)?,
                CatalogOpenMode::ReadOnly => storage::open_read_only_root(root)?,
            }
        };
        // SQLite can leave every concurrent first opener in SQLITE_PROTOCOL
        // while they independently negotiate WAL locking on Windows. Elect
        // one initializer through schema migration and storage reconciliation;
        // normal catalog work remains concurrent after this lock is dropped.
        let initialization_lock = {
            let _scope = crate::profiling::scope("semantic_pack.catalog.initialization_lock");
            if mode == CatalogOpenMode::ReadWrite {
                Some(storage::acquire_initialization_lock(&root)?)
            } else {
                None
            }
        };
        let mut connection = {
            let _scope = crate::profiling::scope("semantic_pack.catalog.db_open");
            db::open(&root, mode)?
        };
        if mode == CatalogOpenMode::ReadWrite {
            let _scope = crate::profiling::scope("semantic_pack.catalog.reconcile_storage");
            reconcile_storage(&root, &mut connection)?;
        }
        drop(initialization_lock);
        static NEXT_CATALOG_INSTANCE: AtomicU64 = AtomicU64::new(1);
        let instance_identity = NEXT_CATALOG_INSTANCE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .expect("semantic-pack catalog instance identity space exhausted");
        Ok(Self {
            root,
            mode,
            options,
            instance_identity,
            connection: Mutex::new(connection),
            session_packs: Mutex::new(Vec::new()),
            session_activations: Mutex::new(HashMap::new()),
            rejected_manifests: Mutex::new(HashSet::new()),
            decoded_manifests: Mutex::new(DecodedManifestMemo {
                entries: HashMap::new(),
                bytes: 0,
            }),
            verified_manifest_inventories: Mutex::new(HashSet::new()),
            manifest_decodes: AtomicU64::new(0),
            manifest_inventory_validations: AtomicU64::new(0),
            lookup_hits: AtomicU64::new(0),
            lookup_misses: AtomicU64::new(0),
            sql_statements: AtomicU64::new(0),
            object_reads: AtomicU64::new(0),
            mutation_generation: AtomicU64::new(0),
            _ephemeral_root: None,
        })
    }

    pub fn open_ephemeral(options: CatalogOptions) -> Result<Self, CatalogError> {
        let root = tempfile::Builder::new()
            .prefix("bifrost-semantic-pack-catalog-")
            .tempdir()
            .map_err(|error| CatalogError::io("create ephemeral catalog root", error))?;
        let mut catalog = Self::open(root.path(), CatalogOpenMode::ReadWrite, options)?;
        catalog._ephemeral_root = Some(root);
        Ok(catalog)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn generated_production_lock(
        &self,
        key: &GeneratedProductionKey,
    ) -> Result<GeneratedProductionLock, CatalogError> {
        self.require_writable()?;
        let file = storage::open_generated_production_lock(&self.root, key.production_digest())?;
        Ok(GeneratedProductionLock { file })
    }

    /// Return the number of production catalog SQL statements issued by this instance.
    ///
    /// Semantic-pack lifecycle measurement uses differences between two snapshots.
    /// In-memory matcher and overlay operations do not hold a catalog reference, so
    /// their expected difference is always zero.
    pub fn sql_statement_count(&self) -> u64 {
        self.sql_statements.load(Ordering::Relaxed)
    }

    /// Return the number of catalog object files this instance has read.
    ///
    /// A cached generated-pack lookup must not read shard objects (#2875).
    /// Tests pin that with the difference between two snapshots.
    pub fn object_read_count(&self) -> u64 {
        self.object_reads.load(Ordering::Relaxed)
    }

    /// Return the number of stored-manifest decodes this instance performed.
    ///
    /// A memo hit is not a decode. Selection, near-miss attribution, and shard
    /// loading all read the same stored manifests, so this count is the pin
    /// that each distinct manifest is deserialized once per catalog (#3101).
    pub fn manifest_decode_count(&self) -> u64 {
        self.manifest_decodes.load(Ordering::Relaxed)
    }

    /// Return the number of whole-manifest inventory validations this instance
    /// performed.
    ///
    /// A memo hit is not a validation. Decoding one shard at a time used to
    /// revalidate every record id of the manifest per shard (#3101).
    pub fn manifest_inventory_validation_count(&self) -> u64 {
        self.manifest_inventory_validations.load(Ordering::Relaxed)
    }

    /// Validate one stored manifest's inventory at most once per catalog.
    fn validated_manifest_inventory(
        &self,
        manifest: &CompiledPackManifest,
    ) -> Result<(), CatalogError> {
        let digest = &manifest.content_sha256;
        if self
            .verified_manifest_inventories
            .lock()
            .expect("semantic-pack inventory mutex poisoned")
            .contains(digest)
        {
            return Ok(());
        }
        validate_manifest_inventory(manifest)
            .map_err(|error| CatalogError::Artifact(error.to_string()))?;
        self.manifest_inventory_validations
            .fetch_add(1, Ordering::Relaxed);
        self.verified_manifest_inventories
            .lock()
            .expect("semantic-pack inventory mutex poisoned")
            .insert(digest.clone());
        Ok(())
    }

    /// Decode one shard of a stored manifest after one inventory validation.
    fn decode_stored_shard(
        &self,
        manifest: &CompiledPackManifest,
        descriptor: &CompiledShardDescriptor,
        bytes: &[u8],
    ) -> Result<CompiledShard, CatalogError> {
        self.validated_manifest_inventory(manifest)?;
        decode_validated_shard_for_manifest(
            manifest,
            descriptor,
            bytes,
            &self.options.decode_limits,
        )
        .map_err(|error| CatalogError::Artifact(error.to_string()))
    }

    /// Decode one stored manifest, reusing the decode of an equal digest.
    ///
    /// Callers read stored manifests by digest, so the memo is keyed by that
    /// digest and the decode re-proves it: a value the cache returns for a key
    /// is the value a miss would decode for the same key.
    fn decoded_manifest(
        &self,
        manifest_digest: &str,
        manifest_bytes: &[u8],
    ) -> Result<Arc<CompiledPackManifest>, CatalogError> {
        if let Some(manifest) = self.memoized_manifest(manifest_digest) {
            return Ok(manifest);
        }
        let manifest = Arc::new(
            decode_manifest(manifest_bytes, &self.options.decode_limits)
                .map_err(|error| CatalogError::Artifact(error.to_string()))?,
        );
        if manifest.content_sha256 != manifest_digest {
            return Err(CatalogError::Integrity(
                "catalog manifest key does not match decoded manifest".to_owned(),
            ));
        }
        self.manifest_decodes.fetch_add(1, Ordering::Relaxed);
        let mut memo = self
            .decoded_manifests
            .lock()
            .expect("semantic-pack manifest memo mutex poisoned");
        if memo.bytes.saturating_add(manifest_bytes.len()) > DECODED_MANIFEST_MEMO_BYTES {
            memo.entries.clear();
            memo.bytes = 0;
        }
        memo.bytes = memo.bytes.saturating_add(manifest_bytes.len());
        memo.entries
            .insert(manifest_digest.to_owned(), Arc::clone(&manifest));
        Ok(manifest)
    }

    /// The memoized decode of one stored manifest, when this catalog has it.
    fn memoized_manifest(&self, manifest_digest: &str) -> Option<Arc<CompiledPackManifest>> {
        self.decoded_manifests
            .lock()
            .expect("semantic-pack manifest memo mutex poisoned")
            .entries
            .get(manifest_digest)
            .map(Arc::clone)
    }

    /// Decode one stored manifest, reading its bytes only on a memo miss.
    ///
    /// Candidate selection visits one row per (shard, selector), so a reader
    /// that pulled `manifest_bytes` per row moved the same multi-megabyte blob
    /// out of SQLite dozens of times per pack (#3101). The memo makes the read
    /// and the decode happen once per distinct digest.
    fn stored_manifest(
        &self,
        manifest_digest: &str,
    ) -> Result<Arc<CompiledPackManifest>, CatalogError> {
        if let Some(manifest) = self.memoized_manifest(manifest_digest) {
            return Ok(manifest);
        }
        let bytes = {
            let connection = self
                .connection
                .lock()
                .expect("semantic-pack catalog connection mutex poisoned");
            self.sql_statements.fetch_add(1, Ordering::Relaxed);
            stored_manifest_bytes_on(&connection, manifest_digest)?
                .ok_or(CatalogError::Unavailable)?
        };
        self.decoded_manifest(manifest_digest, &bytes)
    }

    pub fn inventory_bounded(&self, max_packs: usize) -> Result<CatalogInventory, CatalogError> {
        let row_limit = max_packs.saturating_add(1);
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let mut pack_statement = connection
            .prepare(
                "SELECT manifest_digest, manifest_bytes, state
                 FROM catalog_packs
                 ORDER BY pack_id, pack_version, manifest_digest
                 LIMIT ?1",
            )
            .map_err(|error| CatalogError::sqlite("prepare catalog inventory", error))?;
        let pack_rows = pack_statement
            .query_map([i64::try_from(row_limit).unwrap_or(i64::MAX)], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|error| CatalogError::sqlite("query catalog inventory", error))?;
        let mut packs = BTreeMap::new();
        let mut complete = true;
        for row in pack_rows {
            let (manifest_digest, manifest_bytes, state) =
                row.map_err(|error| CatalogError::sqlite("read catalog inventory", error))?;
            let manifest = self.decoded_manifest(&manifest_digest, &manifest_bytes)?;
            if packs.len() >= max_packs {
                complete = false;
                continue;
            }
            packs.insert(
                manifest.content_sha256.clone(),
                inventory_pack(&manifest, state),
            );
        }
        drop(pack_statement);

        let mut source_statement = connection
            .prepare(
                "SELECT manifest_digest, source_kind, source_id
                 FROM catalog_sources
                 ORDER BY manifest_digest, source_kind, source_id",
            )
            .map_err(|error| CatalogError::sqlite("prepare catalog inventory sources", error))?;
        let source_rows = source_statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|error| CatalogError::sqlite("query catalog inventory sources", error))?;
        for row in source_rows {
            let (manifest_digest, source_kind, source_id) =
                row.map_err(|error| CatalogError::sqlite("read catalog inventory source", error))?;
            if let Some(pack) = packs.get_mut(&manifest_digest) {
                let source_kind = DurablePackSourceKind::parse(&source_kind)?;
                pack.sources.push(CatalogPackInventorySource {
                    source_kind: CatalogPackSourceKind::from(source_kind).as_str().to_owned(),
                    source_id,
                });
            }
        }
        drop(source_statement);

        let mut activation_statement = connection
            .prepare(
                "SELECT scope_id, active_set_digest, manifest_digest, source_kind, source_id
                 FROM catalog_activations
                 ORDER BY manifest_digest, scope_id, source_kind, source_id",
            )
            .map_err(|error| {
                CatalogError::sqlite("prepare catalog inventory activations", error)
            })?;
        let activation_rows = activation_statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(|error| CatalogError::sqlite("query catalog inventory activations", error))?;
        for row in activation_rows {
            let (scope_id, active_set_digest, manifest_digest, source_kind, source_id) = row
                .map_err(|error| {
                    CatalogError::sqlite("read catalog inventory activation", error)
                })?;
            if let Some(pack) = packs.get_mut(&manifest_digest) {
                let source_kind = DurablePackSourceKind::parse(&source_kind)?;
                pack.catalog_activations
                    .push(CatalogPackInventoryActivation {
                        scope_id,
                        active_set_digest,
                        source_kind: CatalogPackSourceKind::from(source_kind).as_str().to_owned(),
                        source_id,
                    });
            }
        }
        drop(activation_statement);
        drop(connection);

        for (manifest_digest, pack) in &mut packs {
            pack.extraction = self.extraction_accounting(manifest_digest)?;
        }

        let session_packs = self
            .session_packs
            .lock()
            .expect("semantic-pack session mutex poisoned");
        for session in session_packs.iter() {
            let digest = session.manifest.content_sha256.clone();
            if !packs.contains_key(&digest) && packs.len() >= max_packs {
                complete = false;
                continue;
            }
            let pack = packs
                .entry(digest)
                .or_insert_with(|| inventory_pack(&session.manifest, "session".to_owned()));
            let source = CatalogPackInventorySource {
                source_kind: CatalogPackSourceKind::from(session.source.kind)
                    .as_str()
                    .to_owned(),
                source_id: session.source.source_id.clone(),
            };
            if !pack.sources.contains(&source) {
                pack.sources.push(source);
            }
        }
        drop(session_packs);

        let mut session_activations = self
            .session_activations
            .lock()
            .expect("semantic-pack session activation mutex poisoned");
        session_activations.retain(|_, activation| activation.owner.upgrade().is_some());
        for (scope_id, activation) in session_activations.iter() {
            for member in &activation.active_set.members {
                if let Some(pack) = packs.get_mut(&member.manifest_digest) {
                    pack.catalog_activations
                        .push(CatalogPackInventoryActivation {
                            scope_id: scope_id.clone(),
                            active_set_digest: activation.active_set.active_set_digest.clone(),
                            source_kind: activation_catalog_kind(member.source_kind)
                                .as_str()
                                .to_owned(),
                            source_id: member.source_id.clone(),
                        });
                }
            }
        }
        drop(session_activations);

        let mut packs = packs.into_values().collect::<Vec<_>>();
        for pack in &mut packs {
            pack.sources.sort_by(|left, right| {
                left.source_kind
                    .cmp(&right.source_kind)
                    .then_with(|| left.source_id.cmp(&right.source_id))
            });
            pack.catalog_activations.sort_by(|left, right| {
                left.scope_id
                    .cmp(&right.scope_id)
                    .then_with(|| left.source_kind.cmp(&right.source_kind))
                    .then_with(|| left.source_id.cmp(&right.source_id))
            });
        }
        packs.sort_by(|left, right| {
            left.pack_id
                .cmp(&right.pack_id)
                .then_with(|| left.pack_version.cmp(&right.pack_version))
                .then_with(|| {
                    left.manifest_content_sha256
                        .cmp(&right.manifest_content_sha256)
                })
        });
        Ok(CatalogInventory { complete, packs })
    }

    pub fn install(
        &self,
        pack: &CompiledSemanticModelPack,
        source: &DurablePackSource,
    ) -> Result<InstallOutcome, CatalogError> {
        self.install_with(pack, source, |_, _, _| Ok(()))
    }

    pub fn install_release(
        &self,
        pack: &CompiledSemanticModelPack,
        source: &DurablePackSource,
        extraction: &PackExtractionAccounting,
    ) -> Result<InstallOutcome, CatalogError> {
        validate_extraction_accounting(extraction)?;
        self.install_with(pack, source, |transaction, manifest, _| {
            insert_extraction_accounting(transaction, &manifest.content_sha256, extraction)
        })
    }

    /// Install a release pack and return an opaque proof of the exact source
    /// row committed by the catalog. Callers cannot construct this proof from
    /// asserted release metadata.
    pub fn install_release_for_receipt(
        &self,
        release: &AcquisitionReceiptRelease,
        pack: &CompiledSemanticModelPack,
        source: &DurablePackSource,
        extraction: &PackExtractionAccounting,
    ) -> Result<(InstallOutcome, AcquisitionReceiptSource), CatalogError> {
        let release_digest = release.digest()?;
        validate_extraction_accounting(extraction)?;
        let validated = validate_pack(pack, &self.options.decode_limits)?;
        let install = if self.unchanged_release_install(
            &validated,
            &pack.manifest_bytes,
            source,
            extraction,
        )? {
            InstallOutcome {
                manifest_digest: validated.manifest.content_sha256,
                inserted_manifest: false,
                inserted_objects: 0,
            }
        } else {
            self.install_release(pack, source, extraction)?
        };
        let proof = AcquisitionReceiptSource {
            release_digest,
            manifest_digest: install.manifest_digest.clone(),
            source: source.clone(),
        };
        Ok((install, proof))
    }

    /// Install a release-provided production as an exact generated entry.
    ///
    /// The release source, extraction accounting, generated mapping, manifest,
    /// and shard rows are committed by one catalog transaction. A synthetic
    /// `generated` source row preserves the invariant used by
    /// [`Self::generated_production`], while `source` retains the release
    /// provenance for inventory and garbage-collection purposes.
    pub fn install_release_generated(
        &self,
        key: &GeneratedProductionKey,
        pack: &CompiledSemanticModelPack,
        source: &DurablePackSource,
        extraction: &PackExtractionAccounting,
    ) -> Result<GeneratedInstallOutcome, CatalogError> {
        validate_generated_pack_identity(key, &pack.manifest)?;
        validate_extraction_accounting(extraction)?;
        let generated_source = DurablePackSource {
            kind: DurablePackSourceKind::Generated,
            source_id: key.source_id(),
        };
        let install = self.install_with(pack, source, |transaction, manifest, now| {
            insert_extraction_accounting(transaction, &manifest.content_sha256, extraction)?;
            insert_generated_production(transaction, key, manifest, now)?;
            insert_source(
                transaction,
                &manifest.content_sha256,
                &generated_source,
                now,
            )
        })?;
        Ok(GeneratedInstallOutcome {
            production: GeneratedProduction {
                key: key.clone(),
                manifest_digest: install.manifest_digest.clone(),
                completeness: pack.manifest.completeness,
            },
            install,
        })
    }

    /// Install a release-generated pack and return opaque proofs for both the
    /// release provenance and canonical generated-production source rows.
    pub fn install_release_generated_for_receipt(
        &self,
        release: &AcquisitionReceiptRelease,
        key: &GeneratedProductionKey,
        pack: &CompiledSemanticModelPack,
        source: &DurablePackSource,
        extraction: &PackExtractionAccounting,
    ) -> Result<(GeneratedInstallOutcome, Vec<AcquisitionReceiptSource>), CatalogError> {
        let release_digest = release.digest()?;
        validate_generated_pack_identity(key, &pack.manifest)?;
        validate_extraction_accounting(extraction)?;
        let validated = validate_pack(pack, &self.options.decode_limits)?;
        let generated_source = DurablePackSource {
            kind: DurablePackSourceKind::Generated,
            source_id: key.source_id(),
        };
        let unchanged =
            self.unchanged_release_install(&validated, &pack.manifest_bytes, source, extraction)?
                && self.exact_verified_install_present(
                    &validated,
                    &pack.manifest_bytes,
                    &generated_source,
                )?
                && self.generated_production(key)?.is_some_and(|production| {
                    production.manifest_digest == validated.manifest.content_sha256
                });
        let installation = if unchanged {
            GeneratedInstallOutcome {
                production: GeneratedProduction {
                    key: key.clone(),
                    manifest_digest: validated.manifest.content_sha256.clone(),
                    completeness: validated.manifest.completeness,
                },
                install: InstallOutcome {
                    manifest_digest: validated.manifest.content_sha256,
                    inserted_manifest: false,
                    inserted_objects: 0,
                },
            }
        } else {
            self.install_release_generated(key, pack, source, extraction)?
        };
        let manifest_digest = installation.install.manifest_digest.clone();
        Ok((
            installation,
            vec![
                AcquisitionReceiptSource {
                    release_digest: release_digest.clone(),
                    manifest_digest: manifest_digest.clone(),
                    source: source.clone(),
                },
                AcquisitionReceiptSource {
                    release_digest,
                    manifest_digest,
                    source: DurablePackSource {
                        kind: DurablePackSourceKind::Generated,
                        source_id: key.source_id(),
                    },
                },
            ],
        ))
    }

    /// Whether a verified durable pack carries exactly this source identity.
    ///
    /// A source may identify several manifests in one release, so this query
    /// intentionally does not require a manifest digest. It is read-only and
    /// does not hydrate or validate shard bytes.
    pub fn durable_source_present(&self, source: &DurablePackSource) -> Result<bool, CatalogError> {
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        connection
            .query_row(
                "SELECT EXISTS(
                   SELECT 1
                   FROM catalog_sources AS sources
                   JOIN catalog_packs AS packs
                     ON packs.manifest_digest = sources.manifest_digest
                   WHERE sources.source_kind = ?1
                     AND sources.source_id = ?2
                     AND packs.state = 'verified'
                 )",
                params![source.kind.as_str(), &source.source_id],
                |row| row.get(0),
            )
            .map_err(|error| CatalogError::sqlite("check durable pack source", error))
    }

    pub fn extraction_accounting(
        &self,
        manifest_digest: &str,
    ) -> Result<Option<PackExtractionAccounting>, CatalogError> {
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let counts = connection
            .query_row(
                "SELECT reject_count, suppressed_reject_count, error_reject_count
                 FROM catalog_pack_extraction_accounting
                 WHERE manifest_digest = ?1",
                [manifest_digest],
                |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, u64>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| CatalogError::sqlite("read pack extraction accounting", error))?;
        let Some((reject_count, suppressed_reject_count, error_reject_count)) = counts else {
            return Ok(None);
        };
        let mut statement = connection
            .prepare(
                "SELECT declaration, reason
                 FROM catalog_pack_extraction_gaps
                 WHERE manifest_digest = ?1
                 ORDER BY ordinal",
            )
            .map_err(|error| CatalogError::sqlite("prepare pack extraction gaps", error))?;
        let rows = statement
            .query_map([manifest_digest], |row| {
                Ok(PackExtractionGap {
                    declaration: row.get(0)?,
                    reason: row.get(1)?,
                })
            })
            .map_err(|error| CatalogError::sqlite("query pack extraction gaps", error))?;
        let gaps = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| CatalogError::sqlite("read pack extraction gap", error))?;
        let mut statement = connection
            .prepare(
                "SELECT source_entry, reason
                 FROM catalog_pack_extraction_source_entries
                 WHERE manifest_digest = ?1
                 ORDER BY ordinal",
            )
            .map_err(|error| {
                CatalogError::sqlite("prepare pack extraction source entries", error)
            })?;
        let rows = statement
            .query_map([manifest_digest], |row| {
                Ok(PackExtractionSourceEntry {
                    source_entry: row.get(0)?,
                    reason: row.get(1)?,
                })
            })
            .map_err(|error| CatalogError::sqlite("query pack extraction source entries", error))?;
        let source_entries = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| CatalogError::sqlite("read pack extraction source entry", error))?;
        Ok(Some(PackExtractionAccounting {
            reject_count,
            suppressed_reject_count,
            error_reject_count,
            gaps,
            source_entries,
        }))
    }

    pub fn install_generated(
        &self,
        key: &GeneratedProductionKey,
        pack: &CompiledSemanticModelPack,
    ) -> Result<GeneratedInstallOutcome, CatalogError> {
        validate_generated_pack_identity(key, &pack.manifest)?;
        let source = DurablePackSource {
            kind: DurablePackSourceKind::Generated,
            source_id: key.source_id(),
        };
        let install = self.install_with(pack, &source, |transaction, manifest, now| {
            insert_generated_production(transaction, key, manifest, now)
        })?;
        Ok(GeneratedInstallOutcome {
            production: GeneratedProduction {
                key: key.clone(),
                manifest_digest: install.manifest_digest.clone(),
                completeness: pack.manifest.completeness,
            },
            install,
        })
    }

    /// Look up the cached generated pack for `key`.
    ///
    /// This lookup is metadata only. It decodes the manifest, checks the key
    /// and producer identity, and confirms in one query that the catalog still
    /// holds a shard row joined to an object row for every manifest
    /// descriptor. It does not read or decode shard bytes. The pack row's
    /// `state = 'verified'`, written inside the install transaction after
    /// `validate_pack` decoded every shard, is the validation record, and the
    /// query requires it. The stored bytes are verified again by
    /// `storage::read` when a shard is loaded, and `load` quarantines a
    /// corrupt object there. Do not re-add a per-lookup decode pass (#2875).
    pub fn generated_production(
        &self,
        key: &GeneratedProductionKey,
    ) -> Result<Option<GeneratedProduction>, CatalogError> {
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let row = connection
            .query_row(
                "SELECT gp.input_digest, gp.producer_name, gp.producer_version,
                        gp.schema_version, gp.manifest_digest, p.manifest_bytes
                 FROM catalog_generated_productions AS gp
                 JOIN catalog_packs AS p
                   ON p.manifest_digest = gp.manifest_digest
                 JOIN catalog_sources AS source
                   ON source.manifest_digest = gp.manifest_digest
                  AND source.source_kind = 'generated'
                  AND source.source_id = 'production:' || gp.production_digest
                 WHERE gp.production_digest = ?1 AND p.state = 'verified'",
                [&key.production_digest],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, u32>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| CatalogError::sqlite("lookup generated production", error))?;
        drop(connection);
        let Some((
            input_digest,
            producer_name,
            producer_version,
            schema_version,
            manifest_digest,
            manifest_bytes,
        )) = row
        else {
            return Ok(None);
        };
        let validated = (|| -> Result<GeneratedProduction, CatalogError> {
            let stored_key = GeneratedProductionKey::new(
                input_digest,
                producer_name,
                producer_version,
                schema_version,
            )?;
            if stored_key != *key {
                return Err(CatalogError::Integrity(
                    "generated-production row does not match its canonical key".to_owned(),
                ));
            }
            let manifest = self.decoded_manifest(&manifest_digest, &manifest_bytes)?;
            validate_generated_pack_identity(key, &manifest)?;
            self.validate_generated_shard_rows(&manifest_digest, &manifest)?;
            Ok(GeneratedProduction {
                key: stored_key,
                manifest_digest: manifest_digest.clone(),
                completeness: manifest.completeness,
            })
        })();
        match validated {
            Ok(production) => Ok(Some(production)),
            Err(error) => {
                self.rejected_manifests
                    .lock()
                    .expect("semantic-pack rejection mutex poisoned")
                    .insert(manifest_digest.clone());
                if self.mode == CatalogOpenMode::ReadWrite {
                    self.quarantine(&manifest_digest, "generated_production_failure", &error)?;
                }
                Ok(None)
            }
        }
    }

    /// Confirm that every manifest descriptor still has its shard row and
    /// object row, in one statement and without reading any object file.
    fn validate_generated_shard_rows(
        &self,
        manifest_digest: &str,
        manifest: &CompiledPackManifest,
    ) -> Result<(), CatalogError> {
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let mut statement = connection
            .prepare(
                "SELECT ps.shard_id, ps.stored_digest
                 FROM catalog_pack_shards AS ps
                 JOIN catalog_objects AS o
                   ON o.stored_digest = ps.stored_digest
                 WHERE ps.manifest_digest = ?1",
            )
            .map_err(|error| CatalogError::sqlite("lookup generated production shards", error))?;
        let rows = statement
            .query_map([manifest_digest], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|error| CatalogError::sqlite("lookup generated production shards", error))?;
        let mut stored = HashMap::with_capacity(manifest.shards.len());
        for row in rows {
            let (shard_id, stored_digest) = row.map_err(|error| {
                CatalogError::sqlite("read generated production shard row", error)
            })?;
            stored.insert(shard_id, stored_digest);
        }
        let missing: Vec<&str> = manifest
            .shards
            .iter()
            .filter(|descriptor| {
                stored.get(&descriptor.shard_id) != Some(&descriptor.stored_sha256)
            })
            .map(|descriptor| descriptor.shard_id.as_str())
            .collect();
        if !missing.is_empty() {
            return Err(CatalogError::Integrity(format!(
                "generated production is missing shards {missing:?}"
            )));
        }
        Ok(())
    }

    fn install_with(
        &self,
        pack: &CompiledSemanticModelPack,
        source: &DurablePackSource,
        record_install: impl FnOnce(
            &Transaction<'_>,
            &CompiledPackManifest,
            i64,
        ) -> Result<(), CatalogError>,
    ) -> Result<InstallOutcome, CatalogError> {
        self.require_writable()?;
        if source.source_id.is_empty() {
            return Err(CatalogError::Integrity(
                "catalog source id must not be empty".to_owned(),
            ));
        }
        let validated = validate_pack(pack, &self.options.decode_limits)?;
        let installation_id = Uuid::new_v4().to_string();
        self.reserve_install_objects(&installation_id, &validated.shards)?;
        let mut published = Vec::with_capacity(validated.shards.len());
        let mut inserted_objects = 0;
        for shard in &validated.shards {
            let (path, inserted) =
                match storage::publish(&self.root, &shard.descriptor.stored_sha256, &shard.bytes) {
                    Ok(published) => published,
                    Err(error) => {
                        return Err(self.release_after_install_failure(&installation_id, error));
                    }
                };
            inserted_objects += usize::from(inserted);
            published.push(path);
        }

        let now = crate::cache_db::now_unix_seconds();
        let install_result = self.commit_install(
            pack,
            source,
            &validated,
            &published,
            &installation_id,
            now,
            record_install,
        );
        match install_result {
            Ok(inserted_manifest) => {
                self.rejected_manifests
                    .lock()
                    .expect("semantic-pack rejection mutex poisoned")
                    .remove(&validated.manifest.content_sha256);
                self.record_mutation();
                Ok(InstallOutcome {
                    manifest_digest: validated.manifest.content_sha256,
                    inserted_manifest,
                    inserted_objects,
                })
            }
            Err(error) => Err(self.release_after_install_failure(&installation_id, error)),
        }
    }

    fn exact_verified_install_present(
        &self,
        validated: &ValidatedPack,
        manifest_bytes: &[u8],
        source: &DurablePackSource,
    ) -> Result<bool, CatalogError> {
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let provenance_json = serde_json::to_vec(&validated.manifest.provenance)
            .map_err(|error| CatalogError::Integrity(error.to_string()))?;
        let pack = connection
            .query_row(
                "SELECT pack.semantic_digest, pack.manifest_bytes, pack.schema_version,
                        pack.pack_id, pack.pack_version, pack.producer_name,
                        pack.producer_version, pack.language, pack.ecosystem,
                        pack.bifrost_compatibility, pack.provenance_json, pack.license,
                        pack.completeness
                 FROM catalog_packs AS pack
                 JOIN catalog_sources AS source
                   ON source.manifest_digest = pack.manifest_digest
                 WHERE pack.manifest_digest = ?1 AND pack.state = 'verified'
                   AND source.source_kind = ?2 AND source.source_id = ?3",
                params![
                    validated.manifest.content_sha256,
                    source.kind.as_str(),
                    source.source_id,
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, u32>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, Vec<u8>>(10)?,
                        row.get::<_, String>(11)?,
                        row.get::<_, String>(12)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| CatalogError::sqlite("read exact verified manifest", error))?;
        let Some((
            semantic_digest,
            stored_manifest_bytes,
            schema_version,
            pack_id,
            pack_version,
            producer_name,
            producer_version,
            language,
            ecosystem,
            bifrost_compatibility,
            stored_provenance_json,
            license,
            completeness,
        )) = pack
        else {
            return Ok(false);
        };
        if semantic_digest != validated.manifest.semantic_sha256
            || stored_manifest_bytes != manifest_bytes
            || schema_version != validated.manifest.schema_version
            || pack_id != validated.manifest.pack_id
            || pack_version != validated.manifest.version
            || producer_name != validated.manifest.producer.name
            || producer_version != validated.manifest.producer.version
            || language != validated.manifest.language
            || ecosystem != validated.manifest.ecosystem
            || bifrost_compatibility != validated.manifest.compatibility.bifrost
            || stored_provenance_json != provenance_json
            || license != validated.manifest.license
            || completeness != completeness_name(&validated.manifest.completeness)
        {
            return Ok(false);
        }

        let mut statement = connection
            .prepare(
                "SELECT shard.ordinal, shard.shard_id, shard.payload_kind,
                        shard.stored_digest, shard.content_digest, shard.semantic_digest,
                        shard.record_count, shard.descriptor_json,
                        object.relative_path, object.stored_size, object.raw_size,
                        object.encoding
                 FROM catalog_packs AS pack
                 JOIN catalog_sources AS source ON source.manifest_digest = pack.manifest_digest
                 JOIN catalog_pack_shards AS shard ON shard.manifest_digest = pack.manifest_digest
                 JOIN catalog_objects AS object ON object.stored_digest = shard.stored_digest
                 WHERE pack.manifest_digest = ?1 AND pack.state = 'verified'
                   AND source.source_kind = ?2 AND source.source_id = ?3
                 ORDER BY shard.ordinal",
            )
            .map_err(|error| {
                CatalogError::sqlite("prepare exact verified installation check", error)
            })?;
        let rows = statement
            .query_map(
                params![
                    validated.manifest.content_sha256,
                    source.kind.as_str(),
                    source.source_id,
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, u64>(6)?,
                        row.get::<_, Vec<u8>>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, u64>(9)?,
                        row.get::<_, u64>(10)?,
                        row.get::<_, String>(11)?,
                    ))
                },
            )
            .map_err(|error| CatalogError::sqlite("check exact verified installation", error))?;
        let mut stored_shards = Vec::with_capacity(validated.shards.len());
        for row in rows {
            stored_shards.push(row.map_err(|error| {
                CatalogError::sqlite("read exact verified installation", error)
            })?);
        }
        if stored_shards.len() != validated.shards.len() {
            return Ok(false);
        }
        for (ordinal, (shard, row)) in validated.shards.iter().zip(stored_shards).enumerate() {
            let (
                stored_ordinal,
                shard_id,
                payload_kind,
                stored_digest,
                content_digest,
                semantic_digest,
                record_count,
                descriptor_json,
                relative_path,
                stored_size,
                raw_size,
                encoding,
            ) = row;
            let expected_ordinal = i64::try_from(ordinal).map_err(|_| {
                CatalogError::Integrity("catalog shard ordinal exceeds i64".to_owned())
            })?;
            let expected_descriptor_json = serde_json::to_vec(&shard.descriptor)
                .map_err(|error| CatalogError::Integrity(error.to_string()))?;
            if stored_ordinal != expected_ordinal
                || shard_id != shard.descriptor.shard_id
                || payload_kind != payload_kind_name(shard.descriptor.payload_kind)
                || stored_digest != shard.descriptor.stored_sha256
                || content_digest != shard.descriptor.content_sha256
                || semantic_digest != shard.descriptor.semantic_sha256
                || record_count != shard.descriptor.record_count
                || descriptor_json != expected_descriptor_json
                || stored_size != shard.descriptor.stored_size
                || raw_size != shard.descriptor.raw_size
                || encoding != encoding_name(shard.descriptor.encoding)
            {
                return Ok(false);
            }
            if !receipt_object_is_valid(
                &self.root,
                Path::new(&relative_path),
                &stored_digest,
                stored_size,
            )? {
                return Ok(false);
            }
        }

        let mut expected_selectors = Vec::new();
        for shard in &validated.shards {
            for (ordinal, selector) in shard.selectors.iter().enumerate() {
                expected_selectors.push((
                    shard.descriptor.shard_id.clone(),
                    i64::try_from(ordinal).map_err(|_| {
                        CatalogError::Integrity("selector ordinal exceeds i64".to_owned())
                    })?,
                    selector.package.as_ref().map(|value| value.name.clone()),
                    selector
                        .package
                        .as_ref()
                        .and_then(|value| value.version.clone()),
                    selector.module.as_ref().map(|value| value.name.clone()),
                    selector
                        .module
                        .as_ref()
                        .and_then(|value| value.version.clone()),
                    selector.toolchain.as_ref().map(|value| value.name.clone()),
                    selector
                        .toolchain
                        .as_ref()
                        .and_then(|value| value.version.clone()),
                    selector.artifact_sha256.clone(),
                    serde_json::to_vec(selector)
                        .map_err(|error| CatalogError::Integrity(error.to_string()))?,
                ));
            }
        }
        expected_selectors.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
        let mut statement = connection
            .prepare(
                "SELECT shard_id, selector_ordinal, package_name, package_version,
                        module_name, module_version, toolchain_name, toolchain_version,
                        artifact_sha256, selector_json
                 FROM catalog_selectors
                 WHERE manifest_digest = ?1
                 ORDER BY shard_id, selector_ordinal",
            )
            .map_err(|error| CatalogError::sqlite("prepare exact selector check", error))?;
        let rows = statement
            .query_map([&validated.manifest.content_sha256], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                ))
            })
            .map_err(|error| CatalogError::sqlite("query exact selector check", error))?;
        let mut stored_selectors = Vec::with_capacity(expected_selectors.len());
        for row in rows {
            stored_selectors.push(
                row.map_err(|error| CatalogError::sqlite("read exact selector check", error))?,
            );
        }
        if stored_selectors != expected_selectors {
            return Ok(false);
        }

        let mut expected_targets = Vec::new();
        let mut expected_configurations = Vec::new();
        for shard in &validated.shards {
            for (ordinal, selector) in shard.selectors.iter().enumerate() {
                let ordinal = i64::try_from(ordinal).map_err(|_| {
                    CatalogError::Integrity("selector ordinal exceeds i64".to_owned())
                })?;
                expected_targets.extend(
                    selector
                        .targets
                        .iter()
                        .map(|target| (shard.descriptor.shard_id.clone(), ordinal, target.clone())),
                );
                expected_configurations.extend(selector.configurations.iter().map(
                    |configuration| {
                        (
                            shard.descriptor.shard_id.clone(),
                            ordinal,
                            configuration.clone(),
                        )
                    },
                ));
            }
        }
        expected_targets.sort();
        expected_configurations.sort();
        let mut statement = connection
            .prepare(
                "SELECT shard_id, selector_ordinal, target
                 FROM catalog_selector_targets
                 WHERE manifest_digest = ?1
                 ORDER BY shard_id, selector_ordinal, target",
            )
            .map_err(|error| CatalogError::sqlite("prepare exact selector target check", error))?;
        let rows = statement
            .query_map([&validated.manifest.content_sha256], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|error| CatalogError::sqlite("query exact selector target check", error))?;
        let stored_targets = rows
            .collect::<Result<Vec<(String, i64, String)>, _>>()
            .map_err(|error| CatalogError::sqlite("read exact selector target check", error))?;
        if stored_targets != expected_targets {
            return Ok(false);
        }
        let mut statement = connection
            .prepare(
                "SELECT shard_id, selector_ordinal, configuration
                 FROM catalog_selector_configurations
                 WHERE manifest_digest = ?1
                 ORDER BY shard_id, selector_ordinal, configuration",
            )
            .map_err(|error| {
                CatalogError::sqlite("prepare exact selector configuration check", error)
            })?;
        let rows = statement
            .query_map([&validated.manifest.content_sha256], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|error| {
                CatalogError::sqlite("query exact selector configuration check", error)
            })?;
        let stored_configurations = rows
            .collect::<Result<Vec<(String, i64, String)>, _>>()
            .map_err(|error| {
                CatalogError::sqlite("read exact selector configuration check", error)
            })?;
        if stored_configurations != expected_configurations {
            return Ok(false);
        }

        let mut expected_routing_keys = Vec::new();
        for shard in &validated.shards {
            expected_routing_keys.extend(
                shard
                    .descriptor
                    .routing_keys
                    .iter()
                    .map(|routing_key| (shard.descriptor.shard_id.clone(), routing_key.clone())),
            );
        }
        expected_routing_keys.sort();
        let mut statement = connection
            .prepare(
                "SELECT shard_id, routing_key
                 FROM catalog_routing_keys
                 WHERE manifest_digest = ?1
                 ORDER BY shard_id, routing_key",
            )
            .map_err(|error| CatalogError::sqlite("prepare exact routing-key check", error))?;
        let rows = statement
            .query_map([&validated.manifest.content_sha256], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .map_err(|error| CatalogError::sqlite("query exact routing-key check", error))?;
        let stored_routing_keys = rows
            .collect::<Result<Vec<(String, String)>, _>>()
            .map_err(|error| CatalogError::sqlite("read exact routing-key check", error))?;
        Ok(stored_routing_keys == expected_routing_keys)
    }

    fn unchanged_release_install(
        &self,
        validated: &ValidatedPack,
        manifest_bytes: &[u8],
        source: &DurablePackSource,
        extraction: &PackExtractionAccounting,
    ) -> Result<bool, CatalogError> {
        Ok(
            self.exact_verified_install_present(validated, manifest_bytes, source)?
                && self
                    .extraction_accounting(&validated.manifest.content_sha256)?
                    .as_ref()
                    == Some(extraction),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_install(
        &self,
        pack: &CompiledSemanticModelPack,
        source: &DurablePackSource,
        validated: &ValidatedPack,
        published: &[PathBuf],
        installation_id: &str,
        now: i64,
        record_install: impl FnOnce(
            &Transaction<'_>,
            &CompiledPackManifest,
            i64,
        ) -> Result<(), CatalogError>,
    ) -> Result<bool, CatalogError> {
        let mut connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| CatalogError::sqlite("begin pack install", error))?;
        for (shard, path) in validated.shards.iter().zip(published) {
            storage::verify_existing(
                &self.root,
                path,
                &shard.descriptor.stored_sha256,
                shard.descriptor.stored_size,
            )?;
        }
        let inserted_manifest =
            insert_manifest(&transaction, &validated.manifest, &pack.manifest_bytes, now)?;
        for (ordinal, ((shard, path), descriptor)) in validated
            .shards
            .iter()
            .zip(published)
            .zip(&validated.manifest.shards)
            .enumerate()
        {
            insert_object(&transaction, descriptor, path, now)?;
            insert_shard(
                &transaction,
                &validated.manifest.content_sha256,
                ordinal,
                descriptor,
            )?;
            insert_selectors(
                &transaction,
                &validated.manifest.content_sha256,
                &descriptor.shard_id,
                &shard.selectors,
            )?;
            insert_routing_keys(
                &transaction,
                &validated.manifest.content_sha256,
                &descriptor.shard_id,
                &descriptor.routing_keys,
            )?;
        }
        insert_source(
            &transaction,
            &validated.manifest.content_sha256,
            source,
            now,
        )?;
        record_install(&transaction, &validated.manifest, now)?;
        transaction
            .execute(
                "UPDATE catalog_packs
                 SET state = 'verified', verified_at = ?2
                 WHERE manifest_digest = ?1",
                params![&validated.manifest.content_sha256, now],
            )
            .map_err(|error| CatalogError::sqlite("verify installed pack", error))?;
        transaction
            .execute(
                "DELETE FROM catalog_install_object_reservations
                 WHERE installation_id = ?1",
                [installation_id],
            )
            .map_err(|error| CatalogError::sqlite("release install reservations", error))?;
        transaction
            .commit()
            .map_err(|error| CatalogError::sqlite("commit pack install", error))?;
        Ok(inserted_manifest)
    }

    fn reserve_install_objects(
        &self,
        installation_id: &str,
        shards: &[ValidatedShard],
    ) -> Result<(), CatalogError> {
        let now = crate::cache_db::now_unix_seconds();
        let expires_at = now.checked_add(300).ok_or_else(|| {
            CatalogError::Integrity("install reservation expiry overflowed".to_owned())
        })?;
        let mut connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| CatalogError::sqlite("begin object reservation", error))?;
        transaction
            .execute(
                "DELETE FROM catalog_install_object_reservations
                 WHERE expires_at <= ?1",
                [now],
            )
            .map_err(|error| CatalogError::sqlite("prune install reservations", error))?;
        for shard in shards {
            transaction
                .execute(
                    "INSERT OR IGNORE INTO catalog_install_object_reservations(
                       installation_id, stored_digest, expires_at
                     ) VALUES(?1, ?2, ?3)",
                    params![installation_id, &shard.descriptor.stored_sha256, expires_at],
                )
                .map_err(|error| CatalogError::sqlite("reserve install object", error))?;
        }
        transaction
            .commit()
            .map_err(|error| CatalogError::sqlite("commit object reservation", error))
    }

    fn release_install_reservations(&self, installation_id: &str) -> Result<(), CatalogError> {
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        connection
            .execute(
                "DELETE FROM catalog_install_object_reservations
                 WHERE installation_id = ?1",
                [installation_id],
            )
            .map_err(|error| CatalogError::sqlite("release install reservations", error))?;
        Ok(())
    }

    fn release_after_install_failure(
        &self,
        installation_id: &str,
        error: CatalogError,
    ) -> CatalogError {
        match self.release_install_reservations(installation_id) {
            Ok(()) => error,
            Err(release_error) => CatalogError::Integrity(format!(
                "{error}; failed to release install reservations: {release_error}"
            )),
        }
    }

    pub fn register_session_pack(
        &self,
        pack: &CompiledSemanticModelPack,
        source: &SessionPackSource,
    ) -> Result<String, CatalogError> {
        if source.source_id.is_empty() {
            return Err(CatalogError::Integrity(
                "session pack source id must not be empty".to_owned(),
            ));
        }
        let validated = validate_pack(pack, &self.options.decode_limits)?;
        let digest = validated.manifest.content_sha256.clone();
        let mut session_packs = self
            .session_packs
            .lock()
            .expect("semantic-pack session mutex poisoned");
        if !session_packs
            .iter()
            .any(|entry| entry.manifest.content_sha256 == digest && entry.source == *source)
        {
            session_packs.push(SessionPack {
                manifest: Arc::new(validated.manifest),
                shards: validated.shards,
                source: source.clone(),
            });
            self.record_mutation();
        }
        Ok(digest)
    }

    pub fn lease(
        &self,
        manifest_digest: &str,
        owner: &str,
        ttl: Duration,
    ) -> Result<CatalogLease<'_>, CatalogError> {
        self.require_writable()?;
        if owner.is_empty() {
            return Err(CatalogError::Integrity(
                "semantic-pack lease owner must not be empty".to_owned(),
            ));
        }
        let lease_id = Uuid::new_v4().to_string();
        let expires_at = lease_expiry(ttl)?;
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        self.sql_statements.fetch_add(1, Ordering::Relaxed);
        let inserted = connection
            .execute(
                "INSERT INTO catalog_leases(lease_id, manifest_digest, owner, expires_at)
                 SELECT ?1, manifest_digest, ?3, ?4
                 FROM catalog_packs
                 WHERE manifest_digest = ?2 AND state = 'verified'",
                params![&lease_id, manifest_digest, owner, expires_at],
            )
            .map_err(|error| CatalogError::sqlite("acquire semantic-pack lease", error))?;
        if inserted == 0 {
            return Err(CatalogError::Unavailable);
        }
        Ok(CatalogLease {
            catalog: self,
            lease_id,
            released: false,
        })
    }

    pub fn pin(&self, manifest_digest: &str, pin_id: &str) -> Result<(), CatalogError> {
        self.require_writable()?;
        if pin_id.is_empty() {
            return Err(CatalogError::Integrity(
                "semantic-pack pin id must not be empty".to_owned(),
            ));
        }
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let inserted = connection
            .execute(
                "INSERT OR IGNORE INTO catalog_pins(manifest_digest, pin_id, created_at)
                 SELECT manifest_digest, ?2, ?3
                 FROM catalog_packs
                 WHERE manifest_digest = ?1 AND state = 'verified'",
                params![manifest_digest, pin_id, crate::cache_db::now_unix_seconds()],
            )
            .map_err(|error| CatalogError::sqlite("pin semantic pack", error))?;
        if inserted == 0 {
            let exists: bool = connection
                .query_row(
                    "SELECT EXISTS(
                       SELECT 1 FROM catalog_pins
                       WHERE manifest_digest = ?1 AND pin_id = ?2
                     )",
                    params![manifest_digest, pin_id],
                    |row| row.get(0),
                )
                .map_err(|error| CatalogError::sqlite("check semantic-pack pin", error))?;
            if !exists {
                return Err(CatalogError::Unavailable);
            }
        }
        Ok(())
    }

    pub fn unpin(&self, manifest_digest: &str, pin_id: &str) -> Result<bool, CatalogError> {
        self.require_writable()?;
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        connection
            .execute(
                "DELETE FROM catalog_pins
                 WHERE manifest_digest = ?1 AND pin_id = ?2",
                params![manifest_digest, pin_id],
            )
            .map(|deleted| deleted != 0)
            .map_err(|error| CatalogError::sqlite("unpin semantic pack", error))
    }

    pub fn remove_source(&self, source: &DurablePackSource) -> Result<bool, CatalogError> {
        self.require_writable()?;
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let removed = connection
            .execute(
                "DELETE FROM catalog_sources
                 WHERE source_kind = ?1 AND source_id = ?2",
                params![source.kind.as_str(), &source.source_id],
            )
            .map(|deleted| deleted != 0)
            .map_err(|error| CatalogError::sqlite("remove semantic-pack source", error))?;
        if removed {
            self.record_mutation();
        }
        Ok(removed)
    }

    pub fn replace_workspace_active_set(
        &self,
        scope_id: &str,
        store: &AnalyzerStore,
        members: &[SemanticPackActiveReference],
    ) -> Result<SemanticPackActiveSet, CatalogError> {
        if scope_id.is_empty() {
            return Err(CatalogError::Integrity(
                "semantic-pack activation scope must not be empty".to_owned(),
            ));
        }
        let desired = SemanticPackActiveSet::from_members(members)
            .map_err(|error| CatalogError::Integrity(error.to_string()))?;
        if store.is_ephemeral() {
            if desired
                .members
                .iter()
                .any(|member| durable_activation_kind(member.source_kind).is_some())
            {
                return Err(CatalogError::Integrity(
                    "ephemeral workspaces can activate only session semantic packs".to_owned(),
                ));
            }
            self.validate_active_members(&desired.members, true, None)?;
            let stored = store
                .replace_semantic_pack_active_set(&desired.members)
                .map_err(|error| CatalogError::Integrity(error.to_string()))?;
            self.replace_session_activations(scope_id, &stored, store);
            return Ok(stored);
        }
        self.validate_active_members(&desired.members, false, Some(scope_id))?;
        if desired
            .members
            .iter()
            .any(|member| durable_activation_kind(member.source_kind).is_none())
        {
            return Err(CatalogError::Integrity(
                "persistent workspaces cannot activate session-only semantic packs".to_owned(),
            ));
        }
        self.require_writable()?;
        let mut leases = self.activation_leases(scope_id, &desired.members)?;
        self.write_activation_rows(scope_id, &desired, false)?;
        let stored = store
            .replace_semantic_pack_active_set(&desired.members)
            .map_err(|error| CatalogError::Integrity(error.to_string()))?;
        self.write_activation_rows(scope_id, &stored, true)?;
        release_leases(&mut leases)?;
        Ok(stored)
    }

    pub fn reconcile_workspace_active_set(
        &self,
        scope_id: &str,
        store: &AnalyzerStore,
    ) -> Result<Option<SemanticPackActiveSet>, CatalogError> {
        if store.is_ephemeral() {
            let active_set = store
                .semantic_pack_active_set()
                .map_err(|error| CatalogError::Integrity(error.to_string()))?;
            let desired = match active_set {
                Some(active_set) => active_set,
                None => SemanticPackActiveSet::from_members(&[])
                    .map_err(|error| CatalogError::Integrity(error.to_string()))?,
            };
            if desired
                .members
                .iter()
                .any(|member| durable_activation_kind(member.source_kind).is_some())
            {
                return Err(CatalogError::Integrity(
                    "ephemeral workspaces can activate only session semantic packs".to_owned(),
                ));
            }
            self.validate_active_members(&desired.members, true, None)?;
            self.replace_session_activations(scope_id, &desired, store);
            return Ok((!desired.members.is_empty()).then_some(desired));
        }
        self.require_writable()?;
        let active_set = store
            .semantic_pack_active_set()
            .map_err(|error| CatalogError::Integrity(error.to_string()))?;
        let desired = match active_set {
            Some(active_set) => active_set,
            None => SemanticPackActiveSet::from_members(&[])
                .map_err(|error| CatalogError::Integrity(error.to_string()))?,
        };
        self.validate_active_members(&desired.members, false, Some(scope_id))?;
        let mut leases = self.activation_leases(scope_id, &desired.members)?;
        self.write_activation_rows(scope_id, &desired, true)?;
        release_leases(&mut leases)?;
        Ok((!desired.members.is_empty()).then_some(desired))
    }

    fn validate_active_members(
        &self,
        members: &[SemanticPackActiveReference],
        allow_session: bool,
        existing_scope: Option<&str>,
    ) -> Result<(), CatalogError> {
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let session_packs = self
            .session_packs
            .lock()
            .expect("semantic-pack session mutex poisoned");
        for member in members {
            if let Some(source_kind) = durable_activation_kind(member.source_kind) {
                let exists: bool = connection
                    .query_row(
                        "SELECT EXISTS(
                           SELECT 1
                           FROM catalog_packs AS packs
                           JOIN catalog_sources AS sources
                             ON sources.manifest_digest = packs.manifest_digest
                           WHERE packs.manifest_digest = ?1
                             AND packs.state = 'verified'
                             AND sources.source_kind = ?2
                             AND sources.source_id = ?3
                           UNION ALL
                           SELECT 1
                           FROM catalog_activations AS activations
                           JOIN catalog_packs AS packs
                             ON packs.manifest_digest = activations.manifest_digest
                           WHERE activations.scope_id = ?4
                             AND activations.manifest_digest = ?1
                             AND activations.source_kind = ?2
                             AND activations.source_id = ?3
                             AND packs.state = 'verified'
                         )",
                        params![
                            &member.manifest_digest,
                            source_kind.as_str(),
                            &member.source_id,
                            existing_scope
                        ],
                        |row| row.get(0),
                    )
                    .map_err(|error| {
                        CatalogError::sqlite("validate durable pack activation", error)
                    })?;
                if !exists {
                    return Err(CatalogError::Unavailable);
                }
            } else {
                if !allow_session {
                    return Err(CatalogError::Integrity(
                        "persistent workspaces cannot activate session-only semantic packs"
                            .to_owned(),
                    ));
                }
                let expected_kind = session_activation_kind(member.source_kind)
                    .expect("non-durable activation kind must be session-scoped");
                if !session_packs.iter().any(|pack| {
                    pack.manifest.content_sha256 == member.manifest_digest
                        && pack.source.kind == expected_kind
                        && pack.source.source_id == member.source_id
                }) {
                    return Err(CatalogError::Unavailable);
                }
            }
        }
        Ok(())
    }

    fn replace_session_activations(
        &self,
        scope_id: &str,
        active_set: &SemanticPackActiveSet,
        store: &AnalyzerStore,
    ) {
        let session_members = active_set
            .members
            .iter()
            .filter(|member| durable_activation_kind(member.source_kind).is_none())
            .cloned()
            .collect::<Vec<_>>();
        let mut activations = self
            .session_activations
            .lock()
            .expect("semantic-pack session activation mutex poisoned");
        if session_members.is_empty() {
            activations.remove(scope_id);
        } else {
            let session_set = SemanticPackActiveSet::from_members(&session_members)
                .expect("validated session activations form a valid active set");
            activations.insert(
                scope_id.to_owned(),
                SessionActivation {
                    active_set: session_set,
                    owner: store.lifetime(),
                },
            );
        }
    }

    fn activation_leases(
        &self,
        scope_id: &str,
        members: &[SemanticPackActiveReference],
    ) -> Result<Vec<CatalogLease<'_>>, CatalogError> {
        let mut leases = Vec::new();
        for member in members {
            if durable_activation_kind(member.source_kind).is_some() {
                leases.push(self.lease(
                    &member.manifest_digest,
                    &format!("activation:{scope_id}"),
                    Duration::from_secs(300),
                )?);
            }
        }
        Ok(leases)
    }

    fn write_activation_rows(
        &self,
        scope_id: &str,
        active_set: &SemanticPackActiveSet,
        replace: bool,
    ) -> Result<(), CatalogError> {
        let now = crate::cache_db::now_unix_seconds();
        let mut connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| CatalogError::sqlite("begin activation update", error))?;
        for member in &active_set.members {
            let Some(source_kind) = durable_activation_kind(member.source_kind) else {
                continue;
            };
            let inserted = transaction
                .execute(
                    "INSERT INTO catalog_activations(
                       scope_id, active_set_digest, manifest_digest,
                       source_kind, source_id, activated_at
                     )
                     SELECT ?1, ?2, packs.manifest_digest, ?4, ?5, ?6
                     FROM catalog_packs AS packs
                     WHERE packs.manifest_digest = ?3
                       AND packs.state = 'verified'
                       AND (
                         EXISTS(
                           SELECT 1 FROM catalog_sources AS sources
                           WHERE sources.manifest_digest = packs.manifest_digest
                             AND sources.source_kind = ?4
                             AND sources.source_id = ?5
                         )
                         OR EXISTS(
                           SELECT 1 FROM catalog_activations AS active
                           WHERE active.scope_id = ?1
                             AND active.manifest_digest = packs.manifest_digest
                             AND active.source_kind = ?4
                             AND active.source_id = ?5
                         )
                       )
                     ON CONFLICT(scope_id, manifest_digest) DO UPDATE SET
                       active_set_digest = excluded.active_set_digest,
                       source_kind = excluded.source_kind,
                       source_id = excluded.source_id,
                       activated_at = excluded.activated_at",
                    params![
                        scope_id,
                        &active_set.active_set_digest,
                        &member.manifest_digest,
                        source_kind.as_str(),
                        &member.source_id,
                        now
                    ],
                )
                .map_err(|error| CatalogError::sqlite("publish activation", error))?;
            if inserted == 0 {
                return Err(CatalogError::Unavailable);
            }
        }
        if replace {
            transaction
                .execute(
                    "DELETE FROM catalog_activations
                     WHERE scope_id = ?1 AND active_set_digest <> ?2",
                    params![scope_id, &active_set.active_set_digest],
                )
                .map_err(|error| CatalogError::sqlite("replace activation scope", error))?;
        }
        transaction
            .commit()
            .map_err(|error| CatalogError::sqlite("commit activation update", error))
    }

    pub fn candidates(
        &self,
        query: &SemanticPackSelectorQuery,
    ) -> Result<Vec<CatalogCandidate>, CatalogError> {
        self.candidates_bounded_inner(query, usize::MAX, false)
    }

    /// Select candidates that explicitly bind at least one exact dependency
    /// coordinate carried by `query`.
    ///
    /// An unconstrained selector is useful for intrinsic, explicitly enabled
    /// language models, but it does not prove that the pack models a specific
    /// discovered package, module, or toolchain version. Dependency
    /// preparation must keep those two activation routes separate.
    pub fn dependency_candidates(
        &self,
        query: &SemanticPackSelectorQuery,
    ) -> Result<Vec<CatalogCandidate>, CatalogError> {
        debug_assert!(query_has_exact_coordinate(query));
        self.candidates_bounded_inner(query, usize::MAX, true)
    }

    /// Check an exact acquisition under a transaction that gives a satisfying
    /// candidate precedence over an absence receipt.
    pub fn acquisition_receipt_lookup(
        &self,
        request: &AcquisitionReceiptRequest,
        release: &AcquisitionReceiptRelease,
    ) -> Result<AcquisitionReceiptLookup, CatalogError> {
        self.require_writable()?;
        validate_acquisition_receipt_request(request)?;
        let request_digest = request.digest();
        let release_digest = release.digest()?;
        let mut connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| CatalogError::sqlite("begin acquisition receipt lookup", error))?;
        if acquisition_request_satisfied(
            &self.root,
            &transaction,
            &self.options.decode_limits,
            request,
        )? {
            transaction
                .commit()
                .map_err(|error| CatalogError::sqlite("commit satisfied receipt lookup", error))?;
            return Ok(AcquisitionReceiptLookup::Satisfied);
        }
        let mutation_epoch = semantic_mutation_epoch(&transaction)?;
        let receipt = transaction
            .query_row(
                "SELECT catalog_mutation_epoch, source_state_digest, source_count
                 FROM catalog_acquisition_absence_receipts
                 WHERE request_digest = ?1 AND release_digest = ?2
                   AND release_repository = ?3 AND release_tag = ?4
                   AND archive_name = ?5 AND archive_digest = ?6
                   AND bundle_schema_version = ?7
                   AND bundle_generator_name = ?8
                   AND bundle_generator_version = ?9
                   AND semantic_schema_version = ?10
                   AND generated_cache_version = ?11
                   AND client_epoch = ?12
                   AND catalog_schema_version = ?13",
                params![
                    request_digest,
                    release_digest,
                    release.repository,
                    release.tag,
                    release.archive_name,
                    release.archive_digest,
                    release.bundle_schema_version,
                    release.bundle_generator_name,
                    release.bundle_generator_version,
                    release.semantic_schema_version,
                    release.generated_cache_version,
                    release.client_epoch,
                    CATALOG_SCHEMA_VERSION,
                ],
                |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, u64>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| CatalogError::sqlite("read acquisition absence receipt", error))?;
        let valid = if let Some((receipt_epoch, source_state_digest, source_count)) = receipt {
            receipt_epoch == mutation_epoch
                && receipt_source_state_digest(
                    &self.root,
                    &transaction,
                    &self.options.decode_limits,
                    &request_digest,
                    &release_digest,
                    source_count,
                )?
                .is_some_and(|digest| digest == source_state_digest)
        } else {
            false
        };
        transaction
            .commit()
            .map_err(|error| CatalogError::sqlite("commit acquisition receipt lookup", error))?;
        Ok(if valid {
            AcquisitionReceiptLookup::KnownVerifiedAbsence
        } else {
            AcquisitionReceiptLookup::ReceiptMiss
        })
    }

    /// Record verified absence only after the caller has completely verified
    /// and installed the selected release. Every source proof is revalidated
    /// against the same catalog transaction before persistence.
    pub fn record_acquisition_absence(
        &self,
        request: &AcquisitionReceiptRequest,
        release: &AcquisitionReceiptRelease,
        sources: &[AcquisitionReceiptSource],
    ) -> Result<AcquisitionReceiptLookup, CatalogError> {
        self.require_writable()?;
        validate_acquisition_receipt_request(request)?;
        if sources.is_empty() {
            return Err(CatalogError::Integrity(
                "acquisition absence requires at least one verified installed source".to_owned(),
            ));
        }
        let mut sources = sources.to_vec();
        sources.sort_by(|left, right| {
            left.release_digest
                .cmp(&right.release_digest)
                .then_with(|| left.manifest_digest.cmp(&right.manifest_digest))
                .then_with(|| left.source.kind.as_str().cmp(right.source.kind.as_str()))
                .then_with(|| left.source.source_id.cmp(&right.source.source_id))
        });
        sources.dedup();
        let request_digest = request.digest();
        let release_digest = release.digest()?;
        let mut connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| CatalogError::sqlite("begin acquisition absence record", error))?;
        if acquisition_request_satisfied(
            &self.root,
            &transaction,
            &self.options.decode_limits,
            request,
        )? {
            transaction
                .commit()
                .map_err(|error| CatalogError::sqlite("commit satisfied absence record", error))?;
            return Ok(AcquisitionReceiptLookup::Satisfied);
        }
        for source in &sources {
            if source.release_digest != release_digest {
                return Err(CatalogError::Integrity(
                    "acquisition receipt source belongs to a different release".to_owned(),
                ));
            }
            let source_state = transaction
                .query_row(
                    "SELECT pack.state, pack.manifest_bytes
                     FROM catalog_sources AS source
                     JOIN catalog_packs AS pack
                       ON pack.manifest_digest = source.manifest_digest
                     WHERE source.manifest_digest = ?1
                       AND source.source_kind = ?2
                       AND source.source_id = ?3",
                    params![
                        source.manifest_digest,
                        source.source.kind.as_str(),
                        source.source.source_id,
                    ],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )
                .optional()
                .map_err(|error| {
                    CatalogError::sqlite("verify acquisition receipt source", error)
                })?;
            let Some((state, manifest_bytes)) = source_state else {
                return Err(CatalogError::Integrity(format!(
                    "acquisition receipt source is not verified: {:?}",
                    source
                )));
            };
            let manifest = self.decoded_manifest(&source.manifest_digest, &manifest_bytes)?;
            if state != "verified"
                || !manifest_shard_rows_present(
                    &self.root,
                    &transaction,
                    &source.manifest_digest,
                    &manifest,
                )?
            {
                return Err(CatalogError::Integrity(format!(
                    "acquisition receipt source is not fully verified: {:?}",
                    source
                )));
            }
        }
        let mutation_epoch = semantic_mutation_epoch(&transaction)?;
        let source_state_digest = acquisition_source_state_digest(&sources);
        let now = crate::cache_db::now_unix_seconds();
        transaction
            .execute(
                "INSERT INTO catalog_acquisition_absence_receipts(
                   request_digest, release_digest, release_repository, release_tag,
                   archive_name, archive_digest, bundle_schema_version,
                   bundle_generator_name, bundle_generator_version,
                   semantic_schema_version, generated_cache_version, client_epoch,
                   catalog_schema_version, catalog_mutation_epoch, source_state_digest,
                   source_count, created_at
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
                 ON CONFLICT(request_digest, release_digest) DO UPDATE SET
                   release_repository = excluded.release_repository,
                   release_tag = excluded.release_tag,
                   archive_name = excluded.archive_name,
                   archive_digest = excluded.archive_digest,
                   bundle_schema_version = excluded.bundle_schema_version,
                   bundle_generator_name = excluded.bundle_generator_name,
                   bundle_generator_version = excluded.bundle_generator_version,
                   semantic_schema_version = excluded.semantic_schema_version,
                   generated_cache_version = excluded.generated_cache_version,
                   client_epoch = excluded.client_epoch,
                   catalog_schema_version = excluded.catalog_schema_version,
                   catalog_mutation_epoch = excluded.catalog_mutation_epoch,
                   source_state_digest = excluded.source_state_digest,
                   source_count = excluded.source_count,
                   created_at = excluded.created_at",
                params![
                    request_digest,
                    release_digest,
                    release.repository,
                    release.tag,
                    release.archive_name,
                    release.archive_digest,
                    release.bundle_schema_version,
                    release.bundle_generator_name,
                    release.bundle_generator_version,
                    release.semantic_schema_version,
                    release.generated_cache_version,
                    release.client_epoch,
                    CATALOG_SCHEMA_VERSION,
                    mutation_epoch,
                    source_state_digest,
                    u64::try_from(sources.len()).unwrap_or(u64::MAX),
                    now,
                ],
            )
            .map_err(|error| CatalogError::sqlite("write acquisition absence receipt", error))?;
        transaction
            .execute(
                "DELETE FROM catalog_acquisition_absence_receipt_sources
                 WHERE request_digest = ?1 AND release_digest = ?2",
                params![request_digest, release_digest],
            )
            .map_err(|error| CatalogError::sqlite("replace acquisition receipt sources", error))?;
        for source in sources {
            transaction
                .execute(
                    "INSERT INTO catalog_acquisition_absence_receipt_sources(
                       request_digest, release_digest, manifest_digest, source_kind, source_id
                     ) VALUES(?1, ?2, ?3, ?4, ?5)",
                    params![
                        request_digest,
                        release_digest,
                        source.manifest_digest,
                        source.source.kind.as_str(),
                        source.source.source_id,
                    ],
                )
                .map_err(|error| CatalogError::sqlite("write acquisition receipt source", error))?;
        }
        transaction
            .commit()
            .map_err(|error| CatalogError::sqlite("commit acquisition absence receipt", error))?;
        Ok(AcquisitionReceiptLookup::KnownVerifiedAbsence)
    }

    pub fn candidates_bounded(
        &self,
        query: &SemanticPackSelectorQuery,
        max_rows: usize,
    ) -> Result<Vec<CatalogCandidate>, CatalogError> {
        self.candidates_bounded_inner(query, max_rows, false)
    }

    fn candidates_bounded_inner(
        &self,
        query: &SemanticPackSelectorQuery,
        max_rows: usize,
        require_exact_coordinate: bool,
    ) -> Result<Vec<CatalogCandidate>, CatalogError> {
        let durable_rows = self.durable_selector_rows(query, max_rows)?;

        let mut candidates = Vec::new();
        let rejected_manifests = self
            .rejected_manifests
            .lock()
            .expect("semantic-pack rejection mutex poisoned");
        let mut corrupt = Vec::new();
        let mut corrupt_digests = HashSet::new();
        for row in durable_rows {
            let DurableSelectorRow {
                manifest_digest,
                shard_id,
                descriptor_json,
                selector_json,
                source_kind,
                source_id,
            } = row;
            if rejected_manifests.contains(&manifest_digest)
                || corrupt_digests.contains(&manifest_digest)
            {
                continue;
            }
            let decoded = (|| -> Result<Option<CatalogCandidate>, CatalogError> {
                let manifest = self.stored_manifest(&manifest_digest)?;
                if !manifest_compatible(&manifest, query)? {
                    return Ok(None);
                }
                let selector: ActivationSelector = serde_json::from_slice(&selector_json)
                    .map_err(|error| CatalogError::Integrity(error.to_string()))?;
                if !selector_matches(&selector, query)? {
                    return Ok(None);
                }
                if require_exact_coordinate && !selector_binds_exact_coordinate(&selector, query) {
                    return Ok(None);
                }
                let descriptor: CompiledShardDescriptor = serde_json::from_slice(&descriptor_json)
                    .map_err(|error| CatalogError::Integrity(error.to_string()))?;
                if manifest
                    .shards
                    .iter()
                    .find(|expected| expected.shard_id == shard_id)
                    != Some(&descriptor)
                {
                    return Err(CatalogError::Integrity(format!(
                        "catalog descriptor does not match manifest shard {shard_id}"
                    )));
                }
                Ok(Some(CatalogCandidate {
                    manifest_digest: manifest_digest.clone(),
                    shard_id,
                    descriptor,
                    completeness: manifest.completeness,
                    source_kind: DurablePackSourceKind::parse(&source_kind)?.into(),
                    source_id,
                    location: CatalogCandidateLocation::Durable,
                }))
            })();
            match decoded {
                Ok(Some(candidate)) if !candidates.contains(&candidate) => {
                    candidates.push(candidate);
                }
                Ok(_) => {}
                Err(error) => {
                    corrupt_digests.insert(manifest_digest.clone());
                    corrupt.push((manifest_digest, error));
                }
            }
        }
        drop(rejected_manifests);
        for (manifest_digest, error) in corrupt {
            candidates.retain(|candidate| candidate.manifest_digest != manifest_digest);
            self.rejected_manifests
                .lock()
                .expect("semantic-pack rejection mutex poisoned")
                .insert(manifest_digest.clone());
            if self.mode == CatalogOpenMode::ReadWrite {
                self.quarantine(&manifest_digest, "candidate_metadata_failure", &error)?;
            }
        }

        let session_packs = self
            .session_packs
            .lock()
            .expect("semantic-pack session mutex poisoned");
        for (pack_ordinal, pack) in session_packs.iter().enumerate() {
            if candidates.len() >= max_rows {
                break;
            }
            if pack.manifest.language != query.language
                || pack.manifest.ecosystem != query.ecosystem
                || !manifest_compatible(&pack.manifest, query)?
            {
                continue;
            }
            for (shard_ordinal, shard) in pack.shards.iter().enumerate() {
                if candidates.len() >= max_rows {
                    break;
                }
                let mut matches = false;
                for selector in &shard.selectors {
                    if selector_matches(selector, query)?
                        && (!require_exact_coordinate
                            || selector_binds_exact_coordinate(selector, query))
                    {
                        matches = true;
                        break;
                    }
                }
                if !matches {
                    continue;
                }
                candidates.push(CatalogCandidate {
                    manifest_digest: pack.manifest.content_sha256.clone(),
                    shard_id: shard.descriptor.shard_id.clone(),
                    descriptor: shard.descriptor.clone(),
                    completeness: pack.manifest.completeness,
                    source_kind: pack.source.kind.into(),
                    source_id: pack.source.source_id.clone(),
                    location: CatalogCandidateLocation::Session {
                        pack_ordinal,
                        shard_ordinal,
                    },
                });
            }
        }
        candidates.sort_by(|left, right| {
            source_precedence(left.source_kind)
                .cmp(&source_precedence(right.source_kind))
                .then_with(|| left.manifest_digest.cmp(&right.manifest_digest))
                .then_with(|| left.shard_id.cmp(&right.shard_id))
                .then_with(|| left.source_id.cmp(&right.source_id))
        });
        candidates.dedup();
        if candidates.is_empty() {
            self.lookup_misses.fetch_add(1, Ordering::Relaxed);
        }
        Ok(candidates)
    }

    /// Name every pack that `candidates` rejected for `query` only because an
    /// exact version requirement did not accept the queried version.
    ///
    /// Candidate selection deliberately drops such a pack in silence: a wrong
    /// version must never activate. Attribution needs the opposite: a
    /// workspace on JDK 17 with only a JDK 21 pack installed must hear "the
    /// pack requires =21.0.2, the workspace has 17.0.10", not a bare
    /// "no pack found". A pack rejected for a non-version reason (name,
    /// target, configuration, artifact digest, Bifrost compatibility) is not
    /// reported here.
    pub fn version_near_misses(
        &self,
        query: &SemanticPackSelectorQuery,
    ) -> Result<Vec<SemanticPackVersionNearMiss>, CatalogError> {
        let rows = self.durable_selector_rows(query, usize::MAX)?;
        let mut misses: Vec<SemanticPackVersionNearMiss> = Vec::new();
        {
            let rejected_manifests = self
                .rejected_manifests
                .lock()
                .expect("semantic-pack rejection mutex poisoned");
            for row in rows {
                if rejected_manifests.contains(&row.manifest_digest)
                    || misses
                        .iter()
                        .any(|miss| miss.manifest_digest == row.manifest_digest)
                {
                    continue;
                }
                let manifest = self.stored_manifest(&row.manifest_digest)?;
                let selector: ActivationSelector = serde_json::from_slice(&row.selector_json)
                    .map_err(|error| CatalogError::Integrity(error.to_string()))?;
                if let Some(miss) =
                    version_near_miss(&manifest, std::slice::from_ref(&selector), query)?
                {
                    misses.push(miss);
                }
            }
        }
        let session_packs = self
            .session_packs
            .lock()
            .expect("semantic-pack session mutex poisoned");
        for pack in session_packs.iter() {
            if pack.manifest.language != query.language
                || pack.manifest.ecosystem != query.ecosystem
                || misses
                    .iter()
                    .any(|miss| miss.manifest_digest == pack.manifest.content_sha256)
            {
                continue;
            }
            let selectors = pack
                .shards
                .iter()
                .flat_map(|shard| shard.selectors.iter().cloned())
                .collect::<Vec<_>>();
            if let Some(miss) = version_near_miss(&pack.manifest, &selectors, query)? {
                misses.push(miss);
            }
        }
        drop(session_packs);
        misses.sort();
        Ok(misses)
    }

    fn durable_selector_rows(
        &self,
        query: &SemanticPackSelectorQuery,
        max_rows: usize,
    ) -> Result<Vec<DurableSelectorRow>, CatalogError> {
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        self.sql_statements.fetch_add(1, Ordering::Relaxed);
        durable_selector_rows_on(&connection, query, max_rows)
    }

    pub fn load(&self, candidate: &CatalogCandidate) -> Result<LoadedCatalogShard, CatalogMiss> {
        match self.load_inner(candidate) {
            Ok(loaded) => {
                self.lookup_hits.fetch_add(1, Ordering::Relaxed);
                Ok(loaded)
            }
            Err(error) => {
                self.lookup_misses.fetch_add(1, Ordering::Relaxed);
                if matches!(error, CatalogError::Unavailable) {
                    return Err(CatalogMiss::NotFound);
                }
                let mut reason = error.to_string();
                if matches!(candidate.location, CatalogCandidateLocation::Durable) {
                    self.rejected_manifests
                        .lock()
                        .expect("semantic-pack rejection mutex poisoned")
                        .insert(candidate.manifest_digest.clone());
                }
                if matches!(candidate.location, CatalogCandidateLocation::Durable)
                    && self.mode == CatalogOpenMode::ReadWrite
                    && let Err(quarantine_error) =
                        self.quarantine(&candidate.manifest_digest, "load_failure", &error)
                {
                    reason.push_str("; failed to record quarantine: ");
                    reason.push_str(&quarantine_error.to_string());
                }
                Err(CatalogMiss::Quarantined { reason })
            }
        }
    }

    pub fn accounting(&self) -> Result<CatalogAccounting, CatalogError> {
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let installed_stored_bytes = connection
            .query_row(
                "SELECT COALESCE(SUM(stored_size), 0)
                 FROM catalog_objects
                 WHERE stored_digest IN (
                   SELECT DISTINCT stored_digest FROM catalog_pack_shards
                 )",
                [],
                |row| row.get::<_, u64>(0),
            )
            .map_err(|error| CatalogError::sqlite("account installed bytes", error))?;
        let mut active_object_sizes = HashMap::new();
        let mut object_statement = connection
            .prepare(
                "SELECT DISTINCT objects.stored_digest, objects.stored_size
                 FROM catalog_objects AS objects
                 JOIN catalog_pack_shards AS shards
                   ON shards.stored_digest = objects.stored_digest
                 JOIN catalog_activations AS active
                   ON active.manifest_digest = shards.manifest_digest",
            )
            .map_err(|error| CatalogError::sqlite("prepare active byte accounting", error))?;
        let object_rows = object_statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
            })
            .map_err(|error| CatalogError::sqlite("query active byte accounting", error))?;
        for row in object_rows {
            let (digest, stored_size) =
                row.map_err(|error| CatalogError::sqlite("read active byte accounting", error))?;
            active_object_sizes.insert(digest, stored_size);
        }
        let mut active_shards = HashSet::new();
        let mut shard_statement = connection
            .prepare(
                "SELECT DISTINCT shards.manifest_digest, shards.shard_id
                 FROM catalog_pack_shards AS shards
                 JOIN catalog_activations AS active
                   ON active.manifest_digest = shards.manifest_digest",
            )
            .map_err(|error| CatalogError::sqlite("prepare active shard accounting", error))?;
        let shard_rows = shard_statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|error| CatalogError::sqlite("query active shard accounting", error))?;
        for row in shard_rows {
            active_shards.insert(
                row.map_err(|error| CatalogError::sqlite("read active shard accounting", error))?,
            );
        }
        let mut activation_statement = connection
            .prepare(
                "SELECT source_kind, source_id, COUNT(*)
                 FROM catalog_activations
                 GROUP BY source_kind, source_id
                 ORDER BY source_kind, source_id",
            )
            .map_err(|error| CatalogError::sqlite("prepare activation accounting", error))?;
        let activation_rows = activation_statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u64>(2)?,
                ))
            })
            .map_err(|error| CatalogError::sqlite("query activation accounting", error))?;
        let mut activation_counts = HashMap::new();
        for row in activation_rows {
            let (source_kind, source_id, pack_count) =
                row.map_err(|error| CatalogError::sqlite("read activation accounting", error))?;
            activation_counts.insert(
                (CatalogPackSourceKind::parse(&source_kind)?, source_id),
                pack_count,
            );
        }
        let mut session_activations = self
            .session_activations
            .lock()
            .expect("semantic-pack session activation mutex poisoned");
        session_activations.retain(|_, activation| activation.owner.upgrade().is_some());
        let mut active_session_digests = HashSet::new();
        for activation in session_activations.values() {
            for member in &activation.active_set.members {
                let source_kind = activation_catalog_kind(member.source_kind);
                *activation_counts
                    .entry((source_kind, member.source_id.clone()))
                    .or_insert(0) += 1;
                active_session_digests.insert(member.manifest_digest.clone());
            }
        }
        let session_packs = self
            .session_packs
            .lock()
            .expect("semantic-pack session mutex poisoned");
        for pack in session_packs.iter() {
            if !active_session_digests.contains(&pack.manifest.content_sha256) {
                continue;
            }
            for shard in &pack.shards {
                active_shards.insert((
                    pack.manifest.content_sha256.clone(),
                    shard.descriptor.shard_id.clone(),
                ));
                active_object_sizes
                    .entry(shard.descriptor.stored_sha256.clone())
                    .or_insert(shard.descriptor.stored_size);
            }
        }
        let active_stored_bytes =
            active_object_sizes
                .values()
                .try_fold(0_u64, |total, stored_size| {
                    total.checked_add(*stored_size).ok_or_else(|| {
                        CatalogError::Integrity("active byte accounting overflowed".to_owned())
                    })
                })?;
        let active_shard_count = u64::try_from(active_shards.len())
            .map_err(|_| CatalogError::Integrity("active shard count exceeds u64".to_owned()))?;
        let mut activations = activation_counts
            .into_iter()
            .map(
                |((source_kind, source_id), pack_count)| ActivationSourceCount {
                    source_kind,
                    source_id,
                    pack_count,
                },
            )
            .collect::<Vec<_>>();
        activations.sort_by(|left, right| {
            source_precedence(left.source_kind)
                .cmp(&source_precedence(right.source_kind))
                .then_with(|| left.source_id.cmp(&right.source_id))
        });
        Ok(CatalogAccounting {
            installed_stored_bytes,
            active_stored_bytes,
            object_count: count(&connection, "catalog_objects")?,
            logical_shard_count: count(&connection, "catalog_pack_shards")?,
            active_shard_count,
            source_count: count(&connection, "catalog_sources")?,
            lookup_hits: self.lookup_hits.load(Ordering::Relaxed),
            lookup_misses: self.lookup_misses.load(Ordering::Relaxed),
            quarantined_pack_count: connection
                .query_row(
                    "SELECT COUNT(*) FROM catalog_packs WHERE state = 'quarantined'",
                    [],
                    |row| row.get(0),
                )
                .map_err(|error| CatalogError::sqlite("account quarantined packs", error))?,
            activations,
        })
    }

    fn load_inner(&self, candidate: &CatalogCandidate) -> Result<LoadedCatalogShard, CatalogError> {
        match candidate.location {
            CatalogCandidateLocation::Durable if self.mode == CatalogOpenMode::ReadWrite => {
                let lease = self.lease(
                    &candidate.manifest_digest,
                    "verified-load",
                    Duration::from_secs(60),
                )?;
                let loaded = self.load_durable(candidate);
                let released = lease.release();
                match (loaded, released) {
                    (Ok(loaded), Ok(())) => Ok(loaded),
                    (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
                    (Err(error), Err(release_error)) => Err(CatalogError::Integrity(format!(
                        "{error}; failed to release load lease: {release_error}"
                    ))),
                }
            }
            CatalogCandidateLocation::Durable => self.load_durable(candidate),
            CatalogCandidateLocation::Session {
                pack_ordinal,
                shard_ordinal,
            } => self.load_session(candidate, pack_ordinal, shard_ordinal),
        }
    }

    fn load_durable(
        &self,
        candidate: &CatalogCandidate,
    ) -> Result<LoadedCatalogShard, CatalogError> {
        // The manifest comes from the memo, not from this statement: a pack
        // with 44 shards used to ship its multi-megabyte manifest bytes out of
        // SQLite once per loaded shard (#3101).
        let manifest = self.stored_manifest(&candidate.manifest_digest)?;
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        self.sql_statements.fetch_add(1, Ordering::Relaxed);
        let row = connection
            .query_row(
                "SELECT o.relative_path, o.stored_size
                 FROM catalog_packs AS p
                 JOIN catalog_pack_shards AS ps
                   ON ps.manifest_digest = p.manifest_digest
                 JOIN catalog_objects AS o
                   ON o.stored_digest = ps.stored_digest
                 WHERE p.state = 'verified'
                   AND p.manifest_digest = ?1
                   AND ps.shard_id = ?2
                   AND ps.stored_digest = ?3",
                params![
                    &candidate.manifest_digest,
                    &candidate.shard_id,
                    &candidate.descriptor.stored_sha256
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?)),
            )
            .optional()
            .map_err(|error| CatalogError::sqlite("load candidate location", error))?
            .ok_or(CatalogError::Unavailable)?;
        self.object_reads.fetch_add(1, Ordering::Relaxed);
        let bytes = storage::read(
            &self.root,
            &row.0,
            &candidate.descriptor.stored_sha256,
            row.1,
        )?;
        let shard = self.decode_stored_shard(&manifest, &candidate.descriptor, &bytes)?;
        if self.mode == CatalogOpenMode::ReadWrite {
            connection
                .execute(
                    "UPDATE catalog_packs SET last_used_at = ?2 WHERE manifest_digest = ?1",
                    params![
                        &candidate.manifest_digest,
                        crate::cache_db::now_unix_seconds()
                    ],
                )
                .map_err(|error| CatalogError::sqlite("touch loaded pack", error))?;
        }
        Ok(LoadedCatalogShard {
            manifest,
            shard,
            source_kind: candidate.source_kind,
            source_id: candidate.source_id.clone(),
        })
    }

    fn load_session(
        &self,
        candidate: &CatalogCandidate,
        pack_ordinal: usize,
        shard_ordinal: usize,
    ) -> Result<LoadedCatalogShard, CatalogError> {
        let session_packs = self
            .session_packs
            .lock()
            .expect("semantic-pack session mutex poisoned");
        let pack = session_packs
            .get(pack_ordinal)
            .ok_or(CatalogError::Unavailable)?;
        let shard = pack
            .shards
            .get(shard_ordinal)
            .ok_or(CatalogError::Unavailable)?;
        if pack.manifest.content_sha256 != candidate.manifest_digest
            || shard.descriptor != candidate.descriptor
        {
            return Err(CatalogError::Unavailable);
        }
        let decoded = self.decode_stored_shard(&pack.manifest, &shard.descriptor, &shard.bytes)?;
        Ok(LoadedCatalogShard {
            manifest: Arc::clone(&pack.manifest),
            shard: decoded,
            source_kind: candidate.source_kind,
            source_id: candidate.source_id.clone(),
        })
    }

    pub fn garbage_collect(
        &self,
        options: &CatalogGcOptions,
    ) -> Result<CatalogGcOutcome, CatalogError> {
        self.require_writable()?;
        let now = crate::cache_db::now_unix_seconds();
        let minimum_age = i64::try_from(options.minimum_age.as_secs()).map_err(|_| {
            CatalogError::Integrity("catalog GC minimum age exceeds i64".to_owned())
        })?;
        let cutoff = now
            .checked_sub(minimum_age)
            .ok_or_else(|| CatalogError::Integrity("catalog GC cutoff underflowed".to_owned()))?;
        let max_packs = i64::try_from(options.max_packs)
            .map_err(|_| CatalogError::Integrity("catalog GC limit exceeds i64".to_owned()))?;
        let max_objects = i64::try_from(options.max_objects).map_err(|_| {
            CatalogError::Integrity("catalog GC object limit exceeds i64".to_owned())
        })?;

        let (pack_digests, object_candidates, pruned_expired_leases) = {
            let mut connection = self
                .connection
                .lock()
                .expect("semantic-pack catalog connection mutex poisoned");
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|error| CatalogError::sqlite("begin catalog GC", error))?;
            let pruned_expired_leases = transaction
                .execute("DELETE FROM catalog_leases WHERE expires_at <= ?1", [now])
                .map_err(|error| CatalogError::sqlite("prune expired pack leases", error))?;
            transaction
                .execute(
                    "DELETE FROM catalog_install_object_reservations
                     WHERE expires_at <= ?1",
                    [now],
                )
                .map_err(|error| CatalogError::sqlite("prune install reservations", error))?;
            let pack_digests = {
                let mut statement = transaction
                    .prepare(
                        "SELECT packs.manifest_digest
                         FROM catalog_packs AS packs
                         WHERE COALESCE(packs.last_used_at, packs.installed_at) <= ?1
                           AND NOT EXISTS(
                             SELECT 1 FROM catalog_sources AS sources
                             WHERE sources.manifest_digest = packs.manifest_digest
                               AND sources.source_kind <> 'generated'
                           )
                           AND NOT EXISTS(
                             SELECT 1 FROM catalog_pins AS pins
                             WHERE pins.manifest_digest = packs.manifest_digest
                           )
                           AND NOT EXISTS(
                             SELECT 1 FROM catalog_activations AS active
                             WHERE active.manifest_digest = packs.manifest_digest
                           )
                           AND NOT EXISTS(
                             SELECT 1 FROM catalog_leases AS leases
                             WHERE leases.manifest_digest = packs.manifest_digest
                               AND leases.expires_at > ?2
                           )
                         ORDER BY COALESCE(packs.last_used_at, packs.installed_at),
                                  packs.manifest_digest
                         LIMIT ?3",
                    )
                    .map_err(|error| CatalogError::sqlite("prepare unreachable packs", error))?;
                let rows = statement
                    .query_map(params![cutoff, now, max_packs], |row| {
                        row.get::<_, String>(0)
                    })
                    .map_err(|error| CatalogError::sqlite("query unreachable packs", error))?;
                let mut digests = Vec::new();
                for row in rows {
                    digests.push(
                        row.map_err(|error| CatalogError::sqlite("read unreachable pack", error))?,
                    );
                }
                digests
            };
            for digest in &pack_digests {
                transaction
                    .execute(
                        "DELETE FROM catalog_packs WHERE manifest_digest = ?1",
                        [digest],
                    )
                    .map_err(|error| CatalogError::sqlite("delete unreachable pack", error))?;
            }
            let object_candidates = {
                let mut statement = transaction
                    .prepare(
                        "SELECT objects.stored_digest, objects.relative_path, objects.stored_size
                         FROM catalog_objects AS objects
                         WHERE objects.verified_at <= ?1
                           AND NOT EXISTS(
                             SELECT 1 FROM catalog_pack_shards AS shards
                             WHERE shards.stored_digest = objects.stored_digest
                           )
                           AND NOT EXISTS(
                             SELECT 1 FROM catalog_install_object_reservations AS reservations
                             WHERE reservations.stored_digest = objects.stored_digest
                               AND reservations.expires_at > ?2
                           )
                         ORDER BY objects.verified_at, objects.stored_digest
                         LIMIT ?3",
                    )
                    .map_err(|error| CatalogError::sqlite("prepare orphan objects", error))?;
                let rows = statement
                    .query_map(params![cutoff, now, max_objects], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, u64>(2)?,
                        ))
                    })
                    .map_err(|error| CatalogError::sqlite("query orphan objects", error))?;
                let mut objects = Vec::new();
                for row in rows {
                    objects.push(
                        row.map_err(|error| CatalogError::sqlite("read orphan object", error))?,
                    );
                }
                objects
            };
            transaction
                .commit()
                .map_err(|error| CatalogError::sqlite("commit catalog GC metadata", error))?;
            (pack_digests, object_candidates, pruned_expired_leases)
        };

        let mut pruned_objects = 0;
        let mut reclaimed_bytes = 0_u64;
        for (digest, relative_path, stored_size) in object_candidates {
            let mut connection = self
                .connection
                .lock()
                .expect("semantic-pack catalog connection mutex poisoned");
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|error| CatalogError::sqlite("begin object GC recheck", error))?;
            let protected: bool = transaction
                .query_row(
                    "SELECT EXISTS(
                       SELECT 1 FROM catalog_pack_shards
                       WHERE stored_digest = ?1
                       UNION ALL
                       SELECT 1 FROM catalog_install_object_reservations
                       WHERE stored_digest = ?1 AND expires_at > ?2
                     )",
                    params![&digest, crate::cache_db::now_unix_seconds()],
                    |row| row.get(0),
                )
                .map_err(|error| CatalogError::sqlite("recheck object reachability", error))?;
            if protected {
                transaction.commit().map_err(|error| {
                    CatalogError::sqlite("finish protected object check", error)
                })?;
                continue;
            }
            let removed_file = storage::delete(&self.root, &relative_path, &digest)?;
            let deleted = transaction
                .execute(
                    "DELETE FROM catalog_objects
                     WHERE stored_digest = ?1
                       AND NOT EXISTS(
                         SELECT 1 FROM catalog_pack_shards
                         WHERE stored_digest = ?1
                       )",
                    [&digest],
                )
                .map_err(|error| CatalogError::sqlite("delete orphan object row", error))?;
            transaction
                .commit()
                .map_err(|error| CatalogError::sqlite("commit object GC", error))?;
            if deleted != 0 {
                pruned_objects += 1;
                if removed_file {
                    reclaimed_bytes =
                        reclaimed_bytes.checked_add(stored_size).ok_or_else(|| {
                            CatalogError::Integrity(
                                "catalog GC reclaimed bytes overflowed".to_owned(),
                            )
                        })?;
                }
            }
        }
        let outcome = CatalogGcOutcome {
            pruned_packs: pack_digests.len(),
            pruned_objects,
            reclaimed_bytes,
            pruned_expired_leases,
        };
        if outcome.pruned_packs != 0 {
            self.record_mutation();
        }
        Ok(outcome)
    }

    fn quarantine(
        &self,
        manifest_digest: &str,
        reason: &str,
        error: &CatalogError,
    ) -> Result<(), CatalogError> {
        let mut connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| CatalogError::sqlite("begin pack quarantine", source))?;
        transaction
            .execute(
                "UPDATE catalog_packs SET state = 'quarantined' WHERE manifest_digest = ?1",
                [manifest_digest],
            )
            .map_err(|source| CatalogError::sqlite("quarantine pack", source))?;
        transaction
            .execute(
                "DELETE FROM catalog_activations WHERE manifest_digest = ?1",
                [manifest_digest],
            )
            .map_err(|source| CatalogError::sqlite("clear quarantined activations", source))?;
        transaction
            .execute(
                "INSERT INTO catalog_quarantine(
                   manifest_digest, reason, detail, detected_at
                 ) VALUES(?1, ?2, ?3, ?4)",
                params![
                    manifest_digest,
                    reason,
                    error.to_string(),
                    crate::cache_db::now_unix_seconds()
                ],
            )
            .map_err(|source| CatalogError::sqlite("record quarantine", source))?;
        transaction
            .commit()
            .map_err(|source| CatalogError::sqlite("commit pack quarantine", source))?;
        self.record_mutation();
        Ok(())
    }

    pub(crate) fn cache_identity(&self) -> Result<SemanticPackCatalogCacheIdentity, CatalogError> {
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let sqlite_data_version = connection
            .query_row("PRAGMA data_version", [], |row| row.get(0))
            .map_err(|error| CatalogError::sqlite("read catalog data version", error))?;
        Ok(SemanticPackCatalogCacheIdentity {
            instance_identity: self.instance_identity,
            mutation_generation: self.mutation_generation.load(Ordering::Relaxed),
            sqlite_data_version,
        })
    }

    fn record_mutation(&self) {
        self.mutation_generation.fetch_add(1, Ordering::Relaxed);
    }

    fn require_writable(&self) -> Result<(), CatalogError> {
        if self.mode == CatalogOpenMode::ReadWrite {
            Ok(())
        } else {
            Err(CatalogError::ReadOnly)
        }
    }
}

fn durable_selector_rows_on(
    connection: &Connection,
    query: &SemanticPackSelectorQuery,
    max_rows: usize,
) -> Result<Vec<DurableSelectorRow>, CatalogError> {
    let selector_source = if query.package.is_some() {
        "SELECT * FROM catalog_selectors INDEXED BY catalog_selectors_package
         WHERE package_name IS NULL
         UNION ALL
         SELECT * FROM catalog_selectors INDEXED BY catalog_selectors_package
         WHERE package_name = ?3"
    } else if query.module.is_some() {
        "SELECT * FROM catalog_selectors INDEXED BY catalog_selectors_module
         WHERE module_name IS NULL
         UNION ALL
         SELECT * FROM catalog_selectors INDEXED BY catalog_selectors_module
         WHERE module_name = ?4"
    } else if query.toolchain.is_some() {
        "SELECT * FROM catalog_selectors INDEXED BY catalog_selectors_toolchain
         WHERE toolchain_name IS NULL
         UNION ALL
         SELECT * FROM catalog_selectors INDEXED BY catalog_selectors_toolchain
         WHERE toolchain_name = ?5"
    } else if query.artifact_sha256.is_some() {
        "SELECT * FROM catalog_selectors INDEXED BY catalog_selectors_artifact
         WHERE artifact_sha256 IS NULL
         UNION ALL
         SELECT * FROM catalog_selectors INDEXED BY catalog_selectors_artifact
         WHERE artifact_sha256 = ?8"
    } else {
        "SELECT * FROM catalog_selectors"
    };
    let candidate_sql = format!(
        "SELECT p.manifest_digest, ps.shard_id,
                ps.descriptor_json, s.selector_json,
                source.source_kind, source.source_id
         FROM catalog_packs AS p
         JOIN catalog_pack_shards AS ps
           ON ps.manifest_digest = p.manifest_digest
         JOIN ({selector_source}) AS s
           ON s.manifest_digest = ps.manifest_digest
          AND s.shard_id = ps.shard_id
         JOIN catalog_sources AS source
           ON source.manifest_digest = p.manifest_digest
         WHERE p.state = 'verified'
           AND p.language = ?1
           AND p.ecosystem = ?2
           AND (?3 IS NULL OR s.package_name IS NULL OR s.package_name = ?3)
           AND (?4 IS NULL OR s.module_name IS NULL OR s.module_name = ?4)
           AND (?5 IS NULL OR s.toolchain_name IS NULL OR s.toolchain_name = ?5)
           AND (
             ?6 IS NULL
             OR NOT EXISTS(
               SELECT 1 FROM catalog_selector_targets AS targets
               WHERE targets.manifest_digest = s.manifest_digest
                 AND targets.shard_id = s.shard_id
                 AND targets.selector_ordinal = s.selector_ordinal
             )
             OR EXISTS(
               SELECT 1 FROM catalog_selector_targets AS targets
               WHERE targets.manifest_digest = s.manifest_digest
                 AND targets.shard_id = s.shard_id
                 AND targets.selector_ordinal = s.selector_ordinal
                 AND targets.target = ?6
             )
           )
           AND (
             ?7 IS NULL
             OR NOT EXISTS(
               SELECT 1 FROM catalog_selector_configurations AS configurations
               WHERE configurations.manifest_digest = s.manifest_digest
                 AND configurations.shard_id = s.shard_id
                 AND configurations.selector_ordinal = s.selector_ordinal
             )
             OR EXISTS(
               SELECT 1 FROM catalog_selector_configurations AS configurations
               WHERE configurations.manifest_digest = s.manifest_digest
                 AND configurations.shard_id = s.shard_id
                 AND configurations.selector_ordinal = s.selector_ordinal
                 AND configurations.configuration = ?7
             )
           )
           AND (
             ?8 IS NULL OR s.artifact_sha256 IS NULL OR s.artifact_sha256 = ?8
           )
         ORDER BY p.manifest_digest, ps.shard_id,
                  source.source_kind, source.source_id, s.selector_ordinal
         LIMIT ?9"
    );
    let mut statement = connection
        .prepare(&candidate_sql)
        .map_err(|error| CatalogError::sqlite("prepare candidate lookup", error))?;
    let rows = statement
        .query_map(
            params![
                &query.language,
                &query.ecosystem,
                query
                    .package
                    .as_ref()
                    .map(|coordinate| coordinate.name.as_str()),
                query
                    .module
                    .as_ref()
                    .map(|coordinate| coordinate.name.as_str()),
                query
                    .toolchain
                    .as_ref()
                    .map(|coordinate| coordinate.name.as_str()),
                query.target.as_deref(),
                query.configuration.as_deref(),
                query.artifact_sha256.as_deref(),
                i64::try_from(max_rows).unwrap_or(i64::MAX)
            ],
            |row| {
                Ok(DurableSelectorRow {
                    manifest_digest: row.get::<_, String>(0)?,
                    shard_id: row.get::<_, String>(1)?,
                    descriptor_json: row.get::<_, Vec<u8>>(2)?,
                    selector_json: row.get::<_, Vec<u8>>(3)?,
                    source_kind: row.get::<_, String>(4)?,
                    source_id: row.get::<_, String>(5)?,
                })
            },
        )
        .map_err(|error| CatalogError::sqlite("query candidates", error))?;
    let mut durable_rows = Vec::new();
    for row in rows {
        durable_rows.push(row.map_err(|error| CatalogError::sqlite("read candidate row", error))?);
    }
    Ok(durable_rows)
}

fn validate_pack(
    pack: &CompiledSemanticModelPack,
    limits: &DecodeLimits,
) -> Result<ValidatedPack, CatalogError> {
    let manifest = decode_manifest(&pack.manifest_bytes, limits)
        .map_err(|error| CatalogError::Artifact(error.to_string()))?;
    if manifest != pack.manifest {
        return Err(CatalogError::Integrity(
            "compiled pack manifest value does not match its bytes".to_owned(),
        ));
    }
    if pack.shards.len() != manifest.shards.len() {
        return Err(CatalogError::Integrity(
            "compiled pack does not contain every manifest shard".to_owned(),
        ));
    }
    // One inventory validation covers every shard below; validating per shard
    // re-walked every record id of the manifest once per shard (#3101).
    validate_manifest_inventory(&manifest)
        .map_err(|error| CatalogError::Artifact(error.to_string()))?;

    let mut shards = Vec::with_capacity(pack.shards.len());
    let mut matched = HashSet::with_capacity(pack.shards.len());
    for descriptor in &manifest.shards {
        let mut artifacts = pack
            .shards
            .iter()
            .filter(|artifact| artifact.descriptor == *descriptor);
        let artifact = artifacts.next().ok_or_else(|| {
            CatalogError::Integrity(format!(
                "compiled pack is missing shard {}",
                descriptor.shard_id
            ))
        })?;
        if artifacts.next().is_some() || !matched.insert(descriptor.shard_id.clone()) {
            return Err(CatalogError::Integrity(format!(
                "compiled pack contains duplicate shard {}",
                descriptor.shard_id
            )));
        }
        let decoded =
            decode_validated_shard_for_manifest(&manifest, descriptor, &artifact.bytes, limits)
                .map_err(|error| CatalogError::Artifact(error.to_string()))?;
        shards.push(ValidatedShard {
            descriptor: descriptor.clone(),
            bytes: artifact.bytes.clone(),
            selectors: decoded.activation.clone(),
        });
    }
    Ok(ValidatedPack { manifest, shards })
}

fn semantic_mutation_epoch(connection: &Connection) -> Result<u64, CatalogError> {
    connection
        .query_row(
            "SELECT mutation_epoch FROM catalog_semantic_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| CatalogError::sqlite("read semantic catalog mutation epoch", error))
}

fn acquisition_request_satisfied(
    root: &Path,
    connection: &Connection,
    limits: &DecodeLimits,
    request: &AcquisitionReceiptRequest,
) -> Result<bool, CatalogError> {
    match request {
        AcquisitionReceiptRequest::GeneratedProduction(key) => {
            let row = connection
                .query_row(
                    "SELECT gp.input_digest, gp.producer_name, gp.producer_version,
                            gp.schema_version, gp.manifest_digest, p.manifest_bytes
                     FROM catalog_generated_productions AS gp
                     JOIN catalog_packs AS p ON p.manifest_digest = gp.manifest_digest
                     JOIN catalog_sources AS source
                       ON source.manifest_digest = gp.manifest_digest
                      AND source.source_kind = 'generated'
                      AND source.source_id = 'production:' || gp.production_digest
                     WHERE gp.production_digest = ?1 AND p.state = 'verified'",
                    [key.production_digest()],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, u32>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, Vec<u8>>(5)?,
                        ))
                    },
                )
                .optional()
                .map_err(|error| {
                    CatalogError::sqlite("lookup receipt generated production", error)
                })?;
            let Some((input, producer, producer_version, schema, digest, manifest_bytes)) = row
            else {
                return Ok(false);
            };
            let stored_key =
                match GeneratedProductionKey::new(input, producer, producer_version, schema) {
                    Ok(key) => key,
                    Err(CatalogError::Integrity(_)) => return Ok(false),
                    Err(error) => return Err(error),
                };
            let manifest = match decode_manifest(&manifest_bytes, limits) {
                Ok(manifest) => manifest,
                Err(_) => return Ok(false),
            };
            Ok(stored_key == *key
                && manifest.content_sha256 == digest
                && manifest_shard_rows_present(root, connection, &digest, &manifest)?
                && validate_generated_pack_identity(key, &manifest).is_ok())
        }
        AcquisitionReceiptRequest::DeclaredPack(query) => {
            assert!(query_has_exact_coordinate(query));
            let mut manifests = HashMap::<String, Option<Arc<CompiledPackManifest>>>::new();
            for row in durable_selector_rows_on(connection, query, usize::MAX)? {
                let manifest = match manifests
                    .entry(row.manifest_digest.clone())
                    .or_insert_with(|| {
                        stored_manifest_bytes_on(connection, &row.manifest_digest)
                            .ok()
                            .flatten()
                            .and_then(|bytes| decode_manifest(&bytes, limits).ok())
                            .map(Arc::new)
                    })
                    .as_ref()
                {
                    Some(manifest) => Arc::clone(manifest),
                    None => continue,
                };
                if manifest.content_sha256 != row.manifest_digest {
                    continue;
                }
                let selector: ActivationSelector = match serde_json::from_slice(&row.selector_json)
                {
                    Ok(selector) => selector,
                    Err(_) => continue,
                };
                let descriptor: CompiledShardDescriptor =
                    match serde_json::from_slice(&row.descriptor_json) {
                        Ok(descriptor) => descriptor,
                        Err(_) => continue,
                    };
                if manifest_shard_rows_present(root, connection, &row.manifest_digest, &manifest)?
                    && matches!(manifest_compatible(&manifest, query), Ok(true))
                    && matches!(selector_matches(&selector, query), Ok(true))
                    && selector_binds_exact_coordinate(&selector, query)
                    && manifest.shards.iter().any(|expected| {
                        expected.shard_id == row.shard_id && *expected == descriptor
                    })
                {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

/// Read one stored manifest's bytes through a caller-held connection.
///
/// The catalog's own readers go through its decoded-manifest memo instead; this
/// is for the receipt proof, which runs on a catalog transaction.
fn stored_manifest_bytes_on(
    connection: &Connection,
    manifest_digest: &str,
) -> Result<Option<Vec<u8>>, CatalogError> {
    connection
        .query_row(
            "SELECT manifest_bytes FROM catalog_packs WHERE manifest_digest = ?1",
            [manifest_digest],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(|error| CatalogError::sqlite("read stored manifest", error))
}

fn manifest_shard_rows_present(
    root: &Path,
    connection: &Connection,
    manifest_digest: &str,
    manifest: &CompiledPackManifest,
) -> Result<bool, CatalogError> {
    let mut statement = connection
        .prepare(
            "SELECT shard.shard_id, shard.stored_digest,
                    object.relative_path, object.stored_size
             FROM catalog_pack_shards AS shard
             JOIN catalog_objects AS object ON object.stored_digest = shard.stored_digest
             WHERE shard.manifest_digest = ?1",
        )
        .map_err(|error| CatalogError::sqlite("prepare receipt shard proof", error))?;
    let rows = statement
        .query_map([manifest_digest], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, u64>(3)?,
            ))
        })
        .map_err(|error| CatalogError::sqlite("query receipt shard proof", error))?;
    let mut stored = HashMap::with_capacity(manifest.shards.len());
    for row in rows {
        let (shard_id, stored_digest, relative_path, stored_size) =
            row.map_err(|error| CatalogError::sqlite("read receipt shard proof", error))?;
        if !receipt_object_is_valid(root, Path::new(&relative_path), &stored_digest, stored_size)? {
            return Ok(false);
        }
        stored.insert(shard_id, stored_digest);
    }
    Ok(stored.len() == manifest.shards.len()
        && manifest
            .shards
            .iter()
            .all(|descriptor| stored.get(&descriptor.shard_id) == Some(&descriptor.stored_sha256)))
}

fn validate_acquisition_receipt_request(
    request: &AcquisitionReceiptRequest,
) -> Result<(), CatalogError> {
    if let AcquisitionReceiptRequest::DeclaredPack(query) = request
        && !query_has_exact_coordinate(query)
    {
        return Err(CatalogError::Integrity(
            "declared-pack acquisition receipts require an exact dependency coordinate".to_owned(),
        ));
    }
    Ok(())
}

fn acquisition_source_state_digest(sources: &[AcquisitionReceiptSource]) -> String {
    let mut hasher = CanonicalHasher::new(ACQUISITION_SOURCE_STATE_DOMAIN);
    hasher.sequence("sources", sources, |hasher, source| {
        hasher.field("release_digest", source.release_digest.as_bytes());
        hasher.field("manifest_digest", source.manifest_digest.as_bytes());
        hasher.field("source_kind", source.source.kind.as_str().as_bytes());
        hasher.field("source_id", source.source.source_id.as_bytes());
    });
    lower_hex_string(&hasher.finish())
}

fn receipt_source_state_digest(
    root: &Path,
    connection: &Connection,
    limits: &DecodeLimits,
    request_digest: &str,
    release_digest: &str,
    expected_count: u64,
) -> Result<Option<String>, CatalogError> {
    let mut statement = connection
        .prepare(
            "SELECT receipt.manifest_digest, receipt.source_kind, receipt.source_id,
                    pack.state, pack.manifest_bytes
             FROM catalog_acquisition_absence_receipt_sources AS receipt
             LEFT JOIN catalog_sources AS source
               ON source.manifest_digest = receipt.manifest_digest
              AND source.source_kind = receipt.source_kind
              AND source.source_id = receipt.source_id
             LEFT JOIN catalog_packs AS pack ON pack.manifest_digest = source.manifest_digest
             WHERE receipt.request_digest = ?1 AND receipt.release_digest = ?2
             ORDER BY receipt.manifest_digest, receipt.source_kind, receipt.source_id",
        )
        .map_err(|error| CatalogError::sqlite("prepare acquisition receipt source proof", error))?;
    let rows = statement
        .query_map(params![request_digest, release_digest], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<Vec<u8>>>(4)?,
            ))
        })
        .map_err(|error| CatalogError::sqlite("query acquisition receipt source proof", error))?;
    let mut sources = Vec::new();
    for row in rows {
        let (manifest_digest, source_kind, source_id, state, manifest_bytes) =
            row.map_err(|error| {
                CatalogError::sqlite("read acquisition receipt source proof", error)
            })?;
        if state.as_deref() != Some("verified") {
            return Ok(None);
        }
        let Some(manifest_bytes) = manifest_bytes else {
            return Ok(None);
        };
        let manifest = match decode_manifest(&manifest_bytes, limits) {
            Ok(manifest) => manifest,
            Err(_) => return Ok(None),
        };
        if manifest.content_sha256 != manifest_digest
            || !manifest_shard_rows_present(root, connection, &manifest_digest, &manifest)?
        {
            return Ok(None);
        }
        sources.push(AcquisitionReceiptSource {
            release_digest: release_digest.to_owned(),
            manifest_digest,
            source: DurablePackSource {
                kind: DurablePackSourceKind::parse(&source_kind)?,
                source_id,
            },
        });
    }
    if u64::try_from(sources.len()).unwrap_or(u64::MAX) != expected_count {
        return Ok(None);
    }
    Ok(Some(acquisition_source_state_digest(&sources)))
}

fn receipt_object_is_valid(
    root: &Path,
    relative_path: &Path,
    digest: &str,
    stored_size: u64,
) -> Result<bool, CatalogError> {
    match storage::verify_existing(root, relative_path, digest, stored_size) {
        Ok(()) => Ok(true),
        Err(CatalogError::Integrity(_)) => Ok(false),
        Err(CatalogError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

fn validate_extraction_accounting(
    extraction: &PackExtractionAccounting,
) -> Result<(), CatalogError> {
    if extraction.error_reject_count > extraction.reject_count {
        return Err(CatalogError::Integrity(
            "error reject count exceeds total reject count".to_owned(),
        ));
    }
    if extraction
        .gaps
        .len()
        .saturating_add(extraction.source_entries.len()) as u64
        > extraction.reject_count
    {
        return Err(CatalogError::Integrity(
            "accounted extraction rejects exceed total reject count".to_owned(),
        ));
    }
    if extraction
        .gaps
        .iter()
        .any(|gap| gap.declaration.is_empty() || gap.reason.is_empty())
    {
        return Err(CatalogError::Integrity(
            "pack extraction gaps require a declaration and reason".to_owned(),
        ));
    }
    if extraction.source_entries.iter().any(|entry| {
        entry.source_entry.is_empty()
            || !is_canonical_relative_path(&entry.source_entry)
            || entry.reason.is_empty()
    }) {
        return Err(CatalogError::Integrity(
            "pack extraction source entries require a canonical relative source entry and reason"
                .to_owned(),
        ));
    }
    Ok(())
}

fn reconcile_storage(root: &Path, connection: &mut Connection) -> Result<(), CatalogError> {
    const RECONCILIATION_LIMIT: usize = 4_096;
    storage::cleanup_stale_staging(root, Duration::from_secs(60 * 60), RECONCILIATION_LIMIT)?;
    let mut removed_objects = 0;
    storage::visit_object_files(root, |relative_path, digest| {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| CatalogError::sqlite("begin catalog object reconciliation", error))?;
        let protected: bool = transaction
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM catalog_objects WHERE stored_digest = ?1
                   UNION ALL
                   SELECT 1 FROM catalog_install_object_reservations
                   WHERE stored_digest = ?1 AND expires_at > ?2
                 )",
                params![&digest, crate::cache_db::now_unix_seconds()],
                |row| row.get(0),
            )
            .map_err(|error| CatalogError::sqlite("reconcile catalog object", error))?;
        if !protected {
            storage::delete(
                root,
                relative_path.to_str().ok_or_else(|| {
                    CatalogError::Integrity("catalog object path is not valid Unicode".to_owned())
                })?,
                &digest,
            )?;
            removed_objects += 1;
        }
        transaction
            .commit()
            .map_err(|error| CatalogError::sqlite("commit catalog object reconciliation", error))?;
        Ok(removed_objects < RECONCILIATION_LIMIT)
    })
}

fn insert_manifest(
    transaction: &Transaction<'_>,
    manifest: &CompiledPackManifest,
    bytes: &[u8],
    now: i64,
) -> Result<bool, CatalogError> {
    let existed: bool = transaction
        .query_row(
            "SELECT EXISTS(
               SELECT 1 FROM catalog_packs WHERE manifest_digest = ?1
             )",
            [&manifest.content_sha256],
            |row| row.get(0),
        )
        .map_err(|error| CatalogError::sqlite("check existing pack manifest", error))?;
    transaction
        .execute(
            "INSERT INTO catalog_packs(
               manifest_digest, semantic_digest, manifest_bytes, schema_version,
               pack_id, pack_version, producer_name, producer_version,
               language, ecosystem, bifrost_compatibility, provenance_json,
               license, completeness, state, installed_at, verified_at
             ) VALUES(
               ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
               ?14, 'verified', ?15, ?15
             )
             ON CONFLICT(manifest_digest) DO UPDATE SET
               semantic_digest = excluded.semantic_digest,
               manifest_bytes = excluded.manifest_bytes,
               schema_version = excluded.schema_version,
               pack_id = excluded.pack_id,
               pack_version = excluded.pack_version,
               producer_name = excluded.producer_name,
               producer_version = excluded.producer_version,
               language = excluded.language,
               ecosystem = excluded.ecosystem,
               bifrost_compatibility = excluded.bifrost_compatibility,
               provenance_json = excluded.provenance_json,
               license = excluded.license,
               completeness = excluded.completeness,
               state = 'verified',
               verified_at = excluded.verified_at",
            params![
                &manifest.content_sha256,
                &manifest.semantic_sha256,
                bytes,
                manifest.schema_version,
                &manifest.pack_id,
                &manifest.version,
                &manifest.producer.name,
                &manifest.producer.version,
                &manifest.language,
                &manifest.ecosystem,
                &manifest.compatibility.bifrost,
                serde_json::to_vec(&manifest.provenance)
                    .map_err(|error| CatalogError::Integrity(error.to_string()))?,
                &manifest.license,
                completeness_name(&manifest.completeness),
                now
            ],
        )
        .map_err(|error| CatalogError::sqlite("insert pack manifest", error))?;
    Ok(!existed)
}

fn insert_source(
    transaction: &Transaction<'_>,
    manifest_digest: &str,
    source: &DurablePackSource,
    now: i64,
) -> Result<(), CatalogError> {
    transaction
        .execute(
            "INSERT OR IGNORE INTO catalog_sources(
               manifest_digest, source_kind, source_id, installed_at
             ) VALUES(?1, ?2, ?3, ?4)",
            params![
                manifest_digest,
                source.kind.as_str(),
                &source.source_id,
                now
            ],
        )
        .map_err(|error| CatalogError::sqlite("insert pack source", error))?;
    Ok(())
}

fn insert_extraction_accounting(
    transaction: &Transaction<'_>,
    manifest_digest: &str,
    extraction: &PackExtractionAccounting,
) -> Result<(), CatalogError> {
    transaction
        .execute(
            "INSERT INTO catalog_pack_extraction_accounting(
               manifest_digest, reject_count, suppressed_reject_count, error_reject_count
             ) VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(manifest_digest) DO UPDATE SET
               reject_count = excluded.reject_count,
               suppressed_reject_count = excluded.suppressed_reject_count,
               error_reject_count = excluded.error_reject_count",
            params![
                manifest_digest,
                extraction.reject_count,
                extraction.suppressed_reject_count,
                extraction.error_reject_count,
            ],
        )
        .map_err(|error| CatalogError::sqlite("insert pack extraction accounting", error))?;
    transaction
        .execute(
            "DELETE FROM catalog_pack_extraction_gaps WHERE manifest_digest = ?1",
            [manifest_digest],
        )
        .map_err(|error| CatalogError::sqlite("replace pack extraction gaps", error))?;
    for (ordinal, gap) in extraction.gaps.iter().enumerate() {
        transaction
            .execute(
                "INSERT INTO catalog_pack_extraction_gaps(
                   manifest_digest, ordinal, declaration, reason
                 ) VALUES(?1, ?2, ?3, ?4)",
                params![manifest_digest, ordinal, &gap.declaration, &gap.reason],
            )
            .map_err(|error| CatalogError::sqlite("insert pack extraction gap", error))?;
    }
    transaction
        .execute(
            "DELETE FROM catalog_pack_extraction_source_entries WHERE manifest_digest = ?1",
            [manifest_digest],
        )
        .map_err(|error| CatalogError::sqlite("replace pack extraction source entries", error))?;
    for (ordinal, entry) in extraction.source_entries.iter().enumerate() {
        transaction
            .execute(
                "INSERT INTO catalog_pack_extraction_source_entries(
                   manifest_digest, ordinal, source_entry, reason
                 ) VALUES(?1, ?2, ?3, ?4)",
                params![manifest_digest, ordinal, &entry.source_entry, &entry.reason],
            )
            .map_err(|error| CatalogError::sqlite("insert pack extraction source entry", error))?;
    }
    Ok(())
}

fn generated_production_digest(
    input_digest: &str,
    producer_name: &str,
    producer_version: &str,
    schema_version: u32,
) -> String {
    generated_production_digest_for_cache_version(
        input_digest,
        producer_name,
        producer_version,
        schema_version,
        GENERATED_PRODUCTION_CACHE_VERSION,
    )
}

fn generated_production_digest_for_cache_version(
    input_digest: &str,
    producer_name: &str,
    producer_version: &str,
    schema_version: u32,
    cache_version: u32,
) -> String {
    let mut hasher = CanonicalHasher::new(GENERATED_PRODUCTION_DOMAIN);
    hasher.field("input_digest", input_digest.as_bytes());
    hasher.field("producer_name", producer_name.as_bytes());
    hasher.field("producer_version", producer_version.as_bytes());
    hasher.field("schema_version", &schema_version.to_be_bytes());
    hasher.field("cache_version", &cache_version.to_be_bytes());
    lower_hex_string(&hasher.finish())
}

fn validate_generated_pack_identity(
    key: &GeneratedProductionKey,
    manifest: &CompiledPackManifest,
) -> Result<(), CatalogError> {
    if manifest.producer.name != key.producer_name
        || manifest.producer.version != key.producer_version
        || manifest.schema_version != key.schema_version
    {
        return Err(CatalogError::Integrity(
            "generated-production producer or schema does not match compiled pack".to_owned(),
        ));
    }
    Ok(())
}

fn insert_generated_production(
    transaction: &Transaction<'_>,
    key: &GeneratedProductionKey,
    manifest: &CompiledPackManifest,
    now: i64,
) -> Result<(), CatalogError> {
    validate_generated_pack_identity(key, manifest)?;
    transaction
        .execute(
            "INSERT OR IGNORE INTO catalog_generated_productions(
               production_digest, input_digest, producer_name, producer_version,
               schema_version, manifest_digest, created_at
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                &key.production_digest,
                &key.input_digest,
                &key.producer_name,
                &key.producer_version,
                key.schema_version,
                &manifest.content_sha256,
                now,
            ],
        )
        .map_err(|error| CatalogError::sqlite("insert generated production", error))?;
    let stored_manifest: String = transaction
        .query_row(
            "SELECT manifest_digest
             FROM catalog_generated_productions
             WHERE production_digest = ?1",
            [&key.production_digest],
            |row| row.get(0),
        )
        .map_err(|error| CatalogError::sqlite("verify generated production", error))?;
    if stored_manifest != manifest.content_sha256 {
        return Err(CatalogError::Integrity(format!(
            "generated-production key {} is already bound to a different manifest",
            key.production_digest
        )));
    }
    Ok(())
}

fn insert_object(
    transaction: &Transaction<'_>,
    descriptor: &CompiledShardDescriptor,
    relative_path: &Path,
    now: i64,
) -> Result<(), CatalogError> {
    transaction
        .execute(
            "INSERT INTO catalog_objects(
               stored_digest, relative_path, stored_size, raw_size, encoding, verified_at
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(stored_digest) DO UPDATE SET
               relative_path = excluded.relative_path,
               stored_size = excluded.stored_size,
               raw_size = excluded.raw_size,
               encoding = excluded.encoding,
               verified_at = excluded.verified_at",
            params![
                &descriptor.stored_sha256,
                relative_path.to_string_lossy(),
                descriptor.stored_size,
                descriptor.raw_size,
                encoding_name(descriptor.encoding),
                now
            ],
        )
        .map_err(|error| CatalogError::sqlite("insert catalog object", error))?;
    Ok(())
}

fn insert_shard(
    transaction: &Transaction<'_>,
    manifest_digest: &str,
    ordinal: usize,
    descriptor: &CompiledShardDescriptor,
) -> Result<(), CatalogError> {
    transaction
        .execute(
            "INSERT OR REPLACE INTO catalog_pack_shards(
               manifest_digest, ordinal, shard_id, payload_kind, stored_digest,
               content_digest, semantic_digest, record_count, descriptor_json
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                manifest_digest,
                ordinal,
                &descriptor.shard_id,
                payload_kind_name(descriptor.payload_kind),
                &descriptor.stored_sha256,
                &descriptor.content_sha256,
                &descriptor.semantic_sha256,
                descriptor.record_count,
                serde_json::to_vec(descriptor)
                    .map_err(|error| CatalogError::Integrity(error.to_string()))?
            ],
        )
        .map_err(|error| CatalogError::sqlite("insert catalog shard", error))?;
    Ok(())
}

fn insert_selectors(
    transaction: &Transaction<'_>,
    manifest_digest: &str,
    shard_id: &str,
    selectors: &[ActivationSelector],
) -> Result<(), CatalogError> {
    transaction
        .execute(
            "DELETE FROM catalog_selectors
             WHERE manifest_digest = ?1 AND shard_id = ?2",
            params![manifest_digest, shard_id],
        )
        .map_err(|error| CatalogError::sqlite("replace catalog selectors", error))?;
    for (ordinal, selector) in selectors.iter().enumerate() {
        transaction
            .execute(
                "INSERT INTO catalog_selectors(
                   manifest_digest, shard_id, selector_ordinal,
                   package_name, package_version, module_name, module_version,
                   toolchain_name, toolchain_version, artifact_sha256, selector_json
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    manifest_digest,
                    shard_id,
                    ordinal,
                    selector.package.as_ref().map(|value| value.name.as_str()),
                    selector
                        .package
                        .as_ref()
                        .and_then(|value| value.version.as_deref()),
                    selector.module.as_ref().map(|value| value.name.as_str()),
                    selector
                        .module
                        .as_ref()
                        .and_then(|value| value.version.as_deref()),
                    selector.toolchain.as_ref().map(|value| value.name.as_str()),
                    selector
                        .toolchain
                        .as_ref()
                        .and_then(|value| value.version.as_deref()),
                    selector.artifact_sha256.as_deref(),
                    serde_json::to_vec(selector)
                        .map_err(|error| CatalogError::Integrity(error.to_string()))?
                ],
            )
            .map_err(|error| CatalogError::sqlite("insert catalog selector", error))?;
        for target in &selector.targets {
            transaction
                .execute(
                    "INSERT INTO catalog_selector_targets(
                       manifest_digest, shard_id, selector_ordinal, target
                     ) VALUES(?1, ?2, ?3, ?4)",
                    params![manifest_digest, shard_id, ordinal, target],
                )
                .map_err(|error| CatalogError::sqlite("insert selector target", error))?;
        }
        for configuration in &selector.configurations {
            transaction
                .execute(
                    "INSERT INTO catalog_selector_configurations(
                       manifest_digest, shard_id, selector_ordinal, configuration
                     ) VALUES(?1, ?2, ?3, ?4)",
                    params![manifest_digest, shard_id, ordinal, configuration],
                )
                .map_err(|error| CatalogError::sqlite("insert selector configuration", error))?;
        }
    }
    Ok(())
}

fn insert_routing_keys(
    transaction: &Transaction<'_>,
    manifest_digest: &str,
    shard_id: &str,
    routing_keys: &[String],
) -> Result<(), CatalogError> {
    transaction
        .execute(
            "DELETE FROM catalog_routing_keys
             WHERE manifest_digest = ?1 AND shard_id = ?2",
            params![manifest_digest, shard_id],
        )
        .map_err(|error| CatalogError::sqlite("replace routing keys", error))?;
    for routing_key in routing_keys {
        transaction
            .execute(
                "INSERT INTO catalog_routing_keys(
                   manifest_digest, shard_id, routing_key
                 ) VALUES(?1, ?2, ?3)",
                params![manifest_digest, shard_id, routing_key],
            )
            .map_err(|error| CatalogError::sqlite("insert routing key", error))?;
    }
    Ok(())
}

fn manifest_compatible(
    manifest: &CompiledPackManifest,
    query: &SemanticPackSelectorQuery,
) -> Result<bool, CatalogError> {
    let requirement = VersionReq::parse(&manifest.compatibility.bifrost)
        .map_err(|error| CatalogError::Integrity(error.to_string()))?;
    if !requirement.matches(&query.bifrost_version) {
        return Ok(false);
    }
    let Some(toolchain) = &query.toolchain else {
        return Ok(true);
    };
    for constraint in &manifest.compatibility.toolchains {
        if constraint.name != toolchain.name {
            continue;
        }
        let Some(version) = &toolchain.version else {
            return Ok(false);
        };
        let requirement = VersionReq::parse(&constraint.requirement)
            .map_err(|error| CatalogError::Integrity(error.to_string()))?;
        if !requirement.matches(version) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn selector_matches(
    selector: &ActivationSelector,
    query: &SemanticPackSelectorQuery,
) -> Result<bool, CatalogError> {
    if !coordinate_matches(selector.package.as_ref(), query.package.as_ref())?
        || !coordinate_matches(selector.module.as_ref(), query.module.as_ref())?
        || !coordinate_matches(selector.toolchain.as_ref(), query.toolchain.as_ref())?
    {
        return Ok(false);
    }
    if let Some(target) = &query.target
        && !selector.targets.is_empty()
        && !selector.targets.contains(target)
    {
        return Ok(false);
    }
    if let Some(configuration) = &query.configuration
        && !selector.configurations.is_empty()
        && !selector.configurations.contains(configuration)
    {
        return Ok(false);
    }
    if let (Some(expected), Some(actual)) = (&query.artifact_sha256, &selector.artifact_sha256)
        && actual != expected
    {
        return Ok(false);
    }
    Ok(true)
}

fn query_has_exact_coordinate(query: &SemanticPackSelectorQuery) -> bool {
    [&query.package, &query.module, &query.toolchain]
        .into_iter()
        .flatten()
        .any(|coordinate| coordinate.version.is_some())
}

fn selector_binds_exact_coordinate(
    selector: &ActivationSelector,
    query: &SemanticPackSelectorQuery,
) -> bool {
    [
        (&selector.package, &query.package),
        (&selector.module, &query.module),
        (&selector.toolchain, &query.toolchain),
    ]
    .into_iter()
    .any(|(selector, query)| {
        matches!(
            (selector, query),
            (Some(selector), Some(query))
                if selector.name == query.name
                    && selector.version.is_some()
                    && query.version.is_some()
        )
    })
}

fn coordinate_matches(
    selector: Option<&NameSelector>,
    query: Option<&CatalogCoordinate>,
) -> Result<bool, CatalogError> {
    match (selector, query) {
        (None, _) | (_, None) => Ok(true),
        (Some(selector), Some(query)) if selector.name != query.name => Ok(false),
        (Some(selector), Some(query)) => match (&selector.version, &query.version) {
            (None, _) => Ok(true),
            (Some(_), None) => Ok(false),
            (Some(requirement), Some(version)) => VersionReq::parse(requirement)
                .map(|requirement| requirement.matches(version))
                .map_err(|error| CatalogError::Integrity(error.to_string())),
        },
    }
}

/// Classify one pack as a version near miss for `query`: every non-version
/// predicate accepts the query, and an exact version requirement rejects it.
/// A pack rejected for a non-version reason is not a near miss and returns
/// `None`.
fn version_near_miss(
    manifest: &CompiledPackManifest,
    selectors: &[ActivationSelector],
    query: &SemanticPackSelectorQuery,
) -> Result<Option<SemanticPackVersionNearMiss>, CatalogError> {
    let bifrost = VersionReq::parse(&manifest.compatibility.bifrost)
        .map_err(|error| CatalogError::Integrity(error.to_string()))?;
    if !bifrost.matches(&query.bifrost_version) {
        return Ok(None);
    }
    if let Some(toolchain) = &query.toolchain {
        for constraint in &manifest.compatibility.toolchains {
            if constraint.name != toolchain.name {
                continue;
            }
            let requirement = VersionReq::parse(&constraint.requirement)
                .map_err(|error| CatalogError::Integrity(error.to_string()))?;
            let satisfied = toolchain
                .version
                .as_ref()
                .is_some_and(|version| requirement.matches(version));
            if !satisfied {
                return Ok(Some(near_miss(
                    manifest,
                    format!("toolchain {}", constraint.name),
                    toolchain.version.as_ref(),
                    &constraint.requirement,
                )));
            }
        }
    }
    for selector in selectors {
        if !coordinate_names_match(selector.package.as_ref(), query.package.as_ref())
            || !coordinate_names_match(selector.module.as_ref(), query.module.as_ref())
            || !coordinate_names_match(selector.toolchain.as_ref(), query.toolchain.as_ref())
        {
            continue;
        }
        if let Some(target) = &query.target
            && !selector.targets.is_empty()
            && !selector.targets.contains(target)
        {
            continue;
        }
        if let Some(configuration) = &query.configuration
            && !selector.configurations.is_empty()
            && !selector.configurations.contains(configuration)
        {
            continue;
        }
        if let (Some(expected), Some(actual)) = (&query.artifact_sha256, &selector.artifact_sha256)
            && actual != expected
        {
            continue;
        }
        for (axis, coordinate_selector, coordinate_query) in [
            ("package", selector.package.as_ref(), query.package.as_ref()),
            ("module", selector.module.as_ref(), query.module.as_ref()),
            (
                "toolchain",
                selector.toolchain.as_ref(),
                query.toolchain.as_ref(),
            ),
        ] {
            let (Some(coordinate_selector), Some(coordinate_query)) =
                (coordinate_selector, coordinate_query)
            else {
                continue;
            };
            let Some(requirement_source) = &coordinate_selector.version else {
                continue;
            };
            let requirement = VersionReq::parse(requirement_source)
                .map_err(|error| CatalogError::Integrity(error.to_string()))?;
            let satisfied = coordinate_query
                .version
                .as_ref()
                .is_some_and(|version| requirement.matches(version));
            if !satisfied {
                return Ok(Some(near_miss(
                    manifest,
                    format!("{axis} {}", coordinate_selector.name),
                    coordinate_query.version.as_ref(),
                    requirement_source,
                )));
            }
        }
    }
    Ok(None)
}

fn near_miss(
    manifest: &CompiledPackManifest,
    coordinate: String,
    installed: Option<&Version>,
    required: &str,
) -> SemanticPackVersionNearMiss {
    SemanticPackVersionNearMiss {
        pack_id: manifest.pack_id.clone(),
        pack_version: manifest.version.clone(),
        manifest_digest: manifest.content_sha256.clone(),
        coordinate,
        installed: installed.map(Version::to_string),
        required: required.to_owned(),
    }
}

/// The name half of `coordinate_matches`: whether the selector could apply to
/// the queried coordinate at some version.
fn coordinate_names_match(
    selector: Option<&NameSelector>,
    query: Option<&CatalogCoordinate>,
) -> bool {
    match (selector, query) {
        (None, _) | (_, None) => true,
        (Some(selector), Some(query)) => selector.name == query.name,
    }
}

fn count(connection: &Connection, table: &str) -> Result<u64, CatalogError> {
    assert!(matches!(
        table,
        "catalog_objects" | "catalog_pack_shards" | "catalog_sources"
    ));
    connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .map_err(|error| CatalogError::sqlite("count catalog rows", error))
}

fn source_precedence(kind: CatalogPackSourceKind) -> u8 {
    match kind {
        CatalogPackSourceKind::Embedded => 0,
        CatalogPackSourceKind::PreShipped => 1,
        CatalogPackSourceKind::Installed => 2,
        CatalogPackSourceKind::Generated => 3,
        CatalogPackSourceKind::WorkspaceProduced => 4,
        CatalogPackSourceKind::EphemeralWorkspace => 5,
    }
}

fn durable_activation_kind(
    kind: SemanticPackActivationSourceKind,
) -> Option<DurablePackSourceKind> {
    match kind {
        SemanticPackActivationSourceKind::Installed => Some(DurablePackSourceKind::Installed),
        SemanticPackActivationSourceKind::Generated => Some(DurablePackSourceKind::Generated),
        SemanticPackActivationSourceKind::PreShipped => Some(DurablePackSourceKind::PreShipped),
        SemanticPackActivationSourceKind::WorkspaceProduced => {
            Some(DurablePackSourceKind::WorkspaceProduced)
        }
        SemanticPackActivationSourceKind::Embedded
        | SemanticPackActivationSourceKind::EphemeralWorkspace => None,
    }
}

fn session_activation_kind(
    kind: SemanticPackActivationSourceKind,
) -> Option<SessionPackSourceKind> {
    match kind {
        SemanticPackActivationSourceKind::Embedded => Some(SessionPackSourceKind::Embedded),
        SemanticPackActivationSourceKind::EphemeralWorkspace => {
            Some(SessionPackSourceKind::EphemeralWorkspace)
        }
        SemanticPackActivationSourceKind::Installed
        | SemanticPackActivationSourceKind::Generated
        | SemanticPackActivationSourceKind::PreShipped
        | SemanticPackActivationSourceKind::WorkspaceProduced => None,
    }
}

fn activation_catalog_kind(kind: SemanticPackActivationSourceKind) -> CatalogPackSourceKind {
    match kind {
        SemanticPackActivationSourceKind::Installed => CatalogPackSourceKind::Installed,
        SemanticPackActivationSourceKind::Generated => CatalogPackSourceKind::Generated,
        SemanticPackActivationSourceKind::PreShipped => CatalogPackSourceKind::PreShipped,
        SemanticPackActivationSourceKind::WorkspaceProduced => {
            CatalogPackSourceKind::WorkspaceProduced
        }
        SemanticPackActivationSourceKind::Embedded => CatalogPackSourceKind::Embedded,
        SemanticPackActivationSourceKind::EphemeralWorkspace => {
            CatalogPackSourceKind::EphemeralWorkspace
        }
    }
}

fn lease_expiry(ttl: Duration) -> Result<i64, CatalogError> {
    if ttl.is_zero() {
        return Err(CatalogError::Integrity(
            "semantic-pack lease TTL must be positive".to_owned(),
        ));
    }
    let seconds = i64::try_from(ttl.as_secs())
        .map_err(|_| CatalogError::Integrity("semantic-pack lease TTL exceeds i64".to_owned()))?;
    let seconds = seconds
        .checked_add(i64::from(ttl.subsec_nanos() != 0))
        .ok_or_else(|| CatalogError::Integrity("semantic-pack lease TTL overflowed".to_owned()))?;
    crate::cache_db::now_unix_seconds()
        .checked_add(seconds)
        .ok_or_else(|| CatalogError::Integrity("semantic-pack lease expiry overflowed".to_owned()))
}

fn release_leases(leases: &mut Vec<CatalogLease<'_>>) -> Result<(), CatalogError> {
    let mut first_error = None;
    while let Some(lease) = leases.pop() {
        if let Err(error) = lease.release()
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn encoding_name(encoding: ArtifactEncoding) -> &'static str {
    match encoding {
        ArtifactEncoding::Raw => "raw",
        ArtifactEncoding::Deflate => "deflate",
    }
}

fn payload_kind_name(kind: PayloadKind) -> &'static str {
    match kind {
        PayloadKind::DeclarationFacts => "declaration_facts",
        PayloadKind::GeneratorRules => "generator_rules",
        PayloadKind::ProcedureSummaries => "procedure_summaries",
    }
}

fn completeness_name(completeness: &super::Completeness) -> &'static str {
    match completeness {
        super::Completeness::Complete => "complete",
        super::Completeness::Partial => "partial",
    }
}

#[cfg(test)]
mod generated_production_cache_version_tests {
    use std::ffi::OsString;
    use std::path::Path;

    use super::{
        CATALOG_SCHEMA_VERSION, default_semantic_pack_catalog_root_with_override,
        generated_production_digest_for_cache_version, verify_recorded_generated_production_digest,
    };

    #[test]
    fn cache_version_separates_generated_production_identity() {
        let input = "a".repeat(64);
        let first = generated_production_digest_for_cache_version(
            &input,
            "fixture-producer",
            "1.0.0",
            1,
            1,
        );
        let second = generated_production_digest_for_cache_version(
            &input,
            "fixture-producer",
            "1.0.0",
            1,
            2,
        );

        assert_ne!(first, second);
    }

    #[test]
    fn recorded_cache_version_verifies_identity_without_current_cache_epoch() {
        let input = "a".repeat(64);
        let recorded = generated_production_digest_for_cache_version(
            &input,
            "fixture-producer",
            "1.0.0",
            1,
            8,
        );
        assert!(
            verify_recorded_generated_production_digest(
                &recorded,
                &input,
                "fixture-producer",
                "1.0.0",
                1,
                8,
            )
            .unwrap()
        );
        assert!(
            !verify_recorded_generated_production_digest(
                &recorded,
                &input,
                "fixture-producer",
                "1.0.0",
                1,
                9,
            )
            .unwrap()
        );
    }

    #[test]
    fn explicit_cache_root_shares_generated_productions_across_workspaces() {
        let cache_root = OsString::from("shared-semantic-packs");
        let first = default_semantic_pack_catalog_root_with_override(
            Path::new("workspace-a"),
            Some(cache_root.clone()),
        );
        let second = default_semantic_pack_catalog_root_with_override(
            Path::new("workspace-b"),
            Some(cache_root),
        );

        assert_eq!(first, second);
        assert_eq!(
            first,
            Path::new("shared-semantic-packs")
                .join(format!("semantic-pack-catalog.v{CATALOG_SCHEMA_VERSION}"))
        );
    }
}

#[cfg(test)]
mod acquisition_receipt_tests {
    use std::fs;

    use semver::Version;
    use tempfile::TempDir;

    use super::{
        AcquisitionReceiptRequest, CatalogCoordinate, GeneratedProductionKey,
        SemanticPackSelectorQuery, lower_hex_string, receipt_object_is_valid,
    };

    fn generated_key() -> GeneratedProductionKey {
        GeneratedProductionKey::new(
            "a".repeat(64),
            "fixture-producer".to_owned(),
            "1.0.0".to_owned(),
            3,
        )
        .unwrap()
    }

    fn declared_query() -> SemanticPackSelectorQuery {
        SemanticPackSelectorQuery {
            language: "java".to_owned(),
            ecosystem: "maven".to_owned(),
            package: Some(CatalogCoordinate {
                name: "com.acme:widget".to_owned(),
                version: Some(Version::parse("1.0.0").unwrap()),
            }),
            module: None,
            toolchain: None,
            target: None,
            configuration: None,
            artifact_sha256: None,
            bifrost_version: Version::parse("0.8.17").unwrap(),
        }
    }

    #[test]
    fn receipt_request_digest_binds_kind_coordinate_and_version() {
        let generated = AcquisitionReceiptRequest::generated(&generated_key()).digest();
        let declared = AcquisitionReceiptRequest::declared(&declared_query()).digest();
        assert_ne!(generated, declared);

        let mut changed = declared_query();
        changed.package.as_mut().unwrap().version = Some(Version::parse("1.1.0").unwrap());
        assert_ne!(
            declared,
            AcquisitionReceiptRequest::declared(&changed).digest()
        );
        let mut changed_flags = declared_query();
        changed_flags.target = Some("jvm".to_owned());
        assert_ne!(
            AcquisitionReceiptRequest::declared(&declared_query()).digest(),
            AcquisitionReceiptRequest::declared(&changed_flags).digest()
        );
    }

    #[test]
    fn receipt_object_validation_rejects_corruption_and_missing_files() {
        let root = TempDir::new().unwrap();
        let bytes = b"receipt-object";
        let digest = lower_hex_string(&crate::analyzer::canonical_hash::sha256_bytes(bytes));
        let relative = std::path::Path::new("objects/sha256")
            .join(&digest[..2])
            .join(&digest[2..]);
        fs::create_dir_all(root.path().join("objects/sha256").join(&digest[..2])).unwrap();
        fs::write(root.path().join(&relative), bytes).unwrap();
        assert!(
            receipt_object_is_valid(root.path(), &relative, &digest, bytes.len() as u64).unwrap()
        );

        fs::write(root.path().join(&relative), b"corrupt").unwrap();
        assert!(
            !receipt_object_is_valid(root.path(), &relative, &digest, bytes.len() as u64).unwrap()
        );
        fs::remove_file(root.path().join(&relative)).unwrap();
        assert!(
            !receipt_object_is_valid(root.path(), &relative, &digest, bytes.len() as u64).unwrap()
        );
    }
}

#[cfg(test)]
mod stored_manifest_memo_tests {
    /// One stored manifest is deserialized once per catalog, however many
    /// (shard, selector) rows selection, near-miss attribution, and shard
    /// loading visit (#3101).
    ///
    /// The fixture holds three shards with two selectors each, so the candidate
    /// query answers with six rows over one manifest. Before the decoded
    /// manifest memo, every row and every loaded shard decoded the same bytes
    /// again: one fresh policy process decoded the same JDK manifests hundreds
    /// of times.
    #[test]
    fn a_stored_manifest_is_decoded_once_per_catalog() {
        use super::{
            CatalogCoordinate, CatalogOptions, DurablePackSource, DurablePackSourceKind,
            SemanticPackCatalog, SemanticPackSelectorQuery,
        };
        use crate::analyzer::semantic_model::{CompilerOptions, SourceFormat, compile_source};
        use semver::Version;

        let mut shards = Vec::new();
        for index in 0..3 {
            shards.push(serde_json::json!({
                "id": format!("python.stdlib.{index}"),
                "activation": [
                    {"toolchain": {"name": "cpython", "version": ">=3.10.0, <3.15.0"}},
                    {"toolchain": {"name": "cpython", "version": ">=3.10.0, <3.15.0"}}
                ],
                "payload": {
                    "kind": "declaration_facts",
                    "types": [{
                        "id": format!("python.types-none-type-{index}"),
                        "name": "types.NoneType",
                        "type_kind": "class",
                        "visibility": "public",
                        "type_parameters": [],
                        "hierarchy": [],
                        "aliases": [],
                        "extension_surfaces": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "stdlib/types.pyi",
                            "symbol": "types.NoneType"
                        }
                    }],
                    "members": [],
                    "relations": []
                }
            }));
        }
        let source = serde_json::json!({
            "schema_version": 2,
            "pack_id": "fixture.python-stdlib",
            "version": "2026.9.4",
            "producer": {"name": "bifrost-fixture", "version": "1.0.0"},
            "language": "python",
            "ecosystem": "python",
            "compatibility": {
                "bifrost": ">=0.8.0, <1.0.0",
                "toolchains": [{"name": "cpython", "requirement": ">=3.10.0, <3.15.0"}]
            },
            "provenance": {"source": "checked-in test source", "revision": "fixture-v1"},
            "license": "Apache-2.0",
            "completeness": "complete",
            "safety": {"generated_code_only": false, "review_required": false},
            "shards": shards,
        });
        let compiled = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&source).unwrap(),
            &CompilerOptions::default(),
        )
        .expect("fixture pack compiles");
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        catalog
            .install(
                &compiled,
                &DurablePackSource {
                    kind: DurablePackSourceKind::Installed,
                    source_id: "fixture".to_owned(),
                },
            )
            .unwrap();
        let query = SemanticPackSelectorQuery {
            language: "python".to_owned(),
            ecosystem: "python".to_owned(),
            package: None,
            module: None,
            toolchain: Some(CatalogCoordinate {
                name: "cpython".to_owned(),
                version: Some(Version::parse("3.12.0").unwrap()),
            }),
            target: None,
            configuration: None,
            artifact_sha256: None,
            bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
        };

        let candidates = catalog.candidates_bounded(&query, usize::MAX).unwrap();
        assert_eq!(candidates.len(), 3);
        assert!(catalog.version_near_misses(&query).unwrap().is_empty());
        assert_eq!(
            catalog.manifest_decode_count(),
            1,
            "six selector rows must not decode the manifest six times"
        );
        for candidate in &candidates {
            catalog.load(candidate).unwrap();
        }
        assert_eq!(
            catalog.manifest_decode_count(),
            1,
            "loading every shard must not decode the manifest again"
        );
        assert_eq!(
            catalog.manifest_inventory_validation_count(),
            1,
            "loading every shard must not revalidate the manifest inventory"
        );
    }
}
