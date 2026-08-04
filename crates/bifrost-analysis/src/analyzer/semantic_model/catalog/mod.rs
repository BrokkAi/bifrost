mod db;
mod storage;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, Weak};
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use tempfile::TempDir;
use uuid::Uuid;

use super::{
    ActivationSelector, ArtifactEncoding, CompiledPackManifest, CompiledSemanticModelPack,
    CompiledShard, CompiledShardDescriptor, Completeness, DecodeLimits, NameSelector, PayloadKind,
    decode_manifest, decode_shard_for_manifest,
};
use crate::analyzer::canonical_hash::{CanonicalHasher, is_lower_sha256, lower_hex_string};
use crate::analyzer::store::{
    AnalyzerStore, SemanticPackActivationSourceKind, SemanticPackActiveReference,
    SemanticPackActiveSet,
};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
    pub manifest: CompiledPackManifest,
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

const GENERATED_PRODUCTION_DOMAIN: &[u8] = b"bifrost.semantic-pack.generated-production.v1";

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
    connection: Mutex<Connection>,
    session_packs: Mutex<Vec<SessionPack>>,
    session_activations: Mutex<HashMap<String, SessionActivation>>,
    rejected_manifests: Mutex<HashSet<String>>,
    lookup_hits: AtomicU64,
    lookup_misses: AtomicU64,
    mutation_generation: AtomicU64,
    _ephemeral_root: Option<TempDir>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SemanticPackCatalogCacheIdentity {
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
    manifest: CompiledPackManifest,
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
        let root = match mode {
            CatalogOpenMode::ReadWrite => storage::prepare_root(root)?,
            CatalogOpenMode::ReadOnly => storage::open_read_only_root(root)?,
        };
        let mut connection = db::open(&root, mode)?;
        if mode == CatalogOpenMode::ReadWrite {
            reconcile_storage(&root, &mut connection)?;
        }
        Ok(Self {
            root,
            mode,
            options,
            connection: Mutex::new(connection),
            session_packs: Mutex::new(Vec::new()),
            session_activations: Mutex::new(HashMap::new()),
            rejected_manifests: Mutex::new(HashSet::new()),
            lookup_hits: AtomicU64::new(0),
            lookup_misses: AtomicU64::new(0),
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

    pub fn inventory_bounded(&self, max_packs: usize) -> Result<CatalogInventory, CatalogError> {
        let row_limit = max_packs.saturating_add(1);
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let mut pack_statement = connection
            .prepare(
                "SELECT manifest_bytes, state
                 FROM catalog_packs
                 ORDER BY pack_id, pack_version, manifest_digest
                 LIMIT ?1",
            )
            .map_err(|error| CatalogError::sqlite("prepare catalog inventory", error))?;
        let pack_rows = pack_statement
            .query_map([i64::try_from(row_limit).unwrap_or(i64::MAX)], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|error| CatalogError::sqlite("query catalog inventory", error))?;
        let mut packs = BTreeMap::new();
        let mut complete = true;
        for row in pack_rows {
            let (manifest_bytes, state) =
                row.map_err(|error| CatalogError::sqlite("read catalog inventory", error))?;
            let manifest = decode_manifest(&manifest_bytes, &self.options.decode_limits)
                .map_err(|error| CatalogError::Artifact(error.to_string()))?;
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
            let manifest = decode_manifest(&manifest_bytes, &self.options.decode_limits)
                .map_err(|error| CatalogError::Artifact(error.to_string()))?;
            if manifest.content_sha256 != manifest_digest {
                return Err(CatalogError::Integrity(
                    "generated-production manifest key does not match decoded manifest".to_owned(),
                ));
            }
            validate_generated_pack_identity(key, &manifest)?;
            self.validate_generated_objects(&manifest_digest, &manifest)?;
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

    fn validate_generated_objects(
        &self,
        manifest_digest: &str,
        manifest: &CompiledPackManifest,
    ) -> Result<(), CatalogError> {
        for descriptor in &manifest.shards {
            let (relative_path, stored_size) = {
                let connection = self
                    .connection
                    .lock()
                    .expect("semantic-pack catalog connection mutex poisoned");
                connection
                    .query_row(
                        "SELECT o.relative_path, o.stored_size
                         FROM catalog_pack_shards AS ps
                         JOIN catalog_objects AS o
                           ON o.stored_digest = ps.stored_digest
                         WHERE ps.manifest_digest = ?1
                           AND ps.shard_id = ?2
                           AND ps.stored_digest = ?3",
                        params![
                            manifest_digest,
                            &descriptor.shard_id,
                            &descriptor.stored_sha256
                        ],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?)),
                    )
                    .optional()
                    .map_err(|error| {
                        CatalogError::sqlite("lookup generated production object", error)
                    })?
                    .ok_or_else(|| {
                        CatalogError::Integrity(format!(
                            "generated production is missing shard {}",
                            descriptor.shard_id
                        ))
                    })?
            };
            let bytes = storage::read(
                &self.root,
                &relative_path,
                &descriptor.stored_sha256,
                stored_size,
            )?;
            decode_shard_for_manifest(manifest, descriptor, &bytes, &self.options.decode_limits)
                .map_err(|error| CatalogError::Artifact(error.to_string()))?;
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
        transaction
            .execute(
                "INSERT OR IGNORE INTO catalog_sources(
                   manifest_digest, source_kind, source_id, installed_at
                 ) VALUES(?1, ?2, ?3, ?4)",
                params![
                    &validated.manifest.content_sha256,
                    source.kind.as_str(),
                    &source.source_id,
                    now
                ],
            )
            .map_err(|error| CatalogError::sqlite("insert pack source", error))?;
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
                manifest: validated.manifest,
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
        if store.is_in_memory() {
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
        if store.is_in_memory() {
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
        self.candidates_bounded(query, usize::MAX)
    }

    pub fn candidates_bounded(
        &self,
        query: &SemanticPackSelectorQuery,
        max_rows: usize,
    ) -> Result<Vec<CatalogCandidate>, CatalogError> {
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
            "SELECT p.manifest_digest, p.manifest_bytes, ps.shard_id,
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
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
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
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                    ))
                },
            )
            .map_err(|error| CatalogError::sqlite("query candidates", error))?;
        let mut durable_rows = Vec::new();
        for row in rows {
            durable_rows
                .push(row.map_err(|error| CatalogError::sqlite("read candidate row", error))?);
        }
        drop(statement);
        drop(connection);

        let mut candidates = Vec::new();
        let rejected_manifests = self
            .rejected_manifests
            .lock()
            .expect("semantic-pack rejection mutex poisoned");
        let mut corrupt = Vec::new();
        let mut corrupt_digests = HashSet::new();
        for row in durable_rows {
            let (
                manifest_digest,
                manifest_bytes,
                shard_id,
                descriptor_json,
                selector_json,
                source_kind,
                source_id,
            ) = row;
            if rejected_manifests.contains(&manifest_digest)
                || corrupt_digests.contains(&manifest_digest)
            {
                continue;
            }
            let decoded = (|| -> Result<Option<CatalogCandidate>, CatalogError> {
                let manifest = decode_manifest(&manifest_bytes, &self.options.decode_limits)
                    .map_err(|error| CatalogError::Artifact(error.to_string()))?;
                if manifest.content_sha256 != manifest_digest {
                    return Err(CatalogError::Integrity(
                        "catalog manifest key does not match decoded manifest".to_owned(),
                    ));
                }
                if !manifest_compatible(&manifest, query)? {
                    return Ok(None);
                }
                let selector: ActivationSelector = serde_json::from_slice(&selector_json)
                    .map_err(|error| CatalogError::Integrity(error.to_string()))?;
                if !selector_matches(&selector, query)? {
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
                    if selector_matches(selector, query)? {
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
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let row = connection
            .query_row(
                "SELECT p.manifest_bytes, o.relative_path, o.stored_size
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
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, u64>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| CatalogError::sqlite("load candidate location", error))?
            .ok_or(CatalogError::Unavailable)?;
        let manifest = decode_manifest(&row.0, &self.options.decode_limits)
            .map_err(|error| CatalogError::Artifact(error.to_string()))?;
        let bytes = storage::read(
            &self.root,
            &row.1,
            &candidate.descriptor.stored_sha256,
            row.2,
        )?;
        let shard = decode_shard_for_manifest(
            &manifest,
            &candidate.descriptor,
            &bytes,
            &self.options.decode_limits,
        )
        .map_err(|error| CatalogError::Artifact(error.to_string()))?;
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
        let decoded = decode_shard_for_manifest(
            &pack.manifest,
            &shard.descriptor,
            &shard.bytes,
            &self.options.decode_limits,
        )
        .map_err(|error| CatalogError::Artifact(error.to_string()))?;
        Ok(LoadedCatalogShard {
            manifest: pack.manifest.clone(),
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
        let decoded = decode_shard_for_manifest(&manifest, descriptor, &artifact.bytes, limits)
            .map_err(|error| CatalogError::Artifact(error.to_string()))?;
        shards.push(ValidatedShard {
            descriptor: descriptor.clone(),
            bytes: artifact.bytes.clone(),
            selectors: decoded.activation.clone(),
        });
    }
    Ok(ValidatedPack { manifest, shards })
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

fn generated_production_digest(
    input_digest: &str,
    producer_name: &str,
    producer_version: &str,
    schema_version: u32,
) -> String {
    let mut hasher = CanonicalHasher::new(GENERATED_PRODUCTION_DOMAIN);
    hasher.field("input_digest", input_digest.as_bytes());
    hasher.field("producer_name", producer_name.as_bytes());
    hasher.field("producer_version", producer_version.as_bytes());
    hasher.field("schema_version", &schema_version.to_be_bytes());
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
