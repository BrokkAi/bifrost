mod db;
mod storage;

use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};

use super::{
    ActivationSelector, ArtifactEncoding, CompiledPackManifest, CompiledSemanticModelPack,
    CompiledShard, CompiledShardDescriptor, DecodeLimits, NameSelector, PayloadKind,
    decode_manifest, decode_shard_for_manifest,
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

#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub manifest_digest: String,
    pub shard_id: String,
    pub descriptor: CompiledShardDescriptor,
    pub source_kind: DurablePackSourceKind,
    pub source_id: String,
}

#[derive(Debug)]
pub struct LoadedCatalogShard {
    pub manifest: CompiledPackManifest,
    pub shard: CompiledShard,
    pub source_kind: DurablePackSourceKind,
    pub source_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallOutcome {
    pub manifest_digest: String,
    pub inserted_manifest: bool,
    pub inserted_objects: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogAccounting {
    pub installed_stored_bytes: u64,
    pub object_count: u64,
    pub logical_shard_count: u64,
    pub source_count: u64,
    pub lookup_hits: u64,
    pub lookup_misses: u64,
    pub quarantined_pack_count: u64,
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
    root: PathBuf,
    mode: CatalogOpenMode,
    options: CatalogOptions,
    connection: Mutex<Connection>,
    rejected_manifests: Mutex<HashSet<String>>,
    lookup_hits: AtomicU64,
    lookup_misses: AtomicU64,
}

struct ValidatedShard {
    descriptor: CompiledShardDescriptor,
    bytes: Vec<u8>,
    selectors: Vec<ActivationSelector>,
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
        let connection = db::open(&root, mode)?;
        Ok(Self {
            root,
            mode,
            options,
            connection: Mutex::new(connection),
            rejected_manifests: Mutex::new(HashSet::new()),
            lookup_hits: AtomicU64::new(0),
            lookup_misses: AtomicU64::new(0),
        })
    }

    pub fn install(
        &self,
        pack: &CompiledSemanticModelPack,
        source: &DurablePackSource,
    ) -> Result<InstallOutcome, CatalogError> {
        self.require_writable()?;
        if source.source_id.is_empty() {
            return Err(CatalogError::Integrity(
                "catalog source id must not be empty".to_owned(),
            ));
        }
        let manifest = decode_manifest(&pack.manifest_bytes, &self.options.decode_limits)
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

        let mut validated = Vec::with_capacity(pack.shards.len());
        for descriptor in &manifest.shards {
            let artifact = pack
                .shards
                .iter()
                .find(|artifact| artifact.descriptor == *descriptor)
                .ok_or_else(|| {
                    CatalogError::Integrity(format!(
                        "compiled pack is missing shard {}",
                        descriptor.shard_id
                    ))
                })?;
            let decoded = decode_shard_for_manifest(
                &manifest,
                descriptor,
                &artifact.bytes,
                &self.options.decode_limits,
            )
            .map_err(|error| CatalogError::Artifact(error.to_string()))?;
            validated.push(ValidatedShard {
                descriptor: descriptor.clone(),
                bytes: artifact.bytes.clone(),
                selectors: decoded.activation.clone(),
            });
        }

        let mut published = Vec::with_capacity(validated.len());
        let mut inserted_objects = 0;
        for shard in &validated {
            let (path, inserted) =
                storage::publish(&self.root, &shard.descriptor.stored_sha256, &shard.bytes)?;
            inserted_objects += usize::from(inserted);
            published.push(path);
        }

        let now = crate::cache_db::now_unix_seconds();
        let mut connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| CatalogError::sqlite("begin pack install", error))?;
        let inserted_manifest =
            insert_manifest(&transaction, &manifest, &pack.manifest_bytes, now)?;
        for (ordinal, ((shard, path), descriptor)) in validated
            .iter()
            .zip(&published)
            .zip(&manifest.shards)
            .enumerate()
        {
            insert_object(&transaction, descriptor, path, now)?;
            insert_shard(&transaction, &manifest.content_sha256, ordinal, descriptor)?;
            insert_selectors(
                &transaction,
                &manifest.content_sha256,
                &descriptor.shard_id,
                &shard.selectors,
            )?;
            insert_routing_keys(
                &transaction,
                &manifest.content_sha256,
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
                    &manifest.content_sha256,
                    source.kind.as_str(),
                    &source.source_id,
                    now
                ],
            )
            .map_err(|error| CatalogError::sqlite("insert pack source", error))?;
        transaction
            .execute(
                "UPDATE catalog_packs
                 SET state = 'verified', verified_at = ?2
                 WHERE manifest_digest = ?1",
                params![&manifest.content_sha256, now],
            )
            .map_err(|error| CatalogError::sqlite("verify installed pack", error))?;
        transaction
            .commit()
            .map_err(|error| CatalogError::sqlite("commit pack install", error))?;
        Ok(InstallOutcome {
            manifest_digest: manifest.content_sha256,
            inserted_manifest,
            inserted_objects,
        })
    }

    pub fn candidates(
        &self,
        query: &SemanticPackSelectorQuery,
    ) -> Result<Vec<CatalogCandidate>, CatalogError> {
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let mut statement = connection
            .prepare(
                "SELECT p.manifest_digest, p.manifest_bytes, ps.shard_id,
                        ps.descriptor_json, s.selector_json,
                        source.source_kind, source.source_id
                 FROM catalog_packs AS p
                 JOIN catalog_pack_shards AS ps
                   ON ps.manifest_digest = p.manifest_digest
                 JOIN catalog_selectors AS s
                   ON s.manifest_digest = ps.manifest_digest
                  AND s.shard_id = ps.shard_id
                 JOIN catalog_sources AS source
                   ON source.manifest_digest = p.manifest_digest
                 WHERE p.state = 'verified'
                   AND p.language = ?1
                   AND p.ecosystem = ?2
                 ORDER BY p.manifest_digest, ps.shard_id,
                          source.source_kind, source.source_id, s.selector_ordinal",
            )
            .map_err(|error| CatalogError::sqlite("prepare candidate lookup", error))?;
        let rows = statement
            .query_map(params![&query.language, &query.ecosystem], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            })
            .map_err(|error| CatalogError::sqlite("query candidates", error))?;
        let mut candidates = Vec::new();
        let rejected_manifests = self
            .rejected_manifests
            .lock()
            .expect("semantic-pack rejection mutex poisoned");
        for row in rows {
            let (
                manifest_digest,
                manifest_bytes,
                shard_id,
                descriptor_json,
                selector_json,
                source_kind,
                source_id,
            ) = row.map_err(|error| CatalogError::sqlite("read candidate row", error))?;
            if rejected_manifests.contains(&manifest_digest) {
                continue;
            }
            let manifest = decode_manifest(&manifest_bytes, &self.options.decode_limits)
                .map_err(|error| CatalogError::Artifact(error.to_string()))?;
            if !manifest_compatible(&manifest, &query.bifrost_version)? {
                continue;
            }
            let selector: ActivationSelector = serde_json::from_slice(&selector_json)
                .map_err(|error| CatalogError::Integrity(error.to_string()))?;
            if !selector_matches(&selector, query)? {
                continue;
            }
            let descriptor: CompiledShardDescriptor = serde_json::from_slice(&descriptor_json)
                .map_err(|error| CatalogError::Integrity(error.to_string()))?;
            let candidate = CatalogCandidate {
                manifest_digest,
                shard_id,
                descriptor,
                source_kind: DurablePackSourceKind::parse(&source_kind)?,
                source_id,
            };
            if !candidates.contains(&candidate) {
                candidates.push(candidate);
            }
        }
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
                self.rejected_manifests
                    .lock()
                    .expect("semantic-pack rejection mutex poisoned")
                    .insert(candidate.manifest_digest.clone());
                let mut reason = error.to_string();
                if self.mode == CatalogOpenMode::ReadWrite
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
        Ok(CatalogAccounting {
            installed_stored_bytes,
            object_count: count(&connection, "catalog_objects")?,
            logical_shard_count: count(&connection, "catalog_pack_shards")?,
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
        })
    }

    fn load_inner(&self, candidate: &CatalogCandidate) -> Result<LoadedCatalogShard, CatalogError> {
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

    fn quarantine(
        &self,
        manifest_digest: &str,
        reason: &str,
        error: &CatalogError,
    ) -> Result<(), CatalogError> {
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        connection
            .execute(
                "UPDATE catalog_packs SET state = 'quarantined' WHERE manifest_digest = ?1",
                [manifest_digest],
            )
            .map_err(|source| CatalogError::sqlite("quarantine pack", source))?;
        connection
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
        Ok(())
    }

    fn require_writable(&self) -> Result<(), CatalogError> {
        if self.mode == CatalogOpenMode::ReadWrite {
            Ok(())
        } else {
            Err(CatalogError::ReadOnly)
        }
    }
}

fn insert_manifest(
    transaction: &Transaction<'_>,
    manifest: &CompiledPackManifest,
    bytes: &[u8],
    now: i64,
) -> Result<bool, CatalogError> {
    let inserted = transaction
        .execute(
            "INSERT OR IGNORE INTO catalog_packs(
               manifest_digest, semantic_digest, manifest_bytes, schema_version,
               pack_id, pack_version, producer_name, producer_version,
               language, ecosystem, bifrost_compatibility, provenance_json,
               license, completeness, state, installed_at, verified_at
             ) VALUES(
               ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
               ?14, 'verified', ?15, ?15
             )",
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
    Ok(inserted == 1)
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
    bifrost_version: &Version,
) -> Result<bool, CatalogError> {
    let requirement = VersionReq::parse(&manifest.compatibility.bifrost)
        .map_err(|error| CatalogError::Integrity(error.to_string()))?;
    Ok(requirement.matches(bifrost_version))
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
    if let Some(digest) = &query.artifact_sha256
        && selector.artifact_sha256.as_ref() != Some(digest)
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
        (None, None) => Ok(true),
        (Some(_), None) | (None, Some(_)) => Ok(false),
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
    }
}

fn completeness_name(completeness: &super::Completeness) -> &'static str {
    match completeness {
        super::Completeness::Complete => "complete",
        super::Completeness::Partial => "partial",
    }
}
