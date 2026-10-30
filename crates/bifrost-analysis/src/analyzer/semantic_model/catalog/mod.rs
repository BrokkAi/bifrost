use crate::CancellationToken;
use crate::analyzer::canonical_hash::{CanonicalHasher, is_lower_sha256, lower_hex_string};
use crate::analyzer::semantic_model::ActivationSelector;
use crate::analyzer::semantic_model::CompiledPackManifest;
use crate::analyzer::semantic_model::CompiledSemanticModelPack;
use crate::analyzer::semantic_model::CompiledShard;
use crate::analyzer::semantic_model::CompiledShardDescriptor;
use crate::analyzer::semantic_model::Completeness;
use crate::analyzer::semantic_model::DecodeLimits;
use crate::analyzer::semantic_model::ExactArtifact;
use crate::analyzer::semantic_model::GoPinnedPackage;
use crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION;
use crate::analyzer::semantic_model::decode_manifest;
use crate::analyzer::semantic_model::decode_validated_shard_for_manifest;
use crate::analyzer::semantic_model::validate_manifest_inventory;
use crate::analyzer::store::{
    AnalyzerStore, SemanticPackActivationSourceKind, SemanticPackActiveReference,
    SemanticPackActiveSet,
};
use brokk_bifrost_semantic::analyzer::semantic_model::catalog::rows;
pub use brokk_bifrost_semantic::analyzer::semantic_model::catalog::*;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use std::collections::{BTreeMap, HashMap, HashSet};

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;
use tempfile::TempDir;
use uuid::Uuid;
// Both GC phases must protect every installed pack file.
const OBJECT_LINKED: &str = "EXISTS(SELECT 1 FROM catalog_pack_shards AS shards
    WHERE shards.stored_digest = objects.stored_digest
    UNION ALL SELECT 1 FROM catalog_packs AS packs
    WHERE packs.manifest_object_digest = objects.stored_digest)";
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
    let mut catalog = SemanticPackCatalog::open(
        &cache_dir.join(directory_name),
        CatalogOpenMode::ReadWrite,
        options,
    )?;
    // The local catalog owns workspace sources and activation state. Only
    // exact generated productions may cross into the host cache.
    if std::env::var_os(SEMANTIC_PACK_CACHE_ROOT_ENV).is_none_or(|value| value.is_empty()) {
        catalog.shared_generated_root = crate::gitblob::machine_cache_dir().map(|root| {
            root.join(format!(
                "generated-semantic-packs.v{CATALOG_SCHEMA_VERSION}"
            ))
        });
    }
    Ok(catalog)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurablePackSource {
    pub kind: DurablePackSourceKind,
    pub source_id: String,
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
    pub descriptor: CompiledShardDescriptor,
    pub selectors: Vec<ActivationSelector>,
    pub shard: Option<CompiledShard>,
    pub has_callable_values: bool,
    pub source_kind: CatalogPackSourceKind,
    pub source_id: String,
}

impl LoadedCatalogShard {
    pub fn decoded(&self) -> &CompiledShard {
        self.shard
            .as_ref()
            .expect("catalog shard payload is decoded")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquisitionReceiptSource {
    release_digest: String,
    manifest_digest: String,
    source: DurablePackSource,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationSourceCount {
    pub source_kind: CatalogPackSourceKind,
    pub source_id: String,
    pub pack_count: u64,
}

pub struct CatalogLease<'a> {
    catalog: &'a SemanticPackCatalog,
    lease_id: String,
    released: bool,
}

pub struct SemanticPackCatalog {
    // Field order is deliberate: all SQLite/session state must drop before an
    // owned ephemeral root is deleted, including on Windows.
    root: PathBuf,
    mode: CatalogOpenMode,
    options: CatalogOptions,
    // Session packs and SQLite data-version counters belong to one opened
    // catalog. Equal counters in another catalog do not identify its content.
    instance_identity: u64,
    #[doc(hidden)]
    pub connection: Arc<Mutex<Connection>>,
    session_catalog: Arc<Mutex<Option<SessionSemanticCatalog>>>,
    session_packs: Mutex<Vec<SessionPack>>,
    session_activations: Mutex<HashMap<String, SessionActivation>>,
    rejected_manifests: Mutex<HashSet<String>>,
    decoded_manifests: Mutex<DecodedManifestMemo>,
    verified_manifest_inventories: Mutex<HashSet<String>>,
    validated_python_profile_packs: Mutex<HashSet<String>>,
    manifest_decodes: AtomicU64,
    manifest_inventory_validations: AtomicU64,
    shard_validations: AtomicU64,
    lookup_hits: AtomicU64,
    lookup_misses: AtomicU64,
    sql_statements: AtomicU64,
    object_reads: AtomicU64,
    mutation_generation: AtomicU64,
    shared_generated_root: Option<PathBuf>,
    // The opened host catalog at `shared_generated_root`. A read-write open
    // reconciles every stored object, and each dependency lookup that missed
    // locally used to pay it: 433 opens and about 4 s per warm start of an npm
    // workspace (#3748). A failed open is not kept, so the next use retries.
    shared_generated: OnceLock<Box<SemanticPackCatalog>>,
    _ephemeral_root: Option<Arc<TempDir>>,
}

pub(crate) struct SessionActivation {
    active_set: SemanticPackActiveSet,
    owner: Weak<()>,
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
    // Catalog selection and decoding precede model publication. Queries read
    // the immutable published set and record its Models key instead.
    fn outside_capture(&self) -> &Self {
        let is_capturing = crate::analyzer::i_analyzer::has_read_attribution_ledgers();
        debug_assert!(
            !is_capturing,
            "catalog acquisition must precede captured semantic reads"
        );
        self
    }

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
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .expect("semantic-pack catalog instance identity space exhausted");
        Ok(Self {
            root,
            mode,
            options,
            instance_identity,
            connection: Arc::new(Mutex::new(connection)),
            session_catalog: Arc::new(Mutex::new(None)),
            session_packs: Mutex::new(Vec::new()),
            session_activations: Mutex::new(HashMap::new()),
            rejected_manifests: Mutex::new(HashSet::new()),
            decoded_manifests: Mutex::new(DecodedManifestMemo {
                entries: HashMap::new(),
                bytes: 0,
            }),
            verified_manifest_inventories: Mutex::new(HashSet::new()),
            validated_python_profile_packs: Mutex::new(HashSet::new()),
            manifest_decodes: AtomicU64::new(0),
            manifest_inventory_validations: AtomicU64::new(0),
            shard_validations: AtomicU64::new(0),
            lookup_hits: AtomicU64::new(0),
            lookup_misses: AtomicU64::new(0),
            sql_statements: AtomicU64::new(0),
            object_reads: AtomicU64::new(0),
            mutation_generation: AtomicU64::new(0),
            shared_generated_root: None,
            shared_generated: OnceLock::new(),
            _ephemeral_root: None,
        })
    }

    pub fn open_ephemeral(options: CatalogOptions) -> Result<Self, CatalogError> {
        let root = tempfile::Builder::new()
            .prefix("bifrost-semantic-pack-catalog-")
            .tempdir()
            .map_err(|error| CatalogError::io("create ephemeral catalog root", error))?;
        let mut catalog = Self::open(root.path(), CatalogOpenMode::ReadWrite, options)?;
        catalog._ephemeral_root = Some(Arc::new(root));
        Ok(catalog)
    }

    /// Reconcile missing row generations without activating or retaining packs.
    pub fn reindex(&self, cancellation: &CancellationToken) -> Result<usize, CatalogError> {
        self.require_writable()?;
        let mut published = 0;
        loop {
            if cancellation.is_cancelled() {
                return Err(CatalogError::Cancelled);
            }
            let row = {
                let connection = self
                    .connection
                    .lock()
                    .expect("semantic catalog mutex poisoned");
                connection
                    .query_row(
                        "SELECT p.manifest_digest,
                         s.descriptor_json, o.relative_path, o.stored_size FROM
                         catalog_pack_shards s JOIN catalog_packs p
                         USING(manifest_digest) JOIN catalog_objects o ON
                         o.stored_digest=s.stored_digest LEFT JOIN
                         catalog_semantic_rows_indexed_shards AS indexed ON
                         indexed.manifest_digest=s.manifest_digest AND
                         indexed.shard_id=s.shard_id AND indexed.index_version=4
                         WHERE p.state='verified' AND indexed.shard_key IS NULL
                         ORDER BY s.manifest_digest, s.ordinal LIMIT 1",
                        [],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, Vec<u8>>(1)?,
                                row.get::<_, String>(2)?,
                                row.get::<_, u64>(3)?,
                            ))
                        },
                    )
                    .optional()
                    .map_err(|error| {
                        CatalogError::sqlite("select unindexed semantic shard", error)
                    })?
            };
            let Some((manifest_digest, descriptor_json, path, size)) = row else {
                break;
            };
            let manifest = self.stored_manifest(&manifest_digest)?;
            let descriptor: CompiledShardDescriptor = serde_json::from_slice(&descriptor_json)
                .map_err(|error| CatalogError::Integrity(error.to_string()))?;
            let lease = self.lease(
                &manifest.content_sha256,
                "semantic-reindex",
                Duration::from_secs(60),
            )?;
            let bytes = storage::read(&self.root, &path, &descriptor.stored_sha256, size)?;
            let shard = self.decode_stored_shard(&manifest, &descriptor, &bytes)?;
            let mut connection = self
                .connection
                .lock()
                .expect("semantic catalog mutex poisoned");
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|error| CatalogError::sqlite("begin semantic reindex", error))?;
            let indexed: bool = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1
                         FROM catalog_semantic_rows_indexed_shards WHERE
                         manifest_digest=?1 AND shard_id=?2 AND index_version=4)",
                    params![manifest.content_sha256, descriptor.shard_id],
                    |row| row.get(0),
                )
                .map_err(|error| CatalogError::sqlite("recheck semantic index", error))?;
            if !indexed {
                rows::publish_semantic_rows(&transaction, &manifest, &shard)?;
                published += 1;
            }
            transaction
                .commit()
                .map_err(|error| CatalogError::sqlite("commit semantic reindex", error))?;
            if !indexed {
                self.record_mutation();
            }
            drop(connection);
            lease.release()?;
        }
        Ok(published)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn active_reader_connection(&self) -> Result<Connection, CatalogError> {
        let mut session = self
            .outside_capture()
            .session_catalog
            .lock()
            .expect("session semantic catalog mutex poisoned");
        if session.is_none() {
            *session = Some(open_session_semantic_catalog()?);
        }
        let connection = brokk_bifrost_semantic::analyzer::semantic_model::catalog::db::open(
            &self.root,
            CatalogOpenMode::ReadOnly,
        )?;
        brokk_bifrost_core::cache_db::sql_profile::install_catalog_active(&connection);
        // db::open also sets query_only, which forbids TEMP writes. The main
        // file remains protected by SQLITE_OPEN_READ_ONLY; membership is TEMP.
        connection
            .pragma_update(None, "query_only", false)
            .map_err(|error| CatalogError::sqlite("enable active TEMP membership", error))?;
        rows::attach_session_rows(
            &connection,
            session.as_ref().expect("session catalog initialized"),
        )?;
        Ok(connection)
    }

    /// A connection and TEMP membership table owned by exactly one active set.
    pub fn runtime_source_reader<'a>(
        &self,
        shards: impl IntoIterator<Item = (&'a str, &'a str, CatalogPackSourceKind)>,
    ) -> Result<CatalogRuntimeSourceReader, CatalogError> {
        self.runtime_source_reader_with_shard_keys(shards)
            .map(|(reader, _)| reader)
    }

    pub fn runtime_source_reader_with_shard_keys<'a>(
        &self,
        shards: impl IntoIterator<Item = (&'a str, &'a str, CatalogPackSourceKind)>,
    ) -> Result<
        (
            CatalogRuntimeSourceReader,
            Vec<crate::analyzer::store::active_models::CatalogShardRowIdentity>,
        ),
        CatalogError,
    > {
        use crate::analyzer::store::active_models::{
            CatalogShardDatabase, CatalogShardRowIdentity,
        };
        let connection = self.active_reader_connection()?;
        let mut identities = Vec::new();
        for (manifest, shard, kind) in shards {
            let source = match kind {
                CatalogPackSourceKind::Embedded | CatalogPackSourceKind::EphemeralWorkspace => {
                    "session"
                }
                _ => "durable",
            };
            let shard_key = rows::select_active_shard_source(&connection, manifest, shard, source)?
                .ok_or_else(|| CatalogError::IndexReconciliationRequired {
                    manifest_digest: manifest.to_owned(),
                    shard_id: shard.to_owned(),
                })?;
            identities.push(CatalogShardRowIdentity {
                shard_key,
                database: if source == "durable" {
                    CatalogShardDatabase::Durable
                } else {
                    CatalogShardDatabase::Session
                },
            });
        }
        Ok((
            CatalogRuntimeSourceReader {
                connection: Arc::new(Mutex::new(connection)),
                session_catalog: Arc::clone(&self.outside_capture().session_catalog),
                _ephemeral_root: self._ephemeral_root.as_ref().map(Arc::clone),
            },
            identities,
        ))
    }

    fn shared_generated_catalog(&self) -> Option<&Self> {
        let root = self.shared_generated_root.as_ref()?;
        if let Some(catalog) = self.outside_capture().shared_generated.get() {
            return Some(catalog);
        }
        match Self::open(root, CatalogOpenMode::ReadWrite, self.options.clone()) {
            // A concurrent first use may have stored its own open; keep that one.
            Ok(catalog) => Some(
                self.outside_capture()
                    .shared_generated
                    .get_or_init(|| Box::new(catalog)),
            ),
            Err(error) => {
                eprintln!(
                    "shared generated cache {root:?} is unavailable; using the workspace catalog: {error}"
                );
                None
            }
        }
    }

    // Publication is optional: a verified local production remains usable if
    // the additional host copy cannot be written. Retry on the next local hit.
    fn retain_shared_generated(&self, production: &GeneratedProduction) {
        let Some(shared) = self.shared_generated_catalog() else {
            return;
        };
        let retained = (|| -> Result<(), CatalogError> {
            if shared.has_verified_generated_production(&production.key)? {
                let connection = shared
                    .connection
                    .lock()
                    .expect("semantic-pack catalog connection mutex poisoned");
                connection
                    .execute(
                        "UPDATE catalog_packs SET last_used_at = ?2
                     WHERE manifest_digest = ?1 AND COALESCE(last_used_at, 0) < ?2 - 60",
                        params![
                            production.manifest_digest,
                            crate::cache_db::now_unix_seconds()
                        ],
                    )
                    .map_err(|error| CatalogError::sqlite("touch shared production", error))?;
            } else {
                shared.copy_generated_from(self, production)?;
                // Only publication pays for bounded cleanup. Active imports
                // hold leases; recent host hits refresh the age above.
                shared.garbage_collect(&CatalogGcOptions::default())?;
            }
            Ok(())
        })();
        if let Err(error) = retained {
            eprintln!(
                "could not retain shared generated production {}; the workspace copy remains available and publication will be retried: {error}",
                production.key.production_digest()
            );
        }
    }

    fn has_verified_generated_production(
        &self,
        key: &GeneratedProductionKey,
    ) -> Result<bool, CatalogError> {
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        connection
            .query_row(
                SHARED_PRODUCTION_PRESENT_SQL,
                [key.production_digest()],
                |row| row.get(0),
            )
            .map_err(|error| CatalogError::sqlite("check shared production publication", error))
    }

    // One exact production is the transfer unit. Installed/workspace sources,
    // activation history, pins and configuration never cross this boundary.
    fn copy_generated_from(
        &self,
        source: &Self,
        production: &GeneratedProduction,
    ) -> Result<(), CatalogError> {
        let _scope = crate::profiling::scope("semantic_pack.copy_generated");
        let lease = source.lease(
            &production.manifest_digest,
            "generated-transfer",
            Duration::from_secs(300),
        )?;
        let manifest = source.stored_manifest(&production.manifest_digest)?;
        validate_generated_pack_identity(&production.key, &manifest)?;
        let manifest_bytes = {
            let connection = source
                .connection
                .lock()
                .expect("semantic-pack catalog connection mutex poisoned");
            read_manifest_on(source.root(), &connection, &production.manifest_digest)?
                .ok_or(CatalogError::Unavailable)?
        };
        let mut shards = Vec::with_capacity(manifest.shards.len());
        for descriptor in &manifest.shards {
            let relative = storage::relative_object_path(&descriptor.stored_sha256);
            let bytes = storage::read(
                source.root(),
                &relative.to_string_lossy(),
                &descriptor.stored_sha256,
                descriptor.stored_size,
            )?;
            shards.push(crate::analyzer::semantic_model::CompiledShardArtifact {
                descriptor: descriptor.clone(),
                bytes,
            });
        }
        let pack = CompiledSemanticModelPack {
            manifest: (*manifest).clone(),
            manifest_bytes,
            shards,
        };
        let extraction = source.extraction_accounting(&production.manifest_digest)?;
        if let Some(extraction) = &extraction {
            validate_extraction_accounting(extraction)?;
        }
        self.install_with(
            &pack,
            &DurablePackSource {
                kind: DurablePackSourceKind::Generated,
                source_id: production.key.source_id(),
            },
            |transaction, manifest, now| {
                insert_generated_production(transaction, &production.key, manifest, now)?;
                if let Some(extraction) = &extraction {
                    insert_extraction_accounting(
                        transaction,
                        &manifest.content_sha256,
                        extraction,
                    )?;
                }
                Ok(())
            },
        )?;
        source
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned")
            .execute(
                "UPDATE catalog_packs SET last_used_at = ?2 WHERE manifest_digest = ?1",
                params![
                    production.manifest_digest,
                    crate::cache_db::now_unix_seconds()
                ],
            )
            .map_err(|error| CatalogError::sqlite("touch imported production", error))?;
        lease.release()?;
        Ok(())
    }

    pub(crate) fn generated_production_lock(
        &self,
        key: &GeneratedProductionKey,
    ) -> Result<GeneratedProductionLock, CatalogError> {
        self.require_writable()?;
        let shared = self.shared_generated_catalog();
        let lock_root = shared.map_or(self.root(), Self::root);
        let file = storage::open_generated_production_lock(lock_root, key.production_digest())?;
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
    /// Full semantic shard validations on cache reads, excluding hydration.
    pub fn shard_validation_count(&self) -> u64 {
        self.shard_validations.load(Ordering::Relaxed)
    }

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
            .outside_capture()
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
        self.outside_capture()
            .verified_manifest_inventories
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
        self.shard_validations.fetch_add(1, Ordering::Relaxed);
        decode_validated_shard_for_manifest(
            manifest,
            descriptor,
            bytes,
            &self.options.decode_limits,
        )
        .map_err(|error| CatalogError::Artifact(error.to_string()))
    }

    /// A verified row may predate the Python profile evidence check. Recheck
    /// every stored shard once per opened catalog before the first PyPI load;
    /// the manifest digest and content-addressed objects bind later loads to
    /// the exact pack that passed this check.
    fn validate_stored_python_profile_pack(
        &self,
        manifest: &CompiledPackManifest,
    ) -> Result<(), CatalogError> {
        if manifest.language != "python"
            || !manifest.shards.iter().any(|descriptor| {
                descriptor
                    .routing_keys
                    .iter()
                    .any(|key| key.starts_with("package:pkg:pypi/"))
            })
        {
            return Ok(());
        }
        let mut checked = self
            .outside_capture()
            .validated_python_profile_packs
            .lock()
            .expect("Python profile validation mutex poisoned");
        if checked.contains(&manifest.content_sha256) {
            return Ok(());
        }
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let mut decoded = Vec::with_capacity(manifest.shards.len());
        for descriptor in &manifest.shards {
            self.sql_statements.fetch_add(1, Ordering::Relaxed);
            let (relative_path, stored_size) = connection
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
                        &manifest.content_sha256,
                        &descriptor.shard_id,
                        &descriptor.stored_sha256
                    ],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?)),
                )
                .optional()
                .map_err(|error| CatalogError::sqlite("load Python profile shard", error))?
                .ok_or(CatalogError::Unavailable)?;
            self.object_reads.fetch_add(1, Ordering::Relaxed);
            let bytes = storage::read(
                &self.root,
                &relative_path,
                &descriptor.stored_sha256,
                stored_size,
            )?;
            decoded.push(self.decode_stored_shard(manifest, descriptor, &bytes)?);
        }
        let authored = crate::analyzer::semantic_model::artifact::authored_pack_from_decoded_shards(
            manifest, &decoded,
        );
        let diagnostics =
            crate::analyzer::semantic_model::validate::validate_csmi_profile_evidence(&authored);
        if !diagnostics.is_empty() {
            return Err(CatalogError::Integrity(format!(
                "stored Python pack has inconsistent full-pack evidence: {diagnostics:?}"
            )));
        }
        checked.insert(manifest.content_sha256.clone());
        Ok(())
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
            .outside_capture()
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
        let memo = self
            .outside_capture()
            .decoded_manifests
            .lock()
            .expect("semantic-pack manifest memo mutex poisoned");
        let manifest = memo.entries.get(manifest_digest)?;
        debug_assert_eq!(
            manifest.content_sha256, manifest_digest,
            "decoded manifest memo is an immutable content transform"
        );
        Some(Arc::clone(manifest))
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
            read_manifest_on(&self.root, &connection, manifest_digest)?
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
                "SELECT manifest_digest, state
                 FROM catalog_packs
                 ORDER BY pack_id, pack_version, manifest_digest
                 LIMIT ?1",
            )
            .map_err(|error| CatalogError::sqlite("prepare catalog inventory", error))?;
        let pack_rows = pack_statement
            .query_map([i64::try_from(row_limit).unwrap_or(i64::MAX)], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|error| CatalogError::sqlite("query catalog inventory", error))?;
        let mut packs = BTreeMap::new();
        let mut complete = true;
        for row in pack_rows {
            let (manifest_digest, state) =
                row.map_err(|error| CatalogError::sqlite("read catalog inventory", error))?;
            let bytes =
                read_manifest_on(&self.root, &connection, &manifest_digest)?.ok_or_else(|| {
                    CatalogError::Integrity("inventory manifest disappeared".to_owned())
                })?;
            let manifest = self.decoded_manifest(&manifest_digest, &bytes)?;
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
            .outside_capture()
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
            .outside_capture()
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
            self.reconcile_installed_semantic_rows(&validated)?;
            InstallOutcome {
                diagnostics: validated
                    .shards
                    .iter()
                    .flat_map(|shard| shard.diagnostics.iter().cloned())
                    .collect(),
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
        let generated_source = DurablePackSource {
            kind: DurablePackSourceKind::Generated,
            source_id: key.source_id(),
        };
        self.install_generated_with(
            key,
            pack,
            source,
            || validate_extraction_accounting(extraction),
            |transaction, manifest, now| {
                insert_extraction_accounting(transaction, &manifest.content_sha256, extraction)?;
                insert_generated_production(transaction, key, manifest, now)?;
                insert_source(
                    transaction,
                    &manifest.content_sha256,
                    &generated_source,
                    now,
                )
            },
        )
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
            self.reconcile_installed_semantic_rows(&validated)?;
            GeneratedInstallOutcome {
                production: GeneratedProduction {
                    key: key.clone(),
                    manifest_digest: validated.manifest.content_sha256.clone(),
                    completeness: validated.manifest.completeness,
                },
                install: InstallOutcome {
                    diagnostics: validated
                        .shards
                        .iter()
                        .flat_map(|shard| shard.diagnostics.iter().cloned())
                        .collect(),
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
        let source = DurablePackSource {
            kind: DurablePackSourceKind::Generated,
            source_id: key.source_id(),
        };
        self.install_generated_with(
            key,
            pack,
            &source,
            || Ok(()),
            |transaction, manifest, now| {
                insert_generated_production(transaction, key, manifest, now)
            },
        )
    }

    pub fn install_generated_with_exact_go_source(
        &self,
        key: &GeneratedProductionKey,
        pack: &CompiledSemanticModelPack,
        artifact: &ExactArtifact,
        packages: &[GoPinnedPackage],
    ) -> Result<GeneratedInstallOutcome, CatalogError> {
        let source = DurablePackSource {
            kind: DurablePackSourceKind::Generated,
            source_id: key.source_id(),
        };
        self.install_generated_with(
            key,
            pack,
            &source,
            || validate_exact_go_source(artifact, packages),
            |transaction, manifest, now| {
                insert_generated_production(transaction, key, manifest, now)?;
                insert_exact_go_source_rows(
                    transaction,
                    &manifest.content_sha256,
                    artifact,
                    packages,
                )
            },
        )
    }

    fn install_generated_with(
        &self,
        key: &GeneratedProductionKey,
        pack: &CompiledSemanticModelPack,
        source: &DurablePackSource,
        validate_install: impl FnOnce() -> Result<(), CatalogError>,
        record_install: impl FnOnce(
            &Transaction<'_>,
            &CompiledPackManifest,
            i64,
        ) -> Result<(), CatalogError>,
    ) -> Result<GeneratedInstallOutcome, CatalogError> {
        validate_generated_pack_identity(key, &pack.manifest)?;
        validate_install()?;
        let install = self.install_with(pack, source, record_install)?;
        let production = GeneratedProduction {
            key: key.clone(),
            manifest_digest: install.manifest_digest.clone(),
            completeness: pack.manifest.completeness,
        };
        self.retain_shared_generated(&production);
        Ok(GeneratedInstallOutcome {
            production,
            install,
        })
    }

    pub fn register_exact_go_source(
        &self,
        manifest_digest: &str,
        artifact: &ExactArtifact,
        packages: &[GoPinnedPackage],
    ) -> Result<(), CatalogError> {
        self.require_writable()?;
        validate_exact_go_source(artifact, packages)?;
        let mut connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| CatalogError::sqlite("begin exact Go source registration", error))?;
        let applicable: bool = transaction
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM catalog_packs
                   WHERE manifest_digest = ?1
                     AND state = 'verified'
                     AND language = 'go')",
                [manifest_digest],
                |row| row.get(0),
            )
            .map_err(|error| CatalogError::sqlite("check exact Go source publication", error))?;
        if !applicable {
            return Err(CatalogError::Unavailable);
        }
        insert_exact_go_source_rows(&transaction, manifest_digest, artifact, packages)?;
        transaction
            .commit()
            .map_err(|error| CatalogError::sqlite("commit exact Go source registration", error))?;
        self.record_mutation();
        Ok(())
    }

    /// Record that `key` can be found again from a read-free source identity.
    ///
    /// The identity is derived by the ecosystem adapter from cheap filesystem
    /// metadata rather than artifact bytes (see
    /// `dependency_source_identity`), so a later process can ask for this
    /// production before it reads anything. The recorded row only names the
    /// production; [`Self::generated_production_by_source_identity`] still
    /// resolves it through the fully verified key path, and the row disappears
    /// with the production it names.
    ///
    /// The row is keyed by the current `GENERATED_PRODUCTION_CACHE_VERSION`, so
    /// a catalog shared by binaries at different cache epochs keeps one mapping
    /// per epoch instead of letting the newest one hide the mapping a running
    /// binary learned.
    pub fn install_generated_source_identity(
        &self,
        source_identity: &str,
        key: &GeneratedProductionKey,
    ) -> Result<(), CatalogError> {
        self.require_writable()?;
        if !is_lower_sha256(source_identity) {
            return Err(CatalogError::Integrity(
                "generated source identity must be a lowercase SHA-256 digest".to_owned(),
            ));
        }
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let inserted = connection
            .execute(
                "INSERT OR REPLACE INTO catalog_generated_source_identities(
                   source_identity, producer_name, producer_version, schema_version,
                   generated_cache_version, production_digest, created_at
                 )
                 SELECT ?1, ?2, ?3, ?4, ?5, gp.production_digest, ?6
                 FROM catalog_generated_productions AS gp
                 WHERE gp.production_digest = ?7
                   AND gp.producer_name = ?2
                   AND gp.producer_version = ?3
                   AND gp.schema_version = ?4",
                params![
                    source_identity,
                    key.producer_name(),
                    key.producer_version(),
                    key.schema_version(),
                    GENERATED_PRODUCTION_CACHE_VERSION,
                    crate::cache_db::now_unix_seconds(),
                    key.production_digest(),
                ],
            )
            .map_err(|error| CatalogError::sqlite("install generated source identity", error))?;
        if inserted != 1 {
            return Err(CatalogError::Integrity(format!(
                "generated production {} is not installed, so its source identity cannot be recorded",
                key.production_digest()
            )));
        }
        drop(connection);
        if let Some(shared) = self.shared_generated_catalog() {
            // Failure of the optional host mapping does not invalidate the
            // local identity just committed. A later local hit retries it.
            if let Err(error) = shared.install_generated_source_identity(source_identity, key) {
                eprintln!(
                    "could not mirror generated source identity to the host cache; retaining the workspace identity: {error}"
                );
            }
        }
        Ok(())
    }

    /// Look up the generated production a read-free source identity was learned
    /// under, without reading or hashing the artifacts that identity describes.
    ///
    /// The row only names a candidate input digest. The returned production
    /// comes from [`Self::generated_production`], which re-validates the key,
    /// the manifest, and every shard row, so a partially deleted or quarantined
    /// production reads as a miss here. Callers treat that miss, and any error,
    /// as "read the artifacts and use the exact path instead".
    pub fn generated_production_by_source_identity(
        &self,
        source_identity: &str,
        producer: &crate::analyzer::semantic_model::Producer,
    ) -> Result<Option<GeneratedProduction>, CatalogError> {
        let connection = self
            .connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        let row = connection
            .query_row(
                "SELECT gp.production_digest, gp.input_digest
                 FROM catalog_generated_source_identities AS ident
                 JOIN catalog_generated_productions AS gp
                   ON gp.production_digest = ident.production_digest
                 WHERE ident.source_identity = ?1
                   AND ident.producer_name = ?2
                   AND ident.producer_version = ?3
                   AND ident.schema_version = ?4
                   AND ident.generated_cache_version = ?5
                   AND gp.producer_name = ident.producer_name
                   AND gp.producer_version = ident.producer_version
                   AND gp.schema_version = ident.schema_version",
                params![
                    source_identity,
                    &producer.name,
                    &producer.version,
                    SEMANTIC_MODEL_SCHEMA_VERSION,
                    GENERATED_PRODUCTION_CACHE_VERSION,
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|error| CatalogError::sqlite("lookup generated source identity", error))?;
        drop(connection);
        let Some((production_digest, input_digest)) = row else {
            let Some(shared) = self.shared_generated_catalog() else {
                return Ok(None);
            };
            let Some(production) =
                shared.generated_production_by_source_identity(source_identity, producer)?
            else {
                return Ok(None);
            };
            self.copy_generated_from(shared, &production)?;
            self.install_generated_source_identity(source_identity, &production.key)?;
            return Ok(Some(production));
        };
        let key = GeneratedProductionKey::new(
            input_digest,
            &producer.name,
            &producer.version,
            SEMANTIC_MODEL_SCHEMA_VERSION,
        )?;
        debug_assert_eq!(
            key.production_digest(),
            production_digest,
            "a source-identity row must name the production its stored key derives"
        );
        self.generated_production(&key)
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
                "SELECT input_digest, producer_name, producer_version,
                        schema_version, manifest_digest
                 FROM catalog_verified_generated_productions
                 WHERE production_digest = ?1",
                [&key.production_digest],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, u32>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| CatalogError::sqlite("lookup generated production", error))?;
        drop(connection);
        let Some((input_digest, producer_name, producer_version, schema_version, manifest_digest)) =
            row
        else {
            let Some(shared) = self.shared_generated_catalog() else {
                return Ok(None);
            };
            let Some(production) = shared.generated_production(key)? else {
                return Ok(None);
            };
            self.copy_generated_from(shared, &production)?;
            return Ok(Some(production));
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
            let manifest = self.stored_manifest(&manifest_digest)?;
            validate_generated_pack_identity(key, &manifest)?;
            self.validate_generated_shard_rows(&manifest_digest, &manifest)?;
            Ok(GeneratedProduction {
                key: stored_key,
                manifest_digest: manifest_digest.clone(),
                completeness: manifest.completeness,
            })
        })();
        match validated {
            Ok(production) => {
                self.retain_shared_generated(&production);
                Ok(Some(production))
            }
            Err(error) => {
                self.outside_capture()
                    .rejected_manifests
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
        let missing = missing_manifest_shard_ids(manifest, &stored);
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
        let manifest_object_digest =
            crate::analyzer::semantic_model::csmi::sha256_hex(&pack.manifest_bytes);
        self.reserve_install_objects(&installation_id, &validated.shards, &manifest_object_digest)?;
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
        let (manifest_path, inserted) =
            match storage::publish(&self.root, &manifest_object_digest, &pack.manifest_bytes) {
                Ok(published) => published,
                Err(error) => {
                    return Err(self.release_after_install_failure(&installation_id, error));
                }
            };
        inserted_objects += usize::from(inserted);

        let now = crate::cache_db::now_unix_seconds();
        let install_result = self.commit_install(
            pack,
            source,
            &validated,
            &published,
            &manifest_path,
            &installation_id,
            now,
            record_install,
        );
        match install_result {
            Ok(inserted_manifest) => {
                self.outside_capture()
                    .rejected_manifests
                    .lock()
                    .expect("semantic-pack rejection mutex poisoned")
                    .remove(&validated.manifest.content_sha256);
                self.record_mutation();
                Ok(InstallOutcome {
                    diagnostics: validated
                        .shards
                        .iter()
                        .flat_map(|shard| shard.diagnostics.iter().cloned())
                        .collect(),
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
                "SELECT pack.semantic_digest, pack.manifest_object_digest, pack.schema_version,
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
                        row.get::<_, String>(1)?,
                        row.get::<_, u32>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, Option<String>>(9)?,
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
            stored_object_digest,
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
            || stored_object_digest
                != crate::analyzer::semantic_model::csmi::sha256_hex(manifest_bytes)
            || schema_version != validated.manifest.schema_version
            || pack_id != validated.manifest.pack_id
            || pack_version != validated.manifest.version
            || producer_name != validated.manifest.producer.name
            || producer_version != validated.manifest.producer.version
            || language != validated.manifest.language
            || ecosystem != validated.manifest.ecosystem
            || bifrost_compatibility.as_deref()
                != validated.manifest.compatibility.bifrost.as_deref()
            || stored_provenance_json != provenance_json
            || license != validated.manifest.license
            || completeness != validated.manifest.completeness.label()
        {
            return Ok(false);
        }

        if read_available_manifest_on(&self.root, &connection, &validated.manifest.content_sha256)?
            .is_none()
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

    fn reconcile_installed_semantic_rows(
        &self,
        validated: &ValidatedPack,
    ) -> Result<(), CatalogError> {
        let mut connection = self
            .connection
            .lock()
            .expect("semantic catalog mutex poisoned");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| {
                CatalogError::sqlite("begin installed semantic row reconciliation", error)
            })?;
        let mut changed = false;
        for shard in &validated.shards {
            changed |=
                rows::publish_semantic_rows(&transaction, &validated.manifest, &shard.decoded)?;
        }
        transaction.commit().map_err(|error| {
            CatalogError::sqlite("commit installed semantic row reconciliation", error)
        })?;
        if changed {
            self.record_mutation();
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_install(
        &self,
        pack: &CompiledSemanticModelPack,
        source: &DurablePackSource,
        validated: &ValidatedPack,
        published: &[PathBuf],
        manifest_path: &Path,
        installation_id: &str,
        now: i64,
        record_install: impl FnOnce(
            &Transaction<'_>,
            &CompiledPackManifest,
            i64,
        ) -> Result<(), CatalogError>,
    ) -> Result<bool, CatalogError> {
        assert_eq!(published.len(), validated.shards.len());
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
        let object_digest = crate::analyzer::semantic_model::csmi::sha256_hex(&pack.manifest_bytes);
        let size = pack.manifest_bytes.len() as u64;
        storage::verify_existing(&self.root, manifest_path, &object_digest, size)?;
        insert_object(
            &transaction,
            &object_digest,
            size,
            size,
            crate::analyzer::semantic_model::ArtifactEncoding::Raw,
            manifest_path,
            now,
        )?;
        let inserted_manifest =
            insert_manifest(&transaction, &validated.manifest, &object_digest, now)?;
        for (ordinal, ((shard, path), descriptor)) in validated
            .shards
            .iter()
            .zip(published)
            .zip(&validated.manifest.shards)
            .enumerate()
        {
            insert_object(
                &transaction,
                &descriptor.stored_sha256,
                descriptor.stored_size,
                descriptor.raw_size,
                descriptor.encoding,
                path,
                now,
            )?;
            insert_shard(
                &transaction,
                &validated.manifest.content_sha256,
                ordinal,
                descriptor,
            )?;
            record_shard_validation(
                &transaction,
                &validated.manifest.content_sha256,
                &descriptor.shard_id,
                &decode_limits_digest(&self.options.decode_limits),
            )?;
            rows::publish_semantic_rows(&transaction, &validated.manifest, &shard.decoded)?;
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
        manifest_object_digest: &str,
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
        for digest in shards
            .iter()
            .map(|shard| shard.descriptor.stored_sha256.as_str())
            .chain(std::iter::once(manifest_object_digest))
        {
            transaction
                .execute(
                    "INSERT OR IGNORE INTO catalog_install_object_reservations(
                       installation_id, stored_digest, expires_at
                     ) VALUES(?1, ?2, ?3)",
                    params![installation_id, digest, expires_at],
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
        self.register_session_pack_internal(pack, source, None)
    }

    pub fn register_compiled_pack(
        &self,
        pack: &CompiledSemanticModelPack,
        source: &SessionPackSource,
    ) -> Result<String, CatalogError> {
        self.register_session_pack(pack, source)
    }

    pub fn register_compiled_pack_with_exact_go_source(
        &self,
        pack: &CompiledSemanticModelPack,
        source: &SessionPackSource,
        artifact: &ExactArtifact,
        packages: &[GoPinnedPackage],
    ) -> Result<String, CatalogError> {
        self.register_session_pack_internal(pack, source, Some((artifact, packages)))
    }

    fn register_session_pack_internal(
        &self,
        pack: &CompiledSemanticModelPack,
        source: &SessionPackSource,
        exact_source: Option<(&ExactArtifact, &[GoPinnedPackage])>,
    ) -> Result<String, CatalogError> {
        if source.source_id.is_empty() {
            return Err(CatalogError::Integrity(
                "session pack source id must not be empty".to_owned(),
            ));
        }
        let validated = validate_pack(pack, &self.options.decode_limits)?;
        let digest = validated.manifest.content_sha256.clone();
        if let Some((artifact, packages)) = exact_source {
            if validated.manifest.language != "go" {
                return Err(CatalogError::Integrity(
                    "exact Go source can only accompany a Go compiled pack".to_owned(),
                ));
            }
            validate_exact_go_source(artifact, packages)?;
        }
        let mut session_packs = self
            .outside_capture()
            .session_packs
            .lock()
            .expect("semantic-pack session mutex poisoned");
        if !session_packs
            .iter()
            .any(|entry| entry.manifest.content_sha256 == digest && entry.source == *source)
        {
            {
                let mut session_catalog_guard = self
                    .outside_capture()
                    .session_catalog
                    .lock()
                    .expect("session callable-values connection mutex poisoned");
                if session_catalog_guard.is_none() {
                    *session_catalog_guard = Some(open_session_semantic_catalog()?);
                }
                let session_catalog = session_catalog_guard
                    .as_mut()
                    .expect("session callable-values catalog was just initialized");
                let transaction = session_catalog
                    .connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(|error| {
                        CatalogError::sqlite("begin session callable-values publication", error)
                    })?;
                transaction
                    .execute(
                        "INSERT OR IGNORE INTO catalog_packs(manifest_digest, state)
                         VALUES(?1, 'verified')",
                        [&digest],
                    )
                    .map_err(|error| {
                        CatalogError::sqlite("publish session callable-values pack", error)
                    })?;
                for shard in &validated.shards {
                    transaction
                        .execute(
                            "INSERT OR IGNORE INTO catalog_pack_shards(manifest_digest, shard_id)
                             VALUES(?1, ?2)",
                            params![&digest, &shard.descriptor.shard_id],
                        )
                        .map_err(|error| {
                            CatalogError::sqlite("publish session callable-values shard", error)
                        })?;
                    insert_selectors(
                        &transaction,
                        &digest,
                        &shard.descriptor.shard_id,
                        &shard.selectors,
                    )?;
                    rows::publish_semantic_rows(&transaction, &validated.manifest, &shard.decoded)?;
                }
                if let Some((artifact, packages)) = exact_source {
                    insert_exact_go_source_rows(&transaction, &digest, artifact, packages)?;
                }
                transaction.commit().map_err(|error| {
                    CatalogError::sqlite("commit session callable-values publication", error)
                })?;
            }
            session_packs.push(SessionPack {
                manifest: Arc::new(validated.manifest),
                // Drop decoded facts after publication. The session registry
                // only needs compiled bytes and selectors for activation.
                shards: validated
                    .shards
                    .into_iter()
                    .map(|shard| SessionShard {
                        descriptor: shard.descriptor,
                        bytes: shard.bytes,
                        selectors: shard.selectors,
                    })
                    .collect(),
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
            self.validate_ephemeral_active_members(&desired.members)?;
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
            self.validate_ephemeral_active_members(&desired.members)?;
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

    fn validate_ephemeral_active_members(
        &self,
        members: &[SemanticPackActiveReference],
    ) -> Result<(), CatalogError> {
        if members
            .iter()
            .any(|member| durable_activation_kind(member.source_kind).is_some())
        {
            return Err(CatalogError::Integrity(
                "ephemeral workspaces can activate only session semantic packs".to_owned(),
            ));
        }
        self.validate_active_members(members, true, None)
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
            .outside_capture()
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
            .outside_capture()
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
                    "SELECT pack.state
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
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|error| {
                    CatalogError::sqlite("verify acquisition receipt source", error)
                })?;
            let Some(state) = source_state else {
                return Err(CatalogError::Integrity(format!(
                    "acquisition receipt source is not verified: {:?}",
                    source
                )));
            };
            let manifest_bytes =
                read_manifest_on(&self.root, &transaction, &source.manifest_digest)?.ok_or_else(
                    || CatalogError::Integrity("receipt manifest disappeared".to_owned()),
                )?;
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
            .outside_capture()
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
            self.outside_capture()
                .rejected_manifests
                .lock()
                .expect("semantic-pack rejection mutex poisoned")
                .insert(manifest_digest.clone());
            if self.mode == CatalogOpenMode::ReadWrite {
                self.quarantine(&manifest_digest, "candidate_metadata_failure", &error)?;
            }
        }

        let session_packs = self
            .outside_capture()
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
            left.source_kind
                .precedence()
                .cmp(&right.source_kind.precedence())
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
                .outside_capture()
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
            .outside_capture()
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
        self.record_load_result(candidate, self.load_inner(candidate))
    }

    fn record_load_result(
        &self,
        candidate: &CatalogCandidate,
        result: Result<LoadedCatalogShard, CatalogError>,
    ) -> Result<LoadedCatalogShard, CatalogMiss> {
        match result {
            Ok(loaded) => {
                self.lookup_hits.fetch_add(1, Ordering::Relaxed);
                Ok(loaded)
            }
            Err(error) => {
                self.lookup_misses.fetch_add(1, Ordering::Relaxed);
                if let CatalogError::IndexReconciliationRequired {
                    manifest_digest,
                    shard_id,
                } = error
                {
                    return Err(CatalogMiss::IndexReconciliationRequired {
                        manifest_digest,
                        shard_id,
                    });
                }
                if matches!(error, CatalogError::Unavailable) {
                    return Err(CatalogMiss::NotFound);
                }
                let mut reason = error.to_string();
                if matches!(candidate.location, CatalogCandidateLocation::Durable) {
                    self.outside_capture()
                        .rejected_manifests
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

    /// SQL-boundary fixture reader. Product callers must use their active set's
    /// reader; a catalog itself does not establish activation membership.
    #[cfg(any(test, feature = "test-support"))]
    pub fn query_callable_values(
        &self,
        query: &CatalogCallableValuesQuery<'_>,
        limits: CatalogCallableValuesQueryLimits,
        cancellation: &CancellationToken,
    ) -> Result<CatalogCallableValuesQueryResult, CatalogError> {
        let connection = self.active_reader_connection()?;
        if limits.max_records == 0 || cancellation.is_cancelled() {
            return crate::analyzer::store::model_catalog::query_callable_values_on_connection(
                &connection,
                query,
                limits,
                cancellation,
            );
        }
        // The fixture explicitly selects this one source shard for a low-level
        // row question; it is not an activation fallback in product code.
        if !rows::select_active_shard(&connection, query.manifest_digest, query.shard_id)? {
            return Ok(
                crate::analyzer::store::model_catalog::callable_values_index_missing_result(limits),
            );
        }
        crate::analyzer::store::model_catalog::query_callable_values_on_connection(
            &connection,
            query,
            limits,
            cancellation,
        )
    }

    #[doc(hidden)]
    pub fn query_callable_values_on_connection(
        connection: &Connection,
        query: &CatalogCallableValuesQuery<'_>,
        limits: CatalogCallableValuesQueryLimits,
        cancellation: &CancellationToken,
    ) -> Result<CatalogCallableValuesQueryResult, CatalogError> {
        crate::analyzer::store::model_catalog::query_callable_values_on_connection(
            connection,
            query,
            limits,
            cancellation,
        )
    }

    #[doc(hidden)]
    pub fn callable_values_publication_present(
        connection: &Connection,
        manifest_digest: &str,
        shard_id: &str,
    ) -> Result<bool, CatalogError> {
        crate::analyzer::store::model_catalog::callable_values_publication_present(
            connection,
            manifest_digest,
            shard_id,
        )
    }

    #[doc(hidden)]
    pub fn callable_values_index_missing_result(
        limits: CatalogCallableValuesQueryLimits,
    ) -> CatalogCallableValuesQueryResult {
        crate::analyzer::store::model_catalog::callable_values_index_missing_result(limits)
    }

    #[doc(hidden)]
    pub fn read_go_source_from_connection(
        connection: &Connection,
        request: &CatalogGoSourceRequest<'_>,
        limits: CatalogGoSourceReadLimits,
        cancellation: &CancellationToken,
    ) -> Result<Option<CatalogExactGoSourceSet>, CatalogError> {
        crate::analyzer::store::model_catalog::read_go_source_from_connection(
            connection,
            request,
            limits,
            cancellation,
        )
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
                   UNION SELECT manifest_object_digest FROM catalog_packs
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
                 WHERE objects.stored_digest IN (
                   SELECT shards.stored_digest FROM catalog_pack_shards AS shards
                   JOIN catalog_activations AS active ON active.manifest_digest = shards.manifest_digest
                   UNION
                   SELECT packs.manifest_object_digest FROM catalog_packs AS packs
                   JOIN catalog_activations AS active ON active.manifest_digest = packs.manifest_digest
                 )",
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
            .outside_capture()
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
            .outside_capture()
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
            left.source_kind
                .precedence()
                .cmp(&right.source_kind.precedence())
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
        if crate::analyzer::Language::from_config_label(
            &self.candidate_manifest(candidate)?.language,
        )
        .and_then(brokk_bifrost_semantic::analyzer::semantic::languages::language_knowledge)
        .is_some_and(|knowledge| knowledge.models_compose_from_catalog_rows())
        {
            return self.load_row_metadata(candidate);
        }
        self.load_with_decoded_payload(candidate)
    }

    fn load_row_metadata(
        &self,
        candidate: &CatalogCandidate,
    ) -> Result<LoadedCatalogShard, CatalogError> {
        let loaded = match self.load_metadata_only(candidate) {
            Err(CatalogError::IndexReconciliationRequired { .. })
                if self.mode == CatalogOpenMode::ReadWrite =>
            {
                // Durable loads reconcile under their lease. Session sources
                // have no durable object and publish into their own database.
                let decoded = self.load_decoded(candidate)?;
                if matches!(candidate.location, CatalogCandidateLocation::Session { .. }) {
                    let mut session = self
                        .outside_capture()
                        .session_catalog
                        .lock()
                        .expect("session semantic catalog mutex poisoned");
                    let connection = &mut session
                        .as_mut()
                        .expect("registered session catalog exists")
                        .connection;
                    let transaction = connection
                        .transaction_with_behavior(TransactionBehavior::Immediate)
                        .map_err(|error| {
                            CatalogError::sqlite("begin row-backed session reconciliation", error)
                        })?;
                    rows::publish_semantic_rows(
                        &transaction,
                        &decoded.manifest,
                        decoded
                            .shard
                            .as_ref()
                            .expect("reconciliation decoded the shard"),
                    )?;
                    transaction.commit().map_err(|error| {
                        CatalogError::sqlite("commit row-backed session reconciliation", error)
                    })?;
                    self.record_mutation();
                }
                self.load_metadata_only(candidate)?
            }
            result => result?,
        };
        if self.mode == CatalogOpenMode::ReadWrite
            && matches!(candidate.location, CatalogCandidateLocation::Durable)
        {
            self.connection
                .lock()
                .expect("semantic-pack catalog connection mutex poisoned")
                .execute(
                    "UPDATE catalog_packs SET last_used_at = ?2 WHERE manifest_digest = ?1",
                    params![
                        candidate.manifest_digest,
                        crate::cache_db::now_unix_seconds()
                    ],
                )
                .map_err(|error| CatalogError::sqlite("touch loaded pack", error))?;
        }
        Ok(loaded)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn load_decoded_for_test(
        &self,
        candidate: &CatalogCandidate,
    ) -> Result<LoadedCatalogShard, CatalogMiss> {
        self.record_load_result(candidate, self.load_with_decoded_payload(candidate))
    }

    fn load_with_decoded_payload(
        &self,
        candidate: &CatalogCandidate,
    ) -> Result<LoadedCatalogShard, CatalogError> {
        let mut loaded = self.load_decoded(candidate)?;
        loaded.selectors = match candidate.location {
            CatalogCandidateLocation::Durable => {
                let connection = self
                    .connection
                    .lock()
                    .expect("semantic-pack catalog connection mutex poisoned");
                self.sql_statements.fetch_add(1, Ordering::Relaxed);
                Self::shard_selectors(&connection, candidate)?
            }
            CatalogCandidateLocation::Session { .. } => {
                let session = self
                    .outside_capture()
                    .session_catalog
                    .lock()
                    .expect("session semantic catalog mutex poisoned");
                self.sql_statements.fetch_add(1, Ordering::Relaxed);
                Self::shard_selectors(
                    &session
                        .as_ref()
                        .expect("registered session catalog exists")
                        .connection,
                    candidate,
                )?
            }
        };
        Ok(loaded)
    }

    /// Exercise metadata-only activation for languages not yet switched in product loading.
    /// A current marker certifies that all of this shard's rows were published.
    #[cfg(any(test, feature = "test-support"))]
    pub fn load_metadata_only_for_test(
        &self,
        candidate: &CatalogCandidate,
    ) -> Result<LoadedCatalogShard, CatalogMiss> {
        self.record_load_result(candidate, self.load_metadata_only(candidate))
    }

    fn candidate_manifest(
        &self,
        candidate: &CatalogCandidate,
    ) -> Result<Arc<CompiledPackManifest>, CatalogError> {
        match candidate.location {
            CatalogCandidateLocation::Durable => self.stored_manifest(&candidate.manifest_digest),
            CatalogCandidateLocation::Session {
                pack_ordinal,
                shard_ordinal,
            } => {
                let packs = self
                    .outside_capture()
                    .session_packs
                    .lock()
                    .expect("semantic-pack session mutex poisoned");
                let pack = packs.get(pack_ordinal).ok_or(CatalogError::Unavailable)?;
                let shard = pack
                    .shards
                    .get(shard_ordinal)
                    .ok_or(CatalogError::Unavailable)?;
                if pack.manifest.content_sha256 != candidate.manifest_digest
                    || shard.descriptor != candidate.descriptor
                {
                    return Err(CatalogError::Unavailable);
                }
                Ok(Arc::clone(&pack.manifest))
            }
        }
    }

    fn load_metadata_only(
        &self,
        candidate: &CatalogCandidate,
    ) -> Result<LoadedCatalogShard, CatalogError> {
        let manifest = self.candidate_manifest(candidate)?;
        let (selectors, has_callable_values) = match candidate.location {
            CatalogCandidateLocation::Durable => {
                self.validate_stored_python_profile_pack(&manifest)?;
                self.validated_manifest_inventory(&manifest)?;
                let connection = self
                    .connection
                    .lock()
                    .expect("semantic-pack catalog connection mutex poisoned");
                let selectors = Self::shard_selectors(&connection, candidate)?;
                let presence = self.metadata_only_presence(&connection, candidate)?;
                (selectors, presence)
            }
            CatalogCandidateLocation::Session { .. } => {
                let session = self
                    .outside_capture()
                    .session_catalog
                    .lock()
                    .expect("session semantic catalog mutex poisoned");
                let connection = &session
                    .as_ref()
                    .expect("registered session catalog exists")
                    .connection;
                let selectors = Self::shard_selectors(connection, candidate)?;
                let presence = self.metadata_only_presence(connection, candidate)?;
                (selectors, presence)
            }
        };
        Ok(LoadedCatalogShard {
            manifest,
            descriptor: candidate.descriptor.clone(),
            selectors,
            shard: None,
            has_callable_values,
            source_kind: candidate.source_kind,
            source_id: candidate.source_id.clone(),
        })
    }

    fn metadata_only_presence(
        &self,
        connection: &Connection,
        candidate: &CatalogCandidate,
    ) -> Result<bool, CatalogError> {
        self.sql_statements.fetch_add(2, Ordering::Relaxed);
        connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM catalog_semantic_payload_families AS family
                  WHERE family.shard_key=marker.shard_key AND family.family='callable_values')
             FROM catalog_semantic_rows_indexed_shards AS marker
             JOIN catalog_packs AS pack USING (manifest_digest)
             WHERE pack.state = 'verified' AND marker.manifest_digest = ?1
               AND marker.shard_id = ?2 AND marker.index_version = 4",
                params![candidate.manifest_digest, candidate.shard_id,],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| CatalogError::sqlite("load metadata-only shard marker", error))?
            .ok_or_else(|| CatalogError::IndexReconciliationRequired {
                manifest_digest: candidate.manifest_digest.clone(),
                shard_id: candidate.shard_id.clone(),
            })
    }

    fn shard_selectors(
        connection: &Connection,
        candidate: &CatalogCandidate,
    ) -> Result<Vec<ActivationSelector>, CatalogError> {
        let mut statement = connection
            .prepare_cached(
                "SELECT selector_json FROM catalog_selectors
             WHERE manifest_digest=?1 AND shard_id=?2 ORDER BY selector_ordinal",
            )
            .map_err(|error| CatalogError::sqlite("prepare full shard selectors", error))?;
        let rows = statement
            .query_map(
                params![candidate.manifest_digest, candidate.shard_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .map_err(|error| CatalogError::sqlite("query full shard selectors", error))?;
        rows.map(|row| {
            let json =
                row.map_err(|error| CatalogError::sqlite("read full shard selector", error))?;
            serde_json::from_slice(&json)
                .map_err(|error| CatalogError::Integrity(error.to_string()))
        })
        .collect()
    }

    fn load_decoded(
        &self,
        candidate: &CatalogCandidate,
    ) -> Result<LoadedCatalogShard, CatalogError> {
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
        self.validate_stored_python_profile_pack(&manifest)?;
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
        let limits_digest = decode_limits_digest(&self.options.decode_limits);
        self.sql_statements.fetch_add(1, Ordering::Relaxed);
        let certified: bool = connection
            .query_row(
                CERTIFIED_SHARD_SQL,
                params![
                    manifest.content_sha256,
                    candidate.shard_id,
                    SHARD_VALIDATION_VERSION,
                    limits_digest
                ],
                |row| row.get(0),
            )
            .map_err(|error| CatalogError::sqlite("lookup shard validation", error))?;
        if self.mode == CatalogOpenMode::ReadOnly {
            let indexed: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1
                         FROM catalog_semantic_rows_indexed_shards WHERE
                         manifest_digest=?1 AND shard_id=?2 AND index_version=4)",
                    params![candidate.manifest_digest, candidate.shard_id],
                    |row| row.get(0),
                )
                .map_err(|error| CatalogError::sqlite("check read-only semantic rows", error))?;
            if !indexed {
                return Err(CatalogError::IndexReconciliationRequired {
                    manifest_digest: candidate.manifest_digest.clone(),
                    shard_id: candidate.shard_id.clone(),
                });
            }
        }
        drop(connection);
        self.object_reads.fetch_add(1, Ordering::Relaxed);
        let bytes = storage::read(
            &self.root,
            &row.0,
            &candidate.descriptor.stored_sha256,
            row.1,
        )?;
        self.validated_manifest_inventory(&manifest)?;
        let shard = if certified {
            crate::analyzer::semantic_model::artifact::hydrate_certified_shard(
                &manifest,
                &candidate.descriptor,
                &bytes,
                &self.options.decode_limits,
            )
            .map_err(|error| CatalogError::Artifact(error.to_string()))?
        } else {
            let shard = self.decode_stored_shard(&manifest, &candidate.descriptor, &bytes)?;
            if self.mode == CatalogOpenMode::ReadWrite {
                let connection = self
                    .connection
                    .lock()
                    .expect("semantic-pack catalog connection mutex poisoned");
                record_shard_validation(
                    &connection,
                    &manifest.content_sha256,
                    &candidate.shard_id,
                    &limits_digest,
                )?;
            }
            shard
        };
        if self.mode == CatalogOpenMode::ReadWrite {
            let mut connection = self
                .connection
                .lock()
                .expect("semantic-pack catalog connection mutex poisoned");
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|error| {
                    CatalogError::sqlite("begin callable-value load reconciliation", error)
                })?;
            let indexed: bool = transaction
                .query_row(
                    "SELECT EXISTS( SELECT 1
                         FROM catalog_semantic_rows_indexed_shards WHERE
                         manifest_digest = ?1 AND shard_id = ?2 AND index_version =
                         4 )",
                    params![&candidate.manifest_digest, &candidate.shard_id],
                    |row| row.get(0),
                )
                .map_err(|error| CatalogError::sqlite("check callable-value load index", error))?;
            if !indexed {
                rows::publish_semantic_rows(&transaction, &manifest, &shard)?;
            }
            transaction.commit().map_err(|error| {
                CatalogError::sqlite("commit callable-value load reconciliation", error)
            })?;
            if !indexed {
                self.record_mutation();
            }
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
            descriptor: candidate.descriptor.clone(),
            selectors: Vec::new(),
            has_callable_values: shard.callable_values().is_some(),
            shard: Some(shard),
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
            .outside_capture()
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
            descriptor: candidate.descriptor.clone(),
            selectors: Vec::new(),
            has_callable_values: decoded.callable_values().is_some(),
            shard: Some(decoded),
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
                    .prepare(&format!(
                        "SELECT objects.stored_digest, objects.relative_path, objects.stored_size
                         FROM catalog_objects AS objects
                         WHERE objects.verified_at <= ?1
                           AND NOT {OBJECT_LINKED}
                           AND NOT EXISTS(
                             SELECT 1 FROM catalog_install_object_reservations AS reservations
                             WHERE reservations.stored_digest = objects.stored_digest
                               AND reservations.expires_at > ?2
                           )
                         ORDER BY objects.verified_at, objects.stored_digest
                         LIMIT ?3"
                    ))
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
                    &format!(
                        "SELECT EXISTS(SELECT 1 FROM catalog_objects AS objects
                       WHERE objects.stored_digest = ?1 AND ({OBJECT_LINKED} OR EXISTS(
                         SELECT 1 FROM catalog_install_object_reservations
                         WHERE stored_digest = ?1 AND expires_at > ?2
                       )))"
                    ),
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
                    &format!(
                        "DELETE FROM catalog_objects AS objects
                     WHERE stored_digest = ?1 AND NOT {OBJECT_LINKED}"
                    ),
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

    /// Whether this catalog handle may write catalog rows.
    ///
    /// Optional accelerator work asks first, so a read-only catalog does not
    /// report a failure for work it was never able to do.
    pub fn is_writable(&self) -> bool {
        self.mode == CatalogOpenMode::ReadWrite
    }
}

pub(crate) fn acquisition_source_state_digest(sources: &[AcquisitionReceiptSource]) -> String {
    let mut hasher = CanonicalHasher::new(ACQUISITION_SOURCE_STATE_DOMAIN);
    hasher.sequence("sources", sources, |hasher, source| {
        hasher.field("release_digest", source.release_digest.as_bytes());
        hasher.field("manifest_digest", source.manifest_digest.as_bytes());
        hasher.field("source_kind", source.source.kind.as_str().as_bytes());
        hasher.field("source_id", source.source.source_id.as_bytes());
    });
    lower_hex_string(&hasher.finish())
}

pub(crate) fn receipt_source_state_digest(
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
                    pack.state
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
            ))
        })
        .map_err(|error| CatalogError::sqlite("query acquisition receipt source proof", error))?;
    let mut sources = Vec::new();
    for row in rows {
        let (manifest_digest, source_kind, source_id, state) = row.map_err(|error| {
            CatalogError::sqlite("read acquisition receipt source proof", error)
        })?;
        if state.as_deref() != Some("verified") {
            return Ok(None);
        }
        let Some(manifest_bytes) = read_available_manifest_on(root, connection, &manifest_digest)?
        else {
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

pub(crate) fn insert_source(
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

pub(crate) fn session_activation_kind(
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

pub(crate) fn release_leases(leases: &mut Vec<CatalogLease<'_>>) -> Result<(), CatalogError> {
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

#[cfg(test)]
pub(crate) mod python_profile_reopen_tests {

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogCandidate;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogCandidateLocation;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogOpenMode;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogOptions;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogPackSourceKind;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::DurablePackSource;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::DurablePackSourceKind;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::insert_manifest;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::insert_object;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::insert_shard;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::storage;

    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CSMI_PYTHON_PROFILE_ID;

    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CSMI_PYTHON_PROFILE_SCHEMA;

    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CSMI_PYTHON_PROFILE_VERSION;

    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::validate::CsmiVocabularySupport;

    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::import::import_logical_csmi_pack;

    use brokk_bifrost_analysis::analyzer::semantic_model::compiler::CompilerOptions;

    use brokk_bifrost_analysis::analyzer::semantic_model::compiler::CompressionPolicy;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::PayloadKind;
    use rusqlite::TransactionBehavior;

    #[test]
    fn old_verified_python_pack_revalidates_all_shards_before_first_load() {
        let source = include_bytes!("../csmi/fixtures/python-distribution-beautifulsoup4.json");
        let portable =
            brokk_bifrost_analysis::analyzer::semantic_model::csmi::tests::logical_pack_from_semantic(source);
        let support = CsmiVocabularySupport::support(
            CSMI_PYTHON_PROFILE_ID,
            CSMI_PYTHON_PROFILE_VERSION,
            CSMI_PYTHON_PROFILE_SCHEMA,
        );
        let imported =
            import_logical_csmi_pack(&portable, &support, &CompilerOptions::default()).unwrap();
        let mut old_pack = imported
            .compile(&CompilerOptions {
                compression: CompressionPolicy::AlwaysRaw,
                ..CompilerOptions::default()
            })
            .unwrap();
        let valid_pack = old_pack.clone();
        brokk_bifrost_analysis::analyzer::semantic_model::csmi::tests::rewrite_raw_declaration_shard(
            &mut old_pack,
            |types, _| {
                for fact in types {
                    if let brokk_bifrost_analysis::analyzer::semantic_model::Locator::Interchange {
                        profile_evidence,
                        ..
                    } = &mut fact.locator
                    {
                        *profile_evidence = None;
                    }
                }
            },
        );
        let root = tempfile::tempdir().unwrap();
        let catalog = SemanticPackCatalog::open(
            root.path(),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        catalog
            .install(
                &valid_pack,
                &DurablePackSource {
                    kind: DurablePackSourceKind::Installed,
                    source_id: "valid-python-distribution".to_owned(),
                },
            )
            .unwrap();
        assert!(
            catalog
                .install(
                    &old_pack,
                    &DurablePackSource {
                        kind: DurablePackSourceKind::Installed,
                        source_id: "rejected-by-current-admission".to_owned(),
                    },
                )
                .is_err()
        );
        // Recreate only the rows an older validator would have marked
        // verified. Every object and manifest digest is internally valid.
        let published = old_pack
            .shards
            .iter()
            .map(|shard| {
                storage::publish(root.path(), &shard.descriptor.stored_sha256, &shard.bytes)
                    .map(|(path, _)| path)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let now = brokk_bifrost_core::cache_db::now_unix_seconds();
        {
            let mut connection = catalog.connection.lock().unwrap();
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            let digest =
                crate::analyzer::semantic_model::csmi::sha256_hex(&old_pack.manifest_bytes);
            let (path, _) =
                storage::publish(root.path(), &digest, &old_pack.manifest_bytes).unwrap();
            let size = old_pack.manifest_bytes.len() as u64;
            insert_object(
                &transaction,
                &digest,
                size,
                size,
                crate::analyzer::semantic_model::ArtifactEncoding::Raw,
                &path,
                now,
            )
            .unwrap();
            insert_manifest(&transaction, &old_pack.manifest, &digest, now).unwrap();
            for (ordinal, (shard, path)) in old_pack.shards.iter().zip(&published).enumerate() {
                insert_object(
                    &transaction,
                    &shard.descriptor.stored_sha256,
                    shard.descriptor.stored_size,
                    shard.descriptor.raw_size,
                    shard.descriptor.encoding,
                    path,
                    now,
                )
                .unwrap();
                insert_shard(
                    &transaction,
                    &old_pack.manifest.content_sha256,
                    ordinal,
                    &shard.descriptor,
                )
                .unwrap();
            }
            transaction.commit().unwrap();
        }
        drop(catalog);
        let reopened = SemanticPackCatalog::open(
            root.path(),
            CatalogOpenMode::ReadOnly,
            CatalogOptions::default(),
        )
        .unwrap();
        let valid_descriptor = valid_pack
            .manifest
            .shards
            .iter()
            .find(|descriptor| descriptor.payload_kind == PayloadKind::ProcedureSummaries)
            .unwrap()
            .clone();
        let valid_candidate = CatalogCandidate {
            manifest_digest: valid_pack.manifest.content_sha256.clone(),
            shard_id: valid_descriptor.shard_id.clone(),
            descriptor: valid_descriptor,
            completeness: valid_pack.manifest.completeness,
            source_kind: CatalogPackSourceKind::Installed,
            source_id: "valid-python-distribution".to_owned(),
            location: CatalogCandidateLocation::Durable,
        };
        reopened.load_durable(&valid_candidate).unwrap();
        assert!(
            reopened
                .validated_python_profile_packs
                .lock()
                .unwrap()
                .contains(&valid_candidate.manifest_digest)
        );
        let descriptor = old_pack
            .manifest
            .shards
            .iter()
            .find(|descriptor| descriptor.payload_kind == PayloadKind::ProcedureSummaries)
            .unwrap()
            .clone();
        let candidate = CatalogCandidate {
            manifest_digest: old_pack.manifest.content_sha256.clone(),
            shard_id: descriptor.shard_id.clone(),
            descriptor,
            completeness: old_pack.manifest.completeness,
            source_kind: CatalogPackSourceKind::Installed,
            source_id: "old-verified-row".to_owned(),
            location: CatalogCandidateLocation::Durable,
        };
        for _ in 0..2 {
            let error = reopened.load_durable(&candidate).unwrap_err();
            assert!(format!("{error:?}").contains("python.profile_evidence_count"));
            assert!(
                !reopened
                    .validated_python_profile_packs
                    .lock()
                    .unwrap()
                    .contains(&candidate.manifest_digest)
            );
        }
    }
}

#[cfg(test)]
pub(crate) mod callable_value_catalog_tests {
    use crate::analyzer::semantic_model::catalog::go_extraction_support_22::*;
    use crate::analyzer::semantic_model::catalog::{CatalogError, CatalogMiss};

    use rusqlite::params;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogCallableValuesQueryGap;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogCallableValuesQueryLimits;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogCallableValuesQuestion;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogCandidate;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogCandidateLocation;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogOpenMode;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogOptions;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogPackSourceKind;

    use std::sync::atomic::Ordering;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SessionPackSource;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SessionPackSourceKind;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiCallableValuesArgument;

    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiCallableValuesPayload;

    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiCallableValuesShape;

    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiCoverageStatus;

    #[test]
    fn sql_questions_preserve_alternatives_unknowns_scoped_coverage_and_exact_shape() {
        let (catalog, pack) = install_fixture();
        let cancellation = CancellationToken::new();
        let returned = catalog
            .query_callable_values(
                &query(
                    &pack,
                    CatalogCallableValuesQuestion::ReturnedCallable { result: 0 },
                ),
                CatalogCallableValuesQueryLimits { max_records: 4 },
                &cancellation,
            )
            .unwrap();
        assert_eq!(returned.facts.len(), 2, "alternatives are retained");
        assert_eq!(returned.coverage_claims.len(), 1);
        assert_eq!(returned.examined_records, 3);
        assert_eq!(returned.executable_coverage, CsmiCoverageStatus::Unknown);
        assert_eq!(
            returned.coverage_claims[0].coverage.status,
            CsmiCoverageStatus::Partial
        );

        let callback = callback_location(0);
        let callbacks = catalog
            .query_callable_values(
                &query(
                    &pack,
                    CatalogCallableValuesQuestion::CallbackInvocation {
                        callback: &callback,
                        shape: CsmiCallableValuesShape {
                            parameters: 1,
                            results: 1,
                        },
                    },
                ),
                CatalogCallableValuesQueryLimits { max_records: 2 },
                &cancellation,
            )
            .unwrap();
        assert_eq!(callbacks.facts.len(), 1);
        assert_eq!(callbacks.coverage_claims.len(), 1);
        let CsmiCallableValuesPayload::CallbackInvocation { arguments, .. } =
            &callbacks.facts[0].fact.payload
        else {
            panic!("callback question returned a non-callback fact");
        };
        assert!(matches!(
            arguments[0],
            CsmiCallableValuesArgument::Unknown { .. }
        ));
        assert_eq!(callbacks.executable_coverage, CsmiCoverageStatus::Unknown);

        let wrong_shape = catalog
            .query_callable_values(
                &query(
                    &pack,
                    CatalogCallableValuesQuestion::CallbackInvocation {
                        callback: &callback,
                        shape: CsmiCallableValuesShape {
                            parameters: 2,
                            results: 1,
                        },
                    },
                ),
                CatalogCallableValuesQueryLimits { max_records: 2 },
                &cancellation,
            )
            .unwrap();
        assert!(wrong_shape.facts.is_empty());
        assert_eq!(wrong_shape.coverage_claims.len(), 1);

        let wrong_location = callback_location(1);
        let near_miss = catalog
            .query_callable_values(
                &query(
                    &pack,
                    CatalogCallableValuesQuestion::CallbackInvocation {
                        callback: &wrong_location,
                        shape: CsmiCallableValuesShape {
                            parameters: 1,
                            results: 1,
                        },
                    },
                ),
                CatalogCallableValuesQueryLimits { max_records: 2 },
                &cancellation,
            )
            .unwrap();
        assert!(near_miss.facts.is_empty());
        assert_eq!(near_miss.coverage_claims.len(), 1);

        let bounded = catalog
            .query_callable_values(
                &query(
                    &pack,
                    CatalogCallableValuesQuestion::ReturnedCallable { result: 0 },
                ),
                CatalogCallableValuesQueryLimits { max_records: 1 },
                &cancellation,
            )
            .unwrap();
        assert_eq!(bounded.facts.len(), 1);
        assert_eq!(
            bounded.gap,
            Some(CatalogCallableValuesQueryGap::RecordBudgetExhausted { max_records: 1 })
        );

        let canceled = CancellationToken::new();
        canceled.cancel();
        let result = catalog
            .query_callable_values(
                &query(
                    &pack,
                    CatalogCallableValuesQuestion::ReturnedCallable { result: 0 },
                ),
                CatalogCallableValuesQueryLimits { max_records: 2 },
                &canceled,
            )
            .unwrap();
        assert_eq!(result.gap, Some(CatalogCallableValuesQueryGap::Cancelled));
        assert!(result.facts.is_empty());
    }

    #[test]
    fn session_sources_publish_queryable_sql_without_writing_read_only_main_catalog() {
        for (source_kind, source_id) in [
            (SessionPackSourceKind::Embedded, "embedded-session"),
            (
                SessionPackSourceKind::EphemeralWorkspace,
                "ephemeral-workspace-session",
            ),
        ] {
            let root = tempfile::tempdir().expect("session catalog root");
            drop(
                SemanticPackCatalog::open(
                    root.path(),
                    CatalogOpenMode::ReadWrite,
                    CatalogOptions::default(),
                )
                .expect("initialize main catalog"),
            );
            let catalog = SemanticPackCatalog::open(
                root.path(),
                CatalogOpenMode::ReadOnly,
                CatalogOptions::default(),
            )
            .expect("open read-only main catalog");
            let pack = callable_pack();
            catalog
                .register_session_pack(
                    &pack,
                    &SessionPackSource {
                        kind: source_kind,
                        source_id: source_id.to_owned(),
                    },
                )
                .expect("register validated session pack");
            catalog
                .register_session_pack(
                    &pack,
                    &SessionPackSource {
                        kind: source_kind,
                        source_id: format!("{source_id}-second"),
                    },
                )
                .expect("register the same populated publication under another source ID");

            let result = catalog
                .query_callable_values(
                    &query(
                        &pack,
                        CatalogCallableValuesQuestion::ReturnedCallable { result: 0 },
                    ),
                    CatalogCallableValuesQueryLimits { max_records: 4 },
                    &CancellationToken::new(),
                )
                .expect("query session SQL sidecar");
            assert_eq!(result.facts.len(), 2, "{source_kind:?}");
            assert_eq!(result.coverage_claims.len(), 1, "{source_kind:?}");
            assert_eq!(result.gap, None, "{source_kind:?}");
            assert_eq!(result.executable_coverage, CsmiCoverageStatus::Unknown);
            assert_eq!(
                catalog
                    .connection
                    .lock()
                    .unwrap()
                    .query_row("SELECT count(*) FROM catalog_packs", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .unwrap(),
                0,
                "session registration never installs into the read-only durable catalog"
            );
            let session_catalog = catalog.session_catalog.lock().unwrap();
            assert_eq!(
                session_catalog
                    .as_ref()
                    .unwrap()
                    .connection
                    .query_row(
                        "SELECT count(*) FROM catalog_semantic_rows_indexed_shards
                         WHERE manifest_digest = ?1 AND shard_id = ?2",
                        params![
                            &pack.manifest.content_sha256,
                            &pack.manifest.shards[0].shard_id
                        ],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                1,
                "session SQL marker is committed with the facts"
            );
        }
    }

    #[test]
    fn rust_metadata_loading_reconciles_once_and_read_only_requires_reindex() {
        use crate::analyzer::semantic_model::SourceFormat;
        use crate::analyzer::semantic_model::artifact::thread_shard_wire_read_count;
        use crate::analyzer::semantic_model::catalog::{DurablePackSource, DurablePackSourceKind};
        use crate::analyzer::semantic_model::compiler::{CompilerOptions, compile_source};
        let mut source: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../../testdata/semantic-model-packs/declarations-v1.json"
        ))
        .unwrap();
        source["language"] = "rust".into();
        let pack = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&source).unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap();
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        catalog
            .install(
                &pack,
                &DurablePackSource {
                    kind: DurablePackSourceKind::Installed,
                    source_id: "rust-reconciliation".into(),
                },
            )
            .unwrap();
        let candidate = CatalogCandidate {
            manifest_digest: pack.manifest.content_sha256.clone(),
            shard_id: pack.manifest.shards[0].shard_id.clone(),
            descriptor: pack.manifest.shards[0].clone(),
            completeness: pack.manifest.completeness,
            source_kind: CatalogPackSourceKind::Installed,
            source_id: "rust-reconciliation".into(),
            location: CatalogCandidateLocation::Durable,
        };
        catalog
            .connection
            .lock()
            .unwrap()
            .execute("DELETE FROM catalog_semantic_rows_indexed_shards", [])
            .unwrap();
        let read_only = SemanticPackCatalog::open(
            catalog.root(),
            CatalogOpenMode::ReadOnly,
            CatalogOptions::default(),
        )
        .unwrap();
        let before = thread_shard_wire_read_count();
        let miss = read_only.load(&candidate).unwrap_err();
        assert!(matches!(
            miss,
            CatalogMiss::IndexReconciliationRequired { .. }
        ));
        assert!(
            brokk_bifrost_semantic::analyzer::semantic_model::runtime::catalog_miss_reason(&miss)
                .contains("bifrost-semantic-pack reindex CATALOG")
        );
        assert_eq!(thread_shard_wire_read_count(), before);
        assert!(catalog.load(&candidate).unwrap().shard.is_none());
        assert_eq!(thread_shard_wire_read_count(), before + 1);
        assert!(catalog.load(&candidate).unwrap().shard.is_none());
        assert!(read_only.load(&candidate).unwrap().shard.is_none());
        assert_eq!(thread_shard_wire_read_count(), before + 1);
        catalog
            .register_compiled_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::EphemeralWorkspace,
                    source_id: "rust-session".into(),
                },
            )
            .unwrap();
        let mut candidate = candidate;
        candidate.location = CatalogCandidateLocation::Session {
            pack_ordinal: 0,
            shard_ordinal: 0,
        };
        candidate.source_kind = CatalogPackSourceKind::EphemeralWorkspace;
        catalog
            .session_catalog
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .connection
            .execute("DELETE FROM catalog_semantic_rows_indexed_shards", [])
            .unwrap();
        let before = thread_shard_wire_read_count();
        assert!(catalog.load(&candidate).unwrap().shard.is_none());
        assert_eq!(thread_shard_wire_read_count(), before + 1);
        assert!(catalog.load(&candidate).unwrap().shard.is_none());
        assert_eq!(thread_shard_wire_read_count(), before + 1);
    }

    #[test]
    fn reindex_restores_missing_semantic_rows_and_is_idempotent() {
        let (catalog, pack) = install_fixture();
        let count = |table: &str| {
            catalog
                .connection
                .lock()
                .unwrap()
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap()
        };
        assert!(count("catalog_declaration_members") > 0);
        catalog
            .connection
            .lock()
            .unwrap()
            .execute("DELETE FROM catalog_semantic_rows_indexed_shards", [])
            .unwrap();
        assert_eq!(count("catalog_declaration_members"), 0);
        assert_eq!(count("catalog_callable_value_facts"), 0);
        assert_eq!(
            catalog.reindex(&CancellationToken::new()).unwrap(),
            pack.manifest.shards.len()
        );
        assert!(count("catalog_declaration_members") > 0);
        assert!(count("catalog_callable_value_facts") > 0);
        assert_eq!(catalog.reindex(&CancellationToken::new()).unwrap(), 0);
    }

    #[test]
    fn read_only_activation_requires_reindex_without_quarantining_or_decoding() {
        let (catalog, pack) = install_fixture();
        catalog
            .connection
            .lock()
            .unwrap()
            .execute("DELETE FROM catalog_semantic_rows_indexed_shards", [])
            .unwrap();
        let read_only = SemanticPackCatalog::open(
            catalog.root(),
            CatalogOpenMode::ReadOnly,
            CatalogOptions::default(),
        )
        .unwrap();
        let candidate = CatalogCandidate {
            manifest_digest: pack.manifest.content_sha256.clone(),
            shard_id: pack.manifest.shards[0].shard_id.clone(),
            descriptor: pack.manifest.shards[0].clone(),
            completeness: pack.manifest.completeness,
            source_kind: CatalogPackSourceKind::Installed,
            source_id: "callable-values-fixture".to_owned(),
            location: CatalogCandidateLocation::Durable,
        };
        let miss = read_only.load(&candidate).unwrap_err();
        assert_eq!(
            miss,
            CatalogMiss::IndexReconciliationRequired {
                manifest_digest: candidate.manifest_digest.clone(),
                shard_id: candidate.shard_id.clone()
            }
        );
        assert!(
            brokk_bifrost_semantic::analyzer::semantic_model::runtime::catalog_miss_reason(&miss)
                .contains("bifrost-semantic-pack reindex CATALOG")
        );
        assert_eq!(read_only.object_reads.load(Ordering::Relaxed), 0);
        assert!(read_only.rejected_manifests.lock().unwrap().is_empty());
        assert!(matches!(
            read_only.runtime_source_reader(std::iter::once((
                candidate.manifest_digest.as_str(),
                candidate.shard_id.as_str(),
                candidate.source_kind
            ))),
            Err(CatalogError::IndexReconciliationRequired { .. })
        ));
        assert_eq!(
            catalog
                .connection
                .lock()
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM catalog_packs WHERE state='quarantined'",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn legacy_missing_index_is_a_gap_until_bounded_normal_hydration_repairs_it() {
        let (catalog, pack) = install_fixture();
        let manifest = &pack.manifest.content_sha256;
        let shard = &pack.manifest.shards[0].shard_id;
        {
            let connection = catalog.connection.lock().unwrap();
            brokk_bifrost_semantic::analyzer::semantic_model::catalog::db::restore_version_26_fixture(&connection);
            // Recreate a populated v23 catalog without changing any retained
            // callable-value table or child table. Opening v25 must not decode.
            connection
                .execute_batch(
                    "PRAGMA foreign_keys=OFF;
                         DROP TRIGGER catalog_semantic_rows_delete_callable;",
                )
                .unwrap();
            let tables = connection
                .prepare("SELECT name FROM sqlite_schema WHERE type='table'")
                .unwrap()
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            for table in tables {
                if connection
                    .prepare(&format!("SELECT shard_key FROM {table} LIMIT 0"))
                    .is_ok()
                {
                    connection
                        .execute_batch(&format!("DROP TABLE {table}"))
                        .unwrap();
                }
            }
            connection
                .execute_batch(
                    "CREATE TABLE
                         catalog_callable_values_indexed_shards(manifest_digest
                         TEXT NOT NULL, shard_id TEXT NOT NULL, index_version
                         INTEGER NOT NULL, PRIMARY KEY(manifest_digest, shard_id),
                         FOREIGN KEY(manifest_digest, shard_id) REFERENCES
                         catalog_pack_shards(manifest_digest, shard_id) ON DELETE
                         CASCADE) STRICT; PRAGMA user_version=23; PRAGMA
                         foreign_keys=ON;",
                )
                .unwrap();
            assert!(
                connection
                    .query_row(
                        "SELECT count(*) FROM catalog_callable_value_facts",
                        [],
                        |row| row.get::<_, i64>(0)
                    )
                    .unwrap()
                    > 0
            );
        }
        let migrated = brokk_bifrost_semantic::analyzer::semantic_model::catalog::db::open(
            catalog.root(),
            CatalogOpenMode::ReadWrite,
        )
        .unwrap();
        assert_eq!(
            migrated
                .query_row(
                    "SELECT count(*) FROM catalog_semantic_rows_indexed_shards",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        assert_eq!(
            migrated
                .query_row(
                    "SELECT count(*) FROM catalog_callable_value_facts",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0,
            "v25 invalidates derived publications so exact presence is recovered by reconciliation"
        );
        drop(migrated);
        let object_reads = catalog.object_reads.load(Ordering::Relaxed);
        let no_budget = catalog
            .query_callable_values(
                &query(
                    &pack,
                    CatalogCallableValuesQuestion::ReturnedCallable { result: 0 },
                ),
                CatalogCallableValuesQueryLimits { max_records: 0 },
                &CancellationToken::new(),
            )
            .unwrap();
        assert_eq!(
            no_budget.gap,
            Some(CatalogCallableValuesQueryGap::RecordBudgetExhausted { max_records: 0 })
        );
        let no_index = catalog
            .query_callable_values(
                &query(
                    &pack,
                    CatalogCallableValuesQuestion::ReturnedCallable { result: 0 },
                ),
                CatalogCallableValuesQueryLimits { max_records: 4 },
                &CancellationToken::new(),
            )
            .unwrap();
        assert_eq!(
            no_index.gap,
            Some(CatalogCallableValuesQueryGap::IndexReconciliationRequired)
        );
        assert_eq!(catalog.object_reads.load(Ordering::Relaxed), object_reads);
        assert_eq!(
            catalog
                .connection
                .lock()
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM catalog_semantic_rows_indexed_shards
                     WHERE manifest_digest = ?1 AND shard_id = ?2",
                    params![manifest, shard],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0,
            "query demand does not repair by decoding an uncharged shard"
        );

        let candidate = CatalogCandidate {
            manifest_digest: manifest.clone(),
            shard_id: shard.clone(),
            descriptor: pack.manifest.shards[0].clone(),
            completeness: pack.manifest.completeness,
            source_kind: CatalogPackSourceKind::Installed,
            source_id: "callable-values-fixture".to_owned(),
            location: CatalogCandidateLocation::Durable,
        };
        catalog
            .load(&candidate)
            .expect("normal shard load succeeds");
        let repaired = catalog
            .query_callable_values(
                &query(
                    &pack,
                    CatalogCallableValuesQuestion::ReturnedCallable { result: 0 },
                ),
                CatalogCallableValuesQueryLimits { max_records: 4 },
                &CancellationToken::new(),
            )
            .unwrap();
        assert_eq!(repaired.facts.len(), 2);
        assert_eq!(repaired.coverage_claims.len(), 1);
        assert_eq!(repaired.gap, None);
    }
}

#[cfg(test)]
pub(crate) mod generated_production_cache_version_tests {

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::generated_production_digest_for_cache_version;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::verify_recorded_generated_production_digest;
    #[cfg(test)]
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    fn migrated_catalog_preserves_old_epochs_and_reuses_the_new_production() {
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogCoordinate;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogOpenMode;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogOptions;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::GeneratedProductionKey;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackSelectorQuery;

        use brokk_bifrost_analysis::analyzer::semantic_model::compiler::CompilerOptions;

        use brokk_bifrost_analysis::analyzer::semantic_model::source::SourceFormat;

        use brokk_bifrost_analysis::analyzer::semantic_model::compiler::compile_source;

        let source = serde_json::json!({
            "schema_version": 2,
            "pack_id": "fixture.generated",
            "version": "1.0.0",
            "producer": {"name": "fixture-producer", "version": "1.0.0"},
            "language": "java", "ecosystem": "jvm",
            "compatibility": {"bifrost": ">=0.8.0, <1.0.0", "toolchains": []},
            "provenance": {"source": "fixture"}, "license": "Apache-2.0",
            "completeness": "complete",
            "safety": {"generated_code_only": false, "review_required": false},
            "shards": [{
                "id": "declarations", "activation": [{"package": {"name": "fixture", "version": "=1.0.0"}}],
                "payload": {"kind": "declaration_facts", "types": [{
                    "id": "fixture.type", "name": "fixture.Type", "type_kind": "class", "visibility": "public",
                    "locator": {"kind": "artifact", "path": "fixture.jar", "symbol": "fixture/Type.class"}
                }], "members": [], "relations": []}
            }]
        });
        let old_pack = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&source).unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap();
        let mut revised = source;
        revised["completeness"] = serde_json::json!("partial");
        let new_pack = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&revised).unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap();
        let key =
            GeneratedProductionKey::new("a".repeat(64), "fixture-producer", "1.0.0", 2).unwrap();
        let mut old_key = key.clone();
        old_key.production_digest = generated_production_digest_for_cache_version(
            key.input_digest(),
            key.producer_name(),
            key.producer_version(),
            key.schema_version(),
            brokk_bifrost_analysis::analyzer::semantic_model::catalog::GENERATED_PRODUCTION_CACHE_VERSION - 1,
        );
        let root = tempfile::tempdir().unwrap();
        let catalog = SemanticPackCatalog::open(
            root.path(),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        catalog.install_generated(&old_key, &old_pack).unwrap();
        let retained_key =
            GeneratedProductionKey::new("b".repeat(64), "fixture-producer", "1.0.0", 2).unwrap();
        catalog.install_generated(&retained_key, &old_pack).unwrap();
        let source_rows = |catalog: &SemanticPackCatalog| {
            catalog
                .connection
                .lock()
                .unwrap()
                .prepare(
                    "SELECT manifest_digest, source_kind, source_id, installed_at
                     FROM catalog_sources
                     ORDER BY manifest_digest, source_kind, source_id",
                )
                .unwrap()
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        };
        let original_sources = source_rows(&catalog);
        assert_eq!(original_sources.len(), 2);
        brokk_bifrost_semantic::analyzer::semantic_model::catalog::db::restore_version_26_fixture(
            &catalog.connection.lock().unwrap(),
        );
        // Recreate schema 8, with both an old and a still-current digest.
        catalog
            .connection
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE UNIQUE INDEX
                         catalog_generated_productions_identity ON
                         catalog_generated_productions(input_digest, producer_name,
                         producer_version, schema_version); ALTER TABLE
                         catalog_generated_productions DROP COLUMN
                         generated_cache_version; DROP VIEW
                         catalog_verified_generated_productions; DROP TRIGGER
                         catalog_semantic_rows_delete_callable; DROP TABLE
                         catalog_declaration_names; DROP TABLE
                         catalog_member_aliases; DROP TABLE
                         catalog_runtime_exposures; DROP TABLE
                         catalog_runtime_behaviors; DROP TABLE
                         catalog_declaration_types; DROP TABLE
                         catalog_declaration_members; DROP TABLE
                         catalog_declaration_relations; DROP TABLE
                         catalog_generator_rules; DROP TABLE
                         catalog_procedure_summaries; DROP TABLE
                         catalog_collection_flows; DROP TABLE
                         catalog_conditional_type_refinements; DROP TABLE
                         catalog_deferred_yields; DROP TABLE
                         catalog_runtime_value_payloads; DROP TABLE
                         catalog_runtime_contract_payloads; DROP TABLE
                         catalog_shard_validations; DROP TABLE
                         catalog_anonymous_callable_signature_shapes; DROP TABLE
                         catalog_anonymous_callable_identity_anchors; DROP TABLE
                         catalog_anonymous_callable_identities; DROP TABLE
                         catalog_callable_value_coverage; DROP TABLE
                         catalog_callable_value_facts; DROP TABLE
                         catalog_semantic_payload_families; DROP TABLE
                         catalog_semantic_rows_indexed_shards; DROP TABLE
                         catalog_exact_go_package_files; DROP TABLE
                         catalog_exact_go_packages; DROP TABLE
                         catalog_exact_go_source_files; DROP TABLE
                         catalog_exact_go_source_sets; PRAGMA user_version = 8;",
            )
            .unwrap();
        drop(catalog);

        let catalog = SemanticPackCatalog::open(
            root.path(),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        assert_eq!(source_rows(&catalog), original_sources);
        let query = SemanticPackSelectorQuery {
            language: "java".to_owned(),
            ecosystem: "jvm".to_owned(),
            package: Some(CatalogCoordinate {
                name: "fixture".to_owned(),
                version: Some(semver::Version::new(1, 0, 0)),
            }),
            module: None,
            toolchain: None,
            target: None,
            configuration: None,
            artifact_sha256: None,
            bifrost_version: semver::Version::new(0, 12, 0),
        };
        assert!(
            catalog
                .generated_production(&retained_key)
                .unwrap()
                .is_some()
        );
        let candidates = catalog.candidates_bounded(&query, 1).unwrap();
        assert_eq!(candidates.len(), 1, "{candidates:?}");
        assert_eq!(candidates[0].source_id(), retained_key.source_id());
        let installed = catalog
            .install_generated(&key, &new_pack)
            .expect("new epoch coexists after migration");
        assert_eq!(
            catalog.generated_production(&key).unwrap().unwrap(),
            installed.production
        );
        assert!(
            catalog.install_generated(&key, &old_pack).is_err(),
            "one exact production key cannot change its output"
        );
        let historical_manifest: String = catalog.connection.lock().unwrap().query_row(
            "SELECT manifest_digest FROM catalog_generated_productions WHERE production_digest = ?1",
            [old_key.production_digest()], |row| row.get(0),
        ).unwrap();
        assert_eq!(historical_manifest, old_pack.manifest.content_sha256);
        let sources: std::collections::BTreeSet<_> = catalog
            .candidates(&query)
            .unwrap()
            .iter()
            .map(|candidate| candidate.source_id().to_owned())
            .collect();
        assert_eq!(
            sources,
            [key.source_id(), retained_key.source_id()]
                .into_iter()
                .collect()
        );
        drop(catalog);
        let reopened = SemanticPackCatalog::open(
            root.path(),
            CatalogOpenMode::ReadOnly,
            CatalogOptions::default(),
        )
        .unwrap();
        assert_eq!(
            reopened.generated_production(&key).unwrap().unwrap(),
            installed.production
        );
    }

    #[test]
    #[hardwon("#3357: startup cache reuse rejected verified entries after an epoch change")]
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

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CATALOG_SCHEMA_VERSION;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::default_semantic_pack_catalog_root_with_override;
    use std::ffi::OsString;
    use std::path::Path;

    #[test]
    #[hardwon("be576f7e556b: a generated production cache epoch change reused an old identity")]
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
pub(crate) mod native_compatibility_catalog_tests {

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogCoordinate;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogOpenMode;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogOptions;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::DurablePackSource;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::DurablePackSourceKind;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackSelectorQuery;

    use brokk_bifrost_analysis::analyzer::semantic_model::compiler::CompilerOptions;

    use brokk_bifrost_analysis::analyzer::semantic_model::source::SourceFormat;

    use brokk_bifrost_analysis::analyzer::semantic_model::compiler::compile_source;
    #[cfg(test)]
    use brokk_bifrost_test_macros::hardwon;
    use semver::Version;

    fn compiled_pack(
        schema_version: u32,
    ) -> brokk_bifrost_analysis::analyzer::semantic_model::artifact::CompiledSemanticModelPack {
        let compatibility = if schema_version
            >= brokk_bifrost_analysis::analyzer::semantic_model::model::VERSION_INDEPENDENT_COMPATIBILITY_SCHEMA_VERSION
        {
            serde_json::json!({
                "toolchains": [{"name": "jdk", "requirement": ">=21.0.0, <22.0.0"}]
            })
        } else {
            serde_json::json!({
                "bifrost": ">=0.8.0, <1.0.0",
                "toolchains": [{"name": "jdk", "requirement": ">=21.0.0, <22.0.0"}]
            })
        };
        let source = serde_json::json!({
            "schema_version": schema_version,
            "pack_id": format!("fixture.schema-{schema_version}"),
            "version": "1.0.0",
            "producer": {"name": "fixture-producer", "version": "1.0.0"},
            "language": "java",
            "ecosystem": "jvm",
            "compatibility": compatibility,
            "provenance": {"source": "catalog-compatibility-test"},
            "license": "Apache-2.0",
            "completeness": "complete",
            "safety": {"generated_code_only": false, "review_required": false},
            "shards": [{
                "id": "declarations",
                "activation": [{"package": {"name": "fixture", "version": "=1.0.0"}}],
                "payload": {"kind": "declaration_facts", "types": [{
                    "id": "fixture.type",
                    "name": "fixture.Type",
                    "type_kind": "class",
                    "visibility": "public",
                    "locator": {"kind": "artifact", "path": "fixture.jar", "symbol": "fixture/Type.class"}
                }], "members": [], "relations": []}
            }]
        });
        compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&source).unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap()
    }

    fn query(engine_version: &str, toolchain_version: &str) -> SemanticPackSelectorQuery {
        SemanticPackSelectorQuery {
            language: "java".to_owned(),
            ecosystem: "jvm".to_owned(),
            package: Some(CatalogCoordinate {
                name: "fixture".to_owned(),
                version: Some(Version::parse("1.0.0").unwrap()),
            }),
            module: None,
            toolchain: Some(CatalogCoordinate {
                name: "jdk".to_owned(),
                version: Some(Version::parse(toolchain_version).unwrap()),
            }),
            target: None,
            configuration: None,
            artifact_sha256: None,
            bifrost_version: Version::parse(engine_version).unwrap(),
        }
    }

    #[test]
    fn cached_manifest_content_does_not_authorize_a_quarantined_catalog_candidate() {
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let pack = compiled_pack(8);
        catalog
            .install(
                &pack,
                &DurablePackSource {
                    kind: DurablePackSourceKind::Installed,
                    source_id: "memo-fixture".into(),
                },
            )
            .unwrap();
        let candidate = catalog
            .candidates(&query("9.0.0", "21.0.2"))
            .unwrap()
            .remove(0);
        let first = catalog
            .stored_manifest(candidate.manifest_digest())
            .unwrap();
        let decodes = catalog.manifest_decode_count();
        let second = catalog
            .stored_manifest(candidate.manifest_digest())
            .unwrap();
        assert!(
            std::sync::Arc::ptr_eq(&first, &second),
            "the second read must hit the immutable decode memo"
        );
        assert_eq!(second.content_sha256, candidate.manifest_digest());
        assert_eq!(catalog.manifest_decode_count(), decodes);
        // Lazy durable loads still consult current pack/shard admission after
        // obtaining the immutable manifest, even when its decode is retained.
        catalog
            .quarantine(
                candidate.manifest_digest(),
                "fixture admission changed",
                &super::CatalogError::Unavailable,
            )
            .unwrap();
        assert!(matches!(
            catalog.load_durable(&candidate),
            Err(super::CatalogError::Unavailable)
        ));
        assert!(
            catalog
                .candidates(&query("9.0.0", "21.0.2"))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    #[hardwon("#3815: native pack admission incorrectly inherited the legacy engine-version gate")]
    fn schema_eight_ignores_engine_version_while_legacy_range_still_filters() {
        let root = tempfile::tempdir().unwrap();
        let root_path = std::fs::canonicalize(root.path()).unwrap();
        let catalog = SemanticPackCatalog::open(
            &root_path,
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        let legacy = compiled_pack(7);
        let native = compiled_pack(8);
        let source = |source_id: &str| DurablePackSource {
            kind: DurablePackSourceKind::Installed,
            source_id: source_id.to_owned(),
        };
        catalog.install(&legacy, &source("legacy")).unwrap();
        catalog.install(&native, &source("native")).unwrap();
        let repeated = catalog.install(&native, &source("native")).unwrap();
        assert!(
            !repeated.inserted_manifest,
            "exact verified native install is reusable"
        );

        let candidates = catalog.candidates(&query("9.0.0", "21.0.2")).unwrap();
        assert_eq!(candidates.len(), 1, "{candidates:?}");
        assert_eq!(
            candidates[0].manifest_digest(),
            native.manifest.content_sha256.as_str()
        );
        assert!(
            catalog
                .version_near_misses(&query("9.0.0", "21.0.2"))
                .unwrap()
                .is_empty()
        );

        let engine_supported = catalog.candidates(&query("0.12.0", "21.0.2")).unwrap();
        assert_eq!(engine_supported.len(), 2, "{engine_supported:?}");
        let bad_toolchain_query = query("9.0.0", "17.0.10");
        assert!(catalog.candidates(&bad_toolchain_query).unwrap().is_empty());
        let near_misses = catalog.version_near_misses(&bad_toolchain_query).unwrap();
        assert_eq!(near_misses.len(), 1, "{near_misses:?}");
        assert_eq!(
            near_misses[0].manifest_digest,
            native.manifest.content_sha256
        );
        assert_eq!(near_misses[0].coordinate, "toolchain jdk");

        let persisted_shapes: Vec<(u32, Option<String>)> = {
            let connection = catalog.connection.lock().unwrap();
            let mut statement = connection
                .prepare(
                    "SELECT schema_version, bifrost_compatibility FROM catalog_packs
                     ORDER BY schema_version",
                )
                .unwrap();
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        assert_eq!(
            persisted_shapes,
            [(7, Some(">=0.8.0, <1.0.0".to_owned())), (8, None)]
        );
        drop(catalog);

        let reopened = SemanticPackCatalog::open(
            &root_path,
            CatalogOpenMode::ReadOnly,
            CatalogOptions::default(),
        )
        .unwrap();
        let reopened_candidates = reopened.candidates(&query("9.0.0", "21.0.2")).unwrap();
        assert_eq!(reopened_candidates.len(), 1, "{reopened_candidates:?}");
        assert_eq!(
            reopened_candidates[0].manifest_digest(),
            native.manifest.content_sha256.as_str()
        );
    }
}

#[cfg(test)]
pub(crate) mod generated_sharing_tests {
    use super::*;

    use rusqlite::params;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogOpenMode;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogOptions;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::CompiledSemanticModelPack;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::DurablePackSource;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::DurablePackSourceKind;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::GeneratedProductionKey;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SHARD_VALIDATION_VERSION;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::decode_limits_digest;

    fn generated_fixture(version: &str) -> (CompiledSemanticModelPack, GeneratedProductionKey) {
        let source = serde_json::json!({
            "schema_version": SEMANTIC_MODEL_SCHEMA_VERSION,
            "pack_id": "cache.fixture", "version": version,
            "producer": {"name": "cache-test", "version": "1.0.0"},
            "language": "java", "ecosystem": "maven",
            "compatibility": {"toolchains": []},
            "provenance": {"source": "cache-test"},
            "license": "Apache-2.0", "completeness": "complete",
            "safety": {"generated_code_only": false, "review_required": false},
            "shards": [{
                "id": "types", "activation": [{"package": {"name": "cache:fixture"}}],
                "payload": {"kind": "declaration_facts", "types": [{
                    "id": "type.example", "name": "cache.Example",
                    "type_kind": "class", "visibility": "public",
                    "locator": {"kind": "artifact", "path": "cache/Example.class", "symbol": "cache.Example"}
                }]}
            }]
        });
        let pack = brokk_bifrost_analysis::analyzer::semantic_model::compiler::compile_source(
            brokk_bifrost_analysis::analyzer::semantic_model::source::SourceFormat::Json,
            &serde_json::to_vec(&source).unwrap(),
            &brokk_bifrost_analysis::analyzer::semantic_model::compiler::CompilerOptions::default(),
        )
        .unwrap();
        let key = GeneratedProductionKey::new(
            pack.manifest.content_sha256.clone(),
            &pack.manifest.producer.name,
            &pack.manifest.producer.version,
            pack.manifest.schema_version,
        )
        .unwrap();
        (pack, key)
    }

    #[test]
    fn unavailable_host_preserves_local_install_identity_and_lock() {
        let root = tempfile::tempdir().unwrap();
        let unavailable = root.path().join("not-a-directory");
        std::fs::write(&unavailable, b"occupied").unwrap();
        let mut local = SemanticPackCatalog::open(
            &root.path().join("local"),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        local.shared_generated_root = Some(unavailable);
        let (pack, key) = generated_fixture("1.2.0");
        local.install_generated(&key, &pack).unwrap();
        let identity = "b".repeat(64);
        local
            .install_generated_source_identity(&identity, &key)
            .unwrap();
        assert_eq!(
            local
                .generated_production_by_source_identity(&identity, &pack.manifest.producer)
                .unwrap()
                .unwrap()
                .key,
            key
        );
        assert!(
            local
                .generated_production_lock(&key)
                .unwrap()
                .try_acquire()
                .unwrap()
        );
    }

    #[test]
    fn host_cleanup_keeps_recent_hits_and_local_copy_repairs_eviction() {
        let root = tempfile::tempdir().unwrap();
        let shared_root = root.path().join("host");
        let mut local = SemanticPackCatalog::open(
            &root.path().join("local"),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        local.shared_generated_root = Some(shared_root.clone());
        let (old, old_key) = generated_fixture("1.2.0");
        local.install_generated(&old_key, &old).unwrap();
        let shared = SemanticPackCatalog::open(
            &shared_root,
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        let age_old = || {
            shared
                .connection
                .lock()
                .unwrap()
                .execute(
                    "UPDATE catalog_packs SET last_used_at = 0 WHERE manifest_digest = ?1",
                    [&old.manifest.content_sha256],
                )
                .unwrap();
        };
        age_old();
        assert!(local.generated_production(&old_key).unwrap().is_some());
        let (new, new_key) = generated_fixture("1.3.0");
        local.install_generated(&new_key, &new).unwrap();
        assert!(shared.has_verified_generated_production(&old_key).unwrap());
        age_old();
        let (newest, newest_key) = generated_fixture("1.4.0");
        local.install_generated(&newest_key, &newest).unwrap();
        assert!(!shared.has_verified_generated_production(&old_key).unwrap());
        assert!(local.generated_production(&old_key).unwrap().is_some());
        assert!(shared.has_verified_generated_production(&old_key).unwrap());
        shared
            .connection
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM catalog_sources WHERE source_id = ?1",
                [old_key.source_id()],
            )
            .unwrap();
        assert!(!shared.has_verified_generated_production(&old_key).unwrap());
        assert!(local.generated_production(&old_key).unwrap().is_some());
        assert!(shared.has_verified_generated_production(&old_key).unwrap());
    }

    #[test]
    fn host_reuse_copies_only_exact_generated_production_and_keeps_activation_local() {
        let root = tempfile::tempdir().unwrap();
        let shared_root = root.path().join("host");
        let mut first = SemanticPackCatalog::open(
            &root.path().join("first"),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        first.shared_generated_root = Some(shared_root.clone());
        let (pack, key) = generated_fixture("1.2.0");
        first
            .install(
                &pack,
                &DurablePackSource {
                    kind: DurablePackSourceKind::WorkspaceProduced,
                    source_id: "first-only".to_owned(),
                },
            )
            .unwrap();
        first.install_generated(&key, &pack).unwrap();
        let identity = "b".repeat(64);
        first
            .install_generated_source_identity(&identity, &key)
            .unwrap();
        let first_lock = first.generated_production_lock(&key).unwrap();
        assert!(first_lock.try_acquire().unwrap());
        let mut second = SemanticPackCatalog::open(
            &root.path().join("second"),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        second.shared_generated_root = Some(shared_root);
        let second_lock = second.generated_production_lock(&key).unwrap();
        assert!(!second_lock.try_acquire().unwrap());
        drop(first_lock);
        assert!(second_lock.try_acquire().unwrap());
        drop(second_lock);
        drop(first);
        let production = second
            .generated_production_by_source_identity(&identity, &pack.manifest.producer)
            .unwrap()
            .unwrap();
        assert_eq!(production.key, key);
        assert_eq!(production.manifest_digest, pack.manifest.content_sha256);
        let connection = second.connection.lock().unwrap();
        let sources: Vec<(String, String)> = connection
            .prepare("SELECT source_kind, source_id FROM catalog_sources")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(sources, vec![("generated".to_owned(), key.source_id())]);
        drop(connection);
        let missing = GeneratedProductionKey::new(
            "c".repeat(64),
            &pack.manifest.producer.name,
            &pack.manifest.producer.version,
            pack.manifest.schema_version,
        )
        .unwrap();
        assert!(second.generated_production(&missing).unwrap().is_none());
    }

    #[test]
    fn certificate_lookup_uses_its_primary_key_with_and_without_statistics() {
        for state in brokk_bifrost_core::cache_gc::PlannerStatisticsState::BOTH {
            let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
            let (pack, key) = generated_fixture("1.2.0");
            catalog
                .install(
                    &pack,
                    &DurablePackSource {
                        kind: DurablePackSourceKind::Installed,
                        source_id: "fixture".to_owned(),
                    },
                )
                .unwrap();
            catalog.install_generated(&key, &pack).unwrap();
            let connection = catalog.connection.lock().unwrap();
            let limits = decode_limits_digest(&catalog.options.decode_limits);
            for version in (1..)
                .filter(|version| *version != SHARD_VALIDATION_VERSION)
                .take(256)
            {
                connection
                    .execute(
                        "INSERT INTO catalog_shard_validations VALUES (?1, ?2, ?3, ?4)",
                        params![
                            pack.manifest.content_sha256,
                            pack.manifest.shards[0].shard_id,
                            version,
                            limits
                        ],
                    )
                    .unwrap();
            }
            state.install(&connection);
            let publication_plan = connection
                .prepare(&format!(
                    "EXPLAIN QUERY PLAN {SHARED_PRODUCTION_PRESENT_SQL}"
                ))
                .unwrap()
                .query_map([key.production_digest()], |row| row.get::<_, String>(3))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert!(
                publication_plan
                    .iter()
                    .any(|line| line.contains("SEARCH gp")),
                "{state}: {publication_plan:?}"
            );
            assert!(
                publication_plan
                    .iter()
                    .any(|line| line.contains("SEARCH p USING")),
                "{state}: {publication_plan:?}"
            );
            assert!(
                !publication_plan.iter().any(|line| line.contains("SCAN gp")
                    || line.contains("SCAN p ")
                    || line.contains("AUTOMATIC")),
                "{state}: {publication_plan:?}"
            );
            let details = connection
                .prepare(&format!("EXPLAIN QUERY PLAN {CERTIFIED_SHARD_SQL}"))
                .unwrap()
                .query_map(
                    params![
                        pack.manifest.content_sha256,
                        pack.manifest.shards[0].shard_id,
                        SHARD_VALIDATION_VERSION,
                        limits
                    ],
                    |row| row.get::<_, String>(3),
                )
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert!(details.iter().any(|line| line.contains("SEARCH catalog_shard_validations USING PRIMARY KEY")), "{state}: {details:?}");
            assert!(
                !details
                    .iter()
                    .any(|line| line.contains("SCAN catalog_shard_validations")),
                "{state}: {details:?}"
            );
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod go_extraction_support_22 {

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::CompiledSemanticModelPack;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogCallableValuesQuery;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogCallableValuesQuestion;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogOptions;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::DurablePackSource;
    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::DurablePackSourceKind;
    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

    use brokk_bifrost_analysis::analyzer::semantic_model::compiler::CompilerOptions;
    use brokk_bifrost_analysis::analyzer::semantic_model::compiler::compile_pack;
    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiCallableValuesArgument;
    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiCallableValuesLimitation;
    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiCallableValuesModality;
    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiCallableValuesPayload;
    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiCallableValuesShape;
    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiCallableValuesTiming;
    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiCoverageStatus;
    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiInputLocation;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::AuthoredSemanticModelPack;
    use brokk_bifrost_analysis::analyzer::semantic_model::model::CallableValuesCoverage;
    use brokk_bifrost_analysis::analyzer::semantic_model::model::CallableValuesFact;
    use brokk_bifrost_analysis::analyzer::semantic_model::model::CallableValuesFamily;
    use brokk_bifrost_analysis::analyzer::semantic_model::model::CallableValuesPayload;

    use serde_json::json;

    #[doc(hidden)]
    pub const DECLARATIONS: &[u8] =
        include_bytes!("../../../../testdata/semantic-model-packs/declarations-v1.json");
    #[doc(hidden)]
    pub const CALLABLE: &str = "member.widget.create";
    #[doc(hidden)]
    pub fn callback_location(position: u32) -> CsmiInputLocation {
        serde_json::from_value(json!({
            "root": {"phase": "input", "role": "parameter", "position": position}
        }))
        .expect("parameter location is valid")
    }
    pub(crate) fn callable_pack() -> CompiledSemanticModelPack {
        let mut authored: AuthoredSemanticModelPack =
            serde_json::from_slice(DECLARATIONS).expect("declaration fixture is valid");
        authored.schema_version = 10;
        authored.compatibility.bifrost = None;
        let callback = callback_location(0);
        authored.shards[0].callable_values = Some(CallableValuesPayload {
            facts: vec![
                CallableValuesFact {
                    payload: CsmiCallableValuesPayload::ReturnedCallable {
                        callable: CALLABLE.to_owned(),
                        result: 0,
                        target: CALLABLE.to_owned(),
                    },
                    provenance: vec!["factory-return-a".to_owned()],
                },
                CallableValuesFact {
                    payload: CsmiCallableValuesPayload::ReturnedCallable {
                        callable: CALLABLE.to_owned(),
                        result: 0,
                        target: CALLABLE.to_owned(),
                    },
                    provenance: vec!["factory-return-b".to_owned()],
                },
                CallableValuesFact {
                    payload: CsmiCallableValuesPayload::CallbackInvocation {
                        callable: CALLABLE.to_owned(),
                        callback: callback.clone(),
                        shape: CsmiCallableValuesShape {
                            parameters: 1,
                            results: 1,
                        },
                        arguments: vec![CsmiCallableValuesArgument::Unknown {
                            limitation: CsmiCallableValuesLimitation {
                                kind: "unmodeled-input".to_owned(),
                                diagnostic: None,
                            },
                        }],
                        timing: CsmiCallableValuesTiming::DuringCall,
                        modality: CsmiCallableValuesModality::May,
                    },
                    provenance: vec!["callback-edge".to_owned()],
                },
            ],
            coverage: vec![
                CallableValuesCoverage {
                    family: CallableValuesFamily::ReturnedCallables,
                    callable: CALLABLE.to_owned(),
                    status: CsmiCoverageStatus::Partial,
                    limitations: Vec::new(),
                    provenance: vec!["returned-scan".to_owned()],
                },
                CallableValuesCoverage {
                    family: CallableValuesFamily::CallbackInvocations,
                    callable: CALLABLE.to_owned(),
                    status: CsmiCoverageStatus::Unknown,
                    limitations: Vec::new(),
                    provenance: vec!["callback-scan".to_owned()],
                },
            ],
            anonymous_callables: Vec::new(),
        });
        compile_pack(&authored, &CompilerOptions::default()).expect("callable pack compiles")
    }
    #[doc(hidden)]
    pub fn install_fixture() -> (SemanticPackCatalog, CompiledSemanticModelPack) {
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let pack = callable_pack();
        catalog
            .install(
                &pack,
                &DurablePackSource {
                    kind: DurablePackSourceKind::Installed,
                    source_id: "callable-values-fixture".to_owned(),
                },
            )
            .unwrap();
        catalog
            .install(
                &pack,
                &DurablePackSource {
                    kind: DurablePackSourceKind::Installed,
                    source_id: "callable-values-fixture-second".to_owned(),
                },
            )
            .expect("same populated publication supports multiple durable source IDs");
        (catalog, pack)
    }
    #[doc(hidden)]
    pub fn query<'a>(
        pack: &'a CompiledSemanticModelPack,
        question: CatalogCallableValuesQuestion<'a>,
    ) -> CatalogCallableValuesQuery<'a> {
        CatalogCallableValuesQuery {
            manifest_digest: &pack.manifest.content_sha256,
            shard_id: &pack.manifest.shards[0].shard_id,
            callable: CALLABLE,
            question,
        }
    }
}

pub use crate::analyzer::store::model_catalog::{
    CatalogPackSourceKind, CatalogRuntimeSourceReader, DurablePackSourceKind,
    activation_catalog_kind, durable_activation_kind, parse_semantic_pack_activation_source_kind,
};

#[cfg(test)]
mod connection_read_tests {
    use super::*;
    use crate::analyzer::{MultiAnalyzer, capture_query_reads};

    #[test]
    fn catalog_connection_reads_live_sql_state_across_captures() {
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let analyzer = MultiAnalyzer::default();
        let connection = catalog.connection.lock().unwrap();
        connection
            .execute_batch(
                "CREATE TEMP TABLE memo_probe(value INTEGER); INSERT INTO memo_probe VALUES (1)",
            )
            .unwrap();
        for value in [1, 2] {
            connection
                .execute("UPDATE memo_probe SET value = ?1", [value])
                .unwrap();
            let (actual, reads) = capture_query_reads(&analyzer, || {
                connection
                    .query_row("SELECT value FROM memo_probe", [], |row| {
                        row.get::<_, i32>(0)
                    })
                    .unwrap()
            });
            assert_eq!(actual, value);
            assert!(
                reads.keys().is_empty(),
                "a connection handle retains no query answer"
            );
        }
    }
}
