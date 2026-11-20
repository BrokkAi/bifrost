//! Request-owned JVM catalog reads over a pinned pair of WAL snapshots.
use super::*;
use crate::analyzer::store::active_models::CatalogShardDatabase;
use crate::analyzer::store::model_catalog::CatalogPackSourceKind;
use brokk_bifrost_semantic::analyzer::semantic_model::artifact::manifest_content_digest;
use rusqlite::types::Value;
use std::sync::TryLockError;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

#[derive(Clone)]
pub enum ExpectedCatalogEntry {
    Dependency {
        adapter: Arc<dyn super::super::dependency::DependencyPackAdapter + Send + Sync>,
        dependency: Box<super::super::dependency::ResolvedDependency>,
        limits: super::super::dependency::DependencyPackLimits,
        fallback: Box<ExpectedCatalogEntry>,
    },
    MissingProduction,
    Shard {
        kind: CatalogPackSourceKind,
        manifest_digest: String,
        shard_id: String,
    },
    Production {
        production_digest: String,
    },
    SourceIdentity {
        producer: crate::analyzer::semantic_model::Producer,
        source_identity: Option<String>,
    },
}

impl std::fmt::Debug for ExpectedCatalogEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dependency { dependency, .. } => {
                f.debug_tuple("Dependency").field(dependency).finish()
            }
            Self::Shard {
                kind,
                manifest_digest,
                shard_id,
            } => f
                .debug_tuple("Shard")
                .field(kind)
                .field(manifest_digest)
                .field(shard_id)
                .finish(),
            Self::Production { production_digest } => f
                .debug_tuple("Production")
                .field(production_digest)
                .finish(),
            Self::SourceIdentity {
                producer,
                source_identity,
            } => f
                .debug_tuple("SourceIdentity")
                .field(producer)
                .field(source_identity)
                .finish(),
            Self::MissingProduction => f.write_str("MissingProduction"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinnedCatalogStatus {
    Present,
    Missing,
    Quarantined,
    Stale,
}

impl PinnedCatalogStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Missing => "missing",
            Self::Quarantined => "quarantined",
            Self::Stale => "stale",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PinnedCatalogRow {
    pub ordinal: usize,
    pub kind: CatalogPackSourceKind,
    pub production_digest: Option<String>,
    pub manifest_digest: Option<String>,
    pub shard_id: Option<String>,
    pub shard_key: Option<i64>,
    pub status: PinnedCatalogStatus,
    pub manifest: Option<Arc<CompiledPackManifest>>,
}

#[derive(Debug)]
pub enum PinnedReaderError {
    Closed,
    Cancelled,
    Catalog(CatalogError),
}

impl From<CatalogError> for PinnedReaderError {
    fn from(error: CatalogError) -> Self {
        Self::Catalog(error)
    }
}

type PinnedReaderPoolReturn = (
    Arc<PinnedReaderPool>,
    (PathBuf, PathBuf, u32),
    crate::analyzer::store::model_catalog::PinnedReaderValidation,
);

/// One request shares one connection; every use releases the lock with owned rows.
/// `main` and `session` are pinned separately by one fully evaluated statement.
/// SQLite does not promise an atomic cross-database instant.
pub struct PinnedCatalogReader {
    connection: Mutex<Option<Connection>>,
    closed: AtomicBool,
    failed: AtomicBool,
    cancellation: CancellationToken,
    pool_return: Option<PinnedReaderPoolReturn>,
    pub membership: Vec<PinnedCatalogRow>,
    _session_catalog: Arc<Mutex<Option<SessionSemanticCatalog>>>,
    _ephemeral_root: Option<Arc<TempDir>>,
}

impl SemanticPackCatalog {
    pub fn pinned_jvm_reader(
        &self,
        expected: &[ExpectedCatalogEntry],
        cancellation: CancellationToken,
    ) -> Result<PinnedCatalogReader, PinnedReaderError> {
        self.unpooled_catalog_source()
            .pinned_jvm_reader(expected, cancellation)
    }
}

impl PinnedCatalogSource {
    pub(super) fn verify_on(
        &self,
        connection: &Connection,
        manifest: &CompiledPackManifest,
        descriptor: &CompiledShardDescriptor,
        session_pack: Option<&SessionPack>,
    ) -> Result<(), CatalogError> {
        self.verifier.ensure_valid_shard(
            ShardVerificationInput {
                root: &self.root,
                stored_in: if session_pack.is_some() {
                    ShardStorage::Session
                } else {
                    ShardStorage::Durable
                },
                object_reads: None,
                manifest,
                descriptor,
                limits: &self.decode_limits,
                instance: self.instance_identity,
            },
            || {
        let stored_in = if session_pack.is_some() {
            ShardStorage::Session
        } else {
            ShardStorage::Durable
        };
        self.verifier.ensure_profile_pack(
            self.instance_identity,
            stored_in,
            manifest,
            &self.decode_limits,
            || {
                validate_stored_python_profile_pack(
                    &self.root,
                    Some(connection),
                    session_pack,
                    manifest,
                    &self.decode_limits,
                    None,
                )
            },
        )?;
        let source = if let Some(pack) = session_pack {
            let shard = pack
                .shards
                .iter()
                .find(|s| &s.descriptor == descriptor)
                .ok_or(CatalogError::Unavailable)?;
            ShardVerificationSource::Session {
                bytes: &shard.bytes,
            }
        } else {
            let location = connection.query_row("SELECT o.relative_path,o.stored_size FROM main.catalog_packs p JOIN main.catalog_pack_shards s USING(manifest_digest) JOIN main.catalog_objects o ON o.stored_digest=s.stored_digest WHERE p.state='verified' AND p.manifest_digest=?1 AND s.shard_id=?2 AND s.stored_digest=?3", params![manifest.content_sha256, descriptor.shard_id, descriptor.stored_sha256], |r| Ok((r.get(0)?,r.get(1)?))).optional().map_err(|e| CatalogError::sqlite("resolve snapshot shard location", e))?.ok_or(CatalogError::Unavailable)?;
            ShardVerificationSource::Durable {
                location,
                certificate: shard_certificate(connection, manifest, &descriptor.shard_id)?,
            }
        };
        Ok(source)

            },
            || {},
            |_| Ok(()),
        )?;
        Ok(())
    }

    pub fn pinned_jvm_reader(
        &self,
        expected: &[ExpectedCatalogEntry],
        cancellation: CancellationToken,
    ) -> Result<PinnedCatalogReader, PinnedReaderError> {
        if cancellation.is_cancelled() {
            return Err(PinnedReaderError::Cancelled);
        }
        let key = {
            // Preparation initializes the session on first use. There is no idle
            // connection before that initialization has completed.
            let session = self
                .session_catalog
                .lock()
                .expect("session catalog mutex poisoned");
            session
                .as_ref()
                .map(|session| (self.root.clone(), session.path.clone(), 1))
        };
        let mut prepared = None;
        if let (Some(pool), Some(key)) = (&self.pool, &key) {
            loop {
                let id = {
                    let mut idle = pool.idle.lock().expect("pinned pool mutex poisoned");
                    let stale = idle
                        .keys()
                        .filter(|old| old.1 != key.1)
                        .cloned()
                        .collect::<Vec<_>>();
                    for old in stale {
                        for id in idle.remove(&old).expect("listed pool key") {
                            pool.region.invalidate(&id);
                        }
                    }
                    idle.get_mut(key).and_then(Vec::pop)
                };
                let Some(id) = id else { break };
                if let Some(entry) = pool.region.get(&id) {
                    let candidate = entry
                        .connection
                        .lock()
                        .expect("idle reader mutex poisoned")
                        .take();
                    pool.region.invalidate(&id);
                    if let Some((connection, validation)) = candidate
                        && validation.matches(&connection)?
                    {
                        prepared = Some((connection, validation));
                        break;
                    }
                }
            }
        }
        let (connection, validation) = match prepared {
            Some(prepared) => prepared,
            None => {
                crate::analyzer::store::model_catalog::prepare_validated_pinned_reader_connection(
                    &self.root,
                    &self.session_catalog,
                )?
            }
        };
        let key = {
            let session = self
                .session_catalog
                .lock()
                .expect("session catalog mutex poisoned");
            (
                self.root.clone(),
                session
                    .as_ref()
                    .expect("prepared reader has session")
                    .path
                    .clone(),
                1,
            )
        };
        #[cfg(test)]
        tests::BEFORE_PIN.with(|hook| {
            if let Some(hook) = hook.borrow_mut().take() {
                hook();
            }
        });
        connection
            .execute_batch("BEGIN")
            .map_err(|error| CatalogError::sqlite("begin pinned catalog reader", error))?;
        // Both scalar subqueries must finish before any TEMP write. Even an
        // empty schema starts its WAL read transaction here.
        let _: (i64, i64) = connection
            .query_row(
                "SELECT (SELECT count(*) FROM main.catalog_packs),
                    (SELECT count(*) FROM session.catalog_packs)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| CatalogError::sqlite("pin both semantic catalogs", error))?;
        // Preparation runs outside this transaction. Both pinned snapshots must
        // still have the validated schema before any membership is published.
        if !validation.schema_matches(&connection)? {
            return Err(CatalogError::Unavailable.into());
        }
        let mut expanded = Vec::new();
        for entry in expected {
            if let ExpectedCatalogEntry::Dependency {
                adapter,
                dependency,
                limits,
                fallback,
            } = entry
            {
                let choice = self.selected_dependency_provider_on(
                    &connection,
                    adapter.as_ref(),
                    dependency,
                    limits,
                )?;
                if let Some(installed) = choice.installed {
                    for digest in installed.manifest_digests {
                        let session = self
                            .session_packs
                            .lock()
                            .expect("session pack mutex poisoned");
                        let manifest = if let Some(pack) = session
                            .iter()
                            .find(|pack| pack.manifest.content_sha256 == digest)
                        {
                            Some(Arc::clone(&pack.manifest))
                        } else {
                            self.available_manifest_on(&connection, &digest)?
                        };
                        let mut kinds = session
                            .iter()
                            .filter(|pack| pack.manifest.content_sha256 == digest)
                            .map(|pack| pack.source.kind.into())
                            .collect::<Vec<CatalogPackSourceKind>>();
                        {
                            let mut statement = connection.prepare("SELECT DISTINCT source_kind FROM main.catalog_sources WHERE manifest_digest=?1 ORDER BY source_kind")
                                .map_err(|error| CatalogError::sqlite("prepare provider sources", error))?;
                            for kind in statement
                                .query_map([&digest], |row| row.get::<_, String>(0))
                                .map_err(|error| {
                                    CatalogError::sqlite("query provider sources", error)
                                })?
                            {
                                let kind = kind.map_err(|error| {
                                    CatalogError::sqlite("read provider source", error)
                                })?;
                                use crate::analyzer::store::model_catalog::{
                                    activation_catalog_kind,
                                    parse_semantic_pack_activation_source_kind,
                                };
                                if let Some(kind) =
                                    parse_semantic_pack_activation_source_kind(&kind)
                                {
                                    kinds.push(activation_catalog_kind(kind));
                                }
                            }
                        }
                        if let Some(manifest) = manifest
                            && crate::analyzer::semantic_pack_realm(&manifest.language) == "jvm"
                        {
                            for kind in kinds {
                                if !matches!(
                                    kind,
                                    CatalogPackSourceKind::Generated
                                        | CatalogPackSourceKind::Installed
                                        | CatalogPackSourceKind::PreShipped
                                        | CatalogPackSourceKind::Embedded
                                ) {
                                    continue;
                                }
                                // Selector-rejected shards remain in ActivationExclusions and pass
                                // the bind's rule (ii); a partly selected curated provider answers
                                // Open through the partial-selection guard (#10712).
                                for shard in &manifest.shards {
                                    if shard.payload_kind != crate::analyzer::semantic_model::PayloadKind::GeneratorRules {
                                            expanded.push(ExpectedCatalogEntry::Shard { kind, manifest_digest: digest.clone(), shard_id: shard.shard_id.clone() });
                                        }
                                }
                            }
                        }
                    }
                }
                if !choice.settled {
                    expanded.push(
                        choice
                            .production
                            .map(|key| ExpectedCatalogEntry::Production {
                                production_digest: key.production_digest,
                            })
                            .unwrap_or_else(|| *fallback.clone()),
                    );
                }
            } else {
                expanded.push(entry.clone());
            }
        }
        let mut seen = std::collections::HashSet::new();
        expanded.retain(|entry| match entry {
            ExpectedCatalogEntry::Shard {
                kind,
                manifest_digest,
                shard_id,
            } => seen.insert((*kind, manifest_digest.clone(), shard_id.clone())),
            _ => true,
        });
        let expected = expanded;
        let session_packs = self
            .session_packs
            .lock()
            .expect("session pack mutex poisoned");
        // Resolve the bounded request membership as a set. Each result keeps
        // its expectation ordinal and manifest shard order, including missing
        // productions, so the fail-closed checks below are unchanged.
        let keys = expected
            .iter()
            .map(|entry| match entry {
                ExpectedCatalogEntry::Shard {
                    kind,
                    manifest_digest,
                    shard_id,
                } => serde_json::json!([
                    kind.as_str(),
                    null,
                    manifest_digest,
                    shard_id,
                    null,
                    null,
                    null
                ]),
                ExpectedCatalogEntry::Production { production_digest } => serde_json::json!([
                    "generated",
                    production_digest,
                    null,
                    null,
                    null,
                    null,
                    null
                ]),
                ExpectedCatalogEntry::SourceIdentity {
                    producer,
                    source_identity,
                } => serde_json::json!([
                    "generated",
                    null,
                    null,
                    null,
                    source_identity,
                    producer.name,
                    producer.version
                ]),
                ExpectedCatalogEntry::MissingProduction => {
                    serde_json::json!(["generated", null, null, null, null, null, null])
                }
                ExpectedCatalogEntry::Dependency { .. } => unreachable!("expanded dependency"),
            })
            .collect::<Vec<_>>();
        let keys = serde_json::to_string(&keys).expect("membership keys serialize");
        type BoundShard = (
            Option<String>,
            Option<String>,
            Option<String>,
            Option<(String, Option<String>, Option<i64>)>,
        );
        let mut bound = HashMap::<usize, Vec<BoundShard>>::new();
        {
            let mut statement = connection.prepare(
                "WITH expected AS MATERIALIZED (
                   SELECT CAST(key AS INTEGER) AS ordinal,
                          value->>'$[0]' AS kind, value->>'$[1]' AS production,
                          value->>'$[2]' AS manifest, value->>'$[3]' AS shard,
                          value->>'$[4]' AS identity, value->>'$[5]' AS producer,
                          value->>'$[6]' AS version FROM json_each(?1)
                 ), resolved AS MATERIALIZED (
                   SELECT e.*, coalesce(e.production, gp.production_digest) AS resolved
                   FROM expected e
                   LEFT JOIN main.catalog_generated_source_identities ident
                     ON ident.source_identity=e.identity AND ident.producer_name=e.producer
                    AND ident.producer_version=e.version AND ident.schema_version=?2
                    AND ident.generated_cache_version=?3
                   LEFT JOIN main.catalog_generated_productions gp
                     ON gp.production_digest=ident.production_digest
                    AND gp.producer_name=ident.producer_name
                    AND gp.producer_version=ident.producer_version
                    AND gp.schema_version=ident.schema_version
                 ), candidates AS MATERIALIZED (
                   SELECT e.ordinal,e.kind,e.resolved AS production,
                          coalesce(e.manifest,gp.manifest_digest) AS manifest,
                          coalesce(e.shard,s.shard_id) AS shard, s.ordinal AS shard_ordinal
                   FROM resolved e
                   LEFT JOIN main.catalog_generated_productions gp
                     ON gp.production_digest=e.resolved
                   LEFT JOIN main.catalog_pack_shards s
                     ON e.manifest IS NULL AND s.manifest_digest=gp.manifest_digest
                 )
                 SELECT c.ordinal,c.production,c.manifest,c.shard,
                        CASE WHEN c.kind IN ('embedded','ephemeral_workspace') THEN sp.state ELSE p.state END,
                        CASE WHEN c.kind IN ('embedded','ephemeral_workspace') THEN NULL ELSE p.completeness END,
                        CASE WHEN c.kind IN ('embedded','ephemeral_workspace') THEN ss.shard_key ELSE s.shard_key END
                 FROM candidates c
                 LEFT JOIN main.catalog_packs p ON p.manifest_digest=c.manifest
                   AND c.kind NOT IN ('embedded','ephemeral_workspace')
                 LEFT JOIN main.catalog_semantic_rows_indexed_shards s
                   ON s.manifest_digest=p.manifest_digest AND s.shard_id=c.shard AND s.index_version=4
                 LEFT JOIN session.catalog_packs sp ON sp.manifest_digest=c.manifest
                   AND c.kind IN ('embedded','ephemeral_workspace')
                 LEFT JOIN session.catalog_semantic_rows_indexed_shards ss
                   ON ss.manifest_digest=sp.manifest_digest AND ss.shard_id=c.shard AND ss.index_version=4
                 ORDER BY c.ordinal,c.shard_ordinal"
            ).map_err(|error| CatalogError::sqlite("prepare batched pinned membership", error))?;
            let rows = statement
                .query_map(
                    params![
                        keys,
                        SEMANTIC_MODEL_SCHEMA_VERSION,
                        GENERATED_PRODUCTION_CACHE_VERSION
                    ],
                    |row| {
                        let state: Option<String> = row.get(4)?;
                        Ok((
                            row.get::<_, usize>(0)?,
                            (
                                row.get(1)?,
                                row.get(2)?,
                                row.get(3)?,
                                state
                                    .map(|state| -> rusqlite::Result<_> {
                                        Ok((state, row.get(5)?, row.get(6)?))
                                    })
                                    .transpose()?,
                            ),
                        ))
                    },
                )
                .map_err(|error| CatalogError::sqlite("query batched pinned membership", error))?;
            for row in rows {
                let (ordinal, shard) = row.map_err(|error| {
                    CatalogError::sqlite("read batched pinned membership", error)
                })?;
                bound.entry(ordinal).or_default().push(shard);
            }
        }
        let mut membership = Vec::with_capacity(expected.len());
        for (ordinal, entry) in expected.iter().enumerate() {
            if cancellation.is_cancelled() {
                return Err(PinnedReaderError::Cancelled);
            }
            let kind = match entry {
                ExpectedCatalogEntry::Shard { kind, .. } => *kind,
                _ => CatalogPackSourceKind::Generated,
            };
            let session = matches!(
                kind,
                CatalogPackSourceKind::Embedded | CatalogPackSourceKind::EphemeralWorkspace
            );
            for (production_digest, manifest_digest, shard_id, pack) in bound
                .remove(&ordinal)
                .expect("one membership answer per expectation")
            {
                let production_digest = production_digest.as_deref();
                let mut status = match pack.as_ref() {
                    None => PinnedCatalogStatus::Missing,
                    Some((state, _, _)) if state == "quarantined" => {
                        PinnedCatalogStatus::Quarantined
                    }
                    Some((_, _, None)) => PinnedCatalogStatus::Missing,
                    Some(_) => PinnedCatalogStatus::Present,
                };
                let mut manifest = None;
                if status == PinnedCatalogStatus::Present {
                    if session {
                        // Publication keys an immutable Arc by manifest content SHA.
                        // Recompute the content digest to bind all diagnostic and
                        // coverage fields to the pinned SQL digest.
                        manifest = session_packs
                            .iter()
                            .find(|pack| {
                                pack.manifest.content_sha256
                                    == manifest_digest
                                        .as_deref()
                                        .expect("present shard has manifest")
                            })
                            .and_then(|pack| {
                                let digest = manifest_content_digest(&pack.manifest).ok()?;
                                (digest
                                    == manifest_digest
                                        .as_deref()
                                        .expect("present shard has manifest"))
                                .then(|| Arc::clone(&pack.manifest))
                            });
                    } else {
                        manifest = self.available_manifest_on(
                            &connection,
                            manifest_digest
                                .as_ref()
                                .expect("present shard has manifest"),
                        )?;
                    }
                    if manifest.is_none()
                        || !session
                            && pack
                                .as_ref()
                                .and_then(|(_, completeness, _)| completeness.as_deref())
                                != manifest
                                    .as_ref()
                                    .map(|manifest| manifest.completeness.label())
                    {
                        status = PinnedCatalogStatus::Stale;
                    }
                }
                if status == PinnedCatalogStatus::Present {
                    let admitted = manifest.as_ref().expect("present manifest");
                    let verification = admitted
                        .shards
                        .iter()
                        .find(|d| Some(d.shard_id.as_str()) == shard_id.as_deref())
                        .ok_or(CatalogError::Unavailable)
                        .and_then(|descriptor| {
                            self.verify_on(
                                &connection,
                                admitted,
                                descriptor,
                                if session {
                                    session_packs.iter().find(|p| {
                                        p.manifest.content_sha256 == admitted.content_sha256
                                    })
                                } else {
                                    None
                                },
                            )
                        });
                    if let Err(error) = verification {
                        status = match error {
                            CatalogError::Unavailable => PinnedCatalogStatus::Missing,
                            CatalogError::Integrity(_) | CatalogError::Artifact(_) => {
                                PinnedCatalogStatus::Quarantined
                            }
                            error => return Err(error.into()),
                        };
                    }
                }
                let shard_key = (status == PinnedCatalogStatus::Present)
                    .then(|| pack.as_ref().and_then(|(_, _, key)| *key))
                    .flatten();
                let source = if session { "session" } else { "durable" };
                connection
                    .execute(
                        "INSERT INTO temp.expected_catalog_shards
                 (ordinal,kind,production_digest,manifest_digest,shard_key,status)
                 VALUES(?1,?2,?3,?4,?5,?6)",
                        params![
                            ordinal as i64,
                            kind.as_str(),
                            production_digest,
                            &manifest_digest,
                            shard_key,
                            status.label()
                        ],
                    )
                    .map_err(|error| CatalogError::sqlite("insert expected membership", error))?;
                if let Some(key) = shard_key {
                    connection.execute("INSERT OR IGNORE INTO temp.active_shards(shard_key,source_db) VALUES(?1,?2)",
                    params![key, source])
                    .map_err(|error| CatalogError::sqlite("insert pinned active shard", error))?;
                }
                membership.push(PinnedCatalogRow {
                    ordinal,
                    kind,
                    production_digest: production_digest.map(str::to_owned),
                    manifest_digest,
                    shard_id,
                    shard_key,
                    status,
                    manifest,
                });
            }
        }
        drop(session_packs);
        Ok(PinnedCatalogReader {
            connection: Mutex::new(Some(connection)),
            closed: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            cancellation,
            pool_return: self
                .pool
                .as_ref()
                .map(|pool| (Arc::clone(pool), key, validation)),
            membership,
            _session_catalog: Arc::clone(&self.session_catalog),
            _ephemeral_root: self._ephemeral_root.as_ref().map(Arc::clone),
        })
    }
}

impl PinnedCatalogReader {
    pub fn is_closed(&self) -> bool {
        self.closed.load(AtomicOrdering::Acquire)
    }

    fn with_connection<T>(
        &self,
        cancellation: &CancellationToken,
        read: impl FnOnce(&Connection) -> Result<T, CatalogError>,
    ) -> Result<T, PinnedReaderError> {
        let result = self.read_connection(cancellation, read);
        if result.is_err() {
            self.failed.store(true, AtomicOrdering::Release);
        }
        result
    }

    fn read_connection<T>(
        &self,
        cancellation: &CancellationToken,
        read: impl FnOnce(&Connection) -> Result<T, CatalogError>,
    ) -> Result<T, PinnedReaderError> {
        if self.closed.load(AtomicOrdering::Acquire) {
            return Err(PinnedReaderError::Closed);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if cancellation.is_cancelled() {
                return Err(PinnedReaderError::Cancelled);
            }
            match self.connection.try_lock() {
                Ok(guard) => {
                    if self.closed.load(AtomicOrdering::Acquire) {
                        return Err(PinnedReaderError::Closed);
                    }
                    if cancellation.is_cancelled() {
                        return Err(PinnedReaderError::Cancelled);
                    }
                    return read(guard.as_ref().ok_or(PinnedReaderError::Closed)?).map_err(
                        |error| match error {
                            CatalogError::Cancelled => PinnedReaderError::Cancelled,
                            error => PinnedReaderError::Catalog(error),
                        },
                    );
                }
                Err(TryLockError::WouldBlock) => {
                    if Instant::now() >= deadline {
                        return Err(PinnedReaderError::Catalog(CatalogError::Unavailable));
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(TryLockError::Poisoned(_)) => panic!("pinned catalog reader mutex poisoned"),
            }
        }
    }

    /// Narrow the `active_catalog_*` views to `keep`. Membership rows are unchanged:
    /// they still describe every pinned shard, but the views no longer return rows
    /// of a shard outside `keep`, so no read can reach a shard the caller excluded.
    /// Narrowing only removes: a key of `keep` that was never pinned stays absent.
    pub fn restrict_active_shards(
        &self,
        keep: &HashSet<(CatalogShardDatabase, i64)>,
        cancellation: &CancellationToken,
    ) -> Result<(), PinnedReaderError> {
        // One statement, so a failed or cancelled narrowing leaves the view as it
        // was, and its cost does not grow by a statement per excluded shard.
        let keep = serde_json::Value::Array(
            keep.iter()
                .map(|(database, shard_key)| {
                    let source_db = match database {
                        CatalogShardDatabase::Durable => "durable",
                        CatalogShardDatabase::Session => "session",
                    };
                    serde_json::json!([source_db, shard_key])
                })
                .collect(),
        )
        .to_string();
        self.with_connection(cancellation, |connection| {
            connection
                .execute(
                    "DELETE FROM temp.active_shards WHERE (source_db, shard_key) NOT IN
                     (SELECT json_extract(value, '$[0]'), json_extract(value, '$[1]')
                      FROM json_each(?1))",
                    params![keep],
                )
                .map_err(|error| CatalogError::sqlite("restrict pinned active shards", error))?;
            Ok(())
        })
    }

    /// One statement's owned SQL values; decoding and callbacks run after unlock.
    pub fn owned_named_rows(
        &self,
        statement: &str,
        bindings: &[(&str, &dyn rusqlite::ToSql)],
        cancellation: &CancellationToken,
    ) -> Result<crate::analyzer::store::model_catalog::OwnedCatalogRows, PinnedReaderError> {
        self.with_connection(cancellation, |connection| {
            let mut query = connection
                .prepare_cached(statement)
                .map_err(|error| CatalogError::sqlite("prepare pinned catalog question", error))?;
            let columns = query
                .column_names()
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>();
            let mut cursor = query
                .query(bindings)
                .map_err(|error| CatalogError::sqlite("query pinned catalog question", error))?;
            let mut rows = Vec::new();
            while let Some(row) = cursor
                .next()
                .map_err(|error| CatalogError::sqlite("step pinned catalog question", error))?
            {
                if cancellation.is_cancelled() {
                    return Err(CatalogError::Cancelled);
                }
                let mut values = Vec::with_capacity(columns.len());
                for index in 0..columns.len() {
                    values.push(row.get(index).map_err(|error| {
                        CatalogError::sqlite("read pinned catalog value", error)
                    })?);
                }
                rows.push(values);
            }
            Ok(crate::analyzer::store::model_catalog::OwnedCatalogRows { columns, rows })
        })
    }

    pub fn owned_rows(
        &self,
        statement: &str,
        bindings: impl rusqlite::Params,
        cancellation: &CancellationToken,
    ) -> Result<Vec<Vec<Value>>, PinnedReaderError> {
        self.with_connection(cancellation, |connection| {
            let mut query = connection
                .prepare_cached(statement)
                .map_err(|error| CatalogError::sqlite("prepare pinned catalog question", error))?;
            let columns = query.column_count();
            let mut rows = query
                .query(bindings)
                .map_err(|error| CatalogError::sqlite("query pinned catalog question", error))?;
            let mut owned = Vec::new();
            while let Some(row) = rows
                .next()
                .map_err(|error| CatalogError::sqlite("step pinned catalog question", error))?
            {
                if cancellation.is_cancelled() {
                    return Err(CatalogError::Cancelled);
                }
                let mut values = Vec::with_capacity(columns);
                for column in 0..columns {
                    values.push(row.get(column).map_err(|error| {
                        CatalogError::sqlite("read pinned catalog value", error)
                    })?);
                }
                owned.push(values);
            }
            Ok(owned)
        })
    }

    pub fn close(&self) -> Result<(), PinnedReaderError> {
        if self.closed.swap(true, AtomicOrdering::AcqRel) {
            return Err(PinnedReaderError::Closed);
        }
        let mut guard = self
            .connection
            .lock()
            .expect("pinned catalog reader mutex poisoned");
        if let Some(connection) = guard.take() {
            connection
                .execute_batch("ROLLBACK")
                .map_err(|error| CatalogError::sqlite("rollback pinned catalog reader", error))?;
            self.return_connection(connection);
        }
        Ok(())
    }

    fn return_connection(&self, connection: Connection) {
        if self.failed.load(AtomicOrdering::Acquire)
            || self.cancellation.is_cancelled()
            || !connection.is_autocommit()
            || connection.is_busy()
        {
            return;
        }
        let Some((pool, key, validation)) = &self.pool_return else {
            return;
        };
        if let Err(error) = connection.execute_batch(
            "DELETE FROM temp.expected_catalog_shards; DELETE FROM temp.active_shards;",
        ) {
            eprintln!("clear idle pinned reader: {error}");
            return;
        }
        let session = self
            ._session_catalog
            .lock()
            .expect("session catalog mutex poisoned");
        if session.as_ref().is_none_or(|session| session.path != key.1) {
            return;
        }
        let mut idle = pool.idle.lock().expect("pinned pool mutex poisoned");
        let stale = idle
            .keys()
            .filter(|old| old.1 != key.1)
            .cloned()
            .collect::<Vec<_>>();
        for old in stale {
            for id in idle.remove(&old).expect("listed pool key") {
                pool.region.invalidate(&id);
            }
        }
        if !idle.contains_key(key) && idle.len() >= 2 {
            return;
        }
        let entries = idle.entry(key.clone()).or_default();
        entries.retain(|id| pool.region.get(id).is_some());
        if entries.len() >= 4 {
            return;
        }
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let value = pool.region.insert(
            id,
            crate::analyzer::store::model_catalog::PreparedPinnedReader {
                connection: Mutex::new(Some((connection, validation.clone()))),
            },
        );
        if matches!(
            value,
            brokk_bifrost_core::retention_budget::BudgetedValue::Retained(_)
        ) {
            entries.push(id);
        }
    }
}

impl Drop for PinnedCatalogReader {
    fn drop(&mut self) {
        if let Some(connection) = self
            .connection
            .get_mut()
            .expect("pinned catalog reader mutex poisoned")
            .take()
        {
            match connection.execute_batch("ROLLBACK") {
                Ok(()) => self.return_connection(connection),
                Err(error) => eprintln!("rollback pinned catalog reader on drop: {error}"),
            }
        }
    }
}

/// Indexes idle entries; the budget region owns and can evict the connections.
pub(super) struct PinnedReaderPool {
    region: brokk_bifrost_core::retention_budget::BudgetRegion<
        u64,
        crate::analyzer::store::model_catalog::PreparedPinnedReader,
    >,
    idle: Mutex<HashMap<(PathBuf, PathBuf, u32), Vec<u64>>>,
}
impl PinnedReaderPool {
    pub(super) fn new(budget: &crate::analyzer::store::cache_budget::StoreCacheBudget) -> Self {
        Self {
            region: budget.pinned_readers.clone(),
            idle: Mutex::new(HashMap::new()),
        }
    }
}

impl Drop for PinnedReaderPool {
    fn drop(&mut self) {
        for ids in self
            .idle
            .get_mut()
            .expect("pinned pool mutex poisoned")
            .values()
        {
            for id in ids {
                self.region.invalidate(id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        pub(super) static BEFORE_PIN: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#14393: a migration after preparation admitted an unsupported pinned snapshot"
    )]
    fn pinned_reader_refuses_migration_before_snapshot() {
        for schema in ["main", "session"] {
            let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
            let source = pooled_source(&catalog);
            let reader = source
                .pinned_jvm_reader(&[], CancellationToken::new())
                .unwrap();
            reader.close().unwrap();
            let path = if schema == "main" {
                source.root.join("catalog.db")
            } else {
                source
                    .session_catalog
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .path
                    .clone()
            };
            BEFORE_PIN.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    let writer = rusqlite::Connection::open(path).unwrap();
                    writer
                        .pragma_update(None, "user_version", CATALOG_SCHEMA_VERSION + 1)
                        .unwrap();
                    let checkpoint: (i64, i64, i64) = writer
                        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                        })
                        .unwrap();
                    assert_eq!(checkpoint, (0, 0, 0));
                }));
            });
            assert!(
                matches!(
                    source.pinned_jvm_reader(&[], CancellationToken::new()),
                    Err(PinnedReaderError::Catalog(CatalogError::Unavailable))
                ),
                "{schema} migration must be refused within the pinned snapshot"
            );
        }
    }

    fn pooled_source(catalog: &SemanticPackCatalog) -> PinnedCatalogSource {
        catalog.pinned_catalog_source(
            &crate::analyzer::store::cache_budget::StoreCacheBudget::new(
                &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
            ),
        )
    }

    fn mark_connection(reader: &PinnedCatalogReader) {
        reader
            .connection
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .execute_batch("PRAGMA temp.cache_size=-12345")
            .unwrap();
    }

    fn is_marked(reader: &PinnedCatalogReader) -> bool {
        reader
            .owned_rows("PRAGMA temp.cache_size", [], &CancellationToken::new())
            .unwrap()[0][0]
            == Value::Integer(-12345)
    }

    #[test]
    fn pinned_pool_cancelled_read_discards_connection() {
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let source = pooled_source(&catalog);
        let token = CancellationToken::new();
        let reader = source.pinned_jvm_reader(&[], token.clone()).unwrap();
        mark_connection(&reader);
        let guard = reader.connection.lock().unwrap();
        let result = std::thread::scope(|scope| {
            let worker = scope.spawn(|| reader.owned_rows("SELECT 1", [], &token));
            token.cancel();
            worker.join().unwrap()
        });
        drop(guard);
        assert!(matches!(result, Err(PinnedReaderError::Cancelled)));
        drop(reader);
        let next = source
            .pinned_jvm_reader(&[], CancellationToken::new())
            .unwrap();
        assert!(!is_marked(&next));
    }

    #[test]
    fn pinned_pool_schema_changes_prepare_fresh_connections() {
        for schema in ["main", "session"] {
            let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
            let source = pooled_source(&catalog);
            let reader = source
                .pinned_jvm_reader(&[], CancellationToken::new())
                .unwrap();
            mark_connection(&reader);
            reader.close().unwrap();
            if schema == "main" {
                catalog
                    .connection
                    .lock()
                    .unwrap()
                    .execute_batch("PRAGMA user_version=1")
                    .unwrap();
            } else {
                catalog
                    .session_catalog
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .connection
                    .execute_batch("PRAGMA user_version=1")
                    .unwrap();
            }
            if schema == "main" {
                assert!(matches!(
                    source.pinned_jvm_reader(&[], CancellationToken::new()),
                    Err(PinnedReaderError::Catalog(
                        CatalogError::ReadOnlySchema { .. }
                    ))
                ));
                catalog
                    .connection
                    .lock()
                    .unwrap()
                    .pragma_update(None, "user_version", CATALOG_SCHEMA_VERSION)
                    .unwrap();
            }
            let next = source
                .pinned_jvm_reader(&[], CancellationToken::new())
                .unwrap();
            assert!(!is_marked(&next), "{schema}");
        }
    }

    #[test]
    fn pinned_pool_idle_connection_allows_truncate_checkpoint() {
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let source = pooled_source(&catalog);
        let reader = source
            .pinned_jvm_reader(&[], CancellationToken::new())
            .unwrap();
        mark_connection(&reader);
        reader.close().unwrap();
        assert!(
            source
                .pool
                .as_ref()
                .unwrap()
                .idle
                .lock()
                .unwrap()
                .values()
                .any(|ids| !ids.is_empty())
        );
        let writer = catalog.connection.lock().unwrap();
        writer
            .execute_batch("CREATE TABLE checkpoint_probe(value INTEGER)")
            .unwrap();
        let checkpoint: (i64, i64, i64) = writer
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .unwrap();
        assert_eq!(checkpoint, (0, 0, 0));
        drop(writer);
        let next = source
            .pinned_jvm_reader(&[], CancellationToken::new())
            .unwrap();
        assert_eq!(
            next.owned_rows(
                "SELECT count(*) FROM checkpoint_probe",
                [],
                &CancellationToken::new()
            )
            .unwrap(),
            vec![vec![Value::Integer(0)]]
        );
    }

    #[cfg(unix)]
    #[test]
    fn pinned_pool_catalog_replacement_prepares_fresh_connection() {
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let source = pooled_source(&catalog);
        let reader = source
            .pinned_jvm_reader(&[], CancellationToken::new())
            .unwrap();
        mark_connection(&reader);
        reader.close().unwrap();
        let path = catalog.root().join("catalog.db");
        catalog
            .connection
            .lock()
            .unwrap()
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        let replacement = catalog.root().join("replacement.db");
        std::fs::copy(&path, &replacement).unwrap();
        std::fs::rename(replacement, &path).unwrap();
        let next = source
            .pinned_jvm_reader(&[], CancellationToken::new())
            .unwrap();
        assert!(!is_marked(&next));
    }

    #[test]
    fn owned_source_keeps_ephemeral_root_until_last_holder_drops() {
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let root = catalog.root().to_path_buf();
        let source = catalog.pinned_catalog_source(
            &brokk_bifrost_store::analyzer::store::cache_budget::StoreCacheBudget::new(
                &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
            ),
        );
        drop(catalog);
        assert!(root.exists());
        let reader = source
            .pinned_jvm_reader(&[], CancellationToken::new())
            .unwrap();
        assert!(reader.membership.is_empty());
        drop(source);
        assert!(root.exists());
        drop(reader);
        assert!(!root.exists());
    }

    #[test]
    fn owned_source_sees_later_session_installation() {
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let source = catalog.pinned_catalog_source(
            &brokk_bifrost_store::analyzer::store::cache_budget::StoreCacheBudget::new(
                &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
            ),
        );
        let manifest = serde_json::json!({
            "schema_version": SEMANTIC_MODEL_SCHEMA_VERSION,
            "pack_id": "pin.session", "version": "1.0.0",
            "producer": {"name": "pin-test", "version": "1.0.0"},
            "language": "java", "ecosystem": "maven",
            "compatibility": {"toolchains": []},
            "provenance": {"source": "pin-test"},
            "license": "Apache-2.0", "completeness": "complete",
            "safety": {"generated_code_only": false, "review_required": false},
            "shards": [{"id": "first", "activation": [{"package": {"name": "pin:session"}}],
                "payload": {"kind": "declaration_facts", "types": [{"id": "type.session", "name": "pin.Session", "type_kind": "class", "visibility": "public", "locator": {"kind": "artifact", "path": "pin/Session.class", "symbol": "pin.Session"}}]}}]
        });
        let pack = crate::analyzer::semantic_model::compiler::compile_source(
            crate::analyzer::semantic_model::source::SourceFormat::Json,
            &serde_json::to_vec(&manifest).unwrap(),
            &crate::analyzer::semantic_model::compiler::CompilerOptions::default(),
        )
        .unwrap();
        let expected = [ExpectedCatalogEntry::Shard {
            kind: CatalogPackSourceKind::Embedded,
            manifest_digest: pack.manifest.content_sha256.clone(),
            shard_id: pack.manifest.shards[0].shard_id.clone(),
        }];
        let before = source
            .pinned_jvm_reader(&expected, CancellationToken::new())
            .unwrap();
        assert_eq!(before.membership[0].status, PinnedCatalogStatus::Missing);
        mark_connection(&before);
        before.close().unwrap();
        catalog
            .register_session_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: "pin-session-fixture".to_owned(),
                },
            )
            .unwrap();
        let after = source
            .pinned_jvm_reader(&expected, CancellationToken::new())
            .unwrap();
        assert_eq!(after.membership[0].status, PinnedCatalogStatus::Present);
        assert!(is_marked(&after));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: request membership eligibility used one query per shard"
    )]
    fn pinned_membership_reads_are_batched() {
        use brokk_bifrost_core::cache_db::sql_profile::{ListenerEvent, attach_listener};
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let source = pooled_source(&catalog);
        let reader = source
            .pinned_jvm_reader(&[], CancellationToken::new())
            .unwrap();
        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = reads.clone();
        let listener = attach_listener(
            reader.connection.lock().unwrap().as_ref().unwrap(),
            Arc::new(move |event| {
                if let ListenerEvent::Statement { sql: Some(sql), .. } = event
                    && (sql.trim_start().starts_with("SELECT")
                        || sql.trim_start().starts_with("WITH"))
                {
                    counted.fetch_add(1, AtomicOrdering::Relaxed);
                }
            }),
        );
        reader.close().unwrap();
        let mut baseline = None;
        for count in [1, 5, 100] {
            reads.store(0, AtomicOrdering::Relaxed);
            let expected = (0..count)
                .map(|i| ExpectedCatalogEntry::Shard {
                    kind: CatalogPackSourceKind::PreShipped,
                    manifest_digest: format!("missing-{i}"),
                    shard_id: "declarations".into(),
                })
                .collect::<Vec<_>>();
            let reader = source
                .pinned_jvm_reader(&expected, CancellationToken::new())
                .unwrap();
            assert_eq!(reader.membership.len(), count);
            assert!(
                reader
                    .membership
                    .iter()
                    .all(|row| row.status == PinnedCatalogStatus::Missing)
            );
            let current = reads.load(AtomicOrdering::Relaxed);
            assert!(current > 0);
            assert_eq!(*baseline.get_or_insert(current), current);
            reader.close().unwrap();
        }
        drop(listener);
    }

    #[test]
    fn pins_empty_main_and_session_before_membership_and_closes() {
        let root = tempfile::tempdir().unwrap();
        let catalog = SemanticPackCatalog::open(
            root.path(),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        catalog
            .connection
            .lock()
            .unwrap()
            .execute_batch("CREATE TABLE pin_probe(value INTEGER); INSERT INTO pin_probe VALUES(1)")
            .unwrap();
        let reader = catalog
            .pinned_jvm_reader(&[], CancellationToken::new())
            .unwrap();
        assert!(reader.membership.is_empty());
        catalog
            .connection
            .lock()
            .unwrap()
            .execute("INSERT INTO pin_probe VALUES(2)", [])
            .unwrap();
        assert_eq!(
            reader
                .owned_rows(
                    "SELECT count(*) FROM main.pin_probe",
                    [],
                    &CancellationToken::default()
                )
                .unwrap()[0][0],
            Value::Integer(1)
        );
        let session = catalog.session_catalog.lock().unwrap();
        let session_connection = &session.as_ref().unwrap().connection;
        session_connection
            .execute(
                "INSERT INTO catalog_packs(manifest_digest,state) VALUES(?1,'verified')",
                ["0".repeat(64)],
            )
            .unwrap();
        drop(session);
        assert_eq!(
            reader
                .owned_rows(
                    "SELECT count(*) FROM session.catalog_packs",
                    [],
                    &CancellationToken::default()
                )
                .unwrap()[0][0],
            Value::Integer(0)
        );
        reader.close().unwrap();
        assert!(matches!(
            reader.owned_rows("SELECT 1", [], &CancellationToken::default()),
            Err(PinnedReaderError::Closed)
        ));
    }

    #[test]
    fn unkeyed_production_keeps_its_missing_ordinal() {
        let root = tempfile::tempdir().unwrap();
        let catalog = SemanticPackCatalog::open(
            root.path(),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        let reader = catalog
            .pinned_jvm_reader(
                &[ExpectedCatalogEntry::MissingProduction],
                CancellationToken::new(),
            )
            .unwrap();
        assert_eq!(reader.membership.len(), 1);
        assert_eq!(reader.membership[0].ordinal, 0);
        assert_eq!(reader.membership[0].status, PinnedCatalogStatus::Missing);
    }

    #[test]
    fn production_expands_shards_and_preserves_missing_and_quarantined_ordinals() {
        let root = tempfile::tempdir().unwrap();
        let catalog = SemanticPackCatalog::open(
            root.path(),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        let source = serde_json::json!({
            "schema_version": SEMANTIC_MODEL_SCHEMA_VERSION,
            "pack_id": "pin.fixture", "version": "1.0.0",
            "producer": {"name": "pin-test", "version": "1.0.0"},
            "language": "java", "ecosystem": "maven",
            "compatibility": {"toolchains": []},
            "provenance": {"source": "pin-test"},
            "license": "Apache-2.0", "completeness": "complete",
            "safety": {"generated_code_only": false, "review_required": false},
            "shards": [
                {"id": "first", "activation": [{"package": {"name": "pin:fixture"}}], "payload": {"kind": "declaration_facts", "types": [{"id":"type.first","name":"pin.First","type_kind":"class","visibility":"public","locator":{"kind":"artifact","path":"pin/First.class","symbol":"pin.First"}}]}},
                {"id": "second", "activation": [{"package": {"name": "pin:fixture"}}], "payload": {"kind": "declaration_facts", "types": [{"id":"type.second","name":"pin.Second","type_kind":"class","visibility":"public","locator":{"kind":"artifact","path":"pin/Second.class","symbol":"pin.Second"}}]}}
            ]
        });
        let pack = crate::analyzer::semantic_model::compiler::compile_source(
            crate::analyzer::semantic_model::source::SourceFormat::Json,
            &serde_json::to_vec(&source).unwrap(),
            &crate::analyzer::semantic_model::compiler::CompilerOptions::default(),
        )
        .unwrap();
        let pack = super::super::generated_test_pack(&pack, &"a".repeat(64));
        let key = GeneratedProductionKey::new(
            "a".repeat(64),
            &pack.manifest.producer.name,
            &pack.manifest.producer.version,
            pack.manifest.schema_version,
        )
        .unwrap();
        catalog
            .install_generated(&key, &pack, &super::super::test_input_slots())
            .unwrap();
        let expected = [
            ExpectedCatalogEntry::Production {
                production_digest: key.production_digest().to_owned(),
            },
            ExpectedCatalogEntry::Production {
                production_digest: "0".repeat(64),
            },
            ExpectedCatalogEntry::Shard {
                kind: CatalogPackSourceKind::Generated,
                manifest_digest: pack.manifest.content_sha256.clone(),
                shard_id: pack.manifest.shards[0].shard_id.clone(),
            },
        ];
        let reader = catalog
            .pinned_jvm_reader(&expected, CancellationToken::new())
            .unwrap();
        assert_eq!(reader.membership.len(), 4);
        assert!(
            reader.membership[..2]
                .iter()
                .all(|row| row.ordinal == 0 && row.status == PinnedCatalogStatus::Present)
        );
        assert_eq!(reader.membership[2].ordinal, 1);
        assert_eq!(reader.membership[2].status, PinnedCatalogStatus::Missing);
        assert_eq!(reader.membership[2].manifest_digest, None);
        assert_eq!(reader.membership[3].status, PinnedCatalogStatus::Present);
        drop(reader);
        catalog
            .connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE catalog_packs SET state='quarantined' WHERE manifest_digest=?1",
                [&pack.manifest.content_sha256],
            )
            .unwrap();
        let reader = catalog
            .pinned_jvm_reader(&expected[..1], CancellationToken::new())
            .unwrap();
        assert!(
            reader
                .membership
                .iter()
                .all(|row| row.status == PinnedCatalogStatus::Quarantined)
        );
    }

    #[test]
    fn missing_expected_ordinal_and_cancelled_wait_are_explicit() {
        let root = tempfile::tempdir().unwrap();
        let catalog = SemanticPackCatalog::open(
            root.path(),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        let token = CancellationToken::new();
        let expected = [
            ExpectedCatalogEntry::Shard {
                kind: CatalogPackSourceKind::Embedded,
                manifest_digest: "0".repeat(64),
                shard_id: "missing".to_owned(),
            },
            ExpectedCatalogEntry::SourceIdentity {
                producer: crate::analyzer::semantic_model::Producer::for_name("unkeyed-jdk"),
                source_identity: None,
            },
        ];
        let reader = catalog.pinned_jvm_reader(&expected, token.clone()).unwrap();
        assert_eq!(reader.membership[0].status, PinnedCatalogStatus::Missing);
        assert_eq!(reader.membership[1].ordinal, 1);
        assert_eq!(reader.membership[1].status, PinnedCatalogStatus::Missing);
        let guard = reader.connection.lock().unwrap();
        let result = std::thread::scope(|scope| {
            let worker = scope.spawn(|| reader.owned_rows("SELECT 1", [], &token));
            token.cancel();
            worker.join().unwrap()
        });
        drop(guard);
        assert!(matches!(result, Err(PinnedReaderError::Cancelled)));
        assert_eq!(
            reader
                .owned_rows("SELECT 1", [], &CancellationToken::default())
                .unwrap(),
            vec![vec![Value::Integer(1)]]
        );
    }
}
