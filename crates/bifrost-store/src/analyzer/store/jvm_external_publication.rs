//! Exact, sealed publication of a JVM provider's catalog row projection.

use super::{AnalyzerStore, Result, StoreError};
use rusqlite::{
    OptionalExtension, Transaction, TransactionBehavior, params, params_from_iter, types::Value,
};
use sha2::{Digest, Sha256};

fn projection_identity_from_lever(lever: [u8; 32]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"jvm-external-projection-identity/v1");
    digest.update(lever);
    digest.update(brokk_bifrost_semantic::analyzer::semantic_model::catalog::rows::SEMANTIC_ROWS_INDEX_VERSION.to_le_bytes());
    digest.finalize().into()
}

pub fn jvm_external_projection_identity() -> [u8; 32] {
    static IDENTITY: std::sync::LazyLock<[u8; 32]> = std::sync::LazyLock::new(|| {
        projection_identity_from_lever(brokk_bifrost_core::lever_tokens::lever_identity(
            "jvm-external-projection",
            brokk_bifrost_core::lever_file!("jvm-external-projection.tokens"),
        ))
    });
    *IDENTITY
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn jvm_external_projection_identity_before_last_token() -> [u8; 32] {
    projection_identity_from_lever(
        brokk_bifrost_core::lever_tokens::lever_identity_before_last_token(
            "jvm-external-projection",
            brokk_bifrost_core::lever_file!("jvm-external-projection.tokens"),
        ),
    )
}

/// Identity of one artifact projection; the database stores this as TEXT.
pub fn jvm_external_provider_id(semantic_sha256: &str) -> String {
    jvm_external_provider_id_for_identity(semantic_sha256, &jvm_external_projection_identity())
}

pub fn jvm_external_provider_id_for_identity(semantic_sha256: &str, identity: &[u8; 32]) -> String {
    use brokk_bifrost_core::analyzer::canonical_hash::{CanonicalHasher, lower_hex_string};
    let mut digest = CanonicalHasher::new(b"jvm-external-provider:v1");
    digest.field("semantic_sha256", semantic_sha256.as_bytes());
    digest.field("projection_identity", identity);
    lower_hex_string(&digest.finish())
}

/// Guard negative reads in the same SQLite statement as the inventory rows.
/// The captured clock covers sealed request providers and legacy uncertified
/// activation alike. Replacement or eviction invalidates either proof; #12428
/// slice 3 removes the legacy writer branch.
pub(crate) fn jvm_inventory_guarded_sql(sql: &str, generation_parameter: usize) -> String {
    format!(
        "SELECT inventory_rows.*, (SELECT generation FROM jvm_external_inventory_generation WHERE id=0)=?{generation_parameter} AS inventory_current FROM (SELECT 1) LEFT JOIN (SELECT query_rows.*, 1 AS inventory_present FROM ({sql}) query_rows) inventory_rows ON 1"
    )
}

/// Add sealing evidence in the same statement and captured epoch as a row fill.
pub(super) fn jvm_inventory_guarded_memo_sql(
    sql: &str,
    generation_parameter: usize,
    providers_parameter: usize,
    identity_parameter: usize,
) -> String {
    let guarded = jvm_inventory_guarded_sql(sql, generation_parameter);
    format!(
        "SELECT guarded.*, NOT EXISTS(SELECT 1 FROM json_each(?{providers_parameter}) selected LEFT JOIN jvm_external_provider_publications publication ON publication.provider_id=selected.value WHERE publication.publication_state IS NOT 'sealed' OR publication.projection_identity IS NOT ?{identity_parameter}) AS inventory_sealed FROM ({guarded}) guarded"
    )
}

/// Sealed provider contents and independent catalog/intrinsic answers are
/// immutable for the request. Mutable legacy rows remain tied to their epoch.
#[derive(Clone, Copy, Debug)]
pub(in crate::analyzer::store) enum JvmInventoryMemoProof {
    Immutable,
    Legacy(i64),
}

impl JvmInventoryMemoProof {
    pub(super) fn from_sealed(sealed: bool, generation: i64) -> Self {
        if sealed {
            Self::Immutable
        } else {
            Self::Legacy(generation)
        }
    }

    pub(super) fn capture(
        connection: &rusqlite::Connection,
        providers: &[String],
        generation: i64,
    ) -> Result<Self> {
        let providers = serde_json::to_string(providers).expect("provider identities serialize");
        let sql = jvm_inventory_guarded_memo_sql("SELECT 1", 2, 1, 3);
        let (current, sealed): (bool, bool) = connection.query_row(
            &sql,
            params![providers, generation, jvm_external_projection_identity()],
            |row| Ok((row.get(2)?, row.get(3)?)),
        )?;
        if !current {
            return Err(StoreError::stale_resolution(
                "JVM provider inventory changed during the request",
            ));
        }
        Ok(Self::from_sealed(sealed, generation))
    }

    pub(super) fn validate_cached(self, connection: &rusqlite::Connection) -> Result<()> {
        if let Self::Legacy(generation) = self {
            let sql = jvm_inventory_guarded_sql("SELECT 1", 1);
            let current: bool = connection.query_row(&sql, [generation], |row| row.get(2))?;
            if !current {
                return Err(StoreError::stale_resolution(
                    "JVM provider inventory changed during the request",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::Immutable, proof) | (proof, Self::Immutable) => proof,
            (Self::Legacy(left), Self::Legacy(right)) => Self::Legacy(left.min(right)),
        }
    }

    pub(super) fn validate_capture(self, generation: i64) -> Result<()> {
        if let Self::Legacy(captured) = self
            && captured != generation
        {
            return Err(StoreError::stale_resolution(
                "JVM provider inventory changed during the request",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(in crate::analyzer::store) struct JvmInventoryMemoValue<T> {
    value: T,
    proof: JvmInventoryMemoProof,
}

impl<T> JvmInventoryMemoValue<T> {
    pub(super) fn new(value: T, proof: JvmInventoryMemoProof) -> Self {
        Self { value, proof }
    }
    pub(super) fn into_value(self) -> T {
        self.value
    }
    pub(super) fn proof(&self) -> JvmInventoryMemoProof {
        self.proof
    }
    pub(super) fn read_cached(&self, connection: &rusqlite::Connection) -> Result<&T> {
        self.proof.validate_cached(connection)?;
        Ok(&self.value)
    }
}

/// A request clock can advance only across a contiguous prefix of its own writes.
/// An older source binding remains covered by that prefix; a source clock from
/// before the prefix instead exposes an earlier, unaccounted-for change.
#[derive(Clone, Copy, Debug)]
pub(in crate::analyzer::store) struct JvmInventoryRequestClock {
    captured: i64,
    generation: i64,
}

impl JvmInventoryRequestClock {
    pub(super) fn captured(generation: i64) -> Self {
        Self {
            captured: generation,
            generation,
        }
    }

    pub(super) fn generation(self) -> i64 {
        self.generation
    }
    pub(super) fn captured_generation(self) -> i64 {
        self.captured
    }

    #[cfg(test)]
    pub(super) fn after_own_publications(mut self, generation: i64) -> Self {
        assert!(
            generation >= self.generation,
            "the JVM inventory clock is monotonic"
        );
        self.generation = generation;
        self
    }

    pub(super) fn with_source_generation(self, source: Option<i64>) -> Self {
        match source {
            Some(generation) if generation < self.captured => Self::captured(generation),
            // Only the owned writer prefix can advance a captured clock. A newer
            // independent binding must not hide a foreign inventory mutation.
            _ => self,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PublicationStore {
    Local(usize),
    Persistent(usize),
}

impl PublicationStore {
    fn for_store(store: &AnalyzerStore) -> Self {
        match &store.conn {
            super::StoreWriter::Local(writer) => Self::Local(std::ptr::from_ref(writer) as usize),
            super::StoreWriter::Persistent(writer) => {
                Self::Persistent(std::sync::Arc::as_ptr(writer) as usize)
            }
        }
    }
}

pub(super) fn request_jvm_inventory_reader(
    models: &crate::analyzer::semantic_model::ResolvedActiveSemanticModels,
) -> std::result::Result<
    Option<super::model_catalog::RequestRowReader>,
    crate::analyzer::semantic_model::FamilyOpen,
> {
    if models.shards().iter().any(|shard| {
        shard.request_owned()
            && matches!(
                shard.manifest.language.as_str(),
                "java" | "kotlin" | "scala"
            )
    }) && let Some(source) = models.request_source()
    {
        return source.jvm_reader(models).map(Some);
    }
    Ok(None)
}

/// Runtime proof shared by clones of one certified request reader. The
/// certificate stays immutable; only a committed own-publication token can
/// extend its upper bound. This object contains no per-file state.
#[doc(hidden)]
pub struct JvmInventoryPublicationClock {
    store: PublicationStore,
    certified_generation: i64,
    upper: std::sync::atomic::AtomicI64,
}

impl JvmInventoryPublicationClock {
    pub(super) fn snapshot(&self) -> JvmInventoryRequestClock {
        JvmInventoryRequestClock {
            captured: self.certified_generation,
            generation: self.generation(),
        }
    }

    fn generation(&self) -> i64 {
        self.upper.load(std::sync::atomic::Ordering::Acquire)
    }

    fn advance(&self, proof: publication_transaction::CommittedOwnPublication) {
        let (observed, committed) = proof.generations();
        assert!(committed >= observed, "inventory generations are monotonic");
        assert_eq!(
            self.upper.compare_exchange(
                observed,
                committed,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            ),
            Ok(observed),
            "the store writer lock serializes advances of one request clock"
        );
    }
}

impl AnalyzerStore {
    /// Construct once when certifying a request reader, then retain it in that
    /// reader's OuterRequest resource. Never reuse this handle in a new request.
    #[doc(hidden)]
    pub fn jvm_inventory_publication_clock(
        &self,
        certified_generation: i64,
    ) -> std::sync::Arc<JvmInventoryPublicationClock> {
        std::sync::Arc::new(JvmInventoryPublicationClock {
            store: PublicationStore::for_store(self),
            certified_generation,
            upper: std::sync::atomic::AtomicI64::new(certified_generation),
        })
    }
}

pub(super) type PublicationClock = std::sync::Arc<JvmInventoryPublicationClock>;
thread_local! {
    static OWN_PUBLICATION_CLOCK: std::cell::RefCell<Option<PublicationClock>> = const { std::cell::RefCell::new(None) };
}

/// Keep attribution across the writer dispatch, without locking discovery.
pub(super) fn with_jvm_inventory_publication_clock<T>(
    store: &AnalyzerStore,
    clock: &PublicationClock,
    work: impl FnOnce() -> T,
) -> T {
    assert!(clock.store == PublicationStore::for_store(store));
    struct RestoreClock(Option<PublicationClock>);
    impl Drop for RestoreClock {
        fn drop(&mut self) {
            OWN_PUBLICATION_CLOCK.with(|slot| {
                slot.replace(self.0.take());
            });
        }
    }
    let previous = OWN_PUBLICATION_CLOCK.with(|slot| slot.replace(Some(clock.clone())));
    let restore = RestoreClock(previous);
    let value = work();
    drop(restore);
    value
}

#[cfg(test)]
fn with_jvm_inventory_own_publications<T>(
    store: &AnalyzerStore,
    generation: i64,
    work: impl FnOnce() -> T,
) -> (T, i64) {
    let clock = store.jvm_inventory_publication_clock(generation);
    let value = with_jvm_inventory_publication_clock(store, &clock, work);
    (value, clock.generation())
}

pub(super) fn own_jvm_inventory_publication_clock(
    store: &AnalyzerStore,
) -> Option<PublicationClock> {
    let store = PublicationStore::for_store(store);
    OWN_PUBLICATION_CLOCK.with(|slot| {
        slot.borrow()
            .as_ref()
            .filter(|clock| clock.store == store)
            .cloned()
    })
}

// Only this module can construct the token. In particular neither the reader
// nor a readiness frame can manufacture an advance from a later observation.
mod publication_transaction {
    use super::*;

    pub(super) struct CommittedOwnPublication {
        observed: i64,
        committed: i64,
    }

    impl CommittedOwnPublication {
        pub(super) fn generations(self) -> (i64, i64) {
            (self.observed, self.committed)
        }
    }

    pub(in crate::analyzer::store) struct JvmExternalPublicationTransaction<'connection> {
        transaction: Transaction<'connection>,
        own_clock: Option<(PublicationClock, i64)>,
    }

    impl<'connection> JvmExternalPublicationTransaction<'connection> {
        pub(in crate::analyzer::store) fn begin(
            connection: &'connection mut rusqlite::Connection,
            own_clock: Option<PublicationClock>,
        ) -> Result<Self> {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let own_clock = match own_clock {
                Some(clock) => {
                    let observed =
                        AnalyzerStore::jvm_external_inventory_generation_in_snapshot(&transaction)?;
                    (clock.generation() == observed).then_some((clock, observed))
                }
                None => None,
            };
            Ok(Self {
                transaction,
                own_clock,
            })
        }

        pub(in crate::analyzer::store) fn commit(self) -> Result<()> {
            let published = self
                .own_clock
                .map(|(clock, observed)| {
                    AnalyzerStore::jvm_external_inventory_generation_in_snapshot(&self.transaction)
                        .map(|committed| (clock, observed, committed))
                })
                .transpose()?;
            self.transaction.commit()?;
            if let Some((clock, observed, committed)) = published {
                // Both callers execute this whole method under StoreWriter's
                // Local mutex or serialized persistent writer job. That writer
                // lock remains held after SQLite COMMIT and through advance.
                clock.advance(CommittedOwnPublication {
                    observed,
                    committed,
                });
            }
            Ok(())
        }
    }

    impl<'connection> std::ops::Deref for JvmExternalPublicationTransaction<'connection> {
        type Target = Transaction<'connection>;
        fn deref(&self) -> &Self::Target {
            &self.transaction
        }
    }
}

pub(super) use publication_transaction::JvmExternalPublicationTransaction;

/// Values use the target inventory table's column order, including provider_id.
/// The caller reads these through its pinned catalog handle. No decoded shard is used.
#[derive(Debug)]
pub struct JvmExternalProjection {
    pub semantic_sha256: String,
    pub provider_id: String,
    pub source_identity: String,
    pub owners: Vec<Vec<Value>>,
    pub members: Vec<Vec<Value>>,
    pub supertypes: Vec<Vec<Value>>,
}

/// Certificate observed by the request's own publication transaction.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct JvmExternalCertificate {
    pub provider_id: String,
    pub projection_identity: [u8; 32],
    pub source_identity: String,
    pub projection_digest: Vec<u8>,
}

fn read_certificate(
    conn: &rusqlite::Connection,
    provider: &str,
) -> Result<Option<JvmExternalCertificate>> {
    Ok(conn.prepare_cached("SELECT projection_identity,source_identity,projected_rows_sha256 FROM jvm_external_provider_publications WHERE provider_id=?1 AND publication_state='sealed'")?
        .query_row([provider], |row| Ok(JvmExternalCertificate {
            provider_id: provider.to_owned(), projection_identity: row.get(0)?,
            source_identity: row.get(1)?, projection_digest: row.get(2)?,
        })).optional()?)
}

fn read_certificates_in_snapshot(
    conn: &rusqlite::Connection,
    providers: &str,
) -> Result<Vec<JvmExternalCertificate>> {
    let mut statement = conn.prepare_cached(
        "SELECT provider_id,projection_identity,source_identity,projected_rows_sha256
                 FROM jvm_external_provider_publications
                 WHERE provider_id IN (SELECT value FROM json_each(?1))
                   AND projection_identity=?2 AND publication_state='sealed'",
    )?;
    Ok(statement
        .query_map(
            params![providers, jvm_external_projection_identity()],
            |row| {
                Ok(JvmExternalCertificate {
                    provider_id: row.get(0)?,
                    projection_identity: row.get(1)?,
                    source_identity: row.get(2)?,
                    projection_digest: row.get(3)?,
                })
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JvmExternalPublication {
    Available,
    Unavailable,
    Conflict,
}

const OWNER_COLUMNS: &str = "provider_id,owner_fqn,callables_complete,values_complete,types_complete,supertypes_complete,type_parameters_jsonb";
const MEMBER_COLUMNS: &str = "provider_id,owner_fqn,ordinal,member_name,member_kind,visibility,is_static,signature_present,callable_family_complete,non_overridable,parameters_jsonb,return_type_jsonb,is_abstract,type_parameters_jsonb";
const MEMBER_READ_COLUMNS: &str = "provider_id,owner_fqn,ordinal,member_name,member_kind,visibility,is_static,signature_present,callable_family_complete,non_overridable,json(parameters_jsonb),json(return_type_jsonb),is_abstract,json(type_parameters_jsonb)";
const SUPERTYPE_COLUMNS: &str = "provider_id,owner_fqn,supertype_fqn,ordinal,type_arguments_jsonb";
const OWNER_READ_COLUMNS: &str = "provider_id,owner_fqn,callables_complete,values_complete,types_complete,supertypes_complete,json(type_parameters_jsonb)";
const SUPERTYPE_READ_COLUMNS: &str =
    "provider_id,owner_fqn,supertype_fqn,ordinal,json(type_arguments_jsonb)";

fn canonical_rows(rows: &[Vec<Value>], columns: usize, digest: &mut Sha256) -> Result<()> {
    let mut encoded = Vec::with_capacity(rows.len());
    for row in rows {
        assert_eq!(row.len(), columns, "JVM projection row width");
        let mut bytes = Vec::new();
        for value in row {
            let (tag, payload): (u8, Vec<u8>) = match value {
                Value::Null => (0, Vec::new()),
                Value::Integer(n) => (1, n.to_le_bytes().to_vec()),
                Value::Real(n) => (2, n.to_bits().to_le_bytes().to_vec()),
                Value::Text(s) => (3, s.as_bytes().to_vec()),
                Value::Blob(b) => (4, b.clone()),
            };
            bytes.push(tag);
            bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
            bytes.extend_from_slice(&payload);
        }
        encoded.push(bytes);
    }
    encoded.sort_unstable();
    for row in encoded {
        digest.update((row.len() as u64).to_le_bytes());
        digest.update(row);
    }
    Ok(())
}

/// Identity of the provider inventory read by a retained JVM index.
/// Certified projections are immutable; legacy rows are hashed by value.
impl AnalyzerStore {
    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
    pub fn jvm_external_provider_inventory_digest(&self, provider: &str) -> Result<[u8; 32]> {
        let conn = self.read_conn()?;
        let snapshot = conn.unchecked_transaction()?;
        Self::jvm_external_provider_inventory_digest_in_snapshot(&snapshot, provider)
    }

    /// Hash the inventory alongside the owner, member and supertype rows it
    /// identifies, including their generic-surface columns (#12385).
    pub fn jvm_external_provider_inventory_digest_in_snapshot(
        conn: &rusqlite::Connection,
        provider: &str,
    ) -> Result<[u8; 32]> {
        let mut digest = Sha256::new();
        digest.update(b"jvm_external_provider_inventory/v2");
        let identity = jvm_external_projection_identity();
        // A persisted read key can name an older binary's retained provider.
        // Replay belongs to this binary's identity, even if that row still exists.
        digest.update(identity);
        let publication = conn
            .prepare_cached(
                "SELECT publication_state,projection_identity,projected_rows_sha256,source_identity
             FROM jvm_external_provider_publications
             WHERE provider_id=?1 AND projection_identity=?2",
            )?
            .query_row(params![provider, identity], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    (1..4)
                        .map(|column| row.get::<_, Value>(column))
                        .collect::<rusqlite::Result<Vec<_>>>()?,
                ))
            })
            .optional()?;
        let Some((state, certificate)) = publication else {
            digest.update(b"unavailable");
            return Ok(digest.finalize().into());
        };
        if state == "sealed" {
            digest.update(b"certified");
            canonical_rows(&[certificate], 3, &mut digest)?;
        } else {
            assert_eq!(state, "uncertified", "closed JVM publication state");
            digest.update(b"legacy");
            for (table, columns, width) in [
                ("jvm_external_owners", OWNER_READ_COLUMNS, 7),
                ("jvm_external_owner_members", MEMBER_READ_COLUMNS, 14),
                ("jvm_external_owner_supertypes", SUPERTYPE_READ_COLUMNS, 5),
            ] {
                digest.update(table.as_bytes());
                let mut statement = conn.prepare_cached(&format!(
                    "SELECT {columns} FROM {table} WHERE provider_id=?1"
                ))?;
                let rows = statement
                    .query_map([provider], |row| {
                        (0..width)
                            .map(|column| row.get::<_, Value>(column))
                            .collect::<rusqlite::Result<Vec<_>>>()
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                canonical_rows(&rows, width, &mut digest)?;
            }
        }
        Ok(digest.finalize().into())
    }
}

fn projection_digest(source: &JvmExternalProjection) -> Result<Vec<u8>> {
    let mut digest = Sha256::new();
    digest.update(b"jvm-external-projection-v2");
    for (tag, rows, width) in [
        (0u8, &source.owners, 7),
        (1, &source.members, 14),
        (2, &source.supertypes, 5),
    ] {
        digest.update([tag]);
        digest.update((rows.len() as u64).to_le_bytes());
        canonical_rows(rows, width, &mut digest)?;
    }
    Ok(digest.finalize().to_vec())
}

fn certificate_matches(
    tx: &Transaction<'_>,
    source: &JvmExternalProjection,
    digest: &[u8],
) -> Result<bool> {
    // The source identity is certificate metadata: equal projected rows from
    // another source certify availability without rewriting rows or identity.
    // Binding directly from a sealed certificate still requires the caller's
    // own source (jvm_external_source_certificate).
    type Certificate = ([u8; 32], Vec<u8>, i64, i64, i64);
    let certificate: Option<Certificate> = tx.prepare_cached(
        "SELECT projection_identity,projected_rows_sha256,owner_count,member_count,supertype_count FROM jvm_external_provider_publications WHERE provider_id=?1 AND publication_state='sealed'",
    )?.query_row([&source.provider_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
    ).optional()?;
    Ok(certificate.is_some_and(|row| {
        row == (
            jvm_external_projection_identity(),
            digest.to_vec(),
            source.owners.len() as i64,
            source.members.len() as i64,
            source.supertypes.len() as i64,
        )
    }))
}

fn read_rows(
    tx: &Transaction<'_>,
    table: &str,
    columns: &str,
    provider: &str,
    width: usize,
) -> Result<Vec<Vec<Value>>> {
    let sql = format!("SELECT {columns} FROM {table} WHERE provider_id=?1");
    let mut statement = tx.prepare_cached(&sql)?;
    let rows = statement
        .query_map([provider], |row| {
            (0..width)
                .map(|i| row.get(i))
                .collect::<rusqlite::Result<Vec<Value>>>()
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn readback_matches(
    tx: &Transaction<'_>,
    source: &JvmExternalProjection,
    digest: &[u8],
) -> Result<bool> {
    let actual = JvmExternalProjection {
        semantic_sha256: source.semantic_sha256.clone(),
        provider_id: source.provider_id.clone(),
        source_identity: source.source_identity.clone(),
        owners: read_rows(
            tx,
            "jvm_external_owners",
            OWNER_READ_COLUMNS,
            &source.provider_id,
            7,
        )?,
        members: read_rows(
            tx,
            "jvm_external_owner_members",
            MEMBER_READ_COLUMNS,
            &source.provider_id,
            14,
        )?,
        supertypes: read_rows(
            tx,
            "jvm_external_owner_supertypes",
            SUPERTYPE_READ_COLUMNS,
            &source.provider_id,
            5,
        )?,
    };
    Ok(actual.owners.len() == source.owners.len()
        && actual.members.len() == source.members.len()
        && actual.supertypes.len() == source.supertypes.len()
        && projection_digest(&actual)? == digest)
}

impl AnalyzerStore {
    /// A sealed certificate certifies the pure projection of this exact source.
    pub fn jvm_external_source_certified(
        &self,
        provider_id: &str,
        source_identity: &str,
    ) -> Result<bool> {
        Ok(self
            .jvm_external_source_certificate(provider_id, source_identity)?
            .is_some())
    }

    /// Read the request's bounded provider set in one statement.
    pub fn jvm_external_source_certificates(
        &self,
        providers: &[String],
    ) -> Result<Vec<JvmExternalCertificate>> {
        let providers =
            serde_json::to_string(providers).map_err(|error| StoreError::new(error.to_string()))?;
        self.conn
            .execute(move |conn| read_certificates_in_snapshot(conn, &providers))
    }

    /// Capture the request clock only while all retained certificates still match.
    pub fn jvm_external_certified_generation(
        &self,
        mut certificates: Vec<JvmExternalCertificate>,
    ) -> Result<Option<i64>> {
        certificates.sort_unstable();
        certificates.dedup();
        let providers = serde_json::to_string(
            &certificates
                .iter()
                .map(|certificate| &certificate.provider_id)
                .collect::<Vec<_>>(),
        )
        .map_err(|error| StoreError::new(error.to_string()))?;
        self.conn.execute(move |conn| {
            let tx = conn.transaction()?;
            let generation = Self::jvm_external_inventory_generation_in_snapshot(&tx)?;
            let mut current = read_certificates_in_snapshot(&tx, &providers)?;
            current.sort_unstable();
            if current != certificates {
                return Ok(None);
            }
            Ok(Some(generation))
        })
    }

    pub fn jvm_external_source_certificate(
        &self,
        provider_id: &str,
        source_identity: &str,
    ) -> Result<Option<JvmExternalCertificate>> {
        let provider_id = provider_id.to_owned();
        let source_identity = source_identity.to_owned();
        self.conn.execute(move |conn| {
            Ok(read_certificate(conn, &provider_id)?.filter(|certificate| {
                certificate.source_identity == source_identity
                    && certificate.projection_identity == jvm_external_projection_identity()
            }))
        })
    }

    /// A missing or conflicting certificate is typed unavailable for read-only callers.
    pub fn jvm_external_publication_status(
        &self,
        source: JvmExternalProjection,
    ) -> Result<JvmExternalPublication> {
        Ok(self
            .jvm_external_publication_status_with_certificate(source)?
            .0)
    }

    pub fn jvm_external_publication_status_with_certificate(
        &self,
        source: JvmExternalProjection,
    ) -> Result<(JvmExternalPublication, Option<JvmExternalCertificate>)> {
        let digest = projection_digest(&source)?;
        self.conn.execute(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Deferred)?;
            let matches = certificate_matches(&tx, &source, &digest)?;
            Ok(if matches {
                (
                    JvmExternalPublication::Available,
                    read_certificate(&tx, &source.provider_id)?,
                )
            } else {
                (JvmExternalPublication::Unavailable, None)
            })
        })
    }

    /// Read the persistent inventory generation in a fresh read snapshot.
    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
    pub fn jvm_external_inventory_generation(&self) -> Result<i64> {
        let conn = self.read_conn()?;
        Self::jvm_external_inventory_generation_in_snapshot(&conn)
    }

    /// Read alongside inventory rows on the caller's existing read transaction.
    pub fn jvm_external_inventory_generation_in_snapshot(
        conn: &rusqlite::Connection,
    ) -> Result<i64> {
        Ok(conn
            .prepare_cached("SELECT generation FROM jvm_external_inventory_generation WHERE id=0")?
            .query_row([], |row| row.get(0))?)
    }

    /// The source callback belongs to the pinned catalog handle. An absent source cannot certify absence.
    pub fn publish_jvm_external_projection(
        &self,
        source: impl FnOnce() -> Result<Option<JvmExternalProjection>>,
        cancelled: impl Fn() -> bool + Send + 'static,
    ) -> Result<JvmExternalPublication> {
        Ok(self
            .publish_jvm_external_projection_with_certificate(source, cancelled)?
            .0)
    }

    pub fn publish_jvm_external_projection_with_certificate(
        &self,
        source: impl FnOnce() -> Result<Option<JvmExternalProjection>>,
        cancelled: impl Fn() -> bool + Send + 'static,
    ) -> Result<(JvmExternalPublication, Option<JvmExternalCertificate>)> {
        let Some(source) = source()? else {
            return Ok((JvmExternalPublication::Unavailable, None));
        };
        assert_ne!(source.semantic_sha256, "jvm-intrinsic");
        assert_ne!(source.provider_id, "jvm-intrinsic");
        assert_eq!(
            source.provider_id,
            jvm_external_provider_id(&source.semantic_sha256)
        );
        for rows in [&source.owners, &source.members, &source.supertypes] {
            for row in rows {
                assert_eq!(row.first(), Some(&Value::Text(source.provider_id.clone())));
            }
        }
        let digest = projection_digest(&source)?;
        let own_clock = own_jvm_inventory_publication_clock(self);
        self.conn.execute(move |conn| {
            let tx = JvmExternalPublicationTransaction::begin(conn, own_clock)?;
            if cancelled() { return Err(StoreError::cancelled("JVM publication cancelled")); }
            if certificate_matches(&tx, &source, &digest)? {
                if !readback_matches(&tx, &source, &digest)? {
                    return Ok((JvmExternalPublication::Conflict, None));
                }
                return Ok((JvmExternalPublication::Available, read_certificate(&tx, &source.provider_id)?));
            }
            let exists: bool = tx.prepare_cached("SELECT EXISTS(SELECT 1 FROM jvm_external_provider_publications WHERE provider_id=?1)")?.query_row([&source.provider_id], |row| row.get(0))?;
            if exists {
                let state: String = tx.prepare_cached("SELECT publication_state FROM jvm_external_provider_publications WHERE provider_id=?1")?.query_row([&source.provider_id], |row| row.get(0))?;
                if state != "uncertified" {
                    return Ok((JvmExternalPublication::Conflict, None));
                }
                // Withdraw the uncertified parent and its cascading inventory before sealing.
                // The transaction also rolls back its generation triggers on failure.
                tx.prepare_cached("DELETE FROM jvm_external_provider_publications WHERE provider_id=?1")?.execute([&source.provider_id])?;
            }
            // Legacy rows have no certificate and cannot be trusted, even if their counts agree.
            tx.prepare_cached("DELETE FROM jvm_external_owners WHERE provider_id=?1")?.execute([&source.provider_id])?;
            for (table, columns, placeholders, rows) in [
                ("jvm_external_owners", OWNER_COLUMNS, "?1,?2,?3,?4,?5,?6,jsonb(?7)", &source.owners),
                ("jvm_external_owner_members", MEMBER_COLUMNS, "?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,jsonb(?11),jsonb(?12),?13,jsonb(?14)", &source.members),
                ("jvm_external_owner_supertypes", SUPERTYPE_COLUMNS, "?1,?2,?3,?4,jsonb(?5)", &source.supertypes),
            ] {
                let sql = format!("INSERT INTO {table}({columns}) VALUES({placeholders})");
                let mut statement = tx.prepare_cached(&sql)?;
                for row in rows {
                    if cancelled() { return Err(StoreError::cancelled("JVM publication cancelled")); }
                    statement.execute(params_from_iter(row))?;
                }
            }
            if !readback_matches(&tx, &source, &digest)? {
                return Err(StoreError::new("JVM provider projection readback mismatch"));
            }
            if cancelled() { return Err(StoreError::cancelled("JVM publication cancelled")); }
            tx.prepare_cached("INSERT INTO jvm_external_provider_publications(provider_id,source_identity,projection_identity,projected_rows_sha256,owner_count,member_count,supertype_count,semantic_sha256,publication_state) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'sealed')")?.execute(
                params![source.provider_id, source.source_identity, jvm_external_projection_identity(), digest,
                    source.owners.len(), source.members.len(), source.supertypes.len(), source.semantic_sha256])?;
            let certificate = read_certificate(&tx, &source.provider_id)?;
            tx.commit()?;
            Ok((JvmExternalPublication::Available, certificate))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy_types() -> Vec<crate::analyzer::semantic_model::TypeFact> {
        serde_json::from_value(serde_json::json!([{
            "id":"owner", "name":"p.C", "type_kind":"class", "visibility":"public",
            "locator":{"kind":"artifact","path":"fixture.jar","symbol":"p.C"}
        }]))
        .unwrap()
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12245: lazy own publication invalidated cold requests or refreshed over foreign writes"
    )]
    #[expect(
        clippy::disallowed_methods,
        reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
    )]
    fn own_publication_advances_only_an_uninterrupted_request_clock() {
        use super::super::resolution_operation::{
            nominal_rules::jvm_external_owner_relations, selected_jvm_declaration_owner,
        };
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let types = legacy_types();
        let captured = store.jvm_external_inventory_generation().unwrap();
        let other = AnalyzerStore::open_ephemeral().unwrap();
        let ((), unaffected) = with_jvm_inventory_own_publications(&store, captured, || {
            other
                .publish_jvm_external_inventory_facts("other-store".into(), &types, &[], true)
                .unwrap();
        });
        assert_eq!(
            unaffected, captured,
            "equal scalar clocks in another store are a different domain"
        );
        assert_eq!(store.jvm_external_inventory_generation().unwrap(), captured);
        let (providers, published) = with_jvm_inventory_own_publications(&store, captured, || {
            store
                .publish_jvm_external_inventory_facts("owned-legacy".into(), &types, &[], true)
                .unwrap();
            store
                .publish_jvm_external_projection(|| Ok(Some(source())), || false)
                .unwrap();
            vec![
                jvm_external_provider_id("owned-legacy"),
                jvm_external_provider_id("sha"),
            ]
        });
        assert!(published > captured);
        assert_eq!(
            published,
            store.jvm_external_inventory_generation().unwrap()
        );
        let state: String = store.read_conn().unwrap().query_row("SELECT publication_state FROM jvm_external_provider_publications WHERE provider_id=?1", [jvm_external_provider_id("owned-legacy")], |row| row.get(0)).unwrap();
        assert_eq!(
            state, "uncertified",
            "own-clock adoption does not change the legacy publication contract"
        );
        for provider in &providers {
            let owner = selected_jvm_declaration_owner(
                jvm_external_owner_relations(),
                &store.read_conn().unwrap(),
                None,
                std::slice::from_ref(provider),
                "p.C",
                published,
            )
            .unwrap();
            assert_eq!(owner.unwrap().unwrap().provider_id.as_ref(), provider);
        }
        let clock = JvmInventoryRequestClock::captured(captured).after_own_publications(published);
        assert_eq!(
            clock.with_source_generation(Some(captured)).generation(),
            published
        );
        assert_eq!(
            clock
                .with_source_generation(Some(published + 1))
                .generation(),
            published
        );
        assert_eq!(
            JvmInventoryRequestClock::captured(published)
                .with_source_generation(Some(captured))
                .generation(),
            captured
        );

        // The foreign write happens after capture and before this request's
        // own writer transaction acquires the lock. It must prevent adoption.
        store
            .publish_jvm_external_inventory_facts("foreign".into(), &types, &[], true)
            .unwrap();
        let (providers, unchanged) = with_jvm_inventory_own_publications(&store, published, || {
            store
                .publish_jvm_external_inventory_facts(
                    "owned-after-foreign".into(),
                    &types,
                    &[],
                    true,
                )
                .unwrap();
            vec![jvm_external_provider_id("owned-after-foreign")]
        });
        assert_eq!(unchanged, published);
        assert!(store.jvm_external_inventory_generation().unwrap() > unchanged);
        let failure = selected_jvm_declaration_owner(
            jvm_external_owner_relations(),
            &store.read_conn().unwrap(),
            None,
            &providers,
            "p.C",
            unchanged,
        )
        .unwrap_err();
        assert!(failure.is_stale_resolution());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12786: a later readiness frame rewound the request's own adopted inventory generation and reported a store error"
    )]
    #[expect(
        clippy::disallowed_methods,
        reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
    )]
    fn request_reader_clock_shares_owned_prefix_and_starts_fresh_per_outer_request() {
        use super::super::model_catalog::{
            CatalogRowReader, OwnedCatalogRows, ReaderBinding, RequestRowReader,
        };
        use super::super::resolution_operation::{
            nominal_rules::jvm_external_owner_relations,
            selected_jvm_declaration_owner_with_memo_proof,
        };
        use brokk_bifrost_core::analyzer::outer_request::{
            OuterRequest, RequestEntryKey, RequestResource,
        };
        use std::sync::Arc;

        struct UnusedCatalogRows;
        impl CatalogRowReader for UnusedCatalogRows {
            fn owned_rows(
                &self,
                _: &str,
                _: &[(&str, &dyn rusqlite::ToSql)],
                _: &brokk_bifrost_core::cancellation::CancellationToken,
            ) -> std::result::Result<
                OwnedCatalogRows,
                crate::analyzer::semantic_model::catalog::CatalogError,
            > {
                unimplemented!("this regression reads the real store, not catalog rows")
            }
        }
        struct ReaderEntry(RequestRowReader);
        impl RequestResource for ReaderEntry {
            fn close(&self) {}
        }

        let store = AnalyzerStore::open_ephemeral().unwrap();
        let (_, certificate) = store
            .publish_jvm_external_projection_with_certificate(|| Ok(Some(source())), || false)
            .unwrap();
        let certificate = certificate.unwrap();
        // The actual OuterRequest resource map supplies the memo lifetime and
        // single fill. The reader carries real same-transaction certification;
        // no workspace, filesystem listing, or ignore receipt is involved.
        let reader = |request: &OuterRequest| {
            request
                .resource::<ReaderEntry, StoreError>(
                    RequestEntryKey::JvmReaderDerivation {
                        activation: "request-clock-fixture".into(),
                        view: [0; 32],
                        excluded: [0; 32],
                        questions: [0; 32],
                        view_stamp: None,
                        generation: 0,
                    },
                    || {
                        let generation = store
                            .jvm_external_certified_generation(vec![certificate.clone()])?
                            .expect("the unchanged provider certificate is valid");
                        Ok(Arc::new(ReaderEntry(RequestRowReader {
                            derivation_extension: Default::default(),
                            certified_providers: std::collections::HashSet::from([certificate
                                .provider_id
                                .clone()]),
                            inventory_generation: Some(generation),
                            inventory_clock: Some(
                                store.jvm_inventory_publication_clock(generation),
                            ),
                            reader: Arc::new(UnusedCatalogRows),
                            binding: ReaderBinding([0; 32]),
                        })))
                    },
                )
                .unwrap()
                .0
                .clone()
        };
        let guarded_owner = |reader: &RequestRowReader, providers: &[String]| {
            let generation = reader
                .inventory_clock
                .as_ref()
                .unwrap()
                .snapshot()
                .with_source_generation(reader.inventory_generation)
                .generation();
            selected_jvm_declaration_owner_with_memo_proof(
                jvm_external_owner_relations(),
                &store.read_conn().unwrap(),
                None,
                providers,
                "p.Direct",
                generation,
            )
        };
        let request = OuterRequest::new();
        let first = reader(&request);
        let certified = first.inventory_generation;
        let certified_providers = first.certified_providers.clone();
        let clock = first.inventory_clock.as_ref().unwrap();
        let mut direct_types = legacy_types();
        direct_types[0].name = "p.Direct".into();
        let providers = vec![jvm_external_provider_id("request-own-direct")];
        assert!(
            guarded_owner(&first, &providers)
                .unwrap()
                .into_value()
                .is_none()
        );
        with_jvm_inventory_publication_clock(&store, clock, || {
            store
                .publish_jvm_external_inventory_facts(
                    "request-own-direct".into(),
                    &direct_types,
                    &[],
                    true,
                )
                .unwrap();
        });
        let adopted = clock.generation();
        assert!(adopted > certified.unwrap());
        let second = reader(&request);
        assert_eq!(second.inventory_generation, certified);
        assert_eq!(second.certified_providers, certified_providers);
        assert!(Arc::ptr_eq(clock, second.inventory_clock.as_ref().unwrap()));
        let acquired = guarded_owner(&second, &providers).unwrap();
        assert!(matches!(acquired.proof(), JvmInventoryMemoProof::Legacy(_)));
        let owner = acquired.clone().into_value().unwrap().unwrap();
        assert_eq!(owner.provider_id.as_ref(), providers[0]);
        acquired.read_cached(&store.read_conn().unwrap()).unwrap();

        // Outside the owned scope, even a publication preserving selected
        // provider contents must invalidate a fresh read and a legacy memo hit.
        store
            .publish_jvm_external_inventory_facts(
                "foreign-request".into(),
                &legacy_types(),
                &[],
                true,
            )
            .unwrap();
        assert_eq!(clock.generation(), adopted);
        assert!(
            guarded_owner(&second, &providers)
                .unwrap_err()
                .is_stale_resolution()
        );
        assert!(
            acquired
                .read_cached(&store.read_conn().unwrap())
                .unwrap_err()
                .is_stale_resolution()
        );
        request.close();
        let next_request = OuterRequest::new();
        let fresh = reader(&next_request);
        let current = store.jvm_external_inventory_generation().unwrap();
        assert_eq!(fresh.inventory_generation, Some(current));
        assert_ne!(fresh.inventory_generation, certified);
        assert!(!Arc::ptr_eq(clock, fresh.inventory_clock.as_ref().unwrap()));
        assert_eq!(
            fresh.inventory_clock.as_ref().unwrap().generation(),
            current
        );
        assert_eq!(
            guarded_owner(&fresh, &providers)
                .unwrap()
                .into_value()
                .unwrap()
                .unwrap(),
            owner
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12245: a mutable JVM owner memo reused a withdrawn inventory epoch"
    )]
    #[expect(
        clippy::disallowed_methods,
        reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
    )]
    fn request_owner_memos_carry_only_sealed_provider_proofs() {
        use super::super::resolution_operation::{
            nominal_rules::jvm_external_owner_relations,
            selected_jvm_declaration_owner_with_memo_proof,
        };
        use super::super::selected_read_memo::ExactReadMemo;
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let types = legacy_types();
        store
            .publish_jvm_external_projection(|| Ok(Some(source())), || false)
            .unwrap();
        store
            .publish_jvm_external_inventory_facts("memo-legacy".into(), &types, &[], true)
            .unwrap();
        let generation = store.jvm_external_inventory_generation().unwrap();
        let sealed = vec![jvm_external_provider_id("sha")];
        let legacy = vec![jvm_external_provider_id("memo-legacy")];
        let mixed = vec![sealed[0].clone(), legacy[0].clone()];
        let connection = store.read_conn().unwrap();
        let mut sealed_memo = ExactReadMemo::default();
        let mut legacy_memo = ExactReadMemo::default();
        let mut mixed_memo = ExactReadMemo::default();
        let read = |providers: &[String], fqn| {
            selected_jvm_declaration_owner_with_memo_proof(
                jvm_external_owner_relations(),
                &connection,
                None,
                providers,
                fqn,
                generation,
            )
        };
        for fqn in ["p.C", "p.New"] {
            sealed_memo.insert(fqn.to_owned(), read(&sealed, fqn).unwrap());
            legacy_memo.insert(fqn.to_owned(), read(&legacy, fqn).unwrap());
            mixed_memo.insert(fqn.to_owned(), read(&mixed, fqn).unwrap());
        }
        assert!(
            sealed_memo
                .get(&"p.C".to_owned())
                .unwrap()
                .read_cached(&connection)
                .unwrap()
                .is_some()
        );
        assert!(
            sealed_memo
                .get(&"p.New".to_owned())
                .unwrap()
                .read_cached(&connection)
                .unwrap()
                .is_none()
        );
        let evicted = sealed[0].clone();
        let modified = legacy[0].clone();
        store.conn.execute(move |conn| -> Result<()> {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute("DELETE FROM jvm_external_provider_publications WHERE provider_id=?1", [evicted])?;
            tx.execute("INSERT INTO jvm_external_owners(provider_id,owner_fqn,callables_complete,values_complete,types_complete,supertypes_complete,type_parameters_jsonb) VALUES(?1,'p.New',1,1,1,1,jsonb('[]'))", [modified])?;
            tx.commit()?;
            Ok(())
        }).unwrap();
        assert!(store.jvm_external_inventory_generation().unwrap() > generation);
        for fqn in ["p.C", "p.New"] {
            // ExactReadMemo is owned by one non-clone operation. Its sealed
            // values were acquired at G and remain facts about that snapshot.
            assert!(
                sealed_memo
                    .get(&fqn.to_owned())
                    .unwrap()
                    .read_cached(&connection)
                    .is_ok()
            );
            assert!(
                legacy_memo
                    .get(&fqn.to_owned())
                    .unwrap()
                    .read_cached(&connection)
                    .unwrap_err()
                    .is_stale_resolution()
            );
            assert!(
                mixed_memo
                    .get(&fqn.to_owned())
                    .unwrap()
                    .read_cached(&connection)
                    .unwrap_err()
                    .is_stale_resolution()
            );
            assert!(read(&sealed, fqn).unwrap_err().is_stale_resolution());
            assert!(read(&legacy, fqn).unwrap_err().is_stale_resolution());
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12245: eviction after provider capture was treated as certified absence"
    )]
    fn evicted_provider_opens_negative_read_until_republication_refreshes_capture() {
        use super::super::resolution_operation::{
            nominal_rules::jvm_external_owner_relations, selected_jvm_declaration_owner,
        };
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let publish = || {
            store
                .publish_jvm_external_projection_with_certificate(|| Ok(Some(source())), || false)
                .unwrap()
                .1
                .unwrap()
        };
        let certificate = publish();
        let captured = store
            .jvm_external_certified_generation(vec![certificate])
            .unwrap()
            .unwrap();
        let read = |generation| {
            store.conn.execute(move |conn| {
                selected_jvm_declaration_owner(
                    jvm_external_owner_relations(),
                    conn,
                    None,
                    &[jvm_external_provider_id("sha")],
                    "example.Missing",
                    generation,
                )
            })
        };
        assert_eq!(read(captured).unwrap(), None); // No change: absence is proven.
        store.conn.execute(|conn| -> Result<()> {
            let mut identity = jvm_external_projection_identity();
            for offset in [1, 2] {
                identity[0] ^= offset;
                conn.execute("INSERT INTO jvm_external_provider_publications(provider_id,semantic_sha256,source_identity,projection_identity,publication_state) VALUES(?1,'sha','',?2,'uncertified')", params![jvm_external_provider_id_for_identity("sha", &identity), identity])?;
            }
            Ok(())
        }).unwrap();
        assert_eq!(store.reclaim_jvm_external_publications().unwrap(), 1);
        assert!(read(captured).unwrap_err().is_stale_resolution());
        let certificate = publish();
        assert!(read(captured).unwrap_err().is_stale_resolution());
        let refreshed = store
            .jvm_external_certified_generation(vec![certificate])
            .unwrap()
            .unwrap();
        assert_eq!(read(refreshed).unwrap(), None); // Our publication and refreshed capture remain usable.
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: request binding read provider certificates one at a time"
    )]
    fn provider_certificate_reads_are_batched() {
        use brokk_bifrost_core::cache_db::sql_profile::{ListenerEvent, attach_listener};
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let counter = count.clone();
        let guard = store.conn.execute(move |conn| -> Result<_> {
            for i in 0..100 {
                conn.execute("INSERT INTO jvm_external_provider_publications(provider_id,semantic_sha256,source_identity,projection_identity,publication_state,projected_rows_sha256,owner_count,member_count,supertype_count) VALUES(?1,?1,'source',?2,'sealed',zeroblob(32),0,0,0)", params![format!("p{i}"), jvm_external_projection_identity()])?;
            }
            Ok(attach_listener(conn, Arc::new(move |event| {
                if matches!(event, ListenerEvent::Statement { .. }) {
                    counter.fetch_add(1, Ordering::Relaxed);
                }
            })))
        }).unwrap();
        for size in [1, 5, 100] {
            count.store(0, Ordering::Relaxed);
            let providers = (0..size).map(|i| format!("p{i}")).collect::<Vec<_>>();
            let certificates = store.jvm_external_source_certificates(&providers).unwrap();
            assert_eq!(certificates.len(), size);
            assert!(certificates.iter().all(|c| c.source_identity == "source"));
            assert_eq!(count.load(Ordering::Relaxed), 1);
        }
        drop(guard);
    }

    #[test]
    fn publication_returns_the_certificate_it_observed() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let (status, written) = store
            .publish_jvm_external_projection_with_certificate(|| Ok(Some(source())), || false)
            .unwrap();
        assert_eq!(status, JvmExternalPublication::Available);
        let written = written.expect("successful publication has its certificate");
        assert_eq!(written.provider_id, jvm_external_provider_id("sha"));
        assert_eq!(written.source_identity, source().source_identity);
        assert_eq!(
            written.projection_identity,
            jvm_external_projection_identity()
        );
        assert_eq!(
            written.projection_digest,
            projection_digest(&source()).unwrap()
        );
        let (_, observed) = store
            .jvm_external_publication_status_with_certificate(source())
            .unwrap();
        assert_eq!(observed.as_ref(), Some(&written));
        assert_eq!(
            store
                .jvm_external_source_certificate(
                    &jvm_external_provider_id("sha"),
                    &written.source_identity
                )
                .unwrap(),
            Some(written)
        );
        assert!(
            store
                .jvm_external_source_certificate(
                    &jvm_external_provider_id("sha"),
                    "different-source"
                )
                .unwrap()
                .is_none()
        );
    }

    fn source() -> JvmExternalProjection {
        JvmExternalProjection {
            semantic_sha256: "sha".into(),
            provider_id: jvm_external_provider_id("sha"),
            source_identity: "sha".into(),
            owners: vec![vec![
                Value::Text(jvm_external_provider_id("sha")),
                Value::Text("p.C".into()),
                Value::Integer(1),
                Value::Integer(1),
                Value::Integer(1),
                Value::Integer(1),
                Value::Text("[]".into()),
            ]],
            members: [false, true]
                .into_iter()
                .enumerate()
                .map(|(ordinal, is_abstract)| {
                    vec![
                        Value::Text(jvm_external_provider_id("sha")),
                        Value::Text("p.C".into()),
                        Value::Integer(ordinal as i64),
                        Value::Text(format!("run{ordinal}")),
                        Value::Text("method".into()),
                        Value::Text("public".into()),
                        Value::Integer(0),
                        Value::Integer(1),
                        Value::Integer(1),
                        Value::Null,
                        Value::Text("[]".into()),
                        Value::Null,
                        Value::Integer(i64::from(is_abstract)),
                        Value::Text("[]".into()),
                    ]
                })
                .collect(),
            supertypes: vec![],
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: retained JVM inventory missed publications from another connection"
    )]
    fn jvm_external_generation_tracks_another_connection_and_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inventory.db");
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        let other = rusqlite::Connection::open(&path).unwrap();
        other.execute_batch("PRAGMA foreign_keys=ON").unwrap();
        let mut previous = store.jvm_external_inventory_generation().unwrap();
        for sql in [
            "INSERT INTO jvm_external_provider_publications(provider_id,semantic_sha256,source_identity,projection_identity,publication_state) VALUES('p','p','',zeroblob(32),'uncertified')",
            "INSERT INTO jvm_external_owners(provider_id,owner_fqn,callables_complete,values_complete,types_complete,supertypes_complete) VALUES('p','Owner',1,1,1,1)",
            "INSERT INTO jvm_external_owner_members(provider_id,owner_fqn,ordinal,member_name,member_kind,visibility,is_static,signature_present,callable_family_complete,non_overridable,parameters_jsonb,return_type_jsonb,is_abstract) VALUES('p','Owner',0,'method','method','public',0,1,1,0,jsonb('[]'),NULL,NULL)",
            "INSERT INTO jvm_external_owner_supertypes(provider_id,owner_fqn,supertype_fqn,ordinal) VALUES('p','Owner','Parent',0)",
            "UPDATE jvm_external_owners SET callables_complete=0",
            "UPDATE jvm_external_owner_members SET member_name='changed'",
            "UPDATE jvm_external_owner_supertypes SET supertype_fqn='Other'",
            "DELETE FROM jvm_external_owner_members",
            "DELETE FROM jvm_external_owner_supertypes",
            "DELETE FROM jvm_external_provider_publications",
        ] {
            other.execute_batch(sql).unwrap();
            let generation = store.jvm_external_inventory_generation().unwrap();
            assert!(generation > previous, "{sql}");
            previous = generation;
        }
        let mut reader = rusqlite::Connection::open(&path).unwrap();
        let snapshot = reader.transaction().unwrap();
        assert_eq!(
            AnalyzerStore::jvm_external_inventory_generation_in_snapshot(&snapshot).unwrap(),
            previous
        );
        other
            .execute_batch("INSERT INTO jvm_external_provider_publications(provider_id,semantic_sha256,source_identity,projection_identity,publication_state) VALUES('q','q','',zeroblob(32),'uncertified'); INSERT INTO jvm_external_owners(provider_id,owner_fqn,callables_complete,values_complete,types_complete,supertypes_complete) VALUES('q','New',1,1,1,1)")
            .unwrap();
        assert_eq!(
            AnalyzerStore::jvm_external_inventory_generation_in_snapshot(&snapshot).unwrap(),
            previous
        );
        snapshot.commit().unwrap();
        assert!(store.jvm_external_inventory_generation().unwrap() > previous);
    }

    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
    )]
    fn publication_preserves_other_identity() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let mut identity = jvm_external_projection_identity();
        identity[0] ^= 1;
        store.conn.execute(move |conn| -> Result<()> {
            let old_provider = jvm_external_provider_id_for_identity("sha", &identity);
            conn.execute("INSERT INTO jvm_external_provider_publications(provider_id,semantic_sha256,source_identity,projection_identity,publication_state) VALUES(?1,'sha','old-source',?2,'uncertified')", params![old_provider, identity])?;
            conn.execute("INSERT INTO jvm_external_owners(provider_id,owner_fqn,callables_complete,values_complete,types_complete,supertypes_complete) VALUES(?1,'old.Owner',0,0,0,0)", [old_provider])?;
            Ok(())
        }).unwrap();
        assert!(
            store
                .jvm_external_source_certificates(&[jvm_external_provider_id("sha")])
                .unwrap()
                .is_empty()
        );
        assert!(
            !store
                .jvm_external_source_certified(&jvm_external_provider_id("sha"), "old-source")
                .unwrap()
        );
        let generation_before = store.jvm_external_inventory_generation().unwrap();
        let result = store
            .publish_jvm_external_projection(|| Ok(Some(source())), || false)
            .unwrap();
        assert_eq!(result, JvmExternalPublication::Available);
        assert!(store.jvm_external_inventory_generation().unwrap() > generation_before);
        let old_owner: bool = store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM jvm_external_owners WHERE owner_fqn='old.Owner')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(old_owner);
        assert!(
            store
                .jvm_external_source_certified(&jvm_external_provider_id("sha"), "sha")
                .unwrap()
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11148: legacy JVM member rows lacked declaration kind and must reproject before sealing"
    )]
    fn publication_after_legacy_eviction_seals_rows() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .conn
            .execute(|conn| -> Result<()> {
                let provider = jvm_external_provider_id("sha");
                conn.execute("INSERT INTO jvm_external_provider_publications(provider_id,semantic_sha256,source_identity,projection_identity,publication_state) VALUES(?1,'sha','',?2,'uncertified')", params![provider, jvm_external_projection_identity()])?;
                conn.execute("INSERT INTO jvm_external_owners(provider_id,owner_fqn,callables_complete,values_complete,types_complete,supertypes_complete) VALUES(?1,'p.C',0,0,0,0)", [&provider])?;
                conn.execute("INSERT INTO jvm_external_owner_members(provider_id,owner_fqn,ordinal,member_name,member_kind,visibility,is_static,signature_present,callable_family_complete,parameters_jsonb) VALUES((SELECT provider_id FROM jvm_external_provider_publications WHERE semantic_sha256='sha'),'p.C',0,'run0','method','public',0,1,1,jsonb('[]'))", [])?;
                let flag: Option<bool> = conn.query_row("SELECT is_abstract FROM jvm_external_owner_members WHERE provider_id=(SELECT provider_id FROM jvm_external_provider_publications WHERE semantic_sha256='sha')", [], |row| row.get(0))?;
                assert_eq!(flag, None);
                Ok(())
            })
            .unwrap();
        assert_eq!(
            store.jvm_external_publication_status(source()).unwrap(),
            JvmExternalPublication::Unavailable
        );
        store
            .conn
            .execute(|conn| {
                conn.execute(
                    "DELETE FROM jvm_external_provider_publications WHERE semantic_sha256='sha'",
                    [],
                )
            })
            .unwrap();
        assert_eq!(
            store
                .publish_jvm_external_projection(|| Ok(Some(source())), || false)
                .unwrap(),
            JvmExternalPublication::Available
        );
        assert_eq!(
            store.jvm_external_publication_status(source()).unwrap(),
            JvmExternalPublication::Available
        );
        store
            .conn
            .execute(|conn| -> Result<()> {
                let flags = conn.prepare("SELECT is_abstract FROM jvm_external_owner_members WHERE provider_id=(SELECT provider_id FROM jvm_external_provider_publications WHERE semantic_sha256='sha') ORDER BY ordinal")?
                    .query_map([], |row| row.get::<_, Option<bool>>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                assert_eq!(flags, [Some(false), Some(true)]);
                assert!(conn.execute("UPDATE jvm_external_owner_members SET is_abstract=NULL WHERE provider_id=(SELECT provider_id FROM jvm_external_provider_publications WHERE semantic_sha256='sha')", []).is_err());
                assert!(
                    conn.execute(
                        "UPDATE jvm_external_owners SET values_complete=0 WHERE provider_id=(SELECT provider_id FROM jvm_external_provider_publications WHERE semantic_sha256='sha')",
                        []
                    )
                    .is_err()
                );
                assert!(
                    conn.execute(
                        "DELETE FROM jvm_external_owners WHERE provider_id=(SELECT provider_id FROM jvm_external_provider_publications WHERE semantic_sha256='sha')",
                        []
                    )
                    .is_err()
                );
            assert!(
                conn.execute(
                    "UPDATE jvm_external_provider_publications SET owner_count=0 WHERE provider_id=(SELECT provider_id FROM jvm_external_provider_publications WHERE semantic_sha256='sha')",
                    []
                )
                .is_err()
            );
                Ok(())
            })
            .unwrap();
    }

    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
    )]
    fn curated_then_generated_certificate_uses_projected_rows() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let mut curated = source();
        curated.source_identity = "installed:manifest:shard".into();
        let digest = projection_digest(&curated).unwrap();
        assert_eq!(
            store
                .publish_jvm_external_projection(|| Ok(Some(curated)), || false)
                .unwrap(),
            JvmExternalPublication::Available
        );
        let mut generated = source();
        generated.source_identity = "generated:manifest:production".into();
        assert_eq!(projection_digest(&generated).unwrap(), digest);
        assert_eq!(
            store.jvm_external_publication_status(source()).unwrap(),
            JvmExternalPublication::Available
        );
        assert_eq!(
            store
                .publish_jvm_external_projection(|| Ok(Some(generated)), || false)
                .unwrap(),
            JvmExternalPublication::Available
        );
        let mut different = source();
        different.source_identity = "generated:manifest:production".into();
        different.owners[0][2] = Value::Integer(0);
        assert_eq!(
            store
                .publish_jvm_external_projection(|| Ok(Some(different)), || false)
                .unwrap(),
            JvmExternalPublication::Conflict
        );
        let stored: Vec<u8> = store.read_conn().unwrap().query_row("SELECT projected_rows_sha256 FROM jvm_external_provider_publications WHERE provider_id=(SELECT provider_id FROM jvm_external_provider_publications WHERE semantic_sha256='sha')", [], |row| row.get(0)).unwrap();
        assert_eq!(stored, digest);
    }

    #[test]
    fn cancelled_publication_rolls_back() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        assert!(
            store
                .publish_jvm_external_projection(|| Ok(Some(source())), {
                    let checks = std::sync::atomic::AtomicUsize::new(0);
                    move || checks.fetch_add(1, std::sync::atomic::Ordering::Relaxed) == 2
                })
                .is_err()
        );
        assert_eq!(
            store.jvm_external_publication_status(source()).unwrap(),
            JvmExternalPublication::Unavailable
        );
        store
            .conn
            .execute(|conn| -> Result<()> {
                let count: i64 = conn.query_row(
                    "SELECT count(*) FROM jvm_external_owners WHERE provider_id=(SELECT provider_id FROM jvm_external_provider_publications WHERE semantic_sha256='sha')",
                    [],
                    |row| row.get(0),
                )?;
                assert_eq!(count, 0);
                Ok(())
            })
            .unwrap();
        assert_eq!(
            store
                .publish_jvm_external_projection(|| Ok(Some(source())), || false)
                .unwrap(),
            JvmExternalPublication::Available
        );
        assert!(
            store
                .jvm_external_source_certified(&jvm_external_provider_id("sha"), "sha")
                .unwrap()
        );
    }

    #[test]
    fn missing_source_is_unavailable() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        assert_eq!(
            store
                .publish_jvm_external_projection(|| Ok(None), || false)
                .unwrap(),
            JvmExternalPublication::Unavailable
        );
    }

    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
    )]
    fn same_sha_different_projection_conflicts() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .publish_jvm_external_projection(|| Ok(Some(source())), || false)
            .unwrap();
        let mut different = source();
        different.owners[0][2] = Value::Integer(0);
        assert_eq!(
            store
                .publish_jvm_external_projection(|| Ok(Some(different)), || false)
                .unwrap(),
            JvmExternalPublication::Conflict
        );
        assert_eq!(
            store.jvm_external_publication_status(source()).unwrap(),
            JvmExternalPublication::Available
        );
        let owner_complete: i64 = store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT callables_complete FROM jvm_external_owners WHERE provider_id=(SELECT provider_id FROM jvm_external_provider_publications WHERE semantic_sha256='sha')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(owner_complete, 1);
    }

    #[test]
    fn concurrent_publishers_verify_one_certificate() {
        use std::sync::{Arc, Barrier};

        let store = Arc::new(AnalyzerStore::open_ephemeral().unwrap());
        // Count actual row writes: one certificate alone would also pass after
        // a redundant delete/reinsert, which is the activation/bind race defect.
        store
            .conn
            .execute(|conn| -> Result<()> {
                conn.execute_batch(
                    "CREATE TABLE publication_writes(count INTEGER NOT NULL);
                 INSERT INTO publication_writes VALUES(0);
                 CREATE TRIGGER count_publication_writes AFTER INSERT ON jvm_external_owners
                 BEGIN UPDATE publication_writes SET count=count+1; END;",
                )?;
                Ok(())
            })
            .unwrap();
        let clock = store
            .jvm_inventory_publication_clock(store.jvm_external_inventory_generation().unwrap());
        let barrier = Arc::new(Barrier::new(2));
        std::thread::scope(|scope| {
            let spawn = || {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                let clock = Arc::clone(&clock);
                scope.spawn(move || {
                    barrier.wait();
                    with_jvm_inventory_publication_clock(&store, &clock, || {
                        store.publish_jvm_external_projection(|| Ok(Some(source())), || false)
                    })
                })
            };
            let first = spawn();
            let second = spawn();
            assert_eq!(
                first.join().unwrap().unwrap(),
                JvmExternalPublication::Available
            );
            assert_eq!(
                second.join().unwrap().unwrap(),
                JvmExternalPublication::Available
            );
        });
        assert_eq!(
            clock.generation(),
            store.jvm_external_inventory_generation().unwrap()
        );
        store
            .conn
            .execute(|conn| -> Result<()> {
                let count: i64 = conn.query_row(
                "SELECT count(*) FROM jvm_external_provider_publications WHERE provider_id=(SELECT provider_id FROM jvm_external_provider_publications WHERE semantic_sha256='sha')",
                [],
                |row| row.get(0),
            )?;
                assert_eq!(count, 1);
                let writes: i64 =
                    conn.query_row("SELECT count FROM publication_writes", [], |row| row.get(0))?;
                assert_eq!(
                    writes, 1,
                    "activation and bind must write the projection once"
                );
                Ok(())
            })
            .unwrap();
    }
}
