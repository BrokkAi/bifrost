pub mod epoch;
pub mod gc;
pub mod liveness;
pub mod query;

use std::cell::RefCell;
use std::fmt;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bincode::Options;
use git2::Oid;
use growable_bloom_filter::GrowableBloom;
use rusqlite::{
    Connection, OptionalExtension, ToSql, Transaction, TransactionBehavior, params,
    params_from_iter,
};
use sha2::{Digest, Sha256};
use tree_sitter::Language as TsLanguage;

use crate::CancellationToken;
use crate::analyzer::fq_name::{FqName, segment_interner};
use crate::analyzer::model::MAX_SIGNATURE_METADATA_BLOB_BYTES;
use crate::analyzer::rust::facts::{
    RustExportFact, RustIdentifierOccurrence, RustImportTargetFact, RustMacroGateFact,
    RustModuleFact, RustModuleRouteFact, RustModuleRouteFacts, RustModuleScopeFact,
    RustRulesItemMacroDefinition, RustUsageFacts, decode_rust_visibility, encode_rust_visibility,
};
use crate::analyzer::rust::imports::RustVisibility;
use crate::analyzer::structural::materialization::{
    MaterializationRecord, MaterializationRecordPayload,
};
use crate::analyzer::tree_sitter_analyzer::{FileState, LanguageAdapter};
use crate::analyzer::{
    CodeUnit, CodeUnitType, CppTemplateMetadata, ImportInfo, Language, ProjectFile, QueryBatch,
    Range, RubyMethodDispatchMode, SignatureMetadata, SummaryFileProjection,
};
use crate::gitblob;
use crate::hash::{HashMap, HashSet, set_with_capacity};
use crate::text_utils::compute_line_starts;

const PREPARED_WRITE_IMMEDIATE_RETRIES: usize = 2;
const STALE_GENERATION_RECLAIM_ROWS: usize = 10_000;
const MAX_LIMITED_QUERY_ROW_BYTES: usize = MAX_SIGNATURE_METADATA_BLOB_BYTES;
const MAX_LIMITED_QUERY_AGGREGATE_BYTES: usize = MAX_SIGNATURE_METADATA_BLOB_BYTES;

pub fn analyzer_db_path(workspace_root: &Path) -> PathBuf {
    gitblob::cache_db_path(workspace_root)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError {
    message: String,
    stale_generation: bool,
}

impl StoreError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            stale_generation: false,
        }
    }

    fn stale_generation(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            stale_generation: true,
        }
    }

    pub(crate) fn is_stale_generation(&self) -> bool {
        self.stale_generation
    }

    pub(crate) fn context(self, context: impl fmt::Display) -> Self {
        Self {
            message: format!("{context}: {}", self.message),
            stale_generation: self.stale_generation,
        }
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for StoreError {}

impl From<std::io::Error> for StoreError {
    fn from(err: std::io::Error) -> Self {
        Self::new(format!("analyzer store I/O error: {err}"))
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(err: rusqlite::Error) -> Self {
        Self::new(format!("analyzer store SQLite error: {err}"))
    }
}

impl From<git2::Error> for StoreError {
    fn from(err: git2::Error) -> Self {
        Self::new(format!("analyzer store git error: {err}"))
    }
}

pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SemanticPackActivationSourceKind {
    Installed,
    Generated,
    PreShipped,
    WorkspaceProduced,
    Embedded,
    EphemeralWorkspace,
}

impl SemanticPackActivationSourceKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Installed => "installed",
            Self::Generated => "generated",
            Self::PreShipped => "pre_shipped",
            Self::WorkspaceProduced => "workspace_produced",
            Self::Embedded => "embedded",
            Self::EphemeralWorkspace => "ephemeral_workspace",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "installed" => Ok(Self::Installed),
            "generated" => Ok(Self::Generated),
            "pre_shipped" => Ok(Self::PreShipped),
            "workspace_produced" => Ok(Self::WorkspaceProduced),
            "embedded" => Ok(Self::Embedded),
            "ephemeral_workspace" => Ok(Self::EphemeralWorkspace),
            _ => Err(StoreError::new(format!(
                "unknown semantic-pack activation source kind {value:?}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SemanticPackActiveReference {
    pub manifest_digest: String,
    pub source_kind: SemanticPackActivationSourceKind,
    pub source_id: String,
    pub workspace_produced: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticPackActiveSet {
    pub active_set_digest: String,
    pub members: Vec<SemanticPackActiveReference>,
}

impl SemanticPackActiveSet {
    pub fn from_members(members: &[SemanticPackActiveReference]) -> Result<Self> {
        let mut members = members.to_vec();
        members.sort();
        validate_semantic_pack_active_references(&members)?;
        let active_set_digest = semantic_pack_active_set_digest(&members)?;
        Ok(Self {
            active_set_digest,
            members,
        })
    }
}

// A completed parse is published atomically with its rows. Hot candidate
// queries rely on this marker; full count validation remains on hydration and
// explicit presence checks to quarantine externally corrupted cache rows.
const PARSED_BLOB_COMPLETE_CONDITION: &str = "
meta.is_complete = 1
AND EXISTS (
  SELECT 1
  FROM blobs AS active_blob
  LEFT JOIN analysis_epochs AS active_epoch ON active_epoch.lang = active_blob.lang
  WHERE active_blob.blob_oid = meta.blob_oid
    AND active_blob.lang = meta.lang
    AND active_blob.generation = COALESCE(active_epoch.generation, 0)
)";

const EXACT_PATH_SYMBOL_FQN_SQL: &str =
    "SELECT lang, rel_path, blob_oid, kind, package_name, short_name,
           exact_fqn, normalized_fqn
    FROM path_symbol_units INDEXED BY idx_path_symbol_units_lang_generation_exact_fqn
    WHERE lang = ?1 AND exact_fqn = ?2
      AND generation = COALESCE(
        (SELECT generation FROM analysis_epochs WHERE lang = ?1), 0
      )
    ORDER BY rel_path, exact_fqn";

const PARSED_BLOB_INTEGRITY_CONDITION: &str = "
meta.is_complete = 1
AND EXISTS (
  SELECT 1
  FROM blobs AS active_blob
  LEFT JOIN analysis_epochs AS active_epoch ON active_epoch.lang = active_blob.lang
  WHERE active_blob.blob_oid = meta.blob_oid
    AND active_blob.lang = meta.lang
    AND active_blob.generation = COALESCE(active_epoch.generation, 0)
)
AND
meta.stored_unit_count = (
  SELECT COUNT(*) FROM code_units AS units
  WHERE units.blob_oid = meta.blob_oid AND units.lang = meta.lang
)
AND meta.range_count = (
  SELECT COUNT(*) FROM unit_ranges AS ranges
  WHERE ranges.blob_oid = meta.blob_oid AND ranges.lang = meta.lang
)
AND meta.signature_count = (
  SELECT COUNT(*) FROM unit_signatures AS signatures
  WHERE signatures.blob_oid = meta.blob_oid AND signatures.lang = meta.lang
)
AND meta.signature_metadata_count = (
  SELECT COUNT(*) FROM unit_signature_metadata AS metadata
  WHERE metadata.blob_oid = meta.blob_oid AND metadata.lang = meta.lang
)
AND meta.cpp_template_metadata_count = (
  SELECT COUNT(*) FROM unit_cpp_template_metadata AS metadata
  WHERE metadata.blob_oid = meta.blob_oid AND metadata.lang = meta.lang
)
AND meta.supertype_count = (
  SELECT COUNT(*) FROM unit_supertypes AS supertypes
  WHERE supertypes.blob_oid = meta.blob_oid AND supertypes.lang = meta.lang
)
AND meta.child_count = (
  SELECT COUNT(*) FROM unit_children AS children
  WHERE children.blob_oid = meta.blob_oid AND children.lang = meta.lang
)
AND meta.import_statement_count = (
  SELECT COUNT(*) FROM import_statements AS statements
  WHERE statements.blob_oid = meta.blob_oid AND statements.lang = meta.lang
)
AND meta.import_count = (
  SELECT COUNT(*) FROM import_details AS details
  WHERE details.blob_oid = meta.blob_oid AND details.lang = meta.lang
)
AND meta.type_identifier_count = (
  SELECT COUNT(*) FROM type_identifiers AS identifiers
  WHERE identifiers.blob_oid = meta.blob_oid AND identifiers.lang = meta.lang
)
AND meta.ruby_dispatch_count = (
  SELECT COUNT(*) FROM ruby_method_dispatch_modes AS modes
  WHERE modes.blob_oid = meta.blob_oid AND modes.lang = meta.lang
)
AND meta.scala_trait_count = (
  SELECT COUNT(*) FROM scala_traits AS traits
  WHERE traits.blob_oid = meta.blob_oid AND traits.lang = meta.lang
)";

pub struct AnalyzerStore {
    // Field order is load-bearing for `Drop`: Rust drops struct fields in
    // declaration order, so the writer `conn` and every pooled reader must be
    // closed before `_ephemeral` runs and deletes the backing temp file (open
    // handles block deletion on Windows).
    conn: Mutex<Connection>,
    readers: ReaderPool,
    active_readers: ReaderPool,
    streaming_readers: ReaderPool,
    db_path: Option<PathBuf>,
    lifetime: Arc<()>,
    _ephemeral: Option<EphemeralDb>,
    #[cfg(test)]
    parsed_blob_transaction_starts: AtomicUsize,
    #[cfg(test)]
    parsed_blob_point_contains_queries: AtomicUsize,
    #[cfg(test)]
    replacement_cost_lookup_queries: AtomicUsize,
    #[cfg(test)]
    replacement_cost_fallback_queries: AtomicUsize,
    #[cfg(test)]
    prepared_generation_lookup_queries: AtomicUsize,
}

/// A hand-rolled checkout pool of read-only SQLite connections for one store.
///
/// The writer connection (`AnalyzerStore::conn`) is untouched by reads; every
/// pure-SELECT method borrows a reader here instead, so N concurrent tool calls
/// run their symbol lookups / hydration / search in parallel against WAL
/// snapshots rather than serializing on the single writer mutex.
///
/// Checkout pops an idle reader or lazily opens a fresh one; there is no upper
/// bound on in-flight readers, so a burst never blocks. Checkin keeps at most
/// `capacity` idle connections and drops the rest (transient burst readers), so
/// the steady-state resident pool is bounded by `capacity`.
///
/// When `source` is `None` the store has no separate readable file (the
/// in-memory single-connection fallback); reads then route back through the
/// writer connection so correctness is preserved at the cost of read
/// parallelism.
struct ReaderPool {
    source: Option<PathBuf>,
    capacity: usize,
    idle: Mutex<Vec<Connection>>,
}

thread_local! {
    static STREAMING_READ_DEPTHS: RefCell<HashMap<usize, usize>> =
        RefCell::new(HashMap::default());
}

impl ReaderPool {
    fn new(source: Option<PathBuf>) -> Self {
        let capacity = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .max(4);
        Self {
            source,
            capacity,
            idle: Mutex::new(Vec::new()),
        }
    }

    fn checkin(&self, conn: Connection) {
        let mut idle = self
            .idle
            .lock()
            .expect("analyzer store reader pool poisoned");
        if idle.len() < self.capacity {
            idle.push(conn);
        }
        // Otherwise this was a transient burst connection opened above capacity;
        // let it drop and close.
    }

    fn close_idle(&self) {
        self.idle
            .lock()
            .expect("analyzer store reader pool poisoned")
            .clear();
    }
}

/// RAII handle to a checked-out reader (or the writer, in the fallback path).
/// Derefs to `Connection` so existing read methods — `conn.transaction()`,
/// helper calls taking `&Connection` — work unchanged. On drop, a pooled reader
/// is returned to its pool.
pub(crate) struct ReaderGuard<'a> {
    inner: ReaderConn<'a>,
}

enum ReaderConn<'a> {
    Pooled {
        pool: &'a ReaderPool,
        conn: Option<Connection>,
    },
    Writer(std::sync::MutexGuard<'a, Connection>),
}

impl std::ops::Deref for ReaderGuard<'_> {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        match &self.inner {
            ReaderConn::Pooled { conn, .. } => {
                conn.as_ref().expect("reader guard already returned")
            }
            ReaderConn::Writer(guard) => guard,
        }
    }
}

impl std::ops::DerefMut for ReaderGuard<'_> {
    fn deref_mut(&mut self) -> &mut Connection {
        match &mut self.inner {
            ReaderConn::Pooled { conn, .. } => {
                conn.as_mut().expect("reader guard already returned")
            }
            ReaderConn::Writer(guard) => guard,
        }
    }
}

impl Drop for ReaderGuard<'_> {
    fn drop(&mut self) {
        if let ReaderConn::Pooled { pool, conn } = &mut self.inner
            && let Some(conn) = conn.take()
        {
            pool.checkin(conn);
        }
    }
}

/// Owns a delete-on-drop temp-file cache DB backing an ephemeral (non-git)
/// workspace. All connections are struct-ordered to close before this drops.
struct EphemeralDb {
    path: PathBuf,
}

impl Drop for EphemeralDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_file(self.path.with_extension("db-wal"));
        let _ = std::fs::remove_file(self.path.with_extension("db-shm"));
    }
}

fn validate_semantic_pack_active_references(members: &[SemanticPackActiveReference]) -> Result<()> {
    for member in members {
        if member.manifest_digest.len() != 64
            || !member
                .manifest_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(StoreError::new(format!(
                "semantic-pack manifest digest must be lowercase SHA-256 hex: {:?}",
                member.manifest_digest
            )));
        }
        if member.source_id.is_empty() {
            return Err(StoreError::new(
                "semantic-pack activation source id must not be empty",
            ));
        }
        let expected_workspace_produced = matches!(
            member.source_kind,
            SemanticPackActivationSourceKind::WorkspaceProduced
                | SemanticPackActivationSourceKind::EphemeralWorkspace
        );
        if member.workspace_produced != expected_workspace_produced {
            return Err(StoreError::new(format!(
                "semantic-pack workspace-produced flag disagrees with source kind {:?}",
                member.source_kind
            )));
        }
    }
    if members
        .windows(2)
        .any(|pair| pair[0].manifest_digest == pair[1].manifest_digest)
    {
        return Err(StoreError::new(
            "semantic-pack active set contains a duplicate manifest digest",
        ));
    }
    Ok(())
}

fn semantic_pack_active_set_digest(members: &[SemanticPackActiveReference]) -> Result<String> {
    let mut canonical = members.to_vec();
    canonical.sort();
    validate_semantic_pack_active_references(&canonical)?;
    let mut hasher = Sha256::new();
    hasher.update(b"bifrost.semantic-pack-active-set.v1\0");
    hasher.update((canonical.len() as u64).to_be_bytes());
    for member in &canonical {
        hash_length_prefixed(&mut hasher, member.manifest_digest.as_bytes());
        hash_length_prefixed(&mut hasher, member.source_kind.as_str().as_bytes());
        hash_length_prefixed(&mut hasher, member.source_id.as_bytes());
        hasher.update([u8::from(member.workspace_produced)]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn hash_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn reader_source_path(conn: &Connection) -> Option<PathBuf> {
    conn.path()
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
}

fn unique_temp_db_path() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    // Deliberately not named `bifrost_cache.db`, so the writer's legacy-cache
    // cleanup treats it as unrelated and never touches sibling temp files.
    std::env::temp_dir().join(format!("bifrost-analyzer-{pid}-{nanos}-{counter}.db"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GenerationId(i64);

impl GenerationId {
    pub(crate) const BOOTSTRAP: Self = Self(0);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImportFacts {
    pub(crate) package_name: String,
    pub(crate) imports: Vec<ImportInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateFlags {
    pub is_type_alias: bool,
    pub is_top_level: bool,
    pub in_declarations: bool,
    pub in_definition_lookup: bool,
    pub synthetic: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateRow {
    pub blob_oid: Oid,
    pub lang: String,
    pub unit_key: i64,
    pub kind: CodeUnitType,
    pub short_name: String,
    pub content_qualifier: String,
    pub signature: Option<String>,
    pub flags: CandidateFlags,
    /// The persisted structured identity envelope. It contains either the full
    /// `FqName` and package boundary or a content-stable tail whose path-derived
    /// prefix is supplied by the language adapter during hydration. Every
    /// candidate projection selects this column at index 12.
    pub fq_segments: Option<Vec<u8>>,
}

/// A provider-owned row batch whose work was capped before materialization.
///
/// `inspected` counts source rows examined, which can differ from `rows.len()`
/// after liveness filtering or one persisted blob expanding to multiple live
/// workspace paths. `complete` is false whenever the provider stopped at its
/// supplied cap or observed cancellation, so bounded callers never mistake a
/// partial batch for an authoritative miss.
pub(crate) type LimitedQueryRows<T> = QueryBatch<T>;

#[derive(Debug, Default)]
struct LimitedQueryByteBudget {
    admitted_bytes: usize,
}

impl LimitedQueryByteBudget {
    fn admit_sqlite_bytes(&mut self, raw_bytes: i64) -> Result<bool> {
        let row_bytes = i64_to_usize(raw_bytes)?;
        if row_bytes > MAX_LIMITED_QUERY_ROW_BYTES {
            return Ok(false);
        }
        let Some(total_bytes) = self.admitted_bytes.checked_add(row_bytes) else {
            return Ok(false);
        };
        if total_bytes > MAX_LIMITED_QUERY_AGGREGATE_BYTES {
            return Ok(false);
        }
        self.admitted_bytes = total_bytes;
        Ok(true)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CandidatePrimaryRangeRow {
    pub(crate) candidate: CandidateRow,
    pub(crate) primary_range: Option<Range>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct HierarchyStorageKey {
    pub(crate) blob_oid: Oid,
    pub(crate) lang: String,
    pub(crate) unit_key: i64,
}

pub(crate) struct PersistedHierarchyFacts {
    pub(crate) imports: Arc<[ImportInfo]>,
    pub(crate) raw_supertypes: Arc<[String]>,
}

/// Persisted metadata needed to preserve definition ordering without
/// reconstructing the candidate's complete file state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DefinitionOrderCandidateRow {
    pub(crate) candidate: CandidateRow,
    pub(crate) first_start_byte: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PathSymbolRow {
    pub(crate) rel_path: String,
    pub(crate) blob_oid: Oid,
    pub(crate) kind: CodeUnitType,
    pub(crate) package_name: String,
    pub(crate) short_name: String,
    pub(crate) exact_fqn: String,
    pub(crate) normalized_fqn: String,
}

type PathSymbolRowsResult = Result<Vec<(String, PathSymbolRow)>>;

fn decode_path_symbol_row(
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> rusqlite::Result<PathSymbolRow> {
    let oid_text: String = row.get(offset + 1)?;
    let blob_oid = Oid::from_str(&oid_text).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(
            offset + 1,
            rusqlite::types::Type::Text,
            Box::new(err),
        )
    })?;
    let kind_raw: i64 = row.get(offset + 2)?;
    let kind = code_unit_kind_from_i64(kind_raw).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(
            offset + 2,
            rusqlite::types::Type::Integer,
            Box::new(err),
        )
    })?;
    Ok(PathSymbolRow {
        rel_path: row.get(offset)?,
        blob_oid,
        kind,
        package_name: row.get(offset + 3)?,
        short_name: row.get(offset + 4)?,
        exact_fqn: row.get(offset + 5)?,
        normalized_fqn: row.get(offset + 6)?,
    })
}

/// Shared row-fetch body of `path_symbol_rows_by_fqn_for_langs` and its batched sibling: runs entirely
/// within a caller-supplied transaction so the batch path can resolve many FQN pairs per transaction.
fn path_symbol_rows_by_fqn_in_tx(
    tx: &Transaction,
    langs: &[String],
    exact_fqn: &str,
    normalized_fqn: &str,
) -> Result<Vec<(String, PathSymbolRow)>> {
    let mut out = Vec::new();
    let sql = format!(
        "SELECT lang, rel_path, blob_oid, kind, package_name, short_name,
                exact_fqn, normalized_fqn
         FROM path_symbol_units AS units
         WHERE lang = ?1 AND (exact_fqn = ?2 OR normalized_fqn = ?3)
           AND units.generation = COALESCE(
             (SELECT generation FROM analysis_epochs WHERE lang = units.lang), 0
           )
           AND (
             lang NOT IN ('javascript', 'typescript:ts', 'typescript:tsx')
             OR EXISTS(
               SELECT 1 FROM import_details AS imports
               JOIN blob_meta AS meta
                 ON meta.blob_oid = imports.blob_oid AND meta.lang = imports.lang
               WHERE imports.blob_oid = units.blob_oid AND imports.lang = units.lang
                 AND {PARSED_BLOB_COMPLETE_CONDITION}
             )
           )
         ORDER BY rel_path, exact_fqn"
    );
    for lang in langs {
        if lang == "python" && exact_fqn == normalized_fqn {
            let mut stmt = tx.prepare_cached(EXACT_PATH_SYMBOL_FQN_SQL)?;
            let mapped = stmt.query_map(params![lang, exact_fqn], |row| {
                Ok((row.get(0)?, decode_path_symbol_row(row, 1)?))
            })?;
            out.extend(mapped.collect::<std::result::Result<Vec<_>, _>>()?);
        } else {
            let mut stmt = tx.prepare_cached(&sql)?;
            let mapped = stmt.query_map(params![lang, exact_fqn, normalized_fqn], |row| {
                Ok((row.get(0)?, decode_path_symbol_row(row, 1)?))
            })?;
            out.extend(mapped.collect::<std::result::Result<Vec<_>, _>>()?);
        }
    }
    Ok(out)
}

fn path_symbol_fingerprint(rows: &[PathSymbolRow]) -> String {
    let mut ordered = rows.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        left.rel_path
            .cmp(&right.rel_path)
            .then_with(|| left.exact_fqn.cmp(&right.exact_fqn))
            .then_with(|| left.kind.cmp(&right.kind))
    });
    let mut digest = Sha256::new();
    for row in ordered {
        for value in [
            row.rel_path.as_bytes(),
            row.blob_oid.as_bytes(),
            row.package_name.as_bytes(),
            row.short_name.as_bytes(),
            row.exact_fqn.as_bytes(),
            row.normalized_fqn.as_bytes(),
        ] {
            digest.update(value.len().to_le_bytes());
            digest.update(value);
        }
        digest.update([code_unit_kind_to_i64(row.kind) as u8]);
    }
    format!("{:x}", digest.finalize())
}

fn insert_path_symbol_row(
    statement: &mut rusqlite::Statement<'_>,
    lang: &str,
    generation: GenerationId,
    row: &PathSymbolRow,
) -> rusqlite::Result<usize> {
    statement.execute(params![
        lang,
        row.rel_path,
        row.blob_oid.to_string(),
        code_unit_kind_to_i64(row.kind),
        row.package_name,
        row.short_name,
        row.exact_fqn,
        row.normalized_fqn,
        generation.0,
    ])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchCandidateRow {
    pub candidate: CandidateRow,
    pub primary_range: Option<Range>,
    /// Per-declaration test-region taint (issue #1102): true when this specific
    /// unit is inside a structurally-evidenced test region, replacing the old
    /// file-level `contains_tests` replication so production symbols in a file
    /// with inline tests are not hidden.
    pub in_test_region: bool,
}

/// The minimum persisted projection a `search_symbols` pattern batch needs to
/// decide whether a declaration matches: its short name plus the qualifier its
/// package prefix hydrates from. `lang_index` indexes the caller's storage
/// language-key slice so a row never allocates a language string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SearchCandidateNameRow {
    pub lang_index: usize,
    pub blob_oid: Oid,
    pub unit_key: i64,
    pub short_name: String,
    pub content_qualifier: String,
}

/// A declaration identity that survived pattern matching and therefore earns
/// the full candidate projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SearchCandidateKey {
    pub lang_index: usize,
    pub blob_oid: Oid,
    pub unit_key: i64,
}

/// Persisted facts required to derive callable arity and return types without
/// reconstructing a complete file state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageFactRow {
    pub candidate: CandidateRow,
    pub signature: Option<String>,
    pub signature_metadata: Option<SignatureMetadata>,
}

impl AnalyzerStore {
    pub(crate) fn sync_path_symbol_units(
        &self,
        lang: &str,
        generation: GenerationId,
        rows: &[PathSymbolRow],
    ) -> Result<()> {
        let fingerprint = path_symbol_fingerprint(rows);
        let mut conn = self.conn.lock().expect("analyzer store mutex poisoned");
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        let existing_fingerprint = tx
            .query_row(
                "SELECT fingerprint FROM path_symbol_snapshots
                 WHERE lang = ?1 AND generation = ?2",
                params![lang, generation.0],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing_fingerprint.as_deref() == Some(fingerprint.as_str()) {
            tx.commit()?;
            return Ok(());
        }
        let existing = {
            let mut stmt = tx.prepare(
                "SELECT rel_path, blob_oid, kind, package_name, short_name,
                        exact_fqn, normalized_fqn
                 FROM path_symbol_units WHERE lang = ?1 AND generation = ?2",
            )?;
            let mapped = stmt.query_map(params![lang, generation.0], |row| {
                decode_path_symbol_row(row, 0)
            })?;
            mapped
                .map(|row| row.map(|row| (row.rel_path.clone(), row)))
                .collect::<std::result::Result<HashMap<_, _>, _>>()?
        };
        let wanted: HashMap<_, _> = rows
            .iter()
            .cloned()
            .map(|row| (row.rel_path.clone(), row))
            .collect();

        let mut delete =
            tx.prepare("DELETE FROM path_symbol_units WHERE lang = ?1 AND rel_path = ?2")?;
        for (rel_path, row) in &existing {
            if wanted.get(rel_path) != Some(row) {
                delete.execute(params![lang, rel_path])?;
            }
        }
        drop(delete);

        let mut insert = tx.prepare(
            "INSERT OR REPLACE INTO path_symbol_units(
               lang, rel_path, blob_oid, kind, package_name, short_name,
               exact_fqn, normalized_fqn, generation
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )?;
        for (rel_path, row) in &wanted {
            if existing.get(rel_path) == Some(row) {
                continue;
            }
            insert_path_symbol_row(&mut insert, lang, generation, row)?;
        }
        drop(insert);
        tx.execute(
            "INSERT INTO path_symbol_snapshots(lang, fingerprint, generation) VALUES(?1, ?2, ?3)
             ON CONFLICT(lang) DO UPDATE SET
               fingerprint = excluded.fingerprint,
               generation = excluded.generation",
            params![lang, fingerprint, generation.0],
        )?;
        tx.commit()?;
        let _ = reclaim_stale_generations_conn(&mut conn, STALE_GENERATION_RECLAIM_ROWS);
        Ok(())
    }

    pub(crate) fn path_symbol_rows_by_fqn_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        exact_fqn: &str,
        normalized_fqn: &str,
    ) -> Result<Vec<(String, PathSymbolRow)>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let out = path_symbol_rows_by_fqn_in_tx(&tx, langs, exact_fqn, normalized_fqn)?;
        tx.commit()?;
        Ok(out)
    }

    /// Batched sibling of `path_symbol_rows_by_fqn_for_langs`: resolves many (exact_fqn,
    /// normalized_fqn) pairs in one transaction instead of one transaction per pair. Used by the
    /// Python import resolver so a file with many imports doesn't open one transaction per import.
    ///
    /// The outer `Result` covers setup failures (can't open the transaction at all); each item's own
    /// `Result` is independent, so one FQN's query/decode error doesn't discard the rest of the
    /// batch's already-successful results the way propagating a single `?` through the loop would.
    pub(crate) fn path_symbol_rows_by_fqns_for_langs_batch(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        fqns: &[(String, String)],
    ) -> Result<Vec<PathSymbolRowsResult>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let results = fqns
            .iter()
            .map(|(exact_fqn, normalized_fqn)| {
                path_symbol_rows_by_fqn_in_tx(&tx, langs, exact_fqn, normalized_fqn)
            })
            .collect();
        tx.commit()?;
        Ok(results)
    }

    pub(crate) fn replace_path_symbol_unit(
        &self,
        storage_langs: &[String],
        generations: &HashMap<String, GenerationId>,
        rel_path: &str,
        replacement: Option<(&str, &PathSymbolRow)>,
    ) -> Result<()> {
        let mut conn = self.conn.lock().expect("analyzer store mutex poisoned");
        let tx = conn.transaction()?;
        for lang in storage_langs {
            let generation = generations.get(lang).copied().ok_or_else(|| {
                StoreError::new(format!("missing captured generation for {lang}"))
            })?;
            require_current_generation(&tx, lang, generation)?;
            tx.execute(
                "DELETE FROM path_symbol_units
                 WHERE lang = ?1 AND rel_path = ?2 AND generation = ?3",
                params![lang, rel_path, generation.0],
            )?;
            tx.execute(
                "DELETE FROM path_symbol_snapshots WHERE lang = ?1 AND generation = ?2",
                params![lang, generation.0],
            )?;
        }
        if let Some((lang, row)) = replacement {
            let generation = generations[lang];
            let mut insert = tx.prepare(
                "INSERT INTO path_symbol_units(
                   lang, rel_path, blob_oid, kind, package_name, short_name,
                   exact_fqn, normalized_fqn, generation
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            )?;
            insert_path_symbol_row(&mut insert, lang, generation, row)?;
        }
        tx.commit()?;
        let _ = reclaim_stale_generations_conn(&mut conn, STALE_GENERATION_RECLAIM_ROWS);
        Ok(())
    }

    pub fn open_for_workspace(workspace_root: &Path) -> Result<Self> {
        if gitblob::discover(workspace_root).is_some() {
            Self::open_persistent(&analyzer_db_path(workspace_root))
        } else {
            Self::open_in_memory()
        }
    }

    fn from_parts(
        conn: Connection,
        reader_source: Option<PathBuf>,
        db_path: Option<PathBuf>,
        ephemeral: Option<EphemeralDb>,
    ) -> Self {
        Self {
            conn: Mutex::new(conn),
            readers: ReaderPool::new(reader_source.clone()),
            active_readers: ReaderPool::new(reader_source.clone()),
            streaming_readers: ReaderPool::new(reader_source),
            db_path,
            lifetime: Arc::new(()),
            _ephemeral: ephemeral,
            #[cfg(test)]
            parsed_blob_transaction_starts: AtomicUsize::new(0),
            #[cfg(test)]
            parsed_blob_point_contains_queries: AtomicUsize::new(0),
            #[cfg(test)]
            replacement_cost_lookup_queries: AtomicUsize::new(0),
            #[cfg(test)]
            replacement_cost_fallback_queries: AtomicUsize::new(0),
            #[cfg(test)]
            prepared_generation_lookup_queries: AtomicUsize::new(0),
        }
    }

    pub fn open_persistent(db_path: &Path) -> Result<Self> {
        let conn = crate::cache_db::open_unified_connection(db_path).map_err(StoreError::new)?;
        let reader_source = reader_source_path(&conn);
        Ok(Self::from_parts(
            conn,
            reader_source,
            Some(db_path.to_path_buf()),
            None,
        ))
    }

    /// Ephemeral (non-git) workspace store.
    ///
    /// Backed by a delete-on-drop temp *file* rather than `:memory:` so the
    /// reader pool works uniformly: an `:memory:` DB is private to a single
    /// connection, which a reader pool could never share. The temp file runs in
    /// WAL at page-cache speed. `db_path()` still reports `None` and
    /// `is_in_memory()` still reports `true` — these mark "no persistent
    /// workspace identity", which is exactly what an ephemeral store is,
    /// independent of the on-disk backing.
    ///
    /// Documented fallback: if the temp-file backing cannot be established on
    /// this platform, fall back to a single in-memory connection whose reads
    /// route through the writer (no read parallelism, but correct).
    pub fn open_in_memory() -> Result<Self> {
        match Self::open_ephemeral_temp_file() {
            Ok(store) => Ok(store),
            Err(_) => Self::open_in_memory_single_connection(),
        }
    }

    pub(crate) fn lifetime(&self) -> std::sync::Weak<()> {
        Arc::downgrade(&self.lifetime)
    }

    pub fn semantic_pack_active_set(&self) -> Result<Option<SemanticPackActiveSet>> {
        let connection = self.read_conn()?;
        let digest = connection
            .query_row(
                "SELECT active_set_digest
                 FROM semantic_pack_active_state
                 WHERE singleton = 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(active_set_digest) = digest else {
            return Ok(None);
        };
        let mut statement = connection.prepare(
            "SELECT manifest_digest, source_kind, source_id, workspace_produced
             FROM semantic_pack_active_members
             ORDER BY ordinal",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, bool>(3)?,
            ))
        })?;
        let mut members = Vec::new();
        for row in rows {
            let (manifest_digest, source_kind, source_id, workspace_produced) = row?;
            members.push(SemanticPackActiveReference {
                manifest_digest,
                source_kind: SemanticPackActivationSourceKind::parse(&source_kind)?,
                source_id,
                workspace_produced,
            });
        }
        let computed = semantic_pack_active_set_digest(&members)?;
        if computed != active_set_digest {
            return Err(StoreError::new(format!(
                "semantic-pack active-set digest mismatch: stored {active_set_digest}, computed {computed}"
            )));
        }
        Ok(Some(SemanticPackActiveSet {
            active_set_digest,
            members,
        }))
    }

    pub fn replace_semantic_pack_active_set(
        &self,
        members: &[SemanticPackActiveReference],
    ) -> Result<SemanticPackActiveSet> {
        let active_set = SemanticPackActiveSet::from_members(members)?;
        let now = crate::cache_db::now_unix_seconds();
        let mut connection = self.conn.lock().expect("analyzer store mutex poisoned");
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute("DELETE FROM semantic_pack_active_members", [])?;
        {
            let mut insert = transaction.prepare(
                "INSERT INTO semantic_pack_active_members(
                   ordinal, manifest_digest, source_kind, source_id, workspace_produced
                 ) VALUES(?1, ?2, ?3, ?4, ?5)",
            )?;
            for (ordinal, member) in active_set.members.iter().enumerate() {
                insert.execute(params![
                    ordinal,
                    &member.manifest_digest,
                    member.source_kind.as_str(),
                    &member.source_id,
                    member.workspace_produced
                ])?;
            }
        }
        transaction.execute(
            "INSERT INTO semantic_pack_active_state(
               singleton, active_set_digest, updated_at
             ) VALUES(1, ?1, ?2)
             ON CONFLICT(singleton) DO UPDATE SET
               active_set_digest = excluded.active_set_digest,
               updated_at = excluded.updated_at",
            params![&active_set.active_set_digest, now],
        )?;
        transaction.commit()?;
        Ok(active_set)
    }

    fn open_ephemeral_temp_file() -> Result<Self> {
        let path = unique_temp_db_path();
        let conn = crate::cache_db::open_unified_connection(&path).map_err(StoreError::new)?;
        let Some(resolved) = reader_source_path(&conn) else {
            return Err(StoreError::new(
                "ephemeral analyzer cache temp file has no resolvable path",
            ));
        };
        Ok(Self::from_parts(
            conn,
            Some(resolved.clone()),
            None,
            Some(EphemeralDb { path: resolved }),
        ))
    }

    fn open_in_memory_single_connection() -> Result<Self> {
        let mut conn = Connection::open_in_memory()?;
        crate::cache_db::configure_connection(&mut conn).map_err(StoreError::new)?;
        crate::cache_db::migrate(&mut conn).map_err(StoreError::new)?;
        // `reader_source = None` routes reads back through the writer connection.
        Ok(Self::from_parts(conn, None, None, None))
    }

    /// Check out a read-only connection for a pure-SELECT method. Pooled readers
    /// run concurrently against WAL snapshots; the writer connection is never
    /// taken by these paths (except in the in-memory single-connection
    /// fallback, where `source` is `None`).
    fn read_conn(&self) -> Result<ReaderGuard<'_>> {
        if self.streaming_read_active() {
            return self.streaming_read_conn();
        }
        self.read_conn_from_pool(&self.readers, crate::cache_db::open_readonly_connection)
    }

    fn streaming_read_conn(&self) -> Result<ReaderGuard<'_>> {
        self.read_conn_from_pool(
            &self.streaming_readers,
            crate::cache_db::open_streaming_readonly_connection,
        )
    }

    fn active_read_conn(&self) -> Result<ReaderGuard<'_>> {
        self.read_conn_from_pool(
            &self.active_readers,
            crate::cache_db::open_readonly_temp_connection,
        )
    }

    fn read_conn_from_pool<'a>(
        &'a self,
        pool: &'a ReaderPool,
        open: fn(&Path) -> crate::cache_db::Result<Connection>,
    ) -> Result<ReaderGuard<'a>> {
        match pool.source.as_deref() {
            Some(path) => {
                let pooled = pool
                    .idle
                    .lock()
                    .expect("analyzer store reader pool poisoned")
                    .pop();
                let conn = match pooled {
                    Some(conn) => conn,
                    None => open(path).map_err(StoreError::new)?,
                };
                Ok(ReaderGuard {
                    inner: ReaderConn::Pooled {
                        pool,
                        conn: Some(conn),
                    },
                })
            }
            None => Ok(ReaderGuard {
                inner: ReaderConn::Writer(self.conn.lock().expect("analyzer store mutex poisoned")),
            }),
        }
    }

    pub(crate) fn close_idle_streaming_readers(&self) {
        self.streaming_readers.close_idle();
    }

    pub(crate) fn begin_streaming_read(&self) {
        let id = self as *const Self as usize;
        STREAMING_READ_DEPTHS.with(|depths| {
            *depths.borrow_mut().entry(id).or_default() += 1;
        });
    }

    pub(crate) fn end_streaming_read(&self) {
        let id = self as *const Self as usize;
        STREAMING_READ_DEPTHS.with(|depths| {
            let mut depths = depths.borrow_mut();
            let depth = depths
                .get_mut(&id)
                .expect("analyzer store streaming read must be active");
            *depth = depth
                .checked_sub(1)
                .expect("analyzer store streaming read depth must be positive");
            if *depth == 0 {
                depths.remove(&id);
            }
        });
    }

    fn streaming_read_active(&self) -> bool {
        let id = self as *const Self as usize;
        STREAMING_READ_DEPTHS.with(|depths| depths.borrow().contains_key(&id))
    }

    pub fn db_path(&self) -> Option<&Path> {
        self.db_path.as_deref()
    }

    pub fn is_in_memory(&self) -> bool {
        self.db_path.is_none()
    }

    pub fn register_blobs(&self, oids: &[Oid], lang: &str, generation: GenerationId) -> Result<()> {
        let mut conn = self.conn.lock().expect("analyzer store mutex poisoned");
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        {
            let mut remove_stale = tx.prepare(
                "DELETE FROM blobs
                 WHERE blob_oid = ?1 AND lang = ?2 AND generation <> ?3",
            )?;
            let mut insert = tx.prepare(
                "INSERT OR IGNORE INTO blobs(blob_oid, lang, generation) VALUES(?1, ?2, ?3)",
            )?;
            let mut seen = HashSet::default();
            for oid in oids {
                if seen.insert(*oid) {
                    remove_stale.execute(params![oid.to_string(), lang, generation.0])?;
                    insert.execute(params![oid.to_string(), lang, generation.0])?;
                }
            }
        }
        tx.commit()?;
        let _ = reclaim_stale_generations_conn(&mut conn, STALE_GENERATION_RECLAIM_ROWS);
        Ok(())
    }

    pub fn ensure_language_epoch(
        &self,
        language: Language,
        ts_language: &TsLanguage,
    ) -> Result<GenerationId> {
        let epoch = epoch::epoch_for(language, ts_language);
        self.ensure_language_epoch_value(language.config_label(), epoch)
    }

    pub fn ensure_language_epoch_value(
        &self,
        lang: &str,
        analysis_epoch: &str,
    ) -> Result<GenerationId> {
        let entries = [(lang.to_string(), analysis_epoch.to_string())];
        Ok(self.ensure_language_epoch_values(&entries)?[lang])
    }

    pub(crate) fn ensure_language_epoch_values(
        &self,
        entries: &[(String, String)],
    ) -> Result<HashMap<String, GenerationId>> {
        let mut conn = self.conn.lock().expect("analyzer store mutex poisoned");
        ensure_language_epochs_tx(&mut conn, entries)
    }

    pub fn missing_blobs(&self, oids: &[Oid], lang: &str) -> Result<Vec<Oid>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let mut stmt = tx.prepare(
            "SELECT 1 FROM blobs
             WHERE blob_oid = ?1 AND lang = ?2
               AND generation = COALESCE(
                 (SELECT generation FROM analysis_epochs WHERE lang = ?2), 0
               )
             LIMIT 1",
        )?;
        let mut out = Vec::new();
        let mut seen = HashSet::default();
        for oid in oids {
            if !seen.insert(*oid) {
                continue;
            }
            let exists = stmt
                .query_row(params![oid.to_string(), lang], |_| Ok(()))
                .optional()?
                .is_some();
            if !exists {
                out.push(*oid);
            }
        }
        drop(stmt);
        tx.commit()?;
        Ok(out)
    }

    pub fn missing_blob_keys(&self, entries: &[(Oid, String)]) -> Result<Vec<(Oid, String)>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let mut stmt = tx.prepare(
            "SELECT 1 FROM blobs
             WHERE blob_oid = ?1 AND lang = ?2
               AND generation = COALESCE(
                 (SELECT generation FROM analysis_epochs WHERE lang = ?2), 0
               )
             LIMIT 1",
        )?;
        let mut out = Vec::new();
        let mut seen = HashSet::default();
        for (oid, lang) in entries {
            if !seen.insert((*oid, lang.clone())) {
                continue;
            }
            let exists = stmt
                .query_row(params![oid.to_string(), lang], |_| Ok(()))
                .optional()?
                .is_some();
            if !exists {
                out.push((*oid, lang.clone()));
            }
        }
        drop(stmt);
        tx.commit()?;
        Ok(out)
    }

    pub fn missing_parsed_blob_keys(
        &self,
        entries: &[(Oid, String)],
    ) -> Result<Vec<(Oid, String)>> {
        let present = self.parsed_blob_keys(entries)?;
        let mut out = Vec::new();
        let mut seen = HashSet::default();
        for entry in entries {
            if seen.insert(entry.clone()) && !present.contains(entry) {
                out.push(entry.clone());
            }
        }
        Ok(out)
    }

    pub(crate) fn missing_parsed_blob_keys_at_generations(
        &self,
        entries: &[(Oid, String)],
        generations: &HashMap<String, GenerationId>,
    ) -> Result<Vec<(Oid, String)>> {
        let present = self.parsed_blob_keys_at_generations(entries, generations)?;
        let mut seen = HashSet::default();
        Ok(entries
            .iter()
            .filter(|entry| seen.insert((*entry).clone()) && !present.contains(*entry))
            .cloned()
            .collect())
    }

    pub(crate) fn missing_published_parsed_blob_keys_at_generations(
        &self,
        entries: &[(Oid, String)],
        generations: &HashMap<String, GenerationId>,
    ) -> Result<Vec<(Oid, String)>> {
        let mut conn = {
            let _scope = crate::profiling::scope("store.missing_blobs.open_reader");
            self.active_read_conn()?
        };
        let tx = conn.transaction()?;
        {
            let _scope = crate::profiling::scope("store.missing_blobs.check_generations");
            require_generation_map(
                &tx,
                generations,
                entries.iter().map(|(_, lang)| lang.as_str()),
            )?;
        }
        let missing = missing_published_parsed_blob_keys_conn(&tx, entries)?;
        tx.commit()?;
        Ok(missing)
    }

    /// Return the complete parsed keys from `entries` using chunked set queries.
    /// This reads blob metadata only; it does not hydrate file state or source.
    pub fn parsed_blob_keys(&self, entries: &[(Oid, String)]) -> Result<HashSet<(Oid, String)>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let present = parsed_blob_keys_conn(&tx, entries)?;
        tx.commit()?;
        Ok(present)
    }

    pub(crate) fn parsed_blob_keys_at_generations(
        &self,
        entries: &[(Oid, String)],
        generations: &HashMap<String, GenerationId>,
    ) -> Result<HashSet<(Oid, String)>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(
            &tx,
            generations,
            entries.iter().map(|(_, lang)| lang.as_str()),
        )?;
        let present = parsed_blob_keys_conn(&tx, entries)?;
        tx.commit()?;
        Ok(present)
    }

    pub fn contains_blob(&self, oid: Oid, lang: &str) -> Result<bool> {
        let conn = self.read_conn()?;
        let exists = conn
            .query_row(
                "SELECT 1 FROM blobs
                 WHERE blob_oid = ?1 AND lang = ?2
                   AND generation = COALESCE(
                     (SELECT generation FROM analysis_epochs WHERE lang = ?2), 0
                   )
                 LIMIT 1",
                params![oid.to_string(), lang],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        Ok(exists)
    }

    pub fn contains_parsed_blob(&self, oid: Oid, lang: &str) -> Result<bool> {
        let conn = self.read_conn()?;
        contains_parsed_blob_conn(&conn, oid, lang)
    }

    pub(crate) fn contains_parsed_blob_at_generation(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
    ) -> Result<bool> {
        #[cfg(test)]
        self.parsed_blob_point_contains_queries
            .fetch_add(1, Ordering::SeqCst);
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        let exists = contains_parsed_blob_conn(&tx, oid, lang)?;
        tx.commit()?;
        Ok(exists)
    }

    pub(crate) fn load_structural_facts_snapshot(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        snapshot_version: i64,
    ) -> Result<Option<Vec<u8>>> {
        if snapshot_version <= 0 {
            return Err(StoreError::new(format!(
                "invalid structural facts snapshot version {snapshot_version}"
            )));
        }
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        let sql = format!(
            "SELECT snapshot.payload
             FROM structural_facts_snapshots AS snapshot
             JOIN blob_meta AS meta
               ON meta.blob_oid = snapshot.blob_oid AND meta.lang = snapshot.lang
             WHERE snapshot.blob_oid = ?1 AND snapshot.lang = ?2
               AND snapshot.snapshot_version = ?3
               AND {PARSED_BLOB_COMPLETE_CONDITION}"
        );
        let payload = tx
            .query_row(
                &sql,
                params![oid.to_string(), lang, snapshot_version],
                |row| row.get(0),
            )
            .optional()?;
        tx.commit()?;
        Ok(payload)
    }

    /// Store the current structural snapshot when the corresponding parsed
    /// blob is still complete in `generation`. Older snapshot versions for
    /// the blob are discarded so rebuildable cache rows cannot accumulate.
    /// Returns false when the parent parsed blob is absent or incomplete.
    pub(crate) fn upsert_structural_facts_snapshot(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        snapshot_version: i64,
        payload: &[u8],
    ) -> Result<bool> {
        if snapshot_version <= 0 {
            return Err(StoreError::new(format!(
                "invalid structural facts snapshot version {snapshot_version}"
            )));
        }
        let mut conn = self.conn.lock().expect("analyzer store mutex poisoned");
        // This transaction reads the existing snapshot/cost before replacing
        // them. Acquire the writer slot up front so a concurrent cache writer
        // cannot commit between the read and a deferred write upgrade, which
        // would surface as SQLITE_BUSY_SNAPSHOT and leave a one-file hole.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_current_generation(&tx, lang, generation)?;
        let complete_sql = format!(
            "SELECT 1 FROM blob_meta AS meta
             WHERE meta.blob_oid = ?1 AND meta.lang = ?2
               AND {PARSED_BLOB_COMPLETE_CONDITION}"
        );
        let oid = oid.to_string();
        let complete = tx
            .query_row(&complete_sql, params![oid, lang], |_| Ok(()))
            .optional()?
            .is_some();
        if !complete {
            tx.commit()?;
            return Ok(false);
        }

        let previous_snapshot_bytes = tx.query_row(
            "SELECT COALESCE(SUM(length(payload)), 0)
             FROM structural_facts_snapshots
             WHERE blob_oid = ?1 AND lang = ?2",
            params![oid, lang],
            |row| row.get::<_, usize>(0),
        )?;
        let previous_payload_cost = tx
            .query_row(
                "SELECT payload_bytes FROM blob_payload_costs
                 WHERE blob_oid = ?1 AND lang = ?2",
                params![oid, lang],
                |row| row.get::<_, usize>(0),
            )
            .optional()?;
        tx.execute(
            "DELETE FROM structural_facts_snapshots
             WHERE blob_oid = ?1 AND lang = ?2",
            params![oid, lang],
        )?;
        tx.execute(
            "INSERT INTO structural_facts_snapshots(
               blob_oid, lang, snapshot_version, payload
             ) VALUES(?1, ?2, ?3, ?4)",
            params![oid, lang, snapshot_version, payload],
        )?;

        if previous_payload_cost.is_some_and(|cost| cost >= previous_snapshot_bytes) {
            tx.execute(
                "UPDATE blob_payload_costs
                 SET payload_bytes = payload_bytes - ?3 + ?4
                 WHERE blob_oid = ?1 AND lang = ?2",
                params![
                    oid,
                    lang,
                    usize_to_i64(previous_snapshot_bytes)?,
                    usize_to_i64(payload.len())?,
                ],
            )?;
        } else {
            tx.execute(
                "DELETE FROM blob_payload_costs WHERE blob_oid = ?1 AND lang = ?2",
                params![oid, lang],
            )?;
            update_blob_payload_cost_tx(&tx, &oid, lang)?;
        }
        tx.commit()?;
        Ok(true)
    }

    #[cfg(test)]
    pub(crate) fn reset_parsed_blob_point_contains_queries_for_test(&self) {
        self.parsed_blob_point_contains_queries
            .store(0, Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn parsed_blob_point_contains_queries_for_test(&self) -> usize {
        self.parsed_blob_point_contains_queries
            .load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn mark_parsed_blob_incomplete_for_test(&self, oid: Oid, lang: &str) {
        self.conn
            .lock()
            .expect("analyzer store mutex poisoned")
            .execute(
                "UPDATE blob_meta SET is_complete = 0 WHERE blob_oid = ?1 AND lang = ?2",
                params![oid.to_string(), lang],
            )
            .expect("mark parsed blob incomplete");
    }

    #[cfg(test)]
    pub(crate) fn write_parsed_blob<A: LanguageAdapter>(
        &self,
        oid: Oid,
        lang: &str,
        adapter: &A,
        state: &FileState,
    ) -> Result<()> {
        let generation = self.current_generation(lang)?;
        self.write_parsed_blob_at_generation(oid, lang, generation, adapter, state)
    }

    pub(crate) fn write_parsed_blob_at_generation<A: LanguageAdapter>(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        adapter: &A,
        state: &FileState,
    ) -> Result<()> {
        #[cfg(test)]
        self.parsed_blob_transaction_starts
            .fetch_add(1, Ordering::SeqCst);
        let mut conn = self.conn.lock().expect("analyzer store mutex poisoned");
        // Reserve the writer slot before reading the generation. A deferred
        // transaction can otherwise fail while upgrading its read snapshot
        // under concurrent pooled-reader churn, particularly on Windows.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_current_generation(&tx, lang, generation)?;
        write_parsed_blob_tx(&tx, oid, lang, generation, adapter, state)?;
        tx.commit()?;
        let _ = reclaim_stale_generations_conn(&mut conn, STALE_GENERATION_RECLAIM_ROWS);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn parsed_blob_transaction_starts_for_test(&self) -> usize {
        self.parsed_blob_transaction_starts.load(Ordering::SeqCst)
    }

    pub(crate) fn prepare_parsed_blob<A: LanguageAdapter>(
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        adapter: &A,
        state: Arc<FileState>,
    ) -> Result<PreparedParsedBlob> {
        prepare_parsed_blob(oid, lang, generation, adapter, state)
    }

    #[cfg(test)]
    pub(crate) fn current_generation(&self, lang: &str) -> Result<GenerationId> {
        let conn = self.read_conn()?;
        current_generation_conn(&conn, lang)
    }

    pub(crate) fn persist_prepared_blobs(
        &self,
        prepared: Vec<PreparedParsedBlob>,
        limits: PersistBatchLimits,
    ) -> (Vec<PersistBlobOutcome>, PersistBatchStats) {
        let limits = limits.normalized();
        let mut outcomes = Vec::with_capacity(prepared.len());
        let mut stats = PersistBatchStats::default();
        let mut batch = Vec::new();
        let mut batch_rows = 0usize;
        let mut batch_bytes = 0usize;
        let mut seen = HashSet::default();

        for blob in prepared {
            if !seen.insert((blob.oid(), blob.lang().to_string())) {
                outcomes.push(PersistBlobOutcome {
                    prepared: blob,
                    error: Some(StoreError::new(
                        "duplicate prepared blob key in one persistence call",
                    )),
                });
                stats.failed_blobs = stats.failed_blobs.saturating_add(1);
                continue;
            }
            let exceeds = !batch.is_empty()
                && (batch.len() >= limits.max_blobs
                    || batch_rows.saturating_add(blob.mutation_logical_rows()) > limits.max_rows
                    || batch_bytes.saturating_add(blob.mutation_payload_bytes())
                        > limits.max_payload_bytes);
            if exceeds {
                let (batch_outcomes, batch_stats) = self.persist_prepared_chunk(batch, limits);
                outcomes.extend(batch_outcomes);
                stats.merge(batch_stats);
                batch = Vec::new();
                batch_rows = 0;
                batch_bytes = 0;
            }
            batch_rows = batch_rows.saturating_add(blob.mutation_logical_rows());
            batch_bytes = batch_bytes.saturating_add(blob.mutation_payload_bytes());
            batch.push(blob);
        }
        if !batch.is_empty() {
            let (batch_outcomes, batch_stats) = self.persist_prepared_chunk(batch, limits);
            outcomes.extend(batch_outcomes);
            stats.merge(batch_stats);
        }
        (outcomes, stats)
    }

    fn persist_prepared_chunk(
        &self,
        mut prepared: Vec<PreparedParsedBlob>,
        limits: PersistBatchLimits,
    ) -> (Vec<PersistBlobOutcome>, PersistBatchStats) {
        let batch_blobs = prepared.len();
        let batch_rows = saturating_sum(
            prepared
                .iter()
                .map(PreparedParsedBlob::mutation_logical_rows),
        );
        let batch_bytes = saturating_sum(
            prepared
                .iter()
                .map(PreparedParsedBlob::mutation_payload_bytes),
        );
        let result = self.try_persist_prepared_chunk(&prepared, limits);

        match result {
            Ok(actual_cost) => {
                let stats = PersistBatchStats {
                    transactions: 1,
                    committed_blobs: batch_blobs,
                    logical_rows: actual_cost.logical_rows,
                    payload_bytes: actual_cost.payload_bytes,
                    peak_batch_blobs: batch_blobs,
                    peak_batch_rows: actual_cost.logical_rows,
                    peak_batch_payload_bytes: actual_cost.payload_bytes,
                    ..PersistBatchStats::default()
                };
                let outcomes = prepared
                    .into_iter()
                    .map(|prepared| PersistBlobOutcome {
                        prepared,
                        error: None,
                    })
                    .collect();
                (outcomes, stats)
            }
            Err(error) if error.is_stale_generation() => {
                let outcomes = prepared
                    .into_iter()
                    .map(|prepared| PersistBlobOutcome {
                        prepared,
                        error: Some(error.clone()),
                    })
                    .collect();
                (
                    outcomes,
                    PersistBatchStats {
                        failed_transaction_attempts: 1,
                        failed_blobs: batch_blobs,
                        peak_batch_blobs: batch_blobs,
                        peak_batch_rows: batch_rows,
                        peak_batch_payload_bytes: batch_bytes,
                        ..PersistBatchStats::default()
                    },
                )
            }
            Err(mut error) if prepared.len() == 1 => {
                let mut failed_attempts = 1;
                for retry in 1..=PREPARED_WRITE_IMMEDIATE_RETRIES {
                    std::thread::sleep(Duration::from_millis(10 * retry as u64));
                    match self.try_persist_prepared_chunk(&prepared, limits) {
                        Ok(actual_cost) => {
                            return (
                                vec![PersistBlobOutcome {
                                    prepared: prepared.pop().expect("single retried prepared blob"),
                                    error: None,
                                }],
                                PersistBatchStats {
                                    transactions: 1,
                                    failed_transaction_attempts: failed_attempts,
                                    committed_blobs: 1,
                                    logical_rows: actual_cost.logical_rows,
                                    payload_bytes: actual_cost.payload_bytes,
                                    peak_batch_blobs: batch_blobs,
                                    peak_batch_rows: actual_cost.logical_rows,
                                    peak_batch_payload_bytes: actual_cost.payload_bytes,
                                    ..PersistBatchStats::default()
                                },
                            );
                        }
                        Err(retry_error) => {
                            failed_attempts = failed_attempts.saturating_add(1);
                            if retry_error.is_stale_generation() {
                                error = retry_error;
                                break;
                            }
                            error = retry_error;
                        }
                    }
                }
                (
                    vec![PersistBlobOutcome {
                        prepared: prepared.pop().expect("single failed prepared blob"),
                        error: Some(error),
                    }],
                    PersistBatchStats {
                        failed_transaction_attempts: failed_attempts,
                        failed_blobs: 1,
                        peak_batch_blobs: batch_blobs,
                        peak_batch_rows: batch_rows,
                        peak_batch_payload_bytes: batch_bytes,
                        ..PersistBatchStats::default()
                    },
                )
            }
            Err(_) => {
                let right = prepared.split_off(prepared.len() / 2);
                let (mut left_outcomes, mut stats) = self.persist_prepared_chunk(prepared, limits);
                let (right_outcomes, right_stats) = self.persist_prepared_chunk(right, limits);
                left_outcomes.extend(right_outcomes);
                stats.failed_transaction_attempts =
                    stats.failed_transaction_attempts.saturating_add(1);
                stats.peak_batch_blobs = stats.peak_batch_blobs.max(batch_blobs);
                stats.peak_batch_rows = stats.peak_batch_rows.max(batch_rows);
                stats.peak_batch_payload_bytes = stats.peak_batch_payload_bytes.max(batch_bytes);
                stats.merge(right_stats);
                (left_outcomes, stats)
            }
        }
    }

    fn try_persist_prepared_chunk(
        &self,
        prepared: &[PreparedParsedBlob],
        limits: PersistBatchLimits,
    ) -> Result<PersistedMutationCost> {
        #[cfg(test)]
        self.parsed_blob_transaction_starts
            .fetch_add(1, Ordering::SeqCst);
        let mut conn = self.conn.lock().expect("analyzer store mutex poisoned");
        let tx = conn.transaction()?;
        let mut generations = HashMap::default();
        for blob in prepared {
            if let Some(existing) = generations.insert(blob.lang(), blob.generation)
                && existing != blob.generation
            {
                return Err(StoreError::stale_generation(format!(
                    "conflicting prepared generations for language {}",
                    blob.lang()
                )));
            }
        }
        for (lang, generation) in generations {
            #[cfg(test)]
            self.prepared_generation_lookup_queries
                .fetch_add(1, Ordering::SeqCst);
            require_current_generation(&tx, lang, generation)?;
        }
        let stored_costs = self.stored_blob_cascade_costs(&tx, prepared)?;
        let mut fallback_cost_statement =
            tx.prepare_cached(persisted_blob_mutation_cost_fallback_sql())?;
        let mut cost = PersistedMutationCost::default();
        for (blob, stored) in prepared.iter().zip(stored_costs) {
            let replaced = match stored {
                StoredCascadeCost::Missing => PersistedMutationCost::default(),
                StoredCascadeCost::Known(cost) => cost,
                StoredCascadeCost::Legacy => {
                    #[cfg(test)]
                    self.replacement_cost_fallback_queries
                        .fetch_add(1, Ordering::SeqCst);
                    persisted_blob_mutation_cost_fallback_statement(
                        &mut fallback_cost_statement,
                        blob.oid_text.as_str(),
                        blob.lang(),
                    )?
                }
            };
            cost.logical_rows = cost
                .logical_rows
                .saturating_add(blob.logical_rows())
                .saturating_add(replaced.logical_rows);
            cost.payload_bytes = cost
                .payload_bytes
                .saturating_add(blob.payload_bytes())
                .saturating_add(replaced.payload_bytes);
        }
        drop(fallback_cost_statement);
        if prepared.len() > 1
            && (prepared.len() > limits.max_blobs
                || cost.logical_rows > limits.max_rows
                || cost.payload_bytes > limits.max_payload_bytes)
        {
            return Err(StoreError::new(format!(
                "prepared replacement mutation batch exceeds limits: blobs={}, rows={}, bytes={}",
                prepared.len(),
                cost.logical_rows,
                cost.payload_bytes
            )));
        }
        for blob in prepared {
            write_prepared_blob_unchecked_tx(&tx, blob)?;
        }
        tx.commit()?;
        let _ = reclaim_stale_generations_conn(&mut conn, STALE_GENERATION_RECLAIM_ROWS);
        Ok(cost)
    }

    fn stored_blob_cascade_costs(
        &self,
        conn: &Connection,
        prepared: &[PreparedParsedBlob],
    ) -> Result<Vec<StoredCascadeCost>> {
        stored_blob_cascade_costs_conn(conn, prepared, || {
            #[cfg(test)]
            self.replacement_cost_lookup_queries
                .fetch_add(1, Ordering::SeqCst);
        })
    }

    #[cfg(test)]
    fn reset_replacement_cost_lookup_queries_for_test(&self) {
        self.replacement_cost_lookup_queries
            .store(0, Ordering::SeqCst);
        self.replacement_cost_fallback_queries
            .store(0, Ordering::SeqCst);
    }

    #[cfg(test)]
    fn replacement_cost_lookup_queries_for_test(&self) -> usize {
        self.replacement_cost_lookup_queries.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    fn replacement_cost_fallback_queries_for_test(&self) -> usize {
        self.replacement_cost_fallback_queries
            .load(Ordering::SeqCst)
    }

    #[cfg(test)]
    fn reset_prepared_generation_lookup_queries_for_test(&self) {
        self.prepared_generation_lookup_queries
            .store(0, Ordering::SeqCst);
    }

    #[cfg(test)]
    fn prepared_generation_lookup_queries_for_test(&self) -> usize {
        self.prepared_generation_lookup_queries
            .load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn hydrate_file_state<A: LanguageAdapter>(
        &self,
        oid: Oid,
        lang: &str,
        adapter: &A,
        file: &ProjectFile,
    ) -> Result<Option<FileState>> {
        let source = file.read_to_string().unwrap_or_default();
        self.hydrate_file_state_with_source(
            oid,
            lang,
            self.current_generation(lang)?,
            adapter,
            file,
            &source,
        )
    }

    pub fn hydrate_file_state_with_source<A: LanguageAdapter>(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        adapter: &A,
        file: &ProjectFile,
        source: &str,
    ) -> Result<Option<FileState>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        let result = hydrate_file_state_conn(&tx, oid, lang, adapter, file, source)?;
        tx.commit()?;
        Ok(result)
    }

    /// Read only the persisted rows required to render a file summary. This
    /// does not replace full `FileState` hydration, which remains responsible
    /// for validating and serving the complete analyzer graph.
    pub fn summary_file_projection<A: LanguageAdapter>(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        adapter: &A,
        file: &ProjectFile,
    ) -> Result<Option<SummaryFileProjection>> {
        let _scope = crate::profiling::scope("AnalyzerStore::summary_file_projection");
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        let result = summary_file_projection_conn(&tx, oid, lang, adapter, file)?;
        tx.commit()?;
        Ok(result)
    }

    /// Read at most `limit` signature-metadata rows for one persisted code
    /// unit without hydrating the owning file state.
    ///
    /// The target identity deliberately includes every stable `CodeUnit`
    /// discriminator. Callers supply a one-row lookahead in `limit`; a batch
    /// that fills the limit is therefore incomplete and must not be treated as
    /// authoritative.
    pub(crate) fn signature_metadata_for_unit_limited(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        unit: &CodeUnit,
        limit: usize,
    ) -> Result<LimitedQueryRows<SignatureMetadata>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        let result = signature_metadata_for_unit_limited_conn(&tx, oid, lang, unit, limit)?;
        tx.commit()?;
        Ok(result)
    }

    /// Read at most `limit` Ruby dispatch-mode rows for one persisted code
    /// unit without hydrating the owning file state.
    pub(crate) fn ruby_method_dispatch_modes_for_unit_limited(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        unit: &CodeUnit,
        limit: usize,
    ) -> Result<LimitedQueryRows<RubyMethodDispatchMode>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        let result = ruby_method_dispatch_modes_for_unit_limited_conn(&tx, oid, lang, unit, limit)?;
        tx.commit()?;
        Ok(result)
    }

    /// Read at most `limit` direct declaration children for one persisted
    /// code unit without hydrating the owning file state.
    pub(crate) fn direct_children_for_unit_limited(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        unit: &CodeUnit,
        limit: usize,
    ) -> Result<LimitedQueryRows<CandidateRow>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        let result = direct_children_for_unit_limited_conn(&tx, oid, lang, unit, limit)?;
        tx.commit()?;
        Ok(result)
    }

    pub(crate) fn raw_supertypes_for_unit_limited(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        unit: &CodeUnit,
        limit: usize,
    ) -> Result<LimitedQueryRows<String>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        let result = raw_supertypes_for_unit_limited_conn(&tx, oid, lang, unit, limit)?;
        tx.commit()?;
        Ok(result)
    }

    pub(crate) fn supertype_lookup_paths_for_unit_limited(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        unit: &CodeUnit,
        limit: usize,
    ) -> Result<LimitedQueryRows<String>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        let result = supertype_lookup_paths_for_unit_limited_conn(&tx, oid, lang, unit, limit)?;
        tx.commit()?;
        Ok(result)
    }

    /// Read at most `limit` declaration ranges for one persisted code unit
    /// without hydrating the owning file state.
    pub(crate) fn ranges_for_unit_limited(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        unit: &CodeUnit,
        limit: usize,
    ) -> Result<LimitedQueryRows<Range>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        let result = ranges_for_unit_limited_conn(&tx, oid, lang, unit, limit)?;
        tx.commit()?;
        Ok(result)
    }

    /// Hydrate many live file states from persisted blob rows using chunked
    /// `IN` scans over the requested OIDs. `source_by_file` controls whether
    /// source-dependent hydrate hooks and file-scope range synthesis run for a
    /// given file. Whole-workspace graph passes pass an empty map so they avoid
    /// all source reads and receive structural rows only.
    pub fn hydrate_file_states<A: LanguageAdapter>(
        &self,
        entries: &[(ProjectFile, Oid)],
        lang: &str,
        adapter: &A,
        source_by_file: &HashMap<ProjectFile, String>,
    ) -> Result<HashMap<ProjectFile, FileState>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let result = hydrate_file_states_conn(&tx, entries, lang, adapter, source_by_file)?;
        tx.commit()?;
        Ok(result)
    }

    pub fn hydrate_file_states_by_key<A: LanguageAdapter>(
        &self,
        entries: &[(ProjectFile, Oid, String)],
        generations: &HashMap<String, GenerationId>,
        adapter: &A,
        source_by_file: &HashMap<ProjectFile, String>,
    ) -> Result<HashMap<ProjectFile, FileState>> {
        let mut out = HashMap::default();
        let mut by_lang: HashMap<String, Vec<(ProjectFile, Oid)>> = HashMap::default();
        for (file, oid, lang) in entries {
            by_lang
                .entry(lang.clone())
                .or_default()
                .push((file.clone(), *oid));
        }
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(
            &tx,
            generations,
            entries.iter().map(|(_, _, lang)| lang.as_str()),
        )?;
        for (lang, lang_entries) in by_lang {
            out.extend(hydrate_file_states_conn(
                &tx,
                &lang_entries,
                &lang,
                adapter,
                source_by_file,
            )?);
        }
        tx.commit()?;
        Ok(out)
    }

    pub fn hydrate_import_infos<A: LanguageAdapter>(
        &self,
        entries: &[(ProjectFile, Oid)],
        lang: &str,
        _adapter: &A,
    ) -> Result<HashMap<ProjectFile, Vec<ImportInfo>>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let oids = unique_oid_strings(entries);
        let imports_by_oid = read_import_infos_bulk(&tx, lang, &oids)?;
        let mut out = HashMap::default();
        for (file, oid) in entries {
            if let Some(imports) = imports_by_oid.get(&oid.to_string()) {
                out.insert(file.clone(), imports.clone());
            }
        }
        tx.commit()?;
        Ok(out)
    }

    pub fn hydrate_import_infos_by_key<A: LanguageAdapter>(
        &self,
        entries: &[(ProjectFile, Oid, String)],
        generations: &HashMap<String, GenerationId>,
        adapter: &A,
    ) -> Result<HashMap<ProjectFile, Vec<ImportInfo>>> {
        Ok(self
            .hydrate_import_facts_by_key(entries, generations, adapter)?
            .into_iter()
            .map(|(file, facts)| (file, facts.imports))
            .collect())
    }

    pub(crate) fn hydrate_import_facts_by_key<A: LanguageAdapter>(
        &self,
        entries: &[(ProjectFile, Oid, String)],
        generations: &HashMap<String, GenerationId>,
        adapter: &A,
    ) -> Result<HashMap<ProjectFile, ImportFacts>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(
            &tx,
            generations,
            entries.iter().map(|(_, _, lang)| lang.as_str()),
        )?;
        let mut out = HashMap::default();
        let mut by_lang: HashMap<String, Vec<(ProjectFile, Oid)>> = HashMap::default();
        for (file, oid, lang) in entries {
            by_lang
                .entry(lang.clone())
                .or_default()
                .push((file.clone(), *oid));
        }
        for (lang, lang_entries) in by_lang {
            let oids = unique_oid_strings(&lang_entries);
            let packages_by_oid = read_content_packages_bulk(&tx, &lang, &oids)?;
            let imports_by_oid = read_import_infos_bulk(&tx, &lang, &oids)?;
            for (file, oid) in lang_entries {
                let oid = oid.to_string();
                let Some(package_name) = packages_by_oid.get(&oid) else {
                    continue;
                };
                out.insert(
                    file.clone(),
                    ImportFacts {
                        package_name: adapter.hydrate_content_qualifier(package_name, &file),
                        imports: imports_by_oid.get(&oid).cloned().unwrap_or_default(),
                    },
                );
            }
        }
        tx.commit()?;
        Ok(out)
    }

    pub(crate) fn content_package(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
    ) -> Result<Option<String>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        let result =
            read_content_packages_bulk(&tx, lang, &[oid.to_string()])?.remove(&oid.to_string());
        tx.commit()?;
        Ok(result)
    }

    pub(crate) fn content_package_limited(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        limit: usize,
    ) -> Result<LimitedQueryRows<String>> {
        if limit == 0 {
            return Ok(LimitedQueryRows::incomplete(Vec::new(), 0));
        }
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        let sql = format!(
            "SELECT length(CAST(meta.content_package AS BLOB)),
                    CASE
                        WHEN length(CAST(meta.content_package AS BLOB))
                               <= {MAX_LIMITED_QUERY_ROW_BYTES}
                        THEN meta.content_package
                        ELSE NULL
                    END
             FROM blob_meta AS meta
             WHERE meta.blob_oid = ?1 AND meta.lang = ?2
               AND {PARSED_BLOB_COMPLETE_CONDITION}"
        );
        let mut statement = tx.prepare_cached(&sql)?;
        let mut query = statement.query(params![oid.to_string(), lang])?;
        let result = if let Some(row) = query.next()? {
            let mut bytes = LimitedQueryByteBudget::default();
            if !bytes.admit_sqlite_bytes(row.get::<_, i64>(0)?)? {
                LimitedQueryRows::incomplete(Vec::new(), 1)
            } else if let Some(content_package) = row.get::<_, Option<String>>(1)? {
                LimitedQueryRows::complete(vec![content_package], 1)
            } else {
                LimitedQueryRows::incomplete(Vec::new(), 1)
            }
        } else {
            LimitedQueryRows::incomplete(Vec::new(), 0)
        };
        drop(query);
        drop(statement);
        tx.commit()?;
        Ok(result)
    }

    pub(crate) fn first_declaration_content_qualifier_for_key_limited(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        limit: usize,
    ) -> Result<LimitedQueryRows<String>> {
        if limit == 0 {
            return Ok(LimitedQueryRows::incomplete(Vec::new(), 0));
        }
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        let sql_limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let sql = format!(
            "SELECT length(CAST(units.content_qualifier AS BLOB)),
                    CASE
                        WHEN length(CAST(units.content_qualifier AS BLOB))
                               <= {MAX_LIMITED_QUERY_ROW_BYTES}
                        THEN units.content_qualifier
                        ELSE NULL
                    END
             FROM code_units AS units
             JOIN blob_meta AS meta
               ON meta.blob_oid = units.blob_oid AND meta.lang = units.lang
             WHERE units.blob_oid = ?1 AND units.lang = ?2
               AND {PARSED_BLOB_COMPLETE_CONDITION}
             ORDER BY units.unit_key
             LIMIT ?3"
        );
        let mut statement = tx.prepare_cached(&sql)?;
        let mut query = statement.query(params![oid.to_string(), lang, sql_limit])?;
        let mut bytes = LimitedQueryByteBudget::default();
        let mut inspected = 0usize;
        let mut result = None;
        while let Some(row) = query.next()? {
            inspected = inspected.saturating_add(1);
            if !bytes.admit_sqlite_bytes(row.get::<_, i64>(0)?)? {
                result = Some(LimitedQueryRows::incomplete(Vec::new(), inspected));
                break;
            }
            let Some(content_qualifier) = row.get::<_, Option<String>>(1)? else {
                result = Some(LimitedQueryRows::incomplete(Vec::new(), inspected));
                break;
            };
            if !content_qualifier.is_empty() {
                result = Some(LimitedQueryRows::complete(
                    vec![content_qualifier],
                    inspected,
                ));
                break;
            }
        }
        let result = result.unwrap_or_else(|| {
            if inspected == limit {
                LimitedQueryRows::incomplete(Vec::new(), inspected)
            } else {
                LimitedQueryRows::complete(Vec::new(), inspected)
            }
        });
        drop(query);
        drop(statement);
        tx.commit()?;
        Ok(result)
    }

    pub(crate) fn import_infos_for_key_limited(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        limit: usize,
    ) -> Result<LimitedQueryRows<ImportInfo>> {
        if limit == 0 {
            return Ok(LimitedQueryRows::incomplete(Vec::new(), 0));
        }
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        let oid = oid.to_string();
        let meta_sql = format!(
            "SELECT meta.import_count
             FROM blob_meta AS meta
             WHERE meta.blob_oid = ?1 AND meta.lang = ?2
               AND {PARSED_BLOB_COMPLETE_CONDITION}"
        );
        let Some(import_count) = tx
            .query_row(&meta_sql, params![&oid, lang], |row| row.get::<_, i64>(0))
            .optional()?
        else {
            tx.commit()?;
            return Ok(LimitedQueryRows::incomplete(Vec::new(), 0));
        };
        let import_count = i64_to_usize(import_count)?;
        let sql_limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let sql = format!(
            "SELECT length(info),
                    CASE
                        WHEN length(info) <= {MAX_LIMITED_QUERY_ROW_BYTES} THEN info
                        ELSE NULL
                    END
             FROM import_details
             WHERE blob_oid = ?1 AND lang = ?2
             ORDER BY ordinal
             LIMIT ?3"
        );
        let mut statement = tx.prepare_cached(&sql)?;
        let mut query = statement.query(params![&oid, lang, sql_limit])?;
        let mut rows = Vec::new();
        let mut inspected = 0usize;
        let mut bytes = LimitedQueryByteBudget::default();
        let mut byte_complete = true;
        while let Some(row) = query.next()? {
            inspected = inspected.saturating_add(1);
            let byte_len = row.get::<_, i64>(0)?;
            if !bytes.admit_sqlite_bytes(byte_len)? {
                byte_complete = false;
                break;
            }
            let Some(info) = row.get::<_, Option<Vec<u8>>>(1)? else {
                byte_complete = false;
                break;
            };
            rows.push(deserialize_limited_blob(&info)?);
        }
        drop(query);
        drop(statement);
        tx.commit()?;
        if !byte_complete || inspected == limit || import_count != inspected {
            Ok(LimitedQueryRows::incomplete(rows, inspected))
        } else {
            Ok(LimitedQueryRows::complete(rows, inspected))
        }
    }

    pub fn declaration_candidate_rows_by_short_name(
        &self,
        lang: &str,
        short_name: &str,
    ) -> Result<Vec<CandidateRow>> {
        let conn = self.read_conn()?;
        let sql = declaration_candidate_sql("units.lang = ?1 AND units.short_name = ?2");
        candidate_rows_for_languages(&conn, std::iter::once(lang), &sql, &[&short_name])
    }

    pub fn declaration_candidate_rows_by_short_name_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        short_name: &str,
    ) -> Result<Vec<CandidateRow>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let sql = declaration_candidate_sql("units.lang = ?1 AND units.short_name = ?2");
        let rows = candidate_rows_for_languages(
            &tx,
            langs.iter().map(String::as_str),
            &sql,
            &[&short_name],
        )?;
        tx.commit()?;
        Ok(rows)
    }

    pub(crate) fn declaration_order_candidate_rows_by_short_name_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        short_name: &str,
    ) -> Result<Vec<DefinitionOrderCandidateRow>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let sql = definition_order_candidate_sql(
            "units.lang = ?1 AND units.short_name = ?2",
            "units.in_declarations = 1",
        );
        let rows = definition_order_candidate_rows_for_languages(
            &tx,
            langs.iter().map(String::as_str),
            &sql,
            &[&short_name],
        )?;
        tx.commit()?;
        Ok(rows)
    }

    /// Returns name-bounded declaration-lookup candidates together with the
    /// persisted range fact needed for definition ordering.
    pub(crate) fn definition_lookup_order_candidate_rows_by_short_name_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        short_name: &str,
    ) -> Result<Vec<DefinitionOrderCandidateRow>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let sql = definition_order_candidate_sql(
            "units.lang = ?1 AND units.short_name = ?2",
            "(units.in_declarations = 1 OR units.in_definition_lookup = 1)",
        );
        let rows = definition_order_candidate_rows_for_languages(
            &tx,
            langs.iter().map(String::as_str),
            &sql,
            &[&short_name],
        )?;
        tx.commit()?;
        Ok(rows)
    }

    /// Backs `IAnalyzer::lookup_candidates_by_identifier`, the sole bare-name
    /// resolution path keyed on the terminal identifier. Its membership must
    /// match `definition_lookup_order_candidate_sql`'s `(in_declarations = 1
    /// OR in_definition_lookup = 1)`, not the `in_declarations`-only
    /// membership `declaration_candidate_sql` uses elsewhere: a spelling the
    /// fq lookup path resolves (which already consults that wider
    /// membership) must be visible here too, or bare-name ambiguity silently
    /// drops definition-lookup-only units (e.g. JS/TS object-literal
    /// properties) that the fq spelling resolves fine (#1088). This widening
    /// is scoped to resolution only — declaration listings
    /// (get_all_declarations, search, summaries) still use the unchanged
    /// `in_declarations`-only surfaces by design (#397).
    pub fn declaration_candidate_rows_by_identifier_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        identifier: &str,
    ) -> Result<Vec<CandidateRow>> {
        self.declaration_candidate_rows_by_identifiers_for_langs(langs, generations, &[identifier])
    }

    /// The several-spelling form of the above, for the suffix-pattern stage of
    /// symbol lookup: one query path can be spelled by more than one persisted
    /// `identifier` (`Foo.Bar` also matches the declaration indexed as
    /// `Foo$Bar`), and an `IN` list seeks the same `(lang, identifier)` index
    /// once per spelling instead of reading the whole declaration table once
    /// per language (#1688).
    pub(crate) fn declaration_candidate_rows_by_identifiers_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        identifiers: &[&str],
    ) -> Result<Vec<CandidateRow>> {
        assert!(
            !identifiers.is_empty(),
            "a suffix query path always spells at least its terminal segment"
        );
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        // `?1` is the language, so the spellings start at `?2`.
        let placeholders = (0..identifiers.len())
            .map(|index| format!("?{}", index + 2))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = candidate_rows_sql_with_membership(
            "units",
            "FROM code_units AS units
             JOIN blob_meta AS meta
               ON meta.blob_oid = units.blob_oid AND meta.lang = units.lang",
            &format!("units.lang = ?1 AND units.identifier IN ({placeholders})"),
            "(units.in_declarations = 1 OR units.in_definition_lookup = 1)",
            "units.blob_oid, units.unit_key",
        );
        let values: Vec<&dyn ToSql> = identifiers
            .iter()
            .map(|identifier| identifier as &dyn ToSql)
            .collect();
        let rows =
            candidate_rows_for_languages(&tx, langs.iter().map(String::as_str), &sql, &values)?;
        tx.commit()?;
        Ok(rows)
    }

    pub(crate) fn declaration_candidate_rows_by_identifier_for_langs_limited(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        identifier: &str,
        limit: usize,
    ) -> Result<LimitedQueryRows<CandidateRow>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let sql = limited_candidate_rows_sql_with_membership(
            "units",
            "FROM code_units AS units
             JOIN blob_meta AS meta
               ON meta.blob_oid = units.blob_oid AND meta.lang = units.lang",
            "units.lang = ?1 AND units.identifier = ?2",
            "(units.in_declarations = 1 OR units.in_definition_lookup = 1)",
            "units.blob_oid, units.unit_key",
        );
        let sql = format!("{sql} LIMIT ?3");
        let rows = candidate_rows_for_languages_limited(
            &tx,
            langs.iter().map(String::as_str),
            &sql,
            &[&identifier],
            limit,
        )?;
        tx.commit()?;
        Ok(rows)
    }

    pub(crate) fn declaration_candidate_rows_by_lookup_key_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        column: PersistedLookupKey,
        value: &str,
    ) -> Result<Vec<CandidateRow>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let column = match column {
            PersistedLookupKey::ExactFqn => "exact_fqn",
            PersistedLookupKey::NormalizedFqn => "normalized_fqn",
        };
        let sql = declaration_candidate_sql(&format!("units.lang = ?1 AND units.{column} = ?2"));
        let rows =
            candidate_rows_for_languages(&tx, langs.iter().map(String::as_str), &sql, &[&value])?;
        tx.commit()?;
        Ok(rows)
    }

    pub(crate) fn declaration_candidate_rows_by_lookup_key_for_langs_limited(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        column: PersistedLookupKey,
        value: &str,
        limit: usize,
    ) -> Result<LimitedQueryRows<CandidateRow>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let column = match column {
            PersistedLookupKey::ExactFqn => "exact_fqn",
            PersistedLookupKey::NormalizedFqn => "normalized_fqn",
        };
        let sql =
            limited_declaration_candidate_sql(&format!("units.lang = ?1 AND units.{column} = ?2"));
        let sql = format!("{sql} LIMIT ?3");
        let rows = candidate_rows_for_languages_limited(
            &tx,
            langs.iter().map(String::as_str),
            &sql,
            &[&value],
            limit,
        )?;
        tx.commit()?;
        Ok(rows)
    }

    pub(crate) fn declaration_member_rows_for_owner_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        owner: &str,
        normalized: bool,
        identifier: &str,
    ) -> Result<Vec<CandidateRow>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let owner_column = if normalized {
            "normalized_fqn"
        } else {
            "exact_fqn"
        };
        let sql = candidate_rows_sql(
            "child",
            "FROM code_units AS owner
             JOIN unit_children AS edge
               ON edge.blob_oid = owner.blob_oid AND edge.lang = owner.lang
              AND edge.parent_key = owner.unit_key
             JOIN code_units AS child
               ON child.blob_oid = edge.blob_oid AND child.lang = edge.lang
              AND child.unit_key = edge.child_key
             JOIN blob_meta AS meta
               ON meta.blob_oid = child.blob_oid AND meta.lang = child.lang",
            &format!(
                "owner.lang = ?1 AND owner.{owner_column} = ?2
                 AND owner.in_declarations = 1 AND child.identifier = ?3"
            ),
        );
        let rows = candidate_rows_for_languages(
            &tx,
            langs.iter().map(String::as_str),
            &sql,
            &[&owner, &identifier],
        )?;
        tx.commit()?;
        Ok(rows)
    }

    pub(crate) fn declaration_member_rows_for_owner_for_langs_limited(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        owner: &str,
        normalized: bool,
        identifier: &str,
        limit: usize,
    ) -> Result<LimitedQueryRows<CandidateRow>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let owner_column = if normalized {
            "normalized_fqn"
        } else {
            "exact_fqn"
        };
        let sql = limited_candidate_rows_sql_with_membership(
            "child",
            "FROM code_units AS owner
             JOIN unit_children AS edge
               ON edge.blob_oid = owner.blob_oid AND edge.lang = owner.lang
              AND edge.parent_key = owner.unit_key
             JOIN code_units AS child
               ON child.blob_oid = edge.blob_oid AND child.lang = edge.lang
              AND child.unit_key = edge.child_key
             JOIN blob_meta AS meta
               ON meta.blob_oid = child.blob_oid AND meta.lang = child.lang",
            &format!(
                "owner.lang = ?1 AND owner.{owner_column} = ?2
                 AND owner.in_declarations = 1 AND child.identifier = ?3"
            ),
            "child.in_declarations = 1",
            "child.blob_oid, child.unit_key",
        );
        let sql = format!("{sql} LIMIT ?4");
        let rows = candidate_rows_for_languages_limited(
            &tx,
            langs.iter().map(String::as_str),
            &sql,
            &[&owner, &identifier],
            limit,
        )?;
        tx.commit()?;
        Ok(rows)
    }

    pub(crate) fn declaration_rows_by_package_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        package: &str,
    ) -> Result<Vec<CandidateRow>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let sql = declaration_candidate_sql("units.lang = ?1 AND units.content_qualifier = ?2");
        let rows =
            candidate_rows_for_languages(&tx, langs.iter().map(String::as_str), &sql, &[&package])?;
        tx.commit()?;
        Ok(rows)
    }

    /// One literal, index-ordered page of candidate rows whose persisted
    /// content qualifier is exactly `package` or is nested beneath it.
    ///
    /// The caller must still resolve rows against the live snapshot because
    /// some adapters derive the hydrated package identity from the live path.
    /// Paging lets that validation stop at the first live match without
    /// materializing the complete package subtree.
    pub(crate) fn declaration_rows_by_package_prefix_page(
        &self,
        lang: &str,
        generation: GenerationId,
        package: &str,
        after: Option<(&str, Oid, i64)>,
        limit: usize,
    ) -> Result<Vec<CandidateRow>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        let nested = format!("{package}.");
        // '/' is the immediate ASCII successor of '.', so the half-open range
        // ["pkg.", "pkg/") contains exactly strings with the literal "pkg."
        // prefix. Unlike LIKE, '%' and '_' in a legal package name remain data.
        let upper = format!("{package}/");
        let cursor_predicate = if after.is_some() {
            "AND (units.content_qualifier, units.blob_oid, units.unit_key) > (?5, ?6, ?7)"
        } else {
            ""
        };
        let predicate = format!(
            "units.lang = ?1
             AND (units.content_qualifier = ?2
                  OR (units.content_qualifier >= ?3 AND units.content_qualifier < ?4))
             {cursor_predicate}"
        );
        let sql = declaration_candidate_sql_with_order(
            &predicate,
            "units.content_qualifier, units.blob_oid, units.unit_key",
        );
        let sql = format!("{sql} LIMIT ?{}", if after.is_some() { 8 } else { 5 });
        let mut statement = tx.prepare(&sql)?;
        let mapped = match after {
            Some((after_qualifier, after_oid, after_unit_key)) => statement.query_map(
                params![
                    lang,
                    package,
                    nested,
                    upper,
                    after_qualifier,
                    after_oid.to_string(),
                    after_unit_key,
                    limit as i64,
                ],
                candidate_row_from_row,
            )?,
            None => statement.query_map(
                params![lang, package, nested, upper, limit as i64],
                candidate_row_from_row,
            )?,
        };
        let rows = collect_candidate_rows(mapped)?;
        drop(statement);
        tx.commit()?;
        Ok(rows)
    }

    pub fn declaration_candidate_rows_by_lang(&self, lang: &str) -> Result<Vec<CandidateRow>> {
        let conn = self.read_conn()?;
        let sql = declaration_candidate_sql("units.lang = ?1");
        candidate_rows_for_languages(&conn, std::iter::once(lang), &sql, &[])
    }

    /// Candidate rows for a literal ASCII substring over a persistently stable
    /// fully-qualified name. Callers must retain the Rust regex filter for
    /// final semantics and use this only when their adapter guarantees that
    /// `content_qualifier` is part of the searchable FQN.
    pub fn declaration_candidate_rows_by_literal_substring(
        &self,
        lang: &str,
        substring: &str,
    ) -> Result<Vec<CandidateRow>> {
        let conn = self.read_conn()?;
        let sql = declaration_candidate_sql(
            "units.lang = ?1 AND (
               instr(lower(units.short_name), lower(?2)) > 0
               OR instr(lower(units.content_qualifier), lower(?2)) > 0
             )",
        );
        candidate_rows_for_languages(&conn, std::iter::once(lang), &sql, &[&substring])
    }

    pub fn declaration_candidate_rows_by_literal_substring_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        substring: &str,
    ) -> Result<Vec<CandidateRow>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let sql = declaration_candidate_sql(
            "units.lang = ?1 AND (
               instr(lower(units.short_name), lower(?2)) > 0
               OR instr(lower(units.content_qualifier), lower(?2)) > 0
             )",
        );
        let rows = candidate_rows_for_languages(
            &tx,
            langs.iter().map(String::as_str),
            &sql,
            &[&substring],
        )?;
        tx.commit()?;
        Ok(rows)
    }

    /// Search candidates carry the metadata that `search_symbols` otherwise
    /// obtains by repeatedly hydrating complete file states.
    pub fn search_candidate_rows_by_lang(&self, lang: &str) -> Result<Vec<SearchCandidateRow>> {
        let conn = self.read_conn()?;
        search_candidate_rows_by_lang_conn(&conn, lang)
    }

    /// Enumerate the declaration projection needed to *decide* whether a
    /// `search_symbols` pattern batch matches, and nothing else.
    ///
    /// Matching only consults a unit's fully-qualified name, which is built
    /// from its short name plus the package prefix hydrated from
    /// `content_qualifier` and the live path. Signature text, primary ranges,
    /// and candidate flags are needed only for units that actually match, so
    /// they are deliberately excluded here and fetched by key afterwards
    /// (issue #1199): a broad request over this repository previously paid for
    /// ~13 MB of signature/range columns and a temp-B-tree sort to answer a
    /// query whose result was a few dozen rows.
    pub(crate) fn search_candidate_name_rows_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        active_oids: &[Oid],
        literal_substrings: Option<&[&str]>,
        cancellation: Option<&CancellationToken>,
    ) -> Result<LimitedQueryRows<SearchCandidateNameRow>> {
        // Pattern matching is performed after language-specific FQN hydration.
        // One request may carry several patterns, so the storage projection
        // intentionally supplies one complete declaration candidate set for
        // the batch while avoiding per-candidate file-state hydration. Keep
        // all languages in one SQL statement: the active-blob join is the
        // dominant cost on large workspaces, and repeating it once per
        // language turned a broad Firefox search into a serial multi-minute
        // scan.
        let mut conn = {
            let _scope = crate::profiling::scope("store.symbol_names.open_reader");
            self.active_read_conn()?
        };
        let tx = conn.transaction()?;
        {
            let _scope = crate::profiling::scope("store.symbol_names.check_generations");
            require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        }
        {
            let _scope = crate::profiling::scope("store.symbol_names.sync_active_oids");
            sync_active_blob_oids(&tx, active_oids)?;
        }
        let rows = {
            let _scope = crate::profiling::scope("store.symbol_names.query_all_languages");
            search_candidate_name_rows_for_langs_conn_cancellable(
                &tx,
                langs,
                literal_substrings,
                cancellation,
            )?
        };
        tx.commit()?;
        if rows.complete && !cancellation.is_some_and(CancellationToken::is_cancelled) {
            Ok(LimitedQueryRows::complete(rows.rows, rows.inspected))
        } else {
            Ok(LimitedQueryRows::incomplete(rows.rows, rows.inspected))
        }
    }

    /// Hydrate the full search-candidate projection for the declaration keys a
    /// pattern batch already matched.
    ///
    /// The projection is fetched one *blob* at a time rather than one unit at a
    /// time. `code_units` is keyed by `(blob_oid, lang, unit_key)`, so a blob is
    /// an index range scan, and the work is proportional to the number of files
    /// in the answer instead of either the number of matched units (which
    /// degrades to tens of thousands of point lookups when a pattern is broad)
    /// or the whole workspace projection.
    pub(crate) fn search_candidate_rows_for_keys(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        keys: &[SearchCandidateKey],
        cancellation: Option<&CancellationToken>,
    ) -> Result<LimitedQueryRows<SearchCandidateRow>> {
        if keys.is_empty() {
            return Ok(LimitedQueryRows::complete(Vec::new(), 0));
        }
        let mut wanted: HashMap<(usize, Oid), HashSet<i64>> = HashMap::default();
        for key in keys {
            wanted
                .entry((key.lang_index, key.blob_oid))
                .or_default()
                .insert(key.unit_key);
        }
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let sql = search_candidate_sql("units.lang = ?1 AND units.blob_oid = ?2");
        let mut stmt = tx.prepare_cached(&sql)?;
        let mut out = Vec::new();
        let mut inspected = 0usize;
        let mut complete = true;
        for ((lang_index, blob_oid), unit_keys) in &wanted {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                complete = false;
                break;
            }
            let Some(lang) = langs.get(*lang_index) else {
                continue;
            };
            let mut query = stmt.query(rusqlite::params![lang, blob_oid.to_string()])?;
            while let Some(row) = query.next()? {
                inspected = inspected.saturating_add(1);
                // `unit_key` is column 2 of the shared candidate projection.
                // Testing it before materializing keeps a blob's unmatched
                // declarations from allocating their signature text.
                if !unit_keys.contains(&row.get::<_, i64>(2)?) {
                    continue;
                }
                out.push(search_candidate_row_from_row(row)?);
            }
        }
        drop(stmt);
        tx.commit()?;
        if complete && !cancellation.is_some_and(CancellationToken::is_cancelled) {
            Ok(LimitedQueryRows::complete(out, inspected))
        } else {
            Ok(LimitedQueryRows::incomplete(out, inspected))
        }
    }

    pub fn usage_fact_rows_by_lang(&self, lang: &str) -> Result<Vec<UsageFactRow>> {
        let conn = self.read_conn()?;
        usage_fact_rows_by_lang_conn(&conn, lang)
    }

    pub fn usage_fact_rows_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
    ) -> Result<Vec<UsageFactRow>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let mut out = Vec::new();
        for lang in langs {
            out.extend(usage_fact_rows_by_lang_conn(&tx, lang)?);
        }
        tx.commit()?;
        Ok(out)
    }

    pub(crate) fn declaration_and_usage_fact_rows_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
    ) -> Result<(Vec<CandidateRow>, Vec<UsageFactRow>)> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let declaration_sql = declaration_candidate_sql("units.lang = ?1");
        let declarations = candidate_rows_for_languages(
            &tx,
            langs.iter().map(String::as_str),
            &declaration_sql,
            &[],
        )?;
        let mut usage_facts = Vec::new();
        for lang in langs {
            usage_facts.extend(usage_fact_rows_by_lang_conn(&tx, lang)?);
        }
        tx.commit()?;
        Ok((declarations, usage_facts))
    }

    pub fn declaration_candidate_rows_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
    ) -> Result<Vec<CandidateRow>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let sql = declaration_candidate_sql("units.lang = ?1");
        let rows = candidate_rows_for_languages(&tx, langs.iter().map(String::as_str), &sql, &[])?;
        tx.commit()?;
        Ok(rows)
    }

    pub fn declaration_candidate_rows_with_primary_ranges_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
    ) -> Result<Vec<(CandidateRow, Option<Range>)>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let sql = declaration_candidate_sql("units.lang = ?1");
        let mut out = Vec::new();
        for lang in langs {
            let rows =
                candidate_rows_for_languages(&tx, std::iter::once(lang.as_str()), &sql, &[])?;
            let mut oids: Vec<_> = rows.iter().map(|row| row.blob_oid).collect();
            oids.sort();
            oids.dedup();
            let ranges = primary_ranges_by_unit_for_lang_conn(&tx, lang, &oids)?;
            out.extend(rows.into_iter().map(|row| {
                let range = ranges.get(&(row.blob_oid, row.unit_key)).copied();
                (row, range)
            }));
        }
        tx.commit()?;
        Ok(out)
    }

    pub(crate) fn declaration_candidate_rows_with_primary_ranges_by_kind_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        kind: CodeUnitType,
    ) -> Result<Vec<CandidatePrimaryRangeRow>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let sql = format!(
            "SELECT units.blob_oid, units.lang, units.unit_key, units.kind, units.short_name,
                    units.content_qualifier, units.signature, units.synthetic,
                    units.is_type_alias, units.top_level_ordinal, units.in_declarations,
                    units.in_definition_lookup, units.fq_segments,
                    primary_range.start_byte, primary_range.end_byte,
                    primary_range.start_line, primary_range.end_line
             FROM code_units AS units
             JOIN blob_meta AS meta
               ON meta.blob_oid = units.blob_oid AND meta.lang = units.lang
             LEFT JOIN unit_ranges AS primary_range
               ON primary_range.blob_oid = units.blob_oid
              AND primary_range.lang = units.lang
              AND primary_range.unit_key = units.unit_key
              AND primary_range.ordinal = 0
             WHERE units.lang = ?1 AND units.kind = ?2 AND units.in_declarations = 1
               AND {PARSED_BLOB_COMPLETE_CONDITION}
             ORDER BY units.blob_oid, units.unit_key"
        );
        let kind = code_unit_kind_to_i64(kind);
        let mut statement = tx.prepare_cached(&sql)?;
        let mut out = Vec::new();
        for lang in langs {
            out.extend(collect_candidate_primary_range_rows(statement.query_map(
                params![lang, kind],
                candidate_primary_range_row_from_row,
            )?)?);
        }
        drop(statement);
        tx.commit()?;
        Ok(out)
    }

    pub(crate) fn hierarchy_facts_by_keys(
        &self,
        keys: &[HierarchyStorageKey],
        generations: &HashMap<String, GenerationId>,
    ) -> Result<HashMap<HierarchyStorageKey, PersistedHierarchyFacts>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, keys.iter().map(|key| key.lang.as_str()))?;
        let mut keys_by_lang: HashMap<String, Vec<&HierarchyStorageKey>> = HashMap::default();
        let unique_keys = keys.iter().collect::<HashSet<_>>();
        for key in unique_keys {
            keys_by_lang.entry(key.lang.clone()).or_default().push(key);
        }
        let mut out = HashMap::default();
        for (lang, lang_keys) in keys_by_lang {
            let mut oids = lang_keys
                .iter()
                .map(|key| key.blob_oid.to_string())
                .collect::<Vec<_>>();
            oids.sort();
            oids.dedup();
            let imports_by_oid = read_import_infos_bulk(&tx, &lang, &oids)?
                .into_iter()
                .map(|(oid, imports)| (oid, Arc::<[ImportInfo]>::from(imports)))
                .collect::<HashMap<_, _>>();
            let mut supertypes_by_unit = HashMap::default();
            for (oid, entries) in
                read_unit_string_vec_bulk(&tx, &lang, "unit_supertypes", "raw", &oids)?
            {
                for (unit_key, raw) in entries {
                    supertypes_by_unit
                        .entry((oid.clone(), unit_key))
                        .or_insert_with(Vec::new)
                        .push(raw);
                }
            }
            for key in lang_keys {
                let oid = key.blob_oid.to_string();
                let imports = imports_by_oid.get(&oid).cloned().unwrap_or_default();
                let raw_supertypes = Arc::from(
                    supertypes_by_unit
                        .remove(&(oid, key.unit_key))
                        .unwrap_or_default(),
                );
                out.insert(
                    key.clone(),
                    PersistedHierarchyFacts {
                        imports,
                        raw_supertypes,
                    },
                );
            }
        }
        tx.commit()?;
        Ok(out)
    }

    pub fn definition_lookup_candidate_rows_by_oids(
        &self,
        lang: &str,
        oids: &[Oid],
    ) -> Result<Vec<CandidateRow>> {
        let _scope = crate::profiling::scope("AnalyzerStore::definition_lookup_rows_by_oids");
        if crate::profiling::enabled() {
            crate::profiling::note(format!("language={lang} oid_count={}", oids.len()));
        }
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let mut out = Vec::new();
        out.extend(definition_lookup_candidate_rows_by_oids_conn(
            &tx, lang, oids,
        )?);
        if crate::profiling::enabled() {
            crate::profiling::note(format!("row_count={}", out.len()));
        }
        tx.commit()?;
        Ok(out)
    }

    pub fn definition_lookup_candidate_rows_by_keys(
        &self,
        entries: &[(Oid, String)],
        generations: &HashMap<String, GenerationId>,
    ) -> Result<Vec<CandidateRow>> {
        let _scope = crate::profiling::scope("AnalyzerStore::definition_lookup_rows_by_keys");
        if crate::profiling::enabled() {
            crate::profiling::note(format!("key_count={}", entries.len()));
        }
        let mut by_lang: HashMap<String, Vec<Oid>> = HashMap::default();
        for (oid, lang) in entries {
            by_lang.entry(lang.clone()).or_default().push(*oid);
        }
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, by_lang.keys().map(String::as_str))?;
        let mut out = Vec::new();
        for (lang, mut oids) in by_lang {
            oids.sort();
            oids.dedup();
            out.extend(definition_lookup_candidate_rows_by_oids_conn(
                &tx, &lang, &oids,
            )?);
        }
        if crate::profiling::enabled() {
            crate::profiling::note(format!("row_count={}", out.len()));
        }
        tx.commit()?;
        Ok(out)
    }

    pub fn declaration_candidate_rows_by_pattern(
        &self,
        lang: &str,
        _pattern: &str,
    ) -> Result<Vec<CandidateRow>> {
        // Full match semantics are over recomposed, adapter-normalized FQNs,
        // so SQL intentionally supplies a declaration-row candidate set and
        // the query layer applies the existing Rust regex semantics after
        // live-path expansion.
        self.declaration_candidate_rows_by_lang(lang)
    }

    pub fn declaration_candidate_rows_by_pattern_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        _pattern: &str,
    ) -> Result<Vec<CandidateRow>> {
        self.declaration_candidate_rows_for_langs(langs, generations)
    }

    pub fn blobs_with_structured_imports(&self, lang: &str, oids: &[Oid]) -> Result<HashSet<Oid>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let present = blobs_with_structured_imports_conn(&tx, lang, oids)?;
        tx.commit()?;
        Ok(present)
    }

    pub fn blobs_with_structured_imports_by_keys(
        &self,
        entries: &[(Oid, String)],
        generations: &HashMap<String, GenerationId>,
    ) -> Result<HashSet<(Oid, String)>> {
        let mut by_lang: HashMap<String, Vec<Oid>> = HashMap::default();
        for (oid, lang) in entries {
            by_lang.entry(lang.clone()).or_default().push(*oid);
        }
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, by_lang.keys().map(String::as_str))?;
        let mut out = HashSet::default();
        for (lang, mut oids) in by_lang {
            oids.sort();
            oids.dedup();
            for oid in blobs_with_structured_imports_conn(&tx, &lang, &oids)? {
                out.insert((oid, lang.clone()));
            }
        }
        tx.commit()?;
        Ok(out)
    }

    pub fn content_row_count(&self, oid: Oid, lang: &str) -> Result<usize> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let oid = oid.to_string();
        let mut total = 0usize;
        for table in [
            "code_units",
            "unit_ranges",
            "unit_signatures",
            "unit_signature_metadata",
            "unit_cpp_template_metadata",
            "unit_supertypes",
            "unit_children",
            "import_statements",
            "import_details",
            "blob_meta",
            "type_identifiers",
            "ruby_method_dispatch_modes",
            "scala_traits",
        ] {
            let sql = format!(
                "SELECT COUNT(*)
                 FROM {table} AS rows
                 JOIN blobs AS active_blob
                   ON active_blob.blob_oid = rows.blob_oid
                  AND active_blob.lang = rows.lang
                 LEFT JOIN analysis_epochs AS active_epoch
                   ON active_epoch.lang = active_blob.lang
                 WHERE rows.blob_oid = ?1 AND rows.lang = ?2
                   AND active_blob.generation = COALESCE(active_epoch.generation, 0)"
            );
            total = total.saturating_add(
                tx.query_row(&sql, params![oid, lang], |row| row.get::<_, usize>(0))?,
            );
        }
        tx.commit()?;
        Ok(total)
    }

    pub fn gc_with_bloom(&self, reachable: &GrowableBloom) -> Result<usize> {
        self.gc_with(|oid| reachable.contains(oid))
    }

    pub fn gc_with(&self, keep: impl Fn(&str) -> bool) -> Result<usize> {
        let mut conn = self.conn.lock().expect("analyzer store mutex poisoned");
        let tx = conn.transaction()?;
        let dead: Vec<(String, String)> = {
            let mut stmt = tx.prepare(
                "SELECT blobs.blob_oid, blobs.lang
                 FROM blobs
                 LEFT JOIN analysis_epochs AS epochs ON epochs.lang = blobs.lang
                 WHERE blobs.generation = COALESCE(epochs.generation, 0)",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            let mut dead = Vec::new();
            for row in rows {
                let (oid, lang) = row?;
                if !keep(&oid) {
                    dead.push((oid, lang));
                }
            }
            dead
        };
        {
            let mut del = tx.prepare(
                "DELETE FROM blobs
                 WHERE blob_oid = ?1 AND lang = ?2
                   AND generation = COALESCE(
                     (SELECT generation FROM analysis_epochs WHERE lang = ?2), 0
                   )",
            )?;
            for (oid, lang) in &dead {
                del.execute(params![oid, lang])?;
            }
        }
        tx.commit()?;
        let _ = reclaim_stale_generations_conn(&mut conn, STALE_GENERATION_RECLAIM_ROWS);
        conn.pragma_update(None, "incremental_vacuum", 0)?;
        Ok(dead.len())
    }

    #[cfg(test)]
    pub(crate) fn reclaim_stale_generations(&self, max_logical_rows: usize) -> Result<usize> {
        let mut conn = self.conn.lock().expect("analyzer store mutex poisoned");
        reclaim_stale_generations_conn(&mut conn, max_logical_rows)
    }

    pub fn seconds_since_gc(&self) -> Result<Option<i64>> {
        let conn = self.read_conn()?;
        let stored: i64 = conn.query_row(
            "SELECT last_gc_at FROM cache_state WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        Ok(Some(stored)
            .filter(|at| *at > 0)
            .map(|at| crate::cache_db::now_unix_seconds() - at))
    }
}

fn declaration_candidate_sql(predicate: &str) -> String {
    declaration_candidate_sql_with_order(predicate, "units.blob_oid, units.unit_key")
}

fn limited_declaration_candidate_sql(predicate: &str) -> String {
    limited_candidate_rows_sql_with_membership(
        "units",
        "FROM code_units AS units
         JOIN blob_meta AS meta
           ON meta.blob_oid = units.blob_oid AND meta.lang = units.lang",
        predicate,
        "units.in_declarations = 1",
        "units.blob_oid, units.unit_key",
    )
}

fn declaration_candidate_sql_with_order(predicate: &str, order_by: &str) -> String {
    candidate_rows_sql_with_membership(
        "units",
        "FROM code_units AS units
         JOIN blob_meta AS meta
           ON meta.blob_oid = units.blob_oid AND meta.lang = units.lang",
        predicate,
        "units.in_declarations = 1",
        order_by,
    )
}

fn candidate_rows_sql(candidate_alias: &str, from_clause: &str, predicate: &str) -> String {
    candidate_rows_sql_with_membership(
        candidate_alias,
        from_clause,
        predicate,
        &format!("{candidate_alias}.in_declarations = 1"),
        &format!("{candidate_alias}.blob_oid, {candidate_alias}.unit_key"),
    )
}

fn candidate_rows_sql_with_membership(
    candidate_alias: &str,
    from_clause: &str,
    predicate: &str,
    membership: &str,
    order_by: &str,
) -> String {
    candidate_rows_sql_with_membership_and_projection(
        candidate_alias,
        from_clause,
        predicate,
        membership,
        order_by,
        "",
    )
}

fn limited_candidate_rows_sql_with_membership(
    candidate_alias: &str,
    from_clause: &str,
    predicate: &str,
    membership: &str,
    order_by: &str,
) -> String {
    let row_bytes = format!(
        "length(CAST({candidate_alias}.blob_oid AS BLOB))
         + length(CAST({candidate_alias}.lang AS BLOB))
         + length(CAST({candidate_alias}.short_name AS BLOB))
         + length(CAST({candidate_alias}.content_qualifier AS BLOB))
         + COALESCE(length(CAST({candidate_alias}.signature AS BLOB)), 0)
         + COALESCE(length(CAST({candidate_alias}.fq_segments AS BLOB)), 0)"
    );
    let admitted = |column: &str| {
        format!(
            "CASE WHEN ({row_bytes}) <= {MAX_LIMITED_QUERY_ROW_BYTES}
                  THEN {candidate_alias}.{column}
                  ELSE NULL
             END"
        )
    };
    format!(
        "SELECT {}, {}, {candidate_alias}.unit_key,
                {candidate_alias}.kind, {},
                {}, {},
                {candidate_alias}.synthetic, {candidate_alias}.is_type_alias,
                {candidate_alias}.top_level_ordinal, {candidate_alias}.in_declarations,
                {candidate_alias}.in_definition_lookup, {},
                ({row_bytes})
         {from_clause}
         WHERE {predicate} AND {membership}
           AND {PARSED_BLOB_COMPLETE_CONDITION}
         ORDER BY {order_by}",
        admitted("blob_oid"),
        admitted("lang"),
        admitted("short_name"),
        admitted("content_qualifier"),
        admitted("signature"),
        admitted("fq_segments"),
    )
}

fn candidate_rows_sql_with_membership_and_projection(
    candidate_alias: &str,
    from_clause: &str,
    predicate: &str,
    membership: &str,
    order_by: &str,
    extra_projection: &str,
) -> String {
    format!(
        "SELECT {candidate_alias}.blob_oid, {candidate_alias}.lang, {candidate_alias}.unit_key,
                {candidate_alias}.kind, {candidate_alias}.short_name,
                {candidate_alias}.content_qualifier, {candidate_alias}.signature,
                {candidate_alias}.synthetic, {candidate_alias}.is_type_alias,
                {candidate_alias}.top_level_ordinal, {candidate_alias}.in_declarations,
                {candidate_alias}.in_definition_lookup, {candidate_alias}.fq_segments{extra_projection}
         {from_clause}
         WHERE {predicate} AND {membership}
           AND {PARSED_BLOB_COMPLETE_CONDITION}
         ORDER BY {order_by}"
    )
}

fn definition_order_candidate_sql(predicate: &str, membership: &str) -> String {
    candidate_rows_sql_with_membership_and_projection(
        "units",
        "FROM code_units AS units
         JOIN blob_meta AS meta
           ON meta.blob_oid = units.blob_oid AND meta.lang = units.lang",
        predicate,
        membership,
        "units.blob_oid, units.unit_key",
        ",
                (SELECT MIN(ranges.start_byte)
                 FROM unit_ranges AS ranges
                 WHERE ranges.blob_oid = units.blob_oid
                   AND ranges.lang = units.lang
                   AND ranges.unit_key = units.unit_key) AS first_start_byte",
    )
}

fn candidate_rows_for_languages<'a>(
    conn: &Connection,
    langs: impl IntoIterator<Item = &'a str>,
    sql: &str,
    values: &[&dyn ToSql],
) -> Result<Vec<CandidateRow>> {
    let mut statement = conn.prepare_cached(sql)?;
    let mut rows = Vec::new();
    for lang in langs {
        let params = std::iter::once(&lang as &dyn ToSql).chain(values.iter().copied());
        rows.extend(collect_candidate_rows(
            statement.query_map(params_from_iter(params), candidate_row_from_row)?,
        )?);
    }
    Ok(rows)
}

fn candidate_rows_for_languages_limited<'a>(
    conn: &Connection,
    langs: impl IntoIterator<Item = &'a str>,
    sql: &str,
    values: &[&dyn ToSql],
    limit: usize,
) -> Result<LimitedQueryRows<CandidateRow>> {
    if limit == 0 {
        return Ok(LimitedQueryRows::incomplete(Vec::new(), 0));
    }

    let mut statement = conn.prepare_cached(sql)?;
    let mut rows = Vec::new();
    let mut inspected = 0usize;
    let mut bytes = LimitedQueryByteBudget::default();
    for lang in langs {
        let remaining = limit.saturating_sub(inspected);
        if remaining == 0 {
            return Ok(LimitedQueryRows::incomplete(rows, inspected));
        }
        let sql_limit = i64::try_from(remaining).unwrap_or(i64::MAX);
        let params = std::iter::once(&lang as &dyn ToSql)
            .chain(values.iter().copied())
            .chain(std::iter::once(&sql_limit as &dyn ToSql));
        let mut query = statement.query(params_from_iter(params))?;
        while let Some(row) = query.next()? {
            inspected = inspected.saturating_add(1);
            // `fq_segments` occupies index 12; the row-byte budget column follows.
            let row_bytes = row.get::<_, i64>(13)?;
            if !bytes.admit_sqlite_bytes(row_bytes)? {
                return Ok(LimitedQueryRows::incomplete(rows, inspected));
            }
            rows.push(candidate_row_from_row(row)?);
        }
        drop(query);
        if inspected == limit {
            return Ok(LimitedQueryRows::incomplete(rows, inspected));
        }
    }
    Ok(LimitedQueryRows::complete(rows, inspected))
}

fn definition_order_candidate_rows_for_languages<'a>(
    conn: &Connection,
    langs: impl IntoIterator<Item = &'a str>,
    sql: &str,
    values: &[&dyn ToSql],
) -> Result<Vec<DefinitionOrderCandidateRow>> {
    let mut statement = conn.prepare_cached(sql)?;
    let mut rows = Vec::new();
    for lang in langs {
        let params = std::iter::once(&lang as &dyn ToSql).chain(values.iter().copied());
        rows.extend(collect_definition_order_candidate_rows(
            statement.query_map(
                params_from_iter(params),
                definition_order_candidate_row_from_row,
            )?,
        )?);
    }
    Ok(rows)
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum PersistedLookupKey {
    ExactFqn,
    NormalizedFqn,
}

#[derive(Debug, Clone)]
struct StoredUnit {
    key: i64,
    unit: CodeUnit,
    is_type_alias: bool,
    top_level_ordinal: Option<usize>,
    in_declarations: bool,
    in_definition_lookup: bool,
    in_test_region: bool,
}

#[derive(Debug)]
struct PreparedUnitRow {
    key: i64,
    kind: i64,
    short_name: String,
    identifier: String,
    content_qualifier: String,
    exact_fqn: Option<String>,
    normalized_fqn: Option<String>,
    simple_type_name: Option<String>,
    signature: Option<String>,
    synthetic: i64,
    is_type_alias: i64,
    top_level_ordinal: Option<i64>,
    in_declarations: i64,
    in_definition_lookup: i64,
    in_test_region: i64,
    /// Serialized `FqName` segments (see `FqName::encode_segments`), or `None`
    /// when the unit's `fq` is empty (synthetic file-scope units, etc.). Written
    /// to `code_units.fq_segments` and re-interned on load.
    fq_segments: Option<Vec<u8>>,
}

/// The four `rust_*` fact tables' rows for one blob, converted from
/// [`crate::analyzer::rust::facts::RustUsageFacts`] and validated for SQLite
/// binding.
///
/// Built during preparation rather than inside the write transaction, like
/// every other row shape here: the byte-offset conversions are the only thing
/// that can fail, and failing them must not abort a batch mid-commit. Empty for
/// every language except Rust.
#[derive(Debug, Default)]
struct RustFactRows {
    exports: Vec<RustExportRow>,
    import_targets: Vec<RustImportTargetRow>,
    modules: Vec<RustModuleRow>,
    /// `(identifier, context_mask)`
    identifier_occurrences: Vec<(String, i64)>,
    /// The `rust_module_scopes` / `rust_module_routes` /
    /// `rust_module_route_gates` / `rust_item_macros` rows (issue #1793).
    module_routes: RustModuleRouteRows,
}

/// The four module-route tables' rows for one blob.
#[derive(Debug, Default)]
struct RustModuleRouteRows {
    scopes: Vec<RustModuleScopeRow>,
    routes: Vec<RustModuleRouteRow>,
    /// `(route_ordinal, gate_ordinal, macro_name, invocation_start)`
    gates: Vec<(i64, i64, String, i64)>,
    item_macros: Vec<RustItemMacroRow>,
}

/// One `rust_module_scopes` row.
#[derive(Debug)]
struct RustModuleScopeRow {
    ordinal: i64,
    parent_ordinal: Option<i64>,
    module_name: String,
    path_attribute: Option<String>,
    imports_macros: i64,
    body_start: i64,
    body_end: i64,
}

/// One `rust_module_routes` row.
#[derive(Debug)]
struct RustModuleRouteRow {
    ordinal: i64,
    scope_ordinal: i64,
    module_name: String,
    path_attribute: Option<String>,
    visibility: String,
    imports_macros: i64,
    test_gated: i64,
    declaration_start: i64,
    declaration_end: i64,
}

/// One `rust_item_macros` row.
#[derive(Debug)]
struct RustItemMacroRow {
    ordinal: i64,
    macro_name: String,
    visible_after: i64,
    scope_start: i64,
    scope_end: i64,
    passthrough: i64,
}

/// One `rust_exports` row.
#[derive(Debug)]
struct RustExportRow {
    ordinal: i64,
    exported_name: Option<String>,
    source_path: String,
    imported_name: Option<String>,
    is_glob: i64,
}

/// One `rust_modules` row.
#[derive(Debug)]
struct RustModuleRow {
    ordinal: i64,
    module_name: String,
    is_inline: i64,
    start_byte: i64,
    end_byte: i64,
}

/// One `rust_import_targets` row. Named fields rather than positional columns
/// because there are eleven of them at the binding site.
#[derive(Debug)]
struct RustImportTargetRow {
    ordinal: i64,
    module_path: String,
    bound_name: Option<String>,
    imported_name: Option<String>,
    is_glob: i64,
    visibility: String,
    owner_module: String,
    owner_start: i64,
    owner_end: i64,
    local_start: Option<i64>,
    local_end: Option<i64>,
}

impl RustFactRows {
    fn from_facts(facts: &crate::analyzer::rust::facts::RustUsageFacts) -> Result<Self> {
        let exports = facts
            .exports
            .iter()
            .enumerate()
            .map(|(ordinal, export)| {
                Ok(RustExportRow {
                    ordinal: usize_to_i64(ordinal)?,
                    exported_name: export.exported_name.clone(),
                    source_path: export.source_path.clone(),
                    imported_name: export.imported_name.clone(),
                    is_glob: bool_to_i64(export.is_glob),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let import_targets = facts
            .import_targets
            .iter()
            .enumerate()
            .map(|(ordinal, target)| {
                let (local_start, local_end) = match target.local_extent {
                    Some((start, end)) => (Some(usize_to_i64(start)?), Some(usize_to_i64(end)?)),
                    None => (None, None),
                };
                Ok(RustImportTargetRow {
                    ordinal: usize_to_i64(ordinal)?,
                    module_path: target.module_path.clone(),
                    bound_name: target.bound_name.clone(),
                    imported_name: target.imported_name.clone(),
                    is_glob: bool_to_i64(target.is_glob),
                    visibility: encode_rust_visibility(&target.visibility),
                    owner_module: target.owner_module.clone(),
                    owner_start: usize_to_i64(target.owner_start)?,
                    owner_end: usize_to_i64(target.owner_end)?,
                    local_start,
                    local_end,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let modules = facts
            .modules
            .iter()
            .enumerate()
            .map(|(ordinal, module)| {
                Ok(RustModuleRow {
                    ordinal: usize_to_i64(ordinal)?,
                    module_name: module.module_name.clone(),
                    is_inline: bool_to_i64(module.is_inline),
                    start_byte: usize_to_i64(module.start_byte)?,
                    end_byte: usize_to_i64(module.end_byte)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let identifier_occurrences = facts
            .identifier_occurrences
            .iter()
            .map(|occurrence| {
                (
                    occurrence.identifier.clone(),
                    i64::from(occurrence.context_mask),
                )
            })
            .collect();
        let module_routes = RustModuleRouteRows::from_facts(&facts.module_routes)?;
        Ok(Self {
            exports,
            import_targets,
            modules,
            identifier_occurrences,
            module_routes,
        })
    }

    fn logical_rows(&self) -> usize {
        saturating_sum([
            self.exports.len(),
            self.import_targets.len(),
            self.modules.len(),
            self.identifier_occurrences.len(),
            self.module_routes.logical_rows(),
        ])
    }

    fn string_bytes(&self) -> usize {
        saturating_sum([
            saturating_sum(self.exports.iter().map(|row| {
                saturating_sum([
                    row.exported_name.as_ref().map_or(0, String::len),
                    row.source_path.len(),
                    row.imported_name.as_ref().map_or(0, String::len),
                ])
            })),
            saturating_sum(self.import_targets.iter().map(|row| {
                saturating_sum([
                    row.module_path.len(),
                    row.bound_name.as_ref().map_or(0, String::len),
                    row.imported_name.as_ref().map_or(0, String::len),
                    row.visibility.len(),
                    row.owner_module.len(),
                ])
            })),
            saturating_sum(self.modules.iter().map(|row| row.module_name.len())),
            saturating_sum(
                self.identifier_occurrences
                    .iter()
                    .map(|(identifier, _)| identifier.len()),
            ),
            self.module_routes.string_bytes(),
        ])
    }
}

impl RustModuleRouteRows {
    fn from_facts(facts: &crate::analyzer::rust::facts::RustModuleRouteFacts) -> Result<Self> {
        let scopes = facts
            .scopes
            .iter()
            .enumerate()
            .map(|(ordinal, scope)| {
                Ok(RustModuleScopeRow {
                    ordinal: usize_to_i64(ordinal)?,
                    parent_ordinal: scope.parent.map(usize_to_i64).transpose()?,
                    module_name: scope.module_name.clone(),
                    path_attribute: scope.path_attribute.clone(),
                    imports_macros: bool_to_i64(scope.imports_macros),
                    body_start: usize_to_i64(scope.body_start)?,
                    body_end: usize_to_i64(scope.body_end)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut routes = Vec::with_capacity(facts.routes.len());
        let mut gates = Vec::new();
        for (ordinal, route) in facts.routes.iter().enumerate() {
            let ordinal = usize_to_i64(ordinal)?;
            routes.push(RustModuleRouteRow {
                ordinal,
                scope_ordinal: usize_to_i64(route.scope)?,
                module_name: route.module_name.clone(),
                path_attribute: route.path_attribute.clone(),
                visibility: encode_rust_visibility(&route.visibility),
                imports_macros: bool_to_i64(route.imports_macros),
                test_gated: bool_to_i64(route.test_gated),
                declaration_start: usize_to_i64(route.declaration_start)?,
                declaration_end: usize_to_i64(route.declaration_end)?,
            });
            for (gate_ordinal, gate) in route.gates.iter().enumerate() {
                gates.push((
                    ordinal,
                    usize_to_i64(gate_ordinal)?,
                    gate.macro_name.clone(),
                    usize_to_i64(gate.invocation_start)?,
                ));
            }
        }
        let item_macros = facts
            .item_macros
            .iter()
            .enumerate()
            .map(|(ordinal, definition)| {
                Ok(RustItemMacroRow {
                    ordinal: usize_to_i64(ordinal)?,
                    macro_name: definition.name.clone(),
                    visible_after: usize_to_i64(definition.visible_after)?,
                    scope_start: usize_to_i64(definition.scope_start)?,
                    scope_end: usize_to_i64(definition.scope_end)?,
                    passthrough: bool_to_i64(definition.passthrough),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            scopes,
            routes,
            gates,
            item_macros,
        })
    }

    fn logical_rows(&self) -> usize {
        saturating_sum([
            self.scopes.len(),
            self.routes.len(),
            self.gates.len(),
            self.item_macros.len(),
        ])
    }

    fn string_bytes(&self) -> usize {
        saturating_sum([
            saturating_sum(self.scopes.iter().map(|row| {
                saturating_sum([
                    row.module_name.len(),
                    row.path_attribute.as_ref().map_or(0, String::len),
                ])
            })),
            saturating_sum(self.routes.iter().map(|row| {
                saturating_sum([
                    row.module_name.len(),
                    row.path_attribute.as_ref().map_or(0, String::len),
                    row.visibility.len(),
                ])
            })),
            saturating_sum(self.gates.iter().map(|(_, _, name, _)| name.len())),
            saturating_sum(self.item_macros.iter().map(|row| row.macro_name.len())),
        ])
    }
}

/// Read access to the per-file Rust usage fact tables.
///
/// Milestone 1 of `.agents/plans/rust-usage-index-v2.md` lands the tables and
/// this reader; Milestone 2's `RustUsageQueries` is the caller. The allow goes
/// away with that commit -- keeping the reader beside the writer it inverts is
/// what makes the round trip reviewable in one place.
#[allow(dead_code)]
impl AnalyzerStore {
    /// Every persisted per-file Rust usage fact for one blob.
    ///
    /// This is the forward direction of the `rust_*` fact tables: "what does
    /// this file export, import, declare, and mention". A caller that already
    /// knows the file reads it directly; a caller searching by name reaches
    /// these rows through the inverted lookups below and then verifies each
    /// candidate against its facts.
    pub(crate) fn rust_usage_facts(&self, oid: Oid, lang: &str) -> Result<RustUsageFacts> {
        let conn = self.read_conn()?;
        read_rust_usage_facts(&conn, &oid.to_string(), lang)
    }

    /// Blobs that import `module_path`, spelled exactly as the importing file
    /// writes it. The inverted direction of `rust_import_targets`.
    pub(crate) fn rust_import_target_blobs(
        &self,
        lang: &str,
        module_path: &str,
    ) -> Result<Vec<Oid>> {
        self.rust_fact_blobs(
            "SELECT DISTINCT blob_oid FROM rust_import_targets
             WHERE lang = ?1 AND module_path = ?2",
            lang,
            module_path,
        )
    }

    /// Blobs that re-export `exported_name`. The inverted direction of
    /// `rust_exports`, and the seed of an export-chain walk.
    pub(crate) fn rust_export_blobs(&self, lang: &str, exported_name: &str) -> Result<Vec<Oid>> {
        self.rust_fact_blobs(
            "SELECT DISTINCT blob_oid FROM rust_exports
             WHERE lang = ?1 AND exported_name = ?2",
            lang,
            exported_name,
        )
    }

    /// Blobs whose text mentions `identifier`, with the OR of the contexts it
    /// was seen in. These are CANDIDATES, never usages: a hit means the name
    /// occurs, and the caller must still resolve it against the candidate's
    /// own facts. Comparison is case-sensitive, matching the spelling the
    /// declaration side stores.
    pub(crate) fn rust_identifier_occurrence_blobs(
        &self,
        lang: &str,
        identifier: &str,
    ) -> Result<Vec<(Oid, u32)>> {
        let conn = self.read_conn()?;
        let mut stmt = conn.prepare_cached(
            "SELECT blob_oid, context_mask FROM rust_identifier_occurrences
             WHERE lang = ?1 AND identifier = ?2",
        )?;
        let rows = stmt.query_map(params![lang, identifier], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (oid, context_mask) = row?;
            out.push((
                Oid::from_str(&oid)?,
                u32::try_from(context_mask).map_err(|_| {
                    StoreError::new(format!(
                        "occurrence context mask out of range: {context_mask}"
                    ))
                })?,
            ));
        }
        out.sort();
        Ok(out)
    }

    /// Test hook: drop every persisted Rust fact row for `lang`, leaving the
    /// blobs analyzed.
    ///
    /// This synthesizes the exact state the Milestone 3 catch-up policy exists
    /// for -- live files whose blobs carry no fact rows -- which no production
    /// path can be asked to produce on demand. It follows
    /// `mark_parsed_blob_incomplete_for_test`, the store's existing way of
    /// putting itself into a state only recovery code should see.
    #[cfg(test)]
    pub(crate) fn delete_rust_facts_for_test(&self, lang: &str) {
        let conn = self.conn.lock().expect("analyzer store mutex poisoned");
        for table in [
            "rust_exports",
            "rust_import_targets",
            "rust_modules",
            "rust_identifier_occurrences",
            "rust_module_scopes",
            "rust_module_routes",
            "rust_module_route_gates",
            "rust_item_macros",
        ] {
            conn.execute(
                &format!("DELETE FROM {table} WHERE lang = ?1"),
                params![lang],
            )
            .expect("delete rust fact rows");
        }
    }

    /// Which of `oids` already carry Rust fact rows.
    ///
    /// `rust_modules` is the witness table: every analyzed Rust blob records
    /// its file-root extent at ordinal 0, so a blob absent from it has no facts
    /// at all. That is the same rule the reader applies when it treats an empty
    /// module list as "never analyzed" (`RustAnalyzer::rust_usage_facts_of_blob`).
    ///
    /// Chunked set membership over the primary key, following
    /// `parsed_blob_keys_conn_with_condition`: each chunk is a batch of index
    /// seeks, so the cost tracks the live file set rather than the table's
    /// accumulated history.
    pub(crate) fn blobs_with_rust_facts(&self, lang: &str, oids: &[Oid]) -> Result<HashSet<Oid>> {
        const OIDS_PER_QUERY: usize = 400;
        let mut unique: Vec<String> = oids.iter().map(Oid::to_string).collect();
        unique.sort();
        unique.dedup();
        let conn = self.read_conn()?;
        let mut present = set_with_capacity(unique.len());
        for chunk in unique.chunks(OIDS_PER_QUERY) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!(
                "SELECT DISTINCT blob_oid FROM rust_modules
                 WHERE lang = ? AND blob_oid IN ({placeholders})"
            );
            let mut stmt = conn.prepare_cached(&sql)?;
            let parameters = std::iter::once(lang).chain(chunk.iter().map(String::as_str));
            let rows =
                stmt.query_map(params_from_iter(parameters), |row| row.get::<_, String>(0))?;
            for row in rows {
                present.insert(Oid::from_str(&row?)?);
            }
        }
        Ok(present)
    }

    /// Every live blob's module-route facts, in one chunked pass.
    ///
    /// This is what replaced hydrating and parsing every analyzed Rust file to
    /// build `RustCargoRouteIndex` (issue #1793). The index is a
    /// whole-workspace product, so it genuinely needs every file's rows; asking
    /// per blob would be tens of thousands of round trips, where four chunked
    /// index seeks per batch is a scan of exactly the rows that exist.
    ///
    /// A blob with no rows is absent from the result, which the caller
    /// distinguishes from "this file declares nothing".
    pub(crate) fn rust_module_route_facts(
        &self,
        lang: &str,
        oids: &[Oid],
    ) -> Result<HashMap<Oid, RustModuleRouteFacts>> {
        const OIDS_PER_QUERY: usize = 400;
        let mut unique: Vec<String> = oids.iter().map(Oid::to_string).collect();
        unique.sort();
        unique.dedup();
        let conn = self.read_conn()?;
        let mut by_oid: HashMap<Oid, RustModuleRouteFacts> = HashMap::default();
        for chunk in unique.chunks(OIDS_PER_QUERY) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(", ");
            let mut stmt = conn.prepare_cached(&format!(
                "SELECT blob_oid, parent_ordinal, module_name, path_attribute, imports_macros,
                        body_start, body_end
                 FROM rust_module_scopes
                 WHERE lang = ? AND blob_oid IN ({placeholders})
                 ORDER BY blob_oid, ordinal"
            ))?;
            let rows = stmt.query_map(
                params_from_iter(std::iter::once(lang).chain(chunk.iter().map(String::as_str))),
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        decode_rust_module_scope_row(row, 1)?,
                    ))
                },
            )?;
            for row in rows {
                let (oid, scope) = row?;
                by_oid
                    .entry(Oid::from_str(&oid)?)
                    .or_default()
                    .scopes
                    .push(scope?);
            }
            let mut stmt = conn.prepare_cached(&format!(
                "SELECT blob_oid, scope_ordinal, module_name, path_attribute, visibility,
                        imports_macros, test_gated, declaration_start, declaration_end
                 FROM rust_module_routes
                 WHERE lang = ? AND blob_oid IN ({placeholders})
                 ORDER BY blob_oid, ordinal"
            ))?;
            let rows = stmt.query_map(
                params_from_iter(std::iter::once(lang).chain(chunk.iter().map(String::as_str))),
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        decode_rust_module_route_row(row, 1)?,
                    ))
                },
            )?;
            for row in rows {
                let (oid, route) = row?;
                by_oid
                    .entry(Oid::from_str(&oid)?)
                    .or_default()
                    .routes
                    .push(route?);
            }
            let mut stmt = conn.prepare_cached(&format!(
                "SELECT blob_oid, route_ordinal, macro_name, invocation_start
                 FROM rust_module_route_gates
                 WHERE lang = ? AND blob_oid IN ({placeholders})
                 ORDER BY blob_oid, route_ordinal, gate_ordinal"
            ))?;
            let rows = stmt.query_map(
                params_from_iter(std::iter::once(lang).chain(chunk.iter().map(String::as_str))),
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        decode_rust_module_route_gate_row(row, 1)?,
                    ))
                },
            )?;
            for row in rows {
                let (oid, gate) = row?;
                let (route_ordinal, gate) = gate?;
                let facts = by_oid.entry(Oid::from_str(&oid)?).or_default();
                attach_rust_module_route_gate(&mut facts.routes, route_ordinal, gate)?;
            }
            let mut stmt = conn.prepare_cached(&format!(
                "SELECT blob_oid, macro_name, visible_after, scope_start, scope_end, passthrough
                 FROM rust_item_macros
                 WHERE lang = ? AND blob_oid IN ({placeholders})
                 ORDER BY blob_oid, ordinal"
            ))?;
            let rows = stmt.query_map(
                params_from_iter(std::iter::once(lang).chain(chunk.iter().map(String::as_str))),
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        decode_rust_item_macro_row(row, 1)?,
                    ))
                },
            )?;
            for row in rows {
                let (oid, definition) = row?;
                by_oid
                    .entry(Oid::from_str(&oid)?)
                    .or_default()
                    .item_macros
                    .push(definition?);
            }
        }
        Ok(by_oid)
    }

    fn rust_fact_blobs(&self, sql: &str, lang: &str, key: &str) -> Result<Vec<Oid>> {
        let conn = self.read_conn()?;
        let mut stmt = conn.prepare_cached(sql)?;
        let rows = stmt.query_map(params![lang, key], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(Oid::from_str(&row?)?);
        }
        out.sort();
        Ok(out)
    }
}

/// Write one blob's `rust_*` fact rows. Shared by the prepared and legacy write
/// paths so both persist exactly the same rows.
fn insert_rust_fact_rows(
    tx: &Transaction<'_>,
    oid: &str,
    lang: &str,
    rows: &RustFactRows,
) -> Result<()> {
    if !rows.exports.is_empty() {
        let mut stmt = tx.prepare(
            "INSERT OR IGNORE INTO rust_exports(
               blob_oid, lang, ordinal, exported_name, source_path, imported_name, is_glob
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;
        for row in &rows.exports {
            stmt.execute(params![
                oid,
                lang,
                row.ordinal,
                row.exported_name,
                row.source_path,
                row.imported_name,
                row.is_glob,
            ])?;
        }
    }
    if !rows.import_targets.is_empty() {
        let mut stmt = tx.prepare(
            "INSERT OR IGNORE INTO rust_import_targets(
               blob_oid, lang, ordinal, module_path, bound_name, imported_name, is_glob,
               visibility, owner_module, owner_start, owner_end, local_start, local_end
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        )?;
        for row in &rows.import_targets {
            stmt.execute(params![
                oid,
                lang,
                row.ordinal,
                row.module_path,
                row.bound_name,
                row.imported_name,
                row.is_glob,
                row.visibility,
                row.owner_module,
                row.owner_start,
                row.owner_end,
                row.local_start,
                row.local_end,
            ])?;
        }
    }
    if !rows.modules.is_empty() {
        let mut stmt = tx.prepare(
            "INSERT OR IGNORE INTO rust_modules(
               blob_oid, lang, ordinal, module_name, is_inline, start_byte, end_byte
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;
        for row in &rows.modules {
            stmt.execute(params![
                oid,
                lang,
                row.ordinal,
                row.module_name,
                row.is_inline,
                row.start_byte,
                row.end_byte,
            ])?;
        }
    }
    if !rows.identifier_occurrences.is_empty() {
        let mut stmt = tx.prepare(
            "INSERT OR IGNORE INTO rust_identifier_occurrences(
               blob_oid, lang, identifier, context_mask
             ) VALUES(?1, ?2, ?3, ?4)",
        )?;
        for (identifier, context_mask) in &rows.identifier_occurrences {
            stmt.execute(params![oid, lang, identifier, context_mask])?;
        }
    }
    let routes = &rows.module_routes;
    if !routes.scopes.is_empty() {
        let mut stmt = tx.prepare(
            "INSERT OR IGNORE INTO rust_module_scopes(
               blob_oid, lang, ordinal, parent_ordinal, module_name, path_attribute,
               imports_macros, body_start, body_end
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )?;
        for row in &routes.scopes {
            stmt.execute(params![
                oid,
                lang,
                row.ordinal,
                row.parent_ordinal,
                row.module_name,
                row.path_attribute,
                row.imports_macros,
                row.body_start,
                row.body_end,
            ])?;
        }
    }
    if !routes.routes.is_empty() {
        let mut stmt = tx.prepare(
            "INSERT OR IGNORE INTO rust_module_routes(
               blob_oid, lang, ordinal, scope_ordinal, module_name, path_attribute,
               visibility, imports_macros, test_gated, declaration_start, declaration_end
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        )?;
        for row in &routes.routes {
            stmt.execute(params![
                oid,
                lang,
                row.ordinal,
                row.scope_ordinal,
                row.module_name,
                row.path_attribute,
                row.visibility,
                row.imports_macros,
                row.test_gated,
                row.declaration_start,
                row.declaration_end,
            ])?;
        }
    }
    if !routes.gates.is_empty() {
        let mut stmt = tx.prepare(
            "INSERT OR IGNORE INTO rust_module_route_gates(
               blob_oid, lang, route_ordinal, gate_ordinal, macro_name, invocation_start
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        for (route_ordinal, gate_ordinal, macro_name, invocation_start) in &routes.gates {
            stmt.execute(params![
                oid,
                lang,
                route_ordinal,
                gate_ordinal,
                macro_name,
                invocation_start,
            ])?;
        }
    }
    if !routes.item_macros.is_empty() {
        let mut stmt = tx.prepare(
            "INSERT OR IGNORE INTO rust_item_macros(
               blob_oid, lang, ordinal, macro_name, visible_after, scope_start, scope_end,
               passthrough
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?;
        for row in &routes.item_macros {
            stmt.execute(params![
                oid,
                lang,
                row.ordinal,
                row.macro_name,
                row.visible_after,
                row.scope_start,
                row.scope_end,
                row.passthrough,
            ])?;
        }
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct PreparedParsedBlob {
    oid: Oid,
    oid_text: String,
    lang: String,
    generation: GenerationId,
    state: Arc<FileState>,
    units: Vec<PreparedUnitRow>,
    ranges: Vec<(i64, i64, i64, i64, i64, i64)>,
    signatures: Vec<(i64, i64, String)>,
    signature_metadata: Vec<(i64, i64, Vec<u8>)>,
    cpp_template_metadata: Vec<(i64, Vec<u8>)>,
    supertypes: Vec<(i64, i64, String, String)>,
    children: Vec<(i64, i64, i64)>,
    import_statements: Vec<(i64, String)>,
    imports: Vec<(i64, Vec<u8>)>,
    scala_exports: Vec<(i64, i64, Vec<u8>)>,
    rust_facts: RustFactRows,
    type_identifiers: Vec<String>,
    ruby_dispatch_modes: Vec<(i64, i64)>,
    scala_traits: Vec<i64>,
    materialization_records: Vec<(i64, Option<i64>, Vec<u8>)>,
    contains_tests: i64,
    content_package: String,
    logical_rows: usize,
    payload_bytes: usize,
    mutation_logical_rows: usize,
    mutation_payload_bytes: usize,
}

impl PreparedParsedBlob {
    pub(crate) fn oid(&self) -> Oid {
        self.oid
    }

    pub(crate) fn lang(&self) -> &str {
        &self.lang
    }

    pub(crate) fn state(&self) -> &Arc<FileState> {
        &self.state
    }

    pub(crate) fn logical_rows(&self) -> usize {
        self.logical_rows
    }

    pub(crate) fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }

    fn mutation_logical_rows(&self) -> usize {
        self.mutation_logical_rows
    }

    fn mutation_payload_bytes(&self) -> usize {
        self.mutation_payload_bytes
    }

    fn persisted_payload_bytes(&self) -> usize {
        self.payload_bytes.saturating_sub(self.state.source.len())
    }

    #[cfg(test)]
    pub(crate) fn inject_invalid_range_for_test(&mut self) {
        self.ranges.push((i64::MAX, 0, 0, 0, 0, 0));
        self.logical_rows = self.logical_rows.saturating_add(1);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PersistBatchLimits {
    pub(crate) max_blobs: usize,
    pub(crate) max_rows: usize,
    pub(crate) max_payload_bytes: usize,
}

impl PersistBatchLimits {
    pub(crate) const PRODUCTION: Self = Self {
        max_blobs: 64,
        max_rows: 100_000,
        max_payload_bytes: 32 * 1024 * 1024,
    };

    fn normalized(self) -> Self {
        Self {
            max_blobs: self.max_blobs.max(1),
            max_rows: self.max_rows.max(1),
            max_payload_bytes: self.max_payload_bytes.max(1),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PersistBatchStats {
    pub(crate) transactions: usize,
    pub(crate) failed_transaction_attempts: usize,
    pub(crate) committed_blobs: usize,
    pub(crate) failed_blobs: usize,
    pub(crate) logical_rows: usize,
    pub(crate) payload_bytes: usize,
    pub(crate) peak_batch_blobs: usize,
    pub(crate) peak_batch_rows: usize,
    pub(crate) peak_batch_payload_bytes: usize,
    pub(crate) peak_in_flight_items: usize,
    pub(crate) peak_in_flight_payload_bytes: usize,
    pub(crate) configured_max_in_flight_items: usize,
}

impl PersistBatchStats {
    pub(crate) fn merge(&mut self, other: Self) {
        self.transactions = self.transactions.saturating_add(other.transactions);
        self.failed_transaction_attempts = self
            .failed_transaction_attempts
            .saturating_add(other.failed_transaction_attempts);
        self.committed_blobs = self.committed_blobs.saturating_add(other.committed_blobs);
        self.failed_blobs = self.failed_blobs.saturating_add(other.failed_blobs);
        self.logical_rows = self.logical_rows.saturating_add(other.logical_rows);
        self.payload_bytes = self.payload_bytes.saturating_add(other.payload_bytes);
        self.peak_batch_blobs = self.peak_batch_blobs.max(other.peak_batch_blobs);
        self.peak_batch_rows = self.peak_batch_rows.max(other.peak_batch_rows);
        self.peak_batch_payload_bytes = self
            .peak_batch_payload_bytes
            .max(other.peak_batch_payload_bytes);
        self.peak_in_flight_items = self.peak_in_flight_items.max(other.peak_in_flight_items);
        self.peak_in_flight_payload_bytes = self
            .peak_in_flight_payload_bytes
            .max(other.peak_in_flight_payload_bytes);
        self.configured_max_in_flight_items = self
            .configured_max_in_flight_items
            .max(other.configured_max_in_flight_items);
    }
}

#[derive(Debug)]
pub(crate) struct PersistBlobOutcome {
    pub(crate) prepared: PreparedParsedBlob,
    pub(crate) error: Option<StoreError>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PersistedMutationCost {
    logical_rows: usize,
    payload_bytes: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PersistedSideTableCounts {
    range_count: usize,
    signature_count: usize,
    signature_metadata_count: usize,
    cpp_template_metadata_count: usize,
    supertype_count: usize,
    child_count: usize,
    import_statement_count: usize,
    import_count: usize,
    type_identifier_count: usize,
    ruby_dispatch_count: usize,
    scala_trait_count: usize,
}

fn saturating_sum(values: impl IntoIterator<Item = usize>) -> usize {
    values
        .into_iter()
        .fold(0usize, |total, value| total.saturating_add(value))
}

fn prepare_parsed_blob<A: LanguageAdapter>(
    oid: Oid,
    lang: &str,
    generation: GenerationId,
    adapter: &A,
    state: Arc<FileState>,
) -> Result<PreparedParsedBlob> {
    let stored_units = collect_stored_units(adapter, state.as_ref());
    let unit_keys: HashMap<CodeUnit, i64> = stored_units
        .iter()
        .map(|stored| (stored.unit.clone(), stored.key))
        .collect();
    let persist_lookup_keys = adapter.persist_content_stable_lookup_keys();
    let mut units = Vec::with_capacity(stored_units.len());
    for stored in stored_units {
        let content_qualifier =
            adapter.storage_content_qualifier(&stored.unit, &state.content_qualifier);
        let exact_fqn = persist_lookup_keys.then(|| stored.unit.fq_name());
        let normalized_fqn = exact_fqn
            .as_deref()
            .map(|fqn| adapter.normalize_full_name(fqn));
        let simple_type_name = (persist_lookup_keys && stored.unit.is_class())
            .then(|| adapter.simple_type_name(&stored.unit));
        units.push(PreparedUnitRow {
            key: stored.key,
            kind: code_unit_kind_to_i64(stored.unit.kind()),
            short_name: stored.unit.short_name().to_string(),
            identifier: stored.unit.identifier().to_string(),
            content_qualifier: content_qualifier.clone(),
            exact_fqn,
            normalized_fqn,
            simple_type_name,
            signature: stored.unit.signature().map(str::to_string),
            synthetic: bool_to_i64(stored.unit.is_synthetic()),
            is_type_alias: bool_to_i64(stored.is_type_alias),
            top_level_ordinal: stored.top_level_ordinal.map(usize_to_i64).transpose()?,
            in_declarations: bool_to_i64(stored.in_declarations),
            in_definition_lookup: bool_to_i64(stored.in_definition_lookup),
            in_test_region: bool_to_i64(stored.in_test_region),
            fq_segments: encode_unit_fq_segments(adapter, &stored.unit, &content_qualifier),
        });
    }

    let mut ranges = Vec::new();
    for (unit, entries) in &state.ranges {
        let Some(&unit_key) = unit_keys.get(unit) else {
            continue;
        };
        for (ordinal, range) in entries.iter().enumerate() {
            ranges.push((
                unit_key,
                usize_to_i64(ordinal)?,
                usize_to_i64(range.start_byte)?,
                usize_to_i64(range.end_byte)?,
                usize_to_i64(range.start_line)?,
                usize_to_i64(range.end_line)?,
            ));
        }
    }
    let mut signatures = Vec::new();
    for (unit, entries) in &state.signatures {
        let Some(&unit_key) = unit_keys.get(unit) else {
            continue;
        };
        for (ordinal, signature) in entries.iter().enumerate() {
            signatures.push((unit_key, usize_to_i64(ordinal)?, signature.clone()));
        }
    }
    let mut signature_metadata = Vec::new();
    for (unit, entries) in &state.signature_metadata {
        let Some(&unit_key) = unit_keys.get(unit) else {
            continue;
        };
        for (ordinal, metadata) in entries.iter().enumerate() {
            let metadata = serialize_signature_metadata_blob(metadata)?;
            signature_metadata.push((unit_key, usize_to_i64(ordinal)?, metadata));
        }
    }
    let mut cpp_template_metadata = Vec::new();
    for (unit, metadata) in &state.cpp_template_metadata {
        let Some(&unit_key) = unit_keys.get(unit) else {
            continue;
        };
        cpp_template_metadata.push((unit_key, serialize_blob(metadata)?));
    }
    let mut supertypes = Vec::new();
    for (unit, entries) in &state.raw_supertypes {
        let Some(&unit_key) = unit_keys.get(unit) else {
            continue;
        };
        for (ordinal, raw) in entries.iter().enumerate() {
            supertypes.push((
                unit_key,
                usize_to_i64(ordinal)?,
                raw.clone(),
                state
                    .supertype_lookup_paths
                    .get(unit)
                    .and_then(|paths| paths.get(ordinal))
                    .cloned()
                    .unwrap_or_default(),
            ));
        }
    }
    let mut children = Vec::new();
    for (parent, entries) in &state.children {
        let Some(&parent_key) = unit_keys.get(parent) else {
            continue;
        };
        for (ordinal, child) in entries.iter().enumerate() {
            let Some(&child_key) = unit_keys.get(child) else {
                continue;
            };
            children.push((parent_key, child_key, usize_to_i64(ordinal)?));
        }
    }
    let mut ruby_dispatch_modes = Vec::new();
    for (unit, mode) in &state.ruby_method_dispatch_modes {
        if let Some(&unit_key) = unit_keys.get(unit) {
            ruby_dispatch_modes.push((unit_key, ruby_dispatch_mode_to_i64(*mode)));
        }
    }
    let mut scala_traits = Vec::new();
    for unit in &state.scala_traits {
        if let Some(&unit_key) = unit_keys.get(unit) {
            scala_traits.push(unit_key);
        }
    }
    let mut materialization_records = Vec::new();
    for (ordinal, record) in state.materialization_records.iter().enumerate() {
        let (unit, payload) = record.split();
        let unit_key = match unit {
            Some(unit) => match unit_keys.get(unit) {
                Some(&key) => Some(key),
                None => continue,
            },
            None => None,
        };
        materialization_records.push((usize_to_i64(ordinal)?, unit_key, serialize_blob(&payload)?));
    }
    let import_statements = state
        .import_statements
        .iter()
        .enumerate()
        .map(|(ordinal, statement)| Ok((usize_to_i64(ordinal)?, statement.clone())))
        .collect::<Result<Vec<_>>>()?;
    let imports = state
        .imports
        .iter()
        .enumerate()
        .map(|(ordinal, import)| Ok((usize_to_i64(ordinal)?, serialize_blob(import)?)))
        .collect::<Result<Vec<_>>>()?;
    let mut scala_exports = Vec::new();
    for (owner, entries) in &state.scala_exports {
        let Some(&owner_key) = unit_keys.get(owner) else {
            continue;
        };
        for (ordinal, info) in entries.iter().enumerate() {
            scala_exports.push((owner_key, usize_to_i64(ordinal)?, serialize_blob(info)?));
        }
    }
    let rust_facts = RustFactRows::from_facts(&state.rust_usage_facts)?;
    let mut type_identifiers: Vec<_> = state.type_identifiers.iter().cloned().collect();
    type_identifiers.sort();

    let logical_rows = saturating_sum([
        3,
        units.len(),
        ranges.len(),
        signatures.len(),
        signature_metadata.len(),
        cpp_template_metadata.len(),
        supertypes.len(),
        children.len(),
        import_statements.len(),
        imports.len(),
        scala_exports.len(),
        type_identifiers.len(),
        ruby_dispatch_modes.len(),
        scala_traits.len(),
        materialization_records.len(),
        rust_facts.logical_rows(),
    ]);
    let unit_string_bytes = saturating_sum(units.iter().map(|row| {
        saturating_sum([
            row.short_name.len(),
            row.identifier.len(),
            row.content_qualifier.len(),
            row.exact_fqn.as_ref().map_or(0, String::len),
            row.normalized_fqn.as_ref().map_or(0, String::len),
            row.simple_type_name.as_ref().map_or(0, String::len),
            row.signature.as_ref().map_or(0, String::len),
        ])
    }));
    let string_bytes = saturating_sum([
        unit_string_bytes,
        saturating_sum(signatures.iter().map(|(_, _, text)| text.len())),
        saturating_sum(
            supertypes
                .iter()
                .map(|(_, _, raw, path)| raw.len().saturating_add(path.len())),
        ),
        saturating_sum(
            import_statements
                .iter()
                .map(|(_, statement)| statement.len()),
        ),
        saturating_sum(type_identifiers.iter().map(String::len)),
        rust_facts.string_bytes(),
    ]);
    let binary_bytes = saturating_sum([
        saturating_sum(signature_metadata.iter().map(|(_, _, bytes)| bytes.len())),
        saturating_sum(cpp_template_metadata.iter().map(|(_, bytes)| bytes.len())),
        saturating_sum(imports.iter().map(|(_, bytes)| bytes.len())),
        saturating_sum(scala_exports.iter().map(|(_, _, bytes)| bytes.len())),
        saturating_sum(
            materialization_records
                .iter()
                .map(|(_, _, bytes)| bytes.len()),
        ),
    ]);
    let content_package = adapter.storage_file_content_qualifier(&state.content_qualifier);
    let contains_tests = bool_to_i64(adapter.storage_contains_tests(&state));
    let payload_bytes = state
        .source
        .len()
        .saturating_add(string_bytes)
        .saturating_add(binary_bytes)
        .saturating_add(content_package.len());

    Ok(PreparedParsedBlob {
        oid,
        oid_text: oid.to_string(),
        lang: lang.to_string(),
        generation,
        state,
        units,
        ranges,
        signatures,
        signature_metadata,
        cpp_template_metadata,
        supertypes,
        children,
        import_statements,
        imports,
        scala_exports,
        rust_facts,
        type_identifiers,
        ruby_dispatch_modes,
        scala_traits,
        materialization_records,
        contains_tests,
        content_package,
        logical_rows,
        payload_bytes,
        mutation_logical_rows: logical_rows,
        mutation_payload_bytes: payload_bytes,
    })
}

// The caller must validate every distinct language generation in this transaction
// before invoking this helper. Keeping that validation at the batch boundary avoids
// repeating the same point lookup for every blob in a language.
fn write_prepared_blob_unchecked_tx(tx: &Transaction<'_>, blob: &PreparedParsedBlob) -> Result<()> {
    let oid = blob.oid_text.as_str();
    let lang = blob.lang.as_str();
    tx.execute(
        "DELETE FROM blobs WHERE blob_oid = ?1 AND lang = ?2",
        params![oid, lang],
    )?;
    tx.execute(
        "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, ?2, ?3)",
        params![oid, lang, blob.generation.0],
    )?;
    {
        let mut stmt = tx.prepare(
            "INSERT OR IGNORE INTO code_units(
               blob_oid, lang, unit_key, kind, short_name, identifier, content_qualifier,
               exact_fqn, normalized_fqn, simple_type_name, signature, synthetic,
               is_type_alias, top_level_ordinal, in_declarations, in_definition_lookup,
               in_test_region, fq_segments
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
        )?;
        for row in &blob.units {
            stmt.execute(params![
                oid,
                lang,
                row.key,
                row.kind,
                row.short_name,
                row.identifier,
                row.content_qualifier,
                row.exact_fqn,
                row.normalized_fqn,
                row.simple_type_name,
                row.signature,
                row.synthetic,
                row.is_type_alias,
                row.top_level_ordinal,
                row.in_declarations,
                row.in_definition_lookup,
                row.in_test_region,
                row.fq_segments,
            ])?;
        }
    }
    macro_rules! insert_rows {
        ($sql:expr, $rows:expr, |$stmt:ident, $row:ident| $body:block) => {{
            let mut $stmt = tx.prepare($sql)?;
            for $row in $rows $body
        }};
    }
    insert_rows!(
        "INSERT OR IGNORE INTO unit_ranges(blob_oid, lang, unit_key, ordinal, start_byte, end_byte, start_line, end_line) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        &blob.ranges,
        |stmt, row| {
            stmt.execute(params![oid, lang, row.0, row.1, row.2, row.3, row.4, row.5])?;
        }
    );
    insert_rows!(
        "INSERT OR IGNORE INTO unit_signatures(blob_oid, lang, unit_key, ordinal, text) VALUES(?1, ?2, ?3, ?4, ?5)",
        &blob.signatures,
        |stmt, row| {
            stmt.execute(params![oid, lang, row.0, row.1, row.2])?;
        }
    );
    insert_rows!(
        "INSERT OR IGNORE INTO unit_signature_metadata(blob_oid, lang, unit_key, ordinal, metadata) VALUES(?1, ?2, ?3, ?4, ?5)",
        &blob.signature_metadata,
        |stmt, row| {
            stmt.execute(params![oid, lang, row.0, row.1, row.2])?;
        }
    );
    insert_rows!(
        "INSERT OR IGNORE INTO unit_cpp_template_metadata(blob_oid, lang, unit_key, metadata) VALUES(?1, ?2, ?3, ?4)",
        &blob.cpp_template_metadata,
        |stmt, row| {
            stmt.execute(params![oid, lang, row.0, row.1])?;
        }
    );
    insert_rows!(
        "INSERT OR IGNORE INTO unit_supertypes(blob_oid, lang, unit_key, ordinal, raw, lookup_path) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
        &blob.supertypes,
        |stmt, row| {
            stmt.execute(params![oid, lang, row.0, row.1, row.2, row.3])?;
        }
    );
    insert_rows!(
        "INSERT OR IGNORE INTO unit_children(blob_oid, lang, parent_key, child_key, ordinal) VALUES(?1, ?2, ?3, ?4, ?5)",
        &blob.children,
        |stmt, row| {
            stmt.execute(params![oid, lang, row.0, row.1, row.2])?;
        }
    );
    insert_rows!(
        "INSERT OR IGNORE INTO import_statements(blob_oid, lang, ordinal, statement) VALUES(?1, ?2, ?3, ?4)",
        &blob.import_statements,
        |stmt, row| {
            stmt.execute(params![oid, lang, row.0, row.1])?;
        }
    );
    insert_rows!(
        "INSERT OR IGNORE INTO import_details(blob_oid, lang, ordinal, info) VALUES(?1, ?2, ?3, ?4)",
        &blob.imports,
        |stmt, row| {
            stmt.execute(params![oid, lang, row.0, row.1])?;
        }
    );
    insert_rows!(
        "INSERT OR IGNORE INTO scala_exports(blob_oid, lang, owner_key, ordinal, info) VALUES(?1, ?2, ?3, ?4, ?5)",
        &blob.scala_exports,
        |stmt, row| {
            stmt.execute(params![oid, lang, row.0, row.1, row.2])?;
        }
    );
    insert_rows!(
        "INSERT OR IGNORE INTO type_identifiers(blob_oid, lang, type_identifier) VALUES(?1, ?2, ?3)",
        &blob.type_identifiers,
        |stmt, row| {
            stmt.execute(params![oid, lang, row])?;
        }
    );
    insert_rows!(
        "INSERT OR IGNORE INTO ruby_method_dispatch_modes(blob_oid, lang, unit_key, mode) VALUES(?1, ?2, ?3, ?4)",
        &blob.ruby_dispatch_modes,
        |stmt, row| {
            stmt.execute(params![oid, lang, row.0, row.1])?;
        }
    );
    insert_rows!(
        "INSERT OR IGNORE INTO materialization_records(blob_oid, lang, ordinal, unit_key, payload) VALUES(?1, ?2, ?3, ?4, ?5)",
        &blob.materialization_records,
        |stmt, row| {
            stmt.execute(params![oid, lang, row.0, row.1, row.2])?;
        }
    );
    insert_rows!(
        "INSERT OR IGNORE INTO scala_traits(blob_oid, lang, unit_key) VALUES(?1, ?2, ?3)",
        &blob.scala_traits,
        |stmt, row| {
            stmt.execute(params![oid, lang, row])?;
        }
    );
    insert_rust_fact_rows(tx, oid, lang, &blob.rust_facts)?;
    tx.execute(
        "INSERT OR IGNORE INTO blob_meta(
           blob_oid, lang, contains_tests, content_package, stored_unit_count,
           range_count, signature_count, signature_metadata_count, supertype_count,
           child_count, import_statement_count, import_count, type_identifier_count,
           ruby_dispatch_count, scala_trait_count, cpp_template_metadata_count, is_complete
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, 1)",
        params![
            oid,
            lang,
            blob.contains_tests,
            blob.content_package,
            usize_to_i64(blob.units.len())?,
            usize_to_i64(blob.ranges.len())?,
            usize_to_i64(blob.signatures.len())?,
            usize_to_i64(blob.signature_metadata.len())?,
            usize_to_i64(blob.supertypes.len())?,
            usize_to_i64(blob.children.len())?,
            usize_to_i64(blob.import_statements.len())?,
            usize_to_i64(blob.imports.len())?,
            usize_to_i64(blob.type_identifiers.len())?,
            usize_to_i64(blob.ruby_dispatch_modes.len())?,
            usize_to_i64(blob.scala_traits.len())?,
            usize_to_i64(blob.cpp_template_metadata.len())?,
        ],
    )?;
    let integrity_sql = format!(
        "SELECT 1 FROM blob_meta AS meta
         WHERE meta.blob_oid = ?1 AND meta.lang = ?2
           AND {PARSED_BLOB_INTEGRITY_CONDITION}"
    );
    let complete = tx
        .query_row(&integrity_sql, params![oid, lang], |_| Ok(()))
        .optional()?
        .is_some();
    if !complete {
        return Err(StoreError::new(format!(
            "prepared blob {oid}/{lang} failed post-write integrity validation"
        )));
    }
    insert_blob_payload_cost_tx(tx, oid, lang, blob.persisted_payload_bytes())?;
    Ok(())
}

fn write_parsed_blob_tx<A: LanguageAdapter>(
    tx: &Transaction<'_>,
    oid: Oid,
    lang: &str,
    generation: GenerationId,
    adapter: &A,
    state: &FileState,
) -> Result<()> {
    let oid = oid.to_string();
    tx.execute(
        "DELETE FROM blobs WHERE blob_oid = ?1 AND lang = ?2",
        params![oid, lang],
    )?;
    tx.execute(
        "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, ?2, ?3)",
        params![oid, lang, generation.0],
    )?;

    let units = collect_stored_units(adapter, state);
    let unit_keys: HashMap<CodeUnit, i64> = units
        .iter()
        .map(|unit| (unit.unit.clone(), unit.key))
        .collect();

    {
        let mut stmt = tx.prepare(
            "INSERT OR IGNORE INTO code_units(
               blob_oid, lang, unit_key, kind, short_name, identifier, content_qualifier,
               exact_fqn, normalized_fqn, simple_type_name,
               signature, synthetic, is_type_alias, top_level_ordinal,
               in_declarations, in_definition_lookup, in_test_region, fq_segments
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
        )?;
        for stored in &units {
            let content_qualifier =
                adapter.storage_content_qualifier(&stored.unit, &state.content_qualifier);
            let fq_segments = encode_unit_fq_segments(adapter, &stored.unit, &content_qualifier);
            let persist_lookup_keys = adapter.persist_content_stable_lookup_keys();
            let exact_fqn = persist_lookup_keys.then(|| stored.unit.fq_name());
            let normalized_fqn = exact_fqn
                .as_deref()
                .map(|fqn| adapter.normalize_full_name(fqn));
            let simple_type_name = (persist_lookup_keys && stored.unit.is_class())
                .then(|| adapter.simple_type_name(&stored.unit));
            stmt.execute(params![
                oid,
                lang,
                stored.key,
                code_unit_kind_to_i64(stored.unit.kind()),
                stored.unit.short_name(),
                stored.unit.identifier(),
                content_qualifier,
                exact_fqn,
                normalized_fqn,
                simple_type_name,
                stored.unit.signature(),
                bool_to_i64(stored.unit.is_synthetic()),
                bool_to_i64(stored.is_type_alias),
                stored.top_level_ordinal.map(usize_to_i64).transpose()?,
                bool_to_i64(stored.in_declarations),
                bool_to_i64(stored.in_definition_lookup),
                bool_to_i64(stored.in_test_region),
                fq_segments,
            ])?;
        }
    }

    let range_count = insert_unit_ranges(tx, &oid, lang, &unit_keys, &state.ranges)?;
    let signature_count = insert_unit_signatures(tx, &oid, lang, &unit_keys, &state.signatures)?;
    let signature_metadata_count =
        insert_unit_signature_metadata(tx, &oid, lang, &unit_keys, &state.signature_metadata)?;
    let cpp_template_metadata_count =
        insert_cpp_template_metadata(tx, &oid, lang, &unit_keys, &state.cpp_template_metadata)?;
    let supertype_count = insert_unit_supertypes(
        tx,
        &oid,
        lang,
        &unit_keys,
        &state.raw_supertypes,
        &state.supertype_lookup_paths,
    )?;
    let child_count = insert_unit_children(tx, &oid, lang, &unit_keys, &state.children)?;
    let ruby_dispatch_count = insert_ruby_method_dispatch_modes(
        tx,
        &oid,
        lang,
        &unit_keys,
        &state.ruby_method_dispatch_modes,
    )?;
    let scala_trait_count = insert_scala_traits(tx, &oid, lang, &unit_keys, &state.scala_traits)?;
    let (import_statement_count, import_count) = insert_imports(tx, &oid, lang, state)?;
    insert_scala_exports(tx, &oid, lang, &unit_keys, &state.scala_exports)?;
    insert_materialization_records(tx, &oid, lang, &unit_keys, &state.materialization_records)?;
    insert_rust_fact_rows(
        tx,
        &oid,
        lang,
        &RustFactRows::from_facts(&state.rust_usage_facts)?,
    )?;
    let side_counts = PersistedSideTableCounts {
        range_count,
        signature_count,
        signature_metadata_count,
        cpp_template_metadata_count,
        supertype_count,
        child_count,
        import_statement_count,
        import_count,
        type_identifier_count: state.type_identifiers.len(),
        ruby_dispatch_count,
        scala_trait_count,
    };
    insert_blob_meta(tx, &oid, lang, adapter, state, units.len(), side_counts)?;
    update_blob_payload_cost_tx(tx, &oid, lang)?;
    Ok(())
}

fn collect_stored_units<A: LanguageAdapter>(adapter: &A, state: &FileState) -> Vec<StoredUnit> {
    let mut candidates: HashSet<CodeUnit> = HashSet::default();
    candidates.extend(state.top_level_declarations.iter().cloned());
    candidates.extend(state.declarations.iter().cloned());
    candidates.extend(state.definition_lookup_units.iter().cloned());
    candidates.extend(state.raw_supertypes.keys().cloned());
    candidates.extend(state.signatures.keys().cloned());
    candidates.extend(state.signature_metadata.keys().cloned());
    candidates.extend(state.cpp_template_metadata.keys().cloned());
    candidates.extend(state.ranges.keys().cloned());
    candidates.extend(state.children.keys().cloned());
    candidates.extend(state.children.values().flatten().cloned());
    candidates.extend(state.type_aliases.iter().cloned());
    candidates.extend(state.ruby_method_dispatch_modes.keys().cloned());
    candidates.extend(state.scala_traits.iter().cloned());
    candidates.extend(state.scala_exports.keys().cloned());
    candidates.extend(
        state
            .materialization_records
            .iter()
            .filter_map(|record| record.split().0.cloned()),
    );

    let top_level_ordinals: HashMap<CodeUnit, usize> = state
        .top_level_declarations
        .iter()
        .enumerate()
        .filter(|(_, unit)| adapter.should_persist_code_unit(unit))
        .map(|(ordinal, unit)| (unit.clone(), ordinal))
        .collect();

    let mut units: Vec<_> = candidates
        .into_iter()
        .filter(|unit| adapter.should_persist_code_unit(unit))
        .map(|unit| {
            let top_level_ordinal = top_level_ordinals.get(&unit).copied();
            StoredUnit {
                key: 0,
                is_type_alias: state.type_aliases.contains(&unit),
                top_level_ordinal,
                in_declarations: state.declarations.contains(&unit),
                in_definition_lookup: state.definition_lookup_units.contains(&unit),
                in_test_region: state.test_region_units.contains(&unit),
                unit,
            }
        })
        .collect();

    units.sort_by(|left, right| {
        stored_unit_order_key(state, &left.unit).cmp(&stored_unit_order_key(state, &right.unit))
    });
    for (index, unit) in units.iter_mut().enumerate() {
        unit.key = index as i64;
    }
    units
}

fn stored_unit_order_key(
    state: &FileState,
    unit: &CodeUnit,
) -> (usize, String, String, i64, String, bool) {
    let first_range = state
        .ranges
        .get(unit)
        .and_then(|ranges| ranges.iter().map(|range| range.start_byte).min())
        .unwrap_or(usize::MAX);
    (
        first_range,
        unit.short_name().to_string(),
        unit.signature().unwrap_or("").to_string(),
        code_unit_kind_to_i64(unit.kind()),
        unit.package_name().to_string(),
        unit.is_synthetic(),
    )
}

fn insert_unit_ranges(
    tx: &Transaction<'_>,
    oid: &str,
    lang: &str,
    unit_keys: &HashMap<CodeUnit, i64>,
    ranges: &HashMap<CodeUnit, Vec<Range>>,
) -> Result<usize> {
    let mut stmt = tx.prepare(
        "INSERT OR IGNORE INTO unit_ranges(
           blob_oid, lang, unit_key, ordinal, start_byte, end_byte, start_line, end_line
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )?;
    let mut count = 0;
    for (unit, entries) in ranges {
        let Some(unit_key) = unit_keys.get(unit) else {
            continue;
        };
        for (ordinal, range) in entries.iter().enumerate() {
            stmt.execute(params![
                oid,
                lang,
                unit_key,
                usize_to_i64(ordinal)?,
                usize_to_i64(range.start_byte)?,
                usize_to_i64(range.end_byte)?,
                usize_to_i64(range.start_line)?,
                usize_to_i64(range.end_line)?,
            ])?;
            count += 1;
        }
    }
    Ok(count)
}

fn insert_unit_signatures(
    tx: &Transaction<'_>,
    oid: &str,
    lang: &str,
    unit_keys: &HashMap<CodeUnit, i64>,
    signatures: &HashMap<CodeUnit, Vec<String>>,
) -> Result<usize> {
    let mut stmt = tx.prepare(
        "INSERT OR IGNORE INTO unit_signatures(
           blob_oid, lang, unit_key, ordinal, text
         ) VALUES(?1, ?2, ?3, ?4, ?5)",
    )?;
    let mut count = 0;
    for (unit, entries) in signatures {
        let Some(unit_key) = unit_keys.get(unit) else {
            continue;
        };
        for (ordinal, signature) in entries.iter().enumerate() {
            stmt.execute(params![
                oid,
                lang,
                unit_key,
                usize_to_i64(ordinal)?,
                signature
            ])?;
            count += 1;
        }
    }
    Ok(count)
}

fn insert_unit_signature_metadata(
    tx: &Transaction<'_>,
    oid: &str,
    lang: &str,
    unit_keys: &HashMap<CodeUnit, i64>,
    metadata: &HashMap<CodeUnit, Vec<SignatureMetadata>>,
) -> Result<usize> {
    let mut stmt = tx.prepare(
        "INSERT OR IGNORE INTO unit_signature_metadata(
           blob_oid, lang, unit_key, ordinal, metadata
         ) VALUES(?1, ?2, ?3, ?4, ?5)",
    )?;
    let mut count = 0;
    for (unit, entries) in metadata {
        let Some(unit_key) = unit_keys.get(unit) else {
            continue;
        };
        for (ordinal, entry) in entries.iter().enumerate() {
            let entry = serialize_signature_metadata_blob(entry)?;
            stmt.execute(params![oid, lang, unit_key, usize_to_i64(ordinal)?, entry,])?;
            count += 1;
        }
    }
    Ok(count)
}

fn insert_cpp_template_metadata(
    tx: &Transaction<'_>,
    oid: &str,
    lang: &str,
    unit_keys: &HashMap<CodeUnit, i64>,
    metadata: &HashMap<CodeUnit, CppTemplateMetadata>,
) -> Result<usize> {
    let mut stmt = tx.prepare(
        "INSERT OR IGNORE INTO unit_cpp_template_metadata(
           blob_oid, lang, unit_key, metadata
         ) VALUES(?1, ?2, ?3, ?4)",
    )?;
    let mut count = 0;
    for (unit, entry) in metadata {
        let Some(unit_key) = unit_keys.get(unit) else {
            continue;
        };
        stmt.execute(params![oid, lang, unit_key, serialize_blob(entry)?])?;
        count += 1;
    }
    Ok(count)
}

fn insert_unit_supertypes(
    tx: &Transaction<'_>,
    oid: &str,
    lang: &str,
    unit_keys: &HashMap<CodeUnit, i64>,
    supertypes: &HashMap<CodeUnit, Vec<String>>,
    lookup_paths: &HashMap<CodeUnit, Vec<String>>,
) -> Result<usize> {
    let mut stmt = tx.prepare(
        "INSERT OR IGNORE INTO unit_supertypes(
           blob_oid, lang, unit_key, ordinal, raw, lookup_path
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    let mut count = 0;
    for (unit, entries) in supertypes {
        let Some(unit_key) = unit_keys.get(unit) else {
            continue;
        };
        for (ordinal, raw) in entries.iter().enumerate() {
            let lookup_path = lookup_paths
                .get(unit)
                .and_then(|paths| paths.get(ordinal))
                .map(String::as_str)
                .unwrap_or("");
            stmt.execute(params![
                oid,
                lang,
                unit_key,
                usize_to_i64(ordinal)?,
                raw,
                lookup_path
            ])?;
            count += 1;
        }
    }
    Ok(count)
}

fn insert_unit_children(
    tx: &Transaction<'_>,
    oid: &str,
    lang: &str,
    unit_keys: &HashMap<CodeUnit, i64>,
    children: &HashMap<CodeUnit, Vec<CodeUnit>>,
) -> Result<usize> {
    let mut stmt = tx.prepare(
        "INSERT OR IGNORE INTO unit_children(
           blob_oid, lang, parent_key, child_key, ordinal
         ) VALUES(?1, ?2, ?3, ?4, ?5)",
    )?;
    let mut count = 0;
    for (parent, entries) in children {
        let Some(parent_key) = unit_keys.get(parent) else {
            continue;
        };
        for (ordinal, child) in entries.iter().enumerate() {
            let Some(child_key) = unit_keys.get(child) else {
                continue;
            };
            stmt.execute(params![
                oid,
                lang,
                parent_key,
                child_key,
                usize_to_i64(ordinal)?,
            ])?;
            count += 1;
        }
    }
    Ok(count)
}

fn insert_ruby_method_dispatch_modes(
    tx: &Transaction<'_>,
    oid: &str,
    lang: &str,
    unit_keys: &HashMap<CodeUnit, i64>,
    dispatch_modes: &HashMap<CodeUnit, RubyMethodDispatchMode>,
) -> Result<usize> {
    let mut stmt = tx.prepare(
        "INSERT OR IGNORE INTO ruby_method_dispatch_modes(
           blob_oid, lang, unit_key, mode
         ) VALUES(?1, ?2, ?3, ?4)",
    )?;
    let mut count = 0;
    for (unit, mode) in dispatch_modes {
        let Some(unit_key) = unit_keys.get(unit) else {
            continue;
        };
        stmt.execute(params![
            oid,
            lang,
            unit_key,
            ruby_dispatch_mode_to_i64(*mode)
        ])?;
        count += 1;
    }
    Ok(count)
}

fn insert_scala_traits(
    tx: &Transaction<'_>,
    oid: &str,
    lang: &str,
    unit_keys: &HashMap<CodeUnit, i64>,
    traits: &HashSet<CodeUnit>,
) -> Result<usize> {
    let mut stmt = tx.prepare(
        "INSERT OR IGNORE INTO scala_traits(
           blob_oid, lang, unit_key
         ) VALUES(?1, ?2, ?3)",
    )?;
    let mut count = 0;
    for unit in traits {
        let Some(unit_key) = unit_keys.get(unit) else {
            continue;
        };
        stmt.execute(params![oid, lang, unit_key])?;
        count += 1;
    }
    Ok(count)
}

fn insert_imports(
    tx: &Transaction<'_>,
    oid: &str,
    lang: &str,
    state: &FileState,
) -> Result<(usize, usize)> {
    let mut stmt = tx.prepare(
        "INSERT OR IGNORE INTO import_statements(
           blob_oid, lang, ordinal, statement
         ) VALUES(?1, ?2, ?3, ?4)",
    )?;
    let mut statement_count = 0;
    for (ordinal, statement) in state.import_statements.iter().enumerate() {
        stmt.execute(params![oid, lang, usize_to_i64(ordinal)?, statement])?;
        statement_count += 1;
    }
    drop(stmt);
    let mut stmt = tx.prepare(
        "INSERT OR IGNORE INTO import_details(
           blob_oid, lang, ordinal, info
         ) VALUES(?1, ?2, ?3, ?4)",
    )?;
    let mut import_count = 0;
    for (ordinal, import) in state.imports.iter().enumerate() {
        stmt.execute(params![
            oid,
            lang,
            usize_to_i64(ordinal)?,
            serialize_blob(import)?,
        ])?;
        import_count += 1;
    }
    Ok((statement_count, import_count))
}

fn insert_scala_exports(
    tx: &Transaction<'_>,
    oid: &str,
    lang: &str,
    unit_keys: &HashMap<CodeUnit, i64>,
    exports: &HashMap<CodeUnit, Vec<crate::analyzer::scala::ScalaExportInfo>>,
) -> Result<usize> {
    let mut stmt = tx.prepare(
        "INSERT OR IGNORE INTO scala_exports(
           blob_oid, lang, owner_key, ordinal, info
         ) VALUES(?1, ?2, ?3, ?4, ?5)",
    )?;
    let mut count = 0;
    for (owner, entries) in exports {
        let Some(owner_key) = unit_keys.get(owner) else {
            continue;
        };
        for (ordinal, info) in entries.iter().enumerate() {
            stmt.execute(params![
                oid,
                lang,
                owner_key,
                usize_to_i64(ordinal)?,
                serialize_blob(info)?,
            ])?;
            count += 1;
        }
    }
    Ok(count)
}

fn insert_blob_meta<A: LanguageAdapter>(
    tx: &Transaction<'_>,
    oid: &str,
    lang: &str,
    adapter: &A,
    state: &FileState,
    stored_unit_count: usize,
    side_counts: PersistedSideTableCounts,
) -> Result<()> {
    tx.execute(
        "INSERT OR IGNORE INTO blob_meta(
           blob_oid, lang, contains_tests, content_package, stored_unit_count,
           range_count, signature_count, signature_metadata_count, supertype_count,
           child_count, import_statement_count, import_count, type_identifier_count,
           ruby_dispatch_count, scala_trait_count, cpp_template_metadata_count, is_complete
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
        params![
            oid,
            lang,
            bool_to_i64(adapter.storage_contains_tests(state)),
            adapter.storage_file_content_qualifier(&state.content_qualifier),
            usize_to_i64(stored_unit_count)?,
            usize_to_i64(side_counts.range_count)?,
            usize_to_i64(side_counts.signature_count)?,
            usize_to_i64(side_counts.signature_metadata_count)?,
            usize_to_i64(side_counts.supertype_count)?,
            usize_to_i64(side_counts.child_count)?,
            usize_to_i64(side_counts.import_statement_count)?,
            usize_to_i64(side_counts.import_count)?,
            usize_to_i64(side_counts.type_identifier_count)?,
            usize_to_i64(side_counts.ruby_dispatch_count)?,
            usize_to_i64(side_counts.scala_trait_count)?,
            usize_to_i64(side_counts.cpp_template_metadata_count)?,
            1,
        ],
    )?;
    let mut type_identifiers: Vec<_> = state.type_identifiers.iter().collect();
    type_identifiers.sort();
    let mut stmt = tx.prepare(
        "INSERT OR IGNORE INTO type_identifiers(
           blob_oid, lang, type_identifier
         ) VALUES(?1, ?2, ?3)",
    )?;
    for identifier in type_identifiers {
        stmt.execute(params![oid, lang, identifier])?;
    }
    Ok(())
}

#[derive(Debug)]
struct UnitRow {
    key: i64,
    unit: CodeUnit,
    is_type_alias: bool,
    top_level_ordinal: Option<usize>,
    in_declarations: bool,
    in_definition_lookup: bool,
    in_test_region: bool,
}

#[derive(Debug, Clone)]
struct RawUnitRow {
    key: i64,
    kind: CodeUnitType,
    content_qualifier: String,
    signature: Option<String>,
    synthetic: bool,
    is_type_alias: bool,
    top_level_ordinal: Option<usize>,
    in_declarations: bool,
    in_definition_lookup: bool,
    in_test_region: bool,
    /// Serialized `FqName` segments (see `FqName::decode_segments`); `None` for
    /// rows written before the segments column existed.
    fq_segments: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct BlobMetaRow {
    contains_tests: bool,
    content_package: String,
    raw_content_package: String,
    type_identifiers: HashSet<String>,
    stored_unit_count: usize,
    side_counts: PersistedSideTableCounts,
}

#[derive(Debug, Clone, Copy)]
struct SummaryProjectionMeta {
    stored_unit_count: usize,
    range_count: usize,
    signature_count: usize,
    child_count: usize,
}

#[derive(Debug, Clone, Copy)]
struct RawSideTableCounts {
    range_count: i64,
    signature_count: i64,
    signature_metadata_count: i64,
    supertype_count: i64,
    child_count: i64,
    import_statement_count: i64,
    import_count: i64,
    type_identifier_count: i64,
    ruby_dispatch_count: i64,
    scala_trait_count: i64,
    cpp_template_metadata_count: i64,
}

type BlobMetaRows = HashMap<String, BlobMetaRow>;
type SignatureMetadataRow = (i64, Vec<u8>);
type SignatureMetadataRows = HashMap<String, Vec<SignatureMetadataRow>>;
type CppTemplateMetadataRows = HashMap<String, Vec<SignatureMetadataRow>>;
type ScalaExportRows = HashMap<String, Vec<(i64, Vec<u8>)>>;
type MaterializationRecordRows = HashMap<String, Vec<(Option<i64>, Vec<u8>)>>;
type RangeRow = (i64, i64, i64, i64, i64);
type RangeRows = HashMap<String, Vec<RangeRow>>;
type RubyDispatchRows = HashMap<String, Vec<(i64, i64)>>;
type ScalaTraitRows = HashMap<String, Vec<i64>>;

fn hydrate_file_state_conn<A: LanguageAdapter>(
    conn: &Connection,
    oid: Oid,
    lang: &str,
    adapter: &A,
    file: &ProjectFile,
    source: &str,
) -> Result<Option<FileState>> {
    let oid = oid.to_string();
    let meta = read_blob_meta(conn, &oid, lang, adapter, file, source)?;
    let Some(meta) = meta else {
        return Ok(None);
    };

    let rows = read_unit_rows(conn, &oid, lang, adapter, file)?;
    if rows.len() != meta.stored_unit_count {
        return Ok(None);
    }
    let mut by_key = HashMap::default();
    for row in rows {
        by_key.insert(row.key, row);
    }

    let mut top_level: Vec<_> = by_key
        .values()
        .filter_map(|row| {
            row.top_level_ordinal
                .map(|ordinal| (ordinal, row.unit.clone()))
        })
        .collect();
    top_level.sort_by_key(|(ordinal, _)| *ordinal);

    let mut declarations = set_with_capacity(by_key.len());
    let mut definition_lookup_units = HashSet::default();
    let mut type_aliases = HashSet::default();
    let mut test_region_units = HashSet::default();
    for row in by_key.values() {
        if row.in_declarations {
            declarations.insert(row.unit.clone());
        }
        if row.in_definition_lookup {
            definition_lookup_units.insert(row.unit.clone());
        }
        if row.is_type_alias {
            type_aliases.insert(row.unit.clone());
        }
        if row.in_test_region {
            test_region_units.insert(row.unit.clone());
        }
    }

    let children = read_children(conn, &oid, lang, &by_key)?;
    let raw_supertypes = read_unit_string_vec(conn, &oid, lang, "unit_supertypes", "raw", &by_key)?;
    let supertype_lookup_paths =
        read_unit_string_vec(conn, &oid, lang, "unit_supertypes", "lookup_path", &by_key)?;
    let ruby_method_dispatch_modes = read_ruby_method_dispatch_modes(conn, &oid, lang, &by_key)?;
    let scala_traits = read_scala_traits(conn, &oid, lang, &by_key)?;
    let import_statements = read_import_statements(conn, &oid, lang)?;
    let imports = read_import_infos(conn, &oid, lang)?;
    let scala_exports = read_scala_exports(conn, &oid, lang, &by_key)?;
    let materialization_records = read_materialization_records(conn, &oid, lang, &by_key)?;
    let signatures = read_unit_string_vec(conn, &oid, lang, "unit_signatures", "text", &by_key)?;
    let signature_metadata = read_signature_metadata(conn, &oid, lang, &by_key)?;
    let cpp_template_metadata = read_cpp_template_metadata(conn, &oid, lang, &by_key)?;
    let ranges = read_ranges(conn, &oid, lang, &by_key)?;

    let actual_counts = side_table_counts_from_hydrated_parts(HydratedSideTableParts {
        ranges: &ranges,
        signatures: &signatures,
        signature_metadata: &signature_metadata,
        cpp_template_metadata: &cpp_template_metadata,
        raw_supertypes: &raw_supertypes,
        children: &children,
        import_statement_count: import_statements.len(),
        import_count: imports.len(),
        type_identifier_count: meta.type_identifiers.len(),
        ruby_dispatch_count: ruby_method_dispatch_modes.len(),
        scala_trait_count: scala_traits.len(),
    });
    if actual_counts != meta.side_counts {
        return Ok(None);
    }

    let mut state = FileState {
        source: String::new(),
        package_name: meta.content_package,
        content_qualifier: meta.raw_content_package,
        top_level_declarations: top_level.into_iter().map(|(_, unit)| unit).collect(),
        declarations,
        definition_lookup_units,
        import_statements,
        imports,
        scala_exports,
        // Not hydrated: the Rust fact tables are read by blob oid straight from
        // SQL, never through a materialized `FileState`. See the field's doc.
        rust_usage_facts: RustUsageFacts::default(),
        raw_supertypes,
        supertype_lookup_paths,
        type_identifiers: meta.type_identifiers,
        signatures,
        signature_metadata,
        cpp_template_metadata,
        ranges,
        children,
        type_aliases,
        ruby_method_dispatch_modes,
        scala_traits,
        contains_tests: meta.contains_tests,
        test_region_units,
        materialization_records,
        parse_errors: None,
    };

    adapter.synthesize_hydrated_units(file, source, &mut state);
    synthesize_file_scope(file, source, &mut state);
    Ok(Some(state))
}

fn summary_file_projection_conn<A: LanguageAdapter>(
    conn: &Connection,
    oid: Oid,
    lang: &str,
    adapter: &A,
    file: &ProjectFile,
) -> Result<Option<SummaryFileProjection>> {
    let oid = oid.to_string();
    let Some(meta) = read_summary_projection_meta(conn, &oid, lang)? else {
        return Ok(None);
    };

    let rows = read_unit_rows(conn, &oid, lang, adapter, file)?;
    if rows.len() != meta.stored_unit_count {
        return Ok(None);
    }
    let mut by_key = HashMap::default();
    for row in rows {
        by_key.insert(row.key, row);
    }

    let mut top_level: Vec<_> = by_key
        .values()
        .filter_map(|row| {
            row.top_level_ordinal
                .map(|ordinal| (ordinal, row.unit.clone()))
        })
        .collect();
    top_level.sort_by_key(|(ordinal, _)| *ordinal);

    let signatures = read_unit_string_vec(conn, &oid, lang, "unit_signatures", "text", &by_key)?;
    let ranges = read_ranges(conn, &oid, lang, &by_key)?;
    let children = read_children(conn, &oid, lang, &by_key)?;
    if count_vec_entries(&signatures) != meta.signature_count
        || count_vec_entries(&ranges) != meta.range_count
        || count_vec_entries(&children) != meta.child_count
    {
        return Ok(None);
    }

    Ok(Some(SummaryFileProjection {
        top_level_declarations: top_level.into_iter().map(|(_, unit)| unit).collect(),
        signatures,
        ranges,
        children,
    }))
}

fn hydrate_file_states_conn<A: LanguageAdapter>(
    conn: &Connection,
    entries: &[(ProjectFile, Oid)],
    lang: &str,
    adapter: &A,
    source_by_file: &HashMap<ProjectFile, String>,
) -> Result<HashMap<ProjectFile, FileState>> {
    if entries.is_empty() {
        return Ok(HashMap::default());
    }

    let oids = unique_oid_strings(entries);
    let meta_by_oid = read_blob_meta_bulk(conn, lang, &oids)?;
    let unit_rows_by_oid = read_unit_rows_bulk(conn, lang, &oids)?;
    let children_by_oid = read_children_bulk(conn, lang, &oids)?;
    let supertypes_by_oid = read_unit_string_vec_bulk(conn, lang, "unit_supertypes", "raw", &oids)?;
    let supertype_lookup_paths_by_oid =
        read_unit_string_vec_bulk(conn, lang, "unit_supertypes", "lookup_path", &oids)?;
    let signatures_by_oid =
        read_unit_string_vec_bulk(conn, lang, "unit_signatures", "text", &oids)?;
    let signature_metadata_by_oid = read_signature_metadata_bulk(conn, lang, &oids)?;
    let cpp_template_metadata_by_oid = read_cpp_template_metadata_bulk(conn, lang, &oids)?;
    let ranges_by_oid = read_ranges_bulk(conn, lang, &oids)?;
    let ruby_dispatch_by_oid = read_ruby_method_dispatch_modes_bulk(conn, lang, &oids)?;
    let scala_traits_by_oid = read_scala_traits_bulk(conn, lang, &oids)?;
    let import_statements_by_oid = read_import_statements_bulk(conn, lang, &oids)?;
    let import_infos_by_oid = read_import_infos_bulk(conn, lang, &oids)?;
    let scala_exports_by_oid = read_scala_exports_bulk(conn, lang, &oids)?;
    let materialization_records_by_oid = read_materialization_records_bulk(conn, lang, &oids)?;

    let mut out = HashMap::default();
    for (file, oid) in entries {
        let oid_text = oid.to_string();
        let Some(meta) = meta_by_oid.get(&oid_text) else {
            continue;
        };
        let source = source_by_file.get(file).map(String::as_str);
        let source_text = source.unwrap_or("");
        let raw_units = unit_rows_by_oid.get(&oid_text).cloned().unwrap_or_default();
        if raw_units.len() != meta.stored_unit_count {
            continue;
        }
        let mut by_key = HashMap::default();
        for raw in raw_units {
            let (fq, package_segment_count) = hydrate_unit_fq(
                adapter,
                raw.fq_segments.as_deref(),
                &raw.content_qualifier,
                file,
            )?;
            let unit = CodeUnit::from_fq(
                file.clone(),
                raw.kind,
                fq,
                package_segment_count,
                raw.signature,
                raw.synthetic,
            );
            by_key.insert(
                raw.key,
                UnitRow {
                    key: raw.key,
                    unit,
                    is_type_alias: raw.is_type_alias,
                    top_level_ordinal: raw.top_level_ordinal,
                    in_declarations: raw.in_declarations,
                    in_definition_lookup: raw.in_definition_lookup,
                    in_test_region: raw.in_test_region,
                },
            );
        }

        let mut top_level: Vec<_> = by_key
            .values()
            .filter_map(|row| {
                row.top_level_ordinal
                    .map(|ordinal| (ordinal, row.unit.clone()))
            })
            .collect();
        top_level.sort_by_key(|(ordinal, _)| *ordinal);

        let mut declarations = set_with_capacity(by_key.len());
        let mut definition_lookup_units = HashSet::default();
        let mut type_aliases = HashSet::default();
        let mut test_region_units = HashSet::default();
        for row in by_key.values() {
            if row.in_declarations {
                declarations.insert(row.unit.clone());
            }
            if row.in_definition_lookup {
                definition_lookup_units.insert(row.unit.clone());
            }
            if row.is_type_alias {
                type_aliases.insert(row.unit.clone());
            }
            if row.in_test_region {
                test_region_units.insert(row.unit.clone());
            }
        }

        let ruby_method_dispatch_modes =
            ruby_dispatch_map_for_file(ruby_dispatch_by_oid.get(&oid_text), &by_key)?;
        let scala_traits = scala_traits_for_file(scala_traits_by_oid.get(&oid_text), &by_key);
        let import_statements = import_statements_by_oid
            .get(&oid_text)
            .cloned()
            .unwrap_or_default();
        let imports = import_infos_by_oid
            .get(&oid_text)
            .cloned()
            .unwrap_or_default();
        let scala_exports =
            scala_exports_map_for_file(scala_exports_by_oid.get(&oid_text), &by_key)?;
        let materialization_records = materialization_records_for_file(
            materialization_records_by_oid.get(&oid_text),
            &by_key,
        )?;
        let raw_supertypes = unit_string_map_for_file(supertypes_by_oid.get(&oid_text), &by_key);
        let supertype_lookup_paths =
            unit_string_map_for_file(supertype_lookup_paths_by_oid.get(&oid_text), &by_key);
        let signatures = unit_string_map_for_file(signatures_by_oid.get(&oid_text), &by_key);
        let signature_metadata =
            signature_metadata_map_for_file(signature_metadata_by_oid.get(&oid_text), &by_key)?;
        let cpp_template_metadata = cpp_template_metadata_map_for_file(
            cpp_template_metadata_by_oid.get(&oid_text),
            &by_key,
        )?;
        let ranges = ranges_map_for_file(ranges_by_oid.get(&oid_text), &by_key)?;
        let children = children_map_for_file(children_by_oid.get(&oid_text), &by_key);

        let actual_counts = side_table_counts_from_hydrated_parts(HydratedSideTableParts {
            ranges: &ranges,
            signatures: &signatures,
            signature_metadata: &signature_metadata,
            cpp_template_metadata: &cpp_template_metadata,
            raw_supertypes: &raw_supertypes,
            children: &children,
            import_statement_count: import_statements.len(),
            import_count: imports.len(),
            type_identifier_count: meta.type_identifiers.len(),
            ruby_dispatch_count: ruby_method_dispatch_modes.len(),
            scala_trait_count: scala_traits.len(),
        });
        if actual_counts != meta.side_counts {
            continue;
        }

        let mut state = FileState {
            source: source.unwrap_or("").to_string(),
            package_name: adapter.hydrate_content_qualifier(&meta.content_package, file),
            content_qualifier: meta.content_package.clone(),
            top_level_declarations: top_level.into_iter().map(|(_, unit)| unit).collect(),
            declarations,
            definition_lookup_units,
            import_statements,
            imports,
            scala_exports,
            rust_usage_facts: RustUsageFacts::default(),
            raw_supertypes,
            supertype_lookup_paths,
            type_identifiers: meta.type_identifiers.clone(),
            signatures,
            signature_metadata,
            cpp_template_metadata,
            ranges,
            children,
            type_aliases,
            ruby_method_dispatch_modes,
            scala_traits,
            contains_tests: adapter.hydrate_contains_tests(meta.contains_tests, file, source_text),
            test_region_units,
            materialization_records,
            parse_errors: None,
        };

        if let Some(source) = source {
            adapter.synthesize_hydrated_units(file, source, &mut state);
            synthesize_file_scope(file, source, &mut state);
        }
        out.insert(file.clone(), state);
    }

    Ok(out)
}

fn read_blob_meta<A: LanguageAdapter>(
    conn: &Connection,
    oid: &str,
    lang: &str,
    adapter: &A,
    file: &ProjectFile,
    source: &str,
) -> Result<Option<BlobMetaRow>> {
    let row: Option<(i64, String, i64, RawSideTableCounts)> = conn
        .query_row(
            &format!(
                "SELECT contains_tests, content_package, stored_unit_count,
                    range_count, signature_count, signature_metadata_count, supertype_count,
                    child_count, import_statement_count, import_count, type_identifier_count,
                    ruby_dispatch_count, scala_trait_count, cpp_template_metadata_count
             FROM blob_meta AS meta
             WHERE blob_oid = ?1 AND lang = ?2
               AND {PARSED_BLOB_COMPLETE_CONDITION}"
            ),
            params![oid, lang],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    raw_side_table_counts_from_row(row, 3)?,
                ))
            },
        )
        .optional()?;
    let Some((contains_tests, content_package, stored_unit_count, raw_side_counts)) = row else {
        return Ok(None);
    };
    let type_identifiers = read_type_identifiers(conn, oid, lang)?;
    Ok(Some(BlobMetaRow {
        contains_tests: adapter.hydrate_contains_tests(contains_tests != 0, file, source),
        content_package: adapter.hydrate_content_qualifier(&content_package, file),
        raw_content_package: content_package,
        type_identifiers,
        stored_unit_count: i64_to_usize(stored_unit_count)?,
        side_counts: side_table_counts_from_raw(raw_side_counts)?,
    }))
}

fn read_summary_projection_meta(
    conn: &Connection,
    oid: &str,
    lang: &str,
) -> Result<Option<SummaryProjectionMeta>> {
    let sql = format!(
        "SELECT stored_unit_count, range_count, signature_count, child_count
         FROM blob_meta AS meta
         WHERE meta.blob_oid = ?1 AND meta.lang = ?2
           AND {PARSED_BLOB_COMPLETE_CONDITION}"
    );
    let row: Option<(i64, i64, i64, i64)> = conn
        .query_row(&sql, params![oid, lang], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .optional()?;
    row.map(
        |(stored_unit_count, range_count, signature_count, child_count)| {
            Ok(SummaryProjectionMeta {
                stored_unit_count: i64_to_usize(stored_unit_count)?,
                range_count: i64_to_usize(range_count)?,
                signature_count: i64_to_usize(signature_count)?,
                child_count: i64_to_usize(child_count)?,
            })
        },
    )
    .transpose()
}

fn read_type_identifiers(conn: &Connection, oid: &str, lang: &str) -> Result<HashSet<String>> {
    let mut stmt = conn.prepare(
        "SELECT type_identifier FROM type_identifiers
         WHERE blob_oid = ?1 AND lang = ?2",
    )?;
    let rows = stmt.query_map(params![oid, lang], |row| row.get::<_, String>(0))?;
    let mut out = HashSet::default();
    for row in rows {
        out.insert(row?);
    }
    Ok(out)
}

fn raw_side_table_counts_from_row(
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> rusqlite::Result<RawSideTableCounts> {
    Ok(RawSideTableCounts {
        range_count: row.get(offset)?,
        signature_count: row.get(offset + 1)?,
        signature_metadata_count: row.get(offset + 2)?,
        supertype_count: row.get(offset + 3)?,
        child_count: row.get(offset + 4)?,
        import_statement_count: row.get(offset + 5)?,
        import_count: row.get(offset + 6)?,
        type_identifier_count: row.get(offset + 7)?,
        ruby_dispatch_count: row.get(offset + 8)?,
        scala_trait_count: row.get(offset + 9)?,
        cpp_template_metadata_count: row.get(offset + 10)?,
    })
}

fn side_table_counts_from_raw(raw: RawSideTableCounts) -> Result<PersistedSideTableCounts> {
    Ok(PersistedSideTableCounts {
        range_count: i64_to_usize(raw.range_count)?,
        signature_count: i64_to_usize(raw.signature_count)?,
        signature_metadata_count: i64_to_usize(raw.signature_metadata_count)?,
        supertype_count: i64_to_usize(raw.supertype_count)?,
        child_count: i64_to_usize(raw.child_count)?,
        import_statement_count: i64_to_usize(raw.import_statement_count)?,
        import_count: i64_to_usize(raw.import_count)?,
        type_identifier_count: i64_to_usize(raw.type_identifier_count)?,
        ruby_dispatch_count: i64_to_usize(raw.ruby_dispatch_count)?,
        scala_trait_count: i64_to_usize(raw.scala_trait_count)?,
        cpp_template_metadata_count: i64_to_usize(raw.cpp_template_metadata_count)?,
    })
}

fn unique_oid_strings(entries: &[(ProjectFile, Oid)]) -> Vec<String> {
    let mut seen = HashSet::default();
    let mut out = Vec::new();
    for (_, oid) in entries {
        let oid = oid.to_string();
        if seen.insert(oid.clone()) {
            out.push(oid);
        }
    }
    out
}

/// Fixed arities the variable-length `IN (…)` chunk queries are padded up to.
/// Every `chunks(900)` bulk reader lands on one of these four SQL shapes
/// instead of up to 900 distinct ones, so `prepare_cached` (64 slots) actually
/// caches them. `900` is the top because the callers chunk at 900.
const IN_CHUNK_ARITY_LADDER: [usize; 4] = [16, 64, 256, 900];

fn padded_in_arity(len: usize) -> usize {
    IN_CHUNK_ARITY_LADDER
        .iter()
        .copied()
        .find(|&arity| arity >= len)
        .unwrap_or(IN_CHUNK_ARITY_LADDER[IN_CHUNK_ARITY_LADDER.len() - 1])
}

/// Parameters for a chunked `IN (…)` query, padded to the next fixed arity with
/// `NULL`s. `NULL` never matches `IN`, so the padding is semantics-preserving:
/// `x IN (a, b, NULL)` returns exactly what `x IN (a, b)` returns for the
/// non-null `blob_oid`s we query.
fn chunk_params(lang: &str, chunk: &[String]) -> Vec<Option<String>> {
    let arity = padded_in_arity(chunk.len());
    let mut params = Vec::with_capacity(arity + 1);
    params.push(Some(lang.to_string()));
    params.extend(chunk.iter().cloned().map(Some));
    params.resize(arity + 1, None);
    params
}

fn chunk_placeholders(chunk: &[String]) -> String {
    let arity = padded_in_arity(chunk.len());
    std::iter::repeat_n("?", arity)
        .collect::<Vec<_>>()
        .join(",")
}

fn read_blob_meta_bulk(conn: &Connection, lang: &str, oids: &[String]) -> Result<BlobMetaRows> {
    let mut out = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT meta.blob_oid, contains_tests, content_package, stored_unit_count,
                    range_count, signature_count, signature_metadata_count, supertype_count,
                    child_count, import_statement_count, import_count, type_identifier_count,
                    ruby_dispatch_count, scala_trait_count, cpp_template_metadata_count
             FROM blob_meta AS meta
             WHERE meta.lang = ? AND meta.blob_oid IN ({placeholders})
               AND {PARSED_BLOB_COMPLETE_CONDITION}
             ORDER BY meta.blob_oid"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                raw_side_table_counts_from_row(row, 4)?,
            ))
        })?;
        for row in rows {
            let (oid, contains_tests, content_package, stored_unit_count, raw_side_counts) = row?;
            out.insert(
                oid,
                BlobMetaRow {
                    contains_tests: contains_tests != 0,
                    raw_content_package: content_package.clone(),
                    content_package,
                    type_identifiers: HashSet::default(),
                    stored_unit_count: i64_to_usize(stored_unit_count)?,
                    side_counts: side_table_counts_from_raw(raw_side_counts)?,
                },
            );
        }
    }

    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT blob_oid, type_identifier
             FROM type_identifiers
             WHERE lang = ? AND blob_oid IN ({placeholders})
             ORDER BY blob_oid, type_identifier"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (oid, identifier) = row?;
            if let Some(meta) = out.get_mut(&oid) {
                meta.type_identifiers.insert(identifier);
            }
        }
    }
    Ok(out)
}

fn read_content_packages_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<HashMap<String, String>> {
    let mut out = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT meta.blob_oid, meta.content_package
             FROM blob_meta AS meta
             WHERE meta.lang = ? AND meta.blob_oid IN ({placeholders})
               AND {PARSED_BLOB_COMPLETE_CONDITION}
             ORDER BY meta.blob_oid"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (oid, package_name) = row?;
            out.insert(oid, package_name);
        }
    }
    Ok(out)
}

fn read_unit_rows_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<HashMap<String, Vec<RawUnitRow>>> {
    let mut out: HashMap<String, Vec<RawUnitRow>> = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT blob_oid, unit_key, kind, content_qualifier, signature, synthetic,
                    is_type_alias, top_level_ordinal, in_declarations, in_definition_lookup,
                    in_test_region, fq_segments
             FROM code_units
             WHERE lang = ? AND blob_oid IN ({placeholders})
             ORDER BY blob_oid, unit_key"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            let kind_raw = row.get::<_, i64>(2)?;
            let kind = code_unit_kind_from_i64(kind_raw).map_err(|err| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Integer,
                    Box::new(err),
                )
            })?;
            Ok((
                row.get::<_, String>(0)?,
                RawUnitRow {
                    key: row.get(1)?,
                    kind,
                    content_qualifier: row.get(3)?,
                    signature: row.get(4)?,
                    synthetic: row.get::<_, i64>(5)? != 0,
                    is_type_alias: row.get::<_, i64>(6)? != 0,
                    top_level_ordinal: row
                        .get::<_, Option<i64>>(7)?
                        .and_then(|value| usize::try_from(value).ok()),
                    in_declarations: row.get::<_, i64>(8)? != 0,
                    in_definition_lookup: row.get::<_, i64>(9)? != 0,
                    in_test_region: row.get::<_, i64>(10)? != 0,
                    fq_segments: row.get::<_, Option<Vec<u8>>>(11)?,
                },
            ))
        })?;
        for row in rows {
            let (oid, raw) = row?;
            out.entry(oid).or_default().push(raw);
        }
    }
    Ok(out)
}

fn read_import_statements_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<HashMap<String, Vec<String>>> {
    let mut out: HashMap<String, Vec<String>> = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT blob_oid, statement FROM import_statements
             WHERE lang = ? AND blob_oid IN ({placeholders})
             ORDER BY blob_oid, ordinal"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (oid, statement) = row?;
            out.entry(oid).or_default().push(statement);
        }
    }
    Ok(out)
}

fn read_import_infos_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<HashMap<String, Vec<ImportInfo>>> {
    let mut out: HashMap<String, Vec<ImportInfo>> = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT imports.blob_oid, imports.info
             FROM import_details AS imports
             JOIN blob_meta AS meta
               ON meta.blob_oid = imports.blob_oid AND meta.lang = imports.lang
             WHERE imports.lang = ? AND imports.blob_oid IN ({placeholders})
               AND {PARSED_BLOB_COMPLETE_CONDITION}
             ORDER BY imports.blob_oid, imports.ordinal"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        for row in rows {
            let (oid, bytes) = row?;
            out.entry(oid).or_default().push(deserialize_blob(&bytes)?);
        }
    }
    Ok(out)
}

fn read_scala_exports_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<ScalaExportRows> {
    let mut out: ScalaExportRows = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT blob_oid, owner_key, info FROM scala_exports
             WHERE lang = ? AND blob_oid IN ({placeholders})
             ORDER BY blob_oid, owner_key, ordinal"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        for row in rows {
            let (oid, owner_key, info) = row?;
            out.entry(oid).or_default().push((owner_key, info));
        }
    }
    Ok(out)
}

fn read_materialization_records_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<MaterializationRecordRows> {
    let mut out: MaterializationRecordRows = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT blob_oid, unit_key, payload FROM materialization_records
             WHERE lang = ? AND blob_oid IN ({placeholders})
             ORDER BY blob_oid, ordinal"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        for row in rows {
            let (oid, unit_key, payload) = row?;
            out.entry(oid).or_default().push((unit_key, payload));
        }
    }
    Ok(out)
}

fn materialization_records_for_file(
    rows: Option<&Vec<(Option<i64>, Vec<u8>)>>,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<Vec<MaterializationRecord>> {
    let mut out = Vec::new();
    for (unit_key, payload) in rows.into_iter().flatten() {
        let payload: MaterializationRecordPayload = deserialize_blob(payload)?;
        let unit = unit_key
            .and_then(|key| by_key.get(&key))
            .map(|row| row.unit.clone());
        if let Some(record) = MaterializationRecord::join(payload, unit) {
            out.push(record);
        }
    }
    Ok(out)
}

fn read_unit_string_vec_bulk(
    conn: &Connection,
    lang: &str,
    table: &str,
    value_column: &str,
    oids: &[String],
) -> Result<HashMap<String, Vec<(i64, String)>>> {
    let mut out: HashMap<String, Vec<(i64, String)>> = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT blob_oid, unit_key, {value_column} FROM {table}
             WHERE lang = ? AND blob_oid IN ({placeholders})
             ORDER BY blob_oid, unit_key, ordinal"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (oid, key, value) = row?;
            out.entry(oid).or_default().push((key, value));
        }
    }
    Ok(out)
}

fn read_signature_metadata_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<SignatureMetadataRows> {
    let mut out: SignatureMetadataRows = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT blob_oid,
                    unit_key,
                    CASE
                        WHEN length(metadata) <= {MAX_SIGNATURE_METADATA_BLOB_BYTES}
                        THEN metadata
                        ELSE NULL
                    END
             FROM unit_signature_metadata
             WHERE lang = ? AND blob_oid IN ({placeholders})
             ORDER BY blob_oid, unit_key, ordinal"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
            ))
        })?;
        for row in rows {
            let (oid, key, value) = row?;
            if let Some(value) = value {
                out.entry(oid).or_default().push((key, value));
            }
        }
    }
    Ok(out)
}

fn read_cpp_template_metadata_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<CppTemplateMetadataRows> {
    let mut out = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT blob_oid, unit_key, metadata FROM unit_cpp_template_metadata
             WHERE lang = ? AND blob_oid IN ({placeholders})
             ORDER BY blob_oid, unit_key"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        for row in rows {
            let (oid, key, value) = row?;
            out.entry(oid).or_insert_with(Vec::new).push((key, value));
        }
    }
    Ok(out)
}

fn read_ranges_bulk(conn: &Connection, lang: &str, oids: &[String]) -> Result<RangeRows> {
    let mut out: RangeRows = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT blob_oid, unit_key, start_byte, end_byte, start_line, end_line
             FROM unit_ranges
             WHERE lang = ? AND blob_oid IN ({placeholders})
             ORDER BY blob_oid, unit_key, ordinal"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })?;
        for row in rows {
            let (oid, key, start_byte, end_byte, start_line, end_line) = row?;
            out.entry(oid)
                .or_default()
                .push((key, start_byte, end_byte, start_line, end_line));
        }
    }
    Ok(out)
}

fn read_children_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<HashMap<String, Vec<(i64, i64)>>> {
    let mut out: HashMap<String, Vec<(i64, i64)>> = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT blob_oid, parent_key, child_key FROM unit_children
             WHERE lang = ? AND blob_oid IN ({placeholders})
             ORDER BY blob_oid, parent_key, ordinal"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        for row in rows {
            let (oid, parent, child) = row?;
            out.entry(oid).or_default().push((parent, child));
        }
    }
    Ok(out)
}

fn read_ruby_method_dispatch_modes_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<RubyDispatchRows> {
    let mut out: RubyDispatchRows = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT blob_oid, unit_key, mode FROM ruby_method_dispatch_modes
             WHERE lang = ? AND blob_oid IN ({placeholders})
             ORDER BY blob_oid, unit_key"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        for row in rows {
            let (oid, key, mode) = row?;
            out.entry(oid).or_default().push((key, mode));
        }
    }
    Ok(out)
}

fn read_scala_traits_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<ScalaTraitRows> {
    let mut out: ScalaTraitRows = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT blob_oid, unit_key FROM scala_traits
             WHERE lang = ? AND blob_oid IN ({placeholders})
             ORDER BY blob_oid, unit_key"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (oid, key) = row?;
            out.entry(oid).or_default().push(key);
        }
    }
    Ok(out)
}

fn unit_string_map_for_file(
    rows: Option<&Vec<(i64, String)>>,
    by_key: &HashMap<i64, UnitRow>,
) -> HashMap<CodeUnit, Vec<String>> {
    let mut out: HashMap<CodeUnit, Vec<String>> = HashMap::default();
    for (key, value) in rows.into_iter().flatten() {
        if let Some(unit) = by_key.get(key) {
            out.entry(unit.unit.clone())
                .or_default()
                .push(value.clone());
        }
    }
    out
}

fn signature_metadata_map_for_file(
    rows: Option<&Vec<(i64, Vec<u8>)>>,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashMap<CodeUnit, Vec<SignatureMetadata>>> {
    let mut out: HashMap<CodeUnit, Vec<SignatureMetadata>> = HashMap::default();
    for (key, value) in rows.into_iter().flatten() {
        if let Some(unit) = by_key.get(key) {
            out.entry(unit.unit.clone())
                .or_default()
                .push(deserialize_signature_metadata_blob(value)?);
        }
    }
    Ok(out)
}

fn cpp_template_metadata_map_for_file(
    rows: Option<&Vec<(i64, Vec<u8>)>>,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashMap<CodeUnit, CppTemplateMetadata>> {
    let mut out = HashMap::default();
    for (key, value) in rows.into_iter().flatten() {
        if let Some(unit) = by_key.get(key) {
            out.insert(unit.unit.clone(), deserialize_blob(value)?);
        }
    }
    Ok(out)
}

fn scala_exports_map_for_file(
    rows: Option<&Vec<(i64, Vec<u8>)>>,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashMap<CodeUnit, Vec<crate::analyzer::scala::ScalaExportInfo>>> {
    let mut out = HashMap::default();
    for (key, value) in rows.into_iter().flatten() {
        if let Some(owner) = by_key.get(key) {
            out.entry(owner.unit.clone())
                .or_insert_with(Vec::new)
                .push(deserialize_blob(value)?);
        }
    }
    Ok(out)
}

fn ranges_map_for_file(
    rows: Option<&Vec<RangeRow>>,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashMap<CodeUnit, Vec<Range>>> {
    let mut out: HashMap<CodeUnit, Vec<Range>> = HashMap::default();
    for (key, start_byte, end_byte, start_line, end_line) in rows.into_iter().flatten() {
        if let Some(unit) = by_key.get(key) {
            out.entry(unit.unit.clone()).or_default().push(Range {
                start_byte: i64_to_usize(*start_byte)?,
                end_byte: i64_to_usize(*end_byte)?,
                start_line: i64_to_usize(*start_line)?,
                end_line: i64_to_usize(*end_line)?,
            });
        }
    }
    Ok(out)
}

fn children_map_for_file(
    rows: Option<&Vec<(i64, i64)>>,
    by_key: &HashMap<i64, UnitRow>,
) -> HashMap<CodeUnit, Vec<CodeUnit>> {
    let mut out: HashMap<CodeUnit, Vec<CodeUnit>> = HashMap::default();
    for (parent_key, child_key) in rows.into_iter().flatten() {
        let (Some(parent), Some(child)) = (by_key.get(parent_key), by_key.get(child_key)) else {
            continue;
        };
        out.entry(parent.unit.clone())
            .or_default()
            .push(child.unit.clone());
    }
    out
}

fn ruby_dispatch_map_for_file(
    rows: Option<&Vec<(i64, i64)>>,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashMap<CodeUnit, RubyMethodDispatchMode>> {
    let mut out = HashMap::default();
    for (key, raw_mode) in rows.into_iter().flatten() {
        if let Some(unit) = by_key.get(key) {
            out.insert(unit.unit.clone(), ruby_dispatch_mode_from_i64(*raw_mode)?);
        }
    }
    Ok(out)
}

fn scala_traits_for_file(
    rows: Option<&Vec<i64>>,
    by_key: &HashMap<i64, UnitRow>,
) -> HashSet<CodeUnit> {
    let mut out = HashSet::default();
    for key in rows.into_iter().flatten() {
        if let Some(unit) = by_key.get(key) {
            out.insert(unit.unit.clone());
        }
    }
    out
}

struct HydratedSideTableParts<'a> {
    ranges: &'a HashMap<CodeUnit, Vec<Range>>,
    signatures: &'a HashMap<CodeUnit, Vec<String>>,
    signature_metadata: &'a HashMap<CodeUnit, Vec<SignatureMetadata>>,
    cpp_template_metadata: &'a HashMap<CodeUnit, CppTemplateMetadata>,
    raw_supertypes: &'a HashMap<CodeUnit, Vec<String>>,
    children: &'a HashMap<CodeUnit, Vec<CodeUnit>>,
    import_statement_count: usize,
    import_count: usize,
    type_identifier_count: usize,
    ruby_dispatch_count: usize,
    scala_trait_count: usize,
}

fn side_table_counts_from_hydrated_parts(
    parts: HydratedSideTableParts<'_>,
) -> PersistedSideTableCounts {
    PersistedSideTableCounts {
        range_count: count_vec_entries(parts.ranges),
        signature_count: count_vec_entries(parts.signatures),
        signature_metadata_count: count_vec_entries(parts.signature_metadata),
        cpp_template_metadata_count: parts.cpp_template_metadata.len(),
        supertype_count: count_vec_entries(parts.raw_supertypes),
        child_count: count_vec_entries(parts.children),
        import_statement_count: parts.import_statement_count,
        import_count: parts.import_count,
        type_identifier_count: parts.type_identifier_count,
        ruby_dispatch_count: parts.ruby_dispatch_count,
        scala_trait_count: parts.scala_trait_count,
    }
}

fn count_vec_entries<T>(map: &HashMap<CodeUnit, Vec<T>>) -> usize {
    map.values().map(Vec::len).sum()
}

fn candidate_row_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CandidateRow> {
    let oid_text = row.get::<_, String>(0)?;
    let blob_oid = Oid::from_str(&oid_text).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(err))
    })?;
    let kind_raw = row.get::<_, i64>(3)?;
    let kind = code_unit_kind_from_i64(kind_raw).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Integer, Box::new(err))
    })?;
    Ok(CandidateRow {
        blob_oid,
        lang: row.get(1)?,
        unit_key: row.get(2)?,
        kind,
        short_name: row.get(4)?,
        content_qualifier: row.get(5)?,
        signature: row.get(6)?,
        flags: CandidateFlags {
            synthetic: row.get::<_, i64>(7)? != 0,
            is_type_alias: row.get::<_, i64>(8)? != 0,
            is_top_level: row.get::<_, Option<i64>>(9)?.is_some(),
            in_declarations: row.get::<_, i64>(10)? != 0,
            in_definition_lookup: row.get::<_, i64>(11)? != 0,
        },
        // Every candidate projection selects `fq_segments` at index 12, directly
        // after `in_definition_lookup`; any extra per-query columns follow at 13+.
        fq_segments: row.get::<_, Option<Vec<u8>>>(12)?,
    })
}

fn definition_order_candidate_row_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<DefinitionOrderCandidateRow> {
    // `fq_segments` occupies index 12; the definition-order extra column follows.
    let first_start_byte = row
        .get::<_, Option<i64>>(13)?
        .map(i64_to_usize)
        .transpose()
        .map_err(rusqlite_error_from_store)?;
    Ok(DefinitionOrderCandidateRow {
        candidate: candidate_row_from_row(row)?,
        first_start_byte,
    })
}

fn candidate_primary_range_row_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<CandidatePrimaryRangeRow> {
    // `fq_segments` occupies index 12; the primary-range columns follow at 13-16.
    let primary_range = match (
        row.get::<_, Option<i64>>(13)?,
        row.get::<_, Option<i64>>(14)?,
        row.get::<_, Option<i64>>(15)?,
        row.get::<_, Option<i64>>(16)?,
    ) {
        (Some(start_byte), Some(end_byte), Some(start_line), Some(end_line)) => Some(Range {
            start_byte: i64_to_usize(start_byte).map_err(rusqlite_error_from_store)?,
            end_byte: i64_to_usize(end_byte).map_err(rusqlite_error_from_store)?,
            start_line: i64_to_usize(start_line).map_err(rusqlite_error_from_store)?,
            end_line: i64_to_usize(end_line).map_err(rusqlite_error_from_store)?,
        }),
        _ => None,
    };
    Ok(CandidatePrimaryRangeRow {
        candidate: candidate_row_from_row(row)?,
        primary_range,
    })
}

fn collect_candidate_primary_range_rows<F>(
    rows: rusqlite::MappedRows<'_, F>,
) -> Result<Vec<CandidatePrimaryRangeRow>>
where
    F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<CandidatePrimaryRangeRow>,
{
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn collect_definition_order_candidate_rows<F>(
    rows: rusqlite::MappedRows<'_, F>,
) -> Result<Vec<DefinitionOrderCandidateRow>>
where
    F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<DefinitionOrderCandidateRow>,
{
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn usage_fact_row_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<UsageFactRow> {
    // `fq_segments` occupies index 12; the usage-fact extras follow at 13-15.
    let metadata_len = row.get::<_, Option<i64>>(14)?;
    if metadata_len
        .map(i64_to_usize)
        .transpose()
        .map_err(rusqlite_error_from_store)?
        .is_some_and(|len| len > MAX_SIGNATURE_METADATA_BLOB_BYTES)
    {
        return Err(rusqlite_error_from_store(StoreError::new(format!(
            "signature metadata blob exceeds the {MAX_SIGNATURE_METADATA_BLOB_BYTES}-byte cap"
        ))));
    }
    let metadata = row
        .get::<_, Option<Vec<u8>>>(15)?
        .map(|bytes| deserialize_signature_metadata_blob(&bytes).map_err(rusqlite_error_from_store))
        .transpose()?;
    Ok(UsageFactRow {
        candidate: candidate_row_from_row(row)?,
        signature: row.get(13)?,
        signature_metadata: metadata,
    })
}

fn search_candidate_row_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SearchCandidateRow> {
    let candidate = candidate_row_from_row(row)?;
    // `fq_segments` occupies index 12; `in_test_region` moves to 13 and the
    // primary-range columns to 14-17.
    let primary_range = match (
        row.get::<_, Option<i64>>(14)?,
        row.get::<_, Option<i64>>(15)?,
        row.get::<_, Option<i64>>(16)?,
        row.get::<_, Option<i64>>(17)?,
    ) {
        (Some(start_byte), Some(end_byte), Some(start_line), Some(end_line)) => Some(Range {
            start_byte: i64_to_usize(start_byte).map_err(rusqlite_error_from_store)?,
            end_byte: i64_to_usize(end_byte).map_err(rusqlite_error_from_store)?,
            start_line: i64_to_usize(start_line).map_err(rusqlite_error_from_store)?,
            end_line: i64_to_usize(end_line).map_err(rusqlite_error_from_store)?,
        }),
        _ => None,
    };
    Ok(SearchCandidateRow {
        candidate,
        primary_range,
        in_test_region: row.get::<_, i64>(13)? != 0,
    })
}

fn collect_candidate_rows<F>(rows: rusqlite::MappedRows<'_, F>) -> Result<Vec<CandidateRow>>
where
    F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<CandidateRow>,
{
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn collect_usage_fact_rows<F>(rows: rusqlite::MappedRows<'_, F>) -> Result<Vec<UsageFactRow>>
where
    F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<UsageFactRow>,
{
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// The full search-candidate projection, parameterized by its row predicate so
/// the by-key hydration and the whole-language enumeration cannot drift apart.
fn search_candidate_sql(predicate: &str) -> String {
    format!(
        "SELECT units.blob_oid, units.lang, units.unit_key, units.kind, units.short_name,
                units.content_qualifier, units.signature, units.synthetic,
                units.is_type_alias, units.top_level_ordinal, units.in_declarations,
                units.in_definition_lookup, units.fq_segments, units.in_test_region,
                primary_range.start_byte, primary_range.end_byte,
                primary_range.start_line, primary_range.end_line
         FROM code_units AS units
         JOIN blob_meta AS meta
           ON meta.blob_oid = units.blob_oid AND meta.lang = units.lang
         LEFT JOIN unit_ranges AS primary_range
           ON primary_range.blob_oid = units.blob_oid
          AND primary_range.lang = units.lang
          AND primary_range.unit_key = units.unit_key
          AND primary_range.ordinal = 0
         WHERE {predicate} AND units.in_declarations = 1
           AND {PARSED_BLOB_COMPLETE_CONDITION}"
    )
}

fn search_candidate_rows_by_lang_conn(
    conn: &Connection,
    lang: &str,
) -> Result<Vec<SearchCandidateRow>> {
    let sql = format!(
        "{} ORDER BY units.blob_oid, units.unit_key",
        search_candidate_sql("units.lang = ?1")
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let mut query = stmt.query([lang])?;
    let mut rows = Vec::new();
    while let Some(row) = query.next()? {
        rows.push(search_candidate_row_from_row(row)?);
    }
    Ok(rows)
}

fn search_candidate_name_rows_for_langs_conn_cancellable(
    conn: &Connection,
    langs: &[String],
    literal_substrings: Option<&[&str]>,
    cancellation: Option<&CancellationToken>,
) -> Result<LimitedQueryRows<SearchCandidateNameRow>> {
    if langs.is_empty() {
        return Ok(LimitedQueryRows::complete(Vec::new(), 0));
    }

    // No `ORDER BY`: candidates are deduplicated through an ordered map after
    // matching, so the storage order carries no meaning, while sorting the
    // whole declaration projection cost a temp B-tree over every workspace
    // declaration on every request (issue #1199).
    let literal_parameter_offset = langs.len() + 1;
    let literal_predicate = literal_substrings
        .filter(|literals| !literals.is_empty())
        .map(|literals| {
            let predicates = (0..literals.len())
                .map(|index| {
                    let parameter = literal_parameter_offset + index;
                    format!(
                        "(instr(lower(units.short_name), lower(?{parameter})) > 0
                          OR instr(lower(units.content_qualifier), lower(?{parameter})) > 0
                          OR instr(lower(coalesce(units.exact_fqn, '')), lower(?{parameter})) > 0
                          OR instr(lower(coalesce(units.normalized_fqn, '')), lower(?{parameter})) > 0)"
                    )
                })
                .collect::<Vec<_>>()
                .join(" OR ");
            format!(" AND ({predicates})")
        })
        .unwrap_or_default();
    let language_parameters = (1..=langs.len())
        .map(|index| format!("?{index}"))
        .collect::<Vec<_>>();
    let language_cases = langs
        .iter()
        .enumerate()
        .map(|(index, _)| format!("WHEN ?{} THEN {index}", index + 1))
        .collect::<Vec<_>>()
        .join(" ");
    let sql = format!(
        "SELECT CASE units.lang {language_cases} END,
                units.blob_oid, units.unit_key, units.short_name, units.content_qualifier
         FROM temp.active_blob_oids AS active
         CROSS JOIN code_units AS units
           ON units.blob_oid = active.blob_oid
         JOIN blob_meta AS meta
           ON meta.blob_oid = units.blob_oid AND meta.lang = units.lang
         WHERE units.lang IN ({}) AND units.in_declarations = 1
           AND {PARSED_BLOB_COMPLETE_CONDITION}{literal_predicate}",
        language_parameters.join(", ")
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let parameters = langs
        .iter()
        .map(String::as_str)
        .chain(literal_substrings.unwrap_or_default().iter().copied())
        .collect::<Vec<_>>();
    let mut query = stmt.query(rusqlite::params_from_iter(parameters))?;
    let mut rows = Vec::new();
    let mut inspected = 0usize;
    while let Some(row) = query.next()? {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Ok(LimitedQueryRows::incomplete(rows, inspected));
        }
        inspected = inspected.saturating_add(1);
        let lang_index = row.get::<_, i64>(0)?;
        let lang_index = usize::try_from(lang_index)
            .map_err(|_| StoreError::new(format!("invalid search language index {lang_index}")))?;
        let oid_text = row.get::<_, String>(1)?;
        let blob_oid = Oid::from_str(&oid_text).map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(err))
        })?;
        rows.push(SearchCandidateNameRow {
            lang_index,
            blob_oid,
            unit_key: row.get(2)?,
            short_name: row.get(3)?,
            content_qualifier: row.get(4)?,
        });
    }
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        Ok(LimitedQueryRows::incomplete(rows, inspected))
    } else {
        Ok(LimitedQueryRows::complete(rows, inspected))
    }
}

fn sync_active_blob_oids(conn: &Connection, active_oids: &[Oid]) -> Result<()> {
    conn.execute_batch(
        "CREATE TEMP TABLE IF NOT EXISTS active_blob_oids(
           blob_oid TEXT PRIMARY KEY
             CHECK(length(blob_oid) = 40 AND blob_oid NOT GLOB '*[^0-9a-f]*')
         ) WITHOUT ROWID, STRICT;
         DELETE FROM temp.active_blob_oids;",
    )?;
    for chunk in active_oids.chunks(400) {
        let values = std::iter::repeat_n("(?)", chunk.len())
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!("INSERT OR IGNORE INTO temp.active_blob_oids(blob_oid) VALUES {values}");
        let parameters = chunk.iter().map(Oid::to_string).collect::<Vec<_>>();
        conn.execute(&sql, params_from_iter(parameters.iter()))?;
    }
    Ok(())
}

fn usage_fact_rows_by_lang_conn(conn: &Connection, lang: &str) -> Result<Vec<UsageFactRow>> {
    let sql = format!(
        "SELECT units.blob_oid, units.lang, units.unit_key, units.kind, units.short_name,
                units.content_qualifier, units.signature, units.synthetic,
                units.is_type_alias, units.top_level_ordinal, units.in_declarations,
                units.in_definition_lookup, units.fq_segments, signature.text,
                length(metadata.metadata),
                CASE
                    WHEN length(metadata.metadata) <= {MAX_SIGNATURE_METADATA_BLOB_BYTES}
                    THEN metadata.metadata
                    ELSE NULL
                END
         FROM code_units AS units
         JOIN blob_meta AS meta
           ON meta.blob_oid = units.blob_oid AND meta.lang = units.lang
         LEFT JOIN unit_signatures AS signature
           ON signature.blob_oid = units.blob_oid
          AND signature.lang = units.lang
          AND signature.unit_key = units.unit_key
          AND signature.ordinal = 0
         LEFT JOIN unit_signature_metadata AS metadata
           ON metadata.blob_oid = units.blob_oid
          AND metadata.lang = units.lang
          AND metadata.unit_key = units.unit_key
          AND metadata.ordinal = 0
         WHERE units.lang = ?1 AND units.in_declarations = 1
           AND {PARSED_BLOB_COMPLETE_CONDITION}
         ORDER BY units.blob_oid, units.unit_key"
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    collect_usage_fact_rows(stmt.query_map([lang], usage_fact_row_from_row)?)
}

fn primary_ranges_by_unit_for_lang_conn(
    conn: &Connection,
    lang: &str,
    oids: &[Oid],
) -> Result<HashMap<(Oid, i64), Range>> {
    let mut out = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = std::iter::repeat_n("?", chunk.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT ranges.blob_oid, ranges.unit_key, ranges.start_byte, ranges.end_byte,
                    ranges.start_line, ranges.end_line
             FROM unit_ranges AS ranges
             JOIN blobs AS active_blob
               ON active_blob.blob_oid = ranges.blob_oid AND active_blob.lang = ranges.lang
             LEFT JOIN analysis_epochs AS active_epoch ON active_epoch.lang = active_blob.lang
             WHERE ranges.lang = ? AND ranges.ordinal = 0
               AND ranges.blob_oid IN ({placeholders})
               AND active_blob.generation = COALESCE(active_epoch.generation, 0)"
        );
        let mut parameters = Vec::with_capacity(chunk.len() + 1);
        parameters.push(lang.to_string());
        parameters.extend(chunk.iter().map(Oid::to_string));
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(params_from_iter(parameters.iter()), |row| {
            let oid_text = row.get::<_, String>(0)?;
            let oid = Oid::from_str(&oid_text).map_err(|err| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(err),
                )
            })?;
            Ok((
                (oid, row.get(1)?),
                Range {
                    start_byte: i64_to_usize(row.get(2)?).map_err(rusqlite_error_from_store)?,
                    end_byte: i64_to_usize(row.get(3)?).map_err(rusqlite_error_from_store)?,
                    start_line: i64_to_usize(row.get(4)?).map_err(rusqlite_error_from_store)?,
                    end_line: i64_to_usize(row.get(5)?).map_err(rusqlite_error_from_store)?,
                },
            ))
        })?;
        for row in rows {
            let (key, range) = row?;
            out.insert(key, range);
        }
    }
    Ok(out)
}

fn definition_lookup_candidate_rows_by_oids_conn(
    conn: &Connection,
    lang: &str,
    oids: &[Oid],
) -> Result<Vec<CandidateRow>> {
    let mut out = Vec::new();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = std::iter::repeat_n("?", chunk.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT units.blob_oid, units.lang, units.unit_key, units.kind, units.short_name,
                    units.content_qualifier, units.signature, units.synthetic,
                    units.is_type_alias, units.top_level_ordinal, units.in_declarations,
                    units.in_definition_lookup, units.fq_segments
             FROM code_units AS units
             JOIN blob_meta AS meta
               ON meta.blob_oid = units.blob_oid AND meta.lang = units.lang
             WHERE units.lang = ?
               AND (units.in_declarations = 1 OR units.in_definition_lookup = 1)
               AND units.blob_oid IN ({placeholders})
               AND {PARSED_BLOB_COMPLETE_CONDITION}
             ORDER BY units.blob_oid, units.unit_key"
        );
        let mut parameters = Vec::with_capacity(chunk.len() + 1);
        parameters.push(lang.to_string());
        parameters.extend(chunk.iter().map(Oid::to_string));
        let mut stmt = conn.prepare_cached(&sql)?;
        out.extend(collect_candidate_rows(stmt.query_map(
            params_from_iter(parameters.iter()),
            candidate_row_from_row,
        )?)?);
    }
    Ok(out)
}

fn blobs_with_structured_imports_conn(
    conn: &Connection,
    lang: &str,
    oids: &[Oid],
) -> Result<HashSet<Oid>> {
    let mut out = HashSet::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = std::iter::repeat_n("?", chunk.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT DISTINCT imports.blob_oid
             FROM import_details AS imports
             JOIN blob_meta AS meta
               ON meta.blob_oid = imports.blob_oid AND meta.lang = imports.lang
             WHERE imports.lang = ? AND imports.blob_oid IN ({placeholders})
               AND {PARSED_BLOB_COMPLETE_CONDITION}"
        );
        let mut parameters = Vec::with_capacity(chunk.len() + 1);
        parameters.push(lang.to_string());
        parameters.extend(chunk.iter().map(Oid::to_string));
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(params_from_iter(parameters.iter()), |row| {
            let oid_text = row.get::<_, String>(0)?;
            Oid::from_str(&oid_text).map_err(|err| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(err),
                )
            })
        })?;
        for row in rows {
            out.insert(row?);
        }
    }
    Ok(out)
}

fn read_unit_rows<A: LanguageAdapter>(
    conn: &Connection,
    oid: &str,
    lang: &str,
    adapter: &A,
    file: &ProjectFile,
) -> Result<Vec<UnitRow>> {
    let mut stmt = conn.prepare_cached(
        "SELECT unit_key, kind, content_qualifier, signature, synthetic,
                is_type_alias, top_level_ordinal, in_declarations, in_definition_lookup,
                in_test_region, fq_segments
         FROM code_units
         WHERE blob_oid = ?1 AND lang = ?2
         ORDER BY unit_key",
    )?;
    let rows = stmt.query_map(params![oid, lang], |row| {
        let key = row.get::<_, i64>(0)?;
        let kind_raw = row.get::<_, i64>(1)?;
        let content_qualifier = row.get::<_, String>(2)?;
        let signature = row.get::<_, Option<String>>(3)?;
        let synthetic = row.get::<_, i64>(4)? != 0;
        let is_type_alias = row.get::<_, i64>(5)? != 0;
        let top_level_ordinal = row
            .get::<_, Option<i64>>(6)?
            .and_then(|value| usize::try_from(value).ok());
        let in_declarations = row.get::<_, i64>(7)? != 0;
        let in_definition_lookup = row.get::<_, i64>(8)? != 0;
        let in_test_region = row.get::<_, i64>(9)? != 0;
        let fq_segments = row.get::<_, Option<Vec<u8>>>(10)?;
        Ok((
            key,
            kind_raw,
            content_qualifier,
            signature,
            synthetic,
            is_type_alias,
            top_level_ordinal,
            in_declarations,
            in_definition_lookup,
            in_test_region,
            fq_segments,
        ))
    })?;

    let mut out = Vec::new();
    for row in rows {
        let (
            key,
            kind_raw,
            content_qualifier,
            signature,
            synthetic,
            is_type_alias,
            top_level_ordinal,
            in_declarations,
            in_definition_lookup,
            in_test_region,
            fq_segments,
        ) = row?;
        let kind = code_unit_kind_from_i64(kind_raw)?;
        let (fq, package_segment_count) =
            hydrate_unit_fq(adapter, fq_segments.as_deref(), &content_qualifier, file)?;
        let unit = CodeUnit::from_fq(
            file.clone(),
            kind,
            fq,
            package_segment_count,
            signature,
            synthetic,
        );
        out.push(UnitRow {
            key,
            unit,
            is_type_alias,
            top_level_ordinal,
            in_declarations,
            in_definition_lookup,
            in_test_region,
        });
    }
    Ok(out)
}

fn read_import_statements(conn: &Connection, oid: &str, lang: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT statement FROM import_statements
         WHERE blob_oid = ?1 AND lang = ?2
         ORDER BY ordinal",
    )?;
    collect_string_rows(stmt.query_map(params![oid, lang], |row| row.get(0))?)
}

fn read_import_infos(conn: &Connection, oid: &str, lang: &str) -> Result<Vec<ImportInfo>> {
    let mut stmt = conn.prepare(
        "SELECT info FROM import_details
         WHERE blob_oid = ?1 AND lang = ?2
         ORDER BY ordinal",
    )?;
    let rows = stmt.query_map(params![oid, lang], |row| row.get::<_, Vec<u8>>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(deserialize_blob(&row?)?);
    }
    Ok(out)
}

fn insert_materialization_records(
    tx: &Transaction<'_>,
    oid: &str,
    lang: &str,
    unit_keys: &HashMap<CodeUnit, i64>,
    records: &[MaterializationRecord],
) -> Result<usize> {
    let mut stmt = tx.prepare(
        "INSERT OR IGNORE INTO materialization_records(
           blob_oid, lang, ordinal, unit_key, payload
         ) VALUES(?1, ?2, ?3, ?4, ?5)",
    )?;
    let mut count = 0;
    for (ordinal, record) in records.iter().enumerate() {
        let (unit, payload) = record.split();
        let unit_key = match unit {
            Some(unit) => match unit_keys.get(unit) {
                Some(&key) => Some(key),
                None => continue,
            },
            None => None,
        };
        stmt.execute(params![
            oid,
            lang,
            usize_to_i64(ordinal)?,
            unit_key,
            serialize_blob(&payload)?,
        ])?;
        count += 1;
    }
    Ok(count)
}

/// Read back one blob's `rust_*` fact rows, in the order they were written.
///
/// The inverse of [`insert_rust_fact_rows`], and the only place the persisted
/// column encodings are decoded. A visibility this build did not write means
/// the row came from a schema this build does not own, which the schema-version
/// file name already prevents -- so it is an assertion, not a recovery path.
#[allow(dead_code)]
fn read_rust_usage_facts(conn: &Connection, oid: &str, lang: &str) -> Result<RustUsageFacts> {
    let mut exports = Vec::new();
    {
        let mut stmt = conn.prepare_cached(
            "SELECT exported_name, source_path, imported_name, is_glob FROM rust_exports
             WHERE blob_oid = ?1 AND lang = ?2 ORDER BY ordinal",
        )?;
        let rows = stmt.query_map(params![oid, lang], |row| {
            Ok(RustExportFact {
                exported_name: row.get(0)?,
                source_path: row.get(1)?,
                imported_name: row.get(2)?,
                is_glob: row.get::<_, i64>(3)? != 0,
            })
        })?;
        for row in rows {
            exports.push(row?);
        }
    }
    let mut import_targets = Vec::new();
    {
        let mut stmt = conn.prepare_cached(
            "SELECT module_path, bound_name, imported_name, is_glob, visibility,
                    owner_module, owner_start, owner_end, local_start, local_end
             FROM rust_import_targets
             WHERE blob_oid = ?1 AND lang = ?2 ORDER BY ordinal",
        )?;
        let rows = stmt.query_map(params![oid, lang], |row| {
            Ok((
                RustImportTargetFact {
                    module_path: row.get(0)?,
                    bound_name: row.get(1)?,
                    imported_name: row.get(2)?,
                    is_glob: row.get::<_, i64>(3)? != 0,
                    visibility: RustVisibility::Private,
                    owner_module: row.get(5)?,
                    owner_start: 0,
                    owner_end: 0,
                    local_extent: None,
                },
                row.get::<_, String>(4)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, Option<i64>>(8)?,
                row.get::<_, Option<i64>>(9)?,
            ))
        })?;
        for row in rows {
            let (mut target, visibility, owner_start, owner_end, local_start, local_end) = row?;
            target.visibility = decode_rust_visibility(&visibility)
                .unwrap_or_else(|| panic!("unknown persisted Rust visibility: {visibility}"));
            target.owner_start = i64_to_usize(owner_start)?;
            target.owner_end = i64_to_usize(owner_end)?;
            target.local_extent = match (local_start, local_end) {
                (Some(start), Some(end)) => Some((i64_to_usize(start)?, i64_to_usize(end)?)),
                (None, None) => None,
                mismatched => panic!("half-open persisted local import extent: {mismatched:?}"),
            };
            import_targets.push(target);
        }
    }
    let mut modules = Vec::new();
    {
        let mut stmt = conn.prepare_cached(
            "SELECT module_name, is_inline, start_byte, end_byte FROM rust_modules
             WHERE blob_oid = ?1 AND lang = ?2 ORDER BY ordinal",
        )?;
        let rows = stmt.query_map(params![oid, lang], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)? != 0,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        for row in rows {
            let (module_name, is_inline, start_byte, end_byte) = row?;
            modules.push(RustModuleFact {
                module_name,
                is_inline,
                start_byte: i64_to_usize(start_byte)?,
                end_byte: i64_to_usize(end_byte)?,
            });
        }
    }
    let mut identifier_occurrences = Vec::new();
    {
        let mut stmt = conn.prepare_cached(
            "SELECT identifier, context_mask FROM rust_identifier_occurrences
             WHERE blob_oid = ?1 AND lang = ?2 ORDER BY identifier",
        )?;
        let rows = stmt.query_map(params![oid, lang], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (identifier, context_mask) = row?;
            identifier_occurrences.push(RustIdentifierOccurrence {
                identifier,
                context_mask: u32::try_from(context_mask).map_err(|_| {
                    StoreError::new(format!(
                        "occurrence context mask out of range: {context_mask}"
                    ))
                })?,
            });
        }
    }
    let module_routes = read_rust_module_route_facts(conn, oid, lang)?;
    Ok(RustUsageFacts {
        exports,
        import_targets,
        modules,
        identifier_occurrences,
        module_routes,
    })
}

/// Read back one blob's module-route facts.
///
/// The per-blob inverse of the `rust_module_*` / `rust_item_macros` inserts.
/// The Cargo-route build does NOT come through here -- it reads every live
/// blob's rows in one chunked pass (`AnalyzerStore::rust_module_route_facts`) --
/// so this exists to keep the per-blob round trip complete and reviewable.
fn read_rust_module_route_facts(
    conn: &Connection,
    oid: &str,
    lang: &str,
) -> Result<RustModuleRouteFacts> {
    let mut facts = RustModuleRouteFacts::default();
    {
        let mut stmt = conn.prepare_cached(
            "SELECT parent_ordinal, module_name, path_attribute, imports_macros,
                    body_start, body_end
             FROM rust_module_scopes
             WHERE blob_oid = ?1 AND lang = ?2 ORDER BY ordinal",
        )?;
        let rows = stmt.query_map(params![oid, lang], |row| {
            decode_rust_module_scope_row(row, 0)
        })?;
        for row in rows {
            facts.scopes.push(row??);
        }
    }
    {
        let mut stmt = conn.prepare_cached(
            "SELECT scope_ordinal, module_name, path_attribute, visibility, imports_macros,
                    test_gated, declaration_start, declaration_end
             FROM rust_module_routes
             WHERE blob_oid = ?1 AND lang = ?2 ORDER BY ordinal",
        )?;
        let rows = stmt.query_map(params![oid, lang], |row| {
            decode_rust_module_route_row(row, 0)
        })?;
        for row in rows {
            facts.routes.push(row??);
        }
    }
    {
        let mut stmt = conn.prepare_cached(
            "SELECT route_ordinal, macro_name, invocation_start
             FROM rust_module_route_gates
             WHERE blob_oid = ?1 AND lang = ?2 ORDER BY route_ordinal, gate_ordinal",
        )?;
        let rows = stmt.query_map(params![oid, lang], |row| {
            decode_rust_module_route_gate_row(row, 0)
        })?;
        for row in rows {
            let (route_ordinal, gate) = row??;
            attach_rust_module_route_gate(&mut facts.routes, route_ordinal, gate)?;
        }
    }
    {
        let mut stmt = conn.prepare_cached(
            "SELECT macro_name, visible_after, scope_start, scope_end, passthrough
             FROM rust_item_macros
             WHERE blob_oid = ?1 AND lang = ?2 ORDER BY ordinal",
        )?;
        let rows = stmt.query_map(params![oid, lang], |row| decode_rust_item_macro_row(row, 0))?;
        for row in rows {
            facts.item_macros.push(row??);
        }
    }
    Ok(facts)
}

/// `base` is the index of this row shape's first column, so the per-blob reads
/// (which select the columns alone) and the batched reads (which select
/// `blob_oid` first) share one decoder.
fn decode_rust_module_scope_row(
    row: &rusqlite::Row<'_>,
    base: usize,
) -> rusqlite::Result<Result<RustModuleScopeFact>> {
    let parent = row.get::<_, Option<i64>>(base)?;
    let module_name = row.get::<_, String>(base + 1)?;
    let path_attribute = row.get::<_, Option<String>>(base + 2)?;
    let imports_macros = row.get::<_, i64>(base + 3)? != 0;
    let body_start = row.get::<_, i64>(base + 4)?;
    let body_end = row.get::<_, i64>(base + 5)?;
    Ok((|| {
        Ok(RustModuleScopeFact {
            parent: parent.map(i64_to_usize).transpose()?,
            module_name,
            path_attribute,
            imports_macros,
            body_start: i64_to_usize(body_start)?,
            body_end: i64_to_usize(body_end)?,
        })
    })())
}

fn decode_rust_module_route_row(
    row: &rusqlite::Row<'_>,
    base: usize,
) -> rusqlite::Result<Result<RustModuleRouteFact>> {
    let scope = row.get::<_, i64>(base)?;
    let module_name = row.get::<_, String>(base + 1)?;
    let path_attribute = row.get::<_, Option<String>>(base + 2)?;
    let visibility = row.get::<_, String>(base + 3)?;
    let imports_macros = row.get::<_, i64>(base + 4)? != 0;
    let test_gated = row.get::<_, i64>(base + 5)? != 0;
    let declaration_start = row.get::<_, i64>(base + 6)?;
    let declaration_end = row.get::<_, i64>(base + 7)?;
    Ok((|| {
        Ok(RustModuleRouteFact {
            scope: i64_to_usize(scope)?,
            module_name,
            path_attribute,
            visibility: decode_rust_visibility(&visibility)
                .unwrap_or_else(|| panic!("unknown persisted Rust visibility: {visibility}")),
            imports_macros,
            test_gated,
            declaration_start: i64_to_usize(declaration_start)?,
            declaration_end: i64_to_usize(declaration_end)?,
            gates: Vec::new(),
        })
    })())
}

fn decode_rust_module_route_gate_row(
    row: &rusqlite::Row<'_>,
    base: usize,
) -> rusqlite::Result<Result<(usize, RustMacroGateFact)>> {
    let route_ordinal = row.get::<_, i64>(base)?;
    let macro_name = row.get::<_, String>(base + 1)?;
    let invocation_start = row.get::<_, i64>(base + 2)?;
    Ok((|| {
        Ok((
            i64_to_usize(route_ordinal)?,
            RustMacroGateFact {
                macro_name,
                invocation_start: i64_to_usize(invocation_start)?,
            },
        ))
    })())
}

fn decode_rust_item_macro_row(
    row: &rusqlite::Row<'_>,
    base: usize,
) -> rusqlite::Result<Result<RustRulesItemMacroDefinition>> {
    let name = row.get::<_, String>(base)?;
    let visible_after = row.get::<_, i64>(base + 1)?;
    let scope_start = row.get::<_, i64>(base + 2)?;
    let scope_end = row.get::<_, i64>(base + 3)?;
    let passthrough = row.get::<_, i64>(base + 4)? != 0;
    Ok((|| {
        Ok(RustRulesItemMacroDefinition {
            name,
            visible_after: i64_to_usize(visible_after)?,
            scope_start: i64_to_usize(scope_start)?,
            scope_end: i64_to_usize(scope_end)?,
            passthrough,
        })
    })())
}

/// Attach one gate row to the route it belongs to.
///
/// Gate rows are read in `(route_ordinal, gate_ordinal)` order, so appending
/// preserves the outermost-first order the reader relies on. A gate naming a
/// route that does not exist can only come from rows this build did not write.
fn attach_rust_module_route_gate(
    routes: &mut [RustModuleRouteFact],
    route_ordinal: usize,
    gate: RustMacroGateFact,
) -> Result<()> {
    let route = routes.get_mut(route_ordinal).ok_or_else(|| {
        StoreError::new(format!(
            "module route gate names missing route {route_ordinal}: {gate:?}"
        ))
    })?;
    route.gates.push(gate);
    Ok(())
}

fn read_materialization_records(
    conn: &Connection,
    oid: &str,
    lang: &str,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<Vec<MaterializationRecord>> {
    let mut stmt = conn.prepare(
        "SELECT unit_key, payload FROM materialization_records
         WHERE blob_oid = ?1 AND lang = ?2
         ORDER BY ordinal",
    )?;
    let rows = stmt.query_map(params![oid, lang], |row| {
        Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (unit_key, payload) = row?;
        let payload: MaterializationRecordPayload = deserialize_blob(&payload)?;
        let unit = unit_key
            .and_then(|key| by_key.get(&key))
            .map(|row| row.unit.clone());
        if let Some(record) = MaterializationRecord::join(payload, unit) {
            out.push(record);
        }
    }
    Ok(out)
}

fn read_scala_exports(
    conn: &Connection,
    oid: &str,
    lang: &str,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashMap<CodeUnit, Vec<crate::analyzer::scala::ScalaExportInfo>>> {
    let mut stmt = conn.prepare(
        "SELECT owner_key, info FROM scala_exports
         WHERE blob_oid = ?1 AND lang = ?2
         ORDER BY owner_key, ordinal",
    )?;
    let rows = stmt.query_map(params![oid, lang], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    let mut out = HashMap::default();
    for row in rows {
        let (key, info) = row?;
        if let Some(owner) = by_key.get(&key) {
            out.entry(owner.unit.clone())
                .or_insert_with(Vec::new)
                .push(deserialize_blob(&info)?);
        }
    }
    Ok(out)
}

fn read_unit_string_vec(
    conn: &Connection,
    oid: &str,
    lang: &str,
    table: &str,
    value_column: &str,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashMap<CodeUnit, Vec<String>>> {
    let sql = format!(
        "SELECT unit_key, {value_column} FROM {table}
         WHERE blob_oid = ?1 AND lang = ?2
         ORDER BY unit_key, ordinal"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![oid, lang], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut out: HashMap<CodeUnit, Vec<String>> = HashMap::default();
    for row in rows {
        let (key, value) = row?;
        if let Some(unit) = by_key.get(&key) {
            out.entry(unit.unit.clone()).or_default().push(value);
        }
    }
    Ok(out)
}

fn read_signature_metadata(
    conn: &Connection,
    oid: &str,
    lang: &str,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashMap<CodeUnit, Vec<SignatureMetadata>>> {
    let mut stmt = conn.prepare(
        "SELECT unit_key,
                CASE
                    WHEN length(metadata) <= ?3 THEN metadata
                    ELSE NULL
                END
         FROM unit_signature_metadata
         WHERE blob_oid = ?1 AND lang = ?2
         ORDER BY unit_key, ordinal",
    )?;
    let rows = stmt.query_map(
        params![oid, lang, usize_to_i64(MAX_SIGNATURE_METADATA_BLOB_BYTES)?],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
    )?;
    let mut out: HashMap<CodeUnit, Vec<SignatureMetadata>> = HashMap::default();
    for row in rows {
        let (key, metadata) = row?;
        let Some(metadata) = metadata else {
            continue;
        };
        if let Some(unit) = by_key.get(&key) {
            out.entry(unit.unit.clone())
                .or_default()
                .push(deserialize_signature_metadata_blob(&metadata)?);
        }
    }
    Ok(out)
}

fn direct_children_for_unit_limited_conn(
    conn: &Connection,
    oid: Oid,
    lang: &str,
    unit: &CodeUnit,
    limit: usize,
) -> Result<LimitedQueryRows<CandidateRow>> {
    if limit == 0 {
        return Ok(LimitedQueryRows::incomplete(Vec::new(), 0));
    }
    let sql = limited_candidate_rows_sql_with_membership(
        "child",
        "FROM code_units AS owner
         JOIN unit_children AS edge
           ON edge.blob_oid = owner.blob_oid
          AND edge.lang = owner.lang
          AND edge.parent_key = owner.unit_key
         JOIN code_units AS child
           ON child.blob_oid = edge.blob_oid
          AND child.lang = edge.lang
          AND child.unit_key = edge.child_key
         JOIN blob_meta AS meta
           ON meta.blob_oid = child.blob_oid
          AND meta.lang = child.lang",
        "owner.blob_oid = ?1
         AND owner.lang = ?2
         AND (owner.exact_fqn = ?3 OR owner.exact_fqn IS NULL)
         AND owner.kind = ?4
         AND owner.short_name = ?5
         AND owner.signature IS ?6
         AND owner.synthetic = ?7",
        "owner.in_declarations = 1 AND child.in_declarations = 1",
        "edge.ordinal, child.unit_key",
    );
    let sql = format!("{sql} LIMIT ?8");
    let oid = oid.to_string();
    let kind = code_unit_kind_to_i64(unit.kind());
    let synthetic = bool_to_i64(unit.is_synthetic());
    let sql_limit = i64::try_from(limit).unwrap_or(i64::MAX);
    let mut statement = conn.prepare_cached(&sql)?;
    let mut query = statement.query(params![
        oid,
        lang,
        unit.fq_name(),
        kind,
        unit.short_name(),
        unit.signature(),
        synthetic,
        sql_limit,
    ])?;
    let mut rows = Vec::new();
    let mut inspected = 0usize;
    let mut bytes = LimitedQueryByteBudget::default();
    while let Some(row) = query.next()? {
        inspected = inspected.saturating_add(1);
        // `fq_segments` occupies index 12; the row-byte budget column follows.
        if !bytes.admit_sqlite_bytes(row.get::<_, i64>(13)?)? {
            return Ok(LimitedQueryRows::incomplete(rows, inspected));
        }
        rows.push(candidate_row_from_row(row)?);
    }
    drop(query);
    if inspected == limit {
        Ok(LimitedQueryRows::incomplete(rows, inspected))
    } else {
        Ok(LimitedQueryRows::complete(rows, inspected))
    }
}

fn signature_metadata_for_unit_limited_conn(
    conn: &Connection,
    oid: Oid,
    lang: &str,
    unit: &CodeUnit,
    limit: usize,
) -> Result<LimitedQueryRows<SignatureMetadata>> {
    if limit == 0 {
        return Ok(LimitedQueryRows::incomplete(Vec::new(), 0));
    }
    let sql = format!(
        "SELECT length(metadata.metadata),
                CASE
                    WHEN length(metadata.metadata) <= ?9 THEN metadata.metadata
                    ELSE NULL
                END
         FROM code_units AS units
         JOIN blob_meta AS meta
           ON meta.blob_oid = units.blob_oid AND meta.lang = units.lang
         JOIN unit_signature_metadata AS metadata
           ON metadata.blob_oid = units.blob_oid
          AND metadata.lang = units.lang
          AND metadata.unit_key = units.unit_key
         WHERE units.blob_oid = ?1
           AND units.lang = ?2
           AND (units.exact_fqn = ?3 OR units.exact_fqn IS NULL)
           AND units.kind = ?4
           AND units.short_name = ?5
           AND units.signature IS ?6
           AND units.synthetic = ?7
           AND {PARSED_BLOB_COMPLETE_CONDITION}
         ORDER BY metadata.ordinal
         LIMIT ?8"
    );
    let oid = oid.to_string();
    let kind = code_unit_kind_to_i64(unit.kind());
    let synthetic = bool_to_i64(unit.is_synthetic());
    let sql_limit = i64::try_from(limit).unwrap_or(i64::MAX);
    let mut statement = conn.prepare_cached(&sql)?;
    let mut query = statement.query(params![
        oid,
        lang,
        unit.fq_name(),
        kind,
        unit.short_name(),
        unit.signature(),
        synthetic,
        sql_limit,
        usize_to_i64(MAX_LIMITED_QUERY_ROW_BYTES)?,
    ])?;
    let mut rows = Vec::new();
    let mut inspected = 0usize;
    let mut byte_budget = LimitedQueryByteBudget::default();
    while let Some(row) = query.next()? {
        inspected = inspected.saturating_add(1);
        let byte_len = row.get::<_, i64>(0)?;
        if !byte_budget.admit_sqlite_bytes(byte_len)? {
            return Ok(LimitedQueryRows::incomplete(Vec::new(), inspected));
        }
        let Some(bytes) = row.get::<_, Option<Vec<u8>>>(1)? else {
            return Ok(LimitedQueryRows::incomplete(Vec::new(), inspected));
        };
        rows.push(deserialize_signature_metadata_blob(&bytes)?);
    }
    drop(query);
    if inspected == limit {
        Ok(LimitedQueryRows::incomplete(rows, inspected))
    } else {
        Ok(LimitedQueryRows::complete(rows, inspected))
    }
}

fn ruby_method_dispatch_modes_for_unit_limited_conn(
    conn: &Connection,
    oid: Oid,
    lang: &str,
    unit: &CodeUnit,
    limit: usize,
) -> Result<LimitedQueryRows<RubyMethodDispatchMode>> {
    if limit == 0 {
        return Ok(LimitedQueryRows::incomplete(Vec::new(), 0));
    }
    let sql = format!(
        "SELECT modes.mode
         FROM code_units AS units
         JOIN blob_meta AS meta
           ON meta.blob_oid = units.blob_oid AND meta.lang = units.lang
         JOIN ruby_method_dispatch_modes AS modes
           ON modes.blob_oid = units.blob_oid
          AND modes.lang = units.lang
          AND modes.unit_key = units.unit_key
         WHERE units.blob_oid = ?1
           AND units.lang = ?2
           AND (units.exact_fqn = ?3 OR units.exact_fqn IS NULL)
           AND units.kind = ?4
           AND units.short_name = ?5
           AND units.signature IS ?6
           AND units.synthetic = ?7
           AND units.in_declarations = 1
           AND {PARSED_BLOB_COMPLETE_CONDITION}
         ORDER BY units.unit_key
         LIMIT ?8"
    );
    let oid = oid.to_string();
    let kind = code_unit_kind_to_i64(unit.kind());
    let synthetic = bool_to_i64(unit.is_synthetic());
    let sql_limit = i64::try_from(limit).unwrap_or(i64::MAX);
    let mut statement = conn.prepare_cached(&sql)?;
    let mapped = statement.query_map(
        params![
            oid,
            lang,
            unit.fq_name(),
            kind,
            unit.short_name(),
            unit.signature(),
            synthetic,
            sql_limit,
        ],
        |row| row.get::<_, i64>(0),
    )?;
    let mut rows = Vec::new();
    for raw_mode in mapped {
        rows.push(ruby_dispatch_mode_from_i64(raw_mode?)?);
    }
    let inspected = rows.len();
    if inspected == limit {
        Ok(LimitedQueryRows::incomplete(rows, inspected))
    } else {
        Ok(LimitedQueryRows::complete(rows, inspected))
    }
}

fn collect_limited_text_rows(
    query: &mut rusqlite::Rows<'_>,
    limit: usize,
) -> Result<LimitedQueryRows<String>> {
    let mut rows = Vec::new();
    let mut inspected = 0usize;
    let mut bytes = LimitedQueryByteBudget::default();
    while let Some(row) = query.next()? {
        inspected = inspected.saturating_add(1);
        let byte_len = row.get::<_, i64>(0)?;
        if !bytes.admit_sqlite_bytes(byte_len)? {
            return Ok(LimitedQueryRows::incomplete(rows, inspected));
        }
        let Some(value) = row.get::<_, Option<String>>(1)? else {
            return Ok(LimitedQueryRows::incomplete(rows, inspected));
        };
        rows.push(value);
    }
    if inspected == limit {
        Ok(LimitedQueryRows::incomplete(rows, inspected))
    } else {
        Ok(LimitedQueryRows::complete(rows, inspected))
    }
}

fn raw_supertypes_for_unit_limited_conn(
    conn: &Connection,
    oid: Oid,
    lang: &str,
    unit: &CodeUnit,
    limit: usize,
) -> Result<LimitedQueryRows<String>> {
    if limit == 0 {
        return Ok(LimitedQueryRows::incomplete(Vec::new(), 0));
    }
    let sql = format!(
        "SELECT length(CAST(supertypes.raw AS BLOB)),
                CASE
                    WHEN length(CAST(supertypes.raw AS BLOB))
                           <= {MAX_LIMITED_QUERY_ROW_BYTES}
                    THEN supertypes.raw
                    ELSE NULL
                END
         FROM code_units AS units
         JOIN blob_meta AS meta
           ON meta.blob_oid = units.blob_oid AND meta.lang = units.lang
         JOIN unit_supertypes AS supertypes
           ON supertypes.blob_oid = units.blob_oid
          AND supertypes.lang = units.lang
          AND supertypes.unit_key = units.unit_key
         WHERE units.blob_oid = ?1
           AND units.lang = ?2
           AND (units.exact_fqn = ?3 OR units.exact_fqn IS NULL)
           AND units.kind = ?4
           AND units.short_name = ?5
           AND units.signature IS ?6
           AND units.synthetic = ?7
           AND {PARSED_BLOB_COMPLETE_CONDITION}
         ORDER BY supertypes.ordinal
         LIMIT ?8"
    );
    let oid = oid.to_string();
    let kind = code_unit_kind_to_i64(unit.kind());
    let synthetic = bool_to_i64(unit.is_synthetic());
    let sql_limit = i64::try_from(limit).unwrap_or(i64::MAX);
    let mut statement = conn.prepare_cached(&sql)?;
    let mut query = statement.query(params![
        oid,
        lang,
        unit.fq_name(),
        kind,
        unit.short_name(),
        unit.signature(),
        synthetic,
        sql_limit,
    ])?;
    collect_limited_text_rows(&mut query, limit)
}

fn supertype_lookup_paths_for_unit_limited_conn(
    conn: &Connection,
    oid: Oid,
    lang: &str,
    unit: &CodeUnit,
    limit: usize,
) -> Result<LimitedQueryRows<String>> {
    if limit == 0 {
        return Ok(LimitedQueryRows::incomplete(Vec::new(), 0));
    }
    let sql = format!(
        "SELECT length(CAST(supertypes.lookup_path AS BLOB)),
                CASE
                    WHEN length(CAST(supertypes.lookup_path AS BLOB))
                           <= {MAX_LIMITED_QUERY_ROW_BYTES}
                    THEN supertypes.lookup_path
                    ELSE NULL
                END
         FROM code_units AS units
         JOIN blob_meta AS meta
           ON meta.blob_oid = units.blob_oid AND meta.lang = units.lang
         JOIN unit_supertypes AS supertypes
           ON supertypes.blob_oid = units.blob_oid
          AND supertypes.lang = units.lang
          AND supertypes.unit_key = units.unit_key
         WHERE units.blob_oid = ?1
           AND units.lang = ?2
           AND (units.exact_fqn = ?3 OR units.exact_fqn IS NULL)
           AND units.kind = ?4
           AND units.short_name = ?5
           AND units.signature IS ?6
           AND units.synthetic = ?7
           AND {PARSED_BLOB_COMPLETE_CONDITION}
         ORDER BY supertypes.ordinal
         LIMIT ?8"
    );
    let oid = oid.to_string();
    let kind = code_unit_kind_to_i64(unit.kind());
    let synthetic = bool_to_i64(unit.is_synthetic());
    let sql_limit = i64::try_from(limit).unwrap_or(i64::MAX);
    let mut statement = conn.prepare_cached(&sql)?;
    let mut query = statement.query(params![
        oid,
        lang,
        unit.fq_name(),
        kind,
        unit.short_name(),
        unit.signature(),
        synthetic,
        sql_limit,
    ])?;
    collect_limited_text_rows(&mut query, limit)
}

fn read_cpp_template_metadata(
    conn: &Connection,
    oid: &str,
    lang: &str,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashMap<CodeUnit, CppTemplateMetadata>> {
    let mut stmt = conn.prepare(
        "SELECT unit_key, metadata FROM unit_cpp_template_metadata
         WHERE blob_oid = ?1 AND lang = ?2
         ORDER BY unit_key",
    )?;
    let rows = stmt.query_map(params![oid, lang], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    let mut out = HashMap::default();
    for row in rows {
        let (key, metadata) = row?;
        if let Some(unit) = by_key.get(&key) {
            out.insert(unit.unit.clone(), deserialize_blob(&metadata)?);
        }
    }
    Ok(out)
}

fn ranges_for_unit_limited_conn(
    conn: &Connection,
    oid: Oid,
    lang: &str,
    unit: &CodeUnit,
    limit: usize,
) -> Result<LimitedQueryRows<Range>> {
    if limit == 0 {
        return Ok(LimitedQueryRows::incomplete(Vec::new(), 0));
    }
    let sql = format!(
        "SELECT ranges.start_byte, ranges.end_byte, ranges.start_line, ranges.end_line
         FROM code_units AS units
         JOIN blob_meta AS meta
           ON meta.blob_oid = units.blob_oid AND meta.lang = units.lang
         JOIN unit_ranges AS ranges
           ON ranges.blob_oid = units.blob_oid
          AND ranges.lang = units.lang
          AND ranges.unit_key = units.unit_key
         WHERE units.blob_oid = ?1
           AND units.lang = ?2
           AND (units.exact_fqn = ?3 OR units.exact_fqn IS NULL)
           AND units.kind = ?4
           AND units.short_name = ?5
           AND units.signature IS ?6
           AND units.synthetic = ?7
           AND {PARSED_BLOB_COMPLETE_CONDITION}
         ORDER BY ranges.ordinal
         LIMIT ?8"
    );
    let oid = oid.to_string();
    let kind = code_unit_kind_to_i64(unit.kind());
    let synthetic = bool_to_i64(unit.is_synthetic());
    let sql_limit = i64::try_from(limit).unwrap_or(i64::MAX);
    let mut statement = conn.prepare_cached(&sql)?;
    let mapped = statement.query_map(
        params![
            oid,
            lang,
            unit.fq_name(),
            kind,
            unit.short_name(),
            unit.signature(),
            synthetic,
            sql_limit,
        ],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        },
    )?;
    let mut rows = Vec::new();
    for row in mapped {
        let (start_byte, end_byte, start_line, end_line) = row?;
        rows.push(Range {
            start_byte: i64_to_usize(start_byte)?,
            end_byte: i64_to_usize(end_byte)?,
            start_line: i64_to_usize(start_line)?,
            end_line: i64_to_usize(end_line)?,
        });
    }
    let inspected = rows.len();
    if inspected == limit {
        Ok(LimitedQueryRows::incomplete(rows, inspected))
    } else {
        Ok(LimitedQueryRows::complete(rows, inspected))
    }
}

fn read_ranges(
    conn: &Connection,
    oid: &str,
    lang: &str,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashMap<CodeUnit, Vec<Range>>> {
    let mut stmt = conn.prepare(
        "SELECT unit_key, start_byte, end_byte, start_line, end_line
         FROM unit_ranges
         WHERE blob_oid = ?1 AND lang = ?2
         ORDER BY unit_key, ordinal",
    )?;
    let rows = stmt.query_map(params![oid, lang], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
        ))
    })?;
    let mut out: HashMap<CodeUnit, Vec<Range>> = HashMap::default();
    for row in rows {
        let (key, start_byte, end_byte, start_line, end_line) = row?;
        if let Some(unit) = by_key.get(&key) {
            out.entry(unit.unit.clone()).or_default().push(Range {
                start_byte: i64_to_usize(start_byte)?,
                end_byte: i64_to_usize(end_byte)?,
                start_line: i64_to_usize(start_line)?,
                end_line: i64_to_usize(end_line)?,
            });
        }
    }
    Ok(out)
}

fn read_children(
    conn: &Connection,
    oid: &str,
    lang: &str,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashMap<CodeUnit, Vec<CodeUnit>>> {
    let mut stmt = conn.prepare(
        "SELECT parent_key, child_key FROM unit_children
         WHERE blob_oid = ?1 AND lang = ?2
         ORDER BY parent_key, ordinal",
    )?;
    let rows = stmt.query_map(params![oid, lang], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
    })?;
    let mut out: HashMap<CodeUnit, Vec<CodeUnit>> = HashMap::default();
    for row in rows {
        let (parent_key, child_key) = row?;
        let (Some(parent), Some(child)) = (by_key.get(&parent_key), by_key.get(&child_key)) else {
            continue;
        };
        out.entry(parent.unit.clone())
            .or_default()
            .push(child.unit.clone());
    }
    Ok(out)
}

fn read_ruby_method_dispatch_modes(
    conn: &Connection,
    oid: &str,
    lang: &str,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashMap<CodeUnit, RubyMethodDispatchMode>> {
    let mut stmt = conn.prepare(
        "SELECT unit_key, mode FROM ruby_method_dispatch_modes
         WHERE blob_oid = ?1 AND lang = ?2
         ORDER BY unit_key",
    )?;
    let rows = stmt.query_map(params![oid, lang], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
    })?;
    let mut out = HashMap::default();
    for row in rows {
        let (key, raw_mode) = row?;
        if let Some(unit) = by_key.get(&key) {
            out.insert(unit.unit.clone(), ruby_dispatch_mode_from_i64(raw_mode)?);
        }
    }
    Ok(out)
}

fn read_scala_traits(
    conn: &Connection,
    oid: &str,
    lang: &str,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashSet<CodeUnit>> {
    let mut stmt = conn.prepare(
        "SELECT unit_key FROM scala_traits
         WHERE blob_oid = ?1 AND lang = ?2
         ORDER BY unit_key",
    )?;
    let rows = stmt.query_map(params![oid, lang], |row| row.get::<_, i64>(0))?;
    let mut out = HashSet::default();
    for row in rows {
        let key = row?;
        if let Some(unit) = by_key.get(&key) {
            out.insert(unit.unit.clone());
        }
    }
    Ok(out)
}

fn synthesize_file_scope(file: &ProjectFile, source: &str, state: &mut FileState) {
    let code_unit = CodeUnit::file_scope(file.clone());
    if state.declarations.contains(&code_unit) {
        return;
    }
    state.top_level_declarations.push(code_unit.clone());
    state.declarations.insert(code_unit.clone());
    state.ranges.entry(code_unit).or_default().push(Range {
        start_byte: 0,
        end_byte: source.len(),
        start_line: 0,
        end_line: compute_line_starts(source).len().saturating_sub(1),
    });
}

fn collect_string_rows(
    rows: rusqlite::MappedRows<'_, impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<String>>,
) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn ensure_language_epochs_tx(
    conn: &mut Connection,
    entries: &[(String, String)],
) -> Result<HashMap<String, GenerationId>> {
    let mut generations = HashMap::default();
    let mut all_match = true;
    for (lang, analysis_epoch) in entries {
        let stored: Option<(String, i64)> = conn
            .query_row(
                "SELECT epoch, generation FROM analysis_epochs WHERE lang = ?1",
                [lang],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        match stored {
            Some((stored_epoch, generation)) if stored_epoch == *analysis_epoch => {
                generations.insert(lang.clone(), GenerationId(generation));
            }
            _ => {
                all_match = false;
                break;
            }
        }
    }
    if all_match {
        return Ok(generations);
    }

    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    generations.clear();
    for (lang, analysis_epoch) in entries {
        let stored_epoch: Option<String> = tx
            .query_row(
                "SELECT epoch FROM analysis_epochs WHERE lang = ?1",
                [lang],
                |row| row.get(0),
            )
            .optional()?;
        if stored_epoch.as_deref() == Some(analysis_epoch) {
            let generation = current_generation_conn(&tx, lang)?;
            generations.insert(lang.clone(), generation);
            continue;
        }
        let generation: i64 = tx.query_row(
            "UPDATE analysis_generation_sequence
         SET next_generation = next_generation + 1
         WHERE id = 1 AND next_generation < 9223372036854775807
         RETURNING next_generation - 1",
            [],
            |row| row.get(0),
        )?;
        tx.execute(
            "INSERT INTO analysis_epochs(lang, epoch, generation) VALUES(?1, ?2, ?3)
         ON CONFLICT(lang) DO UPDATE SET
           epoch = excluded.epoch,
           generation = excluded.generation",
            params![lang, analysis_epoch, generation],
        )?;
        generations.insert(lang.clone(), GenerationId(generation));
    }
    tx.commit()?;
    Ok(generations)
}

fn require_current_generation(
    conn: &Connection,
    lang: &str,
    generation: GenerationId,
) -> Result<()> {
    let current = current_generation_conn(conn, lang)?;
    if current != generation {
        return Err(StoreError::stale_generation(format!(
            "stale analyzer generation for {lang}: captured {}, current {}",
            generation.0, current.0
        )));
    }
    Ok(())
}

fn require_generation_map<'a>(
    conn: &Connection,
    generations: &HashMap<String, GenerationId>,
    requested_languages: impl IntoIterator<Item = &'a str>,
) -> Result<()> {
    let mut seen = HashSet::default();
    for lang in requested_languages {
        if !seen.insert(lang) {
            continue;
        }
        let Some(generation) = generations.get(lang) else {
            return Err(StoreError::stale_generation(format!(
                "missing captured analyzer generation for {lang}"
            )));
        };
        require_current_generation(conn, lang, *generation)?;
    }
    Ok(())
}

fn current_generation_conn(conn: &Connection, lang: &str) -> Result<GenerationId> {
    let generation = conn
        .query_row(
            "SELECT generation FROM analysis_epochs WHERE lang = ?1",
            [lang],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(GenerationId::BOOTSTRAP.0);
    Ok(GenerationId(generation))
}

fn contains_parsed_blob_conn(conn: &Connection, oid: Oid, lang: &str) -> Result<bool> {
    let sql = format!(
        "SELECT 1 FROM blob_meta AS meta
         WHERE meta.blob_oid = ?1 AND meta.lang = ?2
           AND {PARSED_BLOB_INTEGRITY_CONDITION}
         LIMIT 1"
    );
    Ok(conn
        .prepare_cached(&sql)?
        .query_row(params![oid.to_string(), lang], |_| Ok(()))
        .optional()?
        .is_some())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoredCascadeCost {
    Missing,
    Legacy,
    Known(PersistedMutationCost),
}

fn stored_blob_cascade_costs_conn(
    conn: &Connection,
    prepared: &[PreparedParsedBlob],
    mut on_query: impl FnMut(),
) -> Result<Vec<StoredCascadeCost>> {
    const KEYS_PER_QUERY: usize = PersistBatchLimits::PRODUCTION.max_blobs;
    let mut costs = Vec::with_capacity(prepared.len());
    for chunk in prepared.chunks(KEYS_PER_QUERY) {
        // Pad the `VALUES (ordinal, ?, ?)` list to a fixed arity so this query
        // collapses to two cached SQL shapes instead of one per chunk length.
        // The padded rows carry NULL blob_oid/lang, so their LEFT JOINs miss and
        // they report `Missing`; we size `chunk_costs` to the padded arity, fill
        // every ordinal, then truncate the padding away — semantics-preserving.
        let padded = padded_cascade_arity(chunk.len());
        let mut chunk_costs = vec![StoredCascadeCost::Missing; padded];
        let sql = stored_blob_cascade_costs_sql(padded);
        on_query();
        let mut statement = conn.prepare_cached(&sql)?;
        let mut parameters: Vec<Option<&str>> = Vec::with_capacity(padded * 2);
        for blob in chunk {
            parameters.push(Some(blob.oid_text.as_str()));
            parameters.push(Some(blob.lang.as_str()));
        }
        parameters.resize(padded * 2, None);
        let rows = statement.query_map(params_from_iter(parameters.iter()), |row| {
            Ok((
                row.get::<_, usize>(0)?,
                row.get::<_, bool>(1)?,
                row.get::<_, bool>(2)?,
                row.get::<_, usize>(3)?,
                row.get::<_, Option<usize>>(4)?,
            ))
        })?;
        for row in rows {
            let (ordinal, blob_present, meta_present, logical_rows, payload_bytes) = row?;
            chunk_costs[ordinal] = match (blob_present, meta_present, payload_bytes) {
                (false, _, _) => StoredCascadeCost::Missing,
                (true, false, _) => StoredCascadeCost::Known(PersistedMutationCost {
                    logical_rows: 1,
                    payload_bytes: 0,
                }),
                (true, true, Some(payload_bytes)) => {
                    StoredCascadeCost::Known(PersistedMutationCost {
                        logical_rows,
                        payload_bytes,
                    })
                }
                (true, true, None) => StoredCascadeCost::Legacy,
            };
        }
        chunk_costs.truncate(chunk.len());
        costs.extend(chunk_costs);
    }
    Ok(costs)
}

/// Fixed arities for the cascade-cost `VALUES` query. Capped at
/// `PersistBatchLimits::PRODUCTION.max_blobs` (the chunk size), which the SQL
/// builder asserts against.
fn padded_cascade_arity(len: usize) -> usize {
    const LADDER: [usize; 2] = [16, PersistBatchLimits::PRODUCTION.max_blobs];
    LADDER
        .iter()
        .copied()
        .find(|&arity| arity >= len)
        .unwrap_or(LADDER[LADDER.len() - 1])
}

fn stored_blob_cascade_costs_sql(key_count: usize) -> String {
    assert!((1..=PersistBatchLimits::PRODUCTION.max_blobs).contains(&key_count));
    let requested = (0..key_count)
        .map(|ordinal| format!("({ordinal}, ?, ?)"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "WITH requested(ordinal, blob_oid, lang) AS (VALUES {requested})
         SELECT requested.ordinal,
           blob.blob_oid IS NOT NULL,
           meta.blob_oid IS NOT NULL,
           CASE WHEN blob.blob_oid IS NULL THEN 0
             WHEN meta.blob_oid IS NULL THEN 1
             ELSE 2 + meta.stored_unit_count + meta.range_count + meta.signature_count
               + meta.signature_metadata_count + meta.cpp_template_metadata_count
               + meta.supertype_count + meta.child_count
               + meta.import_statement_count + meta.import_count + meta.type_identifier_count
               + meta.ruby_dispatch_count + meta.scala_trait_count
               + (SELECT COUNT(*) FROM scala_exports AS exports
                  WHERE exports.blob_oid = meta.blob_oid AND exports.lang = meta.lang)
               + (SELECT COUNT(*) FROM structural_facts_snapshots AS snapshots
                  WHERE snapshots.blob_oid = meta.blob_oid AND snapshots.lang = meta.lang)
               + CASE WHEN costs.blob_oid IS NULL THEN 0 ELSE 1 END END,
           costs.payload_bytes
         FROM requested
         LEFT JOIN blobs AS blob
           ON blob.blob_oid = requested.blob_oid AND blob.lang = requested.lang
         LEFT JOIN blob_meta AS meta
           ON meta.blob_oid = blob.blob_oid AND meta.lang = blob.lang
         LEFT JOIN blob_payload_costs AS costs
           ON costs.blob_oid = meta.blob_oid AND costs.lang = meta.lang"
    )
}

fn persisted_blob_mutation_cost_fallback_statement(
    statement: &mut rusqlite::Statement<'_>,
    oid: &str,
    lang: &str,
) -> Result<PersistedMutationCost> {
    statement
        .query_row(params![oid, lang], |row| {
            Ok(PersistedMutationCost {
                logical_rows: row.get(0)?,
                payload_bytes: row.get(1)?,
            })
        })
        .map_err(StoreError::from)
}

fn persisted_blob_mutation_cost_fallback_sql() -> &'static str {
    "SELECT
       1 + CASE WHEN meta.blob_oid IS NULL THEN 0 ELSE
         1 + meta.stored_unit_count + meta.range_count + meta.signature_count
           + meta.signature_metadata_count + meta.cpp_template_metadata_count
           + meta.supertype_count + meta.child_count
           + meta.import_statement_count + meta.import_count + meta.type_identifier_count
           + meta.ruby_dispatch_count + meta.scala_trait_count
           + (SELECT COUNT(*) FROM scala_exports AS exports
              WHERE exports.blob_oid = meta.blob_oid AND exports.lang = meta.lang)
           + (SELECT COUNT(*) FROM structural_facts_snapshots AS snapshots
              WHERE snapshots.blob_oid = meta.blob_oid AND snapshots.lang = meta.lang) END,
       CASE WHEN meta.blob_oid IS NULL THEN 0 ELSE
         length(CAST(meta.content_package AS BLOB))
           + COALESCE((SELECT SUM(
               length(CAST(short_name AS BLOB)) + length(CAST(identifier AS BLOB))
               + length(CAST(content_qualifier AS BLOB))
               + COALESCE(length(CAST(exact_fqn AS BLOB)), 0)
               + COALESCE(length(CAST(normalized_fqn AS BLOB)), 0)
               + COALESCE(length(CAST(simple_type_name AS BLOB)), 0)
               + COALESCE(length(CAST(signature AS BLOB)), 0)
             ) FROM code_units WHERE blob_oid = blob.blob_oid AND lang = blob.lang), 0)
           + COALESCE((SELECT SUM(length(CAST(text AS BLOB))) FROM unit_signatures
               WHERE blob_oid = blob.blob_oid AND lang = blob.lang), 0)
           + COALESCE((SELECT SUM(length(metadata)) FROM unit_signature_metadata
               WHERE blob_oid = blob.blob_oid AND lang = blob.lang), 0)
           + COALESCE((SELECT SUM(length(metadata)) FROM unit_cpp_template_metadata
               WHERE blob_oid = blob.blob_oid AND lang = blob.lang), 0)
           + COALESCE((SELECT SUM(length(CAST(raw AS BLOB))
               + length(CAST(lookup_path AS BLOB))) FROM unit_supertypes
               WHERE blob_oid = blob.blob_oid AND lang = blob.lang), 0)
           + COALESCE((SELECT SUM(length(CAST(statement AS BLOB))) FROM import_statements
               WHERE blob_oid = blob.blob_oid AND lang = blob.lang), 0)
           + COALESCE((SELECT SUM(length(info)) FROM import_details
               WHERE blob_oid = blob.blob_oid AND lang = blob.lang), 0)
           + COALESCE((SELECT SUM(length(info)) FROM scala_exports
               WHERE blob_oid = blob.blob_oid AND lang = blob.lang), 0)
           + COALESCE((SELECT SUM(length(CAST(type_identifier AS BLOB))) FROM type_identifiers
               WHERE blob_oid = blob.blob_oid AND lang = blob.lang), 0)
           + COALESCE((SELECT SUM(length(payload)) FROM structural_facts_snapshots
               WHERE blob_oid = blob.blob_oid AND lang = blob.lang), 0) END
     FROM blobs AS blob
     LEFT JOIN blob_meta AS meta
       ON meta.blob_oid = blob.blob_oid AND meta.lang = blob.lang
     WHERE blob.blob_oid = ?1 AND blob.lang = ?2"
}

fn insert_blob_payload_cost_tx(
    tx: &Transaction<'_>,
    oid: &str,
    lang: &str,
    payload_bytes: usize,
) -> Result<()> {
    tx.execute(
        "INSERT INTO blob_payload_costs(blob_oid, lang, payload_bytes)
         VALUES(?1, ?2, ?3)",
        params![oid, lang, usize_to_i64(payload_bytes)?],
    )?;
    Ok(())
}

fn update_blob_payload_cost_tx(tx: &Transaction<'_>, oid: &str, lang: &str) -> Result<()> {
    let cost = {
        let mut statement = tx.prepare_cached(persisted_blob_mutation_cost_fallback_sql())?;
        persisted_blob_mutation_cost_fallback_statement(&mut statement, oid, lang)?
    };
    insert_blob_payload_cost_tx(tx, oid, lang, cost.payload_bytes)
}

/// Fixed arities for the `VALUES (?, ?)` pair lists, capped at the caller's
/// 400-key chunk size.
fn padded_pair_arity(len: usize) -> usize {
    const LADDER: [usize; 4] = [16, 64, 256, 400];
    LADDER
        .iter()
        .copied()
        .find(|&arity| arity >= len)
        .unwrap_or(LADDER[LADDER.len() - 1])
}

fn parsed_blob_keys_conn(
    conn: &Connection,
    entries: &[(Oid, String)],
) -> Result<HashSet<(Oid, String)>> {
    parsed_blob_keys_conn_with_condition(conn, entries, "", PARSED_BLOB_INTEGRITY_CONDITION)
}

fn missing_published_parsed_blob_keys_conn(
    conn: &Connection,
    entries: &[(Oid, String)],
) -> Result<Vec<(Oid, String)>> {
    {
        let _scope = crate::profiling::scope("store.missing_blobs.sync_requested");
        sync_requested_parsed_blobs(conn, entries)?;
    }
    let _query_scope = crate::profiling::scope("store.missing_blobs.query");
    let mut statement = conn.prepare_cached(
        "SELECT requested.blob_oid, requested.lang
         FROM temp.requested_parsed_blobs AS requested
         LEFT JOIN analysis_epochs AS active_epoch ON active_epoch.lang = requested.lang
         LEFT JOIN blob_meta AS meta
           ON meta.blob_oid = requested.blob_oid
          AND meta.lang = requested.lang
          AND meta.is_complete = 1
         LEFT JOIN blobs AS active_blob
           ON active_blob.blob_oid = requested.blob_oid
          AND active_blob.lang = requested.lang
          AND active_blob.generation = COALESCE(active_epoch.generation, 0)
         WHERE meta.blob_oid IS NULL OR active_blob.blob_oid IS NULL
         ORDER BY requested.ordinal",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut missing = Vec::new();
    for row in rows {
        let (oid, lang) = row?;
        if let Ok(oid) = Oid::from_str(&oid) {
            missing.push((oid, lang));
        }
    }
    Ok(missing)
}

fn sync_requested_parsed_blobs(conn: &Connection, entries: &[(Oid, String)]) -> Result<()> {
    conn.execute_batch(
        "CREATE TEMP TABLE IF NOT EXISTS requested_parsed_blobs(
           blob_oid TEXT NOT NULL,
           lang TEXT NOT NULL,
           ordinal INTEGER NOT NULL,
           PRIMARY KEY(blob_oid, lang)
         ) WITHOUT ROWID, STRICT;
         DELETE FROM temp.requested_parsed_blobs;",
    )?;
    const KEYS_PER_INSERT: usize = 300;
    for (chunk_index, chunk) in entries.chunks(KEYS_PER_INSERT).enumerate() {
        let values = std::iter::repeat_n("(?, ?, ?)", chunk.len())
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "INSERT OR IGNORE INTO temp.requested_parsed_blobs(blob_oid, lang, ordinal) VALUES {values}"
        );
        let mut parameters = Vec::with_capacity(chunk.len() * 3);
        let chunk_start = chunk_index * KEYS_PER_INSERT;
        for (offset, (oid, lang)) in chunk.iter().enumerate() {
            parameters.push(rusqlite::types::Value::Text(oid.to_string()));
            parameters.push(rusqlite::types::Value::Text(lang.clone()));
            parameters.push(rusqlite::types::Value::Integer(
                (chunk_start + offset) as i64,
            ));
        }
        conn.execute(&sql, params_from_iter(parameters.iter()))?;
    }
    Ok(())
}

fn parsed_blob_keys_conn_with_condition(
    conn: &Connection,
    entries: &[(Oid, String)],
    joins: &str,
    condition: &str,
) -> Result<HashSet<(Oid, String)>> {
    const KEYS_PER_QUERY: usize = 400;
    let mut unique = Vec::with_capacity(entries.len());
    let mut seen = HashSet::default();
    for entry in entries {
        if seen.insert(entry.clone()) {
            unique.push(entry.clone());
        }
    }
    let mut present = set_with_capacity(unique.len());
    for chunk in unique.chunks(KEYS_PER_QUERY) {
        // Pad the `VALUES (?, ?)` pair list to a fixed arity so this read-path
        // query lands on a small set of cached SQL shapes. Padded rows carry
        // NULL blob_oid/lang; the inner JOIN drops them, so the matched-key set
        // is unchanged.
        let padded = padded_pair_arity(chunk.len());
        let values = std::iter::repeat_n("(?, ?)", padded)
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "WITH requested(blob_oid, lang) AS (VALUES {values})
             SELECT requested.blob_oid, requested.lang
             FROM requested
             JOIN blob_meta AS meta
               ON meta.blob_oid = requested.blob_oid AND meta.lang = requested.lang
             {joins}
             WHERE {condition}"
        );
        let mut parameters: Vec<Option<String>> = Vec::with_capacity(padded * 2);
        for (oid, lang) in chunk {
            parameters.push(Some(oid.to_string()));
            parameters.push(Some(lang.clone()));
        }
        parameters.resize(padded * 2, None);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(params_from_iter(parameters.iter()), |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (oid, lang) = row?;
            if let Ok(oid) = Oid::from_str(&oid) {
                present.insert((oid, lang));
            }
        }
    }
    Ok(present)
}

fn reclaim_stale_generations_conn(conn: &mut Connection, max_logical_rows: usize) -> Result<usize> {
    if max_logical_rows == 0 {
        return Ok(0);
    }
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let stale_blobs = {
        let mut stmt = tx.prepare(
            "SELECT blobs.blob_oid, blobs.lang,
                    1 + CASE WHEN meta.blob_oid IS NULL THEN 0 ELSE
                      1 + meta.stored_unit_count + meta.range_count + meta.signature_count
                        + meta.signature_metadata_count + meta.cpp_template_metadata_count
                        + meta.supertype_count + meta.child_count
                        + meta.import_statement_count + meta.import_count
                        + meta.type_identifier_count + meta.ruby_dispatch_count
                        + meta.scala_trait_count
                        + (SELECT COUNT(*) FROM structural_facts_snapshots AS snapshots
                           WHERE snapshots.blob_oid = meta.blob_oid
                             AND snapshots.lang = meta.lang)
                        + CASE WHEN costs.blob_oid IS NULL THEN 0 ELSE 1 END END AS logical_rows
             FROM blobs
             LEFT JOIN analysis_epochs AS epochs ON epochs.lang = blobs.lang
             LEFT JOIN blob_meta AS meta
               ON meta.blob_oid = blobs.blob_oid AND meta.lang = blobs.lang
             LEFT JOIN blob_payload_costs AS costs
               ON costs.blob_oid = meta.blob_oid AND costs.lang = meta.lang
             WHERE blobs.generation <> COALESCE(epochs.generation, 0)
             ORDER BY blobs.lang, blobs.generation, blobs.blob_oid",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, usize>(2)?,
            ))
        })?;
        let mut selected = Vec::new();
        let mut logical_rows = 0usize;
        for row in rows {
            let (oid, lang, rows) = row?;
            if !selected.is_empty() && logical_rows.saturating_add(rows) > max_logical_rows {
                break;
            }
            selected.push((oid, lang));
            logical_rows = logical_rows.saturating_add(rows);
            if logical_rows >= max_logical_rows {
                break;
            }
        }
        (selected, logical_rows)
    };
    let (stale_blobs, mut reclaimed) = stale_blobs;
    {
        let mut delete = tx.prepare(
            "DELETE FROM blobs
             WHERE blob_oid = ?1 AND lang = ?2
               AND generation <> COALESCE(
                 (SELECT generation FROM analysis_epochs WHERE lang = ?2), 0
               )",
        )?;
        for (oid, lang) in stale_blobs {
            delete.execute(params![oid, lang])?;
        }
    }

    let mut remaining = max_logical_rows.saturating_sub(reclaimed);
    if remaining > 0 {
        let removed = tx.execute(
            "DELETE FROM path_symbol_units
             WHERE (lang, rel_path, kind, exact_fqn) IN (
               SELECT units.lang, units.rel_path, units.kind, units.exact_fqn
               FROM path_symbol_units AS units
               LEFT JOIN analysis_epochs AS epochs ON epochs.lang = units.lang
               WHERE units.generation <> COALESCE(epochs.generation, 0)
               ORDER BY units.lang, units.generation, units.rel_path
               LIMIT ?1
             )",
            [usize_to_i64(remaining)?],
        )?;
        reclaimed = reclaimed.saturating_add(removed);
        remaining = remaining.saturating_sub(removed);
    }
    if remaining > 0 {
        reclaimed = reclaimed.saturating_add(tx.execute(
            "DELETE FROM path_symbol_snapshots
             WHERE lang IN (
               SELECT snapshots.lang
               FROM path_symbol_snapshots AS snapshots
               LEFT JOIN analysis_epochs AS epochs ON epochs.lang = snapshots.lang
               WHERE snapshots.generation <> COALESCE(epochs.generation, 0)
               ORDER BY snapshots.lang
               LIMIT ?1
             )",
            [usize_to_i64(remaining)?],
        )?);
    }
    tx.commit()?;
    Ok(reclaimed)
}

fn serialize_blob<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    bincode::serialize(value)
        .map_err(|err| StoreError::new(format!("analyzer store serialization error: {err}")))
}

const FQ_SEGMENTS_MAGIC: &[u8; 4] = b"FQ2\0";
const FQ_SEGMENTS_FULL: u8 = 0;
const FQ_SEGMENTS_PATH_TAIL: u8 = 1;
const FQ_SEGMENTS_HEADER_LEN: usize = 9;

/// Persist one structured declaration identity. Content-derived packages are
/// stored in full. When a package depends on the live path, only the
/// content-stable declaration tail is stored so one content-addressed blob can
/// still be mounted at multiple paths; the adapter recreates that prefix from
/// the live `ProjectFile` without parsing a rendered name.
fn encode_unit_fq_segments<A: LanguageAdapter>(
    adapter: &A,
    unit: &CodeUnit,
    content_qualifier: &str,
) -> Option<Vec<u8>> {
    let fq = unit.fq();
    if fq.is_empty() {
        return None;
    }
    let interner = segment_interner();
    let path_prefix = adapter
        .code_unit_package_is_path_derived(unit, content_qualifier)
        .then(|| {
            adapter
                .path_derived_package_fq(content_qualifier, unit.source())
                .expect("path-derived CodeUnit package requires an adapter prefix")
        });
    let (mode, package_segment_count, persisted_fq) = match path_prefix {
        Some(prefix) => {
            assert_eq!(
                prefix,
                unit.package_fq(),
                "path-derived package prefix must equal the CodeUnit's structured prefix \
                 (content_qualifier={content_qualifier:?}, unit={unit:?})"
            );
            (
                FQ_SEGMENTS_PATH_TAIL,
                0usize,
                fq.suffix_from(unit.package_segment_count()),
            )
        }
        None => (FQ_SEGMENTS_FULL, unit.package_segment_count(), fq.clone()),
    };
    let package_segment_count = u32::try_from(package_segment_count)
        .expect("CodeUnit package segment count must fit in u32");
    let encoded_segments = persisted_fq.encode_segments(interner);
    let mut encoded = Vec::with_capacity(FQ_SEGMENTS_HEADER_LEN + encoded_segments.len());
    encoded.extend_from_slice(FQ_SEGMENTS_MAGIC);
    encoded.push(mode);
    encoded.extend_from_slice(&package_segment_count.to_le_bytes());
    encoded.extend_from_slice(&encoded_segments);
    Some(encoded)
}

/// Hydrate the structured identity and its package boundary. This format has no
/// legacy-string fallback: stale cache rows are invalidated by the store epoch.
pub(crate) fn hydrate_unit_fq<A: LanguageAdapter>(
    adapter: &A,
    persisted: Option<&[u8]>,
    content_qualifier: &str,
    file: &ProjectFile,
) -> Result<(FqName, usize)> {
    let interner = segment_interner();
    let bytes = persisted
        .ok_or_else(|| StoreError::new("analyzer store row is missing its structured FqName"))?;
    if bytes.len() < FQ_SEGMENTS_HEADER_LEN || &bytes[..4] != FQ_SEGMENTS_MAGIC {
        return Err(StoreError::new(
            "analyzer store row has an unsupported structured FqName encoding",
        ));
    }
    let mode = bytes[4];
    let stored_package_segment_count = u32::from_le_bytes(bytes[5..9].try_into().unwrap()) as usize;
    let stored_fq = FqName::decode_segments(&bytes[FQ_SEGMENTS_HEADER_LEN..], interner)
        .map_err(|err| StoreError::new(format!("analyzer store fq segment decode error: {err}")))?;
    match mode {
        FQ_SEGMENTS_FULL => {
            if stored_package_segment_count >= stored_fq.len() {
                return Err(StoreError::new(
                    "analyzer store FqName package boundary leaves no declaration tail",
                ));
            }
            Ok((stored_fq, stored_package_segment_count))
        }
        FQ_SEGMENTS_PATH_TAIL => {
            let mut prefix = adapter
                .path_derived_package_fq(content_qualifier, file)
                .ok_or_else(|| {
                    StoreError::new(
                        "analyzer adapter did not provide the persisted path-derived package prefix",
                    )
                })?;
            let package_segment_count = prefix.len();
            prefix.extend_from(&stored_fq);
            Ok((prefix, package_segment_count))
        }
        _ => Err(StoreError::new(format!(
            "analyzer store FqName has unknown mode {mode}"
        ))),
    }
}

fn serialize_signature_metadata_blob(value: &SignatureMetadata) -> Result<Vec<u8>> {
    let serialized_size = usize::try_from(bincode::serialized_size(value).map_err(|err| {
        StoreError::new(format!("analyzer store serialization size error: {err}"))
    })?)
    .map_err(|_| StoreError::new("signature metadata size does not fit in usize"))?;
    if serialized_size > MAX_SIGNATURE_METADATA_BLOB_BYTES {
        return Err(StoreError::new(format!(
            "signature metadata blob requires {serialized_size} bytes, exceeding the \
             {MAX_SIGNATURE_METADATA_BLOB_BYTES}-byte cap"
        )));
    }
    let bytes = serialize_blob(value)?;
    debug_assert_eq!(bytes.len(), serialized_size);
    Ok(bytes)
}

fn deserialize_signature_metadata_blob(bytes: &[u8]) -> Result<SignatureMetadata> {
    if bytes.len() > MAX_SIGNATURE_METADATA_BLOB_BYTES {
        return Err(StoreError::new(format!(
            "signature metadata blob exceeds the {MAX_SIGNATURE_METADATA_BLOB_BYTES}-byte cap"
        )));
    }
    let byte_limit = u64::try_from(bytes.len())
        .map_err(|_| StoreError::new("signature metadata blob length does not fit in u64"))?;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(byte_limit)
        .deserialize(bytes)
        .map_err(|err| StoreError::new(format!("analyzer store deserialization error: {err}")))
}

fn deserialize_limited_blob<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let byte_limit = u64::try_from(bytes.len())
        .map_err(|_| StoreError::new("limited-query blob length does not fit in u64"))?;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(byte_limit)
        .deserialize(bytes)
        .map_err(|err| StoreError::new(format!("analyzer store deserialization error: {err}")))
}

fn deserialize_blob<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    bincode::deserialize(bytes)
        .map_err(|err| StoreError::new(format!("analyzer store deserialization error: {err}")))
}

fn bool_to_i64(value: bool) -> i64 {
    i64::from(value)
}

fn usize_to_i64(value: usize) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| StoreError::new(format!("value does not fit in SQLite INTEGER: {value}")))
}

fn i64_to_usize(value: i64) -> Result<usize> {
    usize::try_from(value)
        .map_err(|_| StoreError::new(format!("negative or too-large SQLite INTEGER: {value}")))
}

fn rusqlite_error_from_store(err: StoreError) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Integer, Box::new(err))
}

fn code_unit_kind_to_i64(kind: CodeUnitType) -> i64 {
    match kind {
        CodeUnitType::Class => 0,
        CodeUnitType::Function => 1,
        CodeUnitType::Field => 2,
        CodeUnitType::Module => 3,
        CodeUnitType::Macro => 4,
        CodeUnitType::FileScope => 5,
    }
}

fn code_unit_kind_from_i64(value: i64) -> Result<CodeUnitType> {
    match value {
        0 => Ok(CodeUnitType::Class),
        1 => Ok(CodeUnitType::Function),
        2 => Ok(CodeUnitType::Field),
        3 => Ok(CodeUnitType::Module),
        4 => Ok(CodeUnitType::Macro),
        5 => Ok(CodeUnitType::FileScope),
        _ => Err(StoreError::new(format!("invalid code unit kind: {value}"))),
    }
}

fn ruby_dispatch_mode_to_i64(mode: RubyMethodDispatchMode) -> i64 {
    match mode {
        RubyMethodDispatchMode::Instance => 0,
        RubyMethodDispatchMode::Singleton => 1,
        RubyMethodDispatchMode::ModuleFunction => 2,
    }
}

fn ruby_dispatch_mode_from_i64(value: i64) -> Result<RubyMethodDispatchMode> {
    match value {
        0 => Ok(RubyMethodDispatchMode::Instance),
        1 => Ok(RubyMethodDispatchMode::Singleton),
        2 => Ok(RubyMethodDispatchMode::ModuleFunction),
        other => Err(StoreError::new(format!(
            "unknown persisted Ruby dispatch mode {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::cpp::CppAdapter;
    use crate::analyzer::go::GoAdapter;
    use crate::analyzer::java::JavaAdapter;
    use crate::analyzer::php::PhpAdapter;
    use crate::analyzer::python::PythonAdapter;
    use crate::analyzer::ruby::RubyAdapter;
    use crate::analyzer::rust::RustAdapter;
    use crate::analyzer::scala::ScalaAdapter;
    use crate::analyzer::tree_sitter_analyzer::ParsedFile;
    use crate::analyzer::typescript::TypescriptAdapter;
    use crate::gitblob::test_repo::{commit_all, init_repo};
    use git2::ObjectType;
    use tree_sitter::Parser;

    #[test]
    fn explicit_root_rust_unit_persists_full_identity_despite_empty_qualifier() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "src/tools/clippy/tests/ui/from_over_into.rs",
            "struct ExplicitPaths;\n",
        );
        let unit = CodeUnit::with_signature(
            file.clone(),
            CodeUnitType::Function,
            "",
            "ExplicitPaths.into",
            Some(
                "impl core::convert::Into<bool> for crate::ExplicitPaths::fn into(self) -> bool { ... }"
                    .to_string(),
            ),
            false,
        );
        let adapter = RustAdapter;
        let content_qualifier = adapter.storage_content_qualifier(&unit, "");

        assert!(content_qualifier.is_empty());
        let encoded = encode_unit_fq_segments(&adapter, &unit, &content_qualifier).unwrap();
        assert_eq!(encoded[4], FQ_SEGMENTS_FULL);
        let (hydrated_fq, hydrated_package_segment_count) =
            hydrate_unit_fq(&adapter, Some(&encoded), &content_qualifier, &file).unwrap();
        assert_eq!(hydrated_fq, unit.fq().clone());
        assert_eq!(hydrated_package_segment_count, 0);
    }

    #[test]
    fn signature_metadata_blob_admission_has_a_fixed_byte_cap() {
        let ordinary = SignatureMetadata::new("fn make() -> Service", Vec::new());
        assert!(
            !serialize_signature_metadata_blob(&ordinary)
                .expect("serialize ordinary metadata")
                .is_empty()
        );

        let oversized =
            SignatureMetadata::new("x".repeat(MAX_SIGNATURE_METADATA_BLOB_BYTES), Vec::new());
        assert!(
            serialize_signature_metadata_blob(&oversized)
                .expect_err("oversized metadata must fail before allocation")
                .to_string()
                .contains("exceeding"),
            "oversized signature metadata must fail the non-allocating size preflight"
        );
    }

    #[test]
    fn bounded_regression_oversized_signature_metadata_cannot_publish_a_complete_blob() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "factory.rb",
            "class Factory\n  def make(value)\n    value\n  end\nend\n",
        );
        let source = file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let mut state = parse_state(&RubyAdapter, &file);
        let target = state
            .signature_metadata
            .keys()
            .next()
            .cloned()
            .expect("fixture should produce signature metadata");
        state.signature_metadata.insert(
            target,
            vec![SignatureMetadata::new(
                "x".repeat(MAX_SIGNATURE_METADATA_BLOB_BYTES),
                Vec::new(),
            )],
        );
        let state = Arc::new(state);
        let store = AnalyzerStore::open_in_memory().unwrap();
        let generation = store
            .ensure_language_epoch_value("ruby", "oversized-signature-metadata-write-v1")
            .unwrap();

        let prepare_error = AnalyzerStore::prepare_parsed_blob(
            oid,
            "ruby",
            generation,
            &RubyAdapter,
            Arc::clone(&state),
        )
        .expect_err("preparation must reject oversized signature metadata");
        assert!(prepare_error.to_string().contains("exceeding"));

        let write_error = store
            .write_parsed_blob_at_generation(oid, "ruby", generation, &RubyAdapter, state.as_ref())
            .expect_err("direct persistence must reject oversized signature metadata");
        assert!(write_error.to_string().contains("exceeding"));
        assert!(
            !store
                .contains_parsed_blob_at_generation(oid, "ruby", generation)
                .unwrap(),
            "a rejected metadata row must roll back instead of publishing a complete omission"
        );
    }

    #[test]
    fn resource_bound_oversized_current_epoch_signature_metadata_fails_closed() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "factory.rb",
            "class Service\nend\nclass Factory\n  def make(value)\n    Service.new\n  end\nend\n",
        );
        let source = file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let state = parse_state(&RubyAdapter, &file);
        let target = state
            .signature_metadata
            .iter()
            .find(|(_, metadata)| !metadata.is_empty())
            .map(|(unit, _)| unit.clone())
            .expect("fixture should produce signature metadata");
        let store = AnalyzerStore::open_in_memory().unwrap();
        let generation = store
            .ensure_language_epoch_value("ruby", "oversized-signature-metadata-v1")
            .unwrap();
        store
            .write_parsed_blob_at_generation(oid, "ruby", generation, &RubyAdapter, &state)
            .unwrap();

        let oversized_len = MAX_SIGNATURE_METADATA_BLOB_BYTES + 1;
        {
            let conn = store.conn.lock().unwrap();
            let unit_key: i64 = conn
                .query_row(
                    "SELECT metadata.unit_key
                     FROM unit_signature_metadata AS metadata
                     JOIN code_units AS units
                       ON units.blob_oid = metadata.blob_oid
                      AND units.lang = metadata.lang
                     AND units.unit_key = metadata.unit_key
                     WHERE units.blob_oid = ?1
                       AND units.lang = 'ruby'
                       AND units.exact_fqn = ?2
                       AND units.kind = ?3
                       AND units.short_name = ?4
                       AND units.signature IS ?5
                       AND units.synthetic = ?6
                     ORDER BY metadata.ordinal
                     LIMIT 1",
                    params![
                        oid.to_string(),
                        target.fq_name(),
                        code_unit_kind_to_i64(target.kind()),
                        target.short_name(),
                        target.signature(),
                        bool_to_i64(target.is_synthetic()),
                    ],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(
                conn.execute(
                    "UPDATE unit_signature_metadata
                     SET metadata = zeroblob(?3)
                     WHERE blob_oid = ?1
                       AND lang = 'ruby'
                       AND unit_key = ?2
                       AND ordinal = 0",
                    params![
                        oid.to_string(),
                        unit_key,
                        i64::try_from(oversized_len).unwrap()
                    ],
                )
                .unwrap(),
                1
            );
            assert_eq!(
                conn.query_row(
                    "SELECT length(metadata)
                     FROM unit_signature_metadata
                     WHERE blob_oid = ?1
                       AND lang = 'ruby'
                       AND unit_key = ?2
                       AND ordinal = 0",
                    params![oid.to_string(), unit_key],
                    |row| row.get::<_, usize>(0),
                )
                .unwrap(),
                oversized_len
            );
        }

        assert!(
            store
                .usage_fact_rows_by_lang("ruby")
                .unwrap_err()
                .to_string()
                .contains("signature metadata blob exceeds"),
            "usage-fact projection must reject the oversized row without materializing it"
        );
        assert!(
            store
                .hydrate_file_state_with_source(
                    oid,
                    "ruby",
                    generation,
                    &RubyAdapter,
                    &file,
                    &source,
                )
                .unwrap()
                .is_none(),
            "full hydration must skip the oversized row and fail its side-table count"
        );
        assert!(
            !store
                .hydrate_file_states(
                    &[(file.clone(), oid)],
                    "ruby",
                    &RubyAdapter,
                    &HashMap::from_iter([(file.clone(), source)]),
                )
                .unwrap()
                .contains_key(&file),
            "bulk hydration must skip the oversized row and fail its side-table count"
        );
        let limited = store
            .signature_metadata_for_unit_limited(oid, "ruby", generation, &target, usize::MAX)
            .unwrap();
        assert!(!limited.complete);
        assert!(limited.rows.is_empty());
        assert_eq!(limited.inspected, 1);
    }

    #[test]
    fn limited_query_byte_budget_caps_individual_and_aggregate_rows() {
        let mut bytes = LimitedQueryByteBudget::default();
        let half = MAX_LIMITED_QUERY_AGGREGATE_BYTES / 2;
        assert!(
            bytes
                .admit_sqlite_bytes(usize_to_i64(half).unwrap())
                .unwrap()
        );
        assert!(
            bytes
                .admit_sqlite_bytes(usize_to_i64(half).unwrap())
                .unwrap()
        );
        assert!(!bytes.admit_sqlite_bytes(1).unwrap());

        let mut bytes = LimitedQueryByteBudget::default();
        assert!(
            !bytes
                .admit_sqlite_bytes(usize_to_i64(MAX_LIMITED_QUERY_ROW_BYTES + 1).unwrap())
                .unwrap()
        );
    }

    #[test]
    fn resource_bound_oversized_current_epoch_content_package_fails_closed() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "Target.java",
            "package demo;\nclass Target {}\n",
        );
        let state = parse_state(&JavaAdapter, &file);
        let oid = oid_for(state.source.as_bytes());
        let store = AnalyzerStore::open_in_memory().unwrap();
        let generation = store
            .ensure_language_epoch_value("java", "limited-content-package-row-bytes-v1")
            .unwrap();
        store
            .write_parsed_blob_at_generation(oid, "java", generation, &JavaAdapter, &state)
            .unwrap();

        let ordinary = store
            .content_package_limited(oid, "java", generation, 1)
            .unwrap();
        assert!(ordinary.complete);
        assert_eq!(ordinary.rows, vec!["demo".to_string()]);
        assert_eq!(ordinary.inspected, 1);

        {
            let conn = store.conn.lock().unwrap();
            assert_eq!(
                conn.execute(
                    "UPDATE blob_meta
                     SET content_package = CAST(zeroblob(?3) AS TEXT)
                     WHERE blob_oid = ?1 AND lang = ?2",
                    params![
                        oid.to_string(),
                        "java",
                        usize_to_i64(MAX_LIMITED_QUERY_ROW_BYTES + 1).unwrap(),
                    ],
                )
                .unwrap(),
                1
            );
        }

        let limited = store
            .content_package_limited(oid, "java", generation, 1)
            .unwrap();
        assert!(!limited.complete);
        assert!(limited.rows.is_empty());
        assert_eq!(limited.inspected, 1);
    }

    #[test]
    fn resource_bound_oversized_current_epoch_fallback_qualifier_fails_closed() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "Target.java",
            "package demo;\nclass Target {}\n",
        );
        let state = parse_state(&JavaAdapter, &file);
        let oid = oid_for(state.source.as_bytes());
        let store = AnalyzerStore::open_in_memory().unwrap();
        let generation = store
            .ensure_language_epoch_value("java", "limited-fallback-qualifier-row-bytes-v1")
            .unwrap();
        store
            .write_parsed_blob_at_generation(oid, "java", generation, &JavaAdapter, &state)
            .unwrap();

        let ordinary = store
            .first_declaration_content_qualifier_for_key_limited(
                oid,
                "java",
                generation,
                usize::MAX,
            )
            .unwrap();
        assert!(ordinary.complete);
        assert_eq!(ordinary.rows, vec!["demo".to_string()]);
        assert!(ordinary.inspected > 0);
        let rows_before_qualifier = ordinary.inspected;

        {
            let conn = store.conn.lock().unwrap();
            assert_eq!(
                conn.execute(
                    "UPDATE blob_meta
                     SET content_package = ''
                     WHERE blob_oid = ?1 AND lang = ?2",
                    params![oid.to_string(), "java"],
                )
                .unwrap(),
                1
            );
            assert_eq!(
                conn.execute(
                    "UPDATE code_units
                     SET content_qualifier = CAST(zeroblob(?3) AS TEXT)
                     WHERE blob_oid = ?1 AND lang = ?2
                       AND unit_key = (
                         SELECT MIN(candidate.unit_key)
                         FROM code_units AS candidate
                         WHERE candidate.blob_oid = ?1
                           AND candidate.lang = ?2
                           AND candidate.content_qualifier <> ''
                       )",
                    params![
                        oid.to_string(),
                        "java",
                        usize_to_i64(MAX_LIMITED_QUERY_ROW_BYTES + 1).unwrap(),
                    ],
                )
                .unwrap(),
                1
            );
        }

        let package = store
            .content_package_limited(oid, "java", generation, 1)
            .unwrap();
        assert!(package.complete);
        assert_eq!(package.rows, vec![String::new()]);
        assert_eq!(package.inspected, 1);

        let limited = store
            .first_declaration_content_qualifier_for_key_limited(
                oid,
                "java",
                generation,
                usize::MAX,
            )
            .unwrap();
        assert!(!limited.complete);
        assert!(limited.rows.is_empty());
        assert_eq!(limited.inspected, rows_before_qualifier);
    }

    #[test]
    fn limited_fallback_qualifier_charges_empty_rows_before_evidence() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "Target.java",
            "class Target { void first() {} void second() {} }\n",
        );
        let state = parse_state(&JavaAdapter, &file);
        let oid = oid_for(state.source.as_bytes());
        let store = AnalyzerStore::open_in_memory().unwrap();
        let generation = store
            .ensure_language_epoch_value("java", "limited-fallback-qualifier-scan-v1")
            .unwrap();
        store
            .write_parsed_blob_at_generation(oid, "java", generation, &JavaAdapter, &state)
            .unwrap();

        {
            let conn = store.conn.lock().unwrap();
            let unit_count: usize = conn
                .query_row(
                    "SELECT COUNT(*) FROM code_units
                     WHERE blob_oid = ?1 AND lang = ?2",
                    params![oid.to_string(), "java"],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(unit_count >= 2, "fixture needs two ordered persisted units");
            assert_eq!(
                conn.execute(
                    "UPDATE code_units
                     SET content_qualifier = CASE
                         WHEN unit_key = (
                             SELECT candidate.unit_key
                             FROM code_units AS candidate
                             WHERE candidate.blob_oid = ?1 AND candidate.lang = ?2
                             ORDER BY candidate.unit_key
                             LIMIT 1
                         ) THEN ''
                         WHEN unit_key = (
                             SELECT candidate.unit_key
                             FROM code_units AS candidate
                             WHERE candidate.blob_oid = ?1 AND candidate.lang = ?2
                             ORDER BY candidate.unit_key
                             LIMIT 1 OFFSET 1
                         ) THEN 'late.namespace'
                         ELSE content_qualifier
                     END
                     WHERE blob_oid = ?1 AND lang = ?2",
                    params![oid.to_string(), "java"],
                )
                .unwrap(),
                unit_count
            );
        }

        let tiny = store
            .first_declaration_content_qualifier_for_key_limited(oid, "java", generation, 1)
            .unwrap();
        assert!(!tiny.complete);
        assert!(tiny.rows.is_empty());
        assert_eq!(tiny.inspected, 1);

        let sufficient = store
            .first_declaration_content_qualifier_for_key_limited(oid, "java", generation, 2)
            .unwrap();
        assert!(sufficient.complete);
        assert_eq!(sufficient.rows, vec!["late.namespace".to_string()]);
        assert_eq!(sufficient.inspected, 2);
    }

    #[test]
    fn resource_bound_oversized_current_epoch_import_row_fails_closed() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "main.go",
            "package sample\nimport \"fmt\"\nfunc run() { fmt.Println(\"ok\") }\n",
        );
        let state = parse_state(&GoAdapter, &file);
        assert_eq!(state.imports.len(), 1, "fixture should persist one import");
        let oid = oid_for(state.source.as_bytes());
        let store = AnalyzerStore::open_in_memory().unwrap();
        let generation = store
            .ensure_language_epoch_value("go", "limited-import-row-bytes-v1")
            .unwrap();
        store
            .write_parsed_blob_at_generation(oid, "go", generation, &GoAdapter, &state)
            .unwrap();
        let ordinary = store
            .import_infos_for_key_limited(oid, "go", generation, usize::MAX)
            .unwrap();
        assert!(ordinary.complete);
        assert_eq!(ordinary.rows, state.imports);

        {
            let conn = store.conn.lock().unwrap();
            assert_eq!(
                conn.execute(
                    "UPDATE import_details
                     SET info = zeroblob(?3)
                     WHERE blob_oid = ?1 AND lang = ?2",
                    params![
                        oid.to_string(),
                        "go",
                        usize_to_i64(MAX_LIMITED_QUERY_ROW_BYTES + 1).unwrap(),
                    ],
                )
                .unwrap(),
                1
            );
        }

        let limited = store
            .import_infos_for_key_limited(oid, "go", generation, usize::MAX)
            .unwrap();
        assert!(!limited.complete);
        assert!(limited.rows.is_empty());
        assert_eq!(limited.inspected, 1);
    }

    #[test]
    fn resource_bound_inconsistent_current_epoch_import_count_fails_closed() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "main.go",
            "package sample\nimport (\n  \"fmt\"\n  \"os\"\n)\nfunc run() { fmt.Println(os.Args) }\n",
        );
        let state = parse_state(&GoAdapter, &file);
        assert_eq!(state.imports.len(), 2, "fixture should persist two imports");
        let oid = oid_for(state.source.as_bytes());
        let store = AnalyzerStore::open_in_memory().unwrap();
        let generation = store
            .ensure_language_epoch_value("go", "limited-import-count-integrity-v1")
            .unwrap();
        store
            .write_parsed_blob_at_generation(oid, "go", generation, &GoAdapter, &state)
            .unwrap();

        {
            let conn = store.conn.lock().unwrap();
            assert_eq!(
                conn.execute(
                    "UPDATE blob_meta
                     SET import_count = 1
                     WHERE blob_oid = ?1 AND lang = ?2",
                    params![oid.to_string(), "go"],
                )
                .unwrap(),
                1
            );
        }

        let capped = store
            .import_infos_for_key_limited(oid, "go", generation, 1)
            .unwrap();
        assert!(!capped.complete);
        assert_eq!(capped.rows.len(), 1);
        assert_eq!(capped.inspected, 1);

        let wider = store
            .import_infos_for_key_limited(oid, "go", generation, 3)
            .unwrap();
        assert!(!wider.complete);
        assert_eq!(wider.rows.len(), 2);
        assert_eq!(wider.inspected, 2);
    }

    #[test]
    fn resource_bound_oversized_current_epoch_supertype_rows_fail_closed() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "Hierarchy.scala",
            "package demo\nclass Parent\nclass Child extends Parent\n",
        );
        let state = parse_state(&ScalaAdapter, &file);
        let target = state
            .raw_supertypes
            .iter()
            .find(|(_, supertypes)| !supertypes.is_empty())
            .map(|(unit, _)| unit.clone())
            .expect("fixture should persist a raw supertype");
        assert!(
            state
                .supertype_lookup_paths
                .get(&target)
                .is_some_and(|paths| !paths.is_empty()),
            "fixture should persist a supertype lookup path"
        );
        let oid = oid_for(state.source.as_bytes());
        let store = AnalyzerStore::open_in_memory().unwrap();
        let generation = store
            .ensure_language_epoch_value("scala", "limited-supertype-row-bytes-v1")
            .unwrap();
        store
            .write_parsed_blob_at_generation(oid, "scala", generation, &ScalaAdapter, &state)
            .unwrap();
        let oversized = usize_to_i64(MAX_LIMITED_QUERY_ROW_BYTES + 1).unwrap();

        {
            let conn = store.conn.lock().unwrap();
            assert_eq!(
                conn.execute(
                    "UPDATE unit_supertypes
                     SET raw = CAST(zeroblob(?3) AS TEXT)
                     WHERE blob_oid = ?1 AND lang = ?2",
                    params![oid.to_string(), "scala", oversized],
                )
                .unwrap(),
                1
            );
        }
        let raw = store
            .raw_supertypes_for_unit_limited(oid, "scala", generation, &target, usize::MAX)
            .unwrap();
        assert!(!raw.complete);
        assert!(raw.rows.is_empty());
        assert_eq!(raw.inspected, 1);

        {
            let conn = store.conn.lock().unwrap();
            assert_eq!(
                conn.execute(
                    "UPDATE unit_supertypes
                     SET lookup_path = CAST(zeroblob(?3) AS TEXT)
                     WHERE blob_oid = ?1 AND lang = ?2",
                    params![oid.to_string(), "scala", oversized],
                )
                .unwrap(),
                1
            );
        }
        let lookup_paths = store
            .supertype_lookup_paths_for_unit_limited(oid, "scala", generation, &target, usize::MAX)
            .unwrap();
        assert!(!lookup_paths.complete);
        assert!(lookup_paths.rows.is_empty());
        assert_eq!(lookup_paths.inspected, 1);
    }

    #[test]
    fn resource_bound_oversized_current_epoch_candidate_row_fails_closed() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "Target.java",
            "class Target { void run() {} }\n",
        );
        let state = parse_state(&JavaAdapter, &file);
        let oid = oid_for(state.source.as_bytes());
        let store = AnalyzerStore::open_in_memory().unwrap();
        let generation = store
            .ensure_language_epoch_value("java", "limited-candidate-row-bytes-v1")
            .unwrap();
        store
            .write_parsed_blob_at_generation(oid, "java", generation, &JavaAdapter, &state)
            .unwrap();

        {
            let conn = store.conn.lock().unwrap();
            assert_eq!(
                conn.execute(
                    "UPDATE code_units
                     SET signature = CAST(zeroblob(?3) AS TEXT)
                     WHERE blob_oid = ?1 AND lang = ?2 AND identifier = 'Target'",
                    params![
                        oid.to_string(),
                        "java",
                        usize_to_i64(MAX_LIMITED_QUERY_ROW_BYTES + 1).unwrap(),
                    ],
                )
                .unwrap(),
                1
            );
        }

        let langs = vec!["java".to_string()];
        let generations = HashMap::from_iter([("java".to_string(), generation)]);
        let limited = store
            .declaration_candidate_rows_by_identifier_for_langs_limited(
                &langs,
                &generations,
                "Target",
                usize::MAX,
            )
            .unwrap();
        assert!(!limited.complete);
        assert!(limited.rows.is_empty());
        assert_eq!(limited.inspected, 1);
    }

    /// The actionable cache-denial message reaches the workspace entry point,
    /// not just the SQLite open it wraps (issue #1544).
    #[test]
    #[cfg(unix)]
    fn unwritable_workspace_root_reports_the_ways_out() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::TempDir::new().unwrap();
        let workspace_root = temp.path().join("repo");
        std::fs::create_dir(&workspace_root).unwrap();
        git2::Repository::init(&workspace_root).unwrap();
        std::fs::set_permissions(&workspace_root, std::fs::Permissions::from_mode(0o555)).unwrap();

        let opened = AnalyzerStore::open_for_workspace(&workspace_root);
        let error = match opened {
            Ok(_) => panic!("an unwritable workspace root must not open a persisted store"),
            Err(error) => error,
        };

        // Restored before any assertion can fail, so the tempdir still cleans up.
        std::fs::set_permissions(&workspace_root, std::fs::Permissions::from_mode(0o755)).unwrap();

        let message = error.to_string();
        assert!(
            message.contains("permission denied for")
                && message.contains(&workspace_root.display().to_string())
                && message.contains("elevated filesystem permissions"),
            "{message}"
        );
    }

    #[test]
    fn non_git_root_uses_in_memory_store_and_roundtrips_registry() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = AnalyzerStore::open_for_workspace(temp.path()).unwrap();
        assert!(store.is_in_memory());
        assert!(store.db_path().is_none());

        let one = Oid::hash_object(ObjectType::Blob, b"one").unwrap();
        let two = Oid::hash_object(ObjectType::Blob, b"two").unwrap();
        assert_eq!(
            store.missing_blobs(&[one, two], "rust").unwrap(),
            vec![one, two]
        );

        store
            .register_blobs(&[one], "rust", GenerationId::BOOTSTRAP)
            .unwrap();
        store
            .register_blobs(&[one], "rust", GenerationId::BOOTSTRAP)
            .unwrap();
        assert_eq!(store.missing_blobs(&[one, two], "rust").unwrap(), vec![two]);
        assert_eq!(store.missing_blobs(&[one], "python").unwrap(), vec![one]);
    }

    #[test]
    fn concurrent_mixed_reads_against_one_warm_persistent_store() {
        use std::sync::atomic::{AtomicBool, Ordering};

        // A persistent store exercises the reader pool (`source = Some`): pure
        // reads run on checked-out read-only connections, not the writer mutex.
        let temp = tempfile::TempDir::new().unwrap();
        let db_path = temp.path().join("bifrost_cache.db");
        let store = Arc::new(AnalyzerStore::open_persistent(&db_path).unwrap());

        // Warm the store with one committed Java blob.
        let file = write_file(
            temp.path(),
            "Widget.java",
            "class Widget { int value; void run() {} }\n",
        );
        let state = Arc::new(parse_state(&JavaAdapter, &file));
        let oid = oid_for(state.source.as_bytes());
        let generation = store
            .ensure_language_epoch_value("java", "concurrent-smoke-v1")
            .unwrap();
        store
            .write_parsed_blob_at_generation(oid, "java", generation, &JavaAdapter, state.as_ref())
            .unwrap();

        let langs = vec!["java".to_string()];
        let mut generations = HashMap::default();
        generations.insert("java".to_string(), generation);

        // Single-threaded baseline: the warm reads return the expected rows.
        let baseline = store
            .declaration_candidate_rows_by_short_name_for_langs(&langs, &generations, "Widget")
            .unwrap();
        assert!(baseline.iter().any(|row| row.short_name == "Widget"));

        let stop = Arc::new(AtomicBool::new(false));

        // Writer thread: persist additional distinct blobs through the single
        // writer connection while the readers hammer their pooled readers.
        let writer = {
            let store = Arc::clone(&store);
            let stop = Arc::clone(&stop);
            let root = temp.path().to_path_buf();
            std::thread::spawn(move || {
                let mut index = 0u32;
                while !stop.load(Ordering::Relaxed) {
                    let src = format!("class Extra{index} {{ int f{index}; }}\n");
                    let extra = write_file(&root, &format!("Extra{index}.java"), &src);
                    let extra_state = parse_state(&JavaAdapter, &extra);
                    let extra_oid = oid_for(extra_state.source.as_bytes());
                    store
                        .write_parsed_blob_at_generation(
                            extra_oid,
                            "java",
                            generation,
                            &JavaAdapter,
                            &extra_state,
                        )
                        .unwrap();
                    index += 1;
                }
            })
        };

        // Reader threads: mixed definitions lookup + hydration + search, each
        // asserting the warm Widget rows are always visible.
        let mut readers = Vec::new();
        for _ in 0..8 {
            let store = Arc::clone(&store);
            let langs = langs.clone();
            let generations = generations.clone();
            let file = file.clone();
            readers.push(std::thread::spawn(move || {
                for _ in 0..200 {
                    let rows = store
                        .declaration_candidate_rows_by_short_name_for_langs(
                            &langs,
                            &generations,
                            "Widget",
                        )
                        .unwrap();
                    assert!(rows.iter().any(|row| row.short_name == "Widget"));

                    let hydrated = store
                        .hydrate_file_states(
                            &[(file.clone(), oid)],
                            "java",
                            &JavaAdapter,
                            &HashMap::default(),
                        )
                        .unwrap();
                    assert!(hydrated.contains_key(&file));

                    let search = store.search_candidate_rows_by_lang("java").unwrap();
                    assert!(
                        search
                            .iter()
                            .any(|row| row.candidate.short_name == "Widget")
                    );
                }
            }));
        }

        for reader in readers {
            reader.join().expect("reader thread panicked");
        }
        stop.store(true, Ordering::Relaxed);
        writer.join().expect("writer thread panicked");

        // The concurrently persisted blobs are all visible after the fact.
        let widgets = store
            .declaration_candidate_rows_by_short_name_for_langs(&langs, &generations, "Widget")
            .unwrap();
        assert!(widgets.iter().any(|row| row.short_name == "Widget"));
    }

    #[test]
    fn parsed_blob_presence_requires_completed_parse_rows() {
        let store = AnalyzerStore::open_in_memory().unwrap();
        let oid = Oid::hash_object(ObjectType::Blob, b"class Registered:\n    pass\n").unwrap();

        store
            .register_blobs(&[oid], "python", GenerationId::BOOTSTRAP)
            .unwrap();

        assert!(store.contains_blob(oid, "python").unwrap());
        assert!(!store.contains_parsed_blob(oid, "python").unwrap());
        assert_eq!(
            store
                .missing_parsed_blob_keys(&[(oid, "python".to_string())])
                .unwrap(),
            vec![(oid, "python".to_string())]
        );
    }

    #[test]
    fn scala_empty_lambda_parser_epoch_invalidates_prior_parsed_blobs() {
        // This is the Scala epoch immediately before issue #1068's parser-table
        // change. The change does not add an ABI, node-kind, or field name, so
        // the manual vendored-parser salt must invalidate old parsed blobs.
        const PRE_EMPTY_LAMBDA_EPOCH: &str =
            "68da221d12ed704b76c78dfe72b57f6eca7064aaa95ca39af8bcdcca1c2d1a29";

        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "VCSSpec.scala",
            "class VCSSpec { def run(): Unit = simulation.run() { _ => }; def after = 1 }\n",
        );
        let state = Arc::new(parse_state(&ScalaAdapter, &file));
        let oid = oid_for(state.source.as_bytes());
        let store = AnalyzerStore::open_in_memory().unwrap();
        let prior_generation = store
            .ensure_language_epoch_value("scala", PRE_EMPTY_LAMBDA_EPOCH)
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                oid,
                "scala",
                prior_generation,
                &ScalaAdapter,
                state.as_ref(),
            )
            .unwrap();
        assert!(store.contains_parsed_blob(oid, "scala").unwrap());

        let current_generation = store
            .ensure_language_epoch(
                Language::Scala,
                &crate::analyzer::scala::language::LANGUAGE.into(),
            )
            .unwrap();

        assert_ne!(current_generation, prior_generation);
        assert!(!store.contains_parsed_blob(oid, "scala").unwrap());
        assert_eq!(
            store
                .missing_parsed_blob_keys(&[(oid, "scala".to_string())])
                .unwrap(),
            vec![(oid, "scala".to_string())]
        );
    }

    #[test]
    fn structural_snapshot_roundtrips_replaces_and_updates_cascade_costs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(temp.path(), "Model.java", "class Model { int value; }\n");
        let state = Arc::new(parse_state(&JavaAdapter, &file));
        let oid = oid_for(state.source.as_bytes());
        let store = AnalyzerStore::open_in_memory().unwrap();
        let generation = store
            .ensure_language_epoch_value("java", "structural-snapshot-v1")
            .unwrap();
        store
            .write_parsed_blob_at_generation(oid, "java", generation, &JavaAdapter, state.as_ref())
            .unwrap();
        let prepared = AnalyzerStore::prepare_parsed_blob(
            oid,
            "java",
            generation,
            &JavaAdapter,
            Arc::clone(&state),
        )
        .unwrap();

        assert_eq!(
            store
                .load_structural_facts_snapshot(oid, "java", generation, 1)
                .unwrap(),
            None
        );
        let first = b"first structural snapshot";
        assert!(
            store
                .upsert_structural_facts_snapshot(oid, "java", generation, 1, first)
                .unwrap()
        );
        assert_eq!(
            store
                .load_structural_facts_snapshot(oid, "java", generation, 1)
                .unwrap()
                .as_deref(),
            Some(first.as_slice())
        );

        let expected_first = PersistedMutationCost {
            logical_rows: prepared.logical_rows().saturating_add(1),
            payload_bytes: prepared
                .persisted_payload_bytes()
                .saturating_add(first.len()),
        };
        {
            let conn = store.conn.lock().expect("store mutex");
            assert_eq!(
                store
                    .stored_blob_cascade_costs(&conn, std::slice::from_ref(&prepared))
                    .unwrap(),
                vec![StoredCascadeCost::Known(expected_first)]
            );
        }

        let second = b"second";
        assert!(
            store
                .upsert_structural_facts_snapshot(oid, "java", generation, 2, second)
                .unwrap()
        );
        assert_eq!(
            store
                .load_structural_facts_snapshot(oid, "java", generation, 1)
                .unwrap(),
            None
        );
        assert_eq!(
            store
                .load_structural_facts_snapshot(oid, "java", generation, 2)
                .unwrap()
                .as_deref(),
            Some(second.as_slice())
        );
        let conn = store.conn.lock().expect("store mutex");
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM structural_facts_snapshots
                 WHERE blob_oid = ?1 AND lang = 'java'",
                [oid.to_string()],
                |row| row.get::<_, usize>(0),
            )
            .unwrap(),
            1,
            "old semantic versions must not accumulate"
        );
        assert_eq!(
            conn.query_row(
                "SELECT payload_bytes FROM blob_payload_costs
                 WHERE blob_oid = ?1 AND lang = 'java'",
                [oid.to_string()],
                |row| row.get::<_, usize>(0),
            )
            .unwrap(),
            prepared
                .persisted_payload_bytes()
                .saturating_add(second.len())
        );
        conn.execute(
            "DELETE FROM blob_payload_costs WHERE blob_oid = ?1 AND lang = 'java'",
            [oid.to_string()],
        )
        .unwrap();
        drop(conn);

        let repaired = b"repaired legacy payload cost";
        assert!(
            store
                .upsert_structural_facts_snapshot(oid, "java", generation, 3, repaired)
                .unwrap()
        );
        assert_eq!(
            store
                .conn
                .lock()
                .expect("store mutex")
                .query_row(
                    "SELECT payload_bytes FROM blob_payload_costs
                     WHERE blob_oid = ?1 AND lang = 'java'",
                    [oid.to_string()],
                    |row| row.get::<_, usize>(0),
                )
                .unwrap(),
            prepared
                .persisted_payload_bytes()
                .saturating_add(repaired.len()),
            "a missing legacy cost row must be recomputed with snapshot bytes"
        );

        store
            .write_parsed_blob_at_generation(oid, "java", generation, &JavaAdapter, state.as_ref())
            .unwrap();
        assert_eq!(
            store
                .load_structural_facts_snapshot(oid, "java", generation, 3)
                .unwrap(),
            None,
            "replacing the parsed blob must cascade-delete its snapshot"
        );
    }

    #[test]
    fn structural_snapshot_requires_current_complete_parent_generation() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(temp.path(), "Model.java", "class Model {}\n");
        let state = parse_state(&JavaAdapter, &file);
        let oid = oid_for(state.source.as_bytes());
        let store = AnalyzerStore::open_in_memory().unwrap();
        let old_generation = store
            .ensure_language_epoch_value("java", "snapshot-old-generation")
            .unwrap();
        store
            .write_parsed_blob_at_generation(oid, "java", old_generation, &JavaAdapter, &state)
            .unwrap();
        store.mark_parsed_blob_incomplete_for_test(oid, "java");
        assert!(
            !store
                .upsert_structural_facts_snapshot(oid, "java", old_generation, 1, b"ignored",)
                .unwrap()
        );
        assert_eq!(
            store
                .load_structural_facts_snapshot(oid, "java", old_generation, 1)
                .unwrap(),
            None
        );

        let current_generation = store
            .ensure_language_epoch_value("java", "snapshot-current-generation")
            .unwrap();
        assert!(
            store
                .load_structural_facts_snapshot(oid, "java", old_generation, 1)
                .unwrap_err()
                .is_stale_generation()
        );
        assert!(
            store
                .upsert_structural_facts_snapshot(oid, "java", old_generation, 1, b"stale",)
                .unwrap_err()
                .is_stale_generation()
        );
        assert!(
            !store
                .upsert_structural_facts_snapshot(
                    oid,
                    "java",
                    current_generation,
                    1,
                    b"no current parent",
                )
                .unwrap()
        );
    }

    #[test]
    fn parsed_blob_keys_batches_mixed_languages_and_incomplete_rows() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let python_file = write_file(root, "pkg/model.py", "class Model:\n    pass\n");
        let java_file = write_file(root, "src/Model.java", "class Model {}\n");
        let python_oid = oid_for(python_file.read_to_string().unwrap().as_bytes());
        let java_oid = oid_for(java_file.read_to_string().unwrap().as_bytes());
        let incomplete_oid = oid_for(b"registered but not parsed");
        let missing_oid = oid_for(b"not registered");
        let store = AnalyzerStore::open_in_memory().unwrap();
        store
            .write_parsed_blob(
                python_oid,
                "python",
                &PythonAdapter,
                &parse_state(&PythonAdapter, &python_file),
            )
            .unwrap();
        store
            .write_parsed_blob(
                java_oid,
                "java",
                &JavaAdapter,
                &parse_state(&JavaAdapter, &java_file),
            )
            .unwrap();
        store
            .register_blobs(&[incomplete_oid], "rust", GenerationId::BOOTSTRAP)
            .unwrap();

        let mut entries = vec![
            (python_oid, "python".to_string()),
            (python_oid, "java".to_string()),
            (java_oid, "java".to_string()),
            (incomplete_oid, "rust".to_string()),
            (missing_oid, "python".to_string()),
            (python_oid, "python".to_string()),
        ];
        let bulk_missing = (0..405)
            .map(|index| oid_for(format!("bulk missing {index}").as_bytes()))
            .collect::<Vec<_>>();
        entries.extend(bulk_missing.iter().map(|oid| (*oid, "python".to_string())));
        assert_eq!(
            store.parsed_blob_keys(&entries).unwrap(),
            [
                (python_oid, "python".to_string()),
                (java_oid, "java".to_string()),
            ]
            .into_iter()
            .collect::<HashSet<_>>()
        );
        let missing = store.missing_parsed_blob_keys(&entries).unwrap();
        assert_eq!(missing.len(), 408);
        assert!(missing.contains(&(python_oid, "java".to_string())));
        assert!(missing.contains(&(incomplete_oid, "rust".to_string())));
        assert!(missing.contains(&(missing_oid, "python".to_string())));
        assert!(
            bulk_missing
                .iter()
                .all(|oid| missing.contains(&(*oid, "python".to_string())))
        );
        let generations = ["python", "java", "rust"]
            .into_iter()
            .map(|lang| (lang.to_string(), GenerationId::BOOTSTRAP))
            .collect();
        let startup_missing = store
            .missing_parsed_blob_keys_at_generations(&entries, &generations)
            .unwrap();
        assert_eq!(startup_missing, missing);
    }

    #[test]
    fn active_symbol_candidate_tables_are_isolated_between_concurrent_readers() {
        let temp = tempfile::TempDir::new().unwrap();
        let alpha_file = write_file(
            temp.path(),
            "alpha/AlphaService.java",
            "package alpha; class AlphaService { void run() {} }\n",
        );
        let beta_file = write_file(
            temp.path(),
            "beta/BetaService.java",
            "package beta; class BetaService { void run() {} }\n",
        );
        let alpha_oid = oid_for(alpha_file.read_to_string().unwrap().as_bytes());
        let beta_oid = oid_for(beta_file.read_to_string().unwrap().as_bytes());
        let store =
            Arc::new(AnalyzerStore::open_persistent(&temp.path().join("cache.db")).unwrap());
        for (oid, file) in [(alpha_oid, &alpha_file), (beta_oid, &beta_file)] {
            store
                .write_parsed_blob(oid, "java", &JavaAdapter, &parse_state(&JavaAdapter, file))
                .unwrap();
        }
        let generations = Arc::new(
            [("java".to_string(), GenerationId::BOOTSTRAP)]
                .into_iter()
                .collect::<HashMap<_, _>>(),
        );
        let barrier = Arc::new(std::sync::Barrier::new(2));

        std::thread::scope(|scope| {
            for expected_oid in [alpha_oid, beta_oid] {
                let store = Arc::clone(&store);
                let generations = Arc::clone(&generations);
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    barrier.wait();
                    for _ in 0..10 {
                        let rows = store
                            .search_candidate_name_rows_for_langs(
                                &["java".to_string()],
                                &generations,
                                &[expected_oid],
                                Some(&["Service"]),
                                None,
                            )
                            .unwrap();
                        assert!(rows.complete);
                        assert!(!rows.rows.is_empty());
                        assert!(rows.rows.iter().all(|row| row.blob_oid == expected_oid));
                    }
                });
            }
        });
    }

    #[test]
    fn active_symbol_candidate_scan_batches_languages() {
        let temp = tempfile::TempDir::new().unwrap();
        let java_file = write_file(
            temp.path(),
            "java/Service.java",
            "package java; class Service { void run() {} }\n",
        );
        let rust_file = write_file(temp.path(), "rust/service.rs", "pub fn run() {}\n");
        let java_oid = oid_for(java_file.read_to_string().unwrap().as_bytes());
        let rust_oid = oid_for(rust_file.read_to_string().unwrap().as_bytes());
        let store = AnalyzerStore::open_persistent(&temp.path().join("cache.db")).unwrap();
        store
            .write_parsed_blob(
                java_oid,
                "java",
                &JavaAdapter,
                &parse_state(&JavaAdapter, &java_file),
            )
            .unwrap();
        store
            .write_parsed_blob(
                rust_oid,
                "rust",
                &RustAdapter,
                &parse_state(&RustAdapter, &rust_file),
            )
            .unwrap();

        let languages = vec!["java".to_string(), "rust".to_string()];
        let generations = HashMap::from_iter([
            ("java".to_string(), GenerationId::BOOTSTRAP),
            ("rust".to_string(), GenerationId::BOOTSTRAP),
        ]);
        let rows = store
            .search_candidate_name_rows_for_langs(
                &languages,
                &generations,
                &[java_oid, rust_oid],
                Some(&["run", "Service"]),
                None,
            )
            .unwrap();

        assert!(rows.complete);
        assert!(rows.rows.iter().any(|row| row.lang_index == 0));
        assert!(rows.rows.iter().any(|row| row.lang_index == 1));
    }

    #[test]
    fn generation_map_requires_a_token_for_every_requested_storage_language() {
        let store = AnalyzerStore::open_in_memory().unwrap();
        let typescript = store
            .ensure_language_epoch_value("typescript:ts", "ts-epoch")
            .unwrap();
        store
            .ensure_language_epoch_value("typescript:tsx", "tsx-epoch")
            .unwrap();
        let oid = oid_for(b"mixed ts storage key");
        let mut generations = HashMap::default();
        generations.insert("typescript:ts".to_string(), typescript);

        let error = store
            .parsed_blob_keys_at_generations(
                &[
                    (oid, "typescript:ts".to_string()),
                    (oid, "typescript:tsx".to_string()),
                ],
                &generations,
            )
            .unwrap_err();

        assert!(error.is_stale_generation());
        assert!(error.to_string().contains("missing captured"));
        assert!(error.to_string().contains("typescript:tsx"));
    }

    #[test]
    fn package_prefix_pages_are_literal_and_cursor_bounded() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let adapter = JavaAdapter;
        let store = AnalyzerStore::open_in_memory().unwrap();
        for (path, source) in [
            ("src/a_b/One.java", "package a_b; class One {}\n"),
            (
                "src/a_b/child/Two.java",
                "package a_b.child; class Two {}\n",
            ),
            ("src/aXb/Other.java", "package aXb; class Other {}\n"),
        ] {
            let file = write_file(root, path, source);
            let oid = oid_for(source.as_bytes());
            store
                .write_parsed_blob(oid, "java", &adapter, &parse_state(&adapter, &file))
                .unwrap();
        }

        let first = store
            .declaration_rows_by_package_prefix_page(
                "java",
                GenerationId::BOOTSTRAP,
                "a_b",
                None,
                1,
            )
            .unwrap();
        assert_eq!(first.len(), 1);
        assert!(matches!(
            first[0].content_qualifier.as_str(),
            "a_b" | "a_b.child"
        ));
        let cursor = (
            first[0].content_qualifier.as_str(),
            first[0].blob_oid,
            first[0].unit_key,
        );
        let second = store
            .declaration_rows_by_package_prefix_page(
                "java",
                GenerationId::BOOTSTRAP,
                "a_b",
                Some(cursor),
                16,
            )
            .unwrap();
        let qualifiers = first
            .iter()
            .chain(&second)
            .map(|row| row.content_qualifier.as_str())
            .collect::<HashSet<_>>();
        assert_eq!(
            qualifiers,
            ["a_b", "a_b.child"].into_iter().collect::<HashSet<_>>()
        );
        assert!(!qualifiers.contains("aXb"));
    }

    #[test]
    fn unchanged_path_symbol_snapshot_skips_table_reconciliation() {
        let store = AnalyzerStore::open_in_memory().unwrap();
        let row = PathSymbolRow {
            rel_path: "pkg/model.py".to_string(),
            blob_oid: oid_for(b"class Model:\n    pass\n"),
            kind: CodeUnitType::Module,
            package_name: "pkg".to_string(),
            short_name: "model".to_string(),
            exact_fqn: "pkg.model".to_string(),
            normalized_fqn: "pkg.model".to_string(),
        };

        store
            .sync_path_symbol_units(
                "python",
                GenerationId::BOOTSTRAP,
                std::slice::from_ref(&row),
            )
            .unwrap();
        let changes_after_cold_sync = store.conn.lock().expect("store mutex").total_changes();
        store
            .sync_path_symbol_units(
                "python",
                GenerationId::BOOTSTRAP,
                std::slice::from_ref(&row),
            )
            .unwrap();
        let changes_after_warm_sync = store.conn.lock().expect("store mutex").total_changes();

        assert_eq!(changes_after_warm_sync, changes_after_cold_sync);
    }

    #[test]
    fn python_exact_path_symbol_lookup_uses_fqn_index() {
        let store = AnalyzerStore::open_in_memory().unwrap();
        let conn = store.conn.lock().expect("store mutex");
        let mut stmt = conn
            .prepare(&format!("EXPLAIN QUERY PLAN {EXACT_PATH_SYMBOL_FQN_SQL}"))
            .unwrap();
        let plan = stmt
            .query_map(params!["python", "pkg.service"], |row| {
                row.get::<_, String>(3)
            })
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();

        assert!(
            plan.iter().any(|detail| {
                detail.contains("idx_path_symbol_units_lang_generation_exact_fqn")
            }),
            "expected exact Python lookup to use the FQN index, got {plan:?}"
        );
    }

    #[test]
    fn summary_projection_matches_required_file_state_rows_and_rejects_missing_ranges() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let file = write_file(
            root,
            "src/demo/Example.java",
            "package demo; class Example { String name; void run() {} }\n",
        );
        let source = file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let adapter = JavaAdapter;
        let state = parse_state(&adapter, &file);
        let store = AnalyzerStore::open_in_memory().unwrap();
        store
            .write_parsed_blob(oid, "java", &adapter, &state)
            .unwrap();

        let projection = store
            .summary_file_projection(oid, "java", GenerationId::BOOTSTRAP, &adapter, &file)
            .unwrap()
            .expect("complete summary projection");
        let hydrated = store
            .hydrate_file_state(oid, "java", &adapter, &file)
            .unwrap()
            .expect("complete file state");
        let hydrated_top_level: Vec<_> = hydrated
            .top_level_declarations
            .into_iter()
            .filter(|unit| !unit.is_file_scope())
            .collect();
        assert_eq!(projection.top_level_declarations, hydrated_top_level);
        for (unit, signatures) in &projection.signatures {
            assert_eq!(hydrated.signatures.get(unit), Some(signatures));
        }
        for (unit, ranges) in &projection.ranges {
            assert_eq!(hydrated.ranges.get(unit), Some(ranges));
        }
        for (unit, children) in &projection.children {
            assert_eq!(hydrated.children.get(unit), Some(children));
        }

        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "DELETE FROM unit_ranges WHERE blob_oid = ?1 AND lang = 'java'",
                [oid.to_string()],
            )
            .unwrap();
        }
        assert!(
            store
                .summary_file_projection(oid, "java", GenerationId::BOOTSTRAP, &adapter, &file,)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn bulk_import_facts_include_complete_files_without_import_details() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let file = write_file(
            root,
            "src/demo/NoImports.java",
            "package demo; class NoImports {}\n",
        );
        let source = file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let adapter = JavaAdapter;
        let state = parse_state(&adapter, &file);
        let store = AnalyzerStore::open_in_memory().unwrap();
        store
            .write_parsed_blob(oid, "java", &adapter, &state)
            .unwrap();

        let facts = store
            .hydrate_import_facts_by_key(
                &[(file.clone(), oid, "java".to_string())],
                &HashMap::from_iter([("java".to_string(), GenerationId::BOOTSTRAP)]),
                &adapter,
            )
            .unwrap();
        let facts = facts.get(&file).expect("complete persisted import facts");
        assert_eq!(facts.package_name, "demo");
        assert!(facts.imports.is_empty());
    }

    #[test]
    fn literal_substring_candidates_keep_members_of_matching_java_types() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let file = write_file(
            root,
            "src/demo/Gson.java",
            "package demo; class Gson { void fromJson() {} } class Other { void unrelated() {} }\n",
        );
        let source = file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let adapter = JavaAdapter;
        let state = parse_state(&adapter, &file);
        let store = AnalyzerStore::open_in_memory().unwrap();
        store
            .write_parsed_blob(oid, "java", &adapter, &state)
            .unwrap();

        let candidates = store
            .declaration_candidate_rows_by_literal_substring("java", "Gson")
            .unwrap();
        assert!(
            candidates
                .iter()
                .any(|row| row.short_name.ends_with(".fromJson")),
            "Java persists member selectors with their owning type in short_name"
        );
        assert!(candidates.iter().all(|row| {
            row.short_name.to_ascii_lowercase().contains("gson")
                || row.content_qualifier.to_ascii_lowercase().contains("gson")
        }));
        assert!(
            !candidates
                .iter()
                .any(|row| row.short_name.contains("unrelated"))
        );

        let search_candidates = store.search_candidate_rows_by_lang("java").unwrap();
        let method = search_candidates
            .iter()
            .find(|row| row.candidate.short_name.ends_with(".fromJson"))
            .expect("method search candidate");
        assert!(method.primary_range.is_some());
        assert!(!method.in_test_region);
    }

    #[test]
    fn definition_order_candidates_use_minimum_persisted_range_and_allow_absent_range() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let file = write_file(
            root,
            "src/demo/Sample.java",
            "package demo; class Sample {}\n",
        );
        let source = file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let adapter = JavaAdapter;
        let state = parse_state(&adapter, &file);
        let store = AnalyzerStore::open_in_memory().unwrap();
        store
            .write_parsed_blob(oid, "java", &adapter, &state)
            .unwrap();

        let unit_key = {
            let conn = store.conn.lock().unwrap();
            let unit_key = conn
                .query_row(
                    "SELECT unit_key FROM code_units
                     WHERE blob_oid = ?1 AND lang = 'java'
                       AND short_name = 'Sample' AND in_declarations = 1",
                    [oid.to_string()],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap();
            conn.execute(
                "DELETE FROM unit_ranges
                 WHERE blob_oid = ?1 AND lang = 'java' AND unit_key = ?2",
                params![oid.to_string(), unit_key],
            )
            .unwrap();
            for (ordinal, start_byte) in [(0_i64, 20_i64), (1, 5)] {
                conn.execute(
                    "INSERT INTO unit_ranges(
                       blob_oid, lang, unit_key, ordinal,
                       start_byte, end_byte, start_line, end_line
                     ) VALUES(?1, 'java', ?2, ?3, ?4, ?5, 0, 0)",
                    params![
                        oid.to_string(),
                        unit_key,
                        ordinal,
                        start_byte,
                        start_byte + 1
                    ],
                )
                .unwrap();
            }
            conn.execute(
                "UPDATE blob_meta
                 SET range_count = (
                   SELECT COUNT(*) FROM unit_ranges
                   WHERE blob_oid = ?1 AND lang = 'java'
                 )
                 WHERE blob_oid = ?1 AND lang = 'java'",
                [oid.to_string()],
            )
            .unwrap();
            unit_key
        };

        let generations = HashMap::from_iter([("java".to_string(), GenerationId::BOOTSTRAP)]);
        let rows = store
            .declaration_order_candidate_rows_by_short_name_for_langs(
                &["java".to_string()],
                &generations,
                "Sample",
            )
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].first_start_byte, Some(5));

        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "DELETE FROM unit_ranges
                 WHERE blob_oid = ?1 AND lang = 'java' AND unit_key = ?2",
                params![oid.to_string(), unit_key],
            )
            .unwrap();
            conn.execute(
                "UPDATE blob_meta
                 SET range_count = (
                   SELECT COUNT(*) FROM unit_ranges
                   WHERE blob_oid = ?1 AND lang = 'java'
                 )
                 WHERE blob_oid = ?1 AND lang = 'java'",
                [oid.to_string()],
            )
            .unwrap();
        }
        let rows = store
            .declaration_order_candidate_rows_by_short_name_for_langs(
                &["java".to_string()],
                &generations,
                "Sample",
            )
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].first_start_byte, None);
    }

    #[test]
    fn metadata_unit_count_mismatch_is_treated_as_incomplete() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let file = write_file(root, "pkg/corrupt.py", "class Corrupt:\n    pass\n");
        let source = file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let adapter = PythonAdapter;
        let state = parse_state(&adapter, &file);
        let store = AnalyzerStore::open_in_memory().unwrap();
        store
            .write_parsed_blob(oid, "python", &adapter, &state)
            .unwrap();

        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "DELETE FROM code_units WHERE blob_oid = ?1 AND lang = 'python'",
                [oid.to_string()],
            )
            .unwrap();
        }

        assert!(!store.contains_parsed_blob(oid, "python").unwrap());
        assert!(
            store
                .hydrate_file_state(oid, "python", &adapter, &file)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn metadata_side_table_count_mismatches_are_treated_as_incomplete() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let ruby_file = write_file(
            root,
            "lib/demo.rb",
            "require 'json'\nclass Demo\n  attr_reader :name\n  alias_method :label, :name\n  def initialize(name)\n    @name = name\n  end\n  def self.build(value)\n    new(value)\n  end\nend\n",
        );
        let python_file = write_file(
            root,
            "pkg/corrupt.py",
            "import os\nfrom sys import path\nclass Corrupt:\n    def run(self):\n        return os.getcwd()\n",
        );
        let java_file = write_file(
            root,
            "src/demo/Corrupt.java",
            "package demo;\nimport java.util.List;\nclass Corrupt extends Base { List<String> names; void run(List<String> input) {} }\nclass Base {}\n",
        );
        let scala_file = write_file(
            root,
            "src/main/scala/app/Corrupt.scala",
            "package app\ntrait Runnable\nclass Worker extends Runnable\n",
        );
        let cpp_file = write_file(
            root,
            "include/corrupt.h",
            "template <typename T, typename U = T*> class Corrupt {};\ntemplate <typename T> class Corrupt<T, T*> {};\n",
        );

        for table in [
            "unit_ranges",
            "unit_signatures",
            "unit_signature_metadata",
            "unit_children",
            "ruby_method_dispatch_modes",
        ] {
            assert_deleting_side_table_marks_incomplete(&RubyAdapter, "ruby", &ruby_file, table);
        }
        for table in ["import_statements", "import_details"] {
            assert_deleting_side_table_marks_incomplete(
                &PythonAdapter,
                "python",
                &python_file,
                table,
            );
        }
        for table in ["unit_supertypes", "type_identifiers"] {
            assert_deleting_side_table_marks_incomplete(&JavaAdapter, "java", &java_file, table);
        }
        assert_deleting_side_table_marks_incomplete(
            &ScalaAdapter,
            "scala",
            &scala_file,
            "scala_traits",
        );
        assert_deleting_side_table_marks_incomplete(
            &CppAdapter,
            "cpp",
            &cpp_file,
            "unit_cpp_template_metadata",
        );
    }

    #[test]
    fn cpp_recovered_typedef_base_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "levelrangefilter.h",
            "class LOG4CXX_EXPORT LevelRangeFilter : public spi::Filter {\n\
             typedef spi::Filter BASE_CLASS;\n\
             };\n",
        );
        let state = Arc::new(parse_state(&CppAdapter, &file));
        let oid = oid_for(state.source.as_bytes());
        let store = AnalyzerStore::open_in_memory().unwrap();
        // Recompute the immediately preceding C++ epoch for this target from
        // the complete pre-#1208 language salt, rather than passing an
        // arbitrary old label through the store's generic epoch API. The live
        // grammar fingerprint is target-specific, so the durable contract is
        // the generation cutover below, not one target's full epoch digest.
        let prior_epoch = epoch::cpp_epoch_before_recovered_typedef_base();
        let prior_generation = store
            .ensure_language_epoch_value("cpp", &prior_epoch)
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                oid,
                "cpp",
                prior_generation,
                &CppAdapter,
                state.as_ref(),
            )
            .unwrap();
        assert!(store.contains_parsed_blob(oid, "cpp").unwrap());

        let current_generation = store
            .ensure_language_epoch(Language::Cpp, &tree_sitter_cpp::LANGUAGE.into())
            .unwrap();

        assert_ne!(current_generation, prior_generation);
        assert!(!store.contains_parsed_blob(oid, "cpp").unwrap());
        assert_eq!(
            store
                .missing_parsed_blob_keys(&[(oid, "cpp".to_string())])
                .unwrap(),
            vec![(oid, "cpp".to_string())]
        );
    }

    #[test]
    fn cpp_complete_sentinel_class_tail_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "raw_hash_set.h",
            "namespace absl { namespace container_internal {\n\
             template <class T> class raw_hash_set { using hasher = T; };\n\
             }}\n",
        );
        let state = Arc::new(parse_state(&CppAdapter, &file));
        let oid = oid_for(state.source.as_bytes());
        let store = AnalyzerStore::open_in_memory().unwrap();
        let prior_epoch = epoch::cpp_epoch_before_complete_sentinel_class_tail();
        let prior_generation = store
            .ensure_language_epoch_value("cpp", &prior_epoch)
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                oid,
                "cpp",
                prior_generation,
                &CppAdapter,
                state.as_ref(),
            )
            .unwrap();
        assert!(store.contains_parsed_blob(oid, "cpp").unwrap());

        let current_generation = store
            .ensure_language_epoch(Language::Cpp, &tree_sitter_cpp::LANGUAGE.into())
            .unwrap();

        assert_ne!(current_generation, prior_generation);
        assert!(!store.contains_parsed_blob(oid, "cpp").unwrap());
        assert_eq!(
            store
                .missing_parsed_blob_keys(&[(oid, "cpp".to_string())])
                .unwrap(),
            vec![(oid, "cpp".to_string())]
        );
    }

    #[test]
    fn cpp_sentinel_class_before_member_callable_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "distribution.h",
            "namespace absl { ABSL_NAMESPACE_BEGIN\n\
             template <class T> class distribution { using result_type = T;\n\
             result_type operator()() { return result_type{}; } }; }\n",
        );
        let state = Arc::new(parse_state(&CppAdapter, &file));
        let oid = oid_for(state.source.as_bytes());
        let store = AnalyzerStore::open_in_memory().unwrap();
        let prior_epoch = epoch::cpp_epoch_before_sentinel_class_before_member_callable();
        let prior_generation = store
            .ensure_language_epoch_value("cpp", &prior_epoch)
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                oid,
                "cpp",
                prior_generation,
                &CppAdapter,
                state.as_ref(),
            )
            .unwrap();
        assert!(store.contains_parsed_blob(oid, "cpp").unwrap());

        let current_generation = store
            .ensure_language_epoch(Language::Cpp, &tree_sitter_cpp::LANGUAGE.into())
            .unwrap();

        assert_ne!(current_generation, prior_generation);
        assert!(!store.contains_parsed_blob(oid, "cpp").unwrap());
        assert_eq!(
            store
                .missing_parsed_blob_keys(&[(oid, "cpp".to_string())])
                .unwrap(),
            vec![(oid, "cpp".to_string())]
        );
    }

    #[test]
    fn cpp_plain_fragmented_class_sibling_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "analyzer.h",
            "struct Analyzer {\n\
             struct Action {};\n\
             template<class T> void analyze(T value) { Action action; }\n\
             };\n",
        );
        let state = Arc::new(parse_state(&CppAdapter, &file));
        let oid = oid_for(state.source.as_bytes());
        let store = AnalyzerStore::open_in_memory().unwrap();
        let prior_epoch = epoch::cpp_epoch_before_plain_fragmented_class_sibling_ownership();
        let prior_generation = store
            .ensure_language_epoch_value("cpp", &prior_epoch)
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                oid,
                "cpp",
                prior_generation,
                &CppAdapter,
                state.as_ref(),
            )
            .unwrap();
        assert!(store.contains_parsed_blob(oid, "cpp").unwrap());

        let current_generation = store
            .ensure_language_epoch(Language::Cpp, &tree_sitter_cpp::LANGUAGE.into())
            .unwrap();

        assert_ne!(current_generation, prior_generation);
        assert!(!store.contains_parsed_blob(oid, "cpp").unwrap());
        assert_eq!(
            store
                .missing_parsed_blob_keys(&[(oid, "cpp".to_string())])
                .unwrap(),
            vec![(oid, "cpp".to_string())]
        );
    }

    #[test]
    fn cpp_fragmented_export_sibling_class_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "token.h",
            "#define SIMPLECPP_LIB\n\
             namespace simplecpp {\n\
             using TokenString = std::string;\n\
             struct Location {};\n\
             class SIMPLECPP_LIB Token {\n\
             public:\n\
               Token(const TokenString &s, const Location &loc) :\n\
                   location(loc), string(s) {\n\
               }\n\
               TokenString string;\n\
               Location location;\n\
             };\n\
             }\n",
        );
        let state = Arc::new(parse_state(&CppAdapter, &file));
        let oid = oid_for(state.source.as_bytes());
        let store = AnalyzerStore::open_in_memory().unwrap();
        let prior_epoch = epoch::cpp_epoch_before_fragmented_export_sibling_class_parent_scope();
        let prior_generation = store
            .ensure_language_epoch_value("cpp", &prior_epoch)
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                oid,
                "cpp",
                prior_generation,
                &CppAdapter,
                state.as_ref(),
            )
            .unwrap();
        assert!(store.contains_parsed_blob(oid, "cpp").unwrap());

        let current_generation = store
            .ensure_language_epoch(Language::Cpp, &tree_sitter_cpp::LANGUAGE.into())
            .unwrap();

        assert_ne!(current_generation, prior_generation);
        assert!(!store.contains_parsed_blob(oid, "cpp").unwrap());
        assert_eq!(
            store
                .missing_parsed_blob_keys(&[(oid, "cpp".to_string())])
                .unwrap(),
            vec![(oid, "cpp".to_string())]
        );
    }

    #[test]
    fn php_conditional_free_function_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "functions.php",
            "<?php\nnamespace FastRoute;\nif (true) { function route(): void {} }\n",
        );
        let state = Arc::new(parse_state(&PhpAdapter, &file));
        let oid = oid_for(state.source.as_bytes());
        let store = AnalyzerStore::open_in_memory().unwrap();
        let prior_epoch = epoch::php_epoch_before_conditional_free_function_declarations();
        let prior_generation = store
            .ensure_language_epoch_value("php", &prior_epoch)
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                oid,
                "php",
                prior_generation,
                &PhpAdapter,
                state.as_ref(),
            )
            .unwrap();
        assert!(store.contains_parsed_blob(oid, "php").unwrap());

        let current_generation = store
            .ensure_language_epoch(Language::Php, &tree_sitter_php::LANGUAGE_PHP.into())
            .unwrap();

        assert_ne!(current_generation, prior_generation);
        assert!(!store.contains_parsed_blob(oid, "php").unwrap());
        assert_eq!(
            store
                .missing_parsed_blob_keys(&[(oid, "php".to_string())])
                .unwrap(),
            vec![(oid, "php".to_string())]
        );
    }

    #[test]
    fn scala_scalachess_fqn_recovery_epoch_invalidates_stale_rows_and_reuses_current() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "src/main/scala/chess/tiebreak/Tiebreak.scala",
            "package chess\npackage tiebreak\n\nimport Tiebreak.*\n\ntrait Tournament:\n  def players: Set[String]\n  def gamesById(id: String): List[String]\n  def opponentsOf: String => List[String]\n  def scoreOf: String => Float\n  def lastRoundId: Option[String]\n\n  lazy val maxRounds = players.map(_.length).maxOption.getOrElse(0)\n\nobject Tournament:\n  private final class Impl extends Tournament:\n    override def players: Set[String] = Set.empty\n    override def gamesById(id: String): List[String] = Nil\n    override def opponentsOf: String => List[String] = _ => Nil\n    override def scoreOf: String => Float = _ => 0f\n    override def lastRoundId: Option[String] = None\n\n  def apply(value: Int): Tournament =\n    new Tournament {}\n\nobject Tiebreak:\n  def compute(value: Int): Tournament =\n    Tournament(value)\n",
        );
        let state = Arc::new(parse_state(&ScalaAdapter, &file));
        let oid = oid_for(state.source.as_bytes());
        let store = AnalyzerStore::open_in_memory().unwrap();

        // Commit 20f61961 recovered declarations that tree-sitter attaches to
        // malformed significant-indentation template bodies. That changed
        // Scala FQNs without changing the grammar vocabulary covered by the
        // automatic epoch fingerprint. Do not pin the helper's literal hash:
        // the fingerprint includes CARGO_PKG_VERSION, so a literal breaks at
        // every release. The generation inequality below proves the cutover.
        let prior_epoch = epoch::scala_epoch_before_scalachess_fqn_recovery();
        let prior_generation = store
            .ensure_language_epoch_value("scala", &prior_epoch)
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                oid,
                "scala",
                prior_generation,
                &ScalaAdapter,
                state.as_ref(),
            )
            .unwrap();
        assert!(store.contains_parsed_blob(oid, "scala").unwrap());

        let current_generation = store
            .ensure_language_epoch(
                Language::Scala,
                &crate::analyzer::scala::language::LANGUAGE.into(),
            )
            .unwrap();
        assert_ne!(current_generation, prior_generation);
        assert!(!store.contains_parsed_blob(oid, "scala").unwrap());
        assert_eq!(
            store
                .missing_parsed_blob_keys(&[(oid, "scala".to_string())])
                .unwrap(),
            vec![(oid, "scala".to_string())]
        );

        // Once the current epoch has been populated, reopening the same
        // version must reuse its generation and keep the semantic state warm.
        store
            .write_parsed_blob_at_generation(
                oid,
                "scala",
                current_generation,
                &ScalaAdapter,
                state.as_ref(),
            )
            .unwrap();
        let reused_generation = store
            .ensure_language_epoch(
                Language::Scala,
                &crate::analyzer::scala::language::LANGUAGE.into(),
            )
            .unwrap();
        assert_eq!(reused_generation, current_generation);
        assert!(store.contains_parsed_blob(oid, "scala").unwrap());
        let hydrated = store
            .hydrate_file_state(oid, "scala", &ScalaAdapter, &file)
            .unwrap()
            .expect("current-generation Scala rows should hydrate");
        assert!(
            hydrated
                .declarations
                .iter()
                .any(|unit| unit.fq_name() == "chess.tiebreak.Tournament$.apply"),
            "hydrated declarations should retain the top-level companion apply: {:?}",
            hydrated.declarations
        );
        assert!(
            hydrated
                .declarations
                .iter()
                .all(|unit| unit.fq_name() != "chess.tiebreak.Tournament.Tournament$.apply"),
            "hydrated declarations must not retain the stale duplicate owner: {:?}",
            hydrated.declarations
        );
    }

    #[test]
    fn parsed_blob_presence_allows_zero_persisted_units() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let file = write_file(root, "pkg/side_effect_only.py", "import os\n");
        let source = file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let adapter = PythonAdapter;
        let state = parse_state(&adapter, &file);
        let store = AnalyzerStore::open_in_memory().unwrap();

        store
            .write_parsed_blob(oid, "python", &adapter, &state)
            .unwrap();

        assert!(store.contains_parsed_blob(oid, "python").unwrap());
        assert_eq!(
            store
                .missing_parsed_blob_keys(&[(oid, "python".to_string())])
                .unwrap(),
            Vec::<(Oid, String)>::new()
        );
        let hydrated = store
            .hydrate_file_state(oid, "python", &adapter, &file)
            .unwrap()
            .unwrap();
        assert_file_state_equivalent(&state, &hydrated);
    }

    #[test]
    fn gc_drops_unreachable_blob_registry_rows() {
        let store = AnalyzerStore::open_in_memory().unwrap();
        let reachable = Oid::hash_object(ObjectType::Blob, b"reachable").unwrap();
        let unreachable = Oid::hash_object(ObjectType::Blob, b"unreachable").unwrap();
        store
            .register_blobs(&[reachable, unreachable], "rust", GenerationId::BOOTSTRAP)
            .unwrap();

        let mut bloom = GrowableBloom::new(0.01, 8);
        bloom.insert(reachable.to_string());
        assert_eq!(store.gc_with_bloom(&bloom).unwrap(), 1);
        assert_eq!(
            store
                .missing_blobs(&[reachable, unreachable], "rust")
                .unwrap(),
            vec![unreachable]
        );
    }

    #[test]
    fn language_epoch_mismatch_deletes_only_that_language() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let java_file = write_file(root, "src/demo/One.java", "package demo;\nclass One {}\n");
        let ts_file = write_file(root, "src/two.ts", "export class Two {}\n");
        let java_oid = oid_for(java_file.read_to_string().unwrap().as_bytes());
        let ts_oid = oid_for(ts_file.read_to_string().unwrap().as_bytes());
        let java = JavaAdapter;
        let ts = TypescriptAdapter;
        let java_state = parse_state(&java, &java_file);
        let ts_state = parse_state(&ts, &ts_file);

        let store = AnalyzerStore::open_in_memory().unwrap();
        store
            .ensure_language_epoch_value("java", "epoch-a")
            .unwrap();
        store
            .ensure_language_epoch_value("typescript", "epoch-a")
            .unwrap();
        store
            .write_parsed_blob(java_oid, "java", &java, &java_state)
            .unwrap();
        store
            .write_parsed_blob(ts_oid, "typescript", &ts, &ts_state)
            .unwrap();

        store
            .ensure_language_epoch_value("java", "epoch-b")
            .unwrap();
        assert_eq!(
            store.missing_blobs(&[java_oid], "java").unwrap(),
            vec![java_oid]
        );
        assert_eq!(
            store.missing_blobs(&[ts_oid], "typescript").unwrap(),
            vec![]
        );
        assert_eq!(store.content_row_count(java_oid, "java").unwrap(), 0);
        assert!(store.content_row_count(ts_oid, "typescript").unwrap() > 0);
    }

    #[test]
    fn cpp_epoch_change_hides_old_rows_without_synchronous_physical_deletion() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(temp.path(), "Model.java", "class Model { int value; }\n");
        let oid = oid_for(file.read_to_string().unwrap().as_bytes());
        // Epoch visibility is keyed by storage language independently of the parser adapter.
        let adapter = JavaAdapter;
        let state = parse_state(&adapter, &file);
        let store = AnalyzerStore::open_in_memory().unwrap();
        store.ensure_language_epoch_value("cpp", "epoch-a").unwrap();
        store
            .write_parsed_blob(oid, "cpp", &adapter, &state)
            .unwrap();

        let physical_counts = || {
            let conn = store.conn.lock().expect("analyzer store mutex poisoned");
            ["blobs", "blob_meta", "code_units"].map(|table| {
                conn.query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE blob_oid = ?1 AND lang = 'cpp'"),
                    [oid.to_string()],
                    |row| row.get::<_, usize>(0),
                )
                .unwrap()
            })
        };
        let before = physical_counts();
        assert!(before.into_iter().all(|count| count > 0), "{before:?}");
        assert!(store.contains_parsed_blob(oid, "cpp").unwrap());

        store.ensure_language_epoch_value("cpp", "epoch-b").unwrap();
        assert!(!store.contains_parsed_blob(oid, "cpp").unwrap());
        assert_eq!(
            store
                .missing_parsed_blob_keys(&[(oid, "cpp".to_string())])
                .unwrap(),
            vec![(oid, "cpp".to_string())]
        );
        assert_eq!(
            before,
            physical_counts(),
            "epoch invalidation should be a constant-time logical cutover; old physical rows belong to deferred GC"
        );
    }

    #[test]
    fn repeated_epoch_string_gets_fresh_generation_without_reviving_a1_rows() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(temp.path(), "Model.java", "class Model {}\n");
        let oid = oid_for(file.read_to_string().unwrap().as_bytes());
        let state = parse_state(&JavaAdapter, &file);
        let store = AnalyzerStore::open_in_memory().unwrap();

        let a1 = store
            .ensure_language_epoch_value("java", "epoch-a")
            .unwrap();
        store
            .write_parsed_blob_at_generation(oid, "java", a1, &JavaAdapter, &state)
            .unwrap();
        let b = store
            .ensure_language_epoch_value("java", "epoch-b")
            .unwrap();
        let a2 = store
            .ensure_language_epoch_value("java", "epoch-a")
            .unwrap();

        assert_ne!(a1, b);
        assert_ne!(a1, a2);
        assert_ne!(b, a2);
        assert!(!store.contains_parsed_blob(oid, "java").unwrap());
        assert!(
            store
                .contains_parsed_blob_at_generation(oid, "java", a1)
                .unwrap_err()
                .is_stale_generation()
        );
    }

    #[test]
    fn stale_prepared_register_and_path_writes_cannot_delete_current_rows() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(temp.path(), "Model.java", "class Model {}\n");
        let oid = oid_for(file.read_to_string().unwrap().as_bytes());
        let state = Arc::new(parse_state(&JavaAdapter, &file));
        let store = AnalyzerStore::open_in_memory().unwrap();
        let a = store
            .ensure_language_epoch_value("java", "epoch-a")
            .unwrap();
        let prepared =
            AnalyzerStore::prepare_parsed_blob(oid, "java", a, &JavaAdapter, Arc::clone(&state))
                .unwrap();
        let b = store
            .ensure_language_epoch_value("java", "epoch-b")
            .unwrap();
        store
            .write_parsed_blob_at_generation(oid, "java", b, &JavaAdapter, state.as_ref())
            .unwrap();

        let (outcomes, stats) =
            store.persist_prepared_blobs(vec![prepared], PersistBatchLimits::PRODUCTION);
        assert_eq!(stats.failed_transaction_attempts, 1);
        assert!(outcomes[0].error.as_ref().unwrap().is_stale_generation());
        assert!(
            store
                .register_blobs(&[oid], "java", a)
                .unwrap_err()
                .is_stale_generation()
        );

        let row = PathSymbolRow {
            rel_path: "Model.java".to_string(),
            blob_oid: oid,
            kind: CodeUnitType::Module,
            package_name: String::new(),
            short_name: "Model".to_string(),
            exact_fqn: "Model".to_string(),
            normalized_fqn: "Model".to_string(),
        };
        store
            .sync_path_symbol_units("java", b, std::slice::from_ref(&row))
            .unwrap();
        assert!(
            store
                .sync_path_symbol_units("java", a, std::slice::from_ref(&row))
                .unwrap_err()
                .is_stale_generation()
        );
        assert!(store.contains_parsed_blob(oid, "java").unwrap());
        let langs = vec!["java".to_string()];
        let generations = HashMap::from_iter([("java".to_string(), b)]);
        assert_eq!(
            store
                .path_symbol_rows_by_fqn_for_langs(&langs, &generations, "Model", "Model",)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn candidate_and_path_queries_do_not_leak_across_generation_cutover() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(temp.path(), "Model.java", "class Model {}\n");
        let oid = oid_for(file.read_to_string().unwrap().as_bytes());
        let state = parse_state(&JavaAdapter, &file);
        let store = AnalyzerStore::open_in_memory().unwrap();
        let a = store.ensure_language_epoch_value("java", "a").unwrap();
        store
            .write_parsed_blob_at_generation(oid, "java", a, &JavaAdapter, &state)
            .unwrap();
        let row = PathSymbolRow {
            rel_path: "Model.java".to_string(),
            blob_oid: oid,
            kind: CodeUnitType::Module,
            package_name: String::new(),
            short_name: "Model".to_string(),
            exact_fqn: "Model".to_string(),
            normalized_fqn: "Model".to_string(),
        };
        store
            .sync_path_symbol_units("java", a, std::slice::from_ref(&row))
            .unwrap();
        let langs = vec!["java".to_string()];
        let a_map = HashMap::from_iter([("java".to_string(), a)]);
        assert!(
            !store
                .declaration_candidate_rows_for_langs(&langs, &a_map)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store
                .path_symbol_rows_by_fqn_for_langs(&langs, &a_map, "Model", "Model")
                .unwrap()
                .len(),
            1
        );

        let b = store.ensure_language_epoch_value("java", "b").unwrap();
        let b_map = HashMap::from_iter([("java".to_string(), b)]);
        assert!(
            store
                .declaration_candidate_rows_for_langs(&langs, &a_map)
                .unwrap_err()
                .is_stale_generation()
        );
        assert!(
            store
                .declaration_candidate_rows_for_langs(&langs, &b_map)
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .path_symbol_rows_by_fqn_for_langs(&langs, &b_map, "Model", "Model")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn persistent_epoch_publishers_serialize_same_and_different_epochs() {
        let temp = tempfile::TempDir::new().unwrap();
        let db = temp.path().join("cache.db");
        drop(AnalyzerStore::open_persistent(&db).unwrap());
        let same_barrier = Arc::new(std::sync::Barrier::new(2));
        let same_handles = [0, 1].map(|_| {
            let barrier = Arc::clone(&same_barrier);
            let db = db.clone();
            std::thread::spawn(move || {
                let store = AnalyzerStore::open_persistent(&db).unwrap();
                barrier.wait();
                store.ensure_language_epoch_value("java", "same").unwrap()
            })
        });
        let same = same_handles.map(|handle| handle.join().unwrap());
        assert_eq!(same[0], same[1]);

        let different_barrier = Arc::new(std::sync::Barrier::new(2));
        let different_handles = ["left", "right"].map(|epoch| {
            let barrier = Arc::clone(&different_barrier);
            let db = db.clone();
            std::thread::spawn(move || {
                let store = AnalyzerStore::open_persistent(&db).unwrap();
                barrier.wait();
                let generation = store.ensure_language_epoch_value("java", epoch).unwrap();
                (epoch, generation)
            })
        });
        let different = different_handles.map(|handle| handle.join().unwrap());
        assert_ne!(different[0].1, different[1].1);

        let conn = crate::cache_db::open_unified_connection(&db).unwrap();
        let final_pair: (String, i64) = conn
            .query_row(
                "SELECT epoch, generation FROM analysis_epochs WHERE lang = 'java'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(
            different.iter().any(|(epoch, generation)| {
                *epoch == final_pair.0 && generation.0 == final_pair.1
            })
        );
    }

    #[test]
    fn matching_persistent_epoch_does_not_wait_for_the_writer_slot() {
        let temp = tempfile::TempDir::new().unwrap();
        let db = temp.path().join("cache.db");
        let writer = AnalyzerStore::open_persistent(&db).unwrap();
        let reader = AnalyzerStore::open_persistent(&db).unwrap();
        let generation = writer.ensure_language_epoch_value("java", "same").unwrap();

        reader
            .conn
            .lock()
            .unwrap()
            .busy_timeout(Duration::from_millis(100))
            .unwrap();
        let mut writer_conn = writer.conn.lock().unwrap();
        let writer_tx = writer_conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();

        assert_eq!(
            reader.ensure_language_epoch_value("java", "same").unwrap(),
            generation
        );
        writer_tx.rollback().unwrap();
    }

    #[test]
    fn hydration_read_snapshot_keeps_meta_and_satellites_on_one_generation() {
        let temp = tempfile::TempDir::new().unwrap();
        let db = temp.path().join("cache.db");
        let file = write_file(temp.path(), "Model.java", "class Alpha {}\n");
        let oid = oid_for(b"stable-oid");
        let state_a = parse_state(&JavaAdapter, &file);
        let writer = AnalyzerStore::open_persistent(&db).unwrap();
        let reader = AnalyzerStore::open_persistent(&db).unwrap();
        let a = writer
            .ensure_language_epoch_value("java", "epoch-a")
            .unwrap();
        writer
            .write_parsed_blob_at_generation(oid, "java", a, &JavaAdapter, &state_a)
            .unwrap();

        let mut reader_conn = reader.conn.lock().expect("reader mutex");
        let read_tx = reader_conn.transaction().unwrap();
        require_current_generation(&read_tx, "java", a).unwrap();
        let old_meta = read_blob_meta(
            &read_tx,
            &oid.to_string(),
            "java",
            &JavaAdapter,
            &file,
            "class Alpha {}\n",
        )
        .unwrap()
        .unwrap();

        std::fs::write(file.abs_path(), "class Beta {}\n").unwrap();
        let state_b = parse_state(&JavaAdapter, &file);
        let b = writer
            .ensure_language_epoch_value("java", "epoch-b")
            .unwrap();
        writer
            .write_parsed_blob_at_generation(oid, "java", b, &JavaAdapter, &state_b)
            .unwrap();

        let old_units =
            read_unit_rows(&read_tx, &oid.to_string(), "java", &JavaAdapter, &file).unwrap();
        assert_eq!(old_units.len(), old_meta.stored_unit_count);
        assert!(old_units.iter().any(|row| row.unit.short_name() == "Alpha"));
        assert!(!old_units.iter().any(|row| row.unit.short_name() == "Beta"));
        read_tx.commit().unwrap();
        drop(reader_conn);

        let hydrated = reader
            .hydrate_file_state_with_source(oid, "java", b, &JavaAdapter, &file, "class Beta {}\n")
            .unwrap()
            .unwrap();
        assert!(
            hydrated
                .declarations
                .iter()
                .any(|unit| unit.short_name() == "Beta")
        );
        assert!(
            !hydrated
                .declarations
                .iter()
                .any(|unit| unit.short_name() == "Alpha")
        );
    }

    #[test]
    fn stale_generation_reclamation_makes_one_oversize_progress_and_respects_small_budget() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "Many.java",
            "class A {} class B {} class C {} class D {}\n",
        );
        let oid = oid_for(file.read_to_string().unwrap().as_bytes());
        let state = parse_state(&JavaAdapter, &file);
        let store = AnalyzerStore::open_in_memory().unwrap();
        let a = store.ensure_language_epoch_value("java", "a").unwrap();
        store
            .write_parsed_blob_at_generation(oid, "java", a, &JavaAdapter, &state)
            .unwrap();
        store.ensure_language_epoch_value("java", "b").unwrap();
        store
            .conn
            .lock()
            .expect("store mutex")
            .execute(
                "DELETE FROM blob_payload_costs WHERE blob_oid = ?1 AND lang = 'java'",
                [oid.to_string()],
            )
            .unwrap();
        let reclaimed = store.reclaim_stale_generations(1).unwrap();
        assert!(reclaimed > 1, "one oversize blob must still make progress");
        let physical: usize = store
            .conn
            .lock()
            .expect("store mutex")
            .query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(physical, 0);
        assert_eq!(store.reclaim_stale_generations(1).unwrap(), 0);

        let one = oid_for(b"one");
        let two = oid_for(b"two");
        let c = store.ensure_language_epoch_value("rust", "c").unwrap();
        store.register_blobs(&[one, two], "rust", c).unwrap();
        store.ensure_language_epoch_value("rust", "d").unwrap();
        assert_eq!(store.reclaim_stale_generations(1).unwrap(), 1);
        let remaining: usize = store
            .conn
            .lock()
            .expect("store mutex")
            .query_row(
                "SELECT COUNT(*) FROM blobs WHERE lang = 'rust'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 1);
    }

    #[test]
    fn prepared_blob_persistence_uses_bounded_transactions() {
        const PREPARED_BLOBS: usize = 257;
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(temp.path(), "Model.java", "class Model {}\n");
        let state = Arc::new(parse_state(&JavaAdapter, &file));
        let store = AnalyzerStore::open_in_memory().unwrap();
        store.reset_replacement_cost_lookup_queries_for_test();
        let prepared = (0..PREPARED_BLOBS)
            .map(|index| {
                let oid =
                    Oid::hash_object(ObjectType::Blob, format!("blob-{index}").as_bytes()).unwrap();
                AnalyzerStore::prepare_parsed_blob(
                    oid,
                    "java",
                    GenerationId::BOOTSTRAP,
                    &JavaAdapter,
                    Arc::clone(&state),
                )
                .unwrap()
            })
            .collect();

        let (outcomes, stats) = store.persist_prepared_blobs(
            prepared,
            PersistBatchLimits {
                max_blobs: 64,
                max_rows: usize::MAX,
                max_payload_bytes: usize::MAX,
            },
        );

        assert_eq!(stats.transactions, 5);
        assert_eq!(stats.committed_blobs, PREPARED_BLOBS);
        assert_eq!(stats.failed_transaction_attempts, 0);
        assert!(outcomes.iter().all(|outcome| outcome.error.is_none()));
        assert_eq!(store.parsed_blob_transaction_starts_for_test(), 5);
        assert_eq!(
            store.replacement_cost_lookup_queries_for_test(),
            5,
            "each at-most-64-blob writer transaction must execute one VALUES lookup"
        );
    }

    #[test]
    fn prepared_replacement_cost_is_looked_up_once_per_writer_transaction() {
        const REPLACEMENTS: usize = 8;
        let temp = tempfile::TempDir::new().unwrap();
        let old_file = write_file(temp.path(), "Old.java", "class Old {}\n");
        let replacement_file =
            write_file(temp.path(), "Replacement.java", "class Replacement {}\n");
        let old_state = parse_state(&JavaAdapter, &old_file);
        let replacement_state = Arc::new(parse_state(&JavaAdapter, &replacement_file));
        let store = AnalyzerStore::open_in_memory().unwrap();
        let generation_a = store
            .ensure_language_epoch_value("java", "replacement-query-a")
            .unwrap();
        let oids = (0..REPLACEMENTS)
            .map(|index| oid_for(format!("replacement-query-{index}").as_bytes()))
            .collect::<Vec<_>>();
        for oid in &oids {
            store
                .write_parsed_blob_at_generation(
                    *oid,
                    "java",
                    generation_a,
                    &JavaAdapter,
                    &old_state,
                )
                .unwrap();
        }
        let generation_b = store
            .ensure_language_epoch_value("java", "replacement-query-b")
            .unwrap();
        let prepared = oids
            .iter()
            .copied()
            .map(|oid| {
                AnalyzerStore::prepare_parsed_blob(
                    oid,
                    "java",
                    generation_b,
                    &JavaAdapter,
                    Arc::clone(&replacement_state),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let expected_payload_bytes = prepared[0].persisted_payload_bytes();

        store.reset_replacement_cost_lookup_queries_for_test();
        store.reset_prepared_generation_lookup_queries_for_test();
        let (outcomes, stats) =
            store.persist_prepared_blobs(prepared, PersistBatchLimits::PRODUCTION);

        assert!(outcomes.iter().all(|outcome| outcome.error.is_none()));
        assert_eq!(stats.transactions, 1);
        assert_eq!(stats.committed_blobs, REPLACEMENTS);
        assert_eq!(
            store
                .conn
                .lock()
                .expect("store mutex")
                .query_row(
                    "SELECT payload_bytes FROM blob_payload_costs
                     WHERE blob_oid = ?1 AND lang = 'java'",
                    [oids[0].to_string()],
                    |row| row.get::<_, usize>(0),
                )
                .unwrap(),
            expected_payload_bytes
        );
        assert_eq!(
            store.replacement_cost_lookup_queries_for_test(),
            1,
            "replacement roots must be fetched once as an ordinal-preserving set"
        );
        assert_eq!(store.replacement_cost_fallback_queries_for_test(), 0);
        assert_eq!(
            store.prepared_generation_lookup_queries_for_test(),
            1,
            "one language generation must be validated once per persistence batch"
        );
    }

    #[test]
    fn unicode_legacy_replacements_use_one_set_lookup_and_reused_fallback() {
        const REPLACEMENTS: usize = 3;
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "Unicode.java",
            "package café; class Résumé { String naïve; }\n",
        );
        let state = Arc::new(parse_state(&JavaAdapter, &file));
        let store = AnalyzerStore::open_in_memory().unwrap();
        let generation_a = store
            .ensure_language_epoch_value("java", "unicode-legacy-a")
            .unwrap();
        let oids = (0..REPLACEMENTS)
            .map(|index| oid_for(format!("unicode-legacy-{index}").as_bytes()))
            .collect::<Vec<_>>();
        for oid in &oids {
            store
                .write_parsed_blob_at_generation(*oid, "java", generation_a, &JavaAdapter, &state)
                .unwrap();
        }
        let expected = AnalyzerStore::prepare_parsed_blob(
            oids[0],
            "java",
            generation_a,
            &JavaAdapter,
            Arc::clone(&state),
        )
        .unwrap();
        let conn = store.conn.lock().expect("store mutex");
        conn.execute("DELETE FROM blob_payload_costs WHERE lang = 'java'", [])
            .unwrap();
        let mut fallback_statement = conn
            .prepare_cached(persisted_blob_mutation_cost_fallback_sql())
            .unwrap();
        assert_eq!(
            persisted_blob_mutation_cost_fallback_statement(
                &mut fallback_statement,
                oids[0].to_string().as_str(),
                "java",
            )
            .unwrap(),
            PersistedMutationCost {
                logical_rows: expected.logical_rows().saturating_sub(1),
                payload_bytes: expected.persisted_payload_bytes(),
            },
            "SQLite length() must count UTF-8 bytes like Rust String::len"
        );
        drop(fallback_statement);
        drop(conn);

        let generation_b = store
            .ensure_language_epoch_value("java", "unicode-legacy-b")
            .unwrap();
        let prepared = oids
            .iter()
            .map(|oid| {
                AnalyzerStore::prepare_parsed_blob(
                    *oid,
                    "java",
                    generation_b,
                    &JavaAdapter,
                    Arc::clone(&state),
                )
                .unwrap()
            })
            .collect();
        store.reset_replacement_cost_lookup_queries_for_test();
        let (outcomes, stats) =
            store.persist_prepared_blobs(prepared, PersistBatchLimits::PRODUCTION);

        assert!(outcomes.iter().all(|outcome| outcome.error.is_none()));
        assert_eq!(stats.transactions, 1);
        assert_eq!(stats.committed_blobs, REPLACEMENTS);
        assert_eq!(store.replacement_cost_lookup_queries_for_test(), 1);
        assert_eq!(
            store.replacement_cost_fallback_queries_for_test(),
            REPLACEMENTS
        );
    }

    #[test]
    fn conflicting_prepared_generations_fail_the_whole_batch_before_lookups() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(temp.path(), "Model.java", "class Model {}\n");
        let state = Arc::new(parse_state(&JavaAdapter, &file));
        let store = AnalyzerStore::open_in_memory().unwrap();
        let generation_a = store
            .ensure_language_epoch_value("java", "conflicting-generation-a")
            .unwrap();
        let stale_oid = oid_for(b"conflicting stale prepared blob");
        let stale = AnalyzerStore::prepare_parsed_blob(
            stale_oid,
            "java",
            generation_a,
            &JavaAdapter,
            Arc::clone(&state),
        )
        .unwrap();
        let generation_b = store
            .ensure_language_epoch_value("java", "conflicting-generation-b")
            .unwrap();
        let current_oid = oid_for(b"conflicting current prepared blob");
        let current = AnalyzerStore::prepare_parsed_blob(
            current_oid,
            "java",
            generation_b,
            &JavaAdapter,
            state,
        )
        .unwrap();

        store.reset_replacement_cost_lookup_queries_for_test();
        store.reset_prepared_generation_lookup_queries_for_test();
        let (outcomes, stats) = store.persist_prepared_blobs(
            vec![current, stale],
            PersistBatchLimits {
                max_blobs: usize::MAX,
                max_rows: usize::MAX,
                max_payload_bytes: usize::MAX,
            },
        );

        assert_eq!(stats.transactions, 0);
        assert_eq!(stats.committed_blobs, 0);
        assert_eq!(stats.failed_blobs, 2);
        assert_eq!(stats.failed_transaction_attempts, 1);
        assert!(outcomes.iter().all(|outcome| {
            outcome
                .error
                .as_ref()
                .is_some_and(StoreError::is_stale_generation)
        }));
        assert_eq!(store.prepared_generation_lookup_queries_for_test(), 0);
        assert_eq!(store.replacement_cost_lookup_queries_for_test(), 0);
        assert!(!store.contains_parsed_blob(current_oid, "java").unwrap());
        assert!(!store.contains_parsed_blob(stale_oid, "java").unwrap());
    }

    #[test]
    fn replacement_cost_set_preserves_duplicate_order_and_distinguishes_all_states() {
        let temp = tempfile::TempDir::new().unwrap();
        let old_file = write_file(temp.path(), "Old.java", "class Old { int value; }\n");
        let old_state = Arc::new(parse_state(&JavaAdapter, &old_file));
        let complete_oid = oid_for(b"complete replacement cost");
        let root_only_oid = oid_for(b"root-only replacement cost");
        let missing_oid = oid_for(b"missing replacement cost");
        let store = AnalyzerStore::open_in_memory().unwrap();
        let generation = store
            .ensure_language_epoch_value("java", "mixed-replacement-costs")
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                complete_oid,
                "java",
                generation,
                &JavaAdapter,
                &old_state,
            )
            .unwrap();
        store
            .register_blobs(&[root_only_oid], "java", generation)
            .unwrap();
        let prepare = |oid| {
            AnalyzerStore::prepare_parsed_blob(
                oid,
                "java",
                generation,
                &JavaAdapter,
                Arc::clone(&old_state),
            )
            .unwrap()
        };
        let complete_prepared = prepare(complete_oid);
        let expected_complete = PersistedMutationCost {
            logical_rows: complete_prepared.logical_rows(),
            // Source bytes are part of the transient insertion budget but are not
            // stored in SQLite, so physical replacement cost excludes them.
            payload_bytes: complete_prepared
                .payload_bytes()
                .saturating_sub(old_state.source.len()),
        };
        store.reset_replacement_cost_lookup_queries_for_test();
        let conn = store.conn.lock().expect("store mutex");
        let requested = vec![
            prepare(missing_oid),
            complete_prepared,
            prepare(root_only_oid),
            prepare(complete_oid),
        ];
        assert_eq!(
            store.stored_blob_cascade_costs(&conn, &requested).unwrap(),
            vec![
                StoredCascadeCost::Missing,
                StoredCascadeCost::Known(expected_complete),
                StoredCascadeCost::Known(PersistedMutationCost {
                    logical_rows: 1,
                    payload_bytes: 0,
                }),
                StoredCascadeCost::Known(expected_complete),
            ],
            "the ordinal-bearing VALUES relation must preserve order and duplicates"
        );
        assert_eq!(store.replacement_cost_lookup_queries_for_test(), 1);
        assert_eq!(store.replacement_cost_fallback_queries_for_test(), 0);

        conn.execute(
            "UPDATE blobs
             SET cascade_logical_rows = 999, cascade_payload_bytes = 999
             WHERE blob_oid = ?1 AND lang = 'java'",
            [complete_oid.to_string()],
        )
        .unwrap();
        conn.execute(
            "DELETE FROM blob_payload_costs WHERE blob_oid = ?1 AND lang = 'java'",
            [complete_oid.to_string()],
        )
        .unwrap();
        store.reset_replacement_cost_lookup_queries_for_test();
        let legacy_request = vec![prepare(complete_oid)];
        assert_eq!(
            store
                .stored_blob_cascade_costs(&conn, &legacy_request)
                .unwrap(),
            vec![StoredCascadeCost::Legacy],
            "non-NULL v5 columns are not trustworthy byte costs and must be ignored"
        );
        let mut fallback_statement = conn
            .prepare_cached(persisted_blob_mutation_cost_fallback_sql())
            .unwrap();
        assert_eq!(
            persisted_blob_mutation_cost_fallback_statement(
                &mut fallback_statement,
                complete_oid.to_string().as_str(),
                "java",
            )
            .unwrap(),
            PersistedMutationCost {
                logical_rows: expected_complete.logical_rows.saturating_sub(1),
                payload_bytes: expected_complete.payload_bytes,
            },
            "a migrated parsed row without payload cost must use the legacy aggregate"
        );
        assert_eq!(store.replacement_cost_lookup_queries_for_test(), 1);
    }

    #[test]
    fn replacement_cost_set_uses_only_bounded_primary_key_probes() {
        let store = AnalyzerStore::open_in_memory().unwrap();
        let conn = store.conn.lock().expect("store mutex");
        let explain = |query: &str, parameters: &[&str]| {
            let sql = format!("EXPLAIN QUERY PLAN {query}");
            let mut statement = conn.prepare(&sql).unwrap();
            statement
                .query_map(params_from_iter(parameters.iter().copied()), |row| {
                    row.get::<_, String>(3)
                })
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap()
        };

        let fast_plan = explain(
            &stored_blob_cascade_costs_sql(3),
            &["oid-a", "java", "oid-b", "java", "oid-a", "java"],
        );
        for table in ["blob", "meta", "costs"] {
            assert!(
                fast_plan
                    .iter()
                    .any(|detail| detail.contains(&format!("SEARCH {table} USING PRIMARY KEY"))),
                "set lookup for {table} must use its composite primary key: {fast_plan:#?}"
            );
            assert!(
                fast_plan
                    .iter()
                    .all(|detail| !detail.contains(&format!("SCAN {table}"))),
                "set lookup must not scan persisted table {table}: {fast_plan:#?}"
            );
        }
        assert!(
            fast_plan
                .iter()
                .all(|detail| !detail.contains("USE TEMP B-TREE")),
            "set lookup must not materialize grouping or ordering state: {fast_plan:#?}"
        );

        let fallback_plan = explain(
            persisted_blob_mutation_cost_fallback_sql(),
            &["oid-a", "java"],
        );
        for table in [
            "blob",
            "meta",
            "code_units",
            "unit_signatures",
            "unit_signature_metadata",
            "unit_supertypes",
            "import_statements",
            "import_details",
            "type_identifiers",
        ] {
            assert!(
                fallback_plan
                    .iter()
                    .any(|detail| detail.contains(&format!("SEARCH {table} USING PRIMARY KEY"))),
                "legacy replacement-cost branch for {table} must use its composite primary key: {fallback_plan:#?}"
            );
            assert!(
                fallback_plan
                    .iter()
                    .all(|detail| !detail.contains(&format!("SCAN {table}"))),
                "legacy replacement-cost branch for {table} must not scan: {fallback_plan:#?}"
            );
        }
        assert!(
            fallback_plan
                .iter()
                .all(|detail| !detail.contains("USE TEMP B-TREE")),
            "legacy replacement-cost fallback must not materialize grouping state: {fallback_plan:#?}"
        );
    }

    #[test]
    fn prepared_blob_batches_respect_row_and_payload_caps() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(temp.path(), "Model.java", "class Model {}\n");
        let state = Arc::new(parse_state(&JavaAdapter, &file));
        let make = |index| {
            AnalyzerStore::prepare_parsed_blob(
                Oid::hash_object(ObjectType::Blob, format!("blob-{index}").as_bytes()).unwrap(),
                "java",
                GenerationId::BOOTSTRAP,
                &JavaAdapter,
                Arc::clone(&state),
            )
            .unwrap()
        };
        let sample = make(99);
        let row_cap = sample.logical_rows().saturating_mul(2);
        let byte_cap = sample.payload_bytes().saturating_mul(2);
        let store = AnalyzerStore::open_in_memory().unwrap();
        let (_, stats) = store.persist_prepared_blobs(
            vec![make(0), make(1), make(2)],
            PersistBatchLimits {
                max_blobs: 64,
                max_rows: row_cap,
                max_payload_bytes: byte_cap,
            },
        );
        assert_eq!(stats.transactions, 2);
        assert!(stats.peak_batch_rows <= row_cap);
        assert!(stats.peak_batch_payload_bytes <= byte_cap);
    }

    #[test]
    fn prepared_replacement_budget_counts_deleted_rows_and_isolates_oversize_work() {
        let temp = tempfile::TempDir::new().unwrap();
        let old_file = write_file(
            temp.path(),
            "Old.java",
            "class A {} class B {} class C {} class D {} class E {} class F {}\n",
        );
        let replacement_file = write_file(temp.path(), "Replacement.java", "class Fresh {}\n");
        let peer_file = write_file(temp.path(), "Peer.java", "class Peer {}\n");
        let old_state = parse_state(&JavaAdapter, &old_file);
        let replacement_state = Arc::new(parse_state(&JavaAdapter, &replacement_file));
        let peer_state = Arc::new(parse_state(&JavaAdapter, &peer_file));
        let replaced_oid = oid_for(b"replaced logical identity");
        let peer_oid = oid_for(b"peer logical identity");
        let store = AnalyzerStore::open_in_memory().unwrap();
        let generation_a = store
            .ensure_language_epoch_value("java", "replacement-budget-a")
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                replaced_oid,
                "java",
                generation_a,
                &JavaAdapter,
                &old_state,
            )
            .unwrap();
        let generation_b = store
            .ensure_language_epoch_value("java", "replacement-budget-b")
            .unwrap();
        let replacement = AnalyzerStore::prepare_parsed_blob(
            replaced_oid,
            "java",
            generation_b,
            &JavaAdapter,
            replacement_state,
        )
        .unwrap();
        let replacement_insert_rows = replacement.logical_rows();
        let replacement_insert_bytes = replacement.payload_bytes();
        let peer = AnalyzerStore::prepare_parsed_blob(
            peer_oid,
            "java",
            generation_b,
            &JavaAdapter,
            peer_state,
        )
        .unwrap();
        let row_cap = replacement_insert_rows.saturating_add(peer.logical_rows());
        let byte_cap = replacement_insert_bytes.saturating_add(peer.payload_bytes());

        let (outcomes, stats) = store.persist_prepared_blobs(
            vec![replacement, peer],
            PersistBatchLimits {
                max_blobs: 8,
                max_rows: row_cap,
                max_payload_bytes: byte_cap,
            },
        );

        assert!(outcomes.iter().all(|outcome| outcome.error.is_none()));
        assert_eq!(
            stats.transactions, 2,
            "oversize replacement must be isolated"
        );
        assert_eq!(stats.committed_blobs, 2);
        assert!(stats.logical_rows > row_cap, "deleted rows must be counted");
        assert!(
            stats.peak_batch_rows > row_cap,
            "one oversize item must progress"
        );
        assert!(
            stats.payload_bytes > byte_cap,
            "deleted bytes must be counted"
        );
        assert!(
            stats.peak_batch_payload_bytes > byte_cap,
            "one oversized replacement must progress past the byte cap"
        );
        assert_eq!(
            stats.peak_batch_blobs, 2,
            "stats must retain the failed two-blob attempt that triggered isolation"
        );
    }

    #[test]
    fn failed_prepared_blob_isolated_without_hiding_good_peers() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(temp.path(), "Model.java", "class Model {}\n");
        let state = Arc::new(parse_state(&JavaAdapter, &file));
        let prepare = |text: &[u8]| {
            let oid = Oid::hash_object(ObjectType::Blob, text).unwrap();
            let prepared = AnalyzerStore::prepare_parsed_blob(
                oid,
                "java",
                GenerationId::BOOTSTRAP,
                &JavaAdapter,
                Arc::clone(&state),
            )
            .unwrap();
            (oid, prepared)
        };
        let (good_a_oid, good_a) = prepare(b"good-a");
        let (bad_oid, mut bad) = prepare(b"bad");
        bad.inject_invalid_range_for_test();
        let (good_b_oid, good_b) = prepare(b"good-b");
        let store = AnalyzerStore::open_in_memory().unwrap();

        let (outcomes, stats) = store.persist_prepared_blobs(
            vec![good_a, bad, good_b],
            PersistBatchLimits {
                max_blobs: 64,
                max_rows: usize::MAX,
                max_payload_bytes: usize::MAX,
            },
        );

        assert!(store.contains_parsed_blob(good_a_oid, "java").unwrap());
        assert!(store.contains_parsed_blob(good_b_oid, "java").unwrap());
        assert!(!store.contains_parsed_blob(bad_oid, "java").unwrap());
        assert_eq!(store.content_row_count(bad_oid, "java").unwrap(), 0);
        assert_eq!(stats.committed_blobs, 2);
        assert_eq!(stats.failed_blobs, 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| outcome.error.is_some())
                .count(),
            1
        );
    }

    #[test]
    fn linked_worktrees_share_analyzer_db_path() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo_root = temp.path().join("repo");
        std::fs::create_dir(&repo_root).unwrap();
        let repo = init_repo(&repo_root);
        std::fs::write(repo_root.join("tracked.txt"), "hello\n").unwrap();
        commit_all(&repo, "init");

        let linked_root = temp.path().join("linked");
        let worktree = repo.worktree("linked", &linked_root, None).unwrap();
        let linked_repo = git2::Repository::open_from_worktree(&worktree).unwrap();
        assert!(linked_repo.is_worktree());

        assert_eq!(
            std::fs::canonicalize(
                analyzer_db_path(&repo_root)
                    .parent()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .parent()
                    .unwrap()
            )
            .unwrap(),
            std::fs::canonicalize(
                analyzer_db_path(&linked_root)
                    .parent()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .parent()
                    .unwrap()
            )
            .unwrap()
        );
        assert_eq!(
            analyzer_db_path(&repo_root)
                .file_name()
                .and_then(|n| n.to_str()),
            Some(crate::cache_db::cache_db_file_name())
        );
        assert_eq!(
            analyzer_db_path(&repo_root),
            repo.workdir()
                .unwrap()
                .join(crate::gitblob::PROJECT_DIR_NAME)
                .join(crate::gitblob::CACHE_SUBDIR_NAME)
                .join(crate::cache_db::cache_db_file_name())
        );
        assert_eq!(analyzer_db_path(&repo_root), analyzer_db_path(&linked_root));
    }

    #[test]
    fn round_trips_java_python_and_typescript_file_states() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let java_file = write_file(
            root,
            "src/demo/Example.java",
            "package demo;\nimport java.util.List;\nclass Example { void run() {} }\n",
        );
        let python_init = write_file(root, "pkg/__init__.py", "");
        let python_file = write_file(
            root,
            "pkg/mod.py",
            "import os\nclass Example:\n    def run(self):\n        return os.getcwd()\n",
        );
        let ts_file = write_file(
            root,
            "src/example.test.ts",
            "import {Thing} from './thing';\nexport class Example { run(): Thing { return new Thing(); } }\n",
        );
        let _ = python_init;

        assert_round_trip(&JavaAdapter, "java", &java_file);
        assert_round_trip(&PythonAdapter, "python", &python_file);
        assert_round_trip(&TypescriptAdapter, "typescript", &ts_file);
    }

    #[test]
    fn round_trips_python_crlf_class_signature() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let python_file = write_file(
            root,
            "pkg/documented.py",
            "# Comment before class\r\nclass DocumentedClass:\r\n    pass\r\n",
        );
        let source = python_file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let adapter = PythonAdapter;
        let parsed = parse_state(&adapter, &python_file);
        let store = AnalyzerStore::open_in_memory().unwrap();
        store
            .write_parsed_blob(oid, "python", &adapter, &parsed)
            .unwrap();

        let hydrated = store
            .hydrate_file_state(oid, "python", &adapter, &python_file)
            .unwrap()
            .unwrap();
        assert_file_state_equivalent(&parsed, &hydrated);
        assert!(
            hydrated
                .signatures
                .values()
                .flatten()
                .any(|signature| signature == "class DocumentedClass:"),
            "expected CRLF class signature to survive store round trip, got {:?}",
            hydrated.signatures
        );
    }

    #[test]
    fn round_trips_ruby_dispatch_and_scala_trait_side_tables() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let ruby_file = write_file(
            root,
            "lib/demo.rb",
            "module Demo\n  module_function\n  def build(value)\n    Product.new(value)\n  end\n  class Product\n    attr_reader :name\n    alias_method :label, :name\n    def initialize(name)\n      @name = name\n    end\n    def self.featured\n      new('sample')\n    end\n  end\nend\n",
        );
        let scala_file = write_file(
            root,
            "src/main/scala/app/Demo.scala",
            "package app\ntrait Runnable { def run(first: Int = 0)(rest: String*): Int }\nclass Worker extends Runnable\nobject Core { def run(): Int = 1 }\nobject Facade { export Core.{run as execute, *} }\n",
        );

        assert_round_trip(&RubyAdapter, "ruby", &ruby_file);
        assert_round_trip(&ScalaAdapter, "scala", &scala_file);
    }

    #[test]
    fn prepared_writer_matches_legacy_adapter_projections() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let ruby_file = write_file(
            root,
            "lib/demo.rb",
            "module Demo\n  module_function\n  def build(value)\n    Product.new(value)\n  end\n  class Product\n    attr_reader :name\n    alias_method :label, :name\n  end\nend\n",
        );
        let scala_file = write_file(
            root,
            "src/main/scala/app/Demo.scala",
            "package app\nimport scala.collection.mutable.ListBuffer\ntrait Runnable\nclass Worker extends Runnable\nobject Core { def run(): Int = 1 }\nobject Facade { export Core.{run as execute, *} }\n",
        );
        let ts_file = write_file(
            root,
            "src/demo.test.ts",
            "import {Thing} from './thing';\nexport class Demo { run(value: Thing): Thing { return value; } }\n",
        );

        assert_legacy_prepared_parity(&RubyAdapter, "ruby", &ruby_file);
        assert_legacy_prepared_parity(&ScalaAdapter, "scala", &scala_file);
        assert_legacy_prepared_parity(&TypescriptAdapter, "typescript", &ts_file);
    }

    #[test]
    fn identical_python_blob_hydrates_with_live_path_names() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let content = "class Shared:\n    def run(self):\n        return 1\n";
        let _ = write_file(root, "pkg_a/__init__.py", "");
        let _ = write_file(root, "pkg_b/__init__.py", "");
        let _ = write_file(root, "pkg_b/sub/__init__.py", "");
        let file_a = write_file(root, "pkg_a/mod.py", content);
        let file_b = write_file(root, "pkg_b/sub/mod.py", content);
        let oid = oid_for(content.as_bytes());
        let adapter = PythonAdapter;
        let state_a = parse_state(&adapter, &file_a);
        let state_b = parse_state(&adapter, &file_b);
        let store = AnalyzerStore::open_in_memory().unwrap();

        store
            .write_parsed_blob(oid, "python", &adapter, &state_a)
            .unwrap();
        let first_count = store.content_row_count(oid, "python").unwrap();
        store
            .write_parsed_blob(oid, "python", &adapter, &state_b)
            .unwrap();
        assert_eq!(store.content_row_count(oid, "python").unwrap(), first_count);

        let hydrated_a = store
            .hydrate_file_state(oid, "python", &adapter, &file_a)
            .unwrap()
            .unwrap();
        let hydrated_b = store
            .hydrate_file_state(oid, "python", &adapter, &file_b)
            .unwrap()
            .unwrap();
        assert_file_state_equivalent(&state_a, &hydrated_a);
        assert_file_state_equivalent(&state_b, &hydrated_b);
        assert_eq!(hydrated_a.package_name, "pkg_a.mod");
        assert_eq!(hydrated_b.package_name, "pkg_b.sub.mod");
        assert!(
            hydrated_a
                .declarations
                .iter()
                .any(|unit| unit.fq_name() == "pkg_a.mod.Shared")
        );
        assert!(
            hydrated_b
                .declarations
                .iter()
                .any(|unit| unit.fq_name() == "pkg_b.sub.mod.Shared")
        );
    }

    #[test]
    fn identical_go_blob_hydrates_with_live_import_paths() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let _ = write_file(root, "go.mod", "module example.com/demo\n");
        let content = "package service\ntype Client struct{}\n";
        let file_a = write_file(root, "alpha/client.go", content);
        let file_b = write_file(root, "beta/client.go", content);
        let oid = oid_for(content.as_bytes());
        let adapter = GoAdapter;
        let state = parse_state(&adapter, &file_a);
        let store = AnalyzerStore::open_in_memory().unwrap();

        store
            .write_parsed_blob(oid, "go", &adapter, &state)
            .unwrap();
        let hydrated_a = store
            .hydrate_file_state(oid, "go", &adapter, &file_a)
            .unwrap()
            .unwrap();
        let hydrated_b = store
            .hydrate_file_state(oid, "go", &adapter, &file_b)
            .unwrap()
            .unwrap();

        assert_eq!(hydrated_a.content_qualifier, "service");
        assert_eq!(hydrated_b.content_qualifier, "service");
        assert_eq!(hydrated_a.package_name, "example.com/demo/alpha");
        assert_eq!(hydrated_b.package_name, "example.com/demo/beta");
        assert!(
            hydrated_a
                .declarations
                .iter()
                .any(|unit| unit.fq_name() == "example.com/demo/alpha.Client")
        );
        assert!(
            hydrated_b
                .declarations
                .iter()
                .any(|unit| unit.fq_name() == "example.com/demo/beta.Client")
        );
    }

    #[test]
    fn writer_is_idempotent_for_same_blob() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "src/demo/Repeat.java",
            "package demo;\nclass Repeat { int value; }\n",
        );
        let oid = oid_for(file.read_to_string().unwrap().as_bytes());
        let adapter = JavaAdapter;
        let state = parse_state(&adapter, &file);
        let store = AnalyzerStore::open_in_memory().unwrap();

        store
            .write_parsed_blob(oid, "java", &adapter, &state)
            .unwrap();
        let first_count = store.content_row_count(oid, "java").unwrap();
        store
            .write_parsed_blob(oid, "java", &adapter, &state)
            .unwrap();
        assert_eq!(store.content_row_count(oid, "java").unwrap(), first_count);
    }

    #[test]
    fn rejects_bad_blob_oid_hex() {
        let store = AnalyzerStore::open_in_memory().unwrap();
        let conn = store.conn.lock().unwrap();
        let err = conn
            .execute(
                "INSERT INTO blobs(blob_oid, lang) VALUES(?1, ?2)",
                params!["zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "rust"],
            )
            .unwrap_err();
        assert_constraint_error(err, "CHECK");
    }

    #[test]
    fn rejects_inverted_unit_range() {
        let store = AnalyzerStore::open_in_memory().unwrap();
        let conn = store.conn.lock().unwrap();
        insert_test_blob_and_unit(&conn);
        let err = conn
            .execute(
                "INSERT INTO unit_ranges(
                   blob_oid, lang, unit_key, ordinal, start_byte, end_byte, start_line, end_line
                 ) VALUES(?1, 'rust', 1, 0, 10, 2, 4, 3)",
                [TEST_OID],
            )
            .unwrap_err();
        assert_constraint_error(err, "CHECK");
    }

    #[test]
    fn rejects_self_parent_child_edge() {
        let store = AnalyzerStore::open_in_memory().unwrap();
        let conn = store.conn.lock().unwrap();
        insert_test_blob_and_unit(&conn);
        let err = conn
            .execute(
                "INSERT INTO unit_children(blob_oid, lang, parent_key, child_key, ordinal)
                 VALUES(?1, 'rust', 1, 1, 0)",
                [TEST_OID],
            )
            .unwrap_err();
        assert_constraint_error(err, "CHECK");
    }

    #[test]
    fn rejects_satellite_row_without_code_unit_parent() {
        let store = AnalyzerStore::open_in_memory().unwrap();
        let conn = store.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang) VALUES(?1, 'rust')",
            [TEST_OID],
        )
        .unwrap();
        let err = conn
            .execute(
                "INSERT INTO unit_signatures(blob_oid, lang, unit_key, ordinal, text)
                 VALUES(?1, 'rust', 99, 0, 'fn orphan()')",
                [TEST_OID],
            )
            .unwrap_err();
        assert_constraint_error(err, "FOREIGN KEY");
    }

    #[test]
    fn rejects_forbidden_persisted_code_unit_kinds() {
        let store = AnalyzerStore::open_in_memory().unwrap();
        let conn = store.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang) VALUES(?1, 'rust')",
            [TEST_OID],
        )
        .unwrap();
        let file_scope_err = conn
            .execute(
                "INSERT INTO code_units(
                   blob_oid, lang, unit_key, kind, short_name, identifier, content_qualifier,
                   signature, synthetic, is_type_alias, top_level_ordinal,
                   in_declarations, in_definition_lookup
                 ) VALUES(?1, 'rust', 1, 5, 'file', 'file', '', NULL, 0, 0, 0, 1, 0)",
                [TEST_OID],
            )
            .unwrap_err();
        assert_constraint_error(file_scope_err, "CHECK");

        let python_module_err = conn
            .execute(
                "INSERT INTO blobs(blob_oid, lang) VALUES(?1, 'python')",
                [TEST_OID],
            )
            .and_then(|_| {
                conn.execute(
                    "INSERT INTO code_units(
                       blob_oid, lang, unit_key, kind, short_name, identifier, content_qualifier,
                       signature, synthetic, is_type_alias, top_level_ordinal,
                       in_declarations, in_definition_lookup
                     ) VALUES(?1, 'python', 1, 3, 'mod', 'mod', '', NULL, 0, 0, 0, 1, 0)",
                    [TEST_OID],
                )
            })
            .unwrap_err();
        assert_constraint_error(python_module_err, "CHECK");
    }

    fn assert_round_trip<A: LanguageAdapter>(adapter: &A, lang: &str, file: &ProjectFile) {
        let source = file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let parsed = parse_state(adapter, file);
        let store = AnalyzerStore::open_in_memory().unwrap();
        store
            .write_parsed_blob(oid, lang, adapter, &parsed)
            .unwrap();
        let hydrated = store
            .hydrate_file_state(oid, lang, adapter, file)
            .unwrap()
            .unwrap();
        assert_file_state_equivalent(&parsed, &hydrated);
        assert!(hydrated.source.is_empty());
        assert!(hydrated.parse_errors.is_none());
    }

    fn assert_legacy_prepared_parity<A: LanguageAdapter>(
        adapter: &A,
        lang: &str,
        file: &ProjectFile,
    ) {
        let source = file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let parsed = Arc::new(parse_state(adapter, file));
        let legacy = AnalyzerStore::open_in_memory().unwrap();
        legacy
            .write_parsed_blob(oid, lang, adapter, parsed.as_ref())
            .unwrap();
        let prepared_store = AnalyzerStore::open_in_memory().unwrap();
        let prepared = AnalyzerStore::prepare_parsed_blob(
            oid,
            lang,
            GenerationId::BOOTSTRAP,
            adapter,
            Arc::clone(&parsed),
        )
        .unwrap();
        let (outcomes, stats) =
            prepared_store.persist_prepared_blobs(vec![prepared], PersistBatchLimits::PRODUCTION);
        assert_eq!(stats.transactions, 1);
        assert_eq!(stats.committed_blobs, 1);
        assert!(outcomes.iter().all(|outcome| outcome.error.is_none()));

        let legacy_state = legacy
            .hydrate_file_state(oid, lang, adapter, file)
            .unwrap()
            .unwrap();
        let prepared_state = prepared_store
            .hydrate_file_state(oid, lang, adapter, file)
            .unwrap()
            .unwrap();
        assert_file_state_equivalent(parsed.as_ref(), &legacy_state);
        assert_file_state_equivalent(parsed.as_ref(), &prepared_state);
        assert_file_state_equivalent(&legacy_state, &prepared_state);
        let bulk_states = prepared_store
            .hydrate_file_states(
                &[(file.clone(), oid)],
                lang,
                adapter,
                &HashMap::from_iter([(file.clone(), source)]),
            )
            .unwrap();
        assert_eq!(
            bulk_states
                .get(file)
                .expect("prepared blob should bulk hydrate")
                .scala_exports,
            parsed.scala_exports
        );
        assert_eq!(
            legacy.content_row_count(oid, lang).unwrap(),
            prepared_store.content_row_count(oid, lang).unwrap()
        );
    }

    fn assert_deleting_side_table_marks_incomplete<A: LanguageAdapter>(
        adapter: &A,
        lang: &str,
        file: &ProjectFile,
        table: &str,
    ) {
        let source = file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let parsed = parse_state(adapter, file);
        let store = AnalyzerStore::open_in_memory().unwrap();
        store
            .write_parsed_blob(oid, lang, adapter, &parsed)
            .unwrap();

        {
            let conn = store.conn.lock().unwrap();
            let count_sql =
                format!("SELECT COUNT(*) FROM {table} WHERE blob_oid = ?1 AND lang = ?2");
            let count: usize = conn
                .query_row(&count_sql, params![oid.to_string(), lang], |row| row.get(0))
                .unwrap();
            assert!(
                count > 0,
                "fixture should persist at least one {table} row for {lang}"
            );
            let delete_sql = format!("DELETE FROM {table} WHERE blob_oid = ?1 AND lang = ?2");
            conn.execute(&delete_sql, params![oid.to_string(), lang])
                .unwrap();
        }

        assert!(!store.contains_parsed_blob(oid, lang).unwrap());
        assert_eq!(
            store
                .missing_parsed_blob_keys(&[(oid, lang.to_string())])
                .unwrap(),
            vec![(oid, lang.to_string())]
        );
        assert!(
            store
                .hydrate_file_state(oid, lang, adapter, file)
                .unwrap()
                .is_none()
        );
        assert!(
            !store
                .hydrate_file_states(&[(file.clone(), oid)], lang, adapter, &HashMap::default())
                .unwrap()
                .contains_key(file)
        );
    }

    fn parse_state<A: LanguageAdapter>(adapter: &A, file: &ProjectFile) -> FileState {
        let source = file.read_to_string().unwrap();
        let mut parser = Parser::new();
        parser
            .set_language(&adapter.parser_language())
            .expect("set parser language");
        let tree = parser.parse(source.as_str(), None).expect("parse file");
        let mut parsed: ParsedFile = adapter.parse_file(file, &source, &tree);
        parsed.add_file_scope(file, &source);
        let contains_tests = adapter.contains_tests(file, &source, &tree, &parsed);
        let declarations = parsed.declarations().clone();
        FileState {
            source,
            content_qualifier: parsed.content_qualifier,
            package_name: parsed.package_name,
            top_level_declarations: parsed.top_level_declarations,
            declarations,
            definition_lookup_units: parsed.definition_lookup_units,
            import_statements: parsed.import_statements,
            imports: parsed.imports,
            scala_exports: parsed.scala_exports,
            rust_usage_facts: parsed.rust_usage_facts,
            raw_supertypes: parsed.raw_supertypes,
            supertype_lookup_paths: parsed.supertype_lookup_paths,
            type_identifiers: parsed.type_identifiers,
            signatures: parsed.signatures,
            signature_metadata: parsed.signature_metadata,
            cpp_template_metadata: parsed.cpp_template_metadata,
            ranges: parsed.ranges,
            children: parsed.children,
            type_aliases: parsed.type_aliases,
            ruby_method_dispatch_modes: parsed.ruby_method_dispatch_modes,
            scala_traits: parsed.scala_traits,
            contains_tests,
            test_region_units: parsed.test_region_units,
            materialization_records: parsed.materialization_records,
            parse_errors: Some(Vec::new()),
        }
    }

    fn assert_file_state_equivalent(expected: &FileState, actual: &FileState) {
        assert_eq!(actual.package_name, expected.package_name);
        assert_eq!(
            actual.top_level_declarations,
            expected.top_level_declarations
        );
        assert_eq!(actual.declarations, expected.declarations);
        assert_eq!(actual.scala_exports, expected.scala_exports);
        assert_eq!(
            actual.definition_lookup_units,
            expected.definition_lookup_units
        );
        assert_eq!(actual.import_statements, expected.import_statements);
        assert_eq!(actual.imports, expected.imports);
        assert_eq!(
            non_empty_string_vec_entries(&actual.raw_supertypes),
            non_empty_string_vec_entries(&expected.raw_supertypes)
        );
        assert_eq!(
            non_empty_string_vec_entries(&actual.supertype_lookup_paths),
            non_empty_string_vec_entries(&expected.supertype_lookup_paths)
        );
        assert_eq!(actual.type_identifiers, expected.type_identifiers);
        assert_eq!(actual.signatures, expected.signatures);
        assert_eq!(actual.signature_metadata, expected.signature_metadata);
        assert_eq!(
            actual.materialization_records,
            expected.materialization_records
        );
        assert_eq!(actual.cpp_template_metadata, expected.cpp_template_metadata);
        assert_eq!(actual.ranges, expected.ranges);
        assert_eq!(
            non_empty_code_unit_vec_entries(&actual.children),
            non_empty_code_unit_vec_entries(&expected.children)
        );
        assert_eq!(actual.type_aliases, expected.type_aliases);
        assert_eq!(
            actual.ruby_method_dispatch_modes,
            expected.ruby_method_dispatch_modes
        );
        assert_eq!(actual.scala_traits, expected.scala_traits);
        assert_eq!(actual.contains_tests, expected.contains_tests);
        assert_eq!(actual.test_region_units, expected.test_region_units);
        assert!(actual.source.is_empty());
        assert!(actual.parse_errors.is_none());
    }

    fn non_empty_string_vec_entries(
        map: &HashMap<CodeUnit, Vec<String>>,
    ) -> HashMap<CodeUnit, Vec<String>> {
        map.iter()
            .filter(|(_, values)| !values.is_empty())
            .map(|(unit, values)| (unit.clone(), values.clone()))
            .collect()
    }

    fn non_empty_code_unit_vec_entries(
        map: &HashMap<CodeUnit, Vec<CodeUnit>>,
    ) -> HashMap<CodeUnit, Vec<CodeUnit>> {
        map.iter()
            .filter(|(_, values)| !values.is_empty())
            .map(|(unit, values)| (unit.clone(), values.clone()))
            .collect()
    }

    const TEST_OID: &str = "1111111111111111111111111111111111111111";

    fn insert_test_blob_and_unit(conn: &Connection) {
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang) VALUES(?1, 'rust')",
            [TEST_OID],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO code_units(
               blob_oid, lang, unit_key, kind, short_name, identifier, content_qualifier,
               signature, synthetic, is_type_alias, top_level_ordinal,
               in_declarations, in_definition_lookup
             ) VALUES(?1, 'rust', 1, 0, 'Thing', 'Thing', '', NULL, 0, 0, 0, 1, 0)",
            [TEST_OID],
        )
        .unwrap();
    }

    fn assert_constraint_error(err: rusqlite::Error, expected: &str) {
        let message = err.to_string();
        assert!(
            message.contains(expected),
            "expected {expected} constraint error, got {message}"
        );
    }

    /// Ruby generation provenance (issue #1476) survives the store: the
    /// producer records literal `attr_*`/`alias_method` generation and the
    /// dynamic site, and both hydration paths return the records verbatim.
    #[test]
    fn materialization_records_round_trip_through_persistence() {
        use crate::analyzer::structural::materialization::{
            GenerationInputClass, GenerationKind, MaterializationRecord,
        };

        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "provenance.rb",
            "class Widget\n  attr_accessor :name\n  attr_reader label.to_sym\n  def base; end\n  alias_method :aliased, :base\nend\n",
        );
        let source = file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let state = parse_state(&RubyAdapter, &file);

        let records = &state.materialization_records;
        let generated_units: Vec<_> = records
            .iter()
            .filter_map(|record| match record {
                MaterializationRecord::GeneratedDeclaration { kind, unit, .. } => {
                    Some((*kind, unit.fq_name().to_string()))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            generated_units,
            vec![
                (GenerationKind::AccessorMacro, "Widget.@name".to_string()),
                (GenerationKind::AccessorMacro, "Widget.name".to_string()),
                (GenerationKind::AccessorMacro, "Widget.name=".to_string()),
                (GenerationKind::AliasMacro, "Widget.aliased".to_string()),
            ],
            "complete recorded generation set: {records:?}"
        );
        let dynamic_sites: Vec<_> = records
            .iter()
            .filter_map(|record| match record {
                MaterializationRecord::DynamicGenerationSite { kind, .. } => Some(*kind),
                _ => None,
            })
            .collect();
        assert_eq!(dynamic_sites, vec![GenerationKind::AccessorMacro]);
        for record in records {
            if let MaterializationRecord::GeneratedDeclaration { site, argument, .. } = record {
                assert!(
                    site.start_byte <= argument.start_byte && argument.end_byte <= site.end_byte,
                    "argument must lie inside its generation site: {record:?}"
                );
                assert_eq!(GenerationInputClass::Literal.label(), "literal");
            }
        }

        let store = AnalyzerStore::open_in_memory().unwrap();
        let generation = store
            .ensure_language_epoch_value("ruby", "materialization-round-trip-v1")
            .unwrap();
        store
            .write_parsed_blob_at_generation(oid, "ruby", generation, &RubyAdapter, &state)
            .unwrap();

        let hydrated = store
            .hydrate_file_state_with_source(oid, "ruby", generation, &RubyAdapter, &file, &source)
            .unwrap()
            .expect("hydration should succeed");
        assert_eq!(
            hydrated.materialization_records,
            state.materialization_records
        );

        let bulk = store
            .hydrate_file_states(
                &[(file.clone(), oid)],
                "ruby",
                &RubyAdapter,
                &HashMap::from_iter([(file.clone(), source)]),
            )
            .unwrap();
        assert_eq!(
            bulk.get(&file)
                .expect("bulk hydration")
                .materialization_records,
            state.materialization_records
        );
    }

    /// C++ materialization provenance (issue #1476): a `#define` is a
    /// generation site producing its macro unit, a preprocessor conditional
    /// is a recorded configuration gate, and an export-macro class the parser
    /// broke is recorded as a recovered declaration.
    #[test]
    fn cpp_macro_config_and_recovery_records() {
        use crate::analyzer::structural::materialization::{GenerationKind, MaterializationRecord};

        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "config.h",
            concat!(
                "#define WIDGET_MAX 8\n",
                "#ifdef USE_FAST\n",
                "int fast_path();\n",
                "#else\n",
                "int slow_path();\n",
                "#endif\n",
            ),
        );
        let state = parse_state(&CppAdapter, &file);
        let records = &state.materialization_records;
        let generated: Vec<_> = records
            .iter()
            .filter_map(|record| match record {
                MaterializationRecord::GeneratedDeclaration { kind, unit, .. } => {
                    Some((*kind, unit.fq_name().to_string()))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            generated,
            vec![(
                GenerationKind::PreprocessorDefinition,
                "WIDGET_MAX".to_string()
            )],
            "records: {records:?}"
        );
        let gates: Vec<_> = records
            .iter()
            .filter_map(|record| match record {
                MaterializationRecord::ConfigurationConditional { range } => Some(*range),
                _ => None,
            })
            .collect();
        assert_eq!(gates.len(), 1, "records: {records:?}");
        let source = file.read_to_string().unwrap();
        let ifdef_start = source.find("#ifdef").unwrap();
        assert_eq!(gates[0].start_byte, ifdef_start);
        assert!(
            gates[0].end_byte >= source.find("slow_path").unwrap(),
            "the gate interval must cover the else branch: {:?}",
            gates[0]
        );

        // The f7a2bb5 shape: an export-annotation macro on a single-base class
        // makes tree-sitter parse the class as a bogus function definition;
        // recovery re-derives the class and must say it did so.
        let recovered_file = write_file(
            temp.path(),
            "exported.h",
            concat!(
                "class CORE_EXPORT QgsPoint : public QgsAbstractGeometry\n",
                "{\n",
                "  public:\n",
                "    QgsPoint( double x, double y );\n",
                "};\n",
            ),
        );
        let state = parse_state(&CppAdapter, &recovered_file);
        let recovered: Vec<_> = state
            .materialization_records
            .iter()
            .filter_map(|record| match record {
                MaterializationRecord::RecoveredDeclaration { unit, .. } => {
                    Some(unit.fq_name().to_string())
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            recovered,
            vec!["QgsPoint".to_string()],
            "records: {:?}",
            state.materialization_records
        );
    }

    /// TS export provenance (issue #1476): the TypeScript dialect's own
    /// visitor records the same export-row vocabulary, including type-space
    /// exports (interfaces, type aliases) and the default re-export.
    #[test]
    fn typescript_export_records_state_their_forms() {
        use crate::analyzer::structural::materialization::{ExportForm, MaterializationRecord};

        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "exports.ts",
            concat!(
                "export interface Shape { area(): number }\n",
                "export type Alias = Shape;\n",
                "export const answer = 42;\n",
                "export class Widget {}\n",
                "const table = { greet: 'hi' };\n",
                "export default table;\n",
            ),
        );
        let state = parse_state(&TypescriptAdapter, &file);
        let exports: Vec<_> = state
            .materialization_records
            .iter()
            .filter_map(|record| match record {
                MaterializationRecord::Export {
                    form,
                    exported_name,
                    ..
                } => Some((*form, exported_name.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(
            exports,
            vec![
                (ExportForm::Named, "Shape".to_string()),
                (ExportForm::Named, "Alias".to_string()),
                (ExportForm::Named, "answer".to_string()),
                (ExportForm::Named, "Widget".to_string()),
                (ExportForm::DefaultNamed, "default".to_string()),
            ],
            "records: {:?}",
            state.materialization_records
        );
    }

    /// JS export provenance (issue #1476): the producer records default,
    /// named, and CommonJS export rows with their forms, and the anonymous
    /// default's synthetic `default` unit is the row's target.
    #[test]
    fn javascript_export_records_state_their_forms() {
        use crate::analyzer::structural::materialization::{ExportForm, MaterializationRecord};

        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "exports.js",
            concat!(
                "export const answer = 42;\n",
                "export function makeWidget() {}\n",
                "const messages = { greet: 'hi' };\n",
                "export default messages;\n",
            ),
        );
        let state = parse_state(&crate::analyzer::javascript::JavascriptAdapter, &file);
        let exports: Vec<_> = state
            .materialization_records
            .iter()
            .filter_map(|record| match record {
                MaterializationRecord::Export {
                    form,
                    exported_name,
                    target,
                    ..
                } => Some((*form, exported_name.clone(), target.is_some())),
                _ => None,
            })
            .collect();
        assert_eq!(
            exports,
            vec![
                (ExportForm::Named, "answer".to_string(), false),
                (ExportForm::Named, "makeWidget".to_string(), false),
                (ExportForm::DefaultNamed, "default".to_string(), false),
            ],
            "records: {:?}",
            state.materialization_records
        );

        let commonjs = write_file(
            temp.path(),
            "commonjs.js",
            concat!(
                "const local = () => 1;\n",
                "module.exports = {\n",
                "  inline() { return 2; },\n",
                "  local,\n",
                "};\n",
            ),
        );
        let state = parse_state(&crate::analyzer::javascript::JavascriptAdapter, &commonjs);
        let exports: Vec<_> = state
            .materialization_records
            .iter()
            .filter_map(|record| match record {
                MaterializationRecord::Export {
                    form,
                    exported_name,
                    target,
                    ..
                } => Some((
                    *form,
                    exported_name.clone(),
                    target.as_ref().map(|unit| unit.fq_name().to_string()),
                )),
                _ => None,
            })
            .collect();
        assert_eq!(
            exports,
            vec![
                (ExportForm::CommonJsRoot, "module.exports".to_string(), None),
                (
                    ExportForm::CommonJsMember,
                    "inline".to_string(),
                    Some("inline".to_string())
                ),
                (ExportForm::CommonJsMember, "local".to_string(), None),
            ],
            "records: {:?}",
            state.materialization_records
        );

        let anonymous = write_file(
            temp.path(),
            "anonymous.js",
            "export default { greet: 'hi' };\n",
        );
        let state = parse_state(&crate::analyzer::javascript::JavascriptAdapter, &anonymous);
        let default_export = state
            .materialization_records
            .iter()
            .find_map(|record| match record {
                MaterializationRecord::Export {
                    form: ExportForm::DefaultAnonymous,
                    exported_name,
                    target,
                    ..
                } => Some((exported_name.clone(), target.clone())),
                _ => None,
            })
            .expect("anonymous default export row");
        assert_eq!(default_export.0, "default");
        assert_eq!(
            default_export.1.expect("synthetic default unit").fq_name(),
            "default"
        );
    }

    /// The fixture the `rust_*` fact-table tests share: one file that
    /// re-exports, imports (named, glob, aliased, function-local), declares an
    /// inline and a file module, and mentions identifiers in code, a comment,
    /// and a string.
    const RUST_USAGE_FACT_FIXTURE: &str = "\
pub use alpha::Exported;
pub use beta::Renamed as Alias;
pub use gamma::*;
use delta::Private;
mod detached;
mod inline {
    use crate::Scoped;
    pub fn helper() {
        use crate::Local;
        let _ = \"in_a_string\";
    }
}
// in_a_comment
";

    fn rust_usage_fact_store(temp: &Path) -> (AnalyzerStore, Oid) {
        let file = write_file(temp, "src/lib.rs", RUST_USAGE_FACT_FIXTURE);
        let oid = oid_for(RUST_USAGE_FACT_FIXTURE.as_bytes());
        let store = AnalyzerStore::open_in_memory().unwrap();
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &parse_state(&RustAdapter, &file))
            .unwrap();
        (store, oid)
    }

    #[test]
    fn rust_fact_tables_record_exports_imports_modules_and_occurrences() {
        let temp = tempfile::TempDir::new().unwrap();
        let (store, oid) = rust_usage_fact_store(temp.path());
        let facts = store.rust_usage_facts(oid, "rust").unwrap();

        let exports: Vec<_> = facts
            .exports
            .iter()
            .map(|export| {
                (
                    export.exported_name.as_deref(),
                    export.source_path.as_str(),
                    export.imported_name.as_deref(),
                    export.is_glob,
                )
            })
            .collect();
        assert_eq!(
            exports,
            vec![
                (Some("Exported"), "alpha", Some("Exported"), false),
                (Some("Alias"), "beta", Some("Renamed"), false),
                (None, "gamma", None, true),
            ],
            "private and non-root `use` declarations are not exports: {:?}",
            facts.exports
        );

        let imports: Vec<_> = facts
            .import_targets
            .iter()
            .map(|target| {
                (
                    target.module_path.as_str(),
                    target.bound_name.as_deref(),
                    target.is_glob,
                    target.owner_module.as_str(),
                    target.local_extent.is_some(),
                )
            })
            .collect();
        assert_eq!(
            imports,
            vec![
                ("alpha", Some("Exported"), false, "", false),
                ("beta", Some("Alias"), false, "", false),
                ("gamma", None, true, "", false),
                ("delta", Some("Private"), false, "", false),
                ("crate", Some("Scoped"), false, "inline", false),
                ("crate", Some("Local"), false, "inline", true),
            ],
            "import rows were {:?}",
            facts.import_targets
        );
        assert_eq!(
            facts.import_targets[0].visibility,
            crate::analyzer::rust::imports::RustVisibility::Public
        );
        assert_eq!(
            facts.import_targets[3].visibility,
            crate::analyzer::rust::imports::RustVisibility::Private
        );

        let modules: Vec<_> = facts
            .modules
            .iter()
            .map(|module| (module.module_name.as_str(), module.is_inline))
            .collect();
        assert_eq!(
            modules,
            vec![("", true), ("detached", false), ("inline", true)],
            "module rows were {:?}",
            facts.modules
        );
        assert_eq!(facts.modules[0].start_byte, 0);
        assert_eq!(facts.modules[0].end_byte, RUST_USAGE_FACT_FIXTURE.len());

        let mask = |name: &str| {
            facts
                .identifier_occurrences
                .iter()
                .find(|occurrence| occurrence.identifier == name)
                .map(|occurrence| occurrence.context_mask)
        };
        assert_eq!(
            mask("helper"),
            Some(crate::analyzer::rust::facts::RUST_OCCURRENCE_CODE)
        );
        assert_eq!(
            mask("in_a_comment"),
            Some(crate::analyzer::rust::facts::RUST_OCCURRENCE_COMMENT)
        );
        assert_eq!(
            mask("in_a_string"),
            Some(crate::analyzer::rust::facts::RUST_OCCURRENCE_STRING)
        );
    }

    #[test]
    fn rust_fact_tables_answer_the_inverted_name_lookups() {
        let temp = tempfile::TempDir::new().unwrap();
        let (store, oid) = rust_usage_fact_store(temp.path());

        assert_eq!(store.rust_export_blobs("rust", "Alias").unwrap(), vec![oid]);
        assert!(
            store
                .rust_export_blobs("rust", "Private")
                .unwrap()
                .is_empty(),
            "a private import must not answer an export lookup"
        );
        assert_eq!(
            store.rust_import_target_blobs("rust", "delta").unwrap(),
            vec![oid]
        );
        assert_eq!(
            store
                .rust_identifier_occurrence_blobs("rust", "helper")
                .unwrap(),
            vec![(oid, crate::analyzer::rust::facts::RUST_OCCURRENCE_CODE)]
        );
        assert!(
            store
                .rust_identifier_occurrence_blobs("rust", "HELPER")
                .unwrap()
                .is_empty(),
            "identifier lookups are case-sensitive"
        );
        assert!(
            store
                .rust_identifier_occurrence_blobs("java", "helper")
                .unwrap()
                .is_empty(),
            "identifier lookups are scoped to one language"
        );
    }

    #[test]
    fn rust_fact_rows_cascade_with_their_blob() {
        let temp = tempfile::TempDir::new().unwrap();
        let (store, oid) = rust_usage_fact_store(temp.path());
        let count = |store: &AnalyzerStore| {
            let conn = store.conn.lock().unwrap();
            [
                "rust_exports",
                "rust_import_targets",
                "rust_modules",
                "rust_identifier_occurrences",
                "rust_module_scopes",
                "rust_module_routes",
                "rust_module_route_gates",
                "rust_item_macros",
            ]
            .into_iter()
            .map(|table| {
                conn.query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE blob_oid = ?1 AND lang = ?2"),
                    params![oid.to_string(), "rust"],
                    |row| row.get::<_, usize>(0),
                )
                .unwrap()
            })
            .sum::<usize>()
        };

        assert!(count(&store) > 0, "fixture must persist fact rows");
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "DELETE FROM blobs WHERE blob_oid = ?1 AND lang = ?2",
                params![oid.to_string(), "rust"],
            )
            .unwrap();
        }
        assert_eq!(
            count(&store),
            0,
            "deleting the blob must cascade every rust_* fact row away"
        );
    }

    #[test]
    fn rust_fact_rows_are_stable_across_a_re_analysis_of_the_same_content() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(temp.path(), "src/lib.rs", RUST_USAGE_FACT_FIXTURE);
        let oid = oid_for(RUST_USAGE_FACT_FIXTURE.as_bytes());
        let store = AnalyzerStore::open_in_memory().unwrap();
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &parse_state(&RustAdapter, &file))
            .unwrap();
        let first = store.rust_usage_facts(oid, "rust").unwrap();

        // Same bytes at a different path: the content key is unchanged, so the
        // second analysis must produce byte-identical rows. Nothing persisted
        // here may be path-derived.
        let moved = write_file(temp.path(), "src/other/lib.rs", RUST_USAGE_FACT_FIXTURE);
        store
            .write_parsed_blob(
                oid,
                "rust",
                &RustAdapter,
                &parse_state(&RustAdapter, &moved),
            )
            .unwrap();
        let second = store.rust_usage_facts(oid, "rust").unwrap();

        assert_eq!(first, second);
    }

    /// The module-route fixture (issue #1793): a file whose declarations cover
    /// every column the Cargo route index reads -- an inline scope with a
    /// `#[path]`, a `#[macro_use]` declaration, a bare `#[cfg(test)]` gate, a
    /// `#[path]` on a declaration, an item macro definition, and a declaration
    /// that only exists inside that macro's expansion.
    const RUST_MODULE_ROUTE_FIXTURE: &str = "\
macro_rules! replay {
    ($($item:item)*) => { $($item)* };
}
mod plain;
#[macro_use]
mod macro_source;
#[cfg(test)]
mod gated;
#[path = \"custom/target.rs\"]
mod relocated;
#[path = \"elsewhere\"]
mod scope {
    mod deep;
}
replay! { mod replayed; }
";

    fn rust_module_route_store(temp: &Path, rel_path: &str) -> (AnalyzerStore, Oid) {
        let file = write_file(temp, rel_path, RUST_MODULE_ROUTE_FIXTURE);
        let oid = oid_for(RUST_MODULE_ROUTE_FIXTURE.as_bytes());
        let store = AnalyzerStore::open_in_memory().unwrap();
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &parse_state(&RustAdapter, &file))
            .unwrap();
        (store, oid)
    }

    #[test]
    fn rust_module_route_tables_record_scopes_routes_gates_and_item_macros() {
        let temp = tempfile::TempDir::new().unwrap();
        let (store, oid) = rust_module_route_store(temp.path(), "src/lib.rs");
        let routes = store.rust_usage_facts(oid, "rust").unwrap().module_routes;

        let scopes: Vec<_> = routes
            .scopes
            .iter()
            .map(|scope| {
                (
                    scope.parent,
                    scope.module_name.as_str(),
                    scope.path_attribute.as_deref(),
                    scope.imports_macros,
                )
            })
            .collect();
        assert_eq!(
            scopes,
            vec![
                (None, "", None, true),
                (Some(0), "scope", Some("elsewhere"), false),
            ],
            "scopes were {:?}",
            routes.scopes
        );
        assert_eq!(routes.scopes[0].body_start, 0);
        assert_eq!(
            routes.scopes[0].body_end,
            RUST_MODULE_ROUTE_FIXTURE.len(),
            "the root scope spans the whole source"
        );

        let described: Vec<_> = routes
            .routes
            .iter()
            .map(|route| {
                (
                    route.scope,
                    route.module_name.as_str(),
                    route.path_attribute.as_deref(),
                    route.imports_macros,
                    route.test_gated,
                    route
                        .gates
                        .iter()
                        .map(|gate| gate.macro_name.as_str())
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        assert_eq!(
            described,
            vec![
                (0, "plain", None, false, false, vec![]),
                (0, "macro_source", None, true, false, vec![]),
                (0, "gated", None, false, true, vec![]),
                (
                    0,
                    "relocated",
                    Some("custom/target.rs"),
                    false,
                    false,
                    vec![]
                ),
                (1, "deep", None, false, false, vec![]),
                (0, "replayed", None, false, false, vec!["replay"]),
            ],
            "routes were {:?}",
            routes.routes
        );
        assert_eq!(
            routes
                .item_macros
                .iter()
                .map(|definition| (definition.name.as_str(), definition.passthrough))
                .collect::<Vec<_>>(),
            vec![("replay", true)],
            "item macros were {:?}",
            routes.item_macros
        );
        let gate = &routes.routes[5].gates[0];
        assert_eq!(
            RUST_MODULE_ROUTE_FIXTURE
                .get(gate.invocation_start..)
                .map(|rest| rest.starts_with("replay! { mod replayed; }")),
            Some(true),
            "the gate points at the invocation that produced the route"
        );
    }

    #[test]
    fn rust_module_route_rows_cascade_with_their_blob() {
        let temp = tempfile::TempDir::new().unwrap();
        let (store, oid) = rust_module_route_store(temp.path(), "src/lib.rs");
        let counts = |store: &AnalyzerStore| {
            let conn = store.conn.lock().unwrap();
            [
                "rust_module_scopes",
                "rust_module_routes",
                "rust_module_route_gates",
                "rust_item_macros",
            ]
            .map(|table| {
                conn.query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE blob_oid = ?1 AND lang = ?2"),
                    params![oid.to_string(), "rust"],
                    |row| row.get::<_, usize>(0),
                )
                .unwrap()
            })
        };

        assert!(
            counts(&store).iter().all(|count| *count > 0),
            "every module-route table must carry rows for this fixture: {:?}",
            counts(&store)
        );
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "DELETE FROM blobs WHERE blob_oid = ?1 AND lang = ?2",
                params![oid.to_string(), "rust"],
            )
            .unwrap();
        }
        assert_eq!(counts(&store), [0, 0, 0, 0]);
    }

    /// Nothing in the module-route rows may be path-derived: the blob key is a
    /// content hash, so the same bytes at a different path must produce
    /// byte-identical rows. Directory resolution belongs to the reader.
    #[test]
    fn rust_module_route_rows_are_stable_across_a_re_analysis_of_the_same_content() {
        let temp = tempfile::TempDir::new().unwrap();
        let (store, oid) = rust_module_route_store(temp.path(), "src/lib.rs");
        let first = store.rust_usage_facts(oid, "rust").unwrap().module_routes;
        assert!(!first.routes.is_empty(), "fixture must persist route rows");

        let moved = write_file(
            temp.path(),
            "src/deep/nested/mod.rs",
            RUST_MODULE_ROUTE_FIXTURE,
        );
        store
            .write_parsed_blob(
                oid,
                "rust",
                &RustAdapter,
                &parse_state(&RustAdapter, &moved),
            )
            .unwrap();

        assert_eq!(
            store.rust_usage_facts(oid, "rust").unwrap().module_routes,
            first
        );
    }

    /// The Cargo-route build reads every live blob at once, and that batched
    /// read must agree with the per-blob one it replaces column for column.
    #[test]
    fn batched_module_route_facts_match_the_per_blob_read() {
        let temp = tempfile::TempDir::new().unwrap();
        let (store, oid) = rust_module_route_store(temp.path(), "src/lib.rs");
        let other = write_file(temp.path(), "src/plain.rs", "mod leaf;\n");
        let other_oid = oid_for(b"mod leaf;\n");
        store
            .write_parsed_blob(
                other_oid,
                "rust",
                &RustAdapter,
                &parse_state(&RustAdapter, &other),
            )
            .unwrap();
        let absent = oid_for(b"pub struct NeverAnalyzed;\n");

        let batched = store
            .rust_module_route_facts("rust", &[oid, other_oid, absent])
            .unwrap();

        assert_eq!(batched.len(), 2, "an unanalyzed blob contributes no entry");
        for key in [oid, other_oid] {
            assert_eq!(
                batched.get(&key),
                Some(&store.rust_usage_facts(key, "rust").unwrap().module_routes),
                "batched and per-blob reads disagree for {key}"
            );
        }
    }

    fn write_file(root: &Path, rel_path: &str, contents: &str) -> ProjectFile {
        let file = ProjectFile::new(root.to_path_buf(), rel_path);
        file.write(contents).unwrap();
        file
    }

    fn oid_for(contents: &[u8]) -> Oid {
        Oid::hash_object(ObjectType::Blob, contents).unwrap()
    }
}
