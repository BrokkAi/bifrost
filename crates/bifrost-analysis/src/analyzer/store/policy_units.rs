//! Persisted policy evaluation units and base evaluations (migration 0036).
//!
//! A policy evaluation unit is one policy evaluated over one partition of a
//! workspace, together with the read set that licenses reusing it
//! (`.agents/plans/impact-sliced-diff-base.md`, Milestone 3). This module is
//! the store side of that: the row shapes, the SQL that writes and reads them,
//! and the encoding that turns one [`ReadKey`] into columns and back.
//!
//! The row shapes are deliberately store-neutral. The policy crate owns the
//! typed key ([`PolicyUnitKey`]) and the typed product; the store owns rows.
//! Everything a lookup or a sweep needs is an ordinary column, and the only
//! JSON is the product, which no query inspects.
//!
//! Every read key round-trips: the columns are decoded back into a `ReadKey`
//! and the key's own canonical digest is compared with the stored one. A row
//! that fails that check is a load error, never a silently different read set,
//! because a read set that lost a key would license a reuse nobody proved.
//!
//! [`PolicyUnitKey`]: https://docs.rs/  (crates/bifrost-policy/src/units.rs)

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use git2::Oid;
use rusqlite::{OptionalExtension, TransactionBehavior, params, params_from_iter};

use super::{PARSED_BLOB_COMPLETE_CONDITION, Result, StoreError};
use crate::analyzer::Language;
use crate::analyzer::content_identity::WorkspaceContentIdentity;
use crate::analyzer::invalidation::{DerivedArtifactId, DerivedArtifactKind};
use crate::analyzer::read_ledger::{
    CallSiteLocator, IndexFamily, LookupKind, LookupQuestion, ReadKey,
};
use crate::analyzer::semantic::ids::StableDigest;
use crate::analyzer::store::AnalyzerStore;

/// How many base evaluations one store retains.
///
/// A base evaluation is keyed by a tree id, which no blob cascade can reclaim,
/// so the table is bounded here instead. The bound is per store, which is per
/// primary repository: enough for a working set of branches and pull requests,
/// small enough that the table never becomes a corpus of its own.
pub const MAX_RETAINED_POLICY_EVALUATIONS: usize = 64;

/// How long a published unit or evaluation stays reusable.
///
/// Content-keyed rows never become wrong with age, only useless: a branch that
/// no run has asked about in two weeks is not the working set. The sweep is
/// what keeps a long-lived repository cache from growing one unit per policy
/// per file revision forever.
pub const POLICY_ROW_MAX_AGE_SECS: i64 = 14 * 24 * 60 * 60;

/// Which partition of a workspace one persisted unit covers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PolicyUnitPartitionRow {
    /// One seed file, and the blob that path resolved to.
    Seed {
        rel_path: String,
        blob: Oid,
        language: Language,
    },
    /// The whole policy, which is what a widened evaluation publishes.
    Whole,
}

impl PolicyUnitPartitionRow {
    const fn kind(&self) -> &'static str {
        match self {
            Self::Seed { .. } => "seed",
            Self::Whole => "whole",
        }
    }

    /// The two key columns, with the empty string where a whole-policy unit
    /// has no seed. An absent seed is spelled as a value rather than as NULL
    /// because SQLite treats NULLs in a unique index as distinct, which would
    /// let one policy publish an unbounded number of whole units.
    fn key_columns(&self) -> (String, String) {
        match self {
            Self::Seed { rel_path, blob, .. } => (rel_path.clone(), blob.to_string()),
            Self::Whole => (String::new(), String::new()),
        }
    }
}

/// Everything that decides whether two persisted units answer the same
/// question. The policy crate's `PolicyUnitKey` projects onto exactly this.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PolicyUnitRowKey {
    /// The policy's semantic hash, as lowercase hex.
    pub policy_semantic_hash: String,
    /// The policy family's stable label.
    pub family: String,
    pub partition: PolicyUnitPartitionRow,
    /// The analyzer configuration fingerprint, as lowercase hex.
    pub configuration_fingerprint: String,
    /// The active semantic-model set digest, as lowercase hex.
    pub active_model_set_hash: String,
    /// The analysis epoch digest, as lowercase hex.
    pub engine_epoch: String,
}

/// One published unit: its key, the product it produced, and the reads that
/// licence reusing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyUnitRow {
    pub key: PolicyUnitRowKey,
    /// The product kind's stable label. Only `rows` exists today, and the
    /// schema says so.
    pub product_kind: String,
    /// The product as canonical JSON.
    pub product: String,
    pub read_set_digest: [u8; 32],
    pub reads: Vec<ReadKey>,
}

/// The key of one whole base evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PolicyEvaluationRowKey {
    /// The git tree id of the exported workspace subtree, as lowercase hex.
    pub base_tree_oid: String,
    pub policy_set_digest: String,
    pub options_digest: String,
    pub configuration_fingerprint: String,
    pub active_model_set_hash: String,
    pub engine_epoch: String,
}

/// One completed base evaluation, with the units it published per policy in
/// the order it merged them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvaluationRow {
    pub key: PolicyEvaluationRowKey,
    /// The commit the requested revision resolved to, as lowercase hex.
    pub resolved_commit: String,
    /// The analyzed source volume that scaled the base's per-policy budget.
    pub analyzed_source_bytes: u64,
    pub analyzed_file_count: u64,
    /// The units, per policy, in merge order.
    pub units: Vec<(String, Vec<PolicyUnitRowKey>)>,
}

/// One loaded base evaluation.
///
/// `recorded_unit_count` is what the evaluation published and `units` is what
/// survives; a caller that finds them unequal has an evaluation whose units
/// followed their blobs out of the cache, which is a partial answer rather
/// than a cheaper one.
#[derive(Debug, Clone)]
pub struct LoadedPolicyEvaluation {
    pub resolved_commit: String,
    pub analyzed_source_bytes: u64,
    pub analyzed_file_count: u64,
    pub recorded_unit_count: u64,
    pub units: Vec<(String, Vec<PolicyUnitRow>)>,
}

impl LoadedPolicyEvaluation {
    /// How many unit rows this evaluation still has.
    pub fn loaded_unit_count(&self) -> u64 {
        self.units.iter().map(|(_, units)| units.len() as u64).sum()
    }

    /// Whether every unit this evaluation published is still present.
    pub fn is_complete(&self) -> bool {
        self.loaded_unit_count() == self.recorded_unit_count
    }
}

/// The columns of `policy_units` a load needs, in one place so the reader and
/// the row decoder cannot disagree about their order.
const UNIT_COLUMNS: &str = "units.unit_id, units.policy_semantic_hash, units.family, \
     units.partition_kind, units.seed_rel_path, units.seed_blob_oid, units.lang, \
     units.configuration_fingerprint, units.active_model_set_hash, units.engine_epoch, \
     units.product_kind, units.product, units.read_set_digest";

impl AnalyzerStore {
    /// Publish `units`, replacing any row already published under the same key.
    ///
    /// One transaction for the whole batch: a partially published policy would
    /// let a later run reuse some of a policy's units and recompute the rest,
    /// which is exactly the state the unit key exists to make impossible.
    ///
    /// The caller decides whether to publish at all. A cancelled or
    /// deadline-terminated run never reaches here, because its units describe
    /// work that stopped early.
    pub fn publish_policy_units(&self, units: Vec<PolicyUnitRow>) -> Result<usize> {
        if units.is_empty() {
            return Ok(0);
        }
        let published_at = now_secs();
        self.conn.execute(move |conn| {
            // Immediate: the transaction resolves blob ids and interns read
            // keys before it inserts, so a deferred write upgrade could
            // collide with a concurrent publication between the read and the
            // write.
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let mut written = 0;
            for unit in &units {
                write_unit(&tx, unit, published_at)?;
                written += 1;
            }
            tx.commit()?;
            Ok(written)
        })
    }

    /// The published units for `keys`, in the same order, with `None` where
    /// nothing was published.
    ///
    /// One query per batch of keys rather than one per key: a policy asks about
    /// every seed file of the workspace, and a per-key round trip would make
    /// verification cost a query per file before it reads a single fact.
    pub fn policy_units_for_keys(
        &self,
        keys: &[PolicyUnitRowKey],
    ) -> Result<Vec<Option<PolicyUnitRow>>> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.read_conn()?;
        let mut found: HashMap<PolicyUnitRowKey, PolicyUnitRow> = HashMap::new();
        // The key columns every unit of one lookup shares are equality-tested
        // and the partitions are a row-value list, so the unique index answers
        // the whole batch with one seek per partition.
        let mut parameters: Vec<String> = Vec::with_capacity(5 + keys.len() * 3);
        let head = &keys[0];
        parameters.push(head.policy_semantic_hash.clone());
        parameters.push(head.family.clone());
        parameters.push(head.configuration_fingerprint.clone());
        parameters.push(head.active_model_set_hash.clone());
        parameters.push(head.engine_epoch.clone());
        let mut values = String::new();
        for (index, key) in keys.iter().enumerate() {
            assert_eq!(
                (
                    &key.policy_semantic_hash,
                    &key.family,
                    &key.configuration_fingerprint,
                    &key.active_model_set_hash,
                    &key.engine_epoch
                ),
                (
                    &head.policy_semantic_hash,
                    &head.family,
                    &head.configuration_fingerprint,
                    &head.active_model_set_hash,
                    &head.engine_epoch
                ),
                "one unit lookup asks about one policy under one engine"
            );
            let (rel_path, blob_oid) = key.partition.key_columns();
            parameters.push(key.partition.kind().to_string());
            parameters.push(rel_path);
            parameters.push(blob_oid);
            if index > 0 {
                values.push(',');
            }
            values.push_str("(?,?,?)");
        }
        let sql = policy_unit_batch_sql(&values);
        let mut statement = conn.prepare_cached(&sql)?;
        let mut rows = statement.query(params_from_iter(parameters.iter()))?;
        while let Some(row) = rows.next()? {
            let (unit_id, unit) = decode_unit_row(row)?;
            let reads = load_unit_reads(&conn, unit_id)?;
            found.insert(
                unit.key.clone(),
                PolicyUnitRow {
                    reads,
                    ..unit.clone()
                },
            );
        }
        Ok(keys.iter().map(|key| found.remove(key)).collect())
    }

    /// Record that one policy set evaluated completely over one committed
    /// subtree, and which units that evaluation published.
    ///
    /// The units must already be published: this links them by key, so a unit
    /// whose row is missing makes the evaluation partial and no row is written
    /// at all. Publishing also sweeps, because a base evaluation is keyed by a
    /// tree id and has no blob to follow out of the cache.
    pub fn publish_policy_evaluation(&self, evaluation: PolicyEvaluationRow) -> Result<bool> {
        let published_at = now_secs();
        self.conn.execute(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let mut memberships: Vec<(String, i64, i64)> = Vec::new();
            for (policy_id, keys) in &evaluation.units {
                for (ordinal, key) in keys.iter().enumerate() {
                    let Some(unit_id) = unit_id_for_key(&tx, key)? else {
                        tx.commit()?;
                        return Ok(false);
                    };
                    memberships.push((policy_id.clone(), ordinal as i64, unit_id));
                }
            }
            let key = &evaluation.key;
            tx.execute(
                "DELETE FROM policy_evaluations
                 WHERE base_tree_oid = ?1 AND policy_set_digest = ?2 AND options_digest = ?3
                   AND configuration_fingerprint = ?4 AND active_model_set_hash = ?5
                   AND engine_epoch = ?6",
                params![
                    key.base_tree_oid,
                    key.policy_set_digest,
                    key.options_digest,
                    key.configuration_fingerprint,
                    key.active_model_set_hash,
                    key.engine_epoch,
                ],
            )?;
            tx.execute(
                "INSERT INTO policy_evaluations(
                   base_tree_oid, policy_set_digest, options_digest,
                   configuration_fingerprint, active_model_set_hash, engine_epoch,
                   resolved_commit, analyzed_source_bytes, analyzed_file_count,
                   unit_count, published_at
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    key.base_tree_oid,
                    key.policy_set_digest,
                    key.options_digest,
                    key.configuration_fingerprint,
                    key.active_model_set_hash,
                    key.engine_epoch,
                    evaluation.resolved_commit,
                    evaluation.analyzed_source_bytes as i64,
                    evaluation.analyzed_file_count as i64,
                    memberships.len() as i64,
                    published_at,
                ],
            )?;
            let evaluation_id = tx.last_insert_rowid();
            {
                let mut insert = tx.prepare_cached(
                    "INSERT INTO policy_evaluation_units(
                       evaluation_id, policy_id, ordinal, unit_id
                     ) VALUES(?1, ?2, ?3, ?4)",
                )?;
                for (policy_id, ordinal, unit_id) in &memberships {
                    insert.execute(params![evaluation_id, policy_id, ordinal, unit_id])?;
                }
            }
            sweep_policy_rows(&tx, published_at)?;
            tx.commit()?;
            Ok(true)
        })
    }

    /// The base evaluation published under `key`, with its units.
    pub fn policy_evaluation_for_key(
        &self,
        key: &PolicyEvaluationRowKey,
    ) -> Result<Option<LoadedPolicyEvaluation>> {
        let conn = self.read_conn()?;
        let row = conn
            .query_row(
                POLICY_EVALUATION_LOOKUP_SQL,
                params![
                    key.base_tree_oid,
                    key.policy_set_digest,
                    key.options_digest,
                    key.configuration_fingerprint,
                    key.active_model_set_hash,
                    key.engine_epoch,
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((evaluation_id, resolved_commit, source_bytes, file_count, unit_count)) = row
        else {
            return Ok(None);
        };
        let mut per_policy: Vec<(String, Vec<PolicyUnitRow>)> = Vec::new();
        let mut statement = conn.prepare_cached(&format!(
            "SELECT membership.policy_id, {UNIT_COLUMNS}
             FROM policy_evaluation_units AS membership
             JOIN policy_units AS units ON units.unit_id = membership.unit_id
             WHERE membership.evaluation_id = ?1
             ORDER BY membership.policy_id, membership.ordinal"
        ))?;
        let mut rows = statement.query(params![evaluation_id])?;
        while let Some(row) = rows.next()? {
            let policy_id = row.get::<_, String>(0)?;
            let (unit_id, unit) = decode_unit_row_at(row, 1)?;
            let reads = load_unit_reads(&conn, unit_id)?;
            let unit = PolicyUnitRow { reads, ..unit };
            match per_policy.last_mut() {
                Some((last, units)) if *last == policy_id => units.push(unit),
                _ => per_policy.push((policy_id, vec![unit])),
            }
        }
        Ok(Some(LoadedPolicyEvaluation {
            resolved_commit,
            analyzed_source_bytes: source_bytes as u64,
            analyzed_file_count: file_count as u64,
            recorded_unit_count: unit_count as u64,
            units: per_policy,
        }))
    }
}

/// The batched unit lookup, with `values` holding one `(?,?,?)` row per
/// requested partition.
///
/// Shared with the query-plan pin, which asserts that this exact statement
/// seeks the unit key index instead of scanning the table.
pub(crate) fn policy_unit_batch_sql(values: &str) -> String {
    format!(
        "SELECT {UNIT_COLUMNS} FROM policy_units AS units
         WHERE policy_semantic_hash = ?1 AND family = ?2
           AND configuration_fingerprint = ?3 AND active_model_set_hash = ?4
           AND engine_epoch = ?5
           AND (partition_kind, seed_rel_path, seed_blob_oid) IN (VALUES {values})"
    )
}

/// The evaluation lookup, shared with its query-plan pin.
pub(crate) const POLICY_EVALUATION_LOOKUP_SQL: &str =
    "SELECT evaluation_id, resolved_commit, analyzed_source_bytes, analyzed_file_count, unit_count
     FROM policy_evaluations
     WHERE base_tree_oid = ?1 AND policy_set_digest = ?2 AND options_digest = ?3
       AND configuration_fingerprint = ?4 AND active_model_set_hash = ?5
       AND engine_epoch = ?6";

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() as i64)
}

/// The id of the row published under `key`, if there is one.
fn unit_id_for_key(
    conn: &rusqlite::Connection,
    key: &PolicyUnitRowKey,
) -> rusqlite::Result<Option<i64>> {
    let (rel_path, blob_oid) = key.partition.key_columns();
    conn.query_row(
        "SELECT unit_id FROM policy_units
         WHERE policy_semantic_hash = ?1 AND family = ?2
           AND configuration_fingerprint = ?3 AND active_model_set_hash = ?4
           AND engine_epoch = ?5 AND partition_kind = ?6
           AND seed_rel_path = ?7 AND seed_blob_oid = ?8",
        params![
            key.policy_semantic_hash,
            key.family,
            key.configuration_fingerprint,
            key.active_model_set_hash,
            key.engine_epoch,
            key.partition.kind(),
            rel_path,
            blob_oid,
        ],
        |row| row.get::<_, i64>(0),
    )
    .optional()
}

/// Write one unit and its read-set membership, replacing what its key held.
fn write_unit(
    conn: &rusqlite::Connection,
    unit: &PolicyUnitRow,
    published_at: i64,
) -> rusqlite::Result<()> {
    let key = &unit.key;
    let (rel_path, blob_oid) = key.partition.key_columns();
    let (blob_id, lang) = match &key.partition {
        PolicyUnitPartitionRow::Seed { blob, language, .. } => {
            let lang = language.config_label();
            // Resolved under the complete-blob condition the fact tables use:
            // a unit hangs off its seed blob so that re-parsing that blob
            // takes the unit with it.
            let blob_id = conn
                .query_row(
                    &format!(
                        "SELECT meta.blob_id FROM blob_meta AS meta
                         JOIN blobs ON blobs.id = meta.blob_id
                         WHERE blobs.blob_oid = ?1 AND blobs.lang = ?2
                           AND {PARSED_BLOB_COMPLETE_CONDITION}"
                    ),
                    params![blob.to_string(), lang],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?;
            match blob_id {
                Some(blob_id) => (Some(blob_id), Some(lang.to_string())),
                None => (None, None),
            }
        }
        PolicyUnitPartitionRow::Whole => (None, None),
    };
    conn.execute(
        "DELETE FROM policy_units
         WHERE policy_semantic_hash = ?1 AND family = ?2
           AND configuration_fingerprint = ?3 AND active_model_set_hash = ?4
           AND engine_epoch = ?5 AND partition_kind = ?6
           AND seed_rel_path = ?7 AND seed_blob_oid = ?8",
        params![
            key.policy_semantic_hash,
            key.family,
            key.configuration_fingerprint,
            key.active_model_set_hash,
            key.engine_epoch,
            key.partition.kind(),
            rel_path,
            blob_oid,
        ],
    )?;
    conn.execute(
        "INSERT INTO policy_units(
           policy_semantic_hash, family, partition_kind, seed_rel_path,
           seed_blob_oid, seed_blob_id, lang, configuration_fingerprint,
           active_model_set_hash, engine_epoch, completion, budget_mode,
           product_kind, product, read_set_digest, published_at
         ) VALUES(
           ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'complete', 'exhaustive',
           ?11, ?12, ?13, ?14
         )",
        params![
            key.policy_semantic_hash,
            key.family,
            key.partition.kind(),
            rel_path,
            blob_oid,
            blob_id,
            lang,
            key.configuration_fingerprint,
            key.active_model_set_hash,
            key.engine_epoch,
            unit.product_kind,
            unit.product,
            unit.read_set_digest.as_slice(),
            published_at,
        ],
    )?;
    let unit_id = conn.last_insert_rowid();
    let mut intern = conn.prepare_cached(
        "INSERT INTO policy_read_keys(
           key_digest, kind, family, languages, rel_path, name, index_key,
           blob_oid, subject, start_byte, end_byte, digest
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
         ON CONFLICT(key_digest) DO NOTHING",
    )?;
    let mut find =
        conn.prepare_cached("SELECT read_id FROM policy_read_keys WHERE key_digest = ?1")?;
    let mut member = conn.prepare_cached(
        "INSERT INTO policy_unit_reads(unit_id, read_id) VALUES(?1, ?2)
         ON CONFLICT(unit_id, read_id) DO NOTHING",
    )?;
    for read in &unit.reads {
        let columns = ReadKeyColumns::of(read);
        intern.execute(params![
            columns.key_digest.as_slice(),
            columns.kind,
            columns.family,
            columns.languages,
            columns.rel_path,
            columns.name,
            columns.index_key,
            columns.blob_oid,
            columns.subject,
            columns.start_byte,
            columns.end_byte,
            columns.digest,
        ])?;
        let read_id = find.query_row(params![columns.key_digest.as_slice()], |row| {
            row.get::<_, i64>(0)
        })?;
        member.execute(params![unit_id, read_id])?;
    }
    Ok(())
}

/// Retire the evaluations and units this store no longer needs.
///
/// Age first, then count: a repository that runs one diff-gated evaluation an
/// hour keeps its recent bases, and one that never runs again keeps nothing
/// forever. Units survive independently of evaluations, because a head run
/// reuses a unit whose evaluation is long gone; they are retired by the same
/// age, and by their blob's cascade before that.
fn sweep_policy_rows(conn: &rusqlite::Connection, now: i64) -> rusqlite::Result<()> {
    let oldest_retained = now.saturating_sub(POLICY_ROW_MAX_AGE_SECS);
    conn.execute(
        "DELETE FROM policy_evaluations WHERE published_at < ?1",
        params![oldest_retained],
    )?;
    conn.execute(
        "DELETE FROM policy_evaluations
         WHERE evaluation_id NOT IN (
           SELECT evaluation_id FROM policy_evaluations
           ORDER BY published_at DESC, evaluation_id DESC
           LIMIT ?1
         )",
        params![MAX_RETAINED_POLICY_EVALUATIONS as i64],
    )?;
    conn.execute(
        "DELETE FROM policy_units
         WHERE published_at < ?1
           AND unit_id NOT IN (SELECT unit_id FROM policy_evaluation_units)",
        params![oldest_retained],
    )?;
    // An interned read key nobody reads is dead weight, and the membership
    // rows that named it are already gone with their units.
    conn.execute(
        "DELETE FROM policy_read_keys
         WHERE read_id NOT IN (SELECT read_id FROM policy_unit_reads)",
        [],
    )?;
    Ok(())
}

/// One unit row, without its reads.
fn decode_unit_row(row: &rusqlite::Row<'_>) -> Result<(i64, PolicyUnitRow)> {
    decode_unit_row_at(row, 0)
}

fn decode_unit_row_at(row: &rusqlite::Row<'_>, offset: usize) -> Result<(i64, PolicyUnitRow)> {
    let unit_id = row.get::<_, i64>(offset)?;
    let policy_semantic_hash = row.get::<_, String>(offset + 1)?;
    let family = row.get::<_, String>(offset + 2)?;
    let partition_kind = row.get::<_, String>(offset + 3)?;
    let seed_rel_path = row.get::<_, String>(offset + 4)?;
    let seed_blob_oid = row.get::<_, String>(offset + 5)?;
    let lang = row.get::<_, Option<String>>(offset + 6)?;
    let configuration_fingerprint = row.get::<_, String>(offset + 7)?;
    let active_model_set_hash = row.get::<_, String>(offset + 8)?;
    let engine_epoch = row.get::<_, String>(offset + 9)?;
    let product_kind = row.get::<_, String>(offset + 10)?;
    let product = row.get::<_, String>(offset + 11)?;
    let read_set_digest = row.get::<_, Vec<u8>>(offset + 12)?;
    let partition = match partition_kind.as_str() {
        "seed" => {
            let blob = Oid::from_str(&seed_blob_oid).map_err(|error| {
                StoreError::new(format!(
                    "policy unit {unit_id} names an unreadable seed blob `{seed_blob_oid}`: {error}"
                ))
            })?;
            // The stored language is the blob's storage language and is absent
            // when the seed blob left the cache; the path's own language is
            // what the key means either way.
            let language = lang
                .as_deref()
                .and_then(Language::from_config_label)
                .unwrap_or_else(|| language_of_rel_path(&seed_rel_path));
            PolicyUnitPartitionRow::Seed {
                rel_path: seed_rel_path,
                blob,
                language,
            }
        }
        "whole" => PolicyUnitPartitionRow::Whole,
        other => {
            return Err(StoreError::new(format!(
                "policy unit {unit_id} has unknown partition kind `{other}`"
            )));
        }
    };
    let read_set_digest = <[u8; 32]>::try_from(read_set_digest.as_slice()).map_err(|_| {
        StoreError::new(format!(
            "policy unit {unit_id} has a read-set digest of {} bytes",
            read_set_digest.len()
        ))
    })?;
    Ok((
        unit_id,
        PolicyUnitRow {
            key: PolicyUnitRowKey {
                policy_semantic_hash,
                family,
                partition,
                configuration_fingerprint,
                active_model_set_hash,
                engine_epoch,
            },
            product_kind,
            product,
            read_set_digest,
            reads: Vec::new(),
        },
    ))
}

/// The language a workspace-relative path belongs to, for a unit whose seed
/// blob has left the cache and taken its storage language with it.
fn language_of_rel_path(rel_path: &str) -> Language {
    Language::from_extension(
        std::path::Path::new(rel_path)
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or_default(),
    )
}

/// Every read key one unit recorded.
fn load_unit_reads(conn: &rusqlite::Connection, unit_id: i64) -> Result<Vec<ReadKey>> {
    let mut statement = conn.prepare_cached(
        "SELECT keys.key_digest, keys.kind, keys.family, keys.languages, keys.rel_path,
                keys.name, keys.index_key, keys.blob_oid, keys.subject,
                keys.start_byte, keys.end_byte, keys.digest
         FROM policy_unit_reads AS membership
         JOIN policy_read_keys AS keys ON keys.read_id = membership.read_id
         WHERE membership.unit_id = ?1",
    )?;
    let mut rows = statement.query(params![unit_id])?;
    let mut reads = Vec::new();
    while let Some(row) = rows.next()? {
        reads.push(decode_read_key(row)?);
    }
    Ok(reads)
}

/// One read key as columns.
///
/// The columns are derived from the key by an exhaustive match, so a new key
/// variant is a compile error here rather than a row that silently drops half
/// its identity.
struct ReadKeyColumns {
    key_digest: [u8; 32],
    kind: &'static str,
    family: Option<&'static str>,
    languages: Option<String>,
    rel_path: Option<String>,
    name: Option<String>,
    index_key: Option<Vec<u8>>,
    blob_oid: Option<String>,
    subject: Option<Vec<u8>>,
    start_byte: Option<i64>,
    end_byte: Option<i64>,
    digest: Option<Vec<u8>>,
}

impl ReadKeyColumns {
    fn of(key: &ReadKey) -> Self {
        let mut columns = Self {
            key_digest: *key.canonical_digest().as_bytes(),
            kind: key.stable_label(),
            family: None,
            languages: None,
            rel_path: None,
            name: None,
            index_key: None,
            blob_oid: None,
            subject: None,
            start_byte: None,
            end_byte: None,
            digest: None,
        };
        match key {
            ReadKey::File {
                language,
                rel_path,
                blob,
            } => {
                columns.languages = Some(language.config_label().to_string());
                columns.rel_path = Some(rel_path.to_string());
                columns.blob_oid = Some(blob.to_string());
            }
            ReadKey::PathAbsent { language, rel_path } => {
                columns.languages = Some(language.config_label().to_string());
                columns.rel_path = Some(rel_path.to_string());
            }
            ReadKey::Index { family, key } => {
                columns.family = Some(family.stable_label());
                columns.index_key = Some(key.to_vec());
            }
            ReadKey::Lookup {
                kind,
                question,
                digest,
            } => {
                columns.family = Some(kind.stable_label());
                columns.digest = Some(digest.as_bytes().to_vec());
                match question {
                    LookupQuestion::Declaration { rel_path, fq_name } => {
                        columns.rel_path = Some(rel_path.to_string());
                        columns.name = Some(fq_name.to_string());
                    }
                    LookupQuestion::File { rel_path } => {
                        columns.rel_path = Some(rel_path.to_string());
                    }
                    LookupQuestion::CallSite {
                        rel_path,
                        artifact,
                        site,
                    } => {
                        columns.rel_path = Some(rel_path.to_string());
                        columns.subject = Some(artifact.as_bytes().to_vec());
                        columns.start_byte = Some(site.start_byte as i64);
                        columns.end_byte = Some(site.end_byte as i64);
                    }
                    LookupQuestion::Summary { identity } => {
                        columns.subject = Some(identity.as_bytes().to_vec());
                    }
                }
            }
            ReadKey::Artifact { id, rel_path } => {
                columns.family = Some(id.kind().stable_label());
                columns.subject = Some(id.fingerprint().as_bytes().to_vec());
                columns.rel_path = rel_path.as_ref().map(ToString::to_string);
            }
            ReadKey::Scope {
                languages,
                identity,
            } => {
                columns.languages = Some(language_list(languages));
                columns.digest = Some(identity.digest().as_bytes().to_vec());
            }
            ReadKey::Models(digest) | ReadKey::Configuration(digest) | ReadKey::Epoch(digest) => {
                columns.digest = Some(digest.as_bytes().to_vec());
            }
            ReadKey::Policy {
                semantic_hash,
                source,
            } => {
                columns.subject = Some(semantic_hash.as_bytes().to_vec());
                columns.digest = Some(source.as_bytes().to_vec());
            }
        }
        columns
    }
}

/// The sorted language labels of one scope, as the one text column a scope key
/// is found and rebuilt by.
fn language_list(languages: &[Language]) -> String {
    languages
        .iter()
        .map(|language| language.config_label())
        .collect::<Vec<_>>()
        .join(",")
}

/// Rebuild one read key from its columns, and prove the rebuild is faithful.
///
/// The stored `key_digest` is the canonical digest of the key that was
/// written. Comparing it with the digest of the key just decoded is what makes
/// "these columns are that key" a checked fact instead of a convention two
/// functions happen to share.
fn decode_read_key(row: &rusqlite::Row<'_>) -> Result<ReadKey> {
    let key_digest = row.get::<_, Vec<u8>>(0)?;
    let kind = row.get::<_, String>(1)?;
    let family = row.get::<_, Option<String>>(2)?;
    let languages = row.get::<_, Option<String>>(3)?;
    let rel_path = row.get::<_, Option<String>>(4)?;
    let name = row.get::<_, Option<String>>(5)?;
    let index_key = row.get::<_, Option<Vec<u8>>>(6)?;
    let blob_oid = row.get::<_, Option<String>>(7)?;
    let subject = row.get::<_, Option<Vec<u8>>>(8)?;
    let start_byte = row.get::<_, Option<i64>>(9)?;
    let end_byte = row.get::<_, Option<i64>>(10)?;
    let digest = row.get::<_, Option<Vec<u8>>>(11)?;

    let missing = |column: &str| StoreError::new(format!("read key `{kind}` has no {column}"));
    let key = match kind.as_str() {
        "file" => ReadKey::File {
            language: decode_language(languages.as_deref().ok_or_else(|| missing("language"))?)?,
            rel_path: Box::from(rel_path.ok_or_else(|| missing("path"))?.as_str()),
            blob: decode_oid(&blob_oid.ok_or_else(|| missing("blob"))?)?,
        },
        "path_absent" => ReadKey::PathAbsent {
            language: decode_language(languages.as_deref().ok_or_else(|| missing("language"))?)?,
            rel_path: Box::from(rel_path.ok_or_else(|| missing("path"))?.as_str()),
        },
        "index" => ReadKey::Index {
            family: index_family_of(family.as_deref().ok_or_else(|| missing("family"))?)?,
            key: Box::from(index_key.ok_or_else(|| missing("key"))?.as_slice()),
        },
        "lookup" => {
            let lookup_kind = lookup_kind_of(family.as_deref().ok_or_else(|| missing("kind"))?)?;
            let question = match (rel_path, name, subject, start_byte, end_byte) {
                (Some(rel_path), Some(fq_name), None, None, None) => LookupQuestion::Declaration {
                    rel_path: Box::from(rel_path.as_str()),
                    fq_name: Box::from(fq_name.as_str()),
                },
                (Some(rel_path), None, None, None, None) => LookupQuestion::File {
                    rel_path: Box::from(rel_path.as_str()),
                },
                (Some(rel_path), None, Some(artifact), Some(start), Some(end)) => {
                    LookupQuestion::CallSite {
                        rel_path: Box::from(rel_path.as_str()),
                        artifact: decode_digest(&artifact, "call site artifact")?,
                        site: CallSiteLocator {
                            start_byte: start as usize,
                            end_byte: end as usize,
                        },
                    }
                }
                (None, None, Some(identity), None, None) => LookupQuestion::Summary {
                    identity: decode_digest(&identity, "summary identity")?,
                },
                columns => {
                    return Err(StoreError::new(format!(
                        "read key `lookup` has no question in its columns: {columns:?}"
                    )));
                }
            };
            ReadKey::Lookup {
                kind: lookup_kind,
                question,
                digest: decode_digest(&digest.ok_or_else(|| missing("answer"))?, "lookup answer")?,
            }
        }
        "artifact" => ReadKey::Artifact {
            id: DerivedArtifactId::new(
                artifact_kind_of(family.as_deref().ok_or_else(|| missing("kind"))?)?,
                decode_digest(
                    &subject.ok_or_else(|| missing("fingerprint"))?,
                    "artifact fingerprint",
                )?,
            ),
            rel_path: rel_path.map(|path| Box::from(path.as_str())),
        },
        "scope" => {
            let languages = languages.ok_or_else(|| missing("languages"))?;
            let mut scope = Vec::new();
            for label in languages.split(',') {
                scope.push(decode_language(label)?);
            }
            ReadKey::Scope {
                languages: scope.into_boxed_slice(),
                identity: WorkspaceContentIdentity::from_digest(decode_digest(
                    &digest.ok_or_else(|| missing("identity"))?,
                    "scope identity",
                )?),
            }
        }
        "models" => ReadKey::Models(decode_digest(
            &digest.ok_or_else(|| missing("digest"))?,
            "model set",
        )?),
        "policy" => ReadKey::Policy {
            semantic_hash: decode_digest(
                &subject.ok_or_else(|| missing("semantic hash"))?,
                "policy semantic hash",
            )?,
            source: decode_digest(
                &digest.ok_or_else(|| missing("source digest"))?,
                "policy source",
            )?,
        },
        "configuration" => ReadKey::Configuration(decode_digest(
            &digest.ok_or_else(|| missing("digest"))?,
            "configuration",
        )?),
        "epoch" => ReadKey::Epoch(decode_digest(
            &digest.ok_or_else(|| missing("digest"))?,
            "epoch",
        )?),
        other => {
            return Err(StoreError::new(format!("unknown read key kind `{other}`")));
        }
    };
    let rebuilt = key.canonical_digest();
    if rebuilt.as_bytes().as_slice() != key_digest.as_slice() {
        return Err(StoreError::new(format!(
            "read key `{kind}` did not rebuild to its stored identity {}",
            hex_of(&key_digest)
        )));
    }
    Ok(key)
}

fn hex_of(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn decode_digest(bytes: &[u8], what: &str) -> Result<StableDigest> {
    let array = <[u8; 32]>::try_from(bytes)
        .map_err(|_| StoreError::new(format!("{what} digest has {} bytes, not 32", bytes.len())))?;
    Ok(StableDigest::from_array(array))
}

fn decode_oid(text: &str) -> Result<Oid> {
    Oid::from_str(text)
        .map_err(|error| StoreError::new(format!("unreadable blob `{text}`: {error}")))
}

fn decode_language(label: &str) -> Result<Language> {
    Language::from_config_label(label)
        .filter(|language| language.config_label() == label)
        .ok_or_else(|| StoreError::new(format!("unknown language label `{label}`")))
}

/// Every index family, so a label decodes to the variant that spells it.
const ALL_INDEX_FAMILIES: [IndexFamily; 9] = [
    IndexFamily::DefinitionExact,
    IndexFamily::DefinitionNormalizedTail,
    IndexFamily::DefinitionIdentifier,
    IndexFamily::ReferenceIdentifier,
    IndexFamily::ImportPathSegment,
    IndexFamily::PackageMembership,
    IndexFamily::Supertype,
    IndexFamily::SupertypeLookupPath,
    IndexFamily::PathSymbol,
];

/// Every derived-value lookup kind.
const ALL_LOOKUP_KINDS: [LookupKind; 8] = [
    LookupKind::Callers,
    LookupKind::Callees,
    LookupKind::Usages,
    LookupKind::Importers,
    LookupKind::ReferenceCandidates,
    LookupKind::Descendants,
    LookupKind::Dispatch,
    LookupKind::ProcedureSummary,
];

/// Every derived-artifact kind.
const ALL_ARTIFACT_KINDS: [DerivedArtifactKind; 8] = [
    DerivedArtifactKind::SemanticArtifact,
    DerivedArtifactKind::ProcedureSummary,
    DerivedArtifactKind::FlowSnapshot,
    DerivedArtifactKind::PolicyReport,
    DerivedArtifactKind::DerivedQueryLayer,
    DerivedArtifactKind::WorkspaceUsageGraph,
    DerivedArtifactKind::StructuralIndex,
    DerivedArtifactKind::PolicyEvaluationUnit,
];

fn index_family_of(label: &str) -> Result<IndexFamily> {
    ALL_INDEX_FAMILIES
        .into_iter()
        .find(|family| family.stable_label() == label)
        .ok_or_else(|| StoreError::new(format!("unknown index family `{label}`")))
}

fn lookup_kind_of(label: &str) -> Result<LookupKind> {
    ALL_LOOKUP_KINDS
        .into_iter()
        .find(|kind| kind.stable_label() == label)
        .ok_or_else(|| StoreError::new(format!("unknown lookup kind `{label}`")))
}

fn artifact_kind_of(label: &str) -> Result<DerivedArtifactKind> {
    ALL_ARTIFACT_KINDS
        .into_iter()
        .find(|kind| kind.stable_label() == label)
        .ok_or_else(|| StoreError::new(format!("unknown derived artifact kind `{label}`")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::read_ledger::{CallSiteLocator, read_set_digest};

    const POLICY_HASH: &str = "aa11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee";
    const CONFIGURATION: &str = "bb11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee";
    const MODELS: &str = "cc11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee";
    const EPOCH: &str = "dd11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee";
    const BLOB: &str = "1111111111111111111111111111111111111111";
    const TREE: &str = "2222222222222222222222222222222222222222";
    const COMMIT: &str = "3333333333333333333333333333333333333333";

    fn seed_key(rel_path: &str) -> PolicyUnitRowKey {
        PolicyUnitRowKey {
            policy_semantic_hash: POLICY_HASH.to_string(),
            family: "match".to_string(),
            partition: PolicyUnitPartitionRow::Seed {
                rel_path: rel_path.to_string(),
                blob: Oid::from_str(BLOB).unwrap(),
                language: Language::Java,
            },
            configuration_fingerprint: CONFIGURATION.to_string(),
            active_model_set_hash: MODELS.to_string(),
            engine_epoch: EPOCH.to_string(),
        }
    }

    /// One key of every shape the vocabulary has, so the row encoding is
    /// exercised where it is easiest to get wrong: in the columns one shape
    /// fills and another leaves empty.
    fn every_read_key_shape() -> Vec<ReadKey> {
        let digest = StableDigest::sha256(b"answer");
        vec![
            ReadKey::file(
                Language::Java,
                "src/Main.java",
                Oid::from_str(BLOB).unwrap(),
            ),
            ReadKey::path_absent(Language::Java, "src/Missing.java"),
            ReadKey::index(IndexFamily::DefinitionExact, b"com.example.Main"),
            ReadKey::lookup(
                LookupKind::Callers,
                LookupQuestion::Declaration {
                    rel_path: Box::from("src/Main.java"),
                    fq_name: Box::from("com.example.Main#run"),
                },
                digest,
            ),
            ReadKey::lookup(
                LookupKind::Importers,
                LookupQuestion::File {
                    rel_path: Box::from("src/Main.java"),
                },
                digest,
            ),
            ReadKey::lookup(
                LookupKind::Dispatch,
                LookupQuestion::CallSite {
                    rel_path: Box::from("src/Main.java"),
                    artifact: StableDigest::sha256(b"artifact"),
                    site: CallSiteLocator {
                        start_byte: 10,
                        end_byte: 24,
                    },
                },
                digest,
            ),
            ReadKey::lookup(
                LookupKind::ProcedureSummary,
                LookupQuestion::Summary {
                    identity: StableDigest::sha256(b"summary"),
                },
                digest,
            ),
            ReadKey::artifact(
                DerivedArtifactId::new(
                    DerivedArtifactKind::SemanticArtifact,
                    StableDigest::sha256(b"ir"),
                ),
                Some("src/Main.java"),
            ),
            ReadKey::artifact(
                DerivedArtifactId::new(
                    DerivedArtifactKind::WorkspaceUsageGraph,
                    StableDigest::sha256(b"graph"),
                ),
                None,
            ),
            ReadKey::scope(
                [Language::Java, Language::Go],
                WorkspaceContentIdentity::from_digest(StableDigest::sha256(b"scope")),
            ),
            ReadKey::Models(StableDigest::sha256(b"models")),
            ReadKey::Policy {
                semantic_hash: StableDigest::sha256(b"policy"),
                source: StableDigest::sha256(b"source"),
            },
            ReadKey::Configuration(StableDigest::sha256(b"configuration")),
            ReadKey::Epoch(StableDigest::sha256(b"epoch")),
        ]
    }

    fn unit_row(rel_path: &str, reads: Vec<ReadKey>) -> PolicyUnitRow {
        PolicyUnitRow {
            key: seed_key(rel_path),
            product_kind: "rows".to_string(),
            product: "{\"rows\":[]}".to_string(),
            read_set_digest: *read_set_digest(&reads).digest().as_bytes(),
            reads,
        }
    }

    #[test]
    fn a_published_unit_round_trips_with_every_read_key_shape() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let reads = every_read_key_shape();
        store
            .publish_policy_units(vec![unit_row("src/Main.java", reads.clone())])
            .unwrap();

        let [loaded] = store
            .policy_units_for_keys(&[seed_key("src/Main.java")])
            .unwrap()
            .try_into()
            .expect("one key, one answer");
        let mut loaded = loaded.expect("the published unit is found by its key");
        loaded.reads.sort();
        let mut expected = reads;
        expected.sort();
        assert_eq!(loaded.reads, expected);
        assert_eq!(loaded.key, seed_key("src/Main.java"));
        assert_eq!(loaded.product, "{\"rows\":[]}");
    }

    #[test]
    fn a_unit_published_twice_keeps_one_row_and_the_second_product() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .publish_policy_units(vec![unit_row("src/Main.java", vec![])])
            .unwrap();
        let mut second = unit_row("src/Main.java", vec![]);
        second.product = "{\"rows\":[1]}".to_string();
        store.publish_policy_units(vec![second]).unwrap();

        let conn = store.conn.lock().expect("store mutex");
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM policy_units", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 1, "one key names one unit");
        let product: String = conn
            .query_row("SELECT product FROM policy_units", [], |row| row.get(0))
            .unwrap();
        assert_eq!(product, "{\"rows\":[1]}");
    }

    #[test]
    fn a_key_absent_from_the_store_answers_none_in_its_own_position() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .publish_policy_units(vec![unit_row("src/Second.java", vec![])])
            .unwrap();

        let answers = store
            .policy_units_for_keys(&[
                seed_key("src/First.java"),
                seed_key("src/Second.java"),
                seed_key("src/Third.java"),
            ])
            .unwrap();
        assert!(answers[0].is_none());
        assert!(answers[1].is_some());
        assert!(answers[2].is_none());
    }

    #[test]
    fn a_read_key_row_that_lost_a_column_is_a_load_error() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .publish_policy_units(vec![unit_row(
                "src/Main.java",
                vec![ReadKey::index(
                    IndexFamily::DefinitionExact,
                    b"com.example.Main",
                )],
            )])
            .unwrap();
        {
            let conn = store.conn.lock().expect("store mutex");
            conn.execute(
                "UPDATE policy_read_keys SET index_key = ?1",
                params![b"com.example.Other".as_slice()],
            )
            .unwrap();
        }

        let error = store
            .policy_units_for_keys(&[seed_key("src/Main.java")])
            .expect_err("a key that no longer rebuilds to its identity is an error");
        assert!(error.to_string().contains("did not rebuild"), "{error}");
    }

    #[test]
    fn an_evaluation_links_its_units_in_merge_order() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let units = vec![
            unit_row("src/B.java", vec![]),
            unit_row("src/A.java", vec![]),
        ];
        store.publish_policy_units(units).unwrap();
        let key = PolicyEvaluationRowKey {
            base_tree_oid: TREE.to_string(),
            policy_set_digest: POLICY_HASH.to_string(),
            options_digest: CONFIGURATION.to_string(),
            configuration_fingerprint: CONFIGURATION.to_string(),
            active_model_set_hash: MODELS.to_string(),
            engine_epoch: EPOCH.to_string(),
        };
        assert!(
            store
                .publish_policy_evaluation(PolicyEvaluationRow {
                    key: key.clone(),
                    resolved_commit: COMMIT.to_string(),
                    analyzed_source_bytes: 42,
                    analyzed_file_count: 2,
                    units: vec![(
                        "test.policy".to_string(),
                        vec![seed_key("src/B.java"), seed_key("src/A.java")],
                    )],
                })
                .unwrap()
        );

        let loaded = store
            .policy_evaluation_for_key(&key)
            .unwrap()
            .expect("the evaluation is found by its key");
        assert!(loaded.is_complete());
        assert_eq!(loaded.resolved_commit, COMMIT);
        assert_eq!(loaded.analyzed_source_bytes, 42);
        let [(policy_id, units)] = loaded.units.as_slice() else {
            panic!("one policy: {:#?}", loaded.units);
        };
        assert_eq!(policy_id, "test.policy");
        assert_eq!(
            units
                .iter()
                .map(|unit| unit.key.partition.key_columns().0)
                .collect::<Vec<_>>(),
            vec!["src/B.java".to_string(), "src/A.java".to_string()],
            "the merge order the base walked is the order it is replayed in"
        );
    }

    #[test]
    fn an_evaluation_whose_unit_is_missing_is_not_published() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let published = store
            .publish_policy_evaluation(PolicyEvaluationRow {
                key: PolicyEvaluationRowKey {
                    base_tree_oid: TREE.to_string(),
                    policy_set_digest: POLICY_HASH.to_string(),
                    options_digest: CONFIGURATION.to_string(),
                    configuration_fingerprint: CONFIGURATION.to_string(),
                    active_model_set_hash: MODELS.to_string(),
                    engine_epoch: EPOCH.to_string(),
                },
                resolved_commit: COMMIT.to_string(),
                analyzed_source_bytes: 0,
                analyzed_file_count: 0,
                units: vec![("test.policy".to_string(), vec![seed_key("src/Gone.java")])],
            })
            .unwrap();
        assert!(
            !published,
            "an evaluation that cannot name all of its units is not an evaluation a run may reuse"
        );
        let conn = store.conn.lock().expect("store mutex");
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM policy_evaluations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(rows, 0);
    }

    /// The batched unit lookup must seek the unit key once per requested
    /// partition. A scan here would make verification cost a table walk per
    /// policy, which is the cost the whole mechanism exists to avoid.
    #[test]
    fn the_batched_unit_lookup_seeks_the_unit_key_index() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().expect("store mutex");
        let sql = format!(
            "EXPLAIN QUERY PLAN {}",
            policy_unit_batch_sql("(?,?,?),(?,?,?)")
        );
        let mut statement = conn.prepare(&sql).unwrap();
        let plan = statement
            .query_map(
                params![
                    POLICY_HASH,
                    "match",
                    CONFIGURATION,
                    MODELS,
                    EPOCH,
                    "seed",
                    "src/A.java",
                    BLOB,
                    "seed",
                    "src/B.java",
                    BLOB
                ],
                |row| row.get::<_, String>(3),
            )
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        // The table is aliased in the statement, so the plan names the alias.
        assert!(
            plan.iter()
                .any(|detail| detail.contains("SEARCH units USING")
                    && detail.contains("policy_units_key")),
            "{plan:#?}"
        );
        assert!(
            plan.iter().all(|detail| !detail.contains("SCAN units")),
            "{plan:#?}"
        );
    }

    /// The evaluation lookup is a point read on its own key.
    #[test]
    fn the_evaluation_lookup_seeks_the_evaluation_key_index() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().expect("store mutex");
        let mut statement = conn
            .prepare(&format!(
                "EXPLAIN QUERY PLAN {POLICY_EVALUATION_LOOKUP_SQL}"
            ))
            .unwrap();
        let plan = statement
            .query_map(
                params![
                    TREE,
                    POLICY_HASH,
                    CONFIGURATION,
                    CONFIGURATION,
                    MODELS,
                    EPOCH
                ],
                |row| row.get::<_, String>(3),
            )
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert!(
            plan.iter()
                .any(|detail| detail.contains("SEARCH policy_evaluations USING")
                    && detail.contains("policy_evaluations_key")),
            "{plan:#?}"
        );
        assert!(
            plan.iter()
                .all(|detail| !detail.contains("SCAN policy_evaluations")),
            "{plan:#?}"
        );
    }

    /// The unit membership of one evaluation is one seek, and so is the read
    /// set of one unit.
    #[test]
    fn the_membership_reads_seek_their_primary_keys() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().expect("store mutex");
        let mut statement = conn
            .prepare(
                "EXPLAIN QUERY PLAN
                 SELECT keys.kind FROM policy_unit_reads AS membership
                 JOIN policy_read_keys AS keys ON keys.read_id = membership.read_id
                 WHERE membership.unit_id = ?1",
            )
            .unwrap();
        let plan = statement
            .query_map(params![1_i64], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert!(
            plan.iter()
                .any(|detail| detail.contains("SEARCH membership USING PRIMARY KEY")),
            "{plan:#?}"
        );
        assert!(
            plan.iter()
                .all(|detail| !detail.contains("SCAN membership")),
            "{plan:#?}"
        );
    }
}
