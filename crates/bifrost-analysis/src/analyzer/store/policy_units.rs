//! Persisted policy evaluation units and base evaluations (migration 0036).
//!
//! A policy evaluation unit is one policy evaluated over one partition of a
//! workspace, together with the read set that licenses reusing it
//! (`.agents/plans/impact-sliced-diff-base.md`, Milestone 3). This module is
//! the store side of that: the row shapes and the SQL that writes and reads
//! them. The shared store read-key codec turns each [`ReadKey`] into columns
//! and back.
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
use crate::analyzer::read_ledger::ReadKey;
use crate::analyzer::store::AnalyzerStore;

use super::read_keys::{ReadKeyColumns, decode_read_key};

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
    /// One seed file of one row binding of a relational assertion policy: the
    /// file, the blob that path resolved to, and the digest of the binding's
    /// name. The binding is part of the key because one policy runs one query
    /// per binding over the same seed files, and two of them keyed by the file
    /// alone would answer each other's question.
    Binding {
        rel_path: String,
        blob: Oid,
        language: Language,
        binding: String,
    },
    /// One subject file of an assertion policy: the file, the blob that path
    /// resolved to, and the digest of the subject rows this unit asserted over.
    /// The digest is part of the key because two runs whose subject selector
    /// bound different rows in the same bytes asked different questions.
    AssertFile {
        rel_path: String,
        blob: Oid,
        language: Language,
        subjects: String,
    },
    /// One solver root of a typestate policy: the file the root procedure is
    /// declared in, the blob that path resolved to, and the root's own
    /// checkout-independent semantic locator. The locator is part of the key
    /// because one file declares many procedures and a typestate policy solves
    /// each of them separately: two roots keyed by the file alone would be one
    /// key, and the second root's findings would be served from the first
    /// root's unit.
    Root {
        rel_path: String,
        blob: Oid,
        language: Language,
        locator: String,
    },
    /// One seed file of one selector of a policy that compiles selectors: the
    /// file, the blob that path resolved to, and the digest of the selector's
    /// document path. The selector is part of the key because one policy
    /// compiles many selectors over the same seed files, and two of them keyed
    /// by the file alone would answer each other's question.
    Selector {
        rel_path: String,
        blob: Oid,
        language: Language,
        selector: String,
    },
    /// The whole policy, which is what a widened evaluation publishes.
    Whole,
}

impl PolicyUnitPartitionRow {
    const fn kind(&self) -> &'static str {
        match self {
            Self::Seed { .. } => "seed",
            Self::Binding { .. } => "binding",
            Self::AssertFile { .. } => "assert_file",
            Self::Root { .. } => "root",
            Self::Selector { .. } => "selector",
            Self::Whole => "whole",
        }
    }

    /// The three key columns, with the empty string where a partition has no
    /// seed or no narrowing digest. An absent component is spelled as a value
    /// rather than as NULL because SQLite treats NULLs in a unique index as
    /// distinct, which would let one policy publish an unbounded number of
    /// whole units.
    fn key_columns(&self) -> (String, String, String) {
        match self {
            Self::Seed { rel_path, blob, .. } => {
                (rel_path.clone(), blob.to_string(), String::new())
            }
            Self::Binding {
                rel_path,
                blob,
                binding,
                ..
            } => (rel_path.clone(), blob.to_string(), binding.clone()),
            Self::AssertFile {
                rel_path,
                blob,
                subjects,
                ..
            } => (rel_path.clone(), blob.to_string(), subjects.clone()),
            Self::Root {
                rel_path,
                blob,
                locator,
                ..
            } => (rel_path.clone(), blob.to_string(), locator.clone()),
            Self::Selector {
                rel_path,
                blob,
                selector,
                ..
            } => (rel_path.clone(), blob.to_string(), selector.clone()),
            Self::Whole => (String::new(), String::new(), String::new()),
        }
    }

    /// The blob this partition hangs off, when it covers one file.
    const fn blob(&self) -> Option<(&Oid, &Language)> {
        match self {
            Self::Seed { blob, language, .. }
            | Self::Binding { blob, language, .. }
            | Self::AssertFile { blob, language, .. }
            | Self::Root { blob, language, .. }
            | Self::Selector { blob, language, .. } => Some((blob, language)),
            Self::Whole => None,
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

/// One completed base evaluation: what it concluded, and what it published.
///
/// The identities are the evaluation's answer -- the strong finding identities
/// a later run joins its head findings against -- and they are recorded for
/// every policy that ran, whatever its family. The units are the per-partition
/// work that produced some of those findings; a policy that has no units
/// contributes none, which costs the head reuse and costs the evaluation
/// nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvaluationRow {
    pub key: PolicyEvaluationRowKey,
    /// The commit the requested revision resolved to, as lowercase hex.
    pub resolved_commit: String,
    /// The strong finding identities this evaluation produced, per policy.
    pub identities: Vec<(String, Vec<[u8; 32]>)>,
    /// The units this evaluation published, per policy.
    pub units: Vec<(String, Vec<PolicyUnitRowKey>)>,
}

/// One loaded base evaluation.
///
/// The identities are the whole answer: a run that finds this row skips the
/// export, the build and the evaluation of the base entirely and joins against
/// these. The units it published are found by their own keys when the head
/// asks about them, so they are not loaded here.
#[derive(Debug, Clone)]
pub struct LoadedPolicyEvaluation {
    pub resolved_commit: String,
    pub identities: Vec<(String, Vec<[u8; 32]>)>,
}

/// The columns of `policy_units` a load needs, in one place so the reader and
/// the row decoder cannot disagree about their order.
const UNIT_COLUMNS: &str = "units.unit_id, units.policy_semantic_hash, units.family, \
     units.partition_kind, units.seed_rel_path, units.seed_blob_oid, units.partition_digest, \
     units.lang, units.configuration_fingerprint, units.active_model_set_hash, \
     units.engine_epoch, units.product_kind, units.product, units.read_set_digest";

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
        let mut parameters: Vec<String> = Vec::with_capacity(5 + keys.len() * 4);
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
            let (rel_path, blob_oid, partition_digest) = key.partition.key_columns();
            parameters.push(key.partition.kind().to_string());
            parameters.push(rel_path);
            parameters.push(blob_oid);
            parameters.push(partition_digest);
            if index > 0 {
                values.push(',');
            }
            values.push_str("(?,?,?,?)");
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

    /// Record what one policy set concluded over one committed subtree, and
    /// which units that evaluation published.
    ///
    /// The identities are the record: they are written whether or not any
    /// policy published a unit, because they are what a later run replaces the
    /// base evaluation with. A membership whose unit row is gone -- its blob
    /// was re-parsed between the flush and this write -- is dropped rather
    /// than refusing the evaluation, since a unit is an optimization for the
    /// head and never part of the answer. Publishing also sweeps, because a
    /// base evaluation is keyed by a tree id and has no blob to follow out of
    /// the cache.
    pub fn publish_policy_evaluation(&self, evaluation: PolicyEvaluationRow) -> Result<()> {
        let published_at = now_secs();
        self.conn.execute(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let mut memberships: Vec<(String, i64)> = Vec::new();
            for (policy_id, keys) in &evaluation.units {
                for key in keys {
                    if let Some(unit_id) = unit_id_for_key(&tx, key)? {
                        memberships.push((policy_id.clone(), unit_id));
                    }
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
                   resolved_commit, published_at
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    key.base_tree_oid,
                    key.policy_set_digest,
                    key.options_digest,
                    key.configuration_fingerprint,
                    key.active_model_set_hash,
                    key.engine_epoch,
                    evaluation.resolved_commit,
                    published_at,
                ],
            )?;
            let evaluation_id = tx.last_insert_rowid();
            {
                let mut insert = tx.prepare_cached(
                    "INSERT INTO policy_evaluation_identities(
                       evaluation_id, policy_id, finding_id
                     ) VALUES(?1, ?2, ?3)
                     ON CONFLICT(evaluation_id, policy_id, finding_id) DO NOTHING",
                )?;
                for (policy_id, findings) in &evaluation.identities {
                    for finding_id in findings {
                        insert.execute(params![evaluation_id, policy_id, finding_id.as_slice()])?;
                    }
                }
            }
            {
                let mut insert = tx.prepare_cached(
                    "INSERT INTO policy_evaluation_units(
                       evaluation_id, policy_id, unit_id
                     ) VALUES(?1, ?2, ?3)
                     ON CONFLICT(evaluation_id, policy_id, unit_id) DO NOTHING",
                )?;
                for (policy_id, unit_id) in &memberships {
                    insert.execute(params![evaluation_id, policy_id, unit_id])?;
                }
            }
            sweep_policy_rows(&tx, published_at)?;
            tx.commit()?;
            Ok(())
        })
    }

    /// The base evaluation published under `key`, with the identities it
    /// concluded.
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
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let Some((evaluation_id, resolved_commit)) = row else {
            return Ok(None);
        };
        // The primary key clusters the rows by policy, so consecutive rows
        // group without a sort and without a second pass over the answer.
        let mut per_policy: Vec<(String, Vec<[u8; 32]>)> = Vec::new();
        let mut statement = conn.prepare_cached(POLICY_EVALUATION_IDENTITY_SQL)?;
        let mut rows = statement.query(params![evaluation_id])?;
        while let Some(row) = rows.next()? {
            let policy_id = row.get::<_, String>(0)?;
            let finding_id = row.get::<_, Vec<u8>>(1)?;
            let finding_id = <[u8; 32]>::try_from(finding_id.as_slice()).map_err(|_| {
                StoreError::new(format!(
                    "policy evaluation {evaluation_id} records a finding identity of {} bytes",
                    finding_id.len()
                ))
            })?;
            match per_policy.last_mut() {
                Some((last, findings)) if *last == policy_id => findings.push(finding_id),
                _ => per_policy.push((policy_id, vec![finding_id])),
            }
        }
        Ok(Some(LoadedPolicyEvaluation {
            resolved_commit,
            identities: per_policy,
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
           AND (partition_kind, seed_rel_path, seed_blob_oid, partition_digest)
               IN (VALUES {values})"
    )
}

/// The evaluation lookup, shared with its query-plan pin.
pub(crate) const POLICY_EVALUATION_LOOKUP_SQL: &str = "SELECT evaluation_id, resolved_commit
     FROM policy_evaluations
     WHERE base_tree_oid = ?1 AND policy_set_digest = ?2 AND options_digest = ?3
       AND configuration_fingerprint = ?4 AND active_model_set_hash = ?5
       AND engine_epoch = ?6";

/// The identity read, shared with its query-plan pin.
///
/// One seek on the leading column of a `WITHOUT ROWID` primary key, which
/// returns the rows already grouped by policy.
pub(crate) const POLICY_EVALUATION_IDENTITY_SQL: &str =
    "SELECT policy_id, finding_id FROM policy_evaluation_identities
     WHERE evaluation_id = ?1";

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
    let (rel_path, blob_oid, partition_digest) = key.partition.key_columns();
    conn.query_row(
        "SELECT unit_id FROM policy_units
         WHERE policy_semantic_hash = ?1 AND family = ?2
           AND configuration_fingerprint = ?3 AND active_model_set_hash = ?4
           AND engine_epoch = ?5 AND partition_kind = ?6
           AND seed_rel_path = ?7 AND seed_blob_oid = ?8 AND partition_digest = ?9",
        params![
            key.policy_semantic_hash,
            key.family,
            key.configuration_fingerprint,
            key.active_model_set_hash,
            key.engine_epoch,
            key.partition.kind(),
            rel_path,
            blob_oid,
            partition_digest,
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
    let (rel_path, blob_oid, partition_digest) = key.partition.key_columns();
    let (blob_id, lang) = match key.partition.blob() {
        Some((blob, language)) => {
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
        None => (None, None),
    };
    conn.execute(
        "DELETE FROM policy_units
         WHERE policy_semantic_hash = ?1 AND family = ?2
           AND configuration_fingerprint = ?3 AND active_model_set_hash = ?4
           AND engine_epoch = ?5 AND partition_kind = ?6
           AND seed_rel_path = ?7 AND seed_blob_oid = ?8 AND partition_digest = ?9",
        params![
            key.policy_semantic_hash,
            key.family,
            key.configuration_fingerprint,
            key.active_model_set_hash,
            key.engine_epoch,
            key.partition.kind(),
            rel_path,
            blob_oid,
            partition_digest,
        ],
    )?;
    conn.execute(
        "INSERT INTO policy_units(
           policy_semantic_hash, family, partition_kind, seed_rel_path,
           seed_blob_oid, partition_digest, seed_blob_id, lang,
           configuration_fingerprint, active_model_set_hash, engine_epoch,
           completion, budget_mode, product_kind, product, read_set_digest,
           published_at
         ) VALUES(
           ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'complete',
           'exhaustive', ?12, ?13, ?14, ?15
         )",
        params![
            key.policy_semantic_hash,
            key.family,
            key.partition.kind(),
            rel_path,
            blob_oid,
            partition_digest,
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

/// One unit row, without its reads. The columns are [`UNIT_COLUMNS`], in order.
fn decode_unit_row(row: &rusqlite::Row<'_>) -> Result<(i64, PolicyUnitRow)> {
    let unit_id = row.get::<_, i64>(0)?;
    let policy_semantic_hash = row.get::<_, String>(1)?;
    let family = row.get::<_, String>(2)?;
    let partition_kind = row.get::<_, String>(3)?;
    let seed_rel_path = row.get::<_, String>(4)?;
    let seed_blob_oid = row.get::<_, String>(5)?;
    let partition_digest = row.get::<_, String>(6)?;
    let lang = row.get::<_, Option<String>>(7)?;
    let configuration_fingerprint = row.get::<_, String>(8)?;
    let active_model_set_hash = row.get::<_, String>(9)?;
    let engine_epoch = row.get::<_, String>(10)?;
    let product_kind = row.get::<_, String>(11)?;
    let product = row.get::<_, String>(12)?;
    let read_set_digest = row.get::<_, Vec<u8>>(13)?;
    let partition = match partition_kind.as_str() {
        "seed" | "binding" | "assert_file" | "root" | "selector" => {
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
            match partition_kind.as_str() {
                "seed" => PolicyUnitPartitionRow::Seed {
                    rel_path: seed_rel_path,
                    blob,
                    language,
                },
                "binding" => PolicyUnitPartitionRow::Binding {
                    rel_path: seed_rel_path,
                    blob,
                    language,
                    binding: partition_digest,
                },
                "assert_file" => PolicyUnitPartitionRow::AssertFile {
                    rel_path: seed_rel_path,
                    blob,
                    language,
                    subjects: partition_digest,
                },
                "root" => PolicyUnitPartitionRow::Root {
                    rel_path: seed_rel_path,
                    blob,
                    language,
                    locator: partition_digest,
                },
                _ => PolicyUnitPartitionRow::Selector {
                    rel_path: seed_rel_path,
                    blob,
                    language,
                    selector: partition_digest,
                },
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::content_identity::WorkspaceContentIdentity;
    use crate::analyzer::invalidation::{DerivedArtifactId, DerivedArtifactKind};
    use crate::analyzer::read_ledger::{
        CallSiteLocator, IndexFamily, LookupKind, LookupQuestion, read_set_digest,
    };
    use crate::analyzer::semantic::ids::StableDigest;
    // Every EXPLAIN QUERY PLAN pin below runs its assertions once against a
    // store with no planner statistics and once with the statistics captured
    // from real corpus stores, because production carries the latter (#3016).
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;

    const POLICY_HASH: &str = "aa11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee";
    const CONFIGURATION: &str = "bb11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee";
    const MODELS: &str = "cc11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee";
    const EPOCH: &str = "dd11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee";
    const BLOB: &str = "1111111111111111111111111111111111111111";
    const SUBJECTS: &str = "ee11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee";
    const TREE: &str = "2222222222222222222222222222222222222222";
    const COMMIT: &str = "3333333333333333333333333333333333333333";

    /// One assertion policy's assert unit over `rel_path`.
    fn assert_file_key(rel_path: &str) -> PolicyUnitRowKey {
        PolicyUnitRowKey {
            policy_semantic_hash: POLICY_HASH.to_string(),
            family: "assertion".to_string(),
            partition: PolicyUnitPartitionRow::AssertFile {
                rel_path: rel_path.to_string(),
                blob: Oid::from_str(BLOB).unwrap(),
                language: Language::Java,
                subjects: SUBJECTS.to_string(),
            },
            configuration_fingerprint: CONFIGURATION.to_string(),
            active_model_set_hash: MODELS.to_string(),
            engine_epoch: EPOCH.to_string(),
        }
    }

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

    /// An assert unit and a seed unit over the same file and blob are two
    /// units, because the assert unit's key carries the digest of the subject
    /// rows it asserted over and the seed unit's does not. Without that column
    /// one would overwrite the other and a run would answer an assertion with a
    /// query's rows.
    #[test]
    fn an_assert_file_unit_and_a_seed_unit_over_one_file_are_two_rows() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let reads = vec![ReadKey::Epoch(StableDigest::sha256(b"epoch"))];
        let seed = unit_row("src/Main.java", reads.clone());
        let asserted = PolicyUnitRow {
            key: assert_file_key("src/Main.java"),
            product_kind: "assert_file".to_string(),
            product: "{\"findings\":[]}".to_string(),
            read_set_digest: *read_set_digest(&reads).digest().as_bytes(),
            reads,
        };

        let written = store
            .publish_policy_units(vec![seed, asserted])
            .expect("both units publish");

        assert_eq!(written, 2);
        let answers = store
            .policy_units_for_keys(&[assert_file_key("src/Main.java")])
            .expect("the assert unit is looked up by its own key");
        let [Some(loaded)] = answers.as_slice() else {
            panic!("one key, one answer: {answers:#?}");
        };
        assert_eq!(loaded.product_kind, "assert_file");
        assert_eq!(loaded.key, assert_file_key("src/Main.java"));
    }

    /// A unit whose product kind does not match its partition is refused by the
    /// schema rather than loaded and rejected later.
    #[test]
    fn an_assert_partition_carrying_query_rows_is_refused() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let reads = vec![ReadKey::Epoch(StableDigest::sha256(b"epoch"))];
        let mismatched = PolicyUnitRow {
            key: assert_file_key("src/Main.java"),
            product_kind: "rows".to_string(),
            product: "{\"rows\":[]}".to_string(),
            read_set_digest: *read_set_digest(&reads).digest().as_bytes(),
            reads,
        };

        store
            .publish_policy_units(vec![mismatched])
            .expect_err("a file's findings are an assert's product, not a query's");
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

    fn evaluation_key() -> PolicyEvaluationRowKey {
        PolicyEvaluationRowKey {
            base_tree_oid: TREE.to_string(),
            policy_set_digest: POLICY_HASH.to_string(),
            options_digest: CONFIGURATION.to_string(),
            configuration_fingerprint: CONFIGURATION.to_string(),
            active_model_set_hash: MODELS.to_string(),
            engine_epoch: EPOCH.to_string(),
        }
    }

    fn finding_id(seed: &str) -> [u8; 32] {
        *StableDigest::sha256(seed.as_bytes()).as_bytes()
    }

    #[test]
    fn an_evaluation_records_the_identities_every_policy_concluded() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .publish_policy_units(vec![unit_row("src/A.java", vec![])])
            .unwrap();
        let key = evaluation_key();
        store
            .publish_policy_evaluation(PolicyEvaluationRow {
                key: key.clone(),
                resolved_commit: COMMIT.to_string(),
                identities: vec![
                    (
                        "test.match".to_string(),
                        vec![finding_id("first"), finding_id("second")],
                    ),
                    // A whole-family policy publishes no unit and still
                    // records what it found, which is the whole point of the
                    // identities table.
                    ("test.taint".to_string(), vec![finding_id("taint")]),
                ],
                units: vec![("test.match".to_string(), vec![seed_key("src/A.java")])],
            })
            .unwrap();

        let loaded = store
            .policy_evaluation_for_key(&key)
            .unwrap()
            .expect("the evaluation is found by its key");
        assert_eq!(loaded.resolved_commit, COMMIT);
        let mut identities = loaded.identities;
        for (_, findings) in &mut identities {
            findings.sort_unstable();
        }
        let mut expected = vec![
            (
                "test.match".to_string(),
                vec![finding_id("first"), finding_id("second")],
            ),
            ("test.taint".to_string(), vec![finding_id("taint")]),
        ];
        for (_, findings) in &mut expected {
            findings.sort_unstable();
        }
        identities.sort_by(|left, right| left.0.cmp(&right.0));
        expected.sort_by(|left, right| left.0.cmp(&right.0));
        assert_eq!(identities, expected);
    }

    #[test]
    fn an_evaluation_whose_unit_is_missing_still_records_its_identities() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let key = evaluation_key();
        store
            .publish_policy_evaluation(PolicyEvaluationRow {
                key: key.clone(),
                resolved_commit: COMMIT.to_string(),
                identities: vec![("test.policy".to_string(), vec![finding_id("only")])],
                units: vec![("test.policy".to_string(), vec![seed_key("src/Gone.java")])],
            })
            .unwrap();

        let loaded = store
            .policy_evaluation_for_key(&key)
            .unwrap()
            .expect("an evaluation is its identities, not its units");
        assert_eq!(
            loaded.identities,
            vec![("test.policy".to_string(), vec![finding_id("only")])]
        );
        let conn = store.conn.lock().expect("store mutex");
        let memberships: i64 = conn
            .query_row("SELECT COUNT(*) FROM policy_evaluation_units", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            memberships, 0,
            "a unit that left the cache leaves no membership behind"
        );
    }

    #[test]
    fn an_evaluation_republished_under_one_key_keeps_one_set_of_identities() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let key = evaluation_key();
        for seed in ["first", "second"] {
            store
                .publish_policy_evaluation(PolicyEvaluationRow {
                    key: key.clone(),
                    resolved_commit: COMMIT.to_string(),
                    identities: vec![("test.policy".to_string(), vec![finding_id(seed)])],
                    units: Vec::new(),
                })
                .unwrap();
        }

        let loaded = store
            .policy_evaluation_for_key(&key)
            .unwrap()
            .expect("the evaluation is found by its key");
        assert_eq!(
            loaded.identities,
            vec![("test.policy".to_string(), vec![finding_id("second")])],
            "the second evaluation replaced the first, cascade and all"
        );
        let conn = store.conn.lock().expect("store mutex");
        let rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM policy_evaluation_identities",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rows, 1);
    }

    /// The batched unit lookup must seek the unit key once per requested
    /// partition. A scan here would make verification cost a table walk per
    /// policy, which is the cost the whole mechanism exists to avoid.
    #[test]
    fn the_batched_unit_lookup_seeks_the_unit_key_index() {
        for state in PlannerStatisticsState::BOTH {
            the_batched_unit_lookup_seeks_the_unit_key_index_in(state);
        }
    }

    fn the_batched_unit_lookup_seeks_the_unit_key_index_in(state: PlannerStatisticsState) {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().expect("store mutex");
        state.install(&conn);
        let sql = format!(
            "EXPLAIN QUERY PLAN {}",
            policy_unit_batch_sql("(?,?,?,?),(?,?,?,?)")
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
                    "",
                    "assert_file",
                    "src/B.java",
                    BLOB,
                    SUBJECTS
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
            "{state}: {plan:#?}"
        );
        assert!(
            plan.iter().all(|detail| !detail.contains("SCAN units")),
            "{state}: {plan:#?}"
        );
    }

    /// The evaluation lookup is a point read on its own key.
    #[test]
    fn the_evaluation_lookup_seeks_the_evaluation_key_index() {
        for state in PlannerStatisticsState::BOTH {
            the_evaluation_lookup_seeks_the_evaluation_key_index_in(state);
        }
    }

    fn the_evaluation_lookup_seeks_the_evaluation_key_index_in(state: PlannerStatisticsState) {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().expect("store mutex");
        state.install(&conn);
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
            "{state}: {plan:#?}"
        );
        assert!(
            plan.iter()
                .all(|detail| !detail.contains("SCAN policy_evaluations")),
            "{state}: {plan:#?}"
        );
    }

    /// The identities of one evaluation are one seek on the primary key,
    /// which is what makes the warm path a point read rather than a scan of
    /// every evaluation this store retains.
    #[test]
    fn the_identity_read_seeks_the_evaluation_primary_key() {
        for state in PlannerStatisticsState::BOTH {
            the_identity_read_seeks_the_evaluation_primary_key_in(state);
        }
    }

    fn the_identity_read_seeks_the_evaluation_primary_key_in(state: PlannerStatisticsState) {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().expect("store mutex");
        state.install(&conn);
        let mut statement = conn
            .prepare(&format!(
                "EXPLAIN QUERY PLAN {POLICY_EVALUATION_IDENTITY_SQL}"
            ))
            .unwrap();
        let plan = statement
            .query_map(params![1_i64], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert!(
            plan.iter()
                .any(|detail| detail
                    .contains("SEARCH policy_evaluation_identities USING PRIMARY KEY")),
            "{state}: {plan:#?}"
        );
        assert!(
            plan.iter()
                .all(|detail| !detail.contains("SCAN policy_evaluation_identities")),
            "{state}: {plan:#?}"
        );
    }

    /// The unit membership of one evaluation is one seek, and so is the read
    /// set of one unit.
    #[test]
    fn the_membership_reads_seek_their_primary_keys() {
        for state in PlannerStatisticsState::BOTH {
            the_membership_reads_seek_their_primary_keys_in(state);
        }
    }

    fn the_membership_reads_seek_their_primary_keys_in(state: PlannerStatisticsState) {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().expect("store mutex");
        state.install(&conn);
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
            "{state}: {plan:#?}"
        );
        assert!(
            plan.iter()
                .all(|detail| !detail.contains("SCAN membership")),
            "{state}: {plan:#?}"
        );
    }
}
