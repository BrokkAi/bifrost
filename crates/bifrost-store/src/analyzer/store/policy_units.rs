//! Persisted policy evaluation units and base evaluations (migration 0036).
//!
//! A policy evaluation unit is one policy evaluated over one partition of a
//! workspace, together with the read set that licenses reusing it. This module is
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

#[cfg(test)]
use brokk_bifrost_semantic::analyzer::semantic::read_ledger::{FactSubject, WorkspaceFactFamily};
use git2::Oid;
use rusqlite::{OptionalExtension, TransactionBehavior, params, params_from_iter};
use std::collections::HashMap;

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

/// How many snapshots one unit keeps attestations for.
///
/// Each check that reuses a unit attests it on that check's head, so a unit
/// that survives a long chain of checks would collect one row per commit. A
/// later check asks about its own base and head, which are almost always the
/// most recent snapshots any run verified, so the oldest attestations are the
/// ones dropped.
pub const MAX_UNIT_SNAPSHOTS: usize = 8;

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
    /// The content identities of the workspace snapshots this unit's
    /// name-index answers are known to hold on.
    ///
    /// A unit's name-index reads are proved against the names that moved
    /// between two snapshots, which holds only for index answers of the first
    /// of them. The reader looks for one of the snapshots its own comparison is
    /// between here and recomputes a unit whose index answers are attested on
    /// neither. A publication names at least one; a load returns the most
    /// recent [`MAX_UNIT_SNAPSHOTS`].
    pub snapshots: Vec<[u8; 32]>,
}

/// A loaded unit that a later run verified on one more snapshot.
///
/// Verification proves that the unit's name-index answers on `verified_on`
/// are its answers on each of `snapshots` too. The row it applies to is found
/// by its key and read-set digest, and only a row already attested on
/// `verified_on` gains the new snapshots: a row another run published under
/// the same key since this run loaded it holds answers of some other snapshot,
/// which this verification says nothing about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyUnitAttestation {
    pub key: PolicyUnitRowKey,
    pub read_set_digest: [u8; 32],
    pub verified_on: [u8; 32],
    pub snapshots: Vec<[u8; 32]>,
}

/// The shared key of one base-evaluation context.
///
/// The policy id and its source and semantic identities are stored on each
/// completed child row, so a policy-set change does not invalidate unrelated
/// policy evidence.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PolicyEvaluationRowKey {
    /// The git tree id of the exported workspace subtree, as lowercase hex.
    pub base_tree_oid: String,
    pub options_digest: String,
    pub configuration_fingerprint: String,
    pub active_model_set_hash: String,
    pub engine_epoch: String,
}

/// One policy result under a shared base-evaluation context.
///
/// The policy row records its completion tier and diagnostics. Only a
/// `complete` row's identities are eligible for diff classification; an empty
/// identity vector on such a row is a complete answer with no findings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvaluationPolicyRow {
    pub policy_id: String,
    /// The authored source identity, as lowercase hex.
    pub source_hash: String,
    /// The resolved policy and dependency identity, as lowercase hex.
    pub semantic_hash: String,
    /// Stable completion tier: `complete`, `proven_subset`, `proven_by_summary`,
    /// `inconclusive`, `unsupported`, or `failed`.
    pub completion: String,
    /// Canonical JSON for the typed completion value, including its reasons.
    pub completion_detail: String,
    /// Why this row cannot classify findings when `qualified` is false.
    pub qualification_detail: String,
    /// Whether this result can classify findings from the head. A policy may
    /// finish exhaustively while report-level evidence was truncated.
    pub qualified: bool,
    /// Complete per-policy diagnostic collection, each entry formatted from
    /// the diagnostic's Debug representation.
    pub diagnostics: Vec<String>,
    /// Strong finding identities. Incomplete rows must keep this empty.
    pub identities: Vec<[u8; 32]>,
    /// Complete units this policy published during the evaluation.
    pub units: Vec<PolicyUnitRowKey>,
}

/// Completed policy answers published under one base-evaluation context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvaluationRow {
    pub key: PolicyEvaluationRowKey,
    /// The commit the requested revision resolved to, as lowercase hex.
    pub resolved_commit: String,
    /// The runnable policy identities used to produce `unreliable_detail`.
    /// This is metadata, not part of the shared evidence lookup key.
    pub policy_set_digest: String,
    /// The cold base's aggregate reliability explanation, if any.
    pub unreliable_detail: Option<String>,
    /// Whether the cold base's aggregate result was unreliable.
    pub aggregate_unreliable: bool,
    /// The content identity of the base workspace this evaluation analyzed.
    ///
    /// A later run that reuses this evaluation builds no base workspace, so
    /// this is how it knows which published units were computed on its base.
    pub base_content_identity: [u8; 32],
    /// Exhaustive policy results published by this evaluation.
    pub policies: Vec<PolicyEvaluationPolicyRow>,
    /// Policies evaluated without an exhaustive result. Remove any older
    /// answer for these ids so a prior complete row cannot mask this result.
    pub unqualified_policy_ids: Vec<String>,
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
    pub policy_set_digest: String,
    pub unreliable_detail: Option<String>,
    pub aggregate_unreliable: bool,
    /// The content identity of the base workspace the evaluation analyzed.
    pub base_content_identity: [u8; 32],
    pub policies: Vec<LoadedPolicyEvaluationPolicy>,
}

/// One loaded, exhaustively completed policy answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedPolicyEvaluationPolicy {
    pub policy_id: String,
    pub source_hash: String,
    pub semantic_hash: String,
    pub completion: String,
    pub completion_detail: String,
    pub qualified: bool,
    pub qualification_detail: String,
    pub diagnostics: Vec<String>,
    pub identities: Vec<[u8; 32]>,
}

/// The columns of `policy_units` a load needs, in one place so the reader and
/// the row decoder cannot disagree about their order.
const UNIT_COLUMNS: &str = "units.unit_id, units.policy_semantic_hash, units.family, \
     units.partition_kind, units.seed_rel_path, units.seed_blob_oid, units.partition_digest, \
     units.lang, units.configuration_fingerprint, units.active_model_set_hash, \
     units.engine_epoch, units.product_kind, json(units.product), units.read_set_digest";

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
        let published_at = brokk_bifrost_core::cache_db::now_unix_seconds();
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

    /// Record that loaded units were verified on more snapshots.
    ///
    /// An attestation whose row was replaced or retired since it was loaded
    /// applies to nothing and is dropped: the row now under its key was
    /// computed by another run, on answers this verification did not check.
    /// Returns how many units gained attestations.
    pub fn attest_policy_units(&self, attestations: Vec<PolicyUnitAttestation>) -> Result<usize> {
        if attestations.is_empty() {
            return Ok(0);
        }
        self.conn.execute(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let mut attested = 0;
            for attestation in &attestations {
                let Some(unit_id) = unit_id_for_key(&tx, &attestation.key)? else {
                    continue;
                };
                let verified = tx
                    .prepare_cached(
                        "SELECT 1 FROM policy_units AS units
                         JOIN policy_unit_snapshots AS snapshots
                           ON snapshots.unit_id = units.unit_id
                         WHERE units.unit_id = ?1 AND units.read_set_digest = ?2
                           AND snapshots.content_identity = ?3",
                    )?
                    .exists(params![
                        unit_id,
                        attestation.read_set_digest.as_slice(),
                        attestation.verified_on.as_slice(),
                    ])?;
                if verified {
                    insert_unit_snapshots(&tx, unit_id, &attestation.snapshots)?;
                    attested += 1;
                }
            }
            tx.commit()?;
            Ok(attested)
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
        let mut keys_by_id: HashMap<i64, PolicyUnitRowKey> = HashMap::new();
        while let Some(row) = rows.next()? {
            let (unit_id, mut unit) = decode_unit_row(row)?;
            unit.reads = load_unit_reads(&conn, unit_id)?;
            keys_by_id.insert(unit_id, unit.key.clone());
            found.insert(unit.key.clone(), unit);
        }
        if !keys_by_id.is_empty() {
            // One statement for the whole batch's snapshots, newest first, so
            // each unit keeps its most recent attestations.
            let ids = serde_json::to_string(&keys_by_id.keys().collect::<Vec<_>>())
                .expect("unit ids serialize");
            let mut statement = conn.prepare_cached(POLICY_UNIT_SNAPSHOTS_SQL)?;
            let mut rows = statement.query(params![ids])?;
            while let Some(row) = rows.next()? {
                let unit_id = row.get::<_, i64>(0)?;
                let snapshot = row.get::<_, Vec<u8>>(1)?;
                let snapshot = <[u8; 32]>::try_from(snapshot.as_slice()).map_err(|_| {
                    StoreError::new(format!(
                        "policy unit {unit_id} is attested on a content identity of {} bytes",
                        snapshot.len()
                    ))
                })?;
                let unit = found
                    .get_mut(&keys_by_id[&unit_id])
                    .expect("every loaded unit id names a loaded unit");
                if unit.snapshots.len() < MAX_UNIT_SNAPSHOTS {
                    unit.snapshots.push(snapshot);
                }
            }
        }
        Ok(keys.iter().map(|key| found.remove(key)).collect())
    }

    /// Record exhaustive policy answers over one committed subtree.
    ///
    /// Policy rows are replaced independently. A membership whose unit row is
    /// gone -- its blob was re-parsed between the flush and this write -- is
    /// dropped rather than refusing the policy answer, since a unit is an
    /// optimization for the head and never part of the answer. Publishing also
    /// sweeps, because a base evaluation is keyed by a tree id and has no blob
    /// to follow out of the cache.
    pub fn publish_policy_evaluation(&self, evaluation: PolicyEvaluationRow) -> Result<()> {
        let published_at = brokk_bifrost_core::cache_db::now_unix_seconds();
        self.conn.execute(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let mut memberships: Vec<(String, i64)> = Vec::new();
            for policy in &evaluation.policies {
                for key in &policy.units {
                    if let Some(unit_id) = unit_id_for_key(&tx, key)? {
                        memberships.push((policy.policy_id.clone(), unit_id));
                    }
                }
            }
            let key = &evaluation.key;
            tx.execute(
                "INSERT INTO policy_evaluations(
                   base_tree_oid, options_digest, configuration_fingerprint,
                   active_model_set_hash, engine_epoch, policy_set_digest,
                   unreliable_detail, aggregate_unreliable, resolved_commit, published_at,
                   base_content_identity
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                 ON CONFLICT(base_tree_oid, options_digest, configuration_fingerprint,
                             active_model_set_hash, engine_epoch)
                 DO UPDATE SET resolved_commit = excluded.resolved_commit,
                               policy_set_digest = excluded.policy_set_digest,
                               unreliable_detail = excluded.unreliable_detail,
                               aggregate_unreliable = excluded.aggregate_unreliable,
                               published_at = excluded.published_at,
                               base_content_identity = excluded.base_content_identity",
                params![
                    key.base_tree_oid,
                    key.options_digest,
                    key.configuration_fingerprint,
                    key.active_model_set_hash,
                    key.engine_epoch,
                    evaluation.policy_set_digest,
                    evaluation.unreliable_detail,
                    evaluation.aggregate_unreliable,
                    evaluation.resolved_commit,
                    published_at,
                    evaluation.base_content_identity.as_slice(),
                ],
            )?;
            let evaluation_id = tx.query_row(
                "SELECT evaluation_id FROM policy_evaluations
                 WHERE base_tree_oid = ?1 AND options_digest = ?2
                   AND configuration_fingerprint = ?3 AND active_model_set_hash = ?4
                   AND engine_epoch = ?5",
                params![
                    key.base_tree_oid,
                    key.options_digest,
                    key.configuration_fingerprint,
                    key.active_model_set_hash,
                    key.engine_epoch,
                ],
                |row| row.get::<_, i64>(0),
            )?;
            for policy_id in &evaluation.unqualified_policy_ids {
                tx.execute(
                    "DELETE FROM policy_evaluation_policies
                     WHERE evaluation_id = ?1 AND policy_id = ?2",
                    params![evaluation_id, policy_id],
                )?;
            }
            for policy in &evaluation.policies {
                tx.execute(
                    "DELETE FROM policy_evaluation_policies
                     WHERE evaluation_id = ?1 AND policy_id = ?2",
                    params![evaluation_id, policy.policy_id],
                )?;
                tx.execute(
                    "INSERT INTO policy_evaluation_policies(
                       evaluation_id, policy_id, source_hash, semantic_hash,
                       completion, completion_detail, qualified,
                       qualification_detail, diagnostics
                     ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    params![
                        evaluation_id,
                        policy.policy_id,
                        policy.source_hash,
                        policy.semantic_hash,
                        policy.completion,
                        policy.completion_detail,
                        policy.qualified,
                        policy.qualification_detail,
                        serde_json::to_string(&policy.diagnostics)
                            .expect("policy diagnostic strings serialize"),
                    ],
                )?;
                for finding_id in &policy.identities {
                    tx.execute(
                        "INSERT INTO policy_evaluation_identities(
                           evaluation_id, policy_id, finding_id
                         ) VALUES(?1, ?2, ?3)",
                        params![evaluation_id, policy.policy_id, finding_id.as_slice()],
                    )?;
                }
                for (policy_id, unit_id) in &memberships {
                    if policy_id == &policy.policy_id {
                        tx.execute(
                            "INSERT INTO policy_evaluation_units(
                               evaluation_id, policy_id, unit_id
                             ) VALUES(?1, ?2, ?3)",
                            params![evaluation_id, policy_id, unit_id],
                        )?;
                    }
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
                    key.options_digest,
                    key.configuration_fingerprint,
                    key.active_model_set_hash,
                    key.engine_epoch,
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, bool>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            evaluation_id,
            resolved_commit,
            policy_set_digest,
            unreliable_detail,
            aggregate_unreliable,
            base_content_identity,
        )) = row
        else {
            return Ok(None);
        };
        let base_content_identity = <[u8; 32]>::try_from(base_content_identity.as_slice())
            .map_err(|_| {
                StoreError::new(format!(
                    "policy evaluation {evaluation_id} has a base content identity of {} bytes",
                    base_content_identity.len()
                ))
            })?;
        // The child row exists even for a complete policy with no findings;
        // the LEFT JOIN therefore distinguishes that answer from no evidence.
        let mut policies: Vec<LoadedPolicyEvaluationPolicy> = Vec::new();
        let mut statement = conn.prepare_cached(POLICY_EVALUATION_IDENTITY_SQL)?;
        let mut rows = statement.query(params![evaluation_id])?;
        while let Some(row) = rows.next()? {
            let policy_id = row.get::<_, String>(0)?;
            let source_hash = row.get::<_, String>(1)?;
            let semantic_hash = row.get::<_, String>(2)?;
            let completion = row.get::<_, String>(3)?;
            let completion_detail = row.get::<_, String>(4)?;
            let qualified = row.get::<_, bool>(5)?;
            let qualification_detail = row.get::<_, String>(6)?;
            let diagnostics_json = row.get::<_, String>(7)?;
            match policies.last() {
                Some(last) if last.policy_id == policy_id => {}
                _ => policies.push(LoadedPolicyEvaluationPolicy {
                    policy_id,
                    source_hash,
                    semantic_hash,
                    completion,
                    completion_detail,
                    qualified,
                    qualification_detail,
                    diagnostics: serde_json::from_str(&diagnostics_json).map_err(|error| {
                        StoreError::new(format!(
                            "policy evaluation {evaluation_id} has invalid diagnostic JSON: {error}"
                        ))
                    })?,
                    identities: Vec::new(),
                }),
            }
            if let Some(finding_id) = row.get::<_, Option<Vec<u8>>>(8)? {
                let finding_id = <[u8; 32]>::try_from(finding_id.as_slice()).map_err(|_| {
                    StoreError::new(format!(
                        "policy evaluation {evaluation_id} records a finding identity of {} bytes",
                        finding_id.len()
                    ))
                })?;
                policies
                    .last_mut()
                    .expect("the joined policy row was just loaded")
                    .identities
                    .push(finding_id);
            }
        }
        Ok(Some(LoadedPolicyEvaluation {
            resolved_commit,
            policy_set_digest,
            unreliable_detail,
            aggregate_unreliable,
            base_content_identity,
            policies,
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

/// The snapshots every unit of one lookup batch is attested on, newest first.
///
/// `?1` is a JSON array of unit ids; each id is one seek on the leading column
/// of the snapshot table's primary key.
pub(crate) const POLICY_UNIT_SNAPSHOTS_SQL: &str = "SELECT unit_id, content_identity
     FROM policy_unit_snapshots
     WHERE unit_id IN (SELECT value FROM json_each(?1))
     ORDER BY unit_id, attestation DESC";

/// The evaluation lookup, shared with its query-plan pin.
pub(crate) const POLICY_EVALUATION_LOOKUP_SQL: &str = "SELECT evaluation_id, resolved_commit,
            policy_set_digest, unreliable_detail, aggregate_unreliable, base_content_identity
     FROM policy_evaluations
     WHERE base_tree_oid = ?1 AND options_digest = ?2
       AND configuration_fingerprint = ?3 AND active_model_set_hash = ?4
       AND engine_epoch = ?5";

/// The identity read, shared with its query-plan pin.
///
/// One seek on the leading column of a `WITHOUT ROWID` primary key, which
/// returns the rows already grouped by policy.
pub(crate) const POLICY_EVALUATION_IDENTITY_SQL: &str =
    "SELECT policies.policy_id, policies.source_hash, policies.semantic_hash,
            policies.completion, policies.completion_detail, policies.qualified,
            policies.qualification_detail, policies.diagnostics,
            identities.finding_id
     FROM policy_evaluation_policies AS policies
     LEFT JOIN policy_evaluation_identities AS identities
       ON identities.evaluation_id = policies.evaluation_id
      AND identities.policy_id = policies.policy_id
     WHERE policies.evaluation_id = ?1
     ORDER BY policies.policy_id, identities.finding_id";

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
            let blob_key = super::BlobKey::unvaried(*blob, lang);
            // Resolved under the complete-blob condition the fact tables use:
            // a unit hangs off its seed blob so that re-parsing that blob
            // takes the unit with it.
            let blob_id = conn
                .query_row(
                    &format!(
                        "SELECT meta.blob_id FROM blob_meta AS meta
                         JOIN blobs ON blobs.id = meta.blob_id
                         WHERE blobs.blob_oid = ?1 AND blobs.lang = ?2 AND blobs.parse_variant = ?3
                           AND {PARSED_BLOB_COMPLETE_CONDITION}"
                    ),
                    params![blob_key.oid.to_string(), blob_key.lang, blob_key.variant],
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
           'exhaustive', ?12, jsonb(?13), ?14, ?15
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
    assert!(
        !unit.snapshots.is_empty(),
        "a published unit's index answers hold on the snapshot that computed it"
    );
    insert_unit_snapshots(conn, unit_id, &unit.snapshots)?;
    let mut intern = conn.prepare_cached(
        "INSERT INTO policy_read_keys(
           key_digest, kind, family, languages, rel_path, name, index_key,
           blob_oid, subject, start_byte, end_byte, digest, site_ordinal, decl_kind, decl_signature, workspace_fact_family, fact_member, fact_names
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, jsonb(?18))
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
            columns.site_ordinal,
            columns.decl_kind,
            columns.decl_signature,
            columns.workspace_fact_family,
            columns.fact_member,
            columns.fact_names,
        ])?;
        let read_id = find.query_row(params![columns.key_digest.as_slice()], |row| {
            row.get::<_, i64>(0)
        })?;
        member.execute(params![unit_id, read_id])?;
    }
    Ok(())
}

/// Attest `unit_id` on `snapshots`, then keep only its most recent
/// [`MAX_UNIT_SNAPSHOTS`] attestations.
///
/// Each snapshot takes the unit's next attestation number, including one the
/// unit already held, so the numbers order attestations by recency without a
/// clock that would tie within one run.
fn insert_unit_snapshots(
    conn: &rusqlite::Connection,
    unit_id: i64,
    snapshots: &[[u8; 32]],
) -> rusqlite::Result<()> {
    let mut insert = conn.prepare_cached(
        "INSERT INTO policy_unit_snapshots(unit_id, content_identity, attestation)
         VALUES(?1, ?2, (SELECT coalesce(max(attestation), 0) + 1
                         FROM policy_unit_snapshots WHERE unit_id = ?1))
         ON CONFLICT(unit_id, content_identity) DO UPDATE SET attestation = excluded.attestation",
    )?;
    for snapshot in snapshots {
        insert.execute(params![unit_id, snapshot.as_slice()])?;
    }
    conn.prepare_cached(
        "DELETE FROM policy_unit_snapshots
         WHERE unit_id = ?1 AND attestation < (
           SELECT attestation FROM policy_unit_snapshots WHERE unit_id = ?1
           ORDER BY attestation DESC LIMIT 1 OFFSET ?2
         )",
    )?
    .execute(params![unit_id, MAX_UNIT_SNAPSHOTS as i64 - 1])?;
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
            snapshots: Vec::new(),
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
                keys.start_byte, keys.end_byte, keys.digest, keys.site_ordinal, keys.decl_kind, keys.decl_signature, keys.workspace_fact_family, keys.fact_member, json(keys.fact_names)
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
        CallSiteLocator, IndexFamily, LookupKind, LookupQuestion, ProcedureCallSiteLocator,
        read_set_digest,
    };
    use crate::analyzer::semantic::ids::StableDigest;
    // Every EXPLAIN QUERY PLAN pin below runs its assertions once against a
    // store with no planner statistics and once with the statistics captured
    // from real corpus stores, because production carries the latter (#3016).

    const POLICY_HASH: &str = "aa11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee";
    const CONFIGURATION: &str = "bb11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee";
    const MODELS: &str = "cc11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee";
    const EPOCH: &str = "dd11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee";
    const BLOB: &str = "1111111111111111111111111111111111111111";
    const SUBJECTS: &str = "ee11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee";
    const TREE: &str = "2222222222222222222222222222222222222222";
    const COMMIT: &str = "3333333333333333333333333333333333333333";
    const SNAPSHOT: [u8; 32] = [7; 32];

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
                LookupKind::ResolvedName,
                LookupQuestion::Name {
                    language: Some(Language::Java),
                    name: Box::from("com.example.Main"),
                },
                digest,
            ),
            ReadKey::lookup(
                LookupKind::ResolvedName,
                LookupQuestion::Name {
                    language: None,
                    name: Box::from("com.example.Main"),
                },
                digest,
            ),
            ReadKey::lookup(
                LookupKind::Definitions,
                LookupQuestion::Name {
                    language: Some(Language::Java),
                    name: Box::from("com.example.Main"),
                },
                digest,
            ),
            ReadKey::lookup(
                LookupKind::Definitions,
                LookupQuestion::Name {
                    language: None,
                    name: Box::from("com.example.Main"),
                },
                digest,
            ),
            ReadKey::lookup(
                LookupKind::IdentifierCandidates,
                LookupQuestion::Name {
                    language: Some(Language::Java),
                    name: Box::from("com.example.Main"),
                },
                digest,
            ),
            ReadKey::lookup(
                LookupKind::IdentifierCandidates,
                LookupQuestion::Name {
                    language: None,
                    name: Box::from("com.example.Main"),
                },
                digest,
            ),
            ReadKey::lookup(
                LookupKind::ShortNameCandidates,
                LookupQuestion::Name {
                    language: Some(Language::Java),
                    name: Box::from("com.example.Main"),
                },
                digest,
            ),
            ReadKey::lookup(
                LookupKind::ShortNameCandidates,
                LookupQuestion::Name {
                    language: None,
                    name: Box::from("com.example.Main"),
                },
                digest,
            ),
            ReadKey::lookup(
                LookupKind::DeclarationFacts,
                LookupQuestion::Declaration {
                    rel_path: Box::from("src/Main.java"),
                    fq_name: Box::from("com.example.Main#run"),
                    kind: brokk_bifrost_core::analyzer::model::CodeUnitType::Function,
                    signature: None,
                },
                digest,
            ),
            ReadKey::lookup(
                LookupKind::SignatureMetadata,
                LookupQuestion::Declaration {
                    rel_path: Box::from("src/Main.java"),
                    fq_name: Box::from("com.example.Main#run"),
                    kind: brokk_bifrost_core::analyzer::model::CodeUnitType::Function,
                    signature: Some("run(int)".to_owned()),
                },
                digest,
            ),
            ReadKey::lookup(
                LookupKind::Callers,
                LookupQuestion::Declaration {
                    rel_path: Box::from("src/Main.java"),
                    fq_name: Box::from("com.example.Main#run"),
                    kind: brokk_bifrost_core::analyzer::model::CodeUnitType::Function,
                    signature: None,
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
                LookupKind::ProcedureDispatch,
                LookupQuestion::ProcedureCallSite {
                    rel_path: Box::from("src/Main.java"),
                    procedure: StableDigest::sha256(b"procedure"),
                    site: ProcedureCallSiteLocator {
                        start_byte: 4,
                        end_byte: 18,
                        ordinal: 0,
                    },
                },
                digest,
            ),
            ReadKey::lookup(
                LookupKind::WorkspaceFact,
                LookupQuestion::WorkspaceFact {
                    family: WorkspaceFactFamily::JsTsUsageIndex,
                    language: Language::TypeScript,
                    subject: FactSubject::Whole,
                },
                digest,
            ),
            ReadKey::lookup(
                LookupKind::WorkspaceFact,
                LookupQuestion::WorkspaceFact {
                    family: WorkspaceFactFamily::FieldSlots,
                    language: Language::Python,
                    subject: FactSubject::Class {
                        class: StableDigest::sha256(b"class"),
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
            snapshots: vec![SNAPSHOT],
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
            snapshots: vec![SNAPSHOT],
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

    /// An attestation adds snapshots only to the row it verified: the same
    /// key and read set, already attested on the snapshot it was verified
    /// from. A unit keeps its most recent attestations, and republishing a key
    /// starts its row over with only the snapshots the publication names.
    #[test]
    fn an_attestation_extends_only_the_row_it_verified_and_keeps_the_newest() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let reads = vec![ReadKey::Epoch(StableDigest::sha256(b"epoch"))];
        let unit = unit_row("src/Main.java", reads.clone());
        store.publish_policy_units(vec![unit.clone()]).unwrap();
        let attestation = |verified_on: [u8; 32], snapshots: Vec<[u8; 32]>| PolicyUnitAttestation {
            key: seed_key("src/Main.java"),
            read_set_digest: unit.read_set_digest,
            verified_on,
            snapshots,
        };
        let loaded_snapshots = || {
            let [loaded] = store
                .policy_units_for_keys(&[seed_key("src/Main.java")])
                .unwrap()
                .try_into()
                .expect("one key, one answer");
            let mut snapshots = loaded.expect("the unit is published").snapshots;
            snapshots.sort();
            snapshots
        };

        let attested = store
            .attest_policy_units(vec![
                attestation(SNAPSHOT, vec![[8; 32]]),
                attestation([9; 32], vec![[10; 32]]),
                PolicyUnitAttestation {
                    read_set_digest: [0; 32],
                    ..attestation(SNAPSHOT, vec![[11; 32]])
                },
            ])
            .unwrap();
        assert_eq!(
            attested, 1,
            "only the attestation verified on a held snapshot applies"
        );
        assert_eq!(loaded_snapshots(), vec![SNAPSHOT, [8; 32]]);

        let many = (20..20 + MAX_UNIT_SNAPSHOTS as u8)
            .map(|byte| [byte; 32])
            .collect::<Vec<_>>();
        store
            .attest_policy_units(vec![attestation([8; 32], many.clone())])
            .unwrap();
        let kept = loaded_snapshots();
        assert_eq!(kept.len(), MAX_UNIT_SNAPSHOTS, "{kept:?}");
        assert!(
            many.iter().all(|snapshot| kept.contains(snapshot)),
            "the newest attestations are kept: {kept:?}"
        );

        store.publish_policy_units(vec![unit]).unwrap();
        assert_eq!(loaded_snapshots(), vec![SNAPSHOT]);
    }

    #[test]
    fn a_published_unit_round_trips_with_every_read_key_shape() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let mut reads = every_read_key_shape();
        reads.extend(
            super::super::read_keys::workspace_fact_subjects()
                .into_iter()
                .map(|subject| {
                    ReadKey::lookup(
                        LookupKind::WorkspaceFact,
                        LookupQuestion::WorkspaceFact {
                            family: WorkspaceFactFamily::FieldSlots,
                            language: Language::Python,
                            subject,
                        },
                        StableDigest::sha256(b"answer"),
                    )
                }),
        );
        reads.sort();
        reads.dedup();
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
        let conn = store.conn.lock().unwrap();
        let text_name_group = ReadKey::lookup(
            LookupKind::WorkspaceFact,
            LookupQuestion::WorkspaceFact {
                family: WorkspaceFactFamily::FieldSlots,
                language: Language::Python,
                subject: FactSubject::name_group_member(
                    vec!["pkg.A".into(), "pkg.B".into()],
                    "method".into(),
                ),
            },
            StableDigest::sha256(b"answer"),
        );
        let text_columns = ReadKeyColumns::of(&text_name_group);
        let text_error = conn
            .execute(
                "INSERT INTO policy_read_keys(
                    key_digest,kind,family,languages,rel_path,name,index_key,blob_oid,subject,
                    start_byte,end_byte,digest,site_ordinal,decl_kind,decl_signature,
                    workspace_fact_family,fact_member,fact_names
                 ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
                params![
                    [0u8; 32].as_slice(),
                    text_columns.kind,
                    text_columns.family,
                    text_columns.languages,
                    text_columns.rel_path,
                    text_columns.name,
                    text_columns.index_key,
                    text_columns.blob_oid,
                    text_columns.subject,
                    text_columns.start_byte,
                    text_columns.end_byte,
                    text_columns.digest,
                    text_columns.site_ordinal,
                    text_columns.decl_kind,
                    text_columns.decl_signature,
                    text_columns.workspace_fact_family,
                    text_columns.fact_member,
                    text_columns.fact_names,
                ],
            )
            .expect_err("the STRICT BLOB column rejects TEXT fact_names");
        assert!(
            text_error
                .to_string()
                .contains("cannot store TEXT value in BLOB column"),
            "{text_error}"
        );
        conn.execute("UPDATE policy_read_keys SET workspace_fact_family = 'unregistered' WHERE family = 'workspace_fact'", []).unwrap();
        let unit_id = conn
            .query_row("SELECT unit_id FROM policy_units", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap();
        assert!(load_unit_reads(&conn, unit_id).unwrap_err().is_corrupt());
    }

    #[test]
    #[hardwon("#5113: policy replay mixed traversal and resident census in one persisted total")]
    fn policy_budget_replay_numbers_are_sql_readable_jsonb() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let accounting = crate::analyzer::semantic::SemanticBudgetReplay {
            cumulative: crate::analyzer::semantic::SemanticWork {
                events: 21,
                ..Default::default()
            },
            performed: crate::analyzer::semantic::SemanticWork {
                events: 15,
                ..Default::default()
            },
            root_work_peak: crate::analyzer::semantic::SemanticWork {
                events: 8,
                ..Default::default()
            },
            retained: crate::analyzer::semantic::SemanticWork {
                events: 6,
                ..Default::default()
            },
        };
        let mut unit = unit_row("src/Main.java", vec![]);
        unit.product = serde_json::json!({"semantic": accounting}).to_string();
        store.publish_policy_units(vec![unit]).unwrap();
        let conn = store.conn.lock().expect("store mutex");
        let observed: (String, i64, i64, i64) = conn.query_row(
            "SELECT typeof(product), json_extract(product, '$.semantic.cumulative.events'), json_extract(product, '$.semantic.root_work_peak.events'), json_extract(product, '$.semantic.retained.events') FROM policy_units", [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).unwrap();
        assert_eq!(observed, ("blob".into(), 21, 8, 6));
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
            .query_row("SELECT json(product) FROM policy_units", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(product, "{\"rows\":[1]}");
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
            options_digest: CONFIGURATION.to_string(),
            configuration_fingerprint: CONFIGURATION.to_string(),
            active_model_set_hash: MODELS.to_string(),
            engine_epoch: EPOCH.to_string(),
        }
    }

    fn finding_id(seed: &str) -> [u8; 32] {
        *StableDigest::sha256(seed.as_bytes()).as_bytes()
    }

    fn policy_result(policy_id: &str, findings: &[&str]) -> PolicyEvaluationPolicyRow {
        PolicyEvaluationPolicyRow {
            policy_id: policy_id.to_string(),
            source_hash: POLICY_HASH.to_string(),
            semantic_hash: POLICY_HASH.to_string(),
            completion: "complete".to_string(),
            completion_detail: "\"complete\"".to_string(),
            qualified: true,
            qualification_detail: String::new(),
            diagnostics: Vec::new(),
            identities: findings.iter().map(|seed| finding_id(seed)).collect(),
            units: Vec::new(),
        }
    }

    use brokk_bifrost_test_macros::hardwon;

    #[hardwon("#2586: a complete empty policy is distinct from missing evidence")]
    #[test]
    fn a_complete_empty_policy_is_distinct_from_missing_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("policy-cache.db");
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        let key = evaluation_key();
        store
            .publish_policy_evaluation(PolicyEvaluationRow {
                key: key.clone(),
                resolved_commit: COMMIT.to_string(),
                policy_set_digest: POLICY_HASH.to_string(),
                unreliable_detail: None,
                aggregate_unreliable: false,
                base_content_identity: SNAPSHOT,
                policies: vec![policy_result("test.clean", &[])],
                unqualified_policy_ids: Vec::new(),
            })
            .unwrap();
        drop(store);

        let store = AnalyzerStore::open_persistent(&path).unwrap();
        let loaded = store
            .policy_evaluation_for_key(&key)
            .unwrap()
            .expect("the shared evaluation exists");
        assert_eq!(loaded.policies.len(), 1);
        assert_eq!(loaded.policies[0].policy_id, "test.clean");
        assert_eq!(loaded.policies[0].completion, "complete");
        assert!(loaded.policies[0].qualified);
        assert!(loaded.policies[0].identities.is_empty());

        for different_question in [
            PolicyEvaluationRowKey {
                base_tree_oid: "other-tree".to_string(),
                ..key.clone()
            },
            PolicyEvaluationRowKey {
                options_digest: "other-options-and-limits".to_string(),
                ..key.clone()
            },
            PolicyEvaluationRowKey {
                configuration_fingerprint: "other-configuration".to_string(),
                ..key.clone()
            },
            PolicyEvaluationRowKey {
                active_model_set_hash: "other-models".to_string(),
                ..key.clone()
            },
            PolicyEvaluationRowKey {
                engine_epoch: "other-epoch".to_string(),
                ..key.clone()
            },
        ] {
            assert!(
                store
                    .policy_evaluation_for_key(&different_question)
                    .unwrap()
                    .is_none(),
                "a complete empty answer must not cross shared input keys: {different_question:?}"
            );
        }
    }

    #[test]
    fn an_evaluation_whose_unit_is_missing_still_records_its_identities() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let key = evaluation_key();
        store
            .publish_policy_evaluation(PolicyEvaluationRow {
                key: key.clone(),
                resolved_commit: COMMIT.to_string(),
                policy_set_digest: POLICY_HASH.to_string(),
                unreliable_detail: None,
                aggregate_unreliable: false,
                base_content_identity: SNAPSHOT,
                policies: vec![PolicyEvaluationPolicyRow {
                    units: vec![seed_key("src/Gone.java")],
                    ..policy_result("test.policy", &["only"])
                }],
                unqualified_policy_ids: Vec::new(),
            })
            .unwrap();

        let loaded = store
            .policy_evaluation_for_key(&key)
            .unwrap()
            .expect("an evaluation is its identities, not its units");
        assert_eq!(loaded.policies[0].identities, vec![finding_id("only")]);
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

    #[hardwon("#2586: an evaluation replaces only republished policy evidence")]
    #[test]
    fn an_evaluation_replaces_only_republished_policy_evidence() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let key = evaluation_key();
        let (first, second) = ("first", "second");
        store
            .publish_policy_evaluation(PolicyEvaluationRow {
                key: key.clone(),
                resolved_commit: COMMIT.to_string(),
                policy_set_digest: POLICY_HASH.to_string(),
                unreliable_detail: None,
                aggregate_unreliable: false,
                base_content_identity: SNAPSHOT,
                policies: vec![
                    policy_result("test.policy", &[first]),
                    policy_result("test.other", &["other"]),
                ],
                unqualified_policy_ids: Vec::new(),
            })
            .unwrap();
        store
            .publish_policy_evaluation(PolicyEvaluationRow {
                key: key.clone(),
                resolved_commit: COMMIT.to_string(),
                policy_set_digest: POLICY_HASH.to_string(),
                unreliable_detail: None,
                aggregate_unreliable: false,
                base_content_identity: SNAPSHOT,
                policies: vec![policy_result("test.policy", &[second])],
                unqualified_policy_ids: Vec::new(),
            })
            .unwrap();
        let loaded = store
            .policy_evaluation_for_key(&key)
            .unwrap()
            .expect("the evaluation is found by its key");
        assert_eq!(
            loaded
                .policies
                .iter()
                .map(|policy| policy.policy_id.as_str())
                .collect::<Vec<_>>(),
            vec!["test.other", "test.policy"],
            "updating one child leaves the other policy's evidence intact"
        );
        assert_eq!(loaded.policies[0].identities, vec![finding_id("other")]);
        assert_eq!(loaded.policies[1].identities, vec![finding_id("second")]);
        let conn = store.conn.lock().expect("store mutex");
        let rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM policy_evaluation_identities",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rows, 2);
    }

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
            snapshots: vec![SNAPSHOT],
        };

        store
            .publish_policy_units(vec![mismatched])
            .expect_err("a file's findings are an assert's product, not a query's");
    }
}
