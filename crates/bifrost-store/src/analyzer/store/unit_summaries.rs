//! The shared per-unit resolution summary: one writer and one reconcile driver
//! for every language, and the one validity predicate the writer and every
//! reader use (derivation contract, kind 2; see
//! `.agents/docs/architecture-and-analyzer-store.md`).
//!
//! A language supplies its unit definition and its derivation through
//! [`UnitSummaryLanguage`]. The driver owns the algorithm: it orders the units
//! bottom-up, computes each unit's `lookup_digest` from its own inputs and from
//! the output digests of its direct dependencies, reuses a summary under that
//! digest whose recorded consumed units still have the output digests it saw
//! (`summary_valid_now`), derives and publishes the rest one transaction per
//! unit, and closes the version rows it did not rebind. A derived summary's
//! unique `summary_digest` covers the lookup digest and the consumed set the
//! derivation and its language rows recorded ([`ForeignReader`]).
//!
//! Unit of work: one unit. Retained after the call: rows in SQLite only. The
//! ordering of units lives in session temp tables that the driver empties before
//! it returns, and the only Rust heap structure is the rows of the unit being
//! published, dropped with its transaction.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use super::{AnalyzerStore, Result, StoreError, WorkspaceSnapshotId};
use crate::CancellationToken;
use brokk_bifrost_core::analyzer::canonical_hash::{CanonicalHasher, lower_hex_string};

/// Role of a non-member file consulted by a unit summary.
#[derive(Clone, Copy, Debug)]
pub enum UnitSummaryInputRole {
    InactiveSource,
    OwnManifest,
    WorkspaceManifest,
    CargoConfig,
}

impl UnitSummaryInputRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InactiveSource => "inactive_source",
            Self::OwnManifest => "own_manifest",
            Self::WorkspaceManifest => "workspace_manifest",
            Self::CargoConfig => "cargo_config",
        }
    }
}

/// A non-member file a unit consulted, with the value its key hashed.
#[doc(hidden)]
pub struct UnitInputFile {
    pub role: UnitSummaryInputRole,
    pub rel_path: String,
    pub value: InputFileValue,
}

/// What a unit knows of one input file. The three cases hash under distinct
/// tags, so an empty fingerprint set, a file without admitted facts and a path
/// with no file in the selected revision never share a key.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputFileValue {
    /// The blob has a current-list surface set; this is its fingerprint.
    Fingerprint([u8; 32]),
    /// The blob has no admitted facts; this is the selected blob's OID.
    NoFactsOid(String),
    /// The selected revision has no file at the path.
    Absent,
}

/// One file of a unit: the unit's own input.
#[doc(hidden)]
pub struct UnitMember {
    pub blob_id: i64,
    pub blob_oid: String,
    pub rel_path: String,
    pub source_role: String,
}

/// A recorded input that is neither a member nor a child summary.
#[doc(hidden)]
pub struct UnitRead {
    pub kind: &'static str,
    pub key_digest: [u8; 32],
    pub digest: [u8; 32],
}

/// A unit this one consumes. A workspace dependency that is itself a unit names
/// its `unit_id` so the driver can look up the child's live summary; an external
/// or standard-library dependency names the digest of the provenance it saw.
#[doc(hidden)]
pub struct UnitDependency {
    pub unit_key: [u8; 32],
    pub unit_id: Option<i64>,
    pub label: String,
    pub boundary: &'static str,
    pub provenance: Option<String>,
    pub external_digest: Option<[u8; 32]>,
}

#[doc(hidden)]
pub struct UnitInputs {
    pub unit_id: i64,
    pub unit_key: [u8; 32],
    pub label: String,
    pub members: Vec<UnitMember>,
    /// Non-member files the key covers, in `input_ordinal` order. Go and Python
    /// declare none.
    pub input_files: Vec<UnitInputFile>,
    pub reads: Vec<UnitRead>,
    pub dependencies: Vec<UnitDependency>,
    pub dependency_names: Vec<UnitDependencyName>,
    pub containers: Vec<UnitContainer>,
    pub placements: Vec<UnitPlacement>,
}

/// Language spelling is independent of consumption: several names can bind one unit.
#[derive(Debug)]
#[doc(hidden)]
pub struct UnitDependencyName {
    pub role: String,
    pub name: String,
    pub unit_key: Option<[u8; 32]>,
}

#[doc(hidden)]
pub struct UnitContainer {
    pub path: String,
    pub parent_path: Option<String>,
}

#[doc(hidden)]
pub struct UnitPlacement {
    pub container_path: String,
    pub member_ordinal: usize,
    pub scope_ordinal: Option<UnitCoordinate>,
}

pub(crate) fn member_ordinals(
    members: &[UnitMember],
) -> std::collections::HashMap<(i64, &str, &str), usize> {
    members
        .iter()
        .enumerate()
        .map(|(ordinal, member)| {
            (
                (
                    member.blob_id,
                    member.rel_path.as_str(),
                    member.source_role.as_str(),
                ),
                ordinal,
            )
        })
        .collect()
}

pub(crate) fn dependency_ordinals(
    dependencies: &[ConsumedDependency],
) -> std::collections::HashMap<[u8; 32], usize> {
    dependencies
        .iter()
        .map(|dependency| (dependency.unit_key, dependency.ordinal))
        .collect()
}

/// A name-only consumer requires its selected dependency roles to agree on
/// the target of each name. The complete role/name rows remain independent.
pub(crate) fn dependency_keys_by_name(
    unit: &UnitInputs,
) -> std::collections::HashMap<String, [u8; 32]> {
    let mut keys = std::collections::HashMap::new();
    for binding in &unit.dependency_names {
        if let Some(key) = binding.unit_key
            && let Some(previous) = keys.insert(binding.name.clone(), key)
        {
            assert_eq!(
                previous, key,
                "{}: conflicting role/name bindings: {:?}",
                unit.label, unit.dependency_names
            );
        }
    }
    keys
}

/// One dependency as the derivation consumed it. `available` is false for a
/// workspace dependency that had no live summary at this pass; the digest is then
/// a marker that differs from every real output digest, so a dependent derived
/// without it is derived again when the dependency appears.
#[derive(Debug)]
#[doc(hidden)]
pub struct ConsumedDependency {
    pub ordinal: usize,
    pub unit_key: [u8; 32],
    pub label: String,
    pub consumed_output_digest: [u8; 32],
    pub boundary: &'static str,
    pub available: bool,
}

/// Why a derivation read a unit beyond its direct dependencies. Diagnostics and
/// tests only: validation compares the recorded output digest and does not
/// read the kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[doc(hidden)]
pub enum ReadKind {
    ReexportHop,
    ModuleHop,
    Endpoint,
    Absence,
    ClosureBindings,
    TraitEndpoint,
}

/// A unit a derivation consumed beyond its direct dependencies, with the output
/// digest it had when read. `summary_id` is provenance: `None` when the unit had
/// no settled live summary, and then the digest is the unavailable marker.
#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct ConsumedUnit {
    pub unit_key: [u8; 32],
    pub output_digest: [u8; 32],
    pub summary_id: Option<i64>,
    pub kinds: std::collections::BTreeSet<ReadKind>,
}

/// What one derivation read from units outside its own inputs and direct
/// dependencies. `derive` records into it; the driver stores the set with the
/// summary and hashes it into the summary's identity.
#[derive(Debug, Default)]
#[doc(hidden)]
pub struct ConsumedReads(std::collections::HashMap<[u8; 32], ConsumedUnit>);

impl ConsumedReads {
    /// Record one read of `unit_key`. A unit read more than once in one
    /// derivation keeps every kind and must have the same digest each time.
    pub fn record(
        &mut self,
        unit_key: [u8; 32],
        output_digest: [u8; 32],
        summary_id: Option<i64>,
        kind: ReadKind,
    ) {
        let unit = self.0.entry(unit_key).or_insert_with(|| ConsumedUnit {
            unit_key,
            output_digest,
            summary_id,
            kinds: Default::default(),
        });
        assert_eq!(
            (unit.output_digest, unit.summary_id),
            (output_digest, summary_id),
            "one derivation read unit {} at two different outputs",
            lower_hex_string(&unit_key)
        );
        unit.kinds.insert(kind);
    }

    /// The recorded set in unit key order, which is the order the identity
    /// digest and the stored rows use.
    fn sorted(&self) -> Vec<ConsumedUnit> {
        let mut units: Vec<_> = self.0.values().cloned().collect();
        units.sort_unstable_by_key(|unit| unit.unit_key);
        units
    }
}

/// Explicit coordinate space at the derivation/writer boundary. M3 removes
/// Dense when Rust joins Go and Python in deriving from surface views.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum UnitCoordinate {
    Surface(i64),
    Dense(i64),
}
impl UnitCoordinate {
    fn assert_language(self, language: &str) {
        assert_eq!(matches!(self, Self::Dense(_)), language == "rust");
    }
    fn value(self) -> i64 {
        match self {
            Self::Surface(value) | Self::Dense(value) => value,
        }
    }
}

/// The one way a derivation reads another unit's rows (#11173 D1): the settled
/// check and the live summary lookup of `consume_dependencies`, for a unit that
/// is not necessarily a direct dependency. `None` means the unit is unavailable:
/// it has not settled in this pass, so a row it has from an earlier revision has
/// not been checked against this revision's inputs, or it has no live summary.
pub(crate) fn consume_unit(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
    language: &dyn UnitSummaryLanguage,
    producer_epoch: &str,
    unit_key: &[u8; 32],
) -> Result<Option<(i64, [u8; 32])>> {
    let settled: bool = conn
        .prepare_cached(SETTLED_KEY_SQL)?
        .query_row([unit_key.as_slice()], |row| row.get(0))?;
    if !settled {
        return Ok(None);
    }
    language
        .live_summary(conn, snapshot, producer_epoch, unit_key)?
        .map(|(summary_id, output)| Ok((summary_id, digest_from_row(output)?)))
        .transpose()
}

/// What a derivation reads of other units, and the recorder of it. `derive` and
/// `write_language_rows` reach another unit's rows only through [`Self::consume`],
/// so every foreign unit read is settled, live and recorded, whether the read
/// found something or nothing. The driver stores the recorded set with the summary
/// and hashes it into the summary's identity.
#[doc(hidden)]
pub struct ForeignReader<'a> {
    conn: &'a Connection,
    snapshot: &'a WorkspaceSnapshotId,
    language: &'a dyn UnitSummaryLanguage,
    producer_epoch: &'a str,
    /// The consuming unit, for the scheduling notes of its reads.
    unit_id: i64,
    /// Direct dependencies are recorded in the dependencies table and the lookup
    /// digest, not in the consumed set.
    direct: std::collections::HashSet<[u8; 32]>,
    /// One answer per unit for the whole derivation and publication.
    memo: std::collections::HashMap<[u8; 32], Option<(i64, [u8; 32])>>,
    /// Units that had no live summary at all when first read, settled or not.
    absent: std::collections::HashSet<[u8; 32]>,
    reads: ConsumedReads,
    /// (unit key, unavailable) of every first read of a non-direct unit. Held
    /// here, not written when read, so that undoing a publication attempt cannot
    /// drop them; the driver writes them once the attempt is resolved.
    scheduling: Vec<([u8; 32], bool)>,
}

impl<'a> ForeignReader<'a> {
    fn new(
        conn: &'a Connection,
        snapshot: &'a WorkspaceSnapshotId,
        language: &'a dyn UnitSummaryLanguage,
        producer_epoch: &'a str,
        unit_id: i64,
        dependencies: &[ConsumedDependency],
    ) -> Self {
        Self {
            conn,
            snapshot,
            language,
            producer_epoch,
            unit_id,
            direct: dependencies.iter().map(|d| d.unit_key).collect(),
            memo: Default::default(),
            absent: Default::default(),
            reads: ConsumedReads::default(),
            scheduling: Vec::new(),
        }
    }

    /// Make this unit a dependent of every unit it read, for the rest of the
    /// request: a read that succeeded is stale when that unit's output moves in a
    /// later fixpoint round, and one that failed is retried when the unit settles.
    fn flush_scheduling(&mut self) -> Result<()> {
        for (unit_key, unavailable) in self.scheduling.drain(..) {
            self.conn.prepare_cached(NOTE_READ_SQL)?.execute(params![
                self.unit_id,
                unit_key.as_slice(),
                unavailable
            ])?;
        }
        Ok(())
    }

    /// Consume `unit_key` for a read of `kind` and return its live summary id,
    /// or `None` when the unit is unavailable, in which case the caller reads
    /// nothing of it. A unit that is not a direct dependency is recorded either
    /// way: with its output digest, or with the unavailable marker. Either way
    /// this unit is scheduled again when that unit's output moves or it settles.
    pub fn consume(&mut self, unit_key: [u8; 32], kind: ReadKind) -> Result<Option<i64>> {
        let consumed = self.fetch(unit_key)?;
        self.note(unit_key, kind);
        Ok(consumed)
    }

    /// The first half of [`Self::consume`], for a read whose kind depends on what
    /// the unit's rows say: the live summary id of `unit_key`, or `None` when it
    /// is unavailable. The caller must [`Self::note`] the read before it returns.
    pub fn fetch(&mut self, unit_key: [u8; 32]) -> Result<Option<i64>> {
        let consumed = match self.memo.get(&unit_key) {
            Some(consumed) => *consumed,
            None => {
                let consumed = consume_unit(
                    self.conn,
                    self.snapshot,
                    self.language,
                    self.producer_epoch,
                    &unit_key,
                )?;
                self.memo.insert(unit_key, consumed);
                if consumed.is_none()
                    && self
                        .language
                        .live_summary(self.conn, self.snapshot, self.producer_epoch, &unit_key)?
                        .is_none()
                {
                    self.absent.insert(unit_key);
                }
                if !self.direct.contains(&unit_key) {
                    self.scheduling.push((unit_key, consumed.is_none()));
                }
                consumed
            }
        };
        Ok(consumed.map(|(summary_id, _)| summary_id))
    }

    /// Record that `unit_key`, already fetched, was read for `kind`.
    pub fn note(&mut self, unit_key: [u8; 32], kind: ReadKind) {
        let consumed = *self
            .memo
            .get(&unit_key)
            .expect("a unit is fetched before its read is noted");
        if !self.direct.contains(&unit_key) {
            let (summary_id, output_digest) = match consumed {
                Some((summary_id, output_digest)) => (Some(summary_id), output_digest),
                // A unit with no live summary is recorded as absent, which stays
                // valid while it does; one that exists but had not settled gets
                // the unavailable marker, which never validates again.
                None if self.absent.contains(&unit_key) => (None, ABSENT_DIGEST),
                None => (None, unavailable_digest(&unit_key)),
            };
            self.reads.record(unit_key, output_digest, summary_id, kind);
        }
    }

    /// Record a read whose answer the caller already holds.
    pub fn record(
        &mut self,
        unit_key: [u8; 32],
        output_digest: [u8; 32],
        summary_id: Option<i64>,
        kind: ReadKind,
    ) {
        self.reads.record(unit_key, output_digest, summary_id, kind);
    }

    /// The recorded set so far, in unit key order.
    pub fn consumed(&self) -> Vec<ConsumedUnit> {
        self.reads.sorted()
    }
}

#[doc(hidden)]
pub struct UnitExport {
    pub identity_id: i64,
    pub identity_digest: [u8; 32],
    pub namespace: String,
    pub visibility: &'static str,
    pub origin: &'static str,
    pub alias_dependency_ordinal: Option<usize>,
    pub alias_identity_id: Option<i64>,
    /// Stable semantic content for `alias_identity_id`; row ids are store-local.
    pub alias_identity_digest: Option<[u8; 32]>,
    // Ownership cannot be inferred from content-addressed blob identity.
    pub declaration_unit_key: [u8; 32],
    pub declaration_blob_id: i64,
    pub declaration_site: UnitCoordinate,
    pub declaration_key: UnitCoordinate,
}

#[doc(hidden)]
pub struct UnitImport {
    pub blob_id: i64,
    /// The blob's `source_imports.import_id`.
    pub import_id: UnitCoordinate,
    /// `named`, `blank` or `dot`.
    pub kind: &'static str,
    /// The blob-local import binding key; absent for a dot import.
    pub definition_key: Option<UnitCoordinate>,
    pub spelling: String,
    pub dependency_ordinal: Option<usize>,
    pub state: &'static str,
}

#[doc(hidden)]
pub struct UnitGap {
    pub kind: &'static str,
    pub subject: String,
    /// A JSON document, stored as JSONB.
    pub detail: String,
}

#[doc(hidden)]
pub struct UnitOutputs {
    pub exports: Vec<UnitExport>,
    pub imports: Vec<UnitImport>,
    pub gaps: Vec<UnitGap>,
    pub complete: bool,
    /// Language output read by dependents, including any dependency-visible
    /// provenance relations; `None` keeps the encoding.
    pub public_surface_digest: Option<[u8; 32]>,
}

/// What a language supplies. Every method runs on the store's writer
/// connection, inside one reconcile.
#[doc(hidden)]
pub trait UnitSummaryLanguage {
    fn lang(&self) -> &'static str;
    fn unit_kind(&self) -> &'static str;
    fn derivation_identity(&self) -> [u8; 32];

    /// Context selection whose revision intervals this pass may change.
    /// Languages with one profile use the schema's singleton zero digest.
    fn profile_digest(&self) -> [u8; 32] {
        [0; 32]
    }

    /// Rounds of re-derivation after the ordered pass. Tests of the limit lower it;
    /// a language does not raise it.
    fn fixpoint_rounds(&self) -> i64 {
        FIXPOINT_ROUNDS
    }

    /// Fill `temp.unit_summary_work` with one row per unit and
    /// `temp.unit_summary_edges` with one row per consumed workspace unit. Both
    /// hold language-assigned integer unit ids; an edge must name two units of
    /// the work table.
    fn stage(&self, conn: &Connection, snapshot: &WorkspaceSnapshotId) -> Result<()>;

    /// Clear language-owned TEMP rows before this query-scoped reconcile
    /// returns. The default is enough for adapters that stage directly into
    /// the shared work and edge tables.
    fn clear_stage(&self, _conn: &Connection) -> Result<()> {
        Ok(())
    }

    fn inputs(
        &self,
        conn: &Connection,
        snapshot: &WorkspaceSnapshotId,
        unit_id: i64,
    ) -> Result<UnitInputs>;

    /// The live summary of one unit under this language's validity predicate:
    /// its summary id and output digest. The default is the shared predicate;
    /// a language that keeps more than one live profile adds the profile match.
    fn live_summary(
        &self,
        conn: &Connection,
        snapshot: &WorkspaceSnapshotId,
        producer_epoch: &str,
        unit_key: &[u8; 32],
    ) -> Result<Option<(i64, Vec<u8>)>> {
        Ok(conn
            .prepare_cached(LIVE_SUMMARY_SQL)?
            .query_row(
                params![
                    snapshot.workspace_id.as_str(),
                    self.lang(),
                    snapshot.generation.get(),
                    unit_key.as_slice(),
                    snapshot.revision,
                    producer_epoch,
                    self.derivation_identity()
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    }

    fn derive(
        &self,
        conn: &Connection,
        snapshot: &WorkspaceSnapshotId,
        unit: &UnitInputs,
        dependencies: &[ConsumedDependency],
        producer_epoch: &str,
        reader: &mut ForeignReader<'_>,
    ) -> Result<UnitOutputs>;

    /// Publish language-specific rows that are children of this shared
    /// summary. The default is appropriate for languages whose complete
    /// surface is already represented by the shared rows. A read of another
    /// unit goes through `reader`, as in `derive`: the identity digest is
    /// sealed after these rows are written.
    fn write_language_rows(
        &self,
        _conn: &Connection,
        _snapshot: &WorkspaceSnapshotId,
        _unit: &UnitInputs,
        _dependencies: &[ConsumedDependency],
        _summary_id: i64,
        _reader: &mut ForeignReader<'_>,
    ) -> Result<usize> {
        Ok(0)
    }

    /// A digest of the language child rows that another unit's derivation or a
    /// foreign reader reads, taken after [`Self::write_language_rows`] has written
    /// them. It is hashed into the unit's output digest, which is what a consumer
    /// validates its recorded reads against, so a child column that a foreign reader
    /// reads must be covered here. Only name-level values may be hashed, and no
    /// dense coordinate (an ordinal, a scope, an import or a site id), or an edit
    /// that moves coordinates would move the output and defeat early cutoff.
    /// `None` is for a language whose foreign readers read only the shared rows.
    fn output_supplement(&self, _conn: &Connection, _summary_id: i64) -> Result<Option<[u8; 32]>> {
        Ok(None)
    }

    /// Publish revision-specific language context alongside the shared
    /// version row. The default is appropriate when the language has none.
    fn write_language_version(
        &self,
        _conn: &Connection,
        _snapshot: &WorkspaceSnapshotId,
        _unit: &UnitInputs,
        _summary_id: i64,
    ) -> Result<usize> {
        Ok(0)
    }
}

/// What one reconcile pass did, for profiling and for the caller to report.
#[derive(Debug, Default, PartialEq, Eq)]
#[doc(hidden)]
pub struct UnitSummaryReconciliation {
    pub units: usize,
    /// Units whose live version row already pointed at the digest's summary.
    pub unchanged: usize,
    /// Units rebound to an existing summary, without derivation.
    pub rebound_count: usize,
    /// The pass's net effect on live units, as (language, unit key): for each
    /// unit the pass published or closed, its live output before the pass
    /// compared with its live output after it, so a unit that a fixpoint round
    /// republished several times, or published back to its original output,
    /// is reported once or not at all. Units the pass left alone cost nothing.
    /// Units live both before and after the pass whose output digest differs.
    pub output_changed: Vec<(String, [u8; 32])>,
    /// Units live after the pass and not before it.
    pub added: Vec<(String, [u8; 32])>,
    /// Units live before the pass and not after it.
    pub closed: Vec<(String, [u8; 32])>,
    /// The live output before the pass of every unit the pass published or
    /// closed, by unit key, until the pass classifies them.
    pub(crate) touched: std::collections::HashMap<[u8; 32], Option<Vec<u8>>>,
    pub derived: usize,
    /// Rows written by derived units (header, children and version rows).
    pub rows_written: usize,
    /// Output digest changes among derived units that already had a live summary.
    pub output_changes: usize,
    pub closed_versions: usize,
    /// Fixpoint rounds that derived units again, and the units the round limit
    /// stranded: those still queued after the last round and every unit that
    /// consumes one, transitively. They are unsettled, so their version rows are
    /// closed with the pass and readers see them as unavailable, and each is also
    /// listed in `failed`. Zero when the pass settled.
    pub fixpoint_rounds: usize,
    pub fixpoint_unsettled: usize,
    /// Units whose summary a fixpoint round replaced or rebound.
    pub rederived: usize,
    /// Units whose derivation failed and so publish nothing, with the error.
    pub failed: Vec<(String, String)>,
    pub cancelled: bool,
    /// Wall time of the whole pass: the time the writer job holds the writer.
    pub elapsed: Duration,
    /// Time inside unit transactions, in total and for the longest one: the
    /// time another process's writer can be held off.
    pub transaction_total: Duration,
    pub transaction_max: Duration,
    /// The most rows one derived unit wrote.
    pub max_unit_rows: usize,
    /// Statements the writer connection ran for the pass and for the busiest
    /// unit. Counted only when the store carries a statement counter, which is
    /// test and measurement builds; zero otherwise.
    pub statements: usize,
    pub max_unit_statements: usize,
}

/// The select the validity predicate is written in, once. A version row open at
/// the selected revision, a complete summary, and the active producer epoch and
/// derivation version, within the selected profile. The language supplies the
/// profile expression. Go and Python append `members_current_sql` (every member's
/// recorded input still equals its selected blob's), so a summary derived against
/// an older surface is not live; Rust records no member input. The writer and
/// every reader of a language use that one statement.
macro_rules! live_summary_select {
    ($profile:literal) => {
        $crate::analyzer::store::unit_summaries::live_summary_select!($profile, "?4")
    };
    ($profile:literal, $unit:literal) => {
        concat!("SELECT versions.summary_id, summaries.output_digest
     FROM resolution_unit_summary_versions AS versions
     JOIN resolution_unit_summaries AS summaries ON summaries.summary_id = versions.summary_id
     WHERE versions.workspace_id = ?1 AND versions.lang = ?2 AND versions.generation = ?3
       AND versions.unit_key = ", $unit, " AND versions.profile_digest = ", $profile, "
       AND versions.valid_from <= ?5 AND (versions.valid_until IS NULL OR ?5 < versions.valid_until)
       AND summaries.publication_state = 'complete'
       AND summaries.producer_epoch = ?6 AND summaries.derivation_identity = ?7")
    };
}
pub(crate) use live_summary_select;

/// The child's live summary for a language with one live profile. Go uses
/// `GO_LIVE_SUMMARY_SQL`, which adds the profile read.
pub(crate) const LIVE_SUMMARY_SQL: &str = live_summary_select!("zeroblob(32)");

/// One name in one unit's export relation: the point reader's statement.
#[cfg(any(test, feature = "test-support"))]
pub(crate) const UNIT_EXPORT_POINT_SQL: &str =
    "SELECT declaration.blob_id, site.site, declaration_key.dense_id, exports.visibility
     FROM main.resolution_unit_summary_exports AS exports
     CROSS JOIN main.resolution_unit_summary_members AS members
       ON members.summary_id = exports.summary_id
      AND members.member_ordinal = exports.declaration_member_ordinal
     CROSS JOIN temp.selected_unit_member_blobs AS declaration
       ON declaration.summary_id = members.summary_id
      AND declaration.member_ordinal = members.member_ordinal
     CROSS JOIN temp.surface_dense AS dense
       ON dense.blob_id = declaration.blob_id
      AND dense.id_space = 0
      AND dense.surface_ordinal = exports.site_surface_ordinal
     CROSS JOIN main.resolution_sites AS site
       ON site.blob_id = declaration.blob_id AND site.site = dense.dense_id
     CROSS JOIN temp.surface_dense AS declaration_key
       ON declaration_key.blob_id = declaration.blob_id
      AND declaration_key.id_space = 1
      AND declaration_key.surface_ordinal = exports.declaration_surface_ordinal
     WHERE exports.summary_id = ?1 AND exports.namespace = ?2 AND exports.identity_id = ?3
       AND exports.target_kind = 'own'";

/// The live units that consume one unit: the dependents the reconcile adds to
/// its work list when an output digest moved, and the reverse reader's unit
/// candidates. `CROSS JOIN` fixes the join order: without planner statistics
/// SQLite otherwise walks every version row of the workspace and probes the
/// dependency rows from each, which scales with units times revisions instead
/// of with the dependents of one unit.
#[cfg(any(test, feature = "test-support"))]
pub(crate) const UNIT_DEPENDENTS_SQL: &str = "SELECT versions.unit_key
     FROM resolution_unit_summary_dependencies AS dependencies
     CROSS JOIN resolution_unit_summary_versions AS versions ON versions.summary_id = dependencies.summary_id
     WHERE dependencies.dependency_unit_key = ?1 AND versions.workspace_id = ?2
       AND versions.lang = ?3 AND versions.generation = ?4 AND versions.profile_digest = ?5
       AND versions.valid_until IS NULL";

/// The graph stage's join: each member's root-reaching reference paths against
/// the unit's own export relation. `CROSS JOIN` fixes the order members, paths,
/// exports, so the work is one export probe per root-reaching path; the planner's
/// own choice without statistics probes the paths index once per member and
/// export instead.
#[cfg(any(test, feature = "test-support"))]
pub(crate) const UNIT_GRAPH_JOIN_SQL: &str =
    "SELECT member_blobs.blob_id, paths.path, declaration.blob_id, site.site
     FROM resolution_unit_summary_members AS members
     CROSS JOIN temp.selected_unit_member_blobs AS member_blobs
       ON member_blobs.summary_id = members.summary_id
      AND member_blobs.member_ordinal = members.member_ordinal
     CROSS JOIN resolution_paths AS paths INDEXED BY resolution_paths_root_terminal
       ON paths.blob_id = member_blobs.blob_id AND paths.root_terminal IS NOT NULL
     CROSS JOIN resolution_unit_summary_exports AS exports
       ON exports.summary_id = members.summary_id
      AND exports.identity_id = paths.root_terminal AND exports.target_kind = 'own'
     CROSS JOIN main.resolution_unit_summary_members AS declaration_member
       ON declaration_member.summary_id = exports.summary_id
      AND declaration_member.member_ordinal = exports.declaration_member_ordinal
     CROSS JOIN temp.selected_unit_member_blobs AS declaration
       ON declaration.summary_id = declaration_member.summary_id
      AND declaration.member_ordinal = declaration_member.member_ordinal
     CROSS JOIN temp.surface_dense AS dense
       ON dense.blob_id = declaration.blob_id
      AND dense.id_space = 0
      AND dense.surface_ordinal = exports.site_surface_ordinal
     CROSS JOIN main.resolution_sites AS site
       ON site.blob_id = declaration.blob_id AND site.site = dense.dense_id
     WHERE members.summary_id = ?1";

/// Persist-path hook for a replaced Rust blob. Rust summaries still retain
/// derived-from blob IDs, so replacement cascades their children away and must
/// withdraw every version, including historical versions, before deleting facts.
/// Go and Python members carry NULL: their keys track surface fingerprints (or
/// the tagged OID when facts are unavailable), so repairs re-key them and this
/// join deliberately leaves their reusable versions intact.
/// Seeks blobs(blob_oid, lang, parse_variant), members(blob_id), versions(summary_id).
pub(super) const WITHDRAW_VERSIONS_OF_REPLACED_BLOB_SQL: &str =
    "DELETE FROM resolution_unit_summary_versions
     WHERE summary_id IN (
       SELECT members.summary_id
       FROM blobs
       JOIN resolution_unit_summary_members AS members ON members.blob_id = blobs.id
       WHERE blobs.blob_oid = ?1 AND blobs.lang = ?2 AND blobs.parse_variant = ?3)";

/// Withdraw one workspace's version rows (`delete_workspace_projection`).
pub(super) const DELETE_WORKSPACE_VERSIONS_SQL: &str =
    "DELETE FROM resolution_unit_summary_versions WHERE workspace_id = ?1";

/// Withdraw every version row of one language (analysis epoch rotation).
#[doc(hidden)]
pub const DELETE_LANGUAGE_VERSIONS_SQL: &str =
    "DELETE FROM resolution_unit_summary_versions WHERE lang = ?1";

/// Withdraw the version rows of generations the language epoch has left behind
/// (stale-generation reclaim; the rotation hook normally already did).
pub(super) const DELETE_STALE_GENERATION_VERSIONS_SQL: &str =
    "DELETE FROM resolution_unit_summary_versions
     WHERE generation <> COALESCE(
       (SELECT generation FROM analysis_epochs
        WHERE analysis_epochs.lang = resolution_unit_summary_versions.lang), 0)";

pub(super) use brokk_bifrost_core::cache_gc::DELETE_UNBOUND_SUMMARIES_SQL;

pub(crate) const OPEN_VERSION_SQL: &str =
    "SELECT summary_id, valid_from FROM resolution_unit_summary_versions
     WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3 AND unit_key = ?4
       AND profile_digest = ?5 AND valid_until IS NULL";
const INSERT_VERSION_SQL: &str = "INSERT INTO resolution_unit_summary_versions(workspace_id, lang, generation, unit_key, valid_from, valid_until, summary_id, profile_digest)
     VALUES(?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7)";
pub(crate) const CLOSE_VERSION_SQL: &str =
    "UPDATE resolution_unit_summary_versions SET valid_until = ?5
     WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3 AND unit_key = ?4
       AND profile_digest = ?6 AND valid_until IS NULL";
// An open row that this very revision opened has the empty interval [R, R), which
// the schema rejects; it is withdrawn instead (see `rust_crates.rs`
// `end_open_crate_version`).
pub(crate) const WITHDRAW_VERSION_SQL: &str = "DELETE FROM resolution_unit_summary_versions
     WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3 AND unit_key = ?4
       AND profile_digest = ?6 AND valid_until IS NULL AND valid_from = ?5";

/// Complete, with every blob-referencing child still present, for the summary
/// aliased `candidate`. A blob row replaced since publication cascades its
/// children away, and the counts stored in the header no longer match.
macro_rules! summary_intact {
    () => {
        "candidate.publication_state = 'complete'
       AND candidate.member_count = (SELECT count(*) FROM resolution_unit_summary_members WHERE summary_id = candidate.summary_id)
       AND candidate.export_count = (SELECT count(*) FROM resolution_unit_summary_exports WHERE summary_id = candidate.summary_id)
       AND candidate.import_count = (SELECT count(*) FROM resolution_unit_summary_imports WHERE summary_id = candidate.summary_id)"
    };
}

/// The summary with this identity digest `?1` other than `?2` (the header being
/// written), for a derivation that arrived at an identity that exists already.
pub(super) const FIND_SUMMARY_SQL: &str = concat!(
    "SELECT candidate.summary_id, ",
    summary_intact!(),
    " FROM resolution_unit_summaries AS candidate
      WHERE candidate.summary_digest = ?1 AND candidate.summary_id <> ?2"
);

/// Are the units a summary recorded as consumed beyond its direct dependencies
/// still at the output digests it saw? `?4` is the summary id; `?1`..`?3` and
/// `?5`..`?8` are the selection (workspace, language, generation, revision,
/// producer epoch, derivation version, profile). Each recorded unit must have,
/// at this pass, a settled live summary whose output digest is the recorded
/// one. Liveness is `live_summary_select!`, the statement the writer and every
/// reader use. The unit must also have settled in the pass now running, as
/// `consume_dependencies` requires: a live row of an earlier revision has not
/// been checked against this revision's inputs. A unit recorded absent
/// (`ABSENT_DIGEST`, it had no live summary) is current while it still has none,
/// and stale once it has one, settled or not: its appearance is the change. A
/// unit recorded unavailable (it existed, unsettled) never validates: it is
/// settled by the time of a reuse and its real output must be read. One
/// statement, one probe per recorded unit.
pub(super) const CONSUMED_UNITS_CURRENT_SQL: &str = concat!(
    "SELECT NOT EXISTS (SELECT 1 FROM resolution_unit_summary_consumed_units AS consumed
       WHERE consumed.summary_id = ?4
         AND NOT CASE WHEN consumed.consumed_output_digest = zeroblob(32)
           THEN NOT EXISTS (",
    live_summary_select!("?8", "consumed.consumed_unit_key"),
    ")
           ELSE EXISTS (",
    live_summary_select!("?8", "consumed.consumed_unit_key"),
    " AND summaries.output_digest = consumed.consumed_output_digest
         AND EXISTS (SELECT 1 FROM temp.unit_summary_order AS settled
                     WHERE settled.unit_key = consumed.consumed_unit_key)) END)"
);

/// The open summary `?2` as a candidate for the lookup digest `?1`: its id when
/// it carries that digest and is intact, and whether it recorded any consumed
/// unit (a summary that recorded none needs no check).
pub(super) const OPEN_CANDIDATE_SQL: &str = concat!(
    "SELECT candidate.summary_id,
            EXISTS (SELECT 1 FROM resolution_unit_summary_consumed_units
                    WHERE summary_id = candidate.summary_id)
     FROM resolution_unit_summaries AS candidate
     WHERE candidate.summary_id = ?2 AND candidate.lookup_digest = ?1 AND ",
    summary_intact!()
);

/// The other intact candidates under the lookup digest `?1`, newest first,
/// skipping `?2`. The lookup index yields them in summary id order, so `DESC`
/// needs no sort and the caller stops at the first one that is current: the cost
/// follows the candidates examined, not the history under one lookup digest.
pub(super) const OTHER_CANDIDATES_SQL: &str = concat!(
    "SELECT candidate.summary_id,
            EXISTS (SELECT 1 FROM resolution_unit_summary_consumed_units
                    WHERE summary_id = candidate.summary_id)
     FROM resolution_unit_summaries AS candidate
     WHERE candidate.lookup_digest = ?1 AND candidate.summary_id IS NOT ?2 AND ",
    summary_intact!(),
    " ORDER BY candidate.summary_id DESC"
);

// Close every open row this pass did not rebind. A row opened by this revision
// is withdrawn; an earlier one is closed at this revision. Pin the profile-leading
// open index: otherwise SQLite chooses a primary-key range over every profile
// of the workspace, because the unit key precedes the profile in that key.
pub(crate) const WITHDRAW_UNSETTLED_SQL: &str = "DELETE FROM resolution_unit_summary_versions
       INDEXED BY resolution_unit_summary_versions_open
     WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3
       AND profile_digest = ?5 AND valid_until IS NULL AND valid_from = ?4
       AND NOT EXISTS (SELECT 1 FROM temp.unit_summary_order AS settled
                       WHERE settled.unit_key = resolution_unit_summary_versions.unit_key)
     RETURNING unit_key, summary_id";
pub(crate) const CLOSE_UNSETTLED_SQL: &str =
    "UPDATE resolution_unit_summary_versions INDEXED BY resolution_unit_summary_versions_open
       SET valid_until = ?4
     WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3
       AND profile_digest = ?5 AND valid_until IS NULL AND valid_from < ?4
       AND NOT EXISTS (SELECT 1 FROM temp.unit_summary_order AS settled
                       WHERE settled.unit_key = resolution_unit_summary_versions.unit_key)
     RETURNING unit_key, summary_id";
pub(crate) const LATER_OPEN_VERSION_SQL: &str =
    "SELECT EXISTS(SELECT 1 FROM resolution_unit_summary_versions
       INDEXED BY resolution_unit_summary_versions_open
     WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3
       AND profile_digest = ?5 AND valid_until IS NULL AND valid_from > ?4)";

const STAGING_SCHEMA_SQL: &str = "
CREATE TEMP TABLE IF NOT EXISTS unit_summary_work(unit_id INTEGER PRIMARY KEY) STRICT;
CREATE TEMP TABLE IF NOT EXISTS unit_summary_edges(
  unit_id INTEGER NOT NULL,
  dependency_unit_id INTEGER NOT NULL,
  -- 0 for an edge the unit consumes but that must not order the units: a Rust
  -- library consumes its dev-dependencies, which are inputs of its test
  -- targets and may form a cycle with the library that depends on it.
  orders INTEGER NOT NULL DEFAULT 1 CHECK(orders IN (0, 1)),
  PRIMARY KEY(unit_id, dependency_unit_id)
) WITHOUT ROWID, STRICT;
CREATE INDEX IF NOT EXISTS temp.unit_summary_edges_dependency
  ON unit_summary_edges(dependency_unit_id);
-- The units a unit's derivation read beyond its ordering edges, for the rest of
-- this request: the consumed set of its summary, and every dependency it read as
-- unavailable because the pass had not settled it yet. A moved output sends the
-- units that read it to the next fixpoint round. Keyed by unit key, so a read of
-- a unit that is not staged costs nothing and never fires.
CREATE TEMP TABLE IF NOT EXISTS unit_summary_reads(
  unit_id INTEGER NOT NULL,
  read_unit_key BLOB NOT NULL,
  unavailable INTEGER NOT NULL CHECK(unavailable IN (0, 1)),
  PRIMARY KEY(unit_id, read_unit_key)
) WITHOUT ROWID, STRICT;
CREATE INDEX IF NOT EXISTS temp.unit_summary_reads_key ON unit_summary_reads(read_unit_key);
-- The units to derive again in a fixpoint round.
CREATE TEMP TABLE IF NOT EXISTS unit_summary_fixpoint(
  round INTEGER NOT NULL,
  unit_id INTEGER NOT NULL,
  PRIMARY KEY(round, unit_id)
) WITHOUT ROWID, STRICT;
CREATE TEMP TABLE IF NOT EXISTS unit_summary_order(
  ordinal INTEGER PRIMARY KEY,
  unit_id INTEGER NOT NULL UNIQUE,
  unit_key BLOB UNIQUE
) STRICT;
DELETE FROM temp.unit_summary_work;
DELETE FROM temp.unit_summary_edges;
DELETE FROM temp.unit_summary_reads;
DELETE FROM temp.unit_summary_fixpoint;
DELETE FROM temp.unit_summary_order;";

const CLEAR_STAGING_SQL: &str = "
DELETE FROM temp.unit_summary_work;
DELETE FROM temp.unit_summary_edges;
DELETE FROM temp.unit_summary_reads;
DELETE FROM temp.unit_summary_fixpoint;
DELETE FROM temp.unit_summary_order;";

/// Use dependency-first component waves for the ordered pass. Rust's topology
/// forcing policy is separate from this driver's consumed-only-edge retries.
fn order_units(conn: &Connection) -> Result<()> {
    conn.execute_batch(super::unit_schedule::SCHEMA_SQL)?;
    conn.execute_batch(super::unit_schedule::CLEAR_SQL)?;
    conn.execute_batch("INSERT INTO temp.unit_schedule_units SELECT unit_id FROM temp.unit_summary_work;
        INSERT INTO temp.unit_schedule_edges SELECT unit_id,dependency_unit_id,orders FROM temp.unit_summary_edges;")?;
    super::unit_schedule::build(conn)?;
    conn.execute(
        &format!(
            "INSERT INTO temp.unit_summary_order(unit_id) {}",
            super::unit_schedule::ORDER_SQL
        ),
        [],
    )?;
    Ok(())
}

// A unit that consumed a dependency as unavailable is derived again once the
// dependency has settled, and so is every unit that consumes a unit whose output
// moved in the previous round. Bounded by FIXPOINT_ROUNDS.
const SEED_FIXPOINT_SQL: &str = "INSERT OR IGNORE INTO temp.unit_summary_fixpoint(round, unit_id)
     SELECT DISTINCT 1, reads.unit_id FROM temp.unit_summary_reads AS reads
     JOIN temp.unit_summary_order AS settled ON settled.unit_key = reads.read_unit_key
     WHERE reads.unavailable = 1";
// The dependents of the unit `?1`, whose output moved: the units with an ordering
// edge to it and the units that read it, available or not.
const MARK_DEPENDENTS_SQL: &str = "INSERT OR IGNORE INTO temp.unit_summary_fixpoint(round, unit_id)
     SELECT ?2, edges.unit_id FROM temp.unit_summary_edges AS edges
     WHERE edges.dependency_unit_id = ?1
     UNION ALL
     SELECT ?2, reads.unit_id FROM temp.unit_summary_order AS moved
     JOIN temp.unit_summary_reads AS reads ON reads.read_unit_key = moved.unit_key
     WHERE moved.unit_id = ?1";
const NEXT_FIXPOINT_UNIT_SQL: &str = "SELECT ordered.ordinal, ordered.unit_id
     FROM temp.unit_summary_fixpoint AS fixpoint
     JOIN temp.unit_summary_order AS ordered ON ordered.unit_id = fixpoint.unit_id
     WHERE fixpoint.round = ?1 AND ordered.ordinal > ?2 ORDER BY ordered.ordinal LIMIT 1";
const COUNT_FIXPOINT_UNITS_SQL: &str =
    "SELECT count(*) FROM temp.unit_summary_fixpoint WHERE round = ?1";
const FORGET_READS_SQL: &str = "DELETE FROM temp.unit_summary_reads WHERE unit_id = ?1";
const NOTE_READ_SQL: &str =
    "INSERT OR REPLACE INTO temp.unit_summary_reads(unit_id, read_unit_key, unavailable)
     VALUES(?1, ?2, ?3)";
/// A reused summary reads again what it recorded. A unit it recorded as absent
/// may appear later in this pass, so it is also retried once that unit settles.
const NOTE_RECORDED_READS_SQL: &str =
    "INSERT OR REPLACE INTO temp.unit_summary_reads(unit_id, read_unit_key, unavailable)
     SELECT ?1, consumed_unit_key, consumed_output_digest = zeroblob(32)
     FROM resolution_unit_summary_consumed_units WHERE summary_id = ?2";
/// Rounds of re-derivation after the ordered pass. A unit derived before a
/// dependency it consumes gets that dependency in round one; a round that moves
/// an output sends its dependents to the next. Dependency chains behind a
/// library and its dev-dependency settle within a few rounds.
const FIXPOINT_ROUNDS: i64 = 4;
/// The units still queued for round `?1` (one past the last) and, transitively,
/// every settled unit with an ordering edge to one or a recorded read of one.
const STRANDED_UNITS_SQL: &str = "WITH RECURSIVE stranded(unit_id) AS (
       SELECT unit_id FROM temp.unit_summary_fixpoint WHERE round = ?1
       UNION
       SELECT edges.unit_id FROM stranded
       JOIN temp.unit_summary_edges AS edges ON edges.dependency_unit_id = stranded.unit_id
       UNION
       SELECT reads.unit_id FROM stranded
       JOIN temp.unit_summary_order AS ordered ON ordered.unit_id = stranded.unit_id
       JOIN temp.unit_summary_reads AS reads ON reads.read_unit_key = ordered.unit_key
     )
     SELECT ordered.unit_id, ordered.unit_key FROM stranded
     JOIN temp.unit_summary_order AS ordered ON ordered.unit_id = stranded.unit_id
     WHERE ordered.unit_key IS NOT NULL ORDER BY ordered.ordinal";
const UNSETTLE_UNIT_SQL: &str =
    "UPDATE temp.unit_summary_order SET unit_key = NULL WHERE unit_id = ?1";
const NEXT_UNIT_SQL: &str = "SELECT ordinal, unit_id FROM temp.unit_summary_order
     WHERE ordinal > ?1 ORDER BY ordinal LIMIT 1";
const SETTLE_UNIT_SQL: &str = "UPDATE temp.unit_summary_order SET unit_key = ?2 WHERE unit_id = ?1";
/// Has this pass settled the unit with key `?1`? (`unit_key` is NULL until it has.)
pub(crate) const SETTLED_KEY_SQL: &str =
    "SELECT EXISTS(SELECT 1 FROM temp.unit_summary_order WHERE unit_key = ?1)";

impl AnalyzerStore {
    /// Reconcile one language's unit summaries against one workspace snapshot.
    ///
    /// Runs as one writer job: the units, their inputs and their derivations are
    /// read on the writer connection, so a child published a moment ago is
    /// visible to its dependents. Each unit is its own transaction, so another
    /// process's writer is never held off for more than one unit.
    #[doc(hidden)]
    pub fn reconcile_unit_summaries(
        &self,
        snapshot: &WorkspaceSnapshotId,
        language: impl UnitSummaryLanguage + Send + 'static,
        cancellation: &CancellationToken,
    ) -> Result<UnitSummaryReconciliation> {
        assert_eq!(snapshot.lang, language.lang());
        let snapshot = snapshot.clone();
        let cancellation = cancellation.clone();
        let statements = self.statement_counter();
        self.execute_selection_publication(move |conn| {
            let started = Instant::now();
            let statements_before = statements.count();
            let _trace = StatementCount::register(conn, &statements);
            let mut report = reconcile(conn, &snapshot, &language, &cancellation, &statements)?;
            report.elapsed = started.elapsed();
            report.statements = statements.count() - statements_before;
            Ok(report)
        })
    }

    /// The counter a measurement installs on the store, or an inert one.
    fn statement_counter(&self) -> StatementCounter {
        #[cfg(any(test, feature = "test-support"))]
        {
            StatementCounter(self.crate_statement_counter.lock().unwrap().clone())
        }
        #[cfg(not(any(test, feature = "test-support")))]
        {
            StatementCounter(None)
        }
    }
}

/// Statements run on the writer connection, when a measurement asked for them.
#[derive(Clone)]
pub(super) struct StatementCounter(Option<Arc<AtomicUsize>>);

impl StatementCounter {
    fn count(&self) -> usize {
        self.0
            .as_ref()
            .map_or(0, |counter| counter.load(Ordering::Relaxed))
    }
}

/// Counts statements on one pass without borrowing its mutable connection.
struct StatementCount {
    _guard: Option<brokk_bifrost_core::cache_db::sql_profile::ListenerGuard>,
}

impl StatementCount {
    fn register(conn: &Connection, counter: &StatementCounter) -> Self {
        let guard = counter.0.as_ref().map(|counter| {
            let counter = Arc::clone(counter);
            brokk_bifrost_core::cache_db::sql_profile::attach_listener(
                conn,
                Arc::new(move |event| {
                    if matches!(
                        event,
                        brokk_bifrost_core::cache_db::sql_profile::ListenerEvent::Statement { .. }
                    ) {
                        counter.fetch_add(1, Ordering::Relaxed);
                    }
                }),
            )
        });
        Self { _guard: guard }
    }
}

fn reconcile(
    conn: &mut Connection,
    snapshot: &WorkspaceSnapshotId,
    language: &dyn UnitSummaryLanguage,
    cancellation: &CancellationToken,
    statements: &StatementCounter,
) -> Result<UnitSummaryReconciliation> {
    initialize_staging(conn)?;
    let outcome = reconcile_staged(conn, snapshot, language, cancellation, statements);
    if let Err(error) = clear_pass(conn, language) {
        return Err(StoreError::new(format!(
            "{error}; reconciliation: {outcome:?}"
        )));
    }
    outcome
}

/// Initialize TEMP state on the writer connection that owns this pass.
pub(super) fn initialize_staging(conn: &Connection) -> Result<()> {
    // Derivation and publication share the same connection-local bridges.
    // Persistent writers have no bootstrap TEMP bridges, so install them once
    // per pass instead of repeating the idempotent DDL in every unit's
    // transaction.
    super::surface_relations::create_summary_translation_views(conn)?;
    conn.execute_batch(super::unit_schedule::SCHEMA_SQL)?;
    conn.execute_batch(STAGING_SCHEMA_SQL)?;
    Ok(())
}

/// Clear all pass-owned TEMP state, attempting each cleanup even after failure.
pub(super) fn clear_pass(conn: &Connection, language: &dyn UnitSummaryLanguage) -> Result<()> {
    // The staging rows are this pass's working set and never outlive it.
    let mut cleanup_errors = Vec::new();
    for cleanup in [
        language.clear_stage(conn),
        conn.execute_batch(CLEAR_STAGING_SQL)
            .map_err(StoreError::from),
        conn.execute_batch(super::unit_schedule::CLEAR_SQL)
            .map_err(StoreError::from),
    ] {
        if let Err(error) = cleanup {
            cleanup_errors.push(error);
        }
    }
    if !cleanup_errors.is_empty() {
        return Err(StoreError::new(format!(
            "unit summary cleanup failed: {cleanup_errors:?}"
        )));
    }
    Ok(())
}

fn reconcile_staged(
    conn: &mut Connection,
    snapshot: &WorkspaceSnapshotId,
    language: &dyn UnitSummaryLanguage,
    cancellation: &CancellationToken,
    statements: &StatementCounter,
) -> Result<UnitSummaryReconciliation> {
    let mut state = begin_staged_pass(conn, snapshot, language)?;
    if state.report.units > 0 {
        let mut after = 0_i64;
        loop {
            if cancellation.is_cancelled() {
                state.report.cancelled = true;
                break;
            }
            let next: Option<(i64, i64)> = conn
                .query_row(NEXT_UNIT_SQL, [after], |row| Ok((row.get(0)?, row.get(1)?)))
                .optional()?;
            let Some((ordinal, unit_id)) = next else {
                break;
            };
            after = ordinal;
            let statements_before = statements.count();
            let mut pass = state.context(snapshot, language, cancellation);
            publish_unit(conn, &mut pass, unit_id)?;
            state.report.max_unit_statements = state
                .report
                .max_unit_statements
                .max(statements.count() - statements_before);
        }
    }
    finish_pass(conn, state, snapshot, language, cancellation, statements)
}

/// Owned state retained between a scheduler's per-unit writer jobs.
pub(super) struct UnitSummaryPassState {
    producer_epoch: Option<String>,
    report: UnitSummaryReconciliation,
}

impl UnitSummaryPassState {
    pub(super) fn context<'a>(
        &'a mut self,
        snapshot: &'a WorkspaceSnapshotId,
        language: &'a dyn UnitSummaryLanguage,
        cancellation: &'a CancellationToken,
    ) -> UnitSummaryPass<'a> {
        UnitSummaryPass {
            snapshot,
            language,
            producer_epoch: self
                .producer_epoch
                .as_deref()
                .expect("a staged unit requires an epoch"),
            cancellation,
            report: &mut self.report,
        }
    }
}

/// Stage and order the selected units before their first publications.
pub(super) fn begin_staged_pass(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
    language: &dyn UnitSummaryLanguage,
) -> Result<UnitSummaryPassState> {
    let mut report = UnitSummaryReconciliation::default();
    language.stage(conn, snapshot)?;
    order_units(conn)?;
    report.units = conn.query_row("SELECT count(*) FROM temp.unit_summary_order", [], |row| {
        row.get::<_, usize>(0)
    })?;
    let producer_epoch: Option<String> = conn
        .query_row(
            "SELECT producer_epoch FROM resolution_producer_epochs WHERE lang = ?1",
            [snapshot.lang.as_str()],
            |row| row.get(0),
        )
        .optional()?;
    if report.units > 0 && producer_epoch.is_none() {
        return Err(StoreError::corrupt(format!(
            "{} has {} units but no resolution producer epoch",
            snapshot.lang, report.units
        )));
    }
    Ok(UnitSummaryPassState {
        producer_epoch,
        report,
    })
}

/// Retry unsettled reads, withdraw stranded units, and close version rows.
pub(super) fn finish_pass(
    conn: &mut Connection,
    state: UnitSummaryPassState,
    snapshot: &WorkspaceSnapshotId,
    language: &dyn UnitSummaryLanguage,
    cancellation: &CancellationToken,
    statements: &StatementCounter,
) -> Result<UnitSummaryReconciliation> {
    let UnitSummaryPassState {
        producer_epoch,
        mut report,
    } = state;
    if report.units > 0 {
        let producer_epoch = producer_epoch
            .as_deref()
            .expect("staged units require an epoch");
        if !report.cancelled {
            conn.execute(SEED_FIXPOINT_SQL, [])?;
            reconcile_fixpoint(
                conn,
                snapshot,
                language,
                producer_epoch,
                cancellation,
                statements,
                &mut report,
            )?;
        }
    }
    close_unsettled(conn, snapshot, language, &mut report)?;
    let lang = language.lang();
    for (key, before) in std::mem::take(&mut report.touched) {
        match (before, live_unit_output(conn, snapshot, language, &key)?) {
            (Some(before), Some(after)) if before != after => {
                report.output_changed.push((lang.to_owned(), key));
            }
            (Some(_), None) => report.closed.push((lang.to_owned(), key)),
            (None, Some(_)) => report.added.push((lang.to_owned(), key)),
            _ => {}
        }
    }
    for keys in [
        &mut report.output_changed,
        &mut report.added,
        &mut report.closed,
    ] {
        keys.sort_unstable();
    }
    Ok(report)
}

/// The output digest of a unit's live summary version at the snapshot's
/// revision, if it has one.
fn live_unit_output(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
    language: &dyn UnitSummaryLanguage,
    unit_key: &[u8; 32],
) -> Result<Option<Vec<u8>>> {
    Ok(conn
        .prepare_cached(
            "SELECT summaries.output_digest
             FROM resolution_unit_summary_versions AS versions
             JOIN resolution_unit_summaries AS summaries
               ON summaries.summary_id = versions.summary_id
             WHERE versions.workspace_id = ?1 AND versions.lang = ?2
               AND versions.generation = ?3 AND versions.unit_key = ?4
               AND versions.profile_digest = ?5
               AND versions.valid_until IS NULL AND versions.valid_from <= ?6",
        )?
        .query_row(
            params![
                snapshot.workspace_id.as_str(),
                language.lang(),
                snapshot.generation.get(),
                unit_key.as_slice(),
                language.profile_digest().as_slice(),
                snapshot.revision
            ],
            |row| row.get(0),
        )
        .optional()?)
}

fn summary_output(conn: &Connection, summary_id: i64) -> Result<Vec<u8>> {
    Ok(conn
        .prepare_cached(
            "SELECT output_digest FROM resolution_unit_summaries WHERE summary_id = ?1",
        )?
        .query_row([summary_id], |row| row.get(0))?)
}

/// Derive again, in order, the units that consumed a dependency before the pass
/// settled it, then the units that consume a unit whose output moved. A unit
/// whose consumed digests did not move finds its summary and publishes nothing.
fn reconcile_fixpoint(
    conn: &mut Connection,
    snapshot: &WorkspaceSnapshotId,
    language: &dyn UnitSummaryLanguage,
    producer_epoch: &str,
    cancellation: &CancellationToken,
    statements: &StatementCounter,
    report: &mut UnitSummaryReconciliation,
) -> Result<()> {
    let rounds = language.fixpoint_rounds();
    for round in 1..=rounds {
        let queued: usize = conn
            .prepare_cached(COUNT_FIXPOINT_UNITS_SQL)?
            .query_row([round], |row| row.get(0))?;
        if queued == 0 {
            return Ok(());
        }
        report.fixpoint_rounds = round as usize;
        let mut after = 0_i64;
        loop {
            if cancellation.is_cancelled() {
                report.cancelled = true;
                return Ok(());
            }
            let next: Option<(i64, i64)> = conn
                .prepare_cached(NEXT_FIXPOINT_UNIT_SQL)?
                .query_row(params![round, after], |row| Ok((row.get(0)?, row.get(1)?)))
                .optional()?;
            let Some((ordinal, unit_id)) = next else {
                break;
            };
            after = ordinal;
            let statements_before = statements.count();
            let mut pass = UnitSummaryPass {
                snapshot,
                language,
                producer_epoch,
                cancellation,
                report: &mut *report,
            };
            let published = publish_unit(conn, &mut pass, unit_id)?;
            report.rederived += usize::from(published.republished);
            if published.output_moved {
                conn.prepare_cached(MARK_DEPENDENTS_SQL)?
                    .execute(params![unit_id, round + 1])?;
            }
            report.max_unit_statements = report
                .max_unit_statements
                .max(statements.count() - statements_before);
        }
    }
    // The round limit stopped the fixpoint with units still queued: their
    // summaries describe inputs that have since moved. Present none of them, nor
    // anything derived from one, as current: unsettle them, so the end of the pass
    // closes their version rows and a reader finds no live summary, and report
    // each as failed.
    let stranded = conn
        .prepare_cached(STRANDED_UNITS_SQL)?
        .query_map([rounds + 1], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for (unit_id, unit_key) in &stranded {
        let unit_key: [u8; 32] = digest_from_row(unit_key.clone())?;
        conn.prepare_cached(UNSETTLE_UNIT_SQL)?.execute([unit_id])?;
        report.failed.push((
            format!("{} unit {}", language.lang(), lower_hex_string(&unit_key)),
            format!(
                "the fixpoint did not settle within {rounds} rounds; \
                 its summary is withdrawn until the next reconciliation"
            ),
        ));
    }
    report.fixpoint_unsettled = stranded.len();
    Ok(())
}

/// What publishing one unit did to its version row.
#[doc(hidden)]
pub struct Published {
    /// The unit's summary was replaced or rebound.
    republished: bool,
    /// The replaced summary of this same revision had a different output digest,
    /// so the units that consumed it are stale.
    output_moved: bool,
}

/// The state of one reconciliation pass that `publish_unit` needs for every
/// unit. The owning pass state lends this context to each publication.
pub(super) struct UnitSummaryPass<'a> {
    snapshot: &'a WorkspaceSnapshotId,
    language: &'a dyn UnitSummaryLanguage,
    producer_epoch: &'a str,
    cancellation: &'a CancellationToken,
    report: &'a mut UnitSummaryReconciliation,
}

/// Publish one unit: reuse its summary when the digest exists, otherwise derive
/// and write it, then bind the version row. A unit whose inputs or derivation
/// fail publishes nothing and is not settled, so the end of the pass closes its
/// open version row; the failure is reported, not propagated, so one bad unit
/// does not withhold the others. Store errors still propagate.
pub(super) fn publish_unit(
    conn: &mut Connection,
    pass: &mut UnitSummaryPass<'_>,
    unit_id: i64,
) -> Result<Published> {
    let UnitSummaryPass {
        snapshot,
        language,
        producer_epoch,
        cancellation,
        report,
    } = pass;
    let snapshot = *snapshot;
    let language = *language;
    let producer_epoch = *producer_epoch;
    let cancellation = *cancellation;
    let report = &mut **report;
    let nothing = Published {
        republished: false,
        output_moved: false,
    };
    let mut unit = match language.inputs(conn, snapshot, unit_id) {
        Ok(unit) => unit,
        Err(error) => {
            report.failed.push((
                format!("{} unit {unit_id}", language.lang()),
                error.to_string(),
            ));
            return Ok(nothing);
        }
    };
    unit.containers
        .sort_by(|left, right| left.path.cmp(&right.path));
    unit.containers.dedup_by(|right, left| {
        if left.path != right.path {
            return false;
        }
        assert_eq!(
            left.parent_path, right.parent_path,
            "a container has one parent"
        );
        true
    });
    unit.placements.sort_by(|left, right| {
        (&left.container_path, left.member_ordinal)
            .cmp(&(&right.container_path, right.member_ordinal))
    });
    unit.dependency_names
        .sort_by(|left, right| (&left.role, &left.name).cmp(&(&right.role, &right.name)));
    // Keep the first language-supplied provenance for a consumed unit. Names
    // remain separate rows even when their consumed unit is the same.
    let mut dependency_keys = std::collections::HashSet::new();
    unit.dependencies
        .retain(|dependency| dependency_keys.insert(dependency.unit_key));
    let dependencies = consume_dependencies(conn, snapshot, language, producer_epoch, &unit)?;
    conn.prepare_cached(FORGET_READS_SQL)?.execute([unit_id])?;
    for dependency in dependencies
        .iter()
        .filter(|dependency| !dependency.available)
    {
        // Only a staged workspace dependency settles later.
        if unit
            .dependencies
            .iter()
            .any(|input| input.unit_key == dependency.unit_key && input.unit_id.is_some())
        {
            conn.prepare_cached(NOTE_READ_SQL)?.execute(params![
                unit_id,
                dependency.unit_key.as_slice(),
                true
            ])?;
        }
    }
    let inputs = member_inputs(conn, language, &unit)?;
    let lookup = lookup_digest(
        language,
        snapshot,
        producer_epoch,
        &unit,
        &inputs,
        &dependencies,
    )?;
    let open = open_version(conn, snapshot, language, &unit.unit_key)?;
    let selection = Selection::of(snapshot, language, producer_epoch);
    let reusable = reusable_summary(conn, &selection, &lookup, open.map(|(id, _)| id))?;
    if let Some((summary_id, true)) = reusable {
        conn.prepare_cached(NOTE_RECORDED_READS_SQL)?
            .execute(params![unit_id, summary_id])?;
    }
    let reusable = reusable.map(|(summary_id, _)| summary_id);
    let mut output_moved = false;
    let publication = if let (Some(reusable), Some((open_summary, _))) = (reusable, open)
        && reusable == open_summary
    {
        UnitPublication::Unchanged
    } else {
        if let std::collections::hash_map::Entry::Vacant(slot) = report.touched.entry(unit.unit_key)
        {
            slot.insert(match open {
                Some((open_summary, _)) => Some(summary_output(conn, open_summary)?),
                None => None,
            });
        }
        let transaction_started = Instant::now();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut rows_written = 0;
        let (summary_id, derived_output) = match reusable {
            Some(summary_id) => (summary_id, None),
            None => {
                let mut reader = ForeignReader::new(
                    &tx,
                    snapshot,
                    language,
                    producer_epoch,
                    unit_id,
                    &dependencies,
                );
                #[cfg(any(test, feature = "test-support"))]
                let fence = match language.lang() {
                    "go" => Some(super::surface_relations::SurfaceReadGuard::new(
                        &tx,
                        super::surface_relations::GO_RELATIONS,
                    )?),
                    "python" => Some(super::surface_relations::SurfaceReadGuard::new(
                        &tx,
                        super::surface_relations::PYTHON_RELATIONS,
                    )?),
                    _ => None,
                };
                let mut derive = || {
                    language.derive(
                        &tx,
                        snapshot,
                        &unit,
                        &dependencies,
                        producer_epoch,
                        &mut reader,
                    )
                };
                #[cfg(any(test, feature = "test-support"))]
                let derived = if matches!(language.lang(), "go" | "python") {
                    super::connection_authorizer::without_member_blob_reads(&tx, derive)
                } else {
                    derive()
                };
                #[cfg(not(any(test, feature = "test-support")))]
                let derived = derive();
                let outputs = match derived {
                    Ok(outputs) => outputs,
                    Err(error) => {
                        report.failed.push((unit.label.clone(), error.to_string()));
                        return Ok(nothing);
                    }
                };
                #[cfg(any(test, feature = "test-support"))]
                drop(fence);
                if cancellation.is_cancelled() {
                    report.cancelled = true;
                    return Ok(nothing);
                }
                // Unchanged cached facts may predate this binary's surface list.
                // Ensure every member before any shared or Python child lookup.
                for member in &unit.members {
                    let (surface, cost) =
                        super::surface_relations::ensure_surface_set_tx(&tx, member.blob_id)?;
                    if surface.is_none() {
                        // The member's facts are not admitted completely enough
                        // to publish a surface set, so its child rows have no
                        // surface coordinates to translate to. Refuse the unit
                        // instead of writing the -1 that the summary CHECK
                        // constraints reject.
                        return Err(StoreError::missing_required_source_facts(format!(
                            "{}: member {} ({}) has no publishable surface set",
                            unit.label, member.rel_path, member.blob_oid
                        )));
                    }
                    rows_written += cost.logical_rows;
                }
                let output_digest = output_digest(&unit, &dependencies, &outputs);
                // The identity covers what the derivation and the language rows
                // read, so it is known only when the rows are written.
                let written = write_summary(
                    &tx,
                    language,
                    snapshot,
                    producer_epoch,
                    &lookup,
                    &unit,
                    &inputs,
                    &dependencies,
                    &mut reader,
                    &outputs,
                    &output_digest,
                    &mut rows_written,
                )?;
                // The attempt is resolved, so its scheduling notes cannot be undone.
                reader.flush_scheduling()?;
                match written {
                    Written::Summary(summary_id, output_digest) => {
                        (summary_id, Some(output_digest))
                    }
                    Written::Existing(summary_id) => (summary_id, None),
                }
            }
        };
        let previous_output = match open {
            Some((open_summary, _)) if open_summary != summary_id => tx
                .query_row(
                    "SELECT output_digest FROM resolution_unit_summaries WHERE summary_id = ?1",
                    [open_summary],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?,
            _ => None,
        };
        if let Some((open_summary, opened)) = open
            && open_summary != summary_id
        {
            end_open_version(&tx, snapshot, language, &unit.unit_key, opened)?;
            rows_written += 1;
        }
        if open.is_none_or(|(open_summary, _)| open_summary != summary_id) {
            tx.execute(
                INSERT_VERSION_SQL,
                params![
                    snapshot.workspace_id.as_str(),
                    language.lang(),
                    snapshot.generation.get(),
                    unit.unit_key.as_slice(),
                    snapshot.revision,
                    summary_id,
                    language.profile_digest().as_slice()
                ],
            )?;
            rows_written += 1;
        }
        rows_written += language.write_language_version(&tx, snapshot, &unit, summary_id)?;
        tx.commit()?;
        let held = transaction_started.elapsed();
        report.transaction_total += held;
        report.transaction_max = report.transaction_max.max(held);
        report.max_unit_rows = report.max_unit_rows.max(rows_written);
        output_moved = match (&previous_output, open) {
            (Some(previous), Some((_, opened))) if opened == snapshot.revision => {
                let current: Vec<u8> = match &derived_output {
                    Some(output_digest) => output_digest.to_vec(),
                    None => conn.query_row(
                        "SELECT output_digest FROM resolution_unit_summaries WHERE summary_id = ?1",
                        [summary_id],
                        |row| row.get(0),
                    )?,
                };
                *previous != current
            }
            _ => false,
        };
        match derived_output {
            Some(output_digest) => UnitPublication::Derived {
                rows_written,
                output_changed: previous_output
                    .is_some_and(|previous| previous.as_slice() != output_digest.as_slice()),
            },
            None => UnitPublication::Rebound { rows_written },
        }
    };
    conn.prepare_cached(SETTLE_UNIT_SQL)?
        .execute(params![unit_id, unit.unit_key.as_slice()])?;
    match publication {
        UnitPublication::Unchanged => report.unchanged += 1,
        UnitPublication::Rebound { rows_written } => {
            report.rebound_count += 1;
            report.rows_written += rows_written;
        }
        UnitPublication::Derived {
            rows_written,
            output_changed,
        } => {
            report.derived += 1;
            report.rows_written += rows_written;
            report.output_changes += usize::from(output_changed);
        }
    }
    Ok(Published {
        republished: !matches!(publication, UnitPublication::Unchanged),
        output_moved,
    })
}

enum UnitPublication {
    Unchanged,
    Rebound {
        rows_written: usize,
    },
    Derived {
        rows_written: usize,
        output_changed: bool,
    },
}

struct ExistingSummary {
    summary_id: i64,
    /// See `summary_intact!`.
    intact: bool,
}

/// What a reuse decision is made against: the workspace revision and the
/// language's live-summary parameters.
#[doc(hidden)]
pub struct Selection<'a> {
    snapshot: &'a WorkspaceSnapshotId,
    lang: &'static str,
    profile: [u8; 32],
    producer_epoch: &'a str,
    derivation_identity: [u8; 32],
}

impl<'a> Selection<'a> {
    fn of(
        snapshot: &'a WorkspaceSnapshotId,
        language: &dyn UnitSummaryLanguage,
        producer_epoch: &'a str,
    ) -> Self {
        Self {
            snapshot,
            lang: language.lang(),
            profile: language.profile_digest(),
            producer_epoch,
            derivation_identity: language.derivation_identity(),
        }
    }
}

/// Is a summary valid for reuse now? The one predicate for "this summary still
/// describes its inputs" (#11173 D9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SummaryValidity {
    Valid,
    Stale,
}

/// Is `summary_id` valid at `selection`? Today that is the consumed-set check:
/// every unit it recorded beyond its direct dependencies is settled and still at
/// the output digest it recorded, one batched query, O(the recorded set). A
/// summary that recorded none is valid.
///
/// The member-input half of the identity is already in the lookup digest:
/// Go and Python hash the selected member surfaces, and Rust hashes blob OIDs.
/// A candidate found by this selection's lookup therefore already matches the
/// selected inputs, and this check covers the consumed set beyond direct
/// dependencies.
pub(crate) fn summary_valid_now(
    conn: &Connection,
    summary_id: i64,
    selection: &Selection<'_>,
) -> Result<SummaryValidity> {
    let current: bool = conn.prepare_cached(CONSUMED_UNITS_CURRENT_SQL)?.query_row(
        params![
            selection.snapshot.workspace_id.as_str(),
            selection.lang,
            selection.snapshot.generation.get(),
            summary_id,
            selection.snapshot.revision,
            selection.producer_epoch,
            selection.derivation_identity,
            selection.profile.as_slice()
        ],
        |row| row.get(0),
    )?;
    Ok(if current {
        SummaryValidity::Valid
    } else {
        SummaryValidity::Stale
    })
}

/// The summary to publish without deriving: the open one when it is still a
/// candidate for the lookup digest and its recorded consumed units are current
/// (the unit is unchanged), otherwise the newest other such candidate (the unit
/// is rebound to it). `None` means derive and write a new immutable summary. A
/// summary whose recorded consumed units moved is never changed in place:
/// version rows of older revisions keep pointing at it.
fn reusable_summary(
    conn: &Connection,
    selection: &Selection<'_>,
    lookup: &[u8; 32],
    open: Option<i64>,
) -> Result<Option<(i64, bool)>> {
    let current =
        |(summary_id, recorded): (i64, bool)| -> Result<Option<(i64, bool)>> {
            Ok((!recorded
                || summary_valid_now(conn, summary_id, selection)? == SummaryValidity::Valid)
                .then_some((summary_id, recorded)))
        };
    if let Some(open) = open {
        let candidate = conn
            .prepare_cached(OPEN_CANDIDATE_SQL)?
            .query_row(params![lookup.as_slice(), open], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .optional()?;
        if let Some(open) = candidate.map(current).transpose()?.flatten() {
            return Ok(Some(open));
        }
    }
    let mut statement = conn.prepare_cached(OTHER_CANDIDATES_SQL)?;
    let mut candidates = statement.query(params![lookup.as_slice(), open])?;
    while let Some(row) = candidates.next()? {
        if let Some(found) = current((row.get(0)?, row.get(1)?))? {
            return Ok(Some(found));
        }
    }
    Ok(None)
}

fn find_summary(
    conn: &Connection,
    digest: &[u8; 32],
    other_than: i64,
) -> Result<Option<ExistingSummary>> {
    Ok(conn
        .prepare_cached(FIND_SUMMARY_SQL)?
        .query_row(params![digest.as_slice(), other_than], |row| {
            Ok(ExistingSummary {
                summary_id: row.get(0)?,
                intact: row.get(1)?,
            })
        })
        .optional()?)
}

fn open_version(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
    language: &dyn UnitSummaryLanguage,
    unit_key: &[u8; 32],
) -> Result<Option<(i64, i64)>> {
    Ok(conn
        .prepare_cached(OPEN_VERSION_SQL)?
        .query_row(
            params![
                snapshot.workspace_id.as_str(),
                language.lang(),
                snapshot.generation.get(),
                unit_key.as_slice(),
                language.profile_digest().as_slice()
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?)
}

fn end_open_version(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
    language: &dyn UnitSummaryLanguage,
    unit_key: &[u8; 32],
    opened: i64,
) -> Result<()> {
    let changed = match opened.cmp(&snapshot.revision) {
        std::cmp::Ordering::Less => conn.execute(
            CLOSE_VERSION_SQL,
            params![
                snapshot.workspace_id.as_str(),
                language.lang(),
                snapshot.generation.get(),
                unit_key.as_slice(),
                snapshot.revision,
                language.profile_digest().as_slice()
            ],
        )?,
        std::cmp::Ordering::Equal => conn.execute(
            WITHDRAW_VERSION_SQL,
            params![
                snapshot.workspace_id.as_str(),
                language.lang(),
                snapshot.generation.get(),
                unit_key.as_slice(),
                snapshot.revision,
                language.profile_digest().as_slice()
            ],
        )?,
        std::cmp::Ordering::Greater => {
            return Err(StoreError::new(format!(
                "{} unit summary reconcile at revision {} of workspace {} generation {} found \
                 unit {} open since the later revision {opened}",
                language.lang(),
                snapshot.revision,
                snapshot.workspace_id.as_str(),
                snapshot.generation.get(),
                lower_hex_string(unit_key)
            )));
        }
    };
    assert_eq!(
        changed,
        1,
        "unit {} must have exactly one open version row",
        lower_hex_string(unit_key)
    );
    Ok(())
}

fn close_unsettled(
    conn: &mut Connection,
    snapshot: &WorkspaceSnapshotId,
    language: &dyn UnitSummaryLanguage,
    report: &mut UnitSummaryReconciliation,
) -> Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let later: bool = tx.query_row(
        LATER_OPEN_VERSION_SQL,
        params![
            snapshot.workspace_id.as_str(),
            language.lang(),
            snapshot.generation.get(),
            snapshot.revision,
            language.profile_digest().as_slice()
        ],
        |row| row.get(0),
    )?;
    if later {
        return Err(StoreError::new(format!(
            "{} unit summary reconcile at revision {} of workspace {} generation {} found a \
             version open since a later revision",
            language.lang(),
            snapshot.revision,
            snapshot.workspace_id.as_str(),
            snapshot.generation.get()
        )));
    }
    // The closing statements return the versions they end, so the report
    // learns which units closed without another pass over the live versions.
    for statement in [WITHDRAW_UNSETTLED_SQL, CLOSE_UNSETTLED_SQL] {
        let ended = tx
            .prepare_cached(statement)?
            .query_map(
                params![
                    snapshot.workspace_id.as_str(),
                    language.lang(),
                    snapshot.generation.get(),
                    snapshot.revision,
                    language.profile_digest().as_slice()
                ],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        report.closed_versions += ended.len();
        for (key, summary_id) in ended {
            let key: [u8; 32] = key
                .try_into()
                .map_err(|_| StoreError::corrupt("invalid unit key"))?;
            if let std::collections::hash_map::Entry::Vacant(slot) = report.touched.entry(key) {
                slot.insert(Some(summary_output(&tx, summary_id)?));
            }
        }
    }
    // Unbound content-addressed headers remain reusable by another build until
    // periodic GC. Other profiles keep their own independent intervals.
    tx.commit()?;
    Ok(())
}

/// Resolve each consumed unit to its live summary's output digest. A workspace
/// dependency counts only when this pass already settled it: a live row from an
/// earlier revision has not been checked against this revision's inputs.
fn consume_dependencies(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
    language: &dyn UnitSummaryLanguage,
    producer_epoch: &str,
    unit: &UnitInputs,
) -> Result<Vec<ConsumedDependency>> {
    let mut sorted: Vec<&UnitDependency> = unit.dependencies.iter().collect();
    sorted.sort_by_key(|dependency| dependency.unit_key);
    assert!(
        sorted
            .windows(2)
            .all(|pair| pair[0].unit_key != pair[1].unit_key),
        "unit {} lists a dependency twice: {:?}",
        unit.label,
        unit.dependencies
            .iter()
            .map(|dependency| dependency.label.as_str())
            .collect::<Vec<_>>()
    );
    let mut consumed = Vec::with_capacity(sorted.len());
    for (ordinal, dependency) in sorted.into_iter().enumerate() {
        let live = match dependency.unit_id {
            Some(_) => consume_unit(
                conn,
                snapshot,
                language,
                producer_epoch,
                &dependency.unit_key,
            )?,
            None => None,
        };
        let (digest, available) = match (live, dependency.external_digest) {
            (Some((_, output)), _) => (output, true),
            (None, Some(external)) => (external, true),
            (None, None) => (unavailable_digest(&dependency.unit_key), false),
        };
        consumed.push(ConsumedDependency {
            ordinal,
            unit_key: dependency.unit_key,
            label: dependency.label.clone(),
            consumed_output_digest: digest,
            boundary: dependency.boundary,
            available,
        });
    }
    Ok(consumed)
}

/// The consumed digest of a read of a unit that had no live summary. All zero:
/// the validity statement recognizes it, and no output digest is a hash of zero.
const ABSENT_DIGEST: [u8; 32] = [0; 32];

fn unavailable_digest(unit_key: &[u8; 32]) -> [u8; 32] {
    let mut hash = CanonicalHasher::new(b"bifrost-unit-summary-unavailable:v1");
    hash.field("unit", unit_key);
    hash.finish()
}

fn digest_from_row(value: Vec<u8>) -> Result<[u8; 32]> {
    value
        .try_into()
        .map_err(|value: Vec<u8>| StoreError::corrupt(format!("digest is {} bytes", value.len())))
}

/// Single member-input authority for summary keys and coverage checks.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MemberInput {
    Surface([u8; 32]),
    NoFactsOid(String),
}

pub(crate) fn member_input_for_derivation(
    conn: &Connection,
    language: &str,
    blob_id: i64,
    blob_oid: &str,
) -> Result<MemberInput> {
    if let Some(input) = member_input_selected(conn, language, blob_id, blob_oid)? {
        return Ok(input);
    }
    Ok(match member_surface_fingerprint(conn, language, blob_id)? {
        Some(fingerprint) => MemberInput::Surface(fingerprint),
        None => MemberInput::NoFactsOid(blob_oid.to_owned()),
    })
}

/// Read the current list without publishing a missing set; missing admitted sets fail closed.
pub(crate) fn member_input_selected(
    conn: &Connection,
    language: &str,
    blob_id: i64,
    blob_oid: &str,
) -> Result<Option<MemberInput>> {
    use super::surface_relations::{
        GO_RELATIONS, PYTHON_RELATIONS, RUST_RELATIONS, list_digest, member_has_admitted_facts,
    };
    let relations = match language {
        "go" => GO_RELATIONS,
        "python" => PYTHON_RELATIONS,
        "rust" => RUST_RELATIONS,
        _ => unreachable!("only converted unit languages read surface inputs"),
    };
    let fingerprint = conn
        .query_row(
            "SELECT fingerprint FROM surface_sets WHERE blob_id=?1 AND list_digest=?2",
            params![blob_id, list_digest(relations)],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    if let Some(fingerprint) = fingerprint {
        return Ok(Some(MemberInput::Surface(digest_from_row(fingerprint)?)));
    }
    Ok((!member_has_admitted_facts(conn, blob_id)?)
        .then(|| MemberInput::NoFactsOid(blob_oid.to_owned())))
}

fn hash_member_input(hash: &mut CanonicalHasher, input: &MemberInput) {
    match input {
        MemberInput::Surface(fingerprint) => hash.field("member-surface", fingerprint),
        MemberInput::NoFactsOid(oid) => hash.field("member-no-facts-oid", oid.as_bytes()),
    }
}

/// Read one selected member's current-list fingerprint, publishing only a missing set.
pub(super) fn member_surface_fingerprint(
    conn: &Connection,
    language: &str,
    blob_id: i64,
) -> Result<Option<[u8; 32]>> {
    use super::surface_relations::{
        GO_RELATIONS, PYTHON_RELATIONS, RUST_RELATIONS, ensure_surface_set_tx, list_digest,
    };
    let relations = match language {
        "go" => GO_RELATIONS,
        "python" => PYTHON_RELATIONS,
        "rust" => RUST_RELATIONS,
        _ => unreachable!("only converted unit languages read surface inputs"),
    };
    let fingerprint = conn
        .query_row(
            "SELECT fingerprint FROM surface_sets WHERE blob_id=?1 AND list_digest=?2",
            params![blob_id, list_digest(relations)],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    if let Some(fingerprint) = fingerprint {
        return Ok(Some(digest_from_row(fingerprint)?));
    }
    let tx = conn.unchecked_transaction()?;
    let (fingerprint, _) = ensure_surface_set_tx(&tx, blob_id)?;
    tx.commit()?;
    Ok(fingerprint)
}

/// Each member's consumed input, read once so the key and the member rows record
/// the same value. Rust keeps its OID recipe and records none.
pub(super) fn member_inputs(
    conn: &Connection,
    language: &dyn UnitSummaryLanguage,
    unit: &UnitInputs,
) -> Result<Vec<MemberInput>> {
    if !matches!(language.lang(), "go" | "python") {
        return Ok(Vec::new());
    }
    unit.members
        .iter()
        .map(|member| {
            member_input_for_derivation(conn, language.lang(), member.blob_id, &member.blob_oid)
        })
        .collect()
}

/// The lookup digest, the first phase of a summary's identity: the unit's own
/// inputs and its direct dependencies' output digests. It is known before any
/// derivation, so it finds the candidates; it is not unique, because summaries
/// that read different foreign units under equal own inputs share it. An unmoved
/// output digest of a dependency leaves its dependents' lookup digests unmoved.
pub(super) fn lookup_digest(
    language: &dyn UnitSummaryLanguage,
    snapshot: &WorkspaceSnapshotId,
    producer_epoch: &str,
    unit: &UnitInputs,
    inputs: &[MemberInput],
    dependencies: &[ConsumedDependency],
) -> Result<[u8; 32]> {
    // Rust members keep hashing their OIDs until its M3 row conversion; its
    // input files already hash by surface value, so it moved to v3 with them.
    let surfaced = matches!(language.lang(), "go" | "python");
    assert!(
        language.lang() == "rust" || unit.input_files.is_empty(),
        "only Rust declares input files"
    );
    let mut hash = CanonicalHasher::new(b"bifrost-unit-summary:v3");
    hash.field("lang", language.lang().as_bytes());
    hash.field("unit-kind", language.unit_kind().as_bytes());
    hash.field("derivation-version", &language.derivation_identity());
    hash.field("producer-epoch", producer_epoch.as_bytes());
    hash.field("generation", &snapshot.generation.get().to_be_bytes());
    hash.field("unit", &unit.unit_key);
    assert_eq!(
        inputs.len(),
        if surfaced { unit.members.len() } else { 0 },
        "a surfaced unit hashes one input per member"
    );
    for (ordinal, member) in unit.members.iter().enumerate() {
        hash.field("member-path", member.rel_path.as_bytes());
        hash.field("member-role", member.source_role.as_bytes());
        if surfaced {
            hash_member_input(&mut hash, &inputs[ordinal]);
        } else {
            hash.field("member-oid", member.blob_oid.as_bytes());
        }
    }
    let mut reads: Vec<&UnitRead> = unit.reads.iter().collect();
    reads.sort_by_key(|read| read.key_digest);
    for read in reads {
        hash.field("read-kind", read.kind.as_bytes());
        hash.field("read-key", &read.key_digest);
        hash.field("read-digest", &read.digest);
    }
    for dependency in dependencies {
        hash.field("dependency", &dependency.unit_key);
        hash.field("dependency-digest", &dependency.consumed_output_digest);
        hash.field("dependency-boundary", dependency.boundary.as_bytes());
    }
    // The declared input files, in `input_ordinal` order. Exactly one tagged
    // value field follows each path, so the three cases cannot collide.
    assert!(
        unit.input_files
            .windows(2)
            .all(|pair| (pair[0].role.as_str(), &pair[0].rel_path)
                < (pair[1].role.as_str(), &pair[1].rel_path)),
        "declared inputs must be sorted and unique by role and path"
    );
    for file in &unit.input_files {
        hash.field("input-role", file.role.as_str().as_bytes());
        hash.field("input-path", file.rel_path.as_bytes());
        match &file.value {
            InputFileValue::Fingerprint(fingerprint) => {
                hash.field("input-fingerprint", fingerprint)
            }
            InputFileValue::NoFactsOid(oid) => hash.field("input-no-facts-oid", oid.as_bytes()),
            InputFileValue::Absent => hash.field("input-absent", &[]),
        }
    }
    hash_summary_relations(unit, &mut hash);
    Ok(hash.finish())
}

/// The stored, unique identity digest, the second phase: the lookup digest and
/// the consumed set the derivation recorded, in unit key order. It is computed
/// once, at write time, from the recorded set and never recomputed, so two
/// derivations with an equal lookup digest and an equal set write byte-identical
/// digests, and the unique constraint can collide only on equal content.
fn summary_digest(lookup: &[u8; 32], consumed: &[ConsumedUnit]) -> [u8; 32] {
    debug_assert!(
        consumed
            .windows(2)
            .all(|pair| pair[0].unit_key < pair[1].unit_key)
    );
    let mut hash = CanonicalHasher::new(b"bifrost-unit-summary-identity:v1");
    hash.field("lookup", lookup);
    for unit in consumed {
        hash.field("consumed-unit", &unit.unit_key);
        hash.field("consumed-output", &unit.output_digest);
    }
    hash.finish()
}

/// The digest of what a dependent can see of a unit: its exports (identity,
/// namespace, visibility, origin and alias target), whether it is complete, and the
/// `conflicting_names` gaps (two declarations of one name). It leaves out
/// declaration blob ids, sites and keys, and dependency ordinals, which name
/// where a declaration lives or a dependency sits rather than what the unit exports.
/// It leaves out authored imports unless a language publishes their edges to
/// dependent readers through its output supplement (Rust route provenance).
/// Every relation a dependent reads belongs in that language output. An edit that
/// keeps the surface keeps this digest and stops at the unit's dependents.
/// Readers never copy coordinates out of a summary, so an equal digest cannot
/// leave a stale coordinate behind.
fn output_digest(
    unit: &UnitInputs,
    dependencies: &[ConsumedDependency],
    outputs: &UnitOutputs,
) -> [u8; 32] {
    let mut hash = CanonicalHasher::new(b"bifrost-unit-summary-output-content:v1");
    hash.field("complete", &[u8::from(outputs.complete)]);
    let mut exports: Vec<_> = outputs
        .exports
        .iter()
        .map(|export| {
            let alias_dependency_key = export.alias_dependency_ordinal.map(|ordinal| {
                dependencies
                    .iter()
                    .find(|dependency| dependency.ordinal == ordinal)
                    .unwrap_or_else(|| {
                        panic!(
                            "export identity {} references dependency ordinal {ordinal}; consumed dependencies: {:?}",
                            export.identity_id,
                            dependencies
                                .iter()
                                .map(|dependency| (dependency.ordinal, dependency.unit_key))
                                .collect::<Vec<_>>()
                        )
                    })
                    .unit_key
            });
            (
                export.identity_digest,
                export.namespace.as_str(),
                export.visibility,
                export.origin,
                alias_dependency_key,
                export.alias_identity_digest,
            )
        })
        .collect();
    exports.sort_unstable();
    exports.dedup();
    for (identity, namespace, visibility, origin, alias_dependency_key, alias_identity) in exports {
        hash.field("export-identity", &identity);
        hash.field("export-namespace", namespace.as_bytes());
        hash.field("export-visibility", visibility.as_bytes());
        hash.field("export-origin", origin.as_bytes());
        match alias_dependency_key {
            Some(key) => {
                hash.field("export-alias-dependency-present", &[1]);
                hash.field("export-alias-dependency-key", &key);
            }
            None => hash.field("export-alias-dependency-present", &[0]),
        }
        match alias_identity {
            Some(identity) => {
                hash.field("export-alias-identity-present", &[1]);
                hash.field("export-alias-identity", &identity);
            }
            None => hash.field("export-alias-identity-present", &[0]),
        }
    }
    let mut conflicts: Vec<_> = outputs
        .gaps
        .iter()
        .filter(|gap| gap.kind == "conflicting_names")
        .map(|gap| gap.subject.as_str())
        .collect();
    conflicts.sort_unstable();
    conflicts.dedup();
    for subject in conflicts {
        hash.field("conflicting-subject", subject.as_bytes());
    }
    if let Some(digest) = outputs.public_surface_digest {
        hash.field("language-public-surface:v1", &digest);
    }
    hash_summary_containers(unit, &mut hash);
    for placement in &unit.placements {
        hash.field("placement-container", placement.container_path.as_bytes());
        hash.field(
            "placement-member",
            &(placement.member_ordinal as u64).to_be_bytes(),
        );
    }
    hash_summary_dependency_names(unit, &mut hash);
    hash.finish()
}

fn hash_summary_relations(unit: &UnitInputs, hash: &mut CanonicalHasher) {
    // The input digest retains dense scope invalidation while Rust child rows
    // still depend on the derived-from layout. The output digest does not.
    hash_summary_containers(unit, hash);
    for placement in &unit.placements {
        hash.field("placement-container", placement.container_path.as_bytes());
        hash.field(
            "placement-member",
            &(placement.member_ordinal as u64).to_be_bytes(),
        );
        if let Some(scope) = placement.scope_ordinal {
            hash.field("placement-scope", &scope.value().to_be_bytes());
        }
    }
    hash_summary_dependency_names(unit, hash);
}

fn hash_summary_containers(unit: &UnitInputs, hash: &mut CanonicalHasher) {
    for container in &unit.containers {
        hash.field("container", container.path.as_bytes());
        hash.field(
            "parent-container",
            container.parent_path.as_deref().unwrap_or("").as_bytes(),
        );
    }
}

fn hash_summary_dependency_names(unit: &UnitInputs, hash: &mut CanonicalHasher) {
    for binding in &unit.dependency_names {
        hash.field("dependency-role", binding.role.as_bytes());
        hash.field("dependency-name", binding.name.as_bytes());
        if let Some(key) = binding.unit_key {
            hash.field("named-dependency", &key);
        }
    }
}

const EXPORT_INSERT_SQL: &str = "
WITH
 staged AS (SELECT value->>0 identity_id,value->>1 namespace,value->>2 visibility,
 value->>3 origin,value->>4 dependency,value->>5 alias_identity,value->>6 blob,
 value->>7 site,value->>8 declaration,value->>9 member FROM json_each(?2)),
 translated AS (
 SELECT s.*,CASE WHEN member IS NULL THEN 'foreign' ELSE 'own' END target_kind,
 CASE WHEN member IS NULL THEN NULL WHEN site->>'$.Surface' IS NOT NULL THEN site->>'$.Surface' ELSE coalesce((SELECT ids.surface_ordinal FROM main.surface_sets sets JOIN main.surface_ids ids ON ids.set_id=sets.set_id AND ids.id_space=0 AND ids.dense_id=s.site->>'$.Dense' WHERE sets.blob_id=s.blob AND sets.list_digest=?3),-1) END site_surface,
 CASE WHEN member IS NULL THEN NULL WHEN declaration->>'$.Surface' IS NOT NULL THEN declaration->>'$.Surface' ELSE coalesce((SELECT ids.surface_ordinal FROM main.surface_sets sets JOIN main.surface_ids ids ON ids.set_id=sets.set_id AND ids.id_space=1 AND ids.dense_id=s.declaration->>'$.Dense' WHERE sets.blob_id=s.blob AND sets.list_digest=?3),-1) END declaration_surface,
 dep.dependency_unit_key
 FROM staged s
 LEFT JOIN resolution_unit_summary_dependencies dep ON dep.summary_id=?1 AND dep.dependency_ordinal=s.dependency)
INSERT INTO resolution_unit_summary_exports(summary_id,identity_id,namespace,visibility,origin,alias_dependency_ordinal,alias_identity_id,target_kind,declaration_member_ordinal,site_surface_ordinal,declaration_surface_ordinal,export_rank)
SELECT ?1,identity_id,namespace,visibility,origin,dependency,alias_identity,target_kind,member,site_surface,declaration_surface,
 row_number() OVER (PARTITION BY identity_id,namespace ORDER BY target_kind='foreign',member,site_surface,dependency_unit_key,alias_identity)-1
FROM translated RETURNING identity_id,namespace,target_kind";

/// What writing one derived summary produced.
enum Written {
    /// A new summary, sealed, and its output digest.
    Summary(i64, [u8; 32]),
    /// A summary with the identity this derivation arrived at was already intact:
    /// the derivation read exactly the units it had read, at the outputs it had
    /// seen.
    Existing(i64),
}

enum Attempt {
    Sealed(i64, [u8; 32]),
    /// The final identity digest belongs to another summary.
    Duplicate(ExistingSummary),
}

/// The identity digest a header carries until the language rows have been
/// written and the derivation's whole consumed set is known. It is never
/// committed: sealing replaces it, and a rolled-back attempt leaves nothing.
fn building_digest(lookup: &[u8; 32]) -> [u8; 32] {
    let mut hash = CanonicalHasher::new(b"bifrost-unit-summary-building:v1");
    hash.field("lookup", lookup);
    hash.finish()
}

/// Write one summary's header and children, seal it, and give it its identity:
/// the lookup digest and the consumed set the derivation and the language rows
/// recorded. Reads of other units happen in both phases, so the unique digest
/// is final only here. When another summary already has it, this attempt is
/// undone and that summary is reused if it is intact; a summary whose
/// blob-referencing children were lost is rebuilt in place, so version rows that
/// point at it stay valid.
#[allow(clippy::too_many_arguments)]
fn write_summary(
    tx: &Connection,
    language: &dyn UnitSummaryLanguage,
    snapshot: &WorkspaceSnapshotId,
    producer_epoch: &str,
    lookup: &[u8; 32],
    unit: &UnitInputs,
    inputs: &[MemberInput],
    dependencies: &[ConsumedDependency],
    reader: &mut ForeignReader<'_>,
    outputs: &UnitOutputs,
    output_digest: &[u8; 32],
    rows_written: &mut usize,
) -> Result<Written> {
    let rows_before = *rows_written;
    tx.execute_batch("SAVEPOINT unit_summary_attempt")?;
    let attempt = write_summary_attempt(
        tx,
        language,
        snapshot,
        producer_epoch,
        lookup,
        None,
        unit,
        inputs,
        dependencies,
        reader,
        outputs,
        output_digest,
        rows_written,
    )?;
    match attempt {
        Attempt::Sealed(summary_id, output_digest) => {
            tx.execute_batch("RELEASE unit_summary_attempt")?;
            Ok(Written::Summary(summary_id, output_digest))
        }
        Attempt::Duplicate(existing) => {
            tx.execute_batch("ROLLBACK TO unit_summary_attempt; RELEASE unit_summary_attempt")?;
            *rows_written = rows_before;
            if existing.intact {
                return Ok(Written::Existing(existing.summary_id));
            }
            match write_summary_attempt(
                tx,
                language,
                snapshot,
                producer_epoch,
                lookup,
                Some(existing.summary_id),
                unit,
                inputs,
                dependencies,
                reader,
                outputs,
                output_digest,
                rows_written,
            )? {
                Attempt::Sealed(summary_id, output_digest) => {
                    Ok(Written::Summary(summary_id, output_digest))
                }
                Attempt::Duplicate(other) => panic!(
                    "{}: rebuilding summary {} reached the identity of summary {}",
                    unit.label, existing.summary_id, other.summary_id
                ),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn write_summary_attempt(
    tx: &Connection,
    language: &dyn UnitSummaryLanguage,
    snapshot: &WorkspaceSnapshotId,
    producer_epoch: &str,
    lookup: &[u8; 32],
    replace: Option<i64>,
    unit: &UnitInputs,
    inputs: &[MemberInput],
    dependencies: &[ConsumedDependency],
    reader: &mut ForeignReader<'_>,
    outputs: &UnitOutputs,
    output_digest: &[u8; 32],
    rows_written: &mut usize,
) -> Result<Attempt> {
    let _owner = super::sealed_families::Scope::new(tx, super::sealed_families::Owner::UnitSummary);
    let summary_id = match replace {
        Some(summary_id) => {
            tx.execute(
                "UPDATE resolution_unit_summaries SET publication_state = 'building',
                        output_digest = NULL, member_count = 0, export_count = 0, import_count = 0
                 WHERE summary_id = ?1",
                [summary_id],
            )?;
            tx.execute(
                "DELETE FROM resolution_unit_summary_dependency_names WHERE summary_id=?1",
                [summary_id],
            )?;
            tx.execute(
                "DELETE FROM resolution_unit_summary_containers WHERE summary_id=?1",
                [summary_id],
            )?;
            for table in [
                "resolution_unit_summary_imports",
                "resolution_unit_summary_exports",
                "resolution_unit_summary_gaps",
                "resolution_unit_summary_reads",
                "resolution_unit_summary_consumed_units",
                "resolution_unit_summary_dependencies",
                "resolution_unit_summary_members",
            ] {
                tx.execute(
                    &format!("DELETE FROM {table} WHERE summary_id = ?1"),
                    [summary_id],
                )?;
            }
            summary_id
        }
        None => {
            tx.prepare_cached(
                "INSERT INTO resolution_unit_summaries(lang, unit_kind, unit_key, summary_digest,
                        lookup_digest, producer_epoch, derivation_identity, complete, publication_state)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, 'building')",
            )?
            .execute(params![
                language.lang(),
                language.unit_kind(),
                unit.unit_key.as_slice(),
                building_digest(lookup).as_slice(),
                lookup.as_slice(),
                producer_epoch,
                language.derivation_identity()
            ])?;
            tx.last_insert_rowid()
        }
    };
    *rows_written += 1;
    let members: Vec<_> = unit
        .members
        .iter()
        .enumerate()
        .map(|(ordinal, m)| {
            // Rust alone retains the derived-from blob until M3. Go/Python
            // summaries bind current facts through member paths and re-key on
            // repair; they are reusable across blobs and bypass blob withdrawal.
            let blob = match language.lang() {
                "rust" => Some(m.blob_id),
                "go" | "python" => None,
                other => unreachable!("unsupported unit summary language: {other}"),
            };
            assert_eq!(blob.is_some(), language.lang() == "rust");
            // The recorded input is the value the key hashed; liveness compares
            // it with the selected blob's current input.
            let (fingerprint, no_facts_oid) = match inputs.get(ordinal) {
                Some(MemberInput::Surface(fingerprint)) => {
                    (Some(lower_hex_string(fingerprint)), None)
                }
                Some(MemberInput::NoFactsOid(oid)) => (None, Some(oid.as_str())),
                None => (None, None),
            };
            serde_json::json!([
                ordinal,
                blob,
                m.rel_path,
                m.source_role,
                fingerprint,
                no_facts_oid
            ])
        })
        .collect();
    tx.execute("INSERT INTO resolution_unit_summary_members(summary_id,member_ordinal,blob_id,rel_path,source_role,member_surface_fingerprint,member_no_facts_oid) SELECT ?1,value->>0,value->>1,value->>2,value->>3,unhex(value->>4),value->>5 FROM json_each(?2)", params![summary_id,serde_json::to_string(&members).expect("members serialize")])?;
    let provenance: std::collections::HashMap<_, _> = unit
        .dependencies
        .iter()
        .map(|d| (d.unit_key, d.provenance.as_deref()))
        .collect();
    let deps: Vec<_> = dependencies
        .iter()
        .map(|d| {
            serde_json::json!([
                d.ordinal,
                lower_hex_string(&d.unit_key),
                lower_hex_string(&d.consumed_output_digest),
                d.boundary,
                provenance[&d.unit_key]
            ])
        })
        .collect();
    tx.execute("INSERT INTO resolution_unit_summary_dependencies SELECT ?1,value->>0,unhex(value->>1),unhex(value->>2),value->>3,value->>4 FROM json_each(?2)",params![summary_id,serde_json::to_string(&deps).expect("dependencies serialize")])?;
    let mut reads: Vec<_> = unit.reads.iter().collect();
    reads.sort_by_key(|r| r.key_digest);
    let reads: Vec<_> = reads
        .iter()
        .enumerate()
        .map(|(ordinal, r)| {
            serde_json::json!([
                ordinal,
                r.kind,
                lower_hex_string(&r.key_digest),
                lower_hex_string(&r.digest)
            ])
        })
        .collect();
    tx.execute("INSERT INTO resolution_unit_summary_reads SELECT ?1,value->>0,value->>1,unhex(value->>2),unhex(value->>3) FROM json_each(?2)",params![summary_id,serde_json::to_string(&reads).expect("reads serialize")])?;
    let exports: Vec<_> = outputs
        .exports
        .iter()
        .map(|e| {
            e.declaration_site.assert_language(language.lang());
            e.declaration_key.assert_language(language.lang());
            let member = (e.declaration_unit_key == unit.unit_key)
                .then(|| {
                    unit.members
                        .iter()
                        .position(|m| m.blob_id == e.declaration_blob_id)
                })
                .flatten();
            assert!(
                member.is_some() || language.lang() == "rust",
                "only Rust publishes foreign exports"
            );
            serde_json::json!([
                e.identity_id,
                e.namespace,
                e.visibility,
                e.origin,
                e.alias_dependency_ordinal,
                e.alias_identity_id,
                e.declaration_blob_id,
                e.declaration_site,
                e.declaration_key,
                member
            ])
        })
        .collect();
    let mut statement = tx.prepare_cached(EXPORT_INSERT_SQL)?;
    let mut translated = statement.query(params![
        summary_id,
        serde_json::to_string(&exports).expect("export rows serialize"),
        super::surface_relations::surface_list_digest(language.lang())
    ])?;
    let identities: std::collections::HashMap<_, _> = outputs
        .exports
        .iter()
        .map(|e| (e.identity_id, e.identity_digest))
        .collect();
    let mut targets = Vec::new();
    while let Some(row) = translated.next()? {
        let identity: i64 = row.get(0)?;
        targets.push((
            identities[&identity],
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ));
    }
    targets.sort_unstable();
    let imports: Vec<_> = outputs
        .imports
        .iter()
        .map(|i| {
            i.import_id.assert_language(language.lang());
            if let Some(coordinate) = i.definition_key {
                coordinate.assert_language(language.lang());
            }
            let member = unit
                .members
                .iter()
                .position(|m| m.blob_id == i.blob_id)
                .expect("summary import belongs to a member");
            serde_json::json!([
                member,
                i.blob_id,
                i.import_id,
                i.kind,
                i.definition_key,
                i.dependency_ordinal,
                i.state
            ])
        })
        .collect();
    let (import_space, site_space) = match language.lang() {
        "go" => (5, 1),
        "rust" => (4, 4),
        "python" => {
            assert!(imports.is_empty());
            (1, 0)
        }
        lang => panic!("unexpected import language {lang}"),
    };
    tx.execute("INSERT INTO resolution_unit_summary_imports(summary_id,member_ordinal,import_surface_ordinal,kind,site_surface_ordinal,dependency_ordinal,state)
      SELECT ?1,j.value->>0,coalesce(j.value->>'$[2].Surface',(SELECT ids.surface_ordinal FROM main.surface_sets sets JOIN main.surface_ids ids ON ids.set_id=sets.set_id AND ids.id_space=?3 AND ids.dense_id=j.value->>'$[2].Dense' WHERE sets.blob_id=j.value->>1 AND sets.list_digest=?5)),j.value->>3,CASE WHEN j.value->>4 IS NULL THEN NULL ELSE coalesce(j.value->>'$[4].Surface',(SELECT ids.surface_ordinal FROM main.surface_sets sets JOIN main.surface_ids ids ON ids.set_id=sets.set_id AND ids.id_space=?4 AND ids.dense_id=j.value->>'$[4].Dense' WHERE sets.blob_id=j.value->>1 AND sets.list_digest=?5),-1) END,j.value->>5,j.value->>6
      FROM json_each(?2) j",
      params![summary_id,serde_json::to_string(&imports).expect("import rows serialize"),import_space,site_space,super::surface_relations::surface_list_digest(language.lang())])?;
    let gaps: Vec<_> = outputs
        .gaps
        .iter()
        .map(|g| serde_json::json!([g.kind, g.subject, g.detail]))
        .collect();
    tx.execute("INSERT INTO resolution_unit_summary_gaps SELECT ?1,value->>0,value->>1,jsonb(value->>2) FROM json_each(?2)",params![summary_id,serde_json::to_string(&gaps).expect("gaps serialize")])?;
    let containers: Vec<_> = unit
        .containers
        .iter()
        .map(|c| serde_json::json!([c.path, c.parent_path]))
        .collect();
    *rows_written += tx.execute("INSERT INTO resolution_unit_summary_containers SELECT ?1,value->>0,value->>1 FROM json_each(?2)",params![summary_id,serde_json::to_string(&containers).expect("containers serialize")])?;
    let placements: Vec<_> = unit
        .placements
        .iter()
        .map(|p| {
            if let Some(coordinate) = p.scope_ordinal {
                coordinate.assert_language(language.lang());
            }
            serde_json::json!([
                p.container_path,
                p.member_ordinal,
                unit.members[p.member_ordinal].blob_id,
                p.scope_ordinal
            ])
        })
        .collect();
    *rows_written += tx.execute("INSERT INTO resolution_unit_summary_placements(summary_id,container_path,member_ordinal,scope_surface_ordinal)
      SELECT ?1,j.value->>0,j.value->>1,CASE WHEN j.value->>3 IS NULL THEN NULL ELSE coalesce(j.value->>'$[3].Surface',(SELECT ids.surface_ordinal FROM main.surface_sets sets JOIN main.surface_ids ids ON ids.set_id=sets.set_id AND ids.id_space=7 AND ids.dense_id=j.value->>'$[3].Dense' WHERE sets.blob_id=j.value->>2 AND sets.list_digest=?3),-1) END
      FROM json_each(?2) j",
      params![summary_id,serde_json::to_string(&placements).expect("placement rows serialize"),super::surface_relations::surface_list_digest(language.lang())])?;
    let ordinals = dependency_ordinals(dependencies);
    let names: Vec<_> = unit
        .dependency_names
        .iter()
        .map(|b| serde_json::json!([b.role, b.name, b.unit_key.map(|k| ordinals[&k])]))
        .collect();
    *rows_written += tx.execute("INSERT INTO resolution_unit_summary_dependency_names SELECT ?1,value->>0,value->>1,value->>2 FROM json_each(?2)",params![summary_id,serde_json::to_string(&names).expect("names serialize")])?;
    *rows_written +=
        language.write_language_rows(tx, snapshot, unit, dependencies, summary_id, reader)?;
    // The language child rows exist now, so what a foreign reader reads of them can be
    // hashed into the output.
    let mut hash = CanonicalHasher::new(b"bifrost-unit-summary-output:v5");
    hash.field("content", output_digest);
    for (identity, namespace, target_kind) in targets {
        hash.field("identity", &identity);
        hash.field("namespace", namespace.as_bytes());
        hash.field("target-kind", target_kind.as_bytes());
    }
    if let Some(supplement) = language.output_supplement(tx, summary_id)? {
        hash.field("language-child-rows:v1", &supplement);
    }
    let output_digest = hash.finish();
    // Every unit the derivation and the language rows read beyond the direct
    // dependencies is recorded now, so the identity is known.
    let consumed = reader.consumed();
    let digest = summary_digest(lookup, &consumed);
    if let Some(existing) = find_summary(tx, &digest, summary_id)? {
        assert!(
            replace.is_none(),
            "{}: rebuilding summary {summary_id} reached the identity of summary {}",
            unit.label,
            existing.summary_id
        );
        return Ok(Attempt::Duplicate(existing));
    }
    // An empty set (a language that reads no other unit) writes no statement.
    if !consumed.is_empty() {
        let rows: Vec<_> = consumed
            .iter()
            .map(|c| {
                let has = |kind| u8::from(c.kinds.contains(&kind));
                serde_json::json!([
                    lower_hex_string(&c.unit_key),
                    lower_hex_string(&c.output_digest),
                    c.summary_id,
                    has(ReadKind::ReexportHop),
                    has(ReadKind::ModuleHop),
                    has(ReadKind::Endpoint),
                    has(ReadKind::Absence),
                    has(ReadKind::ClosureBindings),
                    has(ReadKind::TraitEndpoint)
                ])
            })
            .collect();
        let written = tx.execute("INSERT INTO resolution_unit_summary_consumed_units SELECT ?1,unhex(value->>0),unhex(value->>1),value->>2,value->>3,value->>4,value->>5,value->>6,value->>7,value->>8 FROM json_each(?2)",params![summary_id,serde_json::to_string(&rows).expect("consumed units serialize")])?;
        assert_eq!(written, consumed.len(), "consumed rows of {}", unit.label);
        *rows_written += written;
    }
    let counts = |table: &str| -> Result<usize> {
        Ok(tx.query_row(
            &format!("SELECT count(*) FROM {table} WHERE summary_id = ?1"),
            [summary_id],
            |row| row.get(0),
        )?)
    };
    let (members, exports, imports) = (
        counts("resolution_unit_summary_members")?,
        counts("resolution_unit_summary_exports")?,
        counts("resolution_unit_summary_imports")?,
    );
    assert_eq!(members, unit.members.len(), "member rows of {}", unit.label);
    assert_eq!(
        exports,
        outputs.exports.len(),
        "export rows of {}",
        unit.label
    );
    assert_eq!(
        imports,
        outputs.imports.len(),
        "import rows of {}",
        unit.label
    );
    assert_eq!(
        counts("resolution_unit_summary_dependencies")?,
        dependencies.len(),
        "dependency rows of {}",
        unit.label
    );
    *rows_written +=
        members + exports + imports + dependencies.len() + unit.reads.len() + outputs.gaps.len();
    super::publication::seal(
        tx,
        "resolution_unit_summaries",
        "summary_id",
        summary_id,
        &[
            ("complete", &outputs.complete),
            ("member_count", &members),
            ("export_count", &exports),
            ("import_count", &imports),
            ("output_digest", &output_digest.as_slice()),
            ("summary_digest", &digest.as_slice()),
        ],
    )?;
    Ok(Attempt::Sealed(summary_id, output_digest))
}

#[cfg(test)]
mod reconciliation_report_tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Copy)]
    struct FixtureUnit {
        key: [u8; 32],
        input: u8,
        surface: u8,
    }

    #[derive(Clone)]
    struct Fixture(Arc<Mutex<Vec<FixtureUnit>>>);

    impl UnitSummaryLanguage for Fixture {
        fn lang(&self) -> &'static str {
            "rust"
        }
        fn unit_kind(&self) -> &'static str {
            "rust_crate"
        }
        fn derivation_identity(&self) -> [u8; 32] {
            [1; 32]
        }
        fn stage(&self, conn: &Connection, _: &WorkspaceSnapshotId) -> Result<()> {
            for (ordinal, _) in self.0.lock().unwrap().iter().enumerate() {
                conn.execute(
                    "INSERT INTO temp.unit_summary_work(unit_id) VALUES(?1)",
                    [ordinal as i64 + 1],
                )?;
            }
            Ok(())
        }
        fn inputs(
            &self,
            _: &Connection,
            _: &WorkspaceSnapshotId,
            unit_id: i64,
        ) -> Result<UnitInputs> {
            let FixtureUnit { key, input, .. } = self.0.lock().unwrap()[unit_id as usize - 1];
            Ok(UnitInputs {
                unit_id,
                unit_key: key,
                label: format!("crate-{unit_id}"),
                members: vec![],
                input_files: Vec::new(),
                reads: vec![UnitRead {
                    kind: "configuration",
                    key_digest: [0; 32],
                    digest: [input; 32],
                }],
                dependencies: vec![],
                dependency_names: vec![],
                containers: vec![],
                placements: vec![],
            })
        }
        fn derive(
            &self,
            _: &Connection,
            _: &WorkspaceSnapshotId,
            unit: &UnitInputs,
            _: &[ConsumedDependency],
            _: &str,
            _: &mut ForeignReader<'_>,
        ) -> Result<UnitOutputs> {
            let surface = self.0.lock().unwrap()[unit.unit_id as usize - 1].surface;
            Ok(UnitOutputs {
                exports: vec![],
                imports: vec![],
                gaps: vec![],
                complete: true,
                public_surface_digest: Some([surface; 32]),
            })
        }
    }

    #[test]
    fn reconciliation_reports_only_changed_live_unit_outputs() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store.conn.execute(|conn| conn.execute(
            "INSERT INTO resolution_producer_epochs(lang, producer_epoch) VALUES('rust', 'fixture')", []
        )).unwrap();
        let fixture = Fixture(Arc::new(Mutex::new(vec![FixtureUnit {
            key: [1; 32],
            input: 1,
            surface: 1,
        }])));
        let mut snapshot = WorkspaceSnapshotId {
            workspace_id: super::super::WorkspaceId("a".repeat(64)),
            lang: "rust".into(),
            generation: super::super::GenerationId::from_persisted(0),
            revision: 1,
        };
        let run = |snapshot: &WorkspaceSnapshotId| {
            store
                .reconcile_unit_summaries(snapshot, fixture.clone(), &CancellationToken::default())
                .unwrap()
        };
        let first = run(&snapshot);
        assert_eq!(first.added, vec![("rust".into(), [1; 32])], "{first:?}");
        fixture.0.lock().unwrap()[0].input = 2;
        snapshot.revision += 1;
        let body = run(&snapshot);
        assert!(
            body.output_changed.is_empty() && body.added.is_empty() && body.closed.is_empty(),
            "{body:?}"
        );
        fixture.0.lock().unwrap()[0] = FixtureUnit {
            key: [1; 32],
            input: 3,
            surface: 2,
        };
        snapshot.revision += 1;
        let surface = run(&snapshot);
        assert_eq!(
            surface.output_changed,
            vec![("rust".into(), [1; 32])],
            "{surface:?}"
        );
        fixture.0.lock().unwrap().push(FixtureUnit {
            key: [2; 32],
            input: 1,
            surface: 1,
        });
        snapshot.revision += 1;
        let added = run(&snapshot);
        assert_eq!(added.added, vec![("rust".into(), [2; 32])], "{added:?}");
        fixture.0.lock().unwrap().pop();
        snapshot.revision += 1;
        let closed = run(&snapshot);
        assert_eq!(closed.closed, vec![("rust".into(), [2; 32])], "{closed:?}");
        fixture.0.lock().unwrap()[0] = FixtureUnit {
            key: [1; 32],
            input: 2,
            surface: 1,
        };
        snapshot.revision += 1;
        let rebound = run(&snapshot);
        assert_eq!(
            (rebound.rebound_count, &rebound.output_changed),
            (1, &vec![("rust".into(), [1; 32])]),
            "{rebound:?}"
        );
    }
}

#[cfg(test)]
mod consumed_set_tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// A unit with an input, a surface and the units its derivation reads
    /// beyond any direct dependency (unit ids, 1-based).
    #[derive(Clone)]
    struct Unit {
        key: [u8; 32],
        input: u8,
        surface: u8,
        consumes: Vec<usize>,
        /// Units whose keys the derivation reads with no ordering edge.
        peeks: Vec<[u8; 32]>,
        /// Units read while the summary rows are written.
        write_peeks: Vec<[u8; 32]>,
        /// Units whose closure bindings the derivation reads, with no ordering edge.
        closure_peeks: Vec<[u8; 32]>,
    }

    #[derive(Clone)]
    struct Fixture(Arc<Mutex<Vec<Unit>>>, Arc<std::sync::atomic::AtomicI64>);

    impl Fixture {
        fn new(units: Vec<Unit>) -> Self {
            Self(
                Arc::new(Mutex::new(units)),
                Arc::new(std::sync::atomic::AtomicI64::new(FIXPOINT_ROUNDS)),
            )
        }
    }

    impl UnitSummaryLanguage for Fixture {
        fn lang(&self) -> &'static str {
            "rust"
        }
        fn unit_kind(&self) -> &'static str {
            "rust_crate"
        }
        fn derivation_identity(&self) -> [u8; 32] {
            [1; 32]
        }
        fn fixpoint_rounds(&self) -> i64 {
            self.1.load(std::sync::atomic::Ordering::Relaxed)
        }
        fn stage(&self, conn: &Connection, _: &WorkspaceSnapshotId) -> Result<()> {
            for (index, unit) in self.0.lock().unwrap().iter().enumerate() {
                let unit_id = index as i64 + 1;
                conn.execute(
                    "INSERT INTO temp.unit_summary_work(unit_id) VALUES(?1)",
                    [unit_id],
                )?;
                // Consumed units order the pass; they are not direct dependencies.
                for consumed in &unit.consumes {
                    conn.execute(
                        "INSERT INTO temp.unit_summary_edges(unit_id, dependency_unit_id) VALUES(?1, ?2)",
                        [unit_id, *consumed as i64],
                    )?;
                }
            }
            Ok(())
        }
        fn inputs(
            &self,
            _: &Connection,
            _: &WorkspaceSnapshotId,
            unit_id: i64,
        ) -> Result<UnitInputs> {
            let unit = self.0.lock().unwrap()[unit_id as usize - 1].clone();
            Ok(UnitInputs {
                unit_id,
                unit_key: unit.key,
                label: format!("unit-{unit_id}"),
                members: vec![],
                input_files: Vec::new(),
                reads: vec![UnitRead {
                    kind: "configuration",
                    key_digest: [0; 32],
                    digest: [unit.input; 32],
                }],
                dependencies: vec![],
                dependency_names: vec![],
                containers: vec![],
                placements: vec![],
            })
        }
        fn derive(
            &self,
            _: &Connection,
            _: &WorkspaceSnapshotId,
            unit: &UnitInputs,
            _: &[ConsumedDependency],
            _: &str,
            consumed: &mut ForeignReader<'_>,
        ) -> Result<UnitOutputs> {
            let units = self.0.lock().unwrap().clone();
            let this = &units[unit.unit_id as usize - 1];
            for other in &this.consumes {
                let key = units[other - 1].key;
                consumed
                    .consume(key, ReadKind::Endpoint)?
                    .expect("a consumed unit settles before its consumer");
            }
            let mut degraded = false;
            for key in &this.peeks {
                // Unordered: the unit may not have settled yet, or may not exist.
                degraded |= consumed.consume(*key, ReadKind::Absence)?.is_none();
            }
            for key in &this.closure_peeks {
                degraded |= consumed.consume(*key, ReadKind::ClosureBindings)?.is_none();
            }
            Ok(UnitOutputs {
                exports: vec![],
                imports: vec![],
                gaps: vec![],
                complete: true,
                // A unit that read an unavailable unit publishes a different surface.
                public_surface_digest: Some([if degraded { 0xEE } else { this.surface }; 32]),
            })
        }
        fn write_language_rows(
            &self,
            _: &Connection,
            _: &WorkspaceSnapshotId,
            unit: &UnitInputs,
            _: &[ConsumedDependency],
            _: i64,
            reader: &mut ForeignReader<'_>,
        ) -> Result<usize> {
            let this = self.0.lock().unwrap()[unit.unit_id as usize - 1].clone();
            for key in &this.write_peeks {
                reader.consume(*key, ReadKind::Absence)?;
            }
            Ok(0)
        }
    }

    fn producer(key: u8, input: u8) -> Unit {
        Unit {
            key: [key; 32],
            input,
            surface: input,
            consumes: vec![],
            peeks: vec![],
            write_peeks: vec![],
            closure_peeks: vec![],
        }
    }

    fn open_store() -> AnalyzerStore {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .conn
            .execute(|conn| {
                conn.execute(
                    "INSERT INTO resolution_producer_epochs(lang, producer_epoch) VALUES('rust', 'fixture')",
                    [],
                )
            })
            .unwrap();
        store
    }

    fn snapshot(revision: i64) -> WorkspaceSnapshotId {
        WorkspaceSnapshotId {
            workspace_id: super::super::WorkspaceId("a".repeat(64)),
            lang: "rust".into(),
            generation: super::super::GenerationId::from_persisted(0),
            revision,
        }
    }

    fn run(store: &AnalyzerStore, fixture: &Fixture, revision: i64) -> UnitSummaryReconciliation {
        store
            .reconcile_unit_summaries(
                &snapshot(revision),
                fixture.clone(),
                &CancellationToken::default(),
            )
            .unwrap()
    }

    /// The summary id the unit's open version row points at.
    fn live_id(store: &AnalyzerStore, key: u8) -> i64 {
        store
            .conn
            .execute(move |conn| {
                conn.query_row(
                    "SELECT summary_id FROM resolution_unit_summary_versions
                     WHERE unit_key = ?1 AND valid_until IS NULL",
                    [[key; 32].as_slice()],
                    |row| row.get(0),
                )
            })
            .unwrap()
    }

    /// (consumed unit key byte, consumed output digest) rows of one summary.
    fn consumed_rows(store: &AnalyzerStore, summary_id: i64) -> Vec<(u8, Vec<u8>)> {
        store
            .conn
            .execute(move |conn| {
                conn.prepare(
                    "SELECT consumed_unit_key, consumed_output_digest
                     FROM resolution_unit_summary_consumed_units
                     WHERE summary_id = ?1 ORDER BY consumed_unit_key",
                )?
                .query_map([summary_id], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?[0], row.get::<_, Vec<u8>>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()
            })
            .unwrap()
    }

    fn output_of(store: &AnalyzerStore, summary_id: i64) -> Vec<u8> {
        store
            .conn
            .execute(move |conn| summary_output(conn, summary_id).map_err(|e| e.to_string()))
            .unwrap()
    }

    /// A candidate whose recorded consumed unit moved is not reused and not
    /// changed; a candidate whose recorded outputs hold again is reused.
    #[test]
    fn reuse_follows_the_recorded_consumed_outputs() {
        let store = open_store();
        let consumer = Unit {
            key: [2; 32],
            input: 1,
            surface: 1,
            consumes: vec![1],
            peeks: vec![],
            write_peeks: vec![],
            closure_peeks: vec![],
        };
        let fixture = Fixture::new(vec![producer(1, 1), consumer]);

        let first = run(&store, &fixture, 1);
        assert_eq!((first.derived, first.rebound_count), (2, 0), "{first:?}");
        let (consumer_v1, producer_v1) = (live_id(&store, 2), live_id(&store, 1));
        let producer_output_v1 = output_of(&store, producer_v1);
        assert_eq!(
            consumed_rows(&store, consumer_v1),
            vec![(1, producer_output_v1.clone())]
        );

        // The producer's output moves; the consumer's own inputs and direct
        // dependencies did not, so its lookup digest is the same. Its summary
        // recorded the old producer output, so it must be derived again.
        fixture.0.lock().unwrap()[0] = producer(1, 2);
        let second = run(&store, &fixture, 2);
        assert_eq!((second.derived, second.unchanged), (2, 0), "{second:?}");
        let consumer_v2 = live_id(&store, 2);
        assert_ne!(consumer_v2, consumer_v1);
        let producer_output_v2 = output_of(&store, live_id(&store, 1));
        assert_ne!(producer_output_v1, producer_output_v2);
        assert_eq!(
            consumed_rows(&store, consumer_v2),
            vec![(1, producer_output_v2.clone())]
        );
        // The old summary is immutable: older revisions still point at it.
        assert_eq!(
            consumed_rows(&store, consumer_v1),
            vec![(1, producer_output_v1)]
        );
        let lookups: Vec<Vec<u8>> = store
            .conn
            .execute(move |conn| {
                conn.prepare("SELECT lookup_digest FROM resolution_unit_summaries WHERE summary_id IN (?1, ?2)")?
                    .query_map([consumer_v1, consumer_v2], |row| row.get(0))?
                    .collect::<rusqlite::Result<_>>()
            })
            .unwrap();
        assert_eq!(lookups[0], lookups[1], "equal lookup, different sets");

        // The producer returns to its first output: the first consumer summary
        // is valid again and the consumer is rebound to it without a derivation.
        fixture.0.lock().unwrap()[0] = producer(1, 1);
        let third = run(&store, &fixture, 3);
        assert_eq!((third.derived, third.rebound_count), (0, 2), "{third:?}");
        assert_eq!(live_id(&store, 2), consumer_v1);
        assert_eq!(live_id(&store, 1), producer_v1);
    }

    /// Two derivations with an equal lookup digest and an equal recorded set
    /// store byte-identical digests, whichever order the reads were recorded in.
    #[test]
    fn equal_lookup_and_equal_set_give_equal_summary_digests() {
        let digests = || {
            let store = open_store();
            let fixture = Fixture::new(vec![
                producer(1, 1),
                producer(3, 3),
                Unit {
                    key: [2; 32],
                    input: 1,
                    surface: 1,
                    consumes: vec![2, 1],
                    peeks: vec![],
                    write_peeks: vec![],
                    closure_peeks: vec![],
                },
            ]);
            run(&store, &fixture, 1);
            let id = live_id(&store, 2);
            store
                .conn
                .execute(move |conn| {
                    conn.query_row(
                        "SELECT summary_digest, lookup_digest FROM resolution_unit_summaries WHERE summary_id = ?1",
                        [id],
                        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
                    )
                })
                .unwrap()
        };
        let (first, lookup) = digests();
        assert_eq!((first.clone(), lookup.clone()), digests());
        assert_ne!(first, lookup);

        let lookup: [u8; 32] = lookup.try_into().unwrap();
        let unit = |key: u8, digest: u8| ConsumedUnit {
            unit_key: [key; 32],
            output_digest: [digest; 32],
            summary_id: None,
            kinds: Default::default(),
        };
        let base = summary_digest(&lookup, &[unit(1, 9), unit(3, 9)]);
        assert_ne!(base, summary_digest(&lookup, &[unit(1, 9), unit(3, 8)]));
        assert_ne!(base, summary_digest(&lookup, &[unit(1, 9)]));
        assert_ne!(base, summary_digest(&[0; 32], &[unit(1, 9), unit(3, 9)]));
        let mut reads = ConsumedReads::default();
        for key in [3, 1, 3] {
            reads.record([key; 32], [9; 32], None, ReadKind::Absence);
        }
        assert_eq!(base, summary_digest(&lookup, &reads.sorted()));
    }

    /// A summary written before the migration has an empty consumed set and
    /// its lookup digest equals its summary digest: it stays reusable.
    #[test]
    fn a_pre_migration_summary_stays_reusable() {
        let store = open_store();
        let fixture = Fixture::new(vec![producer(1, 1)]);
        run(&store, &fixture, 1);
        store
            .conn
            .execute(|conn| {
                let _fixture = super::super::sealed_families::Fixture::new(conn);
                conn.execute_batch(
                    "UPDATE resolution_unit_summaries SET summary_digest = lookup_digest",
                )
            })
            .unwrap();
        let again = run(&store, &fixture, 2);
        assert_eq!((again.unchanged, again.derived), (1, 0), "{again:?}");
    }

    /// Validation cost in SQLite VM steps for a consumer of `n` units with
    /// `history` unreachable candidates under the same lookup digest. Returns
    /// the steps of the recorded-set check and of the candidate seek.
    fn validation_steps(n: usize, history: usize) -> (i64, i64) {
        let consumer = Unit {
            key: [200; 32],
            input: 1,
            surface: 1,
            consumes: (1..=n).collect(),
            peeks: vec![],
            write_peeks: vec![],
            closure_peeks: vec![],
        };
        let mut units: Vec<Unit> = (1..=n as u8).map(|key| producer(key, 1)).collect();
        units.push(consumer);
        let fixture = Fixture::new(units);
        // The lookup digest depends on the unit's inputs only, so a scratch
        // store names it before the real store gets its history.
        let lookup: Vec<u8> = {
            let scratch = open_store();
            run(&scratch, &fixture, 1);
            let id = live_id(&scratch, 200);
            scratch
                .conn
                .execute(move |conn| {
                    conn.query_row(
                        "SELECT lookup_digest FROM resolution_unit_summaries WHERE summary_id = ?1",
                        [id],
                        |row| row.get(0),
                    )
                })
                .unwrap()
        };
        let store = open_store();
        let stale = lookup.clone();
        store
            .conn
            .execute(move |conn| -> rusqlite::Result<()> {
                let _fixture = super::super::sealed_families::Fixture::new(conn);
                for index in 0..history {
                    let digest = [index as u8, (index >> 8) as u8, 99]
                        .into_iter()
                        .chain([0; 29])
                        .collect::<Vec<u8>>();
                    conn.execute(
                        "INSERT INTO resolution_unit_summaries(lang,unit_kind,unit_key,summary_digest,lookup_digest,producer_epoch,derivation_identity,complete,output_digest,publication_state)
                         VALUES('rust','rust_crate',?1,?2,?3,'fixture',x'0101010101010101010101010101010101010101010101010101010101010101',1,?2,'complete')",
                        rusqlite::params![[200u8; 32].as_slice(), digest, stale],
                    )?;
                    // Each recorded the first consumed unit at a stale output.
                    conn.execute(
                        "INSERT INTO resolution_unit_summary_consumed_units
                         VALUES(last_insert_rowid(), ?1, x'0100000000000000000000000000000000000000000000000000000000000000', NULL, 0, 0, 1, 0, 0, 0)",
                        [[1u8; 32].as_slice()],
                    )?;
                }
                Ok(())
            })
            .unwrap();
        run(&store, &fixture, 1);
        let open = live_id(&store, 200);
        assert_eq!(consumed_rows(&store, open).len(), n);
        store
            .conn
            .execute(move |conn| -> (i64, i64) {
                for key in 1..=n as i64 {
                    conn.execute(
                        "INSERT INTO temp.unit_summary_order(ordinal, unit_id, unit_key) VALUES(?1, ?1, ?2)",
                        rusqlite::params![key, [key as u8; 32].as_slice()],
                    )
                    .unwrap();
                }
                let snapshot = snapshot(1);
                let selection = Selection {
                    snapshot: &snapshot,
                    lang: "rust",
                    profile: [0; 32],
                    producer_epoch: "fixture",
                    derivation_identity: [1; 32],
                };
                let lookup: [u8; 32] = lookup.try_into().unwrap();
                let steps = |statement: &rusqlite::Statement<'_>| {
                    i64::from(statement.get_status(rusqlite::StatementStatus::VmStep))
                };
                // The check of the recorded set, as `reusable_summary` runs it.
                let mut check = conn.prepare(CONSUMED_UNITS_CURRENT_SQL).unwrap();
                let current = check
                    .query_row(
                        rusqlite::params![
                            snapshot.workspace_id.as_str(),
                            "rust",
                            snapshot.generation.get(),
                            open,
                            snapshot.revision,
                            "fixture",
                            selection.derivation_identity,
                            selection.profile.as_slice()
                        ],
                        |row| row.get::<_, bool>(0),
                    )
                    .unwrap();
                assert!(current);
                assert_eq!(
                    summary_valid_now(conn, open, &selection).unwrap(),
                    SummaryValidity::Valid
                );
                // The seek for the other candidates, up to the first row it yields.
                let mut seek = conn.prepare(OTHER_CANDIDATES_SQL).unwrap();
                let mut rows = seek
                    .query(rusqlite::params![lookup.as_slice(), Option::<i64>::None])
                    .unwrap();
                let first: i64 = rows.next().unwrap().unwrap().get(0).unwrap();
                drop(rows);
                assert_eq!(first, open);
                assert_eq!(
                    reusable_summary(conn, &selection, &lookup, None).unwrap(),
                    Some((open, true))
                );
                (steps(&check), steps(&seek))
            })
    }

    #[test]
    fn validation_cost_follows_the_consumed_set_and_not_the_history() {
        let measured: Vec<_> = [1, 8, 32]
            .into_iter()
            .map(|n| (n, validation_steps(n, 0), validation_steps(n, 200)))
            .collect();
        for (n, bare, with_history) in &measured {
            assert_eq!(bare, with_history, "history changed the cost of n={n}");
        }
        // Per consumed unit the cost is constant: equal increments per unit.
        let [
            (_, (open_1, seek_1), _),
            (_, (open_8, seek_8), _),
            (_, (open_32, seek_32), _),
        ] = measured[..]
        else {
            unreachable!()
        };
        assert_eq!(
            (open_8 - open_1) * 24,
            (open_32 - open_8) * 7,
            "{measured:?}"
        );
        // The seek does not read the recorded set at all.
        assert!(seek_1 == seek_8 && seek_8 == seek_32, "{measured:?}");
        assert!(open_32 > open_8 && open_8 > open_1, "{measured:?}");
    }

    #[test]
    fn the_candidate_seek_uses_the_lookup_index_without_a_sort() {
        let store = open_store();
        let plan: Vec<String> = store
            .conn
            .execute(|conn| {
                conn.execute_batch(STAGING_SCHEMA_SQL)?;
                conn.prepare(&format!("EXPLAIN QUERY PLAN {OTHER_CANDIDATES_SQL}"))?
                    .query_map(
                        rusqlite::params_from_iter(std::iter::repeat_n(Option::<i64>::None, 2)),
                        |row| row.get::<_, String>(3),
                    )?
                    .collect::<rusqlite::Result<_>>()
            })
            .unwrap();
        assert!(
            plan.iter()
                .any(|step| step.contains("USING INDEX resolution_unit_summaries_lookup")),
            "{plan:?}"
        );
        assert!(
            !plan.iter().any(|step| step.contains("TEMP B-TREE")),
            "{plan:?}"
        );
    }

    #[test]
    fn externally_scheduled_publications_match_the_driver_after_retry() {
        let fixture = Fixture::new(vec![
            Unit {
                key: [2; 32],
                input: 1,
                surface: 1,
                consumes: vec![],
                peeks: vec![[1; 32]],
                write_peeks: vec![],
                closure_peeks: vec![],
            },
            producer(1, 1),
        ]);
        let driven = open_store();
        let mut expected = run(&driven, &fixture, 1);
        let scheduled = open_store();
        let mut actual = scheduled
            .conn
            .execute(move |conn| -> Result<_> {
                let snapshot = snapshot(1);
                let cancellation = CancellationToken::default();
                let statements = StatementCounter(None);
                initialize_staging(conn)?;
                let mut state = begin_staged_pass(conn, &snapshot, &fixture)?;
                // No dependency edge orders this foreign read: the consumer's
                // first publication must record the producer as unavailable.
                publish_unit(
                    conn,
                    &mut state.context(&snapshot, &fixture, &cancellation),
                    1,
                )?;
                publish_unit(
                    conn,
                    &mut state.context(&snapshot, &fixture, &cancellation),
                    2,
                )?;
                assert_eq!(state.report.rederived, 0);
                let report =
                    finish_pass(conn, state, &snapshot, &fixture, &cancellation, &statements)?;
                clear_pass(conn, &fixture)?;
                Ok(report)
            })
            .unwrap();
        assert!(actual.rederived > 0, "{actual:?}");
        for report in [&mut expected, &mut actual] {
            report.elapsed = Duration::ZERO;
            report.transaction_total = Duration::ZERO;
            report.transaction_max = Duration::ZERO;
        }
        assert_eq!(expected, actual);

        // Include all historical rows, child rows and ids, not just live outputs.
        let rows = |store: &AnalyzerStore| {
            store
                .conn
                .execute(|conn| -> rusqlite::Result<_> {
                    let tables = conn
                        .prepare(
                            "SELECT name FROM sqlite_schema WHERE type = 'table'
                     AND (name = 'resolution_unit_summaries'
                          OR name GLOB 'resolution_unit_summary_*') ORDER BY name",
                        )?
                        .query_map([], |row| row.get::<_, String>(0))?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    tables
                        .into_iter()
                        .map(|table| {
                            let mut statement = conn.prepare(&format!("SELECT * FROM {table}"))?;
                            let columns = statement.column_count();
                            let order = (1..=columns)
                                .map(|i| i.to_string())
                                .collect::<Vec<_>>()
                                .join(",");
                            statement =
                                conn.prepare(&format!("SELECT * FROM {table} ORDER BY {order}"))?;
                            let rows = statement
                                .query_map([], |row| {
                                    (0..columns)
                                        .map(|i| row.get::<_, rusqlite::types::Value>(i))
                                        .collect::<rusqlite::Result<Vec<_>>>()
                                })?
                                .collect::<rusqlite::Result<Vec<_>>>()?;
                            Ok((table, rows))
                        })
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap()
        };
        assert_eq!(rows(&driven), rows(&scheduled));
    }

    /// The three defects of master's foreign reads, on the shared primitive. Master read
    /// another unit's live row with no settled check (a unit not yet derived this
    /// pass was read at its previous revision's row), discarded the result of a
    /// probe that found nothing, and so recorded nothing a consumer could be
    /// invalidated by.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11173: a foreign read of a unit not settled this pass read its previous revision's row"
    )]
    fn a_foreign_read_of_an_unsettled_unit_is_unavailable_and_then_retried() {
        let store = open_store();
        // The consumer is unit 1, so it runs before the producer (unit 2): no
        // edge orders them, and the reader must not use the producer's row.
        let consumer = Unit {
            key: [2; 32],
            input: 1,
            surface: 1,
            consumes: vec![],
            peeks: vec![[1; 32]],
            write_peeks: vec![],
            closure_peeks: vec![],
        };
        let fixture = Fixture::new(vec![consumer, producer(1, 1)]);
        let first = run(&store, &fixture, 1);
        assert_eq!(first.fixpoint_unsettled, 0, "{first:?}");
        assert!(
            first.rederived >= 1,
            "retry after the producer settled: {first:?}"
        );
        assert_eq!(
            consumed_rows(&store, live_id(&store, 2)),
            vec![(1, output_of(&store, live_id(&store, 1)))]
        );

        // The producer's output moves. At the consumer's turn the producer has a
        // live row from revision 1 and has not settled: that row is not read.
        fixture.0.lock().unwrap()[1] = producer(1, 2);
        let second = run(&store, &fixture, 2);
        assert!(second.rederived >= 1, "{second:?}");
        let producer_v2 = output_of(&store, live_id(&store, 1));
        assert_eq!(
            consumed_rows(&store, live_id(&store, 2)),
            vec![(1, producer_v2)],
            "the consumer ends at the producer's new output, not the old row"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11173: a probe that found nothing was discarded, so adding the probed unit left its consumer stale"
    )]
    fn a_probe_that_finds_nothing_is_recorded_and_invalidated_by_the_unit_appearing() {
        let store = open_store();
        let consumer = Unit {
            key: [2; 32],
            input: 1,
            surface: 1,
            consumes: vec![],
            peeks: vec![[9; 32]],
            write_peeks: vec![],
            closure_peeks: vec![],
        };
        let fixture = Fixture::new(vec![consumer]);
        run(&store, &fixture, 1);
        let absent = live_id(&store, 2);
        let rows = consumed_rows(&store, absent);
        assert_eq!(rows.len(), 1, "the absent unit is recorded: {rows:?}");
        assert_eq!(rows[0].0, 9);
        assert_eq!(
            store
                .conn
                .execute(move |conn| conn.query_row(
                    "SELECT consumed_summary_id, read_absence FROM resolution_unit_summary_consumed_units WHERE summary_id = ?1",
                    [absent],
                    |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, bool>(1)?)),
                ))
                .unwrap(),
            (None, true)
        );

        // The probed unit appears: the consumer is derived again and now records
        // the unit's output.
        fixture.0.lock().unwrap().push(producer(9, 1));
        run(&store, &fixture, 2);
        assert_ne!(live_id(&store, 2), absent);
        assert_eq!(
            consumed_rows(&store, live_id(&store, 2)),
            vec![(9, output_of(&store, live_id(&store, 9)))]
        );
    }

    /// A successful foreign read makes the consumer a dependent of the unit it
    /// read for the rest of the request. Master's retry followed only the ordering
    /// edges, so a consumer kept the output of a producer that a later fixpoint
    /// round refreshed.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11173: a consumer kept a foreign producer's output after a later fixpoint round moved it"
    )]
    fn a_consumer_follows_a_read_unit_whose_output_moves_in_a_later_round() {
        let store = open_store();
        // Order is by unit id: x, y, then c. x reads y before y has settled and
        // publishes a degraded surface; c reads x, settled, with no ordering edge.
        // Round one derives x again, its output moves, and c must follow in round two.
        let x = Unit {
            key: [1; 32],
            input: 1,
            surface: 1,
            consumes: vec![],
            peeks: vec![[2; 32]],
            write_peeks: vec![],
            closure_peeks: vec![],
        };
        let c = Unit {
            key: [3; 32],
            input: 1,
            surface: 1,
            consumes: vec![],
            peeks: vec![[1; 32]],
            write_peeks: vec![],
            closure_peeks: vec![],
        };
        let fixture = Fixture::new(vec![x, producer(2, 1), c]);
        let report = run(&store, &fixture, 1);
        assert_eq!(report.fixpoint_unsettled, 0, "{report:?}");
        assert!(report.fixpoint_rounds >= 2, "{report:?}");
        assert_eq!(
            consumed_rows(&store, live_id(&store, 3)),
            vec![(1, output_of(&store, live_id(&store, 1)))],
            "the consumer ends at the producer's final output, as a fresh derivation does"
        );
    }

    /// Two units that read each other, with no ordering edge: whichever runs first
    /// reads the other unavailable and is retried. An edit then ends at the outputs
    /// a fresh store derives, not at the first round's degraded ones.
    #[test]
    fn a_read_cycle_converges_to_the_fresh_outputs_after_an_edit() {
        let units = |input_b: u8| {
            let a = Unit {
                key: [1; 32],
                input: 1,
                surface: 1,
                consumes: vec![],
                peeks: vec![[2; 32]],
                write_peeks: vec![],
                closure_peeks: vec![],
            };
            let b = Unit {
                key: [2; 32],
                input: input_b,
                surface: input_b,
                consumes: vec![],
                peeks: vec![[1; 32]],
                write_peeks: vec![],
                closure_peeks: vec![],
            };
            vec![a, b]
        };
        let store = open_store();
        let fixture = Fixture::new(units(1));
        run(&store, &fixture, 1);
        fixture.0.lock().unwrap().clone_from(&units(2));
        let incremental = run(&store, &fixture, 2);
        assert_eq!(incremental.fixpoint_unsettled, 0, "{incremental:?}");

        let fresh_store = open_store();
        let fresh_fixture = Fixture::new(units(2));
        run(&fresh_store, &fresh_fixture, 1);
        for key in [1, 2] {
            assert_eq!(
                consumed_rows(&store, live_id(&store, key)),
                consumed_rows(&fresh_store, live_id(&fresh_store, key)),
                "unit {key} consumed set"
            );
            assert_eq!(
                output_of(&store, live_id(&store, key)),
                output_of(&fresh_store, live_id(&fresh_store, key)),
                "unit {key} output"
            );
        }
    }

    /// A closure-binding read skips the dependency-witness check, so its correctness
    /// rests on this path: a read of a unit not settled when the consumer derives is
    /// recorded unavailable, seeds a retry when the unit settles, and the consumer
    /// ends settled at the unit's final output, as a fresh derivation does.
    #[test]
    fn an_unsettled_closure_binding_read_is_retried_and_ends_at_the_fresh_outputs() {
        let units = |consumer_first: bool| {
            let consumer = Unit {
                key: [3; 32],
                input: 1,
                surface: 1,
                consumes: vec![],
                peeks: vec![],
                write_peeks: vec![],
                closure_peeks: vec![[2; 32]],
            };
            let producer = producer(2, 1);
            if consumer_first {
                vec![consumer, producer]
            } else {
                vec![producer, consumer]
            }
        };
        // Unit ids order the pass: the consumer (1) derives before the producer (2).
        let store = open_store();
        let fixture = Fixture::new(units(true));
        let report = run(&store, &fixture, 1);
        assert_eq!(report.fixpoint_unsettled, 0, "{report:?}");
        assert!(
            report.fixpoint_rounds >= 1 && report.rederived >= 1,
            "the unavailable read seeded a retry: {report:?}"
        );
        let consumer = live_id(&store, 3);
        let kinds: bool = store
            .conn
            .execute(move |conn| {
                conn.query_row(
                    "SELECT read_closure_bindings FROM resolution_unit_summary_consumed_units
                     WHERE summary_id = ?1",
                    [consumer],
                    |row| row.get(0),
                )
            })
            .unwrap();
        assert!(kinds, "the read is recorded as a closure-binding read");
        assert_eq!(
            consumed_rows(&store, consumer),
            vec![(2, output_of(&store, live_id(&store, 2)))],
            "settled at the unit's final output, not the unavailable marker"
        );

        // A fresh store whose producer settles first never reads it unavailable.
        let fresh_store = open_store();
        let fresh_fixture = Fixture::new(units(false));
        let fresh = run(&fresh_store, &fresh_fixture, 1);
        assert_eq!(fresh.fixpoint_rounds, 0, "{fresh:?}");
        let fresh_consumer = live_id(&fresh_store, 3);
        assert_eq!(
            consumed_rows(&store, consumer),
            consumed_rows(&fresh_store, fresh_consumer)
        );
        assert_eq!(
            output_of(&store, consumer),
            output_of(&fresh_store, fresh_consumer),
            "the retried consumer publishes the fresh output, not the degraded one"
        );
    }

    /// Scheduling notes made while the summary rows are written survive the undo of
    /// a publication attempt whose identity already exists.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11173: a duplicate-identity rollback dropped the retry seed of a read made while writing rows"
    )]
    fn a_rolled_back_attempt_keeps_the_retry_of_a_read_made_while_writing_rows() {
        let store = open_store();
        let c = Unit {
            key: [2; 32],
            input: 1,
            surface: 1,
            consumes: vec![],
            peeks: vec![],
            write_peeks: vec![[1; 32]],
            closure_peeks: vec![],
        };
        let fixture = Fixture::new(vec![c, producer(1, 1)]);
        run(&store, &fixture, 1);
        // The producer's output moves. The consumer runs first, reads it as
        // unavailable and so arrives at the identity of its first summary, which
        // exists: the attempt is undone and that summary is reused.
        fixture.0.lock().unwrap()[1] = producer(1, 2);
        let second = run(&store, &fixture, 2);
        assert_eq!(second.fixpoint_unsettled, 0, "{second:?}");
        assert_eq!(
            consumed_rows(&store, live_id(&store, 2)),
            vec![(1, output_of(&store, live_id(&store, 1)))],
            "the consumer was retried after the producer settled"
        );
    }

    /// A recorded absence stays valid while the unit stays absent. Otherwise a
    /// unit probing a unit that is never indexed was derived again, and its rows
    /// written and undone, on every reconciliation.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11173: a recorded absent unit never validated, so its consumer was derived again every reconcile"
    )]
    fn a_consumer_of_a_permanently_absent_unit_is_reused_until_the_unit_appears() {
        let store = open_store();
        let consumer = Unit {
            key: [2; 32],
            input: 1,
            surface: 1,
            consumes: vec![],
            peeks: vec![[9; 32]],
            write_peeks: vec![],
            closure_peeks: vec![],
        };
        let fixture = Fixture::new(vec![consumer]);
        let first = run(&store, &fixture, 1);
        assert_eq!(first.derived, 1, "{first:?}");
        let recorded = live_id(&store, 2);

        let second = run(&store, &fixture, 2);
        assert_eq!(
            (second.derived, second.unchanged, second.rebound_count),
            (0, 1, 0),
            "{second:?}"
        );
        assert_eq!(live_id(&store, 2), recorded);

        // The unit appears: its appearance is the change.
        fixture.0.lock().unwrap().push(producer(9, 1));
        let third = run(&store, &fixture, 3);
        assert_ne!(live_id(&store, 2), recorded, "{third:?}");
        assert_eq!(
            consumed_rows(&store, live_id(&store, 2)),
            vec![(9, output_of(&store, live_id(&store, 9)))]
        );
    }

    /// When the round limit stops the fixpoint, the units still queued and the
    /// units derived from them are not left live with the stale output they were
    /// published with: their version rows are closed, so a reader finds them
    /// unavailable, and the stop is reported.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11173: a chain of output changes longer than the round limit left its consumers live with stale output and no diagnostic"
    )]
    fn units_stranded_by_the_round_limit_are_withdrawn_and_reported() {
        let store = open_store();
        // x reads y unsettled and publishes a degraded surface; round one derives
        // it again and its output moves, which would need round two for c (reads
        // x) and then d (reads c). The limit is one round.
        let reading = |key: u8, reads: u8| Unit {
            key: [key; 32],
            input: 1,
            surface: 1,
            consumes: vec![],
            peeks: vec![[reads; 32]],
            write_peeks: vec![],
            closure_peeks: vec![],
        };
        let fixture = Fixture::new(vec![
            reading(1, 2),
            producer(2, 1),
            reading(3, 1),
            reading(4, 3),
        ]);
        fixture.1.store(1, std::sync::atomic::Ordering::Relaxed);
        let report = run(&store, &fixture, 1);
        assert_eq!(report.fixpoint_unsettled, 2, "{report:?}");
        assert_eq!(report.failed.len(), 2, "{report:?}");
        assert!(
            report
                .failed
                .iter()
                .all(|(_, why)| why.contains("did not settle")),
            "{report:?}"
        );
        let live_units = |store: &AnalyzerStore| -> Vec<u8> {
            store
                .conn
                .execute(|conn| {
                    conn.prepare(
                        "SELECT unit_key FROM resolution_unit_summary_versions
                         WHERE valid_until IS NULL ORDER BY unit_key",
                    )?
                    .query_map([], |row| Ok(row.get::<_, Vec<u8>>(0)?[0]))?
                    .collect::<rusqlite::Result<_>>()
                })
                .unwrap()
        };
        assert_eq!(
            live_units(&store),
            vec![1, 2],
            "c and d are not live with the stale output they were published with"
        );

        // The next reconciliation, with room to settle, derives them from x's final output.
        fixture
            .1
            .store(FIXPOINT_ROUNDS, std::sync::atomic::Ordering::Relaxed);
        let next = run(&store, &fixture, 2);
        assert!(
            next.failed.is_empty() && next.fixpoint_unsettled == 0,
            "{next:?}"
        );
        assert_eq!(live_units(&store), vec![1, 2, 3, 4]);
        assert_eq!(
            consumed_rows(&store, live_id(&store, 3)),
            vec![(1, output_of(&store, live_id(&store, 1)))]
        );
        assert_eq!(
            consumed_rows(&store, live_id(&store, 4)),
            vec![(3, output_of(&store, live_id(&store, 3)))]
        );
    }

    /// Collection of unreachable candidates: the candidates under a lookup digest
    /// are bounded by what version rows keep reachable, and a row that names a
    /// collected summary keeps its output digest and loses only the provenance id.
    #[test]
    fn collection_removes_unreachable_candidates_with_their_consumed_rows() {
        let store = open_store();
        let consumer = Unit {
            key: [2; 32],
            input: 1,
            surface: 1,
            consumes: vec![1],
            peeks: vec![],
            write_peeks: vec![],
            closure_peeks: vec![],
        };
        let fixture = Fixture::new(vec![producer(1, 1), consumer]);
        run(&store, &fixture, 1);
        let (consumer_v1, producer_v1) = (live_id(&store, 2), live_id(&store, 1));
        fixture.0.lock().unwrap()[0] = producer(1, 2);
        run(&store, &fixture, 2);
        let (consumer_v2, producer_v2) = (live_id(&store, 2), live_id(&store, 1));
        assert!(consumer_v1 != consumer_v2 && producer_v1 != producer_v2);

        // The statement `cache_gc` runs, under the permission a cascade needs.
        let collect = |store: &AnalyzerStore, unbind: i64| {
            store
                .conn
                .execute(move |conn| -> rusqlite::Result<()> {
                    conn.execute(
                        "DELETE FROM resolution_unit_summary_versions WHERE summary_id = ?1",
                        [unbind],
                    )?;
                    let _cascade = super::super::sealed_families::CascadeDelete::new(conn);
                    conn.execute(DELETE_UNBOUND_SUMMARIES_SQL, [])?;
                    Ok(())
                })
                .unwrap()
        };
        let provenance = |store: &AnalyzerStore, summary_id: i64| -> Vec<Option<i64>> {
            store
                .conn
                .execute(move |conn| {
                    conn.prepare("SELECT consumed_summary_id FROM resolution_unit_summary_consumed_units WHERE summary_id = ?1")?
                        .query_map([summary_id], |row| row.get(0))?
                        .collect::<rusqlite::Result<_>>()
                })
                .unwrap()
        };
        assert_eq!(provenance(&store, consumer_v1), vec![Some(producer_v1)]);
        let digests = consumed_rows(&store, consumer_v1);

        // The first producer summary becomes unreachable and is collected. The
        // consumer summary that read it is still bound.
        collect(&store, producer_v1);
        assert_eq!(provenance(&store, consumer_v1), vec![None]);
        assert_eq!(consumed_rows(&store, consumer_v1), digests);

        // The first consumer summary becomes unreachable: it goes with its rows.
        collect(&store, consumer_v1);
        assert!(consumed_rows(&store, consumer_v1).is_empty());
        let remaining: Vec<i64> = store
            .conn
            .execute(|conn| {
                conn.prepare(
                    "SELECT summary_id FROM resolution_unit_summaries ORDER BY summary_id",
                )?
                .query_map([], |row| row.get(0))?
                .collect::<rusqlite::Result<_>>()
            })
            .unwrap();
        assert_eq!(remaining, vec![producer_v2, consumer_v2]);
        assert_eq!(provenance(&store, consumer_v2), vec![Some(producer_v2)]);
    }
}

/// The answer to an exact live-summary read at a selected snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitLive {
    Present { output_digest: [u8; 32] },
    Absent,
}

/// Read with the same revision, profile, epoch and version predicate as reconciliation.
pub fn live_unit_summary(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
    unit_key: &[u8; 32],
    producer_epoch: &str,
    derivation_identity: [u8; 32],
) -> Result<UnitLive> {
    let row: Option<Vec<u8>> = conn
        .prepare_cached(LIVE_SUMMARY_SQL)?
        .query_row(
            params![
                snapshot.workspace_id.as_str(),
                snapshot.lang.as_str(),
                snapshot.generation.get(),
                unit_key.as_slice(),
                snapshot.revision,
                producer_epoch,
                derivation_identity
            ],
            |row| row.get(1),
        )
        .optional()?;
    match row {
        Some(bytes) => {
            let output_digest: [u8; 32] = bytes
                .try_into()
                .map_err(|_| StoreError::corrupt("unit summary output digest width"))?;
            Ok(UnitLive::Present { output_digest })
        }
        None => Ok(UnitLive::Absent),
    }
}

#[cfg(test)]
mod input_file_key_tests {
    use super::*;
    use crate::analyzer::store::{
        GenerationId, WorkspaceId, rust_unit_summaries::RustUnitSummaries,
    };

    fn unit(input_files: Vec<UnitInputFile>) -> UnitInputs {
        UnitInputs {
            unit_id: 1,
            unit_key: [1; 32],
            label: "input-files".into(),
            members: vec![],
            input_files,
            reads: vec![],
            dependencies: vec![],
            dependency_names: vec![],
            containers: vec![],
            placements: vec![],
        }
    }

    fn file(path: &str, value: InputFileValue) -> UnitInputFile {
        UnitInputFile {
            role: UnitSummaryInputRole::InactiveSource,
            rel_path: path.into(),
            value,
        }
    }

    fn key(input_files: Vec<UnitInputFile>) -> [u8; 32] {
        let snapshot = WorkspaceSnapshotId {
            workspace_id: WorkspaceId("a".repeat(64)),
            lang: "rust".into(),
            generation: GenerationId(0),
            revision: 1,
        };
        lookup_digest(
            &RustUnitSummaries,
            &snapshot,
            "epoch",
            &unit(input_files),
            &[],
            &[],
        )
        .unwrap()
    }

    #[test]
    fn input_file_values_hash_under_distinct_tags() {
        let fingerprint = key(vec![file("a.rs", InputFileValue::Fingerprint([7; 32]))]);
        let no_facts = key(vec![file(
            "a.rs",
            InputFileValue::NoFactsOid("7".repeat(40)),
        )]);
        let absent = key(vec![file("a.rs", InputFileValue::Absent)]);
        let missing_row = key(vec![]);
        // An empty fingerprint set is a fingerprint, not Absent, and Absent is
        // not a missing row.
        let empty_fingerprint = key(vec![file("a.rs", InputFileValue::Fingerprint([0; 32]))]);
        let digests = [
            fingerprint,
            no_facts,
            absent,
            missing_row,
            empty_fingerprint,
        ];
        for (index, left) in digests.iter().enumerate() {
            for right in &digests[index + 1..] {
                assert_ne!(left, right, "{digests:?}");
            }
        }
    }

    #[test]
    fn changing_one_input_file_value_moves_the_key() {
        let files = |second: [u8; 32]| {
            vec![
                file("a.rs", InputFileValue::Fingerprint([1; 32])),
                file("b.rs", InputFileValue::Fingerprint(second)),
            ]
        };
        assert_eq!(key(files([2; 32])), key(files([2; 32])));
        assert_ne!(key(files([2; 32])), key(files([3; 32])));
        let mut renamed = files([2; 32]);
        renamed[1].rel_path = "c.rs".into();
        assert_ne!(key(files([2; 32])), key(renamed));
    }
}

#[cfg(test)]
mod derivation_live_tests {
    use super::*;
    use crate::analyzer::store::{GenerationId, WorkspaceId};

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11183: premature coordinate-free cutoff retained stale foreign summary rows"
    )]
    fn output_digest_ignores_dense_scope_coordinates() {
        let mut unit = UnitInputs {
            unit_id: 1,
            unit_key: [1; 32],
            label: "placement-coordinate-perturbation".into(),
            members: ["a.rs", "b.rs"]
                .into_iter()
                .enumerate()
                .map(|(index, path)| UnitMember {
                    blob_id: index as i64,
                    blob_oid: format!("blob-{index}"),
                    rel_path: path.into(),
                    source_role: "source".into(),
                })
                .collect(),
            input_files: Vec::new(),
            reads: vec![],
            dependencies: vec![],
            dependency_names: vec![],
            containers: vec![],
            placements: vec![UnitPlacement {
                container_path: "crate".into(),
                member_ordinal: 0,
                scope_ordinal: Some(UnitCoordinate::Dense(7)),
            }],
        };
        let outputs = UnitOutputs {
            exports: vec![],
            imports: vec![],
            gaps: vec![],
            complete: true,
            public_surface_digest: None,
        };
        let expected = output_digest(&unit, &[], &outputs);
        unit.placements[0].scope_ordinal = Some(UnitCoordinate::Dense(99));
        assert_eq!(expected, output_digest(&unit, &[], &outputs));
    }

    #[test]
    fn live_unit_tracks_rebound_change_close_add_and_missing() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE resolution_unit_summary_versions (
                workspace_id TEXT, lang TEXT, generation INTEGER, unit_key BLOB,
                profile_digest BLOB, valid_from INTEGER, valid_until INTEGER, summary_id INTEGER);
             CREATE TABLE resolution_unit_summaries (
                summary_id INTEGER, output_digest BLOB, publication_state TEXT,
                producer_epoch TEXT, derivation_identity BLOB);",
        )
        .unwrap();
        let snapshot = WorkspaceSnapshotId {
            workspace_id: WorkspaceId("a".repeat(64)),
            lang: "rust".into(),
            generation: GenerationId(0),
            revision: 1,
        };
        let key = [1; 32];
        let added = [2; 32];
        for (id, digest, state, epoch) in [
            (1, [3u8; 32], "complete", "epoch"),
            (2, [3; 32], "complete", "epoch"),
            (3, [4; 32], "complete", "epoch"),
            (4, [5; 32], "building", "epoch"),
            (5, [6; 32], "complete", "old"),
            (6, [7; 32], "complete", "epoch"),
        ] {
            conn.execute(
                "INSERT INTO resolution_unit_summaries VALUES (?1, ?2, ?3, ?4, x'0101010101010101010101010101010101010101010101010101010101010101')",
                params![id, digest.as_slice(), state, epoch],
            )
            .unwrap();
        }
        for (unit_key, from, until, id) in [
            (key, 1, Some(2), 1),
            (key, 2, Some(3), 2),
            (key, 3, Some(4), 3),
            (key, 4, Some(5), 4),
            (key, 5, Some(6), 5),
            (added, 2, None, 6),
        ] {
            conn.execute("INSERT INTO resolution_unit_summary_versions VALUES (?1, 'rust', 0, ?2, zeroblob(32), ?3, ?4, ?5)",
                params![snapshot.workspace_id.as_str(), unit_key.as_slice(), from, until, id]).unwrap();
        }
        let read = |revision, unit_key| {
            let mut selected = snapshot.clone();
            selected.revision = revision;
            live_unit_summary(&conn, &selected, unit_key, "epoch", [1; 32]).unwrap()
        };
        assert_eq!(
            read(1, &key),
            UnitLive::Present {
                output_digest: [3; 32]
            }
        );
        assert_eq!(
            read(2, &key),
            UnitLive::Present {
                output_digest: [3; 32]
            }
        );
        assert_eq!(
            read(3, &key),
            UnitLive::Present {
                output_digest: [4; 32]
            }
        );
        assert_eq!(read(4, &key), UnitLive::Absent);
        assert_eq!(read(5, &key), UnitLive::Absent);
        assert_eq!(read(6, &key), UnitLive::Absent);
        assert_eq!(read(1, &added), UnitLive::Absent);
        assert_eq!(
            read(2, &added),
            UnitLive::Present {
                output_digest: [7; 32]
            }
        );
        assert_eq!(read(2, &[9; 32]), UnitLive::Absent);
        let mut selected = snapshot;
        selected.revision = 2;
        assert_eq!(
            live_unit_summary(&conn, &selected, &key, "epoch", [2; 32]).unwrap(),
            UnitLive::Absent
        );
    }
}
