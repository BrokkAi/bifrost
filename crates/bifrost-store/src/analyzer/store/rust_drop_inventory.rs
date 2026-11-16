//! A non-workspace trait impl may be Drop only when its structural body has a
//! method named `drop`. Workspace trait endpoints exclude local lookalikes.
//! Closed census boundaries block absence, including impl-item macros.
//! Workspaces defining core themselves (no_core or lang items) are out of scope.

use super::resolution::with_resolution_read_progress_handler;
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_semantic::analyzer::semantic::ids::StableDigest;
use rusqlite::{params, types::ValueRef};

use super::{AnalyzerStore, Result, StoreError, WorkspaceSnapshots};
use crate::analyzer::canonical_hash::CanonicalHasher;

/// Selected nominal identity, independent of summary content and source offsets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustDropInventorySubject {
    pub owning_unit: StableDigest,
    pub module_path: Box<str>,
    pub identity_digest: StableDigest,
    pub config_digest: StableDigest,
}

/// Failure to form a question must never be interpreted as proven absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustDropInventoryReason {
    OwnerMissing,
    OwnerAmbiguous,
    CensusMissing,
    CensusCorrupt,
    Boundary(u8),
    ModuleUniverseOpen,
    UnresolvedDropSubject,
    AliasSubject,
    UnpairedImpl,
    UnverifiedImplItems,
    NegatedImpl,
    PublicationIncomplete,
    Budget,
    Cancelled,
}

fn digest(bytes: Vec<u8>) -> Result<StableDigest> {
    Ok(StableDigest::from_array(bytes.try_into().map_err(
        |_| StoreError::corrupt("Rust Drop inventory identity is not a 32-byte digest"),
    )?))
}

impl AnalyzerStore {
    /// Whether one changed overlay path is an input to this canonical crate.
    pub fn rust_drop_inventory_overlay_affects(
        &self,
        snapshots: &WorkspaceSnapshots,
        owning_unit: StableDigest,
        rel_path: &str,
        overlay_oid: &git2::Oid,
    ) -> Result<bool> {
        let conn = self.read_conn_for_workspace(snapshots)?;
        conn.prepare_cached(
            "SELECT EXISTS(
               SELECT 1 FROM selected_rust_unit_summaries u
               WHERE u.unit_key=?1
                 AND NOT EXISTS(SELECT 1 FROM workspace_file_versions live
                     WHERE live.workspace_id=u.workspace_id AND live.lang=u.lang
                       AND live.generation=u.generation AND live.rel_path=?2
                       AND live.valid_from<=u.revision
                       AND (live.valid_until IS NULL OR u.revision<live.valid_until)
                       AND live.blob_oid=?3)
                 AND (EXISTS(SELECT 1 FROM resolution_unit_summary_members m
                              WHERE m.summary_id=u.summary_id AND m.rel_path=?2)
                   OR EXISTS(SELECT 1 FROM rust_crate_broad_placements p
                              WHERE p.topology_id=u.topology_id AND p.rel_path=?2)
                   OR EXISTS(SELECT 1 FROM workspace_file_versions manifest
                              WHERE manifest.file_version_id=u.manifest_file_version_id
                                AND manifest.rel_path=?2)
                   OR EXISTS(SELECT 1 FROM workspace_file_versions configuration
                              WHERE configuration.workspace_id=u.workspace_id
                                AND configuration.lang=u.lang
                                AND configuration.generation=u.generation
                                AND configuration.rel_path=?2
                                AND configuration.valid_from<=u.revision
                                AND (configuration.valid_until IS NULL OR u.revision<configuration.valid_until)
                                AND configuration.input_kind<>'source')))",
        )?
        .query_row(
            params![
                owning_unit.as_bytes().as_slice(),
                rel_path,
                overlay_oid.to_string()
            ],
            |row| row.get(0),
        )
        .map_err(Into::into)
    }

    /// Select one owning unit and nominal placement. The configuration digest
    /// hashes scalar selection context, never topology or summary content.
    pub fn rust_drop_inventory_subject(
        &self,
        snapshots: &WorkspaceSnapshots,
        rel_path: &str,
        blob_oid: &git2::Oid,
        start_byte: usize,
        end_byte: usize,
    ) -> Result<std::result::Result<RustDropInventorySubject, RustDropInventoryReason>> {
        let conn = self.read_conn_for_workspace(snapshots)?;
        let mut statement =
            conn.prepare_cached(include_str!("rust_drop_inventory_question.sql"))?;
        let mut rows = statement.query(params![
            rel_path,
            blob_oid.to_string(),
            start_byte as i64,
            end_byte as i64,
        ])?;
        let Some(row) = rows.next()? else {
            return Ok(Err(RustDropInventoryReason::OwnerMissing));
        };
        let owning_unit = digest(row.get(0)?)?;
        let module_path: String = row.get(1)?;
        let identity_digest = digest(row.get(2)?)?;
        let mut config = CanonicalHasher::new(b"bifrost:rust-drop-selection:v1");
        for column in 3..8 {
            let value: String = row.get(column)?;
            config.value(value.as_bytes());
        }
        config.value(&row.get::<_, i64>(8)?.to_be_bytes());
        let subject = RustDropInventorySubject {
            owning_unit,
            module_path: module_path.into_boxed_str(),
            identity_digest,
            config_digest: StableDigest::from_array(config.finish()),
        };
        if rows.next()?.is_some() {
            return Ok(Err(RustDropInventoryReason::OwnerAmbiguous));
        }
        Ok(Ok(subject))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustDropInventory {
    Present {
        witness: StableDigest,
        digest: StableDigest,
    },
    Absent {
        digest: StableDigest,
    },
    Unknown {
        reason: RustDropInventoryReason,
        digest: StableDigest,
    },
}

/// Compact crate evidence held by the per-request memo, keyed by selected
/// snapshot, owning unit and configuration. Contains no source text.
#[derive(Debug, Clone)]
pub struct RustDropCrateInventory {
    owning_unit: StableDigest,
    config_digest: StableDigest,
    reason: Option<RustDropInventoryReason>,
    crate_digest: StableDigest,
    subjects: std::collections::HashSet<(Box<str>, StableDigest)>,
    witnesses: std::collections::HashMap<(StableDigest, Box<str>, StableDigest), StableDigest>,
    unverified_subjects: std::collections::HashSet<(StableDigest, Box<str>, StableDigest)>,
    stopped: bool,
}

impl RustDropCrateInventory {
    /// Rows retained after the streamed crate scan has finished.
    pub fn retained_rows(&self) -> usize {
        1 + self.subjects.len() + self.witnesses.len() + self.unverified_subjects.len()
    }

    /// Charge the inventory and all allocations retained by its request memo.
    pub fn retained_bytes(&self) -> usize {
        let mut heap = super::cache_budget::RetainedHeap::default();
        heap.add(std::mem::size_of::<Self>());
        heap.hash_set(&self.subjects);
        heap.map(&self.witnesses);
        heap.hash_set(&self.unverified_subjects);
        for (_, module, _) in &self.unverified_subjects {
            heap.add(module.len());
        }
        for (module, _) in &self.subjects {
            heap.add(module.len());
        }
        for (_, module, _) in self.witnesses.keys() {
            heap.add(module.len());
        }
        heap.total()
    }

    /// Assemble a subject-bound answer without reading the store.
    pub fn answer_for(&self, subject: &RustDropInventorySubject) -> RustDropInventory {
        assert_eq!(self.owning_unit, subject.owning_unit);
        assert_eq!(self.config_digest, subject.config_digest);
        let mut hasher = CanonicalHasher::new(b"bifrost:rust-drop-impl-inventory:v1");
        hasher.field("owning_unit", subject.owning_unit.as_bytes());
        hasher.field("target_unit", subject.owning_unit.as_bytes());
        hasher.field("module_path", subject.module_path.as_bytes());
        hasher.field("target_identity", subject.identity_digest.as_bytes());
        hasher.field("config", subject.config_digest.as_bytes());
        hasher.field("crate", self.crate_digest.as_bytes());
        let witness = self.witnesses.get(&(
            subject.owning_unit,
            subject.module_path.clone(),
            subject.identity_digest,
        ));
        if !self.stopped
            && let Some(&witness) = witness
        {
            hasher.field("present", witness.as_bytes());
            RustDropInventory::Present {
                witness,
                digest: StableDigest::from_array(hasher.finish()),
            }
        } else if let Some(reason) = self
            .reason
            .or_else(|| {
                self.unverified_subjects
                    .contains(&(
                        subject.owning_unit,
                        subject.module_path.clone(),
                        subject.identity_digest,
                    ))
                    .then_some(RustDropInventoryReason::UnverifiedImplItems)
            })
            .or_else(|| {
                (!self
                    .subjects
                    .contains(&(subject.module_path.clone(), subject.identity_digest)))
                .then_some(RustDropInventoryReason::OwnerMissing)
            })
        {
            hasher.field("unknown", format!("{reason:?}").as_bytes());
            RustDropInventory::Unknown {
                reason,
                digest: StableDigest::from_array(hasher.finish()),
            }
        } else {
            hasher.field("absent", &[]);
            RustDropInventory::Absent {
                digest: StableDigest::from_array(hasher.finish()),
            }
        }
    }
}

impl AnalyzerStore {
    pub fn rust_drop_inventory_answer(
        &self,
        snapshots: &WorkspaceSnapshots,
        subject: &RustDropInventorySubject,
        cancellation: &CancellationToken,
        charge_row: impl FnMut(),
    ) -> Result<Option<(RustDropInventory, usize)>> {
        let Some((inventory, rows)) = self.rust_drop_inventory_crate(
            snapshots,
            subject.owning_unit,
            subject.config_digest,
            cancellation,
            charge_row,
        )?
        else {
            return Ok(None);
        };
        if !inventory.stopped
            && !inventory
                .subjects
                .contains(&(subject.module_path.clone(), subject.identity_digest))
        {
            return Ok(None);
        }
        Ok(Some((inventory.answer_for(subject), rows)))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn rust_drop_inventory_crate(
        &self,
        snapshots: &WorkspaceSnapshots,
        owning_unit: StableDigest,
        config_digest: StableDigest,
        cancellation: &CancellationToken,
        mut charge_row: impl FnMut(),
    ) -> Result<Option<(RustDropCrateInventory, usize)>> {
        let conn = self.read_conn_for_workspace(snapshots)?;
        let mut charged = 0;
        let mut inventory = RustDropCrateInventory {
            owning_unit,
            config_digest,
            reason: None,
            crate_digest: StableDigest::from_array([0; 32]),
            subjects: std::collections::HashSet::new(),
            witnesses: std::collections::HashMap::new(),
            unverified_subjects: std::collections::HashSet::new(),
            stopped: false,
        };
        let mut placement_digests = Vec::new();
        let result = with_resolution_read_progress_handler(&conn, cancellation, |conn| {
            let mut statement =
                conn.prepare_cached(include_str!("rust_drop_inventory_answer.sql"))?;
            let mut rows = statement.query(params![owning_unit.as_bytes().as_slice()])?;
            let mut semantic_rows: Vec<[u8; 32]> = Vec::new();
            let mut placement = Vec::new();
            let mut header = 0;
            let mut row_count = 0usize;
            let mut reason: Option<(u8, RustDropInventoryReason)> = None;
            let mut put = |rank, next| {
                if reason.is_none_or(|(old, _)| rank < old) {
                    reason = Some((rank, next));
                }
            };
            loop {
                if cancellation.is_cancelled() {
                    inventory.reason = Some(RustDropInventoryReason::Cancelled);
                    inventory.stopped = true;
                    return Ok(Some(row_count));
                }
                // SemanticBudget::charge_work records telemetry; only retained
                // admissions refuse (semantic/provider.rs). SQL scan rows are
                // work, not residency. Cancellation is the operational stop.
                let Some(row) = rows.next()? else { break };
                charge_row();
                charged += 1;
                row_count += 1;
                let row_kind: i64 = row.get(0)?;
                let mut semantic = CanonicalHasher::new(b"bifrost:rust-drop-placement-row:v1");
                semantic.value(&row_kind.to_be_bytes());
                let columns: &[usize] = match row_kind {
                    0 => &[],
                    1 => &[1, 3, 4, 5, 6, 7, 8, 9, 10, 11],
                    2 => &[1, 4],
                    3 => &[1, 4, 5, 8],
                    4 => &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
                    5 => &[1, 2],
                    7 => &[1],
                    8 => &[1, 4],
                    10 => &[1, 2],
                    _ => &[],
                };
                for &column in columns {
                    match row.get_ref(column)? {
                        ValueRef::Null => semantic.field("null", &[]),
                        ValueRef::Integer(v) => semantic.field("integer", &v.to_be_bytes()),
                        ValueRef::Real(v) => semantic.field("real", &v.to_be_bytes()),
                        ValueRef::Text(v) => semantic.field("text", v),
                        ValueRef::Blob(v) => semantic.field("blob", v),
                    }
                }
                let row_digest = semantic.finish();
                let key = match row.get_ref(1)? {
                    ValueRef::Text(v) | ValueRef::Blob(v) => v.to_vec(),
                    _ => Vec::new(),
                };
                if key != placement {
                    semantic_rows.sort_unstable();
                    let mut folded = CanonicalHasher::new(b"bifrost:rust-drop-placement:v1");
                    folded.value(&placement);
                    for value in semantic_rows.drain(..) {
                        folded.value(&value);
                    }
                    placement_digests.push(folded.finish());
                    placement = key;
                }
                semantic_rows.push(row_digest);
                match row_kind {
                    0 => {
                        header += 1;
                        let subjects: Vec<(Box<str>, String)> =
                            serde_json::from_str(&row.get::<_, String>(9)?).map_err(|error| {
                                StoreError::corrupt(format!(
                                    "invalid Drop subject inventory: {error}"
                                ))
                            })?;
                        for (module, hex) in subjects {
                            let mut bytes = [0; 32];
                            if hex.len() != 64 {
                                return Err(StoreError::corrupt(
                                    "invalid Drop subject digest length",
                                ));
                            }
                            for (byte, pair) in
                                bytes.iter_mut().zip(hex.as_bytes().as_chunks::<2>().0)
                            {
                                let value = std::str::from_utf8(pair)
                                    .map_err(|error| StoreError::corrupt(error.to_string()))?;
                                *byte = u8::from_str_radix(value, 16)
                                    .map_err(|error| StoreError::corrupt(error.to_string()))?;
                            }
                            inventory
                                .subjects
                                .insert((module, StableDigest::from_array(bytes)));
                        }
                        // The summary's `complete` flag (column 4) is not a gate:
                        // besides topology completeness, which is gated directly
                        // below, it folds unresolved imports, re-exports, open
                        // export inventories, visibility and unavailable
                        // dependency summaries. Impls are enumerated from each
                        // member's census and every impl's subject and trait
                        // endpoints are checked one by one, so those gaps can
                        // only matter through an impl header, where they show up
                        // as an unresolved endpoint.
                        // `topology_complete` and `context_complete` fold the
                        // whole feature inventory, including unretained external
                        // dependencies. Such a dependency cannot implement Drop
                        // for this crate's types (E0117/E0120), and a feature
                        // that could change this crate's module set appears
                        // below as an `unknown_activation` gap. Gating absence
                        // on the aggregate flag would therefore withhold every
                        // local Drop proof when an unrelated dependency is
                        // unavailable.
                        if row.get::<_, String>(5)? != "complete"
                            || row.get::<_, String>(7)? != "complete"
                        {
                            put(6, RustDropInventoryReason::PublicationIncomplete);
                        }
                    }
                    1 => {
                        if row.get::<_, Option<i64>>(5)? != Some(1) {
                            put(1, RustDropInventoryReason::CensusMissing);
                        } else if row.get::<_, Option<i64>>(6)? != row.get::<_, Option<i64>>(7)?
                            || row.get::<_, Option<i64>>(8)? != row.get::<_, Option<i64>>(10)?
                        {
                            put(1, RustDropInventoryReason::CensusCorrupt);
                        }
                        // A member's incomplete import bindings (column 9) are
                        // not a gate, for the same reason as the summary flag.
                        if row.get::<_, Option<String>>(3)?.as_deref() != Some("complete")
                            || row.get::<_, Option<i64>>(4)? != Some(2)
                        {
                            put(6, RustDropInventoryReason::PublicationIncomplete);
                        }
                        if row.get::<_, i64>(11)? != 0 {
                            put(3, RustDropInventoryReason::ModuleUniverseOpen);
                        }
                    }
                    2 => put(
                        2,
                        RustDropInventoryReason::Boundary(row.get::<_, i64>(4)? as u8),
                    ),
                    3 => {
                        if row.get::<_, i64>(8)? != 0 {
                            put(0, RustDropInventoryReason::NegatedImpl);
                        }
                        if row.get::<_, i64>(4)? != 0 && row.get::<_, i64>(5)? != 1 {
                            put(4, RustDropInventoryReason::UnpairedImpl);
                        }
                    }
                    4 => {
                        if row.get::<_, Option<String>>(11)?.is_none() {
                            put(4, RustDropInventoryReason::UnpairedImpl);
                            continue;
                        }
                        let state: String = row.get(6)?;
                        if row.get::<_, i64>(5)? == 0 {
                            continue;
                        }
                        if row.get::<_, i64>(13)? != 1
                            || row.get::<_, Option<String>>(11)?.is_none()
                        {
                            put(4, RustDropInventoryReason::UnpairedImpl);
                        } else if state != "resolved"
                            || row.get::<_, Option<Vec<u8>>>(9)?.is_none()
                            || row.get::<_, Option<i64>>(10)?.is_none()
                        {
                            put(4, RustDropInventoryReason::UnresolvedDropSubject);
                        } else if row.get::<_, Option<i64>>(10)? == Some(13) {
                            put(4, RustDropInventoryReason::AliasSubject);
                        } else if row.get::<_, Option<i64>>(10)?.is_none() {
                            put(4, RustDropInventoryReason::UnresolvedDropSubject);
                        } else {
                            let key = (
                                digest(row.get(7)?)?,
                                row.get::<_, String>(8)?.into_boxed_str(),
                                digest(row.get(9)?)?,
                            );
                            if row.get::<_, i64>(5)? == 2 {
                                inventory.unverified_subjects.insert(key);
                                continue;
                            }
                            let witness = StableDigest::from_array(row_digest);
                            inventory
                                .witnesses
                                .entry(key)
                                .and_modify(|old| *old = (*old).min(witness))
                                .or_insert(witness);
                        }
                    }
                    5 => {
                        // Inactive placements are outside the selected crate. External
                        // dependencies cannot implement Drop for its types (E0117/E0120).
                        // Import/export/visibility/trait gaps add no missing evidence:
                        // every member's impl census and each impl's endpoints are checked
                        // separately, including unpaired impls and unresolved drop methods.
                        let kind: String = row.get(1)?;
                        if matches!(
                            kind.as_str(),
                            "unsupported_manifest"
                                | "unknown_activation"
                                | "unplaced_module"
                                | "duplicate_placement"
                        ) {
                            put(3, RustDropInventoryReason::ModuleUniverseOpen);
                        }
                    }
                    7 => put(3, RustDropInventoryReason::ModuleUniverseOpen),
                    8 => put(4, RustDropInventoryReason::UnpairedImpl),
                    10 => {}
                    11 => {
                        let mut config = CanonicalHasher::new(b"bifrost:rust-drop-selection:v1");
                        for column in 1..6 {
                            config.value(row.get::<_, String>(column)?.as_bytes());
                        }
                        config.value(&row.get::<_, i64>(6)?.to_be_bytes());
                        if config.finish() != *config_digest.as_bytes() {
                            return Ok(None);
                        }
                    }
                    _ => return Err(StoreError::corrupt("unknown Rust Drop inventory row kind")),
                }
            }
            if header != 1 {
                return Ok(None);
            }
            if cancellation.is_cancelled() {
                inventory.reason = Some(RustDropInventoryReason::Cancelled);
                inventory.stopped = true;
                return Ok(Some(row_count));
            }
            semantic_rows.sort_unstable();
            let mut folded = CanonicalHasher::new(b"bifrost:rust-drop-placement:v1");
            folded.value(&placement);
            for row in semantic_rows {
                folded.value(&row);
            }
            placement_digests.push(folded.finish());
            inventory.reason = reason.map(|(_, reason)| reason);
            Ok(Some(row_count))
        });
        let mut crate_hash = CanonicalHasher::new(b"bifrost:rust-drop-crate-inventory:v1");
        for digest in placement_digests {
            crate_hash.value(&digest);
        }
        let mut subjects: Vec<_> = inventory.subjects.iter().collect();
        subjects.sort_unstable();
        for (module, identity) in subjects {
            crate_hash.value(module.as_bytes());
            crate_hash.value(identity.as_bytes());
        }
        inventory.crate_digest = StableDigest::from_array(crate_hash.finish());
        match result {
            Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => {
                inventory.reason = Some(RustDropInventoryReason::Cancelled);
                inventory.stopped = true;
                Ok(Some((inventory, charged)))
            }
            other => other.map(|result| result.map(|rows| (inventory, rows))),
        }
    }
}
