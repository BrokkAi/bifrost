//! Selected Rust crate Copy-absence proof. The SQL bounds every arm to one
//! selected unit and this reader folds its rows before releasing the statement.

use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_semantic::analyzer::semantic::ids::StableDigest;
use brokk_bifrost_semantic::analyzer::semantic::read_ledger::LookupQuestion;
use rusqlite::{params, types::ValueRef};

use super::resolution::with_resolution_read_progress_handler;
use super::{AnalyzerStore, Result, StoreError, WorkspaceSnapshots};
use crate::analyzer::canonical_hash::CanonicalHasher;

pub(crate) const RUST_COPY_ABSENCE_QUESTION_SQL: &str =
    "SELECT u.unit_key, e.module_path, identity.identity_digest,
                    topology.topology_digest, summary.summary_digest
             FROM blobs AS blob INDEXED BY sqlite_autoindex_blobs_1
             CROSS JOIN source_declarations AS declaration ON declaration.blob_id = blob.id
             CROSS JOIN resolution_unit_summary_members AS m
               INDEXED BY resolution_unit_summary_members_path
               ON m.rel_path = ?1
             CROSS JOIN selected_rust_unit_summaries AS u ON u.summary_id = m.summary_id
             CROSS JOIN temp.selected_unit_member_blobs AS attachment
               ON attachment.summary_id = m.summary_id
              AND attachment.member_ordinal = m.member_ordinal
              AND attachment.blob_id = blob.id
             JOIN workspace_file_versions AS live
               ON live.workspace_id = u.workspace_id AND live.lang = u.lang
              AND live.generation = u.generation AND live.rel_path = m.rel_path
              AND live.input_kind = 'source' AND live.blob_oid = blob.blob_oid
              AND live.valid_from <= u.revision
              AND (live.valid_until IS NULL OR u.revision < live.valid_until)
             JOIN resolution_unit_summaries AS summary ON summary.summary_id = m.summary_id
             JOIN rust_crate_topologies AS topology ON topology.topology_id = u.topology_id
             JOIN source_rust_declaration_properties AS property
               ON property.blob_id = declaration.blob_id
              AND property.declaration_id = declaration.declaration_id
             JOIN resolution_rust_declaration_authorities AS authority
               ON authority.blob_id = declaration.blob_id
              AND authority.declaration = declaration.declaration_id
             JOIN rust_resolution_unit_summary_exports AS e
               ON e.summary_id = m.summary_id
              AND e.declaration_member_ordinal = m.member_ordinal
              /* Rust child sites use the retained derived-from blob. */
              AND m.blob_id = authority.blob_id
              AND e.declaration_site = authority.source_site
              AND e.origin = 'declaration' AND e.namespace = 'type'
             JOIN resolution_identities AS identity ON identity.id = e.identity_id
             WHERE blob.blob_oid = ?2 AND blob.lang = 'rust'
               AND declaration.start_byte = ?3 AND declaration.end_byte = ?4
               AND property.declaration_kind IN (0, 1)
             ORDER BY u.unit_key, e.module_path, identity.identity_digest";

pub(crate) const RUST_COPY_ABSENCE_SQL: &str = include_str!("rust_copy_absence.sql");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustCopyAbsenceReason {
    CensusMissing,
    CensusCorrupt,
    Boundary(u8),
    ModuleUniverseOpen,
    UnresolvedSubject,
    AliasSubject,
    UnpairedImpl,
    MatchingTraitImpl,
    PublicationIncomplete,
}

impl RustCopyAbsenceReason {
    pub const fn label(self) -> &'static str {
        match self {
            Self::CensusMissing => "rust_copy.census_missing",
            Self::CensusCorrupt => "rust_copy.census_corrupt",
            Self::Boundary(0) => "rust_copy.boundary_macro",
            Self::Boundary(1) => "rust_copy.boundary_derive",
            Self::Boundary(2) => "rust_copy.boundary_expanding_attribute",
            Self::Boundary(3) => "rust_copy.boundary_internal_attribute",
            Self::Boundary(4) => "rust_copy.boundary_syntax_error",
            Self::Boundary(_) => "rust_copy.census_corrupt",
            Self::ModuleUniverseOpen => "rust_copy.module_universe_open",
            Self::UnresolvedSubject => "rust_copy.unresolved_subject",
            Self::AliasSubject => "rust_copy.alias_subject",
            Self::UnpairedImpl => "rust_copy.unpaired_impl",
            Self::MatchingTraitImpl => "rust_copy.matching_trait_impl",
            Self::PublicationIncomplete => "rust_copy.publication_incomplete",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustCopyAbsence {
    Absent { digest: StableDigest },
    Unknown(RustCopyAbsenceReason),
}

fn digest(bytes: Vec<u8>, column: &str) -> Result<StableDigest> {
    let array: [u8; 32] = bytes.try_into().map_err(|_| {
        StoreError::corrupt(format!(
            "Rust Copy absence {column} is not a 32-byte digest"
        ))
    })?;
    Ok(StableDigest::from_array(array))
}

impl AnalyzerStore {
    /// Locate one exact selected local struct or enum. Ambiguous crate mounts
    /// cannot choose an owning crate and therefore cannot make a negative proof.
    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
    pub fn rust_copy_absence_question(
        &self,
        snapshots: &WorkspaceSnapshots,
        rel_path: &str,
        blob_oid: &git2::Oid,
        start_byte: usize,
        end_byte: usize,
    ) -> Result<Option<LookupQuestion>> {
        let conn = self.read_conn_for_workspace(snapshots)?;
        let mut statement = conn.prepare_cached(RUST_COPY_ABSENCE_QUESTION_SQL)?;
        let mut rows = statement.query(params![
            rel_path,
            blob_oid.to_string(),
            start_byte as i64,
            end_byte as i64
        ])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let unit = digest(row.get(0)?, "unit key")?;
        let module_path: String = row.get(1)?;
        let identity = digest(row.get(2)?, "identity")?;
        let config = digest(row.get(3)?, "configuration")?;
        let producer = digest(row.get(4)?, "producer")?;
        if rows.next()?.is_some() {
            return Ok(None);
        }
        Ok(Some(LookupQuestion::RustCopyAbsence {
            owning_unit: unit,
            target_unit: unit,
            module_path: module_path.into_boxed_str(),
            target_identity_digest: identity,
            census_version: 1,
            config_digest: config,
            producer_digest: producer,
        }))
    }

    /// Evaluate the recorded question on the current selected crate. Replay
    /// calls this same method; a missing selected unit gives no comparison.
    /// Existing rows are scanned under SQL cancellation/deadline controls;
    /// each visit is observed work, not a refusing semantic work quota.
    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
    pub fn rust_copy_absence_answer(
        &self,
        snapshots: &WorkspaceSnapshots,
        question: &LookupQuestion,
        selected_stdlib_revision: Option<&str>,
        cancellation: &CancellationToken,
        mut charge_row: impl FnMut(),
    ) -> Result<Option<(RustCopyAbsence, usize)>> {
        let LookupQuestion::RustCopyAbsence {
            owning_unit,
            target_unit,
            module_path,
            target_identity_digest,
            census_version,
            config_digest,
            producer_digest,
        } = question
        else {
            return Ok(None);
        };
        if owning_unit != target_unit || *census_version != 1 {
            return Ok(None);
        }
        let conn = self.read_conn_for_workspace(snapshots)?;
        with_resolution_read_progress_handler(&conn, cancellation, |conn| {
            let mut statement = conn.prepare_cached(RUST_COPY_ABSENCE_SQL)?;
            let mut rows = statement.query(params![
                owning_unit.as_bytes().as_slice(),
                target_unit.as_bytes().as_slice(),
                module_path.as_ref(),
                target_identity_digest.as_bytes().as_slice(),
            ])?;
            let mut hasher = CanonicalHasher::new(b"bifrost-rust-copy-absence-answer:v1");
            hasher.field("owning_unit", owning_unit.as_bytes());
            hasher.field("target_unit", target_unit.as_bytes());
            hasher.field("module_path", module_path.as_bytes());
            hasher.field("target_identity", target_identity_digest.as_bytes());
            hasher.field("census_version", &census_version.to_be_bytes());
            hasher.field("config", config_digest.as_bytes());
            hasher.field("producer", producer_digest.as_bytes());
            hasher.field(
                "selected_stdlib_revision",
                selected_stdlib_revision.unwrap_or_default().as_bytes(),
            );
            let mut header = 0;
            let mut row_count = 0usize;
            let mut reason: Option<(u8, RustCopyAbsenceReason)> = None;
            let mut put = |rank, next| {
                if reason.is_none_or(|(old, _)| rank < old) {
                    reason = Some((rank, next));
                }
            };
            loop {
                if cancellation.is_cancelled() {
                    return Err(StoreError::cancelled("Rust Copy absence read cancelled"));
                }
                let Some(row) = rows.next()? else { break };
                charge_row();
                row_count += 1;
                let row_kind: i64 = row.get(0)?;
                hasher.value(&row_kind.to_be_bytes());
                for column in 1..14 {
                    match row.get_ref(column)? {
                        ValueRef::Null => hasher.field("null", &[]),
                        ValueRef::Integer(value) => hasher.field("integer", &value.to_be_bytes()),
                        ValueRef::Real(value) => hasher.field("real", &value.to_be_bytes()),
                        ValueRef::Text(value) => hasher.field("text", value),
                        ValueRef::Blob(value) => hasher.field("blob", value),
                    }
                }
                match row_kind {
                    0 => {
                        header += 1;
                        let selected_config: Vec<u8> = row.get(3)?;
                        let selected_producer: Vec<u8> = row.get(2)?;
                        if selected_config != config_digest.as_bytes()
                            || selected_producer != producer_digest.as_bytes()
                        {
                            return Ok(None);
                        }
                        if row.get::<_, i64>(9)? != 1 {
                            return Ok(None);
                        }
                        if row.get::<_, i64>(4)? != 1
                            || row.get::<_, String>(5)? != "complete"
                            || row.get::<_, i64>(6)? != 1
                            || row.get::<_, String>(7)? != "complete"
                            || row.get::<_, i64>(8)? != 1
                        {
                            put(6, RustCopyAbsenceReason::PublicationIncomplete);
                        }
                    }
                    1 => {
                        if row.get::<_, Option<i64>>(5)? != Some(1) {
                            put(1, RustCopyAbsenceReason::CensusMissing);
                        } else if row.get::<_, Option<i64>>(6)? != row.get::<_, Option<i64>>(7)?
                            || row.get::<_, Option<i64>>(8)? != row.get::<_, Option<i64>>(10)?
                        {
                            put(1, RustCopyAbsenceReason::CensusCorrupt);
                        }
                        if row.get::<_, Option<String>>(3)?.as_deref() != Some("complete")
                            || row.get::<_, Option<i64>>(4)? != Some(2)
                            || row.get::<_, i64>(9)? != 0
                        {
                            put(6, RustCopyAbsenceReason::PublicationIncomplete);
                        }
                        if row.get::<_, i64>(11)? != 0 {
                            put(3, RustCopyAbsenceReason::ModuleUniverseOpen);
                        }
                    }
                    2 => {
                        let kind = row.get::<_, i64>(4)?;
                        // Only a macro boundary (kind 0) can be certified item-free.
                        if kind != 0
                            || !super::rust_drop_inventory::RustCensusMacroBoundary::from_row(row)?
                                .is_item_free(selected_stdlib_revision)
                        {
                            put(2, RustCopyAbsenceReason::Boundary(kind as u8));
                        }
                    }
                    3 => {
                        let trait_present = row.get::<_, i64>(4)? != 0;
                        let pairs: i64 = row.get(5)?;
                        let inherent: i64 = row.get(6)?;
                        let unresolved: i64 = row.get(7)?;
                        if !trait_present && unresolved != 0 {
                            put(4, RustCopyAbsenceReason::UnresolvedSubject);
                        } else if (trait_present && pairs != 1) || (!trait_present && inherent != 1)
                        {
                            put(4, RustCopyAbsenceReason::UnpairedImpl);
                        }
                    }
                    4 => {
                        let state: String = row.get(6)?;
                        if row.get::<_, i64>(13)? != 1
                            || row.get::<_, Option<String>>(11)?.is_none()
                        {
                            put(4, RustCopyAbsenceReason::UnpairedImpl);
                        } else if state != "resolved"
                            || row.get::<_, Option<Vec<u8>>>(9)?.is_none()
                            || row.get::<_, Option<i64>>(10)?.is_none()
                        {
                            put(4, RustCopyAbsenceReason::UnresolvedSubject);
                        } else if row.get::<_, Option<i64>>(10)? == Some(13) {
                            put(4, RustCopyAbsenceReason::AliasSubject);
                        } else if row.get::<_, Option<i64>>(10)?.is_none() {
                            put(4, RustCopyAbsenceReason::UnresolvedSubject);
                        } else if row.get::<_, Option<Vec<u8>>>(7)?.as_deref()
                            == Some(target_unit.as_bytes().as_slice())
                            && row.get::<_, Option<String>>(8)?.as_deref()
                                == Some(module_path.as_ref())
                            && row.get::<_, Option<Vec<u8>>>(9)?.as_deref()
                                == Some(target_identity_digest.as_bytes().as_slice())
                        {
                            put(4, RustCopyAbsenceReason::MatchingTraitImpl);
                        }
                    }
                    5 => {
                        let kind: String = row.get(1)?;
                        if matches!(
                            kind.as_str(),
                            "unknown_activation" | "unplaced_module" | "duplicate_placement"
                        ) {
                            put(3, RustCopyAbsenceReason::ModuleUniverseOpen);
                        }
                    }
                    8 => put(4, RustCopyAbsenceReason::UnpairedImpl),
                    9 => {
                        if row.get::<_, i64>(7)? != 1 {
                            put(4, RustCopyAbsenceReason::UnresolvedSubject);
                        }
                        match row.get::<_, Option<i64>>(5)? {
                            Some(13) => put(4, RustCopyAbsenceReason::AliasSubject),
                            None => put(4, RustCopyAbsenceReason::UnresolvedSubject),
                            Some(_) => {}
                        }
                    }
                    _ => return Err(StoreError::corrupt("unknown Rust Copy absence row kind")),
                }
            }
            if header != 1 {
                return Ok(None);
            }
            if cancellation.is_cancelled() {
                return Err(StoreError::cancelled("Rust Copy absence read cancelled"));
            }
            Ok(Some((
                match reason {
                    Some((_, reason)) => RustCopyAbsence::Unknown(reason),
                    None => RustCopyAbsence::Absent {
                        digest: StableDigest::from_array(hasher.finish()),
                    },
                },
                row_count,
            )))
        })
    }
}

#[cfg(test)]
mod tests {
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
    use brokk_bifrost_test_macros::hardwon;

    use super::super::AnalyzerStore;
    use super::super::planner_statistics::pinned_plans::pinned_queries;

    #[test]
    #[hardwon(
        "#6394: cross-file reads must seek by key; the impl and gap arms now read unit-summary rows"
    )]
    fn copy_absence_impl_and_gap_arms_seek_summary_rows_by_their_keys() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().unwrap();
        store
            .select_writer_workspace_snapshots(&conn, &Default::default())
            .unwrap();
        let query = pinned_queries()
            .into_iter()
            .find(|query| query.name == "rust_copy_absence")
            .unwrap();
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            let plan = conn
                .prepare(&format!("EXPLAIN QUERY PLAN {}", query.sql))
                .unwrap()
                .query_map(rusqlite::params_from_iter(query.params.iter()), |row| {
                    row.get::<_, String>(3)
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            for expected in [
                // per-member inherent and unresolved-inherent counts
                "rust_summary_inherent_declaration (summary_id=? AND impl_member_ordinal=? AND impl_declaration_id=?)",
                "rust_summary_unresolved_inherent_declaration (summary_id=? AND impl_member_ordinal=? AND impl_declaration_id=?)",
                // the foreign subject's one declaration export, by name form
                "rust_summary_decl_export_endpoint (summary_id=? AND module_path=? AND namespace=? AND name=?",
                // the subject rows of one impl member
                "SEARCH h USING PRIMARY KEY (summary_id=? AND impl_member_ordinal=?)",
            ] {
                assert!(
                    plan.iter().any(|step| step.contains(expected)),
                    "{state:?}: missing {expected}: {plan:?}"
                );
            }
            // The gap arm reads both summary gap tables of the one selected unit.
            assert!(
                plan.iter()
                    .any(|step| step.contains("gaps") && step.contains("summary_id=?")),
                "{state:?}: the gap arm does not seek by summary: {plan:?}"
            );
            // No arm reads the topology's impl, gap or source tables any more, and no
            // summary table is read by a scan of every unit.
            for step in &plan {
                assert!(
                    !step.contains("rust_crate_inherent_impls")
                        && !step.contains("rust_crate_unresolved_inherent_impls")
                        && !step.contains("rust_crate_gaps")
                        && !step.contains("rust_crate_container_sources")
                        // The pairs CTE's own automatic index is not a table probe.
                        && !(step.contains("AUTOMATIC")
                            && (step.contains("inherent") || step.contains("gaps")))
                        && !(step.starts_with("SCAN")
                            && step.contains("rust_resolution_unit_summary_")),
                    "{state:?}: {step}: {plan:?}"
                );
            }
        }
    }
}
