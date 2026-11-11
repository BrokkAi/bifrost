//! Selected-live Rust spelling inventories shared by execution and replay.
use super::resolution::with_resolution_read_progress_handler;
use super::{AnalyzerStore, Result, WorkspaceSnapshots};
use crate::analyzer::Language;
use crate::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_semantic::analyzer::semantic::{
    ids::StableDigest,
    read_ledger::{LookupKind, LookupQuestion},
};
use git2::Oid;
use rusqlite::params;

/// Query-scoped rows retain the existing fact-source return shapes.
pub type RustBoundImplRow = (Oid, String, Option<u32>, Option<(Oid, u32, String)>);

pub enum RustInventoryRows {
    Bound(Vec<RustBoundImplRow>),
    Macros(Vec<super::StoredMacroExpansionBlob>),
    Unresolved(Vec<(Oid, String, Option<u32>)>),
    Imports(Vec<Oid>),
    Occurrences(Vec<(Oid, u32)>),
}

pub struct RustInventoryAnswer {
    pub rows: RustInventoryRows,
    pub digest: StableDigest,
    pub incomplete: Vec<RustInventoryIncomplete>,
}

/// Readiness failures are snapshot evidence, not operational store errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RustInventoryIncomplete {
    SelectedRevisionMissing,
    SourceFactsUnsealed,
    WorkspaceSourceRefused,
    SummaryMembershipMissing,
    SummaryUnpublished,
    TopologyUnpublished,
    SummaryInventoryIncomplete,
    TopologyInventoryIncomplete,
}

#[derive(Clone, Copy)]
struct RustInventoryReadiness([bool; 8]);

impl RustInventoryReadiness {
    fn reasons(self, kind: LookupKind) -> Vec<RustInventoryIncomplete> {
        use RustInventoryIncomplete::*;
        let clauses = [
            SelectedRevisionMissing,
            SourceFactsUnsealed,
            WorkspaceSourceRefused,
            SummaryMembershipMissing,
            SummaryUnpublished,
            TopologyUnpublished,
            SummaryInventoryIncomplete,
            TopologyInventoryIncomplete,
        ];
        let count = if matches!(
            kind,
            LookupKind::RustBoundTraitImplInventory
                | LookupKind::RustTraitsImplementedByInventory
                | LookupKind::RustUnresolvedTraitImplInventory
        ) {
            8
        } else {
            3
        };
        clauses
            .into_iter()
            .zip(self.0)
            .take(count)
            .filter_map(|(reason, ready)| (!ready).then_some(reason))
            .collect()
    }

    fn allows_rows(self, kind: LookupKind) -> bool {
        self.0[0]
            && self.0[1]
            && (!matches!(
                kind,
                LookupKind::RustBoundTraitImplInventory
                    | LookupKind::RustTraitsImplementedByInventory
                    | LookupKind::RustUnresolvedTraitImplInventory
            ) || (self.0[4] && self.0[5]))
    }

    fn answer(
        self,
        kind: LookupKind,
        rows: RustInventoryRows,
        mut hash: CanonicalHasher,
    ) -> RustInventoryAnswer {
        let incomplete = self.reasons(kind);
        // The readiness projection is part of the replayed answer even when
        // no rows changed. Repairing a partial workspace invalidates its receipt.
        for reason in &incomplete {
            hash.field("incomplete", format!("{reason:?}").as_bytes());
        }
        RustInventoryAnswer {
            rows,
            digest: StableDigest::from_array(hash.finish()),
            incomplete,
        }
    }

    fn empty(self, kind: LookupKind) -> RustInventoryAnswer {
        let rows = match kind {
            LookupKind::RustBoundTraitImplInventory
            | LookupKind::RustTraitsImplementedByInventory => RustInventoryRows::Bound(Vec::new()),
            LookupKind::RustMacroExpansionInventory => RustInventoryRows::Macros(Vec::new()),
            LookupKind::RustUnresolvedTraitImplInventory => {
                RustInventoryRows::Unresolved(Vec::new())
            }
            LookupKind::RustModuleImportCandidateInventory | LookupKind::RustAliasBlobInventory => {
                RustInventoryRows::Imports(Vec::new())
            }
            LookupKind::RustIdentifierOccurrenceInventory => {
                RustInventoryRows::Occurrences(Vec::new())
            }
            _ => unreachable!("not a Rust inventory"),
        };
        let mut hash = CanonicalHasher::new(b"bifrost-rust-unready-inventory:v1");
        hash.field("kind", format!("{kind:?}").as_bytes());
        self.answer(kind, rows, hash)
    }
}

#[doc(hidden)]
pub const OCCURRENCES: &str = "SELECT DISTINCT b.blob_oid, live.rel_path, o.context_mask
 FROM rust_identifier_occurrences o
 CROSS JOIN blobs b ON b.id=o.blob_id
 CROSS JOIN live_workspace_files live ON live.blob_id=o.blob_id
 WHERE o.lang='rust' AND o.identifier=?1 ORDER BY 1,2,3";
#[doc(hidden)]
pub const IMPORTS: &str = "SELECT DISTINCT b.blob_oid, live.rel_path, NULL
 FROM rust_identifier_occurrences o
 CROSS JOIN source_rust_import_targets i ON i.blob_id=o.blob_id
 CROSS JOIN blobs b ON b.id=o.blob_id
 CROSS JOIN live_workspace_files live ON live.blob_id=o.blob_id
 WHERE o.lang='rust' AND o.identifier=?1
 AND (i.imported_name=?1 OR i.module_path=?1 OR i.module_path LIKE '%::' || ?1)
 ORDER BY 1,2,3";
#[doc(hidden)]
pub const UNRESOLVED: &str = "SELECT DISTINCT b.blob_oid, m.rel_path, e.impl_declaration_id
 FROM rust_resolution_unit_summary_trait_endpoints e
 INDEXED BY rust_resolution_unit_summary_trait_endpoints_unresolved
 CROSS JOIN selected_rust_unit_summaries u ON u.summary_id=e.summary_id
 CROSS JOIN resolution_unit_summary_members m ON m.summary_id=e.summary_id AND m.member_ordinal=e.member_ordinal
 CROSS JOIN blobs b ON b.id=m.blob_id
 CROSS JOIN live_workspace_files live ON live.blob_id=m.blob_id AND live.rel_path=m.rel_path
 WHERE e.endpoint_role='trait' AND e.endpoint_state='unresolved' AND e.unresolved_spelling=?1
 ORDER BY 1,2,3";

#[doc(hidden)]
pub const BOUND: &str = "SELECT DISTINCT ib.blob_oid, im.rel_path, e.impl_declaration_id,
 sb.blob_oid, bridge.declaration_id, sm.rel_path
 FROM blobs asked
 CROSS JOIN source_native_declaration_bridges a INDEXED BY source_native_declaration_bridges_declaration ON a.blob_id=asked.id AND a.declaration_id=?2
 CROSS JOIN resolution_unit_summary_members am INDEXED BY resolution_unit_summary_members_blob ON am.blob_id=asked.id AND am.rel_path=?3
 CROSS JOIN selected_rust_unit_summaries au ON au.summary_id=am.summary_id
 CROSS JOIN live_workspace_files al ON al.blob_id=am.blob_id AND al.rel_path=am.rel_path
 CROSS JOIN rust_resolution_unit_summary_exports ae INDEXED BY rust_resolution_unit_summary_exports_declaration ON ae.summary_id=am.summary_id AND ae.declaration_member_ordinal=am.member_ordinal AND ae.declaration_site=a.source_site AND ae.namespace='type' AND ae.origin='declaration'
 CROSS JOIN rust_resolution_unit_summary_trait_endpoints e INDEXED BY rust_resolution_unit_summary_trait_endpoints_target ON e.target_unit_key=au.unit_key AND e.target_module_path=ae.module_path AND e.target_identity_id=ae.identity_id AND e.endpoint_role='trait' AND e.endpoint_state='resolved'
 CROSS JOIN selected_rust_unit_summaries iu ON iu.summary_id=e.summary_id
 CROSS JOIN resolution_unit_summary_members im ON im.summary_id=e.summary_id AND im.member_ordinal=e.member_ordinal
 CROSS JOIN blobs ib ON ib.id=im.blob_id
 CROSS JOIN live_workspace_files il ON il.blob_id=im.blob_id AND il.rel_path=im.rel_path
 CROSS JOIN rust_resolution_unit_summary_trait_endpoints subject ON subject.summary_id=e.summary_id AND subject.member_ordinal=e.member_ordinal AND subject.owner_module_path=e.owner_module_path AND subject.source_relation_key=e.source_relation_key AND subject.endpoint_role='subject' AND subject.endpoint_state='resolved'
 CROSS JOIN selected_rust_unit_summaries su ON su.unit_key=subject.target_unit_key
 CROSS JOIN rust_resolution_unit_summary_exports se INDEXED BY rust_resolution_unit_summary_exports_identity ON se.summary_id=su.summary_id AND se.identity_id=subject.target_identity_id AND se.module_path=subject.target_module_path AND se.namespace='type' AND se.origin='declaration'
 CROSS JOIN resolution_unit_summary_members sm ON sm.summary_id=se.summary_id AND sm.member_ordinal=se.declaration_member_ordinal
 CROSS JOIN blobs sb ON sb.id=sm.blob_id
 CROSS JOIN live_workspace_files sl ON sl.blob_id=sm.blob_id AND sl.rel_path=sm.rel_path
 LEFT JOIN source_native_declaration_bridges bridge ON bridge.blob_id=sm.blob_id AND bridge.source_site=se.declaration_site
 WHERE asked.blob_oid=?1 AND asked.lang='rust' AND asked.parse_variant=x''
 ORDER BY 1,2,3,4,5,6";

#[doc(hidden)]
pub const IMPLEMENTED: &str = "SELECT DISTINCT ib.blob_oid, im.rel_path, e.impl_declaration_id,
 sb.blob_oid, bridge.declaration_id, sm.rel_path
 FROM blobs asked
 CROSS JOIN source_native_declaration_bridges a INDEXED BY source_native_declaration_bridges_declaration ON a.blob_id=asked.id AND a.declaration_id=?2
 CROSS JOIN resolution_unit_summary_members am INDEXED BY resolution_unit_summary_members_blob ON am.blob_id=asked.id AND am.rel_path=?3
 CROSS JOIN selected_rust_unit_summaries au ON au.summary_id=am.summary_id
 CROSS JOIN live_workspace_files al ON al.blob_id=am.blob_id AND al.rel_path=am.rel_path
 CROSS JOIN rust_resolution_unit_summary_exports ae INDEXED BY rust_resolution_unit_summary_exports_declaration ON ae.summary_id=am.summary_id AND ae.declaration_member_ordinal=am.member_ordinal AND ae.declaration_site=a.source_site AND ae.namespace='type' AND ae.origin='declaration'
 CROSS JOIN rust_resolution_unit_summary_trait_endpoints e INDEXED BY rust_resolution_unit_summary_trait_endpoints_target ON e.target_unit_key=au.unit_key AND e.target_module_path=ae.module_path AND e.target_identity_id=ae.identity_id AND e.endpoint_role='subject' AND e.endpoint_state='resolved'
 CROSS JOIN selected_rust_unit_summaries iu ON iu.summary_id=e.summary_id
 CROSS JOIN resolution_unit_summary_members im ON im.summary_id=e.summary_id AND im.member_ordinal=e.member_ordinal
 CROSS JOIN blobs ib ON ib.id=im.blob_id
 CROSS JOIN live_workspace_files il ON il.blob_id=im.blob_id AND il.rel_path=im.rel_path
 CROSS JOIN rust_resolution_unit_summary_trait_endpoints subject ON subject.summary_id=e.summary_id AND subject.member_ordinal=e.member_ordinal AND subject.owner_module_path=e.owner_module_path AND subject.source_relation_key=e.source_relation_key AND subject.endpoint_role='trait' AND subject.endpoint_state='resolved'
 CROSS JOIN selected_rust_unit_summaries su ON su.unit_key=subject.target_unit_key
 CROSS JOIN rust_resolution_unit_summary_exports se INDEXED BY rust_resolution_unit_summary_exports_identity ON se.summary_id=su.summary_id AND se.identity_id=subject.target_identity_id AND se.module_path=subject.target_module_path AND se.namespace='type' AND se.origin='declaration'
 CROSS JOIN resolution_unit_summary_members sm ON sm.summary_id=se.summary_id AND sm.member_ordinal=se.declaration_member_ordinal
 CROSS JOIN blobs sb ON sb.id=sm.blob_id
 CROSS JOIN live_workspace_files sl ON sl.blob_id=sm.blob_id AND sl.rel_path=sm.rel_path
 LEFT JOIN source_native_declaration_bridges bridge ON bridge.blob_id=sm.blob_id AND bridge.source_site=se.declaration_site
 WHERE asked.blob_oid=?1 AND asked.lang='rust' AND asked.parse_variant=x''
 ORDER BY 1,2,3,4,5,6";

#[doc(hidden)]
pub const ALIASES: &str = "SELECT DISTINCT b.blob_oid, live.rel_path, NULL
 FROM rust_identifier_occurrences o
 CROSS JOIN source_rust_alias_items a ON a.blob_id=o.blob_id
 CROSS JOIN blobs b ON b.id=o.blob_id
 CROSS JOIN live_workspace_files live ON live.blob_id=o.blob_id
 WHERE o.lang='rust' AND o.identifier=?1 ORDER BY 1,2,3";

#[doc(hidden)]
pub const MACROS: &str = "WITH RECURSIVE
     names(name) AS (
       SELECT ?1
       UNION
       SELECT definition.macro_name
       FROM names
       CROSS JOIN rust_identifier_occurrences AS occurrence
         ON occurrence.lang = 'rust' AND occurrence.identifier = names.name
        AND (occurrence.context_mask & ?2) != 0
        AND EXISTS(SELECT 1 FROM live_workspace_files live WHERE live.blob_id=occurrence.blob_id)
       CROSS JOIN source_rust_item_macros AS definition
         ON definition.blob_id = occurrence.blob_id
     ),
     writers(blob_id) AS (
       SELECT occurrence.blob_id
       FROM names
       CROSS JOIN rust_identifier_occurrences AS occurrence
         ON occurrence.lang = 'rust' AND occurrence.identifier = names.name
        AND (occurrence.context_mask & ?2) != 0
        AND EXISTS(SELECT 1 FROM live_workspace_files live WHERE live.blob_id=occurrence.blob_id)
     ),
     macros(name, blob_id) AS (
       SELECT DISTINCT definition.macro_name, definition.blob_id
       FROM writers
       CROSS JOIN source_rust_item_macros AS definition
         ON definition.blob_id = writers.blob_id
     )
     SELECT keys.blob_oid, live.rel_path, NULL, NULL
     FROM writers CROSS JOIN blobs AS keys ON keys.id = writers.blob_id
     CROSS JOIN live_workspace_files AS live ON live.blob_id = writers.blob_id
     UNION
     SELECT keys.blob_oid, live.rel_path, macros.name, defining.blob_oid
     FROM macros
     CROSS JOIN rust_identifier_occurrences AS occurrence
       ON occurrence.lang = 'rust' AND occurrence.identifier = macros.name
      AND (occurrence.context_mask & ?3) != 0
     CROSS JOIN live_workspace_files AS live ON live.blob_id = occurrence.blob_id
     CROSS JOIN blobs AS keys ON keys.id = occurrence.blob_id
     CROSS JOIN blobs AS defining ON defining.id = macros.blob_id";

/// Readiness evidence owned exclusively by one outer query. Each selected
/// snapshot is checked once, independently of spelling and inventory shape.
#[derive(Default)]
pub struct RustInventoryReadinessMemo {
    entries: std::sync::Mutex<Vec<(WorkspaceSnapshots, RustInventoryReadiness)>>,
}

impl RustInventoryReadinessMemo {
    fn readiness(
        &self,
        conn: &rusqlite::Connection,
        snapshots: &WorkspaceSnapshots,
    ) -> Result<RustInventoryReadiness> {
        let mut entries = self
            .entries
            .lock()
            .expect("inventory readiness mutex poisoned");
        if let Some((_, readiness)) = entries.iter().find(|(key, _)| key == snapshots) {
            return Ok(*readiness);
        }
        let readiness = conn.prepare_cached(READINESS)?.query_row(
            params![super::rust_unit_summaries::RUST_UNIT_SUMMARY_DERIVATION_VERSION],
            |row| {
                Ok(RustInventoryReadiness([
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ]))
            },
        )?;
        entries.push((snapshots.clone(), readiness));
        Ok(readiness)
    }
}

// Summary completeness describes name resolution, not enumeration. Unresolved
// imports and open exports are precisely why U must enumerate unresolved impls.
// Require published summaries and complete file/unit inventories instead.
const READINESS: &str = "SELECT
 EXISTS(SELECT 1 FROM selected_workspace_revisions WHERE lang='rust'),
 NOT EXISTS(SELECT 1 FROM selected_workspace_file_versions f
 LEFT JOIN live_workspace_files live ON live.file_id=f.file_version_id
 LEFT JOIN source_fact_manifests seal ON seal.blob_id=live.blob_id
 WHERE f.lang='rust' AND (live.blob_id IS NULL OR seal.publication_state IS NOT 'complete')),
 NOT EXISTS(SELECT 1 FROM selected_workspace_revisions s
 CROSS JOIN workspace_source_refusals r ON r.workspace_id=s.workspace_id AND r.lang=s.lang AND r.generation=s.generation
 WHERE s.lang='rust' AND r.valid_from<=s.revision AND (r.valid_until IS NULL OR s.revision<r.valid_until)),
 NOT EXISTS(SELECT 1 FROM live_workspace_files live
 WHERE live.lang='rust' AND NOT EXISTS(
 SELECT 1 FROM resolution_unit_summary_members m
 JOIN selected_rust_unit_summaries u ON u.summary_id=m.summary_id
 WHERE m.blob_id=live.blob_id AND m.rel_path=live.rel_path)),
 NOT EXISTS(SELECT 1 FROM selected_rust_unit_summaries u
 JOIN resolution_unit_summaries s ON s.summary_id=u.summary_id
 WHERE s.derivation_version<>?1 OR s.publication_state<>'complete'),
 NOT EXISTS(SELECT 1 FROM selected_rust_unit_summaries u
 JOIN rust_crate_topologies t ON t.topology_id=u.topology_id
 WHERE t.publication_state<>'complete'),
 NOT EXISTS(SELECT 1 FROM selected_rust_unit_summaries u
 LEFT JOIN rust_resolution_unit_summary_contexts c ON c.summary_id=u.summary_id
 WHERE c.inventory_complete IS NOT 1),
 NOT EXISTS(SELECT 1 FROM selected_rust_unit_summaries u
 JOIN rust_crate_topologies t ON t.topology_id=u.topology_id
 WHERE t.inventory_complete<>1)
";

impl AnalyzerStore {
    /// None means cancellation, budget exhaustion, or an unsupported question.
    /// Readiness failures return typed incomplete answers; unsealed source facts
    /// and unpublished summaries return no rows.
    /// Empty successful inventories carry a normal domain-separated digest.
    /// Imports and occurrences include every live published file, including files
    /// with unknown placement or unit, as possibly belonging to any unit. Only
    /// unresolved impls require published selected summaries and crate topologies;
    /// incomplete unit or topology inventories return their sound rows with typed
    /// incompleteness. Unresolved names do not prevent enumeration.
    pub fn rust_inventory_answer(
        &self,
        snapshots: &WorkspaceSnapshots,
        kind: LookupKind,
        question: &LookupQuestion,
        cancellation: &CancellationToken,
        row_budget: usize,
        readiness: &RustInventoryReadinessMemo,
    ) -> Result<Option<RustInventoryAnswer>> {
        if let (
            LookupKind::RustBoundTraitImplInventory | LookupKind::RustTraitsImplementedByInventory,
            LookupQuestion::RustPlacedDeclaration {
                blob,
                declaration,
                rel_path,
            },
        ) = (kind, question)
        {
            let mut conn = self.read_conn_for_workspace(snapshots)?;
            let tx = conn.transaction()?;
            return with_resolution_read_progress_handler(&tx, cancellation, |conn| {
                let ready = readiness.readiness(conn, snapshots)?;
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                if !ready.allows_rows(kind) {
                    return Ok(Some(ready.empty(kind)));
                }
                let mut statement = conn.prepare_cached(match kind {
                    LookupKind::RustBoundTraitImplInventory => BOUND,
                    LookupKind::RustTraitsImplementedByInventory => IMPLEMENTED,
                    _ => unreachable!(),
                })?;
                let mut stream = statement.query(params![
                    Oid::from_bytes(blob)?.to_string(),
                    declaration,
                    rel_path.as_ref()
                ])?;
                let mut rows = Vec::new();
                while let Some(row) = stream.next()? {
                    if cancellation.is_cancelled() || rows.len() >= row_budget {
                        return Ok(None);
                    }
                    let subject = row
                        .get::<_, Option<u32>>(4)?
                        .map(|declaration| -> Result<_> {
                            Ok((
                                Oid::from_str(&row.get::<_, String>(3)?)?,
                                declaration,
                                row.get::<_, String>(5)?,
                            ))
                        })
                        .transpose()?;
                    rows.push((
                        Oid::from_str(&row.get::<_, String>(0)?)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<u32>>(2)?,
                        subject,
                    ));
                }
                rows.sort();
                rows.dedup();
                let mut hash = CanonicalHasher::new(match kind {
                    LookupKind::RustTraitsImplementedByInventory => {
                        b"bifrost-rust-traits-implemented-by-inventory:v1".as_slice()
                    }
                    _ => b"bifrost-rust-bound-trait-impl-inventory:v1".as_slice(),
                });
                hash.field("count", &(rows.len() as u64).to_be_bytes());
                for (blob, path, declaration, subject) in &rows {
                    hash.field("blob", blob.as_bytes());
                    hash.field("path", path.as_bytes());
                    hash.field("declaration-present", &[u8::from(declaration.is_some())]);
                    if let Some(declaration) = declaration {
                        hash.field("declaration", &declaration.to_be_bytes());
                    }
                    hash.field("subject-present", &[u8::from(subject.is_some())]);
                    if let Some((blob, declaration, path)) = subject {
                        hash.field("subject-blob", blob.as_bytes());
                        hash.field("subject-declaration", &declaration.to_be_bytes());
                        hash.field("subject-path", path.as_bytes());
                    }
                }
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                Ok(Some(ready.answer(
                    kind,
                    RustInventoryRows::Bound(rows),
                    hash,
                )))
            });
        }
        let LookupQuestion::Name {
            language: Some(Language::Rust),
            name,
        } = question
        else {
            return Ok(None);
        };
        if kind == LookupKind::RustMacroExpansionInventory {
            let mut conn = self.read_conn_for_workspace(snapshots)?;
            let tx = conn.transaction()?;
            return with_resolution_read_progress_handler(&tx, cancellation, |conn| {
                let ready = readiness.readiness(conn, snapshots)?;
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                if !ready.allows_rows(kind) {
                    return Ok(Some(ready.empty(kind)));
                }
                let mut statement = conn.prepare_cached(MACROS)?;
                let mut stream = statement.query(params![
                    name.as_ref(),
                    super::RUST_OCCURRENCE_MACRO,
                    super::RUST_OCCURRENCE_CODE | super::RUST_OCCURRENCE_MACRO
                ])?;
                // Consumers expand each blob to every live path and read it
                // there, so the answer identity covers each live placement.
                let mut placed = Vec::new();
                while let Some(row) = stream.next()? {
                    if cancellation.is_cancelled() || placed.len() >= row_budget {
                        return Ok(None);
                    }
                    let via = match (
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ) {
                        (Some(name), Some(blob)) => Some((name, Oid::from_str(&blob)?)),
                        (None, None) => None,
                        other => unreachable!("macro reason must include name and blob: {other:?}"),
                    };
                    placed.push((
                        super::StoredMacroExpansionBlob {
                            blob: Oid::from_str(&row.get::<_, String>(0)?)?,
                            via,
                        },
                        row.get::<_, String>(1)?,
                    ));
                }
                placed.sort();
                placed.dedup();
                let mut hash = CanonicalHasher::new(b"bifrost-rust-macro-expansion-inventory:v1");
                hash.field("count", &(placed.len() as u64).to_be_bytes());
                for (row, path) in &placed {
                    hash.field("blob", row.blob.as_bytes());
                    hash.field("path", path.as_bytes());
                    hash.field("via-present", &[u8::from(row.via.is_some())]);
                    if let Some((name, blob)) = &row.via {
                        hash.field("via-name", name.as_bytes());
                        hash.field("via-blob", blob.as_bytes());
                    }
                }
                let mut rows = placed.into_iter().map(|(row, _)| row).collect::<Vec<_>>();
                rows.sort();
                rows.dedup();
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                Ok(Some(ready.answer(
                    kind,
                    RustInventoryRows::Macros(rows),
                    hash,
                )))
            });
        }
        let (sql, domain): (&str, &[u8]) = match kind {
            LookupKind::RustUnresolvedTraitImplInventory => {
                (UNRESOLVED, b"bifrost-rust-unresolved-impl-inventory:v1")
            }
            LookupKind::RustModuleImportCandidateInventory => {
                (IMPORTS, b"bifrost-rust-import-inventory:v1")
            }
            LookupKind::RustIdentifierOccurrenceInventory => {
                (OCCURRENCES, b"bifrost-rust-occurrence-inventory:v1")
            }
            LookupKind::RustAliasBlobInventory => {
                (ALIASES, b"bifrost-rust-alias-blob-inventory:v1")
            }
            _ => return Ok(None),
        };
        let mut conn = self.read_conn_for_workspace(snapshots)?;
        let tx = conn.transaction()?;
        with_resolution_read_progress_handler(&tx, cancellation, |conn| {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let ready = readiness.readiness(conn, snapshots)?;
            if !ready.allows_rows(kind) {
                return Ok(Some(ready.empty(kind)));
            }
            let mut statement = conn.prepare_cached(sql)?;
            let mut stream = statement.query(params![name.as_ref()])?;
            let mut rows = Vec::new();
            loop {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let Some(row) = stream.next()? else { break };
                // An inventory of exactly row_budget rows fits; refuse only a
                // row beyond it, as the bound and macro readers do.
                if rows.len() >= row_budget {
                    return Ok(None);
                }
                rows.push((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<u32>>(2)?,
                ));
            }
            let mut hash = CanonicalHasher::new(domain);
            hash.field("count", &(rows.len() as u64).to_be_bytes());
            let mut unresolved = Vec::new();
            let mut imports = Vec::new();
            let mut occurrences = Vec::new();
            for (oid, path, value) in rows {
                let oid = Oid::from_str(&oid)?;
                hash.field("blob", oid.as_bytes());
                hash.field("path", path.as_bytes());
                hash.field("present", &[u8::from(value.is_some())]);
                if let Some(value) = value {
                    hash.field("value", &value.to_be_bytes());
                }
                match kind {
                    LookupKind::RustUnresolvedTraitImplInventory => {
                        unresolved.push((oid, path, value))
                    }
                    LookupKind::RustModuleImportCandidateInventory
                    | LookupKind::RustAliasBlobInventory => imports.push(oid),
                    LookupKind::RustIdentifierOccurrenceInventory => {
                        occurrences.push((oid, value.expect("context mask is non-null")))
                    }
                    _ => unreachable!(),
                }
            }
            // Rows carry each live placement for the digest; the answer keeps
            // one entry per blob, which consumers expand to its live paths.
            imports.dedup();
            occurrences.sort_unstable();
            occurrences.dedup();
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let rows = match kind {
                LookupKind::RustUnresolvedTraitImplInventory => {
                    RustInventoryRows::Unresolved(unresolved)
                }
                LookupKind::RustModuleImportCandidateInventory
                | LookupKind::RustAliasBlobInventory => RustInventoryRows::Imports(imports),
                LookupKind::RustIdentifierOccurrenceInventory => {
                    RustInventoryRows::Occurrences(occurrences)
                }
                _ => unreachable!(),
            };
            Ok(Some(ready.answer(kind, rows, hash)))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_inventory_queries_seek_spelling_indexes() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store.conn.execute_fixture(|conn| {
            conn.execute_batch("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<256)
                INSERT INTO blobs(id,blob_oid,lang,generation) SELECT x,printf('%040x',x),'rust',0 FROM n;
                INSERT INTO rust_identifier_occurrences(blob_id,lang,identifier,context_mask)
                SELECT id,'rust','Clone',3 FROM blobs;").unwrap();
        });
        for analyzed in [false, true] {
            if analyzed {
                store
                    .conn
                    .execute_fixture(|conn| conn.execute_batch("ANALYZE").unwrap());
            }
            let conn = store.read_conn().unwrap();
            for (sql, index) in [
                (
                    UNRESOLVED,
                    "rust_resolution_unit_summary_trait_endpoints_unresolved",
                ),
                (IMPORTS, "idx_rust_identifier_occurrences"),
                (OCCURRENCES, "idx_rust_identifier_occurrences"),
                (MACROS, "idx_rust_identifier_occurrences"),
            ] {
                let sql = sql.replace("?2", "2").replace("?3", "3");
                let mut statement = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
                let plan = statement
                    .query_map(["Clone"], |row| row.get::<_, String>(3))
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                assert!(
                    plan.iter()
                        .any(|line| line.contains("SEARCH") && line.contains(index)),
                    "{plan:?}"
                );
                for relation in ["o", "e", "m", "i", "b"] {
                    assert!(
                        !plan.iter().any(|line| line == &format!("SCAN {relation}")
                            || line.starts_with(&format!("SCAN {relation} "))),
                        "{plan:?}"
                    );
                }
            }
        }
    }
}
