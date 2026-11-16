//! Borrowed crate-row reads shared by point compilation and endpoint demands.
use super::demand_closure::{
    RouteEdgeTier, RouteLocation, RouteRules, RouteStarts, WalkCursor, walk_container_route,
};
use super::rust_crate_context::*;
use super::*;
use crate::analyzer::resolution::{
    DeferredMemberOwnerLookupName, LoweredDeferredMemberOwner, mounted_site_node,
    mounted_site_semantic,
};
use crate::analyzer::store::rust_crates::derivation::gap_evidence;
use crate::analyzer::store::rust_unit_summaries::rust_unit_summary_derivation_identity;
use crate::analyzer::store::selected_read_memo::ExactReadMemo;
use brokk_bifrost_core::analyzer::model::ImportInfo;
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberKind;
use rusqlite::{OptionalExtension, params};

/// Absolute Rust roots retain canonical identity separately from route locations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustAbsoluteRoot {
    Indexed {
        topology: i64,
        consumed: usize,
    },
    /// Edition 2015: the crate root answers, and an active crate-root `use`
    /// binds the name. A caller may expand that import as it would for a
    /// relative path written in the crate root; no other import binds the name
    /// of a leading `::` path.
    CrateRootImport {
        topology: i64,
    },
    External(Vec<String>),
    Unavailable {
        reason: &'static str,
        deterministic: bool,
    },
}

impl SelectedResolutionOperation<'_, '_> {
    pub fn rust_absolute_root(
        &self,
        file: &ProjectFile,
        name: &str,
        namespace: ResolutionNamespace,
        cancellation: &CancellationToken,
    ) -> Result<RustAbsoluteRoot> {
        self.ready
            .rust_absolute_root(file, name, namespace, cancellation)
    }

    /// Import facts pinned by this selection.
    #[doc(hidden)]
    pub fn selected_rust_import_infos(
        &self,
        file: &ProjectFile,
        cfg_contexts: Option<&[std::collections::BTreeSet<String>]>,
        cancellation: &CancellationToken,
    ) -> Result<Option<(git2::Oid, Vec<ImportInfo>)>> {
        if !self.ensure_selected_rust_inputs(cancellation)? {
            return Ok(None);
        }
        self.ready
            .selected_rust_import_infos(file, cfg_contexts, cancellation)
    }
}

impl ReadySelectedResolution<'_, '_> {
    pub(super) fn rust_absolute_root(
        &self,
        file: &ProjectFile,
        name: &str,
        demand_namespace: ResolutionNamespace,
        cancellation: &CancellationToken,
    ) -> Result<RustAbsoluteRoot> {
        if cancellation.is_cancelled() {
            return Ok(RustAbsoluteRoot::Unavailable {
                reason: "absolute root inputs unavailable",
                deterministic: false,
            });
        }
        let conn = self.inventory.connection();
        let topologies = conn
            .prepare_cached(
                "SELECT DISTINCT unit.topology_id
 FROM selected_rust_unit_summaries AS unit
 JOIN main.resolution_unit_summary_members AS member ON member.summary_id=unit.summary_id
 WHERE member.rel_path=?1",
            )?
            .query_map([selected_path_key(file.rel_path())], |row| {
                row.get::<_, i64>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let rows = RustCrateRows { ready: self };
        let mut answer = None;
        for topology in topologies {
            let next = rows.absolute_root(topology, name, demand_namespace)?;
            if answer.as_ref().is_some_and(|prior| prior != &next) {
                return Ok(RustAbsoluteRoot::Unavailable {
                    reason: "ambiguous absolute root",
                    deterministic: true,
                });
            }
            answer = Some(next);
        }
        Ok(answer.unwrap_or(RustAbsoluteRoot::Unavailable {
            reason: "absolute root topology unavailable",
            deterministic: false,
        }))
    }
}

impl SelectedResolutionOperation<'_, '_> {
    /// Whether selected import facts need configuration authority at all.
    pub fn selected_rust_imports_have_cfg(
        &self,
        file: &ProjectFile,
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        if !self.ensure_selected_rust_inputs(cancellation)? {
            return Ok(true);
        }
        let Some(mount) = self
            .ready
            .inventory
            .mount_record_for_path("rust", &selected_path_key(file.rel_path()))?
        else {
            return Ok(true);
        };
        Ok(self
            .ready
            .inventory
            .connection()
            .prepare_cached(
                "SELECT EXISTS(SELECT 1 FROM source_rust_import_targets AS import
 JOIN blobs ON blobs.id=import.blob_id
 WHERE blobs.blob_oid=?1 AND blobs.lang='rust'
 AND import.cfg_condition<>'always')",
            )?
            .query_row([mount.blob_oid().to_string()], |row| row.get(0))?)
    }
}

impl ReadySelectedResolution<'_, '_> {
    /// Import facts pinned by this selection.
    #[doc(hidden)]
    pub(super) fn selected_rust_import_infos(
        &self,
        file: &ProjectFile,
        cfg_contexts: Option<&[std::collections::BTreeSet<String>]>,
        cancellation: &CancellationToken,
    ) -> Result<Option<(git2::Oid, Vec<ImportInfo>)>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let Some(mount) = self
            .inventory
            .mount_record_for_path("rust", &selected_path_key(file.rel_path()))?
        else {
            return Ok(None);
        };
        // Rust parses have one variant, so the selected blob uses the unvaried key.
        let imports = crate::analyzer::store::read_import_infos(
            self.inventory.connection(),
            &crate::analyzer::store::BlobKey::unvaried(mount.blob_oid(), "rust"),
        )?;
        // The generic import projection is ordinal ordered and links the same
        // producer-owned import ids as the Rust target rows. Keep a binder if
        // any selected compilation context can enable it (including Unknown).
        // Without a context there is no proof that a binder is disabled.
        let conn = self.inventory.connection();
        // Configuration derivation output is the sole activity source. The
        // caller records those demands; summary context rows are not read.
        // No certified contexts means no proof of inactivity.
        let contexts = serde_json::to_string(&cfg_contexts.unwrap_or_default())
            .expect("cfg contexts contain only strings");
        let inactive = conn
            .prepare_cached(
                "SELECT statement.ordinal
 FROM import_statements AS statement
 JOIN blobs ON blobs.id=statement.blob_id
 JOIN source_rust_import_targets AS import
  ON import.blob_id=statement.blob_id
 AND import.source_import_id=statement.source_import_id
 CROSS JOIN json_each(?2) AS context
 WHERE blobs.blob_oid=?1 AND blobs.lang='rust'
 GROUP BY statement.ordinal
 HAVING MIN(cr_cfg(import.cfg_condition, context.value))=0
    AND MAX(cr_cfg(import.cfg_condition, context.value))=0",
            )?
            .query_map(params![mount.blob_oid().to_string(), contexts], |row| {
                row.get::<_, i64>(0)
            })?
            .collect::<rusqlite::Result<std::collections::HashSet<_>>>()?;
        let ordinals = conn
            .prepare_cached(
                "SELECT ordinal FROM source_import_statements
 WHERE blob_id=(SELECT id FROM blobs WHERE blob_oid=?1 AND lang='rust' AND parse_variant=x'')
 ORDER BY ordinal",
            )?
            .query_map([mount.blob_oid().to_string()], |row| row.get::<_, i64>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        assert_eq!(
            imports.len(),
            ordinals.len(),
            "import facts and ordinals share the selected blob"
        );
        let imports = imports
            .into_iter()
            .zip(ordinals)
            .filter_map(|(import, ordinal)| (!inactive.contains(&ordinal)).then_some(import))
            .collect();
        Ok((!cancellation.is_cancelled()).then_some((mount.blob_oid(), imports)))
    }
}

/// The `unmounted` column and its `+` are explained beside
/// `rust_crate_context::MODULES`, which reads the same thing for the graph
/// route. The two must not drift. Both leave out a module with no persisted
/// resolution scope: an inline module an unproven item macro's expansion declares
/// outside the file's own lowering, whose body only a request-scoped capsule
/// lowers. No persisted reference is written in such a scope, so it is no
/// requester's module.
pub(super) const MODULES_FOR_BLOB: &str = "WITH request_roots(topology_id) AS (
 SELECT CAST(value AS INTEGER) FROM json_each(?3)
)
SELECT unit.topology_id, CASE placement.container_path WHEN '' THEN 'crate' ELSE placement.container_path END,
 blobs.id, member.rel_path, scopes.resolution_scope, contexts.edition,
 contexts.target_kind='detached' AND EXISTS(
  SELECT 1 FROM selected_rust_unit_summaries AS cargo
  CROSS JOIN main.rust_resolution_unit_summary_contexts AS cargo_context
   ON cargo_context.summary_id=cargo.summary_id
  WHERE cargo.workspace_id=unit.workspace_id AND cargo.generation=unit.generation
   AND cargo_context.target_kind<>'detached'),
 json_array_length(?3)=0 OR unit.topology_id IN (SELECT topology_id FROM request_roots)
 FROM main.resolution_unit_summary_members AS member
  INDEXED BY resolution_unit_summary_members_path
 CROSS JOIN selected_rust_unit_summaries AS unit ON unit.summary_id=member.summary_id
 CROSS JOIN selected_workspace_file_versions AS files
  ON files.workspace_id=unit.workspace_id AND files.lang=unit.lang
 AND files.generation=unit.generation AND files.rel_path=member.rel_path
 CROSS JOIN blobs ON blobs.blob_oid=files.blob_oid
  AND blobs.lang=files.lang AND blobs.generation=files.generation
 CROSS JOIN main.resolution_unit_summary_placements AS placement
  INDEXED BY resolution_unit_summary_placements_member
  ON placement.summary_id=member.summary_id
 AND placement.member_ordinal=member.member_ordinal
 CROSS JOIN main.rust_resolution_unit_summary_contexts AS contexts
  ON contexts.summary_id=unit.summary_id
 CROSS JOIN source_rust_module_scopes AS scopes
  ON scopes.blob_id=blobs.id AND scopes.ordinal=(
   SELECT dense.dense_id FROM temp.surface_dense AS dense
   WHERE dense.blob_id=blobs.id AND dense.id_space=7
     AND dense.surface_ordinal=placement.scope_surface_ordinal)
 WHERE member.rel_path=?2 AND placement.scope_surface_ordinal IS NOT NULL
  AND EXISTS(SELECT 1 FROM temp.selected_unit_member_blobs AS attachment
   WHERE attachment.summary_id=member.summary_id
    AND attachment.member_ordinal=member.member_ordinal AND attachment.blob_id=?1)
  AND scopes.resolution_scope IS NOT NULL";

#[doc(hidden)]
pub struct RustCrateRows<'a, 'store, 'input> {
    pub(super) ready: &'a ReadySelectedResolution<'store, 'input>,
}

impl<'a, 'store, 'input> RustCrateRows<'a, 'store, 'input> {
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn new(ready: &'a ReadySelectedResolution<'store, 'input>) -> Self {
        Self { ready }
    }
}

/// An export's site is owned by its selected blob and mount. Crate topology
/// supplies placement only; no site number is carried over from an old blob.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[doc(hidden)]
pub struct RustCrateExport {
    #[doc(hidden)]
    pub blob: i64,
    #[doc(hidden)]
    pub declaration: RustCrateDeclaration,
    pub(super) topology: i64,
    pub(super) module_path: String,
    #[doc(hidden)]
    pub mount: SelectedResolutionMountOrdinal,
    /// The gap row of `module_path` when the selection unplaced the module: the
    /// persisted export is a true fact about a file the selected root no longer
    /// mounts, so a route that reached it owes an incomplete answer.
    pub(super) unplaced: Option<String>,
}

/// Completion and, for an unsupported visibility group, the independently
/// exact canonical targets. Raw glob walks must not resurrect its members.
pub(super) struct RustBindingInventory {
    pub(super) completion: ResolutionCompletion,
    pub(super) targets: Option<Vec<(i64, String, String)>>,
}

/// The declaration one export names in its blob.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[doc(hidden)]
pub enum RustCrateDeclaration {
    /// A persisted declaration's definition site.
    Site(u32),
    /// Declaration replay's declaration for an item the crate declared for a
    /// cross-file passthrough invocation (`rust_crate_macro_items`). No
    /// persisted site defines it; the invoking file's request-scoped capsule
    /// does, when the request staged that file.
    MacroItem(i64),
}

/// Target topology, module path, namespace, name, requester topology and
/// requester path.
type ExportKey = (i64, String, String, String, i64, String);

/// One crate stage's answers from three crate-row statements, each keyed by
/// its bound parameters.
///
/// - `exports`: `rust_crate_point_export.sql`, keyed by target topology, module
///   path, namespace, name, requester topology and requester path. The rooted
///   generated-file graph ran it 1,582 times for 168 keys: every
///   `flatbuffers::...` path in tract's generated module asks for `flatbuffers`
///   from the same module.
/// - `scopes`: `rust_crate_point_scopes.sql` (a module scope's native import
///   scopes), keyed by blob and resolution scope. On the whole tract graph
///   99.3% of its 265,963 executions repeated a key already asked in the same
///   stage; tract_core asked 172 keys 54,658 times.
/// - `inventories`: `rust_crate_published_inventory.sql` (a demand's open-inventory
///   gaps), keyed by the same target and requester parameters as exports; 76.8% of 221,505
///   executions repeated a key within the stage.
///
/// The rows these statements read (crate rows, the selection's mounts, crates
/// and placements, and persisted source facts) do not change while a stage
/// runs; the stage's own fact tables are separate and none of them reads
/// those.
///
/// Only a crate stage holds one: [`RustGraphStageTables`] installs it for a
/// native graph unit, and [`CrateStageMemos`] installs it for other scoped
/// Rust operations. Outside a crate stage the lookups run the statements
/// directly.
#[derive(Default)]
pub(super) struct CrateRowMemo {
    exports: ExactReadMemo<ExportKey, Vec<RustCrateExport>>,
    scopes: ExactReadMemo<(i64, u32), Vec<u32>>,
    inventories: ExactReadMemo<ExportKey, Vec<String>>,
}

/// Holds one scoped Rust operation's memos: the request's [`CrateRowMemo`],
/// the inventory's `CrateAccessMemo` and its `AuthorityValidations`, and the
/// stage's read transaction on the reader. The native graph path installs the
/// Rust row tables separately under its shared graph-stage guard.
#[doc(hidden)]
pub struct CrateStageMemos<'a> {
    owns_read: bool,
    inventory: &'a super::super::resolution_selection::SelectedResolutionMountInventory<'a>,
    rows: &'a RefCell<Option<CrateRowMemo>>,
    access: &'a RefCell<Option<super::rust_crate_access::CrateAccessMemo>>,
    authority: &'a RefCell<Option<super::super::resolution_authority::AuthorityValidations>>,
}

impl<'a> CrateStageMemos<'a> {
    pub(super) fn install(
        inventory: &'a super::super::resolution_selection::SelectedResolutionMountInventory<'a>,
        rows: &'a RefCell<Option<CrateRowMemo>>,
        access: &'a RefCell<Option<super::rust_crate_access::CrateAccessMemo>>,
        authority: &'a RefCell<Option<super::super::resolution_authority::AuthorityValidations>>,
    ) -> Result<Self> {
        let previous = rows.replace(Some(CrateRowMemo::default()));
        assert!(previous.is_none(), "crate stages do not nest");
        let previous = access.replace(Some(Default::default()));
        assert!(previous.is_none(), "crate stages do not nest");
        let previous = authority.replace(Some(Default::default()));
        assert!(previous.is_none(), "crate stages do not nest");
        let owns_read = !inventory.stage_read_active();
        if owns_read {
            inventory.begin_stage_read()?;
        }
        Ok(Self {
            owns_read,
            inventory,
            rows,
            access,
            authority,
        })
    }
}

impl Drop for CrateStageMemos<'_> {
    fn drop(&mut self) {
        self.rows.take();
        self.access.take();
        self.authority.take();
        // The reader returns to its pool with the request, and it must return
        // outside any transaction. A failed COMMIT is reported and rolled back.
        if !self.owns_read {
            return;
        }
        if let Err(error) = self.inventory.end_stage_read() {
            eprintln!("analyzer store could not end a crate stage's read: {error}");
            if let Err(error) = self.inventory.connection().execute_batch("ROLLBACK") {
                eprintln!("analyzer store could not roll back a crate stage's read: {error}");
            }
        }
        assert!(
            std::thread::panicking() || self.inventory.connection().is_autocommit(),
            "a crate stage left its reader inside a transaction"
        );
    }
}

// Expand a selected declaration to the Rust-owned exported names that route
// to it. Re-export rows carry their target coordinates and identity; the walk
// follows those rows one step at a time and stays bounded by the selected
// summary rows rather than constructing a workspace-sized Rust map.
//
// `$derivation_identity` is the caller's placeholder for
// `rust_unit_summary_derivation_identity()`, bound at the call site so a version
// bump stays one constant.
macro_rules! rust_selected_members_cte {
    ($predicate:literal, $derivation_identity:literal) => {
        concat!(
             "selected_members(workspace_id, generation, unit_key, summary_id, topology_id, \
             member_ordinal, blob_id, rel_path) AS ( \
             SELECT versions.workspace_id, versions.generation, versions.unit_key, \
                    versions.summary_id, rust_versions.topology_id, members.member_ordinal, \
                    members.blob_id, members.rel_path \
             FROM main.resolution_unit_summary_members AS members \
               INDEXED BY resolution_unit_summary_members_path \
             CROSS JOIN main.resolution_unit_summary_versions AS versions \
               INDEXED BY resolution_unit_summary_versions_summary \
               ON versions.summary_id=members.summary_id \
             CROSS JOIN selected_workspace_revisions AS selected \
               ON selected.workspace_id=versions.workspace_id AND selected.lang=versions.lang \
              AND selected.generation=versions.generation \
              AND versions.valid_from<=selected.revision \
              AND (versions.valid_until IS NULL OR selected.revision<versions.valid_until) \
             CROSS JOIN main.resolution_unit_summaries AS summaries \
               ON summaries.summary_id=versions.summary_id \
              AND summaries.lang='rust' AND summaries.unit_kind='rust_crate' \
              AND summaries.publication_state='complete' AND summaries.derivation_identity=",
            $derivation_identity,
            " \
             CROSS JOIN main.resolution_producer_epochs AS epochs \
               ON epochs.lang=versions.lang AND epochs.producer_epoch=summaries.producer_epoch \
             CROSS JOIN main.rust_resolution_unit_summary_versions AS rust_versions \
               INDEXED BY sqlite_autoindex_rust_resolution_unit_summary_versions_1 \
               ON rust_versions.workspace_id=versions.workspace_id \
              AND rust_versions.lang=versions.lang AND rust_versions.generation=versions.generation \
              AND rust_versions.unit_key=versions.unit_key \
              AND rust_versions.valid_from=versions.valid_from \
              AND rust_versions.summary_id=versions.summary_id \
             CROSS JOIN main.rust_resolution_unit_summary_contexts AS contexts \
               ON contexts.summary_id=versions.summary_id \
             CROSS JOIN selected_workspace_file_versions AS files \
               ON files.workspace_id=versions.workspace_id AND files.lang=versions.lang \
              AND files.generation=versions.generation AND files.rel_path=members.rel_path \
             CROSS JOIN main.blobs AS blobs \
               ON blobs.lang=versions.lang \
              AND blobs.generation=versions.generation AND blobs.blob_oid=files.blob_oid \
              AND EXISTS(SELECT 1 FROM temp.selected_unit_member_blobs AS attachment \
               WHERE attachment.summary_id=members.summary_id \
                AND attachment.member_ordinal=members.member_ordinal AND attachment.blob_id=blobs.id) \
             ",
            $predicate,
            ")"
        )
    };
}

macro_rules! rust_trait_name_routes {
    ($predicate:literal, $seed:literal, $derivation_identity:literal) => {
        concat!(
            "WITH RECURSIVE ",
            rust_selected_members_cte!($predicate, $derivation_identity),
            ", trait_names(canonical_blob_id, canonical_site, canonical_rel_path, \
             name_unit_key, name_summary_id, name_topology_id, name_module_path, name, \
             name_visibility, name_identity_id) AS (",
            $seed,
            " UNION SELECT names.canonical_blob_id, names.canonical_site, names.canonical_rel_path, \
             parent.unit_key, parent.summary_id, parent.topology_id, exports.module_path, \
             exports.name, exports.visibility, exports.identity_id \
             FROM trait_names AS names \
             CROSS JOIN main.rust_resolution_unit_summary_exports AS exports \
               INDEXED BY rust_resolution_unit_summary_exports_alias_target \
               ON exports.target_unit_key=names.name_unit_key \
              AND exports.target_module_path=names.name_module_path \
              AND exports.target_name=names.name \
              AND exports.namespace='type' AND exports.alias_identity_id=names.name_identity_id \
              AND exports.origin<>'declaration' \
             CROSS JOIN selected_rust_unit_summaries AS parent \
               ON parent.summary_id=exports.summary_id) "
        )
    };
}

/// The traits a placed type implements that are nameable at the reference.
/// The subject endpoint is sought from its selected declaration export; the
/// paired trait endpoint and selected export rows supply the rest of the route.
/// `?1`/`?2`/`?5` identify the subject declaration and file, `?3`/`?4` the
/// reference module, and `?6`/`?7` the reference mount and semantic key.
#[doc(hidden)]
pub const TRAIT_IMPLS_VISIBLE_AT: &str = concat!(
    rust_trait_name_routes!(
        "WHERE blobs.id=?1 AND members.rel_path=?5",
        "SELECT trait_member.blob_id, trait_export.declaration_site, trait_member.rel_path, \
         trait_unit.unit_key, trait_unit.summary_id, trait_unit.topology_id, \
         trait_export.module_path, trait_export.name, trait_export.visibility, \
         trait_export.identity_id \
         FROM selected_members AS subject_member \
         CROSS JOIN main.rust_resolution_unit_summary_exports AS subject_export \
           INDEXED BY rust_resolution_unit_summary_exports_declaration \
           ON subject_export.summary_id=subject_member.summary_id \
          AND subject_export.declaration_member_ordinal=subject_member.member_ordinal \
          /* Rust-only derived-from blob until #11183 M3 converts Rust child rows */ \
          AND subject_export.declaration_site=?2 \
          AND subject_export.namespace='type' \
          AND subject_export.origin='declaration' \
          AND (subject_export.visibility<>'public' OR EXISTS(SELECT 1 FROM main.resolution_unit_summary_exports AS shared_export \
            INDEXED BY resolution_unit_summary_exports_surface_lookup \
            WHERE shared_export.summary_id=subject_member.summary_id \
             AND shared_export.declaration_member_ordinal=(SELECT min(stored.member_ordinal) \
              FROM main.resolution_unit_summary_members AS stored \
              WHERE stored.summary_id=subject_member.summary_id AND stored.blob_id=(SELECT source_member.blob_id \
               FROM main.resolution_unit_summary_members AS source_member WHERE source_member.summary_id=subject_member.summary_id \
                AND source_member.member_ordinal=subject_member.member_ordinal)) \
             AND shared_export.site_surface_ordinal=(SELECT current_site.surface_ordinal \
              FROM temp.surface_dense AS current_site WHERE current_site.blob_id=subject_member.blob_id \
               AND current_site.id_space=0 AND current_site.dense_id=?2) \
             AND shared_export.identity_id=subject_export.identity_id AND shared_export.namespace=subject_export.namespace \
             AND shared_export.target_kind='own')) \
         CROSS JOIN main.rust_resolution_unit_summary_trait_endpoints AS subject_endpoint \
           INDEXED BY rust_resolution_unit_summary_trait_endpoints_target \
           ON subject_endpoint.target_unit_key=subject_member.unit_key \
          AND subject_endpoint.target_module_path=subject_export.module_path \
          AND subject_endpoint.target_identity_id=subject_export.identity_id \
          AND subject_endpoint.endpoint_role='subject' \
          AND subject_endpoint.endpoint_state='resolved' \
         CROSS JOIN selected_rust_unit_summaries AS impl_unit \
           ON impl_unit.summary_id=subject_endpoint.summary_id \
         CROSS JOIN main.rust_resolution_unit_summary_trait_endpoints AS trait_endpoint \
           ON trait_endpoint.summary_id=subject_endpoint.summary_id \
          AND trait_endpoint.member_ordinal=subject_endpoint.member_ordinal \
          AND trait_endpoint.owner_module_path=subject_endpoint.owner_module_path \
          AND trait_endpoint.source_relation_key=subject_endpoint.source_relation_key \
          AND trait_endpoint.endpoint_role='trait' AND trait_endpoint.endpoint_state='resolved' \
         CROSS JOIN selected_rust_unit_summaries AS trait_unit \
           ON trait_unit.unit_key=trait_endpoint.target_unit_key \
         CROSS JOIN main.rust_resolution_unit_summary_exports AS trait_export \
           INDEXED BY rust_resolution_unit_summary_exports_identity \
           ON trait_export.summary_id=trait_unit.summary_id \
          AND trait_export.identity_id=trait_endpoint.target_identity_id \
          AND trait_export.module_path=trait_endpoint.target_module_path \
          AND trait_export.namespace='type' AND trait_export.origin='declaration' \
         CROSS JOIN main.resolution_unit_summary_members AS trait_member \
           ON trait_member.summary_id=trait_export.summary_id \
          AND trait_member.member_ordinal=trait_export.declaration_member_ordinal \
         WHERE subject_member.blob_id=?1 AND subject_member.rel_path=?5",
        "?8"
    ),
    "SELECT DISTINCT names.canonical_blob_id, names.canonical_site, mount.mount_ordinal \
     FROM trait_names AS names \
     CROSS JOIN temp.selected_resolution_mounts AS mount \
       ON mount.storage_language='rust' \
      AND mount.persisted_relative_path=names.canonical_rel_path \
      AND mount.blob_id=names.canonical_blob_id \
     WHERE (names.name_topology_id=?3 AND names.name_module_path=?4) \
        OR EXISTS( \
          SELECT 1 FROM main.rust_resolution_unit_summary_import_routes AS named \
            INDEXED BY rust_resolution_unit_summary_import_routes_target_identity \
          CROSS JOIN selected_rust_unit_summaries AS naming \
            ON naming.summary_id=named.summary_id AND naming.topology_id=?3 \
          CROSS JOIN main.resolution_unit_summary_members AS member \
            ON member.summary_id=named.summary_id AND member.member_ordinal=named.member_ordinal \
          CROSS JOIN source_rust_import_targets AS placed \
            ON placed.blob_id=member.blob_id AND placed.source_import_id=named.import_id \
           AND placed.native_scope=named.binder_scope \
          WHERE named.target_unit_key=names.name_unit_key \
            AND named.target_module_path=names.name_module_path AND named.target_name=names.name \
            AND named.namespace='type' AND named.module_path=?4 \
            AND (placed.local_start IS NULL OR EXISTS( \
              SELECT 1 FROM temp.selected_resolution_mounts AS at \
              CROSS JOIN resolution_sites AS site ON site.blob_id=at.blob_id AND site.site=?7 \
              WHERE at.mount_ordinal=?6 AND at.blob_id=member.blob_id \
                AND placed.local_start<=site.start_byte AND site.start_byte<placed.local_end))) \
        OR (names.name_visibility='public' AND EXISTS( \
          SELECT 1 FROM main.rust_resolution_unit_summary_glob_imports AS globs \
            INDEXED BY rust_resolution_unit_summary_glob_imports_target_identity \
          CROSS JOIN selected_rust_unit_summaries AS naming \
            ON naming.summary_id=globs.summary_id AND naming.topology_id=?3 \
          CROSS JOIN main.resolution_unit_summary_members AS member \
            ON member.summary_id=globs.summary_id AND member.member_ordinal=globs.member_ordinal \
          CROSS JOIN source_rust_import_targets AS placed \
            ON placed.blob_id=member.blob_id AND placed.source_import_id=globs.source_import_id \
           AND placed.native_scope=globs.binder_scope \
          WHERE globs.target_unit_key=names.name_unit_key \
            AND globs.target_module_path=names.name_module_path AND globs.module_path=?4 \
            AND (placed.local_start IS NULL OR EXISTS( \
              SELECT 1 FROM temp.selected_resolution_mounts AS at \
              CROSS JOIN resolution_sites AS site ON site.blob_id=at.blob_id AND site.site=?7 \
              WHERE at.mount_ordinal=?6 AND at.blob_id=member.blob_id \
                AND placed.local_start<=site.start_byte AND site.start_byte<placed.local_end))))"
);
/// Rust-owned export and access rows for one graph stage. The generic graph
/// guard owns the shared authority-validation memo and reader transaction;
/// this guard installs only the Rust-specific tables inside that boundary.
#[doc(hidden)]
pub struct RustGraphStageTables<'a> {
    rows: &'a RefCell<Option<CrateRowMemo>>,
    access: &'a RefCell<Option<super::rust_crate_access::CrateAccessMemo>>,
}

impl<'a> RustGraphStageTables<'a> {
    pub(super) fn install(
        rows: &'a RefCell<Option<CrateRowMemo>>,
        access: &'a RefCell<Option<super::rust_crate_access::CrateAccessMemo>>,
    ) -> Self {
        assert!(rows.borrow().is_none(), "crate stages do not nest");
        assert!(access.borrow().is_none(), "crate stages do not nest");
        *rows.borrow_mut() = Some(CrateRowMemo::default());
        *access.borrow_mut() = Some(Default::default());
        Self { rows, access }
    }
}

impl Drop for RustGraphStageTables<'_> {
    fn drop(&mut self) {
        self.rows.take();
        self.access.take();
    }
}

/// The exact callable child one selected type's one selected trait impl
/// declares, if any. A trait method value written as `Type::method` can name
/// the concrete override just as a receiver call does. The deferred member
/// identity, subject and trait ends, and impl placement all have to match;
/// sibling types that implement the same trait never enter this result.
pub(super) const TRAIT_IMPL_MEMBER_AT: &str = concat!(
    "WITH RECURSIVE ",
    rust_selected_members_cte!("WHERE blobs.id=?3 AND members.rel_path=?5", "?9"),
    ", subject(workspace_id, generation, unit_key, module_path, identity_id) AS ( \
     SELECT members.workspace_id, members.generation, members.unit_key, \
            exports.module_path, exports.identity_id \
     FROM selected_members AS members \
     CROSS JOIN main.rust_resolution_unit_summary_exports AS exports \
       INDEXED BY rust_resolution_unit_summary_exports_declaration \
       ON exports.summary_id=members.summary_id \
      AND exports.declaration_member_ordinal=members.member_ordinal \
      /* Rust-only derived-from blob until #11183 M3 converts Rust child rows */ \
      AND exports.declaration_site=?4 \
      AND exports.namespace='type' \
      AND exports.origin='declaration' \
      AND (exports.visibility<>'public' OR EXISTS(SELECT 1 FROM main.resolution_unit_summary_exports AS shared_export \
        INDEXED BY resolution_unit_summary_exports_surface_lookup \
        WHERE shared_export.summary_id=members.summary_id \
         AND shared_export.declaration_member_ordinal=(SELECT min(stored.member_ordinal) \
          FROM main.resolution_unit_summary_members AS stored \
          WHERE stored.summary_id=members.summary_id AND stored.blob_id=(SELECT source_member.blob_id \
           FROM main.resolution_unit_summary_members AS source_member WHERE source_member.summary_id=members.summary_id \
            AND source_member.member_ordinal=members.member_ordinal)) \
         AND shared_export.site_surface_ordinal=(SELECT current_site.surface_ordinal \
          FROM temp.surface_dense AS current_site WHERE current_site.blob_id=members.blob_id \
           AND current_site.id_space=0 AND current_site.dense_id=?4) \
         AND shared_export.identity_id=exports.identity_id AND shared_export.namespace=exports.namespace \
         AND shared_export.target_kind='own'))) ",
    "SELECT DISTINCT authority.source_site, member_mount.mount_ordinal \
     FROM subject AS subject_target \
CROSS JOIN main.rust_resolution_unit_summary_trait_endpoints AS subject_endpoint
 INDEXED BY rust_resolution_unit_summary_trait_endpoints_target
 ON subject_endpoint.target_unit_key=subject_target.unit_key
AND subject_endpoint.target_module_path=subject_target.module_path
AND subject_endpoint.target_identity_id=subject_target.identity_id
AND subject_endpoint.endpoint_role='subject' AND subject_endpoint.endpoint_state='resolved'
CROSS JOIN main.rust_resolution_unit_summary_trait_endpoints AS trait_endpoint
 ON trait_endpoint.summary_id=subject_endpoint.summary_id
AND trait_endpoint.member_ordinal=subject_endpoint.member_ordinal
AND trait_endpoint.owner_module_path=subject_endpoint.owner_module_path
AND trait_endpoint.source_relation_key=subject_endpoint.source_relation_key
AND trait_endpoint.endpoint_role='trait' AND trait_endpoint.endpoint_state='resolved'
CROSS JOIN selected_workspace_revisions AS trait_revision
 ON trait_revision.workspace_id=subject_target.workspace_id
AND trait_revision.lang='rust' AND trait_revision.generation=subject_target.generation
CROSS JOIN main.resolution_unit_summary_versions AS trait_version
 INDEXED BY sqlite_autoindex_resolution_unit_summary_versions_1
 ON trait_version.workspace_id=trait_revision.workspace_id
AND trait_version.lang=trait_revision.lang
AND trait_version.generation=trait_revision.generation
AND trait_version.unit_key=trait_endpoint.target_unit_key
AND trait_version.valid_from<=trait_revision.revision
AND (trait_version.valid_until IS NULL OR trait_revision.revision<trait_version.valid_until)
CROSS JOIN main.resolution_unit_summaries AS trait_summary
 ON trait_summary.summary_id=trait_version.summary_id
AND trait_summary.lang='rust' AND trait_summary.unit_kind='rust_crate'
AND trait_summary.publication_state='complete' AND trait_summary.derivation_identity=?9
CROSS JOIN main.resolution_producer_epochs AS trait_epoch
 ON trait_epoch.lang=trait_version.lang
AND trait_epoch.producer_epoch=trait_summary.producer_epoch
CROSS JOIN main.rust_resolution_unit_summary_versions AS trait_rust_version
 ON trait_rust_version.workspace_id=trait_version.workspace_id
AND trait_rust_version.lang=trait_version.lang
AND trait_rust_version.generation=trait_version.generation
AND trait_rust_version.unit_key=trait_version.unit_key
AND trait_rust_version.valid_from=trait_version.valid_from
AND trait_rust_version.summary_id=trait_version.summary_id
CROSS JOIN main.rust_resolution_unit_summary_contexts AS trait_context
 ON trait_context.summary_id=trait_version.summary_id
CROSS JOIN main.resolution_unit_summary_members AS trait_member
 INDEXED BY resolution_unit_summary_members_path
 ON trait_member.summary_id=trait_version.summary_id AND trait_member.rel_path=?8
AND EXISTS(SELECT 1 FROM temp.selected_unit_member_blobs AS attachment
 WHERE attachment.summary_id=trait_member.summary_id
  AND attachment.member_ordinal=trait_member.member_ordinal AND attachment.blob_id=?6)
CROSS JOIN selected_workspace_file_versions AS trait_file
 ON trait_file.workspace_id=trait_version.workspace_id
AND trait_file.lang=trait_version.lang AND trait_file.generation=trait_version.generation
AND trait_file.rel_path=trait_member.rel_path
CROSS JOIN main.blobs AS trait_blob
 ON trait_blob.id=?6 AND trait_blob.lang=trait_version.lang
AND trait_blob.generation=trait_version.generation AND trait_blob.blob_oid=trait_file.blob_oid
CROSS JOIN main.rust_resolution_unit_summary_exports AS trait_export
 INDEXED BY rust_resolution_unit_summary_exports_declaration
 ON trait_export.summary_id=trait_member.summary_id
AND trait_export.declaration_member_ordinal=trait_member.member_ordinal
/* Rust-only derived-from blob until #11183 M3 converts Rust child rows */
AND trait_export.declaration_site=?7
AND trait_export.namespace='type'
AND trait_export.origin='declaration'
AND trait_export.identity_id=trait_endpoint.target_identity_id
CROSS JOIN main.resolution_unit_summary_members AS impl_member
 ON impl_member.summary_id=subject_endpoint.summary_id
AND impl_member.member_ordinal=subject_endpoint.member_ordinal
CROSS JOIN selected_rust_unit_summaries AS impl_unit
 ON impl_unit.summary_id=impl_member.summary_id
CROSS JOIN temp.selected_resolution_mounts AS member_mount
 ON member_mount.mount_ordinal=?1 AND member_mount.blob_id=impl_member.blob_id
AND member_mount.persisted_relative_path=impl_member.rel_path
CROSS JOIN resolution_rust_declaration_authorities AS authority
 ON authority.blob_id=impl_member.blob_id AND authority.semantic_key=?2
CROSS JOIN source_rust_item_body_children AS child
 ON child.blob_id=authority.blob_id AND child.declaration_id=authority.declaration
AND child.owner_declaration_id=subject_endpoint.impl_declaration_id
WHERE trait_export.module_path=trait_endpoint.target_module_path
AND child.syntax_kind='function_item'"
);

/// Visibility of one placed trait, including traits implemented for unindexed
/// external types. Parameters and block-import extents are as for
/// [`TRAIT_IMPLS_VISIBLE_AT`].
pub(super) const TRAIT_VISIBLE_AT: &str = concat!(
    rust_trait_name_routes!(
        "WHERE blobs.id=?1 AND members.rel_path=?5",
        "SELECT members.blob_id, ?2, members.rel_path, \
         members.unit_key, members.summary_id, members.topology_id, exports.module_path, \
         exports.name, exports.visibility, exports.identity_id \
         FROM selected_members AS members \
         CROSS JOIN main.rust_resolution_unit_summary_exports AS exports \
           INDEXED BY rust_resolution_unit_summary_exports_declaration \
           ON exports.summary_id=members.summary_id \
          AND exports.declaration_member_ordinal=members.member_ordinal \
          /* Rust-only derived-from blob until #11183 M3 converts Rust child rows */ \
          AND exports.declaration_site=?2 \
          AND exports.namespace='type' \
          AND exports.origin='declaration' \
          AND (exports.visibility<>'public' OR EXISTS(SELECT 1 FROM main.resolution_unit_summary_exports AS shared_export \
            INDEXED BY resolution_unit_summary_exports_surface_lookup \
            WHERE shared_export.summary_id=members.summary_id \
             AND shared_export.declaration_member_ordinal=(SELECT min(stored.member_ordinal) \
              FROM main.resolution_unit_summary_members AS stored \
              WHERE stored.summary_id=members.summary_id AND stored.blob_id=(SELECT source_member.blob_id \
               FROM main.resolution_unit_summary_members AS source_member WHERE source_member.summary_id=members.summary_id \
                AND source_member.member_ordinal=members.member_ordinal)) \
             AND shared_export.site_surface_ordinal=(SELECT current_site.surface_ordinal \
              FROM temp.surface_dense AS current_site WHERE current_site.blob_id=members.blob_id \
               AND current_site.id_space=0 AND current_site.dense_id=?2) \
             AND shared_export.identity_id=exports.identity_id AND shared_export.namespace=exports.namespace \
             AND shared_export.target_kind='own')) \
         ",
        "?8"
    ),
    "SELECT DISTINCT names.canonical_blob_id, names.canonical_site, mount.mount_ordinal \
     FROM trait_names AS names \
     CROSS JOIN temp.selected_resolution_mounts AS mount \
       ON mount.storage_language='rust' AND mount.persisted_relative_path=names.canonical_rel_path \
      AND mount.blob_id=names.canonical_blob_id \
     WHERE (names.name_topology_id=?3 AND names.name_module_path=?4) \
        OR EXISTS( \
          SELECT 1 FROM main.rust_resolution_unit_summary_import_routes AS named \
            INDEXED BY rust_resolution_unit_summary_import_routes_target_identity \
          CROSS JOIN selected_rust_unit_summaries AS naming \
            ON naming.summary_id=named.summary_id AND naming.topology_id=?3 \
          CROSS JOIN main.resolution_unit_summary_members AS member \
            ON member.summary_id=named.summary_id AND member.member_ordinal=named.member_ordinal \
          CROSS JOIN source_rust_import_targets AS placed \
            ON placed.blob_id=member.blob_id AND placed.source_import_id=named.import_id \
           AND placed.native_scope=named.binder_scope \
          WHERE named.target_unit_key=names.name_unit_key \
            AND named.target_module_path=names.name_module_path AND named.target_name=names.name \
            AND named.namespace='type' AND named.module_path=?4 \
            AND (placed.local_start IS NULL OR EXISTS( \
              SELECT 1 FROM temp.selected_resolution_mounts AS at \
              CROSS JOIN resolution_sites AS site ON site.blob_id=at.blob_id AND site.site=?7 \
              WHERE at.mount_ordinal=?6 AND at.blob_id=member.blob_id \
                AND placed.local_start<=site.start_byte AND site.start_byte<placed.local_end))) \
        OR (names.name_visibility='public' AND EXISTS( \
          SELECT 1 FROM main.rust_resolution_unit_summary_glob_imports AS globs \
            INDEXED BY rust_resolution_unit_summary_glob_imports_target_identity \
          CROSS JOIN selected_rust_unit_summaries AS naming \
            ON naming.summary_id=globs.summary_id AND naming.topology_id=?3 \
          CROSS JOIN main.resolution_unit_summary_members AS member \
            ON member.summary_id=globs.summary_id AND member.member_ordinal=globs.member_ordinal \
          CROSS JOIN source_rust_import_targets AS placed \
            ON placed.blob_id=member.blob_id AND placed.source_import_id=globs.source_import_id \
           AND placed.native_scope=globs.binder_scope \
          WHERE globs.target_unit_key=names.name_unit_key \
            AND globs.target_module_path=names.name_module_path AND globs.module_path=?4 \
            AND (placed.local_start IS NULL OR EXISTS( \
              SELECT 1 FROM temp.selected_resolution_mounts AS at \
              CROSS JOIN resolution_sites AS site ON site.blob_id=at.blob_id AND site.site=?7 \
              WHERE at.mount_ordinal=?6 AND at.blob_id=member.blob_id \
                AND placed.local_start<=site.start_byte AND site.start_byte<placed.local_end))))"
);

/// The crate modules one Rust reference is written in.
///
/// The reference's own context row names its module scope, and
/// `selected_rust_container_placements` places that scope in every selected crate
/// that places the file, aligning an edited file's scopes with the persisted
/// file's. `?1` is the reference's mount ordinal, `?2` its semantic key. No row
/// means the reference has no persisted context or its file is placed in no
/// selected crate.
pub(super) const REFERENCE_MODULE_PLACEMENTS: &str =
    "SELECT DISTINCT placement.topology_id, placement.container_path
 FROM temp.selected_resolution_mounts AS mount
 CROSS JOIN resolution_rust_reference_contexts AS context
  ON context.blob_id=mount.blob_id AND context.semantic_key=?2
 CROSS JOIN selected_rust_container_placements AS placement
  ON placement.mount_ordinal=mount.mount_ordinal
  AND placement.module_declaration IS context.module_declaration
 WHERE mount.mount_ordinal=?1";

/// The workspace crate a path head `?3` names in the module one Rust reference
/// is written in, when it names one: a workspace dependency's extern name, an
/// `extern crate dep as alias;` at the crate root, or a module-level `use` that
/// binds a workspace crate's root. `?1` is the reference's mount ordinal,
/// `?2` its semantic key, as for [`REFERENCE_MODULE_PLACEMENTS`].
pub(super) const REFERENCE_NAMES_WORKSPACE_CRATE_HEAD: &str = r#"WITH owner AS (
 SELECT unit.workspace_id, unit.lang, unit.generation, unit.revision,
        unit.summary_id, unit.unit_key, placement.container_path
 FROM temp.selected_resolution_mounts AS mount
 CROSS JOIN resolution_rust_reference_contexts AS context
  ON context.blob_id=mount.blob_id AND context.semantic_key=?2
 CROSS JOIN selected_rust_container_placements AS placement
  ON placement.mount_ordinal=mount.mount_ordinal
  AND placement.module_declaration IS context.module_declaration
 CROSS JOIN main.rust_resolution_unit_summary_versions AS owner_version
  INDEXED BY rust_resolution_unit_summary_versions_topology
  ON owner_version.topology_id=placement.topology_id
 CROSS JOIN selected_rust_unit_summaries AS unit
  ON unit.workspace_id=owner_version.workspace_id AND unit.lang=owner_version.lang
 AND unit.generation=owner_version.generation AND unit.unit_key=owner_version.unit_key
 AND unit.valid_from=owner_version.valid_from
 WHERE mount.mount_ordinal=?1
),
-- The unit keys the owner's crate names under ?3: a declared workspace
-- dependency, or a crate-root `extern crate` import of a workspace crate.
target_keys(unit_key) AS (
 SELECT dependency.dependency_unit_key
 FROM owner
 CROSS JOIN main.resolution_unit_summary_dependencies AS dependency
  ON dependency.summary_id=owner.summary_id AND dependency.boundary='workspace'
 CROSS JOIN main.rust_unit_summary_dependency_names AS name
  ON name.summary_id=dependency.summary_id
 AND name.dependency_ordinal=dependency.dependency_ordinal AND name.extern_name=?3
 UNION
 SELECT dependency.dependency_unit_key
 FROM owner
 CROSS JOIN temp.rust_unit_summary_placements AS root
  ON root.summary_id=owner.summary_id AND root.module_path='crate'
 CROSS JOIN main.resolution_unit_summary_members AS root_member
  ON root_member.summary_id=root.summary_id AND root_member.member_ordinal=root.member_ordinal
 CROSS JOIN source_rust_import_targets AS import
  ON import.blob_id=(SELECT attachment.blob_id FROM temp.selected_unit_member_blobs AS attachment
                     WHERE attachment.summary_id=root_member.summary_id
                      AND attachment.member_ordinal=root_member.member_ordinal)
 AND import.is_extern_crate=1
 AND import.bound_name=?3 AND import.local_start IS NULL
 AND COALESCE(import.owner_module,'')=''
 CROSS JOIN main.rust_unit_summary_dependency_names AS name
  ON name.summary_id=owner.summary_id AND name.extern_name=import.imported_name
 CROSS JOIN main.resolution_unit_summary_dependencies AS dependency
  ON dependency.summary_id=name.summary_id
 AND dependency.dependency_ordinal=name.dependency_ordinal AND dependency.boundary='workspace'
 UNION
 SELECT import.target_unit_key
 FROM owner
 CROSS JOIN temp.rust_unit_summary_placements AS source
  ON source.summary_id=owner.summary_id AND source.module_path=owner.container_path
 CROSS JOIN main.resolution_unit_summary_members AS member
  ON member.summary_id=source.summary_id AND member.member_ordinal=source.member_ordinal
 CROSS JOIN main.resolution_unit_summary_placements AS shared_placement
  INDEXED BY resolution_unit_summary_placements_member
  ON shared_placement.summary_id=source.summary_id
 AND shared_placement.member_ordinal=source.member_ordinal
 AND shared_placement.container_path=CASE source.module_path WHEN 'crate' THEN '' ELSE source.module_path END
 CROSS JOIN source_rust_module_scopes AS scope
  ON scope.blob_id=member.blob_id
 AND scope.ordinal=(SELECT dense.dense_id FROM temp.surface_dense AS dense
                    WHERE dense.blob_id=scope.blob_id AND dense.id_space=7
                     AND dense.surface_ordinal=shared_placement.scope_surface_ordinal)
 CROSS JOIN main.rust_resolution_unit_summary_import_routes AS import
  INDEXED BY rust_resolution_unit_summary_import_routes_binder
  ON import.summary_id=source.summary_id AND import.member_ordinal=source.member_ordinal
 /* Rust-only derived-from blob until #11183 M3 converts Rust child rows */
 AND import.module_path=source.module_path AND import.binder_scope=scope.resolution_scope
 AND import.namespace='type' AND import.bound_name=?3
 AND import.target_module_path='crate' AND import.target_name='self'
 AND (import.target_unit_key=owner.unit_key OR EXISTS(
   -- Rust-only derived-from blob until #11183 M3 converts Rust child rows
   SELECT 1 FROM main.source_import_segments AS local_root
   WHERE local_root.blob_id=member.blob_id AND local_root.import_id=import.import_id
    AND local_root.ordinal=0 AND local_root.segment IN ('crate','self','super'))
 OR EXISTS(SELECT 1 FROM main.resolution_unit_summary_imports AS shared_import

   WHERE shared_import.summary_id=member.summary_id
    AND shared_import.member_ordinal=(SELECT min(shared_member.member_ordinal)
     FROM main.resolution_unit_summary_members AS shared_member
      INDEXED BY resolution_unit_summary_members_blob
     WHERE shared_member.summary_id=member.summary_id
      AND shared_member.blob_id=member.blob_id)
    AND shared_import.import_surface_ordinal=(SELECT import_surface.surface_ordinal
     FROM temp.surface_dense AS import_surface
     WHERE import_surface.blob_id=member.blob_id AND import_surface.id_space=4
      AND import_surface.dense_id=import.import_id)))
)
"#;

/// The workspace crate names a reference can reach through `extern crate` or a
/// crate-root import. The head is the requester and its target keys; the shared
/// target validity is `rust_crate_context::target_unit_joins`.
pub(super) static REFERENCE_NAMES_WORKSPACE_CRATE: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        format!(
            "{REFERENCE_NAMES_WORKSPACE_CRATE_HEAD}SELECT DISTINCT target_context.crate_name\nFROM owner\nCROSS JOIN target_keys AS keys\n{}\nORDER BY 1 LIMIT 1",
            super::rust_crate_context::target_unit_joins("?4")
        )
    });

/// Whether the module one Rust reference is written in has a declared macro
/// module named `?3`. `?1` is the reference's mount ordinal, `?2` its semantic
/// key, as for [`REFERENCE_MODULE_PLACEMENTS`].
pub(super) const REFERENCE_NAMES_MACRO_MODULE: &str = "SELECT 1
 FROM temp.selected_resolution_mounts AS mount
 CROSS JOIN resolution_rust_reference_contexts AS context
  ON context.blob_id=mount.blob_id AND context.semantic_key=?2
 CROSS JOIN selected_rust_container_placements AS placement
  ON placement.mount_ordinal=mount.mount_ordinal
  AND placement.module_declaration IS context.module_declaration
 CROSS JOIN selected_rust_unit_summaries AS unit
  ON unit.topology_id=placement.topology_id
 CROSS JOIN main.rust_resolution_unit_summary_generated_names AS item
  INDEXED BY rust_resolution_unit_summary_generated_names_module
  ON item.summary_id=unit.summary_id AND item.module_path=placement.container_path
  AND item.namespace='type' AND item.name=?3 AND item.module_item=1
 WHERE mount.mount_ordinal=?1";

/// Whether the file of the mount `?1` declares an edge the selection added
/// (`temp.selected_rust_added_edges`).
pub(super) const REFERENCE_FILE_ADDS_EDGE: &str = "SELECT 1
 FROM temp.selected_resolution_mounts AS mount
 CROSS JOIN temp.selected_rust_added_edges AS added
  ON added.rel_path=mount.persisted_relative_path
 WHERE mount.mount_ordinal=?1";

/// Whether the selection added a `#[macro_use] mod` or an include to the unit
/// that places the module one Rust reference is written in. The textual macro
/// walk reads child modules and included files from persisted placements, so
/// the macros such an edge brings into scope are invisible to it. `?1` and `?2`
/// are as for [`REFERENCE_MODULE_PLACEMENTS`].
pub(super) const REFERENCE_UNIT_ADDS_MACRO_SCOPE: &str = "SELECT 1
 FROM temp.selected_resolution_mounts AS mount
 CROSS JOIN resolution_rust_reference_contexts AS context
  ON context.blob_id=mount.blob_id AND context.semantic_key=?2
 CROSS JOIN selected_rust_container_placements AS placement
  ON placement.mount_ordinal=mount.mount_ordinal
  AND placement.module_declaration IS context.module_declaration
 CROSS JOIN selected_rust_unit_summaries AS unit
  ON unit.topology_id=placement.topology_id
 CROSS JOIN temp.selected_rust_added_edges AS added
  ON added.summary_id=unit.summary_id AND added.macro_use=1
 WHERE mount.mount_ordinal=?1";

/// One Rust declaration as the crate rows key it: its blob, source site and
/// file, and whether that exact blob is placed in a selected crate.
///
/// The placement is the blob's own, not its path's. Crate derivation binds
/// `impl` subjects to the declarations of the blob it derived from, so an
/// edited file's declaration is keyed by a blob the crate rows have never seen
/// and the rows cannot answer for it. `?1` is the declaration's mount ordinal,
/// `?2` its semantic key. No row means the semantic has no Rust declaration
/// authority, so no crate row binds it.
pub(super) const OWNER_DECLARATION: &str = "SELECT authority.blob_id, authority.source_site,
  EXISTS(SELECT 1 FROM main.resolution_unit_summary_members AS placed
          INDEXED BY resolution_unit_summary_members_blob
         CROSS JOIN selected_rust_unit_summaries AS units
          ON units.summary_id=placed.summary_id
         CROSS JOIN selected_workspace_file_versions AS files
          ON files.workspace_id=units.workspace_id AND files.lang=units.lang
         AND files.generation=units.generation AND files.rel_path=placed.rel_path
         CROSS JOIN blobs ON blobs.id=placed.blob_id AND blobs.blob_oid=files.blob_oid
          AND blobs.lang=files.lang AND blobs.generation=files.generation
         WHERE placed.blob_id=authority.blob_id),
  mount.persisted_relative_path
 FROM temp.selected_resolution_mounts AS mount
 CROSS JOIN resolution_rust_declaration_authorities AS authority
  ON authority.blob_id=mount.blob_id AND authority.semantic_key=?2
 WHERE mount.mount_ordinal=?1";

/// Which of a batch of Rust definitions declare a module: the declaration
/// authority names a source declaration the module rows record. `?1` is a JSON
/// array of `[ordinal, mount_ordinal, semantic_key]`; the rows are the
/// ordinals of the definitions that are modules.
pub(super) const MODULE_DEFINITIONS: &str = "SELECT DISTINCT json_extract(asked.value, '$[0]')
 FROM json_each(?1) AS asked
 CROSS JOIN temp.selected_resolution_mounts AS mount
  ON mount.mount_ordinal=json_extract(asked.value, '$[1]')
 CROSS JOIN resolution_rust_declaration_authorities AS authority
  ON authority.blob_id=mount.blob_id AND authority.semantic_key=json_extract(asked.value, '$[2]')
 CROSS JOIN source_rust_module_declarations AS module
  ON module.blob_id=authority.blob_id AND module.declaration_id=authority.declaration";

/// The definitions among `definitions` (each with its mount ordinal and
/// semantic key) that declare a module.
pub(crate) fn module_definitions(
    selection: &SelectedResolutionMountInventory<'_>,
    definitions: &[(SemanticId, SelectedResolutionMountOrdinal, i64)],
) -> Result<Vec<SemanticId>> {
    // Within a crate stage the answers are remembered by (mount, key), and
    // only definitions the stage has not asked about reach the statement.
    let mut modules = Vec::new();
    let mut unknown = Vec::new();
    {
        let memo = selection.crate_access_memo().borrow();
        for definition in definitions {
            match memo.as_ref().and_then(|memo| {
                memo.module_definitions
                    .get(&(definition.1.get(), definition.2))
            }) {
                Some(true) => modules.push(definition.0),
                Some(false) => {}
                None => unknown.push(*definition),
            }
        }
    }
    if unknown.is_empty() {
        return Ok(modules);
    }
    let asked = serde_json::to_string(
        &unknown
            .iter()
            .enumerate()
            .map(|(ordinal, (_, mount, key))| (ordinal, mount.get(), *key))
            .collect::<Vec<_>>(),
    )
    .expect("module definition keys serialize");
    let mut declares_module = vec![false; unknown.len()];
    for ordinal in selection
        .connection()
        .prepare_cached(MODULE_DEFINITIONS)?
        .query_map(params![asked], |row| row.get::<_, usize>(0))?
    {
        declares_module[ordinal?] = true;
    }
    if let Some(memo) = selection.crate_access_memo().borrow_mut().as_mut() {
        for (definition, &module) in unknown.iter().zip(&declares_module) {
            memo.module_definitions
                .insert((definition.1.get(), definition.2), module);
        }
    }
    modules.extend(
        unknown
            .iter()
            .zip(declares_module)
            .filter(|(_, module)| *module)
            .map(|(definition, _)| definition.0),
    );
    Ok(modules)
}

/// The traits one Rust type declaration implements that one Rust reference's
/// module can name, as trait definitions in the selected mounts.
///
/// Both halves are the crate rows [`TRAIT_IMPLS_VISIBLE_AT`] already joins for
/// `Foo::member()`; this asks the same question for a type the member route
/// evaluated rather than one a path prefix named. `owner` and `reference` are
/// each a mount ordinal and a semantic key with ordinary provenance.
pub(crate) fn implemented_traits_nameable_at(
    selection: &SelectedResolutionMountInventory<'_>,
    owner: (SelectedResolutionMountOrdinal, i64),
    reference: (SelectedResolutionMountOrdinal, i64),
    cancellation: &CancellationToken,
) -> Result<crate::analyzer::resolution::RustImplementedTraits> {
    use crate::analyzer::resolution::RustImplementedTraits;
    let conn = selection.connection();
    let Some((owner_blob, owner_site, owner_placed, owner_path)) = conn
        .prepare_cached(OWNER_DECLARATION)?
        .query_row(params![owner.0.get(), owner.1], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, bool>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .optional()?
    else {
        return Ok(RustImplementedTraits::Traits(Vec::new()));
    };
    if !owner_placed {
        return Ok(RustImplementedTraits::Unplaced);
    }
    let modules = conn
        .prepare_cached(REFERENCE_MODULE_PLACEMENTS)?
        .query_map(params![reference.0.get(), reference.1], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if modules.is_empty() {
        return Ok(RustImplementedTraits::Unplaced);
    }
    let mounts = SelectedMountTable::new(selection);
    let mut traits = Vec::new();
    for (topology, path) in modules {
        if cancellation.is_cancelled() {
            return Ok(RustImplementedTraits::Cancelled);
        }
        for row in conn.prepare_cached(TRAIT_IMPLS_VISIBLE_AT)?.query_map(
            params![
                owner_blob,
                owner_site,
                topology,
                path,
                owner_path,
                reference.0.get(),
                reference.1,
                rust_unit_summary_derivation_identity()
            ],
            |row| {
                Ok((
                    row.get::<_, u32>(1)?,
                    SelectedResolutionMountOrdinal::new(row.get::<_, u32>(2)?),
                ))
            },
        )? {
            let (site, ordinal) = row?;
            traits.push(mounted_site_semantic(
                mounts.mount_by_ordinal(ordinal)?.fragment(),
                ResolutionSiteId::new(site),
            ));
        }
    }
    traits.sort_unstable();
    traits.dedup();
    Ok(RustImplementedTraits::Traits(traits))
}

/// The built-in derive names of the Rust declaration whose authority is
/// `?2` in mount `?1`, and whether it is declared at module level (#11325).
const OWNER_BUILTIN_DERIVES: &str = "SELECT json(property.builtin_derives),
  property.nearest_declaration_boundary=0
 FROM temp.selected_resolution_mounts AS mount
 CROSS JOIN resolution_rust_declaration_authorities AS authority
  ON authority.blob_id=mount.blob_id AND authority.semantic_key=?2
 CROSS JOIN source_native_declaration_bridges AS bridge
  ON bridge.blob_id=authority.blob_id AND bridge.source_site=authority.semantic_key
 CROSS JOIN source_rust_declaration_properties AS property
  ON property.blob_id=bridge.blob_id AND property.declaration_id=bridge.declaration_id
 WHERE mount.mount_ordinal=?1";

/// Every module placement of the Rust declaration whose authority is `?2` in
/// mount `?1`, as the crate topology and module path its derive names are
/// looked up in.
const OWNER_PLACEMENTS: &str = "SELECT placement.topology_id, placement.container_path
 FROM temp.selected_resolution_mounts AS mount
 CROSS JOIN resolution_rust_declaration_authorities AS authority
  ON authority.blob_id=mount.blob_id AND authority.semantic_key=?2
 CROSS JOIN selected_rust_container_placements AS placement
  ON placement.mount_ordinal=mount.mount_ordinal
  AND placement.module_declaration IS authority.module_declaration
 WHERE mount.mount_ordinal=?1";

/// What the built-in derives of one Rust type declaration say about one
/// member spelling (#11325).
///
/// A bare derive name reaches the prelude's built-in derive exactly when the
/// macro lookup at the item's module finds no workspace macro, no external
/// binding, no open inventory and no unindexed scope, and the crate's prelude
/// injects the name. That is the derive-helper absence proof
/// ([`super::rust_derive_helpers`]) asked of the derive name itself. Each
/// placement of the declaration must prove every name.
pub(crate) fn builtin_derive_member(
    selection: &SelectedResolutionMountInventory<'_>,
    owner: (SelectedResolutionMountOrdinal, i64),
    lookup: SemanticId,
    cancellation: &CancellationToken,
) -> Result<crate::analyzer::resolution::RustBuiltinDeriveMember> {
    use crate::analyzer::resolution::RustBuiltinDeriveMember;
    use brokk_bifrost_rust::prelude::{
        RustEdition, RustPreludeNamespace, rust_builtin_derive, rust_prelude_name,
    };
    let conn = selection.connection();
    let Some((names, module_level)) = conn
        .prepare_cached(OWNER_BUILTIN_DERIVES)?
        .query_row(params![owner.0.get(), owner.1], |row| {
            Ok((row.get::<_, Option<String>>(0)?, row.get::<_, bool>(1)?))
        })
        .optional()?
    else {
        return Ok(RustBuiltinDeriveMember::NotDerived);
    };
    let Some(names) = names else {
        return Ok(RustBuiltinDeriveMember::NotDerived);
    };
    let names = serde_json::from_str::<Vec<String>>(&names)
        .expect("source facts store built-in derive names as a JSON array");
    let derives = names
        .iter()
        .map(|name| {
            rust_builtin_derive(&[name.as_str()])
                .unwrap_or_else(|| panic!("a recorded built-in derive is reviewed: {name}"))
        })
        .collect::<Vec<_>>();
    // A declaration in a block is placed by its block, not by a module.
    if !module_level {
        return Ok(RustBuiltinDeriveMember::Unproven);
    }
    let placements = conn
        .prepare_cached(OWNER_PLACEMENTS)?
        .query_map(params![owner.0.get(), owner.1], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if placements.is_empty() {
        return Ok(RustBuiltinDeriveMember::Unproven);
    }
    for (topology, path) in &placements {
        if cancellation.is_cancelled() {
            return Ok(RustBuiltinDeriveMember::Cancelled);
        }
        let (edition, prelude): (String, String) = conn
            .prepare_cached(TOPOLOGY_PRELUDE)?
            .query_row([topology], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let edition = RustEdition::from_crate_row(&edition).expect("schema checks the edition");
        let prelude = match prelude.as_str() {
            "std" => brokk_bifrost_rust::prelude::RustPreludeCrate::Std,
            "core" => brokk_bifrost_rust::prelude::RustPreludeCrate::Core,
            "none" => return Ok(RustBuiltinDeriveMember::Unproven),
            other => unreachable!("schema checks the prelude: {other}"),
        };
        for derive in &derives {
            if rust_prelude_name(derive.name, RustPreludeNamespace::Macro, edition, prelude)
                .is_none()
                || !super::rust_derive_helpers::helper_absent_from_macro_lookup(
                    conn,
                    *topology,
                    path,
                    derive.name,
                )?
            {
                return Ok(RustBuiltinDeriveMember::Unproven);
            }
        }
    }
    let Some(spelling) = lookup
        .shared_name_id()
        .filter(|name| name.is_interned())
        .map(|name| {
            conn.prepare_cached("SELECT spelling FROM resolution_identities WHERE id=?1")?
                .query_row([i64::from(name.get())], |row| {
                    row.get::<_, Option<String>>(0)
                })
                .optional()
        })
        .transpose()?
        .flatten()
        .flatten()
    else {
        // A name the store never interned is spelled by no source file, so
        // no derived item can carry it.
        return Ok(RustBuiltinDeriveMember::Absent);
    };
    let mut members = derives.iter().flat_map(|derive| {
        derive
            .items
            .iter()
            .filter(|item| item.name == spelling)
            .map(move |item| (*derive, item))
    });
    let member = members.next();
    assert!(
        members.next().is_none(),
        "the built-in derives declare each item once: {spelling}"
    );
    Ok(match member {
        Some((derive, item)) => RustBuiltinDeriveMember::Member { derive, item },
        None => RustBuiltinDeriveMember::Absent,
    })
}

/// Nameability of a known trait does not require an indexed impl subject.
pub(crate) fn trait_nameable_at(
    selection: &SelectedResolutionMountInventory<'_>,
    owner: (SelectedResolutionMountOrdinal, i64),
    reference: (SelectedResolutionMountOrdinal, i64),
    cancellation: &CancellationToken,
) -> Result<crate::analyzer::resolution::RustImplementedTraits> {
    use crate::analyzer::resolution::RustImplementedTraits;
    let conn = selection.connection();
    let Some((owner_blob, owner_site, owner_placed, owner_path)) = conn
        .prepare_cached(OWNER_DECLARATION)?
        .query_row(params![owner.0.get(), owner.1], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, bool>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .optional()?
    else {
        return Ok(RustImplementedTraits::Traits(Vec::new()));
    };
    if !owner_placed {
        return Ok(RustImplementedTraits::Unplaced);
    }
    let modules = conn
        .prepare_cached(REFERENCE_MODULE_PLACEMENTS)?
        .query_map(params![reference.0.get(), reference.1], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if modules.is_empty() {
        return Ok(RustImplementedTraits::Unplaced);
    }
    let mounts = SelectedMountTable::new(selection);
    let mut traits = Vec::new();
    for (topology, path) in modules {
        if cancellation.is_cancelled() {
            return Ok(RustImplementedTraits::Cancelled);
        }
        for row in conn.prepare_cached(TRAIT_VISIBLE_AT)?.query_map(
            params![
                owner_blob,
                owner_site,
                topology,
                path,
                owner_path,
                reference.0.get(),
                reference.1,
                rust_unit_summary_derivation_identity()
            ],
            |row| {
                Ok((
                    row.get::<_, u32>(1)?,
                    SelectedResolutionMountOrdinal::new(row.get::<_, u32>(2)?),
                ))
            },
        )? {
            let (site, ordinal) = row?;
            traits.push(mounted_site_semantic(
                mounts.mount_by_ordinal(ordinal)?.fragment(),
                ResolutionSiteId::new(site),
            ));
        }
    }
    traits.sort_unstable();
    traits.dedup();
    Ok(RustImplementedTraits::Traits(traits))
}

/// The traits the crate rows say one Rust impl item's own impl states, as trait
/// definitions in the selected mounts. `?1` is the item's mount ordinal, `?2`
/// its semantic key.
///
/// The item's declaration is a body child of its impl declaration
/// (`source_rust_item_body_children`), and the impl declaration is the key
/// `rust_crate_trait_impls_impl` is seeked on, together with the file the
/// impl's crate places it in. Crate derivation bound the header in the impl's
/// own crate, so the answer holds wherever the item is asked from. The trait
/// end is placed by the file the row names, which selects the trait's mount,
/// as [`TRAIT_IMPLS_VISIBLE_AT`] does. The body children are read by their
/// blob's primary key: a declaration id alone is small and repeats in every
/// blob, so its index would visit one row per file.
pub(super) const IMPL_ITEM_TRAITS: &str = concat!(
    "WITH RECURSIVE ",
    rust_selected_members_cte!(
        "WHERE blobs.id=(SELECT blob_id FROM temp.selected_resolution_mounts WHERE mount_ordinal=?1) \
         AND members.rel_path=(SELECT persisted_relative_path FROM temp.selected_resolution_mounts WHERE mount_ordinal=?1)",
        "?3"
    ),
    /* Rust-only derived-from blob until #11183 M3 converts Rust child rows */
    "SELECT DISTINCT trait_export.declaration_site, trait_mount.mount_ordinal \
     FROM selected_members AS impl_member \
     CROSS JOIN temp.selected_resolution_mounts AS mount \
       ON mount.mount_ordinal=?1 AND mount.blob_id=impl_member.blob_id \
      AND mount.persisted_relative_path=impl_member.rel_path \
     CROSS JOIN resolution_rust_declaration_authorities AS authority \
       ON authority.blob_id=impl_member.blob_id AND authority.semantic_key=?2 \
     CROSS JOIN source_rust_item_body_children AS child \
       ON child.blob_id=authority.blob_id AND +child.declaration_id=authority.declaration \
     CROSS JOIN main.rust_resolution_unit_summary_trait_endpoints AS endpoint \
       INDEXED BY rust_resolution_unit_summary_trait_endpoints_impl \
       ON endpoint.summary_id=impl_member.summary_id \
      AND endpoint.member_ordinal=impl_member.member_ordinal \
      AND endpoint.impl_declaration_id=child.owner_declaration_id \
      AND endpoint.endpoint_role='trait' AND endpoint.endpoint_state='resolved' \
     CROSS JOIN selected_workspace_revisions AS trait_revision \
       ON trait_revision.workspace_id=impl_member.workspace_id \
      AND trait_revision.lang='rust' AND trait_revision.generation=impl_member.generation \
     CROSS JOIN main.resolution_unit_summary_versions AS trait_version \
       INDEXED BY sqlite_autoindex_resolution_unit_summary_versions_1 \
       ON trait_version.workspace_id=trait_revision.workspace_id \
      AND trait_version.lang=trait_revision.lang \
      AND trait_version.generation=trait_revision.generation \
      AND trait_version.unit_key=endpoint.target_unit_key \
      AND trait_version.valid_from<=trait_revision.revision \
      AND (trait_version.valid_until IS NULL OR trait_revision.revision<trait_version.valid_until) \
     CROSS JOIN main.resolution_unit_summaries AS trait_summary \
       ON trait_summary.summary_id=trait_version.summary_id \
      AND trait_summary.lang='rust' AND trait_summary.unit_kind='rust_crate' \
      AND trait_summary.publication_state='complete' AND trait_summary.derivation_identity=?3 \
     CROSS JOIN main.resolution_producer_epochs AS trait_epoch \
       ON trait_epoch.lang=trait_version.lang \
      AND trait_epoch.producer_epoch=trait_summary.producer_epoch \
     CROSS JOIN main.rust_resolution_unit_summary_versions AS trait_rust_version \
       ON trait_rust_version.workspace_id=trait_version.workspace_id \
      AND trait_rust_version.lang=trait_version.lang \
      AND trait_rust_version.generation=trait_version.generation \
      AND trait_rust_version.unit_key=trait_version.unit_key \
      AND trait_rust_version.valid_from=trait_version.valid_from \
      AND trait_rust_version.summary_id=trait_version.summary_id \
     CROSS JOIN main.rust_resolution_unit_summary_contexts AS trait_context \
       ON trait_context.summary_id=trait_version.summary_id \
     CROSS JOIN main.rust_resolution_unit_summary_exports AS trait_export \
       INDEXED BY rust_resolution_unit_summary_exports_identity \
       ON trait_export.summary_id=trait_version.summary_id \
      AND trait_export.identity_id=endpoint.target_identity_id \
      AND trait_export.module_path=endpoint.target_module_path \
      AND trait_export.namespace='type' AND trait_export.origin='declaration' \
     CROSS JOIN main.resolution_unit_summary_members AS trait_member \
       ON trait_member.summary_id=trait_export.summary_id \
      AND trait_member.member_ordinal=trait_export.declaration_member_ordinal \
     CROSS JOIN selected_workspace_file_versions AS trait_file \
       ON trait_file.workspace_id=trait_version.workspace_id \
      AND trait_file.lang=trait_version.lang \
      AND trait_file.generation=trait_version.generation \
      AND trait_file.rel_path=trait_member.rel_path \
     CROSS JOIN main.blobs AS trait_blob \
       ON trait_blob.id=(SELECT attachment.blob_id FROM temp.selected_unit_member_blobs AS attachment \
        WHERE attachment.summary_id=trait_member.summary_id AND attachment.member_ordinal=trait_member.member_ordinal) \
      AND trait_blob.lang=trait_version.lang \
      AND trait_blob.generation=trait_version.generation AND trait_blob.blob_oid=trait_file.blob_oid \
     CROSS JOIN temp.selected_resolution_mounts AS trait_mount \
       ON trait_mount.storage_language='rust' \
      AND trait_mount.persisted_relative_path=trait_member.rel_path \
      AND EXISTS(SELECT 1 FROM temp.selected_unit_member_blobs AS attachment \
       WHERE attachment.summary_id=trait_member.summary_id \
        AND attachment.member_ordinal=trait_member.member_ordinal AND attachment.blob_id=trait_mount.blob_id) \
     WHERE child.syntax_kind='function_item'"
);

/// The traits the crate rows say the impl that declares one Rust item
/// states, as trait definitions in the selected mounts.
///
/// An empty answer means the rows bind no trait to that impl: it is not a
/// trait impl, its trait side is unresolved, or the derivation could not
/// bridge the impl to one impl item. The caller then resolves the impl's
/// header as it would without the rows. `member` is a mount ordinal and a
/// semantic key with ordinary provenance.
pub(crate) fn impl_item_traits(
    selection: &SelectedResolutionMountInventory<'_>,
    member: (SelectedResolutionMountOrdinal, i64),
    cancellation: &CancellationToken,
) -> Result<crate::analyzer::resolution::RustImplementedTraits> {
    use crate::analyzer::resolution::RustImplementedTraits;
    if cancellation.is_cancelled() {
        return Ok(RustImplementedTraits::Cancelled);
    }
    let mounts = SelectedMountTable::new(selection);
    let mut traits = Vec::new();
    for row in selection
        .connection()
        .prepare_cached(IMPL_ITEM_TRAITS)?
        .query_map(
            params![
                member.0.get(),
                member.1,
                rust_unit_summary_derivation_identity()
            ],
            |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    SelectedResolutionMountOrdinal::new(row.get::<_, u32>(1)?),
                ))
            },
        )?
    {
        let (site, ordinal) = row?;
        traits.push(mounted_site_semantic(
            mounts.mount_by_ordinal(ordinal)?.fragment(),
            ResolutionSiteId::new(site),
        ));
    }
    traits.sort_unstable();
    traits.dedup();
    Ok(RustImplementedTraits::Traits(traits))
}

/// Match an import's type-namespace token in its existing structured root key.
/// The penultimate root-key cell is the import token; each cell is
/// [local identity, shared identity, scoped]. A reference half has no open
/// tail and therefore cannot impersonate this binding. The identity remains
/// local to the binding: unrelated same-spelled external types never unify.
pub(super) const EXTERNAL_TYPE_IDENTITY: &str = "SELECT 1
 FROM temp.selected_resolution_mounts AS mount
 CROSS JOIN resolution_paths AS binding
  ON binding.blob_id=mount.blob_id AND binding.end_node=-1
  AND binding.start_node<>-1 AND binding.end_open_tail=1
  AND json_extract(binding.end_fixed_key,'$[#-2][0]')=?2
 CROSS JOIN resolution_identities AS identity ON identity.id=binding.root_terminal
 WHERE mount.mount_ordinal=?1 AND identity.namespace=?3 LIMIT 1";

pub(crate) fn external_type_identities(
    selection: &SelectedResolutionMountInventory<'_>,
    boundary: (SelectedResolutionMountOrdinal, i64),
    cancellation: &CancellationToken,
) -> Result<Option<Vec<SemanticId>>> {
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    let present = selection
        .connection()
        .prepare_cached(EXTERNAL_TYPE_IDENTITY)?
        .exists(params![
            boundary.0.get(),
            boundary.1,
            crate::analyzer::store::resolution_prepare::resolution_rows::namespace_code(
                ResolutionNamespace::Type
            )
        ])?;
    let identities = if present {
        let mount = SelectedMountTable::new(selection).mount_by_ordinal(boundary.0)?;
        vec![mounted_site_semantic(
            mount.fragment(),
            ResolutionSiteId::new(u32::try_from(boundary.1).expect("a local semantic fits u32")),
        )]
    } else {
        Vec::new()
    };
    Ok(Some(identities))
}

/// Read one external type import through its explicit token-to-route site.
pub(crate) fn external_type_import_path(
    selection: &SelectedResolutionMountInventory<'_>,
    boundary: (SelectedResolutionMountOrdinal, i64),
    cancellation: &CancellationToken,
) -> Result<Option<Vec<String>>> {
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    let conn = selection.connection();
    let blob = selection.mount_record_by_ordinal(boundary.0)?.blob_id();
    let site: Option<u32> = conn
        .prepare_cached(super::imports::TOKEN_SITE)?
        .query_row(params![blob, boundary.1], |row| row.get(0))
        .optional()?;
    let path = site
        .map(|site| super::imports::route_at_site(conn, blob, site))
        .transpose()?
        .flatten()
        .and_then(|route| {
            // X::{self} binds X, so the retained path names X.
            route.named_path(
                crate::analyzer::store::resolution_prepare::resolution_rows::namespace_code(
                    ResolutionNamespace::Type,
                ),
            )
        })
        .unwrap_or_default();
    Ok(Some(path))
}

/// Keep cfg alternatives separate: a boundary closes only when every route
/// names the same itemless standard marker.
fn external_type_import_paths_for_binding(
    selection: &SelectedResolutionMountInventory<'_>,
    blob: i64,
    scope: u32,
    bound_name: &str,
    cancellation: &CancellationToken,
) -> Result<Option<Vec<Vec<String>>>> {
    let Some(routes) = super::imports::named_routes(
        selection.connection(),
        blob,
        scope,
        bound_name,
        cancellation,
    )?
    else {
        return Ok(None);
    };
    let namespace = crate::analyzer::store::resolution_prepare::resolution_rows::namespace_code(
        ResolutionNamespace::Type,
    );
    let paths = routes
        .iter()
        .filter_map(|route| route.named_path(namespace))
        .collect::<Vec<_>>();
    Ok(Some(paths))
}

impl RustCrateRows<'_, '_, '_> {
    pub(super) fn external_type_import_paths_for_binding(
        &self,
        blob: i64,
        scope: u32,
        bound_name: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<Vec<String>>>> {
        external_type_import_paths_for_binding(
            &self.ready.inventory,
            blob,
            scope,
            bound_name,
            cancellation,
        )
    }

    /// The crate modules one selected file is placed in, with whether they
    /// belong to a directly requested root.
    ///
    /// A file is a module of every topology whose container rows name it.
    /// Lookup asks each directly requested placement; a dependency placement
    /// cannot supply an alternate `crate::` root for that same source. Both
    /// Rust forward routes read this, which is why it lives beside the crate
    /// rows rather than in either one.
    pub(super) fn modules_for_mount(
        &self,
        mounts: SelectedMountTable<'_, '_>,
        ordinal: SelectedResolutionMountOrdinal,
        request_topologies: &[i64],
        cancellation: &CancellationToken,
    ) -> Result<Vec<Module>> {
        let mount = mounts.mount_by_ordinal(ordinal)?;
        let conn = self.ready.inventory.connection();
        let blob: Option<i64> = conn
            .prepare_cached(FILE_BLOB)?
            .query_row([mount.persisted_relative_path()], |row| row.get(0))
            .optional()?;
        let Some(blob) = blob else {
            return Ok(Vec::new());
        };
        // The mount is in hand, so its blob is a dense index into the
        // inventory's records rather than another read.
        let selected_blob = self
            .ready
            .inventory
            .persisted_mount_record(ordinal)?
            .map(|record| record.blob_id());
        let overlay_completion = self.crate_overlay_import_completion(
            blob,
            mount.persisted_relative_path(),
            selected_blob,
            cancellation,
        )?;
        let fragment = mount.fragment();
        let request_topologies = serde_json::to_string(request_topologies)
            .expect("Cargo topology ids serialize as JSON");
        conn.prepare_cached(MODULES_FOR_BLOB)?
            .query_map(
                params![blob, mount.persisted_relative_path(), request_topologies],
                |row| {
                    Ok(Module {
                        topology: row.get(0)?,
                        path: row.get(1)?,
                        blob: row.get(2)?,
                        rel_path: row.get(3)?,
                        selected_blob: selected_blob.expect("selected module has a published blob"),
                        fragment,
                        scope: ResolutionScopeId::new(row.get(4)?),
                        edition: row.get(5)?,
                        unmounted: row.get(6)?,
                        requested: row.get(7)?,
                        overlay_completion: overlay_completion.clone(),
                    })
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// `selected_blob` is the blob of the mount selected for `path`, which
    /// every caller already read while resolving that mount, so this asks the
    /// selection nothing of its own.
    pub(super) fn crate_overlay_import_completion(
        &self,
        blob: i64,
        path: &str,
        selected_blob: Option<i64>,
        cancellation: &CancellationToken,
    ) -> Result<ResolutionCompletion> {
        if selected_blob.is_none_or(|selected| selected == blob) {
            return Ok(ResolutionCompletion::Complete);
        }
        let persisted = self
            .ready
            .inventory
            .connection()
            .prepare_cached(IMPORT_INVENTORY)?
            .query_map([blob], |row| row.get::<_, String>(0))?
            .map(|row| {
                serde_json::from_str::<serde_json::Value>(&row?)
                    .map_err(|error| StoreError::corrupt(error.to_string()))
            })
            .collect::<Result<Vec<_>>>()?;
        let selected = self
            .ready
            .inventory
            .connection()
            .prepare_cached(IMPORT_INVENTORY)?
            .query_map(
                [selected_blob.expect("changed canonical overlay blob")],
                |row| row.get::<_, String>(0),
            )?
            .map(|row| {
                serde_json::from_str::<serde_json::Value>(&row?)
                    .map_err(|error| StoreError::corrupt(error.to_string()))
            })
            .collect::<Result<Vec<_>>>()?;
        // A changed bound name is local. A changed imported name is valid
        // only when its existing route exports that name from selected content.
        let mut name_only_change = selected.len() == persisted.len();
        if name_only_change {
            for (ordinal, (selected, persisted)) in selected.iter().zip(&persisted).enumerate() {
                let selected = selected
                    .as_array()
                    .ok_or_else(|| StoreError::corrupt("selected import tuple"))?;
                let persisted = persisted
                    .as_array()
                    .ok_or_else(|| StoreError::corrupt("persisted import tuple"))?;
                if selected.len() != persisted.len()
                    || !selected
                        .iter()
                        .zip(persisted)
                        .enumerate()
                        .all(|(index, (left, right))| matches!(index, 1 | 2) || left == right)
                    || (selected[2] != persisted[2]
                        && !self.crate_import_target_is_exported(
                            blob,
                            ordinal,
                            selected[2].as_str(),
                            cancellation,
                        )?)
                {
                    name_only_change = false;
                    break;
                }
            }
        }
        Ok(if name_only_change {
            ResolutionCompletion::Complete
        } else {
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic({
                // A reason the context invents, numbered by the request's
                // own table so two reads of one divergence agree.
                let mut digest = CanonicalHasher::new(b"bifrost-rust-overlay-import-divergence:v1");
                digest.field("path", path.as_bytes());
                digest.field("blob", &blob.to_be_bytes());
                self.ready.context_identities.semantic(digest.finish())
            })])
        })
    }

    /// Does the selected target module export this imported name to its caller?
    fn crate_import_target_is_exported(
        &self,
        blob: i64,
        ordinal: usize,
        name: Option<&str>,
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        let Some(name) = name else { return Ok(false) };
        let conn = self.ready.inventory.connection();
        let mut found = false;
        for target in conn.prepare_cached(OVERLAY_IMPORT_TARGETS)?.query_map(
            params![blob, ordinal],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )? {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            let (topology, path, namespace, requester_topology, requester_path) = target?;
            // A topology route is reusable after a name-only edit. Its old
            // declaration coordinate is not: PUBLISHED_EXPORT reads selected authority,
            // including the actual name, visibility, activation and source site.
            if !conn.prepare_cached(PUBLISHED_EXPORT)?.exists(params![
                topology,
                path,
                namespace,
                name,
                requester_topology,
                requester_path,
            ])? {
                return Ok(false);
            }
            found = true;
        }
        Ok(found)
    }

    /// Bridges from one qualified route whose prefix resolved to a type, into
    /// the member scope of each trait that type implements and the reference
    /// can name.
    ///
    /// This is the join gate 6 group 1 named. `Foo::frobnicate()` reaches the
    /// crate route as a prefix reference that resolved to `Foo`'s declaration
    /// and a `frobnicate` demand with nothing left of the route: `Foo` is not a
    /// module, so the module walk has no continuation and the route used to
    /// stop with a decided negative. What it has instead is a subject
    /// declaration identity, which is exactly the key
    /// `rust_crate_trait_impls_subject` is built on.
    ///
    /// The bridge decides how many trait scopes may compete: Rust makes
    /// `Foo::frobnicate()` an error when two traits in scope both declare
    /// `frobnicate`, so a second binding trait publishes nothing and the proved
    /// negative stands. When one visible trait binds a callable and this exact
    /// subject's impl declares that method, the bridge lands on that concrete
    /// impl member. The lowered member identity is joined to that subject's
    /// trait impl body, so another type's implementation of the same trait is
    /// excluded.
    ///
    /// One subject identity per qualifier value, and one statement for it. The
    /// crate's other impls are never enumerated: the read seeks the two subject
    /// columns of a covering index.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn crate_trait_member_bridges(
        &self,
        mounts: &SelectedMountTable<'_, '_>,
        reference: &Module,
        source_fragment: BindingFragmentId,
        token: SemanticId,
        anchor: ResolutionRootImportAnchor,
        anchor_semantic: SemanticId,
        prefix: SemanticId,
        demand: &ResolutionLookupSemanticRecipe,
        subject_blob: i64,
        subject_site: u32,
        subject_path: &str,
        continuation: &ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> Result<Vec<SelectedRootBridgeDescriptor>> {
        let traits = self
            .ready
            .inventory
            .connection()
            .prepare_cached(TRAIT_IMPLS_VISIBLE_AT)?
            .query_map(
                params![
                    subject_blob,
                    subject_site,
                    reference.topology,
                    reference.path,
                    subject_path,
                    token.ordinal(),
                    token.local_key(),
                    rust_unit_summary_derivation_identity()
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, u32>(1)?,
                        SelectedResolutionMountOrdinal::new(row.get::<_, u32>(2)?),
                    ))
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if traits.is_empty() {
            return Ok(Vec::new());
        }
        let mut fragments = HashMap::default();
        let mut trait_declarations = HashMap::default();
        let mut definitions = Vec::with_capacity(traits.len());
        for (blob, site, ordinal) in traits {
            let fragment = mounts.mount_by_ordinal(ordinal)?.fragment();
            let definition = mounted_site_semantic(fragment, ResolutionSiteId::new(site));
            fragments.insert(definition, fragment);
            trait_declarations.insert(definition, (blob, site, ordinal));
            definitions.push(definition);
        }
        let typed = self.ready.typed_source();
        let selected = super::demand_closure::select_unique_exact_member(
            &typed,
            &self.ready.lexical_source(),
            super::demand_closure::AdmissibleMemberOwners {
                definitions,
                lookup: demand.semantic(&self.ready.shared_names()),
            },
            cancellation,
            |definition| {
                if !matches!(
                    demand.namespace(),
                    ResolutionNamespace::Callable | ResolutionNamespace::Value
                ) {
                    return Ok(Vec::new());
                }
                let (trait_blob, trait_site, trait_ordinal) = trait_declarations[&definition];
                let trait_mount = mounts.mount_by_ordinal(trait_ordinal)?;
                let trait_path = trait_mount.persisted_relative_path();
                let callable_demand = ResolutionLookupSemanticRecipe::new(
                    Language::Rust,
                    ResolutionNamespace::Callable,
                    demand.spelling(),
                );
                let lookup = [DeferredMemberOwnerLookupName::new(
                    callable_demand.semantic(&self.ready.shared_names()),
                )];
                let mut definitions = Vec::new();
                let mut collect = |rows: &[SelectedTypedRow<LoweredDeferredMemberOwner>]| {
                    for row in rows {
                        if row.row().kind() == ResolutionMemberKind::Method {
                            definitions.push((row.fragment(), row.row().definition()));
                        }
                    }
                    Ok(!cancellation.is_cancelled())
                };
                let outcome = typed.visit_deferred_member_owner_pages_for_lookup_names(
                    TypedFactRequest::new(&lookup),
                    cancellation,
                    &mut FactPageVisitor::new(&mut collect),
                )?;
                if outcome.is_cancelled() {
                    return Ok(Vec::new());
                }
                definitions.sort_unstable();
                definitions.dedup();
                let mut impl_members = Vec::new();
                let connection = self.ready.inventory.connection();
                for (fragment, member) in definitions {
                    let member_ordinal = SelectedResolutionMountOrdinal::new(fragment.ordinal());
                    assert_eq!(
                        member.ordinal(),
                        Some(fragment.ordinal()),
                        "a deferred impl member belongs to its selected source fragment"
                    );
                    let member_key = member
                        .local_key()
                        .expect("a deferred Rust impl member has a local definition key");
                    for row in connection.prepare_cached(TRAIT_IMPL_MEMBER_AT)?.query_map(
                        params![
                            member_ordinal.get(),
                            member_key,
                            subject_blob,
                            subject_site,
                            subject_path,
                            trait_blob,
                            trait_site,
                            trait_path,
                            rust_unit_summary_derivation_identity()
                        ],
                        |row| {
                            Ok((
                                row.get::<_, u32>(0)?,
                                SelectedResolutionMountOrdinal::new(row.get::<_, u32>(1)?),
                            ))
                        },
                    )? {
                        let (site, ordinal) = row?;
                        let member_fragment = mounts.mount_by_ordinal(ordinal)?.fragment();
                        impl_members.push((
                            member_fragment,
                            mounted_site_node(member_fragment, ResolutionSiteId::new(site)),
                        ));
                    }
                }
                Ok(impl_members)
            },
        )?;
        let Some(selected) = selected else {
            return Ok(Vec::new());
        };
        let definition = selected.owner;
        let trait_fragment = fragments[&definition];
        let (target_fragment, target_definition) = selected
            .override_target
            .map(|(fragment, definition)| (fragment, Some(definition)))
            .unwrap_or((trait_fragment, None));
        let bridge = SelectedRootBridgeDescriptor::from_selected_path_tokens_with_prefix(
            source_fragment,
            Language::Rust,
            token,
            anchor,
            anchor_semantic,
            target_fragment,
            Language::Rust,
            definition,
            prefix,
            Vec::new(),
            demand.clone(),
            demand.clone(),
            continuation.clone(),
        );
        let bridge = if let Some(target_definition) = target_definition {
            bridge.with_selected_member_definition(target_definition)
        } else {
            bridge.with_trait_member_scope(selected.scope_head)
        };
        Ok(vec![bridge])
    }

    /// An import with no active binding can still bind a name under an
    /// undecidable cfg. Inspect the source inventory before following its
    /// terminal route, where an alias's spelling need not exist.
    ///
    /// A module owner's exact set comes from the published authority, with
    /// access checked at the binding: only a mixed-visibility group substitutes
    /// an independently exact set.
    pub(super) fn crate_binding_inventory(
        &self,
        requester: &Module,
        topology: i64,
        path: &str,
        namespace: &str,
        name: &str,
    ) -> Result<RustBindingInventory> {
        let details = self.binding_details(topology, path, 0, 0, namespace, name)?;
        let mut exact_group = false;
        for detail in &details {
            let parsed: serde_json::Value = serde_json::from_str(detail)
                .map_err(|error| StoreError::corrupt(error.to_string()))?;
            exact_group |= gap_evidence(&parsed)?
                .iter()
                .any(|evidence| evidence["reason"] == "UnsupportedGlobConflictVisibility");
        }
        let targets = if exact_group {
            let Some((_complete, targets)) = published_binding_exact(
                self.ready.inventory.connection(),
                topology,
                path,
                namespace,
                name,
                requester.topology,
                &requester.path,
            )?
            else {
                return Err(StoreError::corrupt(
                    "module visibility conflict has no published name certificate",
                ));
            };
            Some(
                targets
                    .into_iter()
                    .filter_map(|(topology, path, name)| Some((topology?, path, name)))
                    .collect(),
            )
        } else {
            None
        };
        Ok(RustBindingInventory {
            completion: self.inventory_completion(details)?,
            targets,
        })
    }

    /// The evidence that a binding's own import path is unproven. An ordinary
    /// precedence conflict keeps its route-level handling; only an unproven
    /// path (`dependency_ambiguity`) makes an empty target a miss that is not a
    /// decided absence.
    pub(super) fn unproven_binding_completion(
        &self,
        topology: i64,
        path: &str,
        namespace: &str,
        name: &str,
    ) -> Result<ResolutionCompletion> {
        let mut details = Vec::new();
        for detail in self.binding_details(topology, path, 0, 0, namespace, name)? {
            let parsed: serde_json::Value = serde_json::from_str(&detail)
                .map_err(|error| StoreError::corrupt(error.to_string()))?;
            let evidence = gap_evidence(&parsed)?
                .iter()
                .filter(|item| {
                    item["reason"].as_str() == Some("InconsistentPrecedence")
                        && item["dependency_ambiguity"].as_bool() == Some(true)
                })
                .collect::<Vec<_>>();
            if !evidence.is_empty() {
                details.push(serde_json::json!({"evidence": evidence}).to_string());
            }
        }
        self.inventory_completion(details)
    }

    /// Completion of exactly one scoped lexical binding owner. Another
    /// function's evidence cannot match. Scoped local owners keep their
    /// selected-catalog inventory; module owners use crate_binding_inventory.
    pub(super) fn crate_owner_binding_inventory(
        &self,
        topology: i64,
        path: &str,
        blob: i64,
        binder_scope: u32,
        namespace: &str,
        name: &str,
    ) -> Result<RustBindingInventory> {
        debug_assert!(
            blob != 0 || binder_scope != 0,
            "a module owner reads crate_binding_inventory"
        );
        self.binding_inventory(self.binding_details(
            topology,
            path,
            blob,
            binder_scope,
            namespace,
            name,
        )?)
    }

    fn binding_details(
        &self,
        topology: i64,
        path: &str,
        blob: i64,
        binder_scope: u32,
        namespace: &str,
        name: &str,
    ) -> Result<Vec<String>> {
        Ok(self
            .ready
            .inventory
            .connection()
            .prepare_cached(BINDING_INVENTORY)?
            .query_map(
                params![topology, path, namespace, name, blob, binder_scope],
                |row| row.get::<_, String>(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub(super) fn crate_import_inventory(
        &self,
        requester: &Module,
        demand: &ResolutionLookupSemanticRecipe,
    ) -> Result<RustBindingInventory> {
        let details = self.import_details(requester, demand, 0, 0)?;
        let mut binding = self.crate_binding_inventory(
            requester,
            requester.topology,
            &requester.path,
            namespace(demand.namespace()),
            demand.spelling(),
        )?;
        binding.completion = binding
            .completion
            .combine(&self.inventory_completion(details)?);
        Ok(binding)
    }

    pub(super) fn crate_owner_import_inventory(
        &self,
        requester: &Module,
        demand: &ResolutionLookupSemanticRecipe,
        blob: i64,
        binder_scope: u32,
    ) -> Result<RustBindingInventory> {
        let details = self.import_details(requester, demand, blob, binder_scope)?;
        let mut binding = self.crate_owner_binding_inventory(
            requester.topology,
            &requester.path,
            blob,
            binder_scope,
            namespace(demand.namespace()),
            demand.spelling(),
        )?;
        binding.completion = binding
            .completion
            .combine(&self.inventory_completion(details)?);
        Ok(binding)
    }

    fn import_details(
        &self,
        requester: &Module,
        demand: &ResolutionLookupSemanticRecipe,
        blob: i64,
        binder_scope: u32,
    ) -> Result<Vec<String>> {
        Ok(self
            .ready
            .inventory
            .connection()
            .prepare_cached(UNKNOWN_IMPORT_INVENTORY)?
            .query_map(
                params![
                    requester.topology,
                    requester.path,
                    demand.spelling(),
                    namespace(demand.namespace()),
                    blob,
                    binder_scope
                ],
                |row| row.get::<_, String>(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    #[doc(hidden)]
    pub fn crate_inventory_completion(
        &self,
        requester: &Module,
        topology: i64,
        path: &str,
        namespace: &str,
        name: &str,
    ) -> Result<ResolutionCompletion> {
        let key = (
            topology,
            path.to_owned(),
            namespace.to_owned(),
            name.to_owned(),
            requester.topology,
            requester.path.clone(),
        );
        let remembered = self
            .ready
            .crate_rows
            .borrow()
            .as_ref()
            .and_then(|memo| memo.inventories.get(&key).cloned());
        let details = match remembered {
            Some(details) => details,
            None => {
                let details = self
                    .ready
                    .inventory
                    .connection()
                    .prepare_cached(PUBLISHED_OPEN_INVENTORY)?
                    .query_map(
                        params![
                            topology,
                            path,
                            namespace,
                            name,
                            requester.topology,
                            requester.path
                        ],
                        |row| row.get::<_, String>(0),
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                if let Some(memo) = self.ready.crate_rows.borrow_mut().as_mut() {
                    memo.inventories.insert(key, details.clone());
                }
                details
            }
        };
        self.inventory_completion(details)
    }

    fn binding_inventory(&self, details: Vec<String>) -> Result<RustBindingInventory> {
        let mut targets = None;
        for detail in &details {
            let parsed: serde_json::Value = serde_json::from_str(detail)
                .map_err(|error| StoreError::corrupt(error.to_string()))?;
            for evidence in gap_evidence(&parsed)? {
                if evidence["reason"].as_str() != Some("UnsupportedGlobConflictVisibility") {
                    continue;
                }
                let canonical = targets.get_or_insert_with(Vec::new);
                for endpoint in evidence["exact_targets"]
                    .as_array()
                    .ok_or_else(|| StoreError::corrupt("exact binding targets"))?
                {
                    let topology = self
                        .ready
                        .inventory
                        .connection()
                        .prepare_cached(BINDING_TARGET_TOPOLOGY)?
                        .query_row(
                            [endpoint["crate"]
                                .as_str()
                                .ok_or_else(|| StoreError::corrupt("canonical crate key"))?],
                            |row| row.get::<_, i64>(0),
                        )
                        .optional()?;
                    if let Some(topology) = topology {
                        let target = (
                            topology,
                            endpoint["module"]
                                .as_str()
                                .ok_or_else(|| StoreError::corrupt("canonical module path"))?
                                .to_owned(),
                            endpoint["name"]
                                .as_str()
                                .ok_or_else(|| StoreError::corrupt("canonical name"))?
                                .to_owned(),
                        );
                        if !canonical.contains(&target) {
                            canonical.push(target);
                        }
                    }
                }
            }
        }
        Ok(RustBindingInventory {
            completion: self.inventory_completion(details)?,
            targets,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn inventory_completion_for_test(
        &self,
        details: Vec<String>,
    ) -> Result<ResolutionCompletion> {
        self.binding_inventory(details)
            .map(|inventory| inventory.completion)
    }

    fn inventory_completion(&self, details: Vec<String>) -> Result<ResolutionCompletion> {
        decode_inventory_completion(&self.ready.context_identities, details)
    }

    /// The native import scopes of one module scope
    /// (`rust_crate_point_scopes.sql`), remembered for the crate stage.
    pub(super) fn module_import_scopes(&self, blob: i64, scope: u32) -> Result<Vec<u32>> {
        if let Some(scopes) = self
            .ready
            .crate_rows
            .borrow()
            .as_ref()
            .and_then(|memo| memo.scopes.get(&(blob, scope)))
        {
            return Ok(scopes.clone());
        }
        let scopes = self
            .ready
            .inventory
            .connection()
            .prepare_cached(SCOPES)?
            .query_map(params![blob, scope], |row| row.get::<_, u32>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if let Some(memo) = self.ready.crate_rows.borrow_mut().as_mut() {
            memo.scopes.insert((blob, scope), scopes.clone());
        }
        Ok(scopes)
    }

    /// Rewrite a module anchor's route targets onto the declarations that name
    /// them, so the export lookup that follows finds a `mod` item.
    ///
    /// `crate`, `self` and `super` name a module, not an export of one: the
    /// producer ends an anchor occurrence's route on the anchor's own step, so
    /// the module the walk reached is the answer rather than the module a name
    /// lookup then searches. A module's own declaration is the `mod` item its
    /// parent's source writes, and `rust_crate_containers`,
    /// `rust_crate_container_sources` and `source_rust_module_declarations`
    /// already join on exactly that relation; `CONTAINER_DECLARATION` is the
    /// inverse of the direction `DEFINITION_MODULE` spells forward, so the
    /// parent path and the declared name both come from rows.
    ///
    /// A crate root is written by no `mod` item and therefore contributes no
    /// target: a caret on the `crate` of `crate::x` has no declaration to
    /// stand on.
    pub(super) fn anchor_declaration_targets(
        &self,
        targets: Vec<(i64, String, String)>,
    ) -> Result<Vec<(i64, String, String)>> {
        let conn = self.ready.inventory.connection();
        let mut declarations = Vec::new();
        for (topology, path, _) in targets {
            for row in conn
                .prepare_cached(CONTAINER_DECLARATION)?
                .query_map(params![topology, path], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
            {
                let (parent, name) = row?;
                declarations.push((topology, parent, name));
            }
        }
        declarations.sort_unstable();
        declarations.dedup();
        Ok(declarations)
    }

    /// Consume the canonical exact set when a raw glob walk is unsupported.
    /// An empty exact set is still incomplete, rather than a proven absence.
    pub(super) fn crate_exports_from_inventory(
        &self,
        requester: &Module,
        topology: i64,
        path: &str,
        namespace: &str,
        name: &str,
        inventory: &RustBindingInventory,
    ) -> Result<Vec<RustCrateExport>> {
        let Some(targets) = &inventory.targets else {
            return self.crate_exports(requester, topology, path, namespace, name);
        };
        let mut exports = Vec::new();
        for (topology, path, name) in targets {
            exports.extend(self.crate_exports(requester, *topology, path, namespace, name)?);
        }
        Ok(exports)
    }

    /// The completion owed for found exports whose module this selection
    /// unplaced (`RustCrateExport::unplaced`).
    pub(super) fn unplaced_exports_completion(
        &self,
        exports: &[RustCrateExport],
    ) -> ResolutionCompletion {
        exports
            .iter()
            .filter_map(|export| export.unplaced.as_deref())
            .fold(ResolutionCompletion::Complete, |completion, detail| {
                completion.combine(&ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(inventory_reason(
                        &self.ready.context_identities,
                        detail,
                    )),
                ]))
            })
    }

    #[doc(hidden)]
    pub fn crate_exports(
        &self,
        requester: &Module,
        topology: i64,
        path: &str,
        namespace: &str,
        name: &str,
    ) -> Result<Vec<RustCrateExport>> {
        let key = self.ready.crate_rows.borrow().is_some().then(|| {
            (
                topology,
                path.to_owned(),
                namespace.to_owned(),
                name.to_owned(),
                requester.topology,
                requester.path.clone(),
            )
        });
        if let Some(key) = &key
            && let Some(exports) = self
                .ready
                .crate_rows
                .borrow()
                .as_ref()
                .and_then(|memo| memo.exports.get(key))
        {
            return Ok(exports.clone());
        }
        let exports = self
            .ready
            .inventory
            .connection()
            .prepare_cached(PUBLISHED_EXPORT)?
            .query_map(
                params![
                    topology,
                    path,
                    namespace,
                    name,
                    requester.topology,
                    requester.path
                ],
                |row| {
                    Ok(RustCrateExport {
                        blob: row.get(0)?,
                        declaration: match (row.get(1)?, row.get(5)?) {
                            (Some(site), None) => RustCrateDeclaration::Site(site),
                            (None, Some(declaration)) => {
                                RustCrateDeclaration::MacroItem(declaration)
                            }
                            other => unreachable!(
                                "an export row names exactly one declaration: {other:?}"
                            ),
                        },
                        topology: row.get(2)?,
                        module_path: row.get(3)?,
                        mount: SelectedResolutionMountOrdinal::new(row.get(4)?),
                        unplaced: row.get(6)?,
                    })
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if let Some(key) = key {
            self.ready
                .crate_rows
                .borrow_mut()
                .as_mut()
                .expect("the memo outlives the lookup that found it")
                .exports
                .insert(key, exports.clone());
        }
        Ok(exports)
    }

    /// The original external import tokens reached through named/glob routes.
    /// Retaining the originating binding makes a local reimport share its type
    /// identity with uses of that binding in the parent module.
    pub(super) fn crate_external_bindings(
        &self,
        requester: &Module,
        topology: i64,
        path: &str,
        demand_namespace: ResolutionNamespace,
        name: &str,
    ) -> Result<Vec<SemanticId>> {
        let mounts = SelectedMountTable::new(&self.ready.inventory);
        let mut identities = Vec::new();
        for row in self
            .ready
            .inventory
            .connection()
            .prepare_cached(EXTERNAL_BINDING)?
            .query_map(
                params![
                    topology,
                    path,
                    namespace(demand_namespace),
                    name,
                    requester.topology,
                    requester.path,
                    crate::analyzer::store::resolution_prepare::resolution_rows::namespace_code(
                        demand_namespace
                    )
                ],
                |row| {
                    Ok((
                        SelectedResolutionMountOrdinal::new(row.get::<_, u32>(0)?),
                        row.get::<_, u32>(1)?,
                    ))
                },
            )?
        {
            let (ordinal, site) = row?;
            identities.push(mounted_site_semantic(
                mounts.mount_by_ordinal(ordinal)?.fragment(),
                ResolutionSiteId::new(site),
            ));
        }
        Ok(identities)
    }

    fn absolute_root(
        &self,
        topology: i64,
        name: &str,
        demand_namespace: ResolutionNamespace,
    ) -> Result<RustAbsoluteRoot> {
        let conn = self.ready.inventory.connection();
        let (edition, prelude): (String, String) = conn
            .prepare_cached(TOPOLOGY_PRELUDE)?
            .query_row([topology], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let detached: bool = conn
            .prepare_cached(
                "SELECT contexts.target_kind='detached'
 FROM selected_rust_unit_summaries AS unit
 JOIN main.rust_resolution_unit_summary_contexts AS contexts USING(summary_id)
 WHERE unit.topology_id=?1",
            )?
            .query_row([topology], |row| row.get(0))?;
        let aliases = conn.prepare_cached("SELECT DISTINCT import.imported_name, cr_cfg(import.cfg_condition, json(contexts.cfg_atoms))
 FROM selected_rust_unit_summaries AS unit
 JOIN main.rust_resolution_unit_summary_contexts AS contexts USING(summary_id)
 JOIN temp.rust_unit_summary_placements AS placement ON placement.summary_id=unit.summary_id AND placement.module_path='crate'
 JOIN main.resolution_unit_summary_members AS member ON member.summary_id=placement.summary_id AND member.member_ordinal=placement.member_ordinal
 JOIN source_rust_import_targets AS import ON import.blob_id=member.blob_id
 WHERE unit.topology_id=?1 AND import.is_extern_crate=1 AND import.bound_name=?2
 AND import.local_start IS NULL AND COALESCE(import.owner_module,'')=''")?
            .query_map(params![topology, name], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if aliases.iter().any(|(_, cfg)| *cfg == -1) {
            return Ok(RustAbsoluteRoot::Unavailable {
                reason: "extern crate binder cfg unavailable",
                deterministic: true,
            });
        }
        let aliases = aliases
            .into_iter()
            .filter_map(|(name, cfg)| (cfg == 1).then_some(name))
            .collect::<Vec<_>>();
        // `extern crate self as alias;` names the crate being compiled. Every
        // edition and a detached file agree on it, because the binder is itself
        // a crate-root item and the extern prelude carries it alike. The crate
        // is not its own dependency, so the dependency lookup below must not see it.
        if aliases.as_slice() == ["self"] {
            return Ok(RustAbsoluteRoot::Indexed {
                topology,
                consumed: 1,
            });
        }
        // Edition 2015 resolves `::name` in the crate root, so a crate-root
        // binding of the name wins and the crate's own namespace answers.
        // Only a type- or module-namespace binding can be a path head: a
        // `fn std` lives in the value namespace beside the injected crate.
        // An active `extern crate` binder is the root binding itself and names
        // its crate as the later editions' extern prelude does. With neither,
        // the prelude crate is the implicit `extern crate std;` (or, under
        // `#![no_std]`, `extern crate core;`) the compiler injects, and the
        // prelude value names it.
        if !detached && edition == "2015" && aliases.is_empty() {
            let bound: bool = conn
                .prepare_cached(
                    "SELECT EXISTS(SELECT 1
 FROM selected_rust_unit_summaries AS unit
 JOIN main.rust_resolution_unit_summary_effective_bindings AS binding USING(summary_id)
 WHERE unit.topology_id=?1 AND binding.module_path='crate' AND binding.name=?2
 AND (binding.namespace=?3 OR (?3='type' AND binding.namespace='module')))
 OR EXISTS(SELECT 1
 FROM selected_rust_unit_summaries AS unit
 JOIN main.resolution_unit_summary_containers AS container USING(summary_id)
 WHERE unit.topology_id=?1 AND container.container_path=?2 AND container.parent_container_path='' AND ?3='type')
",
                )?
                .query_row(params![topology, name, namespace(demand_namespace)], |row| row.get(0))?;
            // A crate-root `use` binds the name only while its cfg is active,
            // the same rule the extern-crate binder query above applies. An
            // undecidable condition proves neither answer.
            //
            // The injected crate occupies the type namespace, so an import
            // competes with it only when it binds there: `use helpers::std;`
            // of a fn is a value and leaves `::std` the injected crate. The
            // namespace of an import is recorded only once it resolves to a
            // binding, so an active import of the prelude's own name that has
            // no binding at all has an unknown namespace and proves nothing.
            // Any other name has no injected crate to compete with.
            let imports = conn
                .prepare_cached(
                    "SELECT cr_cfg(import.cfg_condition, json(contexts.cfg_atoms)),
 EXISTS(SELECT 1 FROM main.rust_crate_binding_provenance AS binding
  WHERE binding.topology_id=?1 AND binding.blob_id=import.blob_id
  AND binding.import_ordinal=import.ordinal AND binding.module_path='crate'
  AND binding.namespace IN ('type','module')),
 EXISTS(SELECT 1 FROM main.rust_crate_binding_provenance AS binding
  WHERE binding.topology_id=?1 AND binding.blob_id=import.blob_id
  AND binding.import_ordinal=import.ordinal AND binding.module_path='crate')
 FROM selected_rust_unit_summaries AS unit
 JOIN main.rust_resolution_unit_summary_contexts AS contexts USING(summary_id)
 JOIN temp.rust_unit_summary_placements AS placement ON placement.summary_id=unit.summary_id AND placement.module_path='crate'
 JOIN main.resolution_unit_summary_members AS member ON member.summary_id=placement.summary_id AND member.member_ordinal=placement.member_ordinal
 JOIN source_rust_import_targets AS import ON import.blob_id=member.blob_id
 WHERE unit.topology_id=?1 AND import.is_extern_crate=0 AND import.bound_name=?2
 AND import.local_start IS NULL AND COALESCE(import.owner_module,'')=''",
                )?
                .query_map(params![topology, name], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, bool>(1)?, row.get::<_, bool>(2)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            if imports.iter().any(|(cfg, ..)| *cfg == -1) {
                return Ok(RustAbsoluteRoot::Unavailable {
                    reason: "crate-root import cfg unavailable",
                    deterministic: true,
                });
            }
            let mut head_binder = false;
            for (_, types, any) in imports.iter().filter(|(cfg, ..)| *cfg == 1) {
                let competes = namespace(demand_namespace) == "type" && name == prelude;
                if competes && !types && !any {
                    return Ok(RustAbsoluteRoot::Unavailable {
                        reason: "crate-root import namespace unavailable",
                        deterministic: true,
                    });
                }
                head_binder |= !competes || *types;
            }
            if head_binder {
                return Ok(RustAbsoluteRoot::CrateRootImport { topology });
            }
            if bound
                || namespace(demand_namespace) != "type"
                || prelude == "none"
                || name != prelude
            {
                return Ok(RustAbsoluteRoot::Indexed {
                    topology,
                    consumed: 0,
                });
            }
            return Ok(RustAbsoluteRoot::External(vec![name.to_owned()]));
        }
        if detached {
            let bound: bool = conn
                .prepare_cached(
                    "SELECT EXISTS(SELECT 1
 FROM selected_rust_unit_summaries AS unit
 JOIN main.rust_resolution_unit_summary_effective_bindings AS binding USING(summary_id)
 WHERE unit.topology_id=?1 AND binding.module_path='crate' AND binding.name=?2
 AND binding.namespace IN ('type','module'))",
                )?
                .query_row(params![topology, name], |row| row.get(0))?;
            if !bound && aliases.is_empty() && (name == "core" || name == "std" && prelude == "std")
            {
                return Ok(RustAbsoluteRoot::External(vec![name.to_owned()]));
            }
            return Ok(RustAbsoluteRoot::Unavailable {
                reason: "absolute root edition has no manifest authority",
                deterministic: true,
            });
        }
        let canonical = match aliases.as_slice() {
            [] => name,
            [alias] => alias,
            _ => {
                return Ok(RustAbsoluteRoot::Unavailable {
                    reason: "ambiguous extern crate binder",
                    deterministic: true,
                });
            }
        };
        let targets = conn
            .prepare_cached(DEPENDENCY.as_str())?
            .query_map(
                params![topology, canonical, rust_unit_summary_derivation_identity()],
                |row| row.get::<_, i64>(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if let [target] = targets.as_slice() {
            return Ok(RustAbsoluteRoot::Indexed {
                topology: *target,
                consumed: 1,
            });
        }
        // The boundary of every dependency the unit declares under this extern
        // name. A Cargo rename is already the extern name here, and the activated
        // model matches it through the crate-root aliases it publishes, so a
        // lone external dependency owns the name exactly as an ordinary
        // `name::item` path does.
        let boundaries = conn
            .prepare_cached(
                "SELECT DISTINCT dependency.boundary
 FROM selected_rust_unit_summaries AS unit
 JOIN main.rust_unit_summary_dependency_names AS name USING(summary_id)
 JOIN main.resolution_unit_summary_dependencies AS dependency
 ON dependency.summary_id=name.summary_id AND dependency.dependency_ordinal=name.dependency_ordinal
 WHERE unit.topology_id=?1 AND name.extern_name=?2",
            )?
            .query_map(params![topology, canonical], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if targets.is_empty() && boundaries.as_slice() == ["external"] {
            return Ok(RustAbsoluteRoot::External(vec![canonical.to_owned()]));
        }
        if targets.is_empty()
            && boundaries.iter().all(|boundary| boundary == "standard")
            && (canonical == "core"
                || canonical == "std" && (prelude == "std" || !aliases.is_empty())
                || canonical == "alloc" && !aliases.is_empty())
        {
            return Ok(RustAbsoluteRoot::External(vec![canonical.to_owned()]));
        }
        Ok(RustAbsoluteRoot::Unavailable {
            reason: "absolute external crate identity unavailable",
            deterministic: true,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn crate_route(
        &self,
        requester: &Module,
        topology: i64,
        path: String,
        route: &[ResolutionLookupSemanticRecipe],
        terminal: &str,
        anchor: ResolutionRootImportAnchor,
        completion: &mut ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> Result<Vec<(i64, String)>> {
        self.crate_route_from(
            requester,
            WalkCursor::container((), topology, path, 0),
            route,
            terminal,
            anchor,
            completion,
            cancellation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn crate_route_from<T: Clone + Eq + std::hash::Hash>(
        &self,
        requester: &Module,
        cursor: WalkCursor<T>,
        route: &[ResolutionLookupSemanticRecipe],
        terminal: &str,
        anchor: ResolutionRootImportAnchor,
        completion: &mut ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> Result<Vec<(i64, String)>> {
        walk_container_route(
            &RustRouteRules {
                rows: RustCrateRows { ready: self.ready },
                requester,
                anchor,
                route,
                terminal,
                demand_namespace: ResolutionNamespace::Type,
            },
            cursor,
            route,
            completion,
            cancellation,
        )
    }
}

impl RustCrateRows<'_, '_, '_> {
    /// What a route that starts at `crate`, `self` or `super` cannot prove from
    /// a file no selected Cargo target compiles: the keyword names the root of
    /// that file's synthetic detached unit, which holds only that file, so a
    /// miss there is not an absence in the real crate. The reason is the
    /// file's macro gate, its inactive `cfg` placement, or else the plain
    /// unmounted-file reason. Complete for any other requester or route.
    ///
    /// A route can miss at a middle segment (`RouteRules::dead_end`) or at the
    /// demanded name after the keyword is consumed (`crate::missing`); both ask
    /// this one question.
    pub(super) fn unmounted_keyword_root_completion(
        &self,
        requester: &Module,
        route: &[ResolutionLookupSemanticRecipe],
    ) -> Result<ResolutionCompletion> {
        let keyword_root = requester.unmounted
            && route
                .first()
                .is_some_and(|segment| matches!(segment.spelling(), "crate" | "self" | "super"));
        if !keyword_root {
            return Ok(ResolutionCompletion::Complete);
        }
        let conn = self.ready.inventory.connection();
        let macro_details = super::rust_crate_context::macro_gated_unmounted_file_details(
            conn,
            &requester.rel_path,
        )?;
        if !macro_details.is_empty() {
            return Ok(super::rust_crate_context::macro_gated_route_boundary(
                &self.ready.context_identities,
                &macro_details,
            ));
        }
        let inactive_cfg_details = super::rust_crate_context::inactive_cfg_unmounted_file_details(
            conn,
            &requester.rel_path,
        )?;
        if inactive_cfg_details.is_empty() {
            Ok(ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnmountedFile {
                    fragment: requester.fragment,
                },
            ]))
        } else {
            Ok(super::rust_crate_context::inactive_cfg_route_boundary(
                &self.ready.context_identities,
                &inactive_cfg_details,
            ))
        }
    }
}

/// Route continuations consume published admitted alternatives with access
/// checked at the source binding. The shared walker owns route precedence.
pub(super) struct RustRouteRules<'a, 'store, 'input> {
    pub(super) rows: RustCrateRows<'a, 'store, 'input>,
    pub(super) requester: &'a Module,
    pub(super) anchor: ResolutionRootImportAnchor,
    pub(super) route: &'a [ResolutionLookupSemanticRecipe],
    /// The name the route's lookup demands after the last segment. Under the
    /// Absolute anchor an empty route is a leading `::name` whose head is this
    /// terminal, so root selection reads the spelling from here.
    pub(super) terminal: &'a str,
    pub(super) demand_namespace: ResolutionNamespace,
}

impl<T: Clone + Eq + std::hash::Hash> RouteRules<T> for RustRouteRules<'_, '_, '_> {
    fn root_starts(
        &self,
        start: &WalkCursor<T>,
        completion: &mut ResolutionCompletion,
    ) -> Result<RouteStarts> {
        let RouteLocation::Container { unit, .. } = &start.location else {
            unreachable!("module start is a container")
        };
        if self.anchor != ResolutionRootImportAnchor::Absolute {
            return Ok(RouteStarts {
                locations: vec![start.location.clone()],
                consumed: 0,
            });
        }
        // A leading `::name` whose head is the terminal has an empty route; the
        // head then selects its root by its own spelling like any other head.
        let head_segment = self.route.get(start.consumed_prefix_segments);
        debug_assert!(head_segment.is_some() || self.route.is_empty());
        let head = head_segment.map_or(self.terminal, |segment| segment.spelling());
        // The crate root answers the same route whether an item or an active
        // crate-root `use` binds the head.
        let answer = match self.rows.absolute_root(
            *unit,
            head,
            if head_segment.is_some() {
                ResolutionNamespace::Type
            } else {
                self.demand_namespace
            },
        )? {
            RustAbsoluteRoot::CrateRootImport { topology } => RustAbsoluteRoot::Indexed {
                topology,
                consumed: 0,
            },
            other => other,
        };
        if !matches!(&answer, RustAbsoluteRoot::Indexed { consumed: 0, .. }) {
            let RouteLocation::Container { container, .. } = &start.location else {
                unreachable!("root starts in a container")
            };
            let inventory = self.rows.crate_binding_inventory(
                self.requester,
                *unit,
                container,
                "type",
                head,
            )?;
            *completion = completion.combine(&inventory.completion);
        }
        match answer {
            // A dependency crate (or `extern crate self as alias`) named as the
            // terminal is the crate itself: no workspace declaration, so no
            // location for the terminal lookup to read.
            RustAbsoluteRoot::Indexed { consumed, .. }
                if consumed > 0 && head_segment.is_none() =>
            {
                Ok(RouteStarts {
                    locations: Vec::new(),
                    consumed: 0,
                })
            }
            RustAbsoluteRoot::Indexed { topology, consumed } => Ok(RouteStarts {
                locations: vec![RouteLocation::Container {
                    unit: topology,
                    container: "crate".into(),
                }],
                consumed,
            }),
            RustAbsoluteRoot::CrateRootImport { .. } => {
                unreachable!("normalized to the crate root above")
            }
            RustAbsoluteRoot::External(_) => {
                *completion = completion.combine(&self.dead_end_at(start, head)?);
                Ok(RouteStarts {
                    locations: Vec::new(),
                    consumed: head_segment.map_or(0, |_| 1),
                })
            }
            RustAbsoluteRoot::Unavailable { reason, .. } => {
                // The root is undecided, not absent: no inventory proves the
                // route complete, so say why it is open.
                *completion = completion.combine(&unavailable_absolute_root(
                    &self.rows.ready.context_identities,
                    reason,
                    head,
                ));
                *completion = completion.combine(&self.dead_end_at(start, head)?);
                Ok(RouteStarts {
                    locations: Vec::new(),
                    consumed: head_segment.map_or(0, |_| 1),
                })
            }
        }
    }

    fn route_tier(
        &self,
        cursor: &WalkCursor<T>,
        segment: &ResolutionLookupSemanticRecipe,
        tier: usize,
    ) -> Result<Option<RouteEdgeTier>> {
        let RouteLocation::Container {
            unit: topology,
            container: path,
        } = &cursor.location
        else {
            unreachable!("module cursor is a container")
        };
        let conn = self.rows.ready.inventory.connection();
        let name = segment.spelling();
        let first = cursor.consumed_prefix_segments == cursor.start_step;
        let mut result = RouteEdgeTier::default();
        let location = |unit, container| RouteLocation::Container { unit, container };
        match name {
            "crate" if first => {
                if tier != 0 {
                    return Ok(None);
                }
                result.edges.push(location(*topology, "crate".into()));
            }
            "self" => {
                if tier != 0 {
                    return Ok(None);
                }
                result.edges.push(cursor.location.clone());
            }
            "super" => {
                if tier != 0 {
                    return Ok(None);
                }
                result.edges = conn
                    .prepare_cached(PARENT)?
                    .query_map(params![topology, path], |row| {
                        Ok(location(*topology, row.get(0)?))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
            }
            _ => match tier {
                0 => {
                    result.independent = true;
                    if first {
                        result.edges = conn
                            .prepare_cached(DEPENDENCY.as_str())?
                            .query_map(
                                params![topology, name, rust_unit_summary_derivation_identity()],
                                |row| Ok(location(row.get(0)?, "crate".into())),
                            )?
                            .collect::<rusqlite::Result<Vec<_>>>()?;
                    }
                }
                1 => {
                    let inventory = self.rows.crate_binding_inventory(
                        self.requester,
                        *topology,
                        path,
                        "type",
                        name,
                    )?;
                    // Some(empty) is an authoritative empty exact set in an
                    // incomplete group. It blocks raw root-reexport fallback.
                    result.blocks_fallback = inventory.targets.is_some();
                    let exports = self.rows.crate_exports_from_inventory(
                        self.requester,
                        *topology,
                        path,
                        "type",
                        name,
                        &inventory,
                    )?;
                    result.coverage = inventory
                        .completion
                        .combine(&self.rows.unplaced_exports_completion(&exports));
                    for RustCrateExport {
                        blob,
                        declaration,
                        topology: export_topology,
                        module_path: export_module_path,
                        ..
                    } in exports
                    {
                        let module = |row: &rusqlite::Row<'_>| -> rusqlite::Result<_> {
                            Ok(location(row.get(0)?, row.get(1)?))
                        };
                        match declaration {
                            RustCrateDeclaration::Site(site) => {
                                result.edges.extend(
                                    conn.prepare_cached(DEFINITION_MODULE)?
                                        .query_map(
                                            params![
                                                blob,
                                                site,
                                                export_topology,
                                                export_module_path
                                            ],
                                            module,
                                        )?
                                        .collect::<rusqlite::Result<Vec<_>>>()?,
                                );
                            }
                            RustCrateDeclaration::MacroItem(declaration) => {
                                result.edges.extend(
                                    conn.prepare_cached(MACRO_ITEM_MODULE)?
                                        .query_map(
                                            params![
                                                blob,
                                                declaration,
                                                export_topology,
                                                export_module_path,
                                                name
                                            ],
                                            module,
                                        )?
                                        .collect::<rusqlite::Result<Vec<_>>>()?,
                                );
                            }
                        }
                    }
                }
                2 => {
                    // Published admitted crate-root alternatives, checked at the binding.
                    result.edges = conn
                        .prepare_cached(PUBLISHED_ROOT_REEXPORT)?
                        .query_map(
                            params![
                                topology,
                                path,
                                "type",
                                name,
                                self.requester.topology,
                                self.requester.path
                            ],
                            |row| Ok(location(row.get(0)?, "crate".into())),
                        )?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                }
                _ => return Ok(None),
            },
        }
        Ok(Some(result))
    }

    fn dead_end(
        &self,
        cursor: &WalkCursor<T>,
        segment: &ResolutionLookupSemanticRecipe,
    ) -> Result<ResolutionCompletion> {
        self.dead_end_at(cursor, segment.spelling())
    }
}

impl RustRouteRules<'_, '_, '_> {
    /// What a miss at `name` leaves open: the unmounted-file boundary, the
    /// name's inventory and any macro-opened route.
    fn dead_end_at<T>(&self, cursor: &WalkCursor<T>, name: &str) -> Result<ResolutionCompletion> {
        let RouteLocation::Container {
            unit: topology,
            container: path,
        } = &cursor.location
        else {
            unreachable!("module cursor is a container")
        };
        let conn = self.rows.ready.inventory.connection();
        let requester = self.requester;
        let topology = *topology;
        let mut completion = self
            .rows
            .unmounted_keyword_root_completion(requester, self.route)?;
        completion = completion.combine(
            &self
                .rows
                .crate_inventory_completion(requester, topology, path, "type", name)?,
        );
        for detail in conn
            .prepare_cached(OPEN_ROUTE)?
            .query_map(params![topology, path, name], |row| row.get::<_, String>(0))?
        {
            let detail = detail?;
            completion = completion.combine(&ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(inventory_reason(
                    &self.rows.ready.context_identities,
                    &detail,
                )),
            ]));
        }
        Ok(completion)
    }
}

impl super::graph_stage::GraphStageHelperTables for RustGraphStageTables<'_> {}

/// Decode stored gap strings into reader-local completion evidence.
fn decode_inventory_completion(
    identities: &SelectedContextIdentities,
    details: Vec<String>,
) -> Result<ResolutionCompletion> {
    let mut completion = ResolutionCompletion::Complete;
    for detail in details {
        let parsed: serde_json::Value = serde_json::from_str(&detail)
            .map_err(|error| StoreError::corrupt(error.to_string()))?;
        let semantic = inventory_reason(identities, &detail);
        let evidence = gap_evidence(&parsed)?;
        for item in evidence {
            // Derivation carries the original structured external route
            // through boundary dependencies. Preserve its identity for
            // marker-trait closure, including X::{self} imports.
            if item["reason"].as_str() == Some("OpenBoundary")
                && item["boundary"].as_str() == Some("external_declared_unindexed")
                && let Some(paths) = item["import_paths"].as_array()
            {
                let paths = paths
                    .iter()
                    .map(|path| {
                        serde_json::from_value::<Vec<String>>(path.clone())
                            .map_err(|error| StoreError::corrupt(error.to_string()))
                    })
                    .collect::<Result<Vec<_>>>()?;
                identities.record_rust_external_type_import_paths(semantic, paths);
            }
            let reason = match GapEvidenceReason::of(item["reason"].as_str()) {
                GapEvidenceReason::UnsupportedMacroGeneratedModule
                | GapEvidenceReason::UnsupportedGlobConflictVisibility => {
                    let detail = serde_json::json!({"evidence": [item]}).to_string();
                    ResolutionIncompleteReason::UnsupportedSemantic(inventory_reason(
                        identities, &detail,
                    ))
                }
                GapEvidenceReason::InconsistentPrecedence => {
                    ResolutionIncompleteReason::InconsistentPrecedence(semantic)
                }
                GapEvidenceReason::OpenBoundary
                    if item["boundary"].as_str() == Some("workspace_local")
                        && item["inventory"]["reason"].as_str()
                            == Some("UnsupportedMacroGeneratedModule") =>
                {
                    // The canonical relation retained this exact invocation,
                    // rather than a generic workspace boundary. Use its
                    // original identity so model coverage can account for it.
                    let detail = serde_json::json!({"evidence": [&item["inventory"]]}).to_string();
                    ResolutionIncompleteReason::OpenBoundary {
                        semantic: inventory_reason(identities, &detail),
                        status: crate::analyzer::structural::BoundaryStatus::WorkspaceLocal,
                    }
                }
                GapEvidenceReason::OpenBoundary => ResolutionIncompleteReason::OpenBoundary {
                    semantic,
                    status: match item["boundary"].as_str() {
                        Some("external_declared_unindexed") => {
                            crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed
                        }
                        _ => crate::analyzer::structural::BoundaryStatus::WorkspaceLocal,
                    },
                },
                GapEvidenceReason::CyclicExpansion => {
                    let mut digest = CanonicalHasher::new(b"rust-crate-binding-cycle:v1");
                    digest.field("evidence", detail.as_bytes());
                    ResolutionIncompleteReason::CyclicExpansion(identities.path(digest.finish()))
                }
                // An unnamed identity has no declared determinism, so it is
                // never a snapshot stop (see `snapshot_stop_semantics`).
                GapEvidenceReason::UnsupportedSemantic => {
                    ResolutionIncompleteReason::UnsupportedSemantic(semantic)
                }
                GapEvidenceReason::Unclassified => {
                    ResolutionIncompleteReason::Unclassified(semantic)
                }
            };
            completion = completion.combine(&ResolutionCompletion::incomplete([reason]));
        }
    }
    Ok(completion)
}

///
/// The evidence reasons a persisted Rust crate gap can name (#11510).
///
/// Every known variant decodes to its existing typed reason. Whether an
/// `UnsupportedSemantic` is a deterministic stop is not decided here: it is
/// declared on the named reason by whoever mints it (`ReasonDeterminism`), and
/// an identity that is not named has no declaration. The match in
/// [`GapEvidenceReason::of`] and the one in `inventory_completion` have no
/// wildcard, so a new reason must be placed in both, and a wire string this
/// build does not know is [`GapEvidenceReason::Unclassified`]. The synthetic
/// `EditedMacroHost`, `AmbiguousGlobSource`, `OverlayUnplacedModule` and
/// `OverlayAddedModule` evidence and the impl-half outcomes `ambiguous`,
/// `unbound_external`, `unbound_incomplete` and `bound_without_declaration`
/// are known producer reasons and decode to `UnsupportedSemantic`. An
/// unrecognized string decodes to an operation-local
/// `Unclassified`, which stays a distinct Provider stop. It never enters
/// persisted completion kinds; writer entry points reject it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GapEvidenceReason {
    UnsupportedMacroGeneratedModule,
    UnsupportedGlobConflictVisibility,
    InconsistentPrecedence,
    OpenBoundary,
    CyclicExpansion,
    /// A reason whose producer writes it into the gap row as a fact about the
    /// snapshot's declarations, imports or public surface, and which the crate
    /// relation reports as an unsupported semantic.
    UnsupportedSemantic,
    Unclassified,
}

impl GapEvidenceReason {
    /// `None` is the evidence of a placement gap (`unknown_activation`,
    /// `unplaced_module`, `duplicate_placement`): those rows name a path and an
    /// activation, not a reason.
    fn of(wire: Option<&str>) -> Self {
        enum Wire {
            UnsupportedMacroGeneratedModule,
            UnsupportedGlobConflictVisibility,
            InconsistentPrecedence,
            OpenBoundary,
            CyclicExpansion,
            GeneratedItemSurface,
            UnloweredDeclaration,
            UnsupportedImportTarget,
            UnresolvedVisibility,
            PublicModuleAmbiguous,
            PublicModuleUnavailable,
            PublicModuleInventoryUnavailable,
            EditedMacroHost,
            AmbiguousGlobSource,
            OverlayUnplacedModule,
            OverlayAddedModule,
            Ambiguous,
            UnboundExternal,
            UnboundIncomplete,
            BoundWithoutDeclaration,
            PlacementGap,
            Unknown,
        }
        let wire = match wire {
            None => Wire::PlacementGap,
            Some("UnsupportedMacroGeneratedModule") => Wire::UnsupportedMacroGeneratedModule,
            Some("UnsupportedGlobConflictVisibility") => Wire::UnsupportedGlobConflictVisibility,
            Some("InconsistentPrecedence") => Wire::InconsistentPrecedence,
            Some("OpenBoundary") => Wire::OpenBoundary,
            Some("CyclicExpansion") => Wire::CyclicExpansion,
            Some("GeneratedItemSurface") => Wire::GeneratedItemSurface,
            Some("UnloweredDeclaration") => Wire::UnloweredDeclaration,
            Some("UnsupportedImportTarget") => Wire::UnsupportedImportTarget,
            Some("UnresolvedVisibility") => Wire::UnresolvedVisibility,
            Some("public_module_ambiguous") => Wire::PublicModuleAmbiguous,
            Some("public_module_unavailable") => Wire::PublicModuleUnavailable,
            Some("public_module_inventory_unavailable") => Wire::PublicModuleInventoryUnavailable,
            Some("EditedMacroHost") => Wire::EditedMacroHost,
            Some("AmbiguousGlobSource") => Wire::AmbiguousGlobSource,
            Some("OverlayUnplacedModule") => Wire::OverlayUnplacedModule,
            Some("OverlayAddedModule") => Wire::OverlayAddedModule,
            Some("ambiguous") => Wire::Ambiguous,
            Some("unbound_external") => Wire::UnboundExternal,
            Some("unbound_incomplete") => Wire::UnboundIncomplete,
            Some("bound_without_declaration") => Wire::BoundWithoutDeclaration,
            Some(_) => Wire::Unknown,
        };
        match wire {
            Wire::UnsupportedMacroGeneratedModule => Self::UnsupportedMacroGeneratedModule,
            Wire::UnsupportedGlobConflictVisibility => Self::UnsupportedGlobConflictVisibility,
            Wire::InconsistentPrecedence => Self::InconsistentPrecedence,
            Wire::OpenBoundary => Self::OpenBoundary,
            Wire::CyclicExpansion => Self::CyclicExpansion,
            Wire::GeneratedItemSurface
            | Wire::UnloweredDeclaration
            | Wire::UnsupportedImportTarget
            | Wire::UnresolvedVisibility
            | Wire::PublicModuleAmbiguous
            | Wire::PublicModuleUnavailable
            | Wire::PublicModuleInventoryUnavailable
            | Wire::EditedMacroHost
            | Wire::AmbiguousGlobSource
            | Wire::OverlayUnplacedModule
            | Wire::OverlayAddedModule
            | Wire::Ambiguous
            | Wire::UnboundExternal
            | Wire::UnboundIncomplete
            | Wire::BoundWithoutDeclaration
            | Wire::PlacementGap => Self::UnsupportedSemantic,
            Wire::Unknown => Self::Unclassified,
        }
    }
}

#[cfg(test)]
mod unclassified_tests {
    use super::*;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11510: an unknown stored gap reason was folded into UnsupportedSemantic"
    )]
    fn unknown_stored_gap_reason_stays_unclassified() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .execute("CREATE TABLE gaps (detail TEXT NOT NULL)", [])
            .unwrap();
        let detail =
            serde_json::json!({"evidence": [{"reason": "FutureRustGapReason"}]}).to_string();
        connection
            .execute("INSERT INTO gaps(detail) VALUES (?1)", [&detail])
            .unwrap();
        let details = connection
            .prepare("SELECT detail FROM gaps")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let completion =
            decode_inventory_completion(&SelectedContextIdentities::new(), details).unwrap();
        let ResolutionCompletion::Incomplete(reasons) = completion else {
            panic!("unknown stored reason must remain incomplete");
        };
        assert_eq!(reasons.len(), 1);
        let reason = reasons.iter().next().unwrap();
        assert!(
            matches!(reason, ResolutionIncompleteReason::Unclassified(_)),
            "{reason:?}"
        );
        assert_eq!(
            super::super::native_units::public_reason_details(reason).0,
            "Unclassified"
        );
    }
}
