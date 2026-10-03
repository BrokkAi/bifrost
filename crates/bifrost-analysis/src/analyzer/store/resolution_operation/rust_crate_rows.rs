//! Borrowed crate-row reads shared by point compilation and endpoint demands.
use super::rust_crate_context::*;
use super::*;
use crate::analyzer::resolution::{
    BatchCandidateRequest, DeferredMemberOwnerLookupName, EndpointSignature,
    LoweredDeferredMemberOwner, LoweredMemberScopeProperty, StackPattern, mounted_site_node,
    mounted_site_semantic,
};
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberKind;
use rusqlite::{OptionalExtension, params};

/// The `unmounted` column and its `+` are explained beside
/// `rust_crate_context::MODULES`, which reads the same thing for the graph
/// route. The two must not drift. Both leave out a module with no persisted
/// resolution scope: an inline module an item macro's expansion declares
/// outside the file's own lowering, whose body only a request-scoped capsule
/// lowers. No persisted reference is written in such a scope, so it is no
/// requester's module.
pub(super) const MODULES_FOR_BLOB: &str = "SELECT source.topology_id, source.container_path,
 source.blob_id, source.rel_path, scopes.resolution_scope, crates.edition,
 crates.target_kind='detached' AND EXISTS(SELECT 1 FROM rust_crate_topologies AS cargo
  WHERE cargo.target_kind<>'detached' AND +cargo.publication_state='complete')
 FROM rust_crate_container_sources AS source
 CROSS JOIN selected_rust_crates AS crates ON crates.topology_id=source.topology_id
 CROSS JOIN source_rust_module_scopes AS scopes ON scopes.blob_id=source.blob_id AND scopes.ordinal=source.scope_ordinal
 WHERE source.blob_id=?1 AND source.rel_path=?2 AND scopes.resolution_scope IS NOT NULL";

pub(super) struct RustCrateRows<'a, 'store, 'input> {
    pub(super) ready: &'a ReadySelectedResolution<'store, 'input>,
}

/// An export's site is owned by its selected blob and mount. Crate topology
/// supplies placement only; no site number is carried over from an old blob.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct RustCrateExport {
    pub(super) blob: i64,
    pub(super) declaration: RustCrateDeclaration,
    pub(super) topology: i64,
    pub(super) module_path: String,
    pub(super) mount: SelectedResolutionMountOrdinal,
}

/// The declaration one export names in its blob.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum RustCrateDeclaration {
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
/// - `inventories`: `rust_crate_point_inventory.sql` (a demand's open-inventory
///   gaps), keyed by the same target and requester parameters as exports; 76.8% of 221,505
///   executions repeated a key within the stage.
///
/// The rows these statements read (crate rows, the selection's mounts, crates
/// and placements, and persisted source facts) do not change while a stage
/// runs; the stage's own fact tables are separate and none of them reads
/// those.
///
/// Only a crate stage holds one: [`CrateStageMemos`] installs it when the
/// graph build starts a crate and drops it when the build moves to the next
/// crate. Outside a crate stage the lookups run the statements directly.
#[derive(Default)]
pub(super) struct CrateRowMemo {
    exports: HashMap<ExportKey, Vec<RustCrateExport>>,
    scopes: HashMap<(i64, u32), Vec<u32>>,
    inventories: HashMap<ExportKey, Vec<String>>,
}

/// Holds one crate stage's memos: the request's [`CrateRowMemo`], the
/// inventory's `CrateAccessMemo` and its `AuthorityValidations`, and the
/// stage's read transaction on the reader. Installed when the graph build
/// starts a crate and emptied when it drops, so no answer crosses into the
/// next crate and the reader leaves the stage outside any transaction.
pub(crate) struct CrateStageMemos<'a> {
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
        inventory.begin_stage_read()?;
        Ok(Self {
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

/// The traits one placed type declaration implements that are also nameable
/// where the reference is written, with the selected mount that declares each
/// trait.
///
/// This is lane TI's stage 2 reads 1, 1b and 4 in one statement, keyed by one
/// subject declaration identity per qualifier value. `rust_crate_trait_impls`
/// is seeked on the subject columns of `rust_crate_trait_impls_subject`,
/// and every trait name the join needs comes from `rust_crate_exports` through
/// `rust_crate_exports_declaration`; neither read enumerates a crate's impls or
/// a module's exports.
///
/// Both declarations are placed: the subject by its file `?5`, the trait by
/// the file the row names, which selects the trait's mount by path. A
/// declaration's `(blob, site)` is shared by every byte-identical file, so
/// without the placement `impl one::Runnable for Worker` would lend
/// `two::Runnable`'s members too, and a `use two::Runnable` would make it
/// nameable. A name row that is the trait's own declaration row is therefore
/// held to the trait's file through its container source. A re-export row
/// carries no placement of its own, so it is matched by `(blob, site)` alone.
///
/// The three visibility arms are Rust's three ways to name a trait at a call
/// site, and a trait that none of them reaches contributes nothing. That is the
/// whole of `ra_goto_def_ufcs_trait_method_scope_filtered` and
/// `rust_ufcs_trait_method_requires_visible_trait`: an implemented trait whose
/// name is not in scope does not lend its members to `Foo::member()`.
///
/// A named or glob import written inside a block (`fn f() { use m::T; }`)
/// names the trait only within that block (rustc E0599 outside it). Its
/// source row carries the block's byte extent, which must contain the
/// reference; an import at module scope has no extent. The reference and a
/// block import are compared in the same blob only.
///
/// `?1`/`?2`/`?5` are the subject declaration and its file, `?3`/`?4` the
/// module the reference is written in, and `?6`/`?7` the reference's mount
/// ordinal and semantic key.
pub(super) const TRAIT_IMPLS_VISIBLE_AT: &str =
    "SELECT DISTINCT names.declaration_blob_id, names.declaration_site, mount.mount_ordinal
 FROM rust_crate_trait_impls AS impls INDEXED BY rust_crate_trait_impls_subject
 CROSS JOIN rust_crate_exports AS names INDEXED BY rust_crate_exports_declaration
  ON names.declaration_blob_id=impls.trait_declaration_blob_id
  AND names.declaration_site=impls.trait_declaration_site AND names.namespace='type'
 CROSS JOIN selected_rust_crates AS naming ON naming.topology_id=names.topology_id
 CROSS JOIN temp.selected_resolution_mounts AS mount
  ON mount.storage_language='rust' AND mount.persisted_relative_path=impls.trait_rel_path
  AND mount.blob_id=names.declaration_blob_id
 WHERE impls.subject_declaration_blob_id=?1 AND impls.subject_declaration_site=?2
  AND impls.subject_rel_path=?5
  AND EXISTS(SELECT 1 FROM selected_rust_crates AS owner WHERE owner.topology_id=impls.topology_id)
  AND (names.origin<>'declaration'
   OR EXISTS(SELECT 1 FROM rust_crate_container_sources AS declared
             WHERE declared.topology_id=names.topology_id
               AND declared.container_path=names.module_path
               AND declared.blob_id=names.declaration_blob_id
               AND declared.rel_path=impls.trait_rel_path))
  AND ((names.topology_id=?3 AND names.module_path=?4)
   OR EXISTS(SELECT 1 FROM rust_crate_imports AS named INDEXED BY rust_crate_imports_target
             CROSS JOIN source_rust_import_targets AS placed
               ON placed.blob_id=named.blob_id AND placed.ordinal=named.import_ordinal
               AND placed.native_scope=named.binder_scope
             WHERE named.target_crate_key=naming.crate_key
               AND named.target_module_path=names.module_path
               AND named.target_name=names.name AND named.topology_id=?3
               AND named.module_path=?4 AND named.namespace='type'
               AND (placed.local_start IS NULL
                    OR EXISTS(SELECT 1 FROM temp.selected_resolution_mounts AS at
                              CROSS JOIN resolution_sites AS site
                                ON site.blob_id=at.blob_id AND site.site=?7
                              WHERE at.mount_ordinal=?6 AND at.blob_id=placed.blob_id
                                AND placed.local_start<=site.start_byte
                                AND site.start_byte<placed.local_end)))
       OR (names.visibility='public'
       AND EXISTS(SELECT 1 FROM rust_crate_glob_imports AS globs
                  CROSS JOIN source_rust_import_targets AS placed
                    ON placed.blob_id=globs.blob_id AND placed.ordinal=globs.import_ordinal
                    AND placed.native_scope=globs.binder_scope
                  WHERE globs.topology_id=?3 AND globs.module_path=?4
                    AND globs.target_crate_key=naming.crate_key
                    AND globs.target_module_path=names.module_path
                    AND (placed.local_start IS NULL
                         OR EXISTS(SELECT 1 FROM temp.selected_resolution_mounts AS at
                                   CROSS JOIN resolution_sites AS site
                                     ON site.blob_id=at.blob_id AND site.site=?7
                                   WHERE at.mount_ordinal=?6 AND at.blob_id=placed.blob_id
                                     AND placed.local_start<=site.start_byte
                                     AND site.start_byte<placed.local_end)))))";

/// The exact callable child one selected type's one selected trait impl
/// declares, if any. A trait method value written as `Type::method` can name
/// the concrete override just as a receiver call does. The deferred member
/// identity, subject and trait ends, and impl placement all have to match;
/// sibling types that implement the same trait never enter this result.
pub(super) const TRAIT_IMPL_MEMBER_AT: &str =
    "SELECT DISTINCT authority.source_site, member_mount.mount_ordinal
 FROM temp.selected_resolution_mounts AS member_mount
 CROSS JOIN resolution_rust_declaration_authorities AS authority
  ON authority.blob_id=member_mount.blob_id AND authority.semantic_key=?2
 CROSS JOIN source_rust_item_body_children AS child
  ON child.blob_id=authority.blob_id AND child.declaration_id=authority.declaration
 CROSS JOIN rust_crate_trait_impls AS impls INDEXED BY rust_crate_trait_impls_subject
  ON impls.impl_blob_id=child.blob_id
  AND impls.impl_declaration_id=child.owner_declaration_id
  AND impls.impl_rel_path=member_mount.persisted_relative_path
 WHERE member_mount.mount_ordinal=?1 AND impls.subject_declaration_blob_id=?3
  AND impls.subject_declaration_site=?4 AND impls.subject_rel_path=?5
  AND impls.trait_declaration_blob_id=?6 AND impls.trait_declaration_site=?7
  AND impls.trait_rel_path=?8
  AND child.syntax_kind='function_item'
  AND EXISTS(SELECT 1 FROM selected_rust_crates AS owner
             WHERE owner.topology_id=impls.topology_id)";

/// Visibility of one placed trait, including traits implemented for unindexed
/// external types. Parameters and block-import extents are as for
/// [`TRAIT_IMPLS_VISIBLE_AT`].
pub(super) const TRAIT_VISIBLE_AT: &str =
    "SELECT DISTINCT names.declaration_blob_id, names.declaration_site, mount.mount_ordinal
 FROM rust_crate_exports AS names INDEXED BY rust_crate_exports_declaration
 CROSS JOIN selected_rust_crates AS naming ON naming.topology_id=names.topology_id
 CROSS JOIN temp.selected_resolution_mounts AS mount
  ON mount.storage_language='rust' AND mount.persisted_relative_path=?5
  AND mount.blob_id=names.declaration_blob_id
 WHERE names.declaration_blob_id=?1 AND names.declaration_site=?2 AND names.namespace='type'
  AND (names.origin<>'declaration'
   OR EXISTS(SELECT 1 FROM rust_crate_container_sources AS declared
             WHERE declared.topology_id=names.topology_id
               AND declared.container_path=names.module_path
               AND declared.blob_id=names.declaration_blob_id
               AND declared.rel_path=?5))
  AND ((names.topology_id=?3 AND names.module_path=?4)
   OR EXISTS(SELECT 1 FROM rust_crate_imports AS named INDEXED BY rust_crate_imports_target
             CROSS JOIN source_rust_import_targets AS placed
               ON placed.blob_id=named.blob_id AND placed.ordinal=named.import_ordinal
               AND placed.native_scope=named.binder_scope
             WHERE named.target_crate_key=naming.crate_key
               AND named.target_module_path=names.module_path
               AND named.target_name=names.name AND named.topology_id=?3
               AND named.module_path=?4 AND named.namespace='type'
               AND (placed.local_start IS NULL
                    OR EXISTS(SELECT 1 FROM temp.selected_resolution_mounts AS at
                              CROSS JOIN resolution_sites AS site
                                ON site.blob_id=at.blob_id AND site.site=?7
                              WHERE at.mount_ordinal=?6 AND at.blob_id=placed.blob_id
                                AND placed.local_start<=site.start_byte
                                AND site.start_byte<placed.local_end)))
   OR (names.visibility='public'
       AND EXISTS(SELECT 1 FROM rust_crate_glob_imports AS globs
                  CROSS JOIN source_rust_import_targets AS placed
                    ON placed.blob_id=globs.blob_id AND placed.ordinal=globs.import_ordinal
                    AND placed.native_scope=globs.binder_scope
                  WHERE globs.topology_id=?3 AND globs.module_path=?4
                    AND globs.target_crate_key=naming.crate_key
                    AND globs.target_module_path=names.module_path
                    AND (placed.local_start IS NULL
                         OR EXISTS(SELECT 1 FROM temp.selected_resolution_mounts AS at
                                   CROSS JOIN resolution_sites AS site
                                     ON site.blob_id=at.blob_id AND site.site=?7
                                   WHERE at.mount_ordinal=?6 AND at.blob_id=placed.blob_id
                                     AND placed.local_start<=site.start_byte
                                     AND site.start_byte<placed.local_end)))))";

/// The crate modules one Rust reference is written in.
///
/// The reference's own context row names its module scope, and
/// `selected_rust_module_placements` places that scope in every selected crate
/// that places the file, aligning an edited file's scopes with the persisted
/// file's. `?1` is the reference's mount ordinal, `?2` its semantic key. No row
/// means the reference has no persisted context or its file is placed in no
/// selected crate.
pub(super) const REFERENCE_MODULE_PLACEMENTS: &str =
    "SELECT DISTINCT placement.topology_id, placement.container_path
 FROM temp.selected_resolution_mounts AS mount
 CROSS JOIN resolution_rust_reference_contexts AS context
  ON context.blob_id=mount.blob_id AND context.semantic_key=?2
 CROSS JOIN selected_rust_module_placements AS placement
  ON placement.mount_ordinal=mount.mount_ordinal
  AND placement.module_declaration IS context.module_declaration
 WHERE mount.mount_ordinal=?1";

/// The workspace crate a path head `?3` names in the module one Rust reference
/// is written in, when it names one: a workspace dependency's extern name, an
/// `extern crate dep as alias;` at the crate root (which puts the alias in the
/// extern prelude, as `rust_crate_point_dependency.sql` reads it), or a
/// module-level `use` that binds a workspace crate's root
/// (`use dep as alias;`, `use dep::{self as alias};`,
/// `extern crate dep as alias;`, persisted by `rust_crate_import_bindings.sql`
/// as the crate's `crate` module named `self`). `?1` is the reference's mount
/// ordinal, `?2` its semantic key, as for [`REFERENCE_MODULE_PLACEMENTS`].
pub(super) const REFERENCE_NAMES_WORKSPACE_CRATE: &str = "SELECT target.crate_name
 FROM temp.selected_resolution_mounts AS mount
 CROSS JOIN resolution_rust_reference_contexts AS context
  ON context.blob_id=mount.blob_id AND context.semantic_key=?2
 CROSS JOIN selected_rust_module_placements AS placement
  ON placement.mount_ordinal=mount.mount_ordinal
  AND placement.module_declaration IS context.module_declaration
 CROSS JOIN rust_crate_dependencies AS dependency
  ON dependency.topology_id=placement.topology_id AND dependency.extern_name=?3
  AND dependency.boundary='workspace'
 CROSS JOIN rust_crate_topologies AS target ON target.crate_key=dependency.dependency_crate_key
 WHERE mount.mount_ordinal=?1
 UNION
 SELECT target.crate_name
 FROM temp.selected_resolution_mounts AS mount
 CROSS JOIN resolution_rust_reference_contexts AS context
  ON context.blob_id=mount.blob_id AND context.semantic_key=?2
 CROSS JOIN selected_rust_module_placements AS placement
  ON placement.mount_ordinal=mount.mount_ordinal
  AND placement.module_declaration IS context.module_declaration
 CROSS JOIN rust_crate_container_sources AS root
  ON root.topology_id=placement.topology_id AND root.container_path='crate'
 CROSS JOIN source_rust_import_targets AS import
  ON import.blob_id=root.blob_id AND import.is_extern_crate=1 AND import.bound_name=?3
  AND import.local_start IS NULL AND COALESCE(import.owner_module,'')=''
 CROSS JOIN rust_crate_dependencies AS dependency
  ON dependency.topology_id=root.topology_id AND dependency.extern_name=import.imported_name
  AND dependency.boundary='workspace'
 CROSS JOIN rust_crate_topologies AS target ON target.crate_key=dependency.dependency_crate_key
 WHERE mount.mount_ordinal=?1
 UNION
 SELECT target.crate_name
 FROM temp.selected_resolution_mounts AS mount
 CROSS JOIN resolution_rust_reference_contexts AS context
  ON context.blob_id=mount.blob_id AND context.semantic_key=?2
 CROSS JOIN selected_rust_module_placements AS placement
  ON placement.mount_ordinal=mount.mount_ordinal
  AND placement.module_declaration IS context.module_declaration
 CROSS JOIN rust_crate_container_sources AS source
  ON source.topology_id=placement.topology_id AND source.container_path=placement.container_path
 CROSS JOIN source_rust_module_scopes AS scope
  ON scope.blob_id=source.blob_id AND scope.ordinal=source.scope_ordinal
 CROSS JOIN rust_crate_imports AS import
  ON import.topology_id=source.topology_id AND import.module_path=source.container_path
  AND import.blob_id=source.blob_id AND import.binder_scope=scope.resolution_scope
  AND import.namespace='type' AND import.bound_name=?3
  AND import.target_module_path='crate' AND import.target_name='self'
 CROSS JOIN rust_crate_topologies AS target ON target.crate_key=import.target_crate_key
 WHERE mount.mount_ordinal=?1
 ORDER BY 1 LIMIT 1";

/// Whether the module one Rust reference is written in has a crate-declared
/// module item (`rust_crate_macro_items`, `module_item`) named `?3`. `?1` is the
/// reference's mount ordinal, `?2` its semantic key, as for
/// [`REFERENCE_MODULE_PLACEMENTS`].
pub(super) const REFERENCE_NAMES_MACRO_MODULE: &str = "SELECT 1
 FROM temp.selected_resolution_mounts AS mount
 CROSS JOIN resolution_rust_reference_contexts AS context
  ON context.blob_id=mount.blob_id AND context.semantic_key=?2
 CROSS JOIN selected_rust_module_placements AS placement
  ON placement.mount_ordinal=mount.mount_ordinal
  AND placement.module_declaration IS context.module_declaration
 CROSS JOIN rust_crate_macro_items AS item
  ON item.topology_id=placement.topology_id AND item.module_path=placement.container_path
  AND item.namespace='type' AND item.name=?3 AND item.module_item=1
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
  EXISTS(SELECT 1 FROM rust_crate_container_sources AS placed
          INDEXED BY rust_crate_containers_blob
         CROSS JOIN selected_rust_crates AS crates ON crates.topology_id=placed.topology_id
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
                reference.1
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
                reference.1
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
pub(super) const IMPL_ITEM_TRAITS: &str = "SELECT DISTINCT impls.trait_declaration_site,
  trait_mount.mount_ordinal
 FROM temp.selected_resolution_mounts AS mount
 CROSS JOIN resolution_rust_declaration_authorities AS authority
  ON authority.blob_id=mount.blob_id AND authority.semantic_key=?2
 CROSS JOIN source_rust_item_body_children AS child
  ON child.blob_id=authority.blob_id AND +child.declaration_id=authority.declaration
 CROSS JOIN rust_crate_trait_impls AS impls INDEXED BY rust_crate_trait_impls_impl
  ON impls.impl_blob_id=child.blob_id AND impls.impl_declaration_id=child.owner_declaration_id
  AND impls.impl_rel_path=mount.persisted_relative_path
 CROSS JOIN temp.selected_resolution_mounts AS trait_mount
  ON trait_mount.storage_language='rust' AND trait_mount.persisted_relative_path=impls.trait_rel_path
  AND trait_mount.blob_id=impls.trait_declaration_blob_id
 WHERE mount.mount_ordinal=?1
  AND EXISTS(SELECT 1 FROM selected_rust_crates AS owner WHERE owner.topology_id=impls.topology_id)";

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
        .query_map(params![member.0.get(), member.1], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                SelectedResolutionMountOrdinal::new(row.get::<_, u32>(1)?),
            ))
        })?
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

/// Module segments plus the terminal item of one external type import. The
/// route is read from structured Rust import facts and the exact mounted
/// identity, never from its rendered spelling.
const EXTERNAL_TYPE_IMPORT_PATH: &str = "SELECT import.imported_name,
 segment.ordinal, segment.segment
 FROM temp.selected_resolution_mounts AS mount
 CROSS JOIN resolution_paths AS binding
  ON binding.blob_id=mount.blob_id AND binding.end_node=-1
  AND binding.start_node<>-1 AND binding.end_open_tail=1
  AND json_extract(binding.end_fixed_key,'$[#-2][0]')=?2
 CROSS JOIN resolution_identities AS identity ON identity.id=binding.root_terminal
 CROSS JOIN source_rust_import_targets AS import
  ON import.blob_id=mount.blob_id
  AND import.ordinal=json_extract(binding.end_fixed_key,'$[#-2][0]')
  AND import.is_glob=0
 LEFT JOIN source_rust_import_module_segments AS segment
  ON segment.blob_id=import.blob_id AND segment.import_ordinal=import.ordinal
 WHERE mount.mount_ordinal=?1 AND identity.namespace=?3
 ORDER BY segment.ordinal";

const EXTERNAL_TYPE_IMPORT_PATHS_FOR_BINDING: &str = "SELECT import.ordinal, import.imported_name,
 segment.segment
 FROM source_rust_import_targets AS import
 LEFT JOIN source_rust_import_module_segments AS segment
  ON segment.blob_id=import.blob_id AND segment.import_ordinal=import.ordinal
 WHERE import.blob_id=?1 AND import.native_scope=?2 AND import.bound_name=?3
  AND import.is_glob=0 AND import.imported_name IS NOT NULL
 ORDER BY import.ordinal, segment.ordinal";

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

pub(crate) fn external_type_import_path(
    selection: &SelectedResolutionMountInventory<'_>,
    boundary: (SelectedResolutionMountOrdinal, i64),
    cancellation: &CancellationToken,
) -> Result<Option<Vec<String>>> {
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    let mut path = Vec::new();
    let mut imported_name = None;
    for row in selection
        .connection()
        .prepare_cached(EXTERNAL_TYPE_IMPORT_PATH)?
        .query_map(
            params![
                boundary.0.get(),
                boundary.1,
                crate::analyzer::store::resolution_prepare::resolution_rows::namespace_code(
                    ResolutionNamespace::Type
                )
            ],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<u32>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )?
    {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let (name, ordinal, segment) = row?;
        if let Some(name) = name {
            if let Some(previous) = &imported_name {
                assert_eq!(previous, &name, "one import path has one terminal name");
            } else {
                imported_name = Some(name);
            }
        }
        assert_eq!(ordinal.is_some(), segment.is_some());
        if let Some(segment) = segment {
            path.push(segment);
        }
    }
    if let Some(name) = imported_name {
        path.push(name);
    }
    Ok(Some(path))
}

/// The source paths behind each named type import binding. This keeps cfg
/// alternatives separate so a caller can close a boundary only when every
/// selected route names the same itemless standard marker.
fn external_type_import_paths_for_binding(
    selection: &SelectedResolutionMountInventory<'_>,
    blob: i64,
    scope: u32,
    bound_name: &str,
    cancellation: &CancellationToken,
) -> Result<Option<Vec<Vec<String>>>> {
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    let mut paths = Vec::new();
    let mut current: Option<(u32, String, Vec<String>)> = None;
    for row in selection
        .connection()
        .prepare_cached(EXTERNAL_TYPE_IMPORT_PATHS_FOR_BINDING)?
        .query_map(params![blob, scope, bound_name], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })?
    {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let (ordinal, imported_name, segment) = row?;
        if current
            .as_ref()
            .is_some_and(|(previous, _, _)| *previous != ordinal)
        {
            let (_, name, mut segments) = current.take().expect("the previous import exists");
            segments.push(name);
            paths.push(segments);
        }
        let (_, name, segments) =
            current.get_or_insert_with(|| (ordinal, imported_name.clone(), Vec::new()));
        assert_eq!(
            name, &imported_name,
            "one import ordinal has one terminal name"
        );
        if let Some(segment) = segment {
            segments.push(segment);
        }
    }
    if let Some((_, name, mut segments)) = current {
        segments.push(name);
        paths.push(segments);
    }
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

    /// The crate modules one selected file is placed in.
    ///
    /// A file is a module of every topology whose container rows name it, so
    /// a lookup written in it asks each placement. Both Rust forward routes
    /// read this, which is why it lives beside the crate rows rather than in
    /// either one.
    pub(super) fn modules_for_mount(
        &self,
        mounts: SelectedMountTable<'_, '_>,
        ordinal: SelectedResolutionMountOrdinal,
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
        conn.prepare_cached(MODULES_FOR_BLOB)?
            .query_map(params![blob, mount.persisted_relative_path()], |row| {
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
                    overlay_completion: overlay_completion.clone(),
                })
            })?
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
                let selected = selected.as_array().expect("selected import tuple");
                let persisted = persisted.as_array().expect("persisted import tuple");
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
            // declaration coordinate is not: EXPORT reads selected authority,
            // including the actual name, visibility, activation and source site.
            if !conn.prepare_cached(EXPORT)?.exists(params![
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
                    token.local_key()
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
        definitions.sort_unstable();
        definitions.dedup();
        let typed = self.ready.typed_source();
        let mut scopes = Vec::new();
        let mut collect = |rows: &[SelectedTypedRow<LoweredMemberScopeProperty>]| {
            for row in rows {
                scopes.push((row.row().definition(), row.row().scope_head()));
            }
            Ok(!cancellation.is_cancelled())
        };
        let outcome = typed.visit_member_scope_pages_for_definitions(
            TypedFactRequest::new(&definitions),
            cancellation,
            &mut FactPageVisitor::new(&mut collect),
        )?;
        if outcome.is_cancelled() {
            return Ok(Vec::new());
        }
        scopes.sort_unstable();
        scopes.dedup();
        // Which of those traits actually declares the member the reference
        // asks for. The scope is the authority, so this asks the scope, with
        // the same endpoint the engine would follow the bridge with.
        //
        // The count is the point. Rust makes `Foo::frobnicate()` an error when
        // two traits in scope both declare `frobnicate`, so a second binding
        // trait is a proved negative and not a choice to make: the bridge is
        // what would invent one. `ra_goto_def_ufcs_trait_method_scope_filtered`
        // is the other half of the same rule -- there the second trait is not
        // nameable, so it never reaches this count.
        //
        // A single candidate is asked too. The bridge lands on the trait
        // body's scope head, and that node also carries the body's outward
        // lexical path, so a scope that declares no such member does not bind
        // nothing: the lookup continues into the module that encloses the
        // trait and binds whatever free item has the member's spelling.
        // `Spanned::START_FIELD` with one `impl Deserialize for Spanned`
        // answered the module's `const START_FIELD` that way, although Rust
        // names only associated items of `Spanned` and its traits there
        // (E0599 when none declares it). Only a trait whose own scope declares
        // the member may be bridged, whatever the count.
        let base = self.ready.lexical_source();
        let mut binding = Vec::new();
        for (definition, scope_head) in scopes {
            let request = BatchCandidateRequest::new(
                0,
                EndpointSignature::new(
                    scope_head,
                    StackPattern::closed([demand.semantic(&self.ready.shared_names())]),
                    StackPattern::closed([]),
                ),
            );
            let outcome =
                base.match_forward_candidates(std::slice::from_ref(&request), cancellation)?;
            if cancellation.is_cancelled() {
                return Ok(Vec::new());
            }
            // The match is coarse by contract: it buckets every path that
            // leaves this node, whatever symbol it carries. Hydrating decides
            // the symbol, which is the whole question here -- a trait that
            // declares some other member must not make the trait that declares
            // this one ambiguous.
            let candidates = outcome
                .matches()
                .iter()
                .map(|matched| matched.candidate())
                .collect::<Vec<_>>();
            let binds = base
                .hydrate_candidate_paths(&candidates, cancellation)?
                .into_iter()
                .any(|(_, path)| {
                    path.start().node() == scope_head
                        && path
                            .start()
                            .symbols()
                            .fixed()
                            .first()
                            .is_some_and(|symbol| {
                                symbol.symbol() == demand.semantic(&self.ready.shared_names())
                            })
                });
            if !binds {
                continue;
            }
            binding.push((definition, scope_head));
        }
        let [(definition, scope_head)] = binding.as_slice() else {
            return Ok(Vec::new());
        };
        let trait_fragment = *fragments
            .get(definition)
            .expect("a member scope answers the definition it was asked for");
        let impl_member = if matches!(
            demand.namespace(),
            ResolutionNamespace::Callable | ResolutionNamespace::Value
        ) {
            let (trait_blob, trait_site, trait_ordinal) = trait_declarations[definition];
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
            let mut impl_members = BTreeSet::new();
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
                        trait_path
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
                    impl_members.insert((
                        member_fragment,
                        mounted_site_node(member_fragment, ResolutionSiteId::new(site)),
                    ));
                }
            }
            let impl_members = impl_members.into_iter().collect::<Vec<_>>();
            if let [(fragment, definition)] = impl_members.as_slice() {
                Some((*definition, *fragment))
            } else {
                None
            }
        } else {
            None
        };
        let (target_fragment, target_definition) = impl_member
            .map(|(definition, fragment)| (fragment, Some(definition)))
            .unwrap_or((trait_fragment, None));
        let bridge = SelectedRootBridgeDescriptor::from_selected_path_tokens_with_prefix(
            source_fragment,
            Language::Rust,
            token,
            anchor,
            anchor_semantic,
            target_fragment,
            Language::Rust,
            *definition,
            prefix,
            Vec::new(),
            demand.clone(),
            demand.clone(),
            continuation.clone(),
        );
        let bridge = if let Some(target_definition) = target_definition {
            bridge.with_selected_member_definition(target_definition)
        } else {
            bridge.with_trait_member_scope(*scope_head)
        };
        Ok(vec![bridge])
    }

    pub(super) fn crate_inventory_completion(
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
                    .prepare_cached(OPEN_INVENTORY)?
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
        let mut completion = ResolutionCompletion::Complete;
        for detail in details {
            completion = completion.combine(&ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(inventory_reason(
                    &self.ready.context_identities,
                    &detail,
                )),
            ]));
        }
        Ok(completion)
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

    pub(super) fn crate_exports(
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
            .prepare_cached(EXPORT)?
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

    #[allow(clippy::too_many_arguments)]
    pub(super) fn crate_route(
        &self,
        requester: &Module,
        topology: i64,
        path: String,
        route: &[ResolutionLookupSemanticRecipe],
        anchor: ResolutionRootImportAnchor,
        completion: &mut ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> Result<Vec<(i64, String)>> {
        let conn = self.ready.inventory.connection();
        let absolute = anchor == ResolutionRootImportAnchor::Absolute;
        let path = if absolute && requester.edition == "2015" {
            "crate".to_owned()
        } else {
            path
        };
        // A route rooted at `crate`, `self` or `super` asks the requester's own
        // crate module tree for an answer. When that requester is a file this
        // workspace's Cargo targets leave out, the tree it asks is the
        // synthetic one the derivation gave the file, so a walk that dies in
        // it has not proved an absence: the build describes the file nowhere.
        // Naming that is the difference between "there is no such item" and
        // "this file is in no crate I could read", and a consumer cannot
        // recover it from a `Complete` answer with no targets.
        let unmounted_root = requester.unmounted
            && route
                .first()
                .is_some_and(|segment| matches!(segment.spelling(), "crate" | "self" | "super"));
        let mut current = vec![(topology, path)];
        for (position, segment) in route.iter().enumerate() {
            if cancellation.is_cancelled() {
                return Ok(Vec::new());
            }
            let mut next = Vec::new();
            for (topology, path) in current {
                let before = next.len();
                match segment.spelling() {
                    "crate" if position == 0 => next.push((topology, "crate".into())),
                    "self" => next.push((topology, path.clone())),
                    "super" => {
                        for row in conn
                            .prepare_cached(PARENT)?
                            .query_map(params![topology, path], |row| row.get::<_, String>(0))?
                        {
                            next.push((topology, row?));
                        }
                    }
                    name => {
                        if position == 0 {
                            for row in conn
                                .prepare_cached(DEPENDENCY)?
                                .query_map(params![topology, name], |row| row.get::<_, i64>(0))?
                            {
                                next.push((row?, "crate".into()));
                            }
                        }
                        if !(position == 0 && absolute && requester.edition != "2015") {
                            let before_exports = next.len();
                            for RustCrateExport {
                                blob,
                                declaration,
                                topology: export_topology,
                                module_path: export_module_path,
                                ..
                            } in self.crate_exports(requester, topology, &path, "type", name)?
                            {
                                let module = |row: &rusqlite::Row<'_>| -> rusqlite::Result<_> {
                                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                                };
                                match declaration {
                                    RustCrateDeclaration::Site(site) => {
                                        for row in
                                            conn.prepare_cached(DEFINITION_MODULE)?.query_map(
                                                params![
                                                    blob,
                                                    site,
                                                    export_topology,
                                                    export_module_path
                                                ],
                                                module,
                                            )?
                                        {
                                            next.push(row?);
                                        }
                                    }
                                    RustCrateDeclaration::MacroItem(declaration) => {
                                        for row in
                                            conn.prepare_cached(MACRO_ITEM_MODULE)?.query_map(
                                                params![
                                                    blob,
                                                    declaration,
                                                    export_topology,
                                                    export_module_path,
                                                    name
                                                ],
                                                module,
                                            )?
                                        {
                                            next.push(row?);
                                        }
                                    }
                                }
                            }
                            // A name this module re-exports as a crate's root,
                            // when no declared module of the name answered: a
                            // container beats a re-export of the same name.
                            if next.len() == before_exports {
                                for row in conn.prepare_cached(ROOT_REEXPORT)?.query_map(
                                    params![
                                        topology,
                                        path,
                                        "type",
                                        name,
                                        requester.topology,
                                        requester.path
                                    ],
                                    |row| row.get::<_, i64>(0),
                                )? {
                                    next.push((row?, "crate".into()));
                                }
                            }
                        }
                    }
                }
                if next.len() == before {
                    if unmounted_root {
                        *completion = completion.combine(&ResolutionCompletion::incomplete([
                            ResolutionIncompleteReason::UnmountedFile {
                                fragment: requester.fragment,
                            },
                        ]));
                    }
                    *completion = completion.combine(&self.crate_inventory_completion(
                        requester,
                        topology,
                        &path,
                        "type",
                        segment.spelling(),
                    )?);
                    for detail in conn
                        .prepare_cached(OPEN_ROUTE)?
                        .query_map(params![topology, path, segment.spelling()], |row| {
                            row.get::<_, String>(0)
                        })?
                    {
                        let detail = detail?;
                        *completion = completion.combine(&ResolutionCompletion::incomplete([
                            ResolutionIncompleteReason::UnsupportedSemantic(inventory_reason(
                                &self.ready.context_identities,
                                &detail,
                            )),
                        ]));
                    }
                }
            }
            next.sort_unstable();
            next.dedup();
            current = next;
        }
        Ok(current)
    }
}
