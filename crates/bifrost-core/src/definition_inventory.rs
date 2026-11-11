//! The blob-keyed writer of `workspace_file_versions.definition_inventory_state`.
//!
//! `definition_inventory_state` has exactly three writer functions. The first is
//! the owner publication, `replace_workspace_file_definition_inventory` in the
//! store crate. This module holds the other two: the readiness hook
//! [`reconcile_definition_inventory_for_blob_tx`] and the delete hook
//! [`withdraw_definition_inventory_for_deleted_blob_tx`]. They live in core
//! because the cache GC in `cache_gc` deletes blobs and cannot call the store;
//! every other caller is in the store crate.

use crate::gitblob::ParseVariant;
use rusqlite::{Transaction, params};

/// The blob row `blobs` is the variant the file version aliased `fv` selects:
/// its C# compilation decision when it has one, otherwise the empty variant.
#[macro_export]
#[doc(hidden)]
macro_rules! definition_inventory_selected_variant {
    () => {
        "blobs.parse_variant = COALESCE((SELECT decisions.decision_digest FROM main.csharp_file_version_decisions AS decisions
   WHERE decisions.file_version_id = fv.file_version_id), x'')"
    };
}

/// The blob half of the known predicate for the file version aliased `fv`: its
/// blob (the variant the file version selects) is complete, its parse is
/// complete, and source readiness is available, including the
/// signature-metadata pairing census. The blob must belong to the file
/// version's own generation.
#[macro_export]
#[doc(hidden)]
macro_rules! definition_inventory_blob_ready {
    () => {
        concat!(
            "EXISTS (SELECT 1 FROM main.blobs AS blobs
 JOIN main.blob_meta AS meta ON meta.blob_id = blobs.id
 LEFT JOIN main.blob_optional_fact_manifest AS pairing ON pairing.blob_id = blobs.id AND pairing.fact_kind = 6
 WHERE blobs.blob_oid = fv.blob_oid AND blobs.lang = fv.lang AND blobs.generation = fv.generation
 AND ",
            $crate::definition_inventory_selected_variant!(),
            "
 AND meta.is_complete = 1 AND meta.parse_completeness = 'complete'
 AND (SELECT available FROM main.source_fact_readiness WHERE blob_id = blobs.id) = 1
 AND (SELECT available FROM main.source_declaration_visibility_readiness WHERE blob_id = blobs.id) = 1
 AND (pairing.blob_id IS NULL OR pairing.row_count = meta.signature_metadata_count))"
        )
    };
}

/// Promotion half: blob-keyed, for file versions whose projection was
/// published before their blob (or its readiness) was.
pub const DEFINITION_INVENTORY_PROMOTE_BLOB_SQL: &str = concat!(
    "UPDATE main.workspace_file_versions AS fv
 SET definition_inventory_state = 'known'
 WHERE fv.blob_oid = ?1 AND fv.lang = ?2 AND fv.generation = ?3 AND fv.input_kind = 'source'
 AND fv.definition_inventory_state = 'blob_pending' AND ",
    definition_inventory_blob_ready!()
);

/// Demotion half: a republished, replaced or deleted blob that is no longer
/// ready cannot leave its file versions known.
pub const DEFINITION_INVENTORY_DEMOTE_BLOB_SQL: &str = concat!(
    "UPDATE main.workspace_file_versions AS fv
 SET definition_inventory_state = 'blob_pending'
 WHERE fv.blob_oid = ?1 AND fv.lang = ?2 AND fv.generation = ?3 AND fv.input_kind = 'source'
 AND fv.definition_inventory_state = 'known' AND NOT ",
    definition_inventory_blob_ready!()
);

/// Withdrawal half: a blob delete cascades away the name rows of every file
/// version that mounts it (`workspace_file_definition_name_rows` references
/// `blobs` and `code_units` with `ON DELETE CASCADE`). Whatever state such a
/// version had, its rows are gone, so it must stop being known in the same
/// transaction. NULL is already unknown and carries no rows. Readiness never
/// leaves `names_withdrawn`; only the publication owner's in-place refill does.
///
/// A blob row is keyed by its parse variant as well (two C# variants of one
/// oid share a generation), and a file version selects exactly one variant.
/// Only the versions that select the deleted row's variant lost their rows;
/// the others still mount a blob that was not touched. `?4` is the deleted
/// blob's `parse_variant`, matched against the same selected-variant
/// expression the readiness predicate uses.
pub const DEFINITION_INVENTORY_WITHDRAW_NAMES_SQL: &str = "UPDATE main.workspace_file_versions AS fv
 SET definition_inventory_state = 'names_withdrawn'
 WHERE fv.blob_oid = ?1 AND fv.lang = ?2 AND fv.generation = ?3 AND fv.input_kind = 'source'
 AND fv.definition_inventory_state IS NOT NULL AND fv.definition_inventory_state <> 'names_withdrawn'
 AND COALESCE((SELECT decisions.decision_digest FROM main.csharp_file_version_decisions AS decisions
   WHERE decisions.file_version_id = fv.file_version_id), x'') = ?4";

/// Writer 3: call it in the transaction that deletes a blob row, for each
/// generation the delete removed and with the deleted row's parse variant,
/// before anything republishes the blob. A
/// republication's readiness hook then finds no `blob_pending` or `known`
/// version to promote for this key.
pub fn withdraw_definition_inventory_for_deleted_blob_tx(
    tx: &Transaction<'_>,
    oid: &str,
    lang: &str,
    generation: i64,
    variant: ParseVariant,
) -> rusqlite::Result<()> {
    tx.prepare_cached(DEFINITION_INVENTORY_WITHDRAW_NAMES_SQL)?
        .execute(params![oid, lang, generation, variant])?;
    Ok(())
}

/// Writer 2: re-evaluates the known predicate for every file version that
/// mounts this blob. Call it inside the transaction that changes anything the
/// predicate reads, after the change: the publication of the blob's source
/// facts, the delete of its row (cache GC, stale-generation removal, resolution
/// repair), or a mutation of its completeness. It is needed because a file
/// version's projection and its blob are published by different transactions in
/// either order, and `known` may only be written in a transaction that proves
/// both halves, or one that finds the blob half no longer true.
pub fn reconcile_definition_inventory_for_blob_tx(
    tx: &Transaction<'_>,
    oid: &str,
    lang: &str,
    generation: i64,
) -> rusqlite::Result<()> {
    let key = params![oid, lang, generation];
    tx.prepare_cached(DEFINITION_INVENTORY_DEMOTE_BLOB_SQL)?
        .execute(key)?;
    tx.prepare_cached(DEFINITION_INVENTORY_PROMOTE_BLOB_SQL)?
        .execute(key)?;
    Ok(())
}
