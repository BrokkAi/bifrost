//! Query-local selected placement and membership reads.
//! Placement SQL reads the shared TEMP placement relation through language side
//! attributes; placement identity stays separate from selected native facts.
use super::*;
use crate::analyzer::store::resolution_selection::SelectedResolutionMountInventory;
use rusqlite::params;

pub(super) type PlacementMemo<T> = HashMap<([u8; 32], i64, Option<u32>), Vec<T>>;
pub(super) type MembershipMemo<T> = HashMap<([u8; 32], i64), Vec<T>>;

/// Placement uses the certified predecessor identity. Native declaration facts
/// continue to use the selected fragment, including content and unsaved aliases.
fn placement_blob(
    selection: &SelectedResolutionMountInventory<'_>,
    base_blobs: &[(BindingFragmentId, i64)],
    fragment: BindingFragmentId,
) -> Result<Option<i64>> {
    if let Some((_, blob)) = base_blobs.iter().find(|(id, _)| *id == fragment) {
        return Ok(Some(*blob));
    }
    Ok(selection
        .mount_record_for_fragment(fragment)?
        .map(|mount| mount.blob_id()))
}

/// Memos belong to a single query/stage; callers own and clear them with that
/// stage. SQL and the decoder supply language-specific context side relations.
#[allow(clippy::too_many_arguments)]
pub(super) fn selected_placements<T: Clone>(
    selection: &SelectedResolutionMountInventory<'_>,
    unit_key: [u8; 32],
    base_blobs: &[(BindingFragmentId, i64)],
    fragment: BindingFragmentId,
    declaration: Option<SourceDeclarationId>,
    sql: &'static str,
    memo: Option<&mut PlacementMemo<T>>,
    mut decode: impl FnMut(&rusqlite::Row<'_>) -> Result<T>,
) -> Result<Vec<T>> {
    let Some(blob) = placement_blob(selection, base_blobs, fragment)? else {
        return Ok(Vec::new());
    };
    let key = (unit_key, blob, declaration.map(SourceDeclarationId::get));
    if let Some(rows) = memo.as_ref().and_then(|memo| memo.get(&key)) {
        return Ok(rows.clone());
    }
    let mut statement = selection.connection().prepare_cached(sql)?;
    let mut cursor = statement.query(params![unit_key.as_slice(), blob, key.2])?;
    let mut rows = Vec::new();
    while let Some(row) = cursor.next()? {
        rows.push(decode(row)?);
    }
    if let Some(memo) = memo {
        memo.insert(key, rows.clone());
    }
    Ok(rows)
}

pub(super) fn selected_memberships<T: Clone>(
    selection: &SelectedResolutionMountInventory<'_>,
    unit_key: [u8; 32],
    base_blobs: &[(BindingFragmentId, i64)],
    fragment: BindingFragmentId,
    sql: &'static str,
    memo: Option<&mut MembershipMemo<T>>,
    mut decode: impl FnMut(&rusqlite::Row<'_>) -> Result<T>,
) -> Result<Vec<T>> {
    let Some(blob) = placement_blob(selection, base_blobs, fragment)? else {
        return Ok(Vec::new());
    };
    let key = (unit_key, blob);
    if let Some(rows) = memo.as_ref().and_then(|memo| memo.get(&key)) {
        return Ok(rows.clone());
    }
    let mut statement = selection.connection().prepare_cached(sql)?;
    let mut cursor = statement.query(params![unit_key.as_slice(), blob])?;
    let mut rows = Vec::new();
    while let Some(row) = cursor.next()? {
        rows.push(decode(row)?);
    }
    if let Some(memo) = memo {
        memo.insert(key, rows.clone());
    }
    Ok(rows)
}
