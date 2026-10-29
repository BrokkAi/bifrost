//! Query-local selected placement and membership reads.
//! Placement SQL reads the shared TEMP placement relation through language side
//! attributes; placement identity stays separate from selected native facts.
use super::*;
use crate::analyzer::store::resolution_selection::SelectedResolutionMountInventory;
use rusqlite::types::Value;

/// The memo identity of a placement read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct PlacementKey {
    pub language: Language,
    /// Language-owned unit and authority coordinates; Rust binds its crate key.
    pub unit_digest: [u8; 32],
    pub subject: PlacementSubject,
    pub declaration: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct PlacementSubject {
    pub blob: Option<i64>,
    /// An operation-local index that is equal for two subjects of one language exactly
    /// when they name the same workspace path. The JVM uses the operation's path interner
    /// (jvm_source_paths). Python uses its mount ordinal, which
    /// UNIQUE(storage_language, persisted_relative_path) on temp.selected_resolution_mounts
    /// makes one per path. Indexes from different languages are not comparable.
    pub path: Option<usize>,
    pub file_version: Option<i64>,
}

/// Each read family owns a separate memo, dropped with its query or stage.
/// RequestReadCache's fixed cap bounds retention independently of workspace size.
/// Once full, misses keep reading SQL without inserting or evicting existing answers.
/// A Rust stage's keys are the distinct (blob, declaration) pairs it reads, so they
/// are bounded by the files of one crate's dependency closure; the cap sits far
/// above any real crate's stage (StoreError usages over bifrost-store/src peaked at 73).
pub(super) struct PlacementMemo<T> {
    rows: crate::analyzer::store::selected_read_memo::RequestReadCache<PlacementKey, Vec<T>>,
}

impl<T> Default for PlacementMemo<T> {
    fn default() -> Self {
        Self {
            rows: Default::default(),
        }
    }
}

/// Placement uses the certified predecessor identity. Native declaration facts
/// continue to use the selected fragment, including content and unsaved aliases.
pub(super) fn certified_predecessor_or_selected_mount(
    selection: &SelectedResolutionMountInventory<'_>,
    base_blobs: &[(BindingFragmentId, i64)],
    fragment: BindingFragmentId,
) -> Result<Option<PlacementSubject>> {
    let blob = if let Some((_, blob)) = base_blobs.iter().find(|(id, _)| *id == fragment) {
        Some(*blob)
    } else {
        selection
            .mount_record_for_fragment(fragment)?
            .map(|mount| mount.blob_id())
    };
    Ok(blob.map(|blob| PlacementSubject {
        blob: Some(blob),
        path: None,
        file_version: None,
    }))
}

pub(super) struct PlacementRead<B, F> {
    pub sql: &'static str,
    pub bind: B,
    pub decode: F,
}

/// The uncached placement read. SQL, binding and decoding belong to the language;
/// iteration preserves cursor order and multiplicity. Resolve the subject first.
pub(super) fn read_placement_rows<T>(
    selection: &SelectedResolutionMountInventory<'_>,
    sql: &'static str,
    params: impl rusqlite::Params,
    mut decode: impl FnMut(&rusqlite::Row<'_>) -> Result<T>,
) -> Result<Vec<T>> {
    let mut statement = selection.connection().prepare_cached(sql)?;
    let mut cursor = statement.query(params)?;
    let mut rows = Vec::new();
    while let Some(row) = cursor.next()? {
        rows.push(decode(row)?);
    }
    Ok(rows)
}

/// Adds a typed memo to the uncached read. PlacementKey is the memo identity;
/// language-owned binding supplies the SQL parameters on a memo miss.
pub(super) fn read_placements<T, B, F>(
    selection: &SelectedResolutionMountInventory<'_>,
    key: &PlacementKey,
    read: PlacementRead<B, F>,
    memo: Option<&mut PlacementMemo<T>>,
) -> Result<Vec<T>>
where
    T: Clone,
    B: Fn(&PlacementKey) -> Vec<Value>,
    F: FnMut(&rusqlite::Row<'_>) -> Result<T>,
{
    if let Some(rows) = memo.as_ref().and_then(|memo| memo.rows.get(key)) {
        return Ok(rows.clone());
    }
    let rows = read_placement_rows(
        selection,
        read.sql,
        rusqlite::params_from_iter((read.bind)(key)),
        read.decode,
    )?;
    if let Some(memo) = memo {
        memo.rows.insert(*key, rows.clone());
    }
    Ok(rows)
}
