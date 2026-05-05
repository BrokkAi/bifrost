//! Startup reconcile: partition the workspace against the persisted
//! baseline into `clean` (hydrate from disk), `dirty` (re-analyze), and
//! `deletes` (remove from baseline).
//!
//! This module is the only place that knows how the staleness key, payload
//! decoding, and epoch comparison combine into a reconcile decision. Both
//! the cold-start path (`build_state`) and the warm-update path
//! (`update`) build on top of these helpers.

use crate::analyzer::persistence::storage::{AnalyzerStorage, BaselineRow, WriteRow};
use crate::analyzer::persistence::{Result, decode, encode};
use crate::analyzer::tree_sitter_analyzer::FileState;
use crate::analyzer::{Language, ProjectFile};
use crate::hash::HashMap;
use std::collections::BTreeMap;

/// Result of partitioning a workspace's current files against the
/// persisted baseline.
pub(crate) struct ReconcilePlan {
    /// Files whose persisted row was still valid; payloads have been
    /// hydrated back into `FileState`.
    pub clean_hydrated: HashMap<ProjectFile, FileState>,
    /// Files that need to be reparsed (changed, new, or epoch mismatch).
    pub dirty_to_analyze: Vec<ProjectFile>,
    /// Baseline rows whose path is no longer in the workspace.
    pub deletes: Vec<String>,
}

/// Build a reconcile plan for `language` against `workspace_files`.
///
/// `epoch_now` is the current analysis epoch (computed by the caller from
/// its language adapter so this module stays decoupled from the
/// `LanguageAdapter` trait). Errors propagating from SQLite/IO/decode
/// short-circuit and surface to the caller, who decides whether to fall
/// back to a full rebuild.
pub(crate) fn plan(
    storage: &AnalyzerStorage,
    language: Language,
    epoch_now: &str,
    workspace_files: &[ProjectFile],
) -> Result<ReconcilePlan> {
    let baseline_epoch = storage.read_epoch(language)?;
    let epoch_matches = baseline_epoch.as_deref() == Some(epoch_now);

    let baseline = storage.read_baseline(language)?;

    let mut clean_hydrated: HashMap<ProjectFile, FileState> = HashMap::default();
    let mut dirty_to_analyze: Vec<ProjectFile> = Vec::new();
    let mut workspace_keys: BTreeMap<String, ()> = BTreeMap::new();

    for file in workspace_files {
        let key = rel_key(file);
        workspace_keys.insert(key.clone(), ());

        if !epoch_matches {
            dirty_to_analyze.push(file.clone());
            continue;
        }

        let Some(row) = baseline.get(&key) else {
            dirty_to_analyze.push(file.clone());
            continue;
        };

        let stat = match stat_for(file) {
            Some(stat) => stat,
            None => {
                dirty_to_analyze.push(file.clone());
                continue;
            }
        };

        if !staleness_matches(row, &stat) || row.epoch != epoch_now {
            dirty_to_analyze.push(file.clone());
            continue;
        }

        match decode(&row.payload, file) {
            Ok(state) => {
                clean_hydrated.insert(file.clone(), state);
            }
            Err(_) => dirty_to_analyze.push(file.clone()),
        }
    }

    let deletes: Vec<String> = baseline
        .keys()
        .filter(|k| !workspace_keys.contains_key(*k))
        .cloned()
        .collect();

    Ok(ReconcilePlan {
        clean_hydrated,
        dirty_to_analyze,
        deletes,
    })
}

/// Encode each `(file, state)` pair as a `WriteRow` for upsert. Files
/// that fail to stat or encode are silently skipped (they will be
/// re-analyzed on the next startup); a single bad file should not abort
/// the whole reconcile commit.
pub(crate) fn encode_writes<'a, I>(fresh_states: I) -> Vec<WriteRow>
where
    I: IntoIterator<Item = (&'a ProjectFile, &'a FileState)>,
{
    let iter = fresh_states.into_iter();
    let (lower, _) = iter.size_hint();
    let mut writes = Vec::with_capacity(lower);
    for (file, state) in iter {
        let Some(stat) = stat_for(file) else {
            continue;
        };
        let payload = match encode(state) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        writes.push(WriteRow {
            rel_path: rel_key(file),
            mtime_ns: stat.mtime_ns,
            size: stat.size,
            payload,
        });
    }
    writes
}

/// Apply the writes + deletes + epoch update in one transaction.
pub(crate) fn commit(
    storage: &AnalyzerStorage,
    language: Language,
    epoch_now: &str,
    writes: &[WriteRow],
    deletes: &[String],
) -> Result<()> {
    storage.commit_reconcile(language, epoch_now, writes, deletes)
}

#[derive(Debug, Clone, Copy)]
struct FileStat {
    mtime_ns: i64,
    size: i64,
}

fn stat_for(file: &ProjectFile) -> Option<FileStat> {
    let metadata = std::fs::metadata(file.abs_path()).ok()?;
    let mtime_ns = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| {
            // saturating cast; SystemTime can in principle exceed i64::MAX ns
            // but realistic mtimes won't.
            i64::try_from(d.as_nanos()).unwrap_or(i64::MAX)
        })
        .unwrap_or(0);
    let size = i64::try_from(metadata.len()).unwrap_or(i64::MAX);
    Some(FileStat { mtime_ns, size })
}

fn staleness_matches(row: &BaselineRow, stat: &FileStat) -> bool {
    row.mtime_ns == stat.mtime_ns && row.size == stat.size
}

/// Stable on-disk key for a project file: forward-slash-joined relative
/// path, regardless of host OS. Two analyzers run on different machines
/// against the same repo agree on this key.
pub(crate) fn rel_key(file: &ProjectFile) -> String {
    file.rel_path()
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect::<Vec<_>>()
        .join("/")
}
