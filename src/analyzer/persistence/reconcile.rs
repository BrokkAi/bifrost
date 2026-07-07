//! Startup reconcile: partition the workspace against the persisted
//! baseline into `clean` (hydrate from disk), `dirty` (re-analyze), and
//! `deletes` (remove from baseline).
//!
//! This module is the only place that knows how the staleness key, payload
//! decoding, and epoch comparison combine into a reconcile decision. Both
//! the cold-start path (`build_state`) and the warm-update path
//! (`update`) build on top of these helpers.

use crate::analyzer::persistence::storage::{AnalyzerStorage, BaselineRow, SymbolRow, WriteRow};
use crate::analyzer::persistence::{Result, decode, encode};
use crate::analyzer::tree_sitter_analyzer::FileState;
use crate::analyzer::{CodeUnitType, Language, ProjectFile};
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

/// Encode each `(file, state)` pair as a `WriteRow` for upsert, including
/// the symbol rows extracted from `state.declarations` and `state.ranges`.
/// `normalize_fq_name` mirrors `LanguageAdapter::normalize_full_name`, so
/// the persisted FQNs match the keys the in-memory `definitions` index
/// uses.
///
/// Files that fail to stat or encode are silently skipped (they will be
/// re-analyzed on the next startup); a single bad file should not abort
/// the whole reconcile commit.
pub(crate) fn encode_writes<'a, I, F>(fresh_states: I, normalize_fq_name: F) -> Vec<WriteRow>
where
    I: IntoIterator<Item = (&'a ProjectFile, &'a FileState)>,
    F: Fn(&str) -> String,
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
        let symbols = extract_symbols(state, &normalize_fq_name);
        writes.push(WriteRow {
            rel_path: rel_key(file),
            mtime_ns: stat.mtime_ns,
            size: stat.size,
            payload,
            symbols,
        });
    }
    writes
}

/// Project a `FileState` onto the flat `SymbolRow` shape stored by the
/// FTS5-backed symbol index. One row per `(declaration, range)` pair — a
/// declaration that occurs at multiple ranges (e.g. partial classes) gets
/// one row per range, sharing fq_name/short_name/kind.
fn extract_symbols<F>(state: &FileState, normalize_fq_name: F) -> Vec<SymbolRow>
where
    F: Fn(&str) -> String,
{
    let mut out = Vec::new();
    for declaration in &state.declarations {
        let Some(ranges) = state.ranges.get(declaration) else {
            continue;
        };
        if ranges.is_empty() {
            continue;
        }
        let fq_name = normalize_fq_name(&declaration.fq_name());
        let short_name = declaration.short_name().to_string();
        let package_name = declaration.package_name().to_string();
        let kind = code_unit_kind_str(declaration.kind()).to_string();
        let signature = declaration.signature().map(|s| s.to_string());
        let synthetic = declaration.is_synthetic();
        for range in ranges {
            // No real source file ever exceeds i64 byte/line offsets;
            // a violation here means the range got corrupted upstream
            // (e.g. a saturating cast back to usize::MAX).
            debug_assert!(
                range.start_byte as u64 <= i64::MAX as u64
                    && range.end_byte as u64 <= i64::MAX as u64
                    && range.start_line as u64 <= i64::MAX as u64
                    && range.end_line as u64 <= i64::MAX as u64,
                "range offsets overflow i64: {range:?}",
            );
            out.push(SymbolRow {
                fq_name: fq_name.clone(),
                short_name: short_name.clone(),
                package_name: package_name.clone(),
                kind: kind.clone(),
                signature: signature.clone(),
                synthetic,
                start_byte: i64::try_from(range.start_byte).unwrap_or(i64::MAX),
                end_byte: i64::try_from(range.end_byte).unwrap_or(i64::MAX),
                start_line: i64::try_from(range.start_line).unwrap_or(i64::MAX),
                end_line: i64::try_from(range.end_line).unwrap_or(i64::MAX),
            });
        }
    }
    out
}

/// Stable on-disk encoding for `CodeUnitType`. Kept intentionally trivial
/// so a row written by an older build is still readable.
pub(crate) fn code_unit_kind_str(kind: CodeUnitType) -> &'static str {
    match kind {
        CodeUnitType::Class => "Class",
        CodeUnitType::Function => "Function",
        CodeUnitType::Method => "Method",
        CodeUnitType::Field => "Field",
        CodeUnitType::Module => "Module",
        CodeUnitType::Macro => "Macro",
        CodeUnitType::FileScope => "FileScope",
    }
}

/// Inverse of `code_unit_kind_str`. Unknown strings round-trip to `None`,
/// letting callers skip rows written by a future build.
pub(crate) fn parse_kind(s: &str) -> Option<CodeUnitType> {
    Some(match s {
        "Class" => CodeUnitType::Class,
        "Function" => CodeUnitType::Function,
        "Method" => CodeUnitType::Method,
        "Field" => CodeUnitType::Field,
        "Module" => CodeUnitType::Module,
        "Macro" => CodeUnitType::Macro,
        "FileScope" => CodeUnitType::FileScope,
        _ => return None,
    })
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
