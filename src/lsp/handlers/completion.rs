use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use lsp_types::{
    CompletionItem, CompletionItemKind, CompletionList, CompletionParams, CompletionResponse,
};

use crate::analyzer::{CodeUnit, CodeUnitType, WorkspaceAnalyzer};
use crate::lsp::conversion::position_to_byte_offset;
use crate::lsp::handlers::util::{identifier_prefix_before_offset, project_file_for_uri};
use crate::text_utils::compute_line_starts;

/// Soft cap on completion results. Matches `workspace_symbol`'s cap — most
/// editors paginate or filter client-side after a few hundred items, and
/// shipping more just delays the first paint. When the analyzer returns more
/// than this many candidates the response is marked `is_incomplete: true` so
/// well-behaved clients re-query as the prefix lengthens.
const MAX_RESULTS: usize = 500;

/// Minimum interval between stderr log emits for repeated read failures on
/// the same path. Completion fires per-keystroke; without throttling, a
/// pointed-at-unreadable-URI editor could flood the LSP host's log with
/// hundreds of identical lines per minute.
const READ_FAILURE_LOG_THROTTLE: Duration = Duration::from_secs(60);

/// Per-handler state for `textDocument/completion`. Owned by `ServerState`
/// (single-threaded request loop), invalidated by `didSave` /
/// `didChangeWatchedFiles`.
///
/// Caching the file content + line_starts avoids paying a full-file disk
/// read and UTF-8 line scan on every keystroke. Mtime-checked so external
/// edits (git checkout, formatter run) don't serve stale bytes.
///
/// Memory bound: unbounded today. An editor with thousands of files open
/// concurrently could grow this map without bound. Acceptable for v1 (no
/// reasonable LSP workflow keeps that many files open at once); revisit if
/// the cache shows up in heap profiles.
#[derive(Default)]
pub(crate) struct CompletionCache {
    files: HashMap<PathBuf, FileCacheEntry>,
    /// Last time we logged a read failure for a given path. Keyed by path
    /// (NOT URI) to coalesce log noise even when the editor sends slightly
    /// different URI forms for the same file.
    last_log_failure: HashMap<PathBuf, Instant>,
}

struct FileCacheEntry {
    mtime: SystemTime,
    content: String,
    line_starts: Vec<usize>,
}

impl CompletionCache {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Drop the cached entry (if any) for `path`. Called from `didSave` /
    /// `didChangeWatchedFiles` so the next completion request re-reads the
    /// new content.
    pub(crate) fn invalidate(&mut self, path: &Path) {
        self.files.remove(path);
    }
}

/// Resolve `textDocument/completion` for the identifier prefix immediately
/// before the cursor. Returns `None` (the LSP "no completions" shape) when:
/// - the URI is outside the project,
/// - the file can't be read,
/// - the cursor isn't sitting at the end of an identifier prefix.
///
/// v1 scope: simple identifier prefix only (`[A-Za-z0-9_]`). Qualified-name
/// completion past `.` / `::` is intentionally out of scope; clients fall back
/// to the editor's word-completion past those separators.
pub fn handle(
    cache: &mut CompletionCache,
    workspace: &WorkspaceAnalyzer,
    project_root: &Path,
    params: &CompletionParams,
) -> Option<CompletionResponse> {
    let uri = &params.text_document_position.text_document.uri;
    let project_file = project_file_for_uri(project_root, uri)?;
    let abs_path = project_file.abs_path();
    let entry = load_or_refresh(cache, &abs_path, uri)?;
    let byte_offset = position_to_byte_offset(
        &entry.content,
        &entry.line_starts,
        &params.text_document_position.position,
    );
    let prefix = identifier_prefix_before_offset(&entry.content, byte_offset)?;

    let analyzer = workspace.analyzer();
    // Cold-start fallback (mirrors `workspace_symbol::handle`): when the
    // in-memory analyzer state is empty (deferred build, rebuild in flight,
    // no analyzable files yet), hit the persisted FTS5 symbol index so
    // completion still responds sub-second on large repos.
    // `search_definitions_persisted` itself falls back to the in-memory regex
    // path when no storage is wired in or the trigram tokenizer can't index
    // the prefix (< 3 chars), so editors on the legacy code path see no
    // regression.
    //
    // Escape asymmetry between the branches is intentional:
    // - Hot path (`autocomplete_definitions`) interpolates `query` into a
    //   regex internally, so we `regex::escape` the prefix. Today this is a
    //   no-op (`is_ident_byte` constrains the prefix to ASCII alphanumeric +
    //   `_`, none of which are regex meta), but it's defence-in-depth against
    //   future widening (e.g. Unicode XID support).
    // - Cold path (`search_definitions_persisted`) treats the query as an
    //   FTS5 trigram phrase, not a regex. Escaping there would inject
    //   backslashes into the trigrams and break matches. The same ASCII
    //   identifier constraint guarantees no metacharacters reach this path
    //   either.
    let raw_matches: Vec<CodeUnit> = if analyzer.is_empty() {
        // The cold-start path doesn't filter synthetic units; we rely on the
        // post-search filter below to match the hot-path contract.
        analyzer
            .search_definitions_persisted(prefix)
            .into_iter()
            .collect()
    } else {
        let escaped = regex::escape(prefix);
        analyzer.autocomplete_definitions(&escaped)
    };

    // Filter BEFORE truncating + computing is_incomplete so the flag reflects
    // what the client actually receives. Otherwise we'd set is_incomplete=true
    // when truncation only dropped anonymous/synthetic units that the client
    // never sees, causing well-behaved clients to re-query for nothing.
    let filtered: Vec<CodeUnit> = raw_matches
        .into_iter()
        .filter(|cu| !cu.is_anonymous() && !cu.is_synthetic())
        .collect();
    let is_incomplete = filtered.len() > MAX_RESULTS;
    let items: Vec<CompletionItem> = filtered
        .into_iter()
        .take(MAX_RESULTS)
        .map(|cu| build_item(&cu))
        .collect();

    Some(CompletionResponse::List(CompletionList {
        is_incomplete,
        items,
    }))
}

/// Return a borrowed reference to the cache entry for `abs_path`, refreshing
/// it from disk when the mtime has changed (or there's no entry yet). The
/// fast path is mtime-only — for a hot file the cost is one `stat` call and
/// a `HashMap` lookup instead of a full file read + `compute_line_starts`.
///
/// Logs a single line to stderr on a stat or read failure, **throttled to one
/// emit per path per minute** (`READ_FAILURE_LOG_THROTTLE`). Returns `None`
/// on any I/O failure so the caller can send the LSP "no completions" shape.
fn load_or_refresh<'cache>(
    cache: &'cache mut CompletionCache,
    abs_path: &Path,
    uri: &lsp_types::Uri,
) -> Option<&'cache FileCacheEntry> {
    let metadata = match std::fs::metadata(abs_path) {
        Ok(m) => m,
        Err(err) => {
            maybe_log_failure(
                &mut cache.last_log_failure,
                abs_path,
                uri,
                &format_args!("stat failed: {err}").to_string(),
            );
            return None;
        }
    };
    let mtime = metadata.modified().ok()?;

    if let Some(existing) = cache.files.get(abs_path)
        && existing.mtime == mtime
    {
        return cache.files.get(abs_path);
    }

    let content = match std::fs::read_to_string(abs_path) {
        Ok(c) => c,
        Err(err) => {
            maybe_log_failure(
                &mut cache.last_log_failure,
                abs_path,
                uri,
                &format_args!("read failed: {err}").to_string(),
            );
            return None;
        }
    };
    let line_starts = compute_line_starts(&content);
    cache.files.insert(
        abs_path.to_path_buf(),
        FileCacheEntry {
            mtime,
            content,
            line_starts,
        },
    );
    cache.files.get(abs_path)
}

/// Emit a stderr line about an I/O failure on `abs_path`, but only if we
/// haven't logged for this path in the last `READ_FAILURE_LOG_THROTTLE`.
/// Logs the relative tail of `abs_path` rather than the full URI so that
/// PII-bearing absolute paths (e.g. `/Users/me/secrets/.aws/credentials`)
/// don't accumulate in LSP host logs that an editor may persist verbatim.
fn maybe_log_failure(
    last_log: &mut HashMap<PathBuf, Instant>,
    abs_path: &Path,
    uri: &lsp_types::Uri,
    detail: &str,
) {
    let now = Instant::now();
    let should_log = match last_log.get(abs_path) {
        Some(prev) => now.duration_since(*prev) >= READ_FAILURE_LOG_THROTTLE,
        None => true,
    };
    if !should_log {
        return;
    }
    last_log.insert(abs_path.to_path_buf(), now);
    let label = abs_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_else(|| uri.as_str());
    eprintln!("[bifrost-lsp] completion: {label}: {detail}");
}

fn build_item(code_unit: &CodeUnit) -> CompletionItem {
    CompletionItem {
        label: code_unit.identifier().to_string(),
        kind: Some(map_completion_kind(code_unit.kind())),
        detail: code_unit.signature().map(str::to_string),
        ..CompletionItem::default()
    }
}

fn map_completion_kind(kind: CodeUnitType) -> CompletionItemKind {
    match kind {
        CodeUnitType::Class => CompletionItemKind::CLASS,
        CodeUnitType::Function => CompletionItemKind::FUNCTION,
        CodeUnitType::Field => CompletionItemKind::FIELD,
        CodeUnitType::Module => CompletionItemKind::MODULE,
    }
}
