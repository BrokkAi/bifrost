use std::path::Path;

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
    workspace: &WorkspaceAnalyzer,
    project_root: &Path,
    params: &CompletionParams,
) -> Option<CompletionResponse> {
    let uri = &params.text_document_position.text_document.uri;
    let project_file = project_file_for_uri(project_root, uri)?;
    let content = match project_file.read_to_string() {
        Ok(content) => content,
        Err(err) => {
            // Same shape as `project_file_for_uri`'s logging — surface a single
            // line so operators chasing "why doesn't completion work" can see
            // permission-denied / transient I/O failures instead of the
            // silently-empty completion list the client would otherwise show.
            eprintln!(
                "[bifrost-lsp] completion: failed to read {}: {err}",
                uri.as_str()
            );
            return None;
        }
    };
    let line_starts = compute_line_starts(&content);
    let byte_offset = position_to_byte_offset(
        &content,
        &line_starts,
        &params.text_document_position.position,
    );
    let prefix = identifier_prefix_before_offset(&content, byte_offset);
    if prefix.is_empty() {
        return None;
    }

    let analyzer = workspace.analyzer();
    // Same cold-start fallback as `workspace_symbol::handle`: when the
    // in-memory analyzer state is empty (deferred build, rebuild in flight,
    // no analyzable files yet), hit the persisted FTS5 symbol index so
    // completion still responds sub-second on large repos.
    // `search_definitions_persisted` itself falls back to the in-memory regex
    // path when no storage is wired in or the trigram tokenizer can't index
    // the prefix (< 3 chars), so editors on the legacy code path see no
    // regression.
    let raw_matches: Vec<CodeUnit> = if analyzer.is_empty() {
        // The cold-start path doesn't filter synthetic units; filter them
        // here to match the hot-path contract.
        analyzer
            .search_definitions_persisted(prefix)
            .into_iter()
            .collect()
    } else {
        // `autocomplete_definitions` interpolates `query` into a regex
        // internally. Escape the prefix so regex metacharacters can never
        // leak through — `is_ident_byte` keeps the prefix to ASCII
        // identifier bytes today, but escaping is cheap defence-in-depth
        // against future widening (e.g. Unicode XID support).
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
