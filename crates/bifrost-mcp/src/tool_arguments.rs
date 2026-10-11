use crate::analyzer::Language;
use crate::git_file::parse_rev_path;
use crate::git_file::{git_history_path_is_file, read_git_file, resolve_git_file_path};
use crate::mcp_common::contains_glob_syntax;
use crate::workspace_document::has_portable_windows_path_prefix;
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct GitHistoryOverlay {
    pub rel_path: PathBuf,
    pub content: String,
}

#[derive(Clone, Copy)]
enum ToolPathArgument {
    StringArray(&'static str),
    ObjectArrayString(&'static str, &'static str),
    OptionalString(&'static str),
    GetFileContents,
    QueryCodeScopes,
    WorkspaceFile(&'static str),
}

fn tool_path_arguments(tool_name: &str) -> &'static [ToolPathArgument] {
    use ToolPathArgument::{
        GetFileContents, ObjectArrayString, OptionalString, QueryCodeScopes, StringArray,
        WorkspaceFile,
    };

    const GET_SUMMARIES: &[ToolPathArgument] = &[StringArray("targets")];
    const LIST_SYMBOLS: &[ToolPathArgument] = &[StringArray("file_patterns")];
    const SCAN_USAGES_BY_REFERENCE: &[ToolPathArgument] = &[StringArray("paths")];
    const SCAN_USAGES_BY_LOCATION: &[ToolPathArgument] =
        &[StringArray("paths"), ObjectArrayString("targets", "path")];
    const USAGE_GRAPH: &[ToolPathArgument] = &[StringArray("paths")];
    const MOST_RELEVANT_FILES: &[ToolPathArgument] = &[StringArray("seed_file_paths")];
    const RENAME_SYMBOL: &[ToolPathArgument] = &[OptionalString("path")];
    const GET_FILE_CONTENTS: &[ToolPathArgument] = &[GetFileContents];
    const QUERY_CODE: &[ToolPathArgument] = &[QueryCodeScopes, WorkspaceFile("query_file")];
    const SEARCH_FILE_CONTENTS: &[ToolPathArgument] = &[OptionalString("file_path")];
    const COMPLEXITY_FILES: &[ToolPathArgument] = &[StringArray("file_paths")];

    match tool_name {
        "get_summaries" => GET_SUMMARIES,
        "list_symbols" => LIST_SYMBOLS,
        "scan_usages_by_reference" => SCAN_USAGES_BY_REFERENCE,
        "scan_usages_by_location" => SCAN_USAGES_BY_LOCATION,
        // `usage_graph` takes the same `paths` selector as the scan tools, so
        // it accepts the same absolute spellings inside the workspace (#3092).
        "usage_graph" => USAGE_GRAPH,
        "most_relevant_files" => MOST_RELEVANT_FILES,
        "rename_symbol" => RENAME_SYMBOL,
        "get_file_contents" => GET_FILE_CONTENTS,
        "query_code" => QUERY_CODE,
        "search_file_contents" => SEARCH_FILE_CONTENTS,
        "compute_cyclomatic_complexity"
        | "compute_cognitive_complexity"
        | "report_comment_density_for_files"
        | "report_exception_handling_smells"
        | "report_test_assertion_smells"
        | "report_structural_clone_smells"
        | "report_long_method_and_god_object_smells"
        | "report_dead_code_and_unused_abstraction_smells" => COMPLEXITY_FILES,
        _ => &[],
    }
}

pub fn normalize_tool_arguments(
    tool_name: &str,
    mut arguments: Value,
    workspace_root: &Path,
) -> Result<Value, String> {
    for path_argument in tool_path_arguments(tool_name) {
        match *path_argument {
            ToolPathArgument::StringArray(field) => {
                normalize_string_array_field(&mut arguments, field, workspace_root)?
            }
            ToolPathArgument::ObjectArrayString(array_field, string_field) => {
                normalize_object_array_string_field(
                    &mut arguments,
                    array_field,
                    string_field,
                    workspace_root,
                )?
            }
            ToolPathArgument::OptionalString(field) => {
                normalize_optional_string_field(&mut arguments, field, workspace_root)?
            }
            ToolPathArgument::GetFileContents => {
                normalize_get_file_contents_paths(&mut arguments, workspace_root)?
            }
            ToolPathArgument::QueryCodeScopes => {
                normalize_query_path_scopes(&mut arguments, workspace_root)?
            }
            ToolPathArgument::WorkspaceFile(field) => {
                normalize_workspace_file_field(&mut arguments, field, workspace_root)?
            }
        }
    }
    Ok(arguments)
}

/// The workspace files a location request names, after
/// [`normalize_tool_arguments`]. A request must observe the current content of
/// every file it names, so the service brings exactly these up to date before
/// answering when the watcher has not delivered their change yet.
pub fn tool_named_files(tool_name: &str, arguments: &Value) -> Vec<String> {
    let object_array_paths = |array_field: &str| {
        arguments
            .get(array_field)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|item| item.get("path").and_then(Value::as_str))
            .map(|path| path.trim().to_owned())
            .collect::<Vec<_>>()
    };
    match tool_name {
        "get_definitions_by_location" => object_array_paths("references"),
        "scan_usages_by_location" => object_array_paths("targets"),
        "rename_symbol" => arguments
            .get("path")
            .and_then(Value::as_str)
            .map(|path| vec![path.trim().to_owned()])
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

pub fn normalize_tool_arguments_for_cli(
    tool_name: &str,
    mut arguments: Value,
    workspace_root: &Path,
) -> Result<(Value, Vec<GitHistoryOverlay>), String> {
    let mut overlays = GitHistoryOverlays::default();
    for path_argument in tool_path_arguments(tool_name) {
        match *path_argument {
            ToolPathArgument::StringArray(field) => normalize_cli_string_array_field(
                &mut arguments,
                field,
                workspace_root,
                &mut overlays,
            )?,
            ToolPathArgument::ObjectArrayString(array_field, string_field) => {
                normalize_cli_object_array_string_field(
                    &mut arguments,
                    array_field,
                    string_field,
                    workspace_root,
                    &mut overlays,
                )?
            }
            ToolPathArgument::OptionalString(field) => normalize_cli_optional_string_field(
                &mut arguments,
                field,
                workspace_root,
                &mut overlays,
            )?,
            ToolPathArgument::QueryCodeScopes => normalize_cli_string_array_field(
                &mut arguments,
                "where",
                workspace_root,
                &mut overlays,
            )?,
            ToolPathArgument::GetFileContents | ToolPathArgument::WorkspaceFile(_) => {}
        }
    }
    match tool_name {
        "get_symbol_sources" => normalize_cli_symbol_source_field(
            &mut arguments,
            "symbols",
            workspace_root,
            &mut overlays,
        )?,
        "get_declarations_by_location" | "get_definitions_by_location" | "get_type_by_location" => {
            normalize_cli_object_array_string_field(
                &mut arguments,
                "references",
                "path",
                workspace_root,
                &mut overlays,
            )?
        }
        _ => {}
    }

    let arguments = normalize_tool_arguments(tool_name, arguments, workspace_root)?;
    Ok((arguments, overlays.into_vec()))
}

fn normalize_get_file_contents_paths(
    arguments: &mut Value,
    workspace_root: &Path,
) -> Result<(), String> {
    let Some(array) = arguments
        .get_mut("file_paths")
        .and_then(Value::as_array_mut)
    else {
        return Ok(());
    };

    for item in array {
        let Some(raw) = item.as_str() else {
            continue;
        };
        if let Some(normalized) = normalize_get_file_contents_path(raw, workspace_root)? {
            *item = Value::String(normalized);
        }
    }
    Ok(())
}

fn normalize_get_file_contents_path(
    raw: &str,
    workspace_root: &Path,
) -> Result<Option<String>, String> {
    let trimmed = raw.trim();
    let Some((rev, path)) = parse_rev_path(trimmed) else {
        return normalize_mcp_path_argument(raw, workspace_root);
    };

    let normalized_path = normalize_rev_path_part(path, workspace_root)?;
    Ok(Some(format!("{rev}:{normalized_path}")))
}

fn normalize_rev_path_part(path: &str, workspace_root: &Path) -> Result<String, String> {
    let trimmed = path.trim();
    if looks_like_absolute_path(trimmed) {
        match normalize_mcp_path_argument(trimmed, workspace_root) {
            Ok(Some(normalized)) => return Ok(normalized),
            Ok(None) => {}
            Err(_) => return Ok(slash_string(trimmed)),
        }
    }

    if let Some(rest) = trimmed.strip_prefix("~/") {
        return Ok(format!("~/{rest}"));
    }

    normalize_relative_path_preserving_escape(trimmed)
}

#[derive(Default)]
struct GitHistoryOverlays {
    by_rel_path: HashMap<PathBuf, (String, String)>,
}

impl GitHistoryOverlays {
    fn add(
        &mut self,
        raw: &str,
        rev: &str,
        rel_path: PathBuf,
        abs_path: PathBuf,
    ) -> Result<(), String> {
        if let Some((existing_rev, _)) = self.by_rel_path.get(&rel_path) {
            if existing_rev == rev {
                return Ok(());
            }
            return Err(format!(
                "cannot use multiple git revisions for `{}` in one --tool analyzer workspace: `{existing_rev}` and `{rev}`",
                path_to_slash_string(&rel_path)
            ));
        }
        let content = read_git_file(rev, &abs_path)
            .map_err(|err| format!("failed to read git history path `{raw}`: {err}"))?;
        self.by_rel_path
            .insert(rel_path, (rev.to_string(), content));
        Ok(())
    }

    fn into_vec(self) -> Vec<GitHistoryOverlay> {
        self.by_rel_path
            .into_iter()
            .map(|(rel_path, (_, content))| GitHistoryOverlay { rel_path, content })
            .collect()
    }
}

fn normalize_cli_string_array_field(
    arguments: &mut Value,
    field: &str,
    workspace_root: &Path,
    overlays: &mut GitHistoryOverlays,
) -> Result<(), String> {
    normalize_string_array_field_with(arguments, field, |raw| {
        normalize_cli_path_argument(raw, workspace_root, overlays)
    })
}

fn normalize_cli_symbol_source_field(
    arguments: &mut Value,
    field: &str,
    workspace_root: &Path,
    overlays: &mut GitHistoryOverlays,
) -> Result<(), String> {
    normalize_string_array_field_with(arguments, field, |raw| {
        normalize_cli_symbol_source_argument(raw, workspace_root, overlays)
    })
}

fn normalize_cli_symbol_source_argument(
    raw: &str,
    workspace_root: &Path,
    overlays: &mut GitHistoryOverlays,
) -> Result<Option<String>, String> {
    let trimmed = raw.trim();
    if let Some((rev, path)) = parse_rev_path(trimmed) {
        let (history_path, selector) = split_git_history_source_selector(rev, path, workspace_root);
        if !is_analyzable_source_path(rev) && is_analyzable_source_path(history_path) {
            let normalized = normalize_cli_revision_path_argument(
                raw,
                rev,
                history_path,
                workspace_root,
                overlays,
            )?;
            return Ok(Some(match selector {
                Some(selector) => format!("{normalized}#{selector}"),
                None => normalized,
            }));
        }
    }

    if !looks_like_absolute_path(trimmed) {
        return Ok(None);
    }

    // An absolute path inside the active workspace remains a supported file or
    // path-qualified symbol selector. Keep external absolute paths unchanged so
    // get_symbol_sources can return its syntax-specific relative-path recovery
    // guidance instead of failing CLI argument normalization first.
    match normalize_mcp_path_argument(raw, workspace_root) {
        Ok(normalized) => Ok(normalized),
        Err(_) => Ok(None),
    }
}

/// Splits a `REV:path#symbol` remainder into the historical file path and an
/// optional symbol selector. A committed filename can itself contain `#`
/// (e.g. `dir/Foo.VerifyGeneratedCode#01.verified.cs`), so a plain
/// `split_once('#')` can truncate the path mid-filename (#1216). This mirrors
/// the boundary rule that #1131 (commit c1053b7f) established for
/// working-tree `path#symbol` anchors in
/// `split_definition_selector_with_resolver` — prefer the `#`-position whose
/// left side names a real file — but resolves existence against the git tree
/// at `rev` (the historical file may not exist in the working tree at all)
/// and, per #1216's prefix-collision requirement, prefers the *longest*
/// resolvable path when more than one candidate exists: the unsplit path
/// (no selector) outranks every split, and among splits the rightmost `#`
/// (longest anchor) is tried before earlier ones.
///
/// When no candidate resolves against the historical tree (unknown revision,
/// non-git workspace, or a path that genuinely does not exist at `rev`), this
/// falls back to the original first-`#` split so behavior for those cases,
/// and for `r#`-raw-identifier selectors, is unchanged.
fn split_git_history_source_selector<'a>(
    rev: &str,
    path: &'a str,
    workspace_root: &Path,
) -> (&'a str, Option<&'a str>) {
    if !path.contains('#') {
        return (path, None);
    }

    if git_history_anchor_is_file(rev, path, workspace_root) {
        return (path, None);
    }

    for (index, _) in path.match_indices('#').rev() {
        let (anchor, rest) = path.split_at(index);
        let selector = &rest[1..];
        if !anchor.is_empty()
            && !selector.is_empty()
            && git_history_anchor_is_file(rev, anchor, workspace_root)
        {
            return (anchor, Some(selector));
        }
    }

    match path.split_once('#') {
        Some((path, selector)) if !path.is_empty() && !selector.is_empty() => {
            (path, Some(selector))
        }
        _ => (path, None),
    }
}

/// Structured (non-text-heuristic) check for whether `anchor` names a real
/// blob at `rev`: resolves `anchor` the same way [`normalize_cli_revision_path_argument`]
/// resolves the final historical path, then queries the repository's git
/// tree via [`git_history_path_is_file`].
fn git_history_anchor_is_file(rev: &str, anchor: &str, workspace_root: &Path) -> bool {
    let abs_path = resolve_git_file_path(anchor, workspace_root);
    git_history_path_is_file(rev, &abs_path)
}

fn is_analyzable_source_path(path: &str) -> bool {
    Language::from_path(Path::new(path)) != Language::None
}

fn normalize_cli_optional_string_field(
    arguments: &mut Value,
    field: &str,
    workspace_root: &Path,
    overlays: &mut GitHistoryOverlays,
) -> Result<(), String> {
    normalize_optional_string_field_with(arguments, field, |raw| {
        normalize_cli_path_argument(raw, workspace_root, overlays)
    })
}

fn normalize_optional_string_field_with(
    arguments: &mut Value,
    field: &str,
    mut normalize: impl FnMut(&str) -> Result<Option<String>, String>,
) -> Result<(), String> {
    let Some(value) = arguments.get_mut(field) else {
        return Ok(());
    };
    let Some(raw) = value.as_str() else {
        return Ok(());
    };
    if let Some(normalized) = normalize(raw)? {
        *value = Value::String(normalized);
    }
    Ok(())
}

fn normalize_cli_object_array_string_field(
    arguments: &mut Value,
    array_field: &str,
    string_field: &str,
    workspace_root: &Path,
    overlays: &mut GitHistoryOverlays,
) -> Result<(), String> {
    normalize_object_array_string_field_with(arguments, array_field, string_field, |item, field| {
        normalize_cli_optional_string_field(item, field, workspace_root, overlays)
    })
}

fn normalize_cli_path_argument(
    raw: &str,
    workspace_root: &Path,
    overlays: &mut GitHistoryOverlays,
) -> Result<Option<String>, String> {
    let trimmed = raw.trim();
    let Some((rev, path)) = parse_rev_path(trimmed) else {
        return normalize_mcp_path_argument(raw, workspace_root);
    };

    normalize_cli_revision_path_argument(raw, rev, path, workspace_root, overlays).map(Some)
}

fn normalize_cli_revision_path_argument(
    raw: &str,
    rev: &str,
    path: &str,
    workspace_root: &Path,
    overlays: &mut GitHistoryOverlays,
) -> Result<String, String> {
    let normalized_path = normalize_rev_path_part_inside_workspace(path, workspace_root)?;
    let rel_path = PathBuf::from(&normalized_path);
    let abs_path = resolve_git_file_path(&normalized_path, workspace_root);
    overlays.add(raw, rev, rel_path, abs_path)?;
    Ok(normalized_path)
}

fn normalize_rev_path_part_inside_workspace(
    path: &str,
    workspace_root: &Path,
) -> Result<String, String> {
    let trimmed = path.trim();
    if looks_like_absolute_path(trimmed) {
        return normalize_absolute_literal_path(trimmed, workspace_root);
    }

    if trimmed.starts_with("~/") {
        let abs_path = resolve_git_file_path(trimmed, workspace_root);
        return normalize_absolute_literal_path(&abs_path.display().to_string(), workspace_root);
    }

    normalize_relative_path_preserving_escape(trimmed)
}

fn normalize_string_array_field(
    arguments: &mut Value,
    field: &str,
    workspace_root: &Path,
) -> Result<(), String> {
    normalize_string_array_field_with(arguments, field, |raw| {
        normalize_mcp_path_argument(raw, workspace_root)
    })
}

fn normalize_query_path_scopes(arguments: &mut Value, workspace_root: &Path) -> Result<(), String> {
    let mut plans = vec![arguments];
    while let Some(plan) = plans.pop() {
        if let Some(scope) = plan.get_mut("where").and_then(Value::as_array_mut) {
            for entry in scope {
                let mut globs = match entry {
                    Value::Array(group) => group.iter_mut(),
                    value => std::slice::from_mut(value).iter_mut(),
                };
                for glob in &mut globs {
                    if let Some(raw) = glob.as_str()
                        && let Some(normalized) = normalize_mcp_path_argument(raw, workspace_root)?
                    {
                        *glob = Value::String(normalized);
                    }
                }
            }
        }
        if let Some(object) = plan.as_object_mut() {
            for (field, value) in object {
                if matches!(field.as_str(), "union" | "intersect" | "except")
                    && let Some(branches) = value.as_array_mut()
                {
                    plans.extend(branches);
                }
            }
        }
    }
    Ok(())
}

fn normalize_string_array_field_with(
    arguments: &mut Value,
    field: &str,
    mut normalize: impl FnMut(&str) -> Result<Option<String>, String>,
) -> Result<(), String> {
    let Some(array) = arguments.get_mut(field).and_then(Value::as_array_mut) else {
        return Ok(());
    };

    for item in array {
        let Some(raw) = item.as_str() else {
            continue;
        };
        if let Some(normalized) = normalize(raw)? {
            *item = Value::String(normalized);
        }
    }
    Ok(())
}

fn normalize_optional_string_field(
    arguments: &mut Value,
    field: &str,
    workspace_root: &Path,
) -> Result<(), String> {
    normalize_optional_string_field_with(arguments, field, |raw| {
        normalize_mcp_path_argument(raw, workspace_root)
    })
}

fn normalize_workspace_file_field(
    arguments: &mut Value,
    field: &str,
    workspace_root: &Path,
) -> Result<(), String> {
    let Some(value) = arguments.get_mut(field) else {
        return Ok(());
    };
    let Some(raw) = value.as_str() else {
        return Ok(());
    };
    *value = Value::String(normalize_workspace_file_path(raw, workspace_root)?);
    Ok(())
}

fn normalize_workspace_file_path(raw: &str, workspace_root: &Path) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("query file path must not be empty".to_string());
    }

    if looks_like_absolute_path(trimmed) {
        return normalize_absolute_path_lexically(trimmed, workspace_root);
    }

    normalize_relative_slash_path(&slash_string(trimmed))
        .map_err(|_| "query file path escapes active workspace".to_string())
}

fn normalize_object_array_string_field(
    arguments: &mut Value,
    array_field: &str,
    string_field: &str,
    workspace_root: &Path,
) -> Result<(), String> {
    normalize_object_array_string_field_with(arguments, array_field, string_field, |item, field| {
        normalize_optional_string_field(item, field, workspace_root)
    })
}

fn normalize_object_array_string_field_with(
    arguments: &mut Value,
    array_field: &str,
    string_field: &str,
    mut normalize: impl FnMut(&mut Value, &str) -> Result<(), String>,
) -> Result<(), String> {
    let Some(array) = arguments.get_mut(array_field).and_then(Value::as_array_mut) else {
        return Ok(());
    };

    for item in array {
        normalize(item, string_field)?;
    }
    Ok(())
}

fn normalize_mcp_path_argument(raw: &str, workspace_root: &Path) -> Result<Option<String>, String> {
    let trimmed = raw.trim();
    if !looks_like_absolute_path(trimmed) {
        return Ok(None);
    }

    if contains_glob_syntax(trimmed) {
        return normalize_absolute_path_lexically(trimmed, workspace_root).map(Some);
    }

    normalize_absolute_literal_path(trimmed, workspace_root).map(Some)
}

fn normalize_absolute_literal_path(raw: &str, workspace_root: &Path) -> Result<String, String> {
    let path = Path::new(raw);
    if let Ok(canonical_path) = path.canonicalize() {
        let canonical_root = workspace_root
            .canonicalize()
            .unwrap_or_else(|_| workspace_root.to_path_buf());
        return canonical_path
            .strip_prefix(&canonical_root)
            .map(path_to_slash_string)
            .map_err(|_| {
                crate::mcp_common::absolute_path_outside_workspace_error(raw, workspace_root)
            });
    }

    normalize_absolute_path_lexically(raw, workspace_root)
}

fn normalize_absolute_path_lexically(raw: &str, workspace_root: &Path) -> Result<String, String> {
    let raw_norm = slash_string(raw);
    let root_norm = slash_string(&workspace_root.display().to_string());
    let relative =
        crate::mcp_common::strip_workspace_root(&raw_norm, &root_norm).ok_or_else(|| {
            crate::mcp_common::absolute_path_outside_workspace_error(raw, workspace_root)
        })?;

    normalize_relative_slash_path(relative)
        .map_err(|_| crate::mcp_common::absolute_path_outside_workspace_error(raw, workspace_root))
}

fn normalize_relative_slash_path(relative: &str) -> Result<String, String> {
    let mut parts: Vec<&str> = Vec::new();
    for part in relative.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err("path escapes active workspace".to_string());
                }
            }
            _ => parts.push(part),
        }
    }
    Ok(parts.join("/"))
}

fn normalize_relative_path_preserving_escape(relative: &str) -> Result<String, String> {
    let path = Path::new(relative);
    if path.is_absolute() || path.has_root() {
        return Ok(slash_string(relative));
    }

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::Normal(part) => normalized.push(part),
            std::path::Component::ParentDir => {
                if !normalized.pop() {
                    return Err("path escapes active workspace".to_string());
                }
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return Ok(slash_string(relative));
            }
        }
    }
    Ok(path_to_slash_string(&normalized))
}

fn looks_like_absolute_path(raw: &str) -> bool {
    Path::new(raw).is_absolute() || has_portable_windows_path_prefix(raw)
}

fn path_to_slash_string(path: &Path) -> String {
    slash_separators(&path.to_string_lossy())
}

fn slash_string(path: &str) -> String {
    let path = if let Some(rest) = path.strip_prefix("\\\\?\\UNC\\") {
        format!("\\\\{rest}")
    } else if let Some(rest) = path.strip_prefix("\\\\?\\") {
        rest.to_string()
    } else {
        path.to_string()
    };
    slash_separators(&path)
}

fn slash_separators(path: &str) -> String {
    path.replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::{normalize_tool_arguments, normalize_tool_arguments_for_cli};
    use brokk_bifrost_test_macros::hardwon;
    use git2::{Repository, Signature};
    use serde_json::json;
    use std::fs;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    /// Stages and commits `paths` (already written under `repo`'s workdir),
    /// mirroring `tests/bifrost_tool_cli.rs`'s `commit_paths` helper so unit
    /// tests here can build small real git histories without process-spawning
    /// the CLI binary.
    fn commit_paths(repo: &Repository, paths: &[&str], message: &str) {
        let signature = Signature::now("Bifrost Test", "bifrost@example.com").expect("signature");
        crate::test_git_support::commit_paths(repo, paths, message, &signature);
    }

    fn rejected_outside_workspace_path(root: &Path, raw: &str) -> String {
        let error =
            normalize_tool_arguments("get_file_contents", json!({ "file_paths": [raw] }), root)
                .expect_err("outside path should fail");
        assert!(error.contains("outside active workspace"), "{error}");
        error
    }

    #[test]
    #[hardwon("8b0bd1e947cd: Windows absolute tool paths regressed during normalization")]
    fn normalizes_windows_absolute_literal_paths_for_tool_fields() {
        let root = Path::new("C:/work/root");

        let normalized = normalize_tool_arguments(
            "get_file_contents",
            json!({ "file_paths": ["C:/work/root/src/A.java"] }),
            root,
        )
        .expect("normalize");

        assert_eq!(normalized["file_paths"][0], "src/A.java");
    }

    #[test]
    #[hardwon("8b0bd1e947cd: Windows REV:path selectors were split at the drive colon")]
    fn normalizes_get_file_contents_windows_rev_path_part() {
        let root = Path::new("C:/work/root");

        let normalized = normalize_tool_arguments(
            "get_file_contents",
            json!({ "file_paths": ["HEAD:C:/work/root/src/relative.py"] }),
            root,
        )
        .expect("normalize");

        assert_eq!(normalized["file_paths"][0], "HEAD:src/relative.py");
    }

    #[test]
    fn normalizes_conjunctive_query_path_groups_without_flattening() {
        let root = TempDir::new().expect("temp dir");
        let absolute = root
            .path()
            .join("src")
            .join("**")
            .to_string_lossy()
            .to_string();
        let normalized = normalize_tool_arguments(
            "query_code",
            json!({"match": {"kind": "call"}, "where": [[absolute], ["**/*.py", "**/*.rb"]]}),
            root.path(),
        )
        .unwrap();
        assert_eq!(
            normalized["where"],
            json!([["src/**"], ["**/*.py", "**/*.rb"]])
        );
    }

    #[test]
    #[hardwon("1b28944cef98: CLI path normalization left source selectors outside tool recovery")]
    fn get_symbol_sources_cli_leaves_colon_selectors_for_tool_recovery() {
        let root = TempDir::new().expect("temp dir");
        let symbols = json!([
            "src/A.java:1-32",
            "src/A.java:A.method2",
            "src/A.java:A.rs",
            "void ns::helper(int value)"
        ]);

        let (normalized, overlays) = normalize_tool_arguments_for_cli(
            "get_symbol_sources",
            json!({ "symbols": symbols.clone() }),
            root.path(),
        )
        .expect("normalize");

        assert!(overlays.is_empty());
        assert_eq!(normalized["symbols"], symbols);
    }

    #[test]
    #[hardwon("1b28944cef98: CLI normalization mishandled in-workspace source selectors")]
    fn get_symbol_sources_cli_normalizes_only_in_workspace_absolute_paths() {
        let root = TempDir::new().expect("root dir");
        let source = root.path().join("src").join("A.java");
        fs::create_dir_all(source.parent().unwrap()).expect("src dir");
        fs::write(&source, "class A {}\n").expect("write source");

        let outside = TempDir::new().expect("outside dir");
        let external = outside.path().join("src").join("A.java");
        fs::create_dir_all(external.parent().unwrap()).expect("external src dir");
        fs::write(&external, "class A {}\n").expect("write external source");

        let (normalized, overlays) = normalize_tool_arguments_for_cli(
            "get_symbol_sources",
            json!({
                "symbols": [source.display().to_string(), external.display().to_string()]
            }),
            root.path(),
        )
        .expect("normalize");

        assert!(overlays.is_empty());
        assert_eq!(normalized["symbols"][0], "src/A.java");
        assert_eq!(normalized["symbols"][1], external.display().to_string());
    }

    #[test]
    fn normalizes_query_code_windows_absolute_where_globs_against_verbatim_root() {
        let root = Path::new(r"\\?\C:\work\root");

        let normalized = normalize_tool_arguments(
            "query_code",
            json!({
                "where": [r"C:\work\root\src\*.java"],
                "match": { "kind": "class" }
            }),
            root,
        )
        .expect("normalize");

        assert_eq!(normalized["where"][0], "src/*.java");
    }

    #[test]
    #[hardwon("8b0bd1e947cd: Windows absolute paths escaped the workspace boundary")]
    fn rejects_windows_absolute_paths_outside_workspace() {
        let root = Path::new("C:/work/root");
        let err = rejected_outside_workspace_path(root, "C:/work/outside/secret.txt");
        assert!(err.contains("C:/work/outside/secret.txt"), "{err}");
    }

    #[test]
    #[hardwon("8b0bd1e947cd: nonexistent Windows paths were not normalized beneath the workspace")]
    fn normalizes_nonexistent_windows_absolute_paths_inside_workspace() {
        let root = Path::new("C:/work/root");

        let normalized = normalize_tool_arguments(
            "get_file_contents",
            json!({ "file_paths": ["C:/work/root/src/Missing.java"] }),
            root,
        )
        .expect("normalize");

        assert_eq!(normalized["file_paths"][0], "src/Missing.java");
    }

    #[test]
    fn rejects_nonexistent_parent_dir_escapes() {
        let root = TempDir::new().expect("temp dir");
        let raw = format!("{}/../outside/Missing.java", root.path().display());

        rejected_outside_workspace_path(root.path(), &raw);
    }

    #[test]
    #[hardwon("8b0bd1e947cd: Windows parent-directory paths escaped the workspace boundary")]
    fn rejects_windows_absolute_parent_dir_escapes() {
        let root = Path::new("C:/work/root");

        rejected_outside_workspace_path(root, "C:/work/root/../outside/Missing.java");
    }

    // #1216 regression pin: an ordinary (no `#` in the filename) historical
    // `REV:path#symbol` selector must still split at its one `#` exactly as
    // before, with a single overlay for the historical path.
    #[test]
    #[hardwon(
        "eac69a1547ef: historical source selector parsing changed the ordinary REV:path#symbol form"
    )]
    fn git_history_symbol_source_ordinary_selector_splits_unchanged() {
        let root = TempDir::new().expect("temp dir");
        fs::write(root.path().join("Demo.java"), "class OldDemo {}\n").expect("write v1");
        let repo = Repository::init(root.path()).expect("init repo");
        commit_paths(&repo, &["Demo.java"], "v1");
        fs::write(root.path().join("Demo.java"), "class NewDemo {}\n").expect("write v2");
        commit_paths(&repo, &["Demo.java"], "v2");

        let (normalized, overlays) = normalize_tool_arguments_for_cli(
            "get_symbol_sources",
            json!({ "symbols": ["HEAD~1:Demo.java#OldDemo"] }),
            root.path(),
        )
        .expect("normalize");

        assert_eq!(normalized["symbols"][0], "Demo.java#OldDemo");
        assert_eq!(overlays.len(), 1, "{overlays:?}");
        assert_eq!(overlays[0].rel_path, PathBuf::from("Demo.java"));
        assert_eq!(overlays[0].content, "class OldDemo {}\n");
    }

    // #1216: a committed filename containing `#` with NO trailing symbol
    // selector (the bug's original repro shape, e.g.
    // `dir/Foo.VerifyGeneratedCode#01.verified.cs`) must keep the whole
    // filename as the historical path rather than truncating it at the `#`.
    // Before the fix, `split_once('#')` split this into path `Foo` (no
    // extension, so `is_analyzable_source_path` rejected it) and a bogus
    // selector `bar.py`, which made `normalize_cli_symbol_source_argument`
    // bail out with `Ok(None)` and leave the raw `HEAD:...` string
    // unnormalized with zero overlays.
    #[test]
    #[hardwon("eac69a1547ef: historical filenames containing # were split as symbol selectors")]
    fn git_history_symbol_source_hash_named_file_without_selector_keeps_full_path() {
        let root = TempDir::new().expect("temp dir");
        fs::write(
            root.path().join("Foo#bar.py"),
            "class Foo:\n    def value(self):\n        return 1\n",
        )
        .expect("write file");
        let repo = Repository::init(root.path()).expect("init repo");
        commit_paths(&repo, &["Foo#bar.py"], "v1");

        let (normalized, overlays) = normalize_tool_arguments_for_cli(
            "get_symbol_sources",
            json!({ "symbols": ["HEAD:Foo#bar.py"] }),
            root.path(),
        )
        .expect("normalize");

        assert_eq!(
            normalized["symbols"][0], "Foo#bar.py",
            "the full `#`-bearing filename must survive normalization unsplit"
        );
        assert_eq!(overlays.len(), 1, "{overlays:?}");
        assert_eq!(overlays[0].rel_path, PathBuf::from("Foo#bar.py"));
        assert_eq!(
            overlays[0].content,
            "class Foo:\n    def value(self):\n        return 1\n"
        );
    }

    // #1216 acceptance criterion: when both a short path and a longer
    // `#`-bearing path exist at the same revision (`Demo.py` and
    // `Demo.py#extra.py`), the longest resolvable historical path must win.
    // Before the fix, `split_once('#')` always took the *first* `#`, so the
    // overlay materialized for `Demo.py#extra.py#Bar` was the short, wrong
    // file (`Demo.py`) with a bogus `extra.py#Bar` selector tail.
    #[test]
    #[hardwon("eac69a1547ef: historical selector parsing chose a shorter colliding path")]
    fn git_history_symbol_source_prefix_collision_selects_longest_committed_path() {
        let root = TempDir::new().expect("temp dir");
        fs::write(
            root.path().join("Demo.py"),
            "class Foo:\n    def value(self):\n        return 1\n",
        )
        .expect("write short file");
        let repo = Repository::init(root.path()).expect("init repo");
        commit_paths(&repo, &["Demo.py"], "v1");
        fs::write(
            root.path().join("Demo.py#extra.py"),
            "class Bar:\n    def value(self):\n        return 2\n",
        )
        .expect("write long file");
        commit_paths(&repo, &["Demo.py#extra.py"], "v2");

        let (normalized, overlays) = normalize_tool_arguments_for_cli(
            "get_symbol_sources",
            json!({ "symbols": ["HEAD:Demo.py#extra.py#Bar"] }),
            root.path(),
        )
        .expect("normalize");

        assert_eq!(normalized["symbols"][0], "Demo.py#extra.py#Bar");
        assert_eq!(overlays.len(), 1, "{overlays:?}");
        assert_eq!(
            overlays[0].rel_path,
            PathBuf::from("Demo.py#extra.py"),
            "the longer, resolvable historical path must win the collision"
        );
        assert_eq!(
            overlays[0].content,
            "class Bar:\n    def value(self):\n        return 2\n"
        );
    }

    // #1216 regression pin: a historical selector whose symbol is itself a
    // Rust raw identifier (`r#type`) must keep splitting at the first `#`
    // (`lib.rs` / `r#type`), the same byte-for-byte behavior as before this
    // fix and as the working-tree case fixed by #1128/#1131.
    #[test]
    #[hardwon("eac69a1547ef: historical raw-identifier selectors must keep their delimiter")]
    fn git_history_symbol_source_raw_identifier_selector_unaffected() {
        let root = TempDir::new().expect("temp dir");
        fs::write(
            root.path().join("lib.rs"),
            "pub struct DbColumn {\n    pub r#type: String,\n}\n",
        )
        .expect("write file");
        let repo = Repository::init(root.path()).expect("init repo");
        commit_paths(&repo, &["lib.rs"], "v1");

        let (normalized, overlays) = normalize_tool_arguments_for_cli(
            "get_symbol_sources",
            json!({ "symbols": ["HEAD:lib.rs#r#type"] }),
            root.path(),
        )
        .expect("normalize");

        assert_eq!(normalized["symbols"][0], "lib.rs#r#type");
        assert_eq!(overlays.len(), 1, "{overlays:?}");
        assert_eq!(overlays[0].rel_path, PathBuf::from("lib.rs"));
        assert_eq!(
            overlays[0].content,
            "pub struct DbColumn {\n    pub r#type: String,\n}\n"
        );
    }

    #[test]
    fn normalizes_absolute_literal_paths_for_tool_fields() {
        let root = TempDir::new().expect("temp dir");
        let src = root.path().join("src");
        fs::create_dir(&src).expect("src dir");
        let file = src.join("A.java");
        fs::write(&file, "class A {}\n").expect("write file");

        let normalized = normalize_tool_arguments(
            "get_file_contents",
            json!({ "file_paths": [file.display().to_string()] }),
            root.path(),
        )
        .expect("normalize");

        assert_eq!(normalized["file_paths"][0], "src/A.java");
    }

    #[test]
    fn normalizes_get_file_contents_rev_path_part() {
        let root = TempDir::new().expect("temp dir");
        let src = root.path().join("src");
        fs::create_dir(&src).expect("src dir");
        let file = src.join("relative.py");
        fs::write(&file, "print('ok')\n").expect("write file");

        let normalized = normalize_tool_arguments(
            "get_file_contents",
            json!({ "file_paths": [format!("HEAD:{}", file.display())] }),
            root.path(),
        )
        .expect("normalize");

        assert_eq!(normalized["file_paths"][0], "HEAD:src/relative.py");
    }

    #[test]
    fn normalizes_absolute_globs_lexically() {
        let root = TempDir::new().expect("temp dir");
        let raw = format!("{}/src/**/*.rs", root.path().display());

        let normalized = normalize_tool_arguments(
            "list_symbols",
            json!({ "file_patterns": [raw] }),
            root.path(),
        )
        .expect("normalize");

        assert_eq!(normalized["file_patterns"][0], "src/**/*.rs");
    }

    #[test]
    fn normalizes_query_code_absolute_where_globs_for_cli() {
        let root = TempDir::new().expect("temp dir");
        let raw = format!("{}/src/**/*.py", root.path().display());

        let (normalized, overlays) = normalize_tool_arguments_for_cli(
            "query_code",
            json!({
                "where": [raw],
                "match": { "kind": "call" }
            }),
            root.path(),
        )
        .expect("normalize");

        assert!(overlays.is_empty());
        assert_eq!(normalized["where"][0], "src/**/*.py");
    }

    #[test]
    fn rejects_existing_absolute_paths_outside_workspace() {
        let root = TempDir::new().expect("root dir");
        let outside = TempDir::new().expect("outside dir");
        let file = outside.path().join("secret.txt");
        fs::write(&file, "secret").expect("write outside");

        let raw = file.display().to_string();
        let err = rejected_outside_workspace_path(root.path(), &raw);
        assert!(err.contains(&file.display().to_string()), "{err}");
    }

    #[test]
    fn leaves_non_path_fields_untouched() {
        let root = TempDir::new().expect("temp dir");
        let absolute_looking_symbol = format!("{}/src/A.java", root.path().display());

        let normalized = normalize_tool_arguments(
            "scan_usages_by_reference",
            json!({ "symbols": [absolute_looking_symbol] }),
            root.path(),
        )
        .expect("normalize");

        assert_eq!(normalized["symbols"][0], absolute_looking_symbol);
    }

    #[test]
    fn normalizes_scan_usages_paths_field() {
        let root = TempDir::new().expect("temp dir");
        let src = root.path().join("src");
        fs::create_dir(&src).expect("src dir");
        let file = src.join("lib.rs");
        fs::write(&file, "fn helper() {}\n").expect("write file");

        let normalized = normalize_tool_arguments(
            "scan_usages_by_reference",
            json!({
                "symbols": ["pkg.helper"],
                "paths": [file.display().to_string()]
            }),
            root.path(),
        )
        .expect("normalize");

        assert_eq!(normalized["paths"][0], "src/lib.rs");
    }

    #[test]
    fn normalizes_scan_usages_target_paths_field() {
        let root = TempDir::new().expect("temp dir");
        let src = root.path().join("src");
        fs::create_dir(&src).expect("src dir");
        let file = src.join("lib.rs");
        fs::write(&file, "fn helper() {}\n").expect("write file");

        let normalized = normalize_tool_arguments(
            "scan_usages_by_location",
            json!({
                "targets": [{
                    "path": file.display().to_string(),
                    "line": 1,
                    "column": 4
                }]
            }),
            root.path(),
        )
        .expect("normalize");

        assert_eq!(normalized["targets"][0]["path"], "src/lib.rs");
        assert_eq!(normalized["targets"][0]["line"], 1);
        assert_eq!(normalized["targets"][0]["column"], 4);
    }

    #[test]
    fn normalizes_only_path_fields_for_mixed_argument_tools() {
        let root = TempDir::new().expect("temp dir");
        let src = root.path().join("src");
        fs::create_dir(&src).expect("src dir");
        let file = src.join("lib.rs");
        fs::write(&file, "fn helper() {}\n").expect("write file");
        let fq_name = format!("{}/src/lib.rs", root.path().display());

        let normalized = normalize_tool_arguments(
            "report_dead_code_and_unused_abstraction_smells",
            json!({
                "file_paths": [file.display().to_string()],
                "fq_names": [fq_name]
            }),
            root.path(),
        )
        .expect("normalize");

        assert_eq!(normalized["file_paths"][0], "src/lib.rs");
        assert_eq!(normalized["fq_names"][0], fq_name);
    }
}
