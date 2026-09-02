//! Scoped MCP sessions: a service over an explicitly named subset of a
//! workspace's files, optionally read at a git revision.
//!
//! Every service built here takes the ephemeral analyzer deliberately, which is
//! why the footgun name appears four times below. A scoped session sees a
//! partial file set, and a partial view must not become the workspace's
//! persisted picture of itself: the files it never listed would read as absent
//! to the next consumer of that cache.
//!
//! Callers see the partial view for what it is because the `FileSetProject`
//! every branch below builds answers `Project::coverage()` with its own file
//! count. Each cross-file tool answer publishes that count as an optional
//! `session_subset` field (`scope.session_subset` on `scan_usages`, top level
//! on `usage_graph`, `most_relevant_files`, `search_symbols`, `query_code`, and
//! `get_active_workspace`), so "nothing found" from one of these sessions reads
//! as "nothing in these N files" rather than "nothing in the workspace". A
//! whole-workspace session omits the field entirely.

use crate::analyzer::{
    AnalyzerConfig, FileSetProject, OverlayProject, Project, SourceIngestionKind,
    ingest_source_bytes,
};
use crate::git_file::{list_git_files_at_revision, read_git_file_bytes};
use crate::tool_arguments::GitHistoryOverlay;
use crate::{SearchToolsService, collect_workspace_files};
use glob::Pattern;
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

pub fn create_scoped_service(
    root: PathBuf,
    sources: &[String],
    revision: Option<&str>,
) -> Result<SearchToolsService, String> {
    let root = root
        .canonicalize()
        .map_err(|err| format!("Failed to resolve project root {}: {err}", root.display()))?;
    let Some(revision) = revision.map(str::trim).filter(|rev| !rev.is_empty()) else {
        let rel_paths = resolve_sources(&root, sources)?;
        let project = Arc::new(FileSetProject::new(root, rel_paths));
        // Ephemeral on purpose: partial file set, see the module doc.
        return SearchToolsService::new_manual_ephemeral_footgun_for_project(
            project,
            AnalyzerConfig::default(),
        );
    };
    let rel_paths = resolve_sources_at_revision(&root, sources, revision)?;
    let mut admitted = Vec::with_capacity(rel_paths.len());
    for rel_path in rel_paths {
        let abs_path = root.join(&rel_path);
        let blob = read_git_file_bytes(revision, &abs_path).map_err(|err| {
            format!(
                "failed to read scoped source `{}` at git revision `{revision}`: {err}",
                rel_path.to_string_lossy().replace('\\', "/")
            )
        })?;
        match ingest_source_bytes(&rel_path, blob.as_bytes()) {
            Ok(source) => {
                if source.kind() == SourceIngestionKind::Projected {
                    eprintln!(
                        "[bifrost] using an offset-preserving source projection for `{}` at `{revision}`",
                        rel_path.to_string_lossy().replace('\\', "/")
                    );
                }
                admitted.push((rel_path, source.into_string()));
            }
            Err(error) if blob.is_binary() => {
                eprintln!(
                    "[bifrost] skipping binary-bearing scoped source `{}` at `{revision}`: {error}",
                    rel_path.to_string_lossy().replace('\\', "/")
                );
            }
            Err(error) => {
                return Err(format!(
                    "failed to ingest scoped source `{}` at git revision `{revision}`: {error}",
                    rel_path.to_string_lossy().replace('\\', "/")
                ));
            }
        }
    }
    // Construct the file set only after admission. If a rejected path remained
    // in the delegate, OverlayProject would fall through to the live checkout.
    let project = Arc::new(FileSetProject::new(
        root.clone(),
        admitted.iter().map(|(path, _)| path.clone()),
    ));
    let overlay_project = Arc::new(OverlayProject::new(project));
    for (rel_path, content) in admitted {
        let abs_path = root.join(&rel_path);
        if !overlay_project.set(abs_path.clone(), content) {
            return Err(format!(
                "git history path `{}` is too large for the analyzer overlay",
                abs_path.display()
            ));
        }
    }
    let project: Arc<dyn Project> = overlay_project;
    // Ephemeral on purpose: partial file set, see the module doc.
    SearchToolsService::new_manual_ephemeral_footgun_for_project(project, AnalyzerConfig::default())
}

pub fn create_cli_tool_service(
    root: PathBuf,
    tool_name: &str,
    sources: &[String],
    overlays: Vec<GitHistoryOverlay>,
) -> Result<SearchToolsService, String> {
    let root = root
        .canonicalize()
        .map_err(|err| format!("Failed to resolve project root {}: {err}", root.display()))?;
    // A workspace-independent tool (`analyze_diff`, `blast_radius`) never reads
    // the live workspace or semantic index; it builds its own per-endpoint
    // analyzers over revision images. Serve it from a lazy service so the
    // one-shot CLI does not boot a whole-repo analyzer it will never touch,
    // which otherwise dwarfs the analysis itself on a large repo. An immutable
    // endpoint's own build does share the repository's content-addressed cache,
    // so what this avoids is the whole-repo parse, not every write. `--sources`
    // and git-history overlays do not apply to such tools, so they are
    // irrelevant here.
    if SearchToolsService::tool_is_workspace_independent(tool_name) {
        return SearchToolsService::new_one_shot_workspace_independent(root);
    }
    if overlays.is_empty() && sources.is_empty() {
        // A one-shot `--tool` call over the whole root. Every other branch here
        // already builds a manual, watcher-free service; this one used to
        // install a whole-tree watcher the process exits without ever polling.
        return SearchToolsService::new_one_shot(root);
    }
    if overlays.is_empty() {
        let rel_paths = resolve_sources(&root, sources)?;
        let project = Arc::new(FileSetProject::new(root, rel_paths));
        // Ephemeral on purpose: partial file set, see the module doc.
        return SearchToolsService::new_manual_ephemeral_footgun_for_project(
            project,
            AnalyzerConfig::default(),
        );
    }

    let mut rel_paths: BTreeSet<PathBuf> = if sources.is_empty() {
        collect_workspace_files(&root)
            .map_err(|err| {
                format!(
                    "Failed to enumerate workspace files under {}: {err}",
                    root.display()
                )
            })?
            .into_iter()
            .map(|file| file.rel_path().to_path_buf())
            .collect()
    } else {
        resolve_sources(&root, sources)?.into_iter().collect()
    };
    for overlay in &overlays {
        rel_paths.insert(overlay.rel_path.clone());
    }
    let project = Arc::new(FileSetProject::new(root.clone(), rel_paths));
    let overlay_project = Arc::new(OverlayProject::new(project));
    install_git_history_overlays(&root, &overlay_project, overlays)?;
    let project: Arc<dyn Project> = overlay_project;
    // Ephemeral on purpose: partial file set, see the module doc.
    SearchToolsService::new_manual_ephemeral_footgun_for_project(project, AnalyzerConfig::default())
}

pub fn resolve_sources(root: &Path, inputs: &[String]) -> Result<Vec<PathBuf>, String> {
    let workspace_files = collect_workspace_files(root).map_err(|err| {
        format!(
            "Failed to enumerate workspace files under {}: {err}",
            root.display()
        )
    })?;
    let workspace_rel_paths: Vec<String> = workspace_files
        .iter()
        .map(|file| file.rel_path().to_string_lossy().replace('\\', "/"))
        .collect();

    let mut selected = BTreeSet::new();
    for input in inputs {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            continue;
        }

        let rel = normalize_literal_source_path(trimmed, root)?;
        let abs = root.join(&rel);
        if abs.is_file() {
            selected.insert(rel);
            continue;
        }
        if abs.is_dir() {
            let prefix = rel.to_string_lossy().replace('\\', "/");
            let prefix_slash = format!("{prefix}/");
            let mut matched_any = false;
            for workspace_rel in &workspace_rel_paths {
                if workspace_rel == &prefix || workspace_rel.starts_with(&prefix_slash) {
                    matched_any = true;
                    selected.insert(PathBuf::from(workspace_rel));
                }
            }
            if !matched_any {
                return Err(format!(
                    "source directory `{trimmed}` contains no analyzer-visible files"
                ));
            }
            continue;
        }

        if contains_glob_syntax(trimmed) {
            let pattern = normalize_source_pattern(trimmed, root)?;
            let glob = Pattern::new(&pattern)
                .map_err(|err| format!("Invalid source glob `{trimmed}`: {err}"))?;
            let mut matched_any = false;
            for rel in &workspace_rel_paths {
                if glob.matches(rel) {
                    matched_any = true;
                    selected.insert(PathBuf::from(rel));
                }
            }
            if !matched_any {
                return Err(format!("source glob `{trimmed}` matched no files"));
            }
            continue;
        }

        return Err(format!("source path does not exist: {trimmed}"));
    }

    if selected.is_empty() {
        return Err(
            "sources resolved to an empty workspace (no non-empty source paths were provided)"
                .to_string(),
        );
    }
    Ok(selected.into_iter().collect())
}

fn resolve_sources_at_revision(
    root: &Path,
    inputs: &[String],
    revision: &str,
) -> Result<Vec<PathBuf>, String> {
    let revision_rel_paths: Vec<String> = list_git_files_at_revision(root, revision)?
        .into_iter()
        .map(|rel| rel.to_string_lossy().replace('\\', "/"))
        .collect();

    resolve_sources_from_rel_paths(root, inputs, revision, &revision_rel_paths)
}

fn resolve_sources_from_rel_paths(
    root: &Path,
    inputs: &[String],
    revision: &str,
    workspace_rel_paths: &[String],
) -> Result<Vec<PathBuf>, String> {
    let workspace_rel_set: BTreeSet<&str> =
        workspace_rel_paths.iter().map(String::as_str).collect();
    let mut selected = BTreeSet::new();
    for input in inputs {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            continue;
        }

        let rel = normalize_literal_source_path(trimmed, root)?;
        let rel_string = rel.to_string_lossy().replace('\\', "/");
        if workspace_rel_set.contains(rel_string.as_str()) {
            selected.insert(rel);
            continue;
        }

        let prefix_slash = format!("{rel_string}/");
        let mut matched_any = false;
        for workspace_rel in workspace_rel_paths {
            if workspace_rel.starts_with(&prefix_slash) {
                matched_any = true;
                selected.insert(PathBuf::from(workspace_rel));
            }
        }
        if matched_any {
            continue;
        }

        if contains_glob_syntax(trimmed) {
            let pattern = normalize_source_pattern(trimmed, root)?;
            let glob = Pattern::new(&pattern)
                .map_err(|err| format!("Invalid source glob `{trimmed}`: {err}"))?;
            let mut matched_any = false;
            for rel in workspace_rel_paths {
                if glob.matches(rel) {
                    matched_any = true;
                    selected.insert(PathBuf::from(rel));
                }
            }
            if !matched_any {
                return Err(format!(
                    "source glob `{trimmed}` matched no files at git revision `{revision}`"
                ));
            }
            continue;
        }

        let working_tree_note = if root.join(&rel).is_file() {
            " (path exists in the working tree but not at this revision)"
        } else {
            ""
        };
        return Err(format!(
            "source path does not exist at git revision `{revision}`: {trimmed}{working_tree_note}"
        ));
    }

    if selected.is_empty() {
        return Err(
            "sources resolved to an empty workspace (no non-empty source paths were provided)"
                .to_string(),
        );
    }
    Ok(selected.into_iter().collect())
}

fn install_git_history_overlays(
    root: &Path,
    project: &OverlayProject,
    overlays: Vec<GitHistoryOverlay>,
) -> Result<(), String> {
    for overlay in overlays {
        let abs_path = root.join(&overlay.rel_path);
        if !project.set(abs_path.clone(), overlay.content) {
            return Err(format!(
                "git history path `{}` is too large for the analyzer overlay",
                abs_path.display()
            ));
        }
    }
    Ok(())
}

fn normalize_source_pattern(raw: &str, root: &Path) -> Result<String, String> {
    if looks_like_absolute_path(raw) {
        normalize_relative_path(&normalize_absolute_source_string(raw, root)?)
            .map(|path| path.to_string_lossy().replace('\\', "/"))
    } else {
        normalize_relative_path(raw).map(|path| path.to_string_lossy().replace('\\', "/"))
    }
}

fn normalize_literal_source_path(raw: &str, root: &Path) -> Result<PathBuf, String> {
    if looks_like_absolute_path(raw) {
        let abs = Path::new(raw);
        let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        if abs.exists() {
            let normalized_abs = abs
                .canonicalize()
                .map_err(|err| format!("Failed to resolve source path {}: {err}", abs.display()))?;
            let rel = normalized_abs
                .strip_prefix(&canonical_root)
                .map_err(|_| absolute_source_outside_workspace_error(raw, root))?;
            return normalize_relative_path(&rel.to_string_lossy());
        }
        return normalize_relative_path(&normalize_absolute_source_string(raw, root)?);
    }

    normalize_relative_path(raw)
}

fn normalize_absolute_source_string(raw: &str, root: &Path) -> Result<String, String> {
    let raw_norm = raw.replace('\\', "/");
    let root_norm = root.display().to_string().replace('\\', "/");
    let root_trimmed = root_norm.trim_end_matches('/');

    if raw_norm == root_trimmed {
        return Ok(String::new());
    }

    raw_norm
        .strip_prefix(&format!("{root_trimmed}/"))
        .map(str::to_string)
        .ok_or_else(|| absolute_source_outside_workspace_error(raw, root))
}

fn absolute_source_outside_workspace_error(raw: &str, root: &Path) -> String {
    format!(
        "absolute path is outside active workspace: {} (workspace: {})",
        raw,
        root.display()
    )
}

fn normalize_relative_path(raw: &str) -> Result<PathBuf, String> {
    let normalized = raw.replace('\\', "/");
    let mut rel = PathBuf::new();
    for component in Path::new(&normalized).components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => rel.push(part),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!("path escapes active workspace: {raw}"));
            }
        }
    }
    if rel.as_os_str().is_empty() {
        return Err(format!("path is empty: {raw}"));
    }
    Ok(rel)
}

fn contains_glob_syntax(raw: &str) -> bool {
    raw.contains(['*', '?', '['])
}

fn looks_like_absolute_path(raw: &str) -> bool {
    Path::new(raw).is_absolute() || is_windows_absolute_path(raw)
}

fn is_windows_absolute_path(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
}
