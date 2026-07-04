use crate::analyzer::{FileSetProject, OverlayProject, Project};
use crate::git_file::{list_git_files_at_revision, read_git_file};
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
        return SearchToolsService::new_manual_for_project(project);
    };
    let rel_paths = resolve_sources_at_revision(&root, sources, revision)?;
    let project = Arc::new(FileSetProject::new(root.clone(), rel_paths));

    let overlay_project = Arc::new(OverlayProject::new(project));
    for file in overlay_project
        .all_files()
        .map_err(|err| format!("Failed to enumerate scoped files: {err}"))?
    {
        let rel_path = file.rel_path().to_path_buf();
        let abs_path = root.join(&rel_path);
        let content = read_git_file(revision, &abs_path).map_err(|err| {
            format!(
                "failed to read scoped source `{}` at git revision `{revision}`: {err}",
                rel_path.to_string_lossy().replace('\\', "/")
            )
        })?;
        if !overlay_project.set(abs_path.clone(), content) {
            return Err(format!(
                "git history path `{}` is too large for the analyzer overlay",
                abs_path.display()
            ));
        }
    }
    let project: Arc<dyn Project> = overlay_project;
    SearchToolsService::new_manual_for_project(project)
}

pub fn create_cli_tool_service(
    root: PathBuf,
    sources: &[String],
    overlays: Vec<GitHistoryOverlay>,
) -> Result<SearchToolsService, String> {
    let root = root
        .canonicalize()
        .map_err(|err| format!("Failed to resolve project root {}: {err}", root.display()))?;
    if overlays.is_empty() && sources.is_empty() {
        return SearchToolsService::new(root);
    }
    if overlays.is_empty() {
        let rel_paths = resolve_sources(&root, sources)?;
        let project = Arc::new(FileSetProject::new(root, rel_paths));
        return SearchToolsService::new_manual_for_project(project);
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
    SearchToolsService::new_manual_for_project(project)
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
