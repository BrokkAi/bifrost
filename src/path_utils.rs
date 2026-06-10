use crate::analyzer::{Project, ProjectFile};
use crate::hash::HashMap;
use serde::Serialize;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AmbiguousPathInput {
    pub input: String,
    pub matches: Vec<String>,
}

pub(crate) enum ResolvedFileInput {
    File(ProjectFile),
    Ambiguous(AmbiguousPathInput),
    NotFound(String),
}

pub(crate) struct WorkspaceFileResolver<'a> {
    project: &'a dyn Project,
    basename_index: OnceLock<HashMap<String, Vec<ProjectFile>>>,
}

impl<'a> WorkspaceFileResolver<'a> {
    pub fn new(project: &'a dyn Project) -> Self {
        Self {
            project,
            basename_index: OnceLock::new(),
        }
    }

    pub fn resolve_literal(&self, input: &str) -> ResolvedFileInput {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return ResolvedFileInput::NotFound(trimmed.to_string());
        }

        let Some(rel) = workspace_rel_path(trimmed) else {
            return ResolvedFileInput::NotFound(trimmed.to_string());
        };

        if let Some(file) = self.project.file_by_rel_path(&rel) {
            return ResolvedFileInput::File(file);
        }

        if !is_bare_literal_candidate(trimmed, &rel) {
            return ResolvedFileInput::NotFound(trimmed.to_string());
        }

        let basename = rel
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(trimmed)
            .to_string();
        let Some(matches) = self.basename_matches(&basename) else {
            return ResolvedFileInput::NotFound(trimmed.to_string());
        };

        match matches {
            [] => ResolvedFileInput::NotFound(trimmed.to_string()),
            [file] => ResolvedFileInput::File(file.clone()),
            _ => ResolvedFileInput::Ambiguous(AmbiguousPathInput {
                input: trimmed.to_string(),
                matches: matches.iter().map(rel_path_string).collect(),
            }),
        }
    }

    fn basename_matches(&self, basename: &str) -> Option<&[ProjectFile]> {
        let index = self.basename_index.get_or_init(|| {
            let mut index: HashMap<String, Vec<ProjectFile>> = HashMap::default();
            if let Ok(files) = self.project.all_files() {
                for file in files {
                    let Some(name) = file.rel_path().file_name().and_then(|name| name.to_str())
                    else {
                        continue;
                    };
                    index.entry(name.to_string()).or_default().push(file);
                }
                for matches in index.values_mut() {
                    matches.sort();
                }
            }
            index
        });
        index.get(basename).map(Vec::as_slice)
    }
}

pub(crate) fn normalize_pattern(pattern: &str) -> String {
    pattern.replace('\\', "/")
}

pub(crate) fn rel_path_string(file: &ProjectFile) -> String {
    file.rel_path().to_string_lossy().replace('\\', "/")
}

// Reject absolute paths, root-anchored paths, and Windows drive-relative
// references so MCP callers cannot escape the active workspace via a crafted
// `file_paths` entry. Returns the normalized project-relative path on success.
pub(crate) fn workspace_rel_path(input: &str) -> Option<PathBuf> {
    let normalized = normalize_pattern(input);
    let trimmed = normalized.trim_start_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    if has_drive_letter_prefix(trimmed) {
        return None;
    }
    let path = Path::new(trimmed);
    if path.is_absolute() || path.has_root() {
        return None;
    }
    let mut rel = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => rel.push(part),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    if rel.as_os_str().is_empty() {
        return None;
    }
    Some(rel)
}

fn is_bare_literal_candidate(input: &str, rel: &Path) -> bool {
    if input.contains('/') || input.contains('\\') || input.contains('*') || input.contains('?') {
        return false;
    }
    rel.components().count() == 1
}

pub(crate) fn has_drive_letter_prefix(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(
        (chars.next(), chars.next()),
        (Some(c1), Some(':')) if c1.is_ascii_alphabetic()
    )
}
