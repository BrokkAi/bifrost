use crate::analyzer::ProjectFile;
use std::path::{Path, PathBuf};

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
    Some(path.to_path_buf())
}

pub(crate) fn has_drive_letter_prefix(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(
        (chars.next(), chars.next()),
        (Some(c1), Some(':')) if c1.is_ascii_alphabetic()
    )
}
