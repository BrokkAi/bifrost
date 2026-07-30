use crate::analyzer::{
    IAnalyzer, Project, ProjectFile, WorkspaceFileIndex, WorkspaceFileIndexCell,
};
use serde::Serialize;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, OnceLock};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AmbiguousPathInput {
    pub input: String,
    pub matches: Vec<String>,
}

pub enum ResolvedFileInput {
    File(ProjectFile),
    Ambiguous(AmbiguousPathInput),
    NotFound(String),
}

pub struct WorkspaceFileResolver<'a> {
    project: &'a dyn Project,
    /// The active request's shared listing cell, when the caller had an
    /// analyzer and a query scope was open. Resolvers are built per call site
    /// and per symbol, so without this each one paid its own whole-workspace
    /// walk (#1334).
    shared_index: Option<WorkspaceFileIndexCell>,
    /// This resolver's own listing: used when no request scope is available,
    /// and as the fallback if the shared cell turns out to describe a different
    /// workspace than this resolver's project.
    private_index: OnceLock<Arc<WorkspaceFileIndex>>,
}

impl<'a> WorkspaceFileResolver<'a> {
    /// A resolver whose listing lives and dies with the resolver. For callers
    /// that have no analyzer at hand; every request-scoped caller should prefer
    /// [`WorkspaceFileResolver::for_analyzer`].
    pub fn new(project: &'a dyn Project) -> Self {
        Self {
            project,
            shared_index: None,
            private_index: OnceLock::new(),
        }
    }

    /// A resolver that shares the active request's workspace listing, so one
    /// request walks the tree at most once however many resolvers it builds.
    /// With no query scope open this behaves exactly like
    /// [`WorkspaceFileResolver::new`].
    pub fn for_analyzer(analyzer: &'a dyn IAnalyzer) -> Self {
        Self {
            project: analyzer.project(),
            shared_index: analyzer.workspace_file_index_cell(),
            private_index: OnceLock::new(),
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
        self.index().matches(basename)
    }

    fn index(&self) -> &WorkspaceFileIndex {
        // `get_or_init` runs on this resolver's own `Arc` handle, which is how
        // the request-shared cell guarantees the walk happens once even when
        // many `rayon` workers miss it at the same instant.
        if let Some(shared) = &self.shared_index {
            let index = shared.get_or_init(|| Arc::new(WorkspaceFileIndex::build(self.project)));
            if index.covers(self.project.root()) {
                return index;
            }
        }
        self.private_index
            .get_or_init(|| Arc::new(WorkspaceFileIndex::build(self.project)))
    }
}

pub(crate) fn normalize_pattern(pattern: &str) -> String {
    pattern.replace('\\', "/")
}

pub fn rel_path_string(file: &ProjectFile) -> String {
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

pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
        {
            out.push((high << 4) | low);
            index += 3;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::percent_decode;

    #[test]
    fn percent_decode_handles_unicode_spaces_and_malformed_escapes() {
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("%E2%9C%93"), "✓");
        assert_eq!(percent_decode("plain/path"), "plain/path");
        assert_eq!(percent_decode("incomplete%2"), "incomplete%2");
        assert_eq!(percent_decode("invalid%XZ"), "invalid%XZ");
    }
}
