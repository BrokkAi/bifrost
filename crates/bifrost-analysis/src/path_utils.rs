//! Resolving caller-supplied path literals against a workspace listing.
//!
//! The pure normalization half lives in
//! [`brokk_bifrost_core::path_utils`]; only the resolver, which reads a
//! workspace listing off an [`IAnalyzer`], stays here.

pub(crate) use brokk_bifrost_core::path_utils::{
    has_drive_letter_prefix, normalize_pattern, workspace_rel_path,
};
pub use brokk_bifrost_core::path_utils::{percent_decode, rel_path_string};

use crate::analyzer::{
    IAnalyzer, Project, ProjectFile, WorkspaceFileIndex, WorkspaceFileIndexCell,
};
use serde::Serialize;
use std::path::Path;
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

fn is_bare_literal_candidate(input: &str, rel: &Path) -> bool {
    if input.contains('/') || input.contains('\\') || input.contains('*') || input.contains('?') {
        return false;
    }
    rel.components().count() == 1
}
