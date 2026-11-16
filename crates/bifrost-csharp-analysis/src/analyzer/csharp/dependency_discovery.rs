use brokk_bifrost_core::analyzer::model::ProjectFile;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub(crate) const MAX_ASSETS_FILES: usize = 64;
pub(crate) const MAX_PROJECT_OUTPUTS: usize = 64;
pub(crate) const MAX_PROJECT_OUTPUT_DEPTH: usize = 5;
const MAX_WALKED_ENTRIES: usize = 4_096;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum TraversalEvent {
    EntryLimit,
    AssetLimit,
    OutputLimit,
    DepthLimit { path: PathBuf },
    IoError { path: PathBuf, error: String },
    SymlinkSkipped { path: PathBuf },
}

#[derive(Default, Debug, PartialEq, Eq)]
pub(crate) struct TraversalStatus {
    pub(crate) events: Vec<TraversalEvent>,
}

impl TraversalStatus {
    pub(crate) fn incomplete(event: TraversalEvent) -> Self {
        Self {
            events: vec![event],
        }
    }

    pub(crate) fn record(&mut self, event: TraversalEvent) {
        self.events.push(event);
    }

    pub(crate) fn sort(&mut self, root: &Path) {
        // Capped subsets and event sorting use the platform's file-name byte
        // order (OsStr ordering), deterministic per platform, not locale order.
        self.events
            .sort_by(|a, b| a.path(root).cmp(b.path(root)).then_with(|| a.cmp(b)));
    }

    pub(crate) fn diagnostic(&self, root: &Path) -> Option<String> {
        if self.events.is_empty() {
            return None;
        }
        let reasons: Vec<_> = self
            .events
            .iter()
            .map(|event| {
                let reason = match event {
                    TraversalEvent::EntryLimit => {
                        format!("entry limit ({MAX_WALKED_ENTRIES} entries)")
                    }
                    TraversalEvent::AssetLimit => {
                        format!("asset limit ({MAX_ASSETS_FILES} assets)")
                    }
                    TraversalEvent::OutputLimit => {
                        format!("output limit ({MAX_PROJECT_OUTPUTS} outputs)")
                    }
                    TraversalEvent::DepthLimit { .. } => {
                        format!("depth limit (depth {MAX_PROJECT_OUTPUT_DEPTH})")
                    }
                    TraversalEvent::IoError { error, .. } => error.clone(),
                    TraversalEvent::SymlinkSkipped { .. } => "symlink skipped".to_owned(),
                };
                format!("{}: {reason}", event.path(root).display())
            })
            .collect();
        Some(format!(".NET dependency traversal incomplete: {reasons:?}"))
    }

    pub(crate) fn skip_symlink(
        &mut self,
        entry: &walkdir::DirEntry,
        selected: impl Fn(&Path, std::fs::FileType) -> bool,
    ) -> bool {
        if !entry.path_is_symlink() {
            return false;
        }
        if selected(entry.path(), entry.file_type()) {
            self.record_skipped_symlink(entry.path(), selected);
        }
        true
    }

    pub(crate) fn record_skipped_symlink(
        &mut self,
        path: &Path,
        selected: impl Fn(&Path, std::fs::FileType) -> bool,
    ) {
        // A skipped link hides this walk's inputs only if the equivalent real
        // directory or file would be searched/selected by the same predicate.
        match std::fs::metadata(path) {
            Ok(metadata) if selected(path, metadata.file_type()) => {
                self.record(TraversalEvent::SymlinkSkipped {
                    path: path.to_owned(),
                });
            }
            Ok(_) => {}
            Err(error) => self.record(TraversalEvent::IoError {
                path: path.to_owned(),
                error: error.to_string(),
            }),
        }
    }
}

impl TraversalEvent {
    fn path<'a>(&'a self, root: &'a Path) -> &'a Path {
        match self {
            Self::IoError { path, .. }
            | Self::SymlinkSkipped { path }
            | Self::DepthLimit { path } => path,
            _ => root,
        }
    }

    pub(crate) fn walk_error(error: walkdir::Error, root: &Path) -> Self {
        Self::IoError {
            path: error.path().unwrap_or(root).to_owned(),
            error: error
                .io_error()
                .map_or_else(|| error.to_string(), ToString::to_string),
        }
    }
}

fn assets_entry_selected(path: &Path, file_type: std::fs::FileType) -> bool {
    // Repository-local SDK/package caches contain no project inputs.
    let directory_selected = !matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some(".git" | "node_modules" | "target" | "bin" | ".dotnet" | ".nuget")
    );
    let file_selected = path
        .file_name()
        .is_some_and(|name| name == "project.assets.json")
        && path
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|name| name == "obj");
    // Before classifying a link, retain it only if either possible target kind
    // would be selected. This also prunes excluded links without probing them.
    (file_type.is_dir() && directory_selected)
        || (file_type.is_file() && file_selected)
        || (file_type.is_symlink() && (directory_selected || file_selected))
}

pub(crate) fn project_assets_files(root: &Path) -> (Vec<PathBuf>, TraversalStatus) {
    let entries = WalkDir::new(root)
        .follow_links(false)
        .follow_root_links(true)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| {
            (!entry.file_type().is_dir() && !entry.file_type().is_symlink())
                || assets_entry_selected(entry.path(), entry.file_type())
        })
        .map(|entry| entry.map_err(|error| TraversalEvent::walk_error(error, root)));
    project_assets_from_entries(root, entries)
}

pub(crate) fn project_assets_from_entries(
    root: &Path,
    entries: impl IntoIterator<Item = Result<walkdir::DirEntry, TraversalEvent>>,
) -> (Vec<PathBuf>, TraversalStatus) {
    let mut assets = Vec::new();
    let mut walked = 0;
    let mut status = TraversalStatus::default();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                status.record(error);
                continue;
            }
        };
        walked += 1;
        if walked > MAX_WALKED_ENTRIES {
            status.record(TraversalEvent::EntryLimit);
            break;
        }
        // The caller's root is a chosen boundary, not a skipped subtree.
        if entry.depth() > 0 && status.skip_symlink(&entry, assets_entry_selected) {
            continue;
        }
        if entry.file_type().is_file() && assets_entry_selected(entry.path(), entry.file_type()) {
            assets.push(entry.into_path());
            if assets.len() == MAX_ASSETS_FILES {
                status.record(TraversalEvent::AssetLimit);
                break;
            }
        }
    }
    assets.sort();
    status.sort(root);
    (assets, status)
}

pub(crate) fn is_csharp_dependency_input(file: &ProjectFile) -> bool {
    is_csharp_dependency_input_path(file.rel_path())
}

pub(crate) fn is_csharp_dependency_input_path(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.eq_ignore_ascii_case("project.assets.json")
        || name.eq_ignore_ascii_case("packages.lock.json")
        || name.eq_ignore_ascii_case("Directory.Packages.props")
        || name.eq_ignore_ascii_case("NuGet.config")
        || path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| {
                ["csproj", "props", "targets", "dll", "exe"]
                    .iter()
                    .any(|expected| extension.eq_ignore_ascii_case(expected))
            })
}

#[cfg(test)]
mod tests {

    use crate::analyzer::csharp::dependency_discovery::is_csharp_dependency_input_path;
    use std::path::Path;

    #[test]
    fn dependency_inputs_are_case_insensitive() {
        for path in [
            "App.CSPROJ",
            "Directory.Build.PROPS",
            "Custom.TARGETS",
            "PROJECT.ASSETS.JSON",
            "PACKAGES.LOCK.JSON",
            "NUGET.CONFIG",
            "Library.DLL",
            "Tool.EXE",
        ] {
            assert!(is_csharp_dependency_input_path(Path::new(path)), "{path}");
        }
        assert!(!is_csharp_dependency_input_path(Path::new("App.cs")));
    }
}
