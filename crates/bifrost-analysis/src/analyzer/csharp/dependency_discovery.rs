use crate::analyzer::ProjectFile;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub(super) const MAX_ASSETS_FILES: usize = 64;
const MAX_WALKED_ENTRIES: usize = 4_096;

pub(super) fn project_assets_files(root: &Path) -> Vec<PathBuf> {
    let mut assets = Vec::new();
    let mut walked = 0;
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            !entry.file_type().is_dir()
                || !matches!(
                    entry.file_name().to_str(),
                    Some(".git" | "node_modules" | "target" | "bin")
                )
        })
        .filter_map(Result::ok)
    {
        walked += 1;
        if walked > MAX_WALKED_ENTRIES {
            break;
        }
        if !entry.file_type().is_file() || entry.file_name() != "project.assets.json" {
            continue;
        }
        if entry
            .path()
            .parent()
            .is_some_and(|parent| parent.file_name().is_some_and(|name| name == "obj"))
        {
            assets.push(entry.into_path());
            if assets.len() == MAX_ASSETS_FILES {
                break;
            }
        }
    }
    assets.sort();
    assets
}

pub(crate) fn is_csharp_dependency_input(file: &ProjectFile) -> bool {
    let path = file.rel_path();
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    name == "project.assets.json"
        || name == "packages.lock.json"
        || name == "Directory.Packages.props"
        || name == "NuGet.config"
        || name.ends_with(".csproj")
        || name.ends_with(".props")
        || name.ends_with(".targets")
        || name.ends_with(".dll")
        || name.ends_with(".exe")
}
