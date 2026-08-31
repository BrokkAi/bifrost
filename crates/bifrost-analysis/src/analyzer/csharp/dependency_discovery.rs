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
    use super::is_csharp_dependency_input_path;
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
