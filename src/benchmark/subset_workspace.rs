use crate::benchmark::BenchmarkRepoTarget;
use crate::{FilesystemProject, Project};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const ROOT_SUPPORT_FILES: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "composer.json",
    "composer.lock",
    "go.mod",
    "go.sum",
    "jsconfig.json",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "pom.xml",
    "pyproject.toml",
    "requirements.txt",
    "settings.gradle",
    "settings.gradle.kts",
    "setup.py",
    "tsconfig.json",
    "tsconfig.base.json",
    "yarn.lock",
];

pub fn prepare_subset_workspace(
    source_root: &Path,
    repo_cache_dir: &Path,
    target: &BenchmarkRepoTarget,
    max_files: usize,
) -> Result<PathBuf, String> {
    let project = FilesystemProject::new(source_root).map_err(|err| {
        format!(
            "failed to open workspace `{}` for subset preparation: {err}",
            source_root.display()
        )
    })?;
    let all_files = project.all_files().map_err(|err| {
        format!(
            "failed to enumerate files for subset workspace `{}`: {err}",
            source_root.display()
        )
    })?;

    let candidate_files = candidate_source_files(target, &all_files);
    if candidate_files.is_empty() {
        return Err(format!(
            "subset selection found no analyzable files for `{}` in `{}`",
            target.name,
            source_root.display()
        ));
    }

    let pinned_files = pinned_probe_files(target, &project, &candidate_files)?;
    if pinned_files.len() > max_files {
        return Err(format!(
            "subset selection for `{}` needs {} pinned files, which exceeds --max-files={max_files}",
            target.name,
            pinned_files.len()
        ));
    }

    let mut selected = pinned_files;
    for file in candidate_files {
        if selected.len() == max_files {
            break;
        }
        selected.insert(file);
    }

    if selected.is_empty() {
        return Err(format!(
            "subset selection chose no files for `{}`",
            target.name
        ));
    }

    let subset_root = repo_cache_dir.join(".subsets").join(format!(
        "{}-{}-max{}",
        sanitize_component(&target.name),
        short_commit(&target.commit),
        max_files
    ));
    if subset_root.exists() {
        fs::remove_dir_all(&subset_root).map_err(|err| {
            format!(
                "failed to reset subset workspace `{}`: {err}",
                subset_root.display()
            )
        })?;
    }
    fs::create_dir_all(&subset_root).map_err(|err| {
        format!(
            "failed to create subset workspace `{}`: {err}",
            subset_root.display()
        )
    })?;

    for rel_path in &selected {
        copy_relative_file(source_root, &subset_root, rel_path)?;
    }

    for rel_path in ROOT_SUPPORT_FILES.iter().map(Path::new) {
        if source_root.join(rel_path).is_file() {
            copy_relative_file(source_root, &subset_root, rel_path)?;
        }
    }

    copy_git_metadata(source_root, &subset_root)?;

    Ok(subset_root)
}

fn candidate_source_files(
    target: &BenchmarkRepoTarget,
    all_files: &BTreeSet<crate::ProjectFile>,
) -> BTreeSet<PathBuf> {
    let allowed_extensions = allowed_extensions(target);
    all_files
        .iter()
        .filter_map(|file| {
            let extension = file.rel_path().extension()?.to_str()?.to_ascii_lowercase();
            allowed_extensions
                .contains(extension.as_str())
                .then(|| file.rel_path().to_path_buf())
        })
        .collect()
}

fn pinned_probe_files(
    target: &BenchmarkRepoTarget,
    project: &FilesystemProject,
    candidate_files: &BTreeSet<PathBuf>,
) -> Result<BTreeSet<PathBuf>, String> {
    let mut pinned = BTreeSet::new();
    for raw_path in target
        .summary_targets
        .iter()
        .chain(target.seed_file_paths.iter())
        .chain(target.usage_targets.iter().map(|query| &query.path))
        .chain(
            target
                .definition_queries
                .iter()
                .map(|query| &query.selector.path),
        )
        .chain(
            target
                .call_hierarchy_queries
                .iter()
                .map(|query| &query.selector.path),
        )
        .chain(
            target
                .type_hierarchy_queries
                .iter()
                .map(|query| &query.selector.path),
        )
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        let rel_path = PathBuf::from(raw_path);
        let Some(project_file) = project.file_by_rel_path(&rel_path) else {
            return Err(format!(
                "subset selection for `{}` requires missing probe file `{}`",
                target.name, raw_path
            ));
        };
        let project_rel = project_file.rel_path().to_path_buf();
        if !candidate_files.contains(&project_rel) {
            return Err(format!(
                "subset selection for `{}` requires probe file `{}` that is outside the repo language filter",
                target.name, raw_path
            ));
        }
        pinned.insert(project_rel);
    }
    Ok(pinned)
}

fn allowed_extensions(target: &BenchmarkRepoTarget) -> BTreeSet<String> {
    if !target.extensions.is_empty() {
        return target
            .extensions
            .iter()
            .map(|extension| normalize_extension(extension))
            .filter(|extension| !extension.is_empty())
            .collect();
    }

    target
        .language_set()
        .into_iter()
        .flat_map(|language| {
            language
                .analyzer_language()
                .extensions()
                .iter()
                .map(|extension| extension.to_string())
                .collect::<Vec<_>>()
        })
        .collect()
}

fn copy_relative_file(
    source_root: &Path,
    subset_root: &Path,
    rel_path: &Path,
) -> Result<(), String> {
    let source = source_root.join(rel_path);
    let destination = subset_root.join(rel_path);
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create subset directory `{}`: {err}",
                parent.display()
            )
        })?;
    }
    fs::copy(&source, &destination).map_err(|err| {
        format!(
            "failed to copy `{}` into subset workspace: {err}",
            source.display()
        )
    })?;
    Ok(())
}

fn copy_git_metadata(source_root: &Path, subset_root: &Path) -> Result<(), String> {
    let source_git = source_root.join(".git");
    if source_git.is_dir() {
        copy_directory_recursively(&source_git, &subset_root.join(".git"))?;
    } else if source_git.is_file() {
        let destination_git = subset_root.join(".git");
        fs::copy(&source_git, &destination_git).map_err(|err| {
            format!(
                "failed to copy git metadata `{}` into subset workspace: {err}",
                source_git.display()
            )
        })?;
    }
    Ok(())
}

fn copy_directory_recursively(source: &Path, destination: &Path) -> Result<(), String> {
    fs::create_dir_all(destination).map_err(|err| {
        format!(
            "failed to create copied directory `{}`: {err}",
            destination.display()
        )
    })?;

    for entry in fs::read_dir(source).map_err(|err| {
        format!(
            "failed to read directory `{}` for subset copy: {err}",
            source.display()
        )
    })? {
        let entry = entry.map_err(|err| {
            format!(
                "failed to read directory entry in `{}`: {err}",
                source.display()
            )
        })?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry.file_type().map_err(|err| {
            format!(
                "failed to inspect `{}` for subset copy: {err}",
                source_path.display()
            )
        })?;

        if file_type.is_dir() {
            copy_directory_recursively(&source_path, &destination_path)?;
        } else {
            fs::copy(&source_path, &destination_path).map_err(|err| {
                format!(
                    "failed to copy `{}` into subset workspace: {err}",
                    source_path.display()
                )
            })?;
        }
    }

    Ok(())
}

fn normalize_extension(extension: &str) -> String {
    extension
        .trim()
        .trim_start_matches('.')
        .to_ascii_lowercase()
}

fn sanitize_component(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = sanitized.trim_matches('-');
    if trimmed.is_empty() {
        "repo".to_string()
    } else {
        trimmed.to_string()
    }
}

fn short_commit(commit: &str) -> String {
    let compact: String = commit
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .take(12)
        .collect();
    if compact.is_empty() {
        "unknown".to_string()
    } else {
        compact
    }
}
