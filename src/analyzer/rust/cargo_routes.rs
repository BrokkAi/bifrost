use crate::analyzer::ProjectFile;
use crate::hash::HashMap;
use std::path::{Component, Path, PathBuf};

use super::declarations::rust_package_name;
use super::imports::{rust_external_module_route, rust_external_module_segments};

pub(super) fn resolve_module_package_for_file(
    importing_file: &ProjectFile,
    module_specifier: &str,
) -> Option<String> {
    let (route_root, nested) = rust_external_module_route(module_specifier)?;
    let manifest_directory = nearest_manifest_directory(importing_file)?;
    let project_root = importing_file.root();
    let current = load_cargo_crate(project_root, manifest_directory.clone())?;
    let manifest = &current.manifest;
    let normalized_route = normalize_crate_name(route_root);

    let mut resolved =
        (current.library_name == normalized_route).then(|| current.root_package.clone());
    if resolved.is_none() {
        'dependencies: for dependencies in cargo_dependency_tables(manifest) {
            for (exposed_name, dependency) in dependencies {
                let Some(path) = dependency
                    .as_table()
                    .and_then(|dependency| dependency.get("path"))
                    .and_then(toml::Value::as_str)
                else {
                    continue;
                };
                let Some(directory) =
                    workspace_relative_path(project_root, &manifest_directory, Path::new(path))
                else {
                    continue;
                };
                let Some(target) = load_cargo_crate(project_root, directory) else {
                    continue;
                };
                let is_renamed = dependency
                    .as_table()
                    .is_some_and(|dependency| dependency.contains_key("package"));
                let exposed_name = if is_renamed {
                    normalize_crate_name(exposed_name)
                } else {
                    target.library_name.clone()
                };
                if exposed_name == normalized_route {
                    resolved = Some(target.root_package);
                    break 'dependencies;
                }
            }
        }
    }

    resolved.map(|package| match nested {
        Some(nested) => format!("{package}.{nested}"),
        None => package,
    })
}

fn read_manifest(root: &Path, directory: &Path) -> Option<toml::Value> {
    std::fs::read_to_string(root.join(directory).join("Cargo.toml"))
        .ok()
        .and_then(|source| toml::from_str(&source).ok())
}

fn load_cargo_crate(root: &Path, directory: PathBuf) -> Option<CargoCrate> {
    let manifest = read_manifest(root, &directory)?;
    cargo_crate(root, directory, manifest)
}

fn cargo_crate(root: &Path, directory: PathBuf, manifest: toml::Value) -> Option<CargoCrate> {
    let package_name = manifest
        .get("package")?
        .get("name")?
        .as_str()
        .map(normalize_crate_name)?;
    let library_name = manifest
        .get("lib")
        .and_then(|lib| lib.get("name"))
        .and_then(toml::Value::as_str)
        .map(normalize_crate_name)
        .unwrap_or_else(|| package_name.clone());
    let library_path = manifest
        .get("lib")
        .and_then(|lib| lib.get("path"))
        .and_then(toml::Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("src/lib.rs"));
    let library_path = workspace_relative_path(root, &directory, &library_path)?;
    let root_file = ProjectFile::new(root.to_path_buf(), library_path);
    Some(CargoCrate {
        directory,
        library_name,
        root_file: root_file.clone(),
        root_package: rust_package_name(&root_file),
        manifest,
    })
}

#[derive(Debug, Clone, Default)]
pub(crate) struct RustCargoRouteIndex {
    manifest_by_file: HashMap<ProjectFile, PathBuf>,
    package_by_route: HashMap<(PathBuf, String), String>,
    root_file_by_route: HashMap<(PathBuf, String), ProjectFile>,
    kind_by_route: HashMap<(PathBuf, String), RustCargoRouteKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RustCargoRouteKind {
    CurrentLibrary,
    Dependency,
}

struct CargoCrate {
    directory: PathBuf,
    library_name: String,
    root_file: ProjectFile,
    root_package: String,
    manifest: toml::Value,
}

impl RustCargoRouteIndex {
    pub(super) fn build(files: &[ProjectFile]) -> Self {
        let Some(root) = files.first().map(ProjectFile::root) else {
            return Self::default();
        };
        let mut manifest_by_file = HashMap::default();
        let mut manifest_directories = crate::hash::HashSet::default();
        for file in files {
            let Some(directory) = nearest_manifest_directory(file) else {
                continue;
            };
            manifest_by_file.insert(file.clone(), directory.clone());
            manifest_directories.insert(directory);
        }

        let crates: Vec<_> = manifest_directories
            .into_iter()
            .filter_map(|directory| load_cargo_crate(root, directory))
            .collect();

        let mut crate_by_directory = HashMap::default();
        for (index, cargo_crate) in crates.iter().enumerate() {
            crate_by_directory.insert(cargo_crate.directory.clone(), index);
        }
        let mut package_by_route = HashMap::default();
        let mut root_file_by_route = HashMap::default();
        let mut kind_by_route = HashMap::default();
        for cargo_crate in &crates {
            let own_route = (
                cargo_crate.directory.clone(),
                cargo_crate.library_name.clone(),
            );
            package_by_route.insert(own_route.clone(), cargo_crate.root_package.clone());
            root_file_by_route.insert(own_route.clone(), cargo_crate.root_file.clone());
            kind_by_route.insert(own_route, RustCargoRouteKind::CurrentLibrary);
            for dependencies in cargo_dependency_tables(&cargo_crate.manifest) {
                for (exposed_name, dependency) in dependencies {
                    let target = dependency
                        .as_table()
                        .and_then(|dependency| dependency.get("path"))
                        .and_then(toml::Value::as_str)
                        .and_then(|path| {
                            workspace_relative_path(root, &cargo_crate.directory, Path::new(path))
                        })
                        .and_then(|directory| crate_by_directory.get(&directory).copied());
                    if let Some(target) = target {
                        let is_renamed = dependency
                            .as_table()
                            .is_some_and(|dependency| dependency.contains_key("package"));
                        let exposed_name = if is_renamed {
                            normalize_crate_name(exposed_name)
                        } else {
                            crates[target].library_name.clone()
                        };
                        package_by_route.insert(
                            (cargo_crate.directory.clone(), exposed_name.clone()),
                            crates[target].root_package.clone(),
                        );
                        root_file_by_route.insert(
                            (cargo_crate.directory.clone(), exposed_name.clone()),
                            crates[target].root_file.clone(),
                        );
                        kind_by_route.insert(
                            (cargo_crate.directory.clone(), exposed_name),
                            RustCargoRouteKind::Dependency,
                        );
                    }
                }
            }
        }
        Self {
            manifest_by_file,
            package_by_route,
            root_file_by_route,
            kind_by_route,
        }
    }

    pub(super) fn resolve_module_package(
        &self,
        importing_file: &ProjectFile,
        module_specifier: &str,
    ) -> Option<String> {
        let manifest = self.manifest_by_file.get(importing_file)?;
        let (root, nested) = rust_external_module_route(module_specifier)?;
        let package = self
            .package_by_route
            .get(&(manifest.clone(), normalize_crate_name(root)))?;
        Some(match nested {
            Some(nested) => format!("{package}.{nested}"),
            None => package.clone(),
        })
    }

    pub(super) fn resolve_module_package_segments_with_kind(
        &self,
        importing_file: &ProjectFile,
        segments: &[String],
    ) -> Option<(String, RustCargoRouteKind)> {
        let manifest = self.manifest_by_file.get(importing_file)?;
        let (root, nested) = rust_external_module_segments(segments)?;
        let route = (manifest.clone(), normalize_crate_name(root));
        let package = self.package_by_route.get(&route)?;
        let kind = *self.kind_by_route.get(&route)?;
        Some((
            match nested {
                Some(nested) => format!("{package}.{nested}"),
                None => package.clone(),
            },
            kind,
        ))
    }

    pub(super) fn resolve_crate_root_file(
        &self,
        importing_file: &ProjectFile,
        module_specifier: &str,
    ) -> Option<ProjectFile> {
        let manifest = self.manifest_by_file.get(importing_file)?;
        let (root, nested) = rust_external_module_route(module_specifier)?;
        if nested.is_some() {
            return None;
        }
        self.root_file_by_route
            .get(&(manifest.clone(), normalize_crate_name(root)))
            .cloned()
    }

    pub(super) fn resolve_crate_root_file_segments_with_kind(
        &self,
        importing_file: &ProjectFile,
        segments: &[String],
    ) -> Option<(ProjectFile, RustCargoRouteKind)> {
        let manifest = self.manifest_by_file.get(importing_file)?;
        let (root, nested) = rust_external_module_segments(segments)?;
        if nested.is_some() {
            return None;
        }
        let route = (manifest.clone(), normalize_crate_name(root));
        Some((
            self.root_file_by_route.get(&route)?.clone(),
            *self.kind_by_route.get(&route)?,
        ))
    }
}

fn cargo_dependency_tables(manifest: &toml::Value) -> Vec<&toml::map::Map<String, toml::Value>> {
    let mut tables = Vec::new();
    for table_name in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(table) = manifest.get(table_name).and_then(toml::Value::as_table) {
            tables.push(table);
        }
    }
    if let Some(targets) = manifest.get("target").and_then(toml::Value::as_table) {
        for target in targets.values().filter_map(toml::Value::as_table) {
            for table_name in ["dependencies", "dev-dependencies", "build-dependencies"] {
                if let Some(table) = target.get(table_name).and_then(toml::Value::as_table) {
                    tables.push(table);
                }
            }
        }
    }
    tables
}

fn nearest_manifest_directory(file: &ProjectFile) -> Option<PathBuf> {
    let mut directory = file.rel_path().parent();
    loop {
        let relative = directory.unwrap_or_else(|| Path::new(""));
        if file.root().join(relative).join("Cargo.toml").is_file() {
            return Some(relative.to_path_buf());
        }
        directory = relative.parent();
        directory?;
    }
}

fn workspace_relative_path(root: &Path, base: &Path, path: &Path) -> Option<PathBuf> {
    let mut normalized = base.to_path_buf();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return None;
                }
            }
            Component::Normal(component) => normalized.push(component),
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    let canonical_root = root.canonicalize().ok()?;
    let canonical_target = root.join(&normalized).canonicalize().ok()?;
    canonical_target
        .strip_prefix(canonical_root)
        .ok()
        .map(Path::to_path_buf)
}

fn normalize_crate_name(name: &str) -> String {
    name.replace('-', "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_dependency_routes_honor_library_name_aliases_and_ignore_registry_matches() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "matcher/Cargo.toml",
            "[package]\nname = \"matcher-package\"\nversion = \"0.1.0\"\n[lib]\nname = \"matcher_lib\"\n",
        );
        write(&root, "matcher/src/lib.rs", "pub struct Pattern;\n");
        write(
            &root,
            "consumer/Cargo.toml",
            "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\n[dependencies]\nmatcher-package = { path = \"../matcher\" }\nregistry_alias = { package = \"matcher-package\", version = \"1\" }\n",
        );
        write(&root, "consumer/src/lib.rs", "pub fn run() {}\n");
        write(
            &root,
            "renamed/Cargo.toml",
            "[package]\nname = \"renamed\"\nversion = \"0.1.0\"\n[dependencies]\ncustom_alias = { package = \"matcher-package\", path = \"../matcher\" }\n",
        );
        write(&root, "renamed/src/lib.rs", "pub fn run() {}\n");

        let matcher = ProjectFile::new(root.clone(), "matcher/src/lib.rs");
        let consumer = ProjectFile::new(root.clone(), "consumer/src/lib.rs");
        let renamed = ProjectFile::new(root.clone(), "renamed/src/lib.rs");
        let routes = RustCargoRouteIndex::build(&[matcher, consumer.clone(), renamed.clone()]);

        assert_eq!(
            routes.resolve_module_package(&consumer, "matcher_lib"),
            Some("matcher.src".to_string())
        );
        assert_eq!(
            routes.resolve_module_package(&consumer, "matcher_lib::nested"),
            Some("matcher.src.nested".to_string())
        );
        assert_eq!(
            routes.resolve_module_package(&renamed, "custom_alias"),
            Some("matcher.src".to_string())
        );
        assert_eq!(
            routes.resolve_module_package(&consumer, "registry_alias"),
            None
        );
        assert_eq!(
            routes.resolve_module_package(&consumer, "matcher_package"),
            None
        );
        assert_eq!(
            resolve_module_package_for_file(&consumer, "matcher_lib"),
            Some("matcher.src".to_string())
        );
    }

    #[test]
    fn cargo_routes_reject_paths_outside_the_workspace() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("workspace");
        std::fs::create_dir_all(&root).expect("workspace root");
        let root = root.canonicalize().expect("canonical root");
        let outside = temp.path().join("outside");
        write(
            temp.path(),
            "outside/Cargo.toml",
            "[package]\nname = \"outside\"\nversion = \"0.1.0\"\n",
        );
        write(temp.path(), "outside/src/lib.rs", "pub struct Escaped;\n");
        write(
            &root,
            "consumer/Cargo.toml",
            &format!(
                "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\n[dependencies]\nparent_escape = {{ path = \"../../outside\" }}\nabsolute_escape = {{ path = {:?} }}\n",
                outside.to_string_lossy()
            ),
        );
        write(&root, "consumer/src/lib.rs", "pub fn run() {}\n");
        let consumer = ProjectFile::new(root.clone(), "consumer/src/lib.rs");

        let routes = RustCargoRouteIndex::build(std::slice::from_ref(&consumer));
        for name in ["parent_escape", "absolute_escape"] {
            assert_eq!(routes.resolve_module_package(&consumer, name), None);
            assert_eq!(resolve_module_package_for_file(&consumer, name), None);
        }
    }

    #[cfg(unix)]
    #[test]
    fn cargo_routes_reject_symlinked_dependency_and_library_paths() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("workspace");
        std::fs::create_dir_all(&root).expect("workspace root");
        let root = root.canonicalize().expect("canonical root");
        write(
            temp.path(),
            "outside/Cargo.toml",
            "[package]\nname = \"outside\"\nversion = \"0.1.0\"\n",
        );
        write(temp.path(), "outside/src/lib.rs", "pub struct Escaped;\n");
        symlink(temp.path().join("outside"), root.join("linked")).expect("dependency symlink");
        write(
            &root,
            "consumer/Cargo.toml",
            "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\n[dependencies]\nlinked = { path = \"../linked\" }\n",
        );
        write(&root, "consumer/src/lib.rs", "pub fn run() {}\n");
        let consumer = ProjectFile::new(root.clone(), "consumer/src/lib.rs");

        assert_eq!(resolve_module_package_for_file(&consumer, "linked"), None);

        write(
            &root,
            "bad_lib/Cargo.toml",
            "[package]\nname = \"bad-lib\"\nversion = \"0.1.0\"\n[lib]\npath = \"../linked/src/lib.rs\"\n",
        );
        let manifest = read_manifest(&root, Path::new("bad_lib")).expect("manifest");
        assert!(cargo_crate(&root, PathBuf::from("bad_lib"), manifest).is_none());
    }

    fn write(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
        std::fs::write(path, contents).expect("write fixture");
    }
}
