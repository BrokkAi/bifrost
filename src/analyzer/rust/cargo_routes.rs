use crate::analyzer::ProjectFile;
use crate::hash::HashMap;
use std::path::{Component, Path, PathBuf};

use super::declarations::rust_package_name;
use super::imports::rust_external_module_route;

pub(super) fn resolve_module_package_for_file(
    importing_file: &ProjectFile,
    module_specifier: &str,
) -> Option<String> {
    let (route_root, nested) = rust_external_module_route(module_specifier)?;
    let manifest_directory = nearest_manifest_directory(importing_file)?;
    let project_root = importing_file.root();
    let manifest = read_manifest(project_root, &manifest_directory)?;
    let current = cargo_crate(project_root, manifest_directory.clone(), manifest.clone())?;
    let normalized_route = normalize_crate_name(route_root);

    let mut resolved =
        (current.library_name == normalized_route).then(|| current.root_package.clone());
    if resolved.is_none() {
        'dependencies: for dependencies in cargo_dependency_tables(&manifest) {
            for (exposed_name, dependency) in dependencies {
                let Some(path) = dependency
                    .as_table()
                    .and_then(|dependency| dependency.get("path"))
                    .and_then(toml::Value::as_str)
                else {
                    continue;
                };
                let directory = normalize_relative_path(&manifest_directory.join(path));
                let Some(target_manifest) = read_manifest(project_root, &directory) else {
                    continue;
                };
                let Some(target) = cargo_crate(project_root, directory, target_manifest) else {
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
    let root_file = ProjectFile::new(root.to_path_buf(), directory.join(library_path));
    Some(CargoCrate {
        directory,
        library_name,
        root_package: rust_package_name(&root_file),
        manifest,
    })
}

#[derive(Debug, Clone, Default)]
pub(crate) struct RustCargoRouteIndex {
    manifest_by_file: HashMap<ProjectFile, PathBuf>,
    package_by_route: HashMap<(PathBuf, String), String>,
}

struct CargoCrate {
    directory: PathBuf,
    library_name: String,
    root_package: String,
    manifest: toml::Value,
}

impl RustCargoRouteIndex {
    pub(super) fn build(files: &[ProjectFile]) -> Self {
        let Some(root) = files.first().map(ProjectFile::root) else {
            return Self::default();
        };
        let mut manifest_by_file = HashMap::default();
        let mut manifests: HashMap<PathBuf, Option<toml::Value>> = HashMap::default();
        for file in files {
            let Some(directory) = nearest_manifest_directory(file) else {
                continue;
            };
            manifest_by_file.insert(file.clone(), directory.clone());
            manifests.entry(directory.clone()).or_insert_with(|| {
                std::fs::read_to_string(root.join(&directory).join("Cargo.toml"))
                    .ok()
                    .and_then(|source| toml::from_str(&source).ok())
            });
        }

        let crates: Vec<_> = manifests
            .into_iter()
            .filter_map(|(directory, manifest)| {
                let manifest = manifest?;
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
                let root_file = ProjectFile::new(root.to_path_buf(), directory.join(library_path));
                Some(CargoCrate {
                    directory,
                    library_name,
                    root_package: rust_package_name(&root_file),
                    manifest,
                })
            })
            .collect();

        let mut crate_by_directory = HashMap::default();
        for (index, cargo_crate) in crates.iter().enumerate() {
            crate_by_directory.insert(cargo_crate.directory.clone(), index);
        }
        let mut package_by_route = HashMap::default();
        for cargo_crate in &crates {
            package_by_route.insert(
                (
                    cargo_crate.directory.clone(),
                    cargo_crate.library_name.clone(),
                ),
                cargo_crate.root_package.clone(),
            );
            for dependencies in cargo_dependency_tables(&cargo_crate.manifest) {
                for (exposed_name, dependency) in dependencies {
                    let target = dependency
                        .as_table()
                        .and_then(|dependency| dependency.get("path"))
                        .and_then(toml::Value::as_str)
                        .map(|path| normalize_relative_path(&cargo_crate.directory.join(path)))
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
                            (cargo_crate.directory.clone(), exposed_name),
                            crates[target].root_package.clone(),
                        );
                    }
                }
            }
        }
        Self {
            manifest_by_file,
            package_by_route,
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

fn normalize_relative_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(component) => normalized.push(component),
            Component::RootDir | Component::Prefix(_) => normalized.push(component.as_os_str()),
        }
    }
    normalized
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
    }

    fn write(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
        std::fs::write(path, contents).expect("write fixture");
    }
}
