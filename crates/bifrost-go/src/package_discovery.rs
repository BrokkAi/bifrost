//! Structured records returned by Go package discovery.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub struct GoEnvironment {
    pub goroot: PathBuf,
    pub gopath: PathBuf,
    pub gomodcache: PathBuf,
    pub goversion: String,
    pub gowork: String,
    pub goos: String,
    pub goarch: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct GoModule {
    pub path: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub sum: String,
    #[serde(default)]
    pub dir: PathBuf,
    #[serde(default)]
    pub main: bool,
    #[serde(default)]
    pub go_mod: PathBuf,
    pub replace: Option<Box<GoModule>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct GoPackageError {
    pub err: String,
    #[serde(default)]
    pub import_stack: Vec<String>,
    #[serde(default)]
    pub pos: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct GoPackage {
    pub import_path: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub dir: PathBuf,
    #[serde(default)]
    pub standard: bool,
    #[serde(default)]
    pub incomplete: bool,
    pub error: Option<GoPackageError>,
    pub module: Option<GoModule>,
    #[serde(default)]
    pub go_files: Vec<PathBuf>,
    #[serde(default)]
    pub cgo_files: Vec<PathBuf>,
    #[serde(default)]
    pub ignored_go_files: Vec<PathBuf>,
    #[serde(default)]
    pub imports: Vec<String>,
    #[serde(default)]
    pub import_map: BTreeMap<String, String>,
    #[serde(default)]
    pub for_test: String,
    #[serde(default)]
    pub test_go_files: Vec<PathBuf>,
    #[serde(default)]
    #[serde(rename = "XTestGoFiles")]
    pub x_test_go_files: Vec<PathBuf>,
    #[serde(default)]
    pub test_imports: Vec<String>,
    #[serde(default)]
    #[serde(rename = "XTestImports")]
    pub x_test_imports: Vec<String>,
    #[serde(default)]
    pub deps_errors: Vec<GoPackageError>,
}

/// One bounded discovery invocation's primary (CGO_ENABLED=0) Go tool records.
/// This is transient build input, not revision-selected authority or a cache.
/// ImportPath is an opaque tool identity, including test variant suffixes;
/// ForTest and ImportMap retain structured variant/provider relationships.
#[derive(Debug, Clone)]
pub struct GoPackageDiscovery {
    pub domain: GoDiscoveryDomain,
    pub input_digest: Option<[u8; 32]>,
    pub failure: Option<String>,
    pub packages: Vec<GoPackage>,
    pub environment: GoEnvironment,
    pub goos: String,
    pub goarch: String,
    pub build_tags: Vec<String>,
    pub workspace_patterns: Vec<String>,
    pub vendor: bool,
}

/// One invocation's identity and its selected workspace modules. Query-owned.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GoDiscoveryDomain {
    pub directory: String,
    /// Workspace-relative workfile; empty means GOWORK=off.
    pub gowork_path: String,
    pub modules: Vec<(String, String)>,
}

/// Derive invocation domains from exact selected configuration snapshots.
pub fn go_discovery_domains(
    root: &std::path::Path,
    inputs: &[(PathBuf, String)],
) -> Result<Vec<GoDiscoveryDomain>, String> {
    use crate::build_files::{BuildFileLimits, GoDirective, parse_go_work};
    use brokk_bifrost_core::path_normalization::NormalizePath;
    use brokk_bifrost_core::path_utils::workspace_relative_slash_path;
    use std::collections::BTreeMap;
    use std::path::{Component, Path};
    let mut modules = Vec::new();
    let mut workfiles = BTreeMap::new();
    for (path, source) in inputs {
        let directory = path.parent().expect("configuration has a parent");
        if directory.components().any(|component| match component {
            Component::Normal(name) => {
                let name = name.to_string_lossy();
                name == "vendor"
                    || name == "testdata"
                    || name.starts_with('_')
                    || name.starts_with('.')
            }
            _ => false,
        }) {
            continue;
        }
        if path.file_name().is_some_and(|name| name == "go.mod") {
            if let Some(Some(module)) = crate::packages::parse_go_module_manifest(source) {
                modules.push((directory.to_path_buf(), module));
            }
        } else if path.file_name().is_some_and(|name| name == "go.work") {
            let document = parse_go_work(source, &BuildFileLimits::default(), || false);
            if !document.issues.is_empty() {
                return Err(format!(
                    "invalid Go workspace {path:?}: {:?}",
                    document.issues
                ));
            }
            let members = document
                .entries
                .into_iter()
                .filter_map(|entry| match entry.directive {
                    GoDirective::Use(member) => {
                        Some(root.join(directory).join(member.value).normalize())
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            workfiles.insert(directory.to_path_buf(), (path.clone(), members));
        }
    }
    let mut domains = BTreeMap::<(String, String), GoDiscoveryDomain>::new();
    for (directory, module) in modules {
        let workspace = directory
            .ancestors()
            .find_map(|ancestor| workfiles.get(ancestor));
        let workspace =
            workspace.filter(|(_, members)| members.contains(&root.join(&directory).normalize()));
        let (invocation_dir, workfile) = if let Some((path, _)) = workspace {
            (path.parent().expect("workfile parent"), path.as_path())
        } else {
            (directory.as_path(), Path::new(""))
        };
        let key = (
            workspace_relative_slash_path(invocation_dir),
            workspace_relative_slash_path(workfile),
        );
        domains
            .entry(key.clone())
            .or_insert_with(|| GoDiscoveryDomain {
                directory: key.0,
                gowork_path: key.1,
                modules: Vec::new(),
            })
            .modules
            .push((workspace_relative_slash_path(&directory), module));
    }
    for domain in domains.values_mut() {
        domain.modules.sort();
    }
    Ok(domains.into_values().collect())
}
