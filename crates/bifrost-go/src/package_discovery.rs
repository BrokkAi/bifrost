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
#[derive(Debug)]
pub struct GoPackageDiscovery {
    pub packages: Vec<GoPackage>,
    pub environment: GoEnvironment,
    pub goos: String,
    pub goarch: String,
    pub build_tags: Vec<String>,
    pub workspace_patterns: Vec<String>,
    pub vendor: bool,
}
