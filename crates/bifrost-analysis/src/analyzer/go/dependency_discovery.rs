use crate::CancellationToken;
use crate::analyzer::canonical_hash::{lower_hex_string, sha256_bytes};
use crate::analyzer::semantic_model::{
    CatalogCoordinate, DependencyArtifactRole, DependencyDiscoveryOutcome,
    DependencyDiscoveryProfile, DependencyPackDiagnostic, DependencyPackDiagnosticSeverity,
    DependencyPackLimits, DependencyProvenance, ExternalArtifactKind, ResolvedDependency,
    ResolvedDependencyArtifact, SemanticModelActivationEvidence,
};
use crate::analyzer::{GoAnalyzerConfig, GoDependencyDiscoveryConfig, Project};
use crate::process::{BoundedProcessRequest, run_bounded_process};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};

const MAX_GO_ENV_STDOUT_BYTES: usize = 1024 * 1024;
const MAX_GO_LIST_STDOUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_GO_STDERR_BYTES: usize = 1024 * 1024;
const MAX_GO_METADATA_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
struct GoEnvironment {
    goroot: PathBuf,
    gopath: PathBuf,
    gomodcache: PathBuf,
    goversion: String,
    gowork: String,
    goos: String,
    goarch: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GoModule {
    path: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    sum: String,
    #[serde(default)]
    dir: PathBuf,
    #[serde(default)]
    main: bool,
    replace: Option<Box<GoModule>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GoPackageError {
    err: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GoPackage {
    import_path: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    dir: PathBuf,
    #[serde(default)]
    standard: bool,
    #[serde(default)]
    incomplete: bool,
    error: Option<GoPackageError>,
    module: Option<GoModule>,
    #[serde(default)]
    go_files: Vec<PathBuf>,
    #[serde(default)]
    cgo_files: Vec<PathBuf>,
    #[serde(default)]
    ignored_go_files: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct DiscoveredGoPackage {
    pub import_path: String,
    #[serde(default)]
    pub name: String,
    pub directory: String,
    pub files: Vec<String>,
    pub ignored_go_files: Vec<String>,
    pub cgo_files: Vec<String>,
}

#[derive(Debug, Clone)]
struct GoInvocation {
    args: Vec<OsString>,
    env: Vec<(OsString, OsString)>,
    stdout_limit: usize,
    description: &'static str,
}

trait GoCommandRunner {
    fn run(
        &self,
        executable: &Path,
        root: &Path,
        config: &GoDependencyDiscoveryConfig,
        invocation: &GoInvocation,
        cancellation: Option<&CancellationToken>,
    ) -> Result<Vec<u8>, String>;
}

struct SystemGoCommandRunner;

impl GoCommandRunner for SystemGoCommandRunner {
    fn run(
        &self,
        executable: &Path,
        root: &Path,
        config: &GoDependencyDiscoveryConfig,
        invocation: &GoInvocation,
        cancellation: Option<&CancellationToken>,
    ) -> Result<Vec<u8>, String> {
        let output = run_bounded_process(
            &BoundedProcessRequest {
                program: executable.as_os_str().to_os_string(),
                args: invocation.args.clone(),
                env: invocation.env.clone(),
                clear_env: true,
                cwd: root.to_path_buf(),
                stdin: None,
                timeout: config.timeout,
                stdout_limit: invocation.stdout_limit,
                stderr_limit: MAX_GO_STDERR_BYTES,
                description: invocation.description.to_owned(),
            },
            || cancellation.is_some_and(CancellationToken::is_cancelled),
        )?;
        if output.status.success() {
            return Ok(output.stdout);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "{} exited with {}: {}",
            invocation.description,
            output.status,
            stderr.trim()
        ))
    }
}

pub fn resolve_go_semantic_pack_dependencies(
    config: &GoAnalyzerConfig,
    project: &dyn Project,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> DependencyDiscoveryOutcome {
    resolve_with_runner(
        config,
        project,
        limits,
        cancellation,
        &SystemGoCommandRunner,
    )
}

fn resolve_with_runner(
    config: &GoAnalyzerConfig,
    project: &dyn Project,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
    runner: &dyn GoCommandRunner,
) -> DependencyDiscoveryOutcome {
    let discovery = &config.dependency_discovery;
    if !discovery.enabled {
        return DependencyDiscoveryOutcome::complete(Vec::new());
    }
    if let Err(error) = validate_config(discovery) {
        return failed_outcome("go.config_invalid", error, cancellation, limits);
    }
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return cancelled_outcome();
    }
    let executable = discovery
        .go_executable
        .as_deref()
        .unwrap_or_else(|| Path::new("go"));
    let base_env = hardened_environment(discovery);
    let env_invocation = GoInvocation {
        args: [
            "env",
            "-json",
            "GOROOT",
            "GOPATH",
            "GOMODCACHE",
            "GOVERSION",
            "GOWORK",
            "GOOS",
            "GOARCH",
        ]
        .into_iter()
        .map(OsString::from)
        .collect(),
        env: base_env,
        stdout_limit: MAX_GO_ENV_STDOUT_BYTES,
        description: "Go environment discovery",
    };
    let env_bytes = match runner.run(
        executable,
        project.root(),
        discovery,
        &env_invocation,
        cancellation,
    ) {
        Ok(bytes) => bytes,
        Err(error) => return failed_outcome("go.env_failed", error, cancellation, limits),
    };
    let environment: GoEnvironment = match serde_json::from_slice(&env_bytes) {
        Ok(environment) => environment,
        Err(error) => {
            return failed_outcome(
                "go.env_invalid_json",
                format!("Go environment discovery returned invalid JSON: {error}"),
                cancellation,
                limits,
            );
        }
    };
    let goos = discovery.goos.as_deref().unwrap_or(&environment.goos);
    let goarch = discovery.goarch.as_deref().unwrap_or(&environment.goarch);
    if goos.is_empty() || goarch.is_empty() {
        return failed_outcome(
            "go.target_missing",
            "Go environment discovery did not return a target GOOS and GOARCH".to_owned(),
            cancellation,
            limits,
        );
    }
    let vendor = project.root().join("vendor").join("modules.txt").is_file();
    let mut list_args = vec![
        OsString::from("list"),
        OsString::from("-deps"),
        OsString::from("-json"),
        OsString::from("-e"),
        OsString::from(if vendor {
            "-mod=vendor"
        } else {
            "-mod=readonly"
        }),
    ];
    if !discovery.build_tags.is_empty() {
        list_args.push(OsString::from(format!(
            "-tags={}",
            discovery.build_tags.join(",")
        )));
    }
    list_args.extend(discovery.workspace_patterns.iter().map(OsString::from));
    let list_invocation = GoInvocation {
        args: list_args,
        env: target_environment(discovery, &environment, goos, goarch),
        stdout_limit: MAX_GO_LIST_STDOUT_BYTES,
        description: "Go package discovery",
    };
    let package_bytes = match runner.run(
        executable,
        project.root(),
        discovery,
        &list_invocation,
        cancellation,
    ) {
        Ok(bytes) => bytes,
        Err(error) => return failed_outcome("go.list_failed", error, cancellation, limits),
    };
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return cancelled_outcome();
    }
    let packages = match parse_package_stream(&package_bytes) {
        Ok(packages) => packages,
        Err(error) => {
            return failed_outcome("go.list_invalid_json", error, cancellation, limits);
        }
    };
    build_outcome(
        packages,
        &environment,
        project.root(),
        goos,
        goarch,
        discovery,
        vendor,
        limits,
    )
}

fn hardened_environment(config: &GoDependencyDiscoveryConfig) -> Vec<(OsString, OsString)> {
    let mut env = reviewed_host_environment();
    env.extend([
        os_env("GOTOOLCHAIN", "local"),
        os_env("GOPROXY", "off"),
        os_env("GOSUMDB", "off"),
        os_env("GOENV", "off"),
        os_env("GOFLAGS", ""),
        os_env("CGO_ENABLED", "0"),
    ]);
    if let Some(path) = &config.gopath {
        env.push((OsString::from("GOPATH"), path.as_os_str().to_os_string()));
    }
    if let Some(path) = &config.gomodcache {
        env.push((
            OsString::from("GOMODCACHE"),
            path.as_os_str().to_os_string(),
        ));
    }
    if let Some(goos) = &config.goos {
        env.push(os_env("GOOS", goos));
    }
    if let Some(goarch) = &config.goarch {
        env.push(os_env("GOARCH", goarch));
    }
    env
}

fn validate_config(config: &GoDependencyDiscoveryConfig) -> Result<(), String> {
    if config.workspace_patterns.is_empty() {
        return Err("Go dependency discovery requires at least one workspace pattern".to_owned());
    }
    for pattern in &config.workspace_patterns {
        if pattern.is_empty() || pattern.starts_with('-') || pattern.contains('\0') {
            return Err(format!("invalid Go workspace pattern {pattern:?}"));
        }
    }
    if let Some(goos) = &config.goos
        && !valid_go_identifier(goos)
    {
        return Err(format!("invalid GOOS value {goos:?}"));
    }
    if let Some(goarch) = &config.goarch
        && !valid_go_identifier(goarch)
    {
        return Err(format!("invalid GOARCH value {goarch:?}"));
    }
    for tag in &config.build_tags {
        if !valid_go_identifier(tag) {
            return Err(format!("invalid Go build tag {tag:?}"));
        }
    }
    Ok(())
}

fn valid_go_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.'))
}

fn target_environment(
    config: &GoDependencyDiscoveryConfig,
    environment: &GoEnvironment,
    goos: &str,
    goarch: &str,
) -> Vec<(OsString, OsString)> {
    let mut env = hardened_environment(config);
    set_env(&mut env, "GOOS", OsStr::new(goos));
    set_env(&mut env, "GOARCH", OsStr::new(goarch));
    set_env(&mut env, "GOROOT", environment.goroot.as_os_str());
    set_env(&mut env, "GOPATH", environment.gopath.as_os_str());
    set_env(&mut env, "GOMODCACHE", environment.gomodcache.as_os_str());
    env
}

fn reviewed_host_environment() -> Vec<(OsString, OsString)> {
    [
        "PATH",
        "HOME",
        "USERPROFILE",
        "TMPDIR",
        "TEMP",
        "TMP",
        "SYSTEMROOT",
        "WINDIR",
    ]
    .into_iter()
    .filter_map(|name| std::env::var_os(name).map(|value| (OsString::from(name), value)))
    .collect()
}

fn os_env(name: &str, value: &str) -> (OsString, OsString) {
    (OsString::from(name), OsString::from(value))
}

fn set_env(env: &mut Vec<(OsString, OsString)>, name: &str, value: &OsStr) {
    env.retain(|(key, _)| key != name);
    env.push((OsString::from(name), value.to_os_string()));
}

fn parse_package_stream(bytes: &[u8]) -> Result<Vec<GoPackage>, String> {
    let values = serde_json::Deserializer::from_slice(bytes).into_iter::<GoPackage>();
    values
        .enumerate()
        .map(|(index, value)| {
            value.map_err(|error| format!("Go package record {index} is invalid: {error}"))
        })
        .collect()
}

#[derive(Debug)]
struct DependencyGroup {
    id: String,
    root: PathBuf,
    module: Option<GoModule>,
    packages: Vec<DiscoveredGoPackage>,
    source_paths: Vec<PathBuf>,
}

#[allow(clippy::too_many_arguments)]
fn build_outcome(
    packages: Vec<GoPackage>,
    environment: &GoEnvironment,
    project_root: &Path,
    goos: &str,
    goarch: &str,
    config: &GoDependencyDiscoveryConfig,
    vendor: bool,
    limits: &DependencyPackLimits,
) -> DependencyDiscoveryOutcome {
    let mut groups: BTreeMap<String, DependencyGroup> = BTreeMap::new();
    let mut diagnostics = Vec::new();
    let import_names = packages
        .iter()
        .filter(|package| !package.name.is_empty())
        .map(|package| (package.import_path.clone(), package.name.clone()))
        .collect::<BTreeMap<_, _>>();
    let import_names_json =
        serde_json::to_string(&import_names).expect("Go import names are JSON serializable");
    let workspace_identity = match metadata_identity(&environment.gowork) {
        Ok(identity) => identity,
        Err(error) => {
            diagnostics.push(error_diagnostic(
                "go.workspace_metadata_invalid",
                None,
                error,
                limits,
            ));
            "workspace-unavailable".to_owned()
        }
    };
    let vendor_identity = if vendor {
        match file_identity(&project_root.join("vendor").join("modules.txt")) {
            Ok(identity) => Some(identity),
            Err(error) => {
                diagnostics.push(error_diagnostic(
                    "go.vendor_metadata_invalid",
                    None,
                    error,
                    limits,
                ));
                None
            }
        }
    } else {
        None
    };
    let goroot_source = environment.goroot.join("src");
    let vendor_root = project_root.join("vendor");
    for package in packages {
        if package.module.as_ref().is_some_and(|module| module.main) {
            continue;
        }
        if let Some(error) = &package.error {
            diagnostics.push(error_diagnostic(
                "go.package_incomplete",
                Some(package.import_path.clone()),
                format!(
                    "Go package {} is incomplete: {}",
                    package.import_path, error.err
                ),
                limits,
            ));
        } else if package.incomplete {
            diagnostics.push(error_diagnostic(
                "go.package_incomplete",
                Some(package.import_path.clone()),
                format!("Go package {} is incomplete", package.import_path),
                limits,
            ));
        }
        if !package.cgo_files.is_empty() {
            diagnostics.push(error_diagnostic(
                "go.cgo_unsupported",
                Some(package.import_path.clone()),
                format!(
                    "Go package {} requires cgo files {:?}, which exact API discovery does not model",
                    package.import_path, package.cgo_files
                ),
                limits,
            ));
        }
        if package.go_files.is_empty() {
            continue;
        }
        let (key, id, root, module) = if package.standard {
            (
                "stdlib".to_owned(),
                format!("go:stdlib:{}", environment.goversion),
                goroot_source.clone(),
                None,
            )
        } else if vendor && package.dir.starts_with(&vendor_root) {
            let Some(module) = package.module.clone() else {
                diagnostics.push(error_diagnostic(
                    "go.module_missing",
                    Some(package.import_path.clone()),
                    format!(
                        "vendored Go package {} has no module metadata",
                        package.import_path
                    ),
                    limits,
                ));
                continue;
            };
            let module_id = module_id(&module);
            (
                format!("vendor:{module_id}"),
                format!("go:vendor:{module_id}"),
                vendor_root.clone(),
                Some(module),
            )
        } else {
            let Some(module) = package.module.clone() else {
                diagnostics.push(error_diagnostic(
                    "go.module_missing",
                    Some(package.import_path.clone()),
                    format!("Go package {} has no module metadata", package.import_path),
                    limits,
                ));
                continue;
            };
            let effective = module.replace.as_deref().unwrap_or(&module);
            if effective.dir.as_os_str().is_empty() {
                diagnostics.push(error_diagnostic(
                    "go.module_root_missing",
                    Some(package.import_path.clone()),
                    format!("Go module {} has no local source directory", module.path),
                    limits,
                ));
                continue;
            }
            let module_id = module_id(&module);
            (
                format!("module:{module_id}"),
                format!("go:module:{module_id}"),
                effective.dir.clone(),
                Some(module),
            )
        };
        let package_record = match validate_package(&package, &root) {
            Ok(record) => record,
            Err(error) => {
                diagnostics.push(error_diagnostic(
                    "go.source_path_invalid",
                    Some(package.import_path.clone()),
                    error,
                    limits,
                ));
                continue;
            }
        };
        let source_paths = package_record.files.iter().map(PathBuf::from);
        let group = groups.entry(key).or_insert_with(|| DependencyGroup {
            id,
            root,
            module,
            packages: Vec::new(),
            source_paths: Vec::new(),
        });
        group.source_paths.extend(source_paths);
        group.packages.push(package_record);
    }
    let target = format!(
        "go-{}-{}",
        goos.to_ascii_lowercase(),
        goarch.to_ascii_lowercase()
    );
    let configuration = configuration_identity(config, vendor);
    let toolchain = CatalogCoordinate {
        name: "go".to_owned(),
        version: go_version(&environment.goversion),
    };
    let mut dependencies = Vec::new();
    for (_, mut group) in groups {
        group.packages.sort_by(|left, right| {
            left.import_path
                .cmp(&right.import_path)
                .then_with(|| left.directory.cmp(&right.directory))
        });
        group.packages.dedup();
        group.source_paths.sort();
        group.source_paths.dedup();
        if group.source_paths.len() > limits.max_source_files_per_artifact {
            diagnostics.push(error_diagnostic(
                "limit.source_files",
                Some(group.id),
                format!(
                    "Go source set exceeded the configured file limit {}",
                    limits.max_source_files_per_artifact
                ),
                limits,
            ));
            continue;
        }
        if group
            .source_paths
            .iter()
            .any(|path| path.components().count() > limits.max_source_path_depth)
        {
            diagnostics.push(error_diagnostic(
                "limit.source_path_depth",
                Some(group.id),
                format!(
                    "Go source set exceeded the configured path-depth limit {}",
                    limits.max_source_path_depth
                ),
                limits,
            ));
            continue;
        }
        let packages_json = serde_json::to_string(&group.packages)
            .expect("discovered Go package metadata is serializable");
        let module_coordinate = group.module.as_ref().map(|module| CatalogCoordinate {
            name: module.path.clone(),
            version: module_version(&module.version),
        });
        let mut provenance = vec![
            DependencyProvenance {
                key: "go.packages".to_owned(),
                value: packages_json,
            },
            DependencyProvenance {
                key: "go.version".to_owned(),
                value: environment.goversion.clone(),
            },
            DependencyProvenance {
                key: "go.import_names".to_owned(),
                value: import_names_json.clone(),
            },
            DependencyProvenance {
                key: "go.workspace".to_owned(),
                value: workspace_identity.clone(),
            },
        ];
        if let Some(identity) = &vendor_identity {
            provenance.push(DependencyProvenance {
                key: "go.vendor".to_owned(),
                value: identity.clone(),
            });
        }
        if let Some(module) = &group.module {
            provenance.extend(module_provenance(module));
        }
        dependencies.push(ResolvedDependency {
            id: group.id,
            evidence: SemanticModelActivationEvidence {
                language: "go".to_owned(),
                ecosystem: if group.module.is_some() {
                    "go-module".to_owned()
                } else {
                    "go-stdlib".to_owned()
                },
                package: None,
                module: module_coordinate,
                toolchain: Some(toolchain.clone()),
                target: Some(target.clone()),
                configuration: Some(configuration.clone()),
                artifact_sha256: None,
            },
            provenance,
            artifacts: vec![ResolvedDependencyArtifact::source_set(
                DependencyArtifactRole::Sources,
                ExternalArtifactKind::GoSourceSet,
                group.root,
                group.source_paths,
            )],
        });
    }
    let mut suppressed_diagnostics = 0;
    if dependencies.len() > limits.max_dependencies {
        suppressed_diagnostics += dependencies.len() - limits.max_dependencies;
        dependencies.truncate(limits.max_dependencies);
        diagnostics.push(error_diagnostic(
            "limit.dependencies",
            None,
            format!(
                "Go dependency discovery exceeded the configured limit {}",
                limits.max_dependencies
            ),
            limits,
        ));
    }
    if diagnostics.len() > limits.max_diagnostics {
        suppressed_diagnostics += diagnostics.len() - limits.max_diagnostics;
        diagnostics.truncate(limits.max_diagnostics);
    }
    DependencyDiscoveryOutcome {
        profile: DependencyDiscoveryProfile {
            metadata_inputs_considered: 2,
            dependencies_resolved: dependencies.len(),
        },
        dependencies,
        complete: diagnostics.is_empty() && suppressed_diagnostics == 0,
        diagnostics,
        suppressed_diagnostics,
        cancelled: false,
    }
}

fn validate_package(package: &GoPackage, root: &Path) -> Result<DiscoveredGoPackage, String> {
    let canonical_root = root
        .canonicalize()
        .map_err(|error| format!("cannot resolve source root {}: {error}", root.display()))?;
    let canonical_directory = package.dir.canonicalize().map_err(|error| {
        format!(
            "cannot resolve package directory {}: {error}",
            package.dir.display()
        )
    })?;
    let directory = canonical_directory
        .strip_prefix(&canonical_root)
        .map_err(|_| {
            format!(
                "package directory {} escapes source root {}",
                package.dir.display(),
                root.display()
            )
        })?
        .to_path_buf();
    let mut files = Vec::with_capacity(package.go_files.len());
    for file in &package.go_files {
        if file.components().count() != 1
            || file
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(format!("selected Go file path {file:?} is not a file name"));
        }
        let path = canonical_directory.join(file);
        let canonical_file = path.canonicalize().map_err(|error| {
            format!(
                "cannot resolve selected Go file {}: {error}",
                path.display()
            )
        })?;
        let relative = canonical_file.strip_prefix(&canonical_root).map_err(|_| {
            format!(
                "selected Go file {} escapes its source root",
                path.display()
            )
        })?;
        files.push(normalize_relative_path(relative)?);
    }
    files.sort();
    files.dedup();
    Ok(DiscoveredGoPackage {
        import_path: package.import_path.clone(),
        name: package.name.clone(),
        directory: normalize_relative_path(&directory)?,
        files,
        ignored_go_files: normalize_file_names(&package.ignored_go_files)?,
        cgo_files: normalize_file_names(&package.cgo_files)?,
    })
}

fn normalize_file_names(paths: &[PathBuf]) -> Result<Vec<String>, String> {
    let mut normalized = paths
        .iter()
        .map(|path| {
            if path.components().count() != 1
                || path
                    .components()
                    .any(|component| !matches!(component, Component::Normal(_)))
            {
                return Err(format!("Go file path {path:?} is not a file name"));
            }
            normalize_relative_path(path)
        })
        .collect::<Result<Vec<_>, _>>()?;
    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

fn normalize_relative_path(path: &Path) -> Result<String, String> {
    let mut segments = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(segment) => segments.push(
                segment
                    .to_str()
                    .ok_or_else(|| format!("Go source path {path:?} is not UTF-8"))?,
            ),
            _ => return Err(format!("Go source path {path:?} is not normalized")),
        }
    }
    if segments.is_empty() {
        return Ok(String::new());
    }
    Ok(segments.join("/"))
}

fn module_id(module: &GoModule) -> String {
    if !module.version.is_empty() {
        format!("{}@{}", module.path, module.version)
    } else if let Some(replacement) = &module.replace {
        if !replacement.version.is_empty() {
            format!(
                "{}=>{}@{}",
                module.path, replacement.path, replacement.version
            )
        } else {
            format!("{}@local", module.path)
        }
    } else {
        format!("{}@local", module.path)
    }
}

fn module_provenance(module: &GoModule) -> Vec<DependencyProvenance> {
    let mut provenance = vec![
        DependencyProvenance {
            key: "module.path".to_owned(),
            value: module.path.clone(),
        },
        DependencyProvenance {
            key: "module.version".to_owned(),
            value: module.version.clone(),
        },
        DependencyProvenance {
            key: "module.sum".to_owned(),
            value: module.sum.clone(),
        },
    ];
    if let Some(replacement) = &module.replace {
        provenance.push(DependencyProvenance {
            key: "module.replacement".to_owned(),
            value: if replacement.version.is_empty() {
                format!("local:{}", replacement.path.replace('\\', "/"))
            } else {
                format!("{}@{}", replacement.path, replacement.version)
            },
        });
    }
    provenance
}

fn module_version(raw: &str) -> Option<Version> {
    Version::parse(raw.strip_prefix('v').unwrap_or(raw)).ok()
}

fn go_version(raw: &str) -> Option<Version> {
    Version::parse(raw.strip_prefix("go").unwrap_or(raw)).ok()
}

fn metadata_identity(raw: &str) -> Result<String, String> {
    if raw.is_empty() || raw == "off" {
        Ok(raw.to_owned())
    } else {
        file_identity(Path::new(raw)).map(|identity| format!("workspace:{identity}"))
    }
}

fn file_identity(path: &Path) -> Result<String, String> {
    let metadata = path.metadata().map_err(|error| {
        format!(
            "cannot inspect Go metadata file {}: {error}",
            path.display()
        )
    })?;
    if !metadata.is_file() {
        return Err(format!("Go metadata path {} is not a file", path.display()));
    }
    if metadata.len() > MAX_GO_METADATA_BYTES {
        return Err(format!(
            "Go metadata file {} exceeds {} bytes",
            path.display(),
            MAX_GO_METADATA_BYTES
        ));
    }
    let bytes = std::fs::read(path)
        .map_err(|error| format!("cannot read Go metadata file {}: {error}", path.display()))?;
    Ok(lower_hex_string(&sha256_bytes(&bytes)))
}

fn configuration_identity(config: &GoDependencyDiscoveryConfig, vendor: bool) -> String {
    let encoded = serde_json::to_vec(&serde_json::json!({
        "cgo": false,
        "module_mode": if vendor { "vendor" } else { "readonly" },
        "tags": config.build_tags,
    }))
    .expect("Go discovery configuration is JSON serializable");
    format!("go-config-{}", lower_hex_string(&sha256_bytes(&encoded)))
}

fn error_diagnostic(
    code: &str,
    dependency_id: Option<String>,
    mut message: String,
    limits: &DependencyPackLimits,
) -> DependencyPackDiagnostic {
    if message.len() > limits.max_diagnostic_message_bytes {
        let mut boundary = limits.max_diagnostic_message_bytes;
        while !message.is_char_boundary(boundary) {
            boundary -= 1;
        }
        message.truncate(boundary);
    }
    DependencyPackDiagnostic {
        severity: DependencyPackDiagnosticSeverity::Error,
        code: code.to_owned(),
        dependency_id,
        location: None,
        message,
    }
}

fn failed_outcome(
    code: &str,
    message: String,
    cancellation: Option<&CancellationToken>,
    limits: &DependencyPackLimits,
) -> DependencyDiscoveryOutcome {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return cancelled_outcome();
    }
    DependencyDiscoveryOutcome {
        dependencies: Vec::new(),
        diagnostics: vec![error_diagnostic(code, None, message, limits)],
        suppressed_diagnostics: 0,
        complete: false,
        cancelled: false,
        profile: DependencyDiscoveryProfile::default(),
    }
}

fn cancelled_outcome() -> DependencyDiscoveryOutcome {
    DependencyDiscoveryOutcome {
        dependencies: Vec::new(),
        diagnostics: vec![DependencyPackDiagnostic {
            severity: DependencyPackDiagnosticSeverity::Error,
            code: "discovery.cancelled".to_owned(),
            dependency_id: None,
            location: None,
            message: "Go dependency discovery was cancelled".to_owned(),
        }],
        suppressed_diagnostics: 0,
        complete: false,
        cancelled: true,
        profile: DependencyDiscoveryProfile::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic_model::ResolvedDependencyArtifactInput;
    use crate::analyzer::{GoAnalyzerConfig, GoDependencyDiscoveryConfig};
    use crate::analyzer::{Language, TestProject};
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::process::Command;
    use std::time::Duration;

    #[derive(Default)]
    struct FakeRunner {
        outputs: RefCell<VecDeque<Result<Vec<u8>, String>>>,
        invocations: RefCell<Vec<GoInvocation>>,
    }

    impl FakeRunner {
        fn with_outputs(outputs: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                outputs: RefCell::new(outputs.into_iter().map(Ok).collect()),
                invocations: RefCell::new(Vec::new()),
            }
        }
    }

    impl GoCommandRunner for FakeRunner {
        fn run(
            &self,
            _executable: &Path,
            _root: &Path,
            _config: &GoDependencyDiscoveryConfig,
            invocation: &GoInvocation,
            _cancellation: Option<&CancellationToken>,
        ) -> Result<Vec<u8>, String> {
            self.invocations.borrow_mut().push(invocation.clone());
            self.outputs.borrow_mut().pop_front().unwrap()
        }
    }

    fn config() -> GoAnalyzerConfig {
        GoAnalyzerConfig {
            dependency_discovery: GoDependencyDiscoveryConfig {
                enabled: true,
                go_executable: Some(PathBuf::from("configured-go")),
                workspace_patterns: vec!["./cmd/...".to_owned()],
                gopath: None,
                gomodcache: None,
                goos: Some("linux".to_owned()),
                goarch: Some("arm64".to_owned()),
                build_tags: vec!["integration".to_owned(), "safe".to_owned()],
                timeout: Duration::from_secs(7),
            },
        }
    }

    fn environment(root: &Path) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "GOROOT": root.join("goroot"),
            "GOPATH": root.join("gopath"),
            "GOMODCACHE": root.join("gopath/pkg/mod"),
            "GOVERSION": "go1.25.1",
            "GOWORK": "off",
            "GOOS": "darwin",
            "GOARCH": "arm64"
        }))
        .unwrap()
    }

    #[test]
    fn discovery_uses_only_hardened_metadata_invocations() {
        let temporary = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temporary.path().join("goroot/src")).unwrap();
        let project = TestProject::new(temporary.path(), Language::Go);
        let runner = FakeRunner::with_outputs([environment(temporary.path()), Vec::new()]);
        let outcome = resolve_with_runner(
            &config(),
            &project,
            &DependencyPackLimits::default(),
            None,
            &runner,
        );
        assert!(outcome.complete, "{:?}", outcome.diagnostics);
        let invocations = runner.invocations.borrow();
        assert_eq!(invocations.len(), 2);
        assert_eq!(invocations[0].args[0], "env");
        assert_eq!(invocations[1].args[0], "list");
        assert!(invocations[1].args.iter().any(|arg| arg == "-mod=readonly"));
        assert!(
            invocations[1]
                .args
                .iter()
                .any(|arg| arg == "-tags=integration,safe")
        );
        let env: BTreeMap<_, _> = invocations[1].env.iter().cloned().collect();
        assert_eq!(env.get(OsStr::new("GOTOOLCHAIN")).unwrap(), "local");
        assert_eq!(env.get(OsStr::new("GOPROXY")).unwrap(), "off");
        assert_eq!(env.get(OsStr::new("GOSUMDB")).unwrap(), "off");
        assert_eq!(env.get(OsStr::new("GOENV")).unwrap(), "off");
        assert_eq!(env.get(OsStr::new("CGO_ENABLED")).unwrap(), "0");
        assert_eq!(env.get(OsStr::new("GOOS")).unwrap(), "linux");
        assert_eq!(env.get(OsStr::new("GOARCH")).unwrap(), "arm64");
    }

    #[test]
    fn discovery_groups_exact_module_and_standard_library_sources() {
        let temporary = tempfile::tempdir().unwrap();
        let goroot = temporary.path().join("goroot/src/fmt");
        let module = temporary
            .path()
            .join("gopath/pkg/mod/example.com/dep@v1.2.3/pkg");
        std::fs::create_dir_all(&goroot).unwrap();
        std::fs::create_dir_all(&module).unwrap();
        std::fs::write(goroot.join("print.go"), "package fmt").unwrap();
        std::fs::write(module.join("api.go"), "package pkg").unwrap();
        let package_stream = format!(
            "{}\n{}\n",
            serde_json::json!({
                "ImportPath": "fmt",
                "Dir": goroot,
                "Standard": true,
                "GoFiles": ["print.go"],
                "IgnoredGoFiles": ["export_test.go"]
            }),
            serde_json::json!({
                "ImportPath": "example.com/dep/pkg",
                "Dir": module,
                "GoFiles": ["api.go"],
                "Module": {
                    "Path": "example.com/dep",
                    "Version": "v1.2.3",
                    "Sum": "h1:exact",
                    "Dir": temporary.path().join("gopath/pkg/mod/example.com/dep@v1.2.3")
                }
            })
        )
        .into_bytes();
        let runner = FakeRunner::with_outputs([environment(temporary.path()), package_stream]);
        let project = TestProject::new(temporary.path(), Language::Go);
        let outcome = resolve_with_runner(
            &config(),
            &project,
            &DependencyPackLimits::default(),
            None,
            &runner,
        );
        assert!(outcome.complete, "{:?}", outcome.diagnostics);
        assert_eq!(outcome.dependencies.len(), 2);
        let module = outcome
            .dependencies
            .iter()
            .find(|dependency| dependency.id.contains("example.com/dep"))
            .unwrap();
        assert_eq!(
            module.evidence.module.as_ref().unwrap().version,
            Some(Version::new(1, 2, 3))
        );
        assert!(
            module
                .provenance
                .iter()
                .any(|fact| fact.key == "module.sum" && fact.value == "h1:exact")
        );
        let ResolvedDependencyArtifactInput::SourceSet { relative_paths, .. } =
            &module.artifacts[0].input
        else {
            panic!("expected source-set input");
        };
        assert_eq!(relative_paths, &[PathBuf::from("pkg/api.go")]);
    }

    #[test]
    fn discovery_reports_cgo_and_package_errors_as_incomplete() {
        let temporary = tempfile::tempdir().unwrap();
        let goroot = temporary.path().join("goroot/src/net");
        std::fs::create_dir_all(&goroot).unwrap();
        std::fs::write(goroot.join("net.go"), "package net").unwrap();
        let packages = serde_json::json!({
            "ImportPath": "net",
            "Dir": goroot,
            "Standard": true,
            "Incomplete": true,
            "Error": {"Err": "missing local package"},
            "GoFiles": ["net.go"],
            "CgoFiles": ["cgo_unix.go"]
        })
        .to_string()
        .into_bytes();
        let runner = FakeRunner::with_outputs([environment(temporary.path()), packages]);
        let project = TestProject::new(temporary.path(), Language::Go);
        let outcome = resolve_with_runner(
            &config(),
            &project,
            &DependencyPackLimits::default(),
            None,
            &runner,
        );
        assert!(!outcome.complete);
        assert!(
            outcome
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "go.package_incomplete")
        );
        assert!(
            outcome
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "go.cgo_unsupported")
        );
    }

    #[test]
    fn discovery_preserves_vendor_mode_and_manifest_identity() {
        let temporary = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temporary.path().join("goroot/src")).unwrap();
        let package_dir = temporary.path().join("vendor/example.com/dep/pkg");
        std::fs::create_dir_all(&package_dir).unwrap();
        std::fs::write(
            temporary.path().join("vendor/modules.txt"),
            "# example.com/dep v1.2.3\n## explicit\nexample.com/dep/pkg\n",
        )
        .unwrap();
        std::fs::write(package_dir.join("api.go"), "package pkg").unwrap();
        let packages = serde_json::json!({
            "ImportPath": "example.com/dep/pkg",
            "Dir": package_dir,
            "GoFiles": ["api.go"],
            "Module": {
                "Path": "example.com/dep",
                "Version": "v1.2.3",
                "Sum": "h1:vendor"
            }
        })
        .to_string()
        .into_bytes();
        let runner = FakeRunner::with_outputs([environment(temporary.path()), packages]);
        let project = TestProject::new(temporary.path(), Language::Go);
        let outcome = resolve_with_runner(
            &config(),
            &project,
            &DependencyPackLimits::default(),
            None,
            &runner,
        );
        assert!(outcome.complete, "{:?}", outcome.diagnostics);
        assert!(
            runner.invocations.borrow()[1]
                .args
                .iter()
                .any(|arg| arg == "-mod=vendor")
        );
        let dependency = &outcome.dependencies[0];
        assert!(dependency.id.starts_with("go:vendor:"));
        assert!(
            dependency
                .provenance
                .iter()
                .any(|entry| entry.key == "go.vendor" && entry.value.len() == 64)
        );
    }

    #[test]
    fn discovery_rejects_flag_shaped_patterns_before_running_go() {
        let temporary = tempfile::tempdir().unwrap();
        let project = TestProject::new(temporary.path(), Language::Go);
        let runner = FakeRunner::default();
        let mut config = config();
        config.dependency_discovery.workspace_patterns = vec!["-exec=attacker".to_owned()];
        let outcome = resolve_with_runner(
            &config,
            &project,
            &DependencyPackLimits::default(),
            None,
            &runner,
        );
        assert!(!outcome.complete);
        assert_eq!(outcome.diagnostics[0].code, "go.config_invalid");
        assert!(runner.invocations.borrow().is_empty());
    }

    #[test]
    fn installed_go_discovers_standard_library_offline() {
        if Command::new("go").arg("version").output().is_err() {
            return;
        }
        let temporary = tempfile::tempdir().unwrap();
        std::fs::write(
            temporary.path().join("go.mod"),
            "module example.com/bifrost-smoke\n\ngo 1.24\n",
        )
        .unwrap();
        std::fs::write(
            temporary.path().join("main.go"),
            "package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"ok\") }\n",
        )
        .unwrap();
        let project = TestProject::new(temporary.path(), Language::Go);
        let mut config = config();
        config.dependency_discovery.go_executable = Some(PathBuf::from("go"));
        config.dependency_discovery.workspace_patterns = vec![".".to_owned()];
        config.dependency_discovery.goos = None;
        config.dependency_discovery.goarch = None;
        config.dependency_discovery.build_tags.clear();
        let outcome = resolve_go_semantic_pack_dependencies(
            &config,
            &project,
            &DependencyPackLimits::default(),
            None,
        );
        assert!(outcome.complete, "{:?}", outcome.diagnostics);
        let standard_library = outcome
            .dependencies
            .iter()
            .find(|dependency| dependency.id.starts_with("go:stdlib:"))
            .expect("fmt dependency should produce a standard-library source set");
        let packages = standard_library
            .provenance
            .iter()
            .find(|entry| entry.key == "go.packages")
            .unwrap();
        assert!(packages.value.contains("\"import_path\":\"fmt\""));
    }
}
